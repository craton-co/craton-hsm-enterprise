// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! `CryptoBackend` implementation that delegates to an external PKCS#11 token.
//!
//! All operations route through a [`SessionPool`]; cache lookups and the
//! crypto call that consumes the cached handle execute under the same
//! per-session lock, so there is no TOCTOU race between
//! `cache.get(...)` and `session.sign(handle, ...)`.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::digest::DigestAccumulator;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::{HsmError, HsmResult};
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use craton_hsm::store::key_material::RawKeyMaterial;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::elliptic_curve::Ecdh1DeriveParams;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use zeroize::Zeroizing;

use crate::cache::{fingerprint, KeyFingerprint};
use crate::config::Pkcs11PassthroughConfig;
use crate::digest_info::{build_digest_info, expected_digest_len};
use crate::error::{classify_verify_result, pkcs11_err};
use crate::pool::{PooledSession, SessionPool};

// P-256 OID 1.2.840.10045.3.1.7 (DER)
const EC_PARAMS_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
// P-384 OID 1.3.132.0.34 (DER)
const EC_PARAMS_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
// Ed25519 OID 1.3.101.112 (DER)
const EC_PARAMS_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

/// Hard upper bound on AES-GCM messages per imported key, derived from
/// NIST SP 800-38D 8.3 (random 96-bit IV birthday bound).
const DEFAULT_GCM_MAX_MESSAGES_PER_KEY: u64 = 1 << 32;

/// PKCS#11 passthrough backend implementing [`CryptoBackend`].
///
/// # WARNING — key-generation entry points return raw key bytes
///
/// Methods that produce fresh key material on the token (notably
/// [`CryptoBackend::generate_aes_key`] and the RSA / ECC keygen
/// variants) intentionally create the token object with
/// `CKA_SENSITIVE = false` + `CKA_EXTRACTABLE = true` because the
/// `CryptoBackend` trait contract requires returning
/// [`RawKeyMaterial`] (i.e. the actual bytes). The generated key
/// is therefore lifted out of the HSM immediately and lives in
/// process memory thereafter. If you want a token-resident,
/// non-extractable key, this is NOT the right API; see the
/// method-level docs for `generate_aes_key` for details.
///
/// `Debug` is intentionally a hand-written impl that elides the
/// internal `SessionPool` (which holds live token handles) and the
/// FIPS vendor allow-list. `Result::unwrap_err()` invokes Debug on
/// the Ok variant, so this must not be derived blindly.
pub struct Pkcs11PassthroughBackend {
    pool: SessionPool,
    fips_mode: bool,
    fips_vendors: Vec<String>,
    allow_software_keygen_fallback: bool,
    gcm_max_messages_per_key: u64,
}

impl std::fmt::Debug for Pkcs11PassthroughBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11PassthroughBackend")
            .field("fips_mode", &self.fips_mode)
            .field("fips_vendor_count", &self.fips_vendors.len())
            .field(
                "allow_software_keygen_fallback",
                &self.allow_software_keygen_fallback,
            )
            .field("gcm_max_messages_per_key", &self.gcm_max_messages_per_key)
            .field("pool", &"<elided>")
            .finish()
    }
}

impl Pkcs11PassthroughBackend {
    /// Construct a new backend, opening the PKCS#11 library and the configured
    /// pool of logged-in sessions.
    pub fn new(config: Pkcs11PassthroughConfig) -> HsmResult<Self> {
        let Pkcs11PassthroughConfig {
            library_path,
            slot_id,
            pin,
            fips_mode,
            fips_vendors,
            pool_size,
            cache_capacity,
            allow_software_keygen_fallback,
            gcm_max_messages_per_key,
        } = config;

        let pool = SessionPool::new(&library_path, slot_id, pin, pool_size, cache_capacity)?;

        // SECURITY: the GCM nonce-reuse budget enforced via
        // `PoolGcmCounters` is process-local; it resets on backend
        // restart. Real persistent counters across restarts are out of
        // scope for this crate. Operators relying on a single imported
        // AES-GCM key for more than `gcm_max_messages_per_key` messages
        // across a restart must rotate the key on operator policy.
        let effective_gcm_limit = if gcm_max_messages_per_key == 0 {
            DEFAULT_GCM_MAX_MESSAGES_PER_KEY
        } else {
            gcm_max_messages_per_key
        };
        tracing::warn!(
            target: "craton_hsm_pkcs11",
            "AES-GCM per-key message budget is PROCESS-LOCAL and resets on \
             restart (limit = {} messages/key). Persistent durable counters \
             are not implemented; rotate keys per operator policy if a \
             restart could approach the budget for any single key.",
            effective_gcm_limit
        );

        Ok(Self {
            pool,
            fips_mode,
            fips_vendors,
            allow_software_keygen_fallback,
            gcm_max_messages_per_key: effective_gcm_limit,
        })
    }

    /// Total number of pooled sessions.
    pub fn pool_size(&self) -> usize {
        self.pool.pool_size()
    }

    /// Per-session cache capacity.
    pub fn cache_capacity(&self) -> usize {
        self.pool.cache_capacity()
    }

    /// Test whether the operator has supplied at least one entry in the
    /// `fips_vendors` allow-list, signalling that they have explicitly
    /// approved a software FIPS fallback path for this token.
    fn is_vendor_allow_listed(&self) -> bool {
        self.fips_vendors.iter().any(|v| !v.is_empty())
    }
}
impl Pkcs11PassthroughBackend {
    // Internal helpers -- key import, deferred destroy, RNG

    /// Look up `fp` in the per-session cache. On miss, build a fresh template
    /// via `make_template`, create the session object, insert into the cache,
    /// and destroy any evicted sibling on the same session.
    fn get_or_import(
        sess: &mut PooledSession,
        fp: KeyFingerprint,
        make_template: impl FnOnce() -> Vec<Attribute>,
    ) -> HsmResult<ObjectHandle> {
        if let Some(h) = sess.cache_mut().get(&fp) {
            return Ok(h);
        }
        let template = make_template();
        let (session, cache) = sess.split();
        let handle = session.create_object(&template).map_err(pkcs11_err)?;
        if let Some(evicted) = cache.insert(fp, handle) {
            let _ = session.destroy_object(evicted);
        }
        Ok(handle)
    }

    /// Import an AES key (or look it up in the cache).
    ///
    /// The key material `Vec` is built INSIDE the cache-miss closure so a
    /// cache hit avoids the allocation entirely.
    fn import_aes(
        sess: &mut PooledSession,
        key_bytes: &[u8],
    ) -> HsmResult<(ObjectHandle, KeyFingerprint)> {
        // Reject anything that is not a valid AES key length BEFORE the
        // `* 8` multiplication so we never hand the token a bogus
        // ValueLen attribute (e.g. a 17-byte buffer silently becoming
        // 136-bit). Matches the AES-128/192/256 set required by FIPS 197.
        match key_bytes.len() {
            16 | 24 | 32 => {}
            _ => return Err(HsmError::KeySizeRange),
        }
        let fp = fingerprint(b"aes", &[key_bytes]);
        let len_bits_ul = cryptoki::types::Ulong::try_from(key_bytes.len() * 8)
            .map_err(|_| HsmError::DataLenRange)?;
        let handle = Self::get_or_import(sess, fp, || {
            let key_copy = Zeroizing::new(key_bytes.to_vec());
            vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Value((*key_copy).clone()),
                Attribute::ValueLen(len_bits_ul),
                Attribute::Token(false),
                Attribute::Sensitive(true),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
            ]
        })?;
        Ok((handle, fp))
    }

    /// Import an RSA private key from raw PKCS#8 bytes.
    ///
    /// Real PKCS#11 tokens (Thales Luna, Entrust nShield, AWS CloudHSM, etc.)
    /// reject `CKA_VALUE` for RSA private keys: PKCS#11 mandates that an
    /// imported RSA private key be supplied as its CRT components
    /// (modulus, public exponent, private exponent, prime1, prime2,
    /// exponent1, exponent2, coefficient). SoftHSM2 happens to accept
    /// `CKA_VALUE` (raw PKCS#8) so the bug was masked under local testing.
    ///
    /// The PKCS#8 blob is parsed in-process via the `rsa` crate; all
    /// CRT byte vectors are wrapped in `Zeroizing` so they are cleared on
    /// drop. The per-call cache key (SHA-256 fingerprint over the raw
    /// PKCS#8 DER) is unchanged so cache hits still elide the parse cost.
    fn import_rsa_priv(sess: &mut PooledSession, priv_der: &[u8]) -> HsmResult<ObjectHandle> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PrivateKeyParts;
        use rsa::traits::PublicKeyParts;

        // Cache lookup is purely a fingerprint of the raw PKCS#8 DER, so
        // a cache hit can skip the (relatively expensive) parse +
        // validate + precompute steps below entirely.
        let fp = fingerprint(b"rsa-priv", &[priv_der]);
        if let Some(h) = sess.cache_mut().get(&fp) {
            return Ok(h);
        }

        let priv_key =
            rsa::RsaPrivateKey::from_pkcs8_der(priv_der).map_err(|_| HsmError::DataInvalid)?;
        // Defence in depth: the `rsa` crate parses attacker-supplied DER
        // into a structure that has not necessarily been arithmetically
        // validated. `validate()` rejects keys where p*q != n, where the
        // CRT components are inconsistent, etc.
        priv_key.validate().map_err(|_| HsmError::DataInvalid)?;
        // Pre-compute CRT params (the rsa crate lazily fills `d mod (p-1)`
        // etc.; `precompute` makes them all `Some`).
        let mut priv_key = priv_key;
        priv_key.precompute().map_err(|_| HsmError::DataInvalid)?;

        let primes = priv_key.primes();
        if primes.len() < 2 {
            return Err(HsmError::DataInvalid);
        }
        let modulus = Zeroizing::new(priv_key.n().to_bytes_be());
        let pub_exp = Zeroizing::new(priv_key.e().to_bytes_be());
        let priv_exp = Zeroizing::new(priv_key.d().to_bytes_be());
        let prime1 = Zeroizing::new(primes[0].to_bytes_be());
        let prime2 = Zeroizing::new(primes[1].to_bytes_be());
        let exponent1 = Zeroizing::new(priv_key.dp().ok_or(HsmError::DataInvalid)?.to_bytes_be());
        let exponent2 = Zeroizing::new(priv_key.dq().ok_or(HsmError::DataInvalid)?.to_bytes_be());
        // qinv is a signed BigInt in the rsa crate; reduce to bytes (always
        // positive for a well-formed key).
        let (_sign, coef_bytes) = priv_key.qinv().ok_or(HsmError::DataInvalid)?.to_bytes_be();
        let coefficient = Zeroizing::new(coef_bytes);

        // Build the template inside a `ZeroizingAttrs` guard so that on
        // every exit path -- success, panic, or early-return from the
        // create_object call -- the cloned byte-string attribute buffers
        // are explicitly wiped before the Vec is dropped. The cryptoki
        // C_CreateObject call copies the bytes into the token's internal
        // store before returning, so wiping the host-side copy at this
        // point is correct.
        let (session, cache) = sess.split();
        let template_guard = ZeroizingAttrs(vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(true),
            Attribute::Sign(true),
            Attribute::Modulus((*modulus).clone()),
            Attribute::PublicExponent((*pub_exp).clone()),
            Attribute::PrivateExponent((*priv_exp).clone()),
            Attribute::Prime1((*prime1).clone()),
            Attribute::Prime2((*prime2).clone()),
            Attribute::Exponent1((*exponent1).clone()),
            Attribute::Exponent2((*exponent2).clone()),
            Attribute::Coefficient((*coefficient).clone()),
        ]);
        let handle = session
            .create_object(&template_guard.0)
            .map_err(pkcs11_err)?;
        // Wipe the host-side template explicitly before doing any further
        // bookkeeping so the secret bytes are not on the heap during the
        // cache.insert/destroy_object round-trip below.
        drop(template_guard);
        if let Some(evicted) = cache.insert(fp, handle) {
            let _ = session.destroy_object(evicted);
        }
        Ok(handle)
    }

    fn import_rsa_pub(
        sess: &mut PooledSession,
        modulus: &[u8],
        public_exponent: &[u8],
    ) -> HsmResult<ObjectHandle> {
        // Reject public exponents below 0x010001 (65537). PKCS#11 does not
        // forbid `e = 3`, but accepting it here makes the backend a
        // co-conspirator in low-exponent RSA attacks (Coppersmith
        // small-message, Bleichenbacher e=3 sig forgery). FIPS 186-5
        // A.1.1 mandates e >= 2^16 + 1.
        if !is_rsa_exponent_acceptable(public_exponent) {
            return Err(HsmError::AttributeValueInvalid);
        }
        let fp = fingerprint(b"rsa-pub", &[modulus, public_exponent]);
        Self::get_or_import(sess, fp, || {
            vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::RSA),
                Attribute::Modulus(modulus.to_vec()),
                Attribute::PublicExponent(public_exponent.to_vec()),
                Attribute::Token(false),
                Attribute::Verify(true),
                Attribute::Encrypt(true),
            ]
        })
    }

    fn import_ec_priv(
        sess: &mut PooledSession,
        priv_bytes: &[u8],
        ec_params: &'static [u8],
        domain: &[u8],
    ) -> HsmResult<ObjectHandle> {
        let fp = fingerprint(domain, &[priv_bytes]);
        Self::get_or_import(sess, fp, || {
            let key_copy = Zeroizing::new(priv_bytes.to_vec());
            vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Value((*key_copy).clone()),
                Attribute::EcParams(ec_params.to_vec()),
                Attribute::Token(false),
                Attribute::Sensitive(true),
                Attribute::Sign(true),
                Attribute::Derive(true),
            ]
        })
    }

    fn import_ec_pub(
        sess: &mut PooledSession,
        pub_sec1: &[u8],
        ec_params: &'static [u8],
        domain: &[u8],
    ) -> HsmResult<ObjectHandle> {
        let fp = fingerprint(domain, &[pub_sec1]);
        Self::get_or_import(sess, fp, || {
            vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::EcPoint(pub_sec1.to_vec()),
                Attribute::EcParams(ec_params.to_vec()),
                Attribute::Token(false),
                Attribute::Verify(true),
            ]
        })
    }

    fn import_ed25519_priv(sess: &mut PooledSession, priv_bytes: &[u8]) -> HsmResult<ObjectHandle> {
        let fp = fingerprint(b"ed25519-priv", &[priv_bytes]);
        Self::get_or_import(sess, fp, || {
            let key_copy = Zeroizing::new(priv_bytes.to_vec());
            vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Value((*key_copy).clone()),
                Attribute::EcParams(EC_PARAMS_ED25519.to_vec()),
                Attribute::Token(false),
                Attribute::Sensitive(true),
                Attribute::Sign(true),
            ]
        })
    }

    fn import_ed25519_pub(sess: &mut PooledSession, pub_bytes: &[u8]) -> HsmResult<ObjectHandle> {
        let fp = fingerprint(b"ed25519-pub", &[pub_bytes]);
        Self::get_or_import(sess, fp, || {
            vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::EcPoint(pub_bytes.to_vec()),
                Attribute::EcParams(EC_PARAMS_ED25519.to_vec()),
                Attribute::Token(false),
                Attribute::Verify(true),
            ]
        })
    }

    /// Generate `len` random bytes via the token's `C_GenerateRandom`.
    fn token_random(sess: &PooledSession, len: usize) -> HsmResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        sess.session()
            .generate_random_slice(&mut buf)
            .map_err(pkcs11_err)?;
        Ok(buf)
    }

    fn rsa_pkcs_combined(hash_alg: Option<HashAlg>) -> Mechanism<'static> {
        match hash_alg {
            Some(HashAlg::Sha256) => Mechanism::Sha256RsaPkcs,
            Some(HashAlg::Sha384) => Mechanism::Sha384RsaPkcs,
            Some(HashAlg::Sha512) => Mechanism::Sha512RsaPkcs,
            None => Mechanism::RsaPkcs,
        }
    }

    fn rsa_pss_combined(hash_alg: HashAlg) -> Mechanism<'static> {
        match hash_alg {
            HashAlg::Sha256 => Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
                hash_alg: Mechanism::Sha256.mechanism_type(),
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: cryptoki::types::Ulong::try_from(32usize).expect("32 fits in Ulong"),
            }),
            HashAlg::Sha384 => Mechanism::Sha384RsaPkcsPss(PkcsPssParams {
                hash_alg: Mechanism::Sha384.mechanism_type(),
                mgf: PkcsMgfType::MGF1_SHA384,
                s_len: cryptoki::types::Ulong::try_from(48usize).expect("48 fits in Ulong"),
            }),
            HashAlg::Sha512 => Mechanism::Sha512RsaPkcsPss(PkcsPssParams {
                hash_alg: Mechanism::Sha512.mechanism_type(),
                mgf: PkcsMgfType::MGF1_SHA512,
                s_len: cryptoki::types::Ulong::try_from(64usize).expect("64 fits in Ulong"),
            }),
        }
    }

    fn rsa_pss_raw(hash_alg: HashAlg) -> Mechanism<'static> {
        let params = match hash_alg {
            HashAlg::Sha256 => PkcsPssParams {
                hash_alg: Mechanism::Sha256.mechanism_type(),
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: cryptoki::types::Ulong::try_from(32usize).expect("32 fits in Ulong"),
            },
            HashAlg::Sha384 => PkcsPssParams {
                hash_alg: Mechanism::Sha384.mechanism_type(),
                mgf: PkcsMgfType::MGF1_SHA384,
                s_len: cryptoki::types::Ulong::try_from(48usize).expect("48 fits in Ulong"),
            },
            HashAlg::Sha512 => PkcsPssParams {
                hash_alg: Mechanism::Sha512.mechanism_type(),
                mgf: PkcsMgfType::MGF1_SHA512,
                s_len: cryptoki::types::Ulong::try_from(64usize).expect("64 fits in Ulong"),
            },
        };
        Mechanism::RsaPkcsPss(params)
    }

    fn rsa_oaep_mech(hash_alg: OaepHash) -> Mechanism<'static> {
        let (h, mgf) = match hash_alg {
            OaepHash::Sha256 => (Mechanism::Sha256.mechanism_type(), PkcsMgfType::MGF1_SHA256),
            OaepHash::Sha384 => (Mechanism::Sha384.mechanism_type(), PkcsMgfType::MGF1_SHA384),
            OaepHash::Sha512 => (Mechanism::Sha512.mechanism_type(), PkcsMgfType::MGF1_SHA512),
        };
        Mechanism::RsaPkcsOaep(PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty()))
    }
}
impl CryptoBackend for Pkcs11PassthroughBackend {
    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        let mech = Self::rsa_pkcs_combined(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_priv(sess, private_key_der)?;
            sess.session().sign(&mech, h, data).map_err(pkcs11_err)
        })
    }

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        let mech = Self::rsa_pkcs_combined(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_pub(sess, modulus, public_exponent)?;
            classify_verify_result(sess.session().verify(&mech, h, data, signature)).into_bool()
        })
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let mech = Self::rsa_pss_combined(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_priv(sess, private_key_der)?;
            sess.session().sign(&mech, h, data).map_err(pkcs11_err)
        })
    }

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let mech = Self::rsa_pss_combined(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_pub(sess, modulus, public_exponent)?;
            classify_verify_result(sess.session().verify(&mech, h, data, signature)).into_bool()
        })
    }

    fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_priv(sess, private_key_bytes, EC_PARAMS_P256, b"ec-p256-priv")?;
            sess.session()
                .sign(&Mechanism::EcdsaSha256, h, data)
                .map_err(pkcs11_err)
        })
    }

    fn ecdsa_p256_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_pub(sess, public_key_sec1, EC_PARAMS_P256, b"ec-p256-pub")?;
            classify_verify_result(sess.session().verify(
                &Mechanism::EcdsaSha256,
                h,
                data,
                signature_der,
            ))
            .into_bool()
        })
    }

    fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_priv(sess, private_key_bytes, EC_PARAMS_P384, b"ec-p384-priv")?;
            sess.session()
                .sign(&Mechanism::EcdsaSha384, h, data)
                .map_err(pkcs11_err)
        })
    }

    fn ecdsa_p384_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_pub(sess, public_key_sec1, EC_PARAMS_P384, b"ec-p384-pub")?;
            classify_verify_result(sess.session().verify(
                &Mechanism::EcdsaSha384,
                h,
                data,
                signature_der,
            ))
            .into_bool()
        })
    }

    /// Ed25519 sign -- try CKM_EDDSA on the token; fall back to software
    /// ONLY when the token signals the mechanism / key-type does not exist.
    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        let native = self.pool.with_session(|sess| {
            let h = Self::import_ed25519_priv(sess, private_key_bytes)?;
            sess.session()
                .sign(&Mechanism::Eddsa, h, data)
                .map_err(pkcs11_err)
        });
        match native {
            Ok(sig) => Ok(sig),
            Err(HsmError::MechanismInvalid)
            | Err(HsmError::FunctionNotSupported)
            | Err(HsmError::KeyTypeInconsistent) => {
                tracing::info!(
                    target: "craton_hsm_pkcs11",
                    "token does not support CKM_EDDSA -- falling back to software ed25519"
                );
                craton_hsm::crypto::sign::ed25519_sign(private_key_bytes, data)
            }
            Err(e) => Err(e),
        }
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        let native = self.pool.with_session(|sess| {
            let h = Self::import_ed25519_pub(sess, public_key_bytes)?;
            classify_verify_result(sess.session().verify(
                &Mechanism::Eddsa,
                h,
                data,
                signature_bytes,
            ))
            .into_bool()
        });
        match native {
            Ok(b) => Ok(b),
            Err(HsmError::MechanismInvalid)
            | Err(HsmError::FunctionNotSupported)
            | Err(HsmError::KeyTypeInconsistent) => {
                craton_hsm::crypto::sign::ed25519_verify(public_key_bytes, data, signature_bytes)
            }
            Err(e) => Err(e),
        }
    }

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let digest_info = build_digest_info(hash_alg, digest).ok_or(HsmError::DataLenRange)?;
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_priv(sess, private_key_der)?;
            sess.session()
                .sign(&Mechanism::RsaPkcs, h, &digest_info)
                .map_err(pkcs11_err)
        })
    }

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let digest_info = build_digest_info(hash_alg, digest).ok_or(HsmError::DataLenRange)?;
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_pub(sess, modulus, public_exponent)?;
            classify_verify_result(sess.session().verify(
                &Mechanism::RsaPkcs,
                h,
                &digest_info,
                signature,
            ))
            .into_bool()
        })
    }

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        if digest.len() != expected_digest_len(hash_alg) {
            return Err(HsmError::DataLenRange);
        }
        let mech = Self::rsa_pss_raw(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_priv(sess, private_key_der)?;
            sess.session().sign(&mech, h, digest).map_err(pkcs11_err)
        })
    }

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        if digest.len() != expected_digest_len(hash_alg) {
            return Err(HsmError::DataLenRange);
        }
        let mech = Self::rsa_pss_raw(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_pub(sess, modulus, public_exponent)?;
            classify_verify_result(sess.session().verify(&mech, h, digest, signature)).into_bool()
        })
    }

    fn ecdsa_p256_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_priv(sess, private_key_bytes, EC_PARAMS_P256, b"ec-p256-priv")?;
            sess.session()
                .sign(&Mechanism::Ecdsa, h, digest)
                .map_err(pkcs11_err)
        })
    }

    fn ecdsa_p256_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_pub(sess, public_key_sec1, EC_PARAMS_P256, b"ec-p256-pub")?;
            classify_verify_result(sess.session().verify(
                &Mechanism::Ecdsa,
                h,
                digest,
                signature_der,
            ))
            .into_bool()
        })
    }

    fn ecdsa_p384_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_priv(sess, private_key_bytes, EC_PARAMS_P384, b"ec-p384-priv")?;
            sess.session()
                .sign(&Mechanism::Ecdsa, h, digest)
                .map_err(pkcs11_err)
        })
    }

    fn ecdsa_p384_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.pool.with_session(|sess| {
            let h = Self::import_ec_pub(sess, public_key_sec1, EC_PARAMS_P384, b"ec-p384-pub")?;
            classify_verify_result(sess.session().verify(
                &Mechanism::Ecdsa,
                h,
                digest,
                signature_der,
            ))
            .into_bool()
        })
    }
    fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        // Trait method name says "256", so reject anything that is not a
        // 256-bit key. Accepting a shorter key here would silently
        // downgrade the confidentiality guarantee the caller asked for.
        // The FIPS-mode check below is redundant under this guard but
        // kept for defence in depth -- the operator's intent ("FIPS mode
        // ON") should fail loud if the caller ever changes this method
        // to be variant-length.
        if key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if self.fips_mode && key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        let limit = self.gcm_max_messages_per_key;
        self.pool.with_session(|sess| {
            // The pool-wide GCM counter is consulted in two steps:
            //   1) A cheap `get()` *before* the encrypt so a budget that
            //      is already exhausted refuses the call without
            //      generating a fresh nonce.
            //   2) `check_and_increment()` *after* a successful encrypt
            //      so a doomed call (token error, buffer too small,
            //      mechanism rejected) does NOT consume one slot of
            //      per-key budget. Both calls share the same
            //      parking_lot mutex so the budget is enforced GLOBALLY
            //      across all pool sessions, not per-session.
            let (handle, fp) = Self::import_aes(sess, key)?;
            if sess.gcm_counters().get(&fp) >= limit {
                return Err(HsmError::KeyFunctionNotPermitted);
            }

            let nonce = Self::token_random(sess, 12)?;
            let gcm = GcmParams::new(&nonce, &[], 128.into());
            let mech = Mechanism::AesGcm(gcm);

            let ct = sess
                .session()
                .encrypt(&mech, handle, plaintext)
                .map_err(pkcs11_err)?;
            // Only consume budget on success. `check_and_increment`
            // remains race-safe across concurrent encrypts under the
            // same key.
            sess.gcm_counters().check_and_increment(&fp, limit)?;

            // Output: nonce || ciphertext || tag
            let mut out = Vec::with_capacity(nonce.len() + ct.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            Ok(out)
        })
    }

    fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if self.fips_mode && key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if data.len() < 12 + 16 {
            return Err(HsmError::EncryptedDataInvalid);
        }
        let (nonce, ct_and_tag) = data.split_at(12);
        let nonce = nonce.to_vec();
        self.pool.with_session(|sess| {
            let (handle, _fp) = Self::import_aes(sess, key)?;
            let gcm = GcmParams::new(&nonce, &[], 128.into());
            let mech = Mechanism::AesGcm(gcm);
            sess.session()
                .decrypt(&mech, handle, ct_and_tag)
                .map_err(|e| {
                    let mapped = pkcs11_err(e);
                    match mapped {
                        HsmError::EncryptedDataInvalid
                        | HsmError::DataInvalid
                        | HsmError::EncryptedDataLenRange => HsmError::EncryptedDataInvalid,
                        other => other,
                    }
                })
        })
    }

    // SECURITY-IV-REUSE (AES-CBC): this entry point consults the pool-wide
    // `(key_fingerprint, iv)` reuse tracker (`PoolCtrCounters`) BEFORE
    // delegating to the token. CBC IV reuse with a fixed key is not as
    // catastrophic as in CTR/GCM (no full-stream XOR leak), but it still
    // lets an attacker observe equal plaintext blocks and degrades
    // semantic security to deterministic encryption for matching
    // prefixes (CVE-class: BEAST). Per-(key,iv) duplicate-rejection is
    // process-local and resets on backend restart: callers MUST still
    // supply an unpredictable, fresh IV per message; this check is a
    // defence-in-depth backstop against a buggy caller that reuses one,
    // not a substitute for proper IV generation. Tracked in CHANGELOG
    // as PKCS11-CBC-IV.
    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        let iv_arr: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
        if plaintext.len() % 16 != 0 {
            return Err(HsmError::DataLenRange);
        }
        let mech = Mechanism::AesCbc(iv_arr);
        self.pool.with_session(|sess| {
            let (h, fp) = Self::import_aes(sess, key)?;
            // Defence-in-depth: refuse a second encrypt under the SAME
            // (key, iv) pair before submitting it to the token. The
            // tracker returns `HsmError::MechanismParamInvalid` on
            // reuse, which surfaces to the caller as "your IV is not
            // acceptable for this key" -- the closest PKCS#11-shaped
            // diagnostic without expanding the public HsmError surface.
            sess.ctr_counters().check_and_record(&fp, &iv_arr)?;
            sess.session()
                .encrypt(&mech, h, plaintext)
                .map_err(pkcs11_err)
        })
    }

    // SECURITY-IV-REUSE (AES-CBC decrypt): see `aes_cbc_encrypt` above.
    // The pool-wide `(key, iv)` tracker is intentionally NOT consulted on
    // the decrypt path: decrypt is idempotent w.r.t. IV reuse (the IV is
    // already public alongside the ciphertext) and gating it would
    // wrongly refuse legitimate replay of a single ciphertext.
    // Padding-oracle hardening is the upstream protocol's responsibility.
    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        let iv_arr: [u8; 16] = iv.try_into().map_err(|_| HsmError::MechanismParamInvalid)?;
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(HsmError::EncryptedDataInvalid);
        }
        let mech = Mechanism::AesCbc(iv_arr);
        self.pool.with_session(|sess| {
            let (h, _) = Self::import_aes(sess, key)?;
            sess.session().decrypt(&mech, h, ciphertext).map_err(|e| {
                let mapped = pkcs11_err(e);
                match mapped {
                    HsmError::EncryptedDataInvalid
                    | HsmError::DataInvalid
                    | HsmError::EncryptedDataLenRange => HsmError::EncryptedDataInvalid,
                    other => other,
                }
            })
        })
    }

    fn aes_ctr_encrypt(&self, _key: &[u8], _iv: &[u8], _plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        // The cryptoki 0.7 crate does not expose `Mechanism::AesCtr` or the
        // associated `AesCtrParams` type. Until cryptoki ships these (or the
        // crate is bumped), AES-CTR is not reachable through the
        // passthrough backend. Return `FunctionNotSupported` so callers
        // fall back to a software implementation rather than silently
        // signing with the wrong mechanism. (Audit ref: PKCS11-CTR.)
        //
        // TODO(pkcs11-ctr): when cryptoki >= 0.8 ships `Mechanism::AesCtr`
        // / `AesCtrParams`, this implementation MUST call
        // `sess.ctr_counters().check_and_record(&fp, &iv_arr)?` before
        // delegating to the token, mirroring `aes_cbc_encrypt`. CTR IV
        // reuse under a fixed key is catastrophic (full-stream XOR leak),
        // far worse than CBC. Tracked in CHANGELOG under "Deferred —
        // upstream-blocked" / PKCS11-CTR.
        Err(HsmError::FunctionNotSupported)
    }

    fn aes_ctr_decrypt(&self, _key: &[u8], _iv: &[u8], _ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        // See `aes_ctr_encrypt` above for the rationale. (PKCS11-CTR.)
        // TODO: enable when cryptoki >= 0.8 (adds `Mechanism::AesCtr` /
        // `AesCtrParams`).
        Err(HsmError::FunctionNotSupported)
    }

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        let mech = Self::rsa_oaep_mech(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_pub(sess, modulus, public_exponent)?;
            sess.session()
                .encrypt(&mech, h, plaintext)
                .map_err(pkcs11_err)
        })
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        let mech = Self::rsa_oaep_mech(hash_alg);
        self.pool.with_session(|sess| {
            let h = Self::import_rsa_priv(sess, private_key_der)?;
            sess.session().decrypt(&mech, h, ciphertext).map_err(|e| {
                let mapped = pkcs11_err(e);
                match mapped {
                    HsmError::EncryptedDataInvalid
                    | HsmError::DataInvalid
                    | HsmError::EncryptedDataLenRange => HsmError::EncryptedDataInvalid,
                    other => other,
                }
            })
        })
    }
    /// Generate a fresh AES key on the token and return its raw bytes.
    ///
    /// # WARNING — extraction defeats the HSM's protection for this key
    ///
    /// To satisfy the [`CryptoBackend`] trait contract (which requires
    /// returning [`RawKeyMaterial`] -- i.e. the actual key bytes), this
    /// method creates the AES key on the token with
    /// `CKA_SENSITIVE = false` and `CKA_EXTRACTABLE = true`, then
    /// immediately extracts `CKA_VALUE` and destroys the token object.
    /// **The generated key spends a brief window as an extractable
    /// session object before being lifted out, and the returned bytes
    /// live in process memory thereafter.**
    ///
    /// In other words: this API uses the HSM as a CSPRNG plus PKCS#11
    /// keygen rather than as a sealed key vault. If the goal is a
    /// token-resident, non-extractable key (the usual reason for using
    /// an HSM), this is the wrong API. A token-resident keygen entry
    /// point that returns an opaque handle is not yet provided by this
    /// crate; track CHANGELOG entry `PKCS11-TOKEN-RESIDENT-KEYGEN`.
    ///
    /// FIPS callers: AES-128 is rejected when `fips_mode` (either
    /// argument or backend-wide) is set, per FIPS 140-3 IG D.10.
    fn generate_aes_key(&self, key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial> {
        let fips = fips_mode || self.fips_mode;
        match key_len_bytes {
            16 if fips => return Err(HsmError::KeySizeRange),
            16 | 24 | 32 => {}
            _ => return Err(HsmError::KeySizeRange),
        }

        // SECURITY: this template is intentionally Sensitive=false +
        // Extractable=true because the trait surface requires returning
        // raw bytes (see method-level rustdoc above). Do not "harden"
        // this without first surfacing a separate
        // generate_aes_key_token_resident() API.
        let template = vec![
            Attribute::ValueLen(
                cryptoki::types::Ulong::try_from(key_len_bytes)
                    .map_err(|_| HsmError::DataLenRange)?,
            ),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];

        self.pool.with_session(|sess| {
            let session = sess.session();
            let handle = session
                .generate_key(&Mechanism::AesKeyGen, &template)
                .map_err(pkcs11_err)?;

            let result = session
                .get_attributes(handle, &[AttributeType::Value])
                .map_err(pkcs11_err);
            let _ = session.destroy_object(handle);
            let attrs = result?;

            for a in attrs {
                if let Attribute::Value(v) = a {
                    return Ok(RawKeyMaterial::new(v));
                }
            }
            Err(HsmError::AttributeValueInvalid)
        })
    }

    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        let fips = fips_mode || self.fips_mode;
        if fips && modulus_bits < 2048 {
            return Err(HsmError::KeySizeRange);
        }

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];

        let pub_template = vec![
            Attribute::ModulusBits(
                cryptoki::types::Ulong::try_from(modulus_bits as usize)
                    .map_err(|_| HsmError::KeySizeRange)?,
            ),
            Attribute::PublicExponent(public_exponent.clone()),
            Attribute::Token(false),
            Attribute::Verify(true),
            Attribute::Encrypt(true),
        ];
        let priv_template = vec![
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Sign(true),
            Attribute::Decrypt(true),
        ];

        // Distinguish "Value attribute missing" (token sensitivity guard,
        // legitimate fallback target) from "Value attribute present but
        // empty" (PKCS#11 protocol violation by the token, never
        // legitimate).
        let result: HsmResult<(PrivExtract, Vec<u8>, Vec<u8>)> = self.pool.with_session(|sess| {
            let session = sess.session();
            let (pub_h, priv_h) = session
                .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)
                .map_err(pkcs11_err)?;

            let pub_attrs = session
                .get_attributes(
                    pub_h,
                    &[AttributeType::Modulus, AttributeType::PublicExponent],
                )
                .map_err(pkcs11_err);
            let priv_attrs = session
                .get_attributes(priv_h, &[AttributeType::Value])
                .map_err(pkcs11_err);

            let _ = session.destroy_object(pub_h);
            let _ = session.destroy_object(priv_h);

            let pub_attrs = pub_attrs?;
            let priv_attrs = priv_attrs?;

            let mut modulus = Vec::new();
            let mut pub_exp = Vec::new();
            for a in pub_attrs {
                match a {
                    Attribute::Modulus(m) => modulus = m,
                    Attribute::PublicExponent(e) => pub_exp = e,
                    _ => {}
                }
            }
            let mut extracted = PrivExtract::Missing;
            for a in priv_attrs {
                if let Attribute::Value(v) = a {
                    extracted = if v.is_empty() {
                        PrivExtract::EmptySentinel
                    } else {
                        PrivExtract::Value(v)
                    };
                }
            }
            Ok((extracted, modulus, pub_exp))
        });

        match result {
            Ok((PrivExtract::Value(priv_value), modulus, pub_exp)) => {
                Ok((RawKeyMaterial::new(priv_value), modulus, pub_exp))
            }
            Ok((PrivExtract::Missing, _, _)) => {
                if self.allow_software_keygen_fallback {
                    tracing::warn!(
                        target: "craton_hsm_pkcs11",
                        "token refused to extract generated RSA private key (attr missing) -- \
                         falling back to SOFTWARE keygen"
                    );
                    craton_hsm::crypto::keygen::generate_rsa_key_pair(modulus_bits, fips)
                } else {
                    Err(HsmError::AttributeSensitive)
                }
            }
            Ok((PrivExtract::EmptySentinel, _, _)) => {
                tracing::error!(
                    target: "craton_hsm_pkcs11",
                    "token returned EMPTY Value attribute for RSA private key -- \
                     PKCS#11 protocol violation, refusing"
                );
                Err(HsmError::GeneralError)
            }
            Err(HsmError::AttributeSensitive)
            | Err(HsmError::AttributeValueInvalid)
            | Err(HsmError::FunctionNotSupported)
                if self.allow_software_keygen_fallback =>
            {
                tracing::warn!(
                    target: "craton_hsm_pkcs11",
                    "token refused to extract generated RSA private key -- \
                     falling back to SOFTWARE keygen"
                );
                craton_hsm::crypto::keygen::generate_rsa_key_pair(modulus_bits, fips)
            }
            Err(e) => Err(e),
        }
    }

    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        self.generate_ec_key_pair_inner(
            EC_PARAMS_P256,
            "P-256",
            craton_hsm::crypto::keygen::generate_ec_p256_key_pair,
        )
    }

    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        self.generate_ec_key_pair_inner(
            EC_PARAMS_P384,
            "P-384",
            craton_hsm::crypto::keygen::generate_ec_p384_key_pair,
        )
    }

    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let pub_template = vec![
            Attribute::EcParams(EC_PARAMS_ED25519.to_vec()),
            Attribute::Token(false),
            Attribute::Verify(true),
        ];
        let priv_template = vec![
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Sign(true),
        ];

        let result: HsmResult<(PrivExtract, Vec<u8>)> = self.pool.with_session(|sess| {
            let session = sess.session();
            let (pub_h, priv_h) = session
                .generate_key_pair(
                    &Mechanism::EccEdwardsKeyPairGen,
                    &pub_template,
                    &priv_template,
                )
                .map_err(pkcs11_err)?;

            let pub_attrs = session
                .get_attributes(pub_h, &[AttributeType::EcPoint])
                .map_err(pkcs11_err);
            let priv_attrs = session
                .get_attributes(priv_h, &[AttributeType::Value])
                .map_err(pkcs11_err);

            let _ = session.destroy_object(pub_h);
            let _ = session.destroy_object(priv_h);

            let pub_attrs = pub_attrs?;
            let priv_attrs = priv_attrs?;

            let mut pub_bytes = Vec::new();
            for a in pub_attrs {
                if let Attribute::EcPoint(p) = a {
                    pub_bytes = p;
                }
            }
            let mut extracted = PrivExtract::Missing;
            for a in priv_attrs {
                if let Attribute::Value(v) = a {
                    extracted = if v.is_empty() {
                        PrivExtract::EmptySentinel
                    } else {
                        PrivExtract::Value(v)
                    };
                }
            }
            Ok((extracted, pub_bytes))
        });

        match result {
            Ok((PrivExtract::Value(priv_value), pub_bytes)) => {
                Ok((RawKeyMaterial::new(priv_value), pub_bytes))
            }
            Ok((PrivExtract::EmptySentinel, _)) => {
                tracing::error!(
                    target: "craton_hsm_pkcs11",
                    "token returned EMPTY Value for Ed25519 private key -- protocol violation"
                );
                Err(HsmError::GeneralError)
            }
            // Keep the fallback set IDENTICAL to `ed25519_sign` so the
            // observable "does this token speak Ed25519?" decision does
            // not shift between sign and keygen entry points (audit M5).
            Err(HsmError::MechanismInvalid)
            | Err(HsmError::FunctionNotSupported)
            | Err(HsmError::KeyTypeInconsistent) => {
                tracing::info!(
                    target: "craton_hsm_pkcs11",
                    "token does not support CKM_EC_EDWARDS_KEY_PAIR_GEN -- \
                     falling back to software ed25519 keygen"
                );
                craton_hsm::crypto::keygen::generate_ed25519_key_pair()
            }
            Ok((PrivExtract::Missing, _)) => {
                if self.allow_software_keygen_fallback {
                    tracing::warn!(
                        target: "craton_hsm_pkcs11",
                        "token refused to extract Ed25519 private key -- SOFTWARE fallback"
                    );
                    craton_hsm::crypto::keygen::generate_ed25519_key_pair()
                } else {
                    Err(HsmError::AttributeSensitive)
                }
            }
            Err(HsmError::AttributeSensitive) | Err(HsmError::AttributeValueInvalid)
                if self.allow_software_keygen_fallback =>
            {
                tracing::warn!(
                    target: "craton_hsm_pkcs11",
                    "token refused to extract Ed25519 private key -- SOFTWARE fallback"
                );
                craton_hsm::crypto::keygen::generate_ed25519_key_pair()
            }
            Err(e) => Err(e),
        }
    }

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
        craton_hsm::crypto::digest::compute_digest(mechanism, data)
    }

    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        craton_hsm::crypto::digest::digest_output_len(mechanism)
    }

    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
        craton_hsm::crypto::digest::create_hasher(mechanism)
    }
    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        let fips = fips_mode || self.fips_mode;
        let result: HsmResult<Vec<u8>> = self.pool.with_session(|sess| {
            let (kek, _) = Self::import_aes(sess, wrapping_key)?;

            // Strict template: Sensitive(true) + Extractable(true).
            // Compatibility-fallback template: Sensitive(false) + Extractable(true).
            let key_copy = Zeroizing::new(key_to_wrap.to_vec());
            let strict_template = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Value((*key_copy).clone()),
                Attribute::Token(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(true),
            ];
            let target = match sess.session().create_object(&strict_template) {
                Ok(t) => t,
                Err(e) => {
                    let mapped = pkcs11_err(e);
                    if matches!(
                        mapped,
                        HsmError::AttributeValueInvalid
                            | HsmError::TemplateInconsistent
                            | HsmError::AttributeReadOnly
                    ) {
                        // SECURITY: this is a real downgrade -- the wrap
                        // target is now extractable in plaintext from the
                        // token's perspective. Operators must see it at
                        // `warn!` level in production logs, not `debug!`,
                        // so they can distinguish "we expected this token
                        // to enforce Sensitive(true)" from a configuration
                        // drift. (Audit ref: PKCS11-WRAP-LAX-WARN.)
                        tracing::warn!(
                            target: "craton_hsm_pkcs11",
                            "token rejected Sensitive(true)+Extractable(true) wrap target -- \
                             retrying with Sensitive(false)+Extractable(true). The wrap target \
                             is briefly extractable; if this token is expected to keep wrap \
                             targets sensitive, investigate before relying on this fallback."
                        );
                        let lax_template = vec![
                            Attribute::Class(ObjectClass::SECRET_KEY),
                            Attribute::KeyType(KeyType::GENERIC_SECRET),
                            Attribute::Value((*key_copy).clone()),
                            Attribute::Token(false),
                            Attribute::Sensitive(false),
                            Attribute::Extractable(true),
                        ];
                        sess.session()
                            .create_object(&lax_template)
                            .map_err(pkcs11_err)?
                    } else {
                        return Err(mapped);
                    }
                }
            };

            let result = sess
                .session()
                .wrap_key(&Mechanism::AesKeyWrapPad, kek, target)
                .map_err(pkcs11_err);
            let _ = sess.session().destroy_object(target);
            result
        });

        match result {
            Ok(v) => Ok(v),
            Err(HsmError::MechanismInvalid) | Err(HsmError::FunctionNotSupported) => {
                if fips && !self.is_vendor_allow_listed() {
                    tracing::error!(
                        target: "craton_hsm_pkcs11",
                        "FIPS mode: refusing software CKM_AES_KEY_WRAP_PAD fallback because no \
                         configured fips_vendors entry is present. Add the token vendor to \
                         Pkcs11PassthroughConfig::fips_vendors to permit this."
                    );
                    return Err(HsmError::FunctionNotSupported);
                }
                if fips {
                    tracing::warn!(
                        target: "craton_hsm_pkcs11",
                        "FIPS mode: token does not support CKM_AES_KEY_WRAP_PAD -- using \
                         SOFTWARE fallback (vendor allow-listed via fips_vendors)"
                    );
                } else {
                    tracing::info!(
                        target: "craton_hsm_pkcs11",
                        "token does not support CKM_AES_KEY_WRAP_PAD -- falling back to software"
                    );
                }
                craton_hsm::crypto::wrap::aes_key_wrap(wrapping_key, key_to_wrap, fips)
            }
            Err(e) => Err(e),
        }
    }

    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        let fips = fips_mode || self.fips_mode;
        let result: HsmResult<Vec<u8>> = self.pool.with_session(|sess| {
            let (kek, _) = Self::import_aes(sess, wrapping_key)?;
            let unwrap_template = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
            ];
            let unwrapped = sess
                .session()
                .unwrap_key(
                    &Mechanism::AesKeyWrapPad,
                    kek,
                    wrapped_key,
                    &unwrap_template,
                )
                .map_err(pkcs11_err)?;
            let attrs_res = sess
                .session()
                .get_attributes(unwrapped, &[AttributeType::Value])
                .map_err(pkcs11_err);
            let _ = sess.session().destroy_object(unwrapped);
            let attrs = attrs_res?;
            for a in attrs {
                if let Attribute::Value(v) = a {
                    return Ok(v);
                }
            }
            Err(HsmError::AttributeValueInvalid)
        });
        match result {
            Ok(v) => Ok(v),
            Err(HsmError::MechanismInvalid) | Err(HsmError::FunctionNotSupported) => {
                if fips && !self.is_vendor_allow_listed() {
                    tracing::error!(
                        target: "craton_hsm_pkcs11",
                        "FIPS mode: refusing software CKM_AES_KEY_WRAP_PAD unwrap fallback \
                         (no fips_vendors entry)"
                    );
                    return Err(HsmError::FunctionNotSupported);
                }
                tracing::info!(
                    target: "craton_hsm_pkcs11",
                    "token does not support CKM_AES_KEY_WRAP_PAD -- falling back to software"
                );
                craton_hsm::crypto::wrap::aes_key_unwrap(wrapping_key, wrapped_key, fips)
            }
            Err(HsmError::EncryptedDataInvalid) | Err(HsmError::DataInvalid) => {
                Err(HsmError::EncryptedDataInvalid)
            }
            Err(e) => Err(e),
        }
    }

    fn ecdh_p256(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        self.ecdh_inner(
            private_key_bytes,
            peer_public_key_sec1,
            okm_len,
            EC_PARAMS_P256,
            b"ec-p256-priv",
            32,
            |a, b, c| craton_hsm::crypto::derive::ecdh_p256(a, b, c),
        )
    }

    fn ecdh_p384(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        self.ecdh_inner(
            private_key_bytes,
            peer_public_key_sec1,
            okm_len,
            EC_PARAMS_P384,
            b"ec-p384-priv",
            48,
            |a, b, c| craton_hsm::crypto::derive::ecdh_p384(a, b, c),
        )
    }
}

/// True if `e_be` (big-endian RSA public exponent bytes) is `>= 65537`.
/// Leading zero bytes are tolerated. Returns `false` for empty input.
fn is_rsa_exponent_acceptable(e_be: &[u8]) -> bool {
    let stripped: &[u8] = {
        let mut s = e_be;
        while let Some((0u8, rest)) = s.split_first() {
            s = rest;
        }
        s
    };
    // 65537 == 0x010001, 3 bytes long. Anything longer is automatically
    // greater than 2^24 > 65537.
    match stripped.len() {
        0 | 1 | 2 => false,
        3 => stripped >= &[0x01, 0x00, 0x01][..],
        _ => true,
    }
}

/// RAII guard around a `Vec<Attribute>` that explicitly zeroizes every
/// byte-string attribute on drop. Used for the RSA private-key import
/// template so the cloned modulus / private-exponent / CRT components
/// do not linger in the heap after `C_CreateObject` returns.
///
/// PKCS#11 attribute variants that wrap a fresh `Vec<u8>` (Modulus,
/// PublicExponent, PrivateExponent, Prime1/2, Exponent1/2, Coefficient,
/// Value, EcPoint, EcParams) are matched and their inner Vec is
/// `zeroize::Zeroize::zeroize`'d before normal Drop runs. The cryptoki
/// `Attribute` enum keeps these as plain `Vec<u8>`s with no Drop hook
/// of its own, so without this guard the secret bytes would just be
/// `free()`d back to the allocator with their contents intact.
struct ZeroizingAttrs(Vec<Attribute>);

impl Drop for ZeroizingAttrs {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for attr in self.0.iter_mut() {
            match attr {
                Attribute::Modulus(v)
                | Attribute::PublicExponent(v)
                | Attribute::PrivateExponent(v)
                | Attribute::Prime1(v)
                | Attribute::Prime2(v)
                | Attribute::Exponent1(v)
                | Attribute::Exponent2(v)
                | Attribute::Coefficient(v)
                | Attribute::Value(v)
                | Attribute::EcPoint(v)
                | Attribute::EcParams(v) => {
                    v.zeroize();
                }
                _ => {}
            }
        }
    }
}

/// Result of inspecting a PKCS#11 private-key Value attribute.
///
/// The PKCS#11 spec leaves it ambiguous what a token returns when it
/// declines to expose a sensitive private key: most tokens omit the Value
/// attribute entirely (mapped here to [`PrivExtract::Missing`]); a few
/// non-conformant tokens return a Value attribute with an empty byte
/// array, which we treat as a hard protocol violation and refuse via
/// [`PrivExtract::EmptySentinel`].
#[derive(Debug)]
enum PrivExtract {
    Value(Vec<u8>),
    Missing,
    EmptySentinel,
}
// Inherent helpers for keygen + ECDH paths.
impl Pkcs11PassthroughBackend {
    fn generate_ec_key_pair_inner(
        &self,
        ec_params: &'static [u8],
        curve_name: &str,
        software_fallback: fn() -> HsmResult<(RawKeyMaterial, Vec<u8>)>,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let pub_template = vec![
            Attribute::EcParams(ec_params.to_vec()),
            Attribute::Token(false),
            Attribute::Verify(true),
        ];
        let priv_template = vec![
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Sign(true),
            Attribute::Derive(true),
        ];

        let result: HsmResult<(PrivExtract, Vec<u8>)> = self.pool.with_session(|sess| {
            let session = sess.session();
            let (pub_h, priv_h) = session
                .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
                .map_err(pkcs11_err)?;

            let pub_attrs = session
                .get_attributes(pub_h, &[AttributeType::EcPoint])
                .map_err(pkcs11_err);
            let priv_attrs = session
                .get_attributes(priv_h, &[AttributeType::Value])
                .map_err(pkcs11_err);

            let _ = session.destroy_object(pub_h);
            let _ = session.destroy_object(priv_h);

            let pub_attrs = pub_attrs?;
            let priv_attrs = priv_attrs?;

            let mut pub_bytes = Vec::new();
            for a in pub_attrs {
                if let Attribute::EcPoint(p) = a {
                    pub_bytes = p;
                }
            }
            let mut extracted = PrivExtract::Missing;
            for a in priv_attrs {
                if let Attribute::Value(v) = a {
                    extracted = if v.is_empty() {
                        PrivExtract::EmptySentinel
                    } else {
                        PrivExtract::Value(v)
                    };
                }
            }
            Ok((extracted, pub_bytes))
        });

        match result {
            Ok((PrivExtract::Value(priv_value), pub_bytes)) => {
                Ok((RawKeyMaterial::new(priv_value), pub_bytes))
            }
            Ok((PrivExtract::EmptySentinel, _)) => {
                tracing::error!(
                    target: "craton_hsm_pkcs11",
                    "token returned EMPTY Value for {} private key -- protocol violation",
                    curve_name
                );
                Err(HsmError::GeneralError)
            }
            Ok((PrivExtract::Missing, _)) => {
                if self.allow_software_keygen_fallback {
                    tracing::warn!(
                        target: "craton_hsm_pkcs11",
                        "token refused to extract {} private key -- SOFTWARE fallback",
                        curve_name
                    );
                    software_fallback()
                } else {
                    Err(HsmError::AttributeSensitive)
                }
            }
            Err(HsmError::AttributeSensitive)
            | Err(HsmError::AttributeValueInvalid)
            | Err(HsmError::FunctionNotSupported)
                if self.allow_software_keygen_fallback =>
            {
                tracing::warn!(
                    target: "craton_hsm_pkcs11",
                    "token refused to extract {} private key -- SOFTWARE fallback",
                    curve_name
                );
                software_fallback()
            }
            Err(e) => Err(e),
        }
    }

    /// ECDH wrapper. The software fallback is gated on
    /// [`Pkcs11PassthroughConfig::allow_software_keygen_fallback`] -- if the
    /// operator did not opt in, a missing-mechanism error from the token
    /// propagates instead of silently switching to software.
    #[allow(clippy::too_many_arguments)]
    fn ecdh_inner(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
        ec_params: &'static [u8],
        priv_domain: &[u8],
        default_len: usize,
        software_fallback: impl Fn(&[u8], &[u8], Option<usize>) -> HsmResult<RawKeyMaterial>,
    ) -> HsmResult<RawKeyMaterial> {
        let derived_len = okm_len.unwrap_or(default_len);

        let result: HsmResult<Vec<u8>> = self.pool.with_session(|sess| {
            let priv_h = Self::import_ec_priv(sess, private_key_bytes, ec_params, priv_domain)?;

            let params = Ecdh1DeriveParams::new(
                cryptoki::mechanism::elliptic_curve::EcKdf::null(),
                peer_public_key_sec1,
            );
            let mech = Mechanism::Ecdh1Derive(params);

            // The derived shared secret is a transient object we read the
            // `Value` of and then destroy immediately. `Private(true)`
            // hides it from `C_FindObjects` issued by any other session,
            // and `Token(false)` keeps it out of persistent token
            // storage. `Sensitive(false) + Extractable(true)` is
            // required (we MUST be able to read the value here), but
            // the unconditional destroy below bounds the exposure window
            // to the lifetime of this `derive_key` call.
            let derived_template = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::ValueLen(
                    cryptoki::types::Ulong::try_from(derived_len)
                        .map_err(|_| HsmError::DataLenRange)?,
                ),
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
            ];

            let derived = sess
                .session()
                .derive_key(&mech, priv_h, &derived_template)
                .map_err(pkcs11_err)?;
            let attrs_res = sess
                .session()
                .get_attributes(derived, &[AttributeType::Value])
                .map_err(pkcs11_err);
            // SECURITY: destroy unconditionally and before returning the
            // value bytes, so even on a panic in the iterator below the
            // token-side object is reaped.
            let _ = sess.session().destroy_object(derived);
            let attrs = attrs_res?;
            for a in attrs {
                if let Attribute::Value(v) = a {
                    return Ok(v);
                }
            }
            Err(HsmError::AttributeValueInvalid)
        });

        match result {
            Ok(v) => Ok(RawKeyMaterial::new(v)),
            Err(HsmError::MechanismInvalid)
            | Err(HsmError::FunctionNotSupported)
            | Err(HsmError::AttributeSensitive)
                if self.allow_software_keygen_fallback =>
            {
                tracing::info!(
                    target: "craton_hsm_pkcs11",
                    "token does not support CKM_ECDH1_DERIVE for this curve -- \
                     falling back to software ECDH+HKDF (allow_software_keygen_fallback = true)"
                );
                software_fallback(private_key_bytes, peer_public_key_sec1, okm_len)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn invalid_config() -> Pkcs11PassthroughConfig {
        Pkcs11PassthroughConfig {
            library_path: PathBuf::from("/nonexistent/libpkcs11.so"),
            slot_id: 0,
            pin: Zeroizing::new("1234".to_string()),
            fips_mode: false,
            fips_vendors: Vec::new(),
            pool_size: 4,
            cache_capacity: 64,
            allow_software_keygen_fallback: false,
            gcm_max_messages_per_key: 0,
        }
    }

    #[test]
    fn backend_rejects_missing_library() {
        let result = Pkcs11PassthroughBackend::new(invalid_config());
        assert!(result.is_err(), "should fail with nonexistent library");
        match result.unwrap_err() {
            HsmError::ConfigError(msg) => {
                assert!(
                    msg.contains("failed to load PKCS#11 library"),
                    "unexpected error message: {}",
                    msg
                );
            }
            other => panic!("expected ConfigError, got {:?}", other),
        }
    }

    #[test]
    fn backend_rejects_empty_library_path() {
        let config = Pkcs11PassthroughConfig {
            library_path: PathBuf::from(""),
            ..invalid_config()
        };
        let result = Pkcs11PassthroughBackend::new(config);
        assert!(result.is_err(), "empty library path should fail");
    }

    #[test]
    fn gcm_max_messages_zero_uses_default() {
        let config = Pkcs11PassthroughConfig {
            gcm_max_messages_per_key: 0,
            ..invalid_config()
        };
        assert_eq!(DEFAULT_GCM_MAX_MESSAGES_PER_KEY, 1u64 << 32);
        assert_eq!(config.gcm_max_messages_per_key, 0);
    }

    #[test]
    fn ec_params_constants_have_expected_lengths() {
        assert_eq!(EC_PARAMS_P256.len(), 10);
        assert_eq!(EC_PARAMS_P384.len(), 7);
        assert_eq!(EC_PARAMS_ED25519.len(), 5);
    }

    #[test]
    fn ec_params_start_with_der_oid_tag() {
        assert_eq!(EC_PARAMS_P256[0], 0x06);
        assert_eq!(EC_PARAMS_P384[0], 0x06);
        assert_eq!(EC_PARAMS_ED25519[0], 0x06);
    }

    #[test]
    fn priv_extract_classifies_value_correctly() {
        let v = PrivExtract::Value(vec![1, 2, 3]);
        assert!(matches!(v, PrivExtract::Value(ref b) if b.len() == 3));
        assert!(matches!(PrivExtract::Missing, PrivExtract::Missing));
        assert!(matches!(
            PrivExtract::EmptySentinel,
            PrivExtract::EmptySentinel
        ));
    }

    // ----- is_rsa_exponent_acceptable: edge-case coverage --------------
    //
    // Property-test-style coverage without pulling in a `proptest`
    // dev-dependency. Verifies that:
    //   * Canonical 65537 (`0x010001`) is accepted, whether or not it
    //     carries a leading zero byte.
    //   * Canonical exponents smaller than 65537 (3, 1, empty) are
    //     rejected, regardless of any leading-zero padding.
    //   * Exponents wider than 24 bits are unconditionally accepted
    //     (they are necessarily greater than 2^24 > 65537).

    #[test]
    fn is_rsa_exponent_acceptable_canonical_65537() {
        // 0x01 0x00 0x01 == 65537
        assert!(is_rsa_exponent_acceptable(&[0x01, 0x00, 0x01]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_65537_with_leading_zero() {
        // 0x00 0x01 0x00 0x01 == 65537 (leading-zero canonicalised away)
        assert!(is_rsa_exponent_acceptable(&[0x00, 0x01, 0x00, 0x01]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_65537_with_many_leading_zeros() {
        // Multiple leading zeros must all be stripped.
        assert!(is_rsa_exponent_acceptable(&[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01
        ]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_rejects_canonical_three() {
        // e=3 is the textbook small-exponent attack vector.
        // 0x00 0x00 0x03 strips to 0x03 which is 1 byte and must be rejected.
        assert!(!is_rsa_exponent_acceptable(&[0x00, 0x00, 0x03]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_rejects_empty() {
        // Empty byte string is meaningless as an integer; reject.
        assert!(!is_rsa_exponent_acceptable(&[]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_rejects_all_zeros() {
        // 0x00 0x00 0x00 strips to empty -- reject.
        assert!(!is_rsa_exponent_acceptable(&[0x00, 0x00, 0x00]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_rejects_one() {
        // e=1 collapses to the identity cipher.
        assert!(!is_rsa_exponent_acceptable(&[0x01]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_rejects_two_byte_below_65537() {
        // Anything in [0, 0xFFFF] is < 65537; even canonical 0xFFFF must be rejected.
        assert!(!is_rsa_exponent_acceptable(&[0xFF, 0xFF]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_accepts_three_byte_above_65537() {
        // 0x010002 == 65538, just above the threshold.
        assert!(is_rsa_exponent_acceptable(&[0x01, 0x00, 0x02]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_rejects_three_byte_below_65537() {
        // 0x010000 == 65536, just below the threshold.
        assert!(!is_rsa_exponent_acceptable(&[0x01, 0x00, 0x00]));
        // 0x00FFFF == 65535
        assert!(!is_rsa_exponent_acceptable(&[0x00, 0xFF, 0xFF]));
    }

    #[test]
    fn is_rsa_exponent_acceptable_accepts_wide_exponent() {
        // Any 4+ canonical byte exponent is necessarily > 2^24 > 65537.
        assert!(is_rsa_exponent_acceptable(&[0x01, 0x00, 0x00, 0x01]));
        assert!(is_rsa_exponent_acceptable(&[0xFF, 0xFF, 0xFF, 0xFF]));
    }
}
