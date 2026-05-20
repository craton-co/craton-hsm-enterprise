// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Approved-mode enforcement wrapper for any [`CryptoBackend`].
//!
//! [`ApprovedModeBackend`] adapts an inner backend so that every
//! cryptographic operation is first gated through
//! [`check_mechanism_approved`] against an [`ApprovedModeConfig`] shared
//! via `Arc`. If the mechanism is not approved under the current FIPS
//! posture, the wrapper returns [`HsmError::MechanismInvalid`] **before**
//! the inner backend ever sees the call.
//!
//! This is the missing dispatch-boundary enforcement that audit finding M3
//! flagged: [`check_mechanism_approved`] existed as a free function but
//! no backend invoked it on its own operations. The wrapper provides a
//! turn-key opt-in for callers that want belt-and-braces enforcement
//! without modifying their underlying backend.
//!
//! ## Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use craton_hsm_certified::approved_mode::default_fips_config;
//! use craton_hsm_certified::approved_mode_wrapper::ApprovedModeBackend;
//!
//! let cfg = Arc::new(default_fips_config());
//! let inner = MyBackend::new();
//! let backend = ApprovedModeBackend::new(inner, cfg);
//! // Every call to `backend` is now gated by `cfg`.
//! ```
//!
//! ## Coverage
//!
//! The wrapper gates every mechanism modelled by
//! [`crate::approved_mode::Mechanism`]: RSA-PKCS1v15 / RSA-PSS sign and
//! verify (including prehashed variants), ECDSA P-256/P-384 sign and
//! verify (including prehashed variants), Ed25519, AES-256-GCM, AES-CBC,
//! AES-CTR, AES key wrap, RSA-OAEP, RSA / EC / Ed25519 key generation,
//! and digest computation.
//!
//! Mechanisms that are not modelled by the classifier (PQC variants,
//! ECDH key agreement, raw HKDF) fall through to the inner backend
//! unchanged. Operators who want stricter coverage should compose this
//! wrapper with their own outer gate.

use std::sync::Arc;

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::digest::DigestAccumulator;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::{HsmError, HsmResult};
use craton_hsm::pkcs11_abi::constants::{CKM_SHA256, CKM_SHA384, CKM_SHA512};
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use craton_hsm::store::key_material::RawKeyMaterial;

use crate::approved_mode::{check_mechanism_approved, ApprovedModeConfig};

/// Wrapper that enforces an [`ApprovedModeConfig`] on every operation of
/// an inner [`CryptoBackend`].
///
/// Construct with [`ApprovedModeBackend::new`]; thereafter the wrapper is
/// itself a [`CryptoBackend`] and can be passed wherever the inner one
/// would have been. Rejections surface as [`HsmError::MechanismInvalid`]
/// — the same error variant a downstream backend would return for any
/// other unsupported mechanism — so existing error-handling code does not
/// need to change.
///
/// `B: Send + Sync` is implied by [`CryptoBackend`].
pub struct ApprovedModeBackend<B: CryptoBackend> {
    inner: B,
    config: Arc<ApprovedModeConfig>,
}

impl<B: CryptoBackend> ApprovedModeBackend<B> {
    /// Wrap `inner` with the approved-mode policy in `config`.
    ///
    /// The `Arc` is held by the wrapper for the lifetime of the
    /// backend; callers can share the same `Arc` across replicas to
    /// avoid duplicating the configuration.
    pub fn new(inner: B, config: Arc<ApprovedModeConfig>) -> Self {
        Self { inner, config }
    }

    /// Borrow the inner backend without giving up the wrapper.
    ///
    /// Intended for inspection / read-only diagnostics; callers who
    /// reach for this to bypass the policy gate are defeating the point
    /// of the wrapper.
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Borrow the active configuration.
    pub fn config(&self) -> &ApprovedModeConfig {
        &self.config
    }

    /// Internal gate: check `mechanism` against the active policy and
    /// translate a rejection into [`HsmError::MechanismInvalid`].
    #[inline]
    fn gate(&self, mechanism: &str) -> HsmResult<()> {
        check_mechanism_approved(mechanism, &self.config).map_err(|_| HsmError::MechanismInvalid)
    }

    /// Map a PKCS#11 digest mechanism constant to the string name the
    /// classifier understands.
    fn digest_mech_name(mech: CK_MECHANISM_TYPE) -> Option<&'static str> {
        match mech {
            CKM_SHA256 => Some("SHA-256"),
            CKM_SHA384 => Some("SHA-384"),
            CKM_SHA512 => Some("SHA-512"),
            _ => None,
        }
    }
}

impl<B: CryptoBackend> CryptoBackend for ApprovedModeBackend<B> {
    // ========================================================================
    // Signing — classical
    // ========================================================================

    fn rsa_pkcs1v15_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        // We cannot infer modulus bits from the DER without parsing, so
        // gate by the minimum RSA size: if RSA-2048 (the minimum the
        // policy allows) is rejected, no RSA can be approved.
        self.gate("RSA-2048")?;
        self.inner
            .rsa_pkcs1v15_sign(private_key_der, data, hash_alg)
    }

    fn rsa_pkcs1v15_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        self.gate("RSA-2048")?;
        self.inner
            .rsa_pkcs1v15_verify(modulus, public_exponent, data, signature, hash_alg)
    }

    fn rsa_pss_sign(
        &self,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        self.gate("RSA-2048")?;
        self.inner.rsa_pss_sign(private_key_der, data, hash_alg)
    }

    fn rsa_pss_verify(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        self.gate("RSA-2048")?;
        self.inner
            .rsa_pss_verify(modulus, public_exponent, data, signature, hash_alg)
    }

    fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        self.gate("ECDSA-P256")?;
        self.inner.ecdsa_p256_sign(private_key_bytes, data)
    }

    fn ecdsa_p256_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.gate("ECDSA-P256")?;
        self.inner
            .ecdsa_p256_verify(public_key_sec1, data, signature_der)
    }

    fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        self.gate("ECDSA-P384")?;
        self.inner.ecdsa_p384_sign(private_key_bytes, data)
    }

    fn ecdsa_p384_verify(
        &self,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.gate("ECDSA-P384")?;
        self.inner
            .ecdsa_p384_verify(public_key_sec1, data, signature_der)
    }

    fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        self.gate("Ed25519")?;
        self.inner.ed25519_sign(private_key_bytes, data)
    }

    fn ed25519_verify(
        &self,
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        self.gate("Ed25519")?;
        self.inner
            .ed25519_verify(public_key_bytes, data, signature_bytes)
    }

    // ========================================================================
    // Signing — prehashed (the policy flag `allow_prehashed_signing` is
    // checked via the `-PREHASHED` suffix).
    // ========================================================================

    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        self.gate("RSA-2048-PREHASHED")?;
        self.inner
            .rsa_pkcs1v15_sign_prehashed(private_key_der, digest, hash_alg)
    }

    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        self.gate("RSA-2048-PREHASHED")?;
        self.inner.rsa_pkcs1v15_verify_prehashed(
            modulus,
            public_exponent,
            digest,
            signature,
            hash_alg,
        )
    }

    fn rsa_pss_sign_prehashed(
        &self,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        self.gate("RSA-2048-PREHASHED")?;
        self.inner
            .rsa_pss_sign_prehashed(private_key_der, digest, hash_alg)
    }

    fn rsa_pss_verify_prehashed(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        self.gate("RSA-2048-PREHASHED")?;
        self.inner
            .rsa_pss_verify_prehashed(modulus, public_exponent, digest, signature, hash_alg)
    }

    fn ecdsa_p256_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.gate("ECDSA-P256-PREHASHED")?;
        self.inner
            .ecdsa_p256_sign_prehashed(private_key_bytes, digest)
    }

    fn ecdsa_p256_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.gate("ECDSA-P256-PREHASHED")?;
        self.inner
            .ecdsa_p256_verify_prehashed(public_key_sec1, digest, signature_der)
    }

    fn ecdsa_p384_sign_prehashed(
        &self,
        private_key_bytes: &[u8],
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.gate("ECDSA-P384-PREHASHED")?;
        self.inner
            .ecdsa_p384_sign_prehashed(private_key_bytes, digest)
    }

    fn ecdsa_p384_verify_prehashed(
        &self,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
    ) -> HsmResult<bool> {
        self.gate("ECDSA-P384-PREHASHED")?;
        self.inner
            .ecdsa_p384_verify_prehashed(public_key_sec1, digest, signature_der)
    }

    // ========================================================================
    // Encryption
    // ========================================================================

    fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        self.gate("AES-256")?;
        self.inner.aes_256_gcm_encrypt(key, plaintext)
    }

    fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        self.gate("AES-256")?;
        self.inner.aes_256_gcm_decrypt(key, data)
    }

    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        // Use the key length to choose the appropriate mechanism string.
        let mech = match key.len() {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner.aes_cbc_encrypt(key, iv, plaintext)
    }

    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        let mech = match key.len() {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner.aes_cbc_decrypt(key, iv, ciphertext)
    }

    fn aes_ctr_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        let mech = match key.len() {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner.aes_ctr_encrypt(key, iv, plaintext)
    }

    fn aes_ctr_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        let mech = match key.len() {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner.aes_ctr_decrypt(key, iv, ciphertext)
    }

    fn rsa_oaep_encrypt(
        &self,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        self.gate("RSA-2048")?;
        self.inner
            .rsa_oaep_encrypt(modulus, public_exponent, plaintext, hash_alg)
    }

    fn rsa_oaep_decrypt(
        &self,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        self.gate("RSA-2048")?;
        self.inner
            .rsa_oaep_decrypt(private_key_der, ciphertext, hash_alg)
    }

    // ========================================================================
    // Key generation
    // ========================================================================

    fn generate_aes_key(&self, key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial> {
        let mech = match key_len_bytes {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner.generate_aes_key(key_len_bytes, fips_mode)
    }

    fn generate_rsa_key_pair(
        &self,
        modulus_bits: u32,
        fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        // We know the exact bit length at keygen time, so use it.
        let mech = format!("RSA-{modulus_bits}");
        self.gate(&mech)?;
        self.inner.generate_rsa_key_pair(modulus_bits, fips_mode)
    }

    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        self.gate("ECDSA-P256")?;
        self.inner.generate_ec_p256_key_pair()
    }

    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        self.gate("ECDSA-P384")?;
        self.inner.generate_ec_p384_key_pair()
    }

    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        self.gate("Ed25519")?;
        self.inner.generate_ed25519_key_pair()
    }

    // ========================================================================
    // Digest
    // ========================================================================

    fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
        if let Some(name) = Self::digest_mech_name(mechanism) {
            self.gate(name)?;
        }
        // Unknown digest mechanisms fall through to the inner backend,
        // which is responsible for rejecting anything it does not
        // support.
        self.inner.compute_digest(mechanism, data)
    }

    fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        // Length lookup is metadata, not a crypto op — pass through
        // without gating so callers can still query the output length
        // of a mechanism the policy does not permit.
        self.inner.digest_output_len(mechanism)
    }

    fn create_hasher(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<Box<dyn DigestAccumulator>> {
        if let Some(name) = Self::digest_mech_name(mechanism) {
            self.gate(name)?;
        }
        self.inner.create_hasher(mechanism)
    }

    // ========================================================================
    // Key wrap / unwrap
    // ========================================================================

    fn aes_key_wrap(
        &self,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        let mech = match wrapping_key.len() {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner
            .aes_key_wrap(wrapping_key, key_to_wrap, fips_mode)
    }

    fn aes_key_unwrap(
        &self,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
        fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        let mech = match wrapping_key.len() {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => return Err(HsmError::MechanismInvalid),
        };
        self.gate(mech)?;
        self.inner
            .aes_key_unwrap(wrapping_key, wrapped_key, fips_mode)
    }

    // ========================================================================
    // Key derivation — ECDH is not modelled by the classifier, so we
    // forward without gating. Operators wanting to forbid ECDH should
    // wrap an outer enforcement layer.
    // ========================================================================

    fn ecdh_p256(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        self.gate("ECDSA-P256")?;
        self.inner
            .ecdh_p256(private_key_bytes, peer_public_key_sec1, okm_len)
    }

    fn ecdh_p384(
        &self,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        self.gate("ECDSA-P384")?;
        self.inner
            .ecdh_p384(private_key_bytes, peer_public_key_sec1, okm_len)
    }

    // PQC mechanisms (ML-KEM / ML-DSA / SLH-DSA / hybrid) are not yet
    // modelled by `ApprovedModeConfig`. They inherit the default trait
    // implementations from `CryptoBackend`, which forwards to the
    // reference `pqc` functions — so the wrapper does not need to
    // override them. That intentional omission is documented in the
    // module rustdoc above.
}

#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::crypto::awslc_backend::AwsLcBackend;
    use std::sync::Arc;

    use crate::approved_mode::default_fips_config;

    #[test]
    fn wrapper_rejects_unapproved_mechanism() {
        // Ed25519 is not approved under the default FIPS config.
        let cfg = Arc::new(default_fips_config());
        let backend = ApprovedModeBackend::new(AwsLcBackend, cfg);

        let err = backend
            .generate_ed25519_key_pair()
            .expect_err("Ed25519 keygen must be rejected under default FIPS config");
        assert!(
            matches!(err, HsmError::MechanismInvalid),
            "expected MechanismInvalid, got {err:?}"
        );
    }

    #[test]
    fn wrapper_rejects_aes_128_under_strict_config() {
        let cfg = Arc::new(default_fips_config());
        let backend = ApprovedModeBackend::new(AwsLcBackend, cfg);

        // AES-128 (16-byte key) is excluded from the strict profile.
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let err = backend
            .aes_cbc_encrypt(&key, &iv, b"hello")
            .expect_err("AES-128 must be rejected under default FIPS config");
        assert!(matches!(err, HsmError::MechanismInvalid));
    }

    #[test]
    fn wrapper_permits_approved_mechanism() {
        // ECDSA-P256 keygen passes the gate, even if the resulting keygen
        // succeeds or fails inside the inner backend.
        let cfg = Arc::new(default_fips_config());
        let backend = ApprovedModeBackend::new(AwsLcBackend, cfg);
        let _ = backend
            .generate_ec_p256_key_pair()
            .expect("ECDSA-P256 keygen passes the gate and the backend succeeds");
    }

    #[test]
    fn wrapper_permits_aes_256_encrypt_decrypt() {
        let cfg = Arc::new(default_fips_config());
        let backend = ApprovedModeBackend::new(AwsLcBackend, cfg);
        let key = [0x42u8; 32];
        let pt = b"approved-mode-wrapper roundtrip";
        let ct = backend
            .aes_256_gcm_encrypt(&key, pt)
            .expect("AES-256-GCM encrypt passes the gate");
        let recovered = backend
            .aes_256_gcm_decrypt(&key, &ct)
            .expect("AES-256-GCM decrypt passes the gate");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrapper_rejects_sub_2048_rsa_keygen() {
        // RSA-1024 falls below the policy minimum.
        let cfg = Arc::new(default_fips_config());
        let backend = ApprovedModeBackend::new(AwsLcBackend, cfg);
        let err = backend
            .generate_rsa_key_pair(1024, true)
            .expect_err("RSA-1024 must be rejected under default FIPS config");
        assert!(matches!(err, HsmError::MechanismInvalid));
    }

    #[test]
    fn config_accessor_returns_active_policy() {
        let cfg = Arc::new(default_fips_config());
        let backend = ApprovedModeBackend::new(AwsLcBackend, Arc::clone(&cfg));
        // The wrapper exposes the same numeric minimum the caller set.
        assert_eq!(backend.config().min_rsa_key_bits, cfg.min_rsa_key_bits);
    }
}
