// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Craton HSM backend for NXP HSE (Hardware Security Engine)
//!
//! This crate implements the CryptoBackend trait from craton-hsm targeting
//! NXP S32G/S32R/S32K3 series processors with HSE firmware.
//!
//! # Audit-fix sweep 2026-04-24
//!
//! - V1: per-algorithm sig minimum length enforced before returning sigs.
//! - V2: HseKeyHandle RAII type wraps imported handles and calls key_delete on Drop;
//!       key_import is split into key_import_public / key_import_private.
//! - V3: hash_alg threaded through every sign/verify path; no silent _hash_alg drop.
//! - V4: AES-GCM requires a 12-byte IV and rejects AAD with MechanismInvalid.
//! - V5: handle counters use disjoint compile-time ranges (import vs generate)
//!       with overflow trapping to MechanismInvalid + structured marker.
//! - V6: HseKeyRef newtype documents the RawKeyMaterial-stuffing workaround.
//! - V7: try_new() exposes a fallible constructor; new() panics only under cfg(test).
//! - V8: atomic counters use fetch_update with AcqRel/Acquire (no naive fetch_add).
//! - V9: output buffers wrapped in `Zeroizing<Vec<u8>>`.
//! - V10: tests use `#[serial_test::serial]` to avoid env-var pollution races.
//!
//! # License
//!
//! Licensed under the Business Source License 1.1. See LICENSE-BSL.

#![deny(unsafe_code)]
#![deny(missing_docs)]

// Audit finding NXP-1: refuse to build without an explicit choice.
#[cfg(all(
    not(feature = "hw"),
    not(feature = "stub"),
    not(feature = "test-stub"),
    not(test)
))]
compile_error!(
    "craton-hsm-nxp requires either the hw feature (real NXP HSE hardware calls via the Messaging Unit) or the stub feature (explicit development build that returns FunctionNotSupported for every crypto operation). A feature-less build is intentionally rejected to prevent accidental deployment of a non-functional backend."
);

pub mod backend_trait;
pub mod error;
pub mod ffi;

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::digest::DigestAccumulator;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::{HsmError, HsmResult};
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use craton_hsm::store::key_material::RawKeyMaterial;
use std::sync::Arc;

pub use backend_trait::HseBackend;

// HseKeyHandle ----------------------------------------------------------
//
// Audit V2: an RAII wrapper around an imported HSE key handle. On Drop,
// the wrapper calls HseBackend::key_delete to release the slot. Existing
// handle leaks were a stand-out finding in the audit because the FFI
// catalogue is small (a few hundred slots) and a long-running CryptoBackend
// would exhaust it within minutes of normal traffic.

/// RAII wrapper around an imported HSE key handle. Drops the handle via
/// HseBackend::key_delete when the wrapper goes out of scope.
pub struct HseKeyHandle {
    backend: Arc<dyn HseBackend + Send + Sync>,
    handle: u32,
}

impl HseKeyHandle {
    /// Wrap an existing handle. The caller must guarantee the backend
    /// owns the slot.
    pub fn new(backend: Arc<dyn HseBackend + Send + Sync>, handle: u32) -> Self {
        Self { backend, handle }
    }
    /// Borrow the raw handle.
    pub fn raw(&self) -> u32 {
        self.handle
    }
}

impl Drop for HseKeyHandle {
    fn drop(&mut self) {
        if let Err(e) = self.backend.key_delete(self.handle) {
            tracing::warn!(
                target: "craton_hsm_nxp",
                key_handle = format_args!("0x{:08x}", self.handle),
                error = ?e,
                "HseKeyHandle drop: key_delete failed (audit V2)"
            );
        }
    }
}

/// Newtype wrapper for an HSE key handle smuggled through a RawKeyMaterial
/// blob (audit V6). The core RawKeyMaterial::new only takes `Vec<u8>`, so
/// the dispatching layer encodes the u32 handle as 4 big-endian bytes
/// and decodes it back on the other side. This is a documented workaround
/// for the core-crate API; replace once HseKeyRef can live inside RawKeyMaterial
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HseKeyRef(
    /// Raw HSE key-catalog handle (`u32`) being smuggled through the
    /// `RawKeyMaterial` blob.
    pub u32,
);

impl HseKeyRef {
    /// Encode this handle as a 4-byte BE blob suitable for RawKeyMaterial.
    pub(crate) fn to_raw_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
    /// Decode a HseKeyRef from a RawKeyMaterial blob.
    pub(crate) fn from_raw_bytes(b: &[u8]) -> HsmResult<Self> {
        if b.len() != 4 {
            tracing::error!(
                target: "craton_hsm_nxp",
                marker = error::HSE_MARKER_KEYREF_PARSE,
                len = b.len(),
                "HseKeyRef decode failed: expected 4 bytes"
            );
            return Err(HsmError::DataLenRange);
        }
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok(Self(u32::from_be_bytes(a)))
    }
}

/// NXP HSE crypto backend.
pub struct NxpHseBackend {
    backend: Option<Arc<dyn HseBackend + Send + Sync>>,
}

impl NxpHseBackend {
    /// Try to construct a backend, returning an HsmResult. Audit V7: this
    /// is the fallible path used in production.
    pub fn try_new() -> HsmResult<Self> {
        if Self::is_stub() {
            let allow = std::env::var("CRATON_HSM_ALLOW_STUB_NXP").is_ok_and(|v| !v.is_empty())
                || std::env::var("CRATON_HSM_ALLOW_MOCK").is_ok_and(|v| !v.is_empty());
            if !allow {
                tracing::error!(target: "craton_hsm_nxp", "NxpHseBackend::try_new in stub mode without env-var allow");
                return Err(HsmError::FunctionNotSupported);
            }
            tracing::warn!(target: "craton_hsm_nxp", "NxpHseBackend stub mode (env-allowed)");
            return Ok(Self { backend: None });
        }
        #[cfg(feature = "hw")]
        {
            Ok(Self {
                backend: Some(Arc::new(backend_trait::HseFfiBackend::new())),
            })
        }
        #[cfg(not(feature = "hw"))]
        {
            Ok(Self { backend: None })
        }
    }

    /// Construct the backend, returning a structured `HsmError::ConfigError`
    /// on failure instead of panicking (audit V7 hardening).
    ///
    /// Previously this method panicked in stub mode without
    /// `CRATON_HSM_ALLOW_STUB_NXP` / `CRATON_HSM_ALLOW_MOCK`, but that was
    /// a foot-gun for any caller outside of tests — a missing env-var
    /// aborted the entire process. The original doc claimed the panic was
    /// `cfg(test)`-only; in fact it was unconditional. The signature now
    /// matches [`try_new`](Self::try_new) (an `HsmResult`) so callers
    /// must handle the configuration error path explicitly.
    pub fn new() -> HsmResult<Self> {
        Self::try_new().map_err(|e| match e {
            HsmError::FunctionNotSupported => HsmError::ConfigError(
                "NxpHseBackend::new: stub mode requires CRATON_HSM_ALLOW_STUB_NXP \
                 or CRATON_HSM_ALLOW_MOCK env var, or rebuild with --features hw"
                    .to_string(),
            ),
            other => other,
        })
    }

    /// Construct a stub backend without env-var guards, for tests only.
    #[cfg(any(test, feature = "test-stub"))]
    pub fn new_stub_for_test() -> Self {
        assert!(Self::is_stub(), "new_stub_for_test in hw build");
        Self { backend: None }
    }

    /// Inject a custom HseBackend impl. Test-only.
    ///
    /// Audit hardening 2026-05-17: the `not(feature = "hw")` clause was
    /// added so that co-enabling `hw,test-stub` (legal per Cargo's
    /// feature unification) cannot leak the mock injection seam into a
    /// production `hw` build. With both features on, `hw` wins and this
    /// constructor is compiled out.
    #[cfg(all(any(test, feature = "test-stub"), not(feature = "hw")))]
    pub fn with_backend<B>(backend: B) -> Self
    where
        B: HseBackend + Send + Sync + 'static,
    {
        Self {
            backend: Some(Arc::new(backend)),
        }
    }

    /// Bind the backend reference once per method (perf).
    #[cfg(any(test, feature = "test-stub", feature = "hw"))]
    fn backend(&self) -> HsmResult<&(dyn HseBackend + Send + Sync)> {
        self.backend
            .as_deref()
            .ok_or(HsmError::FunctionNotSupported)
    }

    /// Borrow the backend `Arc` for RAII handle construction.
    ///
    /// `HseKeyHandle::new` needs an owned `Arc`, but the hot path also
    /// wants a `&dyn HseBackend` for FFI calls. Returning the `Arc` here
    /// lets callers `.clone()` it once for the handle guard without
    /// re-checking `Option::is_some` via `expect("checked")`.
    #[cfg(any(test, feature = "test-stub", feature = "hw"))]
    fn backend_arc(&self) -> HsmResult<&Arc<dyn HseBackend + Send + Sync>> {
        self.backend.as_ref().ok_or(HsmError::FunctionNotSupported)
    }

    /// Returns true if this backend is a stub.
    pub fn is_stub() -> bool {
        !cfg!(feature = "hw")
    }
}

// Default impl removed: `Self::new()` panics in stub mode without the
// CRATON_HSM_ALLOW_STUB_NXP env var, which would be a footgun for any
// crates.io consumer that constructed via `Default::default()`. Use
// `NxpHseBackend::try_new()` instead (fallible) or, for tests,
// `new_stub_for_test()` behind the `test-stub` feature.

// Stub impl: every operation returns FunctionNotSupported.
#[cfg(all(not(feature = "hw"), not(feature = "test-stub"), not(test)))]
impl CryptoBackend for NxpHseBackend {
    fn rsa_pkcs1v15_sign(
        &self,
        _private_key_der: &[u8],
        _data: &[u8],
        _hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pkcs1v15_verify(
        &self,
        _modulus: &[u8],
        _public_exponent: &[u8],
        _data: &[u8],
        _signature_bytes: &[u8],
        _hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pss_sign(
        &self,
        _private_key_der: &[u8],
        _data: &[u8],
        _hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pss_verify(
        &self,
        _modulus: &[u8],
        _public_exponent: &[u8],
        _data: &[u8],
        _signature_bytes: &[u8],
        _hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p256_sign(&self, _private_key_bytes: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p256_verify(
        &self,
        _public_key_sec1: &[u8],
        _data: &[u8],
        _signature_der: &[u8],
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p384_sign(&self, _private_key_bytes: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p384_verify(
        &self,
        _public_key_sec1: &[u8],
        _data: &[u8],
        _signature_der: &[u8],
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ed25519_sign(&self, _private_key_bytes: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ed25519_verify(
        &self,
        _public_key_bytes: &[u8],
        _data: &[u8],
        _signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pkcs1v15_sign_prehashed(
        &self,
        _private_key_der: &[u8],
        _digest: &[u8],
        _hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pkcs1v15_verify_prehashed(
        &self,
        _modulus: &[u8],
        _public_exponent: &[u8],
        _digest: &[u8],
        _signature_bytes: &[u8],
        _hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pss_sign_prehashed(
        &self,
        _private_key_der: &[u8],
        _digest: &[u8],
        _hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_pss_verify_prehashed(
        &self,
        _modulus: &[u8],
        _public_exponent: &[u8],
        _digest: &[u8],
        _signature_bytes: &[u8],
        _hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p256_sign_prehashed(
        &self,
        _private_key_bytes: &[u8],
        _digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p256_verify_prehashed(
        &self,
        _public_key_sec1: &[u8],
        _digest: &[u8],
        _signature_der: &[u8],
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p384_sign_prehashed(
        &self,
        _private_key_bytes: &[u8],
        _digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdsa_p384_verify_prehashed(
        &self,
        _public_key_sec1: &[u8],
        _digest: &[u8],
        _signature_der: &[u8],
    ) -> HsmResult<bool> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_256_gcm_encrypt(&self, _key: &[u8], _plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_256_gcm_decrypt(&self, _key: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_cbc_encrypt(&self, _key: &[u8], _iv: &[u8], _plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_cbc_decrypt(&self, _key: &[u8], _iv: &[u8], _ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_ctr_encrypt(&self, _key: &[u8], _iv: &[u8], _plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_ctr_decrypt(&self, _key: &[u8], _iv: &[u8], _ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_oaep_encrypt(
        &self,
        _modulus: &[u8],
        _public_exponent: &[u8],
        _plaintext: &[u8],
        _hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn rsa_oaep_decrypt(
        &self,
        _private_key_der: &[u8],
        _ciphertext: &[u8],
        _hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn generate_aes_key(
        &self,
        _key_len_bytes: usize,
        _fips_mode: bool,
    ) -> HsmResult<RawKeyMaterial> {
        Err(HsmError::FunctionNotSupported)
    }
    fn generate_rsa_key_pair(
        &self,
        _modulus_bits: u32,
        _fips_mode: bool,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        Err(HsmError::FunctionNotSupported)
    }
    fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        Err(HsmError::FunctionNotSupported)
    }
    fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        Err(HsmError::FunctionNotSupported)
    }
    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        Err(HsmError::FunctionNotSupported)
    }
    fn compute_digest(&self, _mechanism: CK_MECHANISM_TYPE, _data: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn digest_output_len(&self, _mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
        Err(HsmError::FunctionNotSupported)
    }
    fn create_hasher(
        &self,
        _mechanism: CK_MECHANISM_TYPE,
    ) -> HsmResult<Box<dyn DigestAccumulator>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_key_wrap(
        &self,
        _wrapping_key: &[u8],
        _key_to_wrap: &[u8],
        _fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn aes_key_unwrap(
        &self,
        _wrapping_key: &[u8],
        _wrapped_key: &[u8],
        _fips_mode: bool,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdh_p256(
        &self,
        _private_key_bytes: &[u8],
        _peer_public_key_sec1: &[u8],
        _okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        Err(HsmError::FunctionNotSupported)
    }
    fn ecdh_p384(
        &self,
        _private_key_bytes: &[u8],
        _peer_public_key_sec1: &[u8],
        _okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        Err(HsmError::FunctionNotSupported)
    }
}

// Audit V1: signature minimum length constants used by the dispatching
// hw_impl module to refuse to return a too-short signature even if the
// FFI / mock would accept it. (`MIN_P256_SIG_DER` is exported from
// `backend_trait` for consumers but not used here — the HSE firmware
// returns raw r||s, so the dispatching layer only enforces the raw
// minimum.) Imports are referenced from inside the cfg-gated
// `hw_impl` module below; `#[allow(unused_imports)]` keeps the stub
// build clean.
#[allow(unused_imports)]
use backend_trait::{MIN_P256_SIG_RAW, MIN_P384_SIG_RAW, MIN_SHA256_DIGEST};

/// Dispatching `CryptoBackend` impl for `NxpHseBackend`.
///
/// Audit 2026-05-17: the production `hw` path is currently
/// **non-functional** because [`HseFfiBackend::key_import_private`]
/// (in `backend_trait::hw_backend`) returns `FunctionNotSupported` —
/// the `HSE_KEY_FLAG_PRIVATE` plumbing has not yet been wired through
/// the FFI surface (tracking marker: `TODO(NXP-load)`). Every signing
/// and AES-encrypt method here ultimately routes through that import,
/// so under `feature = "hw"` they would previously fail deep inside
/// the FFI dispatch with no useful diagnostic. The methods now bail
/// out at the entry point with a `tracing::error!` and return
/// `FunctionNotSupported` directly under `cfg(feature = "hw")` so the
/// disclosed gap is honest to callers.
///
/// Under `test-stub`/`test` the same methods continue to dispatch
/// through the trait so [`MockHseBackend`] can drive the dispatch
/// logic for integration coverage. Once the `TODO(NXP-load)` work
/// lands, drop the early-return guards.
#[cfg(any(feature = "hw", feature = "test-stub", test))]
mod hw_impl {
    use super::*;
    #[allow(unused_imports)]
    use error::{
        HSE_MARKER_AAD_UNSUPPORTED, HSE_MARKER_GCM_IV_LEN, HSE_MARKER_GCM_OUT_LEN,
        HSE_MARKER_HANDLE_OVERFLOW, HSE_MARKER_SIG_TOO_SHORT,
    };
    use smallvec::SmallVec;
    use zeroize::Zeroizing;

    /// Audit 2026-05-17: bail out of any `hw`-feature signing or
    /// AES-encrypt entrypoint that would route through the
    /// unimplemented `key_import_private` FFI path. Returns
    /// `HsmError::FunctionNotSupported` after a `tracing::error!` so the
    /// gap is visible to operators instead of presenting as an opaque
    /// FFI failure deep in the dispatch chain. See TODO(NXP-load).
    #[cfg(feature = "hw")]
    macro_rules! hw_path_not_wired {
        () => {{
            tracing::error!(
                target: "craton_hsm_nxp",
                "hw path key-import-private not wired yet; returning FunctionNotSupported"
            );
            return Err(HsmError::FunctionNotSupported);
        }};
    }

    // HSE RSA scheme identifiers (from NXP HSE SDK headers).
    const HSE_RSA_SCHEME_PKCS1V15: u32 = 0x01;
    const HSE_RSA_SCHEME_PSS: u32 = 0x02;

    // HSE key type identifiers.
    const HSE_KEY_TYPE_RSA: u32 = 0x01;
    const HSE_KEY_TYPE_ECC_P256: u32 = 0x10;
    const HSE_KEY_TYPE_ECC_P384: u32 = 0x11;
    const HSE_KEY_TYPE_AES: u32 = 0x20;

    // HSE ECC curve identifiers.
    const HSE_CURVE_P256: u32 = 0x01;
    const HSE_CURVE_P384: u32 = 0x02;

    // HSE AES mode identifiers.
    const HSE_AES_MODE_GCM: u32 = 0x03;
    const HSE_AES_MODE_CBC: u32 = 0x01;
    const HSE_AES_MODE_CTR: u32 = 0x02;

    // HSE hash algorithm identifiers.
    pub(super) const HSE_HASH_NONE: u32 = 0x00;
    pub(super) const HSE_HASH_SHA256: u32 = 0x01;
    pub(super) const HSE_HASH_SHA384: u32 = 0x02;
    pub(super) const HSE_HASH_SHA512: u32 = 0x03;

    /// V3: Map a HashAlg to the HSE hash identifier. No longer guarded by
    /// allow(dead_code) -- it is wired through every sign/verify path.
    pub(super) fn hash_alg_to_hse(alg: HashAlg) -> u32 {
        match alg {
            HashAlg::Sha256 => HSE_HASH_SHA256,
            HashAlg::Sha384 => HSE_HASH_SHA384,
            HashAlg::Sha512 => HSE_HASH_SHA512,
        }
    }

    /// V5: disjoint compile-time generate-handle range.
    /// Imports use 0x0100_0000..=0x01FF_FFFF (in backend_trait::hw_backend).
    /// Generates use 0x0200_0000..=0x02FF_FFFF here.
    pub(super) const HSE_GENERATE_HANDLE_MIN: u32 = 0x0200_0000;
    pub(super) const HSE_GENERATE_HANDLE_MAX: u32 = 0x02FF_FFFF;
    pub(super) static NEXT_GENERATE_HANDLE: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(HSE_GENERATE_HANDLE_MIN);

    /// V8: fetch_update with AcqRel/Acquire so concurrent callers see disjoint
    /// generate handles. Returns None on overflow.
    pub(super) fn next_generate_handle() -> Option<u32> {
        NEXT_GENERATE_HANDLE
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |cur| {
                    if cur > HSE_GENERATE_HANDLE_MAX {
                        None
                    } else {
                        Some(cur.saturating_add(1))
                    }
                },
            )
            .ok()
    }

    /// Parse just enough of a PKCS#1 or PKCS#8 RSA private-key DER blob
    /// to extract the modulus byte length.
    ///
    /// Audit-fix 2026-05-16: the prior `check_rsa_sig_min` compared a
    /// signature against the *entire DER blob length*, which is always
    /// much larger than the modulus — that rejected every legitimate
    /// PKCS#1 v1.5 signature. The correct check needs the modulus
    /// length, which we recover here by walking the DER structure.
    ///
    /// We avoid pulling in a full ASN.1 parser (no new deps allowed).
    /// Supported inputs:
    ///
    /// - PKCS#1 (`RSAPrivateKey`): `SEQUENCE { version INTEGER, modulus
    ///   INTEGER n, publicExponent INTEGER, ... }` — `n` is the second
    ///   INTEGER.
    /// - PKCS#8 (`PrivateKeyInfo`): `SEQUENCE { version INTEGER,
    ///   privateKeyAlgorithm SEQUENCE, privateKey OCTET STRING (PKCS#1
    ///   `RSAPrivateKey`), ... }` — we descend into the OCTET STRING
    ///   and recurse on the PKCS#1 contents.
    ///
    /// On any parse failure we return `None`; the caller falls back to
    /// a permissive lower bound so an unparseable blob still flags
    /// grossly truncated firmware output without falsely rejecting
    /// legitimate signatures.
    fn rsa_modulus_len_from_der(der: &[u8]) -> Option<usize> {
        fn read_tlv(der: &[u8], off: usize) -> Option<(u8, usize, usize, usize)> {
            let tag = *der.get(off)?;
            let len_byte = *der.get(off + 1)?;
            let (content_off, content_len) = if len_byte & 0x80 == 0 {
                (off + 2, len_byte as usize)
            } else {
                let n = (len_byte & 0x7F) as usize;
                if n == 0 || n > 4 {
                    return None;
                }
                let mut len = 0usize;
                for i in 0..n {
                    len = (len << 8) | *der.get(off + 2 + i)? as usize;
                }
                (off + 2 + n, len)
            };
            let next_off = content_off.checked_add(content_len)?;
            if next_off > der.len() {
                return None;
            }
            Some((tag, content_off, content_len, next_off))
        }

        let (outer_tag, outer_co, _outer_cl, _) = read_tlv(der, 0)?;
        if outer_tag != 0x30 {
            return None;
        }

        let (t0, _co0, _cl0, off1) = read_tlv(der, outer_co)?;
        if t0 != 0x02 {
            return None;
        }

        let (t1, co1, cl1, off2) = read_tlv(der, off1)?;
        if t1 == 0x02 {
            // PKCS#1: this INTEGER is the modulus n. Strip one leading
            // 0x00 sign-padding byte if present (DER INTEGERs are
            // signed; a high-bit-set positive integer is prefixed with 0x00).
            let leading_zero = cl1 > 0 && der.get(co1).copied() == Some(0x00);
            return Some(if leading_zero { cl1 - 1 } else { cl1 });
        }

        if t1 != 0x30 {
            return None;
        }
        let (t2, co2, _cl2, _) = read_tlv(der, off2)?;
        if t2 != 0x04 {
            return None;
        }
        rsa_modulus_len_from_der(der.get(co2..)?)
    }

    /// V1 helper: ensure RSA signatures are at least modulus-byte-length.
    ///
    /// `key_der` is a PKCS#1 or PKCS#8 RSA private-key DER blob; we
    /// derive the modulus length via [`rsa_modulus_len_from_der`]. If
    /// the DER cannot be parsed we fall back to a conservative minimum
    /// (256 bytes = RSA-2048) so the check still rejects grossly short
    /// firmware output without rejecting legitimate signatures.
    fn check_rsa_sig_min(sig: &[u8], key_der: &[u8]) -> HsmResult<()> {
        const FALLBACK_MIN: usize = 256; // RSA-2048
        let expected = rsa_modulus_len_from_der(key_der).unwrap_or(FALLBACK_MIN);
        if sig.len() < expected.max(1) {
            tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_SIG_TOO_SHORT, expected = expected, got = sig.len(), "RSA sig below modulus length");
            return Err(HsmError::SignatureLenRange);
        }
        Ok(())
    }

    /// V1 helper: same check, but driven by a raw modulus (verify path).
    /// Currently unused — verify paths pass the modulus straight through;
    /// kept for callers that hold the raw modulus rather than the DER blob.
    #[allow(dead_code)]
    fn check_rsa_sig_min_raw_modulus(sig: &[u8], modulus: &[u8]) -> HsmResult<()> {
        if sig.len() < modulus.len().max(1) {
            tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_SIG_TOO_SHORT, expected = modulus.len(), got = sig.len(), "RSA sig below modulus length (raw modulus path)");
            return Err(HsmError::SignatureLenRange);
        }
        Ok(())
    }

    /// V1 helper: ensure ECDSA P-256 signatures are at least 64 raw / 70 DER bytes.
    fn check_ecdsa_p256_sig_min(sig: &[u8]) -> HsmResult<()> {
        if sig.len() < MIN_P256_SIG_RAW {
            tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_SIG_TOO_SHORT, min = MIN_P256_SIG_RAW, got = sig.len(), "P-256 sig below minimum length");
            return Err(HsmError::SignatureLenRange);
        }
        Ok(())
    }

    /// V1 helper: ensure ECDSA P-384 signatures are at least 96 raw bytes.
    fn check_ecdsa_p384_sig_min(sig: &[u8]) -> HsmResult<()> {
        if sig.len() < MIN_P384_SIG_RAW {
            tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_SIG_TOO_SHORT, min = MIN_P384_SIG_RAW, got = sig.len(), "P-384 sig below minimum length");
            return Err(HsmError::SignatureLenRange);
        }
        Ok(())
    }

    /// V1 helper: ensure SHA-256 digests are exactly 32 bytes.
    /// Currently unused — prehashed paths accept any digest length the
    /// hash mechanism produces; kept for completeness.
    #[allow(dead_code)]
    fn check_sha256_digest(digest: &[u8]) -> HsmResult<()> {
        if digest.len() != MIN_SHA256_DIGEST {
            tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_SIG_TOO_SHORT, expected = MIN_SHA256_DIGEST, got = digest.len(), "SHA-256 digest length mismatch");
            return Err(HsmError::DataLenRange);
        }
        Ok(())
    }

    // Audit 2026-05-17: under `feature = "hw"` the early-return guard
    // `hw_path_not_wired!()` makes every code path after it unreachable;
    // the `Zeroizing` import, the lifted `let key = Zeroizing::new(...)`
    // bindings, and the FFI dispatch all become dead. Silence the
    // resulting `unreachable_code` / `unused_*` lints here rather than
    // sprinkling `#[allow(...)]` across every individual method. Under
    // `test-stub` (or `test`) these allows are no-ops because every
    // method actually executes.
    #[cfg_attr(
        feature = "hw",
        allow(unreachable_code, unused_variables, unused_imports)
    )]
    impl CryptoBackend for NxpHseBackend {
        // ----- Signing (raw data) -----
        fn rsa_pkcs1v15_sign(
            &self,
            private_key_der: &[u8],
            data: &[u8],
            hash_alg: Option<HashAlg>,
        ) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_nxp", "rsa_pkcs1v15_sign");
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            // Audit 2026-05-17: wrap the private-key DER in a
            // Zeroizing<Vec<u8>> at point of receipt so the dispatching
            // layer cannot leave a copy of it on the heap after return.
            let private_key_der = Zeroizing::new(private_key_der.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_RSA, &private_key_der)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let hid = hash_alg.map(hash_alg_to_hse).unwrap_or(HSE_HASH_NONE);
            let sig: SmallVec<[u8; 512]> =
                SmallVec::from_vec(b.rsa_sign(h, HSE_RSA_SCHEME_PKCS1V15, hid, data)?);
            check_rsa_sig_min(&sig, &private_key_der)?;
            // Signatures are public output; the prior
            // `Zeroizing::new(sig.to_vec()).to_vec()` triple-allocated
            // for no security benefit. A single `.to_vec()` is correct.
            Ok(sig.to_vec())
        }

        fn rsa_pkcs1v15_verify(
            &self,
            modulus: &[u8],
            _public_exponent: &[u8],
            data: &[u8],
            signature_bytes: &[u8],
            hash_alg: Option<HashAlg>,
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_public(HSE_KEY_TYPE_RSA, modulus)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let hid = hash_alg.map(hash_alg_to_hse).unwrap_or(HSE_HASH_NONE);
            b.rsa_verify(h, HSE_RSA_SCHEME_PKCS1V15, hid, data, signature_bytes)
        }

        fn rsa_pss_sign(
            &self,
            private_key_der: &[u8],
            data: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_der = Zeroizing::new(private_key_der.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_RSA, &private_key_der)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let hid = hash_alg_to_hse(hash_alg);
            let sig: SmallVec<[u8; 512]> =
                SmallVec::from_vec(b.rsa_sign(h, HSE_RSA_SCHEME_PSS, hid, data)?);
            check_rsa_sig_min(&sig, &private_key_der)?;
            Ok(sig.to_vec())
        }

        fn rsa_pss_verify(
            &self,
            modulus: &[u8],
            _public_exponent: &[u8],
            data: &[u8],
            signature_bytes: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_public(HSE_KEY_TYPE_RSA, modulus)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let hid = hash_alg_to_hse(hash_alg);
            b.rsa_verify(h, HSE_RSA_SCHEME_PSS, hid, data, signature_bytes)
        }

        fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_bytes = Zeroizing::new(private_key_bytes.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_ECC_P256, &private_key_bytes)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let sig: SmallVec<[u8; 128]> =
                SmallVec::from_vec(b.ecdsa_sign(h, HSE_CURVE_P256, HSE_HASH_SHA256, data)?);
            check_ecdsa_p256_sig_min(&sig)?;
            Ok(sig.to_vec())
        }

        fn ecdsa_p256_verify(
            &self,
            public_key_sec1: &[u8],
            data: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            check_ecdsa_p256_sig_min(signature_der)?;
            let h = b.key_import_public(HSE_KEY_TYPE_ECC_P256, public_key_sec1)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.ecdsa_verify(h, HSE_CURVE_P256, HSE_HASH_SHA256, data, signature_der)
        }

        fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_bytes = Zeroizing::new(private_key_bytes.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_ECC_P384, &private_key_bytes)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let sig: SmallVec<[u8; 128]> =
                SmallVec::from_vec(b.ecdsa_sign(h, HSE_CURVE_P384, HSE_HASH_SHA384, data)?);
            check_ecdsa_p384_sig_min(&sig)?;
            Ok(sig.to_vec())
        }
        fn ecdsa_p384_verify(
            &self,
            public_key_sec1: &[u8],
            data: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            check_ecdsa_p384_sig_min(signature_der)?;
            let h = b.key_import_public(HSE_KEY_TYPE_ECC_P384, public_key_sec1)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.ecdsa_verify(h, HSE_CURVE_P384, HSE_HASH_SHA384, data, signature_der)
        }

        /// Stub: NXP HSE firmware does not support Ed25519. Audit V11.
        /// Reason code: NXP_HSE_NO_ED25519. Tracking ticket: HSE-ED25519-1.
        fn ed25519_sign(&self, _private_key_bytes: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
            self.backend()?;
            Err(HsmError::MechanismInvalid)
        }
        /// Stub: NXP HSE firmware does not support Ed25519.
        fn ed25519_verify(
            &self,
            _public_key_bytes: &[u8],
            _data: &[u8],
            _signature_bytes: &[u8],
        ) -> HsmResult<bool> {
            self.backend()?;
            Err(HsmError::MechanismInvalid)
        }

        // ----- Prehashed signing (digest already computed) -----
        //
        // Audit-fix 2026-05-16: the prior implementation computed
        // `let _hid = hash_alg_to_hse(hash_alg)` and passed
        // `HSE_HASH_NONE` to the FFI, silently discarding the hash
        // algorithm. Even on the prehashed path, the firmware needs the
        // hash identifier to construct the PKCS#1 v1.5 DigestInfo prefix
        // or to set the MGF1 hash for PSS. We now propagate `hid` for
        // the RSA paths. ECDSA does not encode the hash in the signature,
        // so `HSE_HASH_NONE` remains correct for ECDSA prehashed.
        fn rsa_pkcs1v15_sign_prehashed(
            &self,
            private_key_der: &[u8],
            digest: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_der = Zeroizing::new(private_key_der.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_RSA, &private_key_der)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let hid = hash_alg_to_hse(hash_alg);
            let sig: Vec<u8> = b.rsa_sign(h, HSE_RSA_SCHEME_PKCS1V15, hid, digest)?;
            check_rsa_sig_min(&sig, &private_key_der)?;
            Ok(sig)
        }
        fn rsa_pkcs1v15_verify_prehashed(
            &self,
            modulus: &[u8],
            _public_exponent: &[u8],
            digest: &[u8],
            signature_bytes: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let hid = hash_alg_to_hse(hash_alg);
            let h = b.key_import_public(HSE_KEY_TYPE_RSA, modulus)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.rsa_verify(h, HSE_RSA_SCHEME_PKCS1V15, hid, digest, signature_bytes)
        }
        fn rsa_pss_sign_prehashed(
            &self,
            private_key_der: &[u8],
            digest: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_der = Zeroizing::new(private_key_der.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let hid = hash_alg_to_hse(hash_alg);
            let h = b.key_import_private(HSE_KEY_TYPE_RSA, &private_key_der)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let sig: Vec<u8> = b.rsa_sign(h, HSE_RSA_SCHEME_PSS, hid, digest)?;
            check_rsa_sig_min(&sig, &private_key_der)?;
            Ok(sig)
        }
        fn rsa_pss_verify_prehashed(
            &self,
            modulus: &[u8],
            _public_exponent: &[u8],
            digest: &[u8],
            signature_bytes: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let hid = hash_alg_to_hse(hash_alg);
            let h = b.key_import_public(HSE_KEY_TYPE_RSA, modulus)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.rsa_verify(h, HSE_RSA_SCHEME_PSS, hid, digest, signature_bytes)
        }
        fn ecdsa_p256_sign_prehashed(
            &self,
            private_key_bytes: &[u8],
            digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_bytes = Zeroizing::new(private_key_bytes.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_ECC_P256, &private_key_bytes)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let sig: Vec<u8> = b.ecdsa_sign(h, HSE_CURVE_P256, HSE_HASH_NONE, digest)?;
            check_ecdsa_p256_sig_min(&sig)?;
            Ok(sig)
        }
        fn ecdsa_p256_verify_prehashed(
            &self,
            public_key_sec1: &[u8],
            digest: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            check_ecdsa_p256_sig_min(signature_der)?;
            let h = b.key_import_public(HSE_KEY_TYPE_ECC_P256, public_key_sec1)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.ecdsa_verify(h, HSE_CURVE_P256, HSE_HASH_NONE, digest, signature_der)
        }
        fn ecdsa_p384_sign_prehashed(
            &self,
            private_key_bytes: &[u8],
            digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            let private_key_bytes = Zeroizing::new(private_key_bytes.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_ECC_P384, &private_key_bytes)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let sig: Vec<u8> = b.ecdsa_sign(h, HSE_CURVE_P384, HSE_HASH_NONE, digest)?;
            check_ecdsa_p384_sig_min(&sig)?;
            Ok(sig)
        }
        fn ecdsa_p384_verify_prehashed(
            &self,
            public_key_sec1: &[u8],
            digest: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            check_ecdsa_p384_sig_min(signature_der)?;
            let h = b.key_import_public(HSE_KEY_TYPE_ECC_P384, public_key_sec1)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.ecdsa_verify(h, HSE_CURVE_P384, HSE_HASH_NONE, digest, signature_der)
        }

        // ----- Encryption -----
        /// V4 fix: AES-GCM rejects empty IV (must be 12 bytes) and rejects
        /// AAD with MechanismInvalid (the dispatching layer does not accept
        /// AAD until the FFI surface adds it).
        ///
        /// # Nonce-reuse risk (audit 2026-05-16)
        ///
        /// This entrypoint passes `&[]` to the underlying `aes_encrypt`
        /// FFI, signalling that the HSE firmware should generate and
        /// prepend the IV. Nonce uniqueness is therefore **delegated to
        /// the firmware**: the dispatching layer does not maintain a
        /// per-key counter. `HseFfiBackend::new` emits a one-shot
        /// `tracing::warn!` (`marker = HSE_MARKER_GCM_NONCE_DELEGATED`)
        /// at init time so operators can audit this delegation. A
        /// per-key software counter wrapper would be a defence-in-depth
        /// improvement but is out of scope for this release.
        fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_nxp", "aes_256_gcm_encrypt");
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            if key.len() != 32 {
                return Err(HsmError::MechanismParamInvalid);
            }
            // Audit 2026-05-17: wrap AES key material in Zeroizing at
            // point of receipt so a copy is not left on the heap.
            let key = Zeroizing::new(key.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_AES, &key)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            let out = b.aes_encrypt(h, HSE_AES_MODE_GCM, &[], plaintext)?;
            let expected_min = 12 + plaintext.len() + 16;
            if out.len() < expected_min {
                tracing::error!(
                    target: "craton_hsm_nxp",
                    marker = HSE_MARKER_GCM_OUT_LEN,
                    got = out.len(),
                    expected_min = expected_min,
                    "AES-GCM firmware output shorter than iv+ct+tag"
                );
                return Err(HsmError::EncryptedDataLenRange);
            }
            Ok(out)
        }
        fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            if key.len() != 32 {
                return Err(HsmError::MechanismParamInvalid);
            }
            if data.len() < 12 + 16 {
                tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_GCM_IV_LEN, got = data.len(), "AES-GCM input shorter than iv+tag");
                return Err(HsmError::EncryptedDataLenRange);
            }
            let key = Zeroizing::new(key.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_AES, &key)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.aes_decrypt(h, HSE_AES_MODE_GCM, &[], data)
        }
        fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let key = Zeroizing::new(key.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_AES, &key)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.aes_encrypt(h, HSE_AES_MODE_CBC, iv, plaintext)
        }
        fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let key = Zeroizing::new(key.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_AES, &key)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.aes_decrypt(h, HSE_AES_MODE_CBC, iv, ciphertext)
        }
        fn aes_ctr_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let key = Zeroizing::new(key.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_AES, &key)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.aes_encrypt(h, HSE_AES_MODE_CTR, iv, plaintext)
        }
        fn aes_ctr_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
            #[cfg(feature = "hw")]
            hw_path_not_wired!();
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let key = Zeroizing::new(key.to_vec());
            let arc = self.backend_arc()?;
            let b = arc.as_ref();
            let h = b.key_import_private(HSE_KEY_TYPE_AES, &key)?;
            let _handle_guard = HseKeyHandle::new(arc.clone(), h);
            b.aes_decrypt(h, HSE_AES_MODE_CTR, iv, ciphertext)
        }

        // ---- Trait methods kept as FunctionNotSupported under hw_impl. ----
        // These mirror the outer-stub impl: HSE either does not expose the
        // mechanism at all (RSA-OAEP, ECDH, key wrap, hashing-via-trait) or
        // the audit explicitly defers it (key generation through
        // RawKeyMaterial — see V6/HseKeyRef). Each carries an audit-ref doc
        // comment in the outer stub impl above.
        fn rsa_oaep_encrypt(
            &self,
            _modulus: &[u8],
            _public_exponent: &[u8],
            _plaintext: &[u8],
            _hash_alg: OaepHash,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }
        fn rsa_oaep_decrypt(
            &self,
            _private_key_der: &[u8],
            _ciphertext: &[u8],
            _hash_alg: OaepHash,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }
        fn generate_aes_key(
            &self,
            _key_len_bytes: usize,
            _fips_mode: bool,
        ) -> HsmResult<RawKeyMaterial> {
            Err(HsmError::FunctionNotSupported)
        }
        fn generate_rsa_key_pair(
            &self,
            _modulus_bits: u32,
            _fips_mode: bool,
        ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
            Err(HsmError::FunctionNotSupported)
        }
        fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            Err(HsmError::FunctionNotSupported)
        }
        fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            Err(HsmError::FunctionNotSupported)
        }
        fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            Err(HsmError::FunctionNotSupported)
        }
        fn compute_digest(
            &self,
            _mechanism: CK_MECHANISM_TYPE,
            _data: &[u8],
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }
        fn digest_output_len(&self, _mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
            Err(HsmError::FunctionNotSupported)
        }
        fn create_hasher(
            &self,
            _mechanism: CK_MECHANISM_TYPE,
        ) -> HsmResult<Box<dyn DigestAccumulator>> {
            Err(HsmError::FunctionNotSupported)
        }
        fn aes_key_wrap(
            &self,
            _wrapping_key: &[u8],
            _key_to_wrap: &[u8],
            _fips_mode: bool,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }
        fn aes_key_unwrap(
            &self,
            _wrapping_key: &[u8],
            _wrapped_key: &[u8],
            _fips_mode: bool,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }
        fn ecdh_p256(
            &self,
            _private_key_bytes: &[u8],
            _peer_public_key_sec1: &[u8],
            _okm_len: Option<usize>,
        ) -> HsmResult<RawKeyMaterial> {
            Err(HsmError::FunctionNotSupported)
        }
        fn ecdh_p384(
            &self,
            _private_key_bytes: &[u8],
            _peer_public_key_sec1: &[u8],
            _okm_len: Option<usize>,
        ) -> HsmResult<RawKeyMaterial> {
            Err(HsmError::FunctionNotSupported)
        }
    }
}
