// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Craton HSM backend for Infineon SLB 9670/9672 (OPTIGA TPM)
//!
//! This crate implements the [`CryptoBackend`] trait from `craton-hsm` targeting
//! Infineon OPTIGA TPM 2.0 chips via the TCG TSS ESAPI.
//!
//! # Hardware Support
//!
//! - Infineon SLB 9670 (TPM 2.0, discrete)
//! - Infineon SLB 9672 (TPM 2.0, firmware TPM)
//!
//! Note: Infineon OPTIGA Trust M is **not** supported by this crate —
//! it is an embedded security controller, not a TPM 2.0 device, and
//! does not speak the TCG TSS ESAPI. See `README.md` for details.
//!
//! # Feature Gates
//!
//! - **`hw`** — enables real TPM hardware calls via `libtss2-esys`. Without this
//!   feature every [`CryptoBackend`] method returns
//!   [`HsmError::FunctionNotSupported`].
//!
//! # Ed25519
//!
//! TPM 2.0 does not define Ed25519 support. The `ed25519_sign` and
//! `ed25519_verify` methods return [`HsmError::MechanismInvalid`] even when
//! the `hw` feature is active.
//!
//! # License
//!
//! Licensed under the Business Source License 1.1. See LICENSE-BSL.

#![deny(unsafe_code)]
#![deny(missing_docs)]

// Audit finding INFINEON-1 (mirrors NXP-1): refuse to build without an
// explicit choice between the `hw` (real Infineon OPTIGA TPM 2.0 hardware
// via libtss2-esys) and `stub` (development / CI) features. A
// feature-less build silently returns `FunctionNotSupported` for every
// operation, which is a foot-gun when shipped in a release binary.
#[cfg(all(
    not(feature = "hw"),
    not(feature = "stub"),
    not(feature = "test-stub"),
    not(test)
))]
compile_error!(
    "craton-hsm-infineon requires either the `hw` feature (real TPM 2.0 \
     hardware calls via libtss2-esys) or the `stub` feature (explicit \
     development build that returns FunctionNotSupported for every crypto \
     operation). A feature-less build is intentionally rejected to prevent \
     accidental deployment of a non-functional backend."
);

pub mod backend_trait;
pub mod error;
pub mod ffi;
pub mod tpm2_public;

#[cfg(feature = "hw")]
pub mod context;

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::digest::DigestAccumulator;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::{HsmError, HsmResult};
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use craton_hsm::store::key_material::RawKeyMaterial;
use std::sync::Arc;

pub use backend_trait::EsapiBackend;

/// Infineon OPTIGA TPM 2.0 crypto backend.
///
/// Dispatches every crypto operation through an [`EsapiBackend`] trait
/// object. The default constructor (`new`) under the `hw` feature
/// installs the real TSS2 FFI backend
/// (`backend_trait::EsapiFfiBackend`); tests can substitute a mock via
/// `Self::with_backend` (available under `test-stub` / `cfg(test)`).
///
/// Audit finding INFINEON-3: prior to this refactor the backend called
/// `Esys_*` free functions directly, which made unit-testing the
/// RC-to-`HsmError` mapping and the length-clamp paths impossible without
/// real TPM hardware.
pub struct InfineonTpmBackend {
    /// Installed backend. `None` means "stub mode" — every operation
    /// returns [`HsmError::FunctionNotSupported`] (or `MechanismInvalid`
    /// for hard-refused mechanisms like Ed25519). `None` is the default
    /// without the `hw` feature.
    backend: Option<Arc<dyn EsapiBackend + Send + Sync>>,
}

impl InfineonTpmBackend {
    /// Create a new Infineon TPM backend instance.
    ///
    /// # Stub Warning
    ///
    /// When compiled **without** the `hw` feature (the default), this backend
    /// is non-functional: every crypto operation returns
    /// [`HsmError::FunctionNotSupported`].  Enable the `hw` feature and link
    /// against `libtss2-esys` to activate real TPM 2.0 hardware calls.
    pub fn new() -> Self {
        if Self::is_stub() {
            // Audit finding M (env-var stub bypass in release): the env-var
            // bypass is an aid for tests / development; it MUST NOT be the
            // production opt-in for stub mode. Release builds reaching
            // this point must have been compiled with the explicit
            // `feature = "stub"` (the `compile_error!` at the top of this
            // file otherwise refuses to build). The env var is therefore
            // only consulted under `cfg(any(test, debug_assertions))`;
            // release builds with `feature = "stub"` proceed without it,
            // and release builds without `feature = "stub"` never reach
            // here (they fail at compile time).
            #[cfg(any(test, debug_assertions))]
            {
                let allow = std::env::var("CRATON_HSM_ALLOW_STUB_INFINEON")
                    .is_ok_and(|v| !v.is_empty())
                    || std::env::var("CRATON_HSM_ALLOW_MOCK").is_ok_and(|v| !v.is_empty());
                if !allow && !cfg!(feature = "stub") {
                    panic!(
                        "InfineonTpmBackend is in stub mode (compiled without the `hw` feature) and neither CRATON_HSM_ALLOW_STUB_INFINEON nor CRATON_HSM_ALLOW_MOCK is set. Refusing to construct a stub backend in production. Set either variable to 1 for testing, or rebuild with `--features hw` for real hardware."
                    );
                }
            }
            #[cfg(not(any(test, debug_assertions)))]
            {
                // Release path: `feature = "stub"` is the explicit opt-in
                // (enforced at compile time). The env-var fallback is
                // unreachable here by design.
                if !cfg!(feature = "stub") {
                    panic!(
                        "InfineonTpmBackend stub mode requires the `stub` feature in release builds; refusing to construct."
                    );
                }
            }
            tracing::warn!(
                target: "craton_hsm_infineon",
                "InfineonTpmBackend is running in stub mode - all operations will return FunctionNotSupported."
            );
            return Self { backend: None };
        }
        // Under `feature = "hw"`, install the real TSS2 FFI backend.
        //
        // `EsapiFfiBackend::new` can fail (`Esys_Initialize` returns an
        // error when no TPM device is available). On failure the backend
        // is constructed in stub-mode so downstream calls report
        // `FunctionNotSupported` rather than panicking from a constructor.
        #[cfg(feature = "hw")]
        {
            match backend_trait::EsapiFfiBackend::new() {
                Ok(b) => Self {
                    backend: Some(Arc::new(b)),
                },
                Err(e) => {
                    tracing::error!(
                        target: "craton_hsm_infineon",
                        error = ?e,
                        "failed to initialise TSS2 ESAPI context — backend will \
                         operate in stub mode"
                    );
                    Self { backend: None }
                }
            }
        }
        #[cfg(not(feature = "hw"))]
        {
            // Unreachable: is_stub() returned false above only if hw is on.
            Self { backend: None }
        }
    }

    /// Returns `true` if this backend is a stub (no real hardware calls).
    ///
    /// Returns `false` when compiled with the `hw` feature, which enables
    /// real Infineon OPTIGA TPM 2.0 hardware calls via `libtss2-esys`.
    pub fn is_stub() -> bool {
        !cfg!(feature = "hw")
    }

    /// Construct a backend with a caller-supplied [`EsapiBackend`] impl.
    ///
    /// Used by tests to swap in a [`backend_trait::MockEsapiBackend`]
    /// without a real TPM. Available only with the `test-stub` feature
    /// (or under `cfg(test)` inside this crate).
    #[cfg(any(test, feature = "test-stub"))]
    pub fn with_backend<B>(backend: B) -> Self
    where
        B: EsapiBackend + Send + Sync + 'static,
    {
        Self {
            backend: Some(Arc::new(backend)),
        }
    }

    /// Construct a stub backend without the env-var guard, for tests.
    #[cfg(any(test, feature = "test-stub"))]
    pub fn new_stub_for_test() -> Self {
        assert!(
            Self::is_stub(),
            "new_stub_for_test called in a `hw`-enabled build"
        );
        Self { backend: None }
    }

    /// Access the installed backend, returning `FunctionNotSupported` if
    /// none is installed.
    #[cfg(any(test, feature = "test-stub", feature = "hw"))]
    #[allow(dead_code)]
    fn backend(&self) -> HsmResult<&(dyn EsapiBackend + Send + Sync)> {
        self.backend
            .as_deref()
            .ok_or(HsmError::FunctionNotSupported)
    }
}

impl Default for InfineonTpmBackend {
    /// Audit M (DEFAULT-PANIC): previously delegated to `Self::new()`,
    /// which panics in release builds compiled without `feature = "stub"`
    /// (and in non-test debug builds without the env-var opt-in). A
    /// panicking `Default` is a foot-gun for callers that use
    /// `InfineonTpmBackend::default()` in initialiser contexts where a
    /// panic propagates poorly.
    ///
    /// Under `feature = "hw"`, delegate to `Self::new()` (which never
    /// panics on hw — it falls back to stub mode if `Esys_Initialize`
    /// fails). Otherwise construct a non-functional stub backend
    /// directly so that subsequent crypto calls return
    /// `FunctionNotSupported` rather than panicking inside the
    /// constructor.
    fn default() -> Self {
        #[cfg(feature = "hw")]
        {
            Self::new()
        }
        #[cfg(not(feature = "hw"))]
        {
            tracing::warn!(
                target: "craton_hsm_infineon",
                "InfineonTpmBackend::default() returns a non-functional stub \
                 (compiled without `hw` feature); every crypto operation \
                 returns FunctionNotSupported"
            );
            Self { backend: None }
        }
    }
}

// ---------------------------------------------------------------------------
// When the `hw` feature is NOT enabled and we are NOT in a test-stub build,
// every operation unconditionally returns `FunctionNotSupported` (except
// Ed25519 / Ed25519 keygen which are hard-refused with `MechanismInvalid`).
//
// Under `test-stub` or `cfg(test)` the trait-dispatching impl in
// `hw_impl` is used instead, letting tests inject a
// [`backend_trait::MockEsapiBackend`]. With no backend installed, that
// impl behaves identically to the stub below.
// ---------------------------------------------------------------------------

#[cfg(all(not(feature = "hw"), not(feature = "test-stub"), not(test)))]
impl CryptoBackend for InfineonTpmBackend {
    // ── Signing ─────────────────────────────────────────────────────────

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

    /// TPM 2.0 does not support Ed25519 — always returns [`HsmError::MechanismInvalid`].
    fn ed25519_sign(&self, _private_key_bytes: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
        Err(HsmError::MechanismInvalid)
    }

    /// TPM 2.0 does not support Ed25519 — always returns [`HsmError::MechanismInvalid`].
    fn ed25519_verify(
        &self,
        _public_key_bytes: &[u8],
        _data: &[u8],
        _signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        Err(HsmError::MechanismInvalid)
    }

    // ── Prehashed signing ───────────────────────────────────────────────

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

    // ── Encryption ──────────────────────────────────────────────────────

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

    // ── Key generation ──────────────────────────────────────────────────

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

    /// TPM 2.0 does not support Ed25519 — always returns [`HsmError::MechanismInvalid`].
    fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        Err(HsmError::MechanismInvalid)
    }

    // ── Digest ──────────────────────────────────────────────────────────

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

    // ── Key wrap / unwrap ───────────────────────────────────────────────

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

    // ── Key derivation ──────────────────────────────────────────────────

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

// ---------------------------------------------------------------------------
// When the `hw` feature IS enabled, delegate to the TPM via the ESAPI FFI
// layer. Operations are marshalled through `context::EsapiContext` and the
// FFI bindings declared in `ffi.rs`.
//
// Each method:
//   1. Validates input parameters.
//   2. Creates transient TPM objects as needed (CreatePrimary / Create / Load).
//   3. Calls the corresponding `Esys_*` function (unsafe).
//   4. Maps the TSS2_RC code to an `HsmResult`.
//   5. Flushes transient objects on completion.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "hw", feature = "test-stub", test))]
mod hw_impl {
    use super::*;
    // TPM2_ALG_ID is a plain u16 alias — always available from `ffi`.
    use crate::ffi::TPM2_ALG_ID;

    // These are only needed by the inline-FFI keygen paths that remain
    // gated on `feature = "hw"`.
    #[cfg(feature = "hw")]
    use crate::context::EsapiContext;
    #[cfg(feature = "hw")]
    use crate::error::check_tss2_rc;
    #[cfg(feature = "hw")]
    use crate::ffi::{
        self, ESYS_TR_NONE, ESYS_TR_PASSWORD, TPM2B_CREATION_DATA, TPM2B_DATA, TPM2B_DIGEST,
        TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPM2_RH_OWNER, TPML_PCR_SELECTION,
    };

    // TPM2 algorithm identifiers (from TCG TPM 2.0 Library Spec Part 2).
    // Some of these constants are only referenced by the inline-FFI
    // keygen paths which are gated on `feature = "hw"`. Mark them all as
    // allow-dead-code so the `test-stub`-without-`hw` build does not
    // emit warnings.
    #[allow(dead_code)]
    const TPM2_ALG_RSA: TPM2_ALG_ID = 0x0001;
    const TPM2_ALG_SHA256: TPM2_ALG_ID = 0x000B;
    const TPM2_ALG_SHA384: TPM2_ALG_ID = 0x000C;
    const TPM2_ALG_SHA512: TPM2_ALG_ID = 0x000D;
    #[allow(dead_code)]
    const TPM2_ALG_ECC: TPM2_ALG_ID = 0x0023;
    // Audit fix (PLACEHOLDER-HANDLE-REFUSE): with the placeholder
    // dispatch sites now refusing before ever reaching the FFI, these
    // scheme-tag constants are unused. Kept for documentation /
    // forthcoming Esys_Load wiring; allow dead code in the meantime.
    #[allow(dead_code)]
    const TPM2_ALG_RSASSA: TPM2_ALG_ID = 0x0014;
    #[allow(dead_code)]
    const TPM2_ALG_RSAPSS: TPM2_ALG_ID = 0x0016;
    #[allow(dead_code)]
    const TPM2_ALG_ECDSA: TPM2_ALG_ID = 0x0018;
    #[allow(dead_code)]
    const TPM2_ALG_AES: TPM2_ALG_ID = 0x0006;
    #[allow(dead_code)]
    const TPM2_ALG_CFB: TPM2_ALG_ID = 0x0043;
    #[allow(dead_code)]
    const TPM2_ALG_CBC: TPM2_ALG_ID = 0x0042;
    #[allow(dead_code)]
    const TPM2_ALG_CTR: TPM2_ALG_ID = 0x0040;
    #[allow(dead_code)]
    const TPM2_ALG_NULL: TPM2_ALG_ID = 0x0010;

    // ECC curve identifiers.
    #[allow(dead_code)]
    const TPM2_ECC_NIST_P256: u16 = 0x0003;
    #[allow(dead_code)]
    const TPM2_ECC_NIST_P384: u16 = 0x0004;

    /// Map a `HashAlg` to the corresponding TPM2 algorithm ID.
    fn hash_alg_to_tpm2(alg: HashAlg) -> TPM2_ALG_ID {
        match alg {
            HashAlg::Sha256 => TPM2_ALG_SHA256,
            HashAlg::Sha384 => TPM2_ALG_SHA384,
            HashAlg::Sha512 => TPM2_ALG_SHA512,
        }
    }

    /// Map a PKCS#11 mechanism type to the corresponding TPM2 hash algorithm.
    fn mechanism_to_tpm2_hash(mechanism: CK_MECHANISM_TYPE) -> HsmResult<TPM2_ALG_ID> {
        match mechanism {
            0x0000_0250 => Ok(TPM2_ALG_SHA256), // CKM_SHA256
            0x0000_0260 => Ok(TPM2_ALG_SHA384), // CKM_SHA384
            0x0000_0270 => Ok(TPM2_ALG_SHA512), // CKM_SHA512
            _ => Err(HsmError::MechanismInvalid),
        }
    }

    // Audit finding: duplicate `validate_tpm_handle` removed; the canonical
    // implementation lives in `backend_trait::hw_backend::validate_tpm_handle`.
    // The previous TODO(INFINEON-3-create) markers have been resolved by
    // extracting `do_create_primary` into the same module - see below.

    // ---------------------------------------------------------------------
    // The TPM helper functions (`tpm_get_random`, `tpm_hash`,
    // `tpm_rsa_sign`, `tpm_rsa_verify`, `tpm_symmetric`) that previously
    // lived here have been migrated to [`backend_trait::EsapiFfiBackend`]
    // — see the module-level rustdoc in `backend_trait.rs`. The
    // [`InfineonTpmBackend`] methods below now dispatch through the
    // [`EsapiBackend`] trait via `self.backend()?`.
    //
    // Audit migration status (was 14/17, now 17/17): the three
    // `Esys_CreatePrimary` call sites in
    // `generate_{rsa,ec_p256,ec_p384}_key_pair` now go through
    // `backend_trait::do_create_primary(template_alg)` which handles the
    // RSA-2048 / P-256 / P-384 TPMT_PUBLIC template construction inline.
    // Real public-key extraction parses the marshaled `TPMT_PUBLIC` via
    // `tpm2_public::parse_tpmt_public` (audit finding C-4).
    // ---------------------------------------------------------------------

    /// Audit hardening (PLACEHOLDER-HANDLE): every sign / verify /
    /// encrypt / decrypt operation below currently routes through a
    /// hardcoded TPM persistent handle (0x8100_000{1..4}) because the
    /// caller-supplied key material is opaque DER / SEC1 bytes that this
    /// backend has no way to load into the TPM until an
    /// `Esys_Load`-driven import path is wired (TODO: INFINEON-load).
    /// Helper that logs the placeholder substitution loudly so an
    /// integrator never silently accepts a "signing key replaced by
    /// whatever happens to live at 0x8100_0001" outcome. Emit at
    /// `error!` level to ensure it surfaces in default tracing configs.
    fn log_placeholder_handle(op: &'static str, key_input_len: usize, placeholder: u32) {
        tracing::error!(
            target: "craton_hsm_infineon",
            marker = "PLACEHOLDER_HANDLE",
            op,
            key_input_len,
            placeholder = format!("0x{placeholder:08X}"),
            "Infineon backend: ignoring caller-supplied key material and using \
             hardcoded persistent TPM handle. This path is non-functional in \
             production until Esys_Load orchestration lands (TODO INFINEON-load); \
             callers MUST treat the result as untrusted."
        );
    }

    impl CryptoBackend for InfineonTpmBackend {
        // ── Signing ─────────────────────────────────────────────────────

        fn rsa_pkcs1v15_sign(
            &self,
            _private_key_der: &[u8],
            data: &[u8],
            hash_alg: Option<HashAlg>,
        ) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "rsa_pkcs1v15_sign via TPM ESAPI");
            let _alg = hash_alg_to_tpm2(hash_alg.unwrap_or(HashAlg::Sha256));
            let _ = data;
            // Placeholder handle — in production this would come from a
            // CreatePrimary + Create + Load orchestration (see TODO above).
            let handle = 0x8100_0001;
            log_placeholder_handle("rsa_pkcs1v15_sign", _private_key_der.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): refuse rather than
            // silently signing with whatever happens to be persisted at
            // the hardcoded slot. Re-enable once Esys_Load orchestration
            // lands (TODO INFINEON-load).
            Err(HsmError::FunctionNotSupported)
        }

        fn rsa_pkcs1v15_verify(
            &self,
            _modulus: &[u8],
            _public_exponent: &[u8],
            data: &[u8],
            signature_bytes: &[u8],
            hash_alg: Option<HashAlg>,
        ) -> HsmResult<bool> {
            tracing::debug!(target: "craton_hsm_infineon", "rsa_pkcs1v15_verify via TPM ESAPI");
            let _alg = hash_alg_to_tpm2(hash_alg.unwrap_or(HashAlg::Sha256));
            let _ = (data, signature_bytes);
            let handle = 0x8100_0001;
            log_placeholder_handle("rsa_pkcs1v15_verify", _modulus.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn rsa_pss_sign(
            &self,
            _private_key_der: &[u8],
            data: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "rsa_pss_sign via TPM ESAPI");
            let _alg = hash_alg_to_tpm2(hash_alg);
            let _ = data;
            let handle = 0x8100_0001;
            log_placeholder_handle("rsa_pss_sign", _private_key_der.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn rsa_pss_verify(
            &self,
            _modulus: &[u8],
            _public_exponent: &[u8],
            data: &[u8],
            signature_bytes: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            tracing::debug!(target: "craton_hsm_infineon", "rsa_pss_verify via TPM ESAPI");
            let _alg = hash_alg_to_tpm2(hash_alg);
            let _ = (data, signature_bytes);
            let handle = 0x8100_0001;
            log_placeholder_handle("rsa_pss_verify", _modulus.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn ecdsa_p256_sign(&self, _private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "ecdsa_p256_sign via TPM ESAPI");
            let _ = data;
            let handle = 0x8100_0002;
            log_placeholder_handle("ecdsa_p256_sign", _private_key_bytes.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn ecdsa_p256_verify(
            &self,
            _public_key_sec1: &[u8],
            data: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            tracing::debug!(target: "craton_hsm_infineon", "ecdsa_p256_verify via TPM ESAPI");
            let _ = (data, signature_der);
            let handle = 0x8100_0002;
            log_placeholder_handle("ecdsa_p256_verify", _public_key_sec1.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn ecdsa_p384_sign(&self, _private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "ecdsa_p384_sign via TPM ESAPI");
            let _ = data;
            let handle = 0x8100_0003;
            log_placeholder_handle("ecdsa_p384_sign", _private_key_bytes.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn ecdsa_p384_verify(
            &self,
            _public_key_sec1: &[u8],
            data: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            tracing::debug!(target: "craton_hsm_infineon", "ecdsa_p384_verify via TPM ESAPI");
            let _ = (data, signature_der);
            let handle = 0x8100_0003;
            log_placeholder_handle("ecdsa_p384_verify", _public_key_sec1.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (STUBS): Ed25519 is hard-refused. TPM 2.0 does not
        /// define Ed25519 in any standard profile and the OPTIGA TPM does
        /// not implement it as a vendor extension. This is intentional
        /// per the audit doc and applies whether or not a backend is
        /// installed - parity with `lib.rs:806`.
        fn ed25519_sign(&self, _private_key_bytes: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
            Err(HsmError::MechanismInvalid)
        }

        /// Audit (STUBS): see `ed25519_sign`. lib.rs:818 hard-refuses.
        fn ed25519_verify(
            &self,
            _public_key_bytes: &[u8],
            _data: &[u8],
            _signature_bytes: &[u8],
        ) -> HsmResult<bool> {
            Err(HsmError::MechanismInvalid)
        }

        // ── Prehashed signing ───────────────────────────────────────────
        // The TPM natively operates on digests, so prehashed operations are
        // a natural fit. All paths go through
        // `EsapiBackend::sign_digest` / `verify_signature_digest`.

        fn rsa_pkcs1v15_sign_prehashed(
            &self,
            _private_key_der: &[u8],
            digest: &[u8],
            _hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "rsa_pkcs1v15_sign_prehashed via TPM ESAPI");
            let _ = digest;
            let handle = 0x8100_0001;
            log_placeholder_handle(
                "rsa_pkcs1v15_sign_prehashed",
                _private_key_der.len(),
                handle,
            );
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn rsa_pkcs1v15_verify_prehashed(
            &self,
            _modulus: &[u8],
            _public_exponent: &[u8],
            digest: &[u8],
            signature_bytes: &[u8],
            _hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            tracing::debug!(target: "craton_hsm_infineon", "rsa_pkcs1v15_verify_prehashed via TPM ESAPI");
            let _ = (digest, signature_bytes);
            let handle = 0x8100_0001;
            log_placeholder_handle("rsa_pkcs1v15_verify_prehashed", _modulus.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (WRONG-ALG-FORWARD): the previous implementation
        /// forwarded RSA-PSS prehashed sign to the PKCS#1 v1.5 path,
        /// which silently produced a v1.5 signature instead of a PSS
        /// signature. Wiring a real PSS path requires constructing a
        /// PSS-scheme key template + driving `Esys_Sign` with the
        /// matching `TPMT_SIG_SCHEME` — neither is currently exposed by
        /// the trait dispatch surface. Until that lands, hard-refuse
        /// with `MechanismInvalid` so callers cannot accidentally accept
        /// a wrong-algorithm signature.
        fn rsa_pss_sign_prehashed(
            &self,
            _private_key_der: &[u8],
            _digest: &[u8],
            _hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            tracing::error!(
                target: "craton_hsm_infineon",
                "rsa_pss_sign_prehashed: PSS template+scheme not yet wired; \
                 refusing rather than silently producing PKCS#1 v1.5 (audit \
                 finding WRONG-ALG-FORWARD)"
            );
            Err(HsmError::MechanismInvalid)
        }

        /// Audit (WRONG-ALG-FORWARD): see `rsa_pss_sign_prehashed`.
        fn rsa_pss_verify_prehashed(
            &self,
            _modulus: &[u8],
            _public_exponent: &[u8],
            _digest: &[u8],
            _signature_bytes: &[u8],
            _hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            tracing::error!(
                target: "craton_hsm_infineon",
                "rsa_pss_verify_prehashed: PSS template+scheme not yet wired; \
                 refusing rather than silently verifying as PKCS#1 v1.5 (audit \
                 finding WRONG-ALG-FORWARD)"
            );
            Err(HsmError::MechanismInvalid)
        }

        fn ecdsa_p256_sign_prehashed(
            &self,
            _private_key_bytes: &[u8],
            digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "ecdsa_p256_sign_prehashed via TPM ESAPI");
            let _ = digest;
            let handle = 0x8100_0002;
            log_placeholder_handle(
                "ecdsa_p256_sign_prehashed",
                _private_key_bytes.len(),
                handle,
            );
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn ecdsa_p256_verify_prehashed(
            &self,
            _public_key_sec1: &[u8],
            digest: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            tracing::debug!(target: "craton_hsm_infineon", "ecdsa_p256_verify_prehashed via TPM ESAPI");
            let _ = (digest, signature_der);
            let handle = 0x8100_0002;
            log_placeholder_handle(
                "ecdsa_p256_verify_prehashed",
                _public_key_sec1.len(),
                handle,
            );
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (WRONG-ALG-FORWARD): previously forwarded to the P-256
        /// path, silently using the wrong curve handle (0x8100_0002) and
        /// truncating to 64 bytes instead of 96. Wiring a real P-384
        /// signing path requires loading a P-384 key template at a
        /// distinct handle (0x8100_0003) and threading the curve through
        /// `expected_signature_len`. Hard-refuse with `MechanismInvalid`
        /// until that lands.
        fn ecdsa_p384_sign_prehashed(
            &self,
            _private_key_bytes: &[u8],
            _digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            tracing::error!(
                target: "craton_hsm_infineon",
                "ecdsa_p384_sign_prehashed: P-384 key load not yet wired; \
                 refusing rather than silently producing a truncated P-256 \
                 signature (audit finding WRONG-ALG-FORWARD)"
            );
            Err(HsmError::MechanismInvalid)
        }

        /// Audit (WRONG-ALG-FORWARD): see `ecdsa_p384_sign_prehashed`.
        fn ecdsa_p384_verify_prehashed(
            &self,
            _public_key_sec1: &[u8],
            _digest: &[u8],
            _signature_der: &[u8],
        ) -> HsmResult<bool> {
            tracing::error!(
                target: "craton_hsm_infineon",
                "ecdsa_p384_verify_prehashed: P-384 key load not yet wired; \
                 refusing rather than silently verifying against a P-256 key \
                 (audit finding WRONG-ALG-FORWARD)"
            );
            Err(HsmError::MechanismInvalid)
        }

        // ── Encryption ──────────────────────────────────────────────────

        fn aes_256_gcm_encrypt(&self, _key: &[u8], _plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            // TPM 2.0 does not support AES-GCM as a symmetric mode natively.
            self.backend()?;
            Err(HsmError::MechanismInvalid)
        }

        fn aes_256_gcm_decrypt(&self, _key: &[u8], _data: &[u8]) -> HsmResult<Vec<u8>> {
            self.backend()?;
            Err(HsmError::MechanismInvalid)
        }

        fn aes_cbc_encrypt(&self, _key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "aes_cbc_encrypt via TPM ESAPI");
            let _backend = self.backend()?;
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let _ = plaintext;
            let handle = 0x8100_0004;
            log_placeholder_handle("aes_cbc_encrypt", _key.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn aes_cbc_decrypt(&self, _key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "aes_cbc_decrypt via TPM ESAPI");
            let _backend = self.backend()?;
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let _ = ciphertext;
            let handle = 0x8100_0004;
            log_placeholder_handle("aes_cbc_decrypt", _key.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn aes_ctr_encrypt(&self, _key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "aes_ctr_encrypt via TPM ESAPI");
            let _backend = self.backend()?;
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let _ = plaintext;
            let handle = 0x8100_0004;
            log_placeholder_handle("aes_ctr_encrypt", _key.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        fn aes_ctr_decrypt(&self, _key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", "aes_ctr_decrypt via TPM ESAPI");
            let _backend = self.backend()?;
            if iv.len() != 16 {
                return Err(HsmError::MechanismParamInvalid);
            }
            let _ = ciphertext;
            let handle = 0x8100_0004;
            log_placeholder_handle("aes_ctr_decrypt", _key.len(), handle);
            // Audit fix (PLACEHOLDER-HANDLE-REFUSE): see rsa_pkcs1v15_sign.
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (STUBS lib.rs:1017): RSA-OAEP is in principle a TPM2
        /// command (`Esys_RSA_Decrypt` with TPM_ALG_OAEP scheme) but
        /// requires `Esys_Load` of a parent + private blob; this integration
        /// layer does not yet ship the load orchestration. Externally
        /// blocked on tss-esapi-sys for a real key-load path.
        fn rsa_oaep_encrypt(
            &self,
            _modulus: &[u8],
            _public_exponent: &[u8],
            _plaintext: &[u8],
            _hash_alg: OaepHash,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (STUBS lib.rs:1026): see `rsa_oaep_encrypt`.
        fn rsa_oaep_decrypt(
            &self,
            _private_key_der: &[u8],
            _ciphertext: &[u8],
            _hash_alg: OaepHash,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }

        // ── Key generation ──────────────────────────────────────────────

        fn generate_aes_key(
            &self,
            key_len_bytes: usize,
            _fips_mode: bool,
        ) -> HsmResult<RawKeyMaterial> {
            tracing::debug!(target: "craton_hsm_infineon", key_len_bytes, "generate_aes_key via TPM ESAPI");
            let backend = self.backend()?;
            if key_len_bytes != 16 && key_len_bytes != 24 && key_len_bytes != 32 {
                return Err(HsmError::MechanismParamInvalid);
            }
            // Audit M (zeroize-temp): wrap the temporary Vec in
            // `Zeroizing` so an early-return between `get_random` and
            // `RawKeyMaterial::new` cannot leave plaintext key bytes on
            // the heap (the destination type also zeroizes on drop, but
            // the intermediate ownership window is exactly the gap this
            // wrapper closes).
            let random: zeroize::Zeroizing<Vec<u8>> =
                zeroize::Zeroizing::new(backend.get_random(key_len_bytes as u16)?);
            // Clone into the destination then drop the Zeroizing wrapper;
            // RawKeyMaterial::new takes a Vec<u8> by value and will
            // zeroize on its own drop.
            let key_bytes: Vec<u8> = random.to_vec();
            drop(random);
            Ok(RawKeyMaterial::new(key_bytes))
        }

        // Public-key extraction (audit finding C-4) is handled inline by
        // parsing the marshaled `TPMT_PUBLIC` that ESAPI hands back — see
        // [`tpm2_public::parse_tpmt_public`]. Keygen remains inline under
        // `feature = "hw"` because migrating `Esys_CreatePrimary` through
        // the [`EsapiBackend`] trait would require the trait to carry the
        // ESAPI-allocated output pointer, which is an ergonomics-only
        // refactor tracked separately.

        fn generate_rsa_key_pair(
            &self,
            modulus_bits: u32,
            _fips_mode: bool,
        ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
            tracing::debug!(target: "craton_hsm_infineon", modulus_bits, "generate_rsa_key_pair via TPM ESAPI");
            if modulus_bits < 2048 || modulus_bits > 4096 {
                return Err(HsmError::MechanismParamInvalid);
            }
            #[cfg(feature = "hw")]
            {
                // Audit fix INFINEON-3-create: extracted into
                // `backend_trait::do_create_primary` so all three keygen
                // sites share one helper that builds a real TPMT_PUBLIC
                // template (not all-zeros) before calling Esys_CreatePrimary.
                let mut ctx = EsapiContext::new()?;
                let (object_handle, out_public) =
                    crate::backend_trait::hw_backend::do_create_primary(
                        &mut ctx,
                        crate::tpm2_public::TPM_ALG_RSA,
                        0,
                        modulus_bits as u16,
                    )?;
                let private = RawKeyMaterial::new(object_handle.to_be_bytes().to_vec());
                // SAFETY: `out_public` was populated by ESAPI on success;
                // the slice is bound to the helper-owned TPM allocation,
                // valid for ctx lifetime; we use it before ctx drops.
                let buf = unsafe { crate::tpm2_public::slice_from_raw::<'_>(out_public) }
                    .ok_or(HsmError::GeneralError)?;
                let result = match crate::tpm2_public::parse_tpmt_public(buf)? {
                    crate::tpm2_public::PublicKey::Rsa { modulus, exponent } => {
                        if modulus.len() != (modulus_bits / 8) as usize {
                            Err(HsmError::GeneralError)
                        } else {
                            Ok((private, modulus, exponent))
                        }
                    }
                    _ => Err(HsmError::MechanismInvalid),
                };
                drop(ctx);
                result
            }
            #[cfg(not(feature = "hw"))]
            {
                let _ = self.backend()?; // propagate FunctionNotSupported
                Err(HsmError::FunctionNotSupported)
            }
        }

        fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            tracing::debug!(target: "craton_hsm_infineon", "generate_ec_p256_key_pair via TPM ESAPI");
            #[cfg(feature = "hw")]
            {
                let mut ctx = EsapiContext::new()?;
                let (object_handle, out_public) =
                    crate::backend_trait::hw_backend::do_create_primary(
                        &mut ctx,
                        crate::tpm2_public::TPM_ALG_ECC,
                        crate::tpm2_public::TPM_ECC_NIST_P256,
                        0,
                    )?;
                let private = RawKeyMaterial::new(object_handle.to_be_bytes().to_vec());
                // SAFETY: see generate_rsa_key_pair above.
                let buf = unsafe { crate::tpm2_public::slice_from_raw::<'_>(out_public) }
                    .ok_or(HsmError::GeneralError)?;
                let result = match crate::tpm2_public::parse_tpmt_public(buf)? {
                    crate::tpm2_public::PublicKey::Ecc {
                        curve_id,
                        uncompressed_point,
                    } if curve_id == crate::tpm2_public::TPM_ECC_NIST_P256 => {
                        Ok((private, uncompressed_point))
                    }
                    _ => Err(HsmError::MechanismInvalid),
                };
                drop(ctx);
                result
            }
            #[cfg(not(feature = "hw"))]
            {
                let _ = self.backend()?;
                Err(HsmError::FunctionNotSupported)
            }
        }

        fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            tracing::debug!(target: "craton_hsm_infineon", "generate_ec_p384_key_pair via TPM ESAPI");
            #[cfg(feature = "hw")]
            {
                let mut ctx = EsapiContext::new()?;
                let (object_handle, out_public) =
                    crate::backend_trait::hw_backend::do_create_primary(
                        &mut ctx,
                        crate::tpm2_public::TPM_ALG_ECC,
                        crate::tpm2_public::TPM_ECC_NIST_P384,
                        0,
                    )?;
                let private = RawKeyMaterial::new(object_handle.to_be_bytes().to_vec());
                // SAFETY: see generate_rsa_key_pair above.
                let buf = unsafe { crate::tpm2_public::slice_from_raw::<'_>(out_public) }
                    .ok_or(HsmError::GeneralError)?;
                let result = match crate::tpm2_public::parse_tpmt_public(buf)? {
                    crate::tpm2_public::PublicKey::Ecc {
                        curve_id,
                        uncompressed_point,
                    } if curve_id == crate::tpm2_public::TPM_ECC_NIST_P384 => {
                        Ok((private, uncompressed_point))
                    }
                    _ => Err(HsmError::MechanismInvalid),
                };
                drop(ctx);
                result
            }
            #[cfg(not(feature = "hw"))]
            {
                let _ = self.backend()?;
                Err(HsmError::FunctionNotSupported)
            }
        }

        /// TPM 2.0 does not support Ed25519 — always returns [`HsmError::MechanismInvalid`].
        fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            Err(HsmError::MechanismInvalid)
        }

        // ── Digest ──────────────────────────────────────────────────────

        fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
            tracing::debug!(target: "craton_hsm_infineon", mechanism, "compute_digest via TPM ESAPI");
            // Backend-availability check first so stub builds report
            // FunctionNotSupported (parity with the non-hw stub impl)
            // rather than MechanismInvalid for bogus mechanisms.
            let backend = self.backend()?;
            let alg = mechanism_to_tpm2_hash(mechanism)?;
            backend.hash(alg, data)
        }

        fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
            // Audit M (DIGEST-PROBE-ORACLE): if the backend is absent
            // (stub mode under `test-stub`), do NOT discriminate between
            // "accepted" and "rejected" mechanisms — return the same
            // `FunctionNotSupported` for every input so a caller cannot
            // probe which mechanisms would be honoured by a real
            // backend. Only when a real `EsapiBackend` is installed do
            // we return the per-mechanism length.
            let backend = self.backend();
            if backend.is_err() {
                // Stub build — uniform response, no side channel.
                return Err(HsmError::FunctionNotSupported);
            }
            match mechanism {
                0x0000_0250 => Ok(32), // SHA-256
                0x0000_0260 => Ok(48), // SHA-384
                0x0000_0270 => Ok(64), // SHA-512
                _ => Err(HsmError::MechanismInvalid),
            }
        }

        /// Audit (STUBS lib.rs:1279): incremental hashing requires the
        /// TPM2 HashSequence API (`Esys_HashSequenceStart` /
        /// `Esys_SequenceUpdate` / `Esys_SequenceComplete`). Default
        /// builds return `MechanismInvalid` because the trait-dispatch
        /// path does not yet expose a streaming hash interface — there
        /// is no `compile_error!` in `ffi.rs` (the previous reference
        /// here was stale documentation, audit doc-claim H-FFI). Under
        /// `feature = "test-stub"` (or `cfg(test)`) the mechanism is
        /// validated and the call still returns MechanismInvalid since
        /// the trait dispatch path does not yet expose a streaming hash
        /// interface.
        fn create_hasher(
            &self,
            mechanism: CK_MECHANISM_TYPE,
        ) -> HsmResult<Box<dyn DigestAccumulator>> {
            #[cfg(any(feature = "test-stub", test))]
            {
                // Backend availability first so stub builds report
                // FunctionNotSupported (parity with the no-hw stub path
                // and with `compute_digest`).
                let _backend = self.backend()?;
                let _alg = mechanism_to_tpm2_hash(mechanism)?;
                Err(HsmError::MechanismInvalid)
            }
            #[cfg(not(any(feature = "test-stub", test)))]
            {
                let _ = mechanism;
                Err(HsmError::MechanismInvalid)
            }
        }

        // ── Key wrap / unwrap ───────────────────────────────────────────

        /// Audit (STUBS lib.rs:1291): AES-Key-Wrap (RFC-3394) is not a
        /// native TPM2 mechanism; would have to be emulated in software
        /// using AES-CBC primitives the TPM exposes. Out of scope for
        /// this integration; FIPS-mode key transport should use
        /// `craton-hsm-awslc` instead.
        fn aes_key_wrap(
            &self,
            _wrapping_key: &[u8],
            _key_to_wrap: &[u8],
            _fips_mode: bool,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (STUBS lib.rs:1300): see `aes_key_wrap`.
        fn aes_key_unwrap(
            &self,
            _wrapping_key: &[u8],
            _wrapped_key: &[u8],
            _fips_mode: bool,
        ) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }

        // ── Key derivation ──────────────────────────────────────────────

        /// Audit (STUBS lib.rs:1312): ECDH via TPM requires
        /// `Esys_ECDH_ZGen` and a loaded private key; gated on real
        /// key-load orchestration through tss-esapi-sys.
        fn ecdh_p256(
            &self,
            _private_key_bytes: &[u8],
            _peer_public_key_sec1: &[u8],
            _okm_len: Option<usize>,
        ) -> HsmResult<RawKeyMaterial> {
            Err(HsmError::FunctionNotSupported)
        }

        /// Audit (STUBS lib.rs:1321): see `ecdh_p256`.
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> InfineonTpmBackend {
        InfineonTpmBackend::new_stub_for_test()
    }

    // ── Construction / lifecycle ─────────────────────────────────────────

    #[test]
    fn new_returns_backend() {
        std::env::set_var("CRATON_HSM_ALLOW_STUB_INFINEON", "1");
        let b = InfineonTpmBackend::new();
        drop(b);
    }

    #[test]
    fn default_equals_new() {
        std::env::set_var("CRATON_HSM_ALLOW_STUB_INFINEON", "1");
        let _a = InfineonTpmBackend::new();
        let _b = InfineonTpmBackend::default();
    }

    // Audit M (env-var bypass): under `feature = "stub"`, the env-var
    // bypass is no longer the gate - the explicit feature flag is. The
    // test below only exercises the panic surface when stub is NOT
    // enabled (which under cargo-test only happens for builds that
    // include neither `stub` nor `test-stub`).
    #[test]
    #[cfg(all(not(feature = "hw"), not(feature = "stub")))]
    #[should_panic(expected = "stub mode")]
    fn stub_construction_panics_without_opt_in() {
        std::env::remove_var("CRATON_HSM_ALLOW_STUB_INFINEON");
        std::env::remove_var("CRATON_HSM_ALLOW_MOCK");
        let _ = InfineonTpmBackend::new();
    }

    // Companion: under `feature = "stub"` (which test-stub implies),
    // construction must succeed even with no env-var - the explicit
    // compile-time opt-in is the gate.
    #[test]
    #[cfg(feature = "stub")]
    fn stub_construction_succeeds_with_feature_flag() {
        std::env::remove_var("CRATON_HSM_ALLOW_STUB_INFINEON");
        std::env::remove_var("CRATON_HSM_ALLOW_MOCK");
        let _b = InfineonTpmBackend::new();
    }

    /// Without the `hw` feature, `is_stub()` must return `true`.
    #[cfg(not(feature = "hw"))]
    #[test]
    fn is_stub_without_hw_feature() {
        assert!(
            InfineonTpmBackend::is_stub(),
            "expected stub mode without 'hw' feature"
        );
    }

    /// With the `hw` feature, `is_stub()` must return `false`.
    #[cfg(feature = "hw")]
    #[test]
    fn is_stub_with_hw_feature() {
        assert!(
            !InfineonTpmBackend::is_stub(),
            "expected non-stub mode with 'hw' feature"
        );
    }

    #[test]
    fn backend_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<InfineonTpmBackend>();
        assert_sync::<InfineonTpmBackend>();
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    // The `T: Debug` bound was too strict — some result types (e.g.
    // `Box<dyn DigestAccumulator>`) do not implement Debug. We only need
    // to pattern-match on the `Err` arm, so the generic type is free.
    fn assert_not_supported<T>(result: HsmResult<T>) {
        match result {
            Err(HsmError::FunctionNotSupported) => {}
            Err(other) => panic!("expected FunctionNotSupported, got {:?}", other),
            Ok(_) => panic!("expected FunctionNotSupported, got Ok(_)"),
        }
    }

    fn assert_mechanism_invalid<T>(result: HsmResult<T>) {
        match result {
            Err(HsmError::MechanismInvalid) => {}
            Err(other) => panic!("expected MechanismInvalid, got {:?}", other),
            Ok(_) => panic!("expected MechanismInvalid, got Ok(_)"),
        }
    }

    fn assert_is_error<T>(result: HsmResult<T>) {
        assert!(result.is_err(), "expected an error");
    }

    // ── Stub-mode tests (without `hw` feature) ─────────────────────────

    #[cfg(not(feature = "hw"))]
    mod stub_tests {
        use super::*;

        #[test]
        fn all_rsa_signing_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.rsa_pkcs1v15_sign(b"", b"", None));
            assert_not_supported(b.rsa_pkcs1v15_sign(b"", b"", Some(HashAlg::Sha256)));
            assert_not_supported(b.rsa_pkcs1v15_verify(b"", b"", b"", b"", None));
            assert_not_supported(b.rsa_pss_sign(b"", b"", HashAlg::Sha256));
            assert_not_supported(b.rsa_pss_sign(b"", b"", HashAlg::Sha384));
            assert_not_supported(b.rsa_pss_sign(b"", b"", HashAlg::Sha512));
            assert_not_supported(b.rsa_pss_verify(b"", b"", b"", b"", HashAlg::Sha256));
        }

        #[test]
        fn all_ecdsa_signing_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.ecdsa_p256_sign(b"", b""));
            assert_not_supported(b.ecdsa_p256_verify(b"", b"", b""));
            assert_not_supported(b.ecdsa_p384_sign(b"", b""));
            assert_not_supported(b.ecdsa_p384_verify(b"", b"", b""));
        }

        #[test]
        fn all_prehashed_signing_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.rsa_pkcs1v15_sign_prehashed(b"", b"", HashAlg::Sha256));
            assert_not_supported(b.rsa_pkcs1v15_verify_prehashed(
                b"",
                b"",
                b"",
                b"",
                HashAlg::Sha256,
            ));
            // Audit (WRONG-ALG-FORWARD): the RSA-PSS prehashed path hard-refuses
            // with `MechanismInvalid` rather than silently producing a PKCS#1
            // v1.5 signature. Until the PSS template+scheme wiring lands, both
            // sign and verify return `MechanismInvalid` even from the stub.
            assert_mechanism_invalid(b.rsa_pss_sign_prehashed(b"", b"", HashAlg::Sha256));
            assert_mechanism_invalid(b.rsa_pss_verify_prehashed(
                b"",
                b"",
                b"",
                b"",
                HashAlg::Sha256,
            ));
            assert_not_supported(b.ecdsa_p256_sign_prehashed(b"", b""));
            assert_not_supported(b.ecdsa_p256_verify_prehashed(b"", b"", b""));
            // Audit (WRONG-ALG-FORWARD): the P-384 prehashed path hard-refuses
            // with `MechanismInvalid` until the P-384 key-load is wired up;
            // we don't want to silently fall back to truncated P-256.
            assert_mechanism_invalid(b.ecdsa_p384_sign_prehashed(b"", b""));
            assert_mechanism_invalid(b.ecdsa_p384_verify_prehashed(b"", b"", b""));
        }

        #[test]
        fn all_encryption_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.aes_256_gcm_encrypt(b"", b""));
            assert_not_supported(b.aes_256_gcm_decrypt(b"", b""));
            assert_not_supported(b.aes_cbc_encrypt(b"", b"", b""));
            assert_not_supported(b.aes_cbc_decrypt(b"", b"", b""));
            assert_not_supported(b.aes_ctr_encrypt(b"", b"", b""));
            assert_not_supported(b.aes_ctr_decrypt(b"", b"", b""));
            assert_not_supported(b.rsa_oaep_encrypt(b"", b"", b"", OaepHash::Sha256));
            assert_not_supported(b.rsa_oaep_decrypt(b"", b"", OaepHash::Sha256));
        }

        #[test]
        fn all_keygen_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.generate_aes_key(32, false));
            assert_not_supported(b.generate_aes_key(16, true));
            assert_not_supported(b.generate_rsa_key_pair(2048, false));
            assert_not_supported(b.generate_rsa_key_pair(4096, true));
            assert_not_supported(b.generate_ec_p256_key_pair());
            assert_not_supported(b.generate_ec_p384_key_pair());
        }

        #[test]
        fn all_digest_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.compute_digest(0, b""));
            assert_not_supported(b.compute_digest(0x0000_0250, b"test"));
            assert_not_supported(b.digest_output_len(0));
            assert_not_supported(b.digest_output_len(0x0000_0250));
            assert_not_supported(b.create_hasher(0));
        }

        #[test]
        fn all_key_wrap_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.aes_key_wrap(b"", b"", false));
            assert_not_supported(b.aes_key_wrap(&[0u8; 32], &[0u8; 16], true));
            assert_not_supported(b.aes_key_unwrap(b"", b"", false));
        }

        #[test]
        fn all_key_derivation_operations_return_not_supported() {
            let b = backend();
            assert_not_supported(b.ecdh_p256(b"", b"", None));
            assert_not_supported(b.ecdh_p256(b"", b"", Some(32)));
            assert_not_supported(b.ecdh_p384(b"", b"", None));
        }

        #[test]
        fn stub_encryption_with_nonempty_data() {
            let b = backend();
            let key = [0u8; 32];
            let iv = [0u8; 16];
            let data = b"hello world";
            assert_not_supported(b.aes_256_gcm_encrypt(&key, data));
            assert_not_supported(b.aes_256_gcm_decrypt(&key, data));
            assert_not_supported(b.aes_cbc_encrypt(&key, &iv, data));
            assert_not_supported(b.aes_cbc_decrypt(&key, &iv, data));
            assert_not_supported(b.aes_ctr_encrypt(&key, &iv, data));
            assert_not_supported(b.aes_ctr_decrypt(&key, &iv, data));
        }

        #[test]
        fn stub_signing_with_all_hash_algs() {
            let b = backend();
            for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
                assert_not_supported(b.rsa_pkcs1v15_sign(b"key", b"data", Some(alg)));
                assert_not_supported(b.rsa_pss_sign(b"key", b"data", alg));
                assert_not_supported(b.rsa_pkcs1v15_sign_prehashed(b"key", b"digest", alg));
                // Audit (WRONG-ALG-FORWARD): RSA-PSS prehashed sign hard-refuses
                // with `MechanismInvalid` to prevent a wrong-algorithm signature.
                assert_mechanism_invalid(b.rsa_pss_sign_prehashed(b"key", b"digest", alg));
            }
        }

        #[test]
        fn stub_keygen_with_various_sizes() {
            let b = backend();
            for size in [16, 24, 32] {
                assert_not_supported(b.generate_aes_key(size, false));
            }
            for bits in [2048, 3072, 4096] {
                assert_not_supported(b.generate_rsa_key_pair(bits, false));
            }
        }
    }

    // ── Ed25519 tests (always MechanismInvalid, regardless of hw) ───────

    #[test]
    fn ed25519_sign_mechanism_invalid() {
        assert_mechanism_invalid(backend().ed25519_sign(b"", b""));
    }

    #[test]
    fn ed25519_sign_mechanism_invalid_with_data() {
        assert_mechanism_invalid(backend().ed25519_sign(b"key", b"data"));
    }

    #[test]
    fn ed25519_verify_mechanism_invalid() {
        assert_mechanism_invalid(backend().ed25519_verify(b"", b"", b""));
    }

    #[test]
    fn ed25519_verify_mechanism_invalid_with_data() {
        assert_mechanism_invalid(backend().ed25519_verify(b"key", b"data", b"sig"));
    }

    #[test]
    fn generate_ed25519_key_pair_mechanism_invalid() {
        assert_mechanism_invalid(backend().generate_ed25519_key_pair());
    }

    // ── Error module integration ────────────────────────────────────────

    #[test]
    fn error_module_status_codes_accessible() {
        use crate::error::*;
        assert!(matches!(
            tss2_rc_to_error(TPM2_RC_KEY),
            HsmError::KeyHandleInvalid
        ));
        assert!(matches!(
            tss2_rc_to_error(TPM2_RC_SIGNATURE),
            HsmError::SignatureInvalid
        ));
        assert!(matches!(
            tss2_rc_to_error(TPM2_RC_SCHEME),
            HsmError::MechanismInvalid
        ));
        assert!(matches!(
            tss2_rc_to_error(TPM2_RC_MEMORY),
            HsmError::DeviceMemory
        ));
        assert!(matches!(
            tss2_rc_to_error(TPM2_RC_LOCKOUT),
            HsmError::PinLocked
        ));
        assert!(matches!(
            tss2_rc_to_error(TPM2_RC_SIZE),
            HsmError::DataLenRange
        ));
    }

    #[test]
    fn check_tss2_rc_ok_returns_ok() {
        use crate::error::*;
        assert!(check_tss2_rc(TSS2_RC_SUCCESS).is_ok());
    }

    #[test]
    fn check_tss2_rc_error_returns_err() {
        use crate::error::*;
        assert!(check_tss2_rc(TPM2_RC_FAILURE).is_err());
        assert!(check_tss2_rc(TPM2_RC_KEY).is_err());
        assert!(check_tss2_rc(TPM2_RC_LOCKOUT).is_err());
        assert!(check_tss2_rc(TPM2_RC_RETRY).is_err());
    }

    // ── Backend trait object safety ─────────────────────────────────────

    #[test]
    fn backend_can_be_used_as_trait_object() {
        std::env::set_var("CRATON_HSM_ALLOW_STUB_INFINEON", "1");
        let b = InfineonTpmBackend::new();
        let _dyn_ref: &dyn CryptoBackend = &b;
    }

    #[test]
    fn backend_can_be_boxed_as_trait_object() {
        std::env::set_var("CRATON_HSM_ALLOW_STUB_INFINEON", "1");
        let b = InfineonTpmBackend::new();
        let _boxed: Box<dyn CryptoBackend> = Box::new(b);
    }

    // ── Multiple instantiation ──────────────────────────────────────────

    #[test]
    fn multiple_backends_can_coexist() {
        std::env::set_var("CRATON_HSM_ALLOW_STUB_INFINEON", "1");
        let a = InfineonTpmBackend::new();
        let b = InfineonTpmBackend::new();
        let c = InfineonTpmBackend::default();
        drop(a);
        drop(b);
        drop(c);
    }

    // ── FFI type tests ──────────────────────────────────────────────────

    #[test]
    fn validate_tpm2b_size_within_bounds() {
        use crate::ffi::validate_tpm2b_size;
        assert!(validate_tpm2b_size(0, 64));
        assert!(validate_tpm2b_size(32, 64));
        assert!(validate_tpm2b_size(64, 64));
        assert!(!validate_tpm2b_size(65, 64));
    }

    #[test]
    fn sentinel_handles_have_expected_values() {
        use crate::ffi::*;
        assert_eq!(ESYS_TR_NONE, 0x0000_0FFF);
        assert_eq!(ESYS_TR_PASSWORD, 0x0000_0FF9);
        assert_eq!(TPM2_RH_OWNER, 0x4000_0001);
        assert_eq!(TPM2_RH_NULL, 0x4000_0007);
    }

    // ── Input validation ────────────────────────────────────────────────

    #[test]
    fn signing_returns_error_for_empty_input() {
        let b = backend();
        assert_is_error(b.rsa_pkcs1v15_sign(b"", b"", Some(HashAlg::Sha256)));
        assert_is_error(b.ecdsa_p256_sign(b"", b""));
        assert_is_error(b.ecdsa_p384_sign(b"", b""));
    }

    #[test]
    fn verification_returns_error_for_empty_input() {
        let b = backend();
        assert_is_error(b.rsa_pkcs1v15_verify(b"", b"", b"", b"", Some(HashAlg::Sha256)));
        assert_is_error(b.ecdsa_p256_verify(b"", b"", b""));
        assert_is_error(b.ecdsa_p384_verify(b"", b"", b""));
    }

    #[test]
    fn keygen_returns_error_for_invalid_aes_size() {
        let b = backend();
        assert_is_error(b.generate_aes_key(15, false));
        assert_is_error(b.generate_aes_key(0, false));
        assert_is_error(b.generate_aes_key(33, false));
    }

    #[test]
    fn keygen_returns_error_for_invalid_rsa_bits() {
        let b = backend();
        assert_is_error(b.generate_rsa_key_pair(1024, false));
        assert_is_error(b.generate_rsa_key_pair(0, false));
    }

    #[test]
    fn digest_returns_error_for_unknown_mechanism() {
        let b = backend();
        assert_is_error(b.compute_digest(0xDEAD, b""));
        assert_is_error(b.digest_output_len(0xDEAD));
    }

    // ── Context tests (hw-gated compile only) ───────────────────────────

    #[cfg(feature = "hw")]
    mod context_tests {
        use crate::context::EsapiContext;

        // Note: These tests require an actual TPM device or simulator.
        // They serve as compile-time verification that the context API
        // is correctly structured.

        #[test]
        fn context_type_is_send() {
            fn assert_send<T: Send>() {}
            assert_send::<EsapiContext>();
        }

        // EsapiContext is deliberately !Sync (contains PhantomData<Cell<()>>).
        // This is intentional for thread-safety.
    }
}
