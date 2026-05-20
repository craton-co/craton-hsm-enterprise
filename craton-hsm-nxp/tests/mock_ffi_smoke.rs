// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! FFI mocking smoke test — audit finding NXP-3.
//!
//! The backend now dispatches every crypto operation through the
//! [`HseBackend`](craton_hsm_nxp::HseBackend) trait (see
//! `src/backend_trait.rs`). This test exercises the same high-level
//! [`CryptoBackend`] surface the FFI path uses, but driven by
//! [`MockHseBackend`](craton_hsm_nxp::backend_trait::MockHseBackend) so we
//! can verify:
//!
//! - Success cases (mock-returns-success).
//! - Error-code mapping end-to-end (mock-returns-error, including every
//!   `HSE_ERR_*` variant routed through `hse_status_to_error`).
//! - Length-clamping path — the mock can return an oversize vector and we
//!   verify the backend does *not* truncate it (that responsibility lives
//!   in the real FFI impl). The mock is a thin pass-through; the error
//!   mapping is covered at the `check_hse_status` level.
//! - Concurrent access — `Arc<dyn HseBackend + Send + Sync>` means the
//!   backend can be shared across threads with no data races.
//!
//! # Running
//!
//! ```shell
//! cargo test -p craton-hsm-nxp --features test-stub
//! ```

#[cfg(not(feature = "hw"))]
use craton_hsm::crypto::backend::CryptoBackend;
#[cfg(not(feature = "hw"))]
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm::error::HsmError;
#[cfg(not(feature = "hw"))]
use craton_hsm_nxp::backend_trait::{MockHseBackend, MockResponse};
use craton_hsm_nxp::error::{
    check_hse_status, hse_status_to_error, HSE_ERR_BUSY, HSE_ERR_DATA_LEN, HSE_ERR_GENERAL,
    HSE_ERR_INVALID_PARAM, HSE_ERR_KEY_INVALID, HSE_ERR_KEY_NOT_FOUND, HSE_ERR_MEMORY,
    HSE_ERR_NOT_IMPLEMENTED, HSE_ERR_NOT_SUPPORTED, HSE_ERR_TIMEOUT, HSE_ERR_VERIFY_FAILED, HSE_OK,
};
#[cfg(not(feature = "hw"))]
use craton_hsm_nxp::NxpHseBackend;
#[cfg(not(feature = "hw"))]
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Existing error-code mapping coverage (retained — still worth running).
// ---------------------------------------------------------------------------

#[test]
fn hse_ok_is_success() {
    assert!(check_hse_status(HSE_OK).is_ok());
}

#[test]
fn every_defined_error_code_maps_to_a_concrete_hsm_error() {
    let table: &[(u32, HsmError, &str)] = &[
        (
            HSE_ERR_KEY_NOT_FOUND,
            HsmError::KeyHandleInvalid,
            "KEY_NOT_FOUND",
        ),
        (
            HSE_ERR_KEY_INVALID,
            HsmError::KeyHandleInvalid,
            "KEY_INVALID",
        ),
        (
            HSE_ERR_INVALID_PARAM,
            HsmError::MechanismParamInvalid,
            "INVALID_PARAM",
        ),
        (
            HSE_ERR_NOT_SUPPORTED,
            HsmError::FunctionNotSupported,
            "NOT_SUPPORTED",
        ),
        (
            HSE_ERR_NOT_IMPLEMENTED,
            HsmError::FunctionNotSupported,
            "NOT_IMPLEMENTED",
        ),
        (HSE_ERR_MEMORY, HsmError::DeviceMemory, "MEMORY"),
        (
            HSE_ERR_VERIFY_FAILED,
            HsmError::SignatureInvalid,
            "VERIFY_FAILED",
        ),
        (HSE_ERR_BUSY, HsmError::GeneralError, "BUSY"),
        (HSE_ERR_TIMEOUT, HsmError::GeneralError, "TIMEOUT"),
        (HSE_ERR_DATA_LEN, HsmError::DataLenRange, "DATA_LEN"),
        (HSE_ERR_GENERAL, HsmError::GeneralError, "GENERAL"),
    ];

    for (status, expected, name) in table {
        let got = hse_status_to_error(*status);
        assert_eq!(
            std::mem::discriminant(&got),
            std::mem::discriminant(expected),
            "{name} (0x{status:08X}) mapped to {got:?}, expected {expected:?}"
        );
        let via_check = check_hse_status(*status).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&via_check),
            std::mem::discriminant(expected),
            "{name} check_hse_status yielded {via_check:?}, expected {expected:?}"
        );
    }
}

#[test]
fn unknown_status_maps_to_general_error() {
    for status in [0xDEAD_BEEFu32, 0x0000_9999, 0x7FFF_FFFF] {
        assert!(matches!(
            hse_status_to_error(status),
            HsmError::GeneralError
        ));
    }
}

/// Without the `hw` feature, the FFI stubs must return
/// `HSE_ERR_NOT_IMPLEMENTED` (audit finding H7).
#[cfg(not(feature = "hw"))]
#[test]
fn ffi_stubs_return_not_implemented() {
    use craton_hsm_nxp::ffi;

    assert_eq!(ffi::hse_srv_init(), HSE_ERR_NOT_IMPLEMENTED);
    assert_eq!(ffi::hse_srv_deinit(), HSE_ERR_NOT_IMPLEMENTED);
    assert_eq!(
        ffi::hse_key_generate(0x1000, 0, 256),
        HSE_ERR_NOT_IMPLEMENTED
    );
}

// ---------------------------------------------------------------------------
// Trait-based mock tests — audit finding NXP-3 full coverage.
// ---------------------------------------------------------------------------
//
// Audit 2026-05-17: `NxpHseBackend::with_backend` is gated
// `not(feature = "hw")` so that co-enabling `hw,test-stub` cannot leak
// the mock-injection seam into a production build. The trait-mock
// section below requires that seam, so it is similarly cfg-gated. When
// `hw` is enabled alongside `test-stub`, the early-error mapping is
// already exercised by the production fail-fast (lib.rs hw_impl) and
// the static error-code coverage above is sufficient.

/// Build a backend wrapping a fresh mock. Returns both so the test can
/// drive the mock and query the resulting behaviour.
#[cfg(not(feature = "hw"))]
fn backend_with_mock(mock: Arc<MockHseBackend>) -> NxpHseBackend {
    // Wrap the Arc in a newtype adapter so `NxpHseBackend::with_backend`
    // sees a value that implements `HseBackend`. `Arc<MockHseBackend>`
    // does not implement the trait itself; we use a thin wrapper.
    struct ArcAdapter(Arc<MockHseBackend>);
    impl craton_hsm_nxp::HseBackend for ArcAdapter {
        fn rsa_sign(
            &self,
            k: u32,
            s: u32,
            h: u32,
            d: &[u8],
        ) -> craton_hsm::error::HsmResult<Vec<u8>> {
            self.0.rsa_sign(k, s, h, d)
        }
        fn rsa_verify(
            &self,
            k: u32,
            s: u32,
            h: u32,
            d: &[u8],
            sig: &[u8],
        ) -> craton_hsm::error::HsmResult<bool> {
            self.0.rsa_verify(k, s, h, d, sig)
        }
        fn ecdsa_sign(
            &self,
            k: u32,
            c: u32,
            h: u32,
            d: &[u8],
        ) -> craton_hsm::error::HsmResult<Vec<u8>> {
            self.0.ecdsa_sign(k, c, h, d)
        }
        fn ecdsa_verify(
            &self,
            k: u32,
            c: u32,
            h: u32,
            d: &[u8],
            sig: &[u8],
        ) -> craton_hsm::error::HsmResult<bool> {
            self.0.ecdsa_verify(k, c, h, d, sig)
        }
        fn key_import_public(
            &self,
            key_type: u32,
            key_data: &[u8],
        ) -> craton_hsm::error::HsmResult<u32> {
            self.0.key_import_public(key_type, key_data)
        }
        fn key_import_private(
            &self,
            key_type: u32,
            key_data: &[u8],
        ) -> craton_hsm::error::HsmResult<u32> {
            self.0.key_import_private(key_type, key_data)
        }
        fn aes_encrypt(
            &self,
            k: u32,
            m: u32,
            iv: &[u8],
            p: &[u8],
        ) -> craton_hsm::error::HsmResult<Vec<u8>> {
            self.0.aes_encrypt(k, m, iv, p)
        }
        fn aes_decrypt(
            &self,
            k: u32,
            m: u32,
            iv: &[u8],
            c: &[u8],
        ) -> craton_hsm::error::HsmResult<Vec<u8>> {
            self.0.aes_decrypt(k, m, iv, c)
        }
        fn hash(&self, a: u32, d: &[u8]) -> craton_hsm::error::HsmResult<Vec<u8>> {
            self.0.hash(a, d)
        }
        fn key_import(&self, t: u32, d: &[u8]) -> craton_hsm::error::HsmResult<u32> {
            self.0.key_import(t, d)
        }
        fn key_generate(&self, h: u32, t: u32, b: u32) -> craton_hsm::error::HsmResult<()> {
            self.0.key_generate(h, t, b)
        }
        // The trait's default `key_delete` returns
        // `FunctionNotSupported` (audit hardening: a no-op default
        // would silently break the RAII guarantee of `HseKeyHandle`).
        // The mock provides a real impl, so we just delegate here.
        fn key_delete(&self, h: u32) -> craton_hsm::error::HsmResult<()> {
            self.0.key_delete(h)
        }
    }
    NxpHseBackend::with_backend(ArcAdapter(mock))
}

/// Trait-based mock tests. Under the `test-stub` feature (which this
/// integration test enables via `Cargo.toml`'s `required-features`) and
/// only when `hw` is **not** also enabled, `NxpHseBackend` dispatches
/// `CryptoBackend` methods through the installed `HseBackend`. Tests
/// inject a `MockHseBackend` wrapper and drive the full path. See the
/// `with_backend` audit comment in `lib.rs` for the rationale behind
/// the `not(feature = "hw")` guard.
#[cfg(not(feature = "hw"))]
mod trait_mock_tests {
    use super::*;

    #[test]
    fn mock_returns_success_end_to_end_rsa_sign() {
        let mock = Arc::new(MockHseBackend::new());
        mock.queue_key_import(MockResponse::Handle(0x0100_0042));
        mock.queue_rsa_sign(MockResponse::Bytes(vec![0xAB; 256]));

        let b = backend_with_mock(mock.clone());
        let sig = b
            .rsa_pkcs1v15_sign(b"key-material", b"data", Some(HashAlg::Sha256))
            .expect("expected mock to succeed");
        assert_eq!(sig, vec![0xAB; 256]);

        let counts = mock.call_counts();
        assert_eq!(counts.key_import, 1);
        assert_eq!(counts.rsa_sign, 1);
    }

    #[test]
    fn mock_returns_error_every_hsm_error_variant_propagates() {
        // Drive each error variant through `rsa_sign` to prove the error
        // propagates end-to-end without being mangled or swallowed.
        let errors = [
            HsmError::KeyHandleInvalid,
            HsmError::MechanismParamInvalid,
            HsmError::FunctionNotSupported,
            HsmError::DeviceMemory,
            HsmError::SignatureInvalid,
            HsmError::GeneralError,
            HsmError::DataLenRange,
        ];
        for err in errors {
            let mock = Arc::new(MockHseBackend::new());
            mock.queue_key_import(MockResponse::Handle(0x0100_0042));
            mock.queue_rsa_sign(MockResponse::Err(err.clone()));

            let b = backend_with_mock(mock);
            let got = b.rsa_pkcs1v15_sign(b"key", b"data", Some(HashAlg::Sha256));
            let got_err = got.expect_err("expected error propagation");
            assert_eq!(
                std::mem::discriminant(&got_err),
                std::mem::discriminant(&err),
                "expected {err:?}, got {got_err:?}"
            );
        }
    }

    #[test]
    fn mock_returns_bad_length_backend_passes_through() {
        // The mock returns an oversized signature. The dispatching layer
        // does NOT truncate — that is the real FFI impl's responsibility
        // (it clamps against the HSE's declared buffer capacity). Here
        // we verify the mock path returns what was queued, unmodified.
        let mock = Arc::new(MockHseBackend::new());
        mock.queue_key_import(MockResponse::Handle(0x0100_0042));
        let oversize = vec![0xFF; 1024]; // > MAX_RSA_SIG_LEN (512)
        mock.queue_rsa_sign(MockResponse::Bytes(oversize.clone()));

        let b = backend_with_mock(mock);
        let sig = b
            .rsa_pkcs1v15_sign(b"key", b"data", Some(HashAlg::Sha256))
            .expect("mock always succeeds when queued");
        assert_eq!(sig, oversize);
    }

    #[test]
    fn mock_verify_true_and_false_both_propagate() {
        for outcome in [true, false] {
            let mock = Arc::new(MockHseBackend::new());
            mock.queue_key_import(MockResponse::Handle(0x0100_0099));
            mock.queue_rsa_verify(MockResponse::Bool(outcome));
            let b = backend_with_mock(mock);
            let got = b
                .rsa_pkcs1v15_verify(b"mod", b"\x01\x00\x01", b"data", b"sig", None)
                .expect("expected bool outcome");
            assert_eq!(got, outcome);
        }
    }

    #[test]
    fn mock_aes_cbc_round_trip() {
        let mock = Arc::new(MockHseBackend::new());
        mock.queue_key_import(MockResponse::Handle(0x0200_0001));
        mock.queue_aes_encrypt(MockResponse::Bytes(vec![0xCC; 32]));
        mock.queue_key_import(MockResponse::Handle(0x0200_0002));
        mock.queue_aes_decrypt(MockResponse::Bytes(
            b"plaintext-32-bytes-xxxxxxxxxxxxx".to_vec(),
        ));

        let b = backend_with_mock(mock.clone());
        let ct = b
            .aes_cbc_encrypt(&[0u8; 32], &[0u8; 16], b"plaintext-32-bytes-xxxxxxxxxxxxx")
            .expect("encrypt ok");
        assert_eq!(ct, vec![0xCC; 32]);
        let pt = b
            .aes_cbc_decrypt(&[0u8; 32], &[0u8; 16], &ct)
            .expect("decrypt ok");
        assert_eq!(pt, b"plaintext-32-bytes-xxxxxxxxxxxxx");

        let counts = mock.call_counts();
        assert_eq!(counts.aes_encrypt, 1);
        assert_eq!(counts.aes_decrypt, 1);
        assert_eq!(counts.key_import, 2);
    }

    #[test]
    #[ignore = "Audit V3: hw_impl no longer routes compute_digest through HseBackend (HSE has no streaming hash); see nxp lib.rs `create_hasher` doc"]
    fn mock_hash_returns_digest() {
        let mock = Arc::new(MockHseBackend::new());
        mock.queue_hash(MockResponse::Bytes(vec![0x55; 32]));
        let b = backend_with_mock(mock);
        // CKM_SHA256
        let d = b.compute_digest(0x0000_0250, b"hello").expect("hash ok");
        assert_eq!(d, vec![0x55; 32]);
    }

    /// Concurrent access is serialised per method via the Mutex inside the
    /// mock. Two threads calling `rsa_sign` simultaneously must both see
    /// their own response from the queue without interleaving/tearing.
    #[test]
    fn mock_concurrent_access_is_serialised() {
        let mock = Arc::new(MockHseBackend::new());
        // Queue responses for 4 sign calls (2 threads * 2 signs each).
        for _ in 0..4 {
            mock.queue_key_import(MockResponse::Handle(0x0300_0000));
            mock.queue_rsa_sign(MockResponse::Bytes(vec![0x11; 64]));
        }

        let backend = Arc::new(backend_with_mock(mock.clone()));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let b = backend.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..2 {
                    let sig = b
                        .rsa_pkcs1v15_sign(b"key", b"data", Some(HashAlg::Sha256))
                        .expect("concurrent sign ok");
                    assert_eq!(sig, vec![0x11; 64]);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread panic");
        }

        let counts = mock.call_counts();
        assert_eq!(counts.rsa_sign, 4, "expected 4 sign calls across threads");
        assert_eq!(counts.key_import, 4, "expected 4 import calls");
    }
}
