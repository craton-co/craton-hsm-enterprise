// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! FFI bindings to the NXP HSE SDK.
//!
//! When the `hw` feature is enabled, this module declares `extern "C"` symbols
//! that link against the NXP HSE host-library. When `hw` is **not** enabled
//! (the default), only the status-code type alias is provided so the rest of
//! the crate can still compile.
//!
//! # Safety Requirements for FFI Functions
//!
//! All pointer parameters follow these conventions unless otherwise documented:
//!
//! - **Input pointers** (`*const u8`): must be non-null and valid for reads of
//!   `*_len` bytes when the associated length is > 0. May be null only if the
//!   length is 0.
//! - **Output buffer pointers** (`*mut u8`): must be non-null and point to a
//!   buffer large enough to hold the output. On entry, `*output_len` must
//!   contain the buffer capacity; on return it contains the number of bytes
//!   written.
//! - **Output length pointers** (`*mut u32`): must be non-null and writable.
//! - All pointers must remain valid for the duration of the call (no
//!   concurrent modification from other threads).
//!
//! Callers in `craton-hsm-nxp` are responsible for ensuring these invariants
//! before calling any `unsafe` FFI function.

#[allow(unsafe_code)]
#[cfg(feature = "hw")]
mod hw_bindings {
    use crate::error::HseStatus;

    extern "C" {
        /// Initialize the HSE Messaging Unit (MU) interface.
        pub fn hse_srv_init() -> HseStatus;

        /// De-initialize the HSE MU interface, releasing resources.
        pub fn hse_srv_deinit() -> HseStatus;

        /// Import a key into the HSE key catalog.
        pub fn hse_key_import(
            key_handle: u32,
            key_type: u32,
            key_data: *const u8,
            key_len: u32,
        ) -> HseStatus;

        /// Generate a key inside the HSE.
        pub fn hse_key_generate(key_handle: u32, key_type: u32, key_bits: u32) -> HseStatus;

        /// Release a key handle from the HSE catalog so the slot can be
        /// reused. Mirrors `hse_key_import` minus the data buffer args.
        // TODO: confirm symbol name with NXP SDK header
        pub fn hse_key_delete(key_handle: u32) -> HseStatus;

        /// RSA signature generation.
        pub fn hse_rsa_sign(
            key_handle: u32,
            scheme: u32,
            input: *const u8,
            input_len: u32,
            sig_out: *mut u8,
            sig_out_len: *mut u32,
        ) -> HseStatus;

        /// RSA signature verification.
        pub fn hse_rsa_verify(
            key_handle: u32,
            scheme: u32,
            input: *const u8,
            input_len: u32,
            sig: *const u8,
            sig_len: u32,
        ) -> HseStatus;

        /// ECDSA signature generation.
        pub fn hse_ecdsa_sign(
            key_handle: u32,
            curve_id: u32,
            input: *const u8,
            input_len: u32,
            sig_out: *mut u8,
            sig_out_len: *mut u32,
        ) -> HseStatus;

        /// ECDSA signature verification.
        pub fn hse_ecdsa_verify(
            key_handle: u32,
            curve_id: u32,
            input: *const u8,
            input_len: u32,
            sig: *const u8,
            sig_len: u32,
        ) -> HseStatus;

        /// AES encryption.
        pub fn hse_aes_encrypt(
            key_handle: u32,
            mode: u32,
            iv: *const u8,
            iv_len: u32,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: *mut u32,
        ) -> HseStatus;

        /// AES decryption.
        pub fn hse_aes_decrypt(
            key_handle: u32,
            mode: u32,
            iv: *const u8,
            iv_len: u32,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: *mut u32,
        ) -> HseStatus;

        /// Hash (digest) computation.
        pub fn hse_hash_compute(
            hash_algo: u32,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: *mut u32,
        ) -> HseStatus;
    }
}

#[cfg(feature = "hw")]
pub use hw_bindings::*;

// ---------------------------------------------------------------------------
// Non-`hw` stubs (audit finding H7)
//
// When the `hw` feature is off there is no NXP HSE host library to link
// against. Historically this module exposed no symbols at all under that
// configuration, which meant a caller who reached into `ffi::` by mistake
// would get a "not in scope" *compile* error — useful, but brittle: any
// refactor that keeps the symbol references behind a matching
// `cfg(feature = "hw")` gate would hide the mistake until hardware came
// back online.
//
// The stubs below give every FFI function a concrete non-`hw` body that
// logs loudly via `tracing::error!` and returns [`HSE_ERR_NOT_IMPLEMENTED`]
// so downstream callers can convert it via [`crate::error::check_hse_status`]
// into [`HsmError::FunctionNotSupported`] with a clear diagnostic trail.
//
// These stubs are **not** marked `extern "C"` — they are plain Rust fns
// with matching signatures. Any code that wires them up should go through
// the [`NxpHseBackend`] trait impl, which already routes non-`hw` requests
// to `FunctionNotSupported`.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "hw"))]
mod no_hw_stubs {
    use crate::error::{HseStatus, HSE_ERR_NOT_IMPLEMENTED};

    fn log_stub_called(fname: &'static str) {
        tracing::error!(
            target: "craton_hsm_nxp::ffi",
            function = fname,
            "NXP HSE FFI stub called without `hw` feature — returning NotImplemented"
        );
    }

    /// Stub: initialise the HSE MU. Returns [`HSE_ERR_NOT_IMPLEMENTED`].
    pub fn hse_srv_init() -> HseStatus {
        log_stub_called("hse_srv_init");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: de-initialise the HSE MU.
    pub fn hse_srv_deinit() -> HseStatus {
        log_stub_called("hse_srv_deinit");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: import a key into the HSE catalog.
    pub fn hse_key_import(
        _key_handle: u32,
        _key_type: u32,
        _key_data: *const u8,
        _key_len: u32,
    ) -> HseStatus {
        log_stub_called("hse_key_import");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: generate a key inside the HSE.
    pub fn hse_key_generate(_key_handle: u32, _key_type: u32, _key_bits: u32) -> HseStatus {
        log_stub_called("hse_key_generate");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: release a key handle from the HSE catalog.
    pub fn hse_key_delete(_key_handle: u32) -> HseStatus {
        log_stub_called("hse_key_delete");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: RSA signature generation.
    pub fn hse_rsa_sign(
        _key_handle: u32,
        _scheme: u32,
        _input: *const u8,
        _input_len: u32,
        _sig_out: *mut u8,
        _sig_out_len: *mut u32,
    ) -> HseStatus {
        log_stub_called("hse_rsa_sign");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: RSA signature verification.
    pub fn hse_rsa_verify(
        _key_handle: u32,
        _scheme: u32,
        _input: *const u8,
        _input_len: u32,
        _sig: *const u8,
        _sig_len: u32,
    ) -> HseStatus {
        log_stub_called("hse_rsa_verify");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: ECDSA signature generation.
    pub fn hse_ecdsa_sign(
        _key_handle: u32,
        _curve_id: u32,
        _input: *const u8,
        _input_len: u32,
        _sig_out: *mut u8,
        _sig_out_len: *mut u32,
    ) -> HseStatus {
        log_stub_called("hse_ecdsa_sign");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: ECDSA signature verification.
    pub fn hse_ecdsa_verify(
        _key_handle: u32,
        _curve_id: u32,
        _input: *const u8,
        _input_len: u32,
        _sig: *const u8,
        _sig_len: u32,
    ) -> HseStatus {
        log_stub_called("hse_ecdsa_verify");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: AES encryption.
    pub fn hse_aes_encrypt(
        _key_handle: u32,
        _mode: u32,
        _iv: *const u8,
        _iv_len: u32,
        _input: *const u8,
        _input_len: u32,
        _output: *mut u8,
        _output_len: *mut u32,
    ) -> HseStatus {
        log_stub_called("hse_aes_encrypt");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: AES decryption.
    pub fn hse_aes_decrypt(
        _key_handle: u32,
        _mode: u32,
        _iv: *const u8,
        _iv_len: u32,
        _input: *const u8,
        _input_len: u32,
        _output: *mut u8,
        _output_len: *mut u32,
    ) -> HseStatus {
        log_stub_called("hse_aes_decrypt");
        HSE_ERR_NOT_IMPLEMENTED
    }

    /// Stub: hash (digest) computation.
    pub fn hse_hash_compute(
        _hash_algo: u32,
        _input: *const u8,
        _input_len: u32,
        _output: *mut u8,
        _output_len: *mut u32,
    ) -> HseStatus {
        log_stub_called("hse_hash_compute");
        HSE_ERR_NOT_IMPLEMENTED
    }
}

#[cfg(not(feature = "hw"))]
pub use no_hw_stubs::*;
