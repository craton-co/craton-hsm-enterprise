// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! HSE backend trait -- the dependency-injection seam between the
//! high-level CryptoBackend impl and the underlying FFI layer.
//!
//! # Architecture seam
//!
//! `NxpHseBackend` (in `lib.rs`) is the workspace-facing
//! `CryptoBackend` implementation. It does **not** call NXP HSE FFI
//! directly; instead it dispatches every crypto operation through the
//! [`HseBackend`] trait defined here. This is the
//! dependency-injection seam:
//!
//! ```text
//!     NxpHseBackend  (CryptoBackend impl, no `unsafe`)
//!           |
//!           v
//!     dyn HseBackend (trait, this file)
//!           |
//!     +-----+-----+
//!     |           |
//!     v           v
//! HseFfiBackend  MockHseBackend
//! (this file,   (this file,
//!  `unsafe`     test-only,
//!  FFI calls)   queues canned
//!                responses)
//! ```
//!
//! `HseFfiBackend` is the **one production implementation** that
//! actually invokes `ffi::hse_*` (`unsafe`). All `unsafe` in this
//! crate lives in that impl block and in the FFI extern declarations
//! themselves. The workspace's "FFI migration N/N complete" status
//! refers to the fact that every HSE FFI call is routed through this
//! trait, not that the `unsafe` calls themselves were eliminated —
//! the seam between `HseFfiBackend` and the raw C bindings is the
//! architecturally correct place for them.
//!
//! `MockHseBackend` (test-stub only) implements the same trait with
//! programmable canned responses, allowing the integration tests to
//! exercise every error path end-to-end without a real HSE.

use craton_hsm::error::{HsmError, HsmResult};
use std::sync::Arc;

/// Minimum P-256 raw (r||s) signature length.
pub const MIN_P256_SIG_RAW: usize = 64;
/// Minimum P-256 DER signature length (SEQUENCE of two INTEGERs).
///
/// Currently informational. The dispatching layer enforces the raw-form
/// minimum ([`MIN_P256_SIG_RAW`]) since the HSE firmware returns r||s,
/// not DER. Kept as a documented constant for callers that need to size
/// DER buffers.
#[allow(dead_code)]
pub const MIN_P256_SIG_DER: usize = 70;
/// Minimum P-384 raw (r||s) signature length.
pub const MIN_P384_SIG_RAW: usize = 96;
/// SHA-256 digest length (exactly).
pub const MIN_SHA256_DIGEST: usize = 32;

/// Trait covering every FFI call the HSE-backed crypto paths make.
pub trait HseBackend: Send + Sync {
    /// RSA sign. hash_id propagates the HSE hash identifier (V3 fix).
    fn rsa_sign(
        &self,
        key_handle: u32,
        scheme: u32,
        hash_id: u32,
        data: &[u8],
    ) -> HsmResult<Vec<u8>>;
    /// RSA verify.
    fn rsa_verify(
        &self,
        key_handle: u32,
        scheme: u32,
        hash_id: u32,
        data: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;
    /// ECDSA sign.
    fn ecdsa_sign(
        &self,
        key_handle: u32,
        curve_id: u32,
        hash_id: u32,
        data: &[u8],
    ) -> HsmResult<Vec<u8>>;
    /// ECDSA verify.
    fn ecdsa_verify(
        &self,
        key_handle: u32,
        curve_id: u32,
        hash_id: u32,
        data: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;
    /// AES encrypt.
    fn aes_encrypt(
        &self,
        key_handle: u32,
        mode: u32,
        iv: &[u8],
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>>;
    /// AES decrypt.
    fn aes_decrypt(
        &self,
        key_handle: u32,
        mode: u32,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> HsmResult<Vec<u8>>;
    /// Compute hash digest.
    fn hash(&self, hash_algo: u32, data: &[u8]) -> HsmResult<Vec<u8>>;
    /// Import a public key (V2 fix).
    fn key_import_public(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32>;
    /// Import a private key.
    fn key_import_private(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32>;
    /// Backwards-compatible alias.
    #[doc(hidden)]
    fn key_import(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32> {
        self.key_import_public(key_type, key_data)
    }
    /// Generate a key in the HSE firmware.
    fn key_generate(&self, key_handle: u32, key_type: u32, key_bits: u32) -> HsmResult<()>;
    /// Delete a key handle (V2: RAII).
    ///
    /// Default impl returns `FunctionNotSupported` rather than silently
    /// succeeding: a no-op default would break the RAII guarantee of
    /// [`crate::HseKeyHandle`] for any custom backend that forgot to
    /// implement this method. Implementors MUST override this to
    /// actually release the slot — even mock backends should return
    /// `Ok(())` explicitly so the call is intentional.
    fn key_delete(&self, key_handle: u32) -> HsmResult<()> {
        let _ = key_handle;
        tracing::error!(
            target: "craton_hsm_nxp::backend_trait",
            "HseBackend::key_delete: default impl invoked — backend must override; \
             returning FunctionNotSupported so the RAII Drop logs the leak"
        );
        Err(HsmError::FunctionNotSupported)
    }
}

/// Blanket impl so Arc<T: HseBackend> is itself an HseBackend (perf: replaces ArcAdapter).
impl<T: HseBackend + ?Sized> HseBackend for Arc<T> {
    fn rsa_sign(
        &self,
        key_handle: u32,
        scheme: u32,
        hash_id: u32,
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        (**self).rsa_sign(key_handle, scheme, hash_id, data)
    }
    fn rsa_verify(
        &self,
        key_handle: u32,
        scheme: u32,
        hash_id: u32,
        data: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        (**self).rsa_verify(key_handle, scheme, hash_id, data, signature)
    }
    fn ecdsa_sign(
        &self,
        key_handle: u32,
        curve_id: u32,
        hash_id: u32,
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        (**self).ecdsa_sign(key_handle, curve_id, hash_id, data)
    }
    fn ecdsa_verify(
        &self,
        key_handle: u32,
        curve_id: u32,
        hash_id: u32,
        data: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        (**self).ecdsa_verify(key_handle, curve_id, hash_id, data, signature)
    }
    fn aes_encrypt(
        &self,
        key_handle: u32,
        mode: u32,
        iv: &[u8],
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        (**self).aes_encrypt(key_handle, mode, iv, plaintext)
    }
    fn aes_decrypt(
        &self,
        key_handle: u32,
        mode: u32,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        (**self).aes_decrypt(key_handle, mode, iv, ciphertext)
    }
    fn hash(&self, hash_algo: u32, data: &[u8]) -> HsmResult<Vec<u8>> {
        (**self).hash(hash_algo, data)
    }
    fn key_import_public(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32> {
        (**self).key_import_public(key_type, key_data)
    }
    fn key_import_private(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32> {
        (**self).key_import_private(key_type, key_data)
    }
    fn key_import(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32> {
        (**self).key_import(key_type, key_data)
    }
    fn key_generate(&self, key_handle: u32, key_type: u32, key_bits: u32) -> HsmResult<()> {
        (**self).key_generate(key_handle, key_type, key_bits)
    }
    fn key_delete(&self, key_handle: u32) -> HsmResult<()> {
        (**self).key_delete(key_handle)
    }
}

// Real FFI implementation -- only compiled with feature = hw.

#[cfg(feature = "hw")]
pub use hw_backend::HseFfiBackend;

#[cfg(feature = "hw")]
mod hw_backend {
    use super::HseBackend;
    use crate::error::{
        check_hse_status, hse_status_to_error, HseStatus, HSE_ERR_VERIFY_FAILED,
        HSE_MARKER_GCM_NONCE_DELEGATED, HSE_MARKER_HANDLE_OVERFLOW, HSE_MARKER_HANDLE_PRESSURE,
        HSE_MARKER_INVARIANT_FFI_LEN, HSE_OK,
    };
    use crate::ffi;
    use craton_hsm::error::{HsmError, HsmResult};

    const MAX_RSA_SIG_LEN: usize = 512;
    const MAX_ECDSA_SIG_LEN: usize = 132;
    const MAX_AES_OUTPUT_LEN: usize = 65536;
    const MAX_HASH_OUTPUT_LEN: usize = 64;

    /// Verify that the FFI-reported output length is not larger than the
    /// supplied buffer. An out-of-range length is a firmware/FFI
    /// invariant breach (would imply a buffer overflow had we trusted
    /// it).
    ///
    /// Mapped to `DataLenRange` rather than `GeneralError` so the
    /// operational signal is specific ("a length field from the FFI
    /// was out of range") instead of the catch-all. There is no
    /// `DeviceError` variant in `HsmError`, so `DataLenRange` is the
    /// closest stable code.
    fn clamp_ffi_out_len(reported_len: u32, buf_capacity: usize, what: &str) -> HsmResult<usize> {
        let reported = reported_len as usize;
        if reported > buf_capacity {
            tracing::error!(
                target: "craton_hsm_nxp",
                marker = HSE_MARKER_INVARIANT_FFI_LEN,
                reported_len = reported,
                buf_capacity = buf_capacity,
                path = what,
                "HSE FFI reported output length larger than supplied buffer"
            );
            return Err(HsmError::DataLenRange);
        }
        Ok(reported)
    }

    pub(crate) static NEXT_IMPORT_HANDLE: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(0x0100_0000);
    pub(crate) const HSE_IMPORT_HANDLE_MIN: u32 = 0x0100_0000;
    pub(crate) const HSE_IMPORT_HANDLE_MAX: u32 = 0x01FF_FFFF;

    /// Threshold at which `next_import_handle` emits a pressure
    /// warning. 80% of the disjoint range (~13.4M of 16.7M handles
    /// consumed). At 1k imports/sec the counter exhausts in ~4.6h;
    /// this threshold gives operators ~55min of headroom to rotate
    /// the process. Slot recycling is out of scope for this release.
    const HSE_IMPORT_HANDLE_PRESSURE: u32 = HSE_IMPORT_HANDLE_MIN
        .saturating_add((HSE_IMPORT_HANDLE_MAX - HSE_IMPORT_HANDLE_MIN) / 5 * 4);

    fn next_import_handle() -> Option<u32> {
        let next = NEXT_IMPORT_HANDLE
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |cur| {
                    if cur > HSE_IMPORT_HANDLE_MAX {
                        None
                    } else {
                        Some(cur.saturating_add(1))
                    }
                },
            )
            .ok()?;
        // Emit a single error-level marker per crossed boundary so the
        // operator gets paged before the counter exhausts. We use
        // `error` (not `warn`) because failure is imminent and slot
        // recycling is not implemented yet.
        if next == HSE_IMPORT_HANDLE_PRESSURE {
            tracing::error!(
                target: "craton_hsm_nxp",
                marker = HSE_MARKER_HANDLE_PRESSURE,
                counter = next,
                max = HSE_IMPORT_HANDLE_MAX,
                "HSE import-handle counter crossed 80% of its disjoint range; \
                 rotate the process before exhaustion (slot recycling not yet \
                 implemented)"
            );
        }
        Some(next)
    }

    /// Production [`HseBackend`] implementation that dispatches every
    /// call through the `unsafe` FFI extern declarations in
    /// [`crate::ffi`].
    #[derive(Default, Debug, Clone, Copy)]
    pub struct HseFfiBackend;

    impl HseFfiBackend {
        /// Construct a new `HseFfiBackend`. Emits a one-shot
        /// `tracing::warn!` reminding operators that AES-GCM nonce
        /// uniqueness is delegated to the HSE firmware (see module
        /// docs).
        pub fn new() -> Self {
            // V-GCM: emit a one-shot reminder that AES-GCM nonce
            // uniqueness is delegated to the HSE firmware. The
            // dispatching layer does not maintain a per-key counter;
            // nonce reuse would compromise the cipher's authenticity
            // guarantees. Firmware-managed nonces are the only
            // currently-exposed code path (see lib.rs
            // aes_256_gcm_encrypt).
            tracing::warn!(
                target: "craton_hsm_nxp",
                marker = HSE_MARKER_GCM_NONCE_DELEGATED,
                "AES-GCM nonce uniqueness is delegated to NXP HSE firmware; \
                 the dispatching layer maintains no per-key counter"
            );
            Self
        }
    }

    #[allow(unsafe_code)]
    impl HseBackend for HseFfiBackend {
        fn rsa_sign(
            &self,
            key_handle: u32,
            scheme: u32,
            /* TODO(NXP-hash-id): hash algorithm is currently dropped before reaching firmware — prehashed RSA/PSS will have wrong DigestInfo. */
            _hash_id: u32,
            data: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            let mut sig_buf = vec![0u8; MAX_RSA_SIG_LEN];
            let mut sig_len: u32 = sig_buf.len() as u32;
            // SAFETY: `data` is non-empty (checked above) so
            // `data.as_ptr()` is valid for reads of `data.len()` bytes.
            // `sig_buf` is freshly allocated with `MAX_RSA_SIG_LEN`
            // bytes and uniquely owned (no aliasing) for the duration
            // of the FFI call. `sig_len` initially holds the buffer
            // capacity per FFI contract; the firmware writes back the
            // actual sig length. `&mut sig_len` is a stack-local u32
            // with no aliasing.
            let status: HseStatus = unsafe {
                ffi::hse_rsa_sign(
                    key_handle,
                    scheme,
                    data.as_ptr(),
                    data.len() as u32,
                    sig_buf.as_mut_ptr(),
                    &mut sig_len,
                )
            };
            check_hse_status(status)?;
            let sig_len = clamp_ffi_out_len(sig_len, MAX_RSA_SIG_LEN, "hse_rsa_sign")?;
            sig_buf.truncate(sig_len);
            Ok(sig_buf)
        }
        fn rsa_verify(
            &self,
            key_handle: u32,
            scheme: u32,
            /* TODO(NXP-hash-id): hash algorithm is currently dropped before reaching firmware — prehashed RSA/PSS will have wrong DigestInfo. */
            _hash_id: u32,
            data: &[u8],
            signature: &[u8],
        ) -> HsmResult<bool> {
            if data.is_empty() || signature.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            // SAFETY: both `data` and `signature` are non-empty
            // (checked above), so their `.as_ptr()` values are valid
            // for reads of `.len()` bytes. The FFI does not retain
            // the pointers past the call. Both slices are read-only —
            // no aliasing concerns.
            let status: HseStatus = unsafe {
                ffi::hse_rsa_verify(
                    key_handle,
                    scheme,
                    data.as_ptr(),
                    data.len() as u32,
                    signature.as_ptr(),
                    signature.len() as u32,
                )
            };
            match status {
                HSE_OK => Ok(true),
                _ if status == HSE_ERR_VERIFY_FAILED => Ok(false),
                _ => Err(hse_status_to_error(status)),
            }
        }
        fn ecdsa_sign(
            &self,
            key_handle: u32,
            curve_id: u32,
            /* TODO(NXP-hash-id): hash algorithm is currently dropped before reaching firmware — prehashed RSA/PSS will have wrong DigestInfo. */
            _hash_id: u32,
            data: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            let mut sig_buf = vec![0u8; MAX_ECDSA_SIG_LEN];
            let mut sig_len: u32 = sig_buf.len() as u32;
            // SAFETY: `data` is non-empty (checked above). `sig_buf`
            // is a fresh, exclusively-owned `Vec` of `MAX_ECDSA_SIG_LEN`
            // bytes; its mut pointer is unaliased for the call.
            // `sig_len` starts as the buffer capacity per FFI contract.
            let status: HseStatus = unsafe {
                ffi::hse_ecdsa_sign(
                    key_handle,
                    curve_id,
                    data.as_ptr(),
                    data.len() as u32,
                    sig_buf.as_mut_ptr(),
                    &mut sig_len,
                )
            };
            check_hse_status(status)?;
            let sig_len = clamp_ffi_out_len(sig_len, MAX_ECDSA_SIG_LEN, "hse_ecdsa_sign")?;
            sig_buf.truncate(sig_len);
            Ok(sig_buf)
        }
        fn ecdsa_verify(
            &self,
            key_handle: u32,
            curve_id: u32,
            /* TODO(NXP-hash-id): hash algorithm is currently dropped before reaching firmware — prehashed RSA/PSS will have wrong DigestInfo. */
            _hash_id: u32,
            data: &[u8],
            signature: &[u8],
        ) -> HsmResult<bool> {
            if data.is_empty() || signature.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            // SAFETY: both `data` and `signature` are non-empty
            // (checked above) so their pointers are valid for reads
            // of `.len()` bytes. Read-only slices: no aliasing
            // concerns.
            let status: HseStatus = unsafe {
                ffi::hse_ecdsa_verify(
                    key_handle,
                    curve_id,
                    data.as_ptr(),
                    data.len() as u32,
                    signature.as_ptr(),
                    signature.len() as u32,
                )
            };
            match status {
                HSE_OK => Ok(true),
                _ if status == HSE_ERR_VERIFY_FAILED => Ok(false),
                _ => Err(hse_status_to_error(status)),
            }
        }
        fn aes_encrypt(
            &self,
            key_handle: u32,
            mode: u32,
            iv: &[u8],
            plaintext: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if plaintext.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            let capacity = std::cmp::min(plaintext.len().saturating_add(32), MAX_AES_OUTPUT_LEN);
            let mut output = vec![0u8; capacity];
            let mut output_len: u32 = output.len() as u32;
            // SAFETY: `plaintext` is non-empty (checked above), so its
            // pointer is valid for reads of `plaintext.len()` bytes.
            // `iv` may be empty — that is allowed by the FFI contract
            // when the mode (e.g. GCM with firmware-generated IV) does
            // not consume a caller-supplied IV; the FFI never
            // dereferences when `iv_len == 0`. `output` is a freshly
            // allocated, uniquely-owned `Vec` of `capacity` bytes.
            let status: HseStatus = unsafe {
                ffi::hse_aes_encrypt(
                    key_handle,
                    mode,
                    iv.as_ptr(),
                    iv.len() as u32,
                    plaintext.as_ptr(),
                    plaintext.len() as u32,
                    output.as_mut_ptr(),
                    &mut output_len,
                )
            };
            check_hse_status(status)?;
            let output_len = clamp_ffi_out_len(output_len, capacity, "hse_aes_encrypt")?;
            output.truncate(output_len);
            Ok(output)
        }
        fn aes_decrypt(
            &self,
            key_handle: u32,
            mode: u32,
            iv: &[u8],
            ciphertext: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if ciphertext.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            let capacity = std::cmp::min(ciphertext.len(), MAX_AES_OUTPUT_LEN);
            let mut output = vec![0u8; capacity];
            let mut output_len: u32 = output.len() as u32;
            // SAFETY: `ciphertext` is non-empty (checked above) so its
            // pointer is valid for reads. `iv` may legitimately be
            // empty (see `aes_encrypt` SAFETY note). `output` is a
            // fresh exclusive allocation of `capacity` bytes.
            let status: HseStatus = unsafe {
                ffi::hse_aes_decrypt(
                    key_handle,
                    mode,
                    iv.as_ptr(),
                    iv.len() as u32,
                    ciphertext.as_ptr(),
                    ciphertext.len() as u32,
                    output.as_mut_ptr(),
                    &mut output_len,
                )
            };
            check_hse_status(status)?;
            let output_len = clamp_ffi_out_len(output_len, capacity, "hse_aes_decrypt")?;
            output.truncate(output_len);
            Ok(output)
        }
        fn hash(&self, hash_algo: u32, data: &[u8]) -> HsmResult<Vec<u8>> {
            let mut output = vec![0u8; MAX_HASH_OUTPUT_LEN];
            let mut output_len: u32 = output.len() as u32;
            // SAFETY: `data` may be empty; the FFI tolerates
            // `input_len == 0` (it computes the digest of the empty
            // string). `output` is a fresh exclusive `Vec` of
            // `MAX_HASH_OUTPUT_LEN` bytes — large enough for SHA-512
            // (64) which is the widest digest we emit.
            let status: HseStatus = unsafe {
                ffi::hse_hash_compute(
                    hash_algo,
                    data.as_ptr(),
                    data.len() as u32,
                    output.as_mut_ptr(),
                    &mut output_len,
                )
            };
            check_hse_status(status)?;
            let output_len =
                clamp_ffi_out_len(output_len, MAX_HASH_OUTPUT_LEN, "hse_hash_compute")?;
            output.truncate(output_len);
            Ok(output)
        }
        fn key_import_public(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32> {
            let handle = next_import_handle().ok_or_else(|| {
                tracing::error!(target: "craton_hsm_nxp", marker = HSE_MARKER_HANDLE_OVERFLOW, "HSE import-handle range exhausted");
                HsmError::MechanismInvalid
            })?;
            // SAFETY: `key_data` may be empty (firmware will reject
            // with `HSE_ERR_DATA_LEN`); when non-empty its pointer is
            // valid for reads of `key_data.len()` bytes. The FFI does
            // not retain the pointer past the call. Read-only slice:
            // no aliasing concern.
            let status: HseStatus = unsafe {
                ffi::hse_key_import(handle, key_type, key_data.as_ptr(), key_data.len() as u32)
            };
            check_hse_status(status)?;
            Ok(handle)
        }
        /// Import a private key.
        ///
        /// V2 gap: the HSE catalog distinguishes public/private slots
        /// via a `HSE_KEY_FLAG_PRIVATE` bit in the key-type word.
        /// Until that flag plumbing lands across the FFI surface
        /// (tracked in NXP-V2) this path returns
        /// `FunctionNotSupported` rather than silently aliasing
        /// `key_import_public`. Silently importing private key
        /// material as a public slot would mis-categorise the key in
        /// the HSE catalog and could weaken downstream policy checks;
        /// failing closed forces the caller to surface the gap.
        fn key_import_private(&self, key_type: u32, key_data: &[u8]) -> HsmResult<u32> {
            let _ = (key_type, key_data);
            tracing::error!(
                target: "craton_hsm_nxp::backend_trait",
                "key_import_private is not yet wired through the FFI surface \
                 (NXP-V2); returning FunctionNotSupported rather than aliasing \
                 key_import_public"
            );
            Err(HsmError::FunctionNotSupported)
        }
        fn key_generate(&self, key_handle: u32, key_type: u32, key_bits: u32) -> HsmResult<()> {
            // SAFETY: scalar-only FFI call; no pointers to validate.
            // The firmware is responsible for bounds-checking
            // `key_handle`, `key_type`, and `key_bits` and returning
            // `HSE_ERR_INVALID_PARAM` on out-of-range values.
            let status: HseStatus =
                unsafe { ffi::hse_key_generate(key_handle, key_type, key_bits) };
            check_hse_status(status)
        }
        fn key_delete(&self, key_handle: u32) -> HsmResult<()> {
            // V2: release HSE catalog slot so RAII drop actually
            // frees it. SAFETY: scalar-only FFI call; the firmware
            // validates the handle and returns `HSE_ERR_KEY_NOT_FOUND`
            // if the slot is already free.
            let status: HseStatus = unsafe { ffi::hse_key_delete(key_handle) };
            check_hse_status(status)
        }
    }
}

// Mock implementation -- test / test-stub only.

#[cfg(any(test, feature = "test-stub"))]
pub use mock_backend::{MockHseBackend, MockResponse};

#[cfg(any(test, feature = "test-stub"))]
mod mock_backend {
    use super::HseBackend;
    use craton_hsm::error::{HsmError, HsmResult};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Canned response for one mock call.
    #[derive(Clone, Debug)]
    pub enum MockResponse {
        /// Return the given byte vector.
        Bytes(Vec<u8>),
        /// Return the given boolean (verify path).
        Bool(bool),
        /// Return the given handle (key-import path).
        Handle(u32),
        /// Return `Ok(())` (key-generate / key-delete paths).
        Unit,
        /// Return the given `HsmError`.
        Err(HsmError),
        /// No response was queued — yield a default error.
        Default,
    }

    /// Programmable mock of HseBackend.
    #[derive(Default)]
    pub struct MockHseBackend {
        rsa_sign_q: Mutex<VecDeque<MockResponse>>,
        rsa_verify_q: Mutex<VecDeque<MockResponse>>,
        ecdsa_sign_q: Mutex<VecDeque<MockResponse>>,
        ecdsa_verify_q: Mutex<VecDeque<MockResponse>>,
        aes_encrypt_q: Mutex<VecDeque<MockResponse>>,
        aes_decrypt_q: Mutex<VecDeque<MockResponse>>,
        hash_q: Mutex<VecDeque<MockResponse>>,
        key_import_q: Mutex<VecDeque<MockResponse>>,
        key_generate_q: Mutex<VecDeque<MockResponse>>,
        key_delete_q: Mutex<VecDeque<MockResponse>>,
        last_hash_id: Mutex<u32>,
        calls: Mutex<MockCallCounts>,
    }

    /// Per-method call tallies.
    #[derive(Default, Clone, Debug)]
    pub struct MockCallCounts {
        /// Number of `rsa_sign` invocations observed.
        pub rsa_sign: u32,
        /// Number of `rsa_verify` invocations observed.
        pub rsa_verify: u32,
        /// Number of `ecdsa_sign` invocations observed.
        pub ecdsa_sign: u32,
        /// Number of `ecdsa_verify` invocations observed.
        pub ecdsa_verify: u32,
        /// Number of `aes_encrypt` invocations observed.
        pub aes_encrypt: u32,
        /// Number of `aes_decrypt` invocations observed.
        pub aes_decrypt: u32,
        /// Number of `hash` invocations observed.
        pub hash: u32,
        /// Number of `key_import_public` + `key_import_private` invocations observed.
        pub key_import: u32,
        /// Number of `key_generate` invocations observed.
        pub key_generate: u32,
        /// Number of `key_delete` invocations observed.
        pub key_delete: u32,
    }

    impl MockHseBackend {
        /// Construct an empty mock with no queued responses.
        pub fn new() -> Self {
            Self::default()
        }
        /// Queue a response for the next `rsa_sign` call.
        pub fn queue_rsa_sign(&self, r: MockResponse) {
            self.rsa_sign_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `rsa_verify` call.
        pub fn queue_rsa_verify(&self, r: MockResponse) {
            self.rsa_verify_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `ecdsa_sign` call.
        pub fn queue_ecdsa_sign(&self, r: MockResponse) {
            self.ecdsa_sign_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `ecdsa_verify` call.
        pub fn queue_ecdsa_verify(&self, r: MockResponse) {
            self.ecdsa_verify_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `aes_encrypt` call.
        pub fn queue_aes_encrypt(&self, r: MockResponse) {
            self.aes_encrypt_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `aes_decrypt` call.
        pub fn queue_aes_decrypt(&self, r: MockResponse) {
            self.aes_decrypt_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `hash` call.
        pub fn queue_hash(&self, r: MockResponse) {
            self.hash_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `key_import_public` / `key_import_private` call.
        pub fn queue_key_import(&self, r: MockResponse) {
            self.key_import_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `key_generate` call.
        pub fn queue_key_generate(&self, r: MockResponse) {
            self.key_generate_q.lock().unwrap().push_back(r);
        }
        /// Queue a response for the next `key_delete` call.
        pub fn queue_key_delete(&self, r: MockResponse) {
            self.key_delete_q.lock().unwrap().push_back(r);
        }
        /// Snapshot the per-method call tallies.
        pub fn call_counts(&self) -> MockCallCounts {
            self.calls.lock().unwrap().clone()
        }
        /// Return the last `hash_id` value seen by a sign/verify call.
        pub fn last_hash_id(&self) -> u32 {
            *self.last_hash_id.lock().unwrap()
        }
        fn bump_import(&self) {
            self.calls.lock().unwrap().key_import += 1;
        }
    }

    fn pop(q: &Mutex<VecDeque<MockResponse>>) -> MockResponse {
        q.lock()
            .unwrap()
            .pop_front()
            .unwrap_or(MockResponse::Default)
    }
    fn to_bytes(r: MockResponse) -> HsmResult<Vec<u8>> {
        match r {
            MockResponse::Bytes(b) => Ok(b),
            MockResponse::Err(e) => Err(e),
            MockResponse::Default => Err(HsmError::FunctionNotSupported),
            _ => Err(HsmError::GeneralError),
        }
    }
    fn to_bool(r: MockResponse) -> HsmResult<bool> {
        match r {
            MockResponse::Bool(b) => Ok(b),
            MockResponse::Err(e) => Err(e),
            MockResponse::Default => Err(HsmError::FunctionNotSupported),
            _ => Err(HsmError::GeneralError),
        }
    }
    fn to_handle(r: MockResponse) -> HsmResult<u32> {
        match r {
            MockResponse::Handle(h) => Ok(h),
            MockResponse::Err(e) => Err(e),
            MockResponse::Default => Err(HsmError::FunctionNotSupported),
            _ => Err(HsmError::GeneralError),
        }
    }
    fn to_unit(r: MockResponse) -> HsmResult<()> {
        match r {
            MockResponse::Unit => Ok(()),
            MockResponse::Err(e) => Err(e),
            MockResponse::Default => Err(HsmError::FunctionNotSupported),
            _ => Err(HsmError::GeneralError),
        }
    }

    impl HseBackend for MockHseBackend {
        fn rsa_sign(&self, _k: u32, _s: u32, hash_id: u32, data: &[u8]) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            *self.last_hash_id.lock().unwrap() = hash_id;
            self.calls.lock().unwrap().rsa_sign += 1;
            to_bytes(pop(&self.rsa_sign_q))
        }
        fn rsa_verify(
            &self,
            _k: u32,
            _s: u32,
            hash_id: u32,
            data: &[u8],
            sig: &[u8],
        ) -> HsmResult<bool> {
            if data.is_empty() || sig.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            *self.last_hash_id.lock().unwrap() = hash_id;
            self.calls.lock().unwrap().rsa_verify += 1;
            to_bool(pop(&self.rsa_verify_q))
        }
        fn ecdsa_sign(&self, _k: u32, _c: u32, hash_id: u32, data: &[u8]) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            *self.last_hash_id.lock().unwrap() = hash_id;
            self.calls.lock().unwrap().ecdsa_sign += 1;
            to_bytes(pop(&self.ecdsa_sign_q))
        }
        fn ecdsa_verify(
            &self,
            _k: u32,
            _c: u32,
            hash_id: u32,
            data: &[u8],
            sig: &[u8],
        ) -> HsmResult<bool> {
            if data.is_empty() || sig.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            *self.last_hash_id.lock().unwrap() = hash_id;
            self.calls.lock().unwrap().ecdsa_verify += 1;
            to_bool(pop(&self.ecdsa_verify_q))
        }
        fn aes_encrypt(
            &self,
            _k: u32,
            _m: u32,
            _iv: &[u8],
            plaintext: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if plaintext.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().aes_encrypt += 1;
            to_bytes(pop(&self.aes_encrypt_q))
        }
        fn aes_decrypt(
            &self,
            _k: u32,
            _m: u32,
            _iv: &[u8],
            ciphertext: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if ciphertext.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().aes_decrypt += 1;
            to_bytes(pop(&self.aes_decrypt_q))
        }
        fn hash(&self, _algo: u32, _data: &[u8]) -> HsmResult<Vec<u8>> {
            self.calls.lock().unwrap().hash += 1;
            to_bytes(pop(&self.hash_q))
        }
        fn key_import_public(&self, _key_type: u32, _key_data: &[u8]) -> HsmResult<u32> {
            self.bump_import();
            to_handle(pop(&self.key_import_q))
        }
        fn key_import_private(&self, _key_type: u32, _key_data: &[u8]) -> HsmResult<u32> {
            self.bump_import();
            to_handle(pop(&self.key_import_q))
        }
        fn key_generate(&self, _h: u32, _t: u32, _b: u32) -> HsmResult<()> {
            self.calls.lock().unwrap().key_generate += 1;
            to_unit(pop(&self.key_generate_q))
        }
        fn key_delete(&self, _h: u32) -> HsmResult<()> {
            self.calls.lock().unwrap().key_delete += 1;
            match pop(&self.key_delete_q) {
                MockResponse::Default => Ok(()),
                other => to_unit(other),
            }
        }
    }
}
