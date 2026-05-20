// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! # CNG Backend — Windows BCrypt Cryptography Next Generation
//!
//! This crate provides a [`CryptoBackend`] implementation that calls the native
//! Windows CNG (BCrypt) APIs via [`windows_sys`].  All symmetric/asymmetric
//! operations go through the platform's FIPS 140-2/3 validated CNG module when
//! FIPS mode is enabled.
//!
//! ## FIPS Mode
//!
//! When constructed via [`CngBackend::new_fips()`], the backend opens algorithm
//! providers with the `BCRYPT_PROV_DISPATCH` flag, which restricts operations to
//! FIPS-approved algorithms only.
//!
//! ## Memory Safety
//!
//! All CNG handles are wrapped in RAII types (`AlgHandle`, `KeyHandle`,
//! `HashHandle`) that guarantee cleanup via `BCryptCloseAlgorithmProvider`,
//! `BCryptDestroyKey`, and `BCryptDestroyHash` respectively.
//!
//! Key material is held in [`zeroize::Zeroizing`] buffers where feasible.
//!
//! ## Platform Gate
//!
//! The entire implementation is behind `#[cfg(windows)]`.  On non-Windows
//! platforms, only a stub `CngBackend` is compiled (which rejects all
//! operations at runtime).

#![allow(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::digest::DigestAccumulator;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::{HsmError, HsmResult};
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use craton_hsm::store::key_material::RawKeyMaterial;

// ============================================================================
// Non-Windows stub
// ============================================================================

/// On non-Windows platforms, provide a minimal stub that rejects everything.
#[cfg(not(windows))]
#[derive(Debug)]
pub struct CngBackend {
    _private: (),
    /// FIPS POST gate placeholder. The non-Windows stub doesn't implement
    /// `CryptoBackend`, but we still expose the same `mark_fips_post_passed`
    /// surface so embedders can write portable wiring code that compiles
    /// on every host.
    fips_post_passed: std::sync::atomic::AtomicBool,
}

#[cfg(not(windows))]
impl CngBackend {
    /// Construct a non-Windows stub backend.
    pub fn new(_fips_mode: bool) -> Self {
        Self {
            _private: (),
            fips_post_passed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Reject FIPS construction on non-Windows hosts.
    pub fn new_fips() -> HsmResult<Self> {
        Err(HsmError::FunctionNotSupported)
    }

    /// Mark this backend as having passed the FIPS power-on self-test
    /// (POST). Stubbed on non-Windows for API parity with the Windows
    /// `cng_impl::CngBackend`.
    pub fn mark_fips_post_passed(&self) {
        self.fips_post_passed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Returns whether this backend's POST flag is set.
    pub fn fips_post_passed(&self) -> bool {
        self.fips_post_passed
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(not(windows))]
impl Default for CngBackend {
    fn default() -> Self {
        Self::new(false)
    }
}

// The non-Windows stub does not implement CryptoBackend because all operations
// would fail.  Users should cfg-gate backend selection at the application level.

// ============================================================================
// Windows CNG implementation
// ============================================================================

#[cfg(windows)]
mod cng_impl {
    use super::*;
    use craton_hsm::pkcs11_abi::constants::*;
    use std::collections::HashMap;
    use std::ptr;
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::Security::Cryptography::*;
    use zeroize::Zeroizing;

    // NTSTATUS success code.
    const STATUS_SUCCESS: i32 = 0;

    // AES block size in bytes.
    const AES_BLOCK_SIZE: usize = 16;

    // AES-GCM nonce size (96 bits per NIST SP 800-38D).
    const AES_GCM_NONCE_SIZE: usize = 12;

    // AES-GCM tag size (128 bits).
    const AES_GCM_TAG_SIZE: usize = 16;

    // AES key-wrap overhead (one 64-bit block).
    const AES_KW_OVERHEAD: usize = 8;

    // Magic values for BCrypt key blobs.
    const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x31415352; // "RSA1"
    const BCRYPT_RSAFULLPRIVATE_MAGIC: u32 = 0x33415352; // "RSA3"

    // ECC key blob magic numbers.
    const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x31534345; // "ECS1"
    const BCRYPT_ECDSA_PRIVATE_P256_MAGIC: u32 = 0x32534345; // "ECS2"
    const BCRYPT_ECDSA_PUBLIC_P384_MAGIC: u32 = 0x33534345; // "ECS3"
    const BCRYPT_ECDSA_PRIVATE_P384_MAGIC: u32 = 0x34534345; // "ECS4"
    const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B4345; // "ECK1"
    const BCRYPT_ECDH_PRIVATE_P256_MAGIC: u32 = 0x324B4345; // "ECK2"
    const BCRYPT_ECDH_PUBLIC_P384_MAGIC: u32 = 0x334B4345; // "ECK3"
    const BCRYPT_ECDH_PRIVATE_P384_MAGIC: u32 = 0x344B4345; // "ECK4"

    // ========================================================================
    // RAII handle wrappers
    // ========================================================================

    /// RAII wrapper for `BCRYPT_ALG_HANDLE`.
    struct AlgHandle(BCRYPT_ALG_HANDLE);

    impl AlgHandle {
        fn as_raw(&self) -> BCRYPT_ALG_HANDLE {
            self.0
        }
    }

    impl Drop for AlgHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: self.0 is a valid BCRYPT_ALG_HANDLE obtained from
                // BCryptOpenAlgorithmProvider, and we only close it once (on drop).
                unsafe {
                    BCryptCloseAlgorithmProvider(self.0, 0);
                }
            }
        }
    }

    // SAFETY: CNG algorithm provider handles are documented as thread-safe
    // across concurrent operations. Per MSDN for
    // `BCryptOpenAlgorithmProvider`:
    //
    //   "An algorithm handle can be shared by multiple threads. The caller is
    //   responsible for ensuring that the handle is not closed while it is
    //   being used."
    //
    // Reference:
    //   <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider>
    //
    // `AlgHandle` itself is owned by a single Rust value at a time; `Send`
    // is trivially sound because we only move the handle (not share it) and
    // destroy it exactly once on `Drop`. `Sync` is sound because the MSDN
    // guarantee above covers concurrent `BCrypt*` calls driven by multiple
    // threads through `&AlgHandle`.
    unsafe impl Send for AlgHandle {}
    unsafe impl Sync for AlgHandle {}

    /// RAII wrapper for `BCRYPT_KEY_HANDLE`.
    struct KeyHandle(BCRYPT_KEY_HANDLE);

    impl KeyHandle {
        fn as_raw(&self) -> BCRYPT_KEY_HANDLE {
            self.0
        }
    }

    impl Drop for KeyHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: self.0 is a valid BCRYPT_KEY_HANDLE obtained from
                // BCryptGenerateSymmetricKey / BCryptImportKeyPair / BCryptGenerateKeyPair,
                // and we only destroy it once (on drop).
                unsafe {
                    BCryptDestroyKey(self.0);
                }
            }
        }
    }

    // `KeyHandle` is intentionally NOT `Send` or `Sync`.
    //
    // Audit finding CNG-1: MSDN does NOT document `BCRYPT_KEY_HANDLE` as
    // safe for concurrent use. Asserting `Send + Sync` blanket-ly for this
    // type is unsound because it would allow `Arc<KeyHandle>` to be shared
    // across threads and simultaneously driven through `BCryptEncrypt` /
    // `BCryptDecrypt` / `BCryptSignHash`, whose re-entrancy guarantees are
    // not specified.
    //
    // The design of this backend already avoids the problem: every key
    // handle is created inside a single `*_impl` function, used locally,
    // and dropped before the function returns. `KeyHandle` values never
    // escape their owning stack frame and are never stored in `CngBackend`.
    // Concurrent `CryptoBackend` trait calls through `Arc<CngBackend>` are
    // safe because each call imports its own distinct handle — no handle
    // is shared between threads.
    //
    // If a future refactor needs to cache a `KeyHandle` across calls (e.g.
    // per-session key objects), the cache entry must wrap the handle in a
    // `parking_lot::Mutex<KeyHandle>` and the `Mutex` itself becomes the
    // `Send + Sync` surface; the raw `KeyHandle` must remain neither.
    //
    // NOTE: the `*const c_void` payload of `BCRYPT_KEY_HANDLE` means Rust
    // auto-derives neither `Send` nor `Sync` for `KeyHandle`, which is
    // exactly what we want. Leaving these impls off is a load-bearing
    // soundness invariant, not an oversight.

    /// RAII wrapper for `BCRYPT_HASH_HANDLE`.
    struct HashHandle(BCRYPT_HASH_HANDLE);

    impl HashHandle {
        fn as_raw(&self) -> BCRYPT_HASH_HANDLE {
            self.0
        }
    }

    impl Drop for HashHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: self.0 is a valid BCRYPT_HASH_HANDLE obtained from
                // BCryptCreateHash, and we only destroy it once (on drop).
                unsafe {
                    BCryptDestroyHash(self.0);
                }
            }
        }
    }

    // `HashHandle` is intentionally NOT `Send` or `Sync` — same reasoning
    // as `KeyHandle`. MSDN does not document `BCRYPT_HASH_HANDLE` as
    // re-entrant across threads, and every hash handle in this backend is a
    // local temporary that never crosses a thread boundary. The streaming
    // `DigestAccumulator` built on top of a `HashHandle` (see
    // `create_cng_hasher`) is `Send` only via `Box<dyn DigestAccumulator>`
    // because the caller owns it exclusively and never concurrently drives
    // it from multiple threads — the hasher trait takes `&mut self`, so the
    // borrow checker enforces single-threaded use.

    /// RAII wrapper for `BCRYPT_SECRET_HANDLE` returned by
    /// `BCryptSecretAgreement`. Calls `BCryptDestroySecret` on drop so an
    /// early-return path cannot leak the kernel-allocated secret object
    /// (audit finding: previously ad-hoc cleanups left two `?`-skip leaks).
    struct SecretHandle(BCRYPT_SECRET_HANDLE);

    impl SecretHandle {
        fn as_raw(&self) -> BCRYPT_SECRET_HANDLE {
            self.0
        }
    }

    impl Drop for SecretHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: self.0 is a valid BCRYPT_SECRET_HANDLE obtained from
                // BCryptSecretAgreement, and we only destroy it once (on drop).
                unsafe {
                    BCryptDestroySecret(self.0);
                }
            }
        }
    }

    // ========================================================================
    // Helper: map NTSTATUS to HsmError
    // ========================================================================

    /// Translate a Windows `NTSTATUS` returned by a BCrypt API into an
    /// [`HsmError`]. This mapping is intentionally exhaustive for the BCrypt
    /// error surface documented in `ntstatus.h`; unknown values fall through
    /// to `GeneralError` with the original code logged.
    ///
    /// References:
    /// - Win32 BCrypt return codes:
    ///   <https://learn.microsoft.com/en-us/windows/win32/seccng/cng-error-codes>
    /// - `STATUS_*` symbolic names: `winnt.h` / `ntstatus.h`
    fn ntstatus_to_hsm_error(status: i32) -> HsmError {
        let u = status as u32;
        match u {
            // STATUS_INVALID_PARAMETER — bad argument to a BCrypt call
            0xC000_000D => HsmError::ArgumentsBad,
            // STATUS_INVALID_HANDLE — stale / zeroed algorithm/key/hash handle
            0xC000_0008 => HsmError::SessionHandleInvalid,
            // STATUS_NO_MEMORY
            0xC000_0017 => HsmError::HostMemory,
            // STATUS_BUFFER_TOO_SMALL / STATUS_BUFFER_OVERFLOW
            0xC000_0023 | 0x8000_0005 => HsmError::BufferTooSmall,
            // STATUS_NOT_FOUND — provider/algorithm/key not present
            0xC000_0225 => HsmError::MechanismInvalid,
            // STATUS_NOT_SUPPORTED / STATUS_NOT_IMPLEMENTED
            0xC000_00BB | 0xC000_0002 => HsmError::FunctionNotSupported,
            // STATUS_ACCESS_DENIED — e.g., FIPS policy blocked an operation.
            // `HsmError` has no dedicated "rejected" variant; FunctionNotSupported
            // is the closest PKCS#11 mapping (CKR_FUNCTION_NOT_SUPPORTED) for a
            // capability the provider refuses to exercise.
            0xC000_0022 => HsmError::FunctionNotSupported,
            // STATUS_AUTH_TAG_MISMATCH — AEAD (AES-GCM/CCM) tag verification failed
            0xC000_A002 => HsmError::EncryptedDataInvalid,
            // STATUS_INVALID_SIGNATURE
            0xC000_A000 => HsmError::SignatureInvalid,
            // STATUS_UNSUCCESSFUL — generic BCrypt failure
            0xC000_0001 => HsmError::GeneralError,
            // STATUS_DATA_ERROR — block-cipher padding / integrity failure
            0xC000_003E => HsmError::EncryptedDataInvalid,
            // STATUS_INVALID_KEY / STATUS_INVALID_HANDLE for key-specific paths
            // (used by BCryptImportKeyPair on malformed BLOBs). Mapping to
            // AttributeValueInvalid (CKR_ATTRIBUTE_VALUE_INVALID) so the caller
            // sees "your key material was malformed" rather than a generic
            // error.
            0xC000_0439 => HsmError::AttributeValueInvalid,
            // STATUS_INVALID_DATA — malformed PKCS#1 / DER payload
            0xC000_0184 => HsmError::EncryptedDataInvalid,
            // STATUS_INSUFFICIENT_RESOURCES
            0xC000_009A => HsmError::HostMemory,
            // STATUS_DEVICE_NOT_READY / STATUS_DEVICE_BUSY — TPM / smartcard
            // paths. No `DeviceError` variant exists in `HsmError`; the
            // closest mapping is `TokenNotPresent` (CKR_TOKEN_NOT_PRESENT)
            // which operators will recognise as "the backing token is
            // currently unavailable".
            0xC000_00A3 | 0x8000_0011 => HsmError::TokenNotPresent,
            _ => {
                // Audit finding L3: emit the raw NTSTATUS in both hex and
                // signed-decimal form (operators and vendor tooling
                // routinely quote one or the other) along with the
                // severity/facility breakdown so we can point at
                // `ntstatus.h` by hand. The unit-variant `HsmError` cannot
                // carry a payload, so tracing is the only place this
                // detail can surface.
                let severity = (u >> 30) & 0x3;
                let facility = (u >> 16) & 0xFFF;
                let code = u & 0xFFFF;
                tracing::error!(
                    ntstatus_hex = format!("0x{:08X}", u),
                    ntstatus_i32 = status,
                    severity = severity,
                    facility = facility,
                    code = format!("0x{:04X}", code),
                    "CNG BCrypt API returned unmapped NTSTATUS — \
                     returning HsmError::GeneralError; cross-reference \
                     ntstatus.h with the hex value above to diagnose"
                );
                HsmError::GeneralError
            }
        }
    }

    // Re-exported into the parent module for targeted unit tests. Not part
    // of the crate public API.
    #[cfg(test)]
    pub(super) fn __test_ntstatus_to_hsm_error(status: i32) -> HsmError {
        ntstatus_to_hsm_error(status)
    }

    /// Test-only re-export of  so cross-platform tests can
    /// exercise canonical-DER rejection without needing a CNG handle.
    #[cfg(test)]
    pub(super) fn __test_der_to_raw(der: &[u8], curve_size: usize) -> HsmResult<Vec<u8>> {
        der_ecdsa_to_raw(der, curve_size)
    }

    /// Test-only re-export of  for cross-platform tests of
    /// long-form length encoding (P-521 future-proofing).
    #[cfg(test)]
    pub(super) fn __test_raw_to_der(raw: &[u8]) -> HsmResult<Vec<u8>> {
        raw_ecdsa_to_der(raw)
    }

    /// Test-only re-export of  for the constant-time padding test.
    #[cfg(test)]
    pub(super) fn __test_pkcs7_unpad(data: &[u8]) -> HsmResult<Vec<u8>> {
        pkcs7_unpad(data)
    }

    /// Test-only re-export of  so the cross-platform test
    /// suite can verify the perf-fixed reset-based implementation against an
    /// independent KAT without running the ECDH path.
    #[cfg(test)]
    pub(super) fn __test_hkdf_expand(prk: &[u8], length: usize) -> HsmResult<Vec<u8>> {
        hkdf_expand_sha256(prk, length)
    }

    /// Test-only re-export of `derive_ecc_public_via_ncrypt` so the
    /// Windows-only test suite can confirm that the CNG-derived public
    /// point matches the one computed by the pure-Rust `p256` / `p384`
    /// crates for the same scalar (smoke test for the FIPS-bypass fix).
    #[cfg(test)]
    pub(super) fn __test_derive_ecc_public_via_ncrypt(
        scalar: &[u8],
        curve_size: usize,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        derive_ecc_public_via_ncrypt(scalar, curve_size)
    }

    /// Test-only re-export of `encode_pkcs8_ec_private_key` so the
    /// cross-platform test suite can assert the DER encoding's first few
    /// bytes without needing a Windows host.
    #[cfg(test)]
    pub(super) fn __test_encode_pkcs8_ec_private_key(
        scalar: &[u8],
        curve_size: usize,
    ) -> HsmResult<Vec<u8>> {
        encode_pkcs8_ec_private_key(scalar, curve_size)
    }

    /// Test-only re-export of the now-retired pure-Rust derivation so the
    /// smoke test in `mod tests` can cross-check CNG output against it.
    #[cfg(test)]
    pub(super) fn __test_compute_p256_public_point(scalar: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        compute_p256_public_point(scalar)
    }

    /// Test-only re-export of the now-retired pure-Rust P-384 derivation.
    #[cfg(test)]
    pub(super) fn __test_compute_p384_public_point(scalar: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        compute_p384_public_point(scalar)
    }

    // ========================================================================
    // Helper: open algorithm provider
    // ========================================================================

    fn open_alg(alg_id: *const u16, flags: u32) -> HsmResult<AlgHandle> {
        let mut handle: BCRYPT_ALG_HANDLE = ptr::null_mut();
        // SAFETY: BCryptOpenAlgorithmProvider writes to `handle` on success.
        // `alg_id` points to a valid null-terminated wide string constant.
        // `flags` is either 0 or a valid combination of BCRYPT_PROV_DISPATCH, etc.
        let status =
            unsafe { BCryptOpenAlgorithmProvider(&mut handle, alg_id, ptr::null(), flags) };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(AlgHandle(handle))
    }

    // ========================================================================
    // Helper: generate random bytes
    // ========================================================================

    fn gen_random(buf: &mut [u8]) -> HsmResult<()> {
        // SAFETY: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG does not
        // require an algorithm handle (first arg is null). `buf` is a valid
        // mutable slice.
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(())
    }

    // ========================================================================
    // Helper: set chaining mode on an algorithm provider
    // ========================================================================

    fn set_chaining_mode(alg: &AlgHandle, mode: *const u16) -> HsmResult<()> {
        // Audit fix: previously this walked the wide string with `*p`
        // dereferences inside `unsafe` to find the null terminator. That
        // pattern is a foot-gun — a caller that ever passes a non-static
        // or non-NUL-terminated pointer would walk past the allocation.
        //
        // All Windows BCRYPT chaining-mode strings on this code path are
        // static constants of the form L"ChainingMode<XYZ>" (15 wchars +
        // 1 NUL = 16 wchars = 32 bytes total). Cap the scan at a fixed
        // upper bound so that even a hypothetical caller that hands in a
        // non-terminated pointer cannot drive the loop past 32 wchars
        // (64 bytes) of memory before we bail.
        //
        // If you ever add a chaining mode whose name exceeds 31 chars,
        // extend `MAX_MODE_WCHARS` accordingly.
        const MAX_MODE_WCHARS: usize = 32;
        // SAFETY: `mode` is a known static null-terminated wide string pointer
        // from windows-sys (BCRYPT_CHAIN_MODE_GCM / _CBC / _ECB / _CFB). We
        // bound the scan at MAX_MODE_WCHARS to defang the unbounded-walk
        // foot-gun if a future caller ever passes a non-conforming pointer.
        let mode_byte_len = unsafe {
            let mut len: usize = 0;
            let mut p = mode;
            while len < MAX_MODE_WCHARS && *p != 0 {
                p = p.add(1);
                len += 1;
            }
            if len == MAX_MODE_WCHARS && *p != 0 {
                // No NUL within the cap — refuse rather than continue.
                tracing::error!(
                    cap = MAX_MODE_WCHARS,
                    "set_chaining_mode: wide-string mode pointer not NUL-terminated \
                     within bounded cap; refusing"
                );
                return Err(HsmError::MechanismInvalid);
            }
            ((len + 1) * 2) as u32 // include NUL terminator, in bytes
        };

        // SAFETY: BCRYPT_CHAINING_MODE is a valid property name. `mode` is a
        // valid wide string pointer. `alg.as_raw()` is a valid algorithm handle.
        let status = unsafe {
            BCryptSetProperty(
                alg.as_raw() as *mut _,
                BCRYPT_CHAINING_MODE,
                mode as *const u8,
                mode_byte_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(())
    }

    // ========================================================================
    // Helper: create symmetric key from raw bytes
    // ========================================================================

    fn create_symmetric_key(alg: &AlgHandle, key_bytes: &[u8]) -> HsmResult<KeyHandle> {
        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: BCryptGenerateSymmetricKey creates a key object from raw key
        // material. `alg.as_raw()` is a valid algorithm handle.
        // `key_bytes` is a valid slice. We pass null for the key object buffer
        // (letting CNG allocate it internally).
        let status = unsafe {
            BCryptGenerateSymmetricKey(
                alg.as_raw(),
                &mut key_handle,
                ptr::null_mut(),
                0,
                key_bytes.as_ptr() as *mut u8,
                key_bytes.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(KeyHandle(key_handle))
    }

    // ========================================================================
    // AES-GCM encrypt/decrypt helpers
    // ========================================================================

    fn aes_gcm_encrypt_impl(
        backend: &CngBackend,
        key_bytes: &[u8],
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if key_bytes.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }

        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, Some(BCRYPT_CHAIN_MODE_GCM))?;
        let key = create_symmetric_key(&alg, key_bytes)?;

        let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
        gen_random(&mut nonce)?;

        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        let mut ciphertext = vec![0u8; plaintext.len()];

        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: 1, // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
            pbNonce: nonce.as_mut_ptr(),
            cbNonce: AES_GCM_NONCE_SIZE as u32,
            pbAuthData: ptr::null_mut(),
            cbAuthData: 0,
            pbTag: tag.as_mut_ptr(),
            cbTag: AES_GCM_TAG_SIZE as u32,
            pbMacContext: ptr::null_mut(),
            cbMacContext: 0,
            cbAAD: 0,
            cbData: 0,
            dwFlags: 0,
        };

        let mut ct_len = 0u32;
        // SAFETY: All pointers are valid. `key.as_raw()` is a valid AES-GCM key.
        // `auth_info` is properly initialized with nonce and tag buffers.
        // `ciphertext` is sized to hold `plaintext.len()` bytes of output.
        let status = unsafe {
            BCryptEncrypt(
                key.as_raw(),
                plaintext.as_ptr() as *mut u8,
                plaintext.len() as u32,
                &mut auth_info as *mut _ as *mut _,
                ptr::null_mut(),
                0,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32,
                &mut ct_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // GCM is a stream cipher: |ct| must equal |pt|. A mismatch would
        // mean the kernel reported success but produced a truncated
        // ciphertext — fail closed rather than ship a corrupt AEAD frame.
        if ct_len as usize != plaintext.len() {
            return Err(HsmError::GeneralError);
        }

        // Output format: nonce (12) || ciphertext (N) || tag (16)
        let mut result =
            Vec::with_capacity(AES_GCM_NONCE_SIZE + ct_len as usize + AES_GCM_TAG_SIZE);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext[..ct_len as usize]);
        result.extend_from_slice(&tag);
        Ok(result)
    }

    fn aes_gcm_decrypt_impl(
        backend: &CngBackend,
        key_bytes: &[u8],
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if key_bytes.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }

        let min_len = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
        if data.len() < min_len {
            return Err(HsmError::EncryptedDataInvalid);
        }

        let ct_len = data.len() - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE;
        let ciphertext = &data[AES_GCM_NONCE_SIZE..AES_GCM_NONCE_SIZE + ct_len];

        // Audit fix (CNG aliasing): the previous implementation pointed
        // `pbNonce` / `pbTag` directly at byte ranges inside the immutable
        // `data: &[u8]` slice, casting `*const u8` → `*mut u8`. That casts
        // away the borrow's mutability invariant — CNG's signature is
        // `*mut`, and even though Windows treats those as read-only for
        // AES-GCM decrypt, aliasing a `&[u8]` as `*mut u8` is undefined
        // behaviour in Rust. Copy nonce and tag into local stack arrays
        // first so the `*mut` pointers handed to BCrypt own their own
        // backing memory and never alias the caller's slice.
        let mut nonce_buf = [0u8; AES_GCM_NONCE_SIZE];
        nonce_buf.copy_from_slice(&data[..AES_GCM_NONCE_SIZE]);
        let mut tag_buf = [0u8; AES_GCM_TAG_SIZE];
        tag_buf.copy_from_slice(&data[AES_GCM_NONCE_SIZE + ct_len..]);

        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, Some(BCRYPT_CHAIN_MODE_GCM))?;
        let key = create_symmetric_key(&alg, key_bytes)?;

        // Wrap the plaintext buffer in `Zeroizing` so it is scrubbed on every
        // early-return error path (NTSTATUS != SUCCESS, length mismatch). The
        // success path moves the underlying `Vec` out via `std::mem::take`.
        let mut plaintext = Zeroizing::new(vec![0u8; ct_len]);

        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: 1,
            pbNonce: nonce_buf.as_mut_ptr(),
            cbNonce: AES_GCM_NONCE_SIZE as u32,
            pbAuthData: ptr::null_mut(),
            cbAuthData: 0,
            pbTag: tag_buf.as_mut_ptr(),
            cbTag: AES_GCM_TAG_SIZE as u32,
            pbMacContext: ptr::null_mut(),
            cbMacContext: 0,
            cbAAD: 0,
            cbData: 0,
            dwFlags: 0,
        };

        let mut pt_len = 0u32;
        // SAFETY: All pointers are valid. The key handle, auth_info, and buffers
        // are properly sized and initialized for AES-GCM decryption.
        let status = unsafe {
            BCryptDecrypt(
                key.as_raw(),
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len() as u32,
                &mut auth_info as *mut _ as *mut _,
                ptr::null_mut(),
                0,
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut pt_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // GCM decrypt: |pt| must equal |ct|. Mismatch implies a kernel
        // inconsistency; refuse to return a partial result.
        if pt_len as usize != ct_len {
            return Err(HsmError::GeneralError);
        }

        plaintext.truncate(pt_len as usize);
        // Move out of the Zeroizing wrapper for the return; the in-flight
        // buffer was scrub-protected on every error path above.
        Ok(std::mem::take(&mut *plaintext))
    }

    // ========================================================================
    // AES-CBC encrypt/decrypt helpers
    // ========================================================================

    fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let pad_len = block_size - (data.len() % block_size);
        let mut padded = Vec::with_capacity(data.len() + pad_len);
        padded.extend_from_slice(data);
        padded.resize(data.len() + pad_len, pad_len as u8);
        padded
    }

    fn pkcs7_unpad(data: &[u8]) -> HsmResult<Vec<u8>> {
        // Constant-time PKCS#7 unpadding to mitigate Vaudenay-style padding
        // oracles. We must not branch on individual padding bytes; only
        // branch on the aggregated mask after looking at every byte in the
        // last block.
        if data.is_empty() || data.len() % AES_BLOCK_SIZE != 0 {
            return Err(HsmError::EncryptedDataInvalid);
        }
        let pad_len = *data.last().unwrap() as usize;
        // Length-only checks (public to the attacker) - timing is harmless.
        if pad_len == 0 || pad_len > AES_BLOCK_SIZE || pad_len > data.len() {
            return Err(HsmError::EncryptedDataInvalid);
        }
        // Mask-based comparison: walk every byte of the trailing AES block
        // and accumulate a difference-mask. Bytes within the claimed padding
        // region must equal `pad_len`; bytes outside it are masked out.
        use subtle::ConstantTimeEq;
        let block_start = data.len() - AES_BLOCK_SIZE;
        let mut diff: u8 = 0;
        for i in 0..AES_BLOCK_SIZE {
            // 0xFF iff this index lies inside the pad region, 0x00 otherwise.
            // The branch is on `pad_len` (length-only public), not on any
            // ciphertext byte.
            let in_pad_mask: u8 = if i >= AES_BLOCK_SIZE - pad_len {
                0xFF
            } else {
                0x00
            };
            diff |= in_pad_mask & (data[block_start + i] ^ pad_len as u8);
        }
        let ok: bool = diff.ct_eq(&0u8).into();
        if !ok {
            return Err(HsmError::EncryptedDataInvalid);
        }
        Ok(data[..data.len() - pad_len].to_vec())
    }

    fn aes_cbc_encrypt_impl(
        backend: &CngBackend,
        key_bytes: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if key_bytes.len() != 16 && key_bytes.len() != 24 && key_bytes.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(HsmError::MechanismParamInvalid);
        }

        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, Some(BCRYPT_CHAIN_MODE_CBC))?;
        let key = create_symmetric_key(&alg, key_bytes)?;

        let padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE);
        let mut ciphertext = vec![0u8; padded.len()];
        let mut iv_copy = iv.to_vec();
        let mut ct_len = 0u32;

        // SAFETY: All pointers are valid. Key handle is a valid AES-CBC key.
        // iv_copy is AES_BLOCK_SIZE bytes. padded and ciphertext are equal length.
        let status = unsafe {
            BCryptEncrypt(
                key.as_raw(),
                padded.as_ptr() as *mut u8,
                padded.len() as u32,
                ptr::null_mut(),
                iv_copy.as_mut_ptr(),
                iv_copy.len() as u32,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32,
                &mut ct_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // CBC encrypt over already-padded input: |ct| must equal |padded|.
        if ct_len as usize != padded.len() {
            return Err(HsmError::GeneralError);
        }
        ciphertext.truncate(ct_len as usize);
        Ok(ciphertext)
    }

    fn aes_cbc_decrypt_impl(
        backend: &CngBackend,
        key_bytes: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if key_bytes.len() != 16 && key_bytes.len() != 24 && key_bytes.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(HsmError::MechanismParamInvalid);
        }
        if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(HsmError::EncryptedDataInvalid);
        }

        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, Some(BCRYPT_CHAIN_MODE_CBC))?;
        let key = create_symmetric_key(&alg, key_bytes)?;

        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut iv_copy = iv.to_vec();
        let mut pt_len = 0u32;

        // SAFETY: All pointers are valid. Key handle is a valid AES-CBC key.
        // iv_copy is AES_BLOCK_SIZE bytes. Output buffer is same size as input.
        let status = unsafe {
            BCryptDecrypt(
                key.as_raw(),
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len() as u32,
                ptr::null_mut(),
                iv_copy.as_mut_ptr(),
                iv_copy.len() as u32,
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut pt_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // CBC decrypt: |pt| must equal |ct| before unpadding.
        if pt_len as usize != ciphertext.len() {
            return Err(HsmError::GeneralError);
        }
        plaintext.truncate(pt_len as usize);
        pkcs7_unpad(&plaintext)
    }

    // ========================================================================
    // AES-CTR encrypt/decrypt (CNG does not natively support CTR; we use ECB
    // to build a counter-mode stream cipher)
    // ========================================================================

    fn aes_ctr_crypt_impl(
        backend: &CngBackend,
        key_bytes: &[u8],
        iv: &[u8],
        input: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if key_bytes.len() != 16 && key_bytes.len() != 24 && key_bytes.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(HsmError::MechanismParamInvalid);
        }
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, Some(BCRYPT_CHAIN_MODE_ECB))?;
        let key = create_symmetric_key(&alg, key_bytes)?;

        // Batch the counter blocks and keystream into a single BCryptEncrypt
        // call. ECB on N counter blocks = N independent AES encryptions, which
        // is what CTR mode requires. This eliminates one FFI call per 16-byte
        // chunk (audit perf finding).
        let n_blocks = (input.len() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
        let total_len = n_blocks * AES_BLOCK_SIZE;

        // The keystream is sensitive (XORing into ciphertext recovers
        // plaintext under known-key conditions). Wrap both buffers in
        // `Zeroizing` so every error path scrubs them on Drop.
        let mut counters = Zeroizing::new(vec![0u8; total_len]);
        let mut keystream = Zeroizing::new(vec![0u8; total_len]);
        let mut ctr = [0u8; AES_BLOCK_SIZE];
        ctr.copy_from_slice(iv);
        for blk in 0..n_blocks {
            counters[blk * AES_BLOCK_SIZE..(blk + 1) * AES_BLOCK_SIZE].copy_from_slice(&ctr);
            // Increment counter (big-endian).
            for byte in ctr.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }

        let mut ks_len = 0u32;
        // SAFETY: Key handle is a valid AES-ECB key. `counters` and
        // `keystream` have identical block-multiple lengths.
        let status = unsafe {
            BCryptEncrypt(
                key.as_raw(),
                counters.as_mut_ptr(),
                total_len as u32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                keystream.as_mut_ptr(),
                total_len as u32,
                &mut ks_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            // Zeroizing drop scrubs `keystream` and `counters` on this path.
            return Err(ntstatus_to_hsm_error(status));
        }
        if ks_len as usize != total_len {
            return Err(HsmError::GeneralError);
        }

        // Wrap the output in `Zeroizing` for symmetry with the keystream
        // buffer above: for AES-CTR decrypt this `output` is plaintext, which
        // is sensitive; for encrypt it is ciphertext, but blanket-scrubbing
        // every error path keeps the policy uniform and removes any need for
        // callers to reason about whether `Drop` will leave residue. We
        // `into_inner()` on the success path so the returned `Vec<u8>` retains
        // ownership (the caller is then responsible for further handling).
        let mut output = Zeroizing::new(vec![0u8; input.len()]);
        for i in 0..input.len() {
            output[i] = input[i] ^ keystream[i];
        }
        // Move the `Vec` out of the Zeroizing wrapper for the return; on every
        // *error* path above, `output` would not yet exist, so the wrapper
        // primarily protects the in-flight buffer against panic-unwind.
        Ok(std::mem::take(&mut *output))
    }

    // ========================================================================
    // Hashing helpers
    // ========================================================================

    fn bcrypt_alg_for_hash(hash_alg: HashAlg) -> *const u16 {
        match hash_alg {
            HashAlg::Sha256 => BCRYPT_SHA256_ALGORITHM,
            HashAlg::Sha384 => BCRYPT_SHA384_ALGORITHM,
            HashAlg::Sha512 => BCRYPT_SHA512_ALGORITHM,
        }
    }

    fn hash_len_for_alg(hash_alg: HashAlg) -> usize {
        match hash_alg {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    fn bcrypt_hash(backend: &CngBackend, alg_id: *const u16, data: &[u8]) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(alg_id, 0, None)?;

        // Query hash output length.
        let mut hash_len = 0u32;
        let mut result_size = 0u32;
        // SAFETY: Querying BCRYPT_HASH_LENGTH property from a valid algorithm
        // handle produced by `open_alg`. `hash_len` is a local `u32` (4 bytes)
        // — we pass its address as `*mut u8` and report its exact size to
        // CNG via the `std::mem::size_of::<u32>()` argument. `result_size`
        // receives the number of bytes written and is validated below.
        let status = unsafe {
            BCryptGetProperty(
                alg.as_raw() as *mut _,
                BCRYPT_HASH_LENGTH,
                &mut hash_len as *mut u32 as *mut u8,
                std::mem::size_of::<u32>() as u32,
                &mut result_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // Audit finding CNG-2: validate that CNG wrote exactly 4 bytes into
        // `hash_len`. A lying/driver-corrupted `result_size > 4` would imply
        // that BCrypt scribbled past the `u32` on our stack; refuse to use
        // a partially-written value.
        if result_size as usize != std::mem::size_of::<u32>() {
            tracing::error!(
                result_size = result_size,
                expected = std::mem::size_of::<u32>() as u32,
                "BCryptGetProperty(BCRYPT_HASH_LENGTH) returned unexpected pcbResult"
            );
            return Err(HsmError::GeneralError);
        }

        let mut hash_handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
        // SAFETY: BCryptCreateHash creates a hash object. `alg.as_raw()` is valid.
        // We pass null for the hash object buffer (CNG allocates internally).
        let status = unsafe {
            BCryptCreateHash(
                alg.as_raw(),
                &mut hash_handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let hash_handle = HashHandle(hash_handle);

        // Feed data.
        // SAFETY: hash_handle is a valid hash object. data is a valid slice.
        let status = unsafe {
            BCryptHashData(
                hash_handle.as_raw(),
                data.as_ptr() as *mut u8,
                data.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        // Finalize.
        let mut hash_output = vec![0u8; hash_len as usize];
        // SAFETY: hash_handle is valid. hash_output is correctly sized.
        let status = unsafe {
            BCryptFinishHash(
                hash_handle.as_raw(),
                hash_output.as_mut_ptr(),
                hash_output.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        Ok(hash_output)
    }

    // ========================================================================
    // RSA helpers
    // ========================================================================

    /// Parse a PKCS#8 DER private key into a CNG BCRYPT_RSAFULLPRIVATE_BLOB.
    /// This is a minimal ASN.1 parser that extracts RSA parameters.
    /// For production, you would use a proper ASN.1 library. Here we use
    /// the `rsa` crate just for parsing, then feed parameters to CNG.
    fn import_rsa_private_key(alg: &AlgHandle, private_key_der: &[u8]) -> HsmResult<KeyHandle> {
        // Use the rsa crate to parse the DER, then build a CNG blob.
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use rsa::RsaPrivateKey;

        let priv_key =
            RsaPrivateKey::from_pkcs8_der(private_key_der).map_err(|_| HsmError::DataInvalid)?;

        let n = priv_key.n().to_bytes_be();
        let e = priv_key.e().to_bytes_be();
        // Audit fix: `d`, `p`, `q`, `dp`, `dq`, `qinv` are the secret RSA CRT
        // components. Wrap each in `Zeroizing<Vec<u8>>` so they scrub on drop
        // even on error paths (between extraction and the BCryptImportKeyPair
        // call below). The blob built from these is zeroized at the bottom
        // of this function, but the per-component temporaries also need to
        // be wiped — keeping them as bare `Vec<u8>` left their heap allocations
        // unscrubbed on Drop.
        let d = zeroize::Zeroizing::new(priv_key.d().to_bytes_be());
        let primes = priv_key.primes();
        if primes.len() < 2 {
            return Err(HsmError::DataInvalid);
        }
        let p = zeroize::Zeroizing::new(primes[0].to_bytes_be());
        let q = zeroize::Zeroizing::new(primes[1].to_bytes_be());

        // CRT parameters - audit fix: previously these silently fell back to
        // empty Vec on missing-component PKCS#8 inputs, which would produce a
        // malformed BCRYPT_RSAFULLPRIVATE_BLOB that CNG would still try to
        // import. Reject malformed PKCS#8 explicitly with HsmError::DataInvalid.
        let dp = zeroize::Zeroizing::new(
            priv_key
                .dp()
                .map(|v| v.to_bytes_be())
                .ok_or(HsmError::DataInvalid)?,
        );
        let dq = zeroize::Zeroizing::new(
            priv_key
                .dq()
                .map(|v| v.to_bytes_be())
                .ok_or(HsmError::DataInvalid)?,
        );
        // qinv returns BigInt (signed); convert to unsigned big-endian bytes.
        let qinv = zeroize::Zeroizing::new(
            priv_key
                .qinv()
                .map(|v| {
                    // Convert BigInt to magnitude bytes (unsigned big-endian).
                    let (_sign, bytes) = v.to_bytes_be();
                    bytes
                })
                .ok_or(HsmError::DataInvalid)?,
        );

        let key_byte_len = n.len();
        let half_len = (key_byte_len + 1) / 2;

        // Build BCRYPT_RSAFULLPRIVATE_BLOB.
        // Header: BCRYPT_RSAKEY_BLOB (24 bytes) followed by:
        //   PublicExponent[cbPublicExp], Modulus[cbKeyLength],
        //   Prime1[cbKeyLength/2], Prime2[cbKeyLength/2],
        //   Exponent1[cbKeyLength/2], Exponent2[cbKeyLength/2],
        //   Coefficient[cbKeyLength/2], PrivateExponent[cbKeyLength]
        let header_size = 24; // sizeof(BCRYPT_RSAKEY_BLOB)
        let blob_size = header_size + e.len() + key_byte_len + half_len * 5 + key_byte_len;

        let mut blob = vec![0u8; blob_size];

        // Write header fields as little-endian u32.
        fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
            buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }

        write_u32_le(&mut blob, 0, BCRYPT_RSAFULLPRIVATE_MAGIC);
        write_u32_le(&mut blob, 4, (key_byte_len * 8) as u32); // BitLength
        write_u32_le(&mut blob, 8, e.len() as u32); // cbPublicExp
        write_u32_le(&mut blob, 12, key_byte_len as u32); // cbModulus
        write_u32_le(&mut blob, 16, half_len as u32); // cbPrime1
        write_u32_le(&mut blob, 20, half_len as u32); // cbPrime2

        let mut offset = header_size;

        fn copy_padded(dest: &mut [u8], offset: &mut usize, src: &[u8], target_len: usize) {
            let start = target_len.saturating_sub(src.len());
            dest[*offset + start..*offset + start + src.len()].copy_from_slice(src);
            *offset += target_len;
        }

        copy_padded(&mut blob, &mut offset, &e, e.len());
        copy_padded(&mut blob, &mut offset, &n, key_byte_len);
        copy_padded(&mut blob, &mut offset, &p, half_len);
        copy_padded(&mut blob, &mut offset, &q, half_len);
        copy_padded(&mut blob, &mut offset, &dp, half_len);
        copy_padded(&mut blob, &mut offset, &dq, half_len);
        copy_padded(&mut blob, &mut offset, &qinv, half_len);
        copy_padded(&mut blob, &mut offset, &d, key_byte_len);

        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: `alg.as_raw()` is a valid RSA algorithm handle. `blob` contains
        // a properly formatted BCRYPT_RSAFULLPRIVATE_BLOB. `key_handle` receives
        // the imported key.
        let status = unsafe {
            BCryptImportKeyPair(
                alg.as_raw(),
                ptr::null_mut(),
                BCRYPT_RSAFULLPRIVATE_BLOB,
                &mut key_handle,
                blob.as_mut_ptr(),
                blob.len() as u32,
                0,
            )
        };

        // Zeroize the blob containing private key material.
        zeroize::Zeroize::zeroize(&mut blob[..]);

        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(KeyHandle(key_handle))
    }

    fn import_rsa_public_key(
        alg: &AlgHandle,
        modulus: &[u8],
        public_exponent: &[u8],
    ) -> HsmResult<KeyHandle> {
        let header_size = 24;
        let blob_size = header_size + public_exponent.len() + modulus.len();
        let mut blob = vec![0u8; blob_size];

        fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
            buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }

        write_u32_le(&mut blob, 0, BCRYPT_RSAPUBLIC_MAGIC);
        write_u32_le(&mut blob, 4, (modulus.len() * 8) as u32);
        write_u32_le(&mut blob, 8, public_exponent.len() as u32);
        write_u32_le(&mut blob, 12, modulus.len() as u32);
        write_u32_le(&mut blob, 16, 0); // cbPrime1
        write_u32_le(&mut blob, 20, 0); // cbPrime2

        let mut offset = header_size;
        blob[offset..offset + public_exponent.len()].copy_from_slice(public_exponent);
        offset += public_exponent.len();
        blob[offset..offset + modulus.len()].copy_from_slice(modulus);

        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: `alg.as_raw()` is a valid RSA algorithm handle. `blob` is a
        // valid BCRYPT_RSAPUBLIC_BLOB with correct header and data layout.
        let status = unsafe {
            BCryptImportKeyPair(
                alg.as_raw(),
                ptr::null_mut(),
                BCRYPT_RSAPUBLIC_BLOB,
                &mut key_handle,
                blob.as_mut_ptr(),
                blob.len() as u32,
                0,
            )
        };

        // Zeroize the blob for parity with the private-import path. The bytes
        // are public (modulus + exponent), but blanket-scrubbing every CNG
        // blob keeps the policy uniform: operators auditing the backend never
        // have to reason about which buffers are sensitive, and a future
        // refactor that grows this blob to include private material will not
        // accidentally leak.
        zeroize::Zeroize::zeroize(&mut blob[..]);

        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(KeyHandle(key_handle))
    }

    // ========================================================================
    // RSA PKCS#1 v1.5 sign/verify
    // ========================================================================

    fn rsa_pkcs1v15_sign_impl(
        backend: &CngBackend,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_private_key(&alg, private_key_der)?;

        let (hash_data, pad_info) = match hash_alg {
            Some(h) => {
                let hash_alg_id = bcrypt_alg_for_hash(h);
                let digest = bcrypt_hash(backend, hash_alg_id, data)?;
                let pad = BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: hash_alg_id,
                };
                (digest, pad)
            }
            None => {
                // Raw PKCS#1 v1.5 sign (data is already a DigestInfo or raw).
                let pad = BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: ptr::null(),
                };
                (data.to_vec(), pad)
            }
        };

        // First call to get output size.
        let mut sig_len = 0u32;
        // SAFETY: key.as_raw() is a valid RSA key. pad_info is a valid
        // BCRYPT_PKCS1_PADDING_INFO. We query the required output size.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                hash_data.as_ptr() as *mut u8,
                hash_data.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut signature = vec![0u8; sig_len as usize];
        // SAFETY: Same as above, but now with a properly sized output buffer.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                hash_data.as_ptr() as *mut u8,
                hash_data.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut sig_len,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        signature.truncate(sig_len as usize);
        Ok(signature)
    }

    fn rsa_pkcs1v15_verify_impl(
        backend: &CngBackend,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> HsmResult<bool> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_public_key(&alg, modulus, public_exponent)?;

        let (hash_data, pad_info) = match hash_alg {
            Some(h) => {
                let hash_alg_id = bcrypt_alg_for_hash(h);
                let digest = bcrypt_hash(backend, hash_alg_id, data)?;
                let pad = BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: hash_alg_id,
                };
                (digest, pad)
            }
            None => {
                let pad = BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: ptr::null(),
                };
                (data.to_vec(), pad)
            }
        };

        // SAFETY: key.as_raw() is a valid RSA public key. pad_info and hash_data
        // are valid. signature is a valid byte slice.
        let status = unsafe {
            BCryptVerifySignature(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                hash_data.as_ptr() as *mut u8,
                hash_data.len() as u32,
                signature.as_ptr() as *mut u8,
                signature.len() as u32,
                BCRYPT_PAD_PKCS1,
            )
        };

        match status {
            s if s == STATUS_SUCCESS => Ok(true),
            _ => Ok(false),
        }
    }

    // ========================================================================
    // RSA PSS sign/verify
    // ========================================================================

    fn rsa_pss_sign_impl(
        backend: &CngBackend,
        private_key_der: &[u8],
        data: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_private_key(&alg, private_key_der)?;

        let hash_alg_id = bcrypt_alg_for_hash(hash_alg);
        let digest = bcrypt_hash(backend, hash_alg_id, data)?;
        let salt_len = hash_len_for_alg(hash_alg);

        let pad_info = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: hash_alg_id,
            cbSalt: salt_len as u32,
        };

        let mut sig_len = 0u32;
        // SAFETY: key.as_raw() is a valid RSA key. pad_info is properly set for PSS.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                BCRYPT_PAD_PSS,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut signature = vec![0u8; sig_len as usize];
        // SAFETY: Same as above, with properly sized output buffer.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut sig_len,
                BCRYPT_PAD_PSS,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        signature.truncate(sig_len as usize);
        Ok(signature)
    }

    fn rsa_pss_verify_impl(
        backend: &CngBackend,
        modulus: &[u8],
        public_exponent: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_public_key(&alg, modulus, public_exponent)?;

        let hash_alg_id = bcrypt_alg_for_hash(hash_alg);
        let digest = bcrypt_hash(backend, hash_alg_id, data)?;
        let salt_len = hash_len_for_alg(hash_alg);

        let pad_info = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: hash_alg_id,
            cbSalt: salt_len as u32,
        };

        // SAFETY: key.as_raw() is a valid RSA public key. pad_info, digest, and
        // signature are all valid byte buffers.
        let status = unsafe {
            BCryptVerifySignature(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                signature.as_ptr() as *mut u8,
                signature.len() as u32,
                BCRYPT_PAD_PSS,
            )
        };

        match status {
            s if s == STATUS_SUCCESS => Ok(true),
            _ => Ok(false),
        }
    }

    // ========================================================================
    // RSA prehashed sign/verify
    // ========================================================================

    fn rsa_pkcs1v15_sign_prehashed_impl(
        backend: &CngBackend,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_private_key(&alg, private_key_der)?;

        let pad_info = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: bcrypt_alg_for_hash(hash_alg),
        };

        let mut sig_len = 0u32;
        // SAFETY: key is a valid RSA private key. pad_info is valid PKCS1 info.
        // digest is the pre-computed hash to sign.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut signature = vec![0u8; sig_len as usize];
        // SAFETY: Same as above with properly sized output.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut sig_len,
                BCRYPT_PAD_PKCS1,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        signature.truncate(sig_len as usize);
        Ok(signature)
    }

    fn rsa_pkcs1v15_verify_prehashed_impl(
        backend: &CngBackend,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_public_key(&alg, modulus, public_exponent)?;

        let pad_info = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: bcrypt_alg_for_hash(hash_alg),
        };

        // SAFETY: key is a valid RSA public key. All buffers are valid.
        let status = unsafe {
            BCryptVerifySignature(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                signature.as_ptr() as *mut u8,
                signature.len() as u32,
                BCRYPT_PAD_PKCS1,
            )
        };
        Ok(status == STATUS_SUCCESS)
    }

    fn rsa_pss_sign_prehashed_impl(
        backend: &CngBackend,
        private_key_der: &[u8],
        digest: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_private_key(&alg, private_key_der)?;

        let pad_info = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: bcrypt_alg_for_hash(hash_alg),
            cbSalt: hash_len_for_alg(hash_alg) as u32,
        };

        let mut sig_len = 0u32;
        // SAFETY: key is a valid RSA private key. pad_info is valid PSS info.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                BCRYPT_PAD_PSS,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut signature = vec![0u8; sig_len as usize];
        // SAFETY: Same as above with output buffer.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut sig_len,
                BCRYPT_PAD_PSS,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        signature.truncate(sig_len as usize);
        Ok(signature)
    }

    fn rsa_pss_verify_prehashed_impl(
        backend: &CngBackend,
        modulus: &[u8],
        public_exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> HsmResult<bool> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_public_key(&alg, modulus, public_exponent)?;

        let pad_info = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: bcrypt_alg_for_hash(hash_alg),
            cbSalt: hash_len_for_alg(hash_alg) as u32,
        };

        // SAFETY: key is a valid RSA public key. All buffers are valid.
        let status = unsafe {
            BCryptVerifySignature(
                key.as_raw(),
                &pad_info as *const _ as *const _,
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                signature.as_ptr() as *mut u8,
                signature.len() as u32,
                BCRYPT_PAD_PSS,
            )
        };
        Ok(status == STATUS_SUCCESS)
    }

    // ========================================================================
    // ECDSA helpers
    // ========================================================================

    /// Import an EC private key (raw scalar bytes) into CNG for ECDSA.
    /// `curve_alg` is the algorithm provider (P256 or P384).
    /// `scalar` is the private key scalar (32 or 48 bytes).
    ///
    /// The public point Q = d*G is derived inside the FIPS-validated CNG
    /// module via [`derive_ecc_public_via_ncrypt`] — no pure-Rust scalar
    /// multiplication on the secret scalar happens in this process.
    fn import_ecdsa_private_key(
        alg: &AlgHandle,
        scalar: &[u8],
        curve_size: usize,
        private_magic: u32,
    ) -> HsmResult<KeyHandle> {
        // CNG's BCRYPT_ECCPRIVATE_BLOB requires the public point (X, Y) and
        // the private scalar (d) in the same blob — there is no documented
        // BCrypt path that accepts d alone. To avoid performing the
        // cryptographically sensitive scalar multiplication on the secret
        // outside the FIPS boundary, we round-trip d through the Microsoft
        // Software Key Storage Provider via NCryptImportKey + PKCS#8, which
        // internally derives Q from d, then export Q as a public blob.
        // The (X, Y) we feed into BCRYPT_ECCPRIVATE_BLOB therefore come
        // straight from FIPS-validated CNG code.
        let (x, y) = derive_ecc_public_via_ncrypt(scalar, curve_size)?;

        // Build BCRYPT_ECCKEY_BLOB: magic(4) + cbKey(4) + X(cbKey) + Y(cbKey) + d(cbKey)
        let blob_size = 8 + curve_size * 3;
        let mut blob = Zeroizing::new(vec![0u8; blob_size]);

        blob[0..4].copy_from_slice(&private_magic.to_le_bytes());
        blob[4..8].copy_from_slice(&(curve_size as u32).to_le_bytes());

        let mut off = 8;
        // Pad X to curve_size.
        let x_start = curve_size.saturating_sub(x.len());
        blob[off + x_start..off + x_start + x.len()].copy_from_slice(&x);
        off += curve_size;

        let y_start = curve_size.saturating_sub(y.len());
        blob[off + y_start..off + y_start + y.len()].copy_from_slice(&y);
        off += curve_size;

        let d_start = curve_size.saturating_sub(scalar.len());
        blob[off + d_start..off + d_start + scalar.len()].copy_from_slice(scalar);

        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: alg is a valid ECDSA algorithm handle. blob is a properly
        // formatted BCRYPT_ECCKEY_BLOB with private key data. The blob type
        // for ECC private keys is the same regardless of curve
        // (P-256/P-384); the curve is encoded in private_magic written into
        // the blob header (audit fix: removed dead if/else where both arms
        // returned BCRYPT_ECCPRIVATE_BLOB).
        let status = unsafe {
            BCryptImportKeyPair(
                alg.as_raw(),
                ptr::null_mut(),
                BCRYPT_ECCPRIVATE_BLOB,
                &mut key_handle,
                blob.as_mut_ptr(),
                blob.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(KeyHandle(key_handle))
    }

    /// Import an EC public key (SEC1 uncompressed) into CNG for ECDSA verification.
    fn import_ecdsa_public_key(
        alg: &AlgHandle,
        public_key_sec1: &[u8],
        curve_size: usize,
        public_magic: u32,
    ) -> HsmResult<KeyHandle> {
        // SEC1 uncompressed: 0x04 || X || Y
        if public_key_sec1.len() != 1 + 2 * curve_size || public_key_sec1[0] != 0x04 {
            return Err(HsmError::DataInvalid);
        }

        let x = &public_key_sec1[1..1 + curve_size];
        let y = &public_key_sec1[1 + curve_size..];

        // Build BCRYPT_ECCKEY_BLOB: magic(4) + cbKey(4) + X(cbKey) + Y(cbKey)
        let blob_size = 8 + curve_size * 2;
        let mut blob = vec![0u8; blob_size];

        blob[0..4].copy_from_slice(&public_magic.to_le_bytes());
        blob[4..8].copy_from_slice(&(curve_size as u32).to_le_bytes());

        blob[8..8 + curve_size].copy_from_slice(x);
        blob[8 + curve_size..8 + 2 * curve_size].copy_from_slice(y);

        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: alg is a valid ECDSA algorithm handle. blob is a properly
        // formatted BCRYPT_ECCKEY_BLOB with public key data.
        let status = unsafe {
            BCryptImportKeyPair(
                alg.as_raw(),
                ptr::null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                &mut key_handle,
                blob.as_mut_ptr(),
                blob.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(KeyHandle(key_handle))
    }

    // ========================================================================
    // FIPS-clean public-point derivation (NCrypt + PKCS#8)
    // ========================================================================

    /// RAII wrapper for `NCRYPT_PROV_HANDLE` returned by
    /// `NCryptOpenStorageProvider`.
    struct NCryptProvHandle(NCRYPT_PROV_HANDLE);

    impl Drop for NCryptProvHandle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: self.0 is a valid NCRYPT_PROV_HANDLE returned by
                // NCryptOpenStorageProvider, freed exactly once on drop.
                unsafe {
                    NCryptFreeObject(self.0);
                }
            }
        }
    }

    /// RAII wrapper for `NCRYPT_KEY_HANDLE` returned by `NCryptImportKey`.
    /// `NCryptFreeObject` releases the in-memory key object; for ephemeral
    /// keys (no key name supplied at import time) this is the entirety of
    /// the cleanup — nothing is written to the on-disk key store.
    struct NCryptKeyHandle(NCRYPT_KEY_HANDLE);

    impl Drop for NCryptKeyHandle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: self.0 is a valid NCRYPT_KEY_HANDLE returned by
                // NCryptImportKey, freed exactly once on drop.
                unsafe {
                    NCryptFreeObject(self.0);
                }
            }
        }
    }

    /// Encode an ECC private key as PKCS#8 [RFC 5958] wrapping an
    /// RFC 5915 `ECPrivateKey` whose `publicKey [1]` field is **omitted**.
    ///
    /// Microsoft's Software KSP, when given a `NCRYPT_PKCS8_PRIVATE_KEY_BLOB`
    /// with the public-key field absent, derives `Q = d*G` inside the
    /// FIPS-validated CNG kernel module — this is the only documented BCrypt/
    /// NCrypt entry point that takes a private scalar without a paired
    /// public point. See:
    ///
    /// - <https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey>
    ///   ("If a key name is not supplied, the Microsoft Software KSP treats
    ///   the key as ephemeral and does not store it persistently.")
    /// - <https://datatracker.ietf.org/doc/html/rfc5915> (`publicKey [1]
    ///   BIT STRING OPTIONAL`)
    fn encode_pkcs8_ec_private_key(scalar: &[u8], curve_size: usize) -> HsmResult<Vec<u8>> {
        // OIDs as DER-encoded OBJECT IDENTIFIER content octets.
        // id-ecPublicKey = 1.2.840.10045.2.1
        const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        // secp256r1 = 1.2.840.10045.3.1.7
        const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        // secp384r1 = 1.3.132.0.34
        const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];

        let curve_oid: &[u8] = match curve_size {
            32 => OID_P256,
            48 => OID_P384,
            _ => return Err(HsmError::KeySizeRange),
        };

        // All inputs are short (≤ a few hundred bytes), so plain
        // short-form-only DER length encoding (0x80-marker for ≥128 bytes)
        // is sufficient. We keep a single helper that handles both forms.
        fn der_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
            out.push(tag);
            let len = value.len();
            if len < 0x80 {
                out.push(len as u8);
            } else if len < 0x100 {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push((len & 0xff) as u8);
            }
            out.extend_from_slice(value);
        }

        // Inner ECPrivateKey (RFC 5915):
        //   SEQUENCE {
        //     INTEGER 1,
        //     OCTET STRING d,
        //     -- parameters [0] OPTIONAL  -- omitted (carried in outer AlgorithmIdentifier)
        //     -- publicKey  [1] OPTIONAL  -- OMITTED so CNG derives Q from d
        //   }
        // The private-key scalar must be padded to the full curve size.
        let mut padded_scalar = Zeroizing::new(vec![0u8; curve_size]);
        let pad = curve_size.saturating_sub(scalar.len());
        if scalar.len() > curve_size {
            return Err(HsmError::AttributeValueInvalid);
        }
        padded_scalar[pad..].copy_from_slice(scalar);

        let mut ec_priv_body = Vec::with_capacity(curve_size + 16);
        der_tlv(0x02, &[0x01], &mut ec_priv_body); // INTEGER 1
        der_tlv(0x04, &padded_scalar, &mut ec_priv_body); // OCTET STRING d
        let mut ec_private_key = Vec::with_capacity(ec_priv_body.len() + 4);
        der_tlv(0x30, &ec_priv_body, &mut ec_private_key); // SEQUENCE

        // Outer PrivateKeyInfo (RFC 5958 / PKCS #8 v1):
        //   SEQUENCE {
        //     INTEGER 0,
        //     AlgorithmIdentifier { OID ecPublicKey, OID curve },
        //     OCTET STRING ECPrivateKey
        //   }
        let mut oid_pk = Vec::with_capacity(OID_EC_PUBLIC_KEY.len() + 2);
        der_tlv(0x06, OID_EC_PUBLIC_KEY, &mut oid_pk);
        let mut oid_curve = Vec::with_capacity(curve_oid.len() + 2);
        der_tlv(0x06, curve_oid, &mut oid_curve);

        let mut alg_id_body = Vec::with_capacity(oid_pk.len() + oid_curve.len());
        alg_id_body.extend_from_slice(&oid_pk);
        alg_id_body.extend_from_slice(&oid_curve);
        let mut alg_id = Vec::with_capacity(alg_id_body.len() + 4);
        der_tlv(0x30, &alg_id_body, &mut alg_id);

        let mut priv_octet = Vec::with_capacity(ec_private_key.len() + 4);
        der_tlv(0x04, &ec_private_key, &mut priv_octet);

        let mut pki_body = Vec::with_capacity(3 + alg_id.len() + priv_octet.len());
        der_tlv(0x02, &[0x00], &mut pki_body); // INTEGER 0 (v1)
        pki_body.extend_from_slice(&alg_id);
        pki_body.extend_from_slice(&priv_octet);

        let mut pki = Vec::with_capacity(pki_body.len() + 4);
        der_tlv(0x30, &pki_body, &mut pki);

        Ok(pki)
    }

    /// Derive the public point `Q = d*G` for a NIST P-256 or P-384 private
    /// scalar by round-tripping through the Microsoft Software Key Storage
    /// Provider.
    ///
    /// This replaces the previous `compute_p{256,384}_public_point` helpers
    /// (which performed the scalar multiplication using the non-FIPS pure-
    /// Rust `p256` / `p384` crates) so that every operation touching the
    /// secret scalar happens inside the FIPS-validated Windows CNG module.
    ///
    /// The imported key is ephemeral: per MSDN, the Software KSP does not
    /// persist keys imported without a key name (no
    /// `NCRYPTBUFFER_PKCS_KEY_NAME` parameter is supplied here). The key
    /// object is destroyed via `NCryptFreeObject` on `Drop` of the RAII
    /// wrapper before this function returns.
    ///
    /// Returns the big-endian `(X, Y)` coordinates of the derived public
    /// point, each padded to `curve_size` bytes.
    fn derive_ecc_public_via_ncrypt(
        scalar: &[u8],
        curve_size: usize,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        if scalar.is_empty() || scalar.len() > curve_size {
            return Err(HsmError::AttributeValueInvalid);
        }
        // Reject the all-zero scalar at the API boundary — it would be a
        // bug for a caller to hand us d == 0, but CNG's error mapping is
        // less informative than this check.
        if scalar.iter().all(|&b| b == 0) {
            return Err(HsmError::AttributeValueInvalid);
        }

        // Helper: map a Windows HRESULT (0 == ERROR_SUCCESS, anything else
        // is a failure code in the SECURITY_STATUS / NTE_* / 0x8009xxxx
        // family) to an HsmError. NCrypt error codes are not exhaustively
        // remapped — the caller will see a generic invalid-attribute or
        // host-memory error and trace logs carry the raw HRESULT for
        // diagnosis.
        fn hresult_to_hsm_error(hr: i32) -> HsmError {
            let u = hr as u32;
            tracing::warn!(hresult = format!("0x{:08X}", u), "NCrypt call failed");
            match u {
                // NTE_NO_MEMORY
                0x8009_000E => HsmError::HostMemory,
                // NTE_INVALID_PARAMETER / NTE_BAD_KEY / NTE_BAD_DATA
                0x8009_0027 | 0x8009_0003 | 0x8009_0005 => HsmError::AttributeValueInvalid,
                _ => HsmError::GeneralError,
            }
        }

        // 1. Open the Microsoft Software KSP.
        let mut prov: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: MS_KEY_STORAGE_PROVIDER is a static null-terminated UTF-16
        // string from windows-sys. prov is a fresh stack slot the call
        // populates on success.
        let hr = unsafe { NCryptOpenStorageProvider(&mut prov, MS_KEY_STORAGE_PROVIDER, 0) };
        if hr != 0 {
            return Err(hresult_to_hsm_error(hr));
        }
        let prov = NCryptProvHandle(prov);

        // 2. Build a PKCS#8 PrivateKeyInfo containing only the private
        //    scalar. The KSP will derive Q internally.
        let pkcs8 = Zeroizing::new(encode_pkcs8_ec_private_key(scalar, curve_size)?);

        // 3. Import as an ephemeral key. No key name is supplied (no
        //    pParameterList with NCRYPTBUFFER_PKCS_KEY_NAME), so per MSDN
        //    "the Microsoft Software KSP treats the key as ephemeral and
        //    does not store it persistently".
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: prov is a valid storage provider handle from above.
        // NCRYPT_PKCS8_PRIVATE_KEY_BLOB is a static UTF-16 string. pkcs8 is
        // a contiguous buffer of pkcs8.len() bytes. key is a fresh stack
        // slot populated on success.
        let hr = unsafe {
            NCryptImportKey(
                prov.0,
                0,
                NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                ptr::null(),
                &mut key,
                pkcs8.as_ptr(),
                pkcs8.len() as u32,
                NCRYPT_SILENT_FLAG,
            )
        };
        if hr != 0 {
            return Err(hresult_to_hsm_error(hr));
        }
        let key = NCryptKeyHandle(key);

        // 4. Export the *public* part as BCRYPT_ECCPUBLIC_BLOB. The KSP
        //    will have derived (X, Y) from d during import.
        let mut needed: u32 = 0;
        // SAFETY: key.0 is a valid key handle from NCryptImportKey above.
        // BCRYPT_ECCPUBLIC_BLOB is a static UTF-16 string. The first call
        // is the "query required buffer size" form (pbOutput=null,
        // cbOutput=0) — `needed` receives the byte count.
        let hr = unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut needed,
                0,
            )
        };
        if hr != 0 {
            return Err(hresult_to_hsm_error(hr));
        }
        // Minimum sane size: 8-byte BCRYPT_ECCKEY_BLOB header + X + Y.
        let expected = 8 + 2 * curve_size;
        if (needed as usize) < expected {
            tracing::error!(
                needed = needed,
                expected = expected as u32,
                "NCryptExportKey returned undersized buffer for ECC public blob"
            );
            return Err(HsmError::GeneralError);
        }

        let mut buf = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: buf is `needed` bytes; key.0 is valid; output args are
        // local stack slots.
        let hr = unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                buf.as_mut_ptr(),
                needed,
                &mut written,
                0,
            )
        };
        if hr != 0 {
            return Err(hresult_to_hsm_error(hr));
        }
        if (written as usize) < expected || (written as usize) > buf.len() {
            tracing::error!(
                written = written,
                expected = expected as u32,
                "NCryptExportKey wrote an unexpected number of bytes"
            );
            return Err(HsmError::GeneralError);
        }
        buf.truncate(written as usize);

        // 5. Parse BCRYPT_ECCKEY_BLOB: magic(4) || cbKey(4) || X(cbKey) || Y(cbKey).
        let cb_key = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if cb_key != curve_size {
            tracing::error!(
                cb_key = cb_key as u32,
                expected = curve_size as u32,
                "NCryptExportKey returned blob with mismatched cbKey"
            );
            return Err(HsmError::GeneralError);
        }
        let x = buf[8..8 + curve_size].to_vec();
        let y = buf[8 + curve_size..8 + 2 * curve_size].to_vec();
        Ok((x, y))
        // key + prov drop here, calling NCryptFreeObject on both.
    }

    // ------------------------------------------------------------------------
    // Pure-Rust public-point derivation — RETAINED FOR TESTS ONLY
    // ------------------------------------------------------------------------
    // The functions below were the production scalar-multiplication path
    // until they were retired in favour of `derive_ecc_public_via_ncrypt`
    // (which keeps the secret scalar inside the FIPS-validated CNG module).
    //
    // They are kept under `#[cfg(test)]` so that the smoke test in this
    // file can cross-check CNG's derived (X, Y) against an independent
    // implementation. They MUST NOT be referenced from non-test code.

    /// Compute P-256 public point from scalar using p256 crate.
    #[cfg(test)]
    fn compute_p256_public_point(scalar: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey;

        let sk = SecretKey::from_slice(scalar).map_err(|_| HsmError::DataInvalid)?;
        let pk = sk.public_key();
        let point = pk.to_encoded_point(false);
        let x = point.x().ok_or(HsmError::DataInvalid)?.to_vec();
        let y = point.y().ok_or(HsmError::DataInvalid)?.to_vec();
        Ok((x, y))
    }

    /// Compute P-384 public point from scalar using p384 crate.
    #[cfg(test)]
    fn compute_p384_public_point(scalar: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        use p384::SecretKey;

        let sk = SecretKey::from_slice(scalar).map_err(|_| HsmError::DataInvalid)?;
        let pk = sk.public_key();
        let point = pk.to_encoded_point(false);
        let x = point.x().ok_or(HsmError::DataInvalid)?.to_vec();
        let y = point.y().ok_or(HsmError::DataInvalid)?.to_vec();
        Ok((x, y))
    }

    /// CNG ECDSA produces raw R||S signatures; the trait expects DER-encoded.
    fn raw_ecdsa_to_der(raw: &[u8]) -> HsmResult<Vec<u8>> {
        if raw.len() % 2 != 0 {
            return Err(HsmError::SignatureInvalid);
        }
        let half = raw.len() / 2;
        let r = &raw[..half];
        let s = &raw[half..];

        fn encode_integer(val: &[u8]) -> Vec<u8> {
            // Strip leading zeros but keep at least one byte.
            let stripped = match val.iter().position(|&b| b != 0) {
                Some(pos) => &val[pos..],
                None => &[0],
            };
            let needs_pad = stripped[0] & 0x80 != 0;
            let len = stripped.len() + if needs_pad { 1 } else { 0 };
            let mut out = Vec::with_capacity(2 + len);
            out.push(0x02); // INTEGER tag
            out.push(len as u8);
            if needs_pad {
                out.push(0x00);
            }
            out.extend_from_slice(stripped);
            out
        }

        let r_enc = encode_integer(r);
        let s_enc = encode_integer(s);
        let seq_len = r_enc.len() + s_enc.len();

        let mut der = Vec::with_capacity(4 + seq_len);
        der.push(0x30); // SEQUENCE tag
                        // Length encoding per X.690 Section 8.1.3:
                        //   short form     for 0..=127
                        //   long form 0x81 for 128..=255
                        //   long form 0x82 for 256..=65535 (P-521 reaches this; future-proof)
        if seq_len < 128 {
            der.push(seq_len as u8);
        } else if seq_len <= 0xFF {
            der.push(0x81);
            der.push(seq_len as u8);
        } else if seq_len <= 0xFFFF {
            der.push(0x82);
            der.push((seq_len >> 8) as u8);
            der.push(seq_len as u8);
        } else {
            // ECDSA SEQUENCEs do not legitimately exceed 65535 bytes for any
            // curve we support; refuse to emit a structurally invalid blob.
            return Err(HsmError::SignatureInvalid);
        }
        der.extend_from_slice(&r_enc);
        der.extend_from_slice(&s_enc);
        Ok(der)
    }

    /// Parse DER-encoded ECDSA signature back to raw R||S for CNG.
    ///
    /// Strictly enforces canonical DER per X.690 Section 10:
    /// * SEQUENCE length uses the shortest form (single-byte 0..127, or
    ///   `0x81 <len>` for 128..255). Long-form `0x82+` is rejected because
    ///   ECDSA SEQUENCEs never exceed 255 bytes for P-256/P-384.
    /// * No trailing bytes after the SEQUENCE - prevents signature
    ///   malleability where a verifier accepts the signature concatenated
    ///   with arbitrary trailing junk.
    /// * No trailing bytes inside the SEQUENCE after the second INTEGER.
    fn der_ecdsa_to_raw(der: &[u8], curve_size: usize) -> HsmResult<Vec<u8>> {
        // Minimal DER parser for SEQUENCE { INTEGER r, INTEGER s }.
        if der.len() < 6 || der[0] != 0x30 {
            return Err(HsmError::SignatureInvalid);
        }

        let (seq_len, seq_start): (usize, usize) = if der[1] & 0x80 == 0 {
            (der[1] as usize, 2)
        } else if der[1] == 0x81 {
            // Long-form must use the shortest form: a value < 128 must be
            // encoded as the single byte itself, not as 0x81 0xXX.
            if der.len() < 3 {
                return Err(HsmError::SignatureInvalid);
            }
            let l = der[2] as usize;
            if l < 128 {
                return Err(HsmError::SignatureInvalid);
            }
            (l, 3)
        } else {
            // Reject 0x82+ - ECDSA over P-256/P-384 never produces SEQUENCEs
            // >= 256 bytes, so any 0x82+ length octet is non-canonical.
            return Err(HsmError::SignatureInvalid);
        };

        // Reject trailing bytes after the SEQUENCE (signature malleability).
        let total_len = match seq_start.checked_add(seq_len) {
            Some(n) => n,
            None => return Err(HsmError::SignatureInvalid),
        };
        if total_len != der.len() {
            return Err(HsmError::SignatureInvalid);
        }

        let seq_data = &der[seq_start..seq_start + seq_len];

        fn parse_integer(data: &[u8]) -> HsmResult<(&[u8], &[u8])> {
            if data.len() < 2 || data[0] != 0x02 {
                return Err(HsmError::SignatureInvalid);
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err(HsmError::SignatureInvalid);
            }
            Ok((&data[2..2 + len], &data[2 + len..]))
        }

        let (r_bytes, rest) = parse_integer(seq_data)?;
        let (s_bytes, tail) = parse_integer(rest)?;

        // Reject trailing bytes inside the SEQUENCE.
        if !tail.is_empty() {
            return Err(HsmError::SignatureInvalid);
        }

        fn pad_to_size(val: &[u8], size: usize) -> HsmResult<Vec<u8>> {
            // Strip leading zeros.
            let stripped = match val.iter().position(|&b| b != 0) {
                Some(pos) => &val[pos..],
                None => &[0],
            };
            if stripped.len() > size {
                return Err(HsmError::SignatureInvalid);
            }
            let mut padded = vec![0u8; size];
            padded[size - stripped.len()..].copy_from_slice(stripped);
            Ok(padded)
        }

        let mut raw = pad_to_size(r_bytes, curve_size)?;
        raw.extend_from_slice(&pad_to_size(s_bytes, curve_size)?);
        Ok(raw)
    }

    fn ecdsa_sign_impl(
        backend: &CngBackend,
        alg_id: *const u16,
        private_key_bytes: &[u8],
        data: &[u8],
        curve_size: usize,
        private_magic: u32,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(alg_id, 0, None)?;
        let key = import_ecdsa_private_key(&alg, private_key_bytes, curve_size, private_magic)?;

        // ECDSA in CNG signs a hash, not raw data.
        let hash_alg_id = if curve_size == 32 {
            BCRYPT_SHA256_ALGORITHM
        } else {
            BCRYPT_SHA384_ALGORITHM
        };
        let digest = bcrypt_hash(backend, hash_alg_id, data)?;

        let mut sig_len = 0u32;
        // SAFETY: key is a valid ECDSA private key. digest is the hash to sign.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                ptr::null(),
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut raw_sig = vec![0u8; sig_len as usize];
        // SAFETY: Same as above with output buffer.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                ptr::null(),
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                raw_sig.as_mut_ptr(),
                raw_sig.len() as u32,
                &mut sig_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        raw_sig.truncate(sig_len as usize);

        // Convert raw R||S to DER for the trait interface.
        raw_ecdsa_to_der(&raw_sig)
    }

    fn ecdsa_verify_impl(
        backend: &CngBackend,
        alg_id: *const u16,
        public_key_sec1: &[u8],
        data: &[u8],
        signature_der: &[u8],
        curve_size: usize,
        public_magic: u32,
    ) -> HsmResult<bool> {
        let alg = backend.alg_for(alg_id, 0, None)?;
        let key = import_ecdsa_public_key(&alg, public_key_sec1, curve_size, public_magic)?;

        let hash_alg_id = if curve_size == 32 {
            BCRYPT_SHA256_ALGORITHM
        } else {
            BCRYPT_SHA384_ALGORITHM
        };
        let digest = bcrypt_hash(backend, hash_alg_id, data)?;

        let raw_sig = der_ecdsa_to_raw(signature_der, curve_size)?;

        // SAFETY: key is a valid ECDSA public key. digest and raw_sig are valid buffers.
        let status = unsafe {
            BCryptVerifySignature(
                key.as_raw(),
                ptr::null(),
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                raw_sig.as_ptr() as *mut u8,
                raw_sig.len() as u32,
                0,
            )
        };
        Ok(status == STATUS_SUCCESS)
    }

    fn ecdsa_sign_prehashed_impl(
        backend: &CngBackend,
        alg_id: *const u16,
        private_key_bytes: &[u8],
        digest: &[u8],
        curve_size: usize,
        private_magic: u32,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(alg_id, 0, None)?;
        let key = import_ecdsa_private_key(&alg, private_key_bytes, curve_size, private_magic)?;

        let mut sig_len = 0u32;
        // SAFETY: key is a valid ECDSA key. digest is the prehashed data.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                ptr::null(),
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut raw_sig = vec![0u8; sig_len as usize];
        // SAFETY: Same as above with output buffer.
        let status = unsafe {
            BCryptSignHash(
                key.as_raw(),
                ptr::null(),
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                raw_sig.as_mut_ptr(),
                raw_sig.len() as u32,
                &mut sig_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        raw_sig.truncate(sig_len as usize);
        raw_ecdsa_to_der(&raw_sig)
    }

    fn ecdsa_verify_prehashed_impl(
        backend: &CngBackend,
        alg_id: *const u16,
        public_key_sec1: &[u8],
        digest: &[u8],
        signature_der: &[u8],
        curve_size: usize,
        public_magic: u32,
    ) -> HsmResult<bool> {
        let alg = backend.alg_for(alg_id, 0, None)?;
        let key = import_ecdsa_public_key(&alg, public_key_sec1, curve_size, public_magic)?;
        let raw_sig = der_ecdsa_to_raw(signature_der, curve_size)?;

        // SAFETY: key is a valid ECDSA public key. digest and raw_sig are valid.
        let status = unsafe {
            BCryptVerifySignature(
                key.as_raw(),
                ptr::null(),
                digest.as_ptr() as *mut u8,
                digest.len() as u32,
                raw_sig.as_ptr() as *mut u8,
                raw_sig.len() as u32,
                0,
            )
        };
        Ok(status == STATUS_SUCCESS)
    }

    // ========================================================================
    // RSA-OAEP helpers
    // ========================================================================

    fn oaep_hash_to_bcrypt(h: OaepHash) -> *const u16 {
        match h {
            OaepHash::Sha256 => BCRYPT_SHA256_ALGORITHM,
            OaepHash::Sha384 => BCRYPT_SHA384_ALGORITHM,
            OaepHash::Sha512 => BCRYPT_SHA512_ALGORITHM,
        }
    }

    fn rsa_oaep_encrypt_impl(
        backend: &CngBackend,
        modulus: &[u8],
        public_exponent: &[u8],
        plaintext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_public_key(&alg, modulus, public_exponent)?;

        let pad_info = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: oaep_hash_to_bcrypt(hash_alg),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Query output size.
        let mut ct_len = 0u32;
        // SAFETY: key is a valid RSA public key. pad_info is valid OAEP info.
        let status = unsafe {
            BCryptEncrypt(
                key.as_raw(),
                plaintext.as_ptr() as *mut u8,
                plaintext.len() as u32,
                &pad_info as *const _ as *mut _,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut ct_len,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut ciphertext = vec![0u8; ct_len as usize];
        // SAFETY: Same as above with output buffer.
        let status = unsafe {
            BCryptEncrypt(
                key.as_raw(),
                plaintext.as_ptr() as *mut u8,
                plaintext.len() as u32,
                &pad_info as *const _ as *mut _,
                ptr::null_mut(),
                0,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32,
                &mut ct_len,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        ciphertext.truncate(ct_len as usize);
        Ok(ciphertext)
    }

    fn rsa_oaep_decrypt_impl(
        backend: &CngBackend,
        private_key_der: &[u8],
        ciphertext: &[u8],
        hash_alg: OaepHash,
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let key = import_rsa_private_key(&alg, private_key_der)?;

        let pad_info = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: oaep_hash_to_bcrypt(hash_alg),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Query output size.
        let mut pt_len = 0u32;
        // SAFETY: key is a valid RSA private key. pad_info is valid OAEP info.
        let status = unsafe {
            BCryptDecrypt(
                key.as_raw(),
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len() as u32,
                &pad_info as *const _ as *mut _,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut pt_len,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut plaintext = vec![0u8; pt_len as usize];
        // SAFETY: Same as above with output buffer.
        let status = unsafe {
            BCryptDecrypt(
                key.as_raw(),
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len() as u32,
                &pad_info as *const _ as *mut _,
                ptr::null_mut(),
                0,
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut pt_len,
                BCRYPT_PAD_OAEP,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        plaintext.truncate(pt_len as usize);
        Ok(plaintext)
    }

    // ========================================================================
    // Key generation helpers
    // ========================================================================

    fn generate_aes_key_impl(key_len_bytes: usize) -> HsmResult<RawKeyMaterial> {
        if key_len_bytes != 16 && key_len_bytes != 24 && key_len_bytes != 32 {
            return Err(HsmError::KeySizeRange);
        }
        let mut key_data = Zeroizing::new(vec![0u8; key_len_bytes]);
        gen_random(&mut key_data)?;
        Ok(RawKeyMaterial::new(key_data.to_vec()))
    }

    fn generate_rsa_key_pair_impl(
        backend: &CngBackend,
        modulus_bits: u32,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
        if modulus_bits < 2048 || modulus_bits > 16384 || modulus_bits % 256 != 0 {
            return Err(HsmError::KeySizeRange);
        }

        let alg = backend.alg_for(BCRYPT_RSA_ALGORITHM, 0, None)?;
        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();

        // SAFETY: alg is a valid RSA algorithm handle. BCryptGenerateKeyPair
        // creates a new key pair with the specified bit length.
        let status =
            unsafe { BCryptGenerateKeyPair(alg.as_raw(), &mut key_handle, modulus_bits, 0) };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let key = KeyHandle(key_handle);

        // Finalize the key (required before export).
        // SAFETY: key is a valid key pair handle that was just generated.
        let status = unsafe { BCryptFinalizeKeyPair(key.as_raw(), 0) };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        // Export private key as PKCS#8 DER via BCRYPT_RSAFULLPRIVATE_BLOB,
        // then convert to PKCS#8 using the rsa crate.
        let mut blob_size = 0u32;
        // SAFETY: Query the required blob size. key is a valid finalized key pair.
        let status = unsafe {
            BCryptExportKey(
                key.as_raw(),
                ptr::null_mut(),
                BCRYPT_RSAFULLPRIVATE_BLOB,
                ptr::null_mut(),
                0,
                &mut blob_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut blob = Zeroizing::new(vec![0u8; blob_size as usize]);
        // SAFETY: key is valid. blob is properly sized.
        let status = unsafe {
            BCryptExportKey(
                key.as_raw(),
                ptr::null_mut(),
                BCRYPT_RSAFULLPRIVATE_BLOB,
                blob.as_mut_ptr(),
                blob_size,
                &mut blob_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        // Parse the blob to extract components.
        // BCRYPT_RSAKEY_BLOB header: Magic(4) BitLength(4) cbPublicExp(4)
        //   cbModulus(4) cbPrime1(4) cbPrime2(4)
        // Then: PublicExponent, Modulus, Prime1, Prime2, Exponent1, Exponent2,
        //   Coefficient, PrivateExponent
        if blob.len() < 24 {
            return Err(HsmError::GeneralError);
        }

        let cb_pub_exp = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as usize;
        let cb_modulus = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
        let cb_prime1 = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;
        let cb_prime2 = u32::from_le_bytes(blob[20..24].try_into().unwrap()) as usize;

        // Defence-in-depth: validate the total declared size before slicing.
        // A malicious/corrupt blob with oversized cb_* fields would otherwise
        // panic on out-of-bounds slicing below. Sum via checked_add so we also
        // reject any field that, by itself, exceeds usize::MAX when summed.
        let required: usize = 24usize
            .checked_add(cb_pub_exp)
            .and_then(|n| n.checked_add(cb_modulus))
            .and_then(|n| n.checked_add(cb_prime1))
            .and_then(|n| n.checked_add(cb_prime2))
            .and_then(|n| n.checked_add(cb_prime1))
            .and_then(|n| n.checked_add(cb_prime2))
            .and_then(|n| n.checked_add(cb_prime1))
            .and_then(|n| n.checked_add(cb_modulus))
            .ok_or(HsmError::GeneralError)?;
        if blob.len() < required {
            return Err(HsmError::GeneralError);
        }

        let mut off = 24;
        let pub_exp = blob[off..off + cb_pub_exp].to_vec();
        off += cb_pub_exp;
        let modulus = blob[off..off + cb_modulus].to_vec();
        off += cb_modulus;

        // We need to build a PKCS#8 DER from the CNG blob. Use the rsa crate.
        let p = &blob[off..off + cb_prime1];
        off += cb_prime1;
        let q = &blob[off..off + cb_prime2];
        off += cb_prime2;
        let _dp = &blob[off..off + cb_prime1];
        off += cb_prime1;
        let _dq = &blob[off..off + cb_prime2];
        off += cb_prime2;
        let _qinv = &blob[off..off + cb_prime1];
        off += cb_prime1;
        let d = &blob[off..off + cb_modulus];

        // Build PKCS#8 DER using rsa crate.
        use rsa::BigUint;

        let n = BigUint::from_bytes_be(&modulus);
        let e = BigUint::from_bytes_be(&pub_exp);
        let d_val = BigUint::from_bytes_be(d);
        let p_val = BigUint::from_bytes_be(p);
        let q_val = BigUint::from_bytes_be(q);

        let priv_key = rsa::RsaPrivateKey::from_components(n, e, d_val, vec![p_val, q_val])
            .map_err(|_| HsmError::GeneralError)?;

        use rsa::pkcs8::EncodePrivateKey;
        let pkcs8_der = priv_key
            .to_pkcs8_der()
            .map_err(|_| HsmError::GeneralError)?;

        Ok((
            RawKeyMaterial::new(pkcs8_der.as_bytes().to_vec()),
            modulus,
            pub_exp,
        ))
    }

    fn generate_ec_key_pair_impl(
        backend: &CngBackend,
        alg_id: *const u16,
        curve_size: usize,
    ) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        let alg = backend.alg_for(alg_id, 0, None)?;
        let mut key_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();

        // SAFETY: alg is a valid ECDSA algorithm handle.
        let status = unsafe {
            BCryptGenerateKeyPair(alg.as_raw(), &mut key_handle, (curve_size * 8) as u32, 0)
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let key = KeyHandle(key_handle);

        // SAFETY: key is a valid key pair handle.
        let status = unsafe { BCryptFinalizeKeyPair(key.as_raw(), 0) };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        // Export private key blob.
        let mut blob_size = 0u32;
        // SAFETY: Query export size. key is valid.
        let status = unsafe {
            BCryptExportKey(
                key.as_raw(),
                ptr::null_mut(),
                BCRYPT_ECCPRIVATE_BLOB,
                ptr::null_mut(),
                0,
                &mut blob_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut blob = Zeroizing::new(vec![0u8; blob_size as usize]);
        // SAFETY: key is valid. blob is properly sized.
        let status = unsafe {
            BCryptExportKey(
                key.as_raw(),
                ptr::null_mut(),
                BCRYPT_ECCPRIVATE_BLOB,
                blob.as_mut_ptr(),
                blob_size,
                &mut blob_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        // Parse BCRYPT_ECCKEY_BLOB: magic(4) + cbKey(4) + X(cbKey) + Y(cbKey) + d(cbKey)
        if blob.len() < 8 + curve_size * 3 {
            return Err(HsmError::GeneralError);
        }

        let x = &blob[8..8 + curve_size];
        let y = &blob[8 + curve_size..8 + 2 * curve_size];
        let d = &blob[8 + 2 * curve_size..8 + 3 * curve_size];

        // Build SEC1 uncompressed public key: 0x04 || X || Y
        let mut public_key = Vec::with_capacity(1 + 2 * curve_size);
        public_key.push(0x04);
        public_key.extend_from_slice(x);
        public_key.extend_from_slice(y);

        // Private key is the raw scalar d.
        let private_key = RawKeyMaterial::new(d.to_vec());

        Ok((private_key, public_key))
    }

    // ========================================================================
    // AES key wrap/unwrap (RFC 3394)
    // ========================================================================

    fn aes_key_wrap_impl(
        backend: &CngBackend,
        wrapping_key: &[u8],
        key_to_wrap: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if wrapping_key.len() != 16 && wrapping_key.len() != 24 && wrapping_key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if key_to_wrap.len() < 16 || key_to_wrap.len() % 8 != 0 {
            return Err(HsmError::DataLenRange);
        }

        // Open AES with no chaining-mode property — CNG's default for the
        // AES algorithm provider is sufficient for the BCryptEncrypt
        // key-wrap path used below. The cache key folds the absent
        // chain-mode pointer to `0`, keeping this slot distinct from
        // AES-CBC / AES-GCM / AES-ECB handles.
        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, None)?;
        let key = create_symmetric_key(&alg, wrapping_key)?;

        let output_len = key_to_wrap.len() + AES_KW_OVERHEAD;
        let mut output = vec![0u8; output_len];
        let mut result_len = 0u32;

        // SAFETY: key is a valid AES key. key_to_wrap and output are valid buffers.
        // We pass no IV (null, 0) to use the default AES-KW IV (0xA6A6A6A6A6A6A6A6).
        let status = unsafe {
            BCryptEncrypt(
                key.as_raw(),
                key_to_wrap.as_ptr() as *mut u8,
                key_to_wrap.len() as u32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut result_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        output.truncate(result_len as usize);
        Ok(output)
    }

    fn aes_key_unwrap_impl(
        backend: &CngBackend,
        wrapping_key: &[u8],
        wrapped_key: &[u8],
    ) -> HsmResult<Vec<u8>> {
        if wrapping_key.len() != 16 && wrapping_key.len() != 24 && wrapping_key.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        if wrapped_key.len() < 24 || wrapped_key.len() % 8 != 0 {
            return Err(HsmError::EncryptedDataInvalid);
        }

        // See `aes_key_wrap_impl` for the cache-key rationale on
        // chain_mode=None.
        let alg = backend.alg_for(BCRYPT_AES_ALGORITHM, 0, None)?;
        let key = create_symmetric_key(&alg, wrapping_key)?;

        let output_len = wrapped_key.len() - AES_KW_OVERHEAD;
        let mut output = vec![0u8; output_len];
        let mut result_len = 0u32;

        // SAFETY: key is a valid AES key. wrapped_key and output are valid buffers.
        let status = unsafe {
            BCryptDecrypt(
                key.as_raw(),
                wrapped_key.as_ptr() as *mut u8,
                wrapped_key.len() as u32,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut result_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        output.truncate(result_len as usize);
        Ok(output)
    }

    // ========================================================================
    // ECDH key agreement
    // ========================================================================

    fn ecdh_impl(
        backend: &CngBackend,
        alg_id: *const u16,
        private_key_bytes: &[u8],
        peer_public_key_sec1: &[u8],
        curve_size: usize,
        private_magic: u32,
        public_magic: u32,
        okm_len: Option<usize>,
    ) -> HsmResult<RawKeyMaterial> {
        let alg = backend.alg_for(alg_id, 0, None)?;

        // Import our private key. The public point is derived inside the
        // FIPS-validated CNG module via NCrypt + PKCS#8 — see
        // `derive_ecc_public_via_ncrypt` for the rationale.
        let (x, y) = derive_ecc_public_via_ncrypt(private_key_bytes, curve_size)?;

        let priv_blob_size = 8 + curve_size * 3;
        let mut priv_blob = Zeroizing::new(vec![0u8; priv_blob_size]);
        priv_blob[0..4].copy_from_slice(&private_magic.to_le_bytes());
        priv_blob[4..8].copy_from_slice(&(curve_size as u32).to_le_bytes());
        let mut off = 8;
        let x_start = curve_size.saturating_sub(x.len());
        priv_blob[off + x_start..off + x_start + x.len()].copy_from_slice(&x);
        off += curve_size;
        let y_start = curve_size.saturating_sub(y.len());
        priv_blob[off + y_start..off + y_start + y.len()].copy_from_slice(&y);
        off += curve_size;
        let d_start = curve_size.saturating_sub(private_key_bytes.len());
        priv_blob[off + d_start..off + d_start + private_key_bytes.len()]
            .copy_from_slice(private_key_bytes);

        let mut priv_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: alg is a valid ECDH algorithm handle. priv_blob is a valid
        // BCRYPT_ECCKEY_BLOB containing our private key.
        let status = unsafe {
            BCryptImportKeyPair(
                alg.as_raw(),
                ptr::null_mut(),
                BCRYPT_ECCPRIVATE_BLOB,
                &mut priv_handle,
                priv_blob.as_mut_ptr(),
                priv_blob.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let priv_key = KeyHandle(priv_handle);

        // Import peer public key.
        if peer_public_key_sec1.len() != 1 + 2 * curve_size || peer_public_key_sec1[0] != 0x04 {
            return Err(HsmError::DataInvalid);
        }
        let peer_x = &peer_public_key_sec1[1..1 + curve_size];
        let peer_y = &peer_public_key_sec1[1 + curve_size..];

        let pub_blob_size = 8 + curve_size * 2;
        let mut pub_blob = vec![0u8; pub_blob_size];
        pub_blob[0..4].copy_from_slice(&public_magic.to_le_bytes());
        pub_blob[4..8].copy_from_slice(&(curve_size as u32).to_le_bytes());
        pub_blob[8..8 + curve_size].copy_from_slice(peer_x);
        pub_blob[8 + curve_size..8 + 2 * curve_size].copy_from_slice(peer_y);

        let mut pub_handle: BCRYPT_KEY_HANDLE = ptr::null_mut();
        // SAFETY: alg is valid. pub_blob is a valid BCRYPT_ECCKEY_BLOB for the
        // peer's public key.
        let status = unsafe {
            BCryptImportKeyPair(
                alg.as_raw(),
                ptr::null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                &mut pub_handle,
                pub_blob.as_mut_ptr(),
                pub_blob.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let pub_key = KeyHandle(pub_handle);

        // Perform the secret agreement. The returned handle is wrapped in
        // SecretHandle so that every subsequent early-return path scrubs
        // the kernel object via Drop - no ad-hoc BCryptDestroySecret cleanup
        // that an ? operator could skip.
        let mut secret_raw: BCRYPT_SECRET_HANDLE = ptr::null_mut();
        // SAFETY: priv_key and pub_key are valid ECDH key handles.
        let status = unsafe {
            BCryptSecretAgreement(priv_key.as_raw(), pub_key.as_raw(), &mut secret_raw, 0)
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let secret = SecretHandle(secret_raw);

        // Derive key material via BCryptDeriveKey. The raw-secret KDF is
        // registered as TRUNCATE on Windows 10 1607+. Fall back to
        // BCRYPT_KDF_HASH (SHA-256) when the platform refuses TRUNCATE so
        // we keep working on older builds.
        let kdf_raw: &[u16] = &[
            b'T' as u16,
            b'R' as u16,
            b'U' as u16,
            b'N' as u16,
            b'C' as u16,
            b'A' as u16,
            b'T' as u16,
            b'E' as u16,
            0,
        ];
        let mut derived_len = 0u32;
        // SAFETY: secret.as_raw() is a valid secret-agreement handle.
        // kdf_raw points to a null-terminated UTF-16 string.
        let status = unsafe {
            BCryptDeriveKey(
                secret.as_raw(),
                kdf_raw.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut derived_len,
                0,
            )
        };

        let raw_secret = if status == STATUS_SUCCESS && derived_len > 0 {
            let mut buf = Zeroizing::new(vec![0u8; derived_len as usize]);
            // SAFETY: Same as above with output buffer.
            let status = unsafe {
                BCryptDeriveKey(
                    secret.as_raw(),
                    kdf_raw.as_ptr(),
                    ptr::null(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut derived_len,
                    0,
                )
            };
            if status != STATUS_SUCCESS {
                return Err(ntstatus_to_hsm_error(status));
            }
            buf.truncate(derived_len as usize);
            // Endian: BCRYPT_KDF_RAW_SECRET (TRUNCATE) returns the X
            // coordinate of the agreed point in little-endian byte order
            // (documented MSDN behaviour). Every other Craton backend
            // (OpenSSL, AWS-LC, RustCrypto) emits the X coordinate
            // big-endian per SEC 1 Section 2.3.5, so we reverse here to
            // produce a single canonical big-endian shared secret across
            // backends. The RFC 5903 Section 8.1 P-256 KAT in the test
            // module exercises this conversion.
            buf.reverse();
            buf
        } else {
            // Fallback: use BCRYPT_KDF_HASH with SHA-256.
            let kdf_hash = BCRYPT_KDF_HASH;
            let mut buf = Zeroizing::new(vec![0u8; 32]);
            let mut out_len = 0u32;
            // SAFETY: secret.as_raw() is valid. Using hash-based KDF.
            let status2 = unsafe {
                BCryptDeriveKey(
                    secret.as_raw(),
                    kdf_hash,
                    ptr::null(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut out_len,
                    0,
                )
            };
            if status2 != STATUS_SUCCESS {
                return Err(ntstatus_to_hsm_error(status2));
            }
            buf.truncate(out_len as usize);
            buf
        };
        // secret drops here (or earlier on ?), invoking
        // BCryptDestroySecret via SecretHandle Drop impl.

        // If okm_len is specified and different from the raw secret, use HKDF.
        let output = match okm_len {
            Some(len) if len != raw_secret.len() => {
                // Simple HKDF-expand using SHA-256.
                hkdf_expand_sha256(&raw_secret, len)?
            }
            _ => raw_secret.to_vec(),
        };

        Ok(RawKeyMaterial::new(output))
    }

    /// HKDF-Expand (RFC 5869) using HMAC-SHA-256.
    ///
    /// Audit perf fix: previously each iteration rebuilt the HMAC algorithm
    /// provider from scratch via bcrypt_hmac (which opens a fresh CNG
    /// algorithm handle, derives a key object, and tears them down again).
    /// We now build a single HmacSha256 instance, reset between blocks,
    /// and reuse a single scratch buffer for the per-block input.
    fn hkdf_expand_sha256(prk: &[u8], length: usize) -> HsmResult<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        const HASH_LEN: usize = 32;
        let n = (length + HASH_LEN - 1) / HASH_LEN;
        if n > 255 {
            return Err(HsmError::DataLenRange);
        }

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk).map_err(|_| HsmError::DataInvalid)?;
        let mut okm = Vec::with_capacity(length);
        // Single preallocated scratch buffer of max possible size
        // (HASH_LEN previous-block bytes + 1 counter byte).
        let mut t_prev: [u8; HASH_LEN] = [0u8; HASH_LEN];
        let mut t_prev_len: usize = 0;

        for i in 1..=n {
            mac.reset();
            mac.update(&t_prev[..t_prev_len]);
            mac.update(&[i as u8]);
            let block = mac.finalize_reset().into_bytes();
            t_prev.copy_from_slice(&block);
            t_prev_len = HASH_LEN;
            okm.extend_from_slice(&block);
        }

        okm.truncate(length);
        Ok(okm)
    }

    /// HMAC using CNG.
    ///
    /// Retained as a dead-code helper for any future caller that needs an
    /// HMAC implementation routed through the FIPS-validated CNG provider
    /// rather than the RustCrypto path that HKDF-Expand now uses.
    #[allow(dead_code)]
    fn bcrypt_hmac(
        backend: &CngBackend,
        hash_alg: *const u16,
        key: &[u8],
        data: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let alg = backend.alg_for(hash_alg, BCRYPT_ALG_HANDLE_HMAC_FLAG, None)?;

        // Query hash output length.
        let mut hash_len = 0u32;
        let mut result_size = 0u32;
        // SAFETY: Querying BCRYPT_HASH_LENGTH from an HMAC algorithm handle
        // produced by `open_alg`. `hash_len` is a local `u32`; the size we
        // advertise to CNG exactly matches its storage. `result_size` is
        // validated below before `hash_len` is used.
        let status = unsafe {
            BCryptGetProperty(
                alg.as_raw() as *mut _,
                BCRYPT_HASH_LENGTH,
                &mut hash_len as *mut u32 as *mut u8,
                std::mem::size_of::<u32>() as u32,
                &mut result_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // Audit finding CNG-2: guard against a misbehaving CNG writing past
        // the 4-byte `u32` destination.
        if result_size as usize != std::mem::size_of::<u32>() {
            tracing::error!(
                result_size = result_size,
                expected = std::mem::size_of::<u32>() as u32,
                "BCryptGetProperty(BCRYPT_HASH_LENGTH) HMAC path returned unexpected pcbResult"
            );
            return Err(HsmError::GeneralError);
        }

        let mut hash_handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
        // SAFETY: alg is a valid HMAC algorithm handle. key is the HMAC key.
        let status = unsafe {
            BCryptCreateHash(
                alg.as_raw(),
                &mut hash_handle,
                ptr::null_mut(),
                0,
                key.as_ptr() as *mut u8,
                key.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        let hash_handle = HashHandle(hash_handle);

        // SAFETY: hash_handle is valid. data is a valid slice.
        let status = unsafe {
            BCryptHashData(
                hash_handle.as_raw(),
                data.as_ptr() as *mut u8,
                data.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        let mut output = vec![0u8; hash_len as usize];
        // SAFETY: hash_handle is valid. output is properly sized.
        let status = unsafe {
            BCryptFinishHash(
                hash_handle.as_raw(),
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        Ok(output)
    }

    // ========================================================================
    // CNG DigestAccumulator
    // ========================================================================

    /// CNG-backed multi-part digest accumulator.
    ///
    /// The `DigestAccumulator` trait surface gives `update` a `()` return type,
    /// so a `BCryptHashData` mid-stream failure cannot be propagated to the
    /// caller through the normal channel. To avoid silently returning a digest
    /// of partial bytes (which would be indistinguishable from a digest of all
    /// the bytes the caller fed in), we latch a `failed` flag on every error
    /// inside `update`. On `finalize`, if the flag is set we return a
    /// fixed zero-filled buffer of the algorithm's digest length and emit a
    /// `tracing::error!` so the failure is visible in audit logs.
    ///
    /// `std::cell::Cell<bool>` (not `AtomicBool`) is sufficient because trait
    /// methods take `&mut self` / `Box<Self>`, so the borrow checker already
    /// enforces single-threaded access — there are no concurrent updates to
    /// race against. The `Send`/`Sync` impls below uphold the same invariant.
    struct CngHasher {
        handle: Option<HashHandle>,
        /// We also keep the AlgHandle alive so it's not dropped before the hash.
        /// With backend-level caching the handle is shared via `Arc`; the
        /// `Arc` clone here keeps the handle alive for at least as long as
        /// the hasher is in use even if the backend's cache is otherwise
        /// dropped (which can't happen while the backend exists, but the
        /// invariant is local to this hasher).
        _alg: Arc<AlgHandle>,
        output_len: usize,
        /// Latched on any mid-stream `BCryptHashData` failure. Once true,
        /// `finalize` returns a zero-filled buffer of `output_len` rather than
        /// a digest of partial bytes.
        failed: std::cell::Cell<bool>,
    }

    impl DigestAccumulator for CngHasher {
        fn update(&mut self, data: &[u8]) {
            if self.failed.get() {
                // Once the stream is poisoned, further updates are no-ops:
                // we will return a zero buffer on finalize regardless.
                return;
            }
            if let Some(ref h) = self.handle {
                // SAFETY: h.as_raw() is a valid hash handle. data is a valid slice.
                let status = unsafe {
                    BCryptHashData(h.as_raw(), data.as_ptr() as *mut u8, data.len() as u32, 0)
                };
                if status != STATUS_SUCCESS {
                    tracing::error!(
                        ntstatus = format!("0x{:08X}", status as u32),
                        "BCryptHashData failed during incremental hashing; \
                         hasher poisoned, finalize will return zero buffer"
                    );
                    self.failed.set(true);
                }
            }
        }

        fn finalize(mut self: Box<Self>) -> Vec<u8> {
            if self.failed.get() {
                tracing::error!(
                    output_len = self.output_len,
                    "CngHasher::finalize called on poisoned hasher; \
                     returning zero-filled digest of algorithm output length"
                );
                return vec![0u8; self.output_len];
            }
            if let Some(h) = self.handle.take() {
                let mut output = vec![0u8; self.output_len];
                // SAFETY: h.as_raw() is a valid hash handle. output is properly sized.
                let status = unsafe {
                    BCryptFinishHash(h.as_raw(), output.as_mut_ptr(), output.len() as u32, 0)
                };
                if status != STATUS_SUCCESS {
                    tracing::error!(
                        ntstatus = format!("0x{:08X}", status as u32),
                        "BCryptFinishHash failed; returning zero-filled digest"
                    );
                    return vec![0u8; self.output_len];
                }
                output
            } else {
                vec![0u8; self.output_len]
            }
        }

        fn output_len(&self) -> usize {
            self.output_len
        }
    }

    // SAFETY: CngHasher is exposed only as Box<dyn DigestAccumulator> via
    // create_cng_hasher. The trait update takes &mut self and finalize
    // consumes self, so the borrow checker enforces single-threaded mutation
    // of the inner BCRYPT_HASH_HANDLE. Sending the boxed hasher across thread
    // boundaries is sound because ownership transfers exclusively (no aliasing),
    // and Sync is sound for the same reason: only one thread holds the &mut at
    // a time, so concurrent BCrypt re-entrancy is never invoked through this
    // type. Cf. the load-bearing KeyHandle/HashHandle discussion above (the
    // raw wrappers stay !Send/!Sync; only this owning hasher, which guarantees
    // exclusive access by construction, opts in).
    unsafe impl Send for CngHasher {}
    unsafe impl Sync for CngHasher {}

    fn create_cng_hasher(
        backend: &CngBackend,
        alg_id: *const u16,
    ) -> HsmResult<Box<dyn DigestAccumulator>> {
        let alg = backend.alg_for(alg_id, 0, None)?;

        // Query hash length.
        let mut hash_len = 0u32;
        let mut result_size = 0u32;
        // SAFETY: Querying BCRYPT_HASH_LENGTH from the just-opened algorithm
        // handle. `hash_len` is a local `u32`; advertised size matches its
        // storage. `result_size` is validated below.
        let status = unsafe {
            BCryptGetProperty(
                alg.as_raw() as *mut _,
                BCRYPT_HASH_LENGTH,
                &mut hash_len as *mut u32 as *mut u8,
                std::mem::size_of::<u32>() as u32,
                &mut result_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }
        // Audit finding CNG-2: refuse to trust `hash_len` if CNG reports
        // that it wrote anything other than exactly 4 bytes.
        if result_size as usize != std::mem::size_of::<u32>() {
            tracing::error!(
                result_size = result_size,
                expected = std::mem::size_of::<u32>() as u32,
                "BCryptGetProperty(BCRYPT_HASH_LENGTH) streaming-hasher path returned unexpected pcbResult"
            );
            return Err(HsmError::GeneralError);
        }

        let mut hash_handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
        // SAFETY: alg is a valid algorithm handle for hashing.
        let status = unsafe {
            BCryptCreateHash(
                alg.as_raw(),
                &mut hash_handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(ntstatus_to_hsm_error(status));
        }

        Ok(Box::new(CngHasher {
            handle: Some(HashHandle(hash_handle)),
            _alg: alg,
            output_len: hash_len as usize,
            failed: std::cell::Cell::new(false),
        }))
    }

    // ========================================================================
    // Ed25519 — CNG does not support Ed25519 natively; delegate to RustCrypto
    // ========================================================================

    fn ed25519_sign_impl(private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
        use ed25519_dalek::{Signer, SigningKey};

        if private_key_bytes.len() != 32 {
            return Err(HsmError::KeySizeRange);
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(private_key_bytes);
        let signing_key = SigningKey::from_bytes(&key_arr);
        zeroize::Zeroize::zeroize(&mut key_arr);

        let sig = signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn ed25519_verify_impl(
        public_key_bytes: &[u8],
        data: &[u8],
        signature_bytes: &[u8],
    ) -> HsmResult<bool> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
            return Err(HsmError::DataInvalid);
        }
        let vk_arr: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| HsmError::DataInvalid)?;
        let vk = VerifyingKey::from_bytes(&vk_arr).map_err(|_| HsmError::DataInvalid)?;
        let sig = Signature::from_slice(signature_bytes).map_err(|_| HsmError::SignatureInvalid)?;

        Ok(vk.verify(data, &sig).is_ok())
    }

    fn generate_ed25519_key_pair_impl() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
        use ed25519_dalek::SigningKey;

        let mut seed = [0u8; 32];
        gen_random(&mut seed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);

        let verifying_key = signing_key.verifying_key();
        let private_bytes = signing_key.to_bytes().to_vec();
        let public_bytes = verifying_key.to_bytes().to_vec();

        Ok((RawKeyMaterial::new(private_bytes), public_bytes))
    }

    // ========================================================================
    // CngBackend public struct and CryptoBackend implementation
    // ========================================================================

    /// Cache key for the per-backend algorithm-handle cache.
    ///
    /// The first element is the address of the static wide-string algorithm
    /// identifier (e.g. `BCRYPT_AES_ALGORITHM`); these are stable static
    /// pointers from `windows-sys`, so their address uniquely identifies the
    /// algorithm. The second element is the `BCryptOpenAlgorithmProvider`
    /// flags (encoding the FIPS-dispatch bit and the HMAC bit). The third
    /// element is the address of the chaining-mode wide string when set
    /// (or `0` for "no chaining mode property applied"), so AES handles
    /// pre-configured for GCM/CBC/ECB/CFB each occupy a distinct cache slot
    /// — sharing a single AES handle across chaining modes would race the
    /// `BCryptSetProperty(BCRYPT_CHAINING_MODE)` call on concurrent
    /// operations.
    type AlgCacheKey = (usize, u32, usize);

    /// Windows CNG crypto backend using native BCrypt APIs.
    ///
    /// When `fips_mode` is true, the backend was constructed via `new_fips()` and
    /// all algorithm providers are opened with `BCRYPT_PROV_DISPATCH`, which
    /// constrains CNG to the FIPS-validated dispatch table.
    pub struct CngBackend {
        /// Whether FIPS-restricted algorithm providers are used. When set,
        /// every `BCryptOpenAlgorithmProvider` call is augmented with the
        /// `BCRYPT_PROV_DISPATCH` flag (see [`Self::fips_dispatch_flags`])
        /// and Ed25519 entry points refuse with `FunctionNotSupported`
        /// (RustCrypto's Ed25519 lies outside the validated boundary).
        fips_mode: bool,
        /// FIPS 140-3 power-on self-test (POST) gate. Latched to `true` after
        /// `craton-hsm-certified` drives the KAT suite against this backend
        /// and verifies every KAT passed. While `fips_mode == true` and this
        /// flag is `false`, every FIPS-relevant entry point on this backend
        /// (RSA sign/PSS/OAEP/prehashed, ECDSA P-256/P-384 sign, AES-GCM/CBC/CTR
        /// encrypt+decrypt, key-wrap/unwrap, key generation, ECDH,
        /// `compute_digest`) rejects with `HsmError::ConfigError`. Verify-only
        /// entry points are intentionally not gated so the certified harness
        /// can still validate public-key material during bring-up.
        fips_post_passed: std::sync::atomic::AtomicBool,
        /// Per-backend cache of opened `BCRYPT_ALG_HANDLE` providers. MSDN
        /// documents algorithm handles as safe for concurrent use across
        /// threads (see the `Send + Sync` impl on `AlgHandle`), so we can
        /// share them through `Arc` rather than re-opening on every call.
        ///
        /// The cache key encodes (alg-name-pointer, flags, chain-mode-pointer):
        /// chaining mode is a property on the algorithm handle, so AES-GCM
        /// and AES-CBC each take their own pre-configured slot — caching a
        /// single AES handle across modes would race
        /// `BCryptSetProperty(BCRYPT_CHAINING_MODE)`. Inserting under the
        /// `Mutex` is fine because contention happens only on the first
        /// open per (alg, mode, fips) tuple; subsequent calls take an
        /// uncontended `Arc::clone`.
        alg_cache: Mutex<HashMap<AlgCacheKey, Arc<AlgHandle>>>,
    }

    impl CngBackend {
        /// Create a new CNG backend instance (non-FIPS).
        pub fn new(fips_mode: bool) -> Self {
            tracing::info!(
                target: "craton_hsm_cng",
                fips = fips_mode,
                "CngBackend created — using native Windows BCrypt APIs"
            );
            Self {
                fips_mode,
                fips_post_passed: std::sync::atomic::AtomicBool::new(false),
                alg_cache: Mutex::new(HashMap::new()),
            }
        }

        /// Create a CNG backend in FIPS mode.
        ///
        /// Verifies that CNG FIPS mode is available by opening a test algorithm
        /// provider with `BCRYPT_PROV_DISPATCH`. All subsequent algorithm
        /// providers opened through `Self::alg_for` are opened with the same
        /// flag, restricting CNG to the FIPS-validated dispatch table.
        pub fn new_fips() -> HsmResult<Self> {
            // Verify CNG FIPS is operational by opening a test provider with
            // BCRYPT_PROV_DISPATCH. If the OS FIPS policy is disabled and CNG
            // refuses the flag, the constructor fails closed.
            let _test = open_alg(BCRYPT_AES_ALGORITHM, BCRYPT_PROV_DISPATCH)?;
            tracing::info!(
                target: "craton_hsm_cng",
                "CngBackend created in FIPS mode — Windows CNG FIPS algorithms active"
            );
            Ok(Self {
                fips_mode: true,
                fips_post_passed: std::sync::atomic::AtomicBool::new(false),
                alg_cache: Mutex::new(HashMap::new()),
            })
        }

        /// Mark this backend as having passed the FIPS power-on self-test
        /// (POST). Intended to be called only by `craton-hsm-certified`'s
        /// `run_fips_post_for_backend` helper after every KAT in the
        /// certified suite has succeeded against this backend instance.
        pub fn mark_fips_post_passed(&self) {
            self.fips_post_passed
                .store(true, std::sync::atomic::Ordering::Release);
        }

        /// Returns whether this backend's POST flag is set. Used by the
        /// FIPS gate inside crypto entry points and by tests / external
        /// auditors.
        pub fn fips_post_passed(&self) -> bool {
            self.fips_post_passed
                .load(std::sync::atomic::Ordering::Acquire)
        }

        /// Returns the FIPS-dispatch flag bits to OR into every
        /// `BCryptOpenAlgorithmProvider` call. `BCRYPT_PROV_DISPATCH` when
        /// FIPS mode is on, zero otherwise. The audit prior to this fix
        /// found that the constructor's FIPS-mode promise was never
        /// honoured at the call sites — every `open_alg(_, 0)` ignored
        /// `fips_mode`. This helper is the single source of truth.
        fn fips_dispatch_flags(&self) -> u32 {
            if self.fips_mode {
                BCRYPT_PROV_DISPATCH
            } else {
                0
            }
        }

        /// Open (or fetch from cache) an algorithm provider handle for
        /// `alg_id`, opened with `BCRYPT_PROV_DISPATCH | extra_flags` when
        /// FIPS mode is on, otherwise `extra_flags`. The handle is reused
        /// across calls — MSDN guarantees algorithm handles are
        /// thread-safe (cf. the `Send + Sync` impl on `AlgHandle`). The
        /// `chain_mode` argument, when `Some`, is applied via
        /// `BCryptSetProperty(BCRYPT_CHAINING_MODE)` on the freshly opened
        /// handle and is folded into the cache key so that different
        /// chaining modes don't share a slot.
        fn alg_for(
            &self,
            alg_id: *const u16,
            extra_flags: u32,
            chain_mode: Option<*const u16>,
        ) -> HsmResult<Arc<AlgHandle>> {
            let flags = self.fips_dispatch_flags() | extra_flags;
            let key: AlgCacheKey = (
                alg_id as usize,
                flags,
                chain_mode.map(|p| p as usize).unwrap_or(0),
            );

            // Fast path: handle already cached. Use `Arc::clone` explicitly
            // rather than `.clone()` on `&Arc<_>` so the disambiguated path
            // is impossible to misread — the blanket `Clone` impl on `&T`
            // would otherwise be a candidate at method resolution.
            {
                let cache = self.alg_cache.lock().map_err(|_| HsmError::GeneralError)?;
                if let Some(h) = cache.get(&key) {
                    return Ok(Arc::clone(h));
                }
            }

            // Slow path: open a fresh handle, apply chain mode if requested,
            // and insert into the cache. A concurrent caller may race us;
            // in that case we keep whichever handle is already in the map
            // and drop ours (the drop closes it via `BCryptCloseAlgorithmProvider`).
            let handle = open_alg(alg_id, flags)?;
            if let Some(mode_ptr) = chain_mode {
                set_chaining_mode(&handle, mode_ptr)?;
            }
            let arc = Arc::new(handle);

            let mut cache = self.alg_cache.lock().map_err(|_| HsmError::GeneralError)?;
            // Re-check in case another thread inserted while we were opening.
            if let Some(existing) = cache.get(&key) {
                return Ok(Arc::clone(existing));
            }
            cache.insert(key, Arc::clone(&arc));
            Ok(arc)
        }

        /// Common FIPS gate: when `fips_mode` is on, refuse to perform a
        /// FIPS-relevant crypto operation until the POST flag has been
        /// latched. Returns `Err(HsmError::ConfigError)` otherwise.
        fn enforce_fips_post_gate(&self) -> HsmResult<()> {
            if self.fips_mode && !self.fips_post_passed() {
                return Err(HsmError::ConfigError(
                    "FIPS POST not yet executed".to_string(),
                ));
            }
            Ok(())
        }
    }

    impl Default for CngBackend {
        fn default() -> Self {
            Self::new(false)
        }
    }

    impl CryptoBackend for CngBackend {
        // ====================================================================
        // Signing
        // ====================================================================

        fn rsa_pkcs1v15_sign(
            &self,
            private_key_der: &[u8],
            data: &[u8],
            hash_alg: Option<HashAlg>,
        ) -> HsmResult<Vec<u8>> {
            // FIPS 140-3 §7.10.2: cryptographic services are disabled until
            // the power-on self-test latch has been driven and every KAT has
            // passed against this backend. Every FIPS-relevant entry point in
            // this `impl CryptoBackend` block calls `enforce_fips_post_gate()`
            // first — see `mark_fips_post_passed()` for the latch driver,
            // which is invoked by `craton-hsm-certified` after running the
            // KAT suite against this backend instance.
            self.enforce_fips_post_gate()?;
            rsa_pkcs1v15_sign_impl(self, private_key_der, data, hash_alg)
        }

        fn rsa_pkcs1v15_verify(
            &self,
            modulus: &[u8],
            public_exponent: &[u8],
            data: &[u8],
            signature: &[u8],
            hash_alg: Option<HashAlg>,
        ) -> HsmResult<bool> {
            rsa_pkcs1v15_verify_impl(self, modulus, public_exponent, data, signature, hash_alg)
        }

        fn rsa_pss_sign(
            &self,
            private_key_der: &[u8],
            data: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            rsa_pss_sign_impl(self, private_key_der, data, hash_alg)
        }

        fn rsa_pss_verify(
            &self,
            modulus: &[u8],
            public_exponent: &[u8],
            data: &[u8],
            signature: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            rsa_pss_verify_impl(self, modulus, public_exponent, data, signature, hash_alg)
        }

        fn ecdsa_p256_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            ecdsa_sign_impl(
                self,
                BCRYPT_ECDSA_P256_ALGORITHM,
                private_key_bytes,
                data,
                32,
                BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
            )
        }

        fn ecdsa_p256_verify(
            &self,
            public_key_sec1: &[u8],
            data: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            ecdsa_verify_impl(
                self,
                BCRYPT_ECDSA_P256_ALGORITHM,
                public_key_sec1,
                data,
                signature_der,
                32,
                BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            )
        }

        fn ecdsa_p384_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            ecdsa_sign_impl(
                self,
                BCRYPT_ECDSA_P384_ALGORITHM,
                private_key_bytes,
                data,
                48,
                BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
            )
        }

        fn ecdsa_p384_verify(
            &self,
            public_key_sec1: &[u8],
            data: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            ecdsa_verify_impl(
                self,
                BCRYPT_ECDSA_P384_ALGORITHM,
                public_key_sec1,
                data,
                signature_der,
                48,
                BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
            )
        }

        /// Ed25519 sign. **Not available in FIPS mode** — CNG has no native
        /// Ed25519 implementation, so this path delegates to RustCrypto's
        /// `ed25519-dalek`, which sits outside the validated CNG boundary.
        /// When the backend is constructed via [`CngBackend::new_fips`],
        /// this method refuses with `HsmError::FunctionNotSupported` (the
        /// README and audit findings both call this out as required
        /// behaviour).
        fn ed25519_sign(&self, private_key_bytes: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            if self.fips_mode {
                return Err(HsmError::FunctionNotSupported);
            }
            // Ed25519 is not natively supported by CNG; delegate to RustCrypto.
            ed25519_sign_impl(private_key_bytes, data)
        }

        /// Ed25519 verify. **Not available in FIPS mode** — see
        /// [`CngBackend::ed25519_sign`] for the boundary rationale. Verify
        /// is also refused in FIPS mode because the README documents
        /// Ed25519 as a non-FIPS operation in this backend.
        fn ed25519_verify(
            &self,
            public_key_bytes: &[u8],
            data: &[u8],
            signature_bytes: &[u8],
        ) -> HsmResult<bool> {
            if self.fips_mode {
                return Err(HsmError::FunctionNotSupported);
            }
            ed25519_verify_impl(public_key_bytes, data, signature_bytes)
        }

        // ====================================================================
        // Prehashed signing
        // ====================================================================

        fn rsa_pkcs1v15_sign_prehashed(
            &self,
            private_key_der: &[u8],
            digest: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            rsa_pkcs1v15_sign_prehashed_impl(self, private_key_der, digest, hash_alg)
        }

        fn rsa_pkcs1v15_verify_prehashed(
            &self,
            modulus: &[u8],
            public_exponent: &[u8],
            digest: &[u8],
            signature: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            rsa_pkcs1v15_verify_prehashed_impl(
                self,
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
            self.enforce_fips_post_gate()?;
            rsa_pss_sign_prehashed_impl(self, private_key_der, digest, hash_alg)
        }

        fn rsa_pss_verify_prehashed(
            &self,
            modulus: &[u8],
            public_exponent: &[u8],
            digest: &[u8],
            signature: &[u8],
            hash_alg: HashAlg,
        ) -> HsmResult<bool> {
            rsa_pss_verify_prehashed_impl(
                self,
                modulus,
                public_exponent,
                digest,
                signature,
                hash_alg,
            )
        }

        /// ECDSA P-256 prehashed sign. Gated behind FIPS POST because the
        /// signing path consumes a private scalar and emits a signature
        /// under the CNG-validated boundary; we must not allow it to run
        /// before the certified harness has driven the KAT suite.
        fn ecdsa_p256_sign_prehashed(
            &self,
            private_key_bytes: &[u8],
            digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            ecdsa_sign_prehashed_impl(
                self,
                BCRYPT_ECDSA_P256_ALGORITHM,
                private_key_bytes,
                digest,
                32,
                BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
            )
        }

        fn ecdsa_p256_verify_prehashed(
            &self,
            public_key_sec1: &[u8],
            digest: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            ecdsa_verify_prehashed_impl(
                self,
                BCRYPT_ECDSA_P256_ALGORITHM,
                public_key_sec1,
                digest,
                signature_der,
                32,
                BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            )
        }

        /// ECDSA P-384 prehashed sign. Gated behind FIPS POST for the same
        /// reason as the P-256 variant — see
        /// [`CngBackend::ecdsa_p256_sign_prehashed`].
        fn ecdsa_p384_sign_prehashed(
            &self,
            private_key_bytes: &[u8],
            digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            ecdsa_sign_prehashed_impl(
                self,
                BCRYPT_ECDSA_P384_ALGORITHM,
                private_key_bytes,
                digest,
                48,
                BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
            )
        }

        fn ecdsa_p384_verify_prehashed(
            &self,
            public_key_sec1: &[u8],
            digest: &[u8],
            signature_der: &[u8],
        ) -> HsmResult<bool> {
            ecdsa_verify_prehashed_impl(
                self,
                BCRYPT_ECDSA_P384_ALGORITHM,
                public_key_sec1,
                digest,
                signature_der,
                48,
                BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
            )
        }

        // ====================================================================
        // Encryption
        // ====================================================================

        fn aes_256_gcm_encrypt(&self, key: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_gcm_encrypt_impl(self, key, plaintext)
        }

        fn aes_256_gcm_decrypt(&self, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_gcm_decrypt_impl(self, key, data)
        }

        fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_cbc_encrypt_impl(self, key, iv, plaintext)
        }

        fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_cbc_decrypt_impl(self, key, iv, ciphertext)
        }

        fn aes_ctr_encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_ctr_crypt_impl(self, key, iv, plaintext)
        }

        fn aes_ctr_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_ctr_crypt_impl(self, key, iv, ciphertext)
        }

        fn rsa_oaep_encrypt(
            &self,
            modulus: &[u8],
            public_exponent: &[u8],
            plaintext: &[u8],
            hash_alg: OaepHash,
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            rsa_oaep_encrypt_impl(self, modulus, public_exponent, plaintext, hash_alg)
        }

        fn rsa_oaep_decrypt(
            &self,
            private_key_der: &[u8],
            ciphertext: &[u8],
            hash_alg: OaepHash,
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            rsa_oaep_decrypt_impl(self, private_key_der, ciphertext, hash_alg)
        }

        // ====================================================================
        // Key generation
        // ====================================================================

        /// Generate a fresh AES key. Gated behind FIPS POST — generation
        /// runs `BCryptGenRandom` against the CNG provider, which must be
        /// inside the validated boundary before any secret is produced.
        fn generate_aes_key(
            &self,
            key_len_bytes: usize,
            _fips_mode: bool,
        ) -> HsmResult<RawKeyMaterial> {
            self.enforce_fips_post_gate()?;
            generate_aes_key_impl(key_len_bytes)
        }

        /// Generate an RSA key pair. Gated behind FIPS POST so private-key
        /// generation cannot run before the certified harness has driven
        /// the KAT suite.
        fn generate_rsa_key_pair(
            &self,
            modulus_bits: u32,
            _fips_mode: bool,
        ) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
            self.enforce_fips_post_gate()?;
            generate_rsa_key_pair_impl(self, modulus_bits)
        }

        /// Generate an EC P-256 key pair. Gated behind FIPS POST for the
        /// same reason as the RSA path.
        fn generate_ec_p256_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            self.enforce_fips_post_gate()?;
            generate_ec_key_pair_impl(self, BCRYPT_ECDSA_P256_ALGORITHM, 32)
        }

        /// Generate an EC P-384 key pair. Gated behind FIPS POST for the
        /// same reason as the RSA path.
        fn generate_ec_p384_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            self.enforce_fips_post_gate()?;
            generate_ec_key_pair_impl(self, BCRYPT_ECDSA_P384_ALGORITHM, 48)
        }

        /// Generate an Ed25519 key pair. **Not available in FIPS mode** —
        /// CNG has no native Ed25519, and the RustCrypto fallback lies
        /// outside the validated boundary. The POST gate is checked
        /// regardless so the order-of-operations error message is
        /// consistent across entry points (FIPS-mode call returns
        /// `FunctionNotSupported` from the explicit check below).
        fn generate_ed25519_key_pair(&self) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
            self.enforce_fips_post_gate()?;
            if self.fips_mode {
                return Err(HsmError::FunctionNotSupported);
            }
            generate_ed25519_key_pair_impl()
        }

        // ====================================================================
        // Digest
        // ====================================================================

        fn compute_digest(&self, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            let alg_id = match mechanism {
                CKM_SHA_1 => {
                    tracing::warn!(
                        "SHA-1 digest requested via CNG — SHA-1 is cryptographically broken. \
                         Migrate to SHA-256 or stronger."
                    );
                    BCRYPT_SHA1_ALGORITHM
                }
                CKM_SHA256 => BCRYPT_SHA256_ALGORITHM,
                CKM_SHA384 => BCRYPT_SHA384_ALGORITHM,
                CKM_SHA512 => BCRYPT_SHA512_ALGORITHM,
                _ => return Err(HsmError::MechanismInvalid),
            };
            bcrypt_hash(self, alg_id, data)
        }

        fn digest_output_len(&self, mechanism: CK_MECHANISM_TYPE) -> HsmResult<usize> {
            match mechanism {
                CKM_SHA_1 => Ok(20),
                CKM_SHA256 => Ok(32),
                CKM_SHA384 => Ok(48),
                CKM_SHA512 => Ok(64),
                _ => Err(HsmError::MechanismInvalid),
            }
        }

        fn create_hasher(
            &self,
            mechanism: CK_MECHANISM_TYPE,
        ) -> HsmResult<Box<dyn DigestAccumulator>> {
            let alg_id = match mechanism {
                CKM_SHA_1 => {
                    tracing::warn!(
                        "SHA-1 hasher requested via CNG — SHA-1 is cryptographically broken."
                    );
                    BCRYPT_SHA1_ALGORITHM
                }
                CKM_SHA256 => BCRYPT_SHA256_ALGORITHM,
                CKM_SHA384 => BCRYPT_SHA384_ALGORITHM,
                CKM_SHA512 => BCRYPT_SHA512_ALGORITHM,
                _ => return Err(HsmError::MechanismInvalid),
            };
            create_cng_hasher(self, alg_id)
        }

        // ====================================================================
        // Key wrap/unwrap
        // ====================================================================

        /// AES key wrap (RFC 3394). Gated behind FIPS POST — the wrap
        /// operation is the export half of the secure-key-transport
        /// boundary and must not run before the certified KAT suite has
        /// passed.
        fn aes_key_wrap(
            &self,
            wrapping_key: &[u8],
            key_to_wrap: &[u8],
            _fips_mode: bool,
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_key_wrap_impl(self, wrapping_key, key_to_wrap)
        }

        /// AES key unwrap (RFC 3394). Gated behind FIPS POST so the
        /// import-half of secure key transport cannot run before the
        /// certified KAT suite has passed.
        fn aes_key_unwrap(
            &self,
            wrapping_key: &[u8],
            wrapped_key: &[u8],
            _fips_mode: bool,
        ) -> HsmResult<Vec<u8>> {
            self.enforce_fips_post_gate()?;
            aes_key_unwrap_impl(self, wrapping_key, wrapped_key)
        }

        // ====================================================================
        // Key derivation
        // ====================================================================

        /// ECDH P-256 key agreement. Gated behind FIPS POST — agreement
        /// produces a shared secret from a private scalar and the peer's
        /// public point, both of which are sensitive inputs to a
        /// FIPS-relevant operation.
        fn ecdh_p256(
            &self,
            private_key_bytes: &[u8],
            peer_public_key_sec1: &[u8],
            okm_len: Option<usize>,
        ) -> HsmResult<RawKeyMaterial> {
            self.enforce_fips_post_gate()?;
            ecdh_impl(
                self,
                BCRYPT_ECDH_P256_ALGORITHM,
                private_key_bytes,
                peer_public_key_sec1,
                32,
                BCRYPT_ECDH_PRIVATE_P256_MAGIC,
                BCRYPT_ECDH_PUBLIC_P256_MAGIC,
                okm_len,
            )
        }

        /// ECDH P-384 key agreement. Gated behind FIPS POST for the same
        /// reason as the P-256 path.
        fn ecdh_p384(
            &self,
            private_key_bytes: &[u8],
            peer_public_key_sec1: &[u8],
            okm_len: Option<usize>,
        ) -> HsmResult<RawKeyMaterial> {
            self.enforce_fips_post_gate()?;
            ecdh_impl(
                self,
                BCRYPT_ECDH_P384_ALGORITHM,
                private_key_bytes,
                peer_public_key_sec1,
                48,
                BCRYPT_ECDH_PRIVATE_P384_MAGIC,
                BCRYPT_ECDH_PUBLIC_P384_MAGIC,
                okm_len,
            )
        }
    }
} // mod cng_impl

#[cfg(windows)]
pub use cng_impl::CngBackend;

// ============================================================================
// Cross-platform tests (compile everywhere)
// ============================================================================

#[cfg(test)]
mod cross_platform_tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn non_windows_stub_rejects_fips_mode() {
        let err = CngBackend::new_fips().unwrap_err();
        assert!(matches!(err, HsmError::FunctionNotSupported));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_stub_can_be_constructed() {
        let _backend = CngBackend::new(false);
        let _default = CngBackend::default();
    }

    #[cfg(windows)]
    #[test]
    fn ntstatus_mapping_covers_documented_codes() {
        use cng_impl::__test_ntstatus_to_hsm_error as map;
        // Each match arm in ntstatus_to_hsm_error must resolve to the expected
        // HsmError variant. Using `matches!` avoids leaking implementation
        // details if the variants grow additional fields later.
        assert!(matches!(map(0xC000_000Du32 as i32), HsmError::ArgumentsBad));
        assert!(matches!(
            map(0xC000_0008u32 as i32),
            HsmError::SessionHandleInvalid
        ));
        assert!(matches!(map(0xC000_0017u32 as i32), HsmError::HostMemory));
        assert!(matches!(
            map(0xC000_0023u32 as i32),
            HsmError::BufferTooSmall
        ));
        assert!(matches!(
            map(0x8000_0005u32 as i32),
            HsmError::BufferTooSmall
        ));
        assert!(matches!(
            map(0xC000_0225u32 as i32),
            HsmError::MechanismInvalid
        ));
        assert!(matches!(
            map(0xC000_00BBu32 as i32),
            HsmError::FunctionNotSupported
        ));
        assert!(matches!(
            map(0xC000_0002u32 as i32),
            HsmError::FunctionNotSupported
        ));
        assert!(matches!(
            map(0xC000_0022u32 as i32),
            HsmError::FunctionNotSupported
        ));
        assert!(matches!(
            map(0xC000_A000u32 as i32),
            HsmError::SignatureInvalid
        ));
        assert!(matches!(
            map(0xC000_A002u32 as i32),
            HsmError::EncryptedDataInvalid
        ));
        assert!(matches!(map(0xC000_0001u32 as i32), HsmError::GeneralError));
        assert!(matches!(
            map(0xC000_003Eu32 as i32),
            HsmError::EncryptedDataInvalid
        ));
        assert!(matches!(
            map(0xC000_0439u32 as i32),
            HsmError::AttributeValueInvalid
        ));
        assert!(matches!(
            map(0xC000_0184u32 as i32),
            HsmError::EncryptedDataInvalid
        ));
        assert!(matches!(map(0xC000_009Au32 as i32), HsmError::HostMemory));
        assert!(matches!(
            map(0xC000_00A3u32 as i32),
            HsmError::TokenNotPresent
        ));
        assert!(matches!(
            map(0x8000_0011u32 as i32),
            HsmError::TokenNotPresent
        ));
    }

    #[cfg(windows)]
    #[test]
    fn ntstatus_mapping_unknown_codes_fall_through_to_general() {
        use cng_impl::__test_ntstatus_to_hsm_error as map;
        // An arbitrary unmapped NTSTATUS value must resolve to GeneralError.
        assert!(matches!(map(0xDEAD_BEEFu32 as i32), HsmError::GeneralError));
        // A zero (STATUS_SUCCESS) is not an error per se, but if the mapper is
        // ever invoked with it we still produce a safe default.
        assert!(matches!(map(0), HsmError::GeneralError));
    }

    #[cfg(windows)]
    #[test]
    fn ntstatus_mapping_is_pure() {
        // The mapping function is side-effect-free and idempotent. Exercise it
        // twice with the same value and assert equivalent variant discriminants.
        use cng_impl::__test_ntstatus_to_hsm_error as map;
        let a = map(0xC000_000Du32 as i32);
        let b = map(0xC000_000Du32 as i32);
        assert!(matches!(a, HsmError::ArgumentsBad));
        assert!(matches!(b, HsmError::ArgumentsBad));
    }

    /// `mark_fips_post_passed` flips the latched POST flag from `false`
    /// to `true` (audit finding W3). The test runs on every host — the
    /// non-Windows stub exposes the same surface for portability.
    #[test]
    fn mark_fips_post_passed_flips_flag() {
        let b = CngBackend::new(false);
        assert!(!b.fips_post_passed(), "fresh backend has POST flag clear");
        b.mark_fips_post_passed();
        assert!(b.fips_post_passed(), "after mark, POST flag is set");
        b.mark_fips_post_passed();
        assert!(b.fips_post_passed(), "idempotent");
    }
}

// ============================================================================
// Windows-specific integration tests
// ============================================================================

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use craton_hsm::crypto::backend::CryptoBackend;
    use craton_hsm::pkcs11_abi::constants::*;

    #[test]
    fn cng_backend_can_be_constructed() {
        let _backend = CngBackend::new(false);
    }

    #[test]
    fn cng_backend_default_works() {
        let _backend = CngBackend::default();
    }

    #[test]
    fn cng_backend_fips_mode() {
        let result = CngBackend::new_fips();
        assert!(result.is_ok(), "FIPS mode should initialize on Windows");
    }

    // ====================================================================
    // AES-256-GCM regression tests (trait API: no external AAD)
    // ====================================================================

    #[test]
    fn aes_256_gcm_round_trip_ok() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let plaintext = b"some plaintext worth protecting";
        let ciphertext = backend
            .aes_256_gcm_encrypt(key.as_bytes(), plaintext)
            .unwrap();
        let decrypted = backend
            .aes_256_gcm_decrypt(key.as_bytes(), &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_256_gcm_rejects_tampered_ciphertext() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let mut ct = backend
            .aes_256_gcm_encrypt(key.as_bytes(), b"payload")
            .unwrap();
        // Flip a bit in the ciphertext body (past the 12-byte nonce prefix).
        ct[13] ^= 0x01;
        let err = backend
            .aes_256_gcm_decrypt(key.as_bytes(), &ct)
            .unwrap_err();
        assert!(matches!(err, HsmError::EncryptedDataInvalid));
    }

    #[test]
    fn aes_256_gcm_rejects_short_key() {
        // The CNG backend only supports AES-256; smaller keys are rejected
        // at the API boundary so the FIPS disposition is unambiguous.
        let backend = CngBackend::new(false);
        let err = backend.aes_256_gcm_encrypt(&[0u8; 16], b"pt").unwrap_err();
        assert!(matches!(err, HsmError::KeySizeRange));
    }

    #[test]
    fn aes_256_gcm_nonces_are_unique_across_encryptions() {
        // Each encryption must draw a fresh 96-bit nonce from the OS RNG. A
        // collision over N < 2^48 encryptions is effectively impossible; if
        // any two match, the nonce generation is broken.
        use std::collections::HashSet;
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let mut seen: HashSet<[u8; 12]> = HashSet::new();
        for _ in 0..200 {
            let ct = backend.aes_256_gcm_encrypt(key.as_bytes(), b"x").unwrap();
            let mut n = [0u8; 12];
            n.copy_from_slice(&ct[..12]);
            assert!(seen.insert(n), "duplicate nonce produced by CNG backend");
        }
    }

    #[test]
    fn generate_aes_key_returns_256_bit_key() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    // ====================================================================
    // Digest tests
    // ====================================================================

    #[test]
    fn sha256_digest_produces_32_bytes() {
        let backend = CngBackend::new(false);
        let digest = backend.compute_digest(CKM_SHA256, b"hello");
        assert!(digest.is_ok(), "compute_digest should succeed for SHA-256");
        assert_eq!(digest.unwrap().len(), 32);
    }

    #[test]
    fn sha256_digest_is_deterministic() {
        let backend = CngBackend::new(false);
        let d1 = backend.compute_digest(CKM_SHA256, b"test input").unwrap();
        let d2 = backend.compute_digest(CKM_SHA256, b"test input").unwrap();
        assert_eq!(d1, d2, "same input must produce the same digest");
    }

    #[test]
    fn sha256_known_answer() {
        let backend = CngBackend::new(false);
        let d = backend.compute_digest(CKM_SHA256, b"").unwrap();
        // SHA-256 of empty string.
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(d, expected);
    }

    #[test]
    fn sha384_digest_produces_48_bytes() {
        let backend = CngBackend::new(false);
        let digest = backend.compute_digest(CKM_SHA384, b"hello").unwrap();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn sha512_digest_produces_64_bytes() {
        let backend = CngBackend::new(false);
        let digest = backend.compute_digest(CKM_SHA512, b"hello").unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn sha256_different_inputs_differ() {
        let backend = CngBackend::new(false);
        let d1 = backend.compute_digest(CKM_SHA256, b"aaa").unwrap();
        let d2 = backend.compute_digest(CKM_SHA256, b"bbb").unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn incremental_hasher_matches_oneshot() {
        let backend = CngBackend::new(false);
        let oneshot = backend.compute_digest(CKM_SHA256, b"hello world").unwrap();

        let mut hasher = backend.create_hasher(CKM_SHA256).unwrap();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finalize();
        assert_eq!(oneshot, incremental);
    }

    // ====================================================================
    // AES-GCM tests
    // ====================================================================

    #[test]
    fn aes_256_gcm_roundtrip() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let ciphertext = backend
            .aes_256_gcm_encrypt(key.as_bytes(), plaintext)
            .unwrap();
        assert_ne!(&ciphertext[12..ciphertext.len() - 16], plaintext.as_slice());
        let decrypted = backend
            .aes_256_gcm_decrypt(key.as_bytes(), &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_256_gcm_tamper_detection() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let ciphertext = backend
            .aes_256_gcm_encrypt(key.as_bytes(), b"secret")
            .unwrap();
        let mut tampered = ciphertext.clone();
        // Flip a bit in the ciphertext portion.
        if tampered.len() > 14 {
            tampered[13] ^= 0x01;
        }
        assert!(backend
            .aes_256_gcm_decrypt(key.as_bytes(), &tampered)
            .is_err());
    }

    // ====================================================================
    // AES-CBC tests
    // ====================================================================

    #[test]
    fn aes_cbc_roundtrip() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let iv = [0u8; 16];
        let plaintext = b"sixteen bytes!!";
        let ciphertext = backend
            .aes_cbc_encrypt(key.as_bytes(), &iv, plaintext)
            .unwrap();
        let decrypted = backend
            .aes_cbc_decrypt(key.as_bytes(), &iv, &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ====================================================================
    // AES-CTR tests
    // ====================================================================

    #[test]
    fn aes_ctr_roundtrip() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        let iv = [0u8; 16];
        let plaintext = b"variable length data for CTR mode test!";
        let ciphertext = backend
            .aes_ctr_encrypt(key.as_bytes(), &iv, plaintext)
            .unwrap();
        let decrypted = backend
            .aes_ctr_decrypt(key.as_bytes(), &iv, &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ====================================================================
    // Key generation tests
    // ====================================================================

    #[test]
    fn generate_aes_256_key() {
        let backend = CngBackend::new(false);
        let key = backend.generate_aes_key(32, false).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_rsa_2048_key_pair() {
        let backend = CngBackend::new(false);
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        assert!(!priv_key.as_bytes().is_empty());
        assert_eq!(modulus.len(), 256); // 2048 bits = 256 bytes
        assert!(!pub_exp.is_empty());
    }

    #[test]
    fn generate_ec_p256_key_pair() {
        let backend = CngBackend::new(false);
        let (priv_key, pub_key) = backend.generate_ec_p256_key_pair().unwrap();
        assert_eq!(priv_key.as_bytes().len(), 32);
        assert_eq!(pub_key.len(), 65); // 0x04 || X(32) || Y(32)
        assert_eq!(pub_key[0], 0x04);
    }

    #[test]
    fn generate_ec_p384_key_pair() {
        let backend = CngBackend::new(false);
        let (priv_key, pub_key) = backend.generate_ec_p384_key_pair().unwrap();
        assert_eq!(priv_key.as_bytes().len(), 48);
        assert_eq!(pub_key.len(), 97); // 0x04 || X(48) || Y(48)
        assert_eq!(pub_key[0], 0x04);
    }

    #[test]
    fn generate_ed25519_key_pair() {
        let backend = CngBackend::new(false);
        let (priv_key, pub_key) = backend.generate_ed25519_key_pair().unwrap();
        assert_eq!(priv_key.as_bytes().len(), 32);
        assert_eq!(pub_key.len(), 32);
    }

    // ====================================================================
    // RSA sign/verify tests
    // ====================================================================

    #[test]
    fn rsa_pkcs1v15_sign_verify_roundtrip() {
        let backend = CngBackend::new(false);
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        let data = b"test message for RSA PKCS1v15";
        let hash_alg = Some(craton_hsm::crypto::sign::HashAlg::Sha256);

        let signature = backend
            .rsa_pkcs1v15_sign(priv_key.as_bytes(), data, hash_alg)
            .unwrap();
        assert!(!signature.is_empty());

        let valid = backend
            .rsa_pkcs1v15_verify(&modulus, &pub_exp, data, &signature, hash_alg)
            .unwrap();
        assert!(valid, "Signature should verify successfully");
    }

    #[test]
    fn rsa_pss_sign_verify_roundtrip() {
        let backend = CngBackend::new(false);
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        let data = b"test message for RSA PSS";
        let hash_alg = craton_hsm::crypto::sign::HashAlg::Sha256;

        let signature = backend
            .rsa_pss_sign(priv_key.as_bytes(), data, hash_alg)
            .unwrap();
        let valid = backend
            .rsa_pss_verify(&modulus, &pub_exp, data, &signature, hash_alg)
            .unwrap();
        assert!(valid);
    }

    // ====================================================================
    // ECDSA sign/verify tests
    // ====================================================================

    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let backend = CngBackend::new(false);
        let (priv_key, pub_key) = backend.generate_ec_p256_key_pair().unwrap();
        let data = b"test message for ECDSA P-256";

        let signature = backend.ecdsa_p256_sign(priv_key.as_bytes(), data).unwrap();
        assert!(!signature.is_empty());

        let valid = backend
            .ecdsa_p256_verify(&pub_key, data, &signature)
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn ecdsa_p384_sign_verify_roundtrip() {
        let backend = CngBackend::new(false);
        let (priv_key, pub_key) = backend.generate_ec_p384_key_pair().unwrap();
        let data = b"test message for ECDSA P-384";

        let signature = backend.ecdsa_p384_sign(priv_key.as_bytes(), data).unwrap();
        let valid = backend
            .ecdsa_p384_verify(&pub_key, data, &signature)
            .unwrap();
        assert!(valid);
    }

    // ====================================================================
    // Ed25519 sign/verify tests
    // ====================================================================

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let backend = CngBackend::new(false);
        let (priv_key, pub_key) = backend.generate_ed25519_key_pair().unwrap();
        let data = b"test message for Ed25519";

        let signature = backend.ed25519_sign(priv_key.as_bytes(), data).unwrap();
        assert_eq!(signature.len(), 64);

        let valid = backend.ed25519_verify(&pub_key, data, &signature).unwrap();
        assert!(valid);
    }

    // ====================================================================
    // RSA-OAEP tests
    // ====================================================================

    #[test]
    fn rsa_oaep_encrypt_decrypt_roundtrip() {
        let backend = CngBackend::new(false);
        let (priv_key, modulus, pub_exp) = backend.generate_rsa_key_pair(2048, false).unwrap();
        let plaintext = b"secret data for RSA-OAEP";

        let ciphertext = backend
            .rsa_oaep_encrypt(
                &modulus,
                &pub_exp,
                plaintext,
                craton_hsm::crypto::sign::OaepHash::Sha256,
            )
            .unwrap();
        assert!(!ciphertext.is_empty());

        let decrypted = backend
            .rsa_oaep_decrypt(
                priv_key.as_bytes(),
                &ciphertext,
                craton_hsm::crypto::sign::OaepHash::Sha256,
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ====================================================================
    // ECDH tests
    // ====================================================================

    #[test]
    fn ecdh_p256_shared_secret() {
        let backend = CngBackend::new(false);
        let (priv_a, pub_a) = backend.generate_ec_p256_key_pair().unwrap();
        let (priv_b, pub_b) = backend.generate_ec_p256_key_pair().unwrap();

        let secret_a = backend.ecdh_p256(priv_a.as_bytes(), &pub_b, None).unwrap();
        let secret_b = backend.ecdh_p256(priv_b.as_bytes(), &pub_a, None).unwrap();

        assert_eq!(
            secret_a.as_bytes(),
            secret_b.as_bytes(),
            "ECDH shared secrets should match"
        );
        assert!(!secret_a.as_bytes().is_empty());
    }

    // ====================================================================
    // FIPS-bypass fix: public-point derivation cross-check
    // ====================================================================

    /// CNG must derive the same public point that the retired pure-Rust
    /// path would have computed for the same scalar. This is the smoke
    /// test that gates the FIPS-bypass fix: if NCryptImportKey ever stops
    /// deriving Q internally (or starts deriving a different Q), every
    /// caller of `derive_ecc_public_via_ncrypt` would silently disagree
    /// with the wider ecosystem.
    #[test]
    fn cng_p256_public_point_matches_rustcrypto() {
        use p256::SecretKey;

        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            let sk = SecretKey::random(&mut rng);
            let scalar = sk.to_bytes().to_vec();

            let (x_cng, y_cng) =
                cng_impl::__test_derive_ecc_public_via_ncrypt(&scalar, 32).expect("ncrypt derive");
            let (x_ref, y_ref) =
                cng_impl::__test_compute_p256_public_point(&scalar).expect("rustcrypto derive");

            assert_eq!(x_cng, x_ref, "P-256 X coordinate mismatch");
            assert_eq!(y_cng, y_ref, "P-256 Y coordinate mismatch");
            assert_eq!(x_cng.len(), 32, "P-256 X must be 32 bytes");
            assert_eq!(y_cng.len(), 32, "P-256 Y must be 32 bytes");
        }
    }

    #[test]
    fn cng_p384_public_point_matches_rustcrypto() {
        use p384::SecretKey;

        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            let sk = SecretKey::random(&mut rng);
            let scalar = sk.to_bytes().to_vec();

            let (x_cng, y_cng) =
                cng_impl::__test_derive_ecc_public_via_ncrypt(&scalar, 48).expect("ncrypt derive");
            let (x_ref, y_ref) =
                cng_impl::__test_compute_p384_public_point(&scalar).expect("rustcrypto derive");

            assert_eq!(x_cng, x_ref, "P-384 X coordinate mismatch");
            assert_eq!(y_cng, y_ref, "P-384 Y coordinate mismatch");
            assert_eq!(x_cng.len(), 48, "P-384 X must be 48 bytes");
            assert_eq!(y_cng.len(), 48, "P-384 Y must be 48 bytes");
        }
    }

    /// Ensure the all-zero and oversized scalar checks at the API boundary
    /// reject obviously broken inputs without bothering CNG.
    #[test]
    fn ncrypt_derive_rejects_invalid_scalar_inputs() {
        // All-zero scalar.
        assert!(matches!(
            cng_impl::__test_derive_ecc_public_via_ncrypt(&[0u8; 32], 32),
            Err(HsmError::AttributeValueInvalid)
        ));
        // Empty scalar.
        assert!(matches!(
            cng_impl::__test_derive_ecc_public_via_ncrypt(&[], 32),
            Err(HsmError::AttributeValueInvalid)
        ));
        // Oversized scalar.
        let too_big = vec![0xFFu8; 64];
        assert!(matches!(
            cng_impl::__test_derive_ecc_public_via_ncrypt(&too_big, 32),
            Err(HsmError::AttributeValueInvalid)
        ));
        // Unsupported curve size.
        let scalar = vec![0x01u8; 24];
        assert!(matches!(
            cng_impl::__test_derive_ecc_public_via_ncrypt(&scalar, 24),
            Err(HsmError::KeySizeRange)
        ));
    }

    /// Spot-check the PKCS#8 encoder produces a well-formed envelope.
    #[test]
    fn pkcs8_ec_private_encoding_has_expected_prefix() {
        let scalar = vec![0x11u8; 32];
        let pkcs8 = cng_impl::__test_encode_pkcs8_ec_private_key(&scalar, 32).unwrap();
        // Outer SEQUENCE tag.
        assert_eq!(pkcs8[0], 0x30, "outer tag must be SEQUENCE");
        // The encoded blob must contain the ecPublicKey OID and the
        // secp256r1 OID bytes verbatim.
        let oid_ec_public_key: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let oid_p256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        assert!(
            pkcs8
                .windows(oid_ec_public_key.len())
                .any(|w| w == oid_ec_public_key),
            "PKCS#8 must carry the ecPublicKey OID"
        );
        assert!(
            pkcs8.windows(oid_p256.len()).any(|w| w == oid_p256),
            "PKCS#8 for P-256 must carry the secp256r1 OID"
        );
        // The 32-byte scalar must appear verbatim (it was already padded).
        assert!(
            pkcs8.windows(scalar.len()).any(|w| w == scalar.as_slice()),
            "PKCS#8 must embed the (padded) private scalar"
        );

        // Same for P-384.
        let scalar = vec![0x22u8; 48];
        let pkcs8 = cng_impl::__test_encode_pkcs8_ec_private_key(&scalar, 48).unwrap();
        let oid_p384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
        assert_eq!(pkcs8[0], 0x30, "outer tag must be SEQUENCE");
        assert!(
            pkcs8.windows(oid_p384.len()).any(|w| w == oid_p384),
            "PKCS#8 for P-384 must carry the secp384r1 OID"
        );
        assert!(
            pkcs8.windows(scalar.len()).any(|w| w == scalar.as_slice()),
            "PKCS#8 must embed the (padded) private scalar"
        );
    }
}
