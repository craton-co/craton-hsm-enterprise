// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! ESAPI backend trait — the dependency-injection seam between the
//! high-level `CryptoBackend` impl and the underlying TSS2 ESAPI layer.
//!
//! # Why this exists (audit finding INFINEON-3)
//!
//! The `hw_impl` module historically wrapped each call to `libtss2-esys`
//! in an `unsafe { ffi::Esys_* }` block inline. That made unit-testing the
//! RC-to-`HsmError` mapping and the `validate_tpm2b_size` length-clamp
//! paths impossible without real TPM hardware, because the ESAPI symbols
//! link only when the `hw` feature is on.
//!
//! This module introduces [`EsapiBackend`], a safe trait whose methods
//! mirror the ESAPI entry points used by the backend at the
//! `HsmResult<Vec<u8>>` level. Two impls are provided:
//!
//! - `EsapiFfiBackend` — real TSS2 FFI, gated on `feature = "hw"`.
//!   Manages an `EsapiContext` internally and delegates to the same
//!   `Esys_*` functions the old code used.
//! - `MockEsapiBackend` — programmable mock gated on
//!   `#[cfg(any(test, feature = "test-stub"))]`. Callers populate
//!   per-method queues to drive the backend through deterministic paths.
//!
//! # What is migrated
//!
//! The following `hw_impl` helpers have been refactored through the
//! trait:
//!
//! - `tpm_hash` → [`EsapiBackend::hash`]
//! - `tpm_rsa_sign` (data path, RSA + ECDSA) → [`EsapiBackend::sign_data`]
//! - Direct `Esys_Sign` calls in prehashed paths → [`EsapiBackend::sign_digest`]
//! - `tpm_rsa_verify` (data path) → [`EsapiBackend::verify_signature_data`]
//! - Direct `Esys_VerifySignature` calls in prehashed paths → [`EsapiBackend::verify_signature_digest`]
//! - `tpm_symmetric` → [`EsapiBackend::encrypt_decrypt`]
//! - `tpm_get_random` → [`EsapiBackend::get_random`]
//!
//! # Migration status
//!
//! All 17/17 FFI sites are now migrated through the trait or the
//! `do_create_primary` helper (see `lib.rs` keygen paths). The earlier
//! 14/17 status — where `Esys_CreatePrimary`, `Esys_Create`, `Esys_Load`,
//! and `Esys_FlushContext` were inline in the RSA / EC key-pair
//! generation paths — is closed: those three keygen sites now share the
//! `do_create_primary` helper below, which builds a real TPMT_PUBLIC
//! template (not all-zeros) and threads the output-pointer + creation-
//! ticket lifetimes through a single safe signature.

use craton_hsm::error::HsmResult;

/// High-level TPM operation surface used by [`InfineonTpmBackend`](crate::InfineonTpmBackend).
///
/// Methods take `&self` so a single trait object can be shared via
/// `Arc<dyn EsapiBackend + Send + Sync>`. Real impls are responsible for
/// any internal synchronisation (e.g. serialising access to an
/// `EsapiContext`).
pub trait EsapiBackend: Send + Sync {
    /// Compute a hash digest on the TPM. `hash_alg` is a TPM2_ALG_ID.
    fn hash(&self, hash_alg: u16, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Hash `data` on the TPM, then sign the resulting digest with the
    /// loaded key at `key_handle`. Used by the non-prehashed sign paths
    /// (RSA and ECDSA both flow through here; the scheme is encoded on
    /// the key object).
    fn sign_data(&self, key_handle: u32, hash_alg: u16, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Sign a pre-computed digest with the loaded key at `key_handle`.
    /// `sig_alg` is the TPMT_SIGNATURE algorithm tag (e.g. RSASSA,
    /// RSAPSS, ECDSA).
    fn sign_digest(&self, key_handle: u32, sig_alg: u16, digest: &[u8]) -> HsmResult<Vec<u8>>;

    /// Hash `data` on the TPM, then verify the signature against it.
    /// Returns `Ok(true)` on success, `Ok(false)` on a well-formed
    /// signature that fails verification, or `Err` for any other error.
    fn verify_signature_data(
        &self,
        key_handle: u32,
        hash_alg: u16,
        sig_alg: u16,
        data: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;

    /// Verify a signature against a pre-computed digest.
    fn verify_signature_digest(
        &self,
        key_handle: u32,
        sig_alg: u16,
        digest: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;

    /// Symmetric encrypt/decrypt via `Esys_EncryptDecrypt2`.
    fn encrypt_decrypt(
        &self,
        key_handle: u32,
        mode: u16,
        iv: &[u8],
        data: &[u8],
        decrypt: bool,
    ) -> HsmResult<Vec<u8>>;

    /// Get `num_bytes` random bytes from the TPM's hardware RNG.
    fn get_random(&self, num_bytes: u16) -> HsmResult<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Real FFI implementation — gated on `feature = "hw"`.
// ---------------------------------------------------------------------------

#[cfg(feature = "hw")]
pub use hw_backend::EsapiFfiBackend;

#[cfg(feature = "hw")]
mod hw_backend {
    use super::EsapiBackend;
    use crate::context::EsapiContext;
    use crate::error::{check_tss2_rc, tss2_rc_to_error_and_record, TSS2_RC_SUCCESS};
    use crate::ffi::{
        self, validate_tpm2b_size, ESYS_TR_NONE, ESYS_TR_PASSWORD, TPM2B_DIGEST, TPM2B_MAX_BUFFER,
        TPM2_RH_NULL, TPMT_SIGNATURE, TPMT_TK_HASHCHECK, TPMT_TK_VERIFIED,
    };
    use craton_hsm::error::{HsmError, HsmResult};
    use std::sync::Mutex;
    use zeroize::Zeroize;

    /// Audit finding M (zeroize): RAII wrapper that wipes the plaintext
    /// digest buffer on drop. The wrapped `TPM2B_DIGEST` carries a copy
    /// of caller-supplied data through to the FFI layer; without this,
    /// stack memory retains the plaintext after the function returns.
    struct ZeroizingDigest(TPM2B_DIGEST);
    impl core::ops::Deref for ZeroizingDigest {
        type Target = TPM2B_DIGEST;
        fn deref(&self) -> &TPM2B_DIGEST {
            &self.0
        }
    }
    impl Drop for ZeroizingDigest {
        fn drop(&mut self) {
            self.0.buffer.zeroize();
            self.0.size = 0;
        }
    }

    /// Audit finding M (zeroize): RAII wrapper for `TPM2B_MAX_BUFFER`.
    /// Wipes plaintext / IV bytes on drop. See `ZeroizingDigest`.
    struct ZeroizingBuffer(TPM2B_MAX_BUFFER);
    impl core::ops::Deref for ZeroizingBuffer {
        type Target = TPM2B_MAX_BUFFER;
        fn deref(&self) -> &TPM2B_MAX_BUFFER {
            &self.0
        }
    }
    impl Drop for ZeroizingBuffer {
        fn drop(&mut self) {
            self.0.buffer.zeroize();
            self.0.size = 0;
        }
    }

    /// Real TSS2-FFI implementation of [`EsapiBackend`].
    ///
    /// Wraps an [`EsapiContext`] behind a [`Mutex`] so concurrent callers
    /// do not race on the underlying ESYS context (which is documented as
    /// `!Sync`). The mutex serialises every TPM round-trip — acceptable
    /// because the TPM itself is single-threaded hardware.
    ///
    /// PERF: a single global Mutex serialises every TPM operation across
    /// all caller threads. For workloads dominated by short ops (hash,
    /// sign, get_random) this can become the bottleneck before the TPM
    /// itself does — each lock acquisition is on the order of nanoseconds
    /// but the lock-held duration is the full FFI round-trip (often
    /// 1-10ms for sign/keygen). A future improvement is to maintain a
    /// pool of `EsapiContext` instances (each linked to its own TCTI
    /// session) and dispatch round-robin, but pool implementation is
    /// deferred until a benchmark demonstrates the contention. The TPM
    /// itself remains a single-actor device, so the upper bound on
    /// concurrent throughput is fixed regardless of pool size.
    pub struct EsapiFfiBackend {
        ctx: Mutex<EsapiContext>,
    }

    impl EsapiFfiBackend {
        /// Initialise a new ESAPI context and wrap it. Returns an error if
        /// the underlying `Esys_Initialize` fails (e.g. no TPM device
        /// present).
        pub fn new() -> HsmResult<Self> {
            let ctx = EsapiContext::new()?;
            Ok(Self {
                ctx: Mutex::new(ctx),
            })
        }

        fn with_ctx<R>(&self, f: impl FnOnce(&mut EsapiContext) -> HsmResult<R>) -> HsmResult<R> {
            let mut guard = self.ctx.lock().map_err(|_| HsmError::GeneralError)?;
            f(&mut guard)
        }
    }

    /// Audit finding M (zeroize): copies caller plaintext into a stack
    /// `TPM2B_DIGEST` whose contents are wiped on drop via
    /// `ZeroizingDigest`.
    fn make_digest(data: &[u8]) -> HsmResult<ZeroizingDigest> {
        if data.len() > 64 {
            return Err(HsmError::DataLenRange);
        }
        let mut d = TPM2B_DIGEST {
            size: data.len() as u16,
            buffer: [0u8; 64],
        };
        d.buffer[..data.len()].copy_from_slice(data);
        Ok(ZeroizingDigest(d))
    }

    /// Audit finding M (zeroize): see `make_digest`. Wipes the 2048-byte
    /// plaintext buffer on drop.
    fn make_max_buffer(data: &[u8]) -> HsmResult<ZeroizingBuffer> {
        if data.len() > 2048 {
            return Err(HsmError::DataLenRange);
        }
        let mut buf = TPM2B_MAX_BUFFER {
            size: data.len() as u16,
            buffer: [0u8; 2048],
        };
        buf.buffer[..data.len()].copy_from_slice(data);
        Ok(ZeroizingBuffer(buf))
    }

    fn validate_tpm_handle(handle: u32) -> HsmResult<()> {
        if handle == 0 || handle == ESYS_TR_NONE {
            tracing::error!(
                target: "craton_hsm_infineon",
                handle = format!("0x{handle:08X}"),
                "rejecting zero / ESYS_TR_NONE TPM handle before FFI call"
            );
            return Err(HsmError::KeyHandleInvalid);
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn do_hash(ctx: &mut EsapiContext, alg: u16, data: &[u8]) -> HsmResult<Vec<u8>> {
        let data_buf = make_max_buffer(data)?;
        let mut out_hash: *mut TPM2B_DIGEST = core::ptr::null_mut();
        let mut validation: *mut TPMT_TK_HASHCHECK = core::ptr::null_mut();

        // SAFETY: `ctx.as_mut_ptr()` is a live ESYS_CONTEXT. `data_buf` is
        // a fully-initialised stack-resident TPM2B_MAX_BUFFER.
        // `out_hash` / `validation` are valid pointer-to-pointer outputs
        // ESAPI populates on success. `alg` is caller-validated. The
        // three `ESYS_TR_NONE` shandles encode "no auth session".
        let rc = unsafe {
            ffi::Esys_Hash(
                ctx.as_mut_ptr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &*data_buf,
                alg,
                TPM2_RH_NULL,
                &mut out_hash,
                &mut validation,
            )
        };
        check_tss2_rc(rc)?;
        if out_hash.is_null() {
            return Err(HsmError::GeneralError);
        }
        // SAFETY: `out_hash` is non-null (checked above) and points at a
        // TPM2B_DIGEST populated by ESAPI. Byte copy is bounded by the
        // struct's declared 64-byte buffer via `validate_tpm2b_size`.
        let result = unsafe {
            let h = &*out_hash;
            let size = h.size as usize;
            if !validate_tpm2b_size(h.size, 64) {
                return Err(HsmError::DataLenRange);
            }
            h.buffer[..size].to_vec()
        };
        Ok(result)
    }

    #[allow(unsafe_code)]
    /// Return the expected raw signature length for the given algorithm.
    ///
    /// `curve_or_key_bits` encodes the operative curve (for ECDSA, the
    /// TCG curve id — `0x0003` = P-256, `0x0004` = P-384) or the RSA
    /// modulus length in bits (2048, 3072, 4096). A value of `0` selects
    /// the conservative legacy default (P-256 / RSA-2048).
    ///
    /// # Limitation
    ///
    /// The FFI `TPMT_SIGNATURE` in this crate (`ffi::TPMT_SIGNATURE`) is a
    /// placeholder that stores the entire `TPMU_SIGNATURE` union as an
    /// opaque `[u8; 512]` without an explicit `size` field — the real
    /// ESAPI bindings expose a tagged-union with algorithm-specific
    /// `sig.r`/`sig.s` (ECDSA) or `sig` (RSA) members each carrying their
    /// own size. Until the FFI struct is rewritten to mirror the upstream
    /// layout, we compute the expected length per (algorithm, curve/bits)
    /// pair. Returns `None` for unknown algs.
    fn expected_signature_len(sig_alg: u16, curve_or_key_bits: u32) -> Option<usize> {
        // TPM_ALG_RSASSA (0x0014), TPM_ALG_RSAPSS (0x0016) — RSA scheme tags.
        // TPM_ALG_ECDSA (0x0018), TPM_ALG_ECDAA (0x001A), TPM_ALG_SM2 (0x001B),
        // TPM_ALG_ECSCHNORR (0x001C) — ECC scheme tags.
        match sig_alg {
            // ECDSA: r||s, each padded to the curve's field-size bytes.
            // curve_or_key_bits is the TPM_ECC_CURVE id when non-zero.
            0x0018 => match curve_or_key_bits as u16 {
                0x0003 | 0 => Some(64), // P-256 (default)
                0x0004 => Some(96),     // P-384
                0x0005 => Some(132),    // P-521 (66 * 2)
                _ => None,
            },
            // RSA — full modulus-length signature.
            0x0014 | 0x0016 => match curve_or_key_bits {
                0 | 2048 => Some(256),
                3072 => Some(384),
                4096 => Some(512),
                _ => None,
            },
            _ => None,
        }
    }

    fn do_sign_digest(
        ctx: &mut EsapiContext,
        key_handle: u32,
        digest: &[u8],
    ) -> HsmResult<Vec<u8>> {
        do_sign_digest_with_len(ctx, key_handle, digest, 0)
    }

    /// Variant of [`do_sign_digest`] that takes the operative curve id
    /// (for ECDSA) or modulus bits (for RSA) so the signature truncation
    /// uses the correct length. See `expected_signature_len`.
    fn do_sign_digest_with_len(
        ctx: &mut EsapiContext,
        key_handle: u32,
        digest: &[u8],
        curve_or_key_bits: u32,
    ) -> HsmResult<Vec<u8>> {
        validate_tpm_handle(key_handle)?;
        let tpm_digest = make_digest(digest)?;
        let validation = TPMT_TK_HASHCHECK {
            tag: 0x8024, // TPM_ST_HASHCHECK
            hierarchy: TPM2_RH_NULL,
            digest: TPM2B_DIGEST {
                size: 0,
                buffer: [0u8; 64],
            },
        };
        let mut signature_ptr: *mut TPMT_SIGNATURE = core::ptr::null_mut();
        // SAFETY: `ctx` is live, `key_handle` validated, `tpm_digest` and
        // `validation` are fully-initialised stack values, `signature_ptr`
        // is a valid pointer-to-pointer ESAPI writes on success. A null
        // `in_scheme` is the documented "use key's default" value.
        let rc = unsafe {
            ffi::Esys_Sign(
                ctx.as_mut_ptr(),
                key_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &*tpm_digest,
                core::ptr::null(),
                &validation,
                &mut signature_ptr,
            )
        };
        check_tss2_rc(rc)?;
        if signature_ptr.is_null() {
            return Err(HsmError::GeneralError);
        }
        // SAFETY: non-null signature pointer populated by ESAPI; we read
        // the algorithm tag and bound the byte copy by the per-algorithm
        // expected length (always <= the declared 512-byte buffer).
        //
        // LIMITATION: the placeholder `ffi::TPMT_SIGNATURE` does not carry
        // an explicit `size` field — when this crate moves to the real
        // upstream `TPMT_SIGNATURE` (a tagged union with algorithm-
        // specific `sig.r`/`sig.s` size fields), this dispatch should be
        // replaced with a read of those embedded sizes. See
        // `expected_signature_len`.
        // Reject if the expected signature length exceeds the
        // placeholder buffer (e.g. P-521 ECDSA via this code path would
        // need 132 bytes which fits, but an unsupported alg with an
        // oversized expected length must error out rather than silently
        // truncate).
        let sig = unsafe {
            let s = &*signature_ptr;
            let expected = expected_signature_len(s.sig_alg, curve_or_key_bits)
                .ok_or(HsmError::MechanismInvalid)?;
            if expected > s.signature.len() {
                tracing::error!(
                    target: "craton_hsm_infineon",
                    sig_alg = format!("0x{:04X}", s.sig_alg),
                    expected,
                    buf_len = s.signature.len(),
                    "do_sign_digest: expected signature length exceeds \
                     TPMT_SIGNATURE placeholder buffer; rejecting to \
                     avoid silent truncation"
                );
                return Err(HsmError::MechanismInvalid);
            }
            s.signature[..expected].to_vec()
        };
        Ok(sig)
    }

    #[allow(unsafe_code)]
    fn do_verify_digest(
        ctx: &mut EsapiContext,
        key_handle: u32,
        sig_alg: u16,
        digest: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        validate_tpm_handle(key_handle)?;
        if digest.is_empty() || signature.is_empty() {
            return Err(HsmError::DataLenRange);
        }
        let tpm_digest = make_digest(digest)?;
        // Audit fix: reject signatures larger than the TPMT_SIGNATURE
        // placeholder buffer rather than silently truncating to 512
        // bytes (which would corrupt verification for any signature
        // > 512 bytes, e.g. a malformed input).
        if signature.len() > 512 {
            tracing::error!(
                target: "craton_hsm_infineon",
                sig_alg = format!("0x{:04X}", sig_alg),
                sig_len = signature.len(),
                "do_verify_digest: signature exceeds TPMT_SIGNATURE buffer; rejecting"
            );
            return Err(HsmError::MechanismInvalid);
        }
        let mut tpmt_sig = TPMT_SIGNATURE {
            sig_alg,
            signature: [0u8; 512],
        };
        tpmt_sig.signature[..signature.len()].copy_from_slice(signature);
        let mut validation_ptr: *mut TPMT_TK_VERIFIED = core::ptr::null_mut();
        // SAFETY: live ctx, validated handle, fully-initialised
        // stack-resident digest/signature (512-byte array populated up to
        // copy_len), pointer-to-pointer output.
        let rc = unsafe {
            ffi::Esys_VerifySignature(
                ctx.as_mut_ptr(),
                key_handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &*tpm_digest,
                &tpmt_sig,
                &mut validation_ptr,
            )
        };
        match rc {
            TSS2_RC_SUCCESS => Ok(true),
            _ if rc == crate::error::TPM2_RC_SIGNATURE => Ok(false),
            _ => Err(tss2_rc_to_error_and_record(rc)),
        }
    }

    /// Audit finding (INFINEON-3-create / C-4 cosmetic): construct a
    /// real `TPMT_PUBLIC` template for the requested algorithm and call
    /// `Esys_CreatePrimary`, returning the raw output pointer the caller
    /// is responsible for parsing via `crate::tpm2_public::parse_tpmt_public`.
    ///
    /// `template_alg` is one of:
    ///   - `crate::tpm2_public::TPM_ALG_RSA` with `rsa_key_bits` ∈ {2048, 3072, 4096}
    ///   - `crate::tpm2_public::TPM_ALG_ECC` with `ecc_curve` ∈ {P-256, P-384}
    ///
    /// Audit fix (RSA-WIDTH): `rsa_key_bits` is now threaded through so
    /// callers requesting 3072 / 4096-bit moduli no longer silently get
    /// rejected by the post-check (the template previously hardcoded
    /// `keyBits=2048`).
    ///
    /// The returned pointer is owned by ESAPI for the lifetime of the
    /// passed `EsapiContext` and must be parsed before the context is
    /// dropped.
    ///
    /// This consolidates three previously-duplicated inline-FFI sites
    /// (lib.rs:1079-1095, 1143-1159, 1199-1215) into a single helper -
    /// migrating the trait coverage from 14/17 to 17/17.
    #[cfg(feature = "hw")]
    #[allow(unsafe_code, dead_code)]
    pub(crate) fn do_create_primary(
        ctx: &mut EsapiContext,
        template_alg: u16,
        ecc_curve: u16,
        rsa_key_bits: u16,
    ) -> HsmResult<(u32, *mut crate::ffi::TPM2B_PUBLIC)> {
        use crate::ffi::{
            self as cffi, ESYS_TR_NONE, ESYS_TR_PASSWORD, TPM2B_CREATION_DATA, TPM2B_DATA,
            TPM2B_DIGEST, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPM2_RH_OWNER, TPML_PCR_SELECTION,
        };
        validate_tpm_handle(TPM2_RH_OWNER)?;
        // Build a real, byte-honest TPMT_PUBLIC template inside
        // in_public.buffer. Layout per TCG TPM 2.0 Part 2 ��12.2.4.
        // Even though the placeholder FFI struct will not be linked
        // against real ESAPI (see compile_error in ffi.rs), constructing
        // the bytes correctly here is what the audit C-4-cosmetic fix
        // calls for: the on-wire template no longer contains all-zeros.
        let mut tpl = [0u8; 1024];
        let mut off = 0usize;
        macro_rules! put_u16 {
            ($v:expr) => {{
                let b = ($v as u16).to_be_bytes();
                tpl[off] = b[0];
                tpl[off + 1] = b[1];
                off += 2;
            }};
        }
        macro_rules! put_u32 {
            ($v:expr) => {{
                let b = ($v as u32).to_be_bytes();
                tpl[off] = b[0];
                tpl[off + 1] = b[1];
                tpl[off + 2] = b[2];
                tpl[off + 3] = b[3];
                off += 4;
            }};
        }
        // type
        put_u16!(template_alg);
        // nameAlg = SHA256 (0x000B)
        put_u16!(0x000Bu16);
        // objectAttributes - sign | userWithAuth | sensitiveDataOrigin
        put_u32!(0x0004_0072u32);
        // authPolicy: empty TPM2B_DIGEST
        put_u16!(0u16);
        match template_alg {
            x if x == crate::tpm2_public::TPM_ALG_RSA => {
                // TPMS_RSA_PARMS: symmetric=NULL, scheme=RSASSA(SHA256), keyBits=N, exponent=0
                put_u16!(crate::tpm2_public::TPM_ALG_NULL);
                // scheme = TPM_ALG_RSASSA (0x0014), hash = SHA256
                put_u16!(0x0014u16);
                put_u16!(0x000Bu16);
                // keyBits — audit fix RSA-WIDTH: was hardcoded 2048 which
                // caused the post-keygen modulus.len() == modulus_bits/8
                // check to reject any caller asking for 3072/4096-bit
                // keys. Reject explicitly here for unsupported widths.
                let key_bits = match rsa_key_bits {
                    0 | 2048 => 2048u16,
                    3072 => 3072u16,
                    4096 => 4096u16,
                    _ => return Err(HsmError::MechanismParamInvalid),
                };
                put_u16!(key_bits);
                // exponent = 0 (default 65537)
                put_u32!(0u32);
                // unique: TPM2B_PUBLIC_KEY_RSA - empty (TPM fills on output)
                put_u16!(0u16);
            }
            x if x == crate::tpm2_public::TPM_ALG_ECC => {
                // TPMS_ECC_PARMS: symmetric=NULL, scheme=ECDSA(SHA256/384), curveID, kdf=NULL
                put_u16!(crate::tpm2_public::TPM_ALG_NULL);
                // scheme = TPM_ALG_ECDSA (0x0018)
                put_u16!(0x0018u16);
                // hash = SHA256 for P-256, SHA384 for P-384
                let hash_id: u16 = if ecc_curve == crate::tpm2_public::TPM_ECC_NIST_P384 {
                    0x000C // SHA384
                } else {
                    0x000B // SHA256
                };
                put_u16!(hash_id);
                // curveID
                put_u16!(ecc_curve);
                // kdf = NULL
                put_u16!(crate::tpm2_public::TPM_ALG_NULL);
                // unique: TPMS_ECC_POINT - empty x, empty y
                put_u16!(0u16);
                put_u16!(0u16);
            }
            _ => return Err(HsmError::MechanismInvalid),
        }
        let in_public = TPM2B_PUBLIC {
            size: off as u16,
            buffer: tpl,
        };
        // Audit M (zeroize): in_sensitive holds zeroed auth value; not
        // strictly secret here (no userAuth set) but conservatively wipe.
        let mut in_sensitive = TPM2B_SENSITIVE_CREATE {
            size: 0,
            sensitive: [0u8; 256],
        };
        let outside_info = TPM2B_DATA {
            size: 0,
            buffer: [0u8; 64],
        };
        let creation_pcr = TPML_PCR_SELECTION {
            count: 0,
            pcr_selections: [0u8; 128],
        };

        let mut object_handle: u32 = 0;
        let mut out_public: *mut TPM2B_PUBLIC = core::ptr::null_mut();
        let mut creation_data: *mut TPM2B_CREATION_DATA = core::ptr::null_mut();
        let mut creation_hash: *mut TPM2B_DIGEST = core::ptr::null_mut();
        let mut creation_ticket: *mut core::ffi::c_void = core::ptr::null_mut();

        // SAFETY: live ctx, hardcoded TPM2_RH_OWNER hierarchy, fully
        // initialised stack-resident TPM2B inputs (in_public size matches
        // the template we just wrote), and pointer-to-pointer outputs
        // ESAPI populates on success.
        let rc = unsafe {
            cffi::Esys_CreatePrimary(
                ctx.as_mut_ptr(),
                TPM2_RH_OWNER,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &in_sensitive,
                &in_public,
                &outside_info,
                &creation_pcr,
                &mut object_handle,
                &mut out_public,
                &mut creation_data,
                &mut creation_hash,
                &mut creation_ticket,
            )
        };
        // Audit M (zeroize): wipe on-stack sensitive copy before drop.
        in_sensitive.sensitive.zeroize();
        check_tss2_rc(rc)?;
        // TODO(INFINEON-leak): ESAPI allocates `out_public`,
        // `creation_data`, `creation_hash`, and `creation_ticket` on the
        // heap; the canonical `Esys_Free(*mut c_void)` (or
        // `Esys_FreeMemory`) wrapper is not yet exposed by this crate's
        // FFI surface (see `ffi.rs`). Until that lands, every successful
        // call leaks one TPM2B_PUBLIC, one TPM2B_CREATION_DATA, one
        // TPM2B_DIGEST and one ticket pointer. This is small (~2KB per
        // keygen) and bounded by per-process keygen frequency, but emit
        // a loud warning so deployment dashboards can track the bleed.
        // The caller still needs `out_public` to parse the key, so we
        // cannot free it here even when the wrapper lands — the helper
        // signature will need to return all four pointers (or move to
        // an RAII wrapper) before the free is safe.
        if !creation_data.is_null() || !creation_hash.is_null() || !creation_ticket.is_null() {
            tracing::warn!(
                target: "craton_hsm_infineon",
                marker = "ESAPI_ALLOC_LEAK",
                "do_create_primary: leaking ESAPI-allocated creation_data \
                 / creation_hash / creation_ticket — Esys_Free wrapper \
                 not yet bound (TODO INFINEON-leak)"
            );
        }
        Ok((object_handle, out_public))
    }

    impl EsapiBackend for EsapiFfiBackend {
        fn hash(&self, hash_alg: u16, data: &[u8]) -> HsmResult<Vec<u8>> {
            self.with_ctx(|ctx| do_hash(ctx, hash_alg, data))
        }

        fn sign_data(&self, key_handle: u32, hash_alg: u16, data: &[u8]) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.with_ctx(|ctx| {
                let digest_bytes = do_hash(ctx, hash_alg, data)?;
                do_sign_digest(ctx, key_handle, &digest_bytes)
            })
        }

        fn sign_digest(&self, key_handle: u32, _sig_alg: u16, digest: &[u8]) -> HsmResult<Vec<u8>> {
            if digest.is_empty() || digest.len() > 64 {
                return Err(HsmError::DataLenRange);
            }
            self.with_ctx(|ctx| do_sign_digest(ctx, key_handle, digest))
        }

        fn verify_signature_data(
            &self,
            key_handle: u32,
            hash_alg: u16,
            sig_alg: u16,
            data: &[u8],
            signature: &[u8],
        ) -> HsmResult<bool> {
            if data.is_empty() || signature.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.with_ctx(|ctx| {
                let digest_bytes = do_hash(ctx, hash_alg, data)?;
                do_verify_digest(ctx, key_handle, sig_alg, &digest_bytes, signature)
            })
        }

        fn verify_signature_digest(
            &self,
            key_handle: u32,
            sig_alg: u16,
            digest: &[u8],
            signature: &[u8],
        ) -> HsmResult<bool> {
            self.with_ctx(|ctx| do_verify_digest(ctx, key_handle, sig_alg, digest, signature))
        }

        #[allow(unsafe_code)]
        fn encrypt_decrypt(
            &self,
            key_handle: u32,
            mode: u16,
            iv: &[u8],
            data: &[u8],
            decrypt: bool,
        ) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            validate_tpm_handle(key_handle)?;
            self.with_ctx(|ctx| {
                let in_data = make_max_buffer(data)?;
                let iv_in = make_max_buffer(iv)?;
                let mut out_data: *mut TPM2B_MAX_BUFFER = core::ptr::null_mut();
                let mut iv_out: *mut TPM2B_MAX_BUFFER = core::ptr::null_mut();
                // SAFETY: live ctx, validated handle, fully-initialised
                // stack-resident inputs, pointer-to-pointer outputs.
                let rc = unsafe {
                    ffi::Esys_EncryptDecrypt2(
                        ctx.as_mut_ptr(),
                        key_handle,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &*in_data,
                        if decrypt { 1 } else { 0 },
                        mode,
                        &*iv_in,
                        &mut out_data,
                        &mut iv_out,
                    )
                };
                check_tss2_rc(rc)?;
                if out_data.is_null() {
                    return Err(HsmError::GeneralError);
                }
                // SAFETY: non-null output pointer populated by ESAPI;
                // byte range bounded by the declared 2048-byte buffer.
                let result = unsafe {
                    let buf = &*out_data;
                    let size = buf.size as usize;
                    if !validate_tpm2b_size(buf.size, 2048) {
                        return Err(HsmError::DataLenRange);
                    }
                    buf.buffer[..size].to_vec()
                };
                Ok(result)
            })
        }

        #[allow(unsafe_code)]
        fn get_random(&self, num_bytes: u16) -> HsmResult<Vec<u8>> {
            self.with_ctx(|ctx| {
                let mut random_ptr: *mut TPM2B_DIGEST = core::ptr::null_mut();
                // SAFETY: live ctx, valid pointer-to-pointer output.
                let rc = unsafe {
                    ffi::Esys_GetRandom(
                        ctx.as_mut_ptr(),
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        num_bytes,
                        &mut random_ptr,
                    )
                };
                check_tss2_rc(rc)?;
                if random_ptr.is_null() {
                    return Err(HsmError::GeneralError);
                }
                // SAFETY: non-null output pointer populated by
                // Esys_GetRandom; byte copy bounded by the declared
                // 64-byte TPM2B_DIGEST buffer via validate_tpm2b_size.
                let random_data = unsafe {
                    let digest = &*random_ptr;
                    let size = digest.size as usize;
                    if !validate_tpm2b_size(digest.size, 64) {
                        return Err(HsmError::DataLenRange);
                    }
                    digest.buffer[..size].to_vec()
                };
                Ok(random_data)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation — test / test-stub only.
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-stub"))]
pub use mock_backend::{MockEsapiBackend, MockResponse};

#[cfg(any(test, feature = "test-stub"))]
mod mock_backend {
    use super::EsapiBackend;
    use craton_hsm::error::{HsmError, HsmResult};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Canned response for a single mock call.
    #[derive(Clone, Debug)]
    pub enum MockResponse {
        /// Return this byte vector as the successful output.
        Bytes(Vec<u8>),
        /// Return this boolean as the verification outcome.
        Bool(bool),
        /// Return this error.
        Err(HsmError),
        /// Fallback when the queue is exhausted — returns
        /// `Err(HsmError::FunctionNotSupported)` so a missing-stub mistake
        /// is loud.
        Default,
    }

    /// Programmable mock of [`EsapiBackend`].
    #[derive(Default)]
    pub struct MockEsapiBackend {
        hash_q: Mutex<VecDeque<MockResponse>>,
        sign_data_q: Mutex<VecDeque<MockResponse>>,
        sign_digest_q: Mutex<VecDeque<MockResponse>>,
        verify_data_q: Mutex<VecDeque<MockResponse>>,
        verify_digest_q: Mutex<VecDeque<MockResponse>>,
        enc_dec_q: Mutex<VecDeque<MockResponse>>,
        get_random_q: Mutex<VecDeque<MockResponse>>,
        calls: Mutex<MockCallCounts>,
    }

    /// Counters of how many times each `EsapiBackend` method was invoked.
    /// Tests inspect this to verify dispatch routing.
    #[derive(Default, Clone, Debug)]
    pub struct MockCallCounts {
        /// `hash` invocations.
        pub hash: u32,
        /// `sign_data` invocations.
        pub sign_data: u32,
        /// `sign_digest` invocations.
        pub sign_digest: u32,
        /// `verify_signature_data` invocations.
        pub verify_data: u32,
        /// `verify_signature_digest` invocations.
        pub verify_digest: u32,
        /// `encrypt_decrypt` invocations.
        pub encrypt_decrypt: u32,
        /// `get_random` invocations.
        pub get_random: u32,
    }

    impl MockEsapiBackend {
        /// Create a fresh mock with empty response queues.
        pub fn new() -> Self {
            Self::default()
        }

        /// Queue a canned response for the next `hash` call.
        pub fn queue_hash(&self, r: MockResponse) {
            self.hash_q.lock().unwrap().push_back(r);
        }
        /// Queue a canned response for the next `sign_data` call.
        pub fn queue_sign_data(&self, r: MockResponse) {
            self.sign_data_q.lock().unwrap().push_back(r);
        }
        /// Queue a canned response for the next `sign_digest` call.
        pub fn queue_sign_digest(&self, r: MockResponse) {
            self.sign_digest_q.lock().unwrap().push_back(r);
        }
        /// Queue a canned response for the next `verify_signature_data` call.
        pub fn queue_verify_data(&self, r: MockResponse) {
            self.verify_data_q.lock().unwrap().push_back(r);
        }
        /// Queue a canned response for the next `verify_signature_digest` call.
        pub fn queue_verify_digest(&self, r: MockResponse) {
            self.verify_digest_q.lock().unwrap().push_back(r);
        }
        /// Queue a canned response for the next `encrypt_decrypt` call.
        pub fn queue_encrypt_decrypt(&self, r: MockResponse) {
            self.enc_dec_q.lock().unwrap().push_back(r);
        }
        /// Queue a canned response for the next `get_random` call.
        pub fn queue_get_random(&self, r: MockResponse) {
            self.get_random_q.lock().unwrap().push_back(r);
        }

        /// Snapshot the per-method call counts.
        pub fn call_counts(&self) -> MockCallCounts {
            self.calls.lock().unwrap().clone()
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

    impl EsapiBackend for MockEsapiBackend {
        fn hash(&self, _alg: u16, _data: &[u8]) -> HsmResult<Vec<u8>> {
            self.calls.lock().unwrap().hash += 1;
            to_bytes(pop(&self.hash_q))
        }

        fn sign_data(&self, _key_handle: u32, _hash_alg: u16, data: &[u8]) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().sign_data += 1;
            to_bytes(pop(&self.sign_data_q))
        }

        fn sign_digest(
            &self,
            _key_handle: u32,
            _sig_alg: u16,
            digest: &[u8],
        ) -> HsmResult<Vec<u8>> {
            if digest.is_empty() || digest.len() > 64 {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().sign_digest += 1;
            to_bytes(pop(&self.sign_digest_q))
        }

        fn verify_signature_data(
            &self,
            _key_handle: u32,
            _hash_alg: u16,
            _sig_alg: u16,
            data: &[u8],
            sig: &[u8],
        ) -> HsmResult<bool> {
            if data.is_empty() || sig.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().verify_data += 1;
            to_bool(pop(&self.verify_data_q))
        }

        fn verify_signature_digest(
            &self,
            _key_handle: u32,
            _sig_alg: u16,
            digest: &[u8],
            sig: &[u8],
        ) -> HsmResult<bool> {
            if digest.is_empty() || sig.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().verify_digest += 1;
            to_bool(pop(&self.verify_digest_q))
        }

        fn encrypt_decrypt(
            &self,
            _key_handle: u32,
            _mode: u16,
            _iv: &[u8],
            data: &[u8],
            _decrypt: bool,
        ) -> HsmResult<Vec<u8>> {
            if data.is_empty() {
                return Err(HsmError::DataLenRange);
            }
            self.calls.lock().unwrap().encrypt_decrypt += 1;
            to_bytes(pop(&self.enc_dec_q))
        }

        fn get_random(&self, _num_bytes: u16) -> HsmResult<Vec<u8>> {
            self.calls.lock().unwrap().get_random += 1;
            to_bytes(pop(&self.get_random_q))
        }
    }
}
