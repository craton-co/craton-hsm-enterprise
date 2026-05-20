// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! FFI bindings for the TCG TSS 2.0 Enhanced System API (ESAPI).
//!
//! When the `hw` feature is active, this module declares `extern "C"` functions
//! from `libtss2-esys` and the `#[repr(C)]` types required to call them.
//!
//! Without `hw`, only stub type aliases are provided so that the rest of the
//! crate can reference them without conditional compilation noise.

#![allow(non_camel_case_types)]

// ---------------------------------------------------------------------------
// Primitive type aliases (always available)
// ---------------------------------------------------------------------------

/// TSS2 return code.
pub type TSS2_RC = u32;

/// TPM 2.0 object handle.
pub type TPM2_HANDLE = u32;

/// TPM 2.0 algorithm identifier.
pub type TPM2_ALG_ID = u16;

// ---------------------------------------------------------------------------
// Audit fix (HW-FFI-PLACEHOLDER-ABI): the `#[repr(C)]` types below are
// placeholders — opaque byte buffers with no algorithm-specific union
// shape. Linking them against real `libtss2-esys` is undefined
// behaviour: every `Esys_*` call would write the algorithm-specific
// union members at offsets that do not match the placeholder layout,
// corrupting the stack / TPM output. Refuse to compile the `hw`
// feature until real bindgen output replaces these stubs.
//
// TODO(INFINEON-bindings): replace with tss-esapi-sys generated bindings.
// ---------------------------------------------------------------------------

#[cfg(feature = "hw")]
compile_error!(
    "craton-hsm-infineon hw feature requires real tss-esapi-sys bindings; \
     placeholder FFI structs are not yet replaced — see \
     TODO(INFINEON-bindings) in src/ffi.rs"
);

// ---------------------------------------------------------------------------
// Opaque / repr(C) structs
// ---------------------------------------------------------------------------

/// Opaque ESYS context — only meaningful behind a pointer.
#[repr(C)]
pub struct ESYS_CONTEXT {
    _private: [u8; 0],
}

/// TPM2B_PUBLIC — variable-length public area.
#[repr(C)]
pub struct TPM2B_PUBLIC {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Placeholder; the real struct contains a TPMT_PUBLIC union.
    pub buffer: [u8; 1024],
}

/// TPM2B_PRIVATE — variable-length private area (encrypted by TPM).
#[repr(C)]
pub struct TPM2B_PRIVATE {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Opaque encrypted bytes.
    pub buffer: [u8; 512],
}

/// TPM2B_DIGEST — variable-length digest / nonce.
#[repr(C)]
pub struct TPM2B_DIGEST {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Digest bytes (size-prefixed; only `size` bytes are valid).
    pub buffer: [u8; 64],
}

/// TPM2B_MAX_BUFFER — largest general-purpose TPM buffer (2048 bytes).
#[repr(C)]
pub struct TPM2B_MAX_BUFFER {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Bulk-data bytes (only `size` bytes are valid).
    pub buffer: [u8; 2048],
}

/// TPMT_SIGNATURE — algorithm-tagged signature value.
#[repr(C)]
pub struct TPMT_SIGNATURE {
    /// Algorithm identifier (TPM_ALG_ID) describing the union layout.
    pub sig_alg: TPM2_ALG_ID,
    /// Placeholder for the TPMU_SIGNATURE union. Actual layout depends on
    /// the algorithm; we treat it as an opaque blob until real integration.
    pub signature: [u8; 512],
}

/// TPMT_TK_VERIFIED — ticket proving a signature was verified by the TPM.
#[repr(C)]
pub struct TPMT_TK_VERIFIED {
    /// Structure tag.
    pub tag: u16,
    /// Hierarchy under which the ticket was produced.
    pub hierarchy: TPM2_HANDLE,
    /// Digest of the public part the ticket vouches for.
    pub digest: TPM2B_DIGEST,
}

/// TPMT_TK_HASHCHECK — ticket proving data was hashed by the TPM.
#[repr(C)]
pub struct TPMT_TK_HASHCHECK {
    /// Structure tag.
    pub tag: u16,
    /// Hierarchy under which the ticket was produced.
    pub hierarchy: TPM2_HANDLE,
    /// Digest of the hashed message.
    pub digest: TPM2B_DIGEST,
}

/// TPM2B_SENSITIVE_CREATE — authorization and sensitive data for object creation.
#[repr(C)]
pub struct TPM2B_SENSITIVE_CREATE {
    /// Number of meaningful bytes in `sensitive`.
    pub size: u16,
    /// Marshaled `TPMS_SENSITIVE_CREATE`.
    pub sensitive: [u8; 256],
}

/// TPM2B_DATA — small data buffer.
#[repr(C)]
pub struct TPM2B_DATA {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Bytes (only `size` bytes are valid).
    pub buffer: [u8; 64],
}

/// TPML_PCR_SELECTION — list of PCR selection structures.
#[repr(C)]
pub struct TPML_PCR_SELECTION {
    /// Number of meaningful selection entries.
    pub count: u32,
    /// Marshaled PCR selection entries.
    pub pcr_selections: [u8; 128],
}

/// TPM2B_CREATION_DATA — creation metadata returned by CreatePrimary/Create.
#[repr(C)]
pub struct TPM2B_CREATION_DATA {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Marshaled `TPMS_CREATION_DATA`.
    pub buffer: [u8; 512],
}

/// TPM2B_NV_PUBLIC — NV index public area.
#[repr(C)]
pub struct TPM2B_NV_PUBLIC {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Marshaled `TPMS_NV_PUBLIC`.
    pub buffer: [u8; 256],
}

/// TPM2B_AUTH — authorization value.
#[repr(C)]
pub struct TPM2B_AUTH {
    /// Number of meaningful bytes in `buffer`.
    pub size: u16,
    /// Authorization bytes.
    pub buffer: [u8; 64],
}

// ---------------------------------------------------------------------------
// Bounds-checking helpers
// ---------------------------------------------------------------------------

/// Validate that a `TPM2B_*` size field is within the buffer capacity.
///
/// Returns `true` if `size <= buf_capacity`. Use this before reading
/// `size` bytes from the buffer to avoid out-of-bounds access.
#[inline]
pub fn validate_tpm2b_size(size: u16, buf_capacity: usize) -> bool {
    (size as usize) <= buf_capacity
}

// ---------------------------------------------------------------------------
// Well-known sentinel handles
// ---------------------------------------------------------------------------

/// ESYS_TR_NONE — no session / no handle.
pub const ESYS_TR_NONE: u32 = 0x0000_0FFF;

/// ESYS_TR_PASSWORD — password authorization session.
pub const ESYS_TR_PASSWORD: u32 = 0x0000_0FF9;

/// TPM2_RH_OWNER — owner hierarchy.
pub const TPM2_RH_OWNER: TPM2_HANDLE = 0x4000_0001;

/// TPM2_RH_NULL — null hierarchy.
pub const TPM2_RH_NULL: TPM2_HANDLE = 0x4000_0007;

// ---------------------------------------------------------------------------
// extern "C" declarations (hw feature only)
// ---------------------------------------------------------------------------

#[cfg(feature = "hw")]
#[allow(unsafe_code)]
extern "C" {
    // -- Lifecycle ----------------------------------------------------------

    /// Initialize an ESYS context. `tcti` may be null to use the default TCTI.
    pub fn Esys_Initialize(
        esys_context: *mut *mut ESYS_CONTEXT,
        tcti: *mut core::ffi::c_void,
        abi_version: *const core::ffi::c_void,
    ) -> TSS2_RC;

    /// Finalize (free) an ESYS context.
    pub fn Esys_Finalize(esys_context: *mut *mut ESYS_CONTEXT);

    // -- Random -------------------------------------------------------------

    /// Get random bytes from the TPM RNG.
    pub fn Esys_GetRandom(
        esys_context: *mut ESYS_CONTEXT,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        bytes_requested: u16,
        random_bytes: *mut *mut TPM2B_DIGEST,
    ) -> TSS2_RC;

    // -- Object management --------------------------------------------------

    /// Create a primary key under a hierarchy.
    pub fn Esys_CreatePrimary(
        esys_context: *mut ESYS_CONTEXT,
        primary_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        in_sensitive: *const TPM2B_SENSITIVE_CREATE,
        in_public: *const TPM2B_PUBLIC,
        outside_info: *const TPM2B_DATA,
        creation_pcr: *const TPML_PCR_SELECTION,
        object_handle: *mut u32,
        out_public: *mut *mut TPM2B_PUBLIC,
        creation_data: *mut *mut TPM2B_CREATION_DATA,
        creation_hash: *mut *mut TPM2B_DIGEST,
        creation_ticket: *mut *mut core::ffi::c_void,
    ) -> TSS2_RC;

    /// Create a child key under a loaded parent.
    pub fn Esys_Create(
        esys_context: *mut ESYS_CONTEXT,
        parent_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        in_sensitive: *const TPM2B_SENSITIVE_CREATE,
        in_public: *const TPM2B_PUBLIC,
        outside_info: *const TPM2B_DATA,
        creation_pcr: *const TPML_PCR_SELECTION,
        out_private: *mut *mut TPM2B_PRIVATE,
        out_public: *mut *mut TPM2B_PUBLIC,
        creation_data: *mut *mut TPM2B_CREATION_DATA,
        creation_hash: *mut *mut TPM2B_DIGEST,
        creation_ticket: *mut *mut core::ffi::c_void,
    ) -> TSS2_RC;

    /// Load a key (public + private) under a parent.
    pub fn Esys_Load(
        esys_context: *mut ESYS_CONTEXT,
        parent_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        in_private: *const TPM2B_PRIVATE,
        in_public: *const TPM2B_PUBLIC,
        object_handle: *mut u32,
    ) -> TSS2_RC;

    /// Flush a transient object from TPM memory.
    pub fn Esys_FlushContext(esys_context: *mut ESYS_CONTEXT, flush_handle: u32) -> TSS2_RC;

    // -- Signing / Verification ---------------------------------------------

    /// Sign a digest with a loaded key.
    pub fn Esys_Sign(
        esys_context: *mut ESYS_CONTEXT,
        key_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        digest: *const TPM2B_DIGEST,
        in_scheme: *const core::ffi::c_void,
        validation: *const TPMT_TK_HASHCHECK,
        signature: *mut *mut TPMT_SIGNATURE,
    ) -> TSS2_RC;

    /// Verify a signature against a loaded public key.
    pub fn Esys_VerifySignature(
        esys_context: *mut ESYS_CONTEXT,
        key_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        digest: *const TPM2B_DIGEST,
        signature: *const TPMT_SIGNATURE,
        validation: *mut *mut TPMT_TK_VERIFIED,
    ) -> TSS2_RC;

    // -- Symmetric encryption -----------------------------------------------

    /// Symmetric encrypt/decrypt (TPM2_EncryptDecrypt2).
    pub fn Esys_EncryptDecrypt2(
        esys_context: *mut ESYS_CONTEXT,
        key_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        in_data: *const TPM2B_MAX_BUFFER,
        decrypt: u8,
        mode: u16,
        iv_in: *const TPM2B_MAX_BUFFER,
        out_data: *mut *mut TPM2B_MAX_BUFFER,
        iv_out: *mut *mut TPM2B_MAX_BUFFER,
    ) -> TSS2_RC;

    // -- Hashing ------------------------------------------------------------

    /// Compute a hash of data on the TPM.
    pub fn Esys_Hash(
        esys_context: *mut ESYS_CONTEXT,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        data: *const TPM2B_MAX_BUFFER,
        hash_alg: TPM2_ALG_ID,
        hierarchy: u32,
        out_hash: *mut *mut TPM2B_DIGEST,
        validation: *mut *mut TPMT_TK_HASHCHECK,
    ) -> TSS2_RC;

    // -- NV Storage ---------------------------------------------------------

    /// Define an NV index.
    pub fn Esys_NV_DefineSpace(
        esys_context: *mut ESYS_CONTEXT,
        auth_handle: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        auth: *const TPM2B_AUTH,
        public_info: *const TPM2B_NV_PUBLIC,
    ) -> TSS2_RC;

    /// Write data to an NV index.
    pub fn Esys_NV_Write(
        esys_context: *mut ESYS_CONTEXT,
        auth_handle: u32,
        nv_index: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        data: *const TPM2B_MAX_BUFFER,
        offset: u16,
    ) -> TSS2_RC;

    /// Read data from an NV index.
    pub fn Esys_NV_Read(
        esys_context: *mut ESYS_CONTEXT,
        auth_handle: u32,
        nv_index: u32,
        shandle1: u32,
        shandle2: u32,
        shandle3: u32,
        size: u16,
        offset: u16,
        data: *mut *mut TPM2B_MAX_BUFFER,
    ) -> TSS2_RC;
}
