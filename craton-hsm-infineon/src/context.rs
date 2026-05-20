// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! RAII wrapper around the ESYS context pointer.
//!
//! This module is only compiled when the `hw` feature is active.

#![allow(unsafe_code)]

use crate::error::{tss2_rc_to_error_and_record, TSS2_RC_SUCCESS};
use crate::ffi::{self, ESYS_CONTEXT, TSS2_RC};
use core::ptr;
use craton_hsm::error::{HsmError, HsmResult};

/// RAII wrapper around `*mut ESYS_CONTEXT`.
///
/// On [`Drop`], the context is finalized via [`ffi::Esys_Finalize`], which
/// releases all TPM transient objects and frees allocated memory.
pub struct EsapiContext {
    inner: *mut ESYS_CONTEXT,
    /// Marker to make `EsapiContext` `!Sync`.  The underlying ESYS_CONTEXT is
    /// not safe to share across threads via `&`-references; only moving it
    /// between threads (i.e. `Send`) is sound when guarded by `&mut self`.
    _not_sync: core::marker::PhantomData<std::cell::Cell<()>>,
}

impl EsapiContext {
    /// Initialize a new ESYS context using the default TCTI.
    ///
    /// # Errors
    ///
    /// Returns an [`HsmError`] if `Esys_Initialize` fails (e.g., no TPM
    /// device found, permission denied, or the TSS stack is misconfigured).
    pub fn new() -> HsmResult<Self> {
        let mut ctx: *mut ESYS_CONTEXT = ptr::null_mut();
        // SAFETY: `ctx` is a valid stack-allocated pointer-to-pointer. Passing
        // null for `tcti` is documented to select the default TCTI. Passing
        // null for `abi_version` is documented to use the compiled-in version.
        let rc: TSS2_RC = unsafe {
            ffi::Esys_Initialize(
                &mut ctx,
                ptr::null_mut(), // default TCTI
                ptr::null(),     // default ABI version
            )
        };

        if rc != TSS2_RC_SUCCESS {
            return Err(tss2_rc_to_error_and_record(rc));
        }

        if ctx.is_null() {
            return Err(HsmError::GeneralError);
        }

        Ok(Self {
            inner: ctx,
            _not_sync: core::marker::PhantomData,
        })
    }

    /// Return the raw context pointer for use in FFI calls.
    ///
    /// The pointer is valid for the lifetime of this `EsapiContext`.
    pub fn as_mut_ptr(&mut self) -> *mut ESYS_CONTEXT {
        self.inner
    }
}

impl Drop for EsapiContext {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: `self.inner` is non-null (checked above) and was
            // initialized by `Esys_Initialize`. `Esys_Finalize` is safe to
            // call exactly once per context; we set `self.inner` to null
            // afterwards to prevent double-free.
            unsafe {
                ffi::Esys_Finalize(&mut self.inner);
            }
            self.inner = ptr::null_mut();
        }
    }
}

// Safety: The ESYS context is not inherently thread-safe, but we require
// &mut self for all operations that mutate state, which is enforced by Rust's
// borrow checker. Sending the context across threads is fine as long as only
// one thread uses it at a time.
unsafe impl Send for EsapiContext {}
