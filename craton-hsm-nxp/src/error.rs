// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Mapping from NXP HSE status codes to `HsmError`.

use craton_hsm::error::{HsmError, HsmResult};

/// Raw status code returned by the HSE firmware.
pub type HseStatus = u32;

// Common HSE status codes from the NXP HSE SDK.
/// HSE success sentinel (no error). See module docs.
pub const HSE_OK: HseStatus = 0x0000_0000;
/// HSE status: key not found in catalog. See module docs.
pub const HSE_ERR_KEY_NOT_FOUND: HseStatus = 0x0000_0001;
/// HSE status: key handle invalid for the requested operation.
pub const HSE_ERR_KEY_INVALID: HseStatus = 0x0000_0002;
/// HSE status: invalid mechanism parameter (length, mode, etc.).
pub const HSE_ERR_INVALID_PARAM: HseStatus = 0x0000_0003;
/// HSE status: mechanism not supported by the firmware build.
pub const HSE_ERR_NOT_SUPPORTED: HseStatus = 0x0000_0004;
/// HSE status: device-side memory pressure.
pub const HSE_ERR_MEMORY: HseStatus = 0x0000_0005;
/// HSE status: signature verification failed (signature was invalid).
pub const HSE_ERR_VERIFY_FAILED: HseStatus = 0x0000_0006;
/// HSE status: firmware temporarily busy; retry.
pub const HSE_ERR_BUSY: HseStatus = 0x0000_0007;
/// HSE status: MU request timed out.
pub const HSE_ERR_TIMEOUT: HseStatus = 0x0000_0008;
/// HSE status: input/output length out of range.
pub const HSE_ERR_DATA_LEN: HseStatus = 0x0000_0009;
/// Status returned by the non-`hw` FFI stubs (audit finding H7). Distinct
/// from [`HSE_ERR_NOT_SUPPORTED`] because "not supported by firmware" and
/// "this binary does not contain a firmware bridge at all" are operationally
/// different failure modes. Maps to [`HsmError::FunctionNotSupported`] via
/// [`hse_status_to_error`].
pub const HSE_ERR_NOT_IMPLEMENTED: HseStatus = 0x0000_000A;
/// HSE catch-all general error.
pub const HSE_ERR_GENERAL: HseStatus = 0x0000_FFFF;

/// Tracing marker emitted when an `HseKeyRef` blob fails to decode (audit V6).
pub const HSE_MARKER_KEYREF_PARSE: &str = "HSE_KEYREF_PARSE";
/// Tracing marker for sigs whose firmware-reported length is below the
/// per-algorithm minimum (audit V1). Indicates either a buggy firmware or
/// an active under-report attempt; the operation is rejected.
pub const HSE_MARKER_SIG_TOO_SHORT: &str = "HSE_SIG_TOO_SHORT";
/// Tracing marker emitted when AES-GCM is invoked without a 12-byte IV
/// (audit V4); the operation is rejected with `MechanismParamInvalid`.
pub const HSE_MARKER_GCM_IV_LEN: &str = "HSE_GCM_IV_LEN";
/// Tracing marker emitted when AES-GCM firmware output is shorter than
/// the expected IV+ciphertext+tag layout (audit V4).
pub const HSE_MARKER_GCM_OUT_LEN: &str = "HSE_GCM_OUT_LEN";
/// Tracing marker emitted when AES-GCM is asked to mix AAD before that
/// path is wired (audit V4).
pub const HSE_MARKER_AAD_UNSUPPORTED: &str = "HSE_AAD_UNSUPPORTED";
/// Tracing marker emitted when the per-process key-handle counter
/// exhausts its disjoint range (audit V5/V8).
pub const HSE_MARKER_HANDLE_OVERFLOW: &str = "HSE_HANDLE_OVERFLOW";
/// Tracing marker emitted when the per-process key-handle counter
/// exceeds 80% of its disjoint range. Operators should rotate the
/// process before exhaustion (~4.6h at 1k/s import throughput). Slot
/// recycling is out of scope for this release.
pub const HSE_MARKER_HANDLE_PRESSURE: &str = "HSE_HANDLE_PRESSURE";
/// Tracing marker emitted when the HSE FFI reports an output length
/// larger than the supplied buffer capacity. This is a firmware/FFI
/// invariant breach and the operation is rejected.
pub const HSE_MARKER_INVARIANT_FFI_LEN: &str = "HSE_INVARIANT_FFI_LEN";
/// Tracing marker logged once at backend init to remind operators that
/// AES-GCM nonce uniqueness is delegated to the HSE firmware — the
/// dispatching layer does not maintain its own per-key counter.
pub const HSE_MARKER_GCM_NONCE_DELEGATED: &str = "HSE_GCM_NONCE_DELEGATED";

/// Convert an `HseStatus` code into an `HsmError`.
///
/// `HSE_OK` is **not** an error — callers should check for success before
/// calling this function.
pub fn hse_status_to_error(status: HseStatus) -> HsmError {
    match status {
        HSE_OK => {
            #[cfg(debug_assertions)]
            {
                panic!("hse_rc_to_error called with HSE_OK");
            }
            #[cfg(not(debug_assertions))]
            {
                HsmError::GeneralError
            }
        }
        HSE_ERR_KEY_NOT_FOUND => HsmError::KeyHandleInvalid,
        HSE_ERR_KEY_INVALID => HsmError::KeyHandleInvalid,
        HSE_ERR_INVALID_PARAM => HsmError::MechanismParamInvalid,
        HSE_ERR_NOT_SUPPORTED => HsmError::FunctionNotSupported,
        HSE_ERR_NOT_IMPLEMENTED => HsmError::FunctionNotSupported,
        HSE_ERR_MEMORY => HsmError::DeviceMemory,
        HSE_ERR_VERIFY_FAILED => HsmError::SignatureInvalid,
        HSE_ERR_BUSY => HsmError::GeneralError,
        HSE_ERR_TIMEOUT => HsmError::GeneralError,
        HSE_ERR_DATA_LEN => HsmError::DataLenRange,
        _ => HsmError::GeneralError,
    }
}

/// Check an HSE status code and return `Ok(())` for success, or the
/// corresponding [`HsmError`] for failure.
pub fn check_hse_status(status: HseStatus) -> HsmResult<()> {
    if status == HSE_OK {
        Ok(())
    } else {
        Err(hse_status_to_error(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_status_codes_map_correctly() {
        assert!(matches!(
            hse_status_to_error(HSE_ERR_KEY_NOT_FOUND),
            HsmError::KeyHandleInvalid
        ));
        assert!(matches!(
            hse_status_to_error(HSE_ERR_KEY_INVALID),
            HsmError::KeyHandleInvalid
        ));
        assert!(matches!(
            hse_status_to_error(HSE_ERR_INVALID_PARAM),
            HsmError::MechanismParamInvalid
        ));
        assert!(matches!(
            hse_status_to_error(HSE_ERR_NOT_SUPPORTED),
            HsmError::FunctionNotSupported
        ));
        assert!(matches!(
            hse_status_to_error(HSE_ERR_MEMORY),
            HsmError::DeviceMemory
        ));
        assert!(matches!(
            hse_status_to_error(HSE_ERR_VERIFY_FAILED),
            HsmError::SignatureInvalid
        ));
    }

    #[test]
    fn unknown_status_maps_to_general_error() {
        assert!(matches!(
            hse_status_to_error(0xDEAD_BEEF),
            HsmError::GeneralError
        ));
        assert!(matches!(
            hse_status_to_error(0x0000_9999),
            HsmError::GeneralError
        ));
    }

    /// In release builds, HSE_OK maps to GeneralError as a sentinel. In debug,
    /// it panics — callers must check success first.
    #[cfg(not(debug_assertions))]
    #[test]
    fn success_returns_general_as_sentinel() {
        assert!(matches!(
            hse_status_to_error(HSE_OK),
            HsmError::GeneralError
        ));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "hse_rc_to_error called with HSE_OK")]
    fn success_panics_in_debug() {
        let _ = hse_status_to_error(HSE_OK);
    }
}
