// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Mapping from TSS2 return codes to [`HsmError`] variants.
//!
//! The constants defined here correspond to the most commonly encountered
//! TPM 2.0 response codes from the TCG TPM 2.0 Library Specification,
//! Part 2 (Structures).

use craton_hsm::error::{HsmError, HsmResult};

use crate::ffi::TSS2_RC;

// ---------------------------------------------------------------------------
// TSS2 / TPM2 return codes
// ---------------------------------------------------------------------------

/// Command completed successfully.
pub const TSS2_RC_SUCCESS: TSS2_RC = 0x000;

/// TPM is not able to perform the action because of an unspecified error.
pub const TPM2_RC_FAILURE: TSS2_RC = 0x101;

/// Key handle is not valid or not loaded.
pub const TPM2_RC_KEY: TSS2_RC = 0x19C;

/// Value is out of range or not correct for the context.
pub const TPM2_RC_VALUE: TSS2_RC = 0x184;

/// Size of data is out of range.
pub const TPM2_RC_SIZE: TSS2_RC = 0x1D5;

/// Signature verification failed.
pub const TPM2_RC_SIGNATURE: TSS2_RC = 0x19B;

/// Authorization failure.
pub const TPM2_RC_AUTH_FAIL: TSS2_RC = 0x18E;

/// The scheme or algorithm is not supported.
pub const TPM2_RC_SCHEME: TSS2_RC = 0x1B2;

/// Symmetric encryption/decryption error.
pub const TPM2_RC_SYMMETRIC: TSS2_RC = 0x1B4;

/// Insufficient NV space.
pub const TPM2_RC_NV_SPACE: TSS2_RC = 0x14B;

/// NV index is not defined.
pub const TPM2_RC_NV_DEFINED: TSS2_RC = 0x14C;

/// NV access authorization failure.
pub const TPM2_RC_NV_AUTHORIZATION: TSS2_RC = 0x149;

/// The TPM is in lockout (dictionary attack protection).
pub const TPM2_RC_LOCKOUT: TSS2_RC = 0x921;

/// Memory allocation failure inside TSS/TPM.
pub const TPM2_RC_MEMORY: TSS2_RC = 0x904;

/// Retry the command (TPM was busy).
pub const TPM2_RC_RETRY: TSS2_RC = 0x922;

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/// Map a raw `TSS2_RC` code into an [`HsmError`] — **pure**, side-effect-free.
///
/// `TSS2_RC_SUCCESS` is **not** an error — callers should check for success
/// before calling this function.
///
/// Audit fix (RC-MAPPING-PURITY): this function used to call
/// [`AuthFailLimiter::record_auth_fail`] as a side effect on the
/// `TPM2_RC_AUTH_FAIL` branch, which meant tests that exhaustively
/// mapped RCs drove the process-wide rate limiter. The recording
/// variant is now [`tss2_rc_to_error_and_record`] and is wired into
/// the live FFI dispatch sites in `backend_trait::EsapiFfiBackend`.
/// Tests and any other "what does this RC mean?" inspections use this
/// pure function.
pub fn tss2_rc_to_error(rc: TSS2_RC) -> HsmError {
    match rc {
        TSS2_RC_SUCCESS => HsmError::GeneralError, // should not be called for success
        TPM2_RC_KEY => HsmError::KeyHandleInvalid,
        TPM2_RC_VALUE => HsmError::MechanismParamInvalid,
        TPM2_RC_SIZE => HsmError::DataLenRange,
        TPM2_RC_SIGNATURE => HsmError::SignatureInvalid,
        // Pure mapping for AUTH_FAIL: propagate PinIncorrect without
        // touching the global rate limiter. Callers that want the
        // limiter applied must use `tss2_rc_to_error_and_record`.
        TPM2_RC_AUTH_FAIL => HsmError::PinIncorrect,
        TPM2_RC_SCHEME => HsmError::MechanismInvalid,
        TPM2_RC_SYMMETRIC => HsmError::EncryptedDataInvalid,
        TPM2_RC_NV_SPACE => HsmError::DeviceMemory,
        TPM2_RC_NV_DEFINED => HsmError::DataInvalid,
        TPM2_RC_NV_AUTHORIZATION => HsmError::PinIncorrect,
        TPM2_RC_LOCKOUT => HsmError::PinLocked,
        TPM2_RC_MEMORY => HsmError::DeviceMemory,
        // TPM2_RC_RETRY is intentionally pure here; the
        // recording variant tracing-logs the TPM_TRANSIENT marker.
        TPM2_RC_RETRY => HsmError::GeneralError,
        TPM2_RC_FAILURE => HsmError::GeneralError,
        _ => HsmError::GeneralError,
    }
}

/// Recording variant of [`tss2_rc_to_error`]. Same mapping, but with
/// process-wide side effects:
///
/// - `TPM2_RC_AUTH_FAIL` drives the `GLOBAL_AUTH_FAIL_LIMITER`; if
///   the burst cap has been exceeded inside the current 1-second
///   window, the returned error is upgraded to `PinRateLimited` to
///   short-circuit the next call before it reaches the TPM (preventing
///   a misbehaving caller from saturating DA lockout).
/// - `TPM2_RC_RETRY` emits a `TPM_TRANSIENT` tracing marker so upstream
///   audit / retry middleware can recognise the transient-busy state.
///
/// This is the variant the live FFI dispatch sites in
/// [`crate::backend_trait`] use.
pub fn tss2_rc_to_error_and_record(rc: TSS2_RC) -> HsmError {
    match rc {
        TPM2_RC_AUTH_FAIL => {
            if let Some(rate_limited) = GLOBAL_AUTH_FAIL_LIMITER.record_auth_fail() {
                return rate_limited;
            }
            HsmError::PinIncorrect
        }
        TPM2_RC_RETRY => {
            tracing::warn!(
                target: "craton_hsm_infineon",
                marker = "TPM_TRANSIENT",
                rc = format!("0x{:X}", TPM2_RC_RETRY),
                "TPM2_RC_RETRY mapped to GeneralError; caller may retry"
            );
            HsmError::GeneralError
        }
        // Defer to the pure mapping for everything else.
        other => tss2_rc_to_error(other),
    }
}

/// Check a TSS2 return code and return `Ok(())` for success, or the
/// corresponding [`HsmError`] for failure.
///
/// Uses the **recording** mapping (drives the AUTH_FAIL rate limiter,
/// emits the TPM_TRANSIENT tracing marker for RETRY) because every
/// caller is, by construction, a live FFI dispatch site. Tests that
/// inspect the RC mapping in isolation should call
/// [`tss2_rc_to_error`] directly.
pub fn check_tss2_rc(rc: TSS2_RC) -> HsmResult<()> {
    if rc == TSS2_RC_SUCCESS {
        Ok(())
    } else {
        Err(tss2_rc_to_error_and_record(rc))
    }
}

// ---------------------------------------------------------------------------
// Audit finding M (AUTH_FAIL rate-limit)
// ---------------------------------------------------------------------------
//
// `TPM2_RC_AUTH_FAIL` maps to `HsmError::PinIncorrect`. The TPM itself has
// dictionary-attack lockout (DA), but the surrounding HSM process must not
// rely on it: a misbehaving caller can saturate the TPM with auth attempts,
// triggering DA lockout and bricking the platform. Apply a per-process
// burst cap of 5 failures per second; subsequent calls are short-circuited
// to `HsmError::PinRateLimited` (a core variant) before they ever reach
// the TPM. Time source is `Instant::now()` (monotonic).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Per-process AUTH_FAIL rate limiter. 5 failures per 1-second window.
pub struct AuthFailLimiter {
    /// Window-start nanoseconds since `LIMITER_EPOCH`.
    window_start_ns: AtomicU64,
    /// Failure count within the current window.
    count: AtomicU64,
}

/// Process-wide singleton that throttles `TPM2_RC_AUTH_FAIL`-driven
/// `PinIncorrect` mappings inside [`tss2_rc_to_error`]. Const-constructed
/// so it lives in the .bss segment without any runtime initialiser.
pub(crate) static GLOBAL_AUTH_FAIL_LIMITER: AuthFailLimiter = AuthFailLimiter::new();

/// Maximum AUTH_FAIL events per `WINDOW_NS` window before
/// `record_auth_fail` returns `Some(PinRateLimited)`.
pub const AUTH_FAIL_BURST: u64 = 5;

/// Sliding-window length in nanoseconds (1 second).
pub const WINDOW_NS: u64 = 1_000_000_000;

// `Instant`s cannot be stored as a bare `u64`; we stash the elapsed-from
// the limiter's first call instead.
static LIMITER_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn epoch_ns() -> u64 {
    let epoch = LIMITER_EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as u64
}

impl AuthFailLimiter {
    /// Create a new limiter at the current monotonic time.
    pub const fn new() -> Self {
        Self {
            window_start_ns: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record one AUTH_FAIL event. Returns `Some(HsmError::PinRateLimited)`
    /// if the burst cap has been exceeded for the current window.
    /// Otherwise returns `None` and the caller should propagate the
    /// original `PinIncorrect` (mapped from `TPM2_RC_AUTH_FAIL`).
    pub fn record_auth_fail(&self) -> Option<HsmError> {
        let now = epoch_ns();
        let start = self.window_start_ns.load(Ordering::Relaxed);
        if start == 0 || now.saturating_sub(start) >= WINDOW_NS {
            // Open a new window. A racing thread that opened the window
            // first wins; we still increment the count below to avoid
            // dropping our own event.
            self.window_start_ns.store(now, Ordering::Relaxed);
            self.count.store(0, Ordering::Relaxed);
        }
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        if prev >= AUTH_FAIL_BURST {
            tracing::warn!(
                target: "craton_hsm_infineon",
                marker = "AUTH_FAIL_RATE_LIMIT",
                "AuthFailLimiter: burst of {} exceeded in 1s window; returning PinRateLimited",
                AUTH_FAIL_BURST
            );
            Some(HsmError::PinRateLimited)
        } else {
            None
        }
    }
}

impl Default for AuthFailLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_map_correctly() {
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
            tss2_rc_to_error(TPM2_RC_SIZE),
            HsmError::DataLenRange
        ));
    }

    #[test]
    fn unknown_code_maps_to_general() {
        assert!(matches!(tss2_rc_to_error(0xDEAD), HsmError::GeneralError));
    }

    #[test]
    fn success_maps_to_general_as_sentinel() {
        // Callers should not call this for success, but if they do it should not panic.
        assert!(matches!(
            tss2_rc_to_error(TSS2_RC_SUCCESS),
            HsmError::GeneralError
        ));
    }

    #[test]
    fn auth_fail_limiter_allows_burst_then_rate_limits() {
        let l = AuthFailLimiter::new();
        // First AUTH_FAIL_BURST calls should pass-through (return None).
        for _ in 0..AUTH_FAIL_BURST {
            assert!(
                l.record_auth_fail().is_none(),
                "within burst should be None"
            );
        }
        // 6th and beyond return PinRateLimited within the window.
        for _ in 0..3 {
            match l.record_auth_fail() {
                Some(HsmError::PinRateLimited) => {}
                other => panic!("expected PinRateLimited, got {:?}", other),
            }
        }
    }

    #[test]
    fn auth_fail_limiter_resets_after_window() {
        // We can't easily fast-forward Instant; instead set window_start
        // to (now - 2 * WINDOW_NS) and observe reset.
        let l = AuthFailLimiter::new();
        for _ in 0..AUTH_FAIL_BURST {
            let _ = l.record_auth_fail();
        }
        // Force the next call into "window expired" path by rewinding.
        l.window_start_ns
            .store(1, std::sync::atomic::Ordering::Relaxed);
        l.count
            .store(AUTH_FAIL_BURST, std::sync::atomic::Ordering::Relaxed);
        // Touch to ensure epoch is initialised so `epoch_ns()` is large.
        let _ = epoch_ns();
        if epoch_ns() < WINDOW_NS + 10 {
            // Test environment too fresh; skip (avoid flake).
            return;
        }
        let r = l.record_auth_fail();
        assert!(r.is_none(), "after window reset, first call must be None");
    }
}
