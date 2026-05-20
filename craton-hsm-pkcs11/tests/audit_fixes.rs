// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Regression tests for `craton-hsm-pkcs11` audit findings.
//!
//! Most cryptoki paths require a real PKCS#11 token to exercise.
//! Where a finding can be verified without a live token (counter
//! globalization, IV-reuse rejection, error mapping), the test runs
//! at compile-time level. Tests that need a live token are
//! `#[ignore]` with a comment naming the audit ID.

use craton_hsm::error::HsmError;
use craton_hsm_pkcs11::pool::{PoolCtrCounters, PoolGcmCounters};

/// HIGH — `PoolGcmCounters::check_and_increment` enforces a single
/// global limit per fingerprint, regardless of which session
/// charged the operation. This was the audit's primary concern: the
/// counter must NOT reset across sessions or a 2^32 budget per
/// session multiplies into pool_size × 2^32 globally.
#[test]
fn gcm_counter_is_global_per_fingerprint() {
    let counters = PoolGcmCounters::new();
    let fp = [0xAAu8; 32];

    // Two "sessions" sharing the same counter map — calls must
    // accumulate, not reset.
    assert_eq!(counters.check_and_increment(&fp, 5).unwrap(), 1);
    assert_eq!(counters.check_and_increment(&fp, 5).unwrap(), 2);
    assert_eq!(counters.check_and_increment(&fp, 5).unwrap(), 3);
    assert_eq!(counters.check_and_increment(&fp, 5).unwrap(), 4);
    assert_eq!(counters.check_and_increment(&fp, 5).unwrap(), 5);

    // 6th call would exceed the limit — must fail and poison.
    let r = counters.check_and_increment(&fp, 5);
    assert!(matches!(r, Err(HsmError::KeyFunctionNotPermitted)));

    // Subsequent calls remain refused (the poison sentinel
    // u64::MAX persists).
    let r2 = counters.check_and_increment(&fp, 5);
    assert!(matches!(r2, Err(HsmError::KeyFunctionNotPermitted)));
}

/// HIGH — distinct fingerprints have independent counters.
#[test]
fn gcm_counter_separates_distinct_fingerprints() {
    let counters = PoolGcmCounters::new();
    let fp_a = [0x01u8; 32];
    let fp_b = [0x02u8; 32];

    counters.check_and_increment(&fp_a, 100).unwrap();
    counters.check_and_increment(&fp_a, 100).unwrap();
    counters.check_and_increment(&fp_b, 100).unwrap();

    assert_eq!(counters.get(&fp_a), 2);
    assert_eq!(counters.get(&fp_b), 1);
}

/// LOW — `PoolCtrCounters::check_and_record` rejects (key, iv)
/// reuse. AES-CTR confidentiality breaks instantly on key/IV
/// reuse, so this is fail-closed.
#[test]
fn ctr_counter_rejects_iv_reuse() {
    let counters = PoolCtrCounters::new();
    let fp = [0x77u8; 32];
    let iv = [0xAAu8; 16];

    // First registration succeeds.
    assert!(counters.check_and_record(&fp, &iv).is_ok());

    // Re-using the same (fp, iv) pair must be rejected.
    let r = counters.check_and_record(&fp, &iv);
    assert!(matches!(r, Err(HsmError::MechanismParamInvalid)));
}

/// LOW — distinct IVs under the same key are independent.
#[test]
fn ctr_counter_allows_distinct_ivs() {
    let counters = PoolCtrCounters::new();
    let fp = [0x88u8; 32];
    let iv1 = [0x01u8; 16];
    let iv2 = [0x02u8; 16];

    assert!(counters.check_and_record(&fp, &iv1).is_ok());
    assert!(counters.check_and_record(&fp, &iv2).is_ok());
    assert_eq!(counters.len(), 2);
}

/// LOW — fresh counter map is empty.
#[test]
fn fresh_counter_maps_are_empty() {
    let gcm = PoolGcmCounters::new();
    let ctr = PoolCtrCounters::new();
    assert_eq!(gcm.get(&[0u8; 32]), 0);
    assert!(ctr.is_empty());
}

/// MEDIUM — PIN must never appear in `Debug` formatting of a
/// configuration-derived error.  Verified by source review of the
/// `pool::open_and_login` path (`AuthPin`/`Zeroizing<String>` keep
/// PIN out of any tracing/format args).
#[test]
#[ignore = "audit M-PIN: PIN never logged; verified by source review of open_and_login"]
fn pin_never_appears_in_error_formatting_placeholder() {}

/// MEDIUM — `priv_value.is_empty()` distinguishes
/// attribute-MISSING from attribute-EMPTY.  Requires a live
/// cryptoki token to drive the get_attributes path.
#[test]
#[ignore = "audit M-priv-empty: requires live token; source-level fix verified"]
fn attribute_missing_vs_empty_placeholder() {}

/// MEDIUM — `is_session_level` covers CKR_DEVICE_ERROR /
/// CKR_DEVICE_REMOVED / CKR_FUNCTION_FAILED retry-on-session-recreate.
/// The mapping itself is private; covered by inline tests in
/// `pool.rs` (`is_session_level_*`).
#[test]
#[ignore = "audit M-retry: covered by pool.rs inline tests"]
fn session_level_retry_covers_device_error_placeholder() {}

/// PKCS11-CTR — AES-CTR is not exposed by cryptoki 0.7. The
/// passthrough returns `FunctionNotSupported` so callers fall
/// back to a software impl.  Verified by source review.
#[test]
#[ignore = "audit PKCS11-CTR: AES-CTR returns FunctionNotSupported; verified by source review"]
fn ctr_returns_function_not_supported_placeholder() {}
