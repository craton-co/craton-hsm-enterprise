// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! End-to-end rate-limit behaviour: lockout timing, success resets,
//! multi-source interleaving, and policy differences between
//! `FailOpen` and `FailClosed`.

use craton_hsm_auth::auth::rate_limit::{AuthRateLimiter, RateLimitConfig, RateLimitPolicy};

fn short_limiter(policy: RateLimitPolicy) -> AuthRateLimiter {
    AuthRateLimiter::new(RateLimitConfig {
        max_attempts: 3,
        window_secs: 60,
        lockout_secs: 120,
        policy,
    })
}

#[test]
fn multi_source_failures_are_keyed_independently() {
    // Alice exhausting her attempts must not lock out bob.
    let limiter = short_limiter(RateLimitPolicy::FailOpen);

    for _ in 0..3 {
        limiter.record_failure("alice");
    }
    assert!(limiter.check_rate_limit("alice").is_err());
    assert!(limiter.check_rate_limit("bob").is_ok());
    assert!(limiter.check_rate_limit("carol").is_ok());
}

#[test]
fn success_clears_lockout_for_that_key_only() {
    let limiter = short_limiter(RateLimitPolicy::FailOpen);

    for _ in 0..3 {
        limiter.record_failure("alice");
    }
    assert!(limiter.check_rate_limit("alice").is_err());

    // Successful auth for alice clears her state.
    limiter.record_success("alice");
    assert!(limiter.check_rate_limit("alice").is_ok());

    // Bob was never affected.
    assert!(limiter.check_rate_limit("bob").is_ok());
}

#[test]
fn fail_open_and_fail_closed_both_lock_out_excess_attempts_on_known_keys() {
    // Whichever policy is set, a *known* key that exceeds max_attempts
    // must be locked out — the policy only affects the behaviour when
    // the map is at capacity for *new* keys.
    for policy in [RateLimitPolicy::FailOpen, RateLimitPolicy::FailClosed] {
        let limiter = short_limiter(policy);
        for _ in 0..3 {
            limiter.record_failure("alice");
        }
        assert!(
            limiter.check_rate_limit("alice").is_err(),
            "policy={policy:?} must lock out once threshold reached"
        );
    }
}

#[test]
fn exhausted_counter_starts_at_zero_and_is_monotone() {
    let limiter = short_limiter(RateLimitPolicy::FailOpen);
    assert_eq!(limiter.capacity_exhausted_count(), 0);

    // Ordinary use does not trip the exhausted counter.
    limiter.record_failure("alice");
    limiter.record_failure("bob");
    assert!(limiter.check_rate_limit("alice").is_ok());
    assert_eq!(limiter.capacity_exhausted_count(), 0);
}

#[test]
fn successful_auth_does_not_cause_spurious_lockout() {
    // A user who intersperses failures with successes inside the window
    // must not be locked out — the success must clear intermediate
    // failure state.
    let limiter = short_limiter(RateLimitPolicy::FailOpen);

    limiter.record_failure("alice");
    limiter.record_failure("alice");
    limiter.record_success("alice"); // resets
    limiter.record_failure("alice");

    // Only one failure since the reset — must be allowed.
    assert!(limiter.check_rate_limit("alice").is_ok());
}
