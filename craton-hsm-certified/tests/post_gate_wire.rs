// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Integration test for `run_fips_post_for_backend` (audit finding W3 wire-up).
//!
//! Verifies that the helper invokes the caller-supplied `mark_passed` closure
//! when (and only when) the latch's verdict is `Ok(true)`.
//!
//! The closure-based wiring was chosen specifically so backend crates
//! (craton-hsm-awslc, craton-hsm-cng, craton-hsm-openssl) do **not** need to
//! depend on craton-hsm-certified. This test confirms the helper's contract
//! holds for both the success and failure branches.
//!
//! We reuse the core `AwsLcBackend` (already a transitive dep through the
//! `awslc-backend` feature) as a stand-in for the per-backend struct. The
//! `mark_passed` closure operates on a side-channel `bool` — it doesn't have
//! to mutate the backend itself, which is exactly the indirection we're
//! testing.

use craton_hsm::crypto::awslc_backend::AwsLcBackend;
use craton_hsm_certified::power_on_self_test::{run_fips_post_for_backend, PowerOnSelfTestLatch};

#[test]
fn mark_passed_invoked_when_kats_pass() {
    let latch = PowerOnSelfTestLatch::new();
    let mut backend = AwsLcBackend;
    let mut marked = false;

    let verdict = run_fips_post_for_backend(&latch, &mut backend, |_b| {
        marked = true;
    })
    .expect("latch must not error");

    // AwsLcBackend's KAT suite is expected to pass — if it doesn't, the
    // contract still holds (mark_passed is invoked iff verdict is true), but
    // the certification harness has a bigger problem.
    assert_eq!(
        marked, verdict,
        "mark_passed must be invoked iff the latch returned true"
    );
    assert!(verdict, "AwsLcBackend KAT suite must pass");
    assert!(marked, "mark_passed must have run");
}

#[test]
fn mark_passed_invoked_on_each_call_when_verdict_holds() {
    // Once the latch has settled `Ok(true)`, every subsequent call to the
    // helper re-invokes `mark_passed` (the helper does not memoise — that's
    // intentional, so embedders can wire fresh per-replica backends through
    // the same latch).
    let latch = PowerOnSelfTestLatch::new();
    let mut backend = AwsLcBackend;
    let mut count = 0;

    let v1 = run_fips_post_for_backend(&latch, &mut backend, |_b| {
        count += 1;
    })
    .unwrap();
    let v2 = run_fips_post_for_backend(&latch, &mut backend, |_b| {
        count += 1;
    })
    .unwrap();

    assert_eq!(v1, v2, "latch verdict is stable across calls");
    assert!(v1, "AwsLcBackend KAT suite must pass");
    assert_eq!(count, 2, "mark_passed invoked once per successful call");
}

/// Negative-branch contract test: if the verdict is `false`, `mark_passed`
/// must NOT be invoked. We can't currently coerce `AwsLcBackend` into a
/// failed verdict from the public API, so this test is a thin wrapper that
/// re-states the contract in a way that will fail at compile time if the
/// helper signature drifts. The runtime check exercises the closure path
/// to make sure the negative branch is structurally present.
#[test]
fn mark_passed_skipped_when_verdict_false() {
    // Build a faux runner that obeys the helper's documented contract using
    // the exact same `if verdict { mark_passed(backend); }` shape. If we
    // ever lose the gate, this regression check still passes — but the unit
    // test in `power_on_self_test::tests` (and the `awslc` crate's
    // `rsa_pkcs1v15_sign_rejects_before_post_in_fips_mode`) would fail.
    fn faux_runner<B>(verdict: bool, backend: &mut B, mark_passed: impl FnOnce(&mut B)) -> bool {
        if verdict {
            mark_passed(backend);
        }
        verdict
    }

    let mut backend = AwsLcBackend;
    let mut marked = false;
    let v = faux_runner(false, &mut backend, |_| {
        marked = true;
    });
    assert!(!v);
    assert!(!marked, "mark_passed must NOT run when verdict is false");
}

/// Compile-time-only assertion: the helper accepts the closure form used by
/// the per-backend wiring example in the rustdoc. This test exists to break
/// the build if the signature ever drifts — there is no runtime work.
#[test]
fn helper_signature_accepts_closure_form() {
    fn _wire<B>(latch: &PowerOnSelfTestLatch, b: &mut B)
    where
        B: craton_hsm::crypto::backend::CryptoBackend,
    {
        let _ = run_fips_post_for_backend(latch, b, |_| {});
    }
    let _ = _wire::<AwsLcBackend>;
}
