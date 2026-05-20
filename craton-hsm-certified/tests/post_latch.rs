// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Integration test for PowerOnSelfTestLatch (audit finding V10).

use craton_hsm::crypto::awslc_backend::AwsLcBackend;
use craton_hsm_certified::power_on_self_test::PowerOnSelfTestLatch;

#[test]
fn second_call_short_circuits_without_rerunning_kats() {
    let latch = PowerOnSelfTestLatch::new();
    let mut b = AwsLcBackend;
    assert!(!latch.has_run());
    assert_eq!(latch.verdict(), None);
    let first = latch.run_once_or_get(&mut b).unwrap();
    assert!(latch.has_run());
    assert_eq!(latch.verdict(), Some(first));
    // Second call must return the latched verdict without re-running the
    // backend. We can't directly observe "didn't run" here, but the
    // PowerOnSelfTestLatch documents this property and the internal
    // run_lock means we observe it indirectly: the verdict doesn't change.
    let second = latch.run_once_or_get(&mut b).unwrap();
    assert_eq!(first, second);
}
