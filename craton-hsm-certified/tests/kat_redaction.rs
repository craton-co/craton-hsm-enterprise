// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Audit finding V4: verify KAT details fields do not leak intermediate hex.

use craton_hsm::crypto::awslc_backend::AwsLcBackend;
use craton_hsm_certified::cmvp::TestResult;
use craton_hsm_certified::test_harness::{
    run_digest_kats, run_ecdsa_signing_kats, run_hmac_kats, run_rsa_signing_kats,
    run_symmetric_kats,
};

fn assert_no_long_hex_run(results: &[TestResult]) {
    for r in results {
        let mut run = 0usize;
        let mut max_run = 0usize;
        for c in r.details.chars() {
            if c.is_ascii_hexdigit() {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 0;
            }
        }
        assert!(
            max_run < 8,
            "details leak hex ({} chars): test {:?}, details {:?}",
            max_run,
            r.test_name,
            r.details
        );
    }
}

#[test]
fn digest_kat_details_are_redacted() {
    let b = AwsLcBackend;
    assert_no_long_hex_run(&run_digest_kats(&b));
}

#[test]
fn symmetric_kat_details_are_redacted() {
    let b = AwsLcBackend;
    assert_no_long_hex_run(&run_symmetric_kats(&b));
}

#[test]
fn hmac_kat_details_are_redacted() {
    let b = AwsLcBackend;
    assert_no_long_hex_run(&run_hmac_kats(&b));
}

#[test]
fn rsa_kat_details_are_redacted() {
    let b = AwsLcBackend;
    assert_no_long_hex_run(&run_rsa_signing_kats(&b));
}

#[test]
fn ecdsa_kat_details_are_redacted() {
    let b = AwsLcBackend;
    assert_no_long_hex_run(&run_ecdsa_signing_kats(&b));
}
