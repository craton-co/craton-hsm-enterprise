// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Run the full FIPS 140-3 Known-Answer Test (KAT) suite against the
//! AWS-LC backend and print a one-line verdict per test.
//!
//! This is the same harness `craton-hsm-certified` exposes for CMVP
//! evidence collection, condensed into a runnable program suitable for
//! local sanity checks.
//!
//! Run with:
//!
//! ```text
//! cargo run --example run_kats -p craton-hsm-certified
//! ```
//!
//! The example uses [`run_all_kats_with_default_config`], which applies
//! the default approved-mode policy as a preflight before exercising the
//! digest, symmetric, HMAC, RSA, and ECDSA KATs. A non-zero exit code is
//! returned if any KAT failed.

use craton_hsm::crypto::awslc_backend::AwsLcBackend;
use craton_hsm_certified::test_harness::{run_all_kats_with_default_config, verify_all_pass};

fn main() {
    // AwsLcBackend is a unit struct in this workspace; the FIPS power-on
    // self-test is driven by the certified harness itself, so no
    // explicit POST wiring is needed here.
    let backend = AwsLcBackend;

    let results = run_all_kats_with_default_config(&backend);

    let mut failures = 0usize;
    for r in &results {
        let tag = if r.passed { "PASS" } else { "FAIL" };
        if !r.passed {
            failures += 1;
        }
        println!("[{tag}] {} — {}", r.test_name, r.details);
    }

    let all_passed = verify_all_pass(&results);
    println!(
        "\nVerdict: {} ({} tests, {} failures)",
        if all_passed { "PASS" } else { "FAIL" },
        results.len(),
        failures,
    );

    if !all_passed {
        std::process::exit(1);
    }
}
