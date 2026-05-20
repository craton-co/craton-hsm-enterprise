// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Integration test for firmware rollback rejection (audit finding V5).
//!
//! Exercises the legacy `Option<u32>` API (`verify_signed_binary_with_policy`)
//! to keep regression coverage on the deprecated shim. New tests should
//! use `verify_signed_binary_with_rollback_policy` with the explicit
//! `RollbackPolicy` enum.
#![allow(deprecated)]

use craton_hsm_certified::binary_sign::{
    sign_and_embed, verify_signed_binary, verify_signed_binary_with_policy,
    verify_signed_binary_with_rollback_policy, RollbackPolicy,
};
use craton_hsm_certified::error::CertError;

const KEY: &[u8] = b"32-byte-long-test-hmac-key!-----";
const BINARY: &[u8] = b"ELF content, version 2 build";

#[test]
fn rollback_rejected_when_metadata_below_min_version() {
    // Sign with module_version = "1.2.3"
    let env = sign_and_embed(BINARY, KEY, "1.2.3", "ts", "g", "k").unwrap();
    // Policy requires at least version 2 -> must be rejected.
    let err = verify_signed_binary_with_policy(&env, KEY, Some(2)).unwrap_err();
    assert!(
        matches!(err, CertError::BadEnvelope(msg) if msg.contains("rollback")),
        "expected rollback rejection, got {err:?}"
    );
}

#[test]
fn rollback_accepted_when_metadata_equals_or_exceeds_min_version() {
    let env = sign_and_embed(BINARY, KEY, "3.0.0", "ts", "g", "k").unwrap();
    verify_signed_binary_with_policy(&env, KEY, Some(2)).unwrap();
    verify_signed_binary_with_policy(&env, KEY, Some(3)).unwrap();
}

#[test]
fn none_policy_is_backwards_compatible() {
    let env = sign_and_embed(BINARY, KEY, "0.9.0", "ts", "g", "k").unwrap();
    // None means no policy — must accept (bw compat).
    verify_signed_binary_with_policy(&env, KEY, None).unwrap();
    // And the plain wrapper still works.
    verify_signed_binary(&env, KEY).unwrap();
}

#[test]
fn non_numeric_version_rejected_when_policy_set() {
    let env = sign_and_embed(BINARY, KEY, "alpha-release", "ts", "g", "k").unwrap();
    let err = verify_signed_binary_with_policy(&env, KEY, Some(1)).unwrap_err();
    assert!(matches!(err, CertError::BadEnvelope(_)));
}

#[test]
fn explicit_rollback_policy_enum_rejects_older() {
    let env = sign_and_embed(BINARY, KEY, "1.2.3", "ts", "g", "k").unwrap();
    let err = verify_signed_binary_with_rollback_policy(&env, KEY, RollbackPolicy::AtLeast(2))
        .unwrap_err();
    assert!(matches!(err, CertError::BadEnvelope(msg) if msg.contains("rollback")));
}

#[test]
fn explicit_rollback_policy_any_version_accepts() {
    let env = sign_and_embed(BINARY, KEY, "0.9.0", "ts", "g", "k").unwrap();
    verify_signed_binary_with_rollback_policy(&env, KEY, RollbackPolicy::AnyVersion).unwrap();
}
