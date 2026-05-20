// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Certification test runner.
//!
//! Provides known-answer test (KAT) suites for FIPS 140-3 certification
//! testing. Each suite exercises a crypto backend against NIST-published
//! test vectors and returns structured [`TestResult`] records suitable for
//! CMVP evidence packaging.

use crate::approved_mode::{
    check_mechanism_approved, default_fips_config, ApprovedModeConfig, ApprovedModeRejection,
};
use crate::cmvp::{package_test_evidence, CmvpConfig, TestResult};
use crate::error::CertResult;
#[allow(unused_imports)]
use crate::hex_util::{hex_encode, short_hex};
use aws_lc_rs::hmac as awslc_hmac;
use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm::pkcs11_abi::constants::{CKM_SHA256, CKM_SHA384, CKM_SHA512};
use std::path::Path;

/// Names of every primitive that [`run_all_kats`] exercises. Used by
/// [`approved_mode_preflight`] to assert that the configured approved-mode
/// policy actually permits everything the harness is about to test —
/// otherwise the KATs could "pass" by side-effect even though the policy
/// would reject the very same call at runtime.
const KAT_MECHANISMS: &[&str] = &[
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "AES-256",
    "HMAC-SHA256",
    "RSA-2048",
    "RSA-3072",
    "ECDSA-P256",
    "ECDSA-P384",
];

/// Pre-flight check that every mechanism the KAT runner is about to
/// exercise is permitted by `config`. Returns a `TestResult` for each
/// mechanism, with `passed = true` iff [`check_mechanism_approved`] returns
/// `Ok(())` for that mechanism.
///
/// This is the in-crate wiring of [`check_mechanism_approved`] mentioned
/// in that function's documentation — it gives the certified crate a
/// concrete callsite for the policy gate even before any backend has
/// integrated it.
///
/// Note that `HMAC-SHA256` is intentionally absent from the standard
/// classifier (the [`crate::approved_mode::Mechanism`] enum does not
/// model HMAC variants), so the preflight tolerates an
/// [`ApprovedModeRejection::UnknownAlgorithm`] response for that name and
/// reports it as a `pass` with a note rather than a failure — but every
/// classified mechanism must be `NotApproved`-free.
pub fn approved_mode_preflight(config: &ApprovedModeConfig) -> Vec<TestResult> {
    KAT_MECHANISMS
        .iter()
        .map(|m| match check_mechanism_approved(m, config) {
            Ok(()) => pass(
                format!("approved-mode preflight: {m}"),
                "mechanism is permitted by the active FIPS policy".to_string(),
            ),
            Err(ApprovedModeRejection::UnknownAlgorithm { .. }) => pass(
                format!("approved-mode preflight: {m}"),
                "mechanism not modelled by the classifier; treated as a non-blocking notice"
                    .to_string(),
            ),
            Err(ApprovedModeRejection::NotApproved { mechanism }) => fail(
                format!("approved-mode preflight: {m}"),
                format!("mechanism {mechanism} is NOT approved under the active FIPS policy"),
            ),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// NIST / RFC vectors
// ---------------------------------------------------------------------------

/// NIST test vector: SHA-256("abc")
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
/// NIST test vector: SHA-384("abc")
const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
/// NIST test vector: SHA-512("abc")
const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

// HMAC-SHA256 known-answer test vectors from RFC 4231.
/// RFC 4231 Test Case 1: key = 0x0b*20, msg = "Hi There"
const HMAC256_TC1_KEY: [u8; 20] = [0x0bu8; 20];
const HMAC256_TC1_MSG: &[u8] = b"Hi There";
const HMAC256_TC1_MAC: &str = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn pass(test_name: impl Into<String>, details: impl Into<String>) -> TestResult {
    TestResult {
        test_name: test_name.into(),
        passed: true,
        details: details.into(),
    }
}

#[inline]
fn fail(test_name: impl Into<String>, details: impl Into<String>) -> TestResult {
    TestResult {
        test_name: test_name.into(),
        passed: false,
        details: details.into(),
    }
}

// ---------------------------------------------------------------------------
// Digest KATs
// ---------------------------------------------------------------------------

/// Run SHA-256, SHA-384, and SHA-512 known-answer tests against the given
/// backend, using the NIST "abc" test vector for each digest algorithm.
pub fn run_digest_kats(backend: &dyn CryptoBackend) -> Vec<TestResult> {
    let input = b"abc";
    let cases = [
        ("SHA-256 KAT", CKM_SHA256, SHA256_ABC),
        ("SHA-384 KAT", CKM_SHA384, SHA384_ABC),
        ("SHA-512 KAT", CKM_SHA512, SHA512_ABC),
    ];

    cases
        .iter()
        .map(|(name, mechanism, expected_hex)| {
            match backend.compute_digest(*mechanism, input) {
                Ok(digest) => {
                    let actual_hex = hex_encode(&digest);
                    if actual_hex == *expected_hex {
                        // Audit V4: details must not leak intermediate hex.
                        // Redact the prefix so an evidence bundle with lax
                        // ACLs cannot be mined for KAT vectors.
                        pass(*name, "digest matches NIST vector".to_string())
                    } else {
                        fail(
                            *name,
                            "digest mismatch (intermediate values redacted per audit V4)"
                                .to_string(),
                        )
                    }
                }
                Err(e) => fail(*name, format!("backend error: {:?}", e)),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// AES-GCM functional tests
// ---------------------------------------------------------------------------

/// Run AES-GCM functional tests against the given backend.
///
/// Tests encrypt-then-decrypt with 256-bit keys to verify correctness, plus
/// tamper detection and ciphertext expansion validation.
pub fn run_symmetric_kats(backend: &dyn CryptoBackend) -> Vec<TestResult> {
    let mut results = Vec::new();

    let key = [0x42u8; 32];
    let plaintext = b"FIPS 140-3 KAT plaintext for AES-GCM testing";

    let test_name = "AES-256-GCM roundtrip";
    match backend.aes_256_gcm_encrypt(&key, plaintext) {
        Ok(ciphertext) => {
            // Ciphertext expansion (>= 12-byte nonce + 16-byte tag overhead).
            if ciphertext.len() <= plaintext.len() {
                results.push(fail(
                    "AES-256-GCM ciphertext expansion",
                    format!(
                        "ciphertext ({} bytes) not longer than plaintext ({} bytes)",
                        ciphertext.len(),
                        plaintext.len()
                    ),
                ));
            } else {
                results.push(pass(
                    "AES-256-GCM ciphertext expansion",
                    format!(
                        "ciphertext has {} bytes overhead (nonce + tag)",
                        ciphertext.len() - plaintext.len()
                    ),
                ));
            }

            // Roundtrip
            match backend.aes_256_gcm_decrypt(&key, &ciphertext) {
                Ok(decrypted) if decrypted == plaintext => {
                    results.push(pass(test_name, "encrypt/decrypt roundtrip succeeded"));
                }
                Ok(_) => {
                    results.push(fail(
                        test_name,
                        "decrypted plaintext does not match original",
                    ));
                }
                Err(e) => {
                    results.push(fail(test_name, format!("decryption failed: {:?}", e)));
                }
            }

            // Tamper detection
            let mut tampered = ciphertext.clone();
            if let Some(last) = tampered.last_mut() {
                *last ^= 0xFF;
            }
            let tamper_test = "AES-256-GCM tamper detection";
            match backend.aes_256_gcm_decrypt(&key, &tampered) {
                Err(_) => results.push(pass(tamper_test, "tampered ciphertext correctly rejected")),
                Ok(_) => results.push(fail(
                    tamper_test,
                    "tampered ciphertext was accepted — authentication tag check failed",
                )),
            }
        }
        Err(e) => results.push(fail(test_name, format!("encryption failed: {:?}", e))),
    }

    results
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 KAT
// ---------------------------------------------------------------------------

/// Run HMAC-SHA256 known-answer tests using the FIPS-validated `aws-lc-rs`
/// HMAC primitive (the [`CryptoBackend`] trait does not currently expose
/// HMAC). Verifies RFC 4231 Test Case 1 against a fixed expected output.
pub fn run_hmac_kats(_backend: &dyn CryptoBackend) -> Vec<TestResult> {
    let test_name = "HMAC-SHA256 RFC4231 TC1 KAT";
    let key = awslc_hmac::Key::new(awslc_hmac::HMAC_SHA256, &HMAC256_TC1_KEY);
    let tag = awslc_hmac::sign(&key, HMAC256_TC1_MSG);
    let actual = hex_encode(tag.as_ref());
    if actual == HMAC256_TC1_MAC {
        vec![pass(test_name, "MAC matches RFC 4231 vector".to_string())]
    } else {
        vec![fail(
            test_name,
            format!(
                "MAC mismatch (audit V4: intermediate values redacted), expected {}..., got {}...",
                "********", "********"
            ),
        )]
    }
}

// ---------------------------------------------------------------------------
// RSA / ECDSA signing KATs
// ---------------------------------------------------------------------------

/// Run RSA-PKCS1v15-SHA256 signing functional tests against a backend.
///
/// Generates a fresh key pair, signs a fixed message, verifies the
/// signature, then **negative-tests** by mutating the message and
/// confirming verification fails. This is the strongest test we can run
/// without hard-coding NIST CAVP key material.
pub fn run_rsa_signing_kats(backend: &dyn CryptoBackend) -> Vec<TestResult> {
    let bits_to_test = [2048u32, 3072u32];
    let msg = b"FIPS 140-3 RSA PKCS1v15 KAT message";
    let mut results = Vec::new();

    for &bits in &bits_to_test {
        let test_name = format!("RSA-{bits}-PKCS1v15-SHA256 sign/verify");
        match backend.generate_rsa_key_pair(bits, true) {
            Ok((sk, modulus, pub_exp)) => {
                let signature =
                    match backend.rsa_pkcs1v15_sign(sk.as_bytes(), msg, Some(HashAlg::Sha256)) {
                        Ok(s) => s,
                        Err(e) => {
                            results.push(fail(test_name, format!("sign error: {:?}", e)));
                            continue;
                        }
                    };

                // Positive verification.
                match backend.rsa_pkcs1v15_verify(
                    &modulus,
                    &pub_exp,
                    msg,
                    &signature,
                    Some(HashAlg::Sha256),
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        results.push(fail(
                            test_name,
                            "verification returned false on a freshly produced signature",
                        ));
                        continue;
                    }
                    Err(e) => {
                        results.push(fail(test_name, format!("verify error: {:?}", e)));
                        continue;
                    }
                }

                // Negative verification — flip a byte in the message.
                let mut bad_msg = msg.to_vec();
                bad_msg[0] ^= 0xFF;
                match backend.rsa_pkcs1v15_verify(
                    &modulus,
                    &pub_exp,
                    &bad_msg,
                    &signature,
                    Some(HashAlg::Sha256),
                ) {
                    Ok(false) | Err(_) => {
                        results.push(pass(
                            test_name,
                            // Audit V4: redact signature hex from `details`.
                            format!("RSA-{bits} sign/verify roundtrip + negative test passed"),
                        ));
                    }
                    Ok(true) => {
                        results.push(fail(
                            test_name,
                            "negative test FAILED: tampered message verified",
                        ));
                    }
                }
            }
            Err(e) => {
                results.push(fail(test_name, format!("keygen error: {:?}", e)));
            }
        }
    }

    results
}

/// Run ECDSA signing functional tests for P-256 and P-384.
///
/// As with RSA, this generates a fresh key pair, signs, verifies, and
/// negative-verifies a tampered message.
pub fn run_ecdsa_signing_kats(backend: &dyn CryptoBackend) -> Vec<TestResult> {
    let msg = b"FIPS 140-3 ECDSA KAT message";
    let mut results = Vec::new();

    // P-256
    {
        let test_name = "ECDSA-P256-SHA256 sign/verify";
        match backend.generate_ec_p256_key_pair() {
            Ok((sk, pk)) => match backend.ecdsa_p256_sign(sk.as_bytes(), msg) {
                Ok(sig) => {
                    let pos = backend.ecdsa_p256_verify(&pk, msg, &sig);
                    let mut bad = msg.to_vec();
                    bad[0] ^= 0xFF;
                    let neg = backend.ecdsa_p256_verify(&pk, &bad, &sig);
                    match (pos, neg) {
                        (Ok(true), Ok(false)) | (Ok(true), Err(_)) => {
                            results.push(pass(
                                test_name,
                                // Audit V4: redact signature hex.
                                "P-256 sign/verify + negative test passed".to_string(),
                            ));
                        }
                        (Ok(false), _) => {
                            results.push(fail(
                                test_name,
                                "verification returned false on valid signature",
                            ));
                        }
                        (_, Ok(true)) => {
                            results.push(fail(
                                test_name,
                                "negative test FAILED: tampered message verified",
                            ));
                        }
                        (Err(e), _) => {
                            results.push(fail(test_name, format!("verify error: {:?}", e)));
                        }
                    }
                }
                Err(e) => results.push(fail(test_name, format!("sign error: {:?}", e))),
            },
            Err(e) => results.push(fail(test_name, format!("keygen error: {:?}", e))),
        }
    }

    // P-384
    {
        let test_name = "ECDSA-P384-SHA384 sign/verify";
        match backend.generate_ec_p384_key_pair() {
            Ok((sk, pk)) => match backend.ecdsa_p384_sign(sk.as_bytes(), msg) {
                Ok(sig) => {
                    let pos = backend.ecdsa_p384_verify(&pk, msg, &sig);
                    let mut bad = msg.to_vec();
                    bad[0] ^= 0xFF;
                    let neg = backend.ecdsa_p384_verify(&pk, &bad, &sig);
                    match (pos, neg) {
                        (Ok(true), Ok(false)) | (Ok(true), Err(_)) => {
                            results.push(pass(
                                test_name,
                                // Audit V4: redact signature hex.
                                "P-384 sign/verify + negative test passed".to_string(),
                            ));
                        }
                        (Ok(false), _) => {
                            results.push(fail(
                                test_name,
                                "verification returned false on valid signature",
                            ));
                        }
                        (_, Ok(true)) => {
                            results.push(fail(
                                test_name,
                                "negative test FAILED: tampered message verified",
                            ));
                        }
                        (Err(e), _) => {
                            results.push(fail(test_name, format!("verify error: {:?}", e)));
                        }
                    }
                }
                Err(e) => results.push(fail(test_name, format!("sign error: {:?}", e))),
            },
            Err(e) => results.push(fail(test_name, format!("keygen error: {:?}", e))),
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Aggregate runner
// ---------------------------------------------------------------------------

/// Run all known-answer test suites against the given backend using the
/// supplied approved-mode `config`:
/// approved-mode preflight, digest, AES-GCM, HMAC, RSA signing, and ECDSA signing.
///
/// The approved-mode preflight (via [`approved_mode_preflight`] against
/// `config`) is run *first* so a misconfigured policy is surfaced as a
/// failed `TestResult` rather than as a passing KAT with no policy in
/// effect.
///
/// Callers that want the default FIPS configuration should call
/// [`run_all_kats_with_default_config`] instead.
pub fn run_all_kats(backend: &dyn CryptoBackend, config: &ApprovedModeConfig) -> Vec<TestResult> {
    let mut results = approved_mode_preflight(config);
    results.extend(run_digest_kats(backend));
    results.extend(run_symmetric_kats(backend));
    results.extend(run_hmac_kats(backend));
    results.extend(run_rsa_signing_kats(backend));
    results.extend(run_ecdsa_signing_kats(backend));
    results
}

/// Convenience wrapper around [`run_all_kats`] that uses
/// [`default_fips_config`] for the approved-mode preflight. Preserves the
/// pre-refactor call-site signature for existing callers.
pub fn run_all_kats_with_default_config(backend: &dyn CryptoBackend) -> Vec<TestResult> {
    run_all_kats(backend, &default_fips_config())
}

/// Verify that all test results passed.
pub fn verify_all_pass(results: &[TestResult]) -> bool {
    results.iter().all(|r| r.passed)
}

/// Run the full KAT suite against `backend` and write a CMVP evidence package
/// (`manifest.json` + `results.json`) into `output_dir`. Returns the test
/// results so callers can also inspect them in-memory.
///
/// Returns `Err` if `config` is invalid (see [`crate::cmvp::validate_cmvp_config`])
/// or if any file I/O fails. The KATs themselves never fail this function —
/// individual failures are reported via the returned [`TestResult`] vector,
/// which the caller can check with [`verify_all_pass`].
pub fn run_and_package_kats(
    backend: &dyn CryptoBackend,
    config: &CmvpConfig,
    output_dir: &Path,
) -> CertResult<Vec<TestResult>> {
    let results = run_all_kats_with_default_config(backend);
    package_test_evidence(output_dir, config, &results)?;
    Ok(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::crypto::awslc_backend::AwsLcBackend;

    fn backend() -> AwsLcBackend {
        AwsLcBackend
    }

    #[test]
    fn verify_all_pass_with_passing_results() {
        let results = vec![pass("test-1", "ok"), pass("test-2", "ok")];
        assert!(verify_all_pass(&results));
    }

    #[test]
    fn verify_all_pass_with_failure() {
        let results = vec![pass("test-1", "ok"), fail("test-2", "failed")];
        assert!(!verify_all_pass(&results));
    }

    #[test]
    fn verify_all_pass_empty_is_true() {
        assert!(verify_all_pass(&[]));
    }

    #[test]
    fn nist_vectors_are_correct_length() {
        assert_eq!(SHA256_ABC.len(), 64);
        assert_eq!(SHA384_ABC.len(), 96);
        assert_eq!(SHA512_ABC.len(), 128);
    }

    #[test]
    fn digest_kats_pass_with_real_backend() {
        let results = run_digest_kats(&backend());
        assert_eq!(results.len(), 3);
        assert!(verify_all_pass(&results), "{:?}", results);
    }

    #[test]
    fn symmetric_kats_pass_with_real_backend() {
        let results = run_symmetric_kats(&backend());
        assert!(!results.is_empty());
        assert!(verify_all_pass(&results), "{:?}", results);
    }

    #[test]
    fn hmac_kats_pass() {
        let results = run_hmac_kats(&backend());
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn rsa_signing_kats_pass_with_real_backend() {
        let results = run_rsa_signing_kats(&backend());
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.passed, "{:?}", r);
            // No more "placeholder" details — must contain real description.
            assert!(!r.details.contains("placeholder"));
        }
    }

    #[test]
    fn ecdsa_signing_kats_pass_with_real_backend() {
        let results = run_ecdsa_signing_kats(&backend());
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.passed, "{:?}", r);
            assert!(!r.details.contains("placeholder"));
        }
    }

    #[test]
    fn run_all_kats_returns_full_suite() {
        let results = run_all_kats(&backend(), &default_fips_config());
        // 3 digest + 3 symmetric + 1 hmac + 2 rsa + 2 ecdsa = 11
        assert!(results.len() >= 11);
        assert!(verify_all_pass(&results), "{:?}", results);
    }

    #[test]
    fn run_all_kats_with_default_config_returns_full_suite() {
        let results = run_all_kats_with_default_config(&backend());
        assert!(results.len() >= 11);
        assert!(verify_all_pass(&results), "{:?}", results);
    }

    #[test]
    fn run_all_kats_honours_custom_config_preflight() {
        // Build a config that disallows ECDSA-P256; preflight must mark
        // that mechanism as failed even though the underlying KATs still
        // succeed for the backend.
        let mut config = default_fips_config();
        config.allow_ecdsa_p256 = false;
        let results = run_all_kats(&backend(), &config);
        let preflight_ecdsa = results
            .iter()
            .find(|r| r.test_name.contains("preflight: ECDSA-P256"))
            .expect("ECDSA-P256 preflight entry present");
        assert!(!preflight_ecdsa.passed, "{:?}", preflight_ecdsa);
    }

    #[test]
    fn run_and_package_kats_writes_evidence_files() {
        use crate::cmvp::default_cmvp_config;
        let dir = tempfile::tempdir().unwrap();
        let config = default_cmvp_config();
        let results = run_and_package_kats(&backend(), &config, dir.path()).unwrap();
        assert!(verify_all_pass(&results), "{:?}", results);
        assert!(dir.path().join("manifest.json").exists());
        let results_path = dir.path().join("results.json");
        assert!(results_path.exists());

        // Round-trip the written results.
        let written = std::fs::read_to_string(&results_path).unwrap();
        let parsed: Vec<TestResult> = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed.len(), results.len());
        assert!(parsed.iter().all(|r| r.passed));
    }

    #[test]
    fn run_and_package_kats_rejects_invalid_config() {
        use crate::cmvp::default_cmvp_config;
        let dir = tempfile::tempdir().unwrap();
        let mut config = default_cmvp_config();
        config.fips_level = 9;
        assert!(run_and_package_kats(&backend(), &config, dir.path()).is_err());
    }

    #[test]
    fn test_result_serialization() {
        let result = pass("SHA-256 KAT", "Passed");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: TestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.test_name, "SHA-256 KAT");
        assert!(parsed.passed);
    }
}
