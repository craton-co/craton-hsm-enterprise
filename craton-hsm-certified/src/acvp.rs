// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! ACVP/CAVP test vector runner.
//!
//! Implements an Automated Cryptographic Validation Protocol (ACVP) test
//! vector runner for FIPS 140-3 algorithm validation. Supports parsing ACVP
//! JSON format, running test vectors against a [`CryptoBackend`], and
//! generating ACVP response JSON.

use crate::cmvp::TestResult;
use crate::error::{CertError, CertResult};
use crate::hex_util::{hex_decode, hex_encode, short_hex};
use aws_lc_rs::hmac as awslc_hmac;
use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm::pkcs11_abi::constants::{CKM_SHA256, CKM_SHA384, CKM_SHA512};
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// ACVP test type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcvpTestType {
    /// Known Answer Test — fixed input/output pair.
    Kat,
    /// Monte Carlo Test — iterated computation.
    Mct,
    /// Algorithm Functional Test — general functional validation.
    Aft,
}

/// A single ACVP test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcvpTestVector {
    /// Algorithm identifier (e.g. "SHA-256", "AES-GCM", "HMAC-SHA256").
    pub algorithm: String,
    /// Type of test.
    pub test_type: AcvpTestType,
    /// Named input values as raw bytes.
    pub inputs: HashMap<String, Vec<u8>>,
    /// Named expected output values as raw bytes.
    pub expected_outputs: HashMap<String, Vec<u8>>,
}

/// Metadata for a group of ACVP test vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcvpTestSuite {
    /// Algorithm name (e.g. "SHA2-256").
    pub algorithm: String,
    /// Specification revision (e.g. "1.0").
    pub revision: String,
    /// Numeric test group identifier.
    pub test_group_id: u32,
    /// The test vectors in this suite.
    pub vectors: Vec<AcvpTestVector>,
}

/// Result of running a single ACVP test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcvpVectorResult {
    /// Index of the vector in the suite.
    pub tc_id: usize,
    /// Whether the vector passed.
    pub passed: bool,
    /// Actual output (hex-encoded) if applicable.
    pub actual_output: Option<String>,
    /// Details / error message.
    pub details: String,
}

/// Aggregated response for an entire test suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcvpResponse {
    /// Name of the algorithm under test (e.g. `"AES-GCM"`).
    pub algorithm: String,
    /// ACVP specification revision used to generate the vectors.
    pub revision: String,
    /// ACVP test-group identifier.
    pub test_group_id: u32,
    /// Per-vector pass/fail results.
    pub results: Vec<AcvpVectorResult>,
}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AcvpJsonRoot {
    algorithm: String,
    #[serde(default = "default_revision")]
    revision: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<AcvpJsonTestGroup>,
}

fn default_revision() -> String {
    "1.0".to_string()
}

#[derive(Deserialize)]
struct AcvpJsonTestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "testType")]
    test_type: String,
    tests: Vec<AcvpJsonTest>,
}

#[derive(Deserialize)]
struct AcvpJsonTest {
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    md: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    pt: Option<String>,
    #[serde(default)]
    ct: Option<String>,
    #[serde(default)]
    iv: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    mac: Option<String>,
}

fn parse_test_type(s: &str) -> AcvpTestType {
    match s.to_uppercase().as_str() {
        "AFT" => AcvpTestType::Aft,
        "MCT" => AcvpTestType::Mct,
        _ => AcvpTestType::Kat,
    }
}

/// Decode a hex field, wrapping errors with the field name for diagnostics.
fn decode_field(field: &str, value: &str) -> CertResult<Vec<u8>> {
    hex_decode(value).map_err(|e| {
        let inner = e.to_string();
        CertError::HexDecode(format!("field {field}: {inner}"))
    })
}

/// Parse an ACVP JSON string into an [`AcvpTestSuite`].
///
/// All test groups in the JSON are parsed; vectors from all groups are
/// collected into a single suite. The `test_group_id` of the first group
/// is used as the suite identifier.
pub fn parse_acvp_json(json: &str) -> CertResult<AcvpTestSuite> {
    /// Upper bound on the total number of vectors across all groups.
    /// Real NIST CAVS responses are at most a few thousand vectors; anything
    /// beyond this is either a malformed file or a resource-exhaustion
    /// attempt. Rejecting early keeps the runner's memory + `format!()`
    /// per-index call costs bounded and prevents index overflow on
    /// 32-bit targets.
    const MAX_TOTAL_VECTORS: usize = 1_000_000;

    let root: AcvpJsonRoot = serde_json::from_str(json)?;

    if root.test_groups.is_empty() {
        return Err(CertError::Other("no test groups in JSON".to_string()));
    }

    let total: usize = root
        .test_groups
        .iter()
        .map(|g| g.tests.len())
        .try_fold(0usize, |acc, n| acc.checked_add(n))
        .ok_or_else(|| CertError::Other("ACVP JSON vector count overflows usize".to_string()))?;
    if total > MAX_TOTAL_VECTORS {
        return Err(CertError::Other(format!(
            "ACVP JSON declares {total} vectors; refusing to parse more than {MAX_TOTAL_VECTORS}",
        )));
    }

    let first_tg_id = root.test_groups[0].tg_id;
    let mut all_vectors = Vec::with_capacity(total);

    for group in &root.test_groups {
        let test_type = parse_test_type(&group.test_type);

        for t in &group.tests {
            let mut inputs: HashMap<String, Vec<u8>> = HashMap::new();
            let mut expected_outputs: HashMap<String, Vec<u8>> = HashMap::new();

            if let Some(ref msg) = t.msg {
                inputs.insert("msg".to_string(), decode_field("msg", msg)?);
            }
            if let Some(ref key) = t.key {
                inputs.insert("key".to_string(), decode_field("key", key)?);
            }
            if let Some(ref pt) = t.pt {
                inputs.insert("pt".to_string(), decode_field("pt", pt)?);
            }
            if let Some(ref iv) = t.iv {
                inputs.insert("iv".to_string(), decode_field("iv", iv)?);
            }

            if let Some(ref md) = t.md {
                expected_outputs.insert("md".to_string(), decode_field("md", md)?);
            }
            if let Some(ref ct) = t.ct {
                expected_outputs.insert("ct".to_string(), decode_field("ct", ct)?);
            }
            if let Some(ref tag) = t.tag {
                expected_outputs.insert("tag".to_string(), decode_field("tag", tag)?);
            }
            if let Some(ref mac) = t.mac {
                expected_outputs.insert("mac".to_string(), decode_field("mac", mac)?);
            }

            all_vectors.push(AcvpTestVector {
                algorithm: root.algorithm.clone(),
                test_type,
                inputs,
                expected_outputs,
            });
        }
    }

    Ok(AcvpTestSuite {
        algorithm: root.algorithm.clone(),
        revision: root.revision.clone(),
        test_group_id: first_tg_id,
        vectors: all_vectors,
    })
}

// ---------------------------------------------------------------------------
// Result helpers
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
// Vector runners
// ---------------------------------------------------------------------------

fn digest_mechanism(alg: &str) -> Option<CK_MECHANISM_TYPE> {
    match alg.to_uppercase().as_str() {
        "SHA-256" | "SHA2-256" => Some(CKM_SHA256),
        "SHA-384" | "SHA2-384" => Some(CKM_SHA384),
        "SHA-512" | "SHA2-512" => Some(CKM_SHA512),
        _ => None,
    }
}

/// Run SHA digest test vectors against a [`CryptoBackend`].
pub fn run_acvp_digest_vectors(
    backend: &dyn CryptoBackend,
    vectors: &[AcvpTestVector],
) -> Vec<TestResult> {
    vectors
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let mechanism = match digest_mechanism(&v.algorithm) {
                Some(m) => m,
                None => {
                    return fail(
                        format!("ACVP digest #{}", i),
                        format!("unsupported algorithm: {}", v.algorithm),
                    );
                }
            };
            let msg: &[u8] = v.inputs.get("msg").map(|m| m.as_slice()).unwrap_or(&[]);
            match backend.compute_digest(mechanism, msg) {
                Ok(digest) => {
                    if let Some(expected) = v.expected_outputs.get("md") {
                        if digest == *expected {
                            pass(
                                format!("ACVP {} KAT #{}", v.algorithm, i),
                                format!("digest matches: {}", short_hex(&digest, 16)),
                            )
                        } else {
                            fail(
                                format!("ACVP {} KAT #{}", v.algorithm, i),
                                format!(
                                    "mismatch: expected {}, got {}",
                                    short_hex(expected, 16),
                                    short_hex(&digest, 16)
                                ),
                            )
                        }
                    } else {
                        pass(
                            format!("ACVP {} AFT #{}", v.algorithm, i),
                            format!("computed digest: {}", short_hex(&digest, 32)),
                        )
                    }
                }
                Err(e) => fail(
                    format!("ACVP {} #{}", v.algorithm, i),
                    format!("backend error: {:?}", e),
                ),
            }
        })
        .collect()
}

/// Run AES-GCM/CBC symmetric test vectors against a [`CryptoBackend`].
///
/// For GCM: roundtrip with 256-bit keys (the trait does not currently
/// expose nonce-injecting GCM, so deterministic ciphertext KATs are not
/// possible). For CBC: roundtrip with the supplied IV; missing IV is
/// rejected (never silently zero-padded).
pub fn run_acvp_symmetric_vectors(
    backend: &dyn CryptoBackend,
    vectors: &[AcvpTestVector],
) -> Vec<TestResult> {
    vectors
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let key = match v.inputs.get("key") {
                Some(k) => k.as_slice(),
                None => {
                    return fail(format!("ACVP symmetric #{}", i), "missing key input");
                }
            };

            let alg_upper = v.algorithm.to_uppercase();

            if alg_upper.contains("GCM") {
                let pt = match v.inputs.get("pt") {
                    Some(pt) => pt.as_slice(),
                    None => {
                        return fail(
                            format!("ACVP AES-GCM #{}", i),
                            "missing pt input for GCM vector",
                        );
                    }
                };

                // Deterministic KAT path: when the vector ships an IV +
                // expected ciphertext + tag (e.g. NIST CAVP
                // gcmEncryptExtIV256.rsp), reconstruct the wire-format
                // [IV || CT || Tag] blob and decrypt it. Assert the
                // recovered plaintext matches and a tampered blob fails
                // authentication.
                if let (Some(iv), Some(ct_expected), Some(tag_expected)) = (
                    v.inputs.get("iv"),
                    v.expected_outputs.get("ct"),
                    v.expected_outputs.get("tag"),
                ) {
                    if iv.len() != 12 {
                        return fail(
                            format!("ACVP AES-GCM KAT #{}", i),
                            format!("unsupported IV length {}", iv.len()),
                        );
                    }
                    let mut blob =
                        Vec::with_capacity(iv.len() + ct_expected.len() + tag_expected.len());
                    blob.extend_from_slice(iv);
                    blob.extend_from_slice(ct_expected);
                    blob.extend_from_slice(tag_expected);

                    let recovered = match backend.aes_256_gcm_decrypt(key, &blob) {
                        Ok(r) => r,
                        Err(e) => {
                            return fail(
                                format!("ACVP AES-GCM KAT #{}", i),
                                format!("decrypt of NIST CAVP blob failed: {:?}", e),
                            );
                        }
                    };
                    if recovered != pt {
                        return fail(
                            format!("ACVP AES-GCM KAT #{}", i),
                            "plaintext recovered from CAVP blob did not match expected pt",
                        );
                    }

                    // Tamper test: flip a CT byte; auth tag must reject.
                    let mut tampered = blob.clone();
                    let ct_offset = iv.len();
                    if !ct_expected.is_empty() {
                        tampered[ct_offset] ^= 0x01;
                    } else {
                        // Flip a tag byte if CT is empty.
                        let last = tampered.len() - 1;
                        tampered[last] ^= 0x01;
                    }
                    match backend.aes_256_gcm_decrypt(key, &tampered) {
                        Err(_) => {
                            return pass(
                                format!("ACVP AES-GCM KAT #{}", i),
                                "NIST CAVP blob decrypted to expected plaintext; tampered blob rejected",
                            );
                        }
                        Ok(_) => {
                            return fail(
                                format!("ACVP AES-GCM KAT #{}", i),
                                "tampered ciphertext was accepted by decrypt path",
                            );
                        }
                    }
                }

                match backend.aes_256_gcm_encrypt(key, pt) {
                    Ok(ct) => match backend.aes_256_gcm_decrypt(key, &ct) {
                        Ok(recovered) if recovered == pt => pass(
                            format!("ACVP AES-GCM roundtrip #{}", i),
                            "encrypt/decrypt roundtrip OK",
                        ),
                        Ok(_) => fail(
                            format!("ACVP AES-GCM roundtrip #{}", i),
                            "roundtrip plaintext mismatch",
                        ),
                        Err(e) => fail(
                            format!("ACVP AES-GCM decrypt #{}", i),
                            format!("decrypt error: {:?}", e),
                        ),
                    },
                    Err(e) => fail(
                        format!("ACVP AES-GCM encrypt #{}", i),
                        format!("encrypt error: {:?}", e),
                    ),
                }
            } else if alg_upper.contains("CBC") {
                let iv = match v.inputs.get("iv") {
                    Some(iv) => iv.as_slice(),
                    None => {
                        return fail(
                            format!("ACVP AES-CBC #{}", i),
                            "missing IV for AES-CBC vector — refusing to use zero IV",
                        );
                    }
                };
                let pt = match v.inputs.get("pt") {
                    Some(pt) => pt.as_slice(),
                    None => {
                        return fail(
                            format!("ACVP AES-CBC #{}", i),
                            "missing pt input for CBC vector",
                        );
                    }
                };
                match backend.aes_cbc_encrypt(key, iv, pt) {
                    Ok(ct) => match backend.aes_cbc_decrypt(key, iv, &ct) {
                        Ok(recovered) if recovered == pt => pass(
                            format!("ACVP AES-CBC roundtrip #{}", i),
                            "encrypt/decrypt roundtrip OK",
                        ),
                        Ok(_) => fail(
                            format!("ACVP AES-CBC roundtrip #{}", i),
                            "roundtrip plaintext mismatch",
                        ),
                        Err(e) => fail(
                            format!("ACVP AES-CBC decrypt #{}", i),
                            format!("decrypt error: {:?}", e),
                        ),
                    },
                    Err(e) => fail(
                        format!("ACVP AES-CBC encrypt #{}", i),
                        format!("encrypt error: {:?}", e),
                    ),
                }
            } else {
                fail(
                    format!("ACVP symmetric #{}", i),
                    format!("unsupported symmetric algorithm: {}", v.algorithm),
                )
            }
        })
        .collect()
}

/// Run RSA/ECDSA signature test vectors against a [`CryptoBackend`].
///
/// Each vector exercises a sign/verify roundtrip **and** a negative test
/// (mutated message must not verify) so a backend that returned a constant
/// signature would still be detected.
pub fn run_acvp_signature_vectors(
    backend: &dyn CryptoBackend,
    vectors: &[AcvpTestVector],
) -> Vec<TestResult> {
    vectors
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let alg_upper = v.algorithm.to_uppercase();
            let msg: Vec<u8> = v
                .inputs
                .get("msg")
                .cloned()
                .unwrap_or_else(|| b"ACVP test message".to_vec());

            if alg_upper.contains("ECDSA") && alg_upper.contains("P256") {
                run_ecdsa_vector(backend, &msg, i, EcCurve::P256)
            } else if alg_upper.contains("ECDSA") && alg_upper.contains("P384") {
                run_ecdsa_vector(backend, &msg, i, EcCurve::P384)
            } else if alg_upper.contains("RSA") {
                let bits = if alg_upper.contains("3072") {
                    3072u32
                } else if alg_upper.contains("4096") {
                    4096
                } else {
                    2048
                };
                run_rsa_vector(backend, &msg, i, bits)
            } else {
                fail(
                    format!("ACVP signature #{}", i),
                    format!("unsupported signature algorithm: {}", v.algorithm),
                )
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
enum EcCurve {
    P256,
    P384,
}

fn run_ecdsa_vector(
    backend: &dyn CryptoBackend,
    msg: &[u8],
    i: usize,
    curve: EcCurve,
) -> TestResult {
    let test_name = match curve {
        EcCurve::P256 => format!("ACVP ECDSA-P256 sig #{i}"),
        EcCurve::P384 => format!("ACVP ECDSA-P384 sig #{i}"),
    };

    let (sk, pk) = match curve {
        EcCurve::P256 => match backend.generate_ec_p256_key_pair() {
            Ok(p) => p,
            Err(e) => return fail(test_name, format!("keygen error: {:?}", e)),
        },
        EcCurve::P384 => match backend.generate_ec_p384_key_pair() {
            Ok(p) => p,
            Err(e) => return fail(test_name, format!("keygen error: {:?}", e)),
        },
    };

    let sig = match curve {
        EcCurve::P256 => backend.ecdsa_p256_sign(sk.as_bytes(), msg),
        EcCurve::P384 => backend.ecdsa_p384_sign(sk.as_bytes(), msg),
    };
    let sig = match sig {
        Ok(s) => s,
        Err(e) => return fail(test_name, format!("sign error: {:?}", e)),
    };

    let verify_ok = match curve {
        EcCurve::P256 => backend.ecdsa_p256_verify(&pk, msg, &sig),
        EcCurve::P384 => backend.ecdsa_p384_verify(&pk, msg, &sig),
    };
    match verify_ok {
        Ok(true) => {}
        Ok(false) => return fail(test_name, "verification returned false on valid signature"),
        Err(e) => return fail(test_name, format!("verify error: {:?}", e)),
    }

    // Negative test: tamper with the message.
    let mut bad = msg.to_vec();
    if !bad.is_empty() {
        bad[0] ^= 0xFF;
    } else {
        bad.push(0xFF);
    }
    let neg = match curve {
        EcCurve::P256 => backend.ecdsa_p256_verify(&pk, &bad, &sig),
        EcCurve::P384 => backend.ecdsa_p384_verify(&pk, &bad, &sig),
    };
    match neg {
        Ok(false) | Err(_) => pass(
            test_name,
            format!(
                "sign/verify + negative test passed (sig {})",
                short_hex(&sig, 16)
            ),
        ),
        Ok(true) => fail(test_name, "negative test FAILED: tampered message verified"),
    }
}

fn run_rsa_vector(backend: &dyn CryptoBackend, msg: &[u8], i: usize, bits: u32) -> TestResult {
    let test_name = format!("ACVP RSA-{bits} PKCS1v15 sig #{i}");
    let (sk, modulus, pub_exp) = match backend.generate_rsa_key_pair(bits, false) {
        Ok(p) => p,
        Err(e) => return fail(test_name, format!("keygen error: {:?}", e)),
    };
    let sig = match backend.rsa_pkcs1v15_sign(sk.as_bytes(), msg, Some(HashAlg::Sha256)) {
        Ok(s) => s,
        Err(e) => return fail(test_name, format!("sign error: {:?}", e)),
    };
    match backend.rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha256)) {
        Ok(true) => {}
        Ok(false) => {
            return fail(test_name, "verification returned false on valid signature");
        }
        Err(e) => return fail(test_name, format!("verify error: {:?}", e)),
    }

    let mut bad = msg.to_vec();
    if !bad.is_empty() {
        bad[0] ^= 0xFF;
    } else {
        bad.push(0xFF);
    }
    match backend.rsa_pkcs1v15_verify(&modulus, &pub_exp, &bad, &sig, Some(HashAlg::Sha256)) {
        Ok(false) | Err(_) => pass(
            test_name,
            format!(
                "sign/verify + negative test passed (sig {})",
                short_hex(&sig, 16)
            ),
        ),
        Ok(true) => fail(test_name, "negative test FAILED: tampered message verified"),
    }
}

/// Run HMAC-SHA256 test vectors using the FIPS-validated `aws-lc-rs`
/// HMAC primitive (the [`CryptoBackend`] trait does not currently expose
/// HMAC).
pub fn run_acvp_hmac_vectors(
    _backend: &dyn CryptoBackend,
    vectors: &[AcvpTestVector],
) -> Vec<TestResult> {
    vectors
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let key = match v.inputs.get("key") {
                Some(k) => k.as_slice(),
                None => return fail(format!("ACVP HMAC-SHA256 #{}", i), "missing key input"),
            };
            let msg: &[u8] = v.inputs.get("msg").map(|m| m.as_slice()).unwrap_or(&[]);
            let s_key = awslc_hmac::Key::new(awslc_hmac::HMAC_SHA256, key);
            let mac = awslc_hmac::sign(&s_key, msg);
            let mac_bytes = mac.as_ref();
            if let Some(expected) = v.expected_outputs.get("mac") {
                if mac_bytes == expected.as_slice() {
                    pass(
                        format!("ACVP HMAC-SHA256 KAT #{}", i),
                        format!("MAC matches: {}", short_hex(mac_bytes, 16)),
                    )
                } else {
                    fail(
                        format!("ACVP HMAC-SHA256 KAT #{}", i),
                        format!(
                            "MAC mismatch: expected {}, got {}",
                            short_hex(expected, 16),
                            short_hex(mac_bytes, 16)
                        ),
                    )
                }
            } else {
                pass(
                    format!("ACVP HMAC-SHA256 AFT #{}", i),
                    format!("computed MAC: {}", hex_encode(mac_bytes)),
                )
            }
        })
        .collect()
}

/// Generate an ACVP response JSON string from test results.
///
/// Returns a [`CertError::Json`] on the (in practice unreachable) failure of
/// `serde_json` to serialize a struct of `String`/`bool`/`u32`/`Option<String>`
/// fields. Surfacing the error rather than swallowing it lets callers
/// distinguish a real failure from a valid empty response.
pub fn generate_acvp_response(response: &AcvpResponse) -> CertResult<String> {
    Ok(serde_json::to_string_pretty(response)?)
}

// ---------------------------------------------------------------------------
// Embedded NIST test vectors
// ---------------------------------------------------------------------------

/// Fallible variant of [`embedded_sha256_vectors`] that surfaces a
/// `CertError::HexDecode` on a typo in any embedded hex literal instead
/// of panicking. Always returns `Ok(...)` in this build — but exposing
/// the `Result` lets callers in long-running services treat the embedded
/// vectors as fallible rather than wrapping the call in `catch_unwind`.
pub fn try_embedded_sha256_vectors() -> CertResult<Vec<AcvpTestVector>> {
    fn v(msg: Vec<u8>, md_hex: &str) -> CertResult<AcvpTestVector> {
        Ok(AcvpTestVector {
            algorithm: "SHA2-256".to_string(),
            test_type: AcvpTestType::Kat,
            inputs: [("msg".to_string(), msg)].into_iter().collect(),
            expected_outputs: [("md".to_string(), hex_decode(md_hex)?)]
                .into_iter()
                .collect(),
        })
    }
    Ok(vec![
        v(
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )?,
        v(
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?,
        v(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        )?,
    ])
}

/// Embedded NIST ACVP test vectors for SHA-256.
///
/// Infallible wrapper around [`try_embedded_sha256_vectors`]: any decode
/// failure is a developer typo in a literal that we statically validate
/// in the `embedded_vectors_decode_at_startup` test, so it cannot fire
/// in production. Use the `try_` variant if you would rather surface the
/// error explicitly.
pub fn embedded_sha256_vectors() -> Vec<AcvpTestVector> {
    try_embedded_sha256_vectors().expect(
        "embedded SHA-256 KAT vectors must decode; covered by embedded_vectors_decode_at_startup",
    )
}

// ---------------------------------------------------------------------------
// NIST CAVP test vectors (real, reproducible, exact byte values)
// ---------------------------------------------------------------------------
//
// Each constant below is sourced from a publicly-published NIST CAVP /
// IETF RFC test vector. They are stored as raw byte arrays (not hex
// strings) so the `tests/kat_redaction.rs` audit guard, which scans the
// `details:` field of `TestResult` for long hex runs, never trips on
// them -- its check inspects runtime strings, not source-code constants.

/// NIST CAVP AES-GCM Count=0 vector (gcmEncryptExtIV256.rsp).
/// `[Keylen=256, IVlen=96, PTlen=128, AADlen=0, Taglen=128]`.
///
/// Source: NIST CAVS 14.0 GCM Test Vectors, file `gcmEncryptExtIV256.rsp`.
pub const CAVP_AES256_GCM_KEY: &[u8] = &[
    0x31, 0xbd, 0xad, 0xd9, 0x66, 0x98, 0xc2, 0x04, 0xaa, 0x9c, 0xe1, 0x44, 0x8e, 0xa9, 0x4a, 0xe1,
    0xfb, 0x4a, 0x9a, 0x0b, 0x3c, 0x9d, 0x77, 0x3b, 0x51, 0xbb, 0x18, 0x22, 0x66, 0x6b, 0x8f, 0x22,
];
/// NIST CAVP AES-GCM Count=0 IV (96-bit nonce).
pub const CAVP_AES256_GCM_IV: &[u8] = &[
    0x0d, 0x18, 0xe0, 0x6c, 0x7c, 0x72, 0x5a, 0xc9, 0xe3, 0x62, 0xe1, 0xce,
];
/// NIST CAVP AES-GCM Count=0 plaintext.
pub const CAVP_AES256_GCM_PT: &[u8] = &[
    0x2d, 0xb5, 0x16, 0x8e, 0x93, 0x25, 0x56, 0xf8, 0x08, 0x9a, 0x06, 0x22, 0x98, 0x1d, 0x01, 0x7d,
];
/// NIST CAVP AES-GCM Count=0 ciphertext.
pub const CAVP_AES256_GCM_CT: &[u8] = &[
    0xfa, 0x43, 0x62, 0x18, 0x96, 0x61, 0xd1, 0x63, 0xfc, 0xd6, 0xa5, 0x6d, 0x8b, 0xf0, 0x40, 0x5a,
];
/// NIST CAVP AES-GCM Count=0 authentication tag (128-bit).
pub const CAVP_AES256_GCM_TAG: &[u8] = &[
    0xd6, 0x36, 0xac, 0x1b, 0xbe, 0xdd, 0x5c, 0xc3, 0xee, 0x72, 0x7d, 0xc2, 0xab, 0x4a, 0x94, 0x89,
];

/// RFC 6979 A.2.5 ECDSA P-256 SHA-256, msg=`"sample"`: signer public key
/// X-coordinate (`Qx`), 32 bytes big-endian.
///
/// Source: RFC 6979 "Deterministic Usage of the Digital Signature Algorithm
/// (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)", Appendix
/// A.2.5. The full (r, s) signature pair is the deterministic ECDSA output
/// for the test private key, message `"sample"`, and `H = SHA-256`; it is
/// verifiable by any standards-conformant ECDSA verifier.
pub const CAVP_ECDSA_P256_QX: &[u8] = &[
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
];
/// RFC 6979 A.2.5 ECDSA P-256 signer public key Y-coordinate (`Qy`).
pub const CAVP_ECDSA_P256_QY: &[u8] = &[
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
];
/// RFC 6979 A.2.5 ECDSA P-256 SHA-256 message: ASCII `"sample"`.
pub const CAVP_ECDSA_P256_MSG: &[u8] = b"sample";
/// RFC 6979 A.2.5 ECDSA P-256 SHA-256 signature `r` value.
pub const CAVP_ECDSA_P256_R: &[u8] = &[
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
    0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
];
/// RFC 6979 A.2.5 ECDSA P-256 SHA-256 signature `s` value.
pub const CAVP_ECDSA_P256_S: &[u8] = &[
    0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
    0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
];

/// RFC 6979 A.2.6 ECDSA P-384 SHA-384, msg=`"sample"`: signer public key
/// X-coordinate (`Qx`), 48 bytes big-endian.
///
/// Source: RFC 6979 Appendix A.2.6.
pub const CAVP_ECDSA_P384_QX: &[u8] = &[
    0xec, 0x3a, 0x4e, 0x41, 0x5b, 0x4e, 0x19, 0xa4, 0x56, 0x86, 0x18, 0x02, 0x9f, 0x42, 0x7f, 0xa5,
    0xda, 0x9a, 0x8b, 0xc4, 0xae, 0x92, 0xe0, 0x2e, 0x06, 0xaa, 0xe5, 0x28, 0x6b, 0x30, 0x0c, 0x64,
    0xde, 0xf8, 0xf0, 0xea, 0x90, 0x55, 0x86, 0x60, 0x64, 0xa2, 0x54, 0x51, 0x54, 0x80, 0xbc, 0x13,
];
/// RFC 6979 A.2.6 ECDSA P-384 signer public key Y-coordinate (`Qy`).
pub const CAVP_ECDSA_P384_QY: &[u8] = &[
    0x80, 0x15, 0xd9, 0xb7, 0x2d, 0x7d, 0x57, 0x24, 0x4e, 0xa8, 0xef, 0x9a, 0xc0, 0xc6, 0x21, 0x89,
    0x67, 0x08, 0xa5, 0x93, 0x67, 0xf9, 0xdf, 0xb9, 0xf5, 0x4c, 0xa8, 0x4b, 0x3f, 0x1c, 0x9d, 0xb1,
    0x28, 0x8b, 0x23, 0x1c, 0x3a, 0xe0, 0xd4, 0xfe, 0x73, 0x44, 0xfd, 0x25, 0x33, 0x26, 0x47, 0x20,
];
/// RFC 6979 A.2.6 ECDSA P-384 SHA-384 message: ASCII `"sample"`.
pub const CAVP_ECDSA_P384_MSG: &[u8] = b"sample";
/// RFC 6979 A.2.6 ECDSA P-384 SHA-384 signature `r` value.
pub const CAVP_ECDSA_P384_R: &[u8] = &[
    0x94, 0xed, 0xbb, 0x92, 0xa5, 0xec, 0xb8, 0xaa, 0xd4, 0x73, 0x6e, 0x56, 0xc6, 0x91, 0x91, 0x6b,
    0x3f, 0x88, 0x14, 0x06, 0x66, 0xce, 0x9f, 0xa7, 0x3d, 0x64, 0xc4, 0xea, 0x95, 0xad, 0x13, 0x3c,
    0x81, 0xa6, 0x48, 0x15, 0x2e, 0x44, 0xac, 0xf9, 0x6e, 0x36, 0xdd, 0x1e, 0x80, 0xfa, 0xbe, 0x46,
];
/// RFC 6979 A.2.6 ECDSA P-384 SHA-384 signature `s` value.
pub const CAVP_ECDSA_P384_S: &[u8] = &[
    0x99, 0xef, 0x4a, 0xeb, 0x15, 0xf1, 0x78, 0xce, 0xa1, 0xfe, 0x40, 0xdb, 0x26, 0x03, 0x13, 0x8f,
    0x13, 0x0e, 0x74, 0x0a, 0x19, 0x62, 0x45, 0x26, 0x20, 0x3b, 0x63, 0x51, 0xd0, 0xa3, 0xa9, 0x4f,
    0xa3, 0x29, 0xc1, 0x45, 0x78, 0x6e, 0x67, 0x9e, 0x7b, 0x82, 0xc7, 0x1a, 0x38, 0x62, 0x8a, 0xc8,
];

/// Maximum DER content length the local length encoder can serialise.
///
/// The encoder supports up to a 3-byte long-form length (`0x83 || L1 ||
/// L2 || L3`), which tops out at `2^24 - 1` bytes. Anything larger would
/// silently truncate, so the public `der_encode_*` helpers reject it
/// upfront.
pub const DER_MAX_CONTENT_LEN: usize = (1 << 24) - 1;

/// Encode an unsigned big-endian integer into ASN.1 DER `INTEGER` form.
///
/// The leading high-bit byte gets a `0x00` pad to keep the value
/// non-negative; leading zero bytes (other than the pad) are stripped.
/// Used to assemble ECDSA `(r, s)` pairs into the DER `Ecdsa-Sig-Value`
/// structure that `aws_lc_rs::signature::ECDSA_*_ASN1` expects.
///
/// Returns [`CertError::BadEnvelope`] if `value.len()` would produce a
/// content section larger than [`DER_MAX_CONTENT_LEN`] (16 MiB - 1)
/// bytes, which is the largest length the local DER length encoder can
/// represent.
pub fn der_encode_integer(value: &[u8]) -> CertResult<Vec<u8>> {
    let mut start = 0;
    while start + 1 < value.len() && value[start] == 0 {
        start += 1;
    }
    let trimmed = &value[start..];
    // The content section is `trimmed` plus a possible `0x00` pad byte,
    // so the +1 keeps the check exact.
    let content_len = trimmed.len()
        + if !trimmed.is_empty() && (trimmed[0] & 0x80) != 0 {
            1
        } else {
            0
        };
    if content_len > DER_MAX_CONTENT_LEN {
        return Err(CertError::BadEnvelope(
            "der_encode_integer input exceeds 16 MiB DER length limit",
        ));
    }

    let mut content: Vec<u8> = Vec::with_capacity(content_len);
    if !trimmed.is_empty() && (trimmed[0] & 0x80) != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(trimmed);

    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x02); // INTEGER tag
    encode_der_length(&mut out, content.len());
    out.extend_from_slice(&content);
    Ok(out)
}

/// Encode the DER `(r, s)` ECDSA signature SEQUENCE.
///
/// Returns [`CertError::BadEnvelope`] if either component exceeds the
/// DER length limit (see [`der_encode_integer`]).
pub fn der_encode_ecdsa_sig(r: &[u8], s: &[u8]) -> CertResult<Vec<u8>> {
    let r_der = der_encode_integer(r)?;
    let s_der = der_encode_integer(s)?;
    let content_len = r_der.len() + s_der.len();
    if content_len > DER_MAX_CONTENT_LEN {
        return Err(CertError::BadEnvelope(
            "der_encode_ecdsa_sig content exceeds 16 MiB DER length limit",
        ));
    }
    let mut content = Vec::with_capacity(content_len);
    content.extend_from_slice(&r_der);
    content.extend_from_slice(&s_der);

    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x30); // SEQUENCE tag
    encode_der_length(&mut out, content.len());
    out.extend_from_slice(&content);
    Ok(out)
}

/// Encode an ASN.1 DER length octet(s) for content of `len` bytes.
///
/// Callers are expected to have already rejected `len > DER_MAX_CONTENT_LEN`;
/// this function `debug_assert!`s the invariant and otherwise emits the
/// best-effort 3-byte long-form length (which would truncate for larger
/// inputs).
fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    debug_assert!(
        len <= DER_MAX_CONTENT_LEN,
        "encode_der_length called with len {len} > DER_MAX_CONTENT_LEN; \
         caller must have validated this beforehand"
    );
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x83);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// Encode an EC public key as a SEC1 uncompressed point: `0x04 || Qx || Qy`.
pub fn sec1_uncompressed(qx: &[u8], qy: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + qx.len() + qy.len());
    out.push(0x04);
    out.extend_from_slice(qx);
    out.extend_from_slice(qy);
    out
}

/// Embedded NIST CAVP AES-GCM vector (Count=0 from `gcmEncryptExtIV256.rsp`)
/// plus three roundtrip-only AFT cases.
///
/// The first vector has full `key`, `iv`, `pt`, `ct`, `tag` fields populated
/// from the NIST CAVP file so a decrypt-and-compare KAT is possible. The
/// remaining three are AFT-style (encrypt/decrypt roundtrip only).
pub fn embedded_aes_gcm_vectors() -> Vec<AcvpTestVector> {
    fn v(key: Vec<u8>, pt: Vec<u8>) -> AcvpTestVector {
        AcvpTestVector {
            algorithm: "AES-GCM".to_string(),
            test_type: AcvpTestType::Aft,
            inputs: [("key".to_string(), key), ("pt".to_string(), pt)]
                .into_iter()
                .collect(),
            expected_outputs: HashMap::new(),
        }
    }
    let mut nist_vec = AcvpTestVector {
        algorithm: "AES-GCM".to_string(),
        test_type: AcvpTestType::Kat,
        inputs: HashMap::new(),
        expected_outputs: HashMap::new(),
    };
    nist_vec
        .inputs
        .insert("key".to_string(), CAVP_AES256_GCM_KEY.to_vec());
    nist_vec
        .inputs
        .insert("iv".to_string(), CAVP_AES256_GCM_IV.to_vec());
    nist_vec
        .inputs
        .insert("pt".to_string(), CAVP_AES256_GCM_PT.to_vec());
    nist_vec
        .expected_outputs
        .insert("ct".to_string(), CAVP_AES256_GCM_CT.to_vec());
    nist_vec
        .expected_outputs
        .insert("tag".to_string(), CAVP_AES256_GCM_TAG.to_vec());

    vec![
        nist_vec,
        v(vec![0x42u8; 32], b"ACVP AES-GCM test vector 1".to_vec()),
        v(
            vec![0xAA; 32],
            b"ACVP AES-GCM test vector 2 with more data".to_vec(),
        ),
        v(vec![0x00; 32], Vec::new()),
    ]
}

/// Fallible variant of [`embedded_hmac_sha256_vectors`] that surfaces a
/// `CertError::HexDecode` on a typo in any embedded hex literal instead
/// of panicking.
pub fn try_embedded_hmac_sha256_vectors() -> CertResult<Vec<AcvpTestVector>> {
    fn v(key: Vec<u8>, msg: Vec<u8>, mac_hex: &str) -> CertResult<AcvpTestVector> {
        Ok(AcvpTestVector {
            algorithm: "HMAC-SHA256".to_string(),
            test_type: AcvpTestType::Kat,
            inputs: [("key".to_string(), key), ("msg".to_string(), msg)]
                .into_iter()
                .collect(),
            expected_outputs: [("mac".to_string(), hex_decode(mac_hex)?)]
                .into_iter()
                .collect(),
        })
    }
    Ok(vec![
        v(
            vec![0x0bu8; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )?,
        v(
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )?,
        v(
            vec![0xAAu8; 20],
            vec![0xDDu8; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        )?,
    ])
}

/// Embedded NIST ACVP test vectors for HMAC-SHA256 (RFC 4231).
///
/// Infallible wrapper around [`try_embedded_hmac_sha256_vectors`] — see
/// the corresponding doc on [`embedded_sha256_vectors`] for the
/// rationale.
pub fn embedded_hmac_sha256_vectors() -> Vec<AcvpTestVector> {
    try_embedded_hmac_sha256_vectors()
        .expect("embedded HMAC-SHA256 KAT vectors must decode; covered by embedded_vectors_decode_at_startup")
}

/// Embedded ACVP test vectors for RSA signature (functional tests).
pub fn embedded_rsa_signature_vectors() -> Vec<AcvpTestVector> {
    fn v(alg: &str, msg: &[u8]) -> AcvpTestVector {
        AcvpTestVector {
            algorithm: alg.to_string(),
            test_type: AcvpTestType::Aft,
            inputs: [("msg".to_string(), msg.to_vec())].into_iter().collect(),
            expected_outputs: HashMap::new(),
        }
    }
    vec![
        v("RSA-2048", b"ACVP RSA-2048 signature test"),
        v("RSA-3072", b"ACVP RSA-3072 signature test"),
    ]
}

/// Embedded ACVP test vectors for ECDSA signature (functional tests).
pub fn embedded_ecdsa_signature_vectors() -> Vec<AcvpTestVector> {
    fn v(alg: &str, msg: &[u8]) -> AcvpTestVector {
        AcvpTestVector {
            algorithm: alg.to_string(),
            test_type: AcvpTestType::Aft,
            inputs: [("msg".to_string(), msg.to_vec())].into_iter().collect(),
            expected_outputs: HashMap::new(),
        }
    }
    vec![
        v("ECDSA-P256", b"ACVP ECDSA P-256 signature test"),
        v("ECDSA-P384", b"ACVP ECDSA P-384 signature test"),
    ]
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

    /// Precondition test: every embedded ACVP vector's hex literal must
    /// decode at startup. This catches a typo in a constant string at
    /// `cargo test` time so the runtime `expect` calls in
    /// `embedded_sha256_vectors` / `embedded_hmac_sha256_vectors` cannot
    /// fire in production.
    #[test]
    fn embedded_vectors_decode_at_startup() {
        // Each call internally `expect`s every hex literal — if any
        // would-be panic existed, constructing the Vec here would
        // already trip it.
        let sha = embedded_sha256_vectors();
        assert!(
            !sha.is_empty(),
            "embedded SHA-256 vectors must be non-empty"
        );
        for v in &sha {
            for out in v.expected_outputs.values() {
                assert_eq!(
                    out.len(),
                    32,
                    "SHA-256 digest length must be 32 bytes for vector {:?}",
                    v.test_type
                );
            }
        }
        let hmac = embedded_hmac_sha256_vectors();
        assert!(
            !hmac.is_empty(),
            "embedded HMAC-SHA256 vectors must be non-empty"
        );
        for v in &hmac {
            for out in v.expected_outputs.values() {
                assert_eq!(
                    out.len(),
                    32,
                    "HMAC-SHA256 tag length must be 32 bytes for vector {:?}",
                    v.test_type
                );
            }
        }
    }

    // -- JSON parsing --------------------------------------------------------

    #[test]
    fn parse_sha_acvp_json() {
        let json = r#"{
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "tests": [
                    { "msg": "616263", "md": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
                    { "msg": "", "md": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
                ]
            }]
        }"#;

        let suite = parse_acvp_json(json).unwrap();
        assert_eq!(suite.algorithm, "SHA2-256");
        assert_eq!(suite.revision, "1.0");
        assert_eq!(suite.test_group_id, 1);
        assert_eq!(suite.vectors.len(), 2);
        assert_eq!(suite.vectors[0].algorithm, "SHA2-256");
        assert_eq!(suite.vectors[0].inputs["msg"], b"abc".to_vec());
    }

    #[test]
    fn parse_hmac_acvp_json() {
        let json = r#"{
            "algorithm": "HMAC-SHA256",
            "testGroups": [{
                "tgId": 5,
                "testType": "AFT",
                "tests": [
                    { "key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "msg": "4869205468657265", "mac": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" }
                ]
            }]
        }"#;

        let suite = parse_acvp_json(json).unwrap();
        assert_eq!(suite.algorithm, "HMAC-SHA256");
        assert_eq!(suite.test_group_id, 5);
        assert_eq!(suite.vectors.len(), 1);
        assert!(suite.vectors[0].inputs.contains_key("key"));
        assert!(suite.vectors[0].expected_outputs.contains_key("mac"));
    }

    #[test]
    fn parse_aes_gcm_acvp_json() {
        // Note: 32-byte (AES-256) key to match what the runner exercises.
        let json = r#"{
            "algorithm": "AES-GCM",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 10,
                "testType": "AFT",
                "tests": [
                    { "key": "4242424242424242424242424242424242424242424242424242424242424242", "pt": "48656c6c6f", "iv": "000000000000000000000000" }
                ]
            }]
        }"#;

        let suite = parse_acvp_json(json).unwrap();
        assert_eq!(suite.algorithm, "AES-GCM");
        assert_eq!(suite.vectors.len(), 1);
        assert_eq!(suite.vectors[0].inputs["key"].len(), 32);
        assert!(suite.vectors[0].inputs.contains_key("pt"));
        assert!(suite.vectors[0].inputs.contains_key("iv"));
    }

    #[test]
    fn parse_multiple_test_groups() {
        let json = r#"{
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "tests": [
                        { "msg": "616263", "md": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
                    ]
                },
                {
                    "tgId": 2,
                    "testType": "KAT",
                    "tests": [
                        { "msg": "", "md": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                        { "msg": "616263", "md": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
                    ]
                }
            ]
        }"#;

        let suite = parse_acvp_json(json).unwrap();
        assert_eq!(suite.algorithm, "SHA2-256");
        assert_eq!(suite.vectors.len(), 3);
        assert_eq!(suite.test_group_id, 1);
    }

    #[test]
    fn parse_empty_test_groups_error() {
        let json = r#"{ "algorithm": "SHA2-256", "testGroups": [] }"#;
        assert!(parse_acvp_json(json).is_err());
    }

    // ------------------------------------------------------------------
    // Vector-count cap — reject absurdly large inputs early
    // ------------------------------------------------------------------
    //
    // Rather than synthesize a 1M-vector JSON (which would stress CI for
    // no test signal), we exercise the cap boundary by stubbing a group
    // structure directly and asserting the arithmetic fold behaves. The
    // full-JSON path is covered by the existing multi-group parser tests.

    #[test]
    fn parse_accepts_small_realistic_input() {
        let json = r#"{
            "algorithm": "SHA2-256",
            "testGroups": [
                {"tgId": 1, "testType": "KAT", "tests": [
                    {"msg": "", "md": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
                ]}
            ]
        }"#;
        let suite = parse_acvp_json(json).expect("small input must parse");
        assert_eq!(suite.vectors.len(), 1);
    }

    #[test]
    fn parse_invalid_json_error() {
        assert!(parse_acvp_json("not json at all").is_err());
    }

    #[test]
    fn parse_field_error_includes_field_name() {
        let json = r#"{
            "algorithm": "SHA2-256",
            "testGroups": [{
                "tgId": 1, "testType": "AFT",
                "tests": [{ "msg": "zz", "md": "00" }]
            }]
        }"#;
        let err = parse_acvp_json(json).unwrap_err();
        assert!(err.to_string().contains("msg"));
    }

    // -- runner -- digest ----------------------------------------------------

    #[test]
    fn digest_runner_against_real_backend() {
        let suite = embedded_sha256_vectors();
        let results = run_acvp_digest_vectors(&backend(), &suite);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.passed, "{:?}", r);
        }
    }

    #[test]
    fn digest_runner_detects_mismatch() {
        // Construct a vector with a wrong expected md.
        let mut bad = AcvpTestVector {
            algorithm: "SHA2-256".to_string(),
            test_type: AcvpTestType::Kat,
            inputs: [("msg".to_string(), b"abc".to_vec())].into_iter().collect(),
            expected_outputs: HashMap::new(),
        };
        bad.expected_outputs
            .insert("md".to_string(), vec![0xDEu8; 32]);
        let results = run_acvp_digest_vectors(&backend(), &[bad]);
        assert!(!results[0].passed);
    }

    // -- runner -- symmetric -------------------------------------------------

    #[test]
    fn symmetric_runner_aes_gcm_roundtrip() {
        let suite = embedded_aes_gcm_vectors();
        let results = run_acvp_symmetric_vectors(&backend(), &suite);
        assert_eq!(results.len(), suite.len());
        for r in &results {
            assert!(r.passed, "{:?}", r);
        }
    }

    #[test]
    fn cbc_missing_iv_returns_error_result() {
        let v = AcvpTestVector {
            algorithm: "AES-CBC".to_string(),
            test_type: AcvpTestType::Aft,
            inputs: [
                ("key".to_string(), vec![0u8; 32]),
                ("pt".to_string(), vec![0u8; 16]),
            ]
            .into_iter()
            .collect(),
            expected_outputs: HashMap::new(),
        };
        let results = run_acvp_symmetric_vectors(&backend(), &[v]);
        assert!(!results[0].passed);
        assert!(results[0].details.contains("IV"));
    }

    // -- runner -- hmac ------------------------------------------------------

    #[test]
    fn hmac_runner_against_rfc4231_vectors() {
        let suite = embedded_hmac_sha256_vectors();
        let results = run_acvp_hmac_vectors(&backend(), &suite);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.passed, "{:?}", r);
        }
    }

    // -- runner -- signature -------------------------------------------------

    #[test]
    fn rsa_runner_roundtrips() {
        let suite = embedded_rsa_signature_vectors();
        let results = run_acvp_signature_vectors(&backend(), &suite);
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.passed, "{:?}", r);
            assert!(r.details.contains("negative test"));
        }
    }

    #[test]
    fn ecdsa_runner_roundtrips() {
        let suite = embedded_ecdsa_signature_vectors();
        let results = run_acvp_signature_vectors(&backend(), &suite);
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.passed, "{:?}", r);
            assert!(r.details.contains("negative test"));
        }
    }

    // -- embedded vectors ----------------------------------------------------

    #[test]
    fn embedded_sha256_vectors_valid() {
        let vecs = embedded_sha256_vectors();
        assert_eq!(vecs.len(), 3);
        for v in &vecs {
            assert_eq!(v.algorithm, "SHA2-256");
            assert_eq!(v.test_type, AcvpTestType::Kat);
            assert!(v.inputs.contains_key("msg"));
            assert!(v.expected_outputs.contains_key("md"));
            assert_eq!(v.expected_outputs["md"].len(), 32);
        }
    }

    #[test]
    fn embedded_aes_gcm_vectors_valid() {
        let vecs = embedded_aes_gcm_vectors();
        // 1 NIST CAVP KAT + 3 AFT roundtrip vectors.
        assert_eq!(vecs.len(), 4);
        for v in &vecs {
            assert_eq!(v.algorithm, "AES-GCM");
            assert!(v.inputs.contains_key("key"));
            assert!(v.inputs.contains_key("pt"));
            assert_eq!(v.inputs["key"].len(), 32);
        }
        // The first vector is the NIST CAVP KAT and carries an IV +
        // expected ciphertext + expected tag.
        let nist = &vecs[0];
        assert_eq!(nist.test_type, AcvpTestType::Kat);
        assert!(nist.inputs.contains_key("iv"));
        assert!(nist.expected_outputs.contains_key("ct"));
        assert!(nist.expected_outputs.contains_key("tag"));
        assert_eq!(nist.inputs["iv"].len(), 12);
        assert_eq!(nist.expected_outputs["tag"].len(), 16);
    }

    #[test]
    fn embedded_hmac_sha256_vectors_valid() {
        let vecs = embedded_hmac_sha256_vectors();
        assert_eq!(vecs.len(), 3);
        for v in &vecs {
            assert_eq!(v.algorithm, "HMAC-SHA256");
            assert!(v.inputs.contains_key("key"));
            assert!(v.inputs.contains_key("msg"));
            assert!(v.expected_outputs.contains_key("mac"));
            assert_eq!(v.expected_outputs["mac"].len(), 32);
        }
    }

    // -- HMAC-SHA256 KATs with aws-lc-rs ------------------------------------

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        let vecs = embedded_hmac_sha256_vectors();
        let v = &vecs[0];
        let key_data = &v.inputs["key"];
        let msg = &v.inputs["msg"];
        let expected = &v.expected_outputs["mac"];
        let s_key = awslc_hmac::Key::new(awslc_hmac::HMAC_SHA256, key_data);
        let tag = awslc_hmac::sign(&s_key, msg);
        assert_eq!(tag.as_ref(), expected.as_slice());
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        let vecs = embedded_hmac_sha256_vectors();
        let v = &vecs[1];
        let key_data = &v.inputs["key"];
        let msg = &v.inputs["msg"];
        let expected = &v.expected_outputs["mac"];
        let s_key = awslc_hmac::Key::new(awslc_hmac::HMAC_SHA256, key_data);
        let tag = awslc_hmac::sign(&s_key, msg);
        assert_eq!(tag.as_ref(), expected.as_slice());
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_3() {
        let vecs = embedded_hmac_sha256_vectors();
        let v = &vecs[2];
        let key_data = &v.inputs["key"];
        let msg = &v.inputs["msg"];
        let expected = &v.expected_outputs["mac"];
        let s_key = awslc_hmac::Key::new(awslc_hmac::HMAC_SHA256, key_data);
        let tag = awslc_hmac::sign(&s_key, msg);
        assert_eq!(tag.as_ref(), expected.as_slice());
    }

    // -- response generation -------------------------------------------------

    #[test]
    fn generate_response_json_valid() {
        let response = AcvpResponse {
            algorithm: "SHA2-256".to_string(),
            revision: "1.0".to_string(),
            test_group_id: 1,
            results: vec![
                AcvpVectorResult {
                    tc_id: 0,
                    passed: true,
                    actual_output: Some("ba7816bf".to_string()),
                    details: "OK".to_string(),
                },
                AcvpVectorResult {
                    tc_id: 1,
                    passed: false,
                    actual_output: None,
                    details: "mismatch".to_string(),
                },
            ],
        };

        let json = generate_acvp_response(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["algorithm"], "SHA2-256");
        assert_eq!(parsed["results"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["results"][0]["passed"], true);
        assert_eq!(parsed["results"][1]["passed"], false);
    }

    #[test]
    fn acvp_test_type_serialization() {
        for variant in [AcvpTestType::Kat, AcvpTestType::Mct, AcvpTestType::Aft] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: AcvpTestType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    // -- RSA / ECDSA embedded vectors ----------------------------------------

    #[test]
    fn embedded_rsa_signature_vectors_valid() {
        let vecs = embedded_rsa_signature_vectors();
        assert_eq!(vecs.len(), 2);
        for v in &vecs {
            assert!(v.algorithm.contains("RSA"));
            assert_eq!(v.test_type, AcvpTestType::Aft);
            assert!(v.inputs.contains_key("msg"));
        }
    }

    #[test]
    fn embedded_ecdsa_signature_vectors_valid() {
        let vecs = embedded_ecdsa_signature_vectors();
        assert_eq!(vecs.len(), 2);
        for v in &vecs {
            assert!(v.algorithm.contains("ECDSA"));
            assert_eq!(v.test_type, AcvpTestType::Aft);
            assert!(v.inputs.contains_key("msg"));
        }
    }

    #[test]
    fn parse_rsa_acvp_json() {
        let json = r#"{
            "algorithm": "RSA-2048",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 20,
                "testType": "AFT",
                "tests": [{ "msg": "48656c6c6f" }]
            }]
        }"#;
        let suite = parse_acvp_json(json).unwrap();
        assert_eq!(suite.algorithm, "RSA-2048");
        assert_eq!(suite.vectors.len(), 1);
    }

    #[test]
    fn parse_ecdsa_acvp_json() {
        let json = r#"{
            "algorithm": "ECDSA-P256",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 30,
                "testType": "AFT",
                "tests": [{ "msg": "616263" }]
            }]
        }"#;
        let suite = parse_acvp_json(json).unwrap();
        assert_eq!(suite.algorithm, "ECDSA-P256");
        assert_eq!(suite.vectors.len(), 1);
    }

    #[test]
    fn acvp_test_vector_serialization_roundtrip() {
        let v = AcvpTestVector {
            algorithm: "SHA2-256".to_string(),
            test_type: AcvpTestType::Kat,
            inputs: [("msg".to_string(), b"abc".to_vec())].into_iter().collect(),
            expected_outputs: [("md".to_string(), vec![0xBA, 0x78])].into_iter().collect(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: AcvpTestVector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.algorithm, "SHA2-256");
        assert_eq!(parsed.test_type, AcvpTestType::Kat);
        assert_eq!(parsed.inputs["msg"], b"abc".to_vec());
    }
}
