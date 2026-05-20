// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Cross-backend interoperability tests.
//!
//! These tests generate keys and ciphertexts/signatures under one backend
//! and verify they work under the other. Together with the per-backend KATs
//! they establish that the two crypto backends agree on wire-level formats:
//!
//! - ECDSA P-256 signatures (DER-encoded r‖s)
//! - RSA-2048 PKCS#1 v1.5 signatures
//! - AES-256-GCM ciphertexts (layout: 12-byte nonce ‖ ciphertext ‖ 16-byte tag)
//!
//! A failure here indicates a wire-format drift between the two crates that
//! the single-backend roundtrip suites would miss. Because both backends
//! consume the same core `CryptoBackend` trait surface, wire-level
//! compatibility is what makes them drop-in replacements.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm_awslc::AwsLcBackend;
use craton_hsm_openssl::OpenSslBackend;

fn aws() -> AwsLcBackend {
    AwsLcBackend::new()
}

fn oss() -> OpenSslBackend {
    OpenSslBackend
}

// ============================================================================
// ECDSA P-256
// ============================================================================

#[test]
fn ecdsa_p256_aws_sign_openssl_verify() {
    let a = aws();
    let o = oss();

    let (priv_key, pub_sec1) = a.generate_ec_p256_key_pair().unwrap();
    let msg = b"cross-backend interop: ECDSA P-256 (aws -> openssl)";

    let sig = a.ecdsa_p256_sign(priv_key.as_bytes(), msg).unwrap();
    let ok = o.ecdsa_p256_verify(&pub_sec1, msg, &sig).unwrap();
    assert!(ok, "OpenSSL must verify an AWS-LC P-256 signature");

    // Negative control: a tampered message must not verify.
    let bad = o.ecdsa_p256_verify(&pub_sec1, b"tampered", &sig).unwrap();
    assert!(!bad, "OpenSSL must reject a tampered-message signature");
}

#[test]
fn ecdsa_p256_openssl_sign_aws_verify() {
    let a = aws();
    let o = oss();

    let (priv_key, pub_sec1) = o.generate_ec_p256_key_pair().unwrap();
    let msg = b"cross-backend interop: ECDSA P-256 (openssl -> aws)";

    let sig = o.ecdsa_p256_sign(priv_key.as_bytes(), msg).unwrap();
    let ok = a.ecdsa_p256_verify(&pub_sec1, msg, &sig).unwrap();
    assert!(ok, "AWS-LC must verify an OpenSSL P-256 signature");
}

// ============================================================================
// RSA-2048 PKCS#1 v1.5 SHA-256
// ============================================================================

#[test]
fn rsa_pkcs1v15_sha256_aws_sign_openssl_verify() {
    let a = aws();
    let o = oss();

    let (priv_der, modulus, pub_exp) = a.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"cross-backend interop: RSA-2048 PKCS#1 v1.5 (aws -> openssl)";

    let sig = a
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha256))
        .unwrap();
    assert_eq!(sig.len(), 256);
    let ok = o
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(
        ok,
        "OpenSSL must verify an AWS-LC RSA-2048 PKCS1v15 signature"
    );

    let bad = o
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, b"tampered", &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(
        !bad,
        "OpenSSL must reject a tampered-message PKCS1v15 signature"
    );
}

#[test]
fn rsa_pkcs1v15_sha256_openssl_sign_aws_verify() {
    let a = aws();
    let o = oss();

    let (priv_der, modulus, pub_exp) = o.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"cross-backend interop: RSA-2048 PKCS#1 v1.5 (openssl -> aws)";

    let sig = o
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha256))
        .unwrap();
    let ok = a
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(
        ok,
        "AWS-LC must verify an OpenSSL RSA-2048 PKCS1v15 signature"
    );
}

// ============================================================================
// AES-256-GCM (layout: nonce || ct || tag, empty AAD)
// ============================================================================

/// Shared AES-256 key. Tests use independent keys so per-key nonce counters
/// stay bounded across runs.
fn fresh_aes256_key(seed: u8) -> Vec<u8> {
    // Derive a deterministic-but-unique 32-byte key for each test. Reuses
    // SHA-256 so we don't depend on a random source; these keys never leave
    // the test and the per-process nonce counter ensures we still get random
    // nonces, which is what actually matters for GCM safety.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"craton-hsm-crossbackend-test-key-v1");
    h.update([seed]);
    let out = h.finalize();
    out.to_vec()
}

#[test]
fn aes_256_gcm_aws_encrypt_openssl_decrypt() {
    let a = aws();
    let o = oss();

    let key = fresh_aes256_key(0x01);
    let pt = b"cross-backend interop: AES-256-GCM (aws -> openssl)";

    let ct = a.aes_256_gcm_encrypt(&key, pt).unwrap();
    // Layout sanity: 12-byte nonce || ct || 16-byte tag.
    assert_eq!(ct.len(), 12 + pt.len() + 16);

    let decoded = o.aes_256_gcm_decrypt(&key, &ct).unwrap();
    assert_eq!(decoded, pt);

    // Tampering the tag must fail.
    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(o.aes_256_gcm_decrypt(&key, &tampered).is_err());
}

#[test]
fn aes_256_gcm_openssl_encrypt_aws_decrypt() {
    let a = aws();
    let o = oss();

    let key = fresh_aes256_key(0x02);
    let pt = b"cross-backend interop: AES-256-GCM (openssl -> aws)";

    let ct = o.aes_256_gcm_encrypt(&key, pt).unwrap();
    assert_eq!(ct.len(), 12 + pt.len() + 16);

    let decoded = a.aes_256_gcm_decrypt(&key, &ct).unwrap();
    assert_eq!(decoded, pt);

    // Tampering the ciphertext middle must fail.
    let mut tampered = ct.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert!(a.aes_256_gcm_decrypt(&key, &tampered).is_err());
}
