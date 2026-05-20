// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Comprehensive test suite for the OpenSslBackend CryptoBackend implementation.
//!
//! Tests cover all cryptographic operations: signing, encryption, key generation,
//! digests, key wrap/unwrap, and ECDH key derivation. Includes known-answer tests
//! (KATs) with NIST test vectors, roundtrip tests, and negative/edge-case tests.
//!
//! Modeled after the craton-hsm-awslc test suite, adapted for OpenSSL backend behavior.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm_openssl::OpenSslBackend;

fn backend() -> OpenSslBackend {
    OpenSslBackend
}

// ============================================================================
// Signing roundtrips
// ============================================================================

#[test]
fn test_rsa_pkcs1v15_sign_verify_sha256() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"RSA PKCS#1 v1.5 SHA-256 test message";

    let sig = b
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha256))
        .unwrap();
    assert_eq!(sig.len(), 256); // 2048-bit key -> 256-byte signature

    let valid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(valid);

    // Tampered message should fail
    let invalid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, b"tampered", &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(!invalid);
}

#[test]
fn test_rsa_pkcs1v15_sign_verify_sha384() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"SHA-384 test";

    let sig = b
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha384))
        .unwrap();
    let valid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha384))
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pkcs1v15_sign_verify_sha512() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"SHA-512 test";

    let sig = b
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha512))
        .unwrap();
    let valid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha512))
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pkcs1v15_no_hash_rejected() {
    let b = backend();
    let (priv_der, _, _) = b.generate_rsa_key_pair(2048, false).unwrap();
    let result = b.rsa_pkcs1v15_sign(priv_der.as_bytes(), b"data", None);
    assert!(matches!(result, Err(HsmError::MechanismInvalid)));
}

#[test]
fn test_rsa_pss_sign_verify_sha256() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"RSA-PSS SHA-256 test";

    let sig = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha256)
        .unwrap();
    let valid = b
        .rsa_pss_verify(&modulus, &pub_exp, msg, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pss_sign_verify_sha384() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"RSA-PSS SHA-384 test";

    let sig = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha384)
        .unwrap();
    let valid = b
        .rsa_pss_verify(&modulus, &pub_exp, msg, &sig, HashAlg::Sha384)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pss_sign_verify_sha512() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(3072, false).unwrap();
    let msg = b"RSA-PSS SHA-512 test with 3072-bit key";

    let sig = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha512)
        .unwrap();
    let valid = b
        .rsa_pss_verify(&modulus, &pub_exp, msg, &sig, HashAlg::Sha512)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pss_tampered_signature() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"PSS tamper test";

    let mut sig = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha256)
        .unwrap();
    sig[0] ^= 0xFF;
    let valid = b
        .rsa_pss_verify(&modulus, &pub_exp, msg, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(!valid);
}

#[test]
fn test_ecdsa_p256_sign_verify() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p256_key_pair().unwrap();
    let msg = b"ECDSA P-256 test message";

    let sig = b.ecdsa_p256_sign(priv_key.as_bytes(), msg).unwrap();
    let valid = b.ecdsa_p256_verify(&pub_key, msg, &sig).unwrap();
    assert!(valid);

    let invalid = b.ecdsa_p256_verify(&pub_key, b"tampered", &sig).unwrap();
    assert!(!invalid);
}

#[test]
fn test_ecdsa_p384_sign_verify() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p384_key_pair().unwrap();
    let msg = b"ECDSA P-384 test message";

    let sig = b.ecdsa_p384_sign(priv_key.as_bytes(), msg).unwrap();
    let valid = b.ecdsa_p384_verify(&pub_key, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_p384_tampered_signature() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p384_key_pair().unwrap();
    let msg = b"ECDSA P-384 tamper test";

    let sig = b.ecdsa_p384_sign(priv_key.as_bytes(), msg).unwrap();
    // Verify with wrong message
    let invalid = b
        .ecdsa_p384_verify(&pub_key, b"wrong message", &sig)
        .unwrap();
    assert!(!invalid);
}

#[test]
fn test_ed25519_sign_verify() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ed25519_key_pair().unwrap();
    assert_eq!(priv_key.as_bytes().len(), 32);
    assert_eq!(pub_key.len(), 32);

    let msg = b"Ed25519 test message";
    let sig = b.ed25519_sign(priv_key.as_bytes(), msg).unwrap();
    assert_eq!(sig.len(), 64);

    let valid = b.ed25519_verify(&pub_key, msg, &sig).unwrap();
    assert!(valid);

    let invalid = b.ed25519_verify(&pub_key, b"tampered", &sig).unwrap();
    assert!(!invalid);
}

#[test]
fn test_ed25519_tampered_signature() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ed25519_key_pair().unwrap();
    let msg = b"Ed25519 tamper test";

    let mut sig = b.ed25519_sign(priv_key.as_bytes(), msg).unwrap();
    sig[0] ^= 0xFF;
    let valid = b.ed25519_verify(&pub_key, msg, &sig).unwrap();
    assert!(!valid);
}

// ============================================================================
// Prehashed signing roundtrips
// ============================================================================

#[test]
fn test_rsa_pkcs1v15_prehashed_sha256() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"prehashed message";

    let digest = b.compute_digest(CKM_SHA256, msg).unwrap();
    let sig = b
        .rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha256)
        .unwrap();
    let valid = b
        .rsa_pkcs1v15_verify_prehashed(&modulus, &pub_exp, &digest, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pkcs1v15_prehashed_sha384() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let digest = b.compute_digest(CKM_SHA384, b"data").unwrap();

    let sig = b
        .rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha384)
        .unwrap();
    let valid = b
        .rsa_pkcs1v15_verify_prehashed(&modulus, &pub_exp, &digest, &sig, HashAlg::Sha384)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pkcs1v15_prehashed_sha512() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let digest = b.compute_digest(CKM_SHA512, b"data").unwrap();

    let sig = b
        .rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha512)
        .unwrap();
    let valid = b
        .rsa_pkcs1v15_verify_prehashed(&modulus, &pub_exp, &digest, &sig, HashAlg::Sha512)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pkcs1v15_prehashed_tampered_digest() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();

    let digest = b.compute_digest(CKM_SHA256, b"original").unwrap();
    let sig = b
        .rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha256)
        .unwrap();

    // Verify with different digest
    let wrong_digest = b.compute_digest(CKM_SHA256, b"tampered").unwrap();
    let valid = b
        .rsa_pkcs1v15_verify_prehashed(&modulus, &pub_exp, &wrong_digest, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(!valid);
}

#[test]
fn test_rsa_pss_prehashed_sha256() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"prehashed PSS message";

    let digest = b.compute_digest(CKM_SHA256, msg).unwrap();
    let sig = b
        .rsa_pss_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha256)
        .unwrap();
    let valid = b
        .rsa_pss_verify_prehashed(&modulus, &pub_exp, &digest, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pss_prehashed_sha384() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"prehashed PSS 384";

    let digest = b.compute_digest(CKM_SHA384, msg).unwrap();
    let sig = b
        .rsa_pss_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha384)
        .unwrap();
    let valid = b
        .rsa_pss_verify_prehashed(&modulus, &pub_exp, &digest, &sig, HashAlg::Sha384)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pss_prehashed_sha512() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"prehashed PSS 512";

    let digest = b.compute_digest(CKM_SHA512, msg).unwrap();
    let sig = b
        .rsa_pss_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha512)
        .unwrap();
    let valid = b
        .rsa_pss_verify_prehashed(&modulus, &pub_exp, &digest, &sig, HashAlg::Sha512)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_p256_prehashed() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p256_key_pair().unwrap();
    let msg = b"ECDSA P-256 prehashed";

    let digest = b.compute_digest(CKM_SHA256, msg).unwrap();
    let sig = b
        .ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &digest)
        .unwrap();
    let valid = b
        .ecdsa_p256_verify_prehashed(&pub_key, &digest, &sig)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_p384_prehashed() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p384_key_pair().unwrap();
    let msg = b"ECDSA P-384 prehashed";

    let digest = b.compute_digest(CKM_SHA384, msg).unwrap();
    let sig = b
        .ecdsa_p384_sign_prehashed(priv_key.as_bytes(), &digest)
        .unwrap();
    let valid = b
        .ecdsa_p384_verify_prehashed(&pub_key, &digest, &sig)
        .unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_p256_prehashed_tampered() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p256_key_pair().unwrap();

    let digest = b.compute_digest(CKM_SHA256, b"original").unwrap();
    let sig = b
        .ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &digest)
        .unwrap();

    let wrong_digest = b.compute_digest(CKM_SHA256, b"tampered").unwrap();
    let valid = b
        .ecdsa_p256_verify_prehashed(&pub_key, &wrong_digest, &sig)
        .unwrap();
    assert!(!valid);
}

// ============================================================================
// Encryption roundtrips
// ============================================================================

#[test]
fn test_aes_256_gcm_encrypt_decrypt() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let plaintext = b"AES-256-GCM test plaintext";

    let ciphertext = b.aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
    assert!(ciphertext.len() > plaintext.len()); // nonce + tag overhead

    let decrypted = b.aes_256_gcm_decrypt(key.as_bytes(), &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_256_gcm_tamper_detection() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let plaintext = b"tamper test";

    let mut ct = b.aes_256_gcm_encrypt(key.as_bytes(), plaintext).unwrap();
    // Flip a byte in the ciphertext portion
    if let Some(byte) = ct.last_mut() {
        *byte ^= 0xFF;
    }
    assert!(b.aes_256_gcm_decrypt(key.as_bytes(), &ct).is_err());
}

#[test]
fn test_aes_256_gcm_wrong_key() {
    let b = backend();
    let key1 = b.generate_aes_key(32, false).unwrap();
    let key2 = b.generate_aes_key(32, false).unwrap();
    let ct = b.aes_256_gcm_encrypt(key1.as_bytes(), b"data").unwrap();
    assert!(b.aes_256_gcm_decrypt(key2.as_bytes(), &ct).is_err());
}

#[test]
fn test_aes_256_gcm_unique_nonces() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let ct1 = b.aes_256_gcm_encrypt(key.as_bytes(), b"same").unwrap();
    let ct2 = b.aes_256_gcm_encrypt(key.as_bytes(), b"same").unwrap();
    assert_ne!(&ct1[..12], &ct2[..12], "nonces must differ");
}

#[test]
fn test_aes_256_gcm_empty_plaintext() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let ct = b.aes_256_gcm_encrypt(key.as_bytes(), b"").unwrap();
    let pt = b.aes_256_gcm_decrypt(key.as_bytes(), &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn test_aes_cbc_128_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(16, false).unwrap();
    let iv = [0u8; 16];
    let plaintext = b"AES-CBC-128 test plaintext data!"; // 32 bytes, block-aligned

    let ct = b.aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let pt = b.aes_cbc_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes_cbc_192_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(24, false).unwrap();
    let iv = [1u8; 16];
    let plaintext = b"AES-192 CBC test";

    let ct = b.aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let pt = b.aes_cbc_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes_cbc_256_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let iv = [2u8; 16];
    let plaintext = b"AES-256 CBC test data for roundtrip verification";

    let ct = b.aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let pt = b.aes_cbc_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes_ctr_128_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(16, false).unwrap();
    let iv = [3u8; 16];
    let plaintext = b"AES-CTR stream cipher test";

    let ct = b.aes_ctr_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    assert_eq!(ct.len(), plaintext.len()); // CTR mode: no padding
    assert_ne!(&ct, plaintext.as_slice());

    let pt = b.aes_ctr_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes_ctr_256_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let iv = [4u8; 16];
    let plaintext = b"AES-256-CTR test";

    let ct = b.aes_ctr_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let pt = b.aes_ctr_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes_ctr_192_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(24, false).unwrap();
    let iv = [5u8; 16];
    let plaintext = b"AES-192-CTR roundtrip test data";

    let ct = b.aes_ctr_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    assert_eq!(ct.len(), plaintext.len());
    let pt = b.aes_ctr_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_rsa_oaep_sha256_roundtrip() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let plaintext = b"RSA-OAEP SHA-256 test";

    let ct = b
        .rsa_oaep_encrypt(&modulus, &pub_exp, plaintext, OaepHash::Sha256)
        .unwrap();
    let pt = b
        .rsa_oaep_decrypt(priv_der.as_bytes(), &ct, OaepHash::Sha256)
        .unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_rsa_oaep_sha384_roundtrip() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(3072, false).unwrap();
    let plaintext = b"RSA-OAEP SHA-384";

    let ct = b
        .rsa_oaep_encrypt(&modulus, &pub_exp, plaintext, OaepHash::Sha384)
        .unwrap();
    let pt = b
        .rsa_oaep_decrypt(priv_der.as_bytes(), &ct, OaepHash::Sha384)
        .unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_rsa_oaep_sha512_roundtrip() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(4096, false).unwrap();
    let plaintext = b"RSA-OAEP SHA-512";

    let ct = b
        .rsa_oaep_encrypt(&modulus, &pub_exp, plaintext, OaepHash::Sha512)
        .unwrap();
    let pt = b
        .rsa_oaep_decrypt(priv_der.as_bytes(), &ct, OaepHash::Sha512)
        .unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_rsa_oaep_wrong_key() {
    let b = backend();
    let (_, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let (other_priv, _, _) = b.generate_rsa_key_pair(2048, false).unwrap();
    let ct = b
        .rsa_oaep_encrypt(&modulus, &pub_exp, b"test", OaepHash::Sha256)
        .unwrap();
    assert!(b
        .rsa_oaep_decrypt(other_priv.as_bytes(), &ct, OaepHash::Sha256)
        .is_err());
}

#[test]
fn test_rsa_oaep_wrong_hash() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let plaintext = b"OAEP hash mismatch";

    let ct = b
        .rsa_oaep_encrypt(&modulus, &pub_exp, plaintext, OaepHash::Sha256)
        .unwrap();
    // Decrypting with a different hash algorithm should fail
    assert!(b
        .rsa_oaep_decrypt(priv_der.as_bytes(), &ct, OaepHash::Sha384)
        .is_err());
}

// ============================================================================
// Key generation
// ============================================================================

#[test]
fn test_generate_aes_key_sizes() {
    let b = backend();
    assert_eq!(b.generate_aes_key(16, false).unwrap().as_bytes().len(), 16);
    assert_eq!(b.generate_aes_key(24, false).unwrap().as_bytes().len(), 24);
    assert_eq!(b.generate_aes_key(32, false).unwrap().as_bytes().len(), 32);
}

#[test]
fn test_generate_aes_key_invalid_size() {
    let b = backend();
    assert!(matches!(
        b.generate_aes_key(15, false),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.generate_aes_key(64, false),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.generate_aes_key(0, false),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_generate_aes_key_fips_mode_rejects_short_keys() {
    // L5 audit fix: under FIPS the OpenSSL backend rejects 128-bit and
    // 192-bit AES keys. Only 256-bit keys are accepted, aligning the
    // FIPS-mode crypto profile across the workspace.
    let b = backend();
    assert!(matches!(
        b.generate_aes_key(16, true),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.generate_aes_key(24, true),
        Err(HsmError::KeySizeRange)
    ));
    assert!(b.generate_aes_key(32, true).is_ok());
}

#[test]
fn test_generate_rsa_key_pair_2048() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    assert!(!priv_der.as_bytes().is_empty());
    assert_eq!(modulus.len(), 256); // 2048 bits = 256 bytes
    assert!(!pub_exp.is_empty());
}

#[test]
fn test_generate_rsa_3072() {
    let b = backend();
    let (_, modulus, _) = b.generate_rsa_key_pair(3072, false).unwrap();
    assert_eq!(modulus.len(), 384);
}

#[test]
fn test_generate_rsa_4096() {
    let b = backend();
    let (_, modulus, _) = b.generate_rsa_key_pair(4096, false).unwrap();
    assert_eq!(modulus.len(), 512);
}

#[test]
fn test_generate_rsa_invalid_size_too_small() {
    let b = backend();
    // OpenSSL backend rejects keys below 1024 bits
    assert!(b.generate_rsa_key_pair(512, false).is_err());
}

#[test]
fn test_generate_rsa_invalid_size_too_large() {
    let b = backend();
    // OpenSSL backend rejects keys above 8192 bits
    assert!(b.generate_rsa_key_pair(16384, false).is_err());
}

#[test]
fn test_generate_rsa_fips_rejects_small_keys() {
    let b = backend();
    // FIPS mode now requires ≥3072 bits per NIST SP 800-131A (2024 transition).
    assert!(matches!(
        b.generate_rsa_key_pair(1024, true),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.generate_rsa_key_pair(2048, true),
        Err(HsmError::KeySizeRange)
    ));
    // 3072 is the smallest size accepted in FIPS mode.
    assert!(b.generate_rsa_key_pair(3072, true).is_ok());
    // 2048 still works in non-FIPS mode.
    assert!(b.generate_rsa_key_pair(2048, false).is_ok());
}

#[test]
fn test_generate_ec_p256() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p256_key_pair().unwrap();
    assert_eq!(priv_key.as_bytes().len(), 32);
    assert_eq!(pub_key.len(), 65); // uncompressed SEC1: 0x04 + 32 + 32
    assert_eq!(pub_key[0], 0x04);
}

#[test]
fn test_generate_ec_p384() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p384_key_pair().unwrap();
    assert_eq!(priv_key.as_bytes().len(), 48);
    assert_eq!(pub_key.len(), 97); // 0x04 + 48 + 48
    assert_eq!(pub_key[0], 0x04);
}

#[test]
fn test_generate_ed25519() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ed25519_key_pair().unwrap();
    assert_eq!(priv_key.as_bytes().len(), 32);
    assert_eq!(pub_key.len(), 32);
}

#[test]
fn test_generate_ec_p256_unique_keys() {
    let b = backend();
    let (priv1, pub1) = b.generate_ec_p256_key_pair().unwrap();
    let (priv2, pub2) = b.generate_ec_p256_key_pair().unwrap();
    assert_ne!(priv1.as_bytes(), priv2.as_bytes());
    assert_ne!(pub1, pub2);
}

#[test]
fn test_generate_ed25519_unique_keys() {
    let b = backend();
    let (priv1, pub1) = b.generate_ed25519_key_pair().unwrap();
    let (priv2, pub2) = b.generate_ed25519_key_pair().unwrap();
    assert_ne!(priv1.as_bytes(), priv2.as_bytes());
    assert_ne!(pub1, pub2);
}

// ============================================================================
// Digest -- Known Answer Tests (NIST)
// ============================================================================

#[test]
fn test_sha256_known_vector() {
    let b = backend();
    let digest = b.compute_digest(CKM_SHA256, b"abc").unwrap();
    let expected = hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(digest, expected);
}

#[test]
fn test_sha384_known_vector() {
    let b = backend();
    let digest = b.compute_digest(CKM_SHA384, b"abc").unwrap();
    let expected = hex_to_bytes("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    assert_eq!(digest, expected);
}

#[test]
fn test_sha512_known_vector() {
    let b = backend();
    let digest = b.compute_digest(CKM_SHA512, b"abc").unwrap();
    let expected = hex_to_bytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    assert_eq!(digest, expected);
}

#[test]
fn test_sha256_empty_input() {
    let b = backend();
    let digest = b.compute_digest(CKM_SHA256, b"").unwrap();
    let expected = hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(digest, expected);
}

#[test]
fn test_digest_output_len() {
    let b = backend();
    assert_eq!(b.digest_output_len(CKM_SHA256).unwrap(), 32);
    assert_eq!(b.digest_output_len(CKM_SHA384).unwrap(), 48);
    assert_eq!(b.digest_output_len(CKM_SHA512).unwrap(), 64);
}

#[test]
fn test_digest_invalid_mechanism() {
    let b = backend();
    assert!(matches!(
        b.compute_digest(0xFFFF, b"data"),
        Err(HsmError::MechanismInvalid)
    ));
}

#[test]
fn test_multipart_hasher() {
    let b = backend();
    let mut hasher = b.create_hasher(CKM_SHA256).unwrap();
    hasher.update(b"a");
    hasher.update(b"b");
    hasher.update(b"c");
    let result = hasher.finalize();

    let expected = b.compute_digest(CKM_SHA256, b"abc").unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_hasher_output_len() {
    let b = backend();
    let hasher = b.create_hasher(CKM_SHA256).unwrap();
    assert_eq!(hasher.output_len(), 32);
}

#[test]
fn test_multipart_hasher_sha512() {
    let b = backend();
    let mut hasher = b.create_hasher(CKM_SHA512).unwrap();
    hasher.update(b"abc");
    let result = hasher.finalize();

    let expected = b.compute_digest(CKM_SHA512, b"abc").unwrap();
    assert_eq!(result, expected);
}

// ============================================================================
// Key wrap/unwrap
// ============================================================================

#[test]
fn test_aes_128_key_wrap_roundtrip() {
    let b = backend();
    let wrapping_key = b.generate_aes_key(16, false).unwrap();
    let key_to_wrap = b.generate_aes_key(32, false).unwrap(); // wrap a 256-bit key with 128-bit KEK

    let wrapped = b
        .aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false)
        .unwrap();
    assert_eq!(wrapped.len(), key_to_wrap.as_bytes().len() + 8);

    let unwrapped = b
        .aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false)
        .unwrap();
    assert_eq!(unwrapped, key_to_wrap.as_bytes());
}

#[test]
fn test_aes_256_key_wrap_roundtrip() {
    let b = backend();
    let wrapping_key = b.generate_aes_key(32, false).unwrap();
    let key_to_wrap = b.generate_aes_key(16, false).unwrap();

    let wrapped = b
        .aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false)
        .unwrap();
    let unwrapped = b
        .aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false)
        .unwrap();
    assert_eq!(unwrapped, key_to_wrap.as_bytes());
}

#[test]
fn test_aes_192_key_wrap_roundtrip() {
    let b = backend();
    let wrapping_key = b.generate_aes_key(24, false).unwrap();
    let key_to_wrap = b.generate_aes_key(32, false).unwrap();

    let wrapped = b
        .aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false)
        .unwrap();
    let unwrapped = b
        .aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false)
        .unwrap();
    assert_eq!(unwrapped, key_to_wrap.as_bytes());
}

#[test]
fn test_key_wrap_fips_rejects_aes128() {
    let b = backend();
    let wrapping_key = b.generate_aes_key(16, false).unwrap();
    let key_to_wrap = b.generate_aes_key(16, false).unwrap();
    assert!(matches!(
        b.aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), true),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_key_wrap_invalid_data_alignment() {
    let b = backend();
    let wrapping_key = b.generate_aes_key(32, false).unwrap();
    // 7 bytes is not a multiple of 8
    assert!(b
        .aes_key_wrap(wrapping_key.as_bytes(), &[0u8; 7], false)
        .is_err());
}

#[test]
fn test_key_unwrap_tampered() {
    let b = backend();
    let wrapping_key = b.generate_aes_key(32, false).unwrap();
    let key_to_wrap = b.generate_aes_key(32, false).unwrap();
    let mut wrapped = b
        .aes_key_wrap(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), false)
        .unwrap();

    // Tamper with wrapped data
    wrapped[0] ^= 0xFF;
    assert!(b
        .aes_key_unwrap(wrapping_key.as_bytes(), &wrapped, false)
        .is_err());
}

#[test]
fn test_key_unwrap_wrong_key() {
    let b = backend();
    let wrapping_key1 = b.generate_aes_key(32, false).unwrap();
    let wrapping_key2 = b.generate_aes_key(32, false).unwrap();
    let key_to_wrap = b.generate_aes_key(32, false).unwrap();
    let wrapped = b
        .aes_key_wrap(wrapping_key1.as_bytes(), key_to_wrap.as_bytes(), false)
        .unwrap();

    // Unwrap with wrong key should fail
    assert!(b
        .aes_key_unwrap(wrapping_key2.as_bytes(), &wrapped, false)
        .is_err());
}

#[test]
fn test_key_wrap_invalid_wrapping_key_size() {
    let b = backend();
    assert!(b.aes_key_wrap(&[0u8; 20], &[0u8; 16], false).is_err());
}

// ============================================================================
// ECDH key derivation
// ============================================================================

#[test]
fn test_ecdh_p256_shared_secret() {
    let b = backend();
    let (alice_priv, _alice_pub) = b.generate_ec_p256_key_pair().unwrap();
    let (_bob_priv, bob_pub) = b.generate_ec_p256_key_pair().unwrap();

    // Each side runs HKDF over its own (our_pub, peer_pub) pair, so the
    // OKMs are intentionally asymmetric (domain separation per
    // craton-hsm-core::crypto::derive). Just assert that the derivation
    // succeeds and produces a key of the default curve length.
    let secret_a = b.ecdh_p256(alice_priv.as_bytes(), &bob_pub, None).unwrap();
    assert_eq!(secret_a.as_bytes().len(), 32);

    // Same inputs must produce identical output (deterministic).
    let secret_a2 = b.ecdh_p256(alice_priv.as_bytes(), &bob_pub, None).unwrap();
    assert_eq!(secret_a.as_bytes(), secret_a2.as_bytes());
}

#[test]
fn test_ecdh_p384_shared_secret() {
    let b = backend();
    let (alice_priv, _alice_pub) = b.generate_ec_p384_key_pair().unwrap();
    let (_bob_priv, bob_pub) = b.generate_ec_p384_key_pair().unwrap();

    let secret_a = b.ecdh_p384(alice_priv.as_bytes(), &bob_pub, None).unwrap();
    assert_eq!(secret_a.as_bytes().len(), 48);

    let secret_a2 = b.ecdh_p384(alice_priv.as_bytes(), &bob_pub, None).unwrap();
    assert_eq!(secret_a.as_bytes(), secret_a2.as_bytes());
}

#[test]
fn test_ecdh_p256_with_okm_len() {
    let b = backend();
    let (alice_priv, _) = b.generate_ec_p256_key_pair().unwrap();
    let (_, bob_pub) = b.generate_ec_p256_key_pair().unwrap();

    let secret = b
        .ecdh_p256(alice_priv.as_bytes(), &bob_pub, Some(16))
        .unwrap();
    assert_eq!(secret.as_bytes().len(), 16);
}

#[test]
fn test_ecdh_p384_with_okm_len() {
    let b = backend();
    let (alice_priv, _) = b.generate_ec_p384_key_pair().unwrap();
    let (_, bob_pub) = b.generate_ec_p384_key_pair().unwrap();

    let secret = b
        .ecdh_p384(alice_priv.as_bytes(), &bob_pub, Some(32))
        .unwrap();
    assert_eq!(secret.as_bytes().len(), 32);
}

#[test]
fn test_ecdh_p256_different_okm_lengths() {
    let b = backend();
    let (alice_priv, _) = b.generate_ec_p256_key_pair().unwrap();
    let (_, bob_pub) = b.generate_ec_p256_key_pair().unwrap();

    // The derived secret with different okm_len should differ (different HKDF expand)
    let secret_16 = b
        .ecdh_p256(alice_priv.as_bytes(), &bob_pub, Some(16))
        .unwrap();
    let secret_32 = b
        .ecdh_p256(alice_priv.as_bytes(), &bob_pub, Some(32))
        .unwrap();
    assert_eq!(secret_16.as_bytes().len(), 16);
    assert_eq!(secret_32.as_bytes().len(), 32);
    // The first 16 bytes should NOT match because the HKDF info includes the okm_len
    assert_ne!(secret_16.as_bytes(), &secret_32.as_bytes()[..16]);
}

#[test]
fn test_ecdh_p256_invalid_okm_len_zero() {
    let b = backend();
    let (alice_priv, _) = b.generate_ec_p256_key_pair().unwrap();
    let (_, bob_pub) = b.generate_ec_p256_key_pair().unwrap();

    assert!(matches!(
        b.ecdh_p256(alice_priv.as_bytes(), &bob_pub, Some(0)),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_ecdh_p256_invalid_okm_len_too_large() {
    let b = backend();
    let (alice_priv, _) = b.generate_ec_p256_key_pair().unwrap();
    let (_, bob_pub) = b.generate_ec_p256_key_pair().unwrap();

    // MAX_OKM_LEN is 255 * 32 = 8160 (the HKDF-SHA256 hard limit, RFC 5869).
    // 128 bytes is now valid; anything beyond 8160 must be rejected.
    assert!(b
        .ecdh_p256(alice_priv.as_bytes(), &bob_pub, Some(128))
        .is_ok());
    assert!(matches!(
        b.ecdh_p256(alice_priv.as_bytes(), &bob_pub, Some(8161)),
        Err(HsmError::KeySizeRange)
    ));
}

// ============================================================================
// Negative / edge-case tests
// ============================================================================

#[test]
fn test_rsa_sign_invalid_key() {
    let b = backend();
    assert!(b
        .rsa_pkcs1v15_sign(b"not-a-key", b"data", Some(HashAlg::Sha256))
        .is_err());
}

#[test]
fn test_rsa_pss_sign_invalid_key() {
    let b = backend();
    assert!(b
        .rsa_pss_sign(b"not-a-key", b"data", HashAlg::Sha256)
        .is_err());
}

#[test]
fn test_rsa_verify_no_hash_rejected() {
    let b = backend();
    let (_, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let result = b.rsa_pkcs1v15_verify(&modulus, &pub_exp, b"data", &[0u8; 256], None);
    assert!(matches!(result, Err(HsmError::MechanismInvalid)));
}

#[test]
fn test_rsa_verify_small_modulus_rejected() {
    let b = backend();
    // A 1024-bit (128-byte) modulus should be rejected by the verify function
    let small_modulus = vec![0xFFu8; 128];
    let pub_exp = vec![0x01, 0x00, 0x01]; // 65537
    let result = b.rsa_pkcs1v15_verify(
        &small_modulus,
        &pub_exp,
        b"data",
        &[0u8; 128],
        Some(HashAlg::Sha256),
    );
    assert!(matches!(result, Err(HsmError::KeySizeRange)));
}

#[test]
fn test_rsa_sign_small_modulus_rejected() {
    // Generate a 1024-bit RSA key (below the 2048-bit minimum) and verify
    // that the sign function rejects it.
    let rsa = openssl::rsa::Rsa::generate(1024).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let small_priv_der = pkey.private_key_to_pkcs8().unwrap();

    let b = backend();
    let result = b.rsa_pkcs1v15_sign(&small_priv_der, b"data", Some(HashAlg::Sha256));
    assert!(matches!(result, Err(HsmError::KeySizeRange)));
}

#[test]
fn test_rsa_pss_verify_small_modulus_rejected() {
    let b = backend();
    let small_modulus = vec![0xFFu8; 128];
    let pub_exp = vec![0x01, 0x00, 0x01];
    let result = b.rsa_pss_verify(
        &small_modulus,
        &pub_exp,
        b"data",
        &[0u8; 128],
        HashAlg::Sha256,
    );
    assert!(matches!(result, Err(HsmError::KeySizeRange)));
}

#[test]
fn test_ecdsa_p256_verify_wrong_key() {
    let b = backend();
    let (priv_key, _) = b.generate_ec_p256_key_pair().unwrap();
    let (_, other_pub) = b.generate_ec_p256_key_pair().unwrap();

    let sig = b.ecdsa_p256_sign(priv_key.as_bytes(), b"msg").unwrap();
    let valid = b.ecdsa_p256_verify(&other_pub, b"msg", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_ecdsa_p384_verify_wrong_key() {
    let b = backend();
    let (priv_key, _) = b.generate_ec_p384_key_pair().unwrap();
    let (_, other_pub) = b.generate_ec_p384_key_pair().unwrap();

    let sig = b.ecdsa_p384_sign(priv_key.as_bytes(), b"msg").unwrap();
    let valid = b.ecdsa_p384_verify(&other_pub, b"msg", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_ed25519_wrong_key_length() {
    let b = backend();
    // Wrong-length key bytes are an *argument* error, not a key-handle error.
    assert!(matches!(
        b.ed25519_sign(&[0u8; 16], b"data"),
        Err(HsmError::ArgumentsBad)
    ));
    assert!(matches!(
        b.ed25519_verify(&[0u8; 16], b"data", &[0u8; 64]),
        Err(HsmError::ArgumentsBad)
    ));
}

#[test]
fn test_ed25519_verify_wrong_key() {
    let b = backend();
    let (priv_key, _) = b.generate_ed25519_key_pair().unwrap();
    let (_, other_pub) = b.generate_ed25519_key_pair().unwrap();

    let sig = b.ed25519_sign(priv_key.as_bytes(), b"msg").unwrap();
    let valid = b.ed25519_verify(&other_pub, b"msg", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_aes_gcm_wrong_key_length() {
    let b = backend();
    assert!(matches!(
        b.aes_256_gcm_encrypt(&[0u8; 16], b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_aes_gcm_data_too_short() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    // Data shorter than nonce (12) + tag (16) = 28 bytes minimum
    assert!(matches!(
        b.aes_256_gcm_decrypt(key.as_bytes(), &[0u8; 8]),
        Err(HsmError::EncryptedDataInvalid)
    ));
}

#[test]
fn test_aes_cbc_wrong_key_size() {
    let b = backend();
    // 20-byte key is not valid for any AES variant
    assert!(matches!(
        b.aes_cbc_encrypt(&[0u8; 20], &[0u8; 16], b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_aes_ctr_wrong_key_size() {
    let b = backend();
    assert!(matches!(
        b.aes_ctr_encrypt(&[0u8; 20], &[0u8; 16], b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_rsa_oaep_decrypt_invalid_key() {
    let b = backend();
    assert!(b
        .rsa_oaep_decrypt(b"not-a-key", &[0u8; 256], OaepHash::Sha256)
        .is_err());
}

#[test]
fn test_rsa_pkcs1v15_prehashed_wrong_digest_length() {
    let b = backend();
    let (priv_der, _, _) = b.generate_rsa_key_pair(2048, false).unwrap();
    // SHA-256 expects 32 bytes but we pass 16
    let result = b.rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &[0u8; 16], HashAlg::Sha256);
    assert!(matches!(result, Err(HsmError::ArgumentsBad)));
}

#[test]
fn test_aes_256_gcm_large_plaintext() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let plaintext = vec![0xABu8; 65536]; // 64KB

    let ct = b.aes_256_gcm_encrypt(key.as_bytes(), &plaintext).unwrap();
    let pt = b.aes_256_gcm_decrypt(key.as_bytes(), &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes_cbc_non_block_aligned_plaintext() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let iv = [0u8; 16];
    // 13 bytes -- not a multiple of 16 (block size). CBC with padding should handle this.
    let plaintext = b"13byteslong!!";

    let ct = b.aes_cbc_encrypt(key.as_bytes(), &iv, plaintext).unwrap();
    let pt = b.aes_cbc_decrypt(key.as_bytes(), &iv, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_rsa_sign_verify_different_hash_algs_fail() {
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"hash algorithm mismatch test";

    let sig = b
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha256))
        .unwrap();
    // Verifying with SHA-384 when signed with SHA-256 should fail
    let valid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha384))
        .unwrap();
    assert!(!valid);
}

#[test]
fn test_rsa_pss_sign_verify_deterministic_difference() {
    // PSS signatures should differ each time (random salt)
    let b = backend();
    let (priv_der, _, _) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"PSS randomness test";

    let sig1 = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha256)
        .unwrap();
    let sig2 = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha256)
        .unwrap();
    assert_ne!(sig1, sig2, "PSS signatures should be non-deterministic");
}

// ============================================================================
// Cross-operation consistency tests
// ============================================================================

#[test]
fn test_rsa_pkcs1v15_prehashed_matches_normal() {
    // Verify that prehashed signing produces a signature that can be verified
    // by the normal verify path, when we manually hash the data.
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"cross-check prehashed vs normal";

    let digest = b.compute_digest(CKM_SHA256, msg).unwrap();
    let sig = b
        .rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha256)
        .unwrap();

    // The normal verify should accept the prehashed signature
    let valid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_p256_prehashed_cross_verify() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p256_key_pair().unwrap();
    let msg = b"P-256 prehashed cross-verify";

    // Sign with prehashed API
    let digest = b.compute_digest(CKM_SHA256, msg).unwrap();
    let sig = b
        .ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &digest)
        .unwrap();

    // Verify with normal API (which hashes internally)
    let valid = b.ecdsa_p256_verify(&pub_key, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_p384_prehashed_cross_verify() {
    let b = backend();
    let (priv_key, pub_key) = b.generate_ec_p384_key_pair().unwrap();
    let msg = b"P-384 prehashed cross-verify";

    let digest = b.compute_digest(CKM_SHA384, msg).unwrap();
    let sig = b
        .ecdsa_p384_sign_prehashed(priv_key.as_bytes(), &digest)
        .unwrap();

    let valid = b.ecdsa_p384_verify(&pub_key, msg, &sig).unwrap();
    assert!(valid);
}

// ============================================================================
// GCM counter / nonce tracking tests
// ============================================================================

#[test]
fn test_gcm_counter_tracking() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    // Encrypt twice — nonces should differ (counter increments).
    let ct1 = b.aes_256_gcm_encrypt(key.as_bytes(), b"data1").unwrap();
    let ct2 = b.aes_256_gcm_encrypt(key.as_bytes(), b"data2").unwrap();
    // First 12 bytes are the nonce; they must differ between invocations.
    assert_ne!(
        &ct1[..12],
        &ct2[..12],
        "GCM nonces must differ between encryptions"
    );
}

#[test]
fn test_gcm_counter_auto_eviction() {
    let b = backend();
    // Generate many unique keys and encrypt with each to exercise any
    // internal counter-map eviction logic. The test passes if no panic
    // or OOM occurs.
    for _ in 0..100 {
        let key = b.generate_aes_key(32, false).unwrap();
        let _ = b.aes_256_gcm_encrypt(key.as_bytes(), b"test").unwrap();
    }
}

// ----- S1 regression: prehashed / OAEP must enforce RSA modulus minimum ----

#[test]
fn test_rsa_prehashed_paths_enforce_modulus_minimum() {
    use openssl::bn::BigNum;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    let b = backend();

    // Build a 1024-bit RSA private key for negative testing.
    let rsa = Rsa::generate(1024).unwrap();
    let modulus = rsa.n().to_vec();
    let exponent = rsa.e().to_vec();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let priv_der = pkey.private_key_to_pkcs8().unwrap();

    let digest_sha256 = [0u8; 32];
    let bogus_sig = vec![0u8; 128];
    let bogus_ct = vec![0u8; 128];

    // Sanity: hand the keys to a backend that's known to enforce a 2048-bit
    // minimum and verify *every* prehashed / OAEP entry-point rejects them.
    assert!(matches!(
        b.rsa_pkcs1v15_sign_prehashed(&priv_der, &digest_sha256, HashAlg::Sha256),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.rsa_pkcs1v15_verify_prehashed(
            &modulus,
            &exponent,
            &digest_sha256,
            &bogus_sig,
            HashAlg::Sha256
        ),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.rsa_pss_sign_prehashed(&priv_der, &digest_sha256, HashAlg::Sha256),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.rsa_pss_verify_prehashed(
            &modulus,
            &exponent,
            &digest_sha256,
            &bogus_sig,
            HashAlg::Sha256
        ),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.rsa_oaep_encrypt(&modulus, &exponent, b"x", OaepHash::Sha256),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.rsa_oaep_decrypt(&priv_der, &bogus_ct, OaepHash::Sha256),
        Err(HsmError::KeySizeRange)
    ));

    // The non-prehashed paths must also reject 1024-bit keys (already checked
    // by other tests, but assert here for completeness).
    let _ = BigNum::from_slice(&modulus).unwrap(); // confirm modulus is well-formed
    assert!(matches!(
        b.rsa_pkcs1v15_sign(&priv_der, b"data", Some(HashAlg::Sha256)),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.rsa_pss_sign(&priv_der, b"data", HashAlg::Sha256),
        Err(HsmError::KeySizeRange)
    ));
}

// ----- AAD / IV / OAEP layered behaviour --------------------------------

#[test]
fn test_aes_cbc_rejects_short_iv() {
    let b = backend();
    let key = vec![0u8; 32];
    let iv_short = [0u8; 8];
    let pt = b"hello world12345"; // 16 bytes, block aligned
    assert!(matches!(
        b.aes_cbc_encrypt(&key, &iv_short, pt),
        Err(HsmError::ArgumentsBad)
    ));
    assert!(matches!(
        b.aes_cbc_decrypt(&key, &iv_short, pt),
        Err(HsmError::ArgumentsBad)
    ));
}

#[test]
fn test_aes_ctr_rejects_short_iv() {
    let b = backend();
    let key = vec![0u8; 32];
    let iv_short = [0u8; 12];
    assert!(matches!(
        b.aes_ctr_encrypt(&key, &iv_short, b"hello"),
        Err(HsmError::ArgumentsBad)
    ));
}

#[test]
fn test_oaep_explicit_mgf1_matches_self_roundtrip() {
    // The new code pins MGF1 == OAEP hash explicitly. Confirm the
    // sign-then-verify path round-trips for every supported hash.
    let b = backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, false).unwrap();
    for h in [OaepHash::Sha256, OaepHash::Sha384, OaepHash::Sha512] {
        let pt = b"oaep mgf1 round-trip test";
        let ct = b.rsa_oaep_encrypt(&modulus, &pub_exp, pt, h).unwrap();
        let recovered = b.rsa_oaep_decrypt(priv_der.as_bytes(), &ct, h).unwrap();
        assert_eq!(&recovered, pt, "round-trip failed for hash {:?}", h);
    }
}

#[test]
fn test_aes_gcm_zero_length_plaintext_roundtrip() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    let ct = b.aes_256_gcm_encrypt(key.as_bytes(), b"").unwrap();
    // 12 nonce + 0 ct + 16 tag
    assert_eq!(ct.len(), 28);
    let pt = b.aes_256_gcm_decrypt(key.as_bytes(), &ct).unwrap();
    assert!(pt.is_empty());
}

// ============================================================================
// Helper
// ============================================================================

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
