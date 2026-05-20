// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Comprehensive test suite for the AwsLcBackend CryptoBackend implementation.
//!
//! Tests cover all cryptographic operations: signing, encryption, key generation,
//! digests, key wrap/unwrap, and ECDH key derivation. Includes known-answer tests
//! (KATs) with NIST test vectors, roundtrip tests, and negative/edge-case tests.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm::error::HsmError;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm_awslc::AwsLcBackend;

/// Non-FIPS backend for tests that exercise all operations including prehashed.
fn backend() -> AwsLcBackend {
    AwsLcBackend::new()
}

/// FIPS backend for tests that verify the FIPS mode enforcement boundaries.
///
/// `mark_fips_post_passed` is called here so the FIPS POST gate does not
/// block ordinary crypto ops. Tests that exercise the *gate itself* (i.e.
/// check that operations refuse before POST passes) should construct the
/// backend directly via `AwsLcBackend::new_fips()` instead.
fn fips_backend() -> AwsLcBackend {
    let b = AwsLcBackend::new_fips().expect("fips backend");
    b.mark_fips_post_passed();
    b
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
    assert_eq!(sig.len(), 256); // 2048-bit key → 256-byte signature

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
fn test_generate_aes_key_fips_mode_rejects_128() {
    let b = backend();
    assert!(matches!(
        b.generate_aes_key(16, true),
        Err(HsmError::KeySizeRange)
    ));
    assert!(b.generate_aes_key(24, true).is_ok());
    assert!(b.generate_aes_key(32, true).is_ok());
}

#[test]
fn test_generate_rsa_key_pair_sizes() {
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
fn test_generate_rsa_invalid_size() {
    let b = backend();
    assert!(matches!(
        b.generate_rsa_key_pair(1024, false),
        Err(HsmError::KeySizeRange)
    ));
    assert!(matches!(
        b.generate_rsa_key_pair(8192, false),
        Err(HsmError::KeySizeRange)
    ));
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

// ============================================================================
// Digest — Known Answer Tests (NIST)
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
fn test_sha3_256_known_vector() {
    let b = backend();
    let digest = b.compute_digest(CKM_SHA3_256, b"abc").unwrap();
    let expected = hex_to_bytes("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    assert_eq!(digest, expected);
}

#[test]
fn test_sha1_known_vector() {
    // SHA-1 is deprecated but should still work for legacy compatibility
    let b = backend();
    let digest = b.compute_digest(CKM_SHA_1, b"abc").unwrap();
    let expected = hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(digest, expected);
}

#[test]
fn test_digest_output_len() {
    let b = backend();
    assert_eq!(b.digest_output_len(CKM_SHA_1).unwrap(), 20);
    assert_eq!(b.digest_output_len(CKM_SHA256).unwrap(), 32);
    assert_eq!(b.digest_output_len(CKM_SHA384).unwrap(), 48);
    assert_eq!(b.digest_output_len(CKM_SHA512).unwrap(), 64);
    assert_eq!(b.digest_output_len(CKM_SHA3_256).unwrap(), 32);
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

// ============================================================================
// ECDH key derivation
// ============================================================================

#[test]
fn test_ecdh_p256_shared_secret() {
    let b = backend();
    let (alice_priv, alice_pub) = b.generate_ec_p256_key_pair().unwrap();
    let (bob_priv, bob_pub) = b.generate_ec_p256_key_pair().unwrap();

    let secret_a = b.ecdh_p256(alice_priv.as_bytes(), &bob_pub, None).unwrap();
    let secret_b = b.ecdh_p256(bob_priv.as_bytes(), &alice_pub, None).unwrap();
    assert_eq!(secret_a.as_bytes(), secret_b.as_bytes());
    assert!(!secret_a.as_bytes().is_empty());
}

#[test]
fn test_ecdh_p384_shared_secret() {
    let b = backend();
    let (alice_priv, alice_pub) = b.generate_ec_p384_key_pair().unwrap();
    let (bob_priv, bob_pub) = b.generate_ec_p384_key_pair().unwrap();

    let secret_a = b.ecdh_p384(alice_priv.as_bytes(), &bob_pub, None).unwrap();
    let secret_b = b.ecdh_p384(bob_priv.as_bytes(), &alice_pub, None).unwrap();
    assert_eq!(secret_a.as_bytes(), secret_b.as_bytes());
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
fn test_ecdsa_p256_verify_wrong_key() {
    let b = backend();
    let (priv_key, _) = b.generate_ec_p256_key_pair().unwrap();
    let (_, other_pub) = b.generate_ec_p256_key_pair().unwrap();

    let sig = b.ecdsa_p256_sign(priv_key.as_bytes(), b"msg").unwrap();
    let valid = b.ecdsa_p256_verify(&other_pub, b"msg", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_ed25519_wrong_key_length() {
    let b = backend();
    assert!(matches!(
        b.ed25519_sign(&[0u8; 16], b"data"),
        Err(HsmError::KeyHandleInvalid)
    ));
    assert!(matches!(
        b.ed25519_verify(&[0u8; 16], b"data", &[0u8; 64]),
        Err(HsmError::KeyHandleInvalid)
    ));
    assert!(matches!(
        b.ed25519_verify(&[0u8; 32], b"data", &[0u8; 32]),
        Err(HsmError::SignatureInvalid)
    ));
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
fn test_aes_cbc_wrong_iv_length() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    assert!(matches!(
        b.aes_cbc_encrypt(key.as_bytes(), &[0u8; 8], b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_aes_ctr_wrong_iv_length() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    assert!(matches!(
        b.aes_ctr_encrypt(key.as_bytes(), &[0u8; 8], b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_aes_gcm_data_too_short() {
    let b = backend();
    let key = b.generate_aes_key(32, false).unwrap();
    // Data shorter than nonce (12 bytes)
    assert!(matches!(
        b.aes_256_gcm_decrypt(key.as_bytes(), &[0u8; 8]),
        Err(HsmError::EncryptedDataInvalid)
    ));
}

#[test]
fn test_key_wrap_invalid_wrapping_key_size() {
    let b = backend();
    assert!(b.aes_key_wrap(&[0u8; 20], &[0u8; 16], false).is_err());
}

// ============================================================================
// FIPS mode enforcement tests
// ============================================================================

#[test]
fn test_fips_default_is_non_fips() {
    // Default is non-FIPS; use AwsLcBackend::new_fips() for FIPS-mode.
    // `Default::default()` cannot fail, but FIPS construction is fallible
    // (the runtime probe `aws_lc_rs::try_fips_mode` may refuse), so the
    // Default impl deliberately returns the non-FIPS backend produced by
    // `AwsLcBackend::new()`.
    let b = AwsLcBackend::default();
    assert!(
        !b.is_fips_mode(),
        "Default::default() must produce a non-FIPS backend"
    );
}

#[test]
fn test_new_is_non_fips() {
    let b = AwsLcBackend::new();
    assert!(!b.is_fips_mode());
}

#[test]
fn test_new_fips_is_fips_mode() {
    let b = AwsLcBackend::new_fips().expect("fips backend");
    assert!(b.is_fips_mode());
}

#[test]
fn test_fips_rejects_sha1_digest() {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA_1;
    let b = fips_backend();
    let result = b.compute_digest(CKM_SHA_1, b"hello");
    assert!(
        matches!(result, Err(HsmError::MechanismInvalid)),
        "FIPS mode must reject SHA-1"
    );
}

#[test]
fn test_fips_rejects_prehashed_rsa_pkcs1() {
    use craton_hsm::crypto::sign::HashAlg;
    let b = fips_backend();
    // Key generation still works in FIPS mode (operation-level fips_mode flag).
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, true).unwrap();
    let digest = [0u8; 32]; // 32-byte fake digest for SHA-256

    let sign_result = b.rsa_pkcs1v15_sign_prehashed(priv_der.as_bytes(), &digest, HashAlg::Sha256);
    assert!(
        matches!(sign_result, Err(HsmError::MechanismInvalid)),
        "FIPS mode must reject prehashed RSA-PKCS1v15 sign"
    );

    let dummy_sig = [0u8; 256];
    let verify_result =
        b.rsa_pkcs1v15_verify_prehashed(&modulus, &pub_exp, &digest, &dummy_sig, HashAlg::Sha256);
    assert!(
        matches!(verify_result, Err(HsmError::MechanismInvalid)),
        "FIPS mode must reject prehashed RSA-PKCS1v15 verify"
    );
}

#[test]
fn test_fips_allows_standard_rsa_sign() {
    use craton_hsm::crypto::sign::HashAlg;
    let b = fips_backend();
    let (priv_der, modulus, pub_exp) = b.generate_rsa_key_pair(2048, true).unwrap();
    let msg = b"FIPS-validated RSA sign";

    let sig = b
        .rsa_pkcs1v15_sign(priv_der.as_bytes(), msg, Some(HashAlg::Sha256))
        .expect("standard RSA-SHA256 sign must succeed in FIPS mode");
    let valid = b
        .rsa_pkcs1v15_verify(&modulus, &pub_exp, msg, &sig, Some(HashAlg::Sha256))
        .expect("standard RSA-SHA256 verify must succeed in FIPS mode");
    assert!(valid);
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
