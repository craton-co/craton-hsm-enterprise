// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! RSA sign/verify and OAEP round-trip tests for the CNG backend.
//!
//! Generates RSA-2048 and (optionally, under the `rsa-slow-tests` feature)
//! RSA-4096 keys using the `rsa` crate, then exercises the CNG code paths
//! for PKCS#1 v1.5, PSS, and OAEP.

#![cfg(target_os = "windows")]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::{HashAlg, OaepHash};
use craton_hsm_cng::CngBackend;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

fn gen_rsa_2048() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
    let pub_key = RsaPublicKey::from(&priv_key);

    let priv_der = priv_key
        .to_pkcs8_der()
        .expect("pkcs8 encode")
        .as_bytes()
        .to_vec();
    let modulus = pub_key.n().to_bytes_be();
    let exponent = pub_key.e().to_bytes_be();
    (priv_der, modulus, exponent)
}

fn backend() -> CngBackend {
    CngBackend::new(false)
}

#[test]
fn rsa_2048_pkcs1v15_sign_verify_sha256() {
    let (priv_der, n, e) = gen_rsa_2048();
    let be = backend();
    let msg = b"RSA-PKCS1v15 test message";

    let sig = be
        .rsa_pkcs1v15_sign(&priv_der, msg, Some(HashAlg::Sha256))
        .expect("sign");
    let ok = be
        .rsa_pkcs1v15_verify(&n, &e, msg, &sig, Some(HashAlg::Sha256))
        .expect("verify");
    assert!(ok, "PKCS1v15 SHA-256 signature must verify");
}

#[test]
fn rsa_2048_pkcs1v15_wrong_message_rejected() {
    let (priv_der, n, e) = gen_rsa_2048();
    let be = backend();
    let sig = be
        .rsa_pkcs1v15_sign(&priv_der, b"correct", Some(HashAlg::Sha256))
        .unwrap();
    let ok = be
        .rsa_pkcs1v15_verify(&n, &e, b"tampered", &sig, Some(HashAlg::Sha256))
        .unwrap();
    assert!(!ok);
}

#[test]
fn rsa_2048_pss_sign_verify_all_hashes() {
    let (priv_der, n, e) = gen_rsa_2048();
    let be = backend();
    let msg = b"RSA-PSS test message";

    for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
        let sig = be.rsa_pss_sign(&priv_der, msg, alg).expect("sign");
        let ok = be.rsa_pss_verify(&n, &e, msg, &sig, alg).expect("verify");
        assert!(ok, "PSS with {alg:?} must verify");

        // Wrong-message rejection.
        let bad = be
            .rsa_pss_verify(&n, &e, b"other message", &sig, alg)
            .unwrap();
        assert!(!bad);
    }
}

#[test]
fn rsa_2048_pss_wrong_key_rejected() {
    let (priv_der_a, _n_a, _e_a) = gen_rsa_2048();
    let (_priv_der_b, n_b, e_b) = gen_rsa_2048();
    let be = backend();
    let msg = b"for key A";
    let sig = be.rsa_pss_sign(&priv_der_a, msg, HashAlg::Sha256).unwrap();
    let ok = be
        .rsa_pss_verify(&n_b, &e_b, msg, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(!ok, "signature from key A must not verify under key B");
}

#[test]
fn rsa_2048_oaep_roundtrip() {
    let (priv_der, n, e) = gen_rsa_2048();
    let be = backend();

    for hash in [OaepHash::Sha256, OaepHash::Sha384] {
        let plaintext = b"RSA-OAEP small payload";
        let ct = be
            .rsa_oaep_encrypt(&n, &e, plaintext, hash)
            .expect("oaep encrypt");
        let pt = be
            .rsa_oaep_decrypt(&priv_der, &ct, hash)
            .expect("oaep decrypt");
        assert_eq!(pt, plaintext);
    }
}

#[test]
fn rsa_2048_oaep_wrong_key_rejected() {
    let (_priv_der_a, n_a, e_a) = gen_rsa_2048();
    let (priv_der_b, _n_b, _e_b) = gen_rsa_2048();
    let be = backend();
    let plaintext = b"for key A";
    let ct = be
        .rsa_oaep_encrypt(&n_a, &e_a, plaintext, OaepHash::Sha256)
        .unwrap();
    let res = be.rsa_oaep_decrypt(&priv_der_b, &ct, OaepHash::Sha256);
    assert!(res.is_err(), "OAEP decrypt with wrong key must fail");
}

#[test]
fn rsa_prehashed_sign_verify_matches_one_shot() {
    use sha2::{Digest, Sha256};
    let (priv_der, n, e) = gen_rsa_2048();
    let be = backend();
    let msg = b"prehashed parity";

    let digest = Sha256::digest(msg).to_vec();

    let one_shot = be
        .rsa_pkcs1v15_sign(&priv_der, msg, Some(HashAlg::Sha256))
        .unwrap();
    let prehashed = be
        .rsa_pkcs1v15_sign_prehashed(&priv_der, &digest, HashAlg::Sha256)
        .unwrap();

    // Both must verify under the public key (they are deterministic PKCS1v15).
    assert!(be
        .rsa_pkcs1v15_verify(&n, &e, msg, &one_shot, Some(HashAlg::Sha256))
        .unwrap());
    assert!(be
        .rsa_pkcs1v15_verify_prehashed(&n, &e, &digest, &prehashed, HashAlg::Sha256)
        .unwrap());
}

// RSA-4096 tests are gated behind an opt-in feature because keygen takes
// several seconds. The test still exists and can be invoked with:
//   cargo test -p craton-hsm-cng --features rsa-slow-tests rsa_4096
#[cfg(feature = "rsa-slow-tests")]
#[test]
fn rsa_4096_pss_sign_verify() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 4096).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_der = priv_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();

    let be = backend();
    let sig = be
        .rsa_pss_sign(&priv_der, b"4096-bit PSS", HashAlg::Sha512)
        .unwrap();
    assert!(be
        .rsa_pss_verify(&n, &e, b"4096-bit PSS", &sig, HashAlg::Sha512)
        .unwrap());
}
