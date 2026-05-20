// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! ECDSA P-256 and P-384 sign/verify tests for the CNG backend.

#![cfg(target_os = "windows")]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_cng::CngBackend;

fn backend() -> CngBackend {
    CngBackend::new(false)
}

#[test]
fn ecdsa_p256_sign_verify() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    let scalar = sk.to_bytes().to_vec();
    let pub_point = sk.public_key().to_encoded_point(false);
    let sec1 = pub_point.as_bytes().to_vec();

    let be = backend();
    let msg = b"ECDSA P-256 test message";

    let sig = be.ecdsa_p256_sign(&scalar, msg).expect("sign");
    let ok = be.ecdsa_p256_verify(&sec1, msg, &sig).expect("verify");
    assert!(ok);
}

#[test]
fn ecdsa_p256_wrong_message_rejected() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    let scalar = sk.to_bytes().to_vec();
    let sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();

    let be = backend();
    let sig = be.ecdsa_p256_sign(&scalar, b"authentic").unwrap();
    let ok = be.ecdsa_p256_verify(&sec1, b"tampered", &sig).unwrap();
    assert!(!ok);
}

#[test]
fn ecdsa_p256_wrong_key_rejected() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let mut rng = rand::thread_rng();
    let sk_a = SecretKey::random(&mut rng);
    let sk_b = SecretKey::random(&mut rng);
    let scalar_a = sk_a.to_bytes().to_vec();
    let sec1_b = sk_b
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let be = backend();
    let sig = be.ecdsa_p256_sign(&scalar_a, b"msg").unwrap();
    let ok = be.ecdsa_p256_verify(&sec1_b, b"msg", &sig).unwrap();
    assert!(!ok, "signature under key A must not verify under key B");
}

#[test]
fn ecdsa_p384_sign_verify() {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;

    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    let scalar = sk.to_bytes().to_vec();
    let sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();

    let be = backend();
    let msg = b"ECDSA P-384 test message";
    let sig = be.ecdsa_p384_sign(&scalar, msg).expect("sign");
    let ok = be.ecdsa_p384_verify(&sec1, msg, &sig).expect("verify");
    assert!(ok);
}

#[test]
fn ecdsa_p384_wrong_message_rejected() {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;

    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    let scalar = sk.to_bytes().to_vec();
    let sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();

    let be = backend();
    let sig = be.ecdsa_p384_sign(&scalar, b"authentic").unwrap();
    let ok = be.ecdsa_p384_verify(&sec1, b"tampered", &sig).unwrap();
    assert!(!ok);
}

#[test]
fn ecdsa_signatures_are_non_deterministic() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    let scalar = sk.to_bytes().to_vec();
    let sec1 = sk.public_key().to_encoded_point(false).as_bytes().to_vec();

    let be = backend();
    let msg = b"same message twice";
    let s1 = be.ecdsa_p256_sign(&scalar, msg).unwrap();
    let s2 = be.ecdsa_p256_sign(&scalar, msg).unwrap();

    // CNG ECDSA is randomized — two signatures of the same message should
    // differ. Both must independently verify.
    assert_ne!(s1, s2, "ECDSA signatures must be non-deterministic");
    assert!(be.ecdsa_p256_verify(&sec1, msg, &s1).unwrap());
    assert!(be.ecdsa_p256_verify(&sec1, msg, &s2).unwrap());
}
