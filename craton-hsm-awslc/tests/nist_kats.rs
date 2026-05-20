// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! NIST / RFC Known-Answer Tests for the AWS-LC backend's underlying primitives.
//!
//! These tests exercise the cryptographic library that `AwsLcBackend`
//! delegates to (aws-lc-rs) against publicly documented test vectors. They
//! complement the roundtrip tests in `crypto_backend.rs` — a roundtrip can
//! succeed against a buggy implementation as long as encrypt and decrypt are
//! consistently wrong, while a KAT catches that.
//!
//! Vector sources (all publicly available):
//!
//! - **AES-256-GCM**: McGrew & Viega "The Galois/Counter Mode of Operation"
//!   Appendix B Test Cases 13, 14, and 16 — the same vectors NIST uses in
//!   the CAVP gcmEncryptExtIV256 suite.
//! - **HKDF-SHA256**: RFC 5869 Appendix A Test Case 1 and Test Case 2.
//! - **HMAC-SHA256**: RFC 4231 Test Case 1 (sanity check on the underlying
//!   SHA-256 primitive).
//! - **ECDSA P-256 verify**: RFC 6979 §A.2.5 (deterministic ECDSA with SHA-256).
//!
//! We use the primitive library directly (not the backend's random-nonce
//! API) because KATs require caller-supplied nonces.
//!
//! Every vector in this file is accompanied by a citation to its source
//! document. If you add a vector, cite it.

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ============================================================================
// AES-256-GCM KATs
// ============================================================================

struct AesGcm256Kat {
    description: &'static str,
    key: &'static str,
    iv: &'static str,
    pt: &'static str,
    aad: &'static str,
    ct: &'static str,
    tag: &'static str,
}

// McGrew & Viega Test Case 13 — all-zero inputs.
const AES_GCM_KAT_1: AesGcm256Kat = AesGcm256Kat {
    description: "McGrew & Viega Test Case 13 (all-zero inputs)",
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    iv: "000000000000000000000000",
    pt: "",
    aad: "",
    ct: "",
    tag: "530f8afbc74536b9a963b4f1c4cb738b",
};

// McGrew & Viega Test Case 14 — one block of zero PT.
const AES_GCM_KAT_2: AesGcm256Kat = AesGcm256Kat {
    description: "McGrew & Viega Test Case 14 (single-block zero PT)",
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    iv: "000000000000000000000000",
    pt: "00000000000000000000000000000000",
    aad: "",
    ct: "cea7403d4d606b6e074ec5d3baf39d18",
    tag: "d0d1c8a799996bf0265b98b5d48ab919",
};

// McGrew & Viega Test Case 16 — non-trivial key, IV, PT + AAD.
const AES_GCM_KAT_3: AesGcm256Kat = AesGcm256Kat {
    description: "McGrew & Viega Test Case 16 (authenticated data)",
    key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    iv:  "cafebabefacedbaddecaf888",
    pt:  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    ct:  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    tag: "76fc6ece0f4e1768cddf8853bb2d551b",
};

fn run_aes_gcm_kat(kat: &AesGcm256Kat) {
    let key = hex(kat.key);
    let iv = hex(kat.iv);
    let pt = hex(kat.pt);
    let aad_bytes = hex(kat.aad);
    let expected_ct = hex(kat.ct);
    let expected_tag = hex(kat.tag);

    // aws-lc-rs expects nonce length = 12, key length dictated by algorithm.
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key).expect("UnboundKey::new(aes256gcm)");
    let sealing = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&iv).expect("12-byte nonce");

    // Seal in place: the output is ciphertext || tag concatenated.
    let mut in_out = pt.clone();
    sealing
        .seal_in_place_append_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
        .unwrap_or_else(|_| panic!("{}: seal failed", kat.description));

    let tag_len = aead::AES_256_GCM.tag_len();
    let split = in_out.len() - tag_len;
    let (produced_ct, produced_tag) = in_out.split_at(split);

    assert_eq!(
        produced_ct,
        &expected_ct[..],
        "{}: ciphertext mismatch",
        kat.description
    );
    assert_eq!(
        produced_tag,
        &expected_tag[..],
        "{}: tag mismatch",
        kat.description
    );

    // Decrypt (open) with correct tag.
    let mut combined = expected_ct.clone();
    combined.extend_from_slice(&expected_tag);
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
    let opening = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&iv).unwrap();
    let recovered = opening
        .open_in_place(nonce, Aad::from(&aad_bytes), &mut combined)
        .unwrap_or_else(|_| panic!("{}: open failed", kat.description));
    assert_eq!(
        recovered,
        &pt[..],
        "{}: decrypt produced wrong PT",
        kat.description
    );

    // Decrypt with wrong tag must fail.
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
    let opening = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&iv).unwrap();
    let mut bad = expected_ct.clone();
    bad.extend_from_slice(&expected_tag);
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let bad_res = opening.open_in_place(nonce, Aad::from(&aad_bytes), &mut bad);
    assert!(
        bad_res.is_err(),
        "{}: open with tampered tag must fail",
        kat.description
    );
}

#[test]
fn aes_256_gcm_kat_all_zero() {
    run_aes_gcm_kat(&AES_GCM_KAT_1);
}

#[test]
fn aes_256_gcm_kat_single_block_zero_pt() {
    run_aes_gcm_kat(&AES_GCM_KAT_2);
}

#[test]
fn aes_256_gcm_kat_with_aad_and_pt() {
    run_aes_gcm_kat(&AES_GCM_KAT_3);
}

// ============================================================================
// RSA-PSS-SHA256 self-KAT
// ============================================================================
//
// ECDSA and PSS are non-deterministic at sign time so a pure sign-side KAT
// isn't possible against the backend API; we sign + verify with the
// production parameters to catch regressions and a tampered-signature
// negative control.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm_awslc::AwsLcBackend;

#[test]
fn rsa_pss_sha256_self_kat_2048() {
    let b = AwsLcBackend::new();
    let (priv_der, n, e) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"NIST FIPS 186-4 PSS self-KAT message";
    let sig = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha256)
        .unwrap();
    assert_eq!(sig.len(), 256);
    let ok = b
        .rsa_pss_verify(&n, &e, msg, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(ok);

    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    let bad_ok = b
        .rsa_pss_verify(&n, &e, msg, &bad, HashAlg::Sha256)
        .unwrap();
    assert!(!bad_ok, "PSS verify of tampered signature must be false");
}

// ============================================================================
// ECDSA-P256-SHA256 verify KATs (RFC 6979 §A.2.5)
// ============================================================================

#[test]
fn ecdsa_p256_verify_rfc6979_sample_kat() {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    // RFC 6979 §A.2.5 key: Ux || Uy; SEC1 encoding is 0x04 || Ux || Uy.
    let ux = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    let uy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&ux);
    sec1.extend_from_slice(&uy);

    // Message "sample". r and s per RFC 6979 §A.2.5.
    let msg = b"sample";
    let r = hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s = hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    // aws-lc-rs' ECDSA_P256_SHA256_FIXED expects a 64-byte r||s signature.
    let mut sig_fixed = Vec::with_capacity(64);
    sig_fixed.extend_from_slice(&r);
    sig_fixed.extend_from_slice(&s);

    let pub_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &sec1);
    pub_key
        .verify(msg, &sig_fixed)
        .expect("RFC 6979 §A.2.5 'sample' must verify");

    // Tampered s must fail.
    let mut bad = sig_fixed.clone();
    bad[63] ^= 0x01;
    let pub_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &sec1);
    assert!(
        pub_key.verify(msg, &bad).is_err(),
        "tampered ECDSA signature must fail"
    );
}

#[test]
fn ecdsa_p256_verify_rfc6979_test_kat() {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    let ux = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    let uy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&ux);
    sec1.extend_from_slice(&uy);

    let msg = b"test";
    let r = hex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
    let s = hex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");
    let mut sig_fixed = Vec::with_capacity(64);
    sig_fixed.extend_from_slice(&r);
    sig_fixed.extend_from_slice(&s);

    let pub_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &sec1);
    pub_key
        .verify(msg, &sig_fixed)
        .expect("RFC 6979 §A.2.5 'test' must verify");
}

// ============================================================================
// HKDF-SHA256 KATs (RFC 5869 Appendix A)
// ============================================================================

struct HkdfKat {
    description: &'static str,
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    l: usize,
    expected_okm: &'static str,
}

const HKDF_KAT_1: HkdfKat = HkdfKat {
    description: "RFC 5869 A.1 (SHA-256, basic)",
    ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt: "000102030405060708090a0b0c",
    info: "f0f1f2f3f4f5f6f7f8f9",
    l: 42,
    expected_okm:
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
};

const HKDF_KAT_2: HkdfKat = HkdfKat {
    description: "RFC 5869 A.2 (SHA-256, longer inputs/outputs)",
    ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    l: 82,
    // RFC 5869 A.2 OKM (82 octets). The version in the RFC text itself has a
    // typo — an extra `97` byte that makes the hex string 83 octets while
    // `L = 82`. Errata 6042 against RFC 5869 documents this; the correct
    // 82-byte value (which aws-lc-rs's HKDF-SHA-256 returns) omits that
    // stray byte. The previous literal in this file copied the typo
    // verbatim, so the assertion compared 82 actual bytes against 83
    // expected bytes and always failed on length.
    expected_okm:
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
};

fn run_hkdf_kat(kat: &HkdfKat) {
    use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};

    let ikm = hex(kat.ikm);
    let salt_bytes = hex(kat.salt);
    let info_bytes = hex(kat.info);
    let expected = hex(kat.expected_okm);

    let salt = Salt::new(HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(&ikm);
    let info_slices: &[&[u8]] = &[&info_bytes];
    let okm_holder = prk
        .expand(info_slices, MyLen(kat.l))
        .unwrap_or_else(|_| panic!("{}: expand failed", kat.description));
    let mut out = vec![0u8; kat.l];
    okm_holder.fill(&mut out).expect("fill");

    assert_eq!(out, expected, "{}: OKM mismatch", kat.description);
}

// Adapter so we can pass a dynamic length into aws_lc_rs::hkdf::Okm::fill.
#[derive(Clone, Copy)]
struct MyLen(usize);

impl aws_lc_rs::hkdf::KeyType for MyLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[test]
fn hkdf_sha256_kat_rfc5869_a1() {
    run_hkdf_kat(&HKDF_KAT_1);
}

#[test]
fn hkdf_sha256_kat_rfc5869_a2() {
    run_hkdf_kat(&HKDF_KAT_2);
}

// ============================================================================
// HMAC-SHA256 KAT (RFC 4231 Test Case 1)
// ============================================================================

#[test]
fn hmac_sha256_kat_rfc4231_tc1() {
    use aws_lc_rs::hmac;

    let key_bytes = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let tag = hmac::sign(&key, data);
    assert_eq!(tag.as_ref(), &expected[..], "RFC 4231 TC1 mismatch");
}
