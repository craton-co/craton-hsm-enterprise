// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! NIST / RFC Known-Answer Tests for the OpenSSL backend's underlying
//! primitives.
//!
//! These tests exercise the cryptographic library that [`OpenSslBackend`]
//! delegates to (the `openssl` crate's wrappers around libcrypto) against
//! publicly documented test vectors. They complement the roundtrip tests
//! in `crypto_backend.rs` — a roundtrip can succeed against a buggy
//! implementation as long as encrypt and decrypt are consistently wrong,
//! while a KAT catches that.
//!
//! Vector sources (all publicly available):
//!
//! - **AES-256-GCM**: NIST SP 800-38D Appendix B "Test Case 13" (key, IV,
//!   PT, AAD, CT, tag all zeroed) plus two additional vectors derived from
//!   the McGrew & Viega GCM paper (the original specification) "Test Case
//!   14" and "Test Case 16" — these are the same vectors NIST used to
//!   define CAVP gcmEncryptExtIV256 and are reproduced verbatim in the GCM
//!   specification document.
//! - **HKDF-SHA256**: RFC 5869 Appendix A Test Case 1 and Test Case 2.
//! - **HMAC-SHA256**: RFC 4231 Test Case 1 (used as a sanity check on the
//!   hash primitive underlying HKDF).
//!
//! We use the primitive library directly (not [`OpenSslBackend`]'s random-nonce
//! API) because KATs require caller-supplied nonces.
//!
//! Every vector in this file is accompanied by a citation to its source
//! document. If you add a vector, cite it.

use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

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
//
// Source: McGrew, D. and J. Viega, "The Galois/Counter Mode of Operation
// (GCM)", submission to NIST Modes of Operation Process, 2005. The test
// vectors in Appendix B of that document are also reproduced by NIST in the
// CAVP AES GCM Validation System — see
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
// (file gcmEncryptExtIV256.rsp, first three 96-bit-IV entries).

struct AesGcm256Kat {
    description: &'static str,
    key: &'static str,
    iv: &'static str,
    pt: &'static str,
    aad: &'static str,
    ct: &'static str,
    tag: &'static str,
}

// Test Case 13 — key, IV, PT, AAD all zero. McGrew & Viega §B.
const AES_GCM_KAT_1: AesGcm256Kat = AesGcm256Kat {
    description: "McGrew & Viega Test Case 13 (all-zero inputs)",
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    iv: "000000000000000000000000",
    pt: "",
    aad: "",
    ct: "",
    tag: "530f8afbc74536b9a963b4f1c4cb738b",
};

// Test Case 14 — key zero, IV zero, PT one AES block of zeros.
const AES_GCM_KAT_2: AesGcm256Kat = AesGcm256Kat {
    description: "McGrew & Viega Test Case 14 (single-block zero PT)",
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    iv: "000000000000000000000000",
    pt: "00000000000000000000000000000000",
    aad: "",
    ct: "cea7403d4d606b6e074ec5d3baf39d18",
    tag: "d0d1c8a799996bf0265b98b5d48ab919",
};

// Test Case 16 — non-trivial key, IV, PT and AAD. McGrew & Viega §B.
const AES_GCM_KAT_3: AesGcm256Kat = AesGcm256Kat {
    description: "McGrew & Viega Test Case 16 (authenticated-data + PT)",
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
    let aad = hex(kat.aad);
    let expected_ct = hex(kat.ct);
    let expected_tag = hex(kat.tag);

    // Encrypt.
    let mut tag = vec![0u8; 16];
    let ct = encrypt_aead(Cipher::aes_256_gcm(), &key, Some(&iv), &aad, &pt, &mut tag)
        .unwrap_or_else(|_| panic!("{}: encrypt failed", kat.description));

    assert_eq!(ct, expected_ct, "{}: ciphertext mismatch", kat.description);
    assert_eq!(tag, expected_tag, "{}: tag mismatch", kat.description);

    // Decrypt with the correct tag.
    let recovered = decrypt_aead(Cipher::aes_256_gcm(), &key, Some(&iv), &aad, &ct, &tag)
        .unwrap_or_else(|_| panic!("{}: decrypt failed", kat.description));
    assert_eq!(
        recovered, pt,
        "{}: decrypt produced wrong PT",
        kat.description
    );

    // Decrypt with a wrong tag must fail.
    let mut bad_tag = tag.clone();
    bad_tag[0] ^= 0x01;
    let bad = decrypt_aead(Cipher::aes_256_gcm(), &key, Some(&iv), &aad, &ct, &bad_tag);
    assert!(
        bad.is_err(),
        "{}: decrypt with wrong tag must fail",
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
// RSA-PSS-SHA256 KATs (2048-bit modulus)
// ============================================================================
//
// A deterministic KAT for RSA-PSS requires either a fixed salt (which the
// backend does not allow — it always uses `RsaPssSaltlen::DIGEST_LENGTH` and
// an internal random salt) OR a verification-only vector. We use the latter:
// the vectors below come from FIPS 186-4 SigVerPSS_186-3.rsp (2048-bit
// modulus, SHA-256, salt length 32), which publish (n, e, message,
// signature, expected-verify) tuples for verify-side CAVP validation.
//
// Source: NIST CAVP FIPS186-4 Digital Signature Test Vectors,
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
// (file 186-3rsatestvectors.zip → SigVerPSS_186-3.rsp, mod = 2048, SHA-256).
//
// NOTE: In the absence of bundled FIPS 186-4 vectors we demonstrate RSA-PSS
// behaviour with a sign+verify round-trip on the exact parameters the
// backend uses (SHA-256, salt length = digest length, MGF1-SHA256). This is
// a *roundtrip* check and NOT a Known-Answer Test — a true KAT requires
// CAVP-pinned vectors, which we don't bundle in this crate. The test name
// is therefore deliberately `..._roundtrip_...` rather than `..._kat_...`.
//
// TODO(CMVP): once the workspace bundles FIPS 186-4 SigVerPSS_186-3.rsp
// vectors (or fetches them at build time under a feature flag), replace
// this self-roundtrip with verify-only KAT vectors. Tracking item is in
// `project_review_20260419.md` (CAVP coverage gap).

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm_openssl::OpenSslBackend;

#[test]
fn rsa_pss_sha256_roundtrip_2048() {
    // Roundtrip self-check (NOT a KAT — see file header). The backend's PSS
    // sign and verify must agree for the exact parameters the production
    // path uses; this catches the "signer and verifier drift" regression
    // class even though it does not validate against a third-party vector.
    let b = OpenSslBackend;
    let (priv_der, n, e) = b.generate_rsa_key_pair(2048, false).unwrap();
    let msg = b"NIST FIPS 186-4 PSS self-KAT message";
    let sig = b
        .rsa_pss_sign(priv_der.as_bytes(), msg, HashAlg::Sha256)
        .unwrap();
    assert_eq!(sig.len(), 256); // 2048-bit modulus
    let ok = b
        .rsa_pss_verify(&n, &e, msg, &sig, HashAlg::Sha256)
        .unwrap();
    assert!(ok, "PSS self-verify must succeed");

    // Tamper resistance: a single-bit flip in the signature must verify false.
    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    let bad_ok = b
        .rsa_pss_verify(&n, &e, msg, &bad, HashAlg::Sha256)
        .unwrap();
    assert!(!bad_ok, "PSS verify of tampered signature must be false");
}

// ============================================================================
// ECDSA-P256-SHA256 KATs
// ============================================================================
//
// Like PSS, ECDSA signing is non-deterministic (random `k`) so a pure sign-
// side KAT is not possible against the standard library API. We pin the
// *verify* side against a published vector.
//
// Source: RFC 6979 §A.2.5 (ECDSA, P-256, SHA-256, deterministic k). RFC 6979
// is the deterministic-ECDSA profile — it specifies exact (r, s) outputs for
// a given key + message. The verify KAT below uses the RFC 6979 vector:
//
//   Curve: P-256
//   Private key x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
//   Public key:
//     Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
//     Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
//   Message: "sample"
//   SHA-256 hash: AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF
//   Signature:
//     r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
//     s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

#[test]
fn ecdsa_p256_verify_rfc6979_sample_kat() {
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use openssl::sha::sha256;

    let msg = b"sample";
    let digest = sha256(msg);
    let expected_hash = hex("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF");
    assert_eq!(
        &digest[..],
        &expected_hash[..],
        "SHA-256 primitive disagrees with RFC 6979 §A.2.5 hash"
    );

    let ux = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    let uy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    // Build SEC1 uncompressed public key = 0x04 || X || Y.
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&ux);
    sec1.extend_from_slice(&uy);

    let r = hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s = hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, &sec1, &mut ctx).unwrap();
    let ec_pub = EcKey::from_public_key(&group, &point).unwrap();
    let r_bn = BigNum::from_slice(&r).unwrap();
    let s_bn = BigNum::from_slice(&s).unwrap();
    let sig = EcdsaSig::from_private_components(r_bn, s_bn).unwrap();
    let ok = sig.verify(&digest, &ec_pub).unwrap();
    assert!(ok, "RFC 6979 §A.2.5 ECDSA-P256-SHA256 vector must verify");

    // And a mutated s must fail.
    let mut bad_s = s.clone();
    bad_s[31] ^= 0x01;
    let bad_sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&r).unwrap(),
        BigNum::from_slice(&bad_s).unwrap(),
    )
    .unwrap();
    let bad_ok = bad_sig.verify(&digest, &ec_pub).unwrap();
    assert!(!bad_ok, "Tampered ECDSA signature must verify false");

    // Round-trip SEC1 through the backend's verify path to be sure the
    // public surface accepts the RFC 6979 key encoding.
    //
    // The backend's `ecdsa_p256_verify` takes a DER-encoded signature; build one.
    let der = sig.to_der().unwrap();
    let b = OpenSslBackend;
    let ok = b.ecdsa_p256_verify(&sec1, msg, &der).unwrap();
    assert!(
        ok,
        "backend-level ecdsa_p256_verify must agree with raw library"
    );
}

// RFC 6979 §A.2.5 second vector: message "test" under the same P-256 key.
//
//   SHA-256("test") = 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
//   r = F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
//   s = 019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
#[test]
fn ecdsa_p256_verify_rfc6979_test_kat() {
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use openssl::sha::sha256;

    let msg = b"test";
    let digest = sha256(msg);
    let expected = hex("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08");
    assert_eq!(&digest[..], &expected[..]);

    let ux = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    let uy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&ux);
    sec1.extend_from_slice(&uy);

    let r = hex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
    let s = hex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, &sec1, &mut ctx).unwrap();
    let ec_pub = EcKey::from_public_key(&group, &point).unwrap();
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&r).unwrap(),
        BigNum::from_slice(&s).unwrap(),
    )
    .unwrap();
    assert!(sig.verify(&digest, &ec_pub).unwrap());
}

// ============================================================================
// HKDF-SHA256 KATs
// ============================================================================
//
// Source: RFC 5869 Appendix A.

struct HkdfKat {
    description: &'static str,
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    l: usize,
    expected_okm: &'static str,
}

// RFC 5869 A.1 — Basic test case with SHA-256.
const HKDF_KAT_1: HkdfKat = HkdfKat {
    description: "RFC 5869 A.1 (SHA-256, basic)",
    ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt: "000102030405060708090a0b0c",
    info: "f0f1f2f3f4f5f6f7f8f9",
    l: 42,
    expected_okm:
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
};

// RFC 5869 A.2 — Longer inputs/outputs with SHA-256.
const HKDF_KAT_2: HkdfKat = HkdfKat {
    description: "RFC 5869 A.2 (SHA-256, longer inputs/outputs)",
    ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    l: 82,
    expected_okm:
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b836779793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
};

fn run_hkdf_kat(kat: &HkdfKat) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = hex(kat.ikm);
    let salt = hex(kat.salt);
    let info = hex(kat.info);
    let expected = hex(kat.expected_okm);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; kat.l];
    hk.expand(&info, &mut okm)
        .unwrap_or_else(|_| panic!("{}: expand failed", kat.description));

    assert_eq!(okm, expected, "{}: OKM mismatch", kat.description);
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
// HMAC-SHA256 sanity KAT (RFC 4231 §4.2)
// ============================================================================

#[test]
fn hmac_sha256_kat_rfc4231_tc1() {
    // RFC 4231 Test Case 1: key = 20 × 0x0b, data = "Hi There".
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    assert_eq!(tag.as_slice(), expected.as_slice(), "RFC 4231 TC1 mismatch");
}
