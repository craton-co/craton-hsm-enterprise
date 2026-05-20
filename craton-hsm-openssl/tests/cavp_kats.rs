// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! CAVP / RFC Known-Answer Tests driven through [`OpenSslBackend`]'s
//! public `CryptoBackend` trait surface.
//!
//! Unlike `nist_kats.rs` (which exercises the underlying `openssl` crate
//! primitives directly with caller-supplied nonces / randomness), the
//! vectors in this file drive `OpenSslBackend` end-to-end via the verify /
//! decrypt paths — those are deterministic and require no nonce control.
//!
//! Vector sources (all publicly available, cited inline):
//!
//! - **ECDSA-P384 / SHA-384**: IETF RFC 6979 Appendix A.2.6
//!   "ECDSA, 384 Bits (Prime Field)" — sample message "sample".
//! - **Ed25519**: IETF RFC 8032 §7.1 "TEST 1" (empty message).
//! - **AES-CBC-256**: NIST CAVS CBCMMT256.rsp Count=0 (single-block
//!   ciphertext; decrypt path).
//!
//! Every vector is accompanied by a citation to its source document.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_openssl::OpenSslBackend;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ----------------------------------------------------------------------------
// ECDSA-P384, RFC 6979 §A.2.6 — message "sample", SHA-384.
// ----------------------------------------------------------------------------
//
// Public key (curve P-384, NIST P-384):
//   Ux = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
//        "DEF8F0EA9055866064A254515480BC13"
//   Uy = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
//        "288B231C3AE0D4FE7344FD2533264720"
//
// Signature for SHA-384("sample"):
//   r = "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C"
//       "81A648152E44ACF96E36DD1E80FABE46"
//   s = "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F"
//       "A329C145786E679E7B82C71A38628AC8"

#[test]
fn cavp_ecdsa_p384_verify_rfc6979_a26() {
    let backend = OpenSslBackend;

    let ux = hex(
        "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
         DEF8F0EA9055866064A254515480BC13",
    );
    let uy = hex(
        "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1\
         288B231C3AE0D4FE7344FD2533264720",
    );

    // SEC1 uncompressed: 0x04 || X || Y.
    let mut pk = Vec::with_capacity(1 + 48 + 48);
    pk.push(0x04);
    pk.extend_from_slice(&ux);
    pk.extend_from_slice(&uy);

    let r = hex(
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
         81A648152E44ACF96E36DD1E80FABE46",
    );
    let s = hex(
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F\
         A329C145786E679E7B82C71A38628AC8",
    );

    // DER-encode (r, s) as an ECDSA-Sig-Value SEQUENCE.
    let sig = der_encode_ecdsa_pair(&r, &s);

    let ok = backend
        .ecdsa_p384_verify(&pk, b"sample", &sig)
        .expect("ECDSA-P384 verify call must not error");
    assert!(ok, "RFC 6979 A.2.6 ECDSA-P384 vector failed to verify");

    // Negative: flip one byte of the message; verify must return false.
    let ok_neg = backend
        .ecdsa_p384_verify(&pk, b"Sample", &sig)
        .expect("ECDSA-P384 verify call must not error");
    assert!(!ok_neg, "tampered message accepted");
}

/// Build an ECDSA `Sig-Value` SEQUENCE: SEQ { INTEGER r, INTEGER s }.
fn der_encode_ecdsa_pair(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn enc_int(v: &[u8]) -> Vec<u8> {
        // Strip leading zeros.
        let mut i = 0;
        while i + 1 < v.len() && v[i] == 0 {
            i += 1;
        }
        let trimmed = &v[i..];
        // Re-prepend a single 0 if high bit is set (positive integer).
        let mut buf = Vec::new();
        if !trimmed.is_empty() && (trimmed[0] & 0x80) != 0 {
            buf.push(0x00);
        }
        buf.extend_from_slice(trimmed);
        let mut out = Vec::with_capacity(2 + buf.len());
        out.push(0x02);
        out.push(buf.len() as u8);
        out.extend_from_slice(&buf);
        out
    }
    let r_enc = enc_int(r);
    let s_enc = enc_int(s);
    let mut body = Vec::with_capacity(r_enc.len() + s_enc.len());
    body.extend_from_slice(&r_enc);
    body.extend_from_slice(&s_enc);
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x30);
    assert!(body.len() < 0x80, "test vectors all fit short-form length");
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

// ----------------------------------------------------------------------------
// Ed25519, RFC 8032 §7.1 TEST 1.
// ----------------------------------------------------------------------------
//
// SECRET KEY: "9d61b19deffd5a60ba844af492ec2cc4 4449c5697b326919703bac031cae7f60"
// PUBLIC KEY: "d75a980182b10ab7d54bfed3c964073a 0ee172f3daa62325af021a68f707511a"
// MESSAGE:    (empty)
// SIGNATURE:  "e5564300c360ac729086e2cc806e828a 84877f1eb8e5d974d873e06522490155"
//             "5fb8821590a33bacc61e39701cf9b46b d25bf5f0595bbe24655141438e7a100b"

#[test]
fn cavp_ed25519_verify_rfc8032_test1() {
    let backend = OpenSslBackend;

    let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3\
         3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert_eq!(pk.len(), 32);
    assert_eq!(sig.len(), 64);

    let ok = backend
        .ed25519_verify(&pk, b"", &sig)
        .expect("Ed25519 verify call must not error");
    assert!(ok, "RFC 8032 TEST 1 Ed25519 vector failed to verify");

    // Negative: flip one bit of the signature; verify must return false.
    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    let ok_neg = backend
        .ed25519_verify(&pk, b"", &bad)
        .expect("Ed25519 verify call must not error");
    assert!(!ok_neg, "tampered Ed25519 signature accepted");
}

// ----------------------------------------------------------------------------
// AES-CBC-256, NIST CAVS CBCMMT256.rsp Count=0.
// ----------------------------------------------------------------------------
//
// COUNT = 0
// KEY        = 6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907
// IV         = 851e8764776e6796aab722dbb644ace8
// CIPHERTEXT = 6282b8c05c5c1530b97d4816ca434762
// PLAINTEXT  = 6bc1bee22e409f96e93d7e117393172a

#[test]
fn cavp_aes_cbc_256_cbcmmt256_count0_decrypt() {
    let backend = OpenSslBackend;

    let key = hex("6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907");
    let iv = hex("851e8764776e6796aab722dbb644ace8");
    let ct = hex("6282b8c05c5c1530b97d4816ca434762");
    let expected_pt = hex("6bc1bee22e409f96e93d7e117393172a");

    let pt = backend
        .aes_cbc_decrypt(&key, &iv, &ct)
        .expect("AES-CBC-256 decrypt must succeed for CBCMMT256 Count=0");
    assert_eq!(pt, expected_pt, "CBCMMT256 Count=0 plaintext mismatch");

    // And the encrypt path is the inverse.
    let re_ct = backend
        .aes_cbc_encrypt(&key, &iv, &expected_pt)
        .expect("AES-CBC-256 encrypt must succeed");
    assert_eq!(
        re_ct, ct,
        "CBCMMT256 Count=0 ciphertext mismatch on encrypt"
    );
}
