// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Hash (SHA-256/384/512) tests for the CNG backend.
//!
//! Test vectors:
//! - SHA-256 / SHA-384 / SHA-512: FIPS 180-4 Appendix B examples.
//! - HMAC-SHA256 is exercised through the HKDF path indirectly; dedicated
//!   HMAC coverage lives in the backend's internal tests because the
//!   `CryptoBackend` trait does not currently expose raw HMAC.

#![cfg(target_os = "windows")]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_cng::CngBackend;

const CKM_SHA256: u32 = 0x0000_0250;
const CKM_SHA384: u32 = 0x0000_0260;
const CKM_SHA512: u32 = 0x0000_0270;

fn backend() -> CngBackend {
    CngBackend::new(false)
}

/// SHA-256 "abc" — canonical NIST vector.
#[test]
fn sha256_abc() {
    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
    let got = backend().compute_digest(CKM_SHA256, b"abc").unwrap();
    assert_eq!(got, expected);
}

/// SHA-256 empty input.
#[test]
fn sha256_empty() {
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let got = backend().compute_digest(CKM_SHA256, b"").unwrap();
    assert_eq!(got, expected);
}

/// SHA-256 longer input.
#[test]
fn sha256_448_bit_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let expected =
        hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").unwrap();
    let got = backend().compute_digest(CKM_SHA256, msg).unwrap();
    assert_eq!(got, expected);
}

/// SHA-384 "abc" — canonical NIST vector.
#[test]
fn sha384_abc() {
    let expected = hex::decode(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    )
    .unwrap();
    let got = backend().compute_digest(CKM_SHA384, b"abc").unwrap();
    assert_eq!(got, expected);
}

#[test]
fn sha384_empty() {
    let expected = hex::decode(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
         274edebfe76f65fbd51ad2f14898b95b",
    )
    .unwrap();
    let got = backend().compute_digest(CKM_SHA384, b"").unwrap();
    assert_eq!(got, expected);
}

#[test]
fn sha384_long() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected = hex::decode(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
         fcc7c71a557e2db966c3e9fa91746039",
    )
    .unwrap();
    let got = backend().compute_digest(CKM_SHA384, msg).unwrap();
    assert_eq!(got, expected);
}

/// SHA-512 "abc" — canonical NIST vector.
#[test]
fn sha512_abc() {
    let expected = hex::decode(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )
    .unwrap();
    let got = backend().compute_digest(CKM_SHA512, b"abc").unwrap();
    assert_eq!(got, expected);
}

#[test]
fn sha512_empty() {
    let expected = hex::decode(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )
    .unwrap();
    let got = backend().compute_digest(CKM_SHA512, b"").unwrap();
    assert_eq!(got, expected);
}

#[test]
fn sha512_long() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected = hex::decode(
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    )
    .unwrap();
    let got = backend().compute_digest(CKM_SHA512, msg).unwrap();
    assert_eq!(got, expected);
}

#[test]
fn digest_output_len_matches() {
    let be = backend();
    assert_eq!(be.digest_output_len(CKM_SHA256).unwrap(), 32);
    assert_eq!(be.digest_output_len(CKM_SHA384).unwrap(), 48);
    assert_eq!(be.digest_output_len(CKM_SHA512).unwrap(), 64);
}

#[test]
fn unknown_digest_mechanism_rejected() {
    let be = backend();
    assert!(be.compute_digest(0xDEAD_BEEF, b"x").is_err());
    assert!(be.digest_output_len(0xDEAD_BEEF).is_err());
}

#[test]
fn streaming_hasher_matches_one_shot() {
    let be = backend();
    let data = b"the quick brown fox jumps over the lazy dog";

    for mech in [CKM_SHA256, CKM_SHA384, CKM_SHA512] {
        let one_shot = be.compute_digest(mech, data).unwrap();
        let mut hasher = be.create_hasher(mech).unwrap();
        // Feed in small chunks to exercise multi-part update.
        for chunk in data.chunks(5) {
            hasher.update(chunk);
        }
        let streamed = hasher.finalize();
        assert_eq!(
            streamed, one_shot,
            "streaming mismatch for mech 0x{:X}",
            mech
        );
    }
}
