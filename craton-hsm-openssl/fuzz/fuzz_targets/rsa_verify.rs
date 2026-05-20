// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Fuzz RSA PKCS#1 v1.5 signature verification on the OpenSSL backend.
//!
//! Input layout:
//!   [2 bytes: big-endian modulus length N]
//!   [N bytes: modulus]
//!   [1 byte:  exponent length E]
//!   [E bytes: public exponent]
//!   [2 bytes: big-endian signature length S]
//!   [S bytes: signature]
//!   [remaining bytes: message]

#![no_main]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm_openssl::OpenSslBackend;
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Option<(&[u8], &[u8], &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let nlen = u16::from_be_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    if rest.len() < nlen {
        return None;
    }
    let (modulus, rest) = rest.split_at(nlen);

    if rest.is_empty() {
        return None;
    }
    let elen = rest[0] as usize;
    let rest = &rest[1..];
    if rest.len() < elen {
        return None;
    }
    let (exponent, rest) = rest.split_at(elen);

    if rest.len() < 2 {
        return None;
    }
    let slen = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let rest = &rest[2..];
    if rest.len() < slen {
        return None;
    }
    let (signature, message) = rest.split_at(slen);

    Some((modulus, exponent, signature, message))
}

fuzz_target!(|data: &[u8]| {
    let Some((modulus, exponent, signature, message)) = parse(data) else {
        return;
    };
    let b = OpenSslBackend;
    let _ = b.rsa_pkcs1v15_verify(
        modulus,
        exponent,
        message,
        signature,
        Some(HashAlg::Sha256),
    );
});
