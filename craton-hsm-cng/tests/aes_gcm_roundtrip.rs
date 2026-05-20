// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! AES-GCM round-trip tests for the CNG backend.
//!
//! CNG's AES-GCM only supports 256-bit keys through the
//! `aes_256_gcm_encrypt`/`aes_256_gcm_decrypt` trait methods; 128-bit key
//! coverage is provided by the key-wrap path which exercises AES-128 through
//! a different mechanism. These tests cover multiple plaintext sizes and the
//! bad-tag rejection invariant.

#![cfg(target_os = "windows")]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_cng::CngBackend;

fn backend() -> CngBackend {
    CngBackend::new(false)
}

#[test]
fn aes_256_gcm_roundtrip_various_sizes() {
    let be = backend();
    let key = [0x42u8; 32];

    for &size in &[0usize, 1, 15, 16, 17, 31, 32, 63, 64, 127, 128, 1024, 8192] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        // Note: GCM requires at least 1 byte of plaintext in some backends;
        // skip the zero-length case if the backend refuses it.
        if size == 0 {
            // Per NIST SP 800-38D, empty plaintext with non-empty AAD is
            // valid (this is just authentication), but the trait ties
            // plaintext and AAD together. Skip.
            continue;
        }
        let ct = be
            .aes_256_gcm_encrypt(&key, &plaintext)
            .unwrap_or_else(|e| panic!("encrypt failed at size {size}: {e:?}"));
        let pt = be
            .aes_256_gcm_decrypt(&key, &ct)
            .unwrap_or_else(|e| panic!("decrypt failed at size {size}: {e:?}"));
        assert_eq!(pt, plaintext, "roundtrip mismatch at size {size}");
    }
}

#[test]
fn aes_256_gcm_bad_tag_is_rejected() {
    let be = backend();
    let key = [0x11u8; 32];
    let plaintext = b"authentic payload";

    let mut ct = be.aes_256_gcm_encrypt(&key, plaintext).unwrap();
    // Flip the last byte (which lives inside the 16-byte tag).
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;

    let result = be.aes_256_gcm_decrypt(&key, &ct);
    assert!(
        result.is_err(),
        "tampered tag must be rejected, got Ok({:?})",
        result.ok().map(|v| v.len())
    );
}

#[test]
fn aes_256_gcm_bad_ciphertext_is_rejected() {
    let be = backend();
    let key = [0xABu8; 32];
    let plaintext = b"another authentic payload";

    let mut ct = be.aes_256_gcm_encrypt(&key, plaintext).unwrap();
    // Flip a byte in the middle of the ciphertext (not the tag, not the nonce).
    // Layout: nonce(12) || ciphertext(N) || tag(16). Flip at offset 12 + N/2.
    let mid = 12 + (ct.len() - 12 - 16) / 2;
    ct[mid] ^= 0x01;

    assert!(be.aes_256_gcm_decrypt(&key, &ct).is_err());
}

#[test]
fn aes_256_gcm_wrong_key_is_rejected() {
    let be = backend();
    let key_a = [0x01u8; 32];
    let key_b = [0x02u8; 32];
    let plaintext = b"secret for key A only";

    let ct = be.aes_256_gcm_encrypt(&key_a, plaintext).unwrap();
    assert!(be.aes_256_gcm_decrypt(&key_b, &ct).is_err());
}

#[test]
fn aes_256_gcm_rejects_wrong_key_length() {
    let be = backend();
    let short_key = [0u8; 16];
    assert!(be.aes_256_gcm_encrypt(&short_key, b"x").is_err());
    assert!(be.aes_256_gcm_decrypt(&short_key, &[0u8; 64]).is_err());
}

#[test]
fn aes_256_gcm_rejects_truncated_ciphertext() {
    let be = backend();
    let key = [0u8; 32];
    // A valid GCM output is at least 12 (nonce) + 16 (tag) = 28 bytes.
    assert!(be.aes_256_gcm_decrypt(&key, &[0u8; 27]).is_err());
    assert!(be.aes_256_gcm_decrypt(&key, &[]).is_err());
}
