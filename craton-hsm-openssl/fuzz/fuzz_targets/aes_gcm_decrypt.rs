// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Fuzz AES-256-GCM decryption on the OpenSSL backend.
//!
//! Input layout: [32-byte key][rest = ciphertext+nonce+tag blob].
//! Any `Err` is acceptable; a panic is a bug.

#![no_main]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_openssl::OpenSslBackend;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let (key, blob) = data.split_at(32);
    let b = OpenSslBackend;
    let _ = b.aes_256_gcm_decrypt(key, blob);
});
