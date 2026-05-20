// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Fuzz AES-256-GCM decryption on the aws-lc-rs backend.
//!
//! The input corpus entry is parsed as:
//!   [32-byte key][rest = ciphertext+nonce+tag blob as the backend sees it]
//!
//! Any `Err` from `aes_256_gcm_decrypt` is acceptable; what we're asserting
//! is that the backend never panics on adversarial input — no slice-index
//! OOB, no unwrap-on-None, no arithmetic overflow, no unexpected process
//! abort from the underlying libcrypto.

#![no_main]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_awslc::AwsLcBackend;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let (key, blob) = data.split_at(32);
    let b = AwsLcBackend::new();
    let _ = b.aes_256_gcm_decrypt(key, blob);
});
