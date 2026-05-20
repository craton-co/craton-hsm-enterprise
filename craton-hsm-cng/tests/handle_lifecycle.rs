// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Handle lifecycle stress test for the CNG backend.
//!
//! Round-trips many crypto operations in quick succession to exercise the
//! RAII handle wrappers (`AlgHandle`, `KeyHandle`, `HashHandle`). Without
//! Application Verifier it is impossible to directly observe a leaked
//! BCrypt handle, but repeated create/destroy cycles will fail under common
//! corruption patterns (double-free aborts the process, leaks eventually
//! exhaust the CNG provider cache, stale handles return INVALID_HANDLE
//! NTSTATUS).

#![cfg(target_os = "windows")]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_cng::CngBackend;

const CKM_SHA256: u32 = 0x0000_0250;

#[test]
fn thousand_hash_operations_no_leak() {
    let be = CngBackend::new(false);
    for i in 0..1000u32 {
        let data = i.to_be_bytes();
        let hash = be
            .compute_digest(CKM_SHA256, &data)
            .unwrap_or_else(|e| panic!("hash {i} failed: {e:?}"));
        assert_eq!(hash.len(), 32);
    }
}

#[test]
fn thousand_aes_gcm_operations_no_leak() {
    let be = CngBackend::new(false);
    let key = [0x42u8; 32];
    for i in 0..1000u32 {
        let plaintext = i.to_le_bytes();
        let ct = be
            .aes_256_gcm_encrypt(&key, &plaintext)
            .unwrap_or_else(|e| panic!("encrypt {i} failed: {e:?}"));
        let pt = be
            .aes_256_gcm_decrypt(&key, &ct)
            .unwrap_or_else(|e| panic!("decrypt {i} failed: {e:?}"));
        assert_eq!(pt, plaintext);
    }
}

#[test]
fn thousand_streaming_hashers_no_leak() {
    let be = CngBackend::new(false);
    for i in 0..1000u32 {
        let mut h = be.create_hasher(CKM_SHA256).unwrap();
        h.update(&i.to_be_bytes());
        let out = h.finalize();
        assert_eq!(out.len(), 32);
    }
}

#[test]
fn backend_drop_and_recreate() {
    // Exercise the CngBackend RAII path: create, use, drop, repeat.
    for _ in 0..50 {
        let be = CngBackend::new(false);
        let _ = be.compute_digest(CKM_SHA256, b"x").unwrap();
        drop(be);
    }
}
