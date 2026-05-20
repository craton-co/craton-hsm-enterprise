// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Concurrency soundness test for the CNG backend.
//!
//! This validates fix CNG-1 (KeyHandle `Send + Sync` soundness): 8 threads
//! concurrently sign messages using the same `Arc<dyn CryptoBackend>`. The
//! `CngBackend` trait methods each import their own per-call `KeyHandle`,
//! so no handle is actually shared across threads — the invariant that
//! `KeyHandle` is NOT `Send + Sync` is upheld by design.
//!
//! If the backend ever regresses to sharing a `KeyHandle` across threads,
//! this test would likely flake or crash under `Arc<dyn CryptoBackend>`
//! because `dyn CryptoBackend: Send + Sync` forces soundness-breaking
//! concurrent access on the inner handle.

#![cfg(target_os = "windows")]

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm_cng::CngBackend;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;
use std::thread;

fn gen_rsa_2048() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    (
        priv_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        pub_key.n().to_bytes_be(),
        pub_key.e().to_bytes_be(),
    )
}

#[test]
fn eight_threads_rsa_sign_concurrently() {
    let (priv_der, n, e) = gen_rsa_2048();
    let priv_der = Arc::new(priv_der);
    let n = Arc::new(n);
    let e = Arc::new(e);

    let backend: Arc<dyn CryptoBackend> = Arc::new(CngBackend::new(false));

    let mut handles = Vec::new();
    for tid in 0..8u32 {
        let be = Arc::clone(&backend);
        let priv_der = Arc::clone(&priv_der);
        let n = Arc::clone(&n);
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            for i in 0..20u32 {
                let msg = format!("thread {tid} op {i}");
                let sig = be
                    .rsa_pkcs1v15_sign(&priv_der, msg.as_bytes(), Some(HashAlg::Sha256))
                    .expect("sign");
                let ok = be
                    .rsa_pkcs1v15_verify(&n, &e, msg.as_bytes(), &sig, Some(HashAlg::Sha256))
                    .expect("verify");
                assert!(ok, "verify failed on thread {tid} op {i}");
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn eight_threads_aes_gcm_concurrently() {
    let backend: Arc<dyn CryptoBackend> = Arc::new(CngBackend::new(false));
    let key = Arc::new([0xCDu8; 32]);

    let mut handles = Vec::new();
    for tid in 0..8u32 {
        let be = Arc::clone(&backend);
        let key = Arc::clone(&key);
        handles.push(thread::spawn(move || {
            for i in 0..50u32 {
                let pt = format!("thread {tid} message {i}").into_bytes();
                let ct = be.aes_256_gcm_encrypt(&*key, &pt).expect("enc");
                let round = be.aes_256_gcm_decrypt(&*key, &ct).expect("dec");
                assert_eq!(round, pt);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn eight_threads_hashing_concurrently() {
    const CKM_SHA256: u32 = 0x0000_0250;
    let backend: Arc<dyn CryptoBackend> = Arc::new(CngBackend::new(false));

    let mut handles = Vec::new();
    for tid in 0..8u32 {
        let be = Arc::clone(&backend);
        handles.push(thread::spawn(move || {
            for i in 0..200u32 {
                let data = [tid.to_be_bytes(), i.to_be_bytes()].concat();
                let h = be.compute_digest(CKM_SHA256, &data).expect("hash");
                assert_eq!(h.len(), 32);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}
