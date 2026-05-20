// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//
// SoftHSM2 round-trip example.
//
// Builds a `Pkcs11PassthroughBackend` against a vendor PKCS#11 shared
// library (set via the `SOFTHSM_LIB` environment variable), generates a
// fresh AES-256 key, encrypts and decrypts a fixed plaintext using
// AES-256-GCM, and asserts the round-trip succeeds.
//
// This example compiles by default but exits early at runtime if
// `SOFTHSM_LIB` is not set, so it remains a no-op on CI hosts that do
// not have SoftHSM2 (or any other PKCS#11 library) installed. Set the
// env var to a path like `/usr/lib/softhsm/libsofthsm2.so` (Linux) or
// `C:\SoftHSM2\lib\softhsm2-x64.dll` (Windows) to actually exercise the
// path against a real token. The slot ID and PIN default to typical
// SoftHSM2 values and can be overridden via `SOFTHSM_SLOT` /
// `SOFTHSM_PIN`.
//
// Run with:
//     SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so \
//     SOFTHSM_SLOT=0 SOFTHSM_PIN=1234 \
//     cargo run --example softhsm_roundtrip -p craton-hsm-pkcs11

use std::path::PathBuf;

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_pkcs11::{Pkcs11PassthroughBackend, Pkcs11PassthroughConfig};
use zeroize::Zeroizing;

fn main() {
    let lib = match std::env::var("SOFTHSM_LIB") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            eprintln!(
                "SOFTHSM_LIB is not set; skipping round-trip. \
                 Set it to a PKCS#11 shared-library path (e.g. \
                 /usr/lib/softhsm/libsofthsm2.so) to exercise this example."
            );
            return;
        }
    };
    let slot_id: u64 = std::env::var("SOFTHSM_SLOT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let pin = Zeroizing::new(std::env::var("SOFTHSM_PIN").unwrap_or_else(|_| "1234".to_string()));

    let config = Pkcs11PassthroughConfig {
        library_path: lib,
        slot_id,
        pin,
        fips_mode: false,
        fips_vendors: Vec::new(),
        pool_size: 2,
        cache_capacity: 16,
        allow_software_keygen_fallback: false,
        gcm_max_messages_per_key: 0, // use default (2^32)
    };

    let backend = Pkcs11PassthroughBackend::new(config)
        .expect("failed to initialise PKCS#11 backend (check SOFTHSM_LIB / SLOT / PIN)");

    // 1) Generate a fresh AES-256 key. NOTE: this returns the raw key
    //    bytes (see `Pkcs11PassthroughBackend` rustdoc -- the
    //    `CryptoBackend` trait contract forces extraction). The key is
    //    deliberately discarded at end of `main`.
    let raw = backend
        .generate_aes_key(32, false)
        .expect("AES-256 keygen failed");
    let key = raw.as_bytes();
    assert_eq!(key.len(), 32, "generated AES-256 key is the wrong length");

    // 2) Round-trip a fixed plaintext through AES-256-GCM. The
    //    passthrough backend prepends the 12-byte nonce to the
    //    ciphertext, so the decrypt input is just the output of
    //    encrypt unchanged.
    let plaintext = b"craton-hsm-pkcs11 softhsm round-trip example payload";
    let ciphertext = backend
        .aes_256_gcm_encrypt(key, plaintext)
        .expect("AES-256-GCM encrypt failed");
    assert!(
        ciphertext.len() >= plaintext.len() + 12 + 16,
        "ciphertext is suspiciously short ({} bytes)",
        ciphertext.len()
    );

    let decrypted = backend
        .aes_256_gcm_decrypt(key, &ciphertext)
        .expect("AES-256-GCM decrypt failed");
    assert_eq!(
        decrypted.as_slice(),
        &plaintext[..],
        "round-trip plaintext mismatch"
    );

    eprintln!(
        "softhsm round-trip OK: {} plaintext bytes -> {} ciphertext bytes -> {} decrypted bytes",
        plaintext.len(),
        ciphertext.len(),
        decrypted.len()
    );

    // Backend is dropped here; the SessionPool destructor logs out of
    // every session and releases the token. The generated AES key bytes
    // in `raw` and `key` go out of scope and `RawKeyMaterial` zeroizes
    // on drop.
}
