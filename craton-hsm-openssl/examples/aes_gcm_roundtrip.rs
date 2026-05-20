// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! AES-256-GCM key generation, encrypt, decrypt roundtrip against the
//! OpenSSL backend.
//!
//! Requires system OpenSSL (1.1.1 or 3.x) — the `openssl` crate that
//! `craton-hsm-openssl` links to does not vendor a copy on every host,
//! so plain Windows targets without OpenSSL installed will fail to
//! link. On Linux/macOS hosts with `openssl-dev` / `openssl@3` this
//! example builds and runs without extra configuration.
//!
//! Run with:
//!
//! ```text
//! cargo run --example aes_gcm_roundtrip -p craton-hsm-openssl
//! ```
//!
//! The example uses the non-FIPS constructor; the FIPS-mode
//! constructor (`OpenSslBackend::new_fips()`) is gated against the
//! linked OpenSSL provider's FIPS state and would refuse if the
//! environment variable `CRATON_HSM_REQUIRE_FIPS=1` were set without a
//! FIPS-enabled OpenSSL.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm_openssl::OpenSslBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = OpenSslBackend;

    // Generate a random AES-256 key (32 bytes). `fips_mode = false`
    // skips the strict FIPS posture check; the example does not need
    // it.
    let key = backend.generate_aes_key(32, false)?;
    eprintln!("Generated AES-256 key ({} bytes)", key.as_bytes().len());

    let plaintext: &[u8] = b"OpenSSL backend AES-256-GCM roundtrip example payload";

    // Encrypt — `aes_256_gcm_encrypt` produces a fresh random 96-bit
    // nonce on every call and packs `nonce || ciphertext || tag`.
    let ciphertext = backend.aes_256_gcm_encrypt(key.as_bytes(), plaintext)?;
    eprintln!(
        "Encrypted {} bytes of plaintext -> {} bytes of ciphertext+nonce+tag",
        plaintext.len(),
        ciphertext.len(),
    );

    // Decrypt back and assert byte equality.
    let recovered = backend.aes_256_gcm_decrypt(key.as_bytes(), &ciphertext)?;
    assert_eq!(recovered.as_slice(), plaintext, "roundtrip must match");

    println!("OK: AES-256-GCM encrypt/decrypt roundtrip succeeded.");
    Ok(())
}
