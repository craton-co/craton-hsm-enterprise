// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! End-to-end RSA-2048 PKCS#1 v1.5 sign/verify roundtrip against the
//! Windows CNG (BCrypt) backend.
//!
//! Demonstrates non-FIPS construction (`CngBackend::new(false)`), which
//! skips the power-on self-test latch — `new_fips()` requires
//! `craton-hsm-certified` to drive the KAT suite before any sign/verify
//! call will succeed, which is out of scope for a freestanding example.
//!
//! Run with:
//!
//! ```text
//! cargo run --example sign_verify -p craton-hsm-cng
//! ```
//!
//! On non-Windows targets the binary prints a message and exits 0 —
//! the CNG backend only carries a stub there.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use craton_hsm::crypto::backend::CryptoBackend;
    use craton_hsm::crypto::sign::HashAlg;
    use craton_hsm_cng::CngBackend;

    // Non-FIPS construction: BCRYPT_PROV_DISPATCH is *not* set, so the
    // POST latch does not gate sign/verify and we can drive the
    // roundtrip directly.
    let backend = CngBackend::new(false);

    // Generate an RSA-2048 key pair. `generate_rsa_key_pair` returns
    // `(private_key_der, modulus_bytes, public_exponent_bytes)`.
    let (priv_key, modulus, public_exponent) = backend.generate_rsa_key_pair(2048, false)?;
    eprintln!(
        "Generated RSA-2048 key pair (modulus {} bytes)",
        modulus.len()
    );

    let message: &[u8] = b"Craton HSM CNG sign/verify example";

    // PKCS#1 v1.5 sign with SHA-256.
    let signature =
        backend.rsa_pkcs1v15_sign(priv_key.as_bytes(), message, Some(HashAlg::Sha256))?;
    eprintln!("Produced signature ({} bytes)", signature.len());

    // Verify with the public components.
    let ok = backend.rsa_pkcs1v15_verify(
        &modulus,
        &public_exponent,
        message,
        &signature,
        Some(HashAlg::Sha256),
    )?;
    assert!(ok, "signature should verify under the matching public key");

    // Negative control: a tampered message must NOT verify.
    let mut tampered = message.to_vec();
    tampered[0] ^= 0x01;
    let bad = backend.rsa_pkcs1v15_verify(
        &modulus,
        &public_exponent,
        &tampered,
        &signature,
        Some(HashAlg::Sha256),
    )?;
    assert!(!bad, "tampered message must not verify");

    println!("OK: RSA-2048 PKCS#1 v1.5 SHA-256 sign/verify roundtrip succeeded");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("craton-hsm-cng is Windows-only; this example does nothing on non-Windows hosts.");
}
