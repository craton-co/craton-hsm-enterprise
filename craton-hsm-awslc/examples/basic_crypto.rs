// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Basic example showing how to use the Craton HSM FIPS backend.
//!
//! Run with: cargo run --example basic_crypto -p craton-hsm-awslc
//!
//! NOTE: This example requires `craton-hsm-core` to be checked out as a sibling
//! directory (see README.md). It may not compile without the core crate present.

use craton_hsm::crypto::backend::CryptoBackend;
use craton_hsm::crypto::sign::HashAlg;
use craton_hsm::pkcs11_abi::constants::CKM_SHA256;
use craton_hsm_awslc::AwsLcBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a FIPS-mode backend. Use AwsLcBackend::new() for non-FIPS mode.
    let backend = AwsLcBackend::new_fips()?;
    println!("FIPS mode: {}", backend.is_fips_mode());

    // -----------------------------------------------------------------------
    // AES-256 key generation and encryption
    // -----------------------------------------------------------------------
    let aes_key = backend.generate_aes_key(32, true)?;
    println!("Generated AES-256 key ({} bytes)", aes_key.as_bytes().len());

    let plaintext = b"Hello, Craton HSM!";
    let ciphertext = backend.aes_256_gcm_encrypt(aes_key.as_bytes(), plaintext)?;
    println!(
        "Encrypted {} bytes -> {} bytes",
        plaintext.len(),
        ciphertext.len()
    );

    let decrypted = backend.aes_256_gcm_decrypt(aes_key.as_bytes(), &ciphertext)?;
    assert_eq!(&decrypted, plaintext);
    println!("Decrypted successfully, plaintext matches.");

    // -----------------------------------------------------------------------
    // ECDSA P-256 key generation, signing, and verification
    // -----------------------------------------------------------------------
    let (ec_priv, ec_pub) = backend.generate_ec_p256_key_pair()?;
    println!("Generated EC P-256 key pair (pub {} bytes)", ec_pub.len());

    let message = b"Sign this message";
    let signature = backend.ecdsa_p256_sign(ec_priv.as_bytes(), message)?;
    println!("Signed message ({} byte signature)", signature.len());

    let valid = backend.ecdsa_p256_verify(&ec_pub, message, &signature)?;
    assert!(valid, "Signature should be valid");
    println!("Signature verified successfully.");

    // -----------------------------------------------------------------------
    // RSA key generation and signing
    // -----------------------------------------------------------------------
    let (rsa_priv, _modulus, _exponent) = backend.generate_rsa_key_pair(2048, true)?;
    println!("Generated RSA-2048 key pair");

    let rsa_sig = backend.rsa_pss_sign(rsa_priv.as_bytes(), message, HashAlg::Sha256)?;
    println!("RSA-PSS signed message ({} byte signature)", rsa_sig.len());

    // -----------------------------------------------------------------------
    // Hashing
    // -----------------------------------------------------------------------
    let digest = backend.compute_digest(CKM_SHA256, b"data to hash")?;
    println!("SHA-256 digest: {} bytes", digest.len());

    println!("\nAll operations completed successfully.");
    Ok(())
}
