// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//
// !!! INSECURE MOCK — DO NOT USE IN PRODUCTION !!!
//
// This example exercises the in-memory `MockVaultBackend`, which uses
// trivially forgeable cryptography and an in-process key store. The
// crate gates the mocks behind both a Cargo feature
// (`mock-insecure-do-not-ship`) AND a runtime env var
// (`CRATON_HSM_ALLOW_MOCK=1`) precisely so this scaffolding cannot
// accidentally end up running in a real deployment.
//
//! Mock-only Vault transit roundtrip: Create → Encrypt → Decrypt → Delete.
//!
//! Demonstrates the request/response shape of
//! [`craton_hsm_cloud::vault_plugin::MockVaultBackend`] without touching
//! any real cryptography or any real Vault instance.
//!
//! Run with:
//!
//! ```text
//! CRATON_HSM_ALLOW_MOCK=1 \
//! cargo run --example mock_vault_roundtrip \
//!     -p craton-hsm-cloud \
//!     --features mock-insecure-do-not-ship,permissive-for-tests
//! ```
//!
//! Without the feature flags the example compiles to a single
//! `eprintln!` that explains how to opt in.

#[cfg(all(
    feature = "mock-insecure-do-not-ship",
    feature = "permissive-for-tests",
    feature = "vault",
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use craton_hsm_cloud::vault_plugin::{
        MockVaultBackend, VaultKeyType, VaultTransitBackend, VaultTransitConfig,
        VaultTransitRequest,
    };

    // Mocks require the runtime opt-in. Setting the env var from inside
    // the example keeps the command line short for ad-hoc runs; a
    // production-style harness would instead set it in the launching
    // shell.
    //
    // SAFETY: this is single-threaded example code. `set_var` is safe
    // here because no other thread is reading the environment.
    std::env::set_var("CRATON_HSM_ALLOW_MOCK", "1");
    std::env::set_var("CRATON_HSM_ACCEPT_MOCK_IN_RELEASE", "1");

    // Build a permissive mock backend that allows key deletion so the
    // Destroy step at the end actually succeeds.
    let config = VaultTransitConfig {
        hsm_addr: "https://localhost".to_string(),
        default_key_type: VaultKeyType::Aes256Gcm96,
        auto_rotate_period: None,
        min_decryption_version: 1,
        min_encryption_version: 0,
        deletion_allowed: true,
    };
    let backend = MockVaultBackend::with_config(config).permissive_for_tests();

    // 1. CREATE
    let resp = backend.handle_request(VaultTransitRequest::CreateKey {
        name: "example-key".into(),
        key_type: VaultKeyType::Aes256Gcm96,
        exportable: false,
    })?;
    println!("CreateKey response: {:?}", resp.data);

    // 2. ENCRYPT — plaintext must be base64-encoded.
    let plaintext_b64 = "Y3JhdG9uLWhzbS1leGFtcGxlLXBheWxvYWQ="; // "craton-hsm-example-payload"
    let enc = backend.handle_request(VaultTransitRequest::Encrypt {
        key_name: "example-key".into(),
        plaintext_b64: plaintext_b64.into(),
        context: None,
    })?;
    let ciphertext = enc
        .data
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or("ciphertext missing from Encrypt response")?
        .to_string();
    println!("Encrypt ciphertext: {ciphertext}");
    assert!(ciphertext.starts_with("vault:v1:"));

    // 3. DECRYPT
    let dec = backend.handle_request(VaultTransitRequest::Decrypt {
        key_name: "example-key".into(),
        ciphertext,
        context: None,
    })?;
    let recovered = dec
        .data
        .get("plaintext")
        .and_then(|v| v.as_str())
        .ok_or("plaintext missing from Decrypt response")?;
    assert_eq!(recovered, plaintext_b64);
    println!("Decrypt recovered original plaintext.");

    // 4. DESTROY (DeleteKey, only allowed because `deletion_allowed = true`)
    let del = backend.handle_request(VaultTransitRequest::DeleteKey {
        name: "example-key".into(),
    })?;
    println!("DeleteKey response: {:?}", del.data);

    println!(
        "\nOK: mock Vault transit Create -> Encrypt -> Decrypt -> Destroy roundtrip succeeded."
    );
    Ok(())
}

#[cfg(not(all(
    feature = "mock-insecure-do-not-ship",
    feature = "permissive-for-tests",
    feature = "vault",
)))]
fn main() {
    eprintln!(
        "This example requires the `mock-insecure-do-not-ship`, \
         `permissive-for-tests`, and `vault` features.\n\
         Re-run with: cargo run --example mock_vault_roundtrip -p craton-hsm-cloud \
         --features mock-insecure-do-not-ship,permissive-for-tests"
    );
}
