// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Basic example showing PIN authentication with Craton HSM auth.
//!
//! Run with: cargo run --example basic_auth -p craton-hsm-auth
//!
//! NOTE: This example requires `craton-hsm-core` to be checked out as a sibling
//! directory (see README.md). It may not compile without the core crate present.

use craton_hsm_auth::auth::config::AuthConfig;
use craton_hsm_auth::auth::manager::AuthManager;
use craton_hsm_auth::auth::provider::AuthCredentials;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Configure the auth system (defaults to local PIN provider)
    // -----------------------------------------------------------------------
    let config = AuthConfig::default();
    let manager = AuthManager::new(&config)?;
    println!("AuthManager initialized (provider: PIN)");

    // -----------------------------------------------------------------------
    // 2. Authenticate with a PIN
    // -----------------------------------------------------------------------
    // In a real deployment the PIN verifier callback would delegate to
    // Token::login in craton-hsm-core. Here we show the API surface.
    let credentials = AuthCredentials::Pin {
        user_type: 1, // CKU_USER
        pin: Zeroizing::new(b"example-pin-value".to_vec()),
    };

    match manager.authenticate(&credentials) {
        Ok(identity) => {
            println!("Authenticated as: {:?}", identity);
        }
        Err(e) => {
            // Expected when no real token store is attached.
            println!("Authentication returned error (expected without token store): {e}");
        }
    }

    // -----------------------------------------------------------------------
    // 3. MFA configuration example
    // -----------------------------------------------------------------------
    let mfa_config = AuthConfig {
        require_mfa_for_destructive: true,
        ..AuthConfig::default()
    };
    let mfa_manager = AuthManager::new(&mfa_config)?;

    let session_handle: u64 = 42;
    match mfa_manager.check_mfa_for_destructive(session_handle) {
        Ok(()) => println!("MFA check passed for session {session_handle}"),
        Err(e) => println!("MFA required before destructive ops: {e}"),
    }

    println!("\nAuth example completed.");
    Ok(())
}
