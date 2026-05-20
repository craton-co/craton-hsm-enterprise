// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Pluggable authentication providers for enterprise HSM deployments.
//!
//! The default `LocalPinProvider` wraps the existing PKCS#11 PIN-based
//! login. External providers (LDAP, OIDC, certificate) can be configured
//! via the auth config section.
//!
//! # Example: PIN authentication
//!
//! ```no_run
//! use craton_hsm_auth::auth::{AuthConfig, manager::AuthManager, provider::AuthCredentials};
//! use zeroize::Zeroizing;
//!
//! let config = AuthConfig::default(); // provider = "pin"
//! let mgr = AuthManager::new(&config).expect("init auth manager");
//!
//! let creds = AuthCredentials::Pin {
//!     user_type: 1, // CKU_USER
//!     pin: Zeroizing::new(b"correct horse battery staple".to_vec()),
//! };
//! let _identity = mgr.authenticate(&creds);
//! ```
//!
//! # Example: requiring MFA before destructive ops
//!
//! ```no_run
//! use craton_hsm_auth::auth::{AuthConfig, manager::AuthManager, mfa::MfaChallengeType};
//!
//! let config = AuthConfig {
//!     require_mfa_for_destructive: true,
//!     ..AuthConfig::default()
//! };
//! let mgr = AuthManager::new(&config).unwrap();
//!
//! // The session must complete an MFA challenge before destructive ops
//! // are permitted; otherwise check_mfa_for_destructive returns an error.
//! let session_handle: u64 = 42;
//! let _challenge = mgr.issue_mfa_challenge(
//!     session_handle,
//!     "alice",
//!     MfaChallengeType::ReenterPin,
//!     Some(b"correct horse battery staple"),
//! );
//! // ... user submits response ...
//! // mgr.verify_mfa(&challenge.id, session_handle, response)?;
//! assert!(mgr.check_mfa_for_destructive(session_handle).is_err()); // not yet completed
//! ```

pub mod cert;
pub mod config;
pub mod ldap;
pub mod local_pin;
pub mod manager;
pub mod mfa;
pub mod oidc;
pub mod provider;
pub mod rate_limit;

pub use config::AuthConfig;

use crate::rbac::role::HsmRole;

/// Canonical role-name parser shared by every provider.
///
/// Audit (design): previously each of `cert.rs`, `ldap.rs`, and `oidc.rs`
/// carried its own `parse_role` helper with subtly different case
/// handling — `cert.rs` and `oidc.rs` used `to_lowercase()`,
/// `ldap.rs` used exact matches with capitalised variants. Identical role
/// strings could therefore parse differently depending on the active
/// provider, which is exactly the kind of inconsistency RBAC must not
/// tolerate. This single helper accepts the union of all previously-valid
/// spellings, normalised to ASCII lowercase.
pub(crate) fn parse_role(role_str: &str) -> Option<HsmRole> {
    match role_str.trim().to_ascii_lowercase().as_str() {
        "user" => Some(HsmRole::User),
        "so" | "security_officer" | "securityofficer" => Some(HsmRole::So),
        "auditor" => Some(HsmRole::Auditor),
        "keymanager" | "key_manager" => Some(HsmRole::KeyManager),
        "operator" => Some(HsmRole::Operator),
        _ => None,
    }
}
