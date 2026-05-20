// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Authentication configuration for [`AuthManager`](super::manager::AuthManager).
//!
//! This config is local to `craton-hsm-auth` rather than living in the core
//! `craton-hsm` crate, because the enterprise auth surface (MFA, dual-control,
//! external providers) is intentionally not part of the core PKCS#11 module.
//! Core stays minimal; enterprise features layer on top.

use serde::{Deserialize, Serialize};

/// Configuration for the authentication manager.
///
/// Deserialized from the `[auth]` section of the HSM config file (TOML/JSON).
/// All fields have sensible defaults so existing deployments without an
/// `[auth]` section get the legacy local-PIN behavior with no MFA.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Auth provider to use. One of: `"pin"` (default), `"ldap"`, `"oidc"`,
    /// `"certificate"`. The non-PIN providers also require an explicit
    /// per-provider config block and the corresponding cargo feature.
    pub provider: String,

    /// MFA challenge lifetime in seconds. After this many seconds an issued
    /// challenge is considered expired and cannot be used to satisfy a
    /// destructive operation.
    pub mfa_timeout_secs: u64,

    /// Whether MFA is required before destructive operations such as
    /// `C_DestroyObject`, `C_GenerateKey` (when configured), and other
    /// dual-control gated operations.
    pub require_mfa_for_destructive: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            provider: "pin".to_string(),
            mfa_timeout_secs: 300, // 5 minutes — long enough for a human, short enough to limit replay window
            require_mfa_for_destructive: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_local_pin_no_mfa() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.provider, "pin");
        assert_eq!(cfg.mfa_timeout_secs, 300);
        assert!(!cfg.require_mfa_for_destructive);
    }

    #[test]
    fn deserialize_from_json_with_partial_fields() {
        // Missing fields should fall back to defaults via #[serde(default)].
        let cfg: AuthConfig = serde_json::from_str(r#"{"provider":"ldap"}"#).unwrap();
        assert_eq!(cfg.provider, "ldap");
        assert_eq!(cfg.mfa_timeout_secs, 300);
        assert!(!cfg.require_mfa_for_destructive);
    }

    #[test]
    fn deserialize_full_config() {
        let cfg: AuthConfig = serde_json::from_str(
            r#"{"provider":"oidc","mfa_timeout_secs":120,"require_mfa_for_destructive":true}"#,
        )
        .unwrap();
        assert_eq!(cfg.provider, "oidc");
        assert_eq!(cfg.mfa_timeout_secs, 120);
        assert!(cfg.require_mfa_for_destructive);
    }
}
