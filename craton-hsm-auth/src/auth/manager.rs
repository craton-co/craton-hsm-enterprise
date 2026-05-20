// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Authentication manager — dispatches to the configured auth provider
//! and integrates MFA enforcement.

use std::sync::Arc;

use super::config::AuthConfig;
use super::local_pin::LocalPinProvider;
use super::mfa::{MfaChallengeType, MfaManager};
use super::provider::{AuthCredentials, AuthProvider, AuthResult};
#[cfg(feature = "cert-auth")]
use crate::auth::cert::CertConfig;
#[cfg(feature = "ldap-auth")]
use crate::auth::ldap::LdapConfig;
#[cfg(feature = "oidc-auth")]
use crate::auth::oidc::OidcConfig;
use craton_hsm::error::{HsmError, HsmResult};

/// Central authentication manager that wraps a configured provider and MFA.
pub struct AuthManager {
    /// The active authentication provider.
    provider: Arc<dyn AuthProvider>,
    /// MFA challenge manager.
    pub mfa: MfaManager,
    /// Whether MFA is required for destructive operations.
    require_mfa_for_destructive: bool,
}

/// Audit (design) -- structured selector for the active auth backend.
/// Each variant carries the provider-specific config so callers cannot
/// forget to pass it; previously the matrix of `new_with_*`
/// constructors and the string `provider` field could disagree.
#[non_exhaustive]
pub enum AuthProviderChoice {
    /// Local PKCS#11 PIN authentication.
    Pin,
    /// LDAP / Active Directory bind. Requires the `ldap-auth` feature.
    #[cfg(feature = "ldap-auth")]
    Ldap(LdapConfig),
    /// OAuth2 / OIDC bearer token. Requires the `oidc-auth` feature.
    #[cfg(feature = "oidc-auth")]
    Oidc(OidcConfig),
    /// mTLS client certificate. Requires the `cert-auth` feature.
    #[cfg(feature = "cert-auth")]
    Cert(CertConfig),
}

impl AuthManager {
    /// Create an AuthManager from configuration.
    ///
    /// Only the local PIN provider is constructible from a bare
    /// [`AuthConfig`] because every other provider requires a typed
    /// provider-specific config (`LdapConfig`, `OidcConfig`, `CertConfig`)
    /// that cannot be expressed in a plain string.  Accepts
    /// `config.provider == "pin"` or the empty string (default).  Any
    /// other value is rejected with [`HsmError::ArgumentsBad`]; use
    /// [`Self::from_config`] (or the per-provider
    /// `new_with_ldap` / `new_with_oidc` / `new_with_cert` constructors)
    /// to build a non-PIN provider.
    pub fn new(config: &AuthConfig) -> HsmResult<Self> {
        let provider: Arc<dyn AuthProvider> = match config.provider.as_str() {
            "pin" | "" => {
                tracing::info!("Auth provider: local-pin");
                Arc::new(LocalPinProvider::new())
            }
            other => {
                tracing::error!(
                    provider = %other,
                    "Auth provider '{}' is not constructible from AuthConfig alone. \
                     Use AuthManager::from_config (with the typed AuthProviderChoice) \
                     or the matching new_with_* constructor.",
                    other
                );
                return Err(HsmError::ArgumentsBad);
            }
        };

        Ok(Self {
            provider,
            mfa: MfaManager::new(config.mfa_timeout_secs),
            require_mfa_for_destructive: config.require_mfa_for_destructive,
        })
    }

    /// Create with a specific provider (for testing or advanced configuration).
    pub fn with_provider(provider: Arc<dyn AuthProvider>, config: &AuthConfig) -> Self {
        Self {
            provider,
            mfa: MfaManager::new(config.mfa_timeout_secs),
            require_mfa_for_destructive: config.require_mfa_for_destructive,
        }
    }

    /// Audit (design) -- single typed entry-point that bundles the
    /// `AuthConfig` with whichever provider-specific config the operator
    /// chose. Replaces the matrix of `new_with_ldap` / `new_with_oidc` /
    /// `new_with_cert` constructors when the caller already has a
    /// concrete provider config in hand.
    ///
    /// The `Pin` variant constructs a `LocalPinProvider` with no
    /// verifier; production callers should follow up with
    /// `LocalPinProvider::with_verifier` and `with_provider`.
    pub fn from_config(auth_config: &AuthConfig, choice: AuthProviderChoice) -> HsmResult<Self> {
        match choice {
            AuthProviderChoice::Pin => {
                tracing::info!("Auth provider: local-pin (no verifier wired)");
                Ok(Self {
                    provider: Arc::new(LocalPinProvider::new()),
                    mfa: MfaManager::new(auth_config.mfa_timeout_secs),
                    require_mfa_for_destructive: auth_config.require_mfa_for_destructive,
                })
            }
            #[cfg(feature = "ldap-auth")]
            AuthProviderChoice::Ldap(ldap_config) => Self::new_with_ldap(ldap_config, auth_config),
            #[cfg(feature = "oidc-auth")]
            AuthProviderChoice::Oidc(oidc_config) => Self::new_with_oidc(oidc_config, auth_config),
            #[cfg(feature = "cert-auth")]
            AuthProviderChoice::Cert(cert_config) => Self::new_with_cert(cert_config, auth_config),
        }
    }

    /// Create an AuthManager backed by the LDAP provider.
    ///
    /// Requires the `ldap-auth` feature.  Returns an error rather than
    /// panicking on invalid `LdapConfig` (e.g. a `bind_dn_template` missing
    /// its `{}` placeholder, or `tls_mode = none` without the operator's
    /// explicit `allow_plaintext` opt-in).  The previous implementation
    /// called `LdapAuthProvider::new` directly, which terminates the
    /// process on validation failure — fine for an interactive operator,
    /// dangerous when the config arrives over the gRPC management API.
    #[cfg(feature = "ldap-auth")]
    pub fn new_with_ldap(ldap_config: LdapConfig, auth_config: &AuthConfig) -> HsmResult<Self> {
        use crate::auth::ldap::LdapAuthProvider;
        tracing::info!("Auth provider: ldap");
        let provider = Arc::new(LdapAuthProvider::try_new(ldap_config)?);
        Ok(Self {
            provider,
            mfa: MfaManager::new(auth_config.mfa_timeout_secs),
            require_mfa_for_destructive: auth_config.require_mfa_for_destructive,
        })
    }

    /// Create an AuthManager backed by the OIDC provider.
    ///
    /// Requires the `oidc-auth` feature.
    #[cfg(feature = "oidc-auth")]
    pub fn new_with_oidc(oidc_config: OidcConfig, auth_config: &AuthConfig) -> HsmResult<Self> {
        use crate::auth::oidc::OidcAuthProvider;
        tracing::info!("Auth provider: oidc");
        let provider = Arc::new(OidcAuthProvider::new(oidc_config)?);
        Ok(Self {
            provider,
            mfa: MfaManager::new(auth_config.mfa_timeout_secs),
            require_mfa_for_destructive: auth_config.require_mfa_for_destructive,
        })
    }

    /// Create an AuthManager backed by the certificate provider.
    ///
    /// Requires the `cert-auth` feature.
    #[cfg(feature = "cert-auth")]
    pub fn new_with_cert(cert_config: CertConfig, auth_config: &AuthConfig) -> HsmResult<Self> {
        use crate::auth::cert::CertAuthProvider;
        tracing::info!("Auth provider: certificate");
        let provider = Arc::new(CertAuthProvider::new(cert_config));
        Ok(Self {
            provider,
            mfa: MfaManager::new(auth_config.mfa_timeout_secs),
            require_mfa_for_destructive: auth_config.require_mfa_for_destructive,
        })
    }

    /// Authenticate credentials via the configured provider.
    ///
    /// Audit (design) -- after the provider returns we invoke the
    /// `on_outcome` hook so audit-emitting wrappers can run without
    /// owning the call site. The default trait impl is a no-op.
    #[tracing::instrument(level = "info", skip(self, credentials), fields(provider = self.provider.name()))]
    pub fn authenticate(&self, credentials: &AuthCredentials) -> HsmResult<AuthResult> {
        let outcome = self.provider.authenticate(credentials);
        self.provider.on_outcome(&outcome);
        outcome
    }

    /// Returns the name of the active auth provider.
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Check if MFA is required for a destructive operation.
    ///
    /// Returns `Err(crate::error::mfa_required())` (mapped to
    /// `HsmError::UserNotLoggedIn`) when MFA is required by configuration but
    /// has not yet been completed for the given session. See
    /// [`crate::error`] for the rationale behind the variant mapping.
    pub fn check_mfa_for_destructive(&self, session_handle: u64) -> HsmResult<()> {
        if self.require_mfa_for_destructive && !self.mfa.has_completed_challenge(session_handle) {
            return Err(crate::error::mfa_required());
        }
        Ok(())
    }

    /// Issue an MFA challenge for a session.
    ///
    /// For `ReenterPin` challenges, pass the expected PIN in `expected_pin`
    /// so the manager can verify the response later.
    pub fn issue_mfa_challenge(
        &self,
        session_handle: u64,
        user_id: &str,
        challenge_type: MfaChallengeType,
        expected_pin: Option<&[u8]>,
    ) -> super::mfa::MfaChallenge {
        self.mfa
            .issue_challenge(session_handle, user_id, challenge_type, expected_pin)
    }

    /// Verify an MFA response.
    pub fn verify_mfa(
        &self,
        challenge_id: &str,
        session_handle: u64,
        response: &[u8],
    ) -> HsmResult<()> {
        self.mfa.verify(challenge_id, session_handle, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::AuthCredentials;
    use zeroize::Zeroizing;

    #[test]
    fn test_default_provider_is_pin() {
        let config = AuthConfig::default();
        let mgr = AuthManager::new(&config).unwrap();
        assert_eq!(mgr.provider_name(), "local-pin");
    }

    #[test]
    fn test_authenticate_pin_user() {
        let config = AuthConfig::default();
        let provider = crate::auth::local_pin::LocalPinProvider::with_verifier(|_, _| true);
        let mgr = AuthManager::with_provider(Arc::new(provider), &config);

        let creds = AuthCredentials::Pin {
            user_type: 1, // CKU_USER
            pin: Zeroizing::new(b"test1234".to_vec()),
        };
        let result = mgr.authenticate(&creds).unwrap();
        assert_eq!(result.user_id, "local:User");
    }

    #[test]
    fn test_authenticate_pin_user_wrong_pin() {
        let config = AuthConfig::default();
        // Verifier always returns false — wrong pin.
        let provider = crate::auth::local_pin::LocalPinProvider::with_verifier(|_, _| false);
        let mgr = AuthManager::with_provider(Arc::new(provider), &config);

        let creds = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(b"wrongpin".to_vec()),
        };
        let result = mgr.authenticate(&creds);
        assert!(matches!(result.unwrap_err(), HsmError::PinIncorrect));
    }

    #[test]
    fn test_authenticate_pin_so() {
        let config = AuthConfig::default();
        let provider = crate::auth::local_pin::LocalPinProvider::with_verifier(|_, _| true);
        let mgr = AuthManager::with_provider(Arc::new(provider), &config);

        let creds = AuthCredentials::Pin {
            user_type: 0, // CKU_SO
            pin: Zeroizing::new(b"so_pin_1234".to_vec()),
        };
        let result = mgr.authenticate(&creds).unwrap();
        assert_eq!(result.user_id, "local:SO");
    }

    #[test]
    fn test_unknown_provider_returns_error() {
        let config = AuthConfig {
            provider: "nonexistent".to_string(),
            ..AuthConfig::default()
        };
        let result = AuthManager::new(&config);
        // `AuthManager` deliberately does not implement `Debug` (it holds
        // secrets), so we cannot `unwrap_err()`. Match on the `Result`
        // directly instead.
        match result {
            Err(HsmError::ArgumentsBad) => {}
            Err(other) => panic!("expected ArgumentsBad, got {other:?}"),
            Ok(_) => panic!("expected an error for an unknown provider"),
        }
    }

    #[test]
    fn test_mfa_not_required_by_default() {
        let config = AuthConfig::default();
        let mgr = AuthManager::new(&config).unwrap();
        // Should pass — MFA not required
        assert!(mgr.check_mfa_for_destructive(42).is_ok());
    }

    #[test]
    fn test_mfa_required_blocks_without_challenge() {
        let config = AuthConfig {
            require_mfa_for_destructive: true,
            ..AuthConfig::default()
        };
        let mgr = AuthManager::new(&config).unwrap();
        // Should fail — MFA required but no challenge completed
        let err = mgr.check_mfa_for_destructive(42);
        assert!(err.is_err());
    }

    #[test]
    fn test_custom_provider() {
        struct TestProvider;
        impl AuthProvider for TestProvider {
            fn authenticate(&self, _creds: &AuthCredentials) -> HsmResult<AuthResult> {
                Ok(AuthResult {
                    role: crate::rbac::role::HsmRole::Auditor,
                    user_id: "test:auditor".to_string(),
                    tenant_id: None,
                    mfa_required: false,
                })
            }
            fn name(&self) -> &str {
                "test"
            }
        }

        let config = AuthConfig::default();
        let mgr = AuthManager::with_provider(Arc::new(TestProvider), &config);
        assert_eq!(mgr.provider_name(), "test");

        let creds = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(b"whatever".to_vec()),
        };
        let result = mgr.authenticate(&creds).unwrap();
        assert_eq!(result.user_id, "test:auditor");
    }
}
