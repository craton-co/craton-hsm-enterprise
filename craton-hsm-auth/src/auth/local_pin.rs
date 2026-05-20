// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Local PIN authentication provider.
//!
//! Wraps the existing `Token::login` mechanism in the `AuthProvider` trait.
//! The C ABI path continues to call `Token::login` directly (unchanged).
//! The gRPC path can use this provider for PIN-based login.
//!
//! # Security
//!
//! `LocalPinProvider` requires a `pin_verifier` callback that delegates to the
//! underlying token store's `Token::login` mechanism.  Constructing one without
//! a verifier will cause every `authenticate()` call to return
//! `HsmError::FunctionNotSupported`; it will never silently accept any PIN.

use super::provider::{AuthCredentials, AuthProvider, AuthResult};
use crate::rbac::role::HsmRole;
use craton_hsm::error::{HsmError, HsmResult};

/// Authentication provider that delegates to the existing PIN verification.
///
/// This is a lightweight adapter — the actual PIN verification (PBKDF2,
/// lockout, rate limiting) stays in `Token::login`.
///
/// Construct via [`LocalPinProvider::with_verifier`] to supply the verification
/// callback.  Using [`LocalPinProvider::new`] (no verifier) is useful only when
/// the caller guarantees PIN verification happens outside this provider (e.g.
/// in the PKCS#11 C-ABI dispatch path).
pub struct LocalPinProvider {
    /// Callback that performs the actual PIN check.
    ///
    /// Arguments: `(user_type: u64, pin: &[u8]) -> bool`
    ///
    /// Returns `true` if the PIN is correct for the given user type.
    pin_verifier: Option<Box<dyn Fn(u64, &[u8]) -> bool + Send + Sync>>,
}

impl LocalPinProvider {
    /// Create a provider with **no** PIN verifier.
    ///
    /// Every `authenticate()` call will return `Err(HsmError::FunctionNotSupported)`.
    /// Use this only when PIN checking is guaranteed to happen elsewhere.
    pub fn new() -> Self {
        Self { pin_verifier: None }
    }

    /// Create a provider backed by a concrete PIN verification callback.
    ///
    /// The callback receives `(user_type, pin_bytes)` and returns `true`
    /// if the PIN is correct.  This is normally a closure that calls
    /// `Token::login`.
    pub fn with_verifier<F>(verifier: F) -> Self
    where
        F: Fn(u64, &[u8]) -> bool + Send + Sync + 'static,
    {
        Self {
            pin_verifier: Some(Box::new(verifier)),
        }
    }
}

impl Default for LocalPinProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for LocalPinProvider {
    fn authenticate(&self, credentials: &AuthCredentials) -> HsmResult<AuthResult> {
        match credentials {
            AuthCredentials::Pin { user_type, pin } => {
                let role = match *user_type {
                    0 => HsmRole::So,   // CKU_SO = 0
                    1 => HsmRole::User, // CKU_USER = 1
                    _ => return Err(HsmError::UserTypeInvalid),
                };

                // Verify PIN using the injected callback.
                match &self.pin_verifier {
                    Some(verify) => {
                        if !verify(*user_type, pin.as_slice()) {
                            tracing::warn!(
                                user_type = *user_type,
                                "Local PIN authentication failed: incorrect PIN"
                            );
                            return Err(HsmError::PinIncorrect);
                        }
                    }
                    None => {
                        // No verifier configured — refuse rather than silently
                        // accepting an unverified PIN.
                        tracing::error!(
                            "LocalPinProvider has no pin_verifier configured; \
                             refusing PIN authentication.  Use \
                             LocalPinProvider::with_verifier() to supply a callback."
                        );
                        return Err(HsmError::FunctionNotSupported);
                    }
                }

                Ok(AuthResult {
                    role,
                    user_id: format!("local:{}", role.as_str()),
                    tenant_id: None,
                    mfa_required: false,
                })
            }
            _ => Err(HsmError::FunctionNotSupported),
        }
    }

    fn name(&self) -> &str {
        "local-pin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn test_no_verifier_returns_not_supported() {
        let provider = LocalPinProvider::new();
        let creds = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(b"anypin".to_vec()),
        };
        let result = provider.authenticate(&creds);
        assert!(matches!(
            result.unwrap_err(),
            HsmError::FunctionNotSupported
        ));
    }

    #[test]
    fn test_verifier_accepts_correct_pin() {
        let provider = LocalPinProvider::with_verifier(|_user_type, pin| pin == b"correct");
        let creds = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(b"correct".to_vec()),
        };
        let result = provider.authenticate(&creds).unwrap();
        assert_eq!(result.user_id, "local:User");
        assert!(matches!(result.role, HsmRole::User));
    }

    #[test]
    fn test_verifier_rejects_wrong_pin() {
        let provider = LocalPinProvider::with_verifier(|_user_type, pin| pin == b"correct");
        let creds = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(b"wrong".to_vec()),
        };
        let result = provider.authenticate(&creds);
        assert!(matches!(result.unwrap_err(), HsmError::PinIncorrect));
    }

    #[test]
    fn test_so_role_mapped() {
        let provider = LocalPinProvider::with_verifier(|_, _| true);
        let creds = AuthCredentials::Pin {
            user_type: 0,
            pin: Zeroizing::new(b"sopin".to_vec()),
        };
        let result = provider.authenticate(&creds).unwrap();
        assert!(matches!(result.role, HsmRole::So));
        assert_eq!(result.user_id, "local:SO");
    }

    #[test]
    fn test_invalid_user_type_rejected() {
        let provider = LocalPinProvider::with_verifier(|_, _| true);
        let creds = AuthCredentials::Pin {
            user_type: 99,
            pin: Zeroizing::new(b"pin".to_vec()),
        };
        let result = provider.authenticate(&creds);
        assert!(matches!(result.unwrap_err(), HsmError::UserTypeInvalid));
    }

    #[test]
    fn test_non_pin_credentials_rejected() {
        let provider = LocalPinProvider::new();
        let creds = AuthCredentials::Token {
            bearer_token: zeroize::Zeroizing::new("token".to_string()),
        };
        assert!(matches!(
            provider.authenticate(&creds).unwrap_err(),
            HsmError::FunctionNotSupported
        ));
    }
}
