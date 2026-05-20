// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Authentication provider trait.

use std::fmt;

use zeroize::Zeroizing;

use crate::rbac::role::HsmRole;
use crate::tenant::tenant::TenantId;
use craton_hsm::error::HsmResult;

/// Credentials presented for authentication.
///
/// `#[non_exhaustive]` allows new credential variants (e.g. WebAuthn,
/// Kerberos) to be added in future minor releases without breaking
/// downstream `match` arms.
///
/// # Debug redaction
///
/// A *manual* `Debug` impl is provided that elides all secret-bearing
/// fields (PIN bytes, tokens, passwords, certificate bytes).  This means
/// `{:?}` of an `AuthCredentials` is safe to log by accident.  Usernames
/// are shown only as a SHA-256-prefix hash — they are PII and must not
/// appear in logs verbatim.
#[non_exhaustive]
pub enum AuthCredentials {
    /// Standard PKCS#11 PIN-based login.
    Pin {
        /// User type: CKU_USER or CKU_SO.
        user_type: u64,
        /// The PIN bytes.
        pin: Zeroizing<Vec<u8>>,
    },
    /// OAuth2/OIDC bearer token.
    Token {
        /// The JWT bearer token.  Stored in a zeroing wrapper so it is wiped
        /// from memory when the credential is dropped.
        bearer_token: Zeroizing<String>,
    },
    /// Client certificate (from mTLS).
    Certificate {
        /// DER-encoded certificate chain.
        cert_chain: Vec<Vec<u8>>,
    },
    /// LDAP bind credentials.
    LdapBind {
        /// Username or DN. Wrapped in Zeroizing so the username is wiped from
        /// memory when the credential is dropped — usernames can include
        /// distinguishing attributes (email, DN) that are PII under GDPR/CCPA.
        username: Zeroizing<String>,
        /// Password.
        password: Zeroizing<String>,
    },
}

/// Short SHA-256-prefix hash used to reference PII (usernames) in logs.
///
/// Eight hex characters give 32 bits of uniqueness — plenty for correlating
/// log lines without leaking the original identifier.
fn pii_digest(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    hex::encode(&d[..8])
}

impl fmt::Debug for AuthCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pin { user_type, pin } => f
                .debug_struct("Pin")
                .field("user_type", user_type)
                .field("pin_len", &pin.len())
                .field("pin", &"<redacted>")
                .finish(),
            Self::Token { bearer_token } => f
                .debug_struct("Token")
                .field("token_len", &bearer_token.len())
                .field("bearer_token", &"<redacted>")
                .finish(),
            Self::Certificate { cert_chain } => f
                .debug_struct("Certificate")
                .field("chain_len", &cert_chain.len())
                .finish(),
            Self::LdapBind { username, password } => f
                .debug_struct("LdapBind")
                .field("user_hash", &pii_digest(username.as_str()))
                .field("password_len", &password.len())
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

/// Result of a successful authentication.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// The role assigned to this authenticated session.
    pub role: HsmRole,
    /// Unique user identifier (for audit trail).
    pub user_id: String,
    /// Optional tenant assignment.
    pub tenant_id: Option<TenantId>,
    /// Whether MFA is required before sensitive operations.
    pub mfa_required: bool,
}

/// Pluggable authentication provider.
///
/// Implementations authenticate credentials and return a role assignment.
/// The default `LocalPinProvider` wraps the existing PIN-based login.
pub trait AuthProvider: Send + Sync {
    /// Authenticate credentials and return the assigned identity.
    fn authenticate(&self, credentials: &AuthCredentials) -> HsmResult<AuthResult>;

    /// Human-readable name of this provider (for logging).
    fn name(&self) -> &str;

    /// Audit (design) -- post-authentication audit hook. The default
    /// implementation is a no-op so existing providers are untouched.
    /// `AuthManager::authenticate` calls this with the result of every
    /// authentication attempt (success or failure) so providers can emit
    /// structured audit events without owning the call site.
    fn on_outcome(&self, _result: &HsmResult<AuthResult>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_pin_redacts_bytes() {
        let c = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(b"super-secret-pin".to_vec()),
        };
        let s = format!("{:?}", c);
        assert!(s.contains("<redacted>"), "pin must be redacted: {s}");
        assert!(s.contains("pin_len: 16"), "length metadata kept: {s}");
        assert!(!s.contains("super-secret-pin"), "raw PIN leaked: {s}");
    }

    #[test]
    fn debug_token_redacts_bearer() {
        let c = AuthCredentials::Token {
            bearer_token: Zeroizing::new("eyJhbGciOiJIUzI1NiJ9.secret.sig".to_string()),
        };
        let s = format!("{:?}", c);
        assert!(s.contains("<redacted>"), "token must be redacted: {s}");
        assert!(
            !s.contains("eyJhbGciOiJIUzI1NiJ9"),
            "JWT header leaked: {s}"
        );
        assert!(!s.contains("secret"), "JWT body leaked: {s}");
    }

    #[test]
    fn debug_ldap_hashes_username_and_redacts_password() {
        let c = AuthCredentials::LdapBind {
            username: Zeroizing::new("alice@example.com".to_string()),
            password: Zeroizing::new("hunter2".to_string()),
        };
        let s = format!("{:?}", c);
        assert!(!s.contains("alice@example.com"), "username leaked: {s}");
        assert!(!s.contains("hunter2"), "password leaked: {s}");
        assert!(
            s.contains("<redacted>"),
            "password redaction marker missing: {s}"
        );
        assert!(s.contains("user_hash"), "user_hash field missing: {s}");
    }

    #[test]
    fn debug_certificate_shows_only_chain_length() {
        let c = AuthCredentials::Certificate {
            cert_chain: vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0x01, 0x02]],
        };
        let s = format!("{:?}", c);
        assert!(s.contains("chain_len: 2"), "chain length missing: {s}");
        assert!(!s.contains("deadbeef"), "cert bytes leaked: {s}");
    }

    #[test]
    fn pii_digest_is_stable_and_short() {
        let a = pii_digest("alice@example.com");
        let b = pii_digest("alice@example.com");
        let c = pii_digest("bob@example.com");
        assert_eq!(a, b, "digest must be deterministic");
        assert_ne!(a, c, "different inputs must differ");
        assert_eq!(a.len(), 16, "16 hex chars = 8 bytes = 64 bits");
    }
}
