// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Per-session identity context for RBAC.

use std::sync::OnceLock;

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::role::HsmRole;

/// Audit fix 1.2: the historical implementation embedded the raw
/// `session_handle` directly in the user_id, which leaked the handle
/// counter -- handles are predictable (small, monotonic) so an attacker
/// who can read one user_id can guess adjacent values. Mix in 16 bytes
/// of OS-provided randomness, cached per handle so concurrent calls
/// for the same session see a stable value, and never reuse it across
/// distinct handles.
fn pkcs11_random_suffix_for(handle: u64) -> String {
    static CACHE: OnceLock<DashMap<u64, [u8; 16]>> = OnceLock::new();
    let cache = CACHE.get_or_init(DashMap::new);
    if let Some(existing) = cache.get(&handle) {
        return hex::encode(*existing);
    }
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    cache.insert(handle, bytes);
    hex::encode(bytes)
}

/// 16 raw bytes of opaque per-session token entropy supplied by an
/// external producer (typically `craton-hsm-pkcs11`'s `pool::SessionToken`).
///
/// `craton-hsm-auth` deliberately does **not** depend on `craton-hsm-pkcs11`
/// (that direction would risk a dependency cycle), so the bridge is a
/// fixed-size byte array. The pkcs11 crate provides a
/// `From<pool::SessionToken> for [u8; 16]` impl for the embedder to
/// wire the two together at the call site.
pub type SessionTokenBytes = [u8; 16];

/// Type alias for a `SessionIdentity` constructed for a PKCS#11 session.
///
/// Use the [`SessionIdentity::from_session_token`] (deterministic, takes a
/// caller-supplied [`SessionTokenBytes`]) and
/// [`SessionIdentity::new_with_random_token`] (mints fresh entropy via
/// `OsRng`) constructors to build one.
pub type Pkcs11Identity = SessionIdentity;

/// How the session was authenticated.
///
/// `#[non_exhaustive]` reserves the right to add new auth methods
/// (e.g. WebAuthn, Kerberos) in future minor releases without
/// breaking downstream `match` arms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthMethod {
    /// Standard PKCS#11 PIN-based login.
    Pin,
    /// LDAP/Active Directory bind.
    Ldap,
    /// OAuth2/OIDC bearer token.
    Oidc,
    /// mTLS client certificate.
    Certificate,
}

/// Identity context attached to a session after authentication.
///
/// This is an additional layer on top of the PKCS#11 `SessionState` enum.
/// The existing state machine (RoPublic/RoUser/RwUser/RwSO) is unchanged
/// and continues to drive PKCS#11 compliance. This struct adds enterprise
/// identity information for RBAC enforcement and audit enrichment.
#[derive(Debug, Clone)]
pub struct SessionIdentity {
    /// The role assigned to this session.
    pub role: HsmRole,
    /// Optional user identifier (for audit trail).
    /// Set by external auth providers; None for standard PIN login.
    pub user_id: Option<String>,
    /// Optional tenant identifier (for multi-tenant isolation).
    /// Set by external auth or gRPC metadata.
    pub tenant_id: Option<String>,
    /// How this session was authenticated.
    pub auth_method: AuthMethod,
}

impl SessionIdentity {
    /// Create a PKCS#11 user identity from an externally-supplied
    /// [`SessionTokenBytes`] (the natural producer is `craton-hsm-pkcs11`'s
    /// `pool::SessionToken`). The hex encoding of `token` becomes the
    /// suffix of the synthetic `user_id`, so two callers passing identical
    /// `(handle, token)` produce identical identities -- which is what
    /// embedders want when they need a stable PKCS#11 identity across the
    /// life of a single session.
    ///
    /// Prefer this over [`SessionIdentity::pkcs11_user`] / [`SessionIdentity::new_with_random_token`]
    /// whenever the embedder already owns an opaque session token: it lets
    /// the same map key flow through `auth`'s no-self-approval check, the
    /// audit log, and the pkcs11 backend's `PoolGcmCounters` /
    /// `PoolCtrCounters` without the auth crate having to depend on the
    /// pkcs11 crate.
    pub fn from_session_token(handle: u64, token: SessionTokenBytes) -> Self {
        Self {
            role: HsmRole::User,
            user_id: Some(format!("pkcs11:user:{}:{}", handle, hex::encode(token))),
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        }
    }

    /// Create a PKCS#11 user identity, minting a fresh 16-byte token via
    /// the operating-system CSPRNG.
    ///
    /// This is the moral equivalent of [`SessionIdentity::pkcs11_user`] but
    /// without the per-process handle-to-token DashMap: each call yields a
    /// brand-new token even for the same `handle`. Use this when the
    /// embedder does not yet have an opaque session token to hand in.
    pub fn new_with_random_token(handle: u64) -> Self {
        let mut bytes: SessionTokenBytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self::from_session_token(handle, bytes)
    }

    /// Create an identity for a standard PKCS#11 CKU_USER login.
    ///
    /// `session_handle` is mixed into a synthetic `user_id` so dual-control
    /// approval can distinguish two concurrent CKU_USER sessions.  Without
    /// a unique user_id, the no-self-approval check would treat every PKCS#11
    /// session as the same anonymous principal — and silently disable
    /// dual-control entirely.
    pub fn pkcs11_user(session_handle: u64) -> Self {
        // Audit fix 1.2: random per-session suffix so the user_id
        // does not leak the predictable session-handle counter.
        let suffix = pkcs11_random_suffix_for(session_handle);
        Self {
            role: HsmRole::User,
            user_id: Some(format!("pkcs11:user:{}:{}", session_handle, suffix)),
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        }
    }

    /// Create an identity for a standard PKCS#11 CKU_SO login.
    pub fn pkcs11_so(session_handle: u64) -> Self {
        // Audit fix 1.2: random per-session suffix (see pkcs11_user).
        let suffix = pkcs11_random_suffix_for(session_handle);
        Self {
            role: HsmRole::So,
            user_id: Some(format!("pkcs11:so:{}:{}", session_handle, suffix)),
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs11_user_has_user_role() {
        let id = SessionIdentity::pkcs11_user(0x42);
        assert_eq!(id.role, HsmRole::User);
    }

    #[test]
    fn pkcs11_user_has_pin_auth_method() {
        let id = SessionIdentity::pkcs11_user(1);
        assert_eq!(id.auth_method, AuthMethod::Pin);
    }

    #[test]
    fn pkcs11_user_formats_handle_in_user_id() {
        // Audit fix 1.2: user_id no longer leaks the raw handle as
        // a fixed-width hex value; it now contains the decimal
        // handle and a random hex suffix. The prefix is still
        // load-bearing for downstream parsers.
        let id = SessionIdentity::pkcs11_user(0xDEAD);
        let user_id = id.user_id.unwrap();
        assert!(
            user_id.starts_with("pkcs11:user:57005:"),
            "expected pkcs11:user:<handle>: prefix, got: {}",
            user_id
        );
    }

    #[test]
    fn pkcs11_user_has_no_tenant() {
        let id = SessionIdentity::pkcs11_user(1);
        assert!(id.tenant_id.is_none());
    }

    #[test]
    fn pkcs11_so_has_so_role() {
        let id = SessionIdentity::pkcs11_so(0x99);
        assert_eq!(id.role, HsmRole::So);
    }

    #[test]
    fn pkcs11_so_has_pin_auth_method() {
        let id = SessionIdentity::pkcs11_so(1);
        assert_eq!(id.auth_method, AuthMethod::Pin);
    }

    #[test]
    fn pkcs11_so_formats_handle_in_user_id() {
        // See pkcs11_user_formats_handle_in_user_id (audit fix 1.2).
        let id = SessionIdentity::pkcs11_so(0xBEEF);
        let user_id = id.user_id.unwrap();
        assert!(
            user_id.starts_with("pkcs11:so:48879:"),
            "expected pkcs11:so:<handle>: prefix, got: {}",
            user_id
        );
    }

    #[test]
    fn pkcs11_so_has_no_tenant() {
        let id = SessionIdentity::pkcs11_so(1);
        assert!(id.tenant_id.is_none());
    }

    #[test]
    fn different_handles_produce_different_user_ids() {
        let a = SessionIdentity::pkcs11_user(1);
        let b = SessionIdentity::pkcs11_user(2);
        assert_ne!(a.user_id, b.user_id);
    }

    /// Audit fix 1.2 -- two `pkcs11_user` calls with *different* handles
    /// must produce different random suffixes (the suffix is unique per
    /// session_handle, not derived from it).
    #[test]
    fn pkcs11_user_random_suffix_distinguishes_sessions() {
        let a = SessionIdentity::pkcs11_user(100).user_id.unwrap();
        let b = SessionIdentity::pkcs11_user(200).user_id.unwrap();
        let suffix_a = a.rsplit(":").next().unwrap();
        let suffix_b = b.rsplit(":").next().unwrap();
        assert_eq!(
            suffix_a.len(),
            32,
            "expected 16 random bytes => 32 hex chars"
        );
        assert_eq!(
            suffix_b.len(),
            32,
            "expected 16 random bytes => 32 hex chars"
        );
        assert_ne!(
            suffix_a, suffix_b,
            "two sessions must get distinct suffixes"
        );
    }

    /// The same handle observed twice must produce the same suffix
    /// (the random value is cached per handle so the user_id is
    /// stable for the lifetime of the session).
    #[test]
    fn pkcs11_user_suffix_is_stable_per_handle() {
        let a = SessionIdentity::pkcs11_user(424242).user_id.unwrap();
        let b = SessionIdentity::pkcs11_user(424242).user_id.unwrap();
        assert_eq!(a, b, "same handle must produce stable user_id");
    }

    /// W2: `from_session_token(1, [0u8; 16])` must produce the
    /// deterministic user_id `pkcs11:user:1:` followed by 32 hex zeros.
    /// This pins down the wire format so embedders can reason about
    /// audit / no-self-approval keying without re-deriving the suffix.
    #[test]
    fn from_session_token_is_deterministic_zero_token() {
        let id = Pkcs11Identity::from_session_token(1, [0u8; 16]);
        let user_id = id.user_id.expect("user_id must be Some");
        let expected = format!("pkcs11:user:1:{}", "00000000000000000000000000000000");
        assert_eq!(user_id, expected, "got {}", user_id);
        assert_eq!(id.role, HsmRole::User);
        assert_eq!(id.auth_method, AuthMethod::Pin);
    }

    /// W2: two calls with the same `(handle, token)` MUST produce the
    /// same identity (no internal randomness).
    #[test]
    fn from_session_token_is_pure() {
        let token = [0xABu8; 16];
        let a = Pkcs11Identity::from_session_token(7, token);
        let b = Pkcs11Identity::from_session_token(7, token);
        assert_eq!(a.user_id, b.user_id);
    }

    /// W2: `new_with_random_token` must NOT collide with itself for the
    /// same `handle` -- it freshly mints token entropy each call.
    #[test]
    fn new_with_random_token_is_fresh_per_call() {
        let a = Pkcs11Identity::new_with_random_token(1).user_id.unwrap();
        let b = Pkcs11Identity::new_with_random_token(1).user_id.unwrap();
        assert_ne!(a, b, "each call must mint a fresh token");
    }

    /// W2: `SessionTokenBytes` is a public type alias for `[u8; 16]`.
    /// Pin the alias so any future widening forces a deliberate API
    /// review.
    #[test]
    fn session_token_bytes_alias_is_16_bytes() {
        let _check: SessionTokenBytes = [0u8; 16];
        assert_eq!(std::mem::size_of::<SessionTokenBytes>(), 16);
    }
}
