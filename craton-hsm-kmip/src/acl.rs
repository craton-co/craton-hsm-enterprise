// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Pluggable Access-Control List (ACL) policy for KMIP operations.
//!
//! The built-in owner attribute check in [`crate::operations`] is a minimum
//! viable authorization model that blocks cross-tenant reads of
//! owner-tagged objects (audit finding H6). It does not express richer
//! policies like role-based access, per-operation capability matrices, or
//! separation of the data-plane identity from the administrative identity.
//!
//! Audit finding **M8** pointed out that the KMIP server dispatcher extracts a
//! `caller_identity` from the transport authenticator but never feeds it into
//! any authorization decision beyond owner equality. To close that gap, the
//! server now consults a [`KmipAcl`] object on every destructive or sensitive
//! operation (Destroy, Revoke, Activate, Get, GetAttributes, AddAttribute).
//! The built-in [`AllowAll`] policy preserves the crate's previous behaviour
//! (no additional gating beyond the owner check) for callers who have not yet
//! wired up a real policy engine.
//!
//! # Wiring to `craton-hsm-auth`
//!
//! `craton-hsm-auth` produces an authenticated principal for each incoming
//! request. A typical deployment plugs it in as follows (pseudo-code —
//! `craton-hsm-auth` is not a dependency of this crate by design, so the
//! glue code lives in the embedding binary):
//!
//! ```ignore
//! use craton_hsm_kmip::acl::{KmipAcl, KmipAclDecision};
//! use craton_hsm_kmip::types::{KmipOperation, KmipResultReason};
//!
//! struct AuthBackedAcl {
//!     authz: std::sync::Arc<craton_hsm_auth::AuthzEngine>,
//! }
//!
//! impl KmipAcl for AuthBackedAcl {
//!     fn authorize(
//!         &self,
//!         identity: Option<&str>,
//!         operation: KmipOperation,
//!         object_id: Option<&str>,
//!     ) -> KmipAclDecision {
//!         let principal = match identity {
//!             Some(p) => p,
//!             None => return KmipAclDecision::Deny(KmipResultReason::PermissionDenied),
//!         };
//!         if self.authz.can(principal, operation.to_string(), object_id) {
//!             KmipAclDecision::Allow
//!         } else {
//!             KmipAclDecision::Deny(KmipResultReason::PermissionDenied)
//!         }
//!     }
//! }
//! ```
//!
//! The ACL is invoked **before** the existing owner-attribute check, so a
//! policy can either reject outright (forbidding the operation for any
//! object) or defer to the owner check by returning [`KmipAclDecision::Allow`].

use crate::types::{KmipOperation, KmipResultReason};

/// Outcome of an ACL decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmipAclDecision {
    /// Allow the operation to proceed. Per-object ownership is still
    /// checked downstream.
    Allow,
    /// Deny the operation; the dispatcher converts this into a KMIP
    /// error response carrying the embedded [`KmipResultReason`].
    Deny(KmipResultReason),
}

/// Pluggable access-control policy consulted by the KMIP dispatcher
/// before sensitive operations.
///
/// Implementations MUST be `Send + Sync` because the server holds the ACL
/// inside an [`std::sync::Arc`] and invokes it from every request handler
/// concurrently.
pub trait KmipAcl: Send + Sync {
    /// Decide whether `identity` may perform `operation` on `object_id`.
    ///
    /// `identity` is `None` when the transport did not authenticate the
    /// caller (e.g. `require_auth = false`). `object_id` is `None` for
    /// operations that do not target a specific object (e.g. Query,
    /// Locate, or Create with a server-assigned ID).
    fn authorize(
        &self,
        identity: Option<&str>,
        operation: KmipOperation,
        object_id: Option<&str>,
    ) -> KmipAclDecision;
}

/// Default ACL that permits every operation.
///
/// Chosen as the default so the new trait does not change observable
/// behaviour for existing deployments — they still only see the owner
/// attribute check enforced by [`crate::operations`].
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl KmipAcl for AllowAll {
    fn authorize(
        &self,
        _identity: Option<&str>,
        _operation: KmipOperation,
        _object_id: Option<&str>,
    ) -> KmipAclDecision {
        KmipAclDecision::Allow
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_permits_every_operation() {
        let acl = AllowAll;
        assert_eq!(
            acl.authorize(None, KmipOperation::Destroy, Some("k1")),
            KmipAclDecision::Allow,
        );
        assert_eq!(
            acl.authorize(Some("alice"), KmipOperation::Get, Some("k1")),
            KmipAclDecision::Allow,
        );
    }

    /// A hand-rolled ACL that demonstrates per-caller enforcement and is
    /// exercised by the integration test suite.
    struct OwnerOnlyAcl {
        owner: &'static str,
    }

    impl KmipAcl for OwnerOnlyAcl {
        fn authorize(
            &self,
            identity: Option<&str>,
            _operation: KmipOperation,
            _object_id: Option<&str>,
        ) -> KmipAclDecision {
            match identity {
                Some(id) if id == self.owner => KmipAclDecision::Allow,
                _ => KmipAclDecision::Deny(KmipResultReason::PermissionDenied),
            }
        }
    }

    #[test]
    fn custom_acl_denies_non_owner() {
        let acl = OwnerOnlyAcl { owner: "alice" };
        assert_eq!(
            acl.authorize(Some("alice"), KmipOperation::Destroy, Some("k")),
            KmipAclDecision::Allow,
        );
        assert_eq!(
            acl.authorize(Some("mallory"), KmipOperation::Destroy, Some("k")),
            KmipAclDecision::Deny(KmipResultReason::PermissionDenied),
        );
        assert_eq!(
            acl.authorize(None, KmipOperation::Destroy, Some("k")),
            KmipAclDecision::Deny(KmipResultReason::PermissionDenied),
        );
    }
}
