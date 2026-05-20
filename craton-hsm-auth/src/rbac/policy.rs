// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! RBAC policy engine — enforces role-based permissions at operation dispatch.

use std::collections::{HashMap, HashSet};

use super::acl::KeyAcl;
use super::identity::SessionIdentity;
use super::role::{default_permissions, HsmOperation, HsmRole};
use craton_hsm::error::{HsmError, HsmResult};

/// Policy engine for RBAC enforcement.
///
/// When `enabled` is false, all permission checks are no-ops (zero overhead).
/// When enabled, checks role permissions against the default matrix and
/// optional per-key ACLs.
pub struct PolicyEngine {
    /// Whether RBAC enforcement is active.
    enabled: bool,
    /// Cached default permissions per role.
    default_permissions: HashMap<HsmRole, HashSet<HsmOperation>>,
    /// Operations requiring dual-control approval.
    /// Private: use `configure_dual_control` to set, `requires_dual_control` to query.
    /// Public field access would let callers bypass the minimum-approvals guard (≥ 2).
    dual_control_operations: HashSet<HsmOperation>,
    /// Number of approvals required for dual-control operations (minimum 2).
    /// Private: enforced ≥ 2 by `configure_dual_control`; direct field write
    /// could reduce this to 0 or 1, defeating the dual-control requirement.
    required_approvals: u32,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new(enabled: bool) -> Self {
        let mut perms = HashMap::new();
        for role in [
            HsmRole::User,
            HsmRole::So,
            HsmRole::Auditor,
            HsmRole::KeyManager,
            HsmRole::Operator,
        ] {
            perms.insert(role, default_permissions(role));
        }

        if !enabled {
            tracing::warn!("RBAC policy engine is DISABLED — all operations will be permitted without access control checks");
        }

        Self {
            enabled,
            default_permissions: perms,
            dual_control_operations: HashSet::new(),
            required_approvals: 2,
        }
    }

    /// Create a disabled (no-op) policy engine.
    pub fn disabled() -> Self {
        Self::new(false)
    }

    /// Check if the given identity is allowed to perform the operation.
    ///
    /// If RBAC is disabled, returns `Ok(())` immediately (backward compatible
    /// with pre-RBAC behavior). If RBAC is enabled and `identity` is `None`,
    /// the operation is denied with `HsmError::UserNotLoggedIn`.
    ///
    /// If `acl` is `Some`, the per-key ACL takes precedence over the default
    /// role permissions: the operation is allowed iff the ACL grants it. The
    /// caller (the PKCS#11 session layer) is responsible for looking up the
    /// ACL associated with the target object before invoking this method —
    /// the parent crate's `StoredObject` does not carry an ACL field, so
    /// ACLs are owned and managed by the auth crate's storage rather than
    /// being attached to objects directly.
    #[tracing::instrument(
        level = "debug",
        skip(self, identity, acl),
        fields(
            op = operation.as_str(),
            role = identity.map(|i| i.role.as_str()).unwrap_or("none"),
            acl = acl.is_some(),
        )
    )]
    pub fn check_permission(
        &self,
        identity: Option<&SessionIdentity>,
        operation: HsmOperation,
        acl: Option<&KeyAcl>,
    ) -> HsmResult<()> {
        // Fast path: RBAC disabled — all operations allowed (existing behavior)
        if !self.enabled {
            return Ok(());
        }

        // No identity means no authenticated session.  When RBAC is enabled,
        // unauthenticated callers must be denied — the PKCS#11 state machine
        // is responsible for only calling check_permission after a successful
        // C_Login, so returning an error here is correct.
        let identity = match identity {
            Some(id) => id,
            None => {
                tracing::warn!("RBAC denied: no session identity (user not logged in)");
                return Err(HsmError::UserNotLoggedIn);
            }
        };

        let role = identity.role;

        // Check per-key ACL first (if one was supplied for this object)
        if let Some(acl) = acl {
            return if acl.is_allowed(role, operation) {
                Ok(())
            } else {
                tracing::warn!(
                    "RBAC denied: role={} operation={} on object with ACL",
                    role.as_str(),
                    operation.as_str()
                );
                Err(crate::error::operation_denied())
            };
        }

        // Fall back to default role permissions
        let allowed = self
            .default_permissions
            .get(&role)
            .map_or(false, |perms| perms.contains(&operation));

        if allowed {
            Ok(())
        } else {
            tracing::warn!(
                "RBAC denied: role={} operation={} (default policy)",
                role.as_str(),
                operation.as_str()
            );
            Err(crate::error::operation_denied())
        }
    }

    /// Check if an operation requires dual-control approval.
    pub fn requires_dual_control(&self, operation: HsmOperation) -> bool {
        self.enabled && self.dual_control_operations.contains(&operation)
    }

    /// Whether RBAC is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Configure dual-control for a set of operations.
    ///
    /// `required_approvals` is clamped to a minimum of 2 — a "dual-control"
    /// requirement with fewer than 2 approvals is not dual control at all.
    /// Panics in debug builds if `required_approvals == 0` to catch
    /// misconfiguration early.
    pub fn configure_dual_control(
        &mut self,
        operations: HashSet<HsmOperation>,
        required_approvals: u32,
    ) {
        // Audit fix: clamp silently to 2 rather than `debug_assert!`.
        // A `debug_assert!` here turned the documented "clamp" behavior
        // into a debug-build panic, which the regression test caught.
        // We log the clamp at warn so misconfigurations are still
        // visible to operators without crashing the process.
        if required_approvals < 2 {
            tracing::warn!(
                requested = required_approvals,
                effective = 2,
                "configure_dual_control: required_approvals < 2 — clamping to 2"
            );
        }
        self.dual_control_operations = operations;
        self.required_approvals = required_approvals.max(2);
    }

    /// Return the number of approvals required for dual-control operations.
    pub fn required_approvals(&self) -> u32 {
        self.required_approvals
    }

    /// Return the set of operations that require dual-control approval.
    pub fn dual_control_operations(&self) -> &HashSet<HsmOperation> {
        &self.dual_control_operations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_policy_allows_everything() {
        let engine = PolicyEngine::disabled();
        let identity = SessionIdentity::pkcs11_user(1);
        assert!(engine
            .check_permission(Some(&identity), HsmOperation::Sign, None)
            .is_ok());
    }

    #[test]
    fn test_no_identity_denied_when_rbac_enabled() {
        let engine = PolicyEngine::new(true);
        // When RBAC is enabled, a missing identity must be denied.
        let result = engine.check_permission(None, HsmOperation::Sign, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HsmError::UserNotLoggedIn));
    }

    #[test]
    fn test_no_identity_allowed_when_rbac_disabled() {
        let engine = PolicyEngine::disabled();
        // RBAC disabled: no-op regardless of identity.
        assert!(engine
            .check_permission(None, HsmOperation::Sign, None)
            .is_ok());
    }

    #[test]
    fn test_user_can_sign() {
        let engine = PolicyEngine::new(true);
        let identity = SessionIdentity::pkcs11_user(1);
        assert!(engine
            .check_permission(Some(&identity), HsmOperation::Sign, None)
            .is_ok());
    }

    #[test]
    fn test_auditor_cannot_sign() {
        let engine = PolicyEngine::new(true);
        let identity = SessionIdentity {
            role: HsmRole::Auditor,
            user_id: None,
            tenant_id: None,
            auth_method: super::super::identity::AuthMethod::Pin,
        };
        assert!(engine
            .check_permission(Some(&identity), HsmOperation::Sign, None)
            .is_err());
    }

    #[test]
    fn test_operator_cannot_generate_key() {
        let engine = PolicyEngine::new(true);
        let identity = SessionIdentity {
            role: HsmRole::Operator,
            user_id: None,
            tenant_id: None,
            auth_method: super::super::identity::AuthMethod::Pin,
        };
        assert!(engine
            .check_permission(Some(&identity), HsmOperation::GenerateKey, None)
            .is_err());
    }

    #[test]
    fn test_key_manager_can_generate_but_not_sign() {
        let engine = PolicyEngine::new(true);
        let identity = SessionIdentity {
            role: HsmRole::KeyManager,
            user_id: None,
            tenant_id: None,
            auth_method: super::super::identity::AuthMethod::Pin,
        };
        assert!(engine
            .check_permission(Some(&identity), HsmOperation::GenerateKey, None)
            .is_ok());
        assert!(engine
            .check_permission(Some(&identity), HsmOperation::Sign, None)
            .is_err());
    }

    #[test]
    fn test_per_key_acl_overrides_default() {
        let engine = PolicyEngine::new(true);

        // Build a restrictive ACL: only Operator can Sign.
        let acl = KeyAcl {
            entries: vec![super::super::acl::AclEntry {
                role: HsmRole::Operator,
                allowed_operations: std::iter::once(HsmOperation::Sign).collect(),
            }],
        };

        // User is denied even though default policy allows Sign — the ACL
        // takes precedence and only lists Operator.
        let user_id = SessionIdentity::pkcs11_user(1);
        assert!(engine
            .check_permission(Some(&user_id), HsmOperation::Sign, Some(&acl))
            .is_err());

        // Operator is allowed by the ACL
        let op_id = SessionIdentity {
            role: HsmRole::Operator,
            user_id: None,
            tenant_id: None,
            auth_method: super::super::identity::AuthMethod::Pin,
        };
        assert!(engine
            .check_permission(Some(&op_id), HsmOperation::Sign, Some(&acl))
            .is_ok());
    }

    #[test]
    fn test_configure_dual_control_sets_operations() {
        let mut engine = PolicyEngine::new(true);
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::Sign);
        ops.insert(HsmOperation::GenerateKey);

        engine.configure_dual_control(ops.clone(), 2);

        assert!(engine.requires_dual_control(HsmOperation::Sign));
        assert!(engine.requires_dual_control(HsmOperation::GenerateKey));
        assert!(!engine.requires_dual_control(HsmOperation::Decrypt));
        assert_eq!(engine.required_approvals(), 2);
        assert_eq!(engine.dual_control_operations().len(), 2);
    }

    #[test]
    fn test_configure_dual_control_enforces_minimum_approvals() {
        let mut engine = PolicyEngine::new(true);
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::Sign);

        // required_approvals below 2 must be clamped to 2
        engine.configure_dual_control(ops, 0);
        assert_eq!(engine.required_approvals(), 2, "must clamp to minimum 2");
    }

    #[test]
    fn test_dual_control_not_checked_when_rbac_disabled() {
        let mut engine = PolicyEngine::disabled();
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::Sign);
        engine.configure_dual_control(ops, 2);

        // Even with dual-control configured, disabled engine returns false
        assert!(!engine.requires_dual_control(HsmOperation::Sign));
    }

    #[test]
    fn test_dual_control_operations_initially_empty() {
        let engine = PolicyEngine::new(true);
        assert!(engine.dual_control_operations().is_empty());
        assert_eq!(engine.required_approvals(), 2);
    }
}
