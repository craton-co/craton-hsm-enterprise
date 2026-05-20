// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Tenant-isolation integration tests.
//!
//! The auth crate does not own the PKCS#11 object dispatch layer — that
//! lives in `craton-hsm-core`. These tests therefore exercise the
//! tenant-enforcement surface the auth crate *does* own: the RBAC
//! approval workflow's requester/approver tenant match and the policy
//! engine's identity→role mapping.
//!
//! If a future refactor pulls a dispatch facade into this crate, extend
//! these tests with a direct cross-tenant key-access scenario.

use std::collections::HashSet;

use craton_hsm_auth::rbac::approval::ApprovalQueue;
use craton_hsm_auth::rbac::identity::{AuthMethod, SessionIdentity};
use craton_hsm_auth::rbac::role::{HsmOperation, HsmRole};

fn identity(user_id: &str, role: HsmRole, tenant: Option<&str>) -> SessionIdentity {
    SessionIdentity {
        role,
        user_id: Some(user_id.to_string()),
        tenant_id: tenant.map(|s| s.to_string()),
        auth_method: AuthMethod::Pin,
    }
}

#[test]
fn cross_tenant_approval_blocked_across_every_role() {
    // Any approver role, when paired with a *different* tenant than the
    // requester, must be rejected. This locks the cross-tenant rule to the
    // tenant field rather than any role-based heuristic.
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let requester = identity("alice", HsmRole::User, Some("tenant-a"));
    let id = queue
        .request_approval(HsmOperation::DestroyObject, Some(42), &requester)
        .expect("request must succeed");

    for role in [HsmRole::User, HsmRole::So, HsmRole::KeyManager] {
        let mallory = identity("mallory", role, Some("tenant-b"));
        let res = queue.approve(&id, &mallory);
        assert!(
            res.is_err(),
            "cross-tenant approval by {role:?} must be denied"
        );
    }
}

#[test]
fn same_tenant_approval_succeeds() {
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let requester = identity("alice", HsmRole::User, Some("tenant-a"));
    let bob = identity("bob", HsmRole::User, Some("tenant-a"));
    let carol = identity("carol", HsmRole::KeyManager, Some("tenant-a"));

    let id = queue
        .request_approval(HsmOperation::DestroyObject, Some(1), &requester)
        .unwrap();

    assert!(!queue.approve(&id, &bob).unwrap(), "need 2 approvals");
    assert!(queue.approve(&id, &carol).unwrap(), "fully approved now");
    let consumed = queue.consume_approved(&id).expect("consume succeeds");
    assert_eq!(consumed.operation, HsmOperation::DestroyObject);
}

#[test]
fn tenantless_cannot_approve_tenanted_request() {
    // A request originating in tenant-a must not be approved by a
    // tenantless (None) session — the tenant IDs must match *exactly*,
    // including the tenantless case.
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let requester = identity("alice", HsmRole::User, Some("tenant-a"));
    let tenantless_approver = identity("root", HsmRole::So, None);

    let id = queue
        .request_approval(HsmOperation::DestroyObject, None, &requester)
        .unwrap();
    let res = queue.approve(&id, &tenantless_approver);
    assert!(
        res.is_err(),
        "tenantless approver must not rubber-stamp a tenant-scoped request"
    );
}

#[test]
fn tenanted_cannot_approve_tenantless_request() {
    // The reverse: a tenantless request must not be approvable by a
    // tenanted user. Symmetric to the case above so the check is strict
    // equality rather than "approver has more/fewer qualifications".
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let requester = identity("root", HsmRole::User, None);
    let tenant_approver = identity("alice", HsmRole::So, Some("tenant-a"));

    let id = queue
        .request_approval(HsmOperation::DestroyObject, None, &requester)
        .unwrap();
    assert!(queue.approve(&id, &tenant_approver).is_err());
}
