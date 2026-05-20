// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Dual-control approval workflow — end-to-end integration tests.
//!
//! Covers the full request -> approve x N -> execute path plus replay
//! prevention: once a request has been consumed it must not be
//! re-executable under the same ID.

use std::collections::HashSet;

use craton_hsm_auth::rbac::approval::ApprovalQueue;
use craton_hsm_auth::rbac::identity::{AuthMethod, SessionIdentity};
use craton_hsm_auth::rbac::role::{HsmOperation, HsmRole};

fn ident(user_id: &str, role: HsmRole) -> SessionIdentity {
    SessionIdentity {
        role,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        auth_method: AuthMethod::Pin,
    }
}

#[test]
fn end_to_end_request_approve_execute() {
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 3, 600);

    let requester = ident("alice", HsmRole::User);
    let approvers = [
        ident("bob", HsmRole::KeyManager),
        ident("carol", HsmRole::User),
        ident("dave", HsmRole::So),
    ];

    // 1. Request
    let id = queue
        .request_approval(HsmOperation::DestroyObject, Some(1234), &requester)
        .expect("request must succeed");

    // 2. First two approvals: not yet fully approved
    assert!(!queue.approve(&id, &approvers[0]).unwrap(), "1 of 3");
    assert!(!queue.approve(&id, &approvers[1]).unwrap(), "2 of 3");

    // Consuming before full approval must fail — guards against a caller
    // that races ahead of the approval state machine.
    assert!(queue.consume_approved(&id).is_err());

    // 3. Final approval triggers full-approval state.
    assert!(queue.approve(&id, &approvers[2]).unwrap(), "3 of 3");

    // 4. Execute (consume).
    let consumed = queue.consume_approved(&id).expect("consume must succeed");
    assert_eq!(consumed.operation, HsmOperation::DestroyObject);
    assert_eq!(consumed.object_handle, Some(1234));

    // 5. Replay: the same ID must not be consumable a second time.
    let replay = queue.consume_approved(&id);
    assert!(replay.is_err(), "consumed request must not replay");

    // 6. Re-approving after consumption must also fail (unknown id).
    let reapprove = queue.approve(&id, &approvers[0]);
    assert!(reapprove.is_err(), "approving consumed request must fail");
}

#[test]
fn self_approval_blocked_even_when_approver_would_otherwise_qualify() {
    // Regression guard: a privileged self-approval must never satisfy
    // dual-control. Alice is both requester and approver (KeyManager role);
    // this must be rejected even though KeyManager is in the default
    // approver role set.
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let alice = ident("alice", HsmRole::KeyManager);
    let id = queue
        .request_approval(HsmOperation::DestroyObject, None, &alice)
        .unwrap();
    assert!(queue.approve(&id, &alice).is_err());
}

#[test]
fn duplicate_approval_from_same_user_rejected() {
    // Two distinct approvals required — bob trying twice must be rejected.
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let alice = ident("alice", HsmRole::User);
    let bob = ident("bob", HsmRole::User);

    let id = queue
        .request_approval(HsmOperation::DestroyObject, None, &alice)
        .unwrap();
    assert!(!queue.approve(&id, &bob).unwrap());
    // Second vote from bob is rejected.
    assert!(queue.approve(&id, &bob).is_err());
}

#[test]
fn auditor_cannot_approve_by_default() {
    // Default approver roles are {User, SO, KeyManager}; Auditor and
    // Operator must not be able to push an approval through.
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let alice = ident("alice", HsmRole::User);
    let auditor = ident("aud", HsmRole::Auditor);

    let id = queue
        .request_approval(HsmOperation::DestroyObject, None, &alice)
        .unwrap();
    assert!(queue.approve(&id, &auditor).is_err());
}

#[test]
fn approval_for_non_configured_operation_rejected_at_request_time() {
    let mut ops = HashSet::new();
    ops.insert(HsmOperation::DestroyObject);
    let queue = ApprovalQueue::new(ops, 2, 300);

    let alice = ident("alice", HsmRole::User);
    // Sign is not configured for dual-control — must fail at request time.
    let res = queue.request_approval(HsmOperation::Sign, None, &alice);
    assert!(res.is_err());
}
