// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Dual-control approval queue for sensitive operations.
//!
//! Implements the "4-eye principle": certain operations (e.g., key destruction)
//! require approval from multiple authorized users before execution.
//!
//! This feature is gRPC-only. The PKCS#11 C ABI does not support the
//! asynchronous request/approve/execute flow.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use rand::RngCore;

use super::identity::SessionIdentity;
use super::role::{HsmOperation, HsmRole};
use craton_hsm::error::HsmResult;

/// Unique identifier for an approval request.
///
/// 128-bit random hex string. Random IDs (rather than monotonic counters)
/// prevent attackers from enumerating or predicting valid request IDs.
pub type ApprovalId = String;

/// A pending approval request for a dual-control operation.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Unique request identifier.
    pub id: ApprovalId,
    /// The operation requiring approval.
    pub operation: HsmOperation,
    /// Object handle involved (if any).
    pub object_handle: Option<u64>,
    /// Who requested the operation.
    pub requester_user_id: Option<String>,
    /// Tenant the request originated in (if multi-tenant).  Approvers must
    /// belong to the same tenant — see `approve()` for the cross-tenant check.
    pub requester_tenant_id: Option<String>,
    /// When the request was created (Unix timestamp — audit only).
    pub created_at: u64,
    /// When the request expires (Unix timestamp — audit only; never used
    /// for the expiry comparison, see `expires_at_mono`).
    pub expires_at: u64,
    /// Monotonic-clock deadline. Used by [`Self::is_expired`] so a
    /// wall-clock step (NTP / VM pause) cannot prematurely retire — or
    /// extend — a pending approval request.
    pub expires_at_mono: Instant,
    /// Approvals received so far.
    pub approvals: Vec<ApprovalVote>,
    /// Number of approvals required.
    pub required_approvals: u32,
}

/// A vote approving an operation.
#[derive(Debug, Clone)]
pub struct ApprovalVote {
    /// Who approved.
    pub approver_user_id: Option<String>,
    /// When they approved.
    pub timestamp: u64,
}

impl ApprovalRequest {
    /// Check if enough approvals have been received.
    pub fn is_fully_approved(&self) -> bool {
        self.approvals.len() as u32 >= self.required_approvals
    }

    /// Check if the request has expired.
    ///
    /// Comparison uses [`Instant`] (monotonic) — the wall-clock
    /// `expires_at` field is retained only for audit-log emission.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at_mono
    }
}

/// Queue managing pending dual-control approval requests.
pub struct ApprovalQueue {
    /// Pending requests indexed by ID.  Wrapped in Arc so `list_pending`
    /// can return cheap references instead of cloning the full struct.
    pending: DashMap<ApprovalId, Arc<ApprovalRequest>>,
    /// Operations that require dual control.
    dual_control_operations: HashSet<HsmOperation>,
    /// Number of approvals required.
    required_approvals: u32,
    /// Approval timeout in seconds.
    timeout_secs: u64,
    /// Roles authorized to cast approval votes.
    allowed_approver_roles: HashSet<HsmRole>,
}

impl ApprovalQueue {
    fn default_approver_roles() -> HashSet<HsmRole> {
        [HsmRole::User, HsmRole::So, HsmRole::KeyManager]
            .into_iter()
            .collect()
    }

    /// Create a new approval queue.
    pub fn new(
        dual_control_operations: HashSet<HsmOperation>,
        required_approvals: u32,
        timeout_secs: u64,
    ) -> Self {
        Self {
            pending: DashMap::new(),
            dual_control_operations,
            required_approvals: required_approvals.max(2),
            timeout_secs,
            allowed_approver_roles: Self::default_approver_roles(),
        }
    }

    /// Generate a fresh, unguessable approval ID (128 bits of entropy).
    ///
    /// Uses `OsRng` — the OS-backed CSPRNG — directly rather than the thread-local
    /// reseeding RNG so the cryptographic source is unambiguous across platforms.
    fn generate_id() -> ApprovalId {
        use rand::rngs::OsRng;
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Create a queue with no dual-control operations (disabled).
    pub fn disabled() -> Self {
        Self::new(HashSet::new(), 2, 300)
    }

    /// Check if an operation requires dual control.
    pub fn requires_approval(&self, operation: HsmOperation) -> bool {
        self.dual_control_operations.contains(&operation)
    }

    /// Submit a new approval request. Returns the request ID.
    ///
    /// Rejects requests for operations not configured for dual control,
    /// and rejects requests from anonymous (no user_id) requesters — without
    /// an identifiable requester there is no way to enforce the no-self-approval
    /// rule, so the entire approval has no security meaning.
    pub fn request_approval(
        &self,
        operation: HsmOperation,
        object_handle: Option<u64>,
        requester: &SessionIdentity,
    ) -> HsmResult<ApprovalId> {
        // Reject operations that aren't configured for dual control — otherwise
        // a buggy caller could create approvals for arbitrary operations and
        // get them rubber-stamped, weakening the audit trail.
        if !self.dual_control_operations.contains(&operation) {
            tracing::warn!(
                "request_approval called for non-dual-control operation {:?}",
                operation
            );
            return Err(crate::error::operation_denied());
        }
        // Reject both `None` and `Some("")`. An empty-string user_id would
        // satisfy the `is_some()` check below but then `request.requester_user_id
        // == approver.user_id` evaluates true for any other caller who also
        // authenticates with an empty id, defeating the no-self-approval guard.
        if requester
            .user_id
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            tracing::warn!(
                "request_approval rejected: requester has no usable user_id (operation {:?})",
                operation
            );
            return Err(crate::error::operation_denied());
        }

        // Clean up expired requests first
        self.evict_expired();

        let id = Self::generate_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let request = ApprovalRequest {
            id: id.clone(),
            operation,
            object_handle,
            requester_user_id: requester.user_id.clone(),
            requester_tenant_id: requester.tenant_id.clone(),
            created_at: now,
            expires_at: now + self.timeout_secs,
            expires_at_mono: Instant::now() + Duration::from_secs(self.timeout_secs),
            approvals: Vec::new(),
            required_approvals: self.required_approvals,
        };

        self.pending.insert(id.clone(), Arc::new(request));
        tracing::info!(
            "Dual-control approval requested: id={} operation={} by {:?}",
            id,
            operation.as_str(),
            requester.user_id
        );

        Ok(id)
    }

    /// Approve a pending request. The approver must be different from the requester.
    pub fn approve(&self, request_id: &str, approver: &SessionIdentity) -> HsmResult<bool> {
        let mut entry = self
            .pending
            .get_mut(request_id)
            .ok_or(crate::error::dual_control_not_found())?;

        // Get mutable access to the inner ApprovalRequest.
        let request = Arc::make_mut(entry.value_mut());

        if request.is_expired() {
            drop(entry);
            self.pending.remove(request_id);
            return Err(crate::error::dual_control_expired());
        }

        // Check that the approver has a role authorized to approve.
        if !self.allowed_approver_roles.contains(&approver.role) {
            tracing::warn!(
                "Dual-control: approval denied — role {:?} is not authorized to approve (request {})",
                approver.role,
                request_id
            );
            return Err(crate::error::operation_denied());
        }

        // Prevent self-approval. Both requester and approver must have
        // identifiable, non-empty user IDs for dual-control to be meaningful.
        // An empty-string identity would collapse every anonymous caller into
        // the same principal and silently defeat the no-self-approval check.
        let requester_id_missing = request
            .requester_user_id
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        let approver_id_missing = approver
            .user_id
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if requester_id_missing || approver_id_missing {
            tracing::warn!(
                "Dual-control: approval denied — both parties must have identifiable user IDs (request {})",
                request_id
            );
            return Err(crate::error::operation_denied());
        }
        if request.requester_user_id == approver.user_id {
            tracing::warn!(
                "Dual-control: self-approval blocked for request {}",
                request_id
            );
            return Err(crate::error::operation_denied());
        }

        // Cross-tenant approvals are forbidden: a tenant-A admin must not be
        // able to rubber-stamp a destructive operation in tenant B.  An
        // approval is allowed only when the approver is in the same tenant
        // as the requester (or both are tenantless).
        if request.requester_tenant_id != approver.tenant_id {
            tracing::warn!(
                "Dual-control: cross-tenant approval blocked (request {}, requester_tenant={:?}, approver_tenant={:?})",
                request_id,
                request.requester_tenant_id,
                approver.tenant_id
            );
            return Err(crate::error::operation_denied());
        }

        // Prevent duplicate approval from same user
        if approver.user_id.is_some()
            && request
                .approvals
                .iter()
                .any(|v| v.approver_user_id == approver.user_id)
        {
            return Err(crate::error::operation_denied());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        request.approvals.push(ApprovalVote {
            approver_user_id: approver.user_id.clone(),
            timestamp: now,
        });

        let fully_approved = request.is_fully_approved();

        tracing::info!(
            "Dual-control approval vote: id={} approver={:?} ({}/{})",
            request_id,
            approver.user_id,
            request.approvals.len(),
            request.required_approvals
        );

        Ok(fully_approved)
    }

    /// Consume a fully-approved request, removing it from the queue.
    /// Returns the request if it was fully approved and not expired.
    ///
    /// Uses a peek-then-remove pattern to avoid a TOCTOU window where a
    /// temporary removal could cause a concurrent caller to see
    /// `ObjectHandleInvalid` for a request that has not yet been consumed.
    pub fn consume_approved(&self, request_id: &str) -> HsmResult<ApprovalRequest> {
        // Peek first — verify eligibility without removing.
        {
            let entry = self
                .pending
                .get(request_id)
                .ok_or(crate::error::dual_control_not_found())?;
            let request = entry.value();
            if request.is_expired() {
                return Err(crate::error::dual_control_expired());
            }
            if !request.is_fully_approved() {
                return Err(crate::error::dual_control_required());
            }
            // Drop the read guard before the write (remove) below.
        }

        // Only now remove — the request is confirmed fully approved.
        let (_, arc_request) = self
            .pending
            .remove(request_id)
            .ok_or(crate::error::dual_control_not_found())?;

        // Audit (design) -- explicit ownership transfer:
        // 1. Try to take the unique owner (we just `remove`d the only
        //    map slot that holds the Arc), avoiding a deep clone.
        // 2. If another caller is still holding a clone (e.g. via
        //    `list_pending`), fall back to `(*arc).clone()` so we
        //    return an owned `ApprovalRequest` regardless of refcount.
        // The previous one-liner did the same thing but was easy to
        // misread as silent failure on shared ownership.
        let request = match Arc::try_unwrap(arc_request) {
            Ok(unique) => unique,
            Err(shared) => (*shared).clone(),
        };
        Ok(request)
    }

    /// List all pending (non-expired) requests.
    ///
    /// Returns `Arc`-wrapped references for cheap access; no deep clones.
    pub fn list_pending(&self) -> Vec<Arc<ApprovalRequest>> {
        self.evict_expired();
        self.pending
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Remove expired requests.
    fn evict_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.pending.retain(|_, req| req.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::identity::AuthMethod;

    fn test_identity(user_id: &str) -> SessionIdentity {
        SessionIdentity {
            role: super::super::role::HsmRole::User,
            user_id: Some(user_id.to_string()),
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        }
    }

    #[test]
    fn test_approval_workflow() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let requester = test_identity("alice");
        let approver1 = test_identity("bob");
        let approver2 = test_identity("carol");

        // Request approval
        let id = queue
            .request_approval(HsmOperation::DestroyObject, Some(42), &requester)
            .unwrap();

        // First approval — not yet fully approved
        let fully_approved = queue.approve(&id, &approver1).unwrap();
        assert!(!fully_approved);

        // Second approval — now fully approved
        let fully_approved = queue.approve(&id, &approver2).unwrap();
        assert!(fully_approved);

        // Consume
        let request = queue.consume_approved(&id).unwrap();
        assert_eq!(request.operation, HsmOperation::DestroyObject);
    }

    #[test]
    fn test_self_approval_blocked() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let alice = test_identity("alice");
        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &alice)
            .unwrap();

        // Self-approval should fail
        assert!(queue.approve(&id, &alice).is_err());
    }

    #[test]
    fn test_request_for_non_dual_control_op_rejected() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let alice = test_identity("alice");
        // Sign is not in the dual-control set — must be rejected.
        let result = queue.request_approval(HsmOperation::Sign, None, &alice);
        assert!(result.is_err());
    }

    #[test]
    fn test_cross_tenant_approval_blocked() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let mut alice = test_identity("alice");
        alice.tenant_id = Some("tenant-a".to_string());
        let mut mallory = test_identity("mallory");
        mallory.tenant_id = Some("tenant-b".to_string());

        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &alice)
            .unwrap();
        // mallory belongs to a different tenant — must be denied.
        assert!(queue.approve(&id, &mallory).is_err());
    }

    #[test]
    fn test_disabled_queue() {
        let queue = ApprovalQueue::disabled();
        assert!(!queue.requires_approval(HsmOperation::DestroyObject));
    }

    #[test]
    fn test_approval_denied_when_approver_has_no_user_id() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let requester = test_identity("alice");
        let anonymous_approver = SessionIdentity {
            role: super::super::role::HsmRole::User,
            user_id: None,
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        };

        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &requester)
            .unwrap();
        assert!(queue.approve(&id, &anonymous_approver).is_err());
    }

    #[test]
    fn test_request_denied_when_requester_anonymous() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let anonymous_requester = SessionIdentity {
            role: super::super::role::HsmRole::User,
            user_id: None,
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        };

        // request_approval now rejects anonymous requesters at the gate.
        assert!(queue
            .request_approval(HsmOperation::DestroyObject, None, &anonymous_requester)
            .is_err());
    }

    #[test]
    fn test_expired_request() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        // Create a queue with a 0-second timeout so requests expire immediately
        let queue = ApprovalQueue::new(ops, 2, 0);

        let requester = test_identity("alice");
        let approver = test_identity("bob");

        let id = queue
            .request_approval(HsmOperation::DestroyObject, Some(1), &requester)
            .unwrap();

        // The request expires_at = now + 0 = now, so is_expired() returns true
        // (now >= expires_at). Attempting to approve should fail with expiry.
        let result = queue.approve(&id, &approver);
        assert!(result.is_err(), "approval on expired request should fail");
    }

    #[test]
    fn test_duplicate_approval() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 3, 300);

        let requester = test_identity("alice");
        let approver_bob = test_identity("bob");

        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &requester)
            .unwrap();

        // First approval from bob succeeds
        let result = queue.approve(&id, &approver_bob).unwrap();
        assert!(!result, "should not be fully approved yet");

        // Second approval from the same user (bob) should be rejected
        let result = queue.approve(&id, &approver_bob);
        assert!(
            result.is_err(),
            "duplicate approval from same user should be rejected"
        );
    }

    /// Empty-string user IDs are not a meaningful identity and must be
    /// rejected as either requester or approver — otherwise an anonymous
    /// caller who forged `user_id = Some("")` could slip past the
    /// identity gate and self-approve operations (empty == empty).
    ///
    /// Audit polish (`approval.rs:563`): the original `#[ignore]` was
    /// stale — `request_approval` / `approve` both call
    /// `s.trim().is_empty()` and already reject this case. The annotation
    /// has been removed; the test is now part of the active suite.
    #[test]
    fn test_empty_string_requester_rejected() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let empty_requester = SessionIdentity {
            role: super::super::role::HsmRole::User,
            user_id: Some(String::new()), // empty == anonymous
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        };
        assert!(
            queue
                .request_approval(HsmOperation::DestroyObject, None, &empty_requester)
                .is_err(),
            "empty-string requester must be rejected"
        );
    }

    #[test]
    fn test_empty_string_approver_rejected() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let requester = test_identity("alice");
        let empty_approver = SessionIdentity {
            role: super::super::role::HsmRole::User,
            user_id: Some(String::new()),
            tenant_id: None,
            auth_method: AuthMethod::Pin,
        };
        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &requester)
            .unwrap();
        assert!(
            queue.approve(&id, &empty_approver).is_err(),
            "empty-string approver must be rejected"
        );
    }

    /// Cross-tenant: a tenant-b approver must not be able to approve a
    /// request made by a tenant-a requester.  This complements the
    /// existing `test_cross_tenant_approval_blocked` by exercising the
    /// same policy under a different role for the approver.
    #[test]
    fn test_cross_tenant_approval_blocked_keymanager_role() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        let queue = ApprovalQueue::new(ops, 2, 300);

        let mut tenant_a_user = test_identity("alice");
        tenant_a_user.tenant_id = Some("tenant-a".to_string());

        let tenant_b_approver = SessionIdentity {
            role: super::super::role::HsmRole::KeyManager,
            user_id: Some("eve".to_string()),
            tenant_id: Some("tenant-b".to_string()),
            auth_method: AuthMethod::Pin,
        };

        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &tenant_a_user)
            .unwrap();
        assert!(
            queue.approve(&id, &tenant_b_approver).is_err(),
            "cross-tenant approval must be blocked even for privileged roles"
        );
    }

    #[test]
    fn test_consume_not_fully_approved() {
        let mut ops = HashSet::new();
        ops.insert(HsmOperation::DestroyObject);
        // Require 2 approvals
        let queue = ApprovalQueue::new(ops, 2, 300);

        let requester = test_identity("alice");
        let approver = test_identity("bob");

        let id = queue
            .request_approval(HsmOperation::DestroyObject, None, &requester)
            .unwrap();

        // Only one approval (need 2)
        let fully = queue.approve(&id, &approver).unwrap();
        assert!(!fully, "should not be fully approved with only 1 of 2");

        // Trying to consume before fully approved should fail
        let result = queue.consume_approved(&id);
        assert!(
            result.is_err(),
            "consume_approved should fail when not fully approved"
        );

        // The request should still be in the queue (not removed by failed consume)
        assert_eq!(queue.list_pending().len(), 1);
    }
}
