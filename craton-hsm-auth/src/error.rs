// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Compatibility layer that maps enterprise-auth-specific error semantics
//! onto the existing variants in [`craton_hsm::error::HsmError`].
//!
//! The parent `craton-hsm` crate intentionally does not expose dedicated
//! variants for MFA, dual-control, RBAC denial, or tenant quotas — those are
//! enterprise concepts that layer on top of the core PKCS#11 module. To keep
//! the auth crate compiling against the parent's stable error type, each of
//! the helpers below returns the closest existing variant whose `CK_RV`
//! mapping is semantically appropriate.
//!
//! ## Mapping rationale
//!
//! | enterprise concept       | parent variant            | `CK_RV`                       |
//! |--------------------------|---------------------------|-------------------------------|
//! | MFA required             | `UserNotLoggedIn`         | `CKR_USER_NOT_LOGGED_IN`      |
//! | MFA challenge invalid    | `PinIncorrect`            | `CKR_PIN_INCORRECT`           |
//! | Operation denied (RBAC)  | `KeyFunctionNotPermitted` | `CKR_KEY_FUNCTION_NOT_PERMITTED` |
//! | Dual-control not found   | `ArgumentsBad`            | `CKR_ARGUMENTS_BAD`           |
//! | Dual-control expired     | `ArgumentsBad`            | `CKR_ARGUMENTS_BAD`           |
//! | Dual-control required    | `KeyFunctionNotPermitted` | `CKR_KEY_FUNCTION_NOT_PERMITTED` |
//! | Tenant quota exceeded    | `HostMemory`              | `CKR_HOST_MEMORY`             |
//!
//! Using these helper constructors (instead of `HsmError::Foo` directly)
//! makes call sites self-documenting and centralizes the mapping in one
//! place — if the parent crate ever introduces dedicated variants, only
//! this file changes.

use craton_hsm::error::HsmError;

// Each helper below maps an enterprise-auth-specific error concept onto the
// closest `HsmError` variant. Because the parent crate's error enum is the
// stable ABI boundary (it converts to `CK_RV`), callers never see the rich
// enterprise reason directly — so every mapping helper emits a single
// `tracing::debug!` on the `craton_hsm_auth::error` target so operators can
// still recover the original domain reason for triage. The mapping behaviour
// is otherwise identical to the direct constructors it replaced.
//
// Using `debug!` (not `warn!`) keeps the noise floor sensible: these mappings
// happen on every failed auth attempt, and a warn-level log on every
// PinIncorrect would be unreadable on a busy HSM. Operators investigating a
// specific denial can enable `craton_hsm_auth::error=debug` without touching
// the rest of the logging config.

/// MFA challenge required but not yet completed for the current session.
#[inline]
pub fn mfa_required() -> HsmError {
    let mapped = HsmError::UserNotLoggedIn;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "mfa_required",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// MFA challenge response was invalid, expired, or replayed.
#[inline]
pub fn mfa_challenge_invalid() -> HsmError {
    let mapped = HsmError::PinIncorrect;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "mfa_challenge_invalid",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// Operation denied by RBAC policy or per-key ACL.
#[inline]
pub fn operation_denied() -> HsmError {
    let mapped = HsmError::KeyFunctionNotPermitted;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "operation_denied",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// Dual-control approval request not found (unknown id or already consumed).
#[inline]
pub fn dual_control_not_found() -> HsmError {
    let mapped = HsmError::ArgumentsBad;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "dual_control_not_found",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// Dual-control approval request has expired.
#[inline]
pub fn dual_control_expired() -> HsmError {
    let mapped = HsmError::ArgumentsBad;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "dual_control_expired",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// Operation requires dual-control approval that has not yet been granted.
#[inline]
pub fn dual_control_required() -> HsmError {
    let mapped = HsmError::KeyFunctionNotPermitted;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "dual_control_required",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// Tenant has reached its configured key/session quota.
#[inline]
pub fn tenant_quota_exceeded() -> HsmError {
    let mapped = HsmError::HostMemory;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "tenant_quota_exceeded",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

/// LDAP connection pool exhausted — all slots are in use and the overflow
/// limit has been reached.
#[inline]
pub fn connection_pool_exhausted() -> HsmError {
    let mapped = HsmError::GeneralError;
    tracing::debug!(
        target: "craton_hsm_auth::error",
        original = "connection_pool_exhausted",
        mapped = ?mapped,
        "domain error mapped to HsmError for ABI stability"
    );
    mapped
}

#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::error::HsmError;

    #[test]
    fn each_helper_returns_a_distinct_or_documented_variant() {
        // These mappings are deliberate; if a future change reorders them,
        // this test should be updated together with the doc table above.
        assert!(matches!(mfa_required(), HsmError::UserNotLoggedIn));
        assert!(matches!(mfa_challenge_invalid(), HsmError::PinIncorrect));
        assert!(matches!(
            operation_denied(),
            HsmError::KeyFunctionNotPermitted
        ));
        assert!(matches!(dual_control_not_found(), HsmError::ArgumentsBad));
        assert!(matches!(dual_control_expired(), HsmError::ArgumentsBad));
        assert!(matches!(
            dual_control_required(),
            HsmError::KeyFunctionNotPermitted
        ));
        assert!(matches!(tenant_quota_exceeded(), HsmError::HostMemory));
        assert!(matches!(
            connection_pool_exhausted(),
            HsmError::GeneralError
        ));
    }
}
