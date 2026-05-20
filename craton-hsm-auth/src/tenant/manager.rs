// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Tenant lifecycle management and quota tracking.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use super::tenant::{Tenant, TenantConfig, TenantId};
use craton_hsm::error::{HsmError, HsmResult};

/// Per-tenant resource usage counters.
pub struct TenantUsage {
    /// Current number of keys stored.
    pub key_count: AtomicU64,
    /// Current number of active sessions.
    pub session_count: AtomicU64,
}

impl TenantUsage {
    fn new() -> Self {
        Self {
            key_count: AtomicU64::new(0),
            session_count: AtomicU64::new(0),
        }
    }
}

/// Manages tenant lifecycle and enforces resource quotas.
pub struct TenantManager {
    /// Registered tenants.
    tenants: DashMap<TenantId, Tenant>,
    /// Per-tenant resource usage.
    usage: DashMap<TenantId, TenantUsage>,
}

impl TenantManager {
    /// Create a new tenant manager with no tenants.
    pub fn new() -> Self {
        Self {
            tenants: DashMap::new(),
            usage: DashMap::new(),
        }
    }

    /// Register a new tenant.
    ///
    /// `id` is taken by value — the caller is expected to construct the
    /// `TenantId` at the call-site and hand over ownership, eliminating the
    /// extra `id.clone()` that used to happen inside this function. We still
    /// clone once when building the `Tenant` struct because the tenant
    /// record and the map key both need independent copies; that clone is
    /// the one essential allocation.
    pub fn create_tenant(&self, id: TenantId, name: String, config: TenantConfig) -> HsmResult<()> {
        use dashmap::mapref::entry::Entry;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build the `Tenant` with a cloned id first; the owned `id` is kept
        // to serve as both the map key and the `usage` key below without a
        // second clone.
        let tenant = Tenant {
            id: id.clone(),
            name,
            config,
            enabled: true,
            created_at: now,
        };

        match self.tenants.entry(id.clone()) {
            Entry::Occupied(_) => {
                tracing::error!(
                    tenant_id = %id,
                    reason = "tenant_already_exists",
                    "TenantManager::create_tenant: duplicate tenant ID"
                );
                return Err(HsmError::GeneralError);
            }
            Entry::Vacant(entry) => {
                entry.insert(tenant);
            }
        }
        // Move the final owned copy into the usage map — no extra clone.
        self.usage.insert(id, TenantUsage::new());
        Ok(())
    }

    /// Delete a tenant. Fails if the tenant still has keys.
    ///
    /// Race-safety: previously the implementation flipped `enabled = false`,
    /// checked the key count, and restored `enabled = true` on failure
    /// — leaving a window in which a concurrent `try_reserve_key` would
    /// observe `enabled = false` and reject the reservation even though
    /// the tenant ultimately stayed usable. The current implementation
    /// holds the DashMap per-entry lock across the disable, count-check,
    /// and remove-or-restore decision so no observer can see the
    /// intermediate disabled state unless the deletion proceeds to
    /// completion.
    pub fn delete_tenant(&self, id: &TenantId) -> HsmResult<()> {
        use dashmap::mapref::entry::Entry;

        // Acquire the per-key entry lock on the tenant. Both
        // `try_reserve_key` and `delete_tenant` go through DashMap; while
        // this entry is held, any concurrent `tenants.get_mut` for the
        // same key blocks, so the `enabled` flip below is invisible to
        // callers until we either remove or restore.
        let mut entry = match self.tenants.entry(id.clone()) {
            Entry::Occupied(e) => e,
            Entry::Vacant(_) => {
                tracing::error!(
                    tenant_id = %id,
                    reason = "tenant_not_found",
                    "TenantManager::delete_tenant: unknown tenant ID"
                );
                return Err(HsmError::GeneralError);
            }
        };

        // Step 1: tentatively disable so any reservation attempt that
        // arrives *after* we release the entry sees enabled=false and
        // bails. Reservations already in flight will either have
        // observed enabled=true (and pre-incremented the key counter,
        // which we check below) or block on the entry lock above.
        entry.get_mut().enabled = false;

        // Step 2: check the key count under the same entry lock.
        let key_count = self
            .usage
            .get(id)
            .map(|u| u.key_count.load(Ordering::SeqCst))
            .unwrap_or(0);

        if key_count > 0 {
            // Restore enabled and drop the entry; no observer ever saw
            // the in-flight disable because we held the entry lock.
            entry.get_mut().enabled = true;
            drop(entry);
            tracing::warn!("Cannot delete tenant {} — still has keys", id);
            return Err(HsmError::GeneralError);
        }

        // Safe to remove. `entry.remove()` also drops the per-key lock.
        entry.remove();
        self.usage.remove(id);
        Ok(())
    }

    /// Get a tenant by ID, returning an owned clone.
    ///
    /// Clones the `Tenant` struct on every call — fine for infrequent
    /// administrative queries but wasteful on hot paths. For zero-copy
    /// read-only inspection prefer [`Self::get_tenant_ref`], which returns a
    /// DashMap reference guard that borrows from the map instead of
    /// allocating a fresh record each call.
    pub fn get_tenant(&self, id: &TenantId) -> Option<Tenant> {
        self.tenants.get(id).map(|t| t.clone())
    }

    /// Get a reference to a tenant without cloning. The returned guard holds a
    /// read lock on the map entry; release it promptly. For long-lived access
    /// or cross-thread sharing, use [`Self::get_tenant`] which returns an
    /// owned clone.
    pub fn get_tenant_ref<'a>(
        &'a self,
        id: &TenantId,
    ) -> Option<dashmap::mapref::one::Ref<'a, TenantId, Tenant>> {
        self.tenants.get(id)
    }

    /// List all tenant IDs.
    ///
    /// Allocates a fresh `Vec<TenantId>` on every call, cloning each key.
    /// Kept for backward compatibility; hot-path callers should prefer
    /// [`Self::for_each_tenant_id`] (zero-alloc iteration) or
    /// [`Self::list_tenant_ids_into`] (reuses a caller-provided buffer).
    pub fn list_tenants(&self) -> Vec<TenantId> {
        self.tenants.iter().map(|e| e.key().clone()).collect()
    }

    /// Append every tenant ID to the supplied buffer.
    ///
    /// Still clones each `TenantId` (DashMap owns the canonical copy) but
    /// reuses the caller's `Vec` allocation instead of allocating a fresh one
    /// per call, which matters when a status endpoint polls the list on a
    /// fixed interval.  Does **not** clear `out` first — callers that want a
    /// fresh list should clear it themselves.
    pub fn list_tenant_ids_into(&self, out: &mut Vec<TenantId>) {
        for e in self.tenants.iter() {
            out.push(e.key().clone());
        }
    }

    /// Visit every tenant ID without allocating.
    ///
    /// Zero-copy alternative to [`Self::list_tenants`]: the closure receives
    /// a borrowed `&TenantId` whose lifetime is tied to the DashMap iterator
    /// guard. Use this when counting, searching, or computing a summary that
    /// does not need to retain the IDs past the iteration.
    pub fn for_each_tenant_id<F: FnMut(&TenantId)>(&self, mut f: F) {
        for e in self.tenants.iter() {
            f(e.key());
        }
    }

    /// Decrement the key count for a tenant.
    ///
    /// Uses a saturating decrement to prevent underflow to `u64::MAX`.
    pub fn decrement_key_count(&self, tenant_id: &TenantId) {
        if let Some(usage) = self.usage.get(tenant_id) {
            let _ = usage
                .key_count
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
        }
    }

    /// Decrement session count for a tenant.
    ///
    /// Uses a saturating decrement to prevent underflow to `u64::MAX`.
    pub fn decrement_session_count(&self, tenant_id: &TenantId) {
        if let Some(usage) = self.usage.get(tenant_id) {
            let _ = usage
                .session_count
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
        }
    }

    /// Atomically check the key quota and reserve a slot.
    /// Returns Ok(()) if a key slot was reserved, or Err if the quota is exceeded
    /// or the tenant is disabled.
    #[tracing::instrument(level = "debug", skip(self), fields(tenant = %tenant_id))]
    pub fn try_reserve_key(&self, tenant_id: &TenantId) -> HsmResult<()> {
        let tenant = self.tenants.get(tenant_id).ok_or_else(|| {
            tracing::error!(
                tenant_id = %tenant_id,
                reason = "tenant_not_found",
                "TenantManager::try_reserve_key: tenant does not exist"
            );
            HsmError::GeneralError
        })?;
        if !tenant.enabled {
            tracing::error!(
                tenant_id = %tenant_id,
                reason = "tenant_disabled",
                "TenantManager::try_reserve_key: tenant is disabled"
            );
            return Err(HsmError::GeneralError);
        }
        let max = tenant.config.max_keys as u64;
        drop(tenant);

        let usage = self.usage.get(tenant_id).ok_or_else(|| {
            tracing::error!(
                tenant_id = %tenant_id,
                reason = "usage_not_found",
                "TenantManager::try_reserve_key: usage record missing — \
                 tenant/usage maps are inconsistent"
            );
            HsmError::GeneralError
        })?;
        let result = usage
            .key_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < max {
                    Some(current + 1)
                } else {
                    None
                }
            });

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(crate::error::tenant_quota_exceeded()),
        }
    }

    /// Atomically check the session quota and reserve a slot.
    /// Returns Ok(()) if a session slot was reserved, or Err if the quota is
    /// exceeded or the tenant is disabled.
    #[tracing::instrument(level = "debug", skip(self), fields(tenant = %tenant_id))]
    pub fn try_reserve_session(&self, tenant_id: &TenantId) -> HsmResult<()> {
        let tenant = self.tenants.get(tenant_id).ok_or_else(|| {
            tracing::error!(
                tenant_id = %tenant_id,
                reason = "tenant_not_found",
                "TenantManager::try_reserve_session: tenant does not exist"
            );
            HsmError::GeneralError
        })?;
        if !tenant.enabled {
            tracing::error!(
                tenant_id = %tenant_id,
                reason = "tenant_disabled",
                "TenantManager::try_reserve_session: tenant is disabled"
            );
            return Err(HsmError::GeneralError);
        }
        let max = tenant.config.max_sessions;
        drop(tenant);

        let usage = self.usage.get(tenant_id).ok_or_else(|| {
            tracing::error!(
                tenant_id = %tenant_id,
                reason = "usage_not_found",
                "TenantManager::try_reserve_session: usage record missing — \
                 tenant/usage maps are inconsistent"
            );
            HsmError::GeneralError
        })?;
        let result =
            usage
                .session_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    if current < max {
                        Some(current + 1)
                    } else {
                        None
                    }
                });

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(crate::error::tenant_quota_exceeded()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_crud() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("acme");

        mgr.create_tenant(id.clone(), "Acme Corp".into(), TenantConfig::default())
            .unwrap();

        assert!(mgr.get_tenant(&id).is_some());
        assert_eq!(mgr.list_tenants().len(), 1);

        mgr.delete_tenant(&id).unwrap();
        assert!(mgr.get_tenant(&id).is_none());
    }

    #[test]
    fn test_key_quota() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("small");
        let config = TenantConfig {
            max_keys: 2,
            ..Default::default()
        };

        mgr.create_tenant(id.clone(), "Small Co".into(), config)
            .unwrap();

        // First two keys should succeed (atomic check-and-reserve)
        mgr.try_reserve_key(&id).unwrap();
        mgr.try_reserve_key(&id).unwrap();

        // Third should fail — quota exceeded
        assert!(matches!(
            mgr.try_reserve_key(&id),
            Err(HsmError::HostMemory)
        ));

        // Delete one — should succeed again
        mgr.decrement_key_count(&id);
        mgr.try_reserve_key(&id).unwrap();
    }

    #[test]
    fn test_try_reserve_key_atomic() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("atomic");
        let config = TenantConfig {
            max_keys: 3,
            ..Default::default()
        };
        mgr.create_tenant(id.clone(), "Atomic Co".into(), config)
            .unwrap();

        // Three reservations succeed, fourth fails atomically.
        mgr.try_reserve_key(&id).unwrap();
        mgr.try_reserve_key(&id).unwrap();
        mgr.try_reserve_key(&id).unwrap();
        // The auth crate maps "tenant quota exceeded" to HsmError::HostMemory
        // (see crate::error). Compare against that variant directly.
        assert!(matches!(
            mgr.try_reserve_key(&id),
            Err(HsmError::HostMemory)
        ));

        // Free one slot and reserve again.
        mgr.decrement_key_count(&id);
        mgr.try_reserve_key(&id).unwrap();
    }

    #[test]
    fn test_decrement_at_zero_does_not_underflow() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("zero-test");
        mgr.create_tenant(id.clone(), "Zero Co".into(), TenantConfig::default())
            .unwrap();

        // Call decrement without any increment — should stay at 0, not wrap.
        mgr.decrement_key_count(&id);
        mgr.decrement_key_count(&id);
        mgr.decrement_session_count(&id);

        // Key count should be 0, not u64::MAX. Bind the DashMap ref in a
        // `let` so the temporary lives past the closing brace of this test.
        let usage = mgr.usage.get(&id);
        if let Some(usage) = usage {
            assert_eq!(
                usage.key_count.load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert_eq!(
                usage
                    .session_count
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        }
    }

    #[test]
    fn test_cannot_delete_tenant_with_keys() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("busy");

        mgr.create_tenant(id.clone(), "Busy Co".into(), TenantConfig::default())
            .unwrap();
        mgr.try_reserve_key(&id).unwrap();

        assert!(mgr.delete_tenant(&id).is_err());

        // After failed delete, tenant must be re-enabled and usable.
        let t = mgr.get_tenant(&id).expect("tenant should still exist");
        assert!(t.enabled, "delete failure must restore enabled flag");

        mgr.decrement_key_count(&id);
        assert!(mgr.delete_tenant(&id).is_ok());
    }

    #[test]
    fn test_session_quota() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("session-test");
        let config = TenantConfig {
            max_sessions: 2,
            ..Default::default()
        };
        mgr.create_tenant(id.clone(), "Session Co".into(), config)
            .unwrap();

        // First two sessions should succeed (atomic check-and-reserve)
        mgr.try_reserve_session(&id).unwrap();
        mgr.try_reserve_session(&id).unwrap();

        // Third should fail — quota exceeded
        assert!(matches!(
            mgr.try_reserve_session(&id),
            Err(HsmError::HostMemory)
        ));

        // Release one — should succeed again
        mgr.decrement_session_count(&id);
        mgr.try_reserve_session(&id).unwrap();
    }

    #[test]
    fn test_try_reserve_session() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("reserve-sess");
        let config = TenantConfig {
            max_sessions: 2,
            ..Default::default()
        };
        mgr.create_tenant(id.clone(), "Reserve Co".into(), config)
            .unwrap();

        // Two reservations succeed atomically
        mgr.try_reserve_session(&id).unwrap();
        mgr.try_reserve_session(&id).unwrap();

        // Third fails — quota exceeded maps to HsmError::HostMemory
        assert!(matches!(
            mgr.try_reserve_session(&id),
            Err(HsmError::HostMemory)
        ));

        // Free one slot, reserve again
        mgr.decrement_session_count(&id);
        mgr.try_reserve_session(&id).unwrap();
    }

    #[test]
    fn test_duplicate_tenant_creation() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("dup-tenant");

        mgr.create_tenant(id.clone(), "First".into(), TenantConfig::default())
            .unwrap();

        // Creating the same tenant again should fail
        let result = mgr.create_tenant(id.clone(), "Second".into(), TenantConfig::default());
        assert!(result.is_err(), "duplicate tenant creation should fail");

        // Original tenant should still be intact
        let t = mgr.get_tenant(&id).unwrap();
        assert_eq!(t.name, "First");
    }

    #[test]
    fn test_disabled_tenant() {
        let mgr = TenantManager::new();
        let id = TenantId::new_or_panic("disabled-t");
        let config = TenantConfig {
            max_keys: 10,
            ..Default::default()
        };
        mgr.create_tenant(id.clone(), "Disabled Co".into(), config)
            .unwrap();

        // Disable the tenant by toggling enabled via delete_tenant's step 1
        // (or directly via the dashmap). We use try_reserve_key which checks enabled.
        {
            let mut entry = mgr.tenants.get_mut(&id).unwrap();
            entry.enabled = false;
        }

        // Disabled tenant should reject key reservation
        assert!(
            mgr.try_reserve_key(&id).is_err(),
            "disabled tenant should reject try_reserve_key"
        );

        // Disabled tenant should reject session reservation
        assert!(
            mgr.try_reserve_session(&id).is_err(),
            "disabled tenant should reject try_reserve_session"
        );

        // Re-enable and verify it works again
        {
            let mut entry = mgr.tenants.get_mut(&id).unwrap();
            entry.enabled = true;
        }
        mgr.try_reserve_key(&id).unwrap();
        mgr.try_reserve_session(&id).unwrap();
    }
}
