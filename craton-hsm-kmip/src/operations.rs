// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! KMIP key lifecycle operations.
//!
//! Defines request/response structures, a key-store trait, an in-memory
//! implementation, and the individual operation handlers (Create, Get,
//! Activate, Revoke, Destroy, Query, GetAttributes, Register, Locate).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use zeroize::{Zeroize, Zeroizing};

use crate::types::{KmipObjectType, KmipOperation, KmipResultReason, KmipResultStatus};

// ---------------------------------------------------------------------------
// Object state
// ---------------------------------------------------------------------------

/// Lifecycle state of a managed cryptographic object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmipObjectState {
    /// Created but not yet `Activate`d; object is not usable.
    PreActive,
    /// Activated and usable for cryptographic operations.
    Active,
    /// Revoked; still retained but no longer usable.
    Deactivated,
    /// Revoked because key material is believed to be compromised.
    Compromised,
    /// Destroyed; key material is erased and the object is tombstoned.
    Destroyed,
}

impl fmt::Display for KmipObjectState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// Attribute types
// ---------------------------------------------------------------------------

/// Value of a KMIP attribute.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum KmipAttributeValue {
    /// UTF-8 text value.
    Text(String),
    /// 32-bit signed integer value.
    Integer(i32),
    /// 64-bit integer for values that exceed i32 range (e.g., epoch timestamps after 2038).
    LongInteger(i64),
    /// 32-bit enumeration value.
    Enum(u32),
    /// Opaque byte string.
    Bytes(Vec<u8>),
    /// Boolean value.
    Boolean(bool),
}

/// A named attribute attached to a KMIP object.
#[derive(Debug, Clone, PartialEq)]
pub struct KmipAttribute {
    /// KMIP attribute name.
    pub name: String,
    /// Attribute payload.
    pub value: KmipAttributeValue,
}

// ---------------------------------------------------------------------------
// Stored object
// ---------------------------------------------------------------------------

/// A cryptographic object stored in the key store.
///
/// Audit C/M (key-material zeroization): every clone produced by the
/// store carries its own copy of `key_material`. We implement
/// [`Drop`] (and [`Zeroize`]) so each copy is wiped from memory when
/// dropped — including evictions from the underlying [`DashMap`] when the
/// store is truncated, and copies returned to handlers that finish reading
/// the bytes. Without this, a `DashMap::remove` would deallocate the
/// `Vec<u8>` and leave the plaintext in the freed-but-not-cleared heap
/// region. [`Clone`] is implemented manually so the cloned `Vec` is
/// allocated fresh (so the original and the clone each get their own
/// `Drop` zeroization).
#[derive(Debug)]
pub struct KmipStoredObject {
    /// Unique identifier assigned by the server.
    pub id: String,
    /// Object type (symmetric key, private key, etc.).
    pub object_type: KmipObjectType,
    /// Current lifecycle state.
    pub state: KmipObjectState,
    /// Raw key material, if the object carries any.
    pub key_material: Option<Vec<u8>>,
    /// Named attributes attached to the object.
    pub attributes: HashMap<String, KmipAttributeValue>,
    /// Creation time in Unix seconds.
    pub created: u64,
    /// Last modification time in Unix seconds.
    pub modified: u64,
}

impl Clone for KmipStoredObject {
    fn clone(&self) -> Self {
        // Manual clone so the cloned `key_material` is its own allocation
        // and is itself zeroized on Drop (rather than sharing a reference
        // count with the original).
        Self {
            id: self.id.clone(),
            object_type: self.object_type,
            state: self.state,
            key_material: self.key_material.clone(),
            attributes: self.attributes.clone(),
            created: self.created,
            modified: self.modified,
        }
    }
}

impl Zeroize for KmipStoredObject {
    fn zeroize(&mut self) {
        if let Some(km) = self.key_material.as_mut() {
            km.zeroize();
        }
        self.key_material = None;
    }
}

impl Drop for KmipStoredObject {
    fn drop(&mut self) {
        // Audit C/M: wipe key material before the underlying allocation is
        // returned to the heap so a subsequent allocation cannot read it
        // back. The `Option` and `Vec` themselves do not need to be
        // zeroized — only the bytes the Vec owns.
        if let Some(km) = self.key_material.as_mut() {
            km.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------

/// A parsed KMIP request.
#[derive(Debug, Clone)]
pub struct KmipRequest {
    /// Requested operation.
    pub operation: KmipOperation,
    /// Target object identifier, if the operation references one.
    pub unique_id: Option<String>,
    /// Request attributes (e.g. `Create` template attributes).
    pub attributes: Vec<KmipAttribute>,
    /// Identity of the authenticated caller (set by the server after auth; `None`
    /// means unauthenticated or auth is disabled).
    pub caller_identity: Option<String>,
    /// Audit M / strict-owner-ACL: when `true`, an authenticated caller is
    /// denied access to ownerless objects. Set by the server dispatcher
    /// from `KmipOptions::strict_owner_acl`. Defaults to `false` so
    /// existing call sites that build `KmipRequest` directly retain
    /// pre-audit behaviour.
    pub strict_owner_acl: bool,
}

impl Default for KmipRequest {
    fn default() -> Self {
        Self {
            operation: KmipOperation::Query,
            unique_id: None,
            attributes: Vec::new(),
            caller_identity: None,
            strict_owner_acl: false,
        }
    }
}

/// A KMIP response to be serialized back to the client.
#[derive(Debug, Clone)]
pub struct KmipResponse {
    /// Result status (Success / OperationFailed / ...).
    pub status: KmipResultStatus,
    /// Reason code, present when `status` is not `Success`.
    pub reason: Option<KmipResultReason>,
    /// Free-form diagnostic message.
    pub message: Option<String>,
    /// Unique identifier of the affected object, when applicable.
    pub unique_id: Option<String>,
    /// Object type of the returned object (e.g. on `Get`).
    pub object_type: Option<KmipObjectType>,
    /// Key material returned by `Get`, when the object carries any.
    pub key_material: Option<Vec<u8>>,
    /// Attributes returned by GetAttributes.
    pub attributes: Vec<KmipAttribute>,
    /// Object IDs returned by Locate or capability lists returned by Query.
    pub located_ids: Vec<String>,
}

impl KmipResponse {
    /// Build a successful response with just a unique ID.
    pub fn success(unique_id: &str) -> Self {
        Self {
            status: KmipResultStatus::Success,
            reason: None,
            message: None,
            unique_id: Some(unique_id.to_string()),
            object_type: None,
            key_material: None,
            attributes: Vec::new(),
            located_ids: Vec::new(),
        }
    }

    /// Build an error response.
    pub fn error(reason: KmipResultReason, msg: &str) -> Self {
        Self {
            status: KmipResultStatus::OperationFailed,
            reason: Some(reason),
            message: Some(msg.to_string()),
            unique_id: None,
            object_type: None,
            key_material: None,
            attributes: Vec::new(),
            located_ids: Vec::new(),
        }
    }

    /// Build a bare success response with no unique ID (for Query, Locate).
    pub fn success_bare() -> Self {
        Self {
            status: KmipResultStatus::Success,
            reason: None,
            message: None,
            unique_id: None,
            object_type: None,
            key_material: None,
            attributes: Vec::new(),
            located_ids: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Immutable-attribute enforcement
// ---------------------------------------------------------------------------

/// Server-managed attributes that callers must never mutate via the
/// `add_attributes` / `modify_attributes` / `delete_attributes` trait
/// surface. Audit C/H: previously these were policed only by the dispatcher
/// handlers (`process_add_attribute`, `process_modify_attribute`,
/// `process_delete_attribute`), which meant a caller that obtained a
/// `KmipKeyStore` reference directly (e.g. through a tenant-facing library
/// embedding the in-memory store) could rewrite `owner` and silently
/// re-home a key. Centralising the list and enforcing it inside every
/// implementation of the store trait closes the bypass.
///
/// Comparisons against this list MUST be case-insensitive so a caller cannot
/// register `Owner` (capital O) to slip past a case-sensitive contains check.
pub const IMMUTABLE_ATTRIBUTES: &[&str] = &[
    "owner",
    "Cryptographic Algorithm",
    "Cryptographic Length",
    "Object Type",
    "Key Material",
];

/// Returns `true` when `name` (case-insensitively) is in
/// [`IMMUTABLE_ATTRIBUTES`] and therefore must not be added, modified, or
/// deleted by the caller.
pub fn is_immutable_attribute(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    IMMUTABLE_ATTRIBUTES
        .iter()
        .any(|i| i.to_ascii_lowercase() == lname)
}

// ---------------------------------------------------------------------------
// Server capability constants
// ---------------------------------------------------------------------------

/// Supported KMIP operations advertised via the Query response.
///
/// Only operations whose dispatcher returns a real KMIP result (not the
/// generic `OperationNotSupported` stub) are advertised here. Adding a new
/// entry implies a working handler in [`crate::operations`] and a routing
/// arm in `process_request`.
pub const SUPPORTED_OPERATIONS: &[KmipOperation] = &[
    KmipOperation::Create,
    KmipOperation::Get,
    KmipOperation::Activate,
    KmipOperation::Revoke,
    KmipOperation::Destroy,
    KmipOperation::Query,
    KmipOperation::GetAttributes,
    KmipOperation::Register,
    KmipOperation::Locate,
    KmipOperation::Check,
    KmipOperation::AddAttribute,
    KmipOperation::ModifyAttribute,
    KmipOperation::DeleteAttribute,
    KmipOperation::DeriveKey,
    KmipOperation::RngRetrieve,
];

/// Supported KMIP object types advertised via the Query response.
pub const SUPPORTED_OBJECT_TYPES: &[KmipObjectType] = &[
    KmipObjectType::SymmetricKey,
    KmipObjectType::PublicKey,
    KmipObjectType::PrivateKey,
];

// ---------------------------------------------------------------------------
// Key-store trait
// ---------------------------------------------------------------------------

/// Trait for KMIP key storage backends.
pub trait KmipKeyStore: Send + Sync {
    /// Create a new object, returning its unique identifier.
    fn create(
        &self,
        object_type: KmipObjectType,
        key_material: Vec<u8>,
        attributes: HashMap<String, KmipAttributeValue>,
    ) -> String;

    /// Retrieve an object by ID.
    fn get(&self, id: &str) -> Option<KmipStoredObject>;

    /// Transition an object to the Active state.
    fn activate(&self, id: &str) -> Result<(), KmipResultReason>;

    /// Transition an object to the Deactivated state (revoke).
    fn revoke(&self, id: &str) -> Result<(), KmipResultReason>;

    /// Mark an object as Destroyed.
    fn destroy(&self, id: &str) -> Result<(), KmipResultReason>;

    /// Locate objects matching the given attributes.
    fn locate(&self, attributes: &HashMap<String, KmipAttributeValue>) -> Vec<String>;

    /// Return the attributes for a given object ID.
    fn get_attributes(&self, id: &str) -> Option<Vec<KmipAttribute>>;

    /// Register an externally-created object, storing it in PreActive state.
    /// Returns the new object's unique identifier, or an error reason.
    fn register(
        &self,
        id: String,
        object_type: KmipObjectType,
        key_material: Option<Vec<u8>>,
        attributes: HashMap<String, KmipAttributeValue>,
    ) -> Result<String, KmipResultReason>;

    /// Add new attributes to an existing object. Returns an error if the
    /// object does not exist or if any attribute name already exists on
    /// it (case-insensitive comparison) — callers must resolve collisions
    /// (see `process_add_attribute`).
    fn add_attributes(
        &self,
        id: &str,
        new_attrs: HashMap<String, KmipAttributeValue>,
    ) -> Result<(), KmipResultReason>;

    /// Replace existing attributes on an object. Errors if the object does
    /// not exist; missing attribute names are validated by the caller before
    /// invocation (see `process_modify_attribute`).
    fn modify_attributes(
        &self,
        id: &str,
        attrs: HashMap<String, KmipAttributeValue>,
    ) -> Result<(), KmipResultReason>;

    /// Delete the named attributes from an object. Missing names should be
    /// validated by the caller; this method silently skips unknown names.
    fn delete_attributes(&self, id: &str, names: &[String]) -> Result<(), KmipResultReason>;

    /// Decrement an object's usage counter (if any). Returns the new value
    /// or `None` when the object has no `Cryptographic Usage Limits Counter`
    /// attribute. Used by `Check` to model real KMIP usage limits.
    fn decrement_usage_counter(&self, id: &str) -> Option<i64>;

    /// Run an ACL probe against the object identified by `id` without
    /// cloning it (returns `Some(true)` if the closure permits, `Some(false)`
    /// if it denies, `None` if the object does not exist).
    ///
    /// This is a deliberately monomorphic specialisation of a more general
    /// `with_object<R>(...)` callback: the generic version would force the
    /// trait into a non-`dyn`-compatible shape. Today every hot-path caller
    /// only needs a boolean answer (does this caller see this object?), so
    /// the boolean variant is the only `dyn`-safe form we expose.
    ///
    /// The default implementation calls [`KmipKeyStore::get`] which clones
    /// the entry; [`InMemoryKeyStore`] overrides this with a true
    /// borrow-only fast path that holds the DashMap reference for the
    /// lifetime of the closure.
    fn with_object_acl_probe(
        &self,
        id: &str,
        f: &(dyn Fn(&KmipStoredObject) -> bool + Send + Sync),
    ) -> Option<bool> {
        self.get(id).map(|o| f(&o))
    }
}

// ---------------------------------------------------------------------------
// In-memory key store
// ---------------------------------------------------------------------------

/// A thread-safe in-memory implementation of [`KmipKeyStore`].
///
/// Maintains a secondary index by `ObjectType` to accelerate `locate` queries
/// that filter on type (the most common KMIP locate pattern).
pub struct InMemoryKeyStore {
    objects: DashMap<String, KmipStoredObject>,
    /// Secondary index: object type → set of object IDs.
    type_index: DashMap<KmipObjectType, DashMap<String, ()>>,
    counter: AtomicU64,
}

impl InMemoryKeyStore {
    /// Create an empty in-memory key store.
    pub fn new() -> Self {
        Self {
            objects: DashMap::new(),
            type_index: DashMap::new(),
            counter: AtomicU64::new(1),
        }
    }

    /// Add an ID to the type index.
    fn index_insert(&self, object_type: KmipObjectType, id: &str) {
        self.type_index
            .entry(object_type)
            .or_insert_with(DashMap::new)
            .insert(id.to_string(), ());
    }

    /// Remove an ID from the type index.
    fn index_remove(&self, object_type: KmipObjectType, id: &str) {
        if let Some(ids) = self.type_index.get(&object_type) {
            ids.remove(id);
        }
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Monotonic-floor wall-clock seconds.
///
/// Audit M: `SystemTime::now()` can jump backwards if the operator slews
/// the wall clock (NTP step, manual `date -s ...`). Returning 0 on error
/// was also silent and would corrupt downstream lifecycle timestamps. We
/// instead remember the highest epoch we have ever observed and clamp the
/// current reading to that floor, so `created`/`modified` timestamps are
/// monotonically non-decreasing for the lifetime of the process. On a
/// genuine pre-epoch clock reading we still return the recorded floor
/// (never zero), which keeps every freshly-stored object distinguishable
/// in audit logs.
fn now_epoch() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static MONO_FLOOR: AtomicU64 = AtomicU64::new(0);
    let raw = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Compare-and-swap loop so concurrent callers settle on the max.
    let mut cur = MONO_FLOOR.load(AtomicOrdering::Acquire);
    loop {
        let candidate = raw.max(cur);
        match MONO_FLOOR.compare_exchange_weak(
            cur,
            candidate,
            AtomicOrdering::AcqRel,
            AtomicOrdering::Acquire,
        ) {
            Ok(_) => return candidate,
            Err(observed) => cur = observed,
        }
    }
}

impl KmipKeyStore for InMemoryKeyStore {
    fn create(
        &self,
        object_type: KmipObjectType,
        key_material: Vec<u8>,
        attributes: HashMap<String, KmipAttributeValue>,
    ) -> String {
        let seq = self.counter.fetch_add(1, Ordering::SeqCst);
        let id = format!("kmip-{seq:08x}");
        let ts = now_epoch();
        let obj = KmipStoredObject {
            id: id.clone(),
            object_type,
            state: KmipObjectState::PreActive,
            key_material: Some(key_material),
            attributes,
            created: ts,
            modified: ts,
        };
        self.index_insert(object_type, &id);
        self.objects.insert(id.clone(), obj);
        id
    }

    fn get(&self, id: &str) -> Option<KmipStoredObject> {
        self.objects.get(id).map(|r| r.clone())
    }

    fn activate(&self, id: &str) -> Result<(), KmipResultReason> {
        let mut entry = self
            .objects
            .get_mut(id)
            .ok_or(KmipResultReason::ObjectNotFound)?;
        if entry.state == KmipObjectState::Destroyed {
            return Err(KmipResultReason::ObjectNotFound);
        }
        if !allowed_transitions(entry.state, KmipObjectState::Active) {
            return Err(KmipResultReason::PermissionDenied);
        }
        entry.state = KmipObjectState::Active;
        entry.modified = now_epoch();
        Ok(())
    }

    fn revoke(&self, id: &str) -> Result<(), KmipResultReason> {
        let mut entry = self
            .objects
            .get_mut(id)
            .ok_or(KmipResultReason::ObjectNotFound)?;
        if entry.state == KmipObjectState::Destroyed {
            return Err(KmipResultReason::ObjectNotFound);
        }
        if !allowed_transitions(entry.state, KmipObjectState::Deactivated) {
            return Err(KmipResultReason::PermissionDenied);
        }
        entry.state = KmipObjectState::Deactivated;
        entry.modified = now_epoch();
        Ok(())
    }

    fn destroy(&self, id: &str) -> Result<(), KmipResultReason> {
        let mut entry = self
            .objects
            .get_mut(id)
            .ok_or(KmipResultReason::ObjectNotFound)?;
        if entry.state == KmipObjectState::Destroyed {
            return Err(KmipResultReason::ObjectNotFound);
        }
        // Centralised state-machine check (audit follow-up). Every destructive
        // transition routes through `allowed_transitions` so destroy and
        // activate cannot drift apart; in particular destroy(Compromised) is
        // rejected like destroy(Active) — a compromised key must be retained
        // for forensics and only the operator can erase it out-of-band.
        if !allowed_transitions(entry.state, KmipObjectState::Destroyed) {
            return Err(KmipResultReason::PermissionDenied);
        }
        entry.state = KmipObjectState::Destroyed;
        // Remove from type index since destroyed objects are filtered out.
        self.index_remove(entry.object_type, id);
        // Securely zero key material before deallocation to prevent recovery
        // from process memory dumps or cold-boot attacks.
        if let Some(ref mut km) = entry.key_material {
            km.zeroize();
        }
        entry.key_material = None;
        entry.modified = now_epoch();
        Ok(())
    }

    fn locate(&self, attributes: &HashMap<String, KmipAttributeValue>) -> Vec<String> {
        // Audit perf finding: when the filter pins an Object Type, scan the
        // type_index (small set of ids) instead of the full objects map.
        if let Some(KmipAttributeValue::Enum(ot_val)) = attributes.get("Object Type") {
            if let Some(ot) = KmipObjectType::from_u32(*ot_val) {
                if let Some(type_ids) = self.type_index.get(&ot) {
                    let mut out = Vec::new();
                    for entry in type_ids.iter() {
                        let id = entry.key().clone();
                        if let Some(obj) = self.objects.get(&id) {
                            let obj = obj.value();
                            if obj.state == KmipObjectState::Destroyed {
                                continue;
                            }
                            if attributes.iter().all(|(k, v)| {
                                if k == "Object Type" {
                                    true
                                } else {
                                    obj.attributes.get(k) == Some(v)
                                }
                            }) {
                                out.push(id);
                            }
                        }
                    }
                    return out;
                }
                return Vec::new();
            }
        }
        self.objects
            .iter()
            .filter(|entry| {
                let obj = entry.value();
                if obj.state == KmipObjectState::Destroyed {
                    return false;
                }
                attributes
                    .iter()
                    .all(|(k, v)| obj.attributes.get(k) == Some(v))
            })
            .map(|entry| entry.key().clone())
            .collect()
    }

    fn get_attributes(&self, id: &str) -> Option<Vec<KmipAttribute>> {
        let entry = self.objects.get(id)?;
        let obj = entry.value();
        // Names that this method synthesizes from object-intrinsic fields.
        // If a stored attribute collides (case-insensitively), the synthetic
        // value wins and the stored copy is dropped with a `warn!` — audit M
        // (synthetic-attribute shadowing). The reason: callers always expect
        // these names to reflect server-managed lifecycle state; allowing
        // a stored-attribute override would let a malicious Register call
        // forge a fake `State` or `Object Type` for the same object.
        const SYNTHETIC_NAMES: &[&str] =
            &["State", "Object Type", "Initial Date", "Last Change Date"];

        let mut attrs: Vec<KmipAttribute> = Vec::with_capacity(obj.attributes.len() + 4);
        for (name, value) in obj.attributes.iter() {
            let lname = name.to_ascii_lowercase();
            if SYNTHETIC_NAMES
                .iter()
                .any(|s| s.to_ascii_lowercase() == lname)
            {
                tracing::warn!(
                    target: "craton_hsm_kmip::attrs",
                    object_id = %id,
                    attribute = %name,
                    "stored attribute name collides with synthetic; dropping stored value in favour of server-managed synthetic"
                );
                continue;
            }
            attrs.push(KmipAttribute {
                name: name.clone(),
                value: value.clone(),
            });
        }

        // Synthetic attribute: State (as text so callers don't need to know
        // the numeric encoding).
        attrs.push(KmipAttribute {
            name: "State".to_string(),
            value: KmipAttributeValue::Text(obj.state.to_string()),
        });

        // Synthetic attribute: Object Type (numeric enum value).
        attrs.push(KmipAttribute {
            name: "Object Type".to_string(),
            value: KmipAttributeValue::Enum(obj.object_type.to_u32()),
        });

        // Synthetic attribute: Initial Date (creation timestamp).
        // Use i64 to avoid Y2038 overflow (u64 epoch seconds exceed i32 range after 2038).
        attrs.push(KmipAttribute {
            name: "Initial Date".to_string(),
            value: KmipAttributeValue::LongInteger(obj.created as i64),
        });

        // Synthetic attribute: Last Change Date (modification timestamp).
        attrs.push(KmipAttribute {
            name: "Last Change Date".to_string(),
            value: KmipAttributeValue::LongInteger(obj.modified as i64),
        });

        Some(attrs)
    }

    fn register(
        &self,
        id: String,
        object_type: KmipObjectType,
        key_material: Option<Vec<u8>>,
        attributes: HashMap<String, KmipAttributeValue>,
    ) -> Result<String, KmipResultReason> {
        let ts = now_epoch();
        // Audit C/H: atomic insert-if-absent via DashMap::entry. The TOCTOU
        // race between a previous `contains_key`/`insert` pair could let two
        // concurrent Register calls both observe "id free" and have the
        // second silently overwrite the first. The entry API locks the
        // shard so the closure inside `or_insert_with` runs at most once
        // per id across all threads.
        let mut inserted = false;
        self.objects.entry(id.clone()).or_insert_with(|| {
            inserted = true;
            KmipStoredObject {
                id: id.clone(),
                object_type,
                state: KmipObjectState::PreActive,
                key_material,
                attributes,
                created: ts,
                modified: ts,
            }
        });
        if inserted {
            // Index update happens only on a real insert so collided ids
            // never pollute the type_index.
            self.index_insert(object_type, &id);
            Ok(id)
        } else {
            // Audit M (Register collision as existence oracle): masking the
            // collision as `ObjectNotFound` matches the rest of the ACL
            // surface so an attacker who races a Register against a known
            // foreign id cannot tell duplicate-id from unauthorized. The
            // ACL gate in `process_register` already returns ObjectNotFound
            // when the caller is not the owner of the pre-existing id; we
            // now return the same reason on the owner path so the wire
            // response shape is uniform.
            Err(KmipResultReason::ObjectNotFound)
        }
    }

    fn add_attributes(
        &self,
        id: &str,
        new_attrs: HashMap<String, KmipAttributeValue>,
    ) -> Result<(), KmipResultReason> {
        let mut entry = match self.objects.get_mut(id) {
            Some(e) => e,
            None => return Err(KmipResultReason::ObjectNotFound),
        };
        // Audit C/H (Owner ACL bypass): every store implementation MUST
        // refuse to mutate the IMMUTABLE_ATTRIBUTES set, not just the
        // dispatcher. Centralising the check here means a caller that
        // obtains a `KmipKeyStore` reference cannot rewrite `owner` (and
        // re-home a key) by bypassing `process_add_attribute`.
        for (k, _) in new_attrs.iter() {
            if is_immutable_attribute(k) {
                return Err(KmipResultReason::PermissionDenied);
            }
        }
        // Audit finding M (AddAttribute case-sensitivity): collision check
        // must be case-insensitive so a caller cannot register two
        // attributes that differ only in case (e.g. `Owner` vs `owner`)
        // and bypass the immutable list. Internal whitespace in attribute
        // names is also rejected — KMIP spec uses spaces only between
        // tokens, never embedded tabs / repeated whitespace.
        for (k, _) in new_attrs.iter() {
            let trimmed = k.trim();
            if trimmed.is_empty()
                || trimmed != k
                || k.chars().any(|c| c.is_whitespace() && c != ' ')
            {
                return Err(KmipResultReason::InvalidField);
            }
            let lk = k.to_ascii_lowercase();
            if entry
                .attributes
                .keys()
                .any(|existing| existing.to_ascii_lowercase() == lk)
            {
                return Err(KmipResultReason::InvalidField);
            }
        }
        for (k, v) in new_attrs {
            entry.attributes.insert(k, v);
        }
        entry.modified = now_epoch();
        Ok(())
    }

    fn modify_attributes(
        &self,
        id: &str,
        attrs: HashMap<String, KmipAttributeValue>,
    ) -> Result<(), KmipResultReason> {
        let mut entry = match self.objects.get_mut(id) {
            Some(e) => e,
            None => return Err(KmipResultReason::ObjectNotFound),
        };
        // Audit C/H (Owner ACL bypass) — see `add_attributes` above.
        for (k, _) in attrs.iter() {
            if is_immutable_attribute(k) {
                return Err(KmipResultReason::PermissionDenied);
            }
        }
        for (k, v) in attrs {
            entry.attributes.insert(k, v);
        }
        entry.modified = now_epoch();
        Ok(())
    }

    fn delete_attributes(&self, id: &str, names: &[String]) -> Result<(), KmipResultReason> {
        let mut entry = match self.objects.get_mut(id) {
            Some(e) => e,
            None => return Err(KmipResultReason::ObjectNotFound),
        };
        // Audit C/H (Owner ACL bypass) — see `add_attributes` above.
        for n in names {
            if is_immutable_attribute(n) {
                return Err(KmipResultReason::PermissionDenied);
            }
        }
        for n in names {
            entry.attributes.remove(n);
        }
        entry.modified = now_epoch();
        Ok(())
    }

    fn decrement_usage_counter(&self, id: &str) -> Option<i64> {
        let mut entry = self.objects.get_mut(id)?;
        let cur = match entry.attributes.get("Cryptographic Usage Limits Counter") {
            Some(KmipAttributeValue::LongInteger(v)) => *v,
            Some(KmipAttributeValue::Integer(v)) => *v as i64,
            _ => return None,
        };
        let next = cur.saturating_sub(1).max(0);
        entry.attributes.insert(
            "Cryptographic Usage Limits Counter".to_string(),
            KmipAttributeValue::LongInteger(next),
        );
        entry.modified = now_epoch();
        Some(next)
    }

    fn with_object_acl_probe(
        &self,
        id: &str,
        f: &(dyn Fn(&KmipStoredObject) -> bool + Send + Sync),
    ) -> Option<bool> {
        // Audit perf finding: avoid cloning KmipStoredObject on every owner-
        // ACL probe. The DashMap reference guard keeps the entry pinned for
        // the duration of the closure call.
        self.objects.get(id).map(|r| f(r.value()))
    }
}

// ---------------------------------------------------------------------------
// Operation handlers
// ---------------------------------------------------------------------------

/// Constant-time string equality used for the owner-ACL comparison so a
/// remote attacker cannot use timing differences to enumerate the owner
/// attribute of objects they do not own (audit finding H23).
fn ct_str_eq(a: &str, b: &str) -> bool {
    use subtle::{Choice, ConstantTimeEq};
    let aa = a.as_bytes();
    let bb = b.as_bytes();

    // Audit M (length-mismatch timing): never short-circuit on length. Pad
    // both inputs to the maximum of the two lengths and fold the byte-by-byte
    // XOR through a constant-time accumulator. A length difference is folded
    // into the final `Choice` so callers cannot distinguish "same length,
    // different bytes" from "different lengths" by timing the response.
    let max_len = aa.len().max(bb.len());
    let mut diff: u8 = 0;
    for i in 0..max_len {
        let av = *aa.get(i).unwrap_or(&0);
        let bv = *bb.get(i).unwrap_or(&0);
        diff |= av ^ bv;
    }
    // Length-mismatch component, folded in constant time (the cast is a
    // constant-time operation; `Choice::from` only accepts 0 or 1).
    let len_mismatch: u8 = ((aa.len() ^ bb.len()) != 0) as u8;

    // Both `diff == 0` AND `len_mismatch == 0` ⇒ equal.
    let byte_eq: Choice = 0u8.ct_eq(&diff);
    let len_eq: Choice = 0u8.ct_eq(&len_mismatch);
    bool::from(byte_eq & len_eq)
}

/// Check owner-based access control on an object.
///
/// If the object has an "owner" attribute, only the matching caller identity
/// may perform operations on it. Returns `Ok(())` if access is permitted,
/// or an error `KmipResponse` if denied.
///
/// Security: the wire-level error returned to unauthorized callers is
/// `ObjectNotFound`, not `PermissionDenied`, so an unauthenticated or
/// other-tenant probe cannot map the keyspace by distinguishing
/// "key exists but you can't see it" from "key doesn't exist". The real
/// reason is still logged server-side for audit.
fn check_owner_acl(
    obj: &KmipStoredObject,
    caller_identity: &Option<String>,
) -> Result<(), KmipResponse> {
    // Backwards-compatible legacy entrypoint. Audit-aware callers should
    // route through `check_owner_acl_for_request` so the strict flag from
    // the dispatcher is honoured.
    check_owner_acl_with_options(obj, caller_identity, false)
}

/// Audit-aware variant: reads `strict_owner_acl` from the parsed request.
fn check_owner_acl_for_request(
    obj: &KmipStoredObject,
    request: &KmipRequest,
) -> Result<(), KmipResponse> {
    check_owner_acl_with_options(obj, &request.caller_identity, request.strict_owner_acl)
}

/// Owner-ACL check with the audit-driven `strict_owner_acl` toggle.
///
/// When `strict_owner_acl` is `true` AND the caller is authenticated AND
/// the object has no `owner` attribute, the check fails closed (audit M).
/// This prevents tenants from accidentally sharing legacy ownerless keys
/// once the policy is tightened. When the flag is `false` the legacy
/// behaviour is preserved: ownerless objects remain visible.
///
/// All `owner == caller` comparisons are performed with
/// [`subtle::ConstantTimeEq`] so a malicious client cannot use timing
/// differences in the comparison loop to enumerate other tenants.
fn check_owner_acl_with_options(
    obj: &KmipStoredObject,
    caller_identity: &Option<String>,
    strict_owner_acl: bool,
) -> Result<(), KmipResponse> {
    if let Some(KmipAttributeValue::Text(owner)) = obj.attributes.get("owner") {
        match caller_identity {
            Some(caller) if ct_str_eq(caller, owner) => Ok(()),
            Some(caller) => {
                tracing::warn!(
                    target: "kmip.audit",
                    caller = %caller,
                    "owner ACL denied; responding with ObjectNotFound to avoid key-existence oracle"
                );
                Err(KmipResponse::error(
                    KmipResultReason::ObjectNotFound,
                    "object not found",
                ))
            }
            None => {
                tracing::warn!(
                    target: "kmip.audit",
                    "unauthenticated access to owner-protected object; responding with ObjectNotFound"
                );
                Err(KmipResponse::error(
                    KmipResultReason::ObjectNotFound,
                    "object not found",
                ))
            }
        }
    } else if strict_owner_acl && caller_identity.is_some() {
        // Audit finding (M): under `strict_owner_acl`, an authenticated
        // caller is denied access to legacy ownerless objects. The error
        // is masked as `ObjectNotFound` for parity with the owner-mismatch
        // branch above so the wire response does not become an existence
        // oracle for ownerless keys.
        tracing::warn!(
            target: "kmip.audit",
            "strict_owner_acl: denying access to ownerless object"
        );
        Err(KmipResponse::error(
            KmipResultReason::ObjectNotFound,
            "object not found",
        ))
    } else {
        Ok(())
    }
}

/// Perform an ACL-checked state transition atomically.
/// Gets the object, verifies ownership, then applies the mutation.
fn acl_checked_transition(
    store: &dyn KmipKeyStore,
    id: &str,
    caller_identity: &Option<String>,
    _operation_name: &str,
    mutate: impl FnOnce(&str, &dyn KmipKeyStore) -> KmipResponse,
) -> KmipResponse {
    // Verify ACL before proceeding. The window between check and mutation
    // is minimized by performing them in sequence without yielding.
    if let Some(obj) = store.get(id) {
        if let Err(resp) = check_owner_acl(&obj, caller_identity) {
            return resp;
        }
    }
    mutate(id, store)
}

/// Process a Create operation: generate key material and store it.
pub fn process_create(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    // Determine algorithm and length from attributes.
    let mut algo = None;
    // Explicit key length is now mandatory (audit finding H7). A silent
    // default of 256 could produce a key of a different size than the
    // caller assumed, especially if the default ever changes.
    let mut key_len: Option<i32> = None;

    let mut attrs = HashMap::new();

    for attr in &request.attributes {
        match attr.name.as_str() {
            "Cryptographic Algorithm" => {
                if let KmipAttributeValue::Enum(v) = &attr.value {
                    algo = Some(*v);
                }
                attrs.insert(attr.name.clone(), attr.value.clone());
            }
            "Cryptographic Length" => {
                if let KmipAttributeValue::Integer(v) = &attr.value {
                    key_len = Some(*v);
                }
                attrs.insert(attr.name.clone(), attr.value.clone());
            }
            _ => {
                attrs.insert(attr.name.clone(), attr.value.clone());
            }
        }
    }

    let key_len = match key_len {
        Some(v) => v,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidField,
                "Create requires an explicit Cryptographic Length attribute",
            );
        }
    };

    // Validate algorithm if specified. Only symmetric algorithms are supported
    // for key creation (random-byte generation). Asymmetric algorithms require
    // proper key-pair generation which is not yet implemented.
    if let Some(alg) = algo {
        match alg {
            0x01 => {
                // 3DES
                if key_len != 128 && key_len != 192 {
                    return KmipResponse::error(
                        KmipResultReason::InvalidField,
                        &format!("3DES requires key length 128 or 192 bits, got {key_len}"),
                    );
                }
            }
            0x03 => {
                // AES
                if key_len != 128 && key_len != 192 && key_len != 256 {
                    return KmipResponse::error(
                        KmipResultReason::InvalidField,
                        &format!("AES requires key length 128, 192, or 256 bits, got {key_len}"),
                    );
                }
            }
            _ => {
                return KmipResponse::error(
                    KmipResultReason::InvalidField,
                    &format!("unsupported algorithm 0x{alg:04x} for symmetric key creation"),
                );
            }
        }
    }

    if key_len <= 0 {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            &format!("Cryptographic Length must be positive, got {key_len}"),
        );
    }

    if key_len % 8 != 0 || key_len < 128 {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            "Cryptographic Length must be a multiple of 8 and at least 128 bits",
        );
    }

    // Auto-attach the authenticated caller as `owner` if the request did not
    // set one. Without this, Create produces world-readable objects (M5).
    if !attrs.contains_key("owner") {
        if let Some(caller) = request.caller_identity.clone() {
            attrs.insert("owner".to_string(), KmipAttributeValue::Text(caller));
        }
    }

    // Generate random key material via a positive-bounded u32 so the
    // `i32 → usize` cast is guaranteed safe.
    let byte_len = (key_len as u32) as usize / 8;
    let mut material = vec![0u8; byte_len];
    use rand::RngCore;
    if let Err(e) = rand::rngs::OsRng.try_fill_bytes(&mut material) {
        tracing::error!(
            target: "craton_hsm_kmip::rng",
            error = %e,
            "OS RNG failed during Create; returning CryptographicFailure"
        );
        return KmipResponse::error(KmipResultReason::CryptographicFailure, "OS RNG unavailable");
    }

    let id = key_store.create(KmipObjectType::SymmetricKey, material, attrs);
    tracing::info!(
        kmip.op = "Create",
        kmip.unique_id = %id,
        kmip.caller = ?request.caller_identity,
        kmip.key_len_bits = key_len,
        "KMIP Create succeeded"
    );
    let mut resp = KmipResponse::success(&id);
    resp.object_type = Some(KmipObjectType::SymmetricKey);
    resp
}

/// Process a Get operation: retrieve key by ID.
pub fn process_get(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "Get requires a UniqueIdentifier",
            );
        }
    };

    match key_store.get(id) {
        Some(obj) if obj.state == KmipObjectState::Destroyed => KmipResponse::error(
            KmipResultReason::ObjectNotFound,
            "object has been destroyed",
        ),
        Some(mut obj) => {
            if let Err(resp) = check_owner_acl_for_request(&obj, request) {
                return resp;
            }
            let mut resp = KmipResponse::success(&obj.id);
            resp.object_type = Some(obj.object_type);
            // `KmipStoredObject` now implements `Drop` (audit C/M: zeroize
            // key material on drop) so we cannot move the field out of `obj`
            // — the Drop impl needs to run on a complete struct. Take the
            // field via `Option::take()` instead so the receiver-side Drop
            // sees a `None` and does no work.
            resp.key_material = obj.key_material.take();
            resp
        }
        None => KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found"),
    }
}

/// Process an Activate operation.
pub fn process_activate(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "Activate requires a UniqueIdentifier",
            );
        }
    };

    // ACL-checked state transition: verify ownership and activate atomically.
    let caller = request.caller_identity.clone();
    acl_checked_transition(
        key_store,
        id,
        &request.caller_identity,
        "Activate",
        move |id, store| match store.activate(id) {
            Ok(()) => {
                tracing::info!(
                    kmip.op = "Activate",
                    kmip.unique_id = %id,
                    kmip.caller = ?caller,
                    "KMIP Activate succeeded"
                );
                KmipResponse::success(id)
            }
            Err(reason) => KmipResponse::error(reason, &format!("activate failed for {id}")),
        },
    )
}

/// Process a Revoke operation.
pub fn process_revoke(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "Revoke requires a UniqueIdentifier",
            );
        }
    };

    // ACL-checked state transition: verify ownership and revoke atomically.
    let caller = request.caller_identity.clone();
    acl_checked_transition(
        key_store,
        id,
        &request.caller_identity,
        "Revoke",
        move |id, store| match store.revoke(id) {
            Ok(()) => {
                tracing::info!(
                    kmip.op = "Revoke",
                    kmip.unique_id = %id,
                    kmip.caller = ?caller,
                    "KMIP Revoke succeeded"
                );
                KmipResponse::success(id)
            }
            Err(reason) => KmipResponse::error(reason, &format!("revoke failed for {id}")),
        },
    )
}

/// Process a Destroy operation.
pub fn process_destroy(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "Destroy requires a UniqueIdentifier",
            );
        }
    };

    // ACL-checked state transition: verify ownership and destroy atomically.
    let caller = request.caller_identity.clone();
    acl_checked_transition(
        key_store,
        id,
        &request.caller_identity,
        "Destroy",
        move |id, store| match store.destroy(id) {
            Ok(()) => {
                tracing::info!(
                    kmip.op = "Destroy",
                    kmip.unique_id = %id,
                    kmip.caller = ?caller,
                    "KMIP Destroy succeeded"
                );
                KmipResponse::success(id)
            }
            Err(reason) => KmipResponse::error(reason, &format!("destroy failed for {id}")),
        },
    )
}

/// Process a Query operation: return server capabilities.
///
/// The response carries the supported operations and object types in the
/// `located_ids` field (encoded as their string names) so the caller can
/// inspect them without needing additional fields on `KmipResponse`.
/// Supported operations are serialised as "OP:<name>" entries and supported
/// object types as "OT:<name>" entries in `located_ids`.
pub fn process_query(_request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    let mut resp = KmipResponse::success_bare();

    for op in SUPPORTED_OPERATIONS {
        resp.located_ids.push(format!("OP:{op}"));
    }

    for ot in SUPPORTED_OBJECT_TYPES {
        resp.located_ids.push(format!("OT:{ot}"));
    }

    resp
}

/// Process a GetAttributes operation: return attributes for a given object.
///
/// Owner ACL is enforced: a caller that is not the object's owner receives a
/// `PermissionDenied` (or, for a non-existent object, `ObjectNotFound`). This
/// closes the metadata-leak cross-tenant gap reported as audit finding H6.
pub fn process_get_attributes(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "GetAttributes requires a UniqueIdentifier",
            );
        }
    };

    let obj = match key_store.get(id) {
        Some(o) => o,
        None => {
            return KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found");
        }
    };
    if let Err(resp) = check_owner_acl_for_request(&obj, request) {
        return resp;
    }

    match key_store.get_attributes(id) {
        Some(attrs) => {
            let mut resp = KmipResponse::success(id);
            resp.attributes = attrs;
            resp
        }
        None => KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found"),
    }
}

/// Process a Register operation: import an externally-created key.
///
/// The request must include a `unique_id` (used as the object's identifier).
/// An "Object Type" attribute (Enum value) specifies the type; if absent,
/// `SymmetricKey` is assumed.  Optional `key_material` is taken from a
/// "Key Material" attribute (Bytes value) if present.  All other attributes
/// are stored as-is.  The imported object is placed in PreActive state.
///
/// # Pre-existing-ID handling
///
/// If a non-destroyed object already exists under `unique_id`, the owner ACL
/// is consulted to decide whether the caller is permitted to replace it. A
/// non-owner receives `ObjectNotFound` (the same masking pattern used
/// everywhere else in this module — see [`check_owner_acl`]) so that
/// Register cannot be abused as a key-existence oracle for cross-tenant
/// identifiers.
pub fn process_register(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id.clone(),
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "Register requires a UniqueIdentifier",
            );
        }
    };

    // Audit follow-up (2026-04-19 pass 3): Register must consult the
    // owner ACL when an object already exists under the requested ID so an
    // attacker cannot overwrite — or probe the existence of — another
    // tenant's object. `process_create` generates a fresh ID and therefore
    // cannot collide, but Register is caller-chosen. We intentionally return
    // the same `ObjectNotFound` reason the rest of the ACL layer uses to
    // avoid turning Register into an existence oracle.
    if let Some(existing) = key_store.get(&id) {
        if let Err(resp) = check_owner_acl_for_request(&existing, request) {
            return resp;
        }
    }

    // Derive object type and optional key material from the request attributes.
    let mut object_type = KmipObjectType::SymmetricKey;
    let mut key_material: Option<Vec<u8>> = None;
    let mut attrs: HashMap<String, KmipAttributeValue> = HashMap::new();

    for attr in &request.attributes {
        match attr.name.as_str() {
            "Object Type" => {
                if let KmipAttributeValue::Enum(v) = &attr.value {
                    match KmipObjectType::from_u32(*v) {
                        Some(ot) => object_type = ot,
                        None => {
                            // Audit M (silent default on unknown Object Type):
                            // refuse the request rather than coerce an unknown
                            // wire enum into the default `SymmetricKey`. A
                            // server that silently picks `SymmetricKey` would
                            // let a misbehaving client register e.g. a chunk
                            // of arbitrary key material claiming an unsupported
                            // type and then read it back as a symmetric key.
                            return KmipResponse::error(
                                KmipResultReason::InvalidField,
                                &format!("unknown Object Type enum value: 0x{v:08x}"),
                            );
                        }
                    }
                }
                // Still store it in the attribute map.
                attrs.insert(attr.name.clone(), attr.value.clone());
            }
            "Key Material" => {
                if let KmipAttributeValue::Bytes(b) = &attr.value {
                    key_material = Some(b.clone());
                }
                // Do NOT store key material in the attribute map; it lives in
                // the dedicated field on the stored object.
            }
            _ => {
                attrs.insert(attr.name.clone(), attr.value.clone());
            }
        }
    }

    // Auto-attach the authenticated caller as `owner` if Register did not
    // specify one. Without this, Register could produce world-readable
    // objects (audit finding M5).
    if !attrs.contains_key("owner") {
        if let Some(caller) = request.caller_identity.clone() {
            attrs.insert("owner".to_string(), KmipAttributeValue::Text(caller));
        }
    }

    match key_store.register(id, object_type, key_material, attrs) {
        Ok(new_id) => {
            tracing::info!(
                kmip.op = "Register",
                kmip.unique_id = %new_id,
                kmip.caller = ?request.caller_identity,
                "KMIP Register succeeded"
            );
            let mut resp = KmipResponse::success(&new_id);
            resp.object_type = Some(object_type);
            resp
        }
        Err(reason) => KmipResponse::error(reason, "register failed"),
    }
}

/// Process a Check operation: test whether an object is usable (exists,
/// is not destroyed, and the caller has access). KMIP 2.1 §6 defines
/// Check as a lightweight usability probe used by health checks.
pub fn process_check(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "Check requires a UniqueIdentifier",
            );
        }
    };
    let obj = match key_store.get(id) {
        Some(o) => o,
        None => {
            return KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found");
        }
    };
    if obj.state == KmipObjectState::Destroyed {
        return KmipResponse::error(
            KmipResultReason::ObjectNotFound,
            "object has been destroyed",
        );
    }
    if let Err(resp) = check_owner_acl_for_request(&obj, request) {
        return resp;
    }
    // Real usage-count decrement (audit follow-up). When the object has a
    // `Cryptographic Usage Limits Counter` attribute we decrement by one and
    // surface the remaining count in the response. Objects without a counter
    // continue to behave as a plain "is this key usable?" probe.
    let mut resp = KmipResponse::success(&obj.id);
    if let Some(remaining) = key_store.decrement_usage_counter(&obj.id) {
        resp.attributes.push(KmipAttribute {
            name: "Cryptographic Usage Limits Counter".to_string(),
            value: KmipAttributeValue::LongInteger(remaining),
        });
    }
    resp
}

/// Process an AddAttribute operation.
///
/// KMIP 2.1 §6 semantics are only partially implemented: we allow the caller
/// to add (but not replace) custom attributes on an object they own. Mutation
/// of security-critical attributes (`owner`, `Cryptographic Algorithm`,
/// `Cryptographic Length`, `Object Type`) is refused so that a compromised
/// client cannot re-home a key or silently reinterpret it. Operators who
/// need full AddAttribute semantics (replace-on-collision, server-assigned
/// values) should layer their own policy above this handler.
pub fn process_add_attribute(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id,
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "AddAttribute requires a UniqueIdentifier",
            );
        }
    };
    if request.attributes.is_empty() {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            "AddAttribute requires at least one attribute",
        );
    }

    let obj = match key_store.get(id) {
        Some(o) => o,
        None => {
            return KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found");
        }
    };
    if let Err(resp) = check_owner_acl_for_request(&obj, request) {
        return resp;
    }

    // Refuse replacement of existing attributes and mutation of the immutable
    // set. Audit M: the comparison is case-insensitive so a caller cannot
    // register `Owner` to bypass the immutable check on `owner`. Names with
    // surrounding or internal whitespace are also rejected.
    for attr in &request.attributes {
        let trimmed = attr.name.trim();
        if trimmed.is_empty() || trimmed != attr.name {
            return KmipResponse::error(
                KmipResultReason::InvalidField,
                "attribute name must not have surrounding whitespace",
            );
        }
        if attr
            .name
            .chars()
            .any(|c| c == '\t' || c == '\n' || c == '\r')
        {
            return KmipResponse::error(
                KmipResultReason::InvalidField,
                "attribute name must not contain control whitespace",
            );
        }
        if is_immutable_attribute(&attr.name) {
            return KmipResponse::error(
                KmipResultReason::PermissionDenied,
                &format!("attribute '{}' is immutable via AddAttribute", attr.name),
            );
        }
        let lname = attr.name.to_ascii_lowercase();
        if obj
            .attributes
            .keys()
            .any(|k| k.to_ascii_lowercase() == lname)
        {
            return KmipResponse::error(
                KmipResultReason::InvalidField,
                &format!(
                    "attribute '{}' already exists (case-insensitive); use ModifyAttribute instead",
                    attr.name
                ),
            );
        }
    }

    let new_attrs: HashMap<String, KmipAttributeValue> = request
        .attributes
        .iter()
        .map(|a| (a.name.clone(), a.value.clone()))
        .collect();
    match key_store.add_attributes(id, new_attrs) {
        Ok(()) => {
            tracing::info!(
                kmip.op = "AddAttribute",
                kmip.unique_id = %id,
                kmip.caller = ?request.caller_identity,
                "KMIP AddAttribute succeeded"
            );
            KmipResponse::success(id)
        }
        Err(reason) => KmipResponse::error(reason, "add_attribute failed"),
    }
}

/// Process a Locate operation: search objects by attribute filters.
///
/// The request attributes act as equality filters. Every attribute present in
/// the request must match the stored object for it to be included. If no
/// attributes are provided, all non-destroyed objects are returned.
///
/// # Tenant isolation (H6)
///
/// Every returned ID is post-filtered so that only objects owned by the
/// authenticated caller (matching the `owner` attribute) appear. Objects
/// without an `owner` attribute remain globally visible by design — callers
/// that need strict isolation must either set an owner on every object
/// (Create does this automatically if `caller_identity` is set) or add an
/// explicit `owner` filter to their Locate request.
/// Default upper bound on the number of object identifiers returned by a
/// single Locate response. Audit M: without this cap a tenant with a large
/// keyspace could pull megabytes of identifiers in a single request,
/// blowing past the configured `max_message_size` on the wire and forcing
/// the server to allocate and TTLV-encode an arbitrarily large response.
pub const LOCATE_MAX_RESULTS_DEFAULT: usize = 1000;

/// Synthetic attribute name appended to the response when the locate result
/// set was truncated to fit inside [`LOCATE_MAX_RESULTS_DEFAULT`]. Callers
/// that need the full result set should issue a more selective Locate
/// (e.g. by adding an `owner` or `Object Type` filter).
const LOCATE_TRUNCATED_ATTR: &str = "Locate-Truncated";

/// Process a `Locate` request: scan the store for objects matching every
/// attribute in `request.attributes`, then post-filter by the owner ACL.
/// Result sets longer than [`LOCATE_MAX_RESULTS_DEFAULT`] are clipped and
/// a `Locate-Truncated = true` synthetic attribute is appended (audit M).
pub fn process_locate(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    let filter: HashMap<String, KmipAttributeValue> = request
        .attributes
        .iter()
        .map(|a| (a.name.clone(), a.value.clone()))
        .collect();

    let ids = key_store.locate(&filter);

    // Post-filter through the owner ACL using a borrow-only callback to
    // avoid cloning every object on the hot path. Stop accumulating once
    // the per-response cap is reached and emit a `Locate-Truncated` flag so
    // the caller knows the result was clipped.
    let caller = request.caller_identity.clone();
    let probe = |obj: &KmipStoredObject| check_owner_acl(obj, &caller).is_ok();
    let mut filtered: Vec<String> = Vec::new();
    let mut truncated = false;
    for id in ids {
        if filtered.len() >= LOCATE_MAX_RESULTS_DEFAULT {
            truncated = true;
            break;
        }
        if key_store
            .with_object_acl_probe(&id, &probe)
            .unwrap_or(false)
        {
            filtered.push(id);
        }
    }

    let mut resp = KmipResponse::success_bare();
    resp.located_ids = filtered;
    if truncated {
        resp.attributes.push(KmipAttribute {
            name: LOCATE_TRUNCATED_ATTR.to_string(),
            value: KmipAttributeValue::Boolean(true),
        });
    }
    resp
}

// ---------------------------------------------------------------------------
// State-machine transition table
// ---------------------------------------------------------------------------

/// Decide whether the lifecycle transition from `from` to `to` is permitted.
///
/// Centralises the lifecycle policy so destructive operations cannot diverge
/// from each other. The policy follows KMIP 2.1 §4.8:
///
/// * `PreActive -> Active`        via `Activate`
/// * `Active -> Deactivated`      via `Revoke`
/// * `PreActive -> Destroyed`     via `Destroy`
/// * `Deactivated -> Destroyed`   via `Destroy`
///
/// `Compromised` is intentionally **not** a destroy precondition: a
/// compromised key must be retained for forensics and only the operator
/// (out-of-band) can erase it. Activating or destroying a `Compromised`
/// object is therefore rejected, mirroring the rejection of `Active`
/// destruction (audit follow-up).
pub fn allowed_transitions(from: KmipObjectState, to: KmipObjectState) -> bool {
    use KmipObjectState::*;
    matches!(
        (from, to),
        (PreActive, Active)
            | (Active, Deactivated)
            | (PreActive, Destroyed)
            | (Deactivated, Destroyed)
    )
}

// ---------------------------------------------------------------------------
// Stub handlers for cryptographic operations
// ---------------------------------------------------------------------------

/// Stable error reason returned by every stub crypto handler so the wire
/// reason does not drift if individual operations are wired up out-of-order.
const STUB_OP_REASON: &str = "operation not implemented in this build";

/// Build a uniform `OperationNotSupported` response for every stub handler.
///
/// All of `Encrypt`, `Decrypt`, `Sign`, `SignatureVerify`, `MAC`, `MACVerify`,
/// and `CreateKeyPair` route through this helper today so a downstream
/// integrator can grep for the message and trace the dispatch path before
/// implementing the real semantics.
fn stub_response(op: KmipOperation) -> KmipResponse {
    tracing::debug!(
        target: "craton_hsm_kmip::ops",
        op = %op,
        "operation handled by stub: returning OperationNotSupported"
    );
    KmipResponse::error(
        KmipResultReason::OperationNotSupported,
        &format!("{op}: {STUB_OP_REASON}"),
    )
}

/// `Encrypt` stub. Returns [`KmipResultReason::OperationNotSupported`].
pub fn process_encrypt(_request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    stub_response(KmipOperation::Encrypt)
}

/// `Decrypt` stub. Returns [`KmipResultReason::OperationNotSupported`].
pub fn process_decrypt(_request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    stub_response(KmipOperation::Decrypt)
}

/// `Sign` stub. Returns [`KmipResultReason::OperationNotSupported`].
pub fn process_sign(_request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    stub_response(KmipOperation::Sign)
}

/// `SignatureVerify` stub. Returns [`KmipResultReason::OperationNotSupported`].
pub fn process_signature_verify(
    _request: &KmipRequest,
    _key_store: &dyn KmipKeyStore,
) -> KmipResponse {
    stub_response(KmipOperation::SignatureVerify)
}

/// `MAC` stub. Returns [`KmipResultReason::OperationNotSupported`].
pub fn process_mac(_request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    stub_response(KmipOperation::MAC)
}

/// `MACVerify` stub. Returns [`KmipResultReason::OperationNotSupported`].
pub fn process_mac_verify(_request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    stub_response(KmipOperation::MACVerify)
}

/// `CreateKeyPair` stub. Returns [`KmipResultReason::OperationNotSupported`].
///
/// TODO: real asymmetric key-pair generation will be wired into the OpenSSL /
/// AWS-LC backends in a follow-up commit. Today the stub exists so callers
/// receive a stable error reason instead of `InvalidMessage`.
pub fn process_create_key_pair(
    _request: &KmipRequest,
    _key_store: &dyn KmipKeyStore,
) -> KmipResponse {
    stub_response(KmipOperation::CreateKeyPair)
}

/// `RNG_Retrieve` — return a fresh chunk of random bytes from the OS RNG.
///
/// The amount of bytes requested is taken from a `Cryptographic Length`
/// (i32, BITS) attribute. Defaults to 256 bits when absent. Capped at 16 KiB
/// to avoid unbounded allocations from a malicious client.
pub fn process_rng_retrieve(request: &KmipRequest, _key_store: &dyn KmipKeyStore) -> KmipResponse {
    const DEFAULT_BITS: i32 = 256;
    const MAX_BYTES: usize = 16 * 1024;

    let mut bits = DEFAULT_BITS;
    for attr in &request.attributes {
        if attr.name == "Cryptographic Length" {
            if let KmipAttributeValue::Integer(v) = &attr.value {
                bits = *v;
            }
        }
    }
    if bits <= 0 || bits % 8 != 0 {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            "RNG_Retrieve length must be positive and a multiple of 8 bits",
        );
    }
    let want = (bits as usize) / 8;
    if want > MAX_BYTES {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            "RNG_Retrieve length exceeds server cap (16 KiB)",
        );
    }

    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut buf = vec![0u8; want];
    // Audit finding L: prefer fallible RNG so a degraded entropy path
    // surfaces as `CryptographicFailure` rather than panicking the server.
    if let Err(e) = OsRng.try_fill_bytes(&mut buf) {
        tracing::error!(
            target: "craton_hsm_kmip::rng",
            error = %e,
            "OS RNG failed to fill buffer; returning CryptographicFailure"
        );
        return KmipResponse::error(KmipResultReason::CryptographicFailure, "OS RNG unavailable");
    }
    let mut resp = KmipResponse::success_bare();
    // The bytes ride back as a single Bytes attribute under "Data".
    resp.attributes.push(KmipAttribute {
        name: "Data".to_string(),
        value: KmipAttributeValue::Bytes(buf),
    });
    resp
}

/// `DeriveKey` — derive a new symmetric key from existing key material via
/// HKDF-SHA256.
///
/// The request must carry:
/// * `unique_id` — id of the input keying material (IKM).
/// * `Cryptographic Length` — output length **in bits** (must be a multiple
///   of 8, ≤ 8192 bits which is the HKDF-SHA256 output cap).
///
/// Optional attributes:
/// * `Salt` — Bytes value used as HKDF salt (defaults to empty).
/// * `Info` — Bytes value used as HKDF info (defaults to empty).
///
/// The derived key is registered as a fresh PreActive `SymmetricKey` and the
/// new id is returned. Owner ACL on the IKM is enforced.
pub fn process_derive_key(request: &KmipRequest, key_store: &dyn KmipKeyStore) -> KmipResponse {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let id = match &request.unique_id {
        Some(id) => id.clone(),
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "DeriveKey requires a UniqueIdentifier",
            );
        }
    };

    let mut out_bits: Option<i32> = None;
    let mut salt: Vec<u8> = Vec::new();
    let mut info: Vec<u8> = Vec::new();
    for attr in &request.attributes {
        match attr.name.as_str() {
            "Cryptographic Length" => {
                if let KmipAttributeValue::Integer(v) = &attr.value {
                    out_bits = Some(*v);
                }
            }
            "Salt" => {
                if let KmipAttributeValue::Bytes(b) = &attr.value {
                    salt = b.clone();
                }
            }
            "Info" => {
                if let KmipAttributeValue::Bytes(b) = &attr.value {
                    info = b.clone();
                }
            }
            _ => {}
        }
    }
    let out_bits = match out_bits {
        Some(b) if b > 0 && b % 8 == 0 && b <= 8192 => b,
        _ => {
            return KmipResponse::error(
                KmipResultReason::InvalidField,
                "DeriveKey requires a positive Cryptographic Length (multiple of 8, <= 8192 bits)",
            );
        }
    };

    let ikm_obj = match key_store.get(&id) {
        Some(o) if o.state != KmipObjectState::Destroyed => o,
        _ => {
            return KmipResponse::error(
                KmipResultReason::ObjectNotFound,
                "DeriveKey: input key not found",
            );
        }
    };
    if let Err(resp) = check_owner_acl_for_request(&ikm_obj, request) {
        return resp;
    }
    // Audit M: IKM (and OKM below) carry key material and must be wiped
    // before this stack frame unwinds. Wrap both in `Zeroizing` so a panic
    // — or normal return — guarantees the bytes are cleared.
    let ikm: Zeroizing<Vec<u8>> = match &ikm_obj.key_material {
        Some(m) if !m.is_empty() => Zeroizing::new(m.clone()),
        _ => {
            return KmipResponse::error(
                KmipResultReason::CryptographicFailure,
                "DeriveKey: input key has no material",
            );
        }
    };

    let hk = Hkdf::<Sha256>::new(
        if salt.is_empty() { None } else { Some(&salt) },
        ikm.as_slice(),
    );
    let want = (out_bits as usize) / 8;
    let mut okm: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; want]);
    if hk.expand(&info, okm.as_mut_slice()).is_err() {
        return KmipResponse::error(
            KmipResultReason::CryptographicFailure,
            "DeriveKey: HKDF expand failed",
        );
    }

    // Inherit owner from caller identity, mirroring Create.
    let mut attrs: HashMap<String, KmipAttributeValue> = HashMap::new();
    if let Some(caller) = request.caller_identity.clone() {
        attrs.insert("owner".to_string(), KmipAttributeValue::Text(caller));
    }
    attrs.insert(
        "Cryptographic Length".to_string(),
        KmipAttributeValue::Integer(out_bits),
    );
    attrs.insert(
        "Derived From".to_string(),
        KmipAttributeValue::Text(id.clone()),
    );
    // Hand the derived bytes to the store. We copy out of `Zeroizing` (which
    // wipes its own buffer on drop) into a fresh `Vec<u8>` that the stored
    // object now owns; the store's `KmipStoredObject::Drop` impl will wipe
    // *that* copy when the object is evicted or destroyed.
    let new_id = key_store.create(KmipObjectType::SymmetricKey, okm.to_vec(), attrs);
    let mut resp = KmipResponse::success(&new_id);
    resp.object_type = Some(KmipObjectType::SymmetricKey);
    resp
}

/// `ModifyAttribute` — replace an existing attribute on an object.
///
/// Mutation of the immutable set (`owner`, `Cryptographic Algorithm`,
/// `Cryptographic Length`, `Object Type`, `Key Material`) is rejected.
/// Modifying a non-existent attribute is also rejected; callers should
/// use `AddAttribute` for that path.
pub fn process_modify_attribute(
    request: &KmipRequest,
    key_store: &dyn KmipKeyStore,
) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id.clone(),
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "ModifyAttribute requires a UniqueIdentifier",
            );
        }
    };
    if request.attributes.is_empty() {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            "ModifyAttribute requires at least one attribute",
        );
    }
    let obj = match key_store.get(&id) {
        Some(o) => o,
        None => {
            return KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found");
        }
    };
    if let Err(resp) = check_owner_acl_for_request(&obj, request) {
        return resp;
    }
    for attr in &request.attributes {
        if is_immutable_attribute(&attr.name) {
            return KmipResponse::error(
                KmipResultReason::PermissionDenied,
                &format!("attribute '{}' is immutable", attr.name),
            );
        }
        if !obj.attributes.contains_key(&attr.name) {
            return KmipResponse::error(
                KmipResultReason::ItemNotFound,
                &format!("attribute '{}' does not exist; use AddAttribute", attr.name),
            );
        }
    }
    let new_attrs: HashMap<String, KmipAttributeValue> = request
        .attributes
        .iter()
        .map(|a| (a.name.clone(), a.value.clone()))
        .collect();
    match key_store.modify_attributes(&id, new_attrs) {
        Ok(()) => KmipResponse::success(&id),
        Err(reason) => KmipResponse::error(reason, "modify_attribute failed"),
    }
}

/// `DeleteAttribute` — remove a named attribute from an object.
///
/// Mutation of the immutable set is rejected. Names that do not exist on
/// the object are reported with [`KmipResultReason::ItemNotFound`].
pub fn process_delete_attribute(
    request: &KmipRequest,
    key_store: &dyn KmipKeyStore,
) -> KmipResponse {
    let id = match &request.unique_id {
        Some(id) => id.clone(),
        None => {
            return KmipResponse::error(
                KmipResultReason::InvalidMessage,
                "DeleteAttribute requires a UniqueIdentifier",
            );
        }
    };
    if request.attributes.is_empty() {
        return KmipResponse::error(
            KmipResultReason::InvalidField,
            "DeleteAttribute requires at least one attribute name",
        );
    }
    let obj = match key_store.get(&id) {
        Some(o) => o,
        None => {
            return KmipResponse::error(KmipResultReason::ObjectNotFound, "object not found");
        }
    };
    if let Err(resp) = check_owner_acl_for_request(&obj, request) {
        return resp;
    }
    let names: Vec<String> = request.attributes.iter().map(|a| a.name.clone()).collect();
    for n in &names {
        if is_immutable_attribute(n) {
            return KmipResponse::error(
                KmipResultReason::PermissionDenied,
                &format!("attribute '{}' is immutable", n),
            );
        }
        if !obj.attributes.contains_key(n) {
            return KmipResponse::error(
                KmipResultReason::ItemNotFound,
                &format!("attribute '{}' does not exist", n),
            );
        }
    }
    match key_store.delete_attributes(&id, &names) {
        Ok(()) => KmipResponse::success(&id),
        Err(reason) => KmipResponse::error(reason, "delete_attribute failed"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> InMemoryKeyStore {
        InMemoryKeyStore::new()
    }

    fn create_request(mut attrs: Vec<KmipAttribute>) -> KmipRequest {
        // `process_create` now requires an explicit Cryptographic Length
        // (audit finding H7). Tests that don't care about the length get
        // a default AES-256 so legacy tests continue to exercise the rest
        // of the create path.
        if !attrs.iter().any(|a| a.name == "Cryptographic Length") {
            attrs.push(KmipAttribute {
                name: "Cryptographic Length".to_string(),
                value: KmipAttributeValue::Integer(256),
            });
        }
        KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: attrs,
            caller_identity: None,
            strict_owner_acl: false,
        }
    }

    fn get_request(id: &str) -> KmipRequest {
        KmipRequest {
            operation: KmipOperation::Get,
            unique_id: Some(id.to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        }
    }

    fn activate_request(id: &str) -> KmipRequest {
        KmipRequest {
            operation: KmipOperation::Activate,
            unique_id: Some(id.to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        }
    }

    fn revoke_request(id: &str) -> KmipRequest {
        KmipRequest {
            operation: KmipOperation::Revoke,
            unique_id: Some(id.to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        }
    }

    fn destroy_request(id: &str) -> KmipRequest {
        KmipRequest {
            operation: KmipOperation::Destroy,
            unique_id: Some(id.to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        }
    }

    #[test]
    fn create_returns_success_with_id() {
        let store = make_store();
        let req = create_request(vec![
            KmipAttribute {
                name: "Cryptographic Algorithm".into(),
                value: KmipAttributeValue::Enum(3), // AES
            },
            KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            },
        ]);
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert!(resp.unique_id.is_some());
        assert_eq!(resp.object_type, Some(KmipObjectType::SymmetricKey));
    }

    #[test]
    fn get_returns_key_material() {
        let store = make_store();
        let req = create_request(vec![]);
        let create_resp = process_create(&req, &store);
        let id = create_resp.unique_id.unwrap();

        let resp = process_get(&get_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert!(resp.key_material.is_some());
        assert_eq!(resp.key_material.as_ref().unwrap().len(), 32); // 256 bits
    }

    #[test]
    fn get_not_found() {
        let store = make_store();
        let resp = process_get(&get_request("nonexistent"), &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn activate_transitions_to_active() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        let resp = process_activate(&activate_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        let obj = store.get(&id).unwrap();
        assert_eq!(obj.state, KmipObjectState::Active);
    }

    #[test]
    fn revoke_active_key() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        process_activate(&activate_request(&id), &store);
        let resp = process_revoke(&revoke_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        let obj = store.get(&id).unwrap();
        assert_eq!(obj.state, KmipObjectState::Deactivated);
    }

    #[test]
    fn revoke_preactive_fails() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        let resp = process_revoke(&revoke_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::PermissionDenied));
    }

    #[test]
    fn destroy_key() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        let resp = process_destroy(&destroy_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        // key material should be gone
        let obj = store.get(&id).unwrap();
        assert_eq!(obj.state, KmipObjectState::Destroyed);
        assert!(obj.key_material.is_none());
    }

    #[test]
    fn double_destroy_fails() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        process_destroy(&destroy_request(&id), &store);
        let resp = process_destroy(&destroy_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn get_destroyed_key_fails() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        process_destroy(&destroy_request(&id), &store);
        let resp = process_get(&get_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn full_lifecycle() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        // PreActive -> Active
        let resp = process_activate(&activate_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        // Active -> Deactivated (revoke)
        let resp = process_revoke(&revoke_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        // Deactivated -> Destroyed
        let resp = process_destroy(&destroy_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
    }

    #[test]
    fn locate_by_attribute() {
        let store = make_store();
        let mut attrs = HashMap::new();
        attrs.insert(
            "Name".to_string(),
            KmipAttributeValue::Text("my-key".to_string()),
        );
        store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);

        // Create another without the name attribute.
        store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], HashMap::new());

        let mut query = HashMap::new();
        query.insert(
            "Name".to_string(),
            KmipAttributeValue::Text("my-key".to_string()),
        );
        let results = store.locate(&query);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn locate_excludes_destroyed() {
        let store = make_store();
        let mut attrs = HashMap::new();
        attrs.insert(
            "Name".to_string(),
            KmipAttributeValue::Text("to-destroy".to_string()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);
        store.destroy(&id).unwrap();

        let mut query = HashMap::new();
        query.insert(
            "Name".to_string(),
            KmipAttributeValue::Text("to-destroy".to_string()),
        );
        let results = store.locate(&query);
        assert!(results.is_empty());
    }

    #[test]
    fn get_without_id_fails() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Get,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_get(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidMessage));
    }

    #[test]
    fn activate_without_id_fails() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Activate,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_activate(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
    }

    #[test]
    fn state_display() {
        assert_eq!(format!("{}", KmipObjectState::PreActive), "PreActive");
        assert_eq!(format!("{}", KmipObjectState::Destroyed), "Destroyed");
    }

    // -----------------------------------------------------------------------
    // Query tests
    // -----------------------------------------------------------------------

    #[test]
    fn query_returns_supported_operations() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Query,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_query(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        // Every supported operation should appear as "OP:<name>" in located_ids.
        for op in SUPPORTED_OPERATIONS {
            let entry = format!("OP:{op}");
            assert!(
                resp.located_ids.contains(&entry),
                "missing operation entry: {entry}"
            );
        }
    }

    #[test]
    fn query_returns_supported_object_types() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Query,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_query(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        for ot in SUPPORTED_OBJECT_TYPES {
            let entry = format!("OT:{ot}");
            assert!(
                resp.located_ids.contains(&entry),
                "missing object-type entry: {entry}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // GetAttributes tests
    // -----------------------------------------------------------------------

    #[test]
    fn get_attributes_returns_stored_attrs() {
        let store = make_store();
        let req = create_request(vec![KmipAttribute {
            name: "Name".into(),
            value: KmipAttributeValue::Text("test-key".into()),
        }]);
        let create_resp = process_create(&req, &store);
        let id = create_resp.unique_id.unwrap();

        let ga_req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_get_attributes(&ga_req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.unique_id.as_deref(), Some(id.as_str()));

        // The "Name" attribute we stored should be present.
        let has_name = resp.attributes.iter().any(|a| {
            a.name == "Name" && a.value == KmipAttributeValue::Text("test-key".to_string())
        });
        assert!(has_name, "expected 'Name' attribute in response");
    }

    #[test]
    fn get_attributes_includes_synthetic_state() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        let ga_req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: Some(id),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_get_attributes(&ga_req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        let has_state = resp.attributes.iter().any(|a| {
            a.name == "State" && a.value == KmipAttributeValue::Text("PreActive".to_string())
        });
        assert!(has_state, "expected 'State' attribute in response");
    }

    #[test]
    fn get_attributes_not_found() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: Some("no-such-id".to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_get_attributes(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn get_attributes_without_id_fails() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_get_attributes(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidMessage));
    }

    // -----------------------------------------------------------------------
    // Register tests
    // -----------------------------------------------------------------------

    #[test]
    fn register_stores_key_in_preactive_state() {
        let store = make_store();
        let key_bytes = vec![0xAB_u8; 32];
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("ext-key-001".to_string()),
            attributes: vec![
                KmipAttribute {
                    name: "Object Type".into(),
                    value: KmipAttributeValue::Enum(KmipObjectType::SymmetricKey.to_u32()),
                },
                KmipAttribute {
                    name: "Key Material".into(),
                    value: KmipAttributeValue::Bytes(key_bytes.clone()),
                },
                KmipAttribute {
                    name: "Name".into(),
                    value: KmipAttributeValue::Text("imported-key".into()),
                },
            ],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_register(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.unique_id.as_deref(), Some("ext-key-001"));
        assert_eq!(resp.object_type, Some(KmipObjectType::SymmetricKey));

        // Verify state and key material via the store.
        let obj = store.get("ext-key-001").unwrap();
        assert_eq!(obj.state, KmipObjectState::PreActive);
        assert_eq!(obj.key_material.as_deref(), Some(key_bytes.as_slice()));
    }

    #[test]
    fn register_without_id_fails() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_register(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidMessage));
    }

    #[test]
    fn register_duplicate_id_fails() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("dup-key".to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        process_register(&req, &store);
        let resp = process_register(&req, &store);
        // Audit M (existence oracle): duplicate-id collisions now mask as
        // `ObjectNotFound` to match the ACL-deny shape elsewhere in the
        // module. Previously this returned `InvalidMessage`, which let a
        // probing client distinguish "id taken by another tenant" from
        // "id available".
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn register_defaults_to_symmetric_key_type() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("no-type-key".to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_register(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.object_type, Some(KmipObjectType::SymmetricKey));
    }

    #[test]
    fn register_private_key_type() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("priv-key-001".to_string()),
            attributes: vec![KmipAttribute {
                name: "Object Type".into(),
                value: KmipAttributeValue::Enum(KmipObjectType::PrivateKey.to_u32()),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_register(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        let obj = store.get("priv-key-001").unwrap();
        assert_eq!(obj.object_type, KmipObjectType::PrivateKey);
    }

    // -----------------------------------------------------------------------
    // Locate tests
    // -----------------------------------------------------------------------

    #[test]
    fn locate_no_filter_returns_all_non_destroyed() {
        let store = make_store();
        process_create(&create_request(vec![]), &store);
        process_create(&create_request(vec![]), &store);

        let req = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_locate(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.located_ids.len(), 2);
    }

    #[test]
    fn locate_with_filter_returns_matching() {
        let store = make_store();
        process_create(
            &create_request(vec![KmipAttribute {
                name: "Name".into(),
                value: KmipAttributeValue::Text("needle".into()),
            }]),
            &store,
        );
        process_create(&create_request(vec![]), &store);

        let req = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Name".into(),
                value: KmipAttributeValue::Text("needle".into()),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_locate(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.located_ids.len(), 1);
    }

    #[test]
    fn locate_excludes_destroyed_objects() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();
        process_destroy(
            &KmipRequest {
                operation: KmipOperation::Destroy,
                unique_id: Some(id),
                attributes: vec![],
                caller_identity: None,
                strict_owner_acl: false,
            },
            &store,
        );

        let req = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_locate(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert!(resp.located_ids.is_empty());
    }

    #[test]
    fn locate_no_match_returns_empty() {
        let store = make_store();
        process_create(&create_request(vec![]), &store);

        let req = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Name".into(),
                value: KmipAttributeValue::Text("does-not-exist".into()),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_locate(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert!(resp.located_ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // ACL / owner-attribute tests for process_get
    // -----------------------------------------------------------------------

    /// Objects without an "owner" attribute are accessible regardless of identity.
    #[test]
    fn get_unowned_object_accessible_without_identity() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        let resp = process_get(&get_request(&id), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert!(resp.key_material.is_some());
    }

    /// Owner can retrieve their own object.
    #[test]
    fn get_owner_can_access_own_object() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("owned-key".to_string()),
            attributes: vec![KmipAttribute {
                name: "owner".into(),
                value: KmipAttributeValue::Text("alice".into()),
            }],
            caller_identity: Some("alice".to_string()),
            strict_owner_acl: false,
        };
        process_register(&req, &store);

        let get = KmipRequest {
            operation: KmipOperation::Get,
            unique_id: Some("owned-key".to_string()),
            attributes: vec![],
            caller_identity: Some("alice".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_get(&get, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
    }

    /// A different identity is denied access to an owner-protected object.
    #[test]
    fn get_non_owner_denied_access() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("owned-key2".to_string()),
            attributes: vec![KmipAttribute {
                name: "owner".into(),
                value: KmipAttributeValue::Text("alice".into()),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        process_register(&req, &store);

        let get = KmipRequest {
            operation: KmipOperation::Get,
            unique_id: Some("owned-key2".to_string()),
            attributes: vec![],
            caller_identity: Some("bob".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_get(&get, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound to avoid a
        // key-existence oracle across tenants.
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    /// Unauthenticated access to an owner-protected object is denied.
    #[test]
    fn get_unauthenticated_denied_for_owned_object() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("owned-key3".to_string()),
            attributes: vec![KmipAttribute {
                name: "owner".into(),
                value: KmipAttributeValue::Text("alice".into()),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        process_register(&req, &store);

        let get = KmipRequest {
            operation: KmipOperation::Get,
            unique_id: Some("owned-key3".to_string()),
            attributes: vec![],
            caller_identity: None, // no identity,
            strict_owner_acl: false,
        };
        let resp = process_get(&get, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound (see check_owner_acl).
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    // -----------------------------------------------------------------------
    // Negative key length rejection
    // -----------------------------------------------------------------------

    #[test]
    fn create_negative_key_length_rejected() {
        let store = make_store();
        let req = create_request(vec![
            KmipAttribute {
                name: "Cryptographic Algorithm".into(),
                value: KmipAttributeValue::Enum(3), // AES (already rejects first on bad length)
            },
            KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(-128),
            },
        ]);
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidField));
    }

    #[test]
    fn create_zero_key_length_rejected() {
        let store = make_store();
        let req = create_request(vec![KmipAttribute {
            name: "Cryptographic Length".into(),
            value: KmipAttributeValue::Integer(0),
        }]);
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidField));
    }

    #[test]
    fn create_requires_explicit_key_length() {
        let store = make_store();
        // Build directly, bypassing the create_request helper's default.
        let req = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Algorithm".into(),
                value: KmipAttributeValue::Enum(3),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidField));
    }

    #[test]
    fn create_sets_owner_from_caller_identity() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        let obj = store.get(&resp.unique_id.unwrap()).unwrap();
        assert_eq!(
            obj.attributes.get("owner"),
            Some(&KmipAttributeValue::Text("alice".into())),
        );
    }

    #[test]
    fn locate_filters_by_owner_acl() {
        let store = make_store();
        // Alice creates a key.
        let r = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        process_create(&r, &store);
        // Bob locates — should see nothing.
        let bob_locate = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![],
            caller_identity: Some("bob".into()),
            strict_owner_acl: false,
        };
        let resp = process_locate(&bob_locate, &store);
        assert!(resp.located_ids.is_empty(), "bob must not see alice's keys");
        // Alice sees her own.
        let alice_locate = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_locate(&alice_locate, &store);
        assert_eq!(resp.located_ids.len(), 1);
    }

    #[test]
    fn get_attributes_enforces_owner_acl() {
        let store = make_store();
        let r = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let id = process_create(&r, &store).unique_id.unwrap();
        let req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("mallory".into()),
            strict_owner_acl: false,
        };
        let resp = process_get_attributes(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound (see check_owner_acl).
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn check_op_accepts_active_object_for_owner() {
        let store = make_store();
        let r = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let id = process_create(&r, &store).unique_id.unwrap();
        let req = KmipRequest {
            operation: KmipOperation::Check,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_check(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
    }

    #[test]
    fn check_op_rejects_destroyed() {
        let store = make_store();
        let r = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let id = process_create(&r, &store).unique_id.unwrap();
        // PreActive -> Active -> Deactivated -> Destroyed so the state-machine
        // allows destruction.
        store.activate(&id).unwrap();
        store.revoke(&id).unwrap();
        store.destroy(&id).unwrap();
        let req = KmipRequest {
            operation: KmipOperation::Check,
            unique_id: Some(id),
            attributes: vec![],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_check(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn add_attribute_rejects_immutable() {
        let store = make_store();
        let r = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let id = process_create(&r, &store).unique_id.unwrap();
        // Attempt to overwrite owner via AddAttribute.
        let req = KmipRequest {
            operation: KmipOperation::AddAttribute,
            unique_id: Some(id),
            attributes: vec![KmipAttribute {
                name: "owner".into(),
                value: KmipAttributeValue::Text("mallory".into()),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_add_attribute(&req, &store);
        assert_eq!(resp.reason, Some(KmipResultReason::PermissionDenied));
    }

    #[test]
    fn add_attribute_adds_custom() {
        let store = make_store();
        let r = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let id = process_create(&r, &store).unique_id.unwrap();
        let req = KmipRequest {
            operation: KmipOperation::AddAttribute,
            unique_id: Some(id.clone()),
            attributes: vec![KmipAttribute {
                name: "Description".into(),
                value: KmipAttributeValue::Text("prod signing".into()),
            }],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_add_attribute(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        let obj = store.get(&id).unwrap();
        assert_eq!(
            obj.attributes.get("Description"),
            Some(&KmipAttributeValue::Text("prod signing".into())),
        );
    }

    // -----------------------------------------------------------------------
    // Concurrent register race (TOCTOU)
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_register_race_only_one_succeeds() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(make_store());
        let num_threads = 10;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let req = KmipRequest {
                    operation: KmipOperation::Register,
                    unique_id: Some("race-key".to_string()),
                    attributes: vec![],
                    caller_identity: None,
                    strict_owner_acl: false,
                };
                process_register(&req, store.as_ref())
            }));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let successes = results
            .iter()
            .filter(|r| r.status == KmipResultStatus::Success)
            .count();
        let failures = results
            .iter()
            .filter(|r| r.status == KmipResultStatus::OperationFailed)
            .count();

        // Exactly one thread should win; the rest should fail.
        assert_eq!(successes, 1, "expected exactly 1 success, got {successes}");
        assert_eq!(
            failures,
            num_threads - 1,
            "expected {} failures, got {failures}",
            num_threads - 1
        );
    }

    // -----------------------------------------------------------------------
    // ACL enforcement tests for Activate / Revoke / Destroy
    // -----------------------------------------------------------------------

    #[test]
    fn test_activate_acl_blocks_wrong_caller() {
        let store = InMemoryKeyStore::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("alice".to_string()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);

        let request = KmipRequest {
            operation: KmipOperation::Activate,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("bob".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_activate(&request, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound (see check_owner_acl).
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn test_activate_acl_allows_owner() {
        let store = InMemoryKeyStore::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("alice".to_string()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);

        let request = KmipRequest {
            operation: KmipOperation::Activate,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("alice".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_activate(&request, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
    }

    #[test]
    fn test_revoke_acl_blocks_wrong_caller() {
        let store = InMemoryKeyStore::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("alice".to_string()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);
        store.activate(&id).unwrap();

        let request = KmipRequest {
            operation: KmipOperation::Revoke,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("bob".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_revoke(&request, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound (see check_owner_acl).
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn test_destroy_acl_blocks_wrong_caller() {
        let store = InMemoryKeyStore::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("alice".to_string()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);

        let request = KmipRequest {
            operation: KmipOperation::Destroy,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("bob".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_destroy(&request, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound (see check_owner_acl).
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn test_destroy_acl_blocks_unauthenticated() {
        let store = InMemoryKeyStore::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("alice".to_string()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);

        let request = KmipRequest {
            operation: KmipOperation::Destroy,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_destroy(&request, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        // ACL denials are reported as ObjectNotFound (see check_owner_acl).
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    #[test]
    fn test_activate_no_owner_allows_anyone() {
        let store = InMemoryKeyStore::new();
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], HashMap::new());

        let request = KmipRequest {
            operation: KmipOperation::Activate,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: Some("anyone".to_string()),
            strict_owner_acl: false,
        };
        let resp = process_activate(&request, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
    }

    // -----------------------------------------------------------------------
    // Algorithm validation tests (process_create)
    // -----------------------------------------------------------------------

    #[test]
    fn create_rejects_unsupported_algorithm() {
        let store = make_store();
        let req = create_request(vec![
            KmipAttribute {
                name: "Cryptographic Algorithm".into(),
                value: KmipAttributeValue::Enum(0x04), // RSA — not a symmetric algorithm
            },
            KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(2048),
            },
        ]);
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidField));
    }

    #[test]
    fn create_rejects_mismatched_aes_key_length() {
        let store = make_store();
        let req = create_request(vec![
            KmipAttribute {
                name: "Cryptographic Algorithm".into(),
                value: KmipAttributeValue::Enum(0x03), // AES
            },
            KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(512), // invalid for AES
            },
        ]);
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidField));
    }

    #[test]
    fn test_destroy_zeroizes_key_material() {
        let store = make_store();
        // Register a key with known material.
        let material = vec![0xAA; 32];
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("zeroize-key".to_string()),
            attributes: vec![KmipAttribute {
                name: "Key Material".into(),
                value: KmipAttributeValue::Bytes(material.clone()),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let create_resp = process_register(&req, &store);
        assert_eq!(create_resp.status, KmipResultStatus::Success);

        // Verify key exists with material.
        let obj = store.get("zeroize-key").unwrap();
        assert!(obj.key_material.is_some());
        assert_eq!(obj.key_material.as_ref().unwrap().len(), 32);

        // Destroy the key.
        let resp = process_destroy(&destroy_request("zeroize-key"), &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        // Verify key material is gone and state is Destroyed.
        let obj = store.get("zeroize-key").unwrap();
        assert!(
            obj.key_material.is_none(),
            "key material must be cleared after destroy"
        );
        assert_eq!(obj.state, KmipObjectState::Destroyed);
    }

    #[test]
    fn create_accepts_valid_aes_256() {
        let store = make_store();
        let req = create_request(vec![
            KmipAttribute {
                name: "Cryptographic Algorithm".into(),
                value: KmipAttributeValue::Enum(0x03), // AES
            },
            KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            },
        ]);
        let resp = process_create(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert!(resp.unique_id.is_some());
    }

    /// KMIP 2.1 §4.8: destroying an Active key must be rejected with
    /// PermissionDenied; the caller must Revoke (deactivate) first.
    #[test]
    fn destroy_active_key_rejected() {
        let store = make_store();
        let create_resp = process_create(&create_request(vec![]), &store);
        let id = create_resp.unique_id.unwrap();

        // Activate the key
        let activate_resp = process_activate(&activate_request(&id), &store);
        assert_eq!(activate_resp.status, KmipResultStatus::Success);

        // Attempt to destroy while Active — must fail
        let destroy_resp = process_destroy(&destroy_request(&id), &store);
        assert_eq!(destroy_resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(
            destroy_resp.reason,
            Some(KmipResultReason::PermissionDenied)
        );

        // Key must still be intact
        let obj = store.get(&id).unwrap();
        assert_eq!(obj.state, KmipObjectState::Active);
        assert!(obj.key_material.is_some());
    }

    // -----------------------------------------------------------------------
    // Audit-followup hardening tests (ported from kmip-verify worktree)
    // -----------------------------------------------------------------------

    /// `ct_str_eq` returns `true` for equal strings and `false` for any
    /// difference, including length mismatch. The implementation folds
    /// over `max(len_a, len_b)` so callers can't use timing to learn
    /// the stored length.
    #[test]
    fn ct_str_eq_equal_and_mismatch() {
        assert!(ct_str_eq("alice", "alice"));
        assert!(!ct_str_eq("alice", "bob"));
        assert!(!ct_str_eq("alice", "alicea"));
        assert!(!ct_str_eq("", "x"));
        assert!(ct_str_eq("", ""));
    }

    /// `now_epoch` is weakly monotonic: two back-to-back calls must
    /// never observe the second value strictly below the first.
    #[test]
    fn now_epoch_is_weakly_monotonic() {
        let a = now_epoch();
        let mut prev = a;
        for _ in 0..1000 {
            let cur = now_epoch();
            assert!(cur >= prev, "now_epoch regressed: prev={prev} cur={cur}");
            prev = cur;
        }
    }

    /// Register with an unknown `Object Type` enum value must surface
    /// `InvalidField` rather than silently defaulting to SymmetricKey.
    #[test]
    fn register_unknown_object_type_rejected() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("badtype".into()),
            attributes: vec![KmipAttribute {
                name: "Object Type".into(),
                value: KmipAttributeValue::Enum(0xDEAD_BEEF),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_register(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidField));
    }

    /// `is_immutable_attribute` is case-insensitive and matches every
    /// entry in [`IMMUTABLE_ATTRIBUTES`].
    #[test]
    fn immutable_attribute_predicate_covers_all_names() {
        for name in IMMUTABLE_ATTRIBUTES {
            assert!(is_immutable_attribute(name));
            assert!(is_immutable_attribute(&name.to_ascii_uppercase()));
        }
        assert!(!is_immutable_attribute("Description"));
        assert!(!is_immutable_attribute(""));
    }

    /// Trait-layer defence in depth: modify_attributes must refuse to
    /// mutate an immutable attribute even when the dispatcher is
    /// bypassed.
    #[test]
    fn modify_attributes_trait_refuses_immutable() {
        let store = make_store();
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], HashMap::new());
        let mut payload = HashMap::new();
        payload.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("attacker".into()),
        );
        let result = store.modify_attributes(&id, payload);
        assert_eq!(result, Err(KmipResultReason::PermissionDenied));
    }

    /// Trait-layer defence: delete_attributes must refuse to delete an
    /// immutable attribute.
    #[test]
    fn delete_attributes_trait_refuses_immutable() {
        let store = make_store();
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            KmipAttributeValue::Text("alice".into()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);
        let result = store.delete_attributes(&id, &["owner".to_string()]);
        assert_eq!(result, Err(KmipResultReason::PermissionDenied));
    }

    /// Trait-layer defence: add_attributes must refuse to add an
    /// immutable attribute.
    #[test]
    fn add_attributes_trait_refuses_immutable() {
        let store = make_store();
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], HashMap::new());
        let mut payload = HashMap::new();
        payload.insert(
            "Cryptographic Algorithm".to_string(),
            KmipAttributeValue::Enum(0xFF),
        );
        let result = store.add_attributes(&id, payload);
        assert_eq!(result, Err(KmipResultReason::PermissionDenied));
    }

    /// GetAttributes must drop any stored attribute whose name shadows
    /// a server-synthesised one, and emit only the synthetic copy.
    #[test]
    fn get_attributes_drops_synthetic_shadow() {
        let store = make_store();
        let mut attrs = HashMap::new();
        attrs.insert(
            "State".to_string(),
            KmipAttributeValue::Text("Hijacked".into()),
        );
        let id = store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], attrs);
        let out = store.get_attributes(&id).unwrap();
        let states: Vec<&KmipAttribute> = out.iter().filter(|a| a.name == "State").collect();
        assert_eq!(states.len(), 1, "exactly one State attribute must appear");
        assert_eq!(
            states[0].value,
            KmipAttributeValue::Text("PreActive".into())
        );
    }

    /// `process_locate` clips at LOCATE_MAX_RESULTS_DEFAULT and attaches
    /// a synthetic `Locate-Truncated` attribute when it does so.
    #[test]
    fn locate_truncates_at_default_cap() {
        let store = make_store();
        for _ in 0..(LOCATE_MAX_RESULTS_DEFAULT + 5) {
            let mut a = HashMap::new();
            a.insert(
                "owner".to_string(),
                KmipAttributeValue::Text("alice".into()),
            );
            store.create(KmipObjectType::SymmetricKey, vec![0u8; 32], a);
        }
        let req = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![],
            caller_identity: Some("alice".into()),
            strict_owner_acl: false,
        };
        let resp = process_locate(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.located_ids.len(), LOCATE_MAX_RESULTS_DEFAULT);
        let trunc = resp.attributes.iter().any(|a| a.name == "Locate-Truncated");
        assert!(trunc, "expected Locate-Truncated synthetic attribute");
    }

    /// DeriveKey happy-path smoke test — verifies the `Zeroizing`
    /// rewrite of IKM/OKM did not break end-to-end behaviour.
    #[test]
    fn derive_key_succeeds_and_returns_new_id() {
        let store = make_store();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("ikm".into()),
            attributes: vec![KmipAttribute {
                name: "Key Material".into(),
                value: KmipAttributeValue::Bytes(vec![0xAB; 32]),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        assert_eq!(
            process_register(&req, &store).status,
            KmipResultStatus::Success
        );
        let dreq = KmipRequest {
            operation: KmipOperation::DeriveKey,
            unique_id: Some("ikm".into()),
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = process_derive_key(&dreq, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        let new_id = resp.unique_id.expect("new id");
        let obj = store.get(&new_id).unwrap();
        assert_eq!(obj.key_material.as_ref().unwrap().len(), 32);
    }
}
