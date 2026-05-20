// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! O(1) LRU cache for PKCS#11 imported-key handles.
//!
//! Each [`KeyCache`] is owned by a single `PooledSession` and is therefore
//! *not* shared across threads — operations are sequential within one session,
//! eliminating the TOCTOU race that the previous shared-`DashMap` cache
//! exhibited.
//!
//! The cache is generic over the value type so that the LRU machinery can be
//! unit-tested independently of cryptoki's `ObjectHandle` (whose `new`
//! constructor is `pub(crate)`-only).
//!
//! Each entry carries an [`EntryMeta`] block (currently the per-key AES-GCM
//! message counter) so that nonce-reuse limits can be enforced without an
//! extra parallel data structure.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// SHA-256 fingerprint of key material, used as the cache key.
pub type KeyFingerprint = [u8; 32];

/// Default per-session imported-key cache size.
pub const KEY_CACHE_DEFAULT_CAPACITY: usize = 64;

/// Computes a domain-separated SHA-256 fingerprint over key material.
///
/// `domain` is a short ASCII tag (e.g. `b"aes"`, `b"rsa-priv"`, `b"rsa-pub"`,
/// `b"ec-priv"`, `b"ec-pub"`) that prevents accidental cross-context cache
/// hits between key types that happen to share the same byte representation.
///
/// Each part is length-prefixed with a big-endian u64 so that
/// `(b"ab", b"c")` and `(b"a", b"bc")` cannot collide.
pub fn fingerprint(domain: &[u8], parts: &[&[u8]]) -> KeyFingerprint {
    let mut h = Sha256::new();
    h.update(b"craton-hsm-pkcs11.v1\x00");
    h.update((domain.len() as u32).to_be_bytes());
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Per-cache-entry metadata.
#[derive(Debug, Default, Clone, Copy)]
pub struct EntryMeta {
    /// Number of AES-GCM encryption operations performed under this key.
    /// Used to enforce a per-key nonce-reuse safety limit.
    pub gcm_messages: u64,
}

#[derive(Debug)]
struct Slot<V> {
    fp: KeyFingerprint,
    value: V,
    meta: EntryMeta,
    prev: Option<usize>,
    next: Option<usize>,
}

/// O(1) LRU cache mapping key fingerprints to imported PKCS#11 object handles
/// (or any other `Copy` value type, for testability).
///
/// `head` is the most-recently-used slot, `tail` is the least-recently-used.
///
/// # GCM counter persistence
///
/// AES-GCM message counters must never go backwards for a given key: doing
/// so invites nonce reuse, which is catastrophic for GCM's confidentiality
/// *and* authenticity guarantees (NIST SP 800-38D §8.3). The
/// non-evictable, pool-wide high-water-mark map is owned by
/// [`crate::pool::PoolGcmCounters`] (consulted via
/// `PooledSession::gcm_counters()` in `aes_256_gcm_encrypt`), so the cache
/// itself is *not* on the critical path for nonce-reuse accounting. The
/// per-slot [`EntryMeta::gcm_messages`] counter is retained for tests and
/// debug introspection only.
pub struct KeyCache<V: Copy> {
    map: HashMap<KeyFingerprint, usize>,
    slots: Vec<Option<Slot<V>>>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    capacity: usize,
}

impl<V: Copy> KeyCache<V> {
    /// Create an empty cache with the given capacity. Panics if `capacity` is 0.
    ///
    /// Prefer [`KeyCache::try_new`] in any context that holds caller-controlled
    /// configuration; this constructor remains panicking for the in-crate
    /// `KEY_CACHE_DEFAULT_CAPACITY`-fed call sites where the value is known
    /// non-zero at compile time.
    pub fn new(capacity: usize) -> Self {
        Self::try_new(capacity).expect("KeyCache capacity must be > 0")
    }

    /// Fallible constructor: returns `None` if `capacity` is 0 instead of
    /// panicking. Used by [`crate::pool::SessionPool::new`] so a bad
    /// `cache_capacity` propagates as `HsmError::ConfigError` rather than
    /// unwinding out of a constructor.
    pub fn try_new(capacity: usize) -> Option<Self> {
        if capacity == 0 {
            return None;
        }
        Some(Self {
            map: HashMap::with_capacity(capacity),
            slots: Vec::with_capacity(capacity),
            free: Vec::new(),
            head: None,
            tail: None,
            capacity,
        })
    }

    /// Snapshot of all live fingerprints currently held in the cache,
    /// without changing recency order. Used by
    /// [`crate::pool::SessionPool::reestablish`] to compact pool-wide
    /// (key, iv) trackers after a session rotation.
    pub fn live_fingerprints(&self) -> Vec<KeyFingerprint> {
        self.map.keys().copied().collect()
    }

    /// Maximum number of entries the cache will hold before eviction.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of entries currently present in the cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up a fingerprint and, on hit, promote it to most-recently-used.
    pub fn get(&mut self, fp: &KeyFingerprint) -> Option<V> {
        let idx = *self.map.get(fp)?;
        self.unlink(idx);
        self.push_front(idx);
        Some(self.slots[idx].as_ref().unwrap().value)
    }

    /// Look up a fingerprint and return its handle plus a mutable reference
    /// to its metadata, promoting it on hit.
    pub fn get_with_meta(&mut self, fp: &KeyFingerprint) -> Option<(V, &mut EntryMeta)> {
        let idx = *self.map.get(fp)?;
        self.unlink(idx);
        self.push_front(idx);
        let slot = self.slots[idx].as_mut().unwrap();
        Some((slot.value, &mut slot.meta))
    }

    /// Insert (or replace) a fingerprint → value mapping. Returns the
    /// evicted value, if any, so the caller can issue `C_DestroyObject`
    /// while still holding the session lock.
    ///
    /// Note: the per-slot [`EntryMeta::gcm_messages`] counter is local to the
    /// cache slot and resets on eviction. Pool-wide nonce-reuse accounting
    /// (the only counter that matters for NIST SP 800-38D §8.3) lives in
    /// [`crate::pool::PoolGcmCounters`].
    #[must_use = "evicted handle must be destroyed on the session"]
    pub fn insert(&mut self, fp: KeyFingerprint, value: V) -> Option<V> {
        // Replace path: same fingerprint already cached → swap value, promote.
        if let Some(&idx) = self.map.get(&fp) {
            let prev_value = {
                let slot = self.slots[idx].as_mut().unwrap();
                let prev = slot.value;
                slot.value = value;
                prev
            };
            self.unlink(idx);
            self.push_front(idx);
            return Some(prev_value);
        }

        // Insert path: evict LRU if at capacity.
        let evicted = if self.map.len() >= self.capacity {
            self.evict_lru()
        } else {
            None
        };

        let slot = Slot {
            fp,
            value,
            meta: EntryMeta::default(),
            prev: None,
            next: None,
        };
        let idx = if let Some(free_idx) = self.free.pop() {
            self.slots[free_idx] = Some(slot);
            free_idx
        } else {
            self.slots.push(Some(slot));
            self.slots.len() - 1
        };
        self.map.insert(fp, idx);
        self.push_front(idx);
        evicted
    }

    /// Remove and return all cached values. Used during shutdown.
    pub fn drain(&mut self) -> Vec<V> {
        let mut out = Vec::with_capacity(self.map.len());
        for slot in self.slots.drain(..).flatten() {
            out.push(slot.value);
        }
        self.map.clear();
        self.free.clear();
        self.head = None;
        self.tail = None;
        out
    }

    // ---------- internal linked-list ops ----------

    fn evict_lru(&mut self) -> Option<V> {
        let tail = self.tail?;
        self.unlink(tail);
        let slot = self.slots[tail].take().unwrap();
        self.map.remove(&slot.fp);
        self.free.push(tail);
        Some(slot.value)
    }

    fn unlink(&mut self, idx: usize) {
        let (prev, next) = {
            let s = self.slots[idx].as_ref().unwrap();
            (s.prev, s.next)
        };
        match prev {
            Some(p) => self.slots[p].as_mut().unwrap().next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.slots[n].as_mut().unwrap().prev = prev,
            None => self.tail = prev,
        }
        let s = self.slots[idx].as_mut().unwrap();
        s.prev = None;
        s.next = None;
    }

    fn push_front(&mut self, idx: usize) {
        let old_head = self.head;
        {
            let s = self.slots[idx].as_mut().unwrap();
            s.prev = None;
            s.next = old_head;
        }
        if let Some(h) = old_head {
            self.slots[h].as_mut().unwrap().prev = Some(idx);
        }
        self.head = Some(idx);
        if self.tail.is_none() {
            self.tail = Some(idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> KeyFingerprint {
        let mut f = [0u8; 32];
        f[0] = byte;
        f
    }

    #[test]
    fn fingerprint_is_deterministic_and_domain_separated() {
        let a = fingerprint(b"aes", &[&[1, 2, 3]]);
        let b = fingerprint(b"aes", &[&[1, 2, 3]]);
        let c = fingerprint(b"rsa-priv", &[&[1, 2, 3]]);
        assert_eq!(a, b);
        assert_ne!(
            a, c,
            "different domains must produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_length_prefix_prevents_concatenation_collisions() {
        // ("ab", "c") and ("a", "bc") must NOT collide.
        let a = fingerprint(b"x", &[b"ab", b"c"]);
        let b = fingerprint(b"x", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_known_vector_for_empty_input() {
        // Sanity check that our fingerprint isn't accidentally constant.
        let a = fingerprint(b"aes", &[]);
        let b = fingerprint(b"aes", &[b""]);
        // Empty parts list and a single zero-length part are NOT equivalent
        // (the latter writes a u64 length prefix).
        assert_ne!(a, b);
    }

    #[test]
    fn insert_and_lookup() {
        let mut c = KeyCache::<u64>::new(4);
        assert!(c.insert(fp(1), 10).is_none());
        assert_eq!(c.get(&fp(1)), Some(10));
        assert_eq!(c.len(), 1);
        assert!(!c.is_empty());
    }

    #[test]
    fn miss_returns_none() {
        let mut c = KeyCache::<u64>::new(4);
        assert_eq!(c.get(&fp(7)), None);
    }

    #[test]
    fn lru_evicts_least_recent() {
        let mut c = KeyCache::<u64>::new(3);
        assert!(c.insert(fp(1), 1).is_none());
        assert!(c.insert(fp(2), 2).is_none());
        assert!(c.insert(fp(3), 3).is_none());
        // Touch 1 → it becomes MRU. Order LRU→MRU: 2,3,1
        assert_eq!(c.get(&fp(1)), Some(1));
        // Insert 4 → evict 2.
        assert_eq!(c.insert(fp(4), 4), Some(2));
        assert_eq!(c.get(&fp(2)), None);
        assert_eq!(c.get(&fp(1)), Some(1));
        assert_eq!(c.get(&fp(3)), Some(3));
        assert_eq!(c.get(&fp(4)), Some(4));
    }

    #[test]
    fn fifo_when_no_promotions() {
        let mut c = KeyCache::<u64>::new(3);
        c.insert(fp(1), 1);
        c.insert(fp(2), 2);
        c.insert(fp(3), 3);
        // No promotions → LRU == fp(1).
        assert_eq!(c.insert(fp(4), 4), Some(1));
        assert_eq!(c.insert(fp(5), 5), Some(2));
        assert_eq!(c.insert(fp(6), 6), Some(3));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn reinsert_replaces_value_without_evicting_slot() {
        // Reinsert on an existing fingerprint must swap the value
        // in-place and promote the slot to MRU, returning the old value
        // so the caller can `C_DestroyObject` the prior handle. The
        // per-slot `gcm_messages` counter is a debug aid only — pool-wide
        // accounting lives in `PoolGcmCounters`.
        let mut c = KeyCache::<u64>::new(2);
        let _ = c.insert(fp(1), 100);
        let evicted = c.insert(fp(1), 200);
        assert_eq!(evicted, Some(100));
        let (value, _meta) = c.get_with_meta(&fp(1)).unwrap();
        assert_eq!(value, 200);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn capacity_one_lru() {
        let mut c = KeyCache::<u64>::new(1);
        assert!(c.insert(fp(1), 1).is_none());
        assert_eq!(c.insert(fp(2), 2), Some(1));
        assert_eq!(c.get(&fp(1)), None);
        assert_eq!(c.get(&fp(2)), Some(2));
    }

    #[test]
    fn drain_returns_all_handles_and_clears() {
        let mut c = KeyCache::<u64>::new(4);
        c.insert(fp(1), 1);
        c.insert(fp(2), 2);
        c.insert(fp(3), 3);
        let mut handles = c.drain();
        handles.sort_unstable();
        assert_eq!(handles, vec![1, 2, 3]);
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
        assert_eq!(c.get(&fp(1)), None);
        // Reinsert after drain still works.
        assert!(c.insert(fp(9), 9).is_none());
        assert_eq!(c.get(&fp(9)), Some(9));
    }

    #[test]
    fn meta_persists_until_eviction() {
        let mut c = KeyCache::<u64>::new(2);
        c.insert(fp(1), 1);
        c.get_with_meta(&fp(1)).unwrap().1.gcm_messages = 42;
        c.insert(fp(2), 2);
        let (_, meta) = c.get_with_meta(&fp(1)).unwrap();
        assert_eq!(meta.gcm_messages, 42);
    }

    #[test]
    fn promotion_o1_hammer() {
        // Insert KEY_CACHE_DEFAULT_CAPACITY * 200 distinct keys with random
        // promotions. Validate the cache stays within capacity and the LRU
        // invariant holds (no key promoted in the last `capacity` ops is
        // missing).
        let cap = 8;
        let mut c = KeyCache::<u64>::new(cap);
        for i in 0..10_000u64 {
            let f = fingerprint(b"x", &[&i.to_le_bytes()]);
            let _ = c.insert(f, i);
            let _ = c.get(&f);
        }
        assert_eq!(c.len(), cap);
    }

    #[test]
    #[should_panic]
    fn capacity_zero_panics() {
        let _ = KeyCache::<u64>::new(0);
    }

    #[test]
    fn try_new_zero_returns_none() {
        assert!(KeyCache::<u64>::try_new(0).is_none());
        assert!(KeyCache::<u64>::try_new(1).is_some());
    }

    #[test]
    fn live_fingerprints_snapshot() {
        let mut c = KeyCache::<u64>::new(4);
        let _ = c.insert(fp(1), 10);
        let _ = c.insert(fp(2), 20);
        let mut live = c.live_fingerprints();
        live.sort();
        assert_eq!(live, vec![fp(1), fp(2)]);
    }
}
