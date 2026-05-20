// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Session pool for the PKCS#11 passthrough backend.
//!
//! The previous backend held a single `Mutex<Session>`, serializing every
//! crypto call across the entire process. This module replaces that with a
//! pool of N sessions, each with its own [`KeyCache`].
//!
//! ## Global GCM/CTR counters
//!
//! AES-GCM nonce-reuse safety (NIST SP 800-38D 8.3) requires a *global*
//! per-key message counter. Two sessions checked out concurrently for the
//! same imported AES key share a single counter held in [`PoolGcmCounters`]
//! behind a `parking_lot::RwLock`. The same treatment applies to CTR
//! (key, iv) reuse tracking via [`PoolCtrCounters`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use craton_hsm::error::{HsmError, HsmResult};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::cache::{KeyCache, KeyFingerprint, KEY_CACHE_DEFAULT_CAPACITY};
use crate::error::map_cryptoki_error;

/// Opaque, per-session token used by [`PoolGcmCounters`], [`PoolCtrCounters`],
/// and [`crate::cache::KeyFingerprint`]-keyed structures whenever a caller
/// would otherwise reach for the bare cryptoki `ObjectHandle`.
///
/// PKCS#11 session handles are recycled across logout/login cycles
/// -- keying a long-lived map directly on the cryptoki handle therefore
/// risks aliasing two unrelated sessions. `SessionToken` is 16 bytes of
/// `OsRng` entropy minted exactly once when the session is opened and
/// retired with the session.
///
/// `Debug` is hand-written to redact most of the entropy (only an 8-hex-char
/// prefix is shown) so that error/panic logs cannot leak the full token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionToken(pub [u8; 16]);

impl SessionToken {
    /// Mint a fresh token from the operating-system CSPRNG.
    ///
    /// Two consecutive calls return tokens that differ with probability
    /// `1 - 2^-128`; treat collisions as impossible.
    pub fn new_random() -> Self {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show an 8-hex-char (4-byte) prefix and elide the rest. Logging the
        // full token would let an attacker who scrapes panic dumps re-key
        // pool-wide counter maps to a victim session.
        let p = &self.0;
        write!(
            f,
            "SessionToken({:02x}{:02x}{:02x}{:02x}...)",
            p[0], p[1], p[2], p[3]
        )
    }
}

impl From<SessionToken> for [u8; 16] {
    fn from(t: SessionToken) -> [u8; 16] {
        t.0
    }
}

/// Global, pool-wide AES-GCM message counters keyed by imported-key
/// fingerprint. Lifted out of the per-session [`KeyCache`] so concurrent
/// sessions encrypting under the same key share a single budget.
///
/// A counter value of [`u64::MAX`] is treated as a poison sentinel.
///
/// Backed by a plain `Mutex` (not `RwLock`): every public entry point on
/// this type mutates the inner `HashMap`, so the read-write split would
/// only add overhead.
#[derive(Debug, Default)]
pub struct PoolGcmCounters {
    inner: Mutex<HashMap<KeyFingerprint, u64>>,
}

impl PoolGcmCounters {
    /// Create an empty counter map.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Snapshot the current counter for `fp`, or `0` if absent.
    pub fn get(&self, fp: &KeyFingerprint) -> u64 {
        self.inner.lock().get(fp).copied().unwrap_or(0)
    }

    /// Atomically read the current counter, refuse if it has reached `limit`,
    /// and otherwise increment by 1 and return the new value.
    pub fn check_and_increment(&self, fp: &KeyFingerprint, limit: u64) -> HsmResult<u64> {
        let mut guard = self.inner.lock();
        let current = guard.get(fp).copied().unwrap_or(0);
        if current >= limit {
            guard.insert(*fp, u64::MAX);
            return Err(HsmError::KeyFunctionNotPermitted);
        }
        let next = current.saturating_add(1);
        guard.insert(*fp, next);
        Ok(next)
    }

    /// Drop entries whose key is not in `live` AND whose counter has not
    /// reached the poison sentinel.
    pub fn compact(&self, live: &HashSet<KeyFingerprint>) {
        let mut guard = self.inner.lock();
        guard.retain(|fp, hwm| live.contains(fp) || *hwm == u64::MAX);
    }
}

/// Global per-(key,iv) CTR usage tracker.
#[derive(Debug, Default)]
pub struct PoolCtrCounters {
    inner: Mutex<HashMap<(KeyFingerprint, [u8; 16]), ()>>,
}

impl PoolCtrCounters {
    /// Create an empty CTR-usage map.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record a `(fingerprint, iv)` pair. Returns
    /// [`HsmError::MechanismParamInvalid`] if the pair was already seen.
    pub fn check_and_record(&self, fp: &KeyFingerprint, iv: &[u8; 16]) -> HsmResult<()> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&(*fp, *iv)) {
            return Err(HsmError::MechanismParamInvalid);
        }
        guard.insert((*fp, *iv), ());
        Ok(())
    }

    /// Number of distinct `(fingerprint, iv)` pairs currently tracked.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Drop entries whose key fingerprint is not in `live`. Called from
    /// [`SessionPool::reestablish`] so that imported-key handles that
    /// will be re-imported under fresh PKCS#11 object handles do not
    /// carry stale (key, iv) usage that would falsely reject a
    /// legitimate caller after a token reboot.
    pub fn compact(&self, live: &HashSet<KeyFingerprint>) {
        let mut guard = self.inner.lock();
        guard.retain(|(fp, _iv), _| live.contains(fp));
    }
}

/// A single pooled, logged-in PKCS#11 session plus its imported-key cache.
pub struct PooledSession {
    session: Session,
    /// Opaque per-session token. See [`SessionToken`].
    /// Populated at session-construction time and rotated when
    /// [`SessionPool::reestablish`] re-opens the session.
    pub(crate) token: SessionToken,
    pub(crate) cache: KeyCache<cryptoki::object::ObjectHandle>,
    pub(crate) gcm_counters: Arc<PoolGcmCounters>,
    pub(crate) ctr_counters: Arc<PoolCtrCounters>,
}

impl PooledSession {
    /// Borrow the underlying PKCS#11 session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Borrow this session's opaque [`SessionToken`].
    ///
    /// Use this in preference to the cryptoki session/object handle
    /// when keying long-lived maps that must survive logout/login.
    pub fn token(&self) -> SessionToken {
        self.token
    }

    /// Mutable access to the per-session imported-key cache.
    pub fn cache_mut(&mut self) -> &mut KeyCache<cryptoki::object::ObjectHandle> {
        &mut self.cache
    }

    /// Both at once for ergonomic borrows in the backend.
    pub fn split(&mut self) -> (&Session, &mut KeyCache<cryptoki::object::ObjectHandle>) {
        (&self.session, &mut self.cache)
    }

    /// Borrow the pool-wide GCM counter map.
    pub fn gcm_counters(&self) -> &PoolGcmCounters {
        &self.gcm_counters
    }

    /// Borrow the pool-wide CTR (key,iv) tracker.
    pub fn ctr_counters(&self) -> &PoolCtrCounters {
        &self.ctr_counters
    }
}

impl Drop for PooledSession {
    fn drop(&mut self) {
        for handle in self.cache.drain() {
            let _ = self.session.destroy_object(handle);
        }
        let _ = self.session.logout();
    }
}

/// Pool of [`PooledSession`]s sharing a single PKCS#11 library context.
///
/// `Debug` is hand-written to elide the live PKCS#11 context, the PIN,
/// and per-session state. `Result::unwrap_err()` invokes Debug on the
/// Ok variant, so deriving Debug on a struct holding a PIN would
/// route the secret straight to operator logs.
pub struct SessionPool {
    ctx: Arc<Pkcs11>,
    slot: Slot,
    pin: Zeroizing<String>,
    sessions: Vec<Mutex<PooledSession>>,
    next: AtomicUsize,
    cache_capacity: usize,
    gcm_counters: Arc<PoolGcmCounters>,
    ctr_counters: Arc<PoolCtrCounters>,
}

impl std::fmt::Debug for SessionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPool")
            .field("slot", &self.slot)
            .field("session_count", &self.sessions.len())
            .field("cache_capacity", &self.cache_capacity)
            .field("pin", &"<redacted>")
            .field("ctx", &"<elided>")
            .finish()
    }
}

impl SessionPool {
    /// Initialise the PKCS#11 library, open `pool_size` logged-in sessions, and
    /// return a pool wrapping them.
    pub fn new(
        library_path: &std::path::Path,
        slot_id: u64,
        pin: Zeroizing<String>,
        pool_size: usize,
        cache_capacity: usize,
    ) -> HsmResult<Self> {
        // Previously `assert!(pool_size > 0)`; panicking from a
        // constructor would unwind into caller test harnesses and
        // supervisor processes. Surface as ConfigError so callers can
        // react gracefully.
        if pool_size == 0 {
            return Err(HsmError::ConfigError("pool_size must be > 0".to_string()));
        }
        let cache_capacity = if cache_capacity == 0 {
            KEY_CACHE_DEFAULT_CAPACITY
        } else {
            cache_capacity
        };

        let ctx = Pkcs11::new(library_path).map_err(|e| {
            HsmError::ConfigError(format!(
                "failed to load PKCS#11 library at {}: {}",
                library_path.display(),
                e
            ))
        })?;

        ctx.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::ConfigError(format!("C_Initialize failed: {}", e)))?;

        let slot = Slot::try_from(slot_id)
            .map_err(|e| HsmError::ConfigError(format!("invalid slot ID {}: {}", slot_id, e)))?;

        let ctx = Arc::new(ctx);
        let gcm_counters = Arc::new(PoolGcmCounters::new());
        let ctr_counters = Arc::new(PoolCtrCounters::new());

        let mut sessions = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let session = open_and_login(&ctx, slot, pin.as_str())?;
            let cache = KeyCache::try_new(cache_capacity).ok_or_else(|| {
                HsmError::ConfigError(
                    "cache_capacity must be > 0 (use 0 to request the default)".to_string(),
                )
            })?;
            sessions.push(Mutex::new(PooledSession {
                session,
                token: SessionToken::new_random(),
                cache,
                gcm_counters: Arc::clone(&gcm_counters),
                ctr_counters: Arc::clone(&ctr_counters),
            }));
        }

        Ok(Self {
            ctx,
            slot,
            pin,
            sessions,
            next: AtomicUsize::new(0),
            cache_capacity,
            gcm_counters,
            ctr_counters,
        })
    }

    /// Number of sessions held in the pool.
    pub fn pool_size(&self) -> usize {
        self.sessions.len()
    }

    /// Per-session key-cache capacity configured for this pool.
    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity
    }

    /// Borrow the pool-wide GCM counter map.
    pub fn gcm_counters(&self) -> &Arc<PoolGcmCounters> {
        &self.gcm_counters
    }

    /// Borrow the pool-wide CTR (key,iv) tracker.
    pub fn ctr_counters(&self) -> &Arc<PoolCtrCounters> {
        &self.ctr_counters
    }

    /// Snapshot the [`SessionToken`] of every session currently in the pool.
    ///
    /// The returned `Vec` reflects the tokens at the moment of the call;
    /// concurrent [`SessionPool::reestablish`] calls may rotate any token
    /// after the snapshot is taken. Useful for diagnostics and for embedders
    /// that want to wire `auth`'s `Pkcs11Identity::from_session_token` to a
    /// concrete pool session.
    pub fn session_tokens(&self) -> Vec<SessionToken> {
        self.sessions.iter().map(|m| m.lock().token).collect()
    }

    /// Check out a session and run `f` with exclusive access. On a
    /// session-level error the session is re-established and `f` is retried
    /// once.
    ///
    /// Selection strategy: sweep all sessions once with `try_lock` to grab
    /// any free slot immediately; if every session is contended, fall back
    /// to a round-robin index and `lock` (block) on it.
    pub fn with_session<R>(
        &self,
        mut f: impl FnMut(&mut PooledSession) -> HsmResult<R>,
    ) -> HsmResult<R> {
        let n = self.sessions.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;
        let mut chosen_idx: Option<usize> = None;
        let mut chosen_guard = None;
        for offset in 0..n {
            let idx = (start + offset) % n;
            if let Some(g) = self.sessions[idx].try_lock() {
                chosen_idx = Some(idx);
                chosen_guard = Some(g);
                break;
            }
        }
        let (idx, mut guard) = match (chosen_idx, chosen_guard) {
            (Some(i), Some(g)) => (i, g),
            _ => {
                let idx = start;
                let guard = self.sessions[idx].lock();
                (idx, guard)
            }
        };

        match f(&mut guard) {
            Ok(v) => Ok(v),
            Err(e) if is_session_level(&e) => {
                tracing::warn!(
                    target: "craton_hsm_pkcs11",
                    "session #{} entered bad state ({:?}); re-establishing",
                    idx,
                    e
                );
                self.reestablish(&mut guard)?;
                f(&mut guard)
            }
            Err(e) => Err(e),
        }
    }

    fn reestablish(&self, slot_guard: &mut PooledSession) -> HsmResult<()> {
        let _ = slot_guard.cache.drain();
        let new_session = open_and_login(&self.ctx, self.slot, self.pin.as_str())?;
        slot_guard.session = new_session;
        // Rotate the opaque token: the old cryptoki handle is gone and any
        // counters keyed on the old token belong to a session that no longer
        // exists. Minting a fresh token here is the whole point of W2.
        slot_guard.token = SessionToken::new_random();
        // Compact the CTR-IV tracker for fingerprints no longer cached on
        // ANY session in the pool. Without this, a key re-imported after
        // a token reboot would inherit its stale (key, iv) usage and
        // erroneously refuse a legitimate caller for replay-protection
        // that the operator did not ask for. The GCM counter is left
        // alone -- its high-water mark MUST persist across session
        // resets within the same process, per NIST SP 800-38D 8.3.
        // `try_lock` skips the slot we currently hold a guard on,
        // avoiding a double-lock; sessions we cannot inspect contribute
        // nothing to `live`, which is safe (it only causes us to drop
        // a few extra entries early -- never a false-positive replay).
        let mut live: HashSet<KeyFingerprint> = HashSet::new();
        // Include the just-reestablished slot's own (now-empty) cache.
        live.extend(slot_guard.cache.live_fingerprints());
        for m in &self.sessions {
            if let Some(g) = m.try_lock() {
                live.extend(g.cache.live_fingerprints());
            }
        }
        self.ctr_counters.compact(&live);
        Ok(())
    }
}

/// Open a R/W session on `slot` and log in as CKU_USER with `pin`.
///
/// `pin` is consumed only to construct an [`AuthPin`], whose inner
/// `secrecy::SecretString` zeroizes its allocation on drop. The error
/// paths below deliberately do NOT include the `pin` value in any
/// formatted output.
fn open_and_login(ctx: &Pkcs11, slot: Slot, pin: &str) -> HsmResult<Session> {
    let session = ctx
        .open_rw_session(slot)
        .map_err(|e| HsmError::ConfigError(format!("failed to open R/W session: {}", e)))?;
    // Build the owned PIN copy inside a `Zeroizing` wrapper so that on
    // every exit path (including a panic unwinding through
    // `login.map_err`) the intermediate `String` allocation is wiped
    // before being returned to the allocator. `AuthPin` itself wraps a
    // `secrecy::SecretString` that zeroizes on drop, so once we hand off
    // a clone the only surviving plaintext copy lives inside `AuthPin`.
    // The double-allocation for the duration of `C_Login` is negligible.
    let owned_pin: Zeroizing<String> = Zeroizing::new(pin.to_owned());
    let auth_pin = AuthPin::new((*owned_pin).clone());
    session
        .login(UserType::User, Some(&auth_pin))
        .map_err(|e| match &e {
            CryptokiError::Pkcs11(RvError::PinIncorrect, _) => HsmError::PinIncorrect,
            CryptokiError::Pkcs11(RvError::PinLocked, _) => HsmError::PinLocked,
            // SAFETY: cryptoki Display impl for CryptokiError does not
            // embed any PIN bytes; only the structural error variant.
            _ => HsmError::ConfigError(format!("C_Login failed: {}", e)),
        })?;
    Ok(session)
}

/// True if `e` indicates a stale / unrecoverable session that the caller
/// should retry on a fresh session.
///
/// `DeviceMemory` / `HostMemory` are treated as session-level because the
/// only safe recovery is to drop the per-session imported-key cache
/// (exactly what `reestablish` does) and give the token a clean slate.
/// Likewise, `OperationActive` and `OperationNotInitialized` indicate
/// the session's crypto-op state machine has diverged from the host's
/// expectation; re-establishing the session resets it.
fn is_session_level(e: &HsmError) -> bool {
    matches!(
        e,
        HsmError::SessionHandleInvalid
            | HsmError::UserNotLoggedIn
            | HsmError::TokenNotPresent
            | HsmError::SessionClosed
            | HsmError::DeviceMemory
            | HsmError::HostMemory
            | HsmError::OperationActive
            | HsmError::OperationNotInitialized
    )
}

/// Helper used by the backend to map a cryptoki error inline.
#[inline]
pub fn map_err(e: CryptokiError) -> HsmError {
    map_cryptoki_error(&e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_session_level_detects_session_handle_invalid() {
        assert!(is_session_level(&HsmError::SessionHandleInvalid));
    }

    #[test]
    fn is_session_level_detects_user_not_logged_in() {
        assert!(is_session_level(&HsmError::UserNotLoggedIn));
    }

    #[test]
    fn is_session_level_detects_token_not_present() {
        assert!(is_session_level(&HsmError::TokenNotPresent));
    }

    #[test]
    fn is_session_level_detects_session_closed() {
        assert!(is_session_level(&HsmError::SessionClosed));
    }

    #[test]
    fn is_session_level_rejects_non_session_errors() {
        assert!(!is_session_level(&HsmError::GeneralError));
        assert!(!is_session_level(&HsmError::ArgumentsBad));
        assert!(!is_session_level(&HsmError::PinIncorrect));
        assert!(!is_session_level(&HsmError::MechanismInvalid));
        assert!(!is_session_level(&HsmError::KeyHandleInvalid));
    }

    #[test]
    fn is_session_level_accepts_memory_and_op_state_errors() {
        // DeviceMemory / HostMemory / OperationActive /
        // OperationNotInitialized are now session-level: see the doc
        // comment on `is_session_level`.
        assert!(is_session_level(&HsmError::DeviceMemory));
        assert!(is_session_level(&HsmError::HostMemory));
        assert!(is_session_level(&HsmError::OperationActive));
        assert!(is_session_level(&HsmError::OperationNotInitialized));
    }

    #[test]
    fn map_err_delegates_to_map_cryptoki_error() {
        let e = CryptokiError::NotSupported;
        assert!(matches!(map_err(e), HsmError::FunctionNotSupported));
    }

    #[test]
    fn map_err_already_initialized() {
        let e = CryptokiError::AlreadyInitialized;
        assert!(matches!(map_err(e), HsmError::AlreadyInitialized));
    }

    #[test]
    fn map_err_pin_not_set() {
        let e = CryptokiError::PinNotSet;
        assert!(matches!(map_err(e), HsmError::UserPinNotInitialized));
    }

    #[test]
    fn new_rejects_nonexistent_library() {
        let result = SessionPool::new(
            std::path::Path::new("/nonexistent/libpkcs11.so"),
            0,
            Zeroizing::new("1234".to_string()),
            4,
            64,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            HsmError::ConfigError(msg) => {
                assert!(
                    msg.contains("failed to load PKCS#11 library"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("expected ConfigError, got {:?}", other),
        }
    }

    #[test]
    fn new_returns_config_error_on_zero_pool_size() {
        let res = SessionPool::new(
            std::path::Path::new("/nonexistent/lib.so"),
            0,
            Zeroizing::new("pin".to_string()),
            0,
            64,
        );
        match res {
            Err(HsmError::ConfigError(msg)) => {
                assert!(
                    msg.contains("pool_size must be > 0"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("expected ConfigError, got {:?}", other),
        }
    }

    #[test]
    fn pool_gcm_counters_check_and_increment_monotonic() {
        let counters = PoolGcmCounters::new();
        let fp = [9u8; 32];
        assert_eq!(counters.check_and_increment(&fp, 100).unwrap(), 1);
        assert_eq!(counters.check_and_increment(&fp, 100).unwrap(), 2);
        assert_eq!(counters.get(&fp), 2);
    }

    #[test]
    fn pool_gcm_counters_refuse_at_limit() {
        let counters = PoolGcmCounters::new();
        let fp = [3u8; 32];
        for _ in 0..5 {
            let _ = counters.check_and_increment(&fp, 5);
        }
        let res = counters.check_and_increment(&fp, 5);
        assert!(matches!(res, Err(HsmError::KeyFunctionNotPermitted)));
        assert_eq!(counters.get(&fp), u64::MAX);
    }

    #[test]
    fn pool_gcm_counters_compact_drops_unrelated_unpoisoned() {
        let counters = PoolGcmCounters::new();
        let live_fp = [1u8; 32];
        let dead_fp = [2u8; 32];
        let _ = counters.check_and_increment(&live_fp, 100);
        let _ = counters.check_and_increment(&dead_fp, 100);
        let mut live = HashSet::new();
        live.insert(live_fp);
        counters.compact(&live);
        assert_eq!(counters.get(&live_fp), 1);
        assert_eq!(counters.get(&dead_fp), 0);
    }

    #[test]
    fn pool_ctr_counters_reject_reuse() {
        let ctr = PoolCtrCounters::new();
        let fp = [7u8; 32];
        let iv = [0xAAu8; 16];
        assert!(ctr.check_and_record(&fp, &iv).is_ok());
        let res = ctr.check_and_record(&fp, &iv);
        assert!(matches!(res, Err(HsmError::MechanismParamInvalid)));
    }

    #[test]
    fn pool_ctr_counters_distinct_iv_ok() {
        let ctr = PoolCtrCounters::new();
        let fp = [7u8; 32];
        let iv1 = [0xAAu8; 16];
        let iv2 = [0xBBu8; 16];
        assert!(ctr.check_and_record(&fp, &iv1).is_ok());
        assert!(ctr.check_and_record(&fp, &iv2).is_ok());
        assert_eq!(ctr.len(), 2);
    }

    #[test]
    fn pool_ctr_counters_distinct_keys_ok() {
        let ctr = PoolCtrCounters::new();
        let fp1 = [7u8; 32];
        let fp2 = [8u8; 32];
        let iv = [0xAAu8; 16];
        assert!(ctr.check_and_record(&fp1, &iv).is_ok());
        assert!(ctr.check_and_record(&fp2, &iv).is_ok());
    }

    /// W2: two consecutive `new_random()` calls must yield distinct tokens.
    /// Collision probability is 2^-128 -- astronomically lower than typical
    /// flaky-test thresholds.
    #[test]
    fn session_token_new_random_is_distinct() {
        let a = SessionToken::new_random();
        let b = SessionToken::new_random();
        assert_ne!(a.0, b.0, "OsRng must yield distinct 16-byte tokens");
    }

    /// `Debug` must redact the bulk of the token. Only the first 8 hex
    /// characters of entropy may appear; the literal `...` follows.
    #[test]
    fn session_token_debug_is_redacted() {
        let token = SessionToken([
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B,
        ]);
        let s = format!("{:?}", token);
        assert!(s.contains("deadbeef"), "expected 8-hex prefix, got: {}", s);
        assert!(s.contains("..."), "expected redaction marker, got: {}", s);
        // None of the trailing entropy may appear.
        assert!(
            !s.contains("0a0b"),
            "trailing entropy must not be logged: {}",
            s
        );
    }

    #[test]
    fn session_token_into_array_roundtrips() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let token = SessionToken(bytes);
        let out: [u8; 16] = token.into();
        assert_eq!(out, bytes);
    }
}
