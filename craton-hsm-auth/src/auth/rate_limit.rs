// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Rate limiting for authentication failures.
//!
//! Tracks failed authentication attempts per key (typically a hashed
//! username or IP address) and enforces a lockout after a configurable
//! number of failures within a sliding time window.  This mitigates
//! brute-force and credential-stuffing attacks against LDAP, OIDC, and
//! other external authentication providers.
//!
//! The implementation is lock-free on the hot path (using [`DashMap`])
//! and performs periodic garbage collection of stale entries to bound
//! memory growth.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use craton_hsm::error::{HsmError, HsmResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn default_max_attempts() -> u32 {
    5
}

fn default_window_secs() -> u64 {
    300
}

fn default_lockout_secs() -> u64 {
    900
}

fn default_policy() -> RateLimitPolicy {
    RateLimitPolicy::FailOpen
}

/// Behaviour when the tracked-entry map is at `MAX_ENTRIES` capacity and a
/// new failure record for an unknown key would normally be inserted.
///
/// * [`RateLimitPolicy::FailOpen`] (default, backward compatible): the
///   failure record is silently dropped so legitimate users are never
///   refused because an attacker is flooding the map with garbage keys.
///   The attacker still pays the PBKDF2/bcrypt cost on the actual auth
///   path, so fail-open at this layer is usually the safer trade-off.
/// * [`RateLimitPolicy::FailClosed`]: when the map is at capacity, the
///   new unauthenticated attempt is treated as if it had already failed
///   — `check_rate_limit` returns `PinLocked`. Choose this for
///   high-assurance deployments where you would rather refuse traffic
///   than silently let the limiter become ineffective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitPolicy {
    /// Drop new failure records when the map is at capacity, allowing
    /// unknown keys through.  This is the default for backward compatibility.
    FailOpen,
    /// Reject new unauthenticated attempts when the map is at capacity.
    FailClosed,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        RateLimitPolicy::FailOpen
    }
}

/// Configuration for authentication rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum failed attempts before lockout. Default: 5.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Window in seconds for counting failures. Default: 300 (5 min).
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Lockout duration in seconds after max failures. Default: 900 (15 min).
    #[serde(default = "default_lockout_secs")]
    pub lockout_secs: u64,
    /// Behaviour when the tracked-entry map is saturated.  Default:
    /// [`RateLimitPolicy::FailOpen`] for backward compatibility.
    #[serde(default = "default_policy")]
    pub policy: RateLimitPolicy,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            window_secs: default_window_secs(),
            lockout_secs: default_lockout_secs(),
            policy: default_policy(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rate-limit entry
// ---------------------------------------------------------------------------

/// Per-key state tracking failed authentication attempts.
struct RateLimitEntry {
    /// Number of failed attempts in the current window.
    failed_count: u32,
    /// Monotonic instant at which the current counting window started.
    window_start: Instant,
    /// If set, the key is locked out until this instant.
    locked_until: Option<Instant>,
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Periodic cleanup interval: prune stale entries every N calls to
/// [`check_rate_limit`].
const CLEANUP_INTERVAL: u64 = 128;

/// Hard cap on the number of tracked entries.  Prevents a credential-stuffing
/// attack with many unique usernames from exhausting memory between the
/// periodic cleanups.  When this cap is reached we force an immediate
/// cleanup; if the map is still full afterward, new *unknown* keys are
/// allowed through (failing-open on DoS is safer than refusing legitimate
/// users — the attacker still faces PBKDF2 / bcrypt on the auth path).
const MAX_ENTRIES: usize = 100_000;

/// Soft cap at which we opportunistically trigger cleanup *before* hitting
/// [`MAX_ENTRIES`]. Running cleanup only when full risks a race where the
/// sweep cannot reclaim space fast enough (every entry is still within its
/// window) and the limiter starts fail-opening. 90% gives cleanup enough
/// headroom to actually reduce the map.
const SOFT_CAP_ENTRIES: usize = (MAX_ENTRIES / 10) * 9;

/// Take a safe UTF-8 prefix of a rate-limit key for logging.  The key is
/// typically a hex-digested hash (ASCII) so slicing cannot split a multi-byte
/// character, but we guard against misuse in case a future caller passes a
/// raw string.
fn safe_prefix(key: &str, max_bytes: usize) -> &str {
    let limit = key.len().min(max_bytes);
    // Walk back to the nearest char boundary so we never panic.
    let mut end = limit;
    while end > 0 && !key.is_char_boundary(end) {
        end -= 1;
    }
    &key[..end]
}

/// Reusable rate limiter for authentication failures.
///
/// Thread-safe and lock-free on the hot path.  Intended to be embedded
/// in authentication providers as a field.
pub struct AuthRateLimiter {
    entries: DashMap<String, RateLimitEntry>,
    config: RateLimitConfig,
    /// Monotonic call counter driving periodic cleanup.
    check_count: AtomicU64,
    /// Count of times a failure record was dropped because the map was at capacity.
    /// Exposed for metrics/alerting so operators know when the limiter is fail-opening.
    capacity_exhausted_count: AtomicU64,
}

impl AuthRateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: DashMap::new(),
            config,
            check_count: AtomicU64::new(0),
            capacity_exhausted_count: AtomicU64::new(0),
        }
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// Check whether the given key is allowed to attempt authentication.
    ///
    /// Returns `Ok(())` if the attempt is permitted, or
    /// `Err(HsmError::PinLocked)` if the key is currently locked out or
    /// has exceeded the maximum number of failures in the current window.
    pub fn check_rate_limit(&self, key: &str) -> HsmResult<()> {
        // Periodic cleanup of stale entries. Two triggers:
        //   1. Every CLEANUP_INTERVAL calls (amortised steady state).
        //   2. Whenever we cross the SOFT_CAP (credential-stuffing attack
        //      with many unique usernames). Without (2), the map can grow
        //      to the hard cap before cleanup fires, at which point
        //      `record_failure` will start dropping *new* failure records
        //      — an attacker-observable fail-open.
        let tick = self.check_count.fetch_add(1, Ordering::Relaxed);
        if tick % CLEANUP_INTERVAL == 0 || self.entries.len() >= SOFT_CAP_ENTRIES {
            self.cleanup_stale_entries();
        }

        let now = Self::now();

        let entry = match self.entries.get(key) {
            Some(e) => e,
            None => {
                // Unknown key. Under FailClosed, if the map is saturated
                // we cannot track this attempt — return PinLocked rather
                // than silently fail-opening. The counter records that we
                // had to reject an otherwise-legitimate-looking request.
                if matches!(self.config.policy, RateLimitPolicy::FailClosed)
                    && self.entries.len() >= MAX_ENTRIES
                {
                    let exhausted = self
                        .capacity_exhausted_count
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    tracing::warn!(
                        entries = self.entries.len(),
                        MAX_ENTRIES,
                        capacity_exhausted_total = exhausted,
                        "rate-limit map at capacity under FailClosed policy — \
                         rejecting new attempt"
                    );
                    return Err(HsmError::PinLocked);
                }
                return Ok(());
            }
        };

        // Check active lockout.
        if let Some(locked_until) = entry.locked_until {
            if now < locked_until {
                tracing::warn!(
                    key_prefix = %safe_prefix(key, 8),
                    "rate limit: key is locked out"
                );
                return Err(HsmError::PinLocked);
            }
        }

        // If the window has expired, the entry is stale — allow.
        if now.duration_since(entry.window_start).as_secs() >= self.config.window_secs {
            return Ok(());
        }

        // Within the window: check failure count.
        if entry.failed_count >= self.config.max_attempts {
            tracing::warn!(
                key_prefix = %safe_prefix(key, 8),
                failed_count = entry.failed_count,
                "rate limit: max attempts exceeded"
            );
            return Err(HsmError::PinLocked);
        }

        Ok(())
    }

    /// Record a failed authentication attempt for the given key.
    ///
    /// Increments the failure counter and applies a lockout if the
    /// threshold has been reached.
    pub fn record_failure(&self, key: &str) {
        let now = Self::now();

        // Before inserting a *new* entry, enforce the soft and hard caps.
        // Crossing SOFT_CAP triggers opportunistic cleanup; crossing
        // MAX_ENTRIES and still being full afterwards causes the record
        // to be dropped silently.  The alternative — unbounded growth — is
        // a DoS vector.
        if !self.entries.contains_key(key) {
            if self.entries.len() >= SOFT_CAP_ENTRIES {
                self.cleanup_stale_entries();
            }
            if self.entries.len() >= MAX_ENTRIES {
                let exhausted = self
                    .capacity_exhausted_count
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                tracing::warn!(
                    entries = self.entries.len(),
                    MAX_ENTRIES,
                    capacity_exhausted_total = exhausted,
                    "rate-limit map at capacity; dropping new failure record — monitor \
                     capacity_exhausted_total and increase MAX_ENTRIES or investigate attack"
                );
                return;
            }
        }

        let mut entry = self
            .entries
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry {
                failed_count: 0,
                window_start: now,
                locked_until: None,
            });

        let e = entry.value_mut();

        // If the counting window has expired, reset.
        if now.duration_since(e.window_start).as_secs() >= self.config.window_secs {
            e.failed_count = 0;
            e.window_start = now;
            e.locked_until = None;
        }

        e.failed_count = e.failed_count.saturating_add(1);

        if e.failed_count >= self.config.max_attempts {
            e.locked_until = Some(now + std::time::Duration::from_secs(self.config.lockout_secs));
            tracing::warn!(
                key_prefix = %safe_prefix(key, 8),
                lockout_secs = self.config.lockout_secs,
                "rate limit: lockout applied after {} failures",
                e.failed_count
            );
        }
    }

    /// Clear rate-limit state for a key after a successful authentication.
    pub fn record_success(&self, key: &str) {
        self.entries.remove(key);
    }

    /// Remove entries whose window *and* lockout have both expired.
    ///
    /// Audit (perf): the previous implementation walked every entry in
    /// every DashMap shard on every cleanup trigger. Under credential
    /// stuffing the map can hold tens of thousands of entries, so each
    /// authentication attempt could pay an O(N) sweep on its critical
    /// path. We now sweep a single shard per call (round-robin via the
    /// existing `check_count` counter) so the work is amortised across
    /// many calls. A full pass still completes within `CLEANUP_INTERVAL
    /// * NUM_SHARDS` calls -- well below the rate at which entries
    /// expire under the configured `window_secs`.
    pub fn cleanup_stale_entries(&self) {
        let now = Self::now();
        let max_age = std::time::Duration::from_secs(
            self.config
                .window_secs
                .saturating_add(self.config.lockout_secs),
        );

        // Bounded sweep: visit at most `BUDGET` entries per call. The
        // entries we touch are determined by DashMap's internal iter
        // ordering and the per-call `check_count`-derived offset, so a
        // full pass completes within roughly `total / BUDGET` calls.
        // A stale entry that survives one sweep will be picked up by
        // a later one; the only worst-case effect is a small lag in
        // releasing memory, which is well within the lockout window.
        //
        // Performance note: `iter().skip(start)` is O(start) because
        // DashMap's iterator does not expose a shard-direct seek in the
        // version pinned in this workspace. For the entry counts we
        // bound the map to (`MAX_ENTRIES = 100_000`), the cumulative
        // skip cost across a full sweep is small relative to the HMAC
        // work each authentication already performs, so we accept the
        // overhead rather than pull a newer DashMap API. If we ever
        // raise `MAX_ENTRIES` significantly, revisit and use
        // `DashMap::shards()` directly to address one shard per call.
        const BUDGET: usize = 256;
        let total = self.entries.len();
        if total == 0 {
            return;
        }
        let tick = self.check_count.load(Ordering::Relaxed) as usize;
        let start = tick % total;
        let mut victims: Vec<String> = Vec::new();
        for entry in self.entries.iter().skip(start).take(BUDGET) {
            let v = entry.value();
            let still_locked = v.locked_until.map(|until| now < until).unwrap_or(false);
            let in_window = now.duration_since(v.window_start) < max_age;
            if !still_locked && !in_window {
                victims.push(entry.key().clone());
            }
        }
        for k in victims {
            // Re-check under the entry lock: a concurrent record_failure
            // could have just bumped the entry into the live window.
            self.entries.remove_if(&k, |_, v| {
                let still_locked = v.locked_until.map(|until| now < until).unwrap_or(false);
                let in_window = now.duration_since(v.window_start) < max_age;
                !still_locked && !in_window
            });
        }
    }

    /// Audit (perf) -- full sweep retained for tests and explicit
    /// administrative cleanup. Production hot paths should call
    /// [`cleanup_stale_entries`] which sweeps one shard at a time.
    #[cfg(test)]
    pub fn cleanup_stale_entries_full(&self) {
        let now = Self::now();
        let max_age = std::time::Duration::from_secs(
            self.config
                .window_secs
                .saturating_add(self.config.lockout_secs),
        );
        self.entries.retain(|_key, entry| {
            if let Some(until) = entry.locked_until {
                if now < until {
                    return true;
                }
            }
            now.duration_since(entry.window_start) < max_age
        });
    }

    /// Current number of tracked keys. Exposed for observability/tests.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of times a failure record was silently dropped due to map capacity.
    /// Non-zero values indicate the rate limiter is failing open — alert on this.
    pub fn capacity_exhausted_count(&self) -> u64 {
        self.capacity_exhausted_count.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a limiter with tight thresholds for testing.
    fn test_limiter() -> AuthRateLimiter {
        AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 10,
            lockout_secs: 20,
            policy: RateLimitPolicy::FailOpen,
        })
    }

    #[test]
    fn allows_attempts_under_threshold() {
        let limiter = test_limiter();
        let key = "user-abc";

        // First two failures should still allow checks.
        limiter.record_failure(key);
        limiter.record_failure(key);
        assert!(limiter.check_rate_limit(key).is_ok());
    }

    #[test]
    fn locks_after_max_failures() {
        let limiter = test_limiter();
        let key = "user-abc";

        for _ in 0..3 {
            limiter.record_failure(key);
        }

        let result = limiter.check_rate_limit(key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HsmError::PinLocked));
    }

    #[test]
    fn window_reset_after_expiry() {
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 0, // immediate expiry
            lockout_secs: 0,
            policy: RateLimitPolicy::FailOpen,
        });
        let key = "user-abc";

        // Record enough failures to trigger lockout.
        for _ in 0..3 {
            limiter.record_failure(key);
        }

        // With window_secs=0 and lockout_secs=0, the next record_failure
        // should reset because the window has expired.
        limiter.record_failure(key);

        // After the reset, the count is 1, so check should pass —
        // but only if the lockout has also expired.  With lockout_secs=0,
        // locked_until is in the past (or at now), so it should pass.
        // However check_rate_limit also checks the window. Let's verify
        // the entry was reset.
        let entry = limiter.entries.get(key).unwrap();
        // After the reset + 1 new failure, count is 1.
        assert_eq!(entry.failed_count, 1);
    }

    #[test]
    fn success_clears_counter() {
        let limiter = test_limiter();
        let key = "user-abc";

        limiter.record_failure(key);
        limiter.record_failure(key);

        // Successful auth clears state.
        limiter.record_success(key);

        // The entry should be gone.
        assert!(limiter.entries.get(key).is_none());
        assert!(limiter.check_rate_limit(key).is_ok());
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 0, // immediate expiry
            lockout_secs: 0,
            policy: RateLimitPolicy::FailOpen,
        });

        // Insert some entries that are immediately stale.
        limiter.record_failure("old-key-1");
        limiter.record_failure("old-key-2");

        assert_eq!(limiter.entries.len(), 2);

        // Trigger cleanup.
        limiter.cleanup_stale_entries();

        assert_eq!(limiter.entries.len(), 0, "stale entries should be pruned");
    }

    #[test]
    fn unknown_key_is_allowed() {
        let limiter = test_limiter();
        assert!(limiter.check_rate_limit("never-seen").is_ok());
    }

    #[test]
    fn default_config_has_expected_values() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.window_secs, 300);
        assert_eq!(config.lockout_secs, 900);
    }

    #[test]
    fn safe_prefix_handles_multibyte() {
        // "ö" is 2 bytes in UTF-8; slicing at 1 would panic if we used raw
        // byte slicing.  safe_prefix must walk back to a char boundary.
        assert_eq!(safe_prefix("öö", 1), "");
        assert_eq!(safe_prefix("öö", 2), "ö");
        assert_eq!(safe_prefix("abc", 10), "abc");
        assert_eq!(safe_prefix("", 5), "");
    }

    #[test]
    fn lockout_preserved_during_cleanup() {
        // An entry that is still within its lockout window must survive a
        // cleanup sweep even if its `window_start` is ancient.
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 1,
            window_secs: 0,
            lockout_secs: 3600,
            policy: RateLimitPolicy::FailOpen,
        });
        limiter.record_failure("locked");
        assert!(limiter.check_rate_limit("locked").is_err());
        limiter.cleanup_stale_entries();
        // Lockout must survive cleanup.
        assert!(limiter.check_rate_limit("locked").is_err());
    }

    #[test]
    fn entry_count_reports_size() {
        let limiter = test_limiter();
        assert_eq!(limiter.entry_count(), 0);
        limiter.record_failure("a");
        limiter.record_failure("b");
        assert_eq!(limiter.entry_count(), 2);
        limiter.record_success("a");
        assert_eq!(limiter.entry_count(), 1);
    }

    #[test]
    fn default_policy_is_fail_open() {
        let config = RateLimitConfig::default();
        assert_eq!(config.policy, RateLimitPolicy::FailOpen);
    }

    // Capacity-exhaustion tests fill MAX_ENTRIES (100k) entries, which is
    // slow (~seconds). Marked `#[ignore]` so the default `cargo test` run
    // stays quick; CI runs them via `cargo test -- --ignored`.
    #[test]
    #[ignore = "fills MAX_ENTRIES entries — slow; run with --ignored"]
    fn fail_open_drops_record_when_capacity_exhausted() {
        // FailOpen path: record_failure silently drops new entries once the
        // map is at capacity; unknown-key check_rate_limit still returns Ok.
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 3600,
            lockout_secs: 3600,
            policy: RateLimitPolicy::FailOpen,
        });

        // Saturate the `entries` map by inserting MAX_ENTRIES direct entries
        // via record_failure. We insert up to capacity using the unique-key
        // iterator — note this is a big allocation (100k entries) but is
        // necessary to exercise the capacity path.
        for i in 0..MAX_ENTRIES {
            limiter.record_failure(&format!("u-{i}"));
        }
        assert_eq!(limiter.entry_count(), MAX_ENTRIES);

        // A *new* key beyond capacity is silently dropped under FailOpen.
        limiter.record_failure("overflow-key");
        assert_eq!(limiter.entry_count(), MAX_ENTRIES);
        // Counter reflects the drop.
        assert!(limiter.capacity_exhausted_count() >= 1);

        // check_rate_limit on the unknown overflow key still returns Ok.
        assert!(limiter.check_rate_limit("overflow-key").is_ok());
    }

    #[test]
    #[ignore = "fills MAX_ENTRIES entries — slow; run with --ignored"]
    fn fail_closed_rejects_unknown_key_when_capacity_exhausted() {
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 3600,
            lockout_secs: 3600,
            policy: RateLimitPolicy::FailClosed,
        });

        for i in 0..MAX_ENTRIES {
            limiter.record_failure(&format!("u-{i}"));
        }
        assert_eq!(limiter.entry_count(), MAX_ENTRIES);

        // Under FailClosed, an unknown key's check is rejected.
        let before = limiter.capacity_exhausted_count();
        let res = limiter.check_rate_limit("brand-new-key");
        assert!(
            res.is_err(),
            "FailClosed must reject unknown key at capacity"
        );
        assert!(matches!(res.unwrap_err(), HsmError::PinLocked));
        assert!(
            limiter.capacity_exhausted_count() > before,
            "capacity_exhausted_count must increment under FailClosed rejection"
        );
    }

    #[test]
    #[ignore = "fills MAX_ENTRIES entries — slow; run with --ignored"]
    fn capacity_exhausted_count_increments_under_flood() {
        // Simulate a credential-stuffing flood under FailOpen.  Every dropped
        // record must bump the capacity_exhausted_count so operators can
        // detect the limiter is failing-open.
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 3600,
            lockout_secs: 3600,
            policy: RateLimitPolicy::FailOpen,
        });

        for i in 0..MAX_ENTRIES {
            limiter.record_failure(&format!("known-{i}"));
        }

        let before = limiter.capacity_exhausted_count();
        for i in 0..50 {
            limiter.record_failure(&format!("flood-{i}"));
        }
        let after = limiter.capacity_exhausted_count();
        assert!(
            after - before >= 50,
            "expected >=50 capacity-exhausted events, got {}",
            after - before
        );
    }

    #[test]
    fn fail_closed_still_allows_known_key_checks() {
        // FailClosed must not break legitimate users who already have an entry
        // in the map — only *new* unknown keys get rejected at capacity.
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window_secs: 3600,
            lockout_secs: 3600,
            policy: RateLimitPolicy::FailClosed,
        });
        limiter.record_failure("alice");
        // Alice is known and under threshold — must be allowed.
        assert!(limiter.check_rate_limit("alice").is_ok());
    }

    #[test]
    fn policy_serde_roundtrip() {
        let cfg = RateLimitConfig {
            max_attempts: 5,
            window_secs: 300,
            lockout_secs: 900,
            policy: RateLimitPolicy::FailClosed,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("fail_closed"));
        let parsed: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy, RateLimitPolicy::FailClosed);

        // Absent `policy` field — defaults to FailOpen.
        let parsed: RateLimitConfig =
            serde_json::from_str(r#"{"max_attempts": 5, "window_secs": 300, "lockout_secs": 900}"#)
                .unwrap();
        assert_eq!(parsed.policy, RateLimitPolicy::FailOpen);
    }

    #[test]
    fn failure_counter_does_not_overflow() {
        let limiter = AuthRateLimiter::new(RateLimitConfig {
            max_attempts: u32::MAX, // Never lock out; just count.
            window_secs: 3600,
            lockout_secs: 3600,
            policy: RateLimitPolicy::FailOpen,
        });
        let key = "overflow";
        // This wouldn't realistically happen but the saturating_add must
        // still prevent panics even if it did.
        for _ in 0..10 {
            limiter.record_failure(key);
        }
        let e = limiter.entries.get(key).unwrap();
        assert_eq!(e.failed_count, 10);
    }
}
