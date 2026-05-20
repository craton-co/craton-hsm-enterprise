// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Multi-Factor Authentication (MFA) gate for sensitive operations.
//!
//! The policy engine can require MFA before certain operations (e.g.,
//! key destruction, key export). This module manages MFA challenges.
//!
//! # TOTP hash algorithm selection
//!
//! [`TotpHashAlgorithm`] defaults to `Sha1` because RFC 6238 specifies
//! HMAC-SHA-1 as the baseline and almost every authenticator app
//! (Google Authenticator, Authy, 1Password, …) supports it. Use `Sha1`
//! when you need broad client compatibility.
//!
//! For new internal deployments where you control the authenticator,
//! prefer `Sha256`. SHA-256 has no known practical attacks against
//! HMAC-SHA-1 used in TOTP, but it removes a long-deprecated primitive
//! from your security surface and aligns with FIPS 180-4 guidance.
//!
//! # Constant-time verification
//!
//! [`MfaManager::verify`] uses [`subtle::ConstantTimeEq`] for code
//! comparison and a constant-time loop over the accepted time-step
//! window so that neither the response value nor the matched step
//! leak via timing.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use craton_hsm::error::{HsmError, HsmResult};
use zeroize::Zeroizing;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256Totp = Hmac<sha2::Sha256>;

/// Hash algorithm for TOTP code generation.
///
/// Deprecation plan for SHA-1:
/// - Today (v1.x):  SHA-1 is the default for broad authenticator-app compatibility.
/// - v2.0:          SHA-256 becomes the default; SHA-1 requires explicit opt-in.
/// - v3.0:          SHA-1 is removed.
///
/// Call sites that register a SHA-1 TOTP secret emit a one-time deprecation
/// `tracing::warn!` so operators can see they are on the deprecated path and
/// plan migration while still being able to use classic authenticator apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TotpHashAlgorithm {
    /// SHA-1 (RFC 6238 default, widely compatible).
    ///
    /// **Deprecated**: prefer [`TotpHashAlgorithm::Sha256`] for new deployments.
    #[default]
    Sha1,
    /// SHA-256 (stronger, recommended for new deployments).
    Sha256,
}

/// Emit a one-time deprecation warning for SHA-1 TOTP configuration.
///
/// Uses a static `AtomicBool` to suppress duplicate warnings when many users
/// register SHA-1 secrets in a row — we don't want to flood operator logs.
fn warn_sha1_deprecated_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if WARNED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        tracing::warn!(
            "TOTP configured with SHA-1: SHA-1 TOTP is deprecated and will become \
             opt-in in v2.0 / removed in v3.0. Migrate new deployments to SHA-256. \
             See the TotpHashAlgorithm docs for the deprecation timeline."
        );
    }
}

// ---------------------------------------------------------------------------
// Base32 decoding (RFC 4648)
// ---------------------------------------------------------------------------

/// Upper bound on accepted base32 input length. TOTP shared secrets are at
/// most 32 bytes (= 64 base32 chars). We allow up to 512 encoded characters
/// as slack for tolerant decoders, which is still too small for DoS and large
/// enough that no well-formed TOTP registration is rejected.
const MAX_BASE32_INPUT: usize = 512;

/// Decode an RFC 4648 base32-encoded string (case-insensitive, no padding
/// required). Returns `None` on invalid input or if `input` exceeds
/// [`MAX_BASE32_INPUT`] characters — this prevents an authenticated operator
/// from exhausting process memory by registering a multi-MiB "secret".
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    if input.len() > MAX_BASE32_INPUT {
        return None;
    }
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);

    for &b in input.as_bytes() {
        if b == b'=' {
            // Padding -- skip
            continue;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None, // invalid character
        };
        buf = (buf << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u64 << bits) - 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238) implementation
// ---------------------------------------------------------------------------

/// Maximum allowed TOTP time-step skew. Values above this are rejected by
/// [`TotpConfig::with_skew`] because a wider window makes replay attacks
/// significantly easier and indicates a likely misconfiguration.
pub const MAX_TOTP_SKEW: u64 = 5;

/// TOTP configuration for a user.
///
/// The base32-encoded secret is decoded *once* on construction and the raw
/// bytes are cached, so each verification only does HMAC work — no repeated
/// base32 parsing on the hot path.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Base32-encoded shared secret (kept for diagnostics / round-tripping).
    pub secret: Zeroizing<String>,
    /// Pre-decoded raw secret bytes (filled in at construction).
    raw_secret: Zeroizing<Vec<u8>>,
    /// Number of digits in the OTP code (default 6).
    pub digits: u32,
    /// Time step period in seconds (default 30).
    pub period: u64,
    /// Number of time-step windows to accept before/after current (default 0
    /// — i.e. only the current 30-second step). Operators whose user base has
    /// noticeable clock drift can raise this via [`TotpConfig::with_skew`];
    /// the cost is a proportionally wider replay window (each additional step
    /// doubles the time a captured code remains usable).
    pub skew: u64,
    /// Hash algorithm used for TOTP computation (default SHA-1).
    pub hash_algorithm: TotpHashAlgorithm,
}

impl TotpConfig {
    /// Create a new `TotpConfig` with the given base32 secret and defaults.
    ///
    /// Returns `None` if the secret is not valid base32.
    pub fn new(secret: impl Into<String>) -> Option<Self> {
        let s: String = secret.into();
        let raw = base32_decode(&s)?;
        Some(Self {
            secret: Zeroizing::new(s),
            raw_secret: Zeroizing::new(raw),
            digits: 6,
            period: 30,
            // Tightened from 1 → 0: accept only the current 30s step so a
            // captured code has at most ~30s replay window (bounded further
            // by the per-step replay cache). Operators can widen this via
            // `with_skew` if their user base has measurable clock drift.
            skew: 0,
            hash_algorithm: TotpHashAlgorithm::default(),
        })
    }

    /// Set the skew (number of time-step windows accepted before/after current).
    ///
    /// Returns `None` if `skew` exceeds [`MAX_TOTP_SKEW`]. A skew > 2 logs a
    /// warning because the replay window becomes unusually wide.
    #[must_use = "with_skew consumes self; drop the return value and the skew change is lost"]
    pub fn with_skew(mut self, skew: u64) -> Option<Self> {
        if skew > MAX_TOTP_SKEW {
            tracing::warn!(
                skew,
                max = MAX_TOTP_SKEW,
                "TOTP skew exceeds maximum allowed value — rejecting configuration"
            );
            return None;
        }
        if skew > 2 {
            tracing::warn!(skew, "TOTP skew > 2: replay window is unusually wide");
        }
        self.skew = skew;
        Some(self)
    }

    /// Pre-decoded secret bytes for fast verification.
    pub(crate) fn raw_secret(&self) -> &[u8] {
        &self.raw_secret
    }
}

/// Generate a TOTP code for the given raw secret bytes and Unix timestamp.
///
/// This is the core HOTP/TOTP algorithm (RFC 4226 / RFC 6238):
///   1. counter = floor(time / period)
///   2. hmac = HMAC-SHA1(secret, counter_be_bytes)
///   3. dynamic truncation -> 31-bit integer
///   4. code = truncated mod 10^digits
///
/// Exposed publicly for testing; callers normally go through [`MfaManager`].
///
/// Returns [`HsmError::GeneralError`] if the underlying HMAC primitive
/// reports an invalid key length. In practice the `hmac` crate accepts
/// any key length for SHA-1 / SHA-256, but the error is propagated for
/// strict-lint compliance (`deny(clippy::expect_used)`).
pub fn generate_totp_code(secret: &[u8], time: u64, period: u64, digits: u32) -> HsmResult<u32> {
    generate_totp_code_with_alg(secret, time, period, digits, TotpHashAlgorithm::Sha1)
}

/// Generate a TOTP code using the specified hash algorithm. See
/// [`generate_totp_code`] for the error contract.
pub fn generate_totp_code_with_alg(
    secret: &[u8],
    time: u64,
    period: u64,
    digits: u32,
    algorithm: TotpHashAlgorithm,
) -> HsmResult<u32> {
    let counter = time / period;
    let counter_bytes = counter.to_be_bytes(); // 8-byte big-endian

    // RFC 4226 §5.4 dynamic truncation, expressed without panicking index
    // ops so the function complies with `deny(clippy::indexing_slicing)`.
    // The HMAC primitives we use produce fixed-size outputs (20 / 32 bytes),
    // so the slice lookups always succeed in practice -- but expressing
    // them via `Option` makes that invariant explicit and ensures a future
    // change (e.g. swapping in a stub HMAC) fails loudly rather than
    // panicking on the auth hot path.
    fn dynamic_truncate(result: &[u8]) -> HsmResult<u32> {
        let last = *result.last().ok_or_else(|| {
            tracing::error!("HMAC output unexpectedly empty during TOTP dynamic truncation");
            HsmError::GeneralError
        })?;
        let offset = (last & 0x0f) as usize;
        let window = result.get(offset..offset + 4).ok_or_else(|| {
            tracing::error!(
                offset,
                len = result.len(),
                "HMAC output too short for TOTP dynamic truncation window"
            );
            HsmError::GeneralError
        })?;
        let b0 = *window.first().ok_or(HsmError::GeneralError)? & 0x7f;
        let b1 = *window.get(1).ok_or(HsmError::GeneralError)?;
        let b2 = *window.get(2).ok_or(HsmError::GeneralError)?;
        let b3 = *window.get(3).ok_or(HsmError::GeneralError)?;
        Ok(u32::from_be_bytes([b0, b1, b2, b3]))
    }

    let code = match algorithm {
        TotpHashAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| HsmError::GeneralError)?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            let code = dynamic_truncate(result.as_slice())?;
            code % 10u32.pow(digits)
        }
        TotpHashAlgorithm::Sha256 => {
            let mut mac =
                HmacSha256Totp::new_from_slice(secret).map_err(|_| HsmError::GeneralError)?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            let code = dynamic_truncate(result.as_slice())?;
            code % 10u32.pow(digits)
        }
    };
    Ok(code)
}

/// Generate TOTP code from a base32-encoded secret. Returns `None` if the
/// secret is not valid base32.
pub fn generate_totp_code_base32(
    base32_secret: &str,
    time: u64,
    period: u64,
    digits: u32,
) -> Option<u32> {
    let raw = base32_decode(base32_secret)?;
    // The underlying HMAC call cannot fail in practice for SHA-1; map any
    // error to `None` so the public signature stays `Option<u32>`.
    generate_totp_code(&raw, time, period, digits).ok()
}

// (The standalone `verify_totp` helper was removed: `MfaManager::verify_totp_response`
// is the only verification path and must additionally track the matched step
// for replay protection, so a bool-returning helper does not fit. The replay
// path now performs the same constant-time loop inline.)

// ---------------------------------------------------------------------------
// MFA types and manager
// ---------------------------------------------------------------------------

/// MFA challenge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaChallengeType {
    /// Time-based One-Time Password (TOTP).
    Totp,
    /// Re-enter PIN to confirm destructive operation.
    ReenterPin,
}

/// A pending MFA challenge.
#[derive(Debug, Clone)]
pub struct MfaChallenge {
    /// Unique challenge identifier — 128 bits of randomness, hex-encoded.
    /// Random IDs (vs. monotonic AtomicU64) prevent an attacker from
    /// predicting valid challenge IDs by observing one and incrementing.
    pub id: String,
    /// Session that must complete this challenge.
    pub session_handle: u64,
    /// User to whom this challenge belongs.
    pub user_id: String,
    /// Type of MFA required.
    pub challenge_type: MfaChallengeType,
    /// When the challenge was issued (Unix seconds — retained for audit
    /// logs only; never used for expiry decisions).
    pub created_at: u64,
    /// When the challenge expires (Unix seconds — retained for audit
    /// logs only; never used for expiry decisions).
    pub expires_at: u64,
    /// Monotonic-clock deadline used for the actual expiry comparison.
    /// Switched away from `SystemTime` so that wall-clock skips (NTP step,
    /// VM pause, manual `date -s`) cannot prematurely expire or extend a
    /// challenge.
    pub expires_at_mono: Instant,
    /// Whether the challenge has been completed.
    pub completed: bool,
    /// For `ReenterPin` challenges: PBKDF2 hash of the expected PIN.
    ///
    /// Audit fix -- crate-private so a downstream caller cannot forge a
    /// `MfaChallenge` with an attacker-chosen hash and feed it back into
    /// internal verification helpers. Tests inside the crate (same module)
    /// can still construct fixtures directly.
    pub(crate) expected_pin_hash: Option<[u8; 32]>,
    /// Random salt for PIN hashing.
    ///
    /// Audit fix -- crate-private; see [`Self::expected_pin_hash`].
    pub(crate) salt: [u8; 16],
    /// Operation tag this challenge authorizes (e.g. "destroy_key:1234"),
    /// or `None` for an untyped session-level challenge.  When set,
    /// `has_completed_challenge_for` will only return true for the same tag.
    pub bound_operation: Option<String>,
}

/// Default PBKDF2 iteration count. Matches OWASP 2023 guidance for
/// PBKDF2-HMAC-SHA256; operators who track newer baselines (SP 800-132 rev
/// or OWASP updates) can override via the `CRATON_HSM_PBKDF2_ITERATIONS`
/// environment variable.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;

/// Minimum PBKDF2 iteration count. Anything below this is refused to keep
/// operator misconfiguration from silently weakening PIN hashing.
pub const MIN_PBKDF2_ITERATIONS: u32 = 100_000;

fn pbkdf2_iterations() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static CACHED: AtomicU32 = AtomicU32::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let value = match std::env::var("CRATON_HSM_PBKDF2_ITERATIONS") {
        Ok(s) => match s.parse::<u32>() {
            Ok(n) if n >= MIN_PBKDF2_ITERATIONS => n,
            Ok(n) => {
                tracing::warn!(
                    requested = n,
                    minimum = MIN_PBKDF2_ITERATIONS,
                    "CRATON_HSM_PBKDF2_ITERATIONS below floor; using default"
                );
                DEFAULT_PBKDF2_ITERATIONS
            }
            Err(_) => {
                tracing::warn!(
                    value = %s,
                    "CRATON_HSM_PBKDF2_ITERATIONS not parseable; using default"
                );
                DEFAULT_PBKDF2_ITERATIONS
            }
        },
        Err(_) => DEFAULT_PBKDF2_ITERATIONS,
    };
    CACHED.store(value, Ordering::Relaxed);
    value
}

/// Hash a PIN using PBKDF2-HMAC-SHA256.
///
/// Iteration count is fetched from `CRATON_HSM_PBKDF2_ITERATIONS` (if set
/// and above `MIN_PBKDF2_ITERATIONS`) or falls back to
/// [`DEFAULT_PBKDF2_ITERATIONS`]. The value is cached at first call so repeat
/// verifications don't pay the env-var lookup cost.
fn hash_pin(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pin, salt, pbkdf2_iterations(), &mut out);
    out
}

/// MFA challenge manager.
pub struct MfaManager {
    /// Active challenges indexed by ID.
    challenges: DashMap<String, MfaChallenge>,
    /// Set of session_handles that currently have at least one completed
    /// (unexpired) challenge.  Lets `has_completed_challenge` answer in O(1)
    /// instead of scanning every challenge in the map.
    completed_sessions: DashMap<u64, ()>,
    /// Index of `(session_handle, operation)` pairs that currently have a
    /// completed (unexpired) challenge with a matching `bound_operation`.
    /// Lets `has_completed_challenge_for` answer in O(1) instead of scanning
    /// every challenge. An entry is only inserted when a challenge actually
    /// carries a `bound_operation`; session-level (blanket) approvals never
    /// touch this map.
    completed_ops: DashMap<(u64, String), ()>,
    /// Challenge timeout in seconds.
    timeout_secs: u64,
    /// Per-user TOTP configurations, keyed by user_id.
    totp_secrets: DashMap<String, TotpConfig>,
    /// Used TOTP time-steps to prevent replay attacks.
    ///
    /// Audit fix 1.5 -- the key is now `(user_id, session_handle, step)`.
    /// Previously a single replay cache per user_id meant a captured
    /// code from session A could not be replayed to session A again, but
    /// also could not be reused legitimately by *session B* in the same
    /// 30-second window. More importantly, an attacker who replayed a
    /// code under a *different* session_handle would be allowed: each
    /// successful verification only marked the step against the user_id,
    /// not the (user, session) pair. Binding the cache key to the
    /// session_handle closes that gap and aligns with the MFA design
    /// intent that an MFA approval authorise exactly one session.
    /// Audit fix 1.5: keyed on `(user_id, step)`. Cross-session replay
    /// rejection is the security-critical property here — RFC 6238 §5.2
    /// requires that a code be accepted at most once per user, ever, so a
    /// TOTP intercepted from one session cannot be replayed in another.
    /// The `session_handle == 0` rejection is enforced separately (see
    /// `verify_totp_response`) so unbound challenges still fail closed.
    used_totp_steps: DashMap<(String, u64), ()>,
    /// Counter of TOTP verifications; triggers full-map pruning every 64 calls.
    totp_verify_count: AtomicU64,
    /// Audit fix 1.6 -- min-heap of (expiry_unix, challenge_id) so
    /// `evict_expired` can pop expired entries in O(log n) instead of
    /// scanning every entry in `challenges`. The heap may contain stale
    /// references to challenges that were already removed (e.g. via
    /// `verify`); the eviction path tolerates that by checking the live
    /// map before deletion.
    expiry_heap: parking_lot::Mutex<BinaryHeap<Reverse<(u64, String)>>>,
}

impl MfaManager {
    /// Create a new MFA manager.
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            challenges: DashMap::new(),
            completed_sessions: DashMap::new(),
            completed_ops: DashMap::new(),
            timeout_secs,
            totp_secrets: DashMap::new(),
            used_totp_steps: DashMap::new(),
            totp_verify_count: AtomicU64::new(0),
            expiry_heap: parking_lot::Mutex::new(BinaryHeap::new()),
        }
    }

    /// Generate a fresh, unguessable challenge ID (128 bits of entropy).
    ///
    /// Uses `OsRng` — the OS-backed CSPRNG — directly rather than the thread-local
    /// reseeding RNG so the cryptographic source is unambiguous across platforms.
    fn generate_id() -> String {
        use rand::rngs::OsRng;
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Register (or update) a TOTP secret for a user.
    ///
    /// `base32_secret` must be a valid RFC 4648 base32 string. Returns an
    /// error if decoding fails.
    pub fn register_totp_secret(&self, user_id: &str, base32_secret: &str) -> HsmResult<()> {
        let cfg = TotpConfig::new(base32_secret).ok_or(HsmError::ArgumentsBad)?;
        if matches!(cfg.hash_algorithm, TotpHashAlgorithm::Sha1) {
            warn_sha1_deprecated_once();
        }
        self.totp_secrets.insert(user_id.to_owned(), cfg);
        Ok(())
    }

    /// Register a TOTP secret with custom configuration.
    pub fn register_totp_config(&self, user_id: &str, config: TotpConfig) -> HsmResult<()> {
        // base32 was validated when TotpConfig was constructed; raw_secret must be present.
        if config.raw_secret().is_empty() {
            return Err(HsmError::ArgumentsBad);
        }
        if matches!(config.hash_algorithm, TotpHashAlgorithm::Sha1) {
            warn_sha1_deprecated_once();
        }
        self.totp_secrets.insert(user_id.to_owned(), config);
        Ok(())
    }

    /// Issue a new MFA challenge for a session.
    ///
    /// For `ReenterPin` challenges, pass the expected PIN in `expected_pin`
    /// so the manager can verify the response later. For `Totp` challenges
    /// the PIN argument is ignored.
    pub fn issue_challenge(
        &self,
        session_handle: u64,
        user_id: &str,
        challenge_type: MfaChallengeType,
        expected_pin: Option<&[u8]>,
    ) -> MfaChallenge {
        self.issue_challenge_for(session_handle, user_id, challenge_type, expected_pin, None)
    }

    /// Issue an MFA challenge bound to a specific operation tag.
    ///
    /// The resulting challenge will only satisfy
    /// [`Self::has_completed_challenge_for`] when called with the same tag,
    /// preventing one MFA approval from authorizing an unrelated destructive
    /// operation later in the session.
    pub fn issue_challenge_for(
        &self,
        session_handle: u64,
        user_id: &str,
        challenge_type: MfaChallengeType,
        expected_pin: Option<&[u8]>,
        bound_operation: Option<&str>,
    ) -> MfaChallenge {
        let id = Self::generate_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut salt = [0u8; 16];
        {
            use rand::rngs::OsRng;
            OsRng.fill_bytes(&mut salt);
        }

        let expected_pin_hash = match challenge_type {
            MfaChallengeType::ReenterPin => expected_pin.map(|p| hash_pin(p, &salt)),
            _ => None,
        };

        let challenge = MfaChallenge {
            id: id.clone(),
            session_handle,
            user_id: user_id.to_owned(),
            challenge_type,
            created_at: now,
            expires_at: now + self.timeout_secs,
            expires_at_mono: Instant::now() + Duration::from_secs(self.timeout_secs),
            completed: false,
            expected_pin_hash,
            salt,
            bound_operation: bound_operation.map(|s| s.to_owned()),
        };

        // Audit fix 1.6: push the (expiry, id) tuple into the min-heap
        // so eviction can find the next-to-expire entry without scanning.
        // Reverse() so BinaryHeap (a max-heap) yields the smallest expiry.
        self.expiry_heap
            .lock()
            .push(Reverse((challenge.expires_at, id.clone())));
        self.challenges.insert(id, challenge.clone());
        challenge
    }

    /// Verify an MFA response. Returns Ok(()) if the challenge is valid
    /// and the response is correct.
    ///
    /// For `Totp` challenges, `response` is the TOTP code as a UTF-8 string
    /// of decimal digits. For `ReenterPin`, `response` is the raw PIN bytes.
    pub fn verify(
        &self,
        challenge_id: &str,
        session_handle: u64,
        response: &[u8],
    ) -> HsmResult<()> {
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or(crate::error::mfa_challenge_invalid())?;

        let challenge = entry.value_mut();

        if challenge.session_handle != session_handle {
            return Err(crate::error::mfa_challenge_invalid());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Audit polish: compare monotonic clocks here so a wall-clock step
        // (NTP / VM pause / `date -s`) cannot prematurely expire or extend
        // a valid challenge. `expires_at` is retained only for audit logs.
        if Instant::now() >= challenge.expires_at_mono {
            drop(entry);
            self.challenges.remove(challenge_id);
            return Err(crate::error::mfa_challenge_invalid());
        }

        // Validate the MFA response based on challenge type.
        match challenge.challenge_type {
            MfaChallengeType::Totp => {
                self.verify_totp_response(challenge, response, now)?;
            }
            MfaChallengeType::ReenterPin => {
                self.verify_pin_response(challenge, response)?;
            }
        }

        challenge.completed = true;
        let session = challenge.session_handle;
        let bound_op = challenge.bound_operation.clone();
        drop(entry);
        // Mark the session as having a completed challenge for O(1) lookups.
        self.completed_sessions.insert(session, ());
        // Also index the bound-operation (if any) so per-operation gating is
        // O(1) instead of scanning every challenge.
        if let Some(op) = bound_op {
            self.completed_ops.insert((session, op), ());
        }
        Ok(())
    }

    /// Verify a TOTP response against the user's registered secret.
    ///
    /// Prevents replay attacks by tracking the accepted time-step per user.
    /// A code that was already accepted within its validity window is rejected.
    fn verify_totp_response(
        &self,
        challenge: &MfaChallenge,
        response: &[u8],
        now: u64,
    ) -> HsmResult<()> {
        // Audit fix 1.5: refuse session-unbound challenges BEFORE we even
        // parse the response. A `session_handle == 0` indicates that
        // somewhere upstream a caller forgot to bind the challenge to
        // a real session — fail closed regardless of code validity.
        if challenge.session_handle == 0 {
            tracing::error!(
                user_id = %challenge.user_id,
                "TOTP verify rejected: challenge has no session_handle bound"
            );
            return Err(HsmError::ArgumentsBad);
        }

        // Parse the response as a UTF-8 decimal string.
        let code_str = std::str::from_utf8(response).map_err(|_| HsmError::SignatureInvalid)?;
        let code: u32 = code_str.parse().map_err(|_| HsmError::SignatureInvalid)?;

        // Look up the user's TOTP config.
        let config = self
            .totp_secrets
            .get(&challenge.user_id)
            .ok_or(crate::error::mfa_challenge_invalid())?;

        // Use the *cached* raw secret — no per-verify base32 decode.
        let raw_secret = config.raw_secret();

        if config.skew > 2 {
            tracing::warn!(
                user_id = %challenge.user_id,
                skew = config.skew,
                "TOTP skew > 2: replay window is unusually wide"
            );
        }

        // Find which time-step the code belongs to.
        //
        // SECURITY: this loop must run for every step in the skew window
        // regardless of where (or whether) a match occurs. An early `break`
        // would leak — via wall-clock timing of the response — *which* step
        // produced the match, which in turn discloses the client's clock
        // offset relative to the server. We use `subtle::ConstantTimeEq`
        // for the per-step comparison and `ConditionallySelectable` to
        // record the matched step without branching on the comparison result.
        // Because TOTP codes do not collide across consecutive time steps for
        // the same secret, at most one step can match in any window, so a
        // single sentinel `matched_step` suffices.
        use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

        let current_step = now / config.period;
        let start = current_step.saturating_sub(config.skew);
        let end = current_step + config.skew;

        let mut matched: Choice = 0u8.into();
        // Sentinel value: end + 1 cannot be a valid matched step inside the
        // loop. After the loop, `matched` tells us whether to trust this.
        let mut matched_step: u64 = end.saturating_add(1);
        for step in start..=end {
            let t = step * config.period;
            let expected = generate_totp_code_with_alg(
                raw_secret,
                t,
                config.period,
                config.digits,
                config.hash_algorithm,
            )?;
            let this_eq: Choice = expected
                .to_be_bytes()
                .as_slice()
                .ct_eq(code.to_be_bytes().as_slice());
            matched_step = u64::conditional_select(&matched_step, &step, this_eq);
            matched |= this_eq;
        }

        if !bool::from(matched) {
            return Err(HsmError::SignatureInvalid);
        }

        let step = matched_step;

        // Audit fix 1.5: replay cache key is `(user, step)` — RFC 6238
        // requires a TOTP code be accepted at most once per user globally
        // (cross-session). The earlier session_handle != 0 guard ensures
        // the challenge that *attempts* the verify is session-bound, but
        // the cache key itself is session-agnostic so an intercepted code
        // cannot be reused from a different session.
        let key = (challenge.user_id.clone(), step);
        use dashmap::mapref::entry::Entry;
        match self.used_totp_steps.entry(key) {
            Entry::Occupied(_) => {
                tracing::warn!(
                    user_id = %challenge.user_id,
                    step,
                    "TOTP replay attack detected: time-step already consumed for this user"
                );
                return Err(HsmError::SignatureInvalid);
            }
            Entry::Vacant(slot) => {
                slot.insert(());
            }
        }
        // Prune entries whose step has fallen outside the acceptance window.
        let prune_cutoff = current_step.saturating_sub(2 * config.skew + 1);
        self.used_totp_steps.retain(|k, _| k.1 >= prune_cutoff);

        // Periodic full-map cleanup: every 64 verifications, sweep all users
        // to remove stale entries from users who stopped authenticating.
        let count = self.totp_verify_count.fetch_add(1, Ordering::Relaxed);
        if count % 64 == 0 {
            self.prune_expired_totp_steps();
        }

        Ok(())
    }

    /// Remove expired TOTP time-steps from all users.
    ///
    /// This can be called externally for periodic maintenance, or it is
    /// triggered automatically every 64 TOTP verifications. For each user,
    /// the method looks up the configured TOTP period and skew to compute
    /// the pruning cutoff. Entries with no remaining steps are removed
    /// from the map entirely.
    pub fn prune_expired_totp_steps(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Audit fix 1.5: the replay cache is keyed by `(user_id, step)`.
        // Compute the per-user cutoff from the registered TotpConfig and
        // drop entries whose step already falls outside the acceptance
        // window. Users without a registered config have all of their
        // entries pruned.
        self.used_totp_steps.retain(|key, _| {
            let cutoff = if let Some(config) = self.totp_secrets.get(&key.0) {
                let current_step = now / config.period;
                current_step.saturating_sub(2 * config.skew + 1)
            } else {
                u64::MAX
            };
            key.1 >= cutoff
        });
    }

    /// Verify a PIN re-entry response.
    fn verify_pin_response(&self, challenge: &MfaChallenge, response: &[u8]) -> HsmResult<()> {
        match challenge.expected_pin_hash {
            Some(expected) => {
                let actual = hash_pin(response, &challenge.salt);
                // Constant-time comparison.
                if subtle::ConstantTimeEq::ct_eq(&expected[..], &actual[..]).into() {
                    Ok(())
                } else {
                    Err(HsmError::PinIncorrect)
                }
            }
            None => {
                // No expected PIN was registered -- reject.
                Err(HsmError::GeneralError)
            }
        }
    }

    /// Check if a session has a completed (unexpired) MFA challenge.
    ///
    /// O(1) average: backed by `completed_sessions`, refreshed by
    /// `evict_expired`.  This used to scan every challenge in the map,
    /// turning every destructive PKCS#11 operation into O(n_challenges).
    pub fn has_completed_challenge(&self, session_handle: u64) -> bool {
        self.evict_expired();
        self.completed_sessions.contains_key(&session_handle)
    }

    /// Check whether a specific operation has been authorized via an
    /// MFA challenge that was bound to this operation tag.
    ///
    /// Use this for high-stakes operations (e.g. key destruction) where a
    /// blanket session-level MFA approval would be too coarse — completing
    /// MFA for "destroy_key:1234" must NOT authorize "export_key:5678".
    pub fn has_completed_challenge_for(&self, session_handle: u64, operation: &str) -> bool {
        self.evict_expired();
        // O(1) index lookup — see `completed_ops` doc-comment.
        self.completed_ops
            .contains_key(&(session_handle, operation.to_string()))
    }

    /// Remove expired challenges and update the `completed_sessions` /
    /// `completed_ops` indices.
    ///
    /// Audit fix 1.6 -- previously this scanned every entry in the
    /// `challenges` DashMap on every call (O(n)), which made every
    /// `has_completed_challenge[_for]` lookup O(n) in the number of live
    /// challenges. The heap of `(expires_at, id)` lets us pop only the
    /// entries that are actually past their deadline.
    fn evict_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect sessions (and per-op pairs) whose challenges are about to
        // be evicted so we can recompute their completion state afterward.
        let mut affected_sessions: Vec<u64> = Vec::new();
        let mut dropped_ops: Vec<(u64, String)> = Vec::new();

        // Pop expired heap entries; each entry may be stale (the challenge
        // was already removed by `verify` cleanup or a prior eviction).
        let mut heap = self.expiry_heap.lock();
        while let Some(Reverse((expiry, id))) = heap.peek().cloned() {
            if expiry > now {
                break;
            }
            heap.pop();
            // Remove the corresponding challenge from the live map only if
            // it has the same expiry the heap saw (defensive: a future
            // refactor could re-issue an id, and we do not want to drop a
            // newer challenge whose expiry is in the future).
            let removed = self.challenges.remove_if(&id, |_, c| c.expires_at <= now);
            if let Some((_, c)) = removed {
                if c.completed {
                    affected_sessions.push(c.session_handle);
                    if let Some(op) = c.bound_operation {
                        dropped_ops.push((c.session_handle, op));
                    }
                }
            }
        }
        drop(heap);
        if affected_sessions.is_empty() && dropped_ops.is_empty() {
            return;
        }
        // For each session that lost a challenge, recheck whether it still
        // has any completed unexpired challenge.
        for session in affected_sessions {
            let still_active = self
                .challenges
                .iter()
                .any(|e| e.session_handle == session && e.completed && e.expires_at > now);
            if !still_active {
                self.completed_sessions.remove(&session);
            }
        }
        // Drop per-op index entries that can no longer be satisfied by any
        // surviving challenge. A fresh challenge for the same (session, op)
        // pair would reinstate the index on completion.
        for (session, op) in dropped_ops {
            let still_active = self.challenges.iter().any(|e| {
                e.session_handle == session
                    && e.completed
                    && e.expires_at > now
                    && e.bound_operation.as_deref() == Some(op.as_str())
            });
            if !still_active {
                self.completed_ops.remove(&(session, op));
            }
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Standalone TOTP verification helper for unit tests.
    ///
    /// Performs the same constant-time loop as `MfaManager::verify_totp_response`
    /// but without the replay-tracking state, making it suitable for testing
    /// the core TOTP algorithm and skew acceptance in isolation.
    fn verify_totp(secret: &[u8], code: u32, time: u64, config: &TotpConfig) -> bool {
        use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

        let current_step = time / config.period;
        let start = current_step.saturating_sub(config.skew);
        let end = current_step + config.skew;

        let mut matched: Choice = 0u8.into();
        let mut _matched_step: u64 = end.saturating_add(1);
        for step in start..=end {
            let t = step * config.period;
            let expected = match generate_totp_code_with_alg(
                secret,
                t,
                config.period,
                config.digits,
                config.hash_algorithm,
            ) {
                Ok(c) => c,
                Err(_) => return false,
            };
            let this_eq: Choice = expected
                .to_be_bytes()
                .as_slice()
                .ct_eq(code.to_be_bytes().as_slice());
            _matched_step = u64::conditional_select(&_matched_step, &step, this_eq);
            matched |= this_eq;
        }

        bool::from(matched)
    }

    // -----------------------------------------------------------------------
    // Base32 decoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_base32_decode_rfc4648_vectors() {
        // RFC 4648 Section 10 test vectors.
        assert_eq!(base32_decode("").unwrap(), b"");
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn test_base32_decode_no_padding() {
        assert_eq!(base32_decode("MY").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
    }

    #[test]
    fn test_base32_decode_lowercase() {
        assert_eq!(base32_decode("mzxw6ytb").unwrap(), b"fooba");
    }

    #[test]
    fn test_base32_decode_invalid() {
        assert!(base32_decode("0189").is_none()); // '0', '1', '8', '9' invalid
    }

    // -----------------------------------------------------------------------
    // TOTP generation -- RFC 6238 Appendix B test vectors (SHA-1)
    // -----------------------------------------------------------------------

    /// The RFC 6238 test secret for SHA-1 is the ASCII string
    /// "12345678901234567890" (20 bytes).
    const RFC6238_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn test_totp_rfc6238_sha1_vectors() {
        // Table 1 of RFC 6238 (SHA-1, 8 digits, 30-second period).
        let vectors: &[(u64, u32)] = &[
            (59, 94287082),
            (1111111109, 07081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];

        for &(time, expected) in vectors {
            let code = generate_totp_code(RFC6238_SECRET, time, 30, 8).unwrap();
            assert_eq!(
                code, expected,
                "TOTP mismatch at time={time}: got {code}, expected {expected}"
            );
        }
    }

    #[test]
    fn test_totp_6_digit_generation() {
        // With 6 digits, the code should be < 1_000_000.
        let code = generate_totp_code(RFC6238_SECRET, 59, 30, 6).unwrap();
        assert!(code < 1_000_000);
    }

    // -----------------------------------------------------------------------
    // generate_totp_code_base32 helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_totp_code_base32() {
        // "12345678901234567890" in base32 is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = generate_totp_code_base32(base32_secret, 59, 30, 8).unwrap();
        assert_eq!(code, 94287082);
    }

    #[test]
    fn test_generate_totp_code_base32_invalid() {
        assert!(generate_totp_code_base32("!!invalid!!", 59, 30, 6).is_none());
    }

    // -----------------------------------------------------------------------
    // Time window / skew verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_skew_acceptance() {
        let config = TotpConfig {
            secret: Zeroizing::new(String::new()), // not used by verify_totp directly
            raw_secret: Zeroizing::new(Vec::new()),
            digits: 8,
            period: 30,
            skew: 1,
            hash_algorithm: TotpHashAlgorithm::default(),
        };

        // At time=59, counter=1. With skew=1 we also accept counter 0 and 2.
        let code_at_0 = generate_totp_code(RFC6238_SECRET, 0, 30, 8).unwrap();
        let code_at_59 = generate_totp_code(RFC6238_SECRET, 59, 30, 8).unwrap();
        let code_at_60 = generate_totp_code(RFC6238_SECRET, 60, 30, 8).unwrap();

        // Code generated at counter=0 should be accepted at time=59 (counter=1, skew=1).
        assert!(verify_totp(RFC6238_SECRET, code_at_0, 59, &config));
        // Code for the current window.
        assert!(verify_totp(RFC6238_SECRET, code_at_59, 59, &config));
        // Code for the next window (counter=2).
        assert!(verify_totp(RFC6238_SECRET, code_at_60, 59, &config));
    }

    #[test]
    fn test_totp_skew_rejection() {
        let config = TotpConfig {
            secret: Zeroizing::new(String::new()),
            raw_secret: Zeroizing::new(Vec::new()),
            digits: 8,
            period: 30,
            skew: 0, // no skew -- only the exact window
            hash_algorithm: TotpHashAlgorithm::default(),
        };

        // Code from a different window should be rejected with skew=0.
        let code_at_0 = generate_totp_code(RFC6238_SECRET, 0, 30, 8).unwrap();
        // At time=60, counter=2. Code from counter=0 is two steps away.
        assert!(!verify_totp(RFC6238_SECRET, code_at_0, 60, &config));
    }

    // -----------------------------------------------------------------------
    // MfaManager integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_verify_correct_code() {
        let mgr = MfaManager::new(300);
        let user = "alice";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        mgr.register_totp_secret(user, base32_secret).unwrap();

        let challenge = mgr.issue_challenge(42, user, MfaChallengeType::Totp, None);

        // Generate a valid code for the current time.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = generate_totp_code_base32(base32_secret, now, 30, 6).unwrap();
        let code_str = format!("{:06}", code);

        assert!(mgr.verify(&challenge.id, 42, code_str.as_bytes()).is_ok());
    }

    #[test]
    fn test_totp_verify_wrong_code() {
        let mgr = MfaManager::new(300);
        let user = "bob";
        mgr.register_totp_secret(user, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap();

        let challenge = mgr.issue_challenge(42, user, MfaChallengeType::Totp, None);
        // Provide an obviously wrong code.
        let result = mgr.verify(&challenge.id, 42, b"000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_verify_no_secret_registered() {
        let mgr = MfaManager::new(300);
        let challenge = mgr.issue_challenge(42, "unknown_user", MfaChallengeType::Totp, None);
        let result = mgr.verify(&challenge.id, 42, b"123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_reenter_pin_correct() {
        let mgr = MfaManager::new(300);
        let pin = b"my-secret-pin";
        let challenge = mgr.issue_challenge(
            42,
            "carol",
            MfaChallengeType::ReenterPin,
            Some(pin.as_slice()),
        );

        assert!(mgr.verify(&challenge.id, 42, pin).is_ok());
    }

    #[test]
    fn test_reenter_pin_wrong() {
        let mgr = MfaManager::new(300);
        let pin = b"correct-pin";
        let challenge = mgr.issue_challenge(
            42,
            "dave",
            MfaChallengeType::ReenterPin,
            Some(pin.as_slice()),
        );

        let result = mgr.verify(&challenge.id, 42, b"wrong-pin");
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_wrong_session() {
        let mgr = MfaManager::new(300);
        mgr.register_totp_secret("eve", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap();
        let challenge = mgr.issue_challenge(42, "eve", MfaChallengeType::Totp, None);

        // Different session handle should fail.
        let result = mgr.verify(&challenge.id, 99, b"123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_expired() {
        let mgr = MfaManager::new(0); // 0 second timeout = immediately expired

        mgr.register_totp_secret("frank", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap();
        let challenge = mgr.issue_challenge(42, "frank", MfaChallengeType::Totp, None);

        // The challenge expires immediately (expires_at == created_at + 0).
        // SystemTime::now() >= expires_at, so it should be rejected.
        let result = mgr.verify(&challenge.id, 42, b"123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_not_found() {
        let mgr = MfaManager::new(300);
        let result = mgr.verify("nonexistent-id", 42, b"123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_register_invalid_base32() {
        let mgr = MfaManager::new(300);
        let result = mgr.register_totp_secret("test", "!!invalid!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_has_completed_challenge() {
        let mgr = MfaManager::new(300);
        let pin = b"pin123";
        let challenge = mgr.issue_challenge(
            42,
            "grace",
            MfaChallengeType::ReenterPin,
            Some(pin.as_slice()),
        );

        assert!(!mgr.has_completed_challenge(42));
        mgr.verify(&challenge.id, 42, pin).unwrap();
        assert!(mgr.has_completed_challenge(42));
    }

    // ------------------------------------------------------------------
    // Per-operation MFA index (was O(n) scan, now O(1) DashMap lookup)
    // ------------------------------------------------------------------

    #[test]
    fn per_op_index_populated_on_verify() {
        let mgr = MfaManager::new(300);
        let pin = b"pin-op";
        let ch = mgr.issue_challenge_for(
            7,
            "grace",
            MfaChallengeType::ReenterPin,
            Some(pin),
            Some("destroy_key:1"),
        );
        assert!(!mgr.has_completed_challenge_for(7, "destroy_key:1"));
        mgr.verify(&ch.id, 7, pin).unwrap();
        assert!(mgr.has_completed_challenge_for(7, "destroy_key:1"));
        // Distinct operation tag on the same session is NOT authorised.
        assert!(!mgr.has_completed_challenge_for(7, "export_key:1"));
    }

    #[test]
    fn per_op_index_isolates_sessions() {
        let mgr = MfaManager::new(300);
        let pin = b"pin-iso";
        let ch = mgr.issue_challenge_for(
            1,
            "grace",
            MfaChallengeType::ReenterPin,
            Some(pin),
            Some("destroy_key:1"),
        );
        mgr.verify(&ch.id, 1, pin).unwrap();
        // A different session_handle must not inherit the approval.
        assert!(!mgr.has_completed_challenge_for(2, "destroy_key:1"));
    }

    #[test]
    fn test_totp_verify_constant_time() {
        // Verify that the constant-time comparison still produces correct results.
        // verify_totp uses an externally-supplied raw secret, so the config's
        // own raw_secret field is unused in this test path.
        let config = TotpConfig {
            secret: Zeroizing::new(String::new()),
            raw_secret: Zeroizing::new(Vec::new()),
            digits: 8,
            period: 30,
            skew: 1,
            hash_algorithm: TotpHashAlgorithm::default(),
        };
        let code = generate_totp_code(RFC6238_SECRET, 59, 30, 8).unwrap();
        assert!(verify_totp(RFC6238_SECRET, code, 59, &config));
        // Wrong code should fail.
        assert!(!verify_totp(RFC6238_SECRET, code + 1, 59, &config));
    }

    /// Audit fix 1.5 -- the replay cache is now keyed by
    /// `(user_id, session_handle, step)`, so a captured code replayed
    /// against the SAME session must be rejected. (Cross-session replay
    /// is gated by the auth-rate-limit + the session establishment path,
    /// not by this cache.)
    #[test]
    fn test_totp_replay_rejected_same_session() {
        let mgr = MfaManager::new(300);
        let user = "replay-user";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        mgr.register_totp_secret(user, base32_secret).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = generate_totp_code_base32(base32_secret, now, 30, 6).unwrap();
        let code_str = format!("{:06}", code);

        // First use within session 11: accepted.
        let challenge1 = mgr.issue_challenge(11, user, MfaChallengeType::Totp, None);
        assert!(mgr.verify(&challenge1.id, 11, code_str.as_bytes()).is_ok());

        // Second use of the same code, SAME session 11: rejected as replay.
        let challenge2 = mgr.issue_challenge(11, user, MfaChallengeType::Totp, None);
        let result = mgr.verify(&challenge2.id, 11, code_str.as_bytes());
        assert!(result.is_err(), "same-session replay must be rejected");
    }

    #[test]
    fn test_pin_hash_uses_pbkdf2() {
        // PBKDF2 should be noticeably slower than a single SHA-256.
        let start = std::time::Instant::now();
        let _ = hash_pin(b"test-pin", &[0u8; 16]);
        let elapsed = start.elapsed();
        // On any modern machine PBKDF2 at 600k iterations should take > 50ms.
        // If this fails, hash_pin is not using PBKDF2.
        assert!(
            elapsed.as_millis() >= 10,
            "hash_pin finished in only {}ms — PBKDF2 may not be in use",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_register_totp_config_custom() {
        let mgr = MfaManager::new(300);
        let mut config = TotpConfig::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        config.digits = 8;
        config.period = 60;
        config.skew = 2;
        mgr.register_totp_config("user1", config).unwrap();

        // Verify it was stored correctly by issuing and verifying a challenge.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code =
            generate_totp_code_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now, 60, 8).unwrap();
        let code_str = format!("{:08}", code);

        let challenge = mgr.issue_challenge(10, "user1", MfaChallengeType::Totp, None);
        assert!(mgr.verify(&challenge.id, 10, code_str.as_bytes()).is_ok());
    }

    // -----------------------------------------------------------------------
    // SHA-256 TOTP tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_sha256_generates_6_digit_code() {
        let secret = b"12345678901234567890123456789012"; // 32-byte secret
        let code =
            generate_totp_code_with_alg(secret, 59, 30, 6, TotpHashAlgorithm::Sha256).unwrap();
        assert!(
            code < 1_000_000,
            "SHA-256 TOTP should produce a 6-digit code, got {code}"
        );
    }

    #[test]
    fn test_totp_sha256_differs_from_sha1() {
        let secret = b"12345678901234567890";
        let sha1_code =
            generate_totp_code_with_alg(secret, 59, 30, 8, TotpHashAlgorithm::Sha1).unwrap();
        let sha256_code =
            generate_totp_code_with_alg(secret, 59, 30, 8, TotpHashAlgorithm::Sha256).unwrap();
        // The two algorithms should (almost certainly) produce different codes.
        assert_ne!(
            sha1_code, sha256_code,
            "SHA-1 and SHA-256 produced the same code"
        );
    }

    #[test]
    fn test_totp_sha256_verify_via_manager() {
        let mgr = MfaManager::new(300);
        let user = "sha256-user";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        let mut config = TotpConfig::new(base32_secret).unwrap();
        config.hash_algorithm = TotpHashAlgorithm::Sha256;
        mgr.register_totp_config(user, config).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let raw = base32_decode(base32_secret).unwrap();
        let code =
            generate_totp_code_with_alg(&raw, now, 30, 6, TotpHashAlgorithm::Sha256).unwrap();
        let code_str = format!("{:06}", code);

        let challenge = mgr.issue_challenge(50, user, MfaChallengeType::Totp, None);
        assert!(mgr.verify(&challenge.id, 50, code_str.as_bytes()).is_ok());
    }

    // -----------------------------------------------------------------------
    // TOTP step pruning tests (M4)
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_old_steps_are_pruned_after_verify() {
        let mgr = MfaManager::new(300);
        let user = "prune-user";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let raw = base32_decode(base32_secret).unwrap();

        // Register with default skew (0), period=30.
        let config = TotpConfig::new(base32_secret).unwrap();
        mgr.register_totp_config(user, config).unwrap();

        // Manually insert old steps that should be pruned.
        // With skew=0, period=30, current_step = now/30.
        // Cutoff = current_step - 2*0 - 1 = current_step - 1, so any step
        // older than current_step-1 must be pruned.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_step = now / 30;
        let session = 99u64;
        // Audit fix 1.5: replay cache key is `(user, step)` (cross-session).
        // Insert steps that are well outside the pruning window.
        mgr.used_totp_steps
            .insert((user.to_owned(), current_step.saturating_sub(100)), ());
        mgr.used_totp_steps
            .insert((user.to_owned(), current_step.saturating_sub(50)), ());
        mgr.used_totp_steps
            .insert((user.to_owned(), current_step.saturating_sub(10)), ());

        // Verify a valid TOTP code (which triggers per-user pruning).
        let code = generate_totp_code(&raw, now, 30, 6).unwrap();
        let code_str = format!("{:06}", code);
        let challenge = mgr.issue_challenge(session, user, MfaChallengeType::Totp, None);
        mgr.verify(&challenge.id, session, code_str.as_bytes())
            .unwrap();

        // After verification, old steps should be gone.
        for old in [100u64, 50, 10] {
            assert!(
                !mgr.used_totp_steps
                    .contains_key(&(user.to_owned(), current_step.saturating_sub(old))),
                "Step from {} windows ago should be pruned",
                old
            );
        }
        // The current step should still be present.
        assert!(
            mgr.used_totp_steps
                .contains_key(&(user.to_owned(), current_step)),
            "Current step should remain"
        );
    }

    #[test]
    fn test_prune_expired_totp_steps_external() {
        let mgr = MfaManager::new(300);
        let user = "ext-prune-user";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        mgr.register_totp_secret(user, base32_secret).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_step = now / 30;
        let _session = 1u64;

        // Insert only very old steps (audit fix 1.5: keyed `(user, step)`).
        mgr.used_totp_steps
            .insert((user.to_owned(), current_step.saturating_sub(1000)), ());
        mgr.used_totp_steps
            .insert((user.to_owned(), current_step.saturating_sub(500)), ());

        // Call the public maintenance method.
        mgr.prune_expired_totp_steps();

        // All entries for this user must be gone -- no key with the user_id
        // prefix should remain.
        let any_left = mgr.used_totp_steps.iter().any(|kv| kv.key().0 == user);
        assert!(
            !any_left,
            "User entry with only expired steps should be removed entirely"
        );
    }

    #[test]
    fn test_prune_removes_entries_for_deregistered_users() {
        let mgr = MfaManager::new(300);
        let user = "gone-user";

        // Insert steps without registering a TOTP secret
        // (audit fix 1.5: keyed `(user, step)`).
        mgr.used_totp_steps.insert((user.to_owned(), 42), ());
        mgr.used_totp_steps.insert((user.to_owned(), 43), ());

        mgr.prune_expired_totp_steps();

        // Without a TOTP config, all steps should be pruned.
        let any_left = mgr.used_totp_steps.iter().any(|kv| kv.key().0 == user);
        assert!(
            !any_left,
            "Steps for user without TOTP config should be removed"
        );
    }

    // -----------------------------------------------------------------------
    // TotpConfig::with_skew and MAX_TOTP_SKEW tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_with_skew_within_bounds() {
        let config = TotpConfig::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .with_skew(2)
            .expect("skew=2 should be accepted");
        assert_eq!(config.skew, 2);
    }

    #[test]
    fn test_with_skew_at_max() {
        let config = TotpConfig::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .with_skew(MAX_TOTP_SKEW)
            .expect("skew at MAX_TOTP_SKEW should be accepted");
        assert_eq!(config.skew, MAX_TOTP_SKEW);
    }

    #[test]
    fn test_with_skew_exceeds_max_rejected() {
        let result = TotpConfig::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .with_skew(MAX_TOTP_SKEW + 1);
        assert!(result.is_none(), "skew > MAX_TOTP_SKEW should be rejected");
    }

    #[test]
    fn test_with_skew_zero() {
        let config = TotpConfig::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .with_skew(0)
            .expect("skew=0 should be accepted");
        assert_eq!(config.skew, 0);
    }

    // -----------------------------------------------------------------------
    // Operation-binding tests (issue_challenge_for / has_completed_challenge_for)
    //
    // These tests verify that a completed MFA challenge authorizes only the
    // specific operation tag it was issued for, so one approval cannot
    // silently cover an unrelated destructive operation later in the session.
    // -----------------------------------------------------------------------

    /// Completing a bound challenge authorises the matching op tag, and only
    /// that tag.  A different tag must be rejected.
    #[test]
    fn test_bound_challenge_authorizes_only_matching_tag() {
        let mgr = MfaManager::new(300);
        let pin = b"opbind-pin";
        let challenge = mgr.issue_challenge_for(
            77,
            "user-bind",
            MfaChallengeType::ReenterPin,
            Some(pin.as_slice()),
            Some("destroy_key:1234"),
        );
        assert_eq!(
            challenge.bound_operation.as_deref(),
            Some("destroy_key:1234")
        );

        // Before completing the challenge, neither tag is authorised.
        assert!(!mgr.has_completed_challenge_for(77, "destroy_key:1234"));
        assert!(!mgr.has_completed_challenge_for(77, "export_key:5678"));

        mgr.verify(&challenge.id, 77, pin).expect("pin must verify");

        // After completion, the matching tag is authorised; the other is not.
        assert!(
            mgr.has_completed_challenge_for(77, "destroy_key:1234"),
            "completed bound challenge must authorise its own tag"
        );
        assert!(
            !mgr.has_completed_challenge_for(77, "export_key:5678"),
            "completed bound challenge must NOT authorise a different tag"
        );
    }

    /// An unbound challenge (bound_operation = None) must NOT be treated as a
    /// blanket approval by `has_completed_challenge_for`: the bound-for API
    /// only matches challenges that were explicitly bound to that tag.
    /// Blanket session-level approval is surfaced through
    /// `has_completed_challenge`.
    #[test]
    fn test_unbound_challenge_not_accepted_by_bound_for_lookup() {
        let mgr = MfaManager::new(300);
        let pin = b"unbound-pin";
        let challenge =
            mgr.issue_challenge(88, "user-unbound", MfaChallengeType::ReenterPin, Some(pin));
        assert!(challenge.bound_operation.is_none());

        mgr.verify(&challenge.id, 88, pin).expect("pin must verify");

        // Blanket lookup: must succeed.
        assert!(mgr.has_completed_challenge(88));
        // Bound-specific lookup for any tag must NOT succeed — an unbound
        // approval must not silently satisfy a bound operation check, as that
        // would re-open the escalation gap the bound_operation tag is meant
        // to close.
        assert!(
            !mgr.has_completed_challenge_for(88, "any_operation"),
            "unbound challenge must not satisfy bound-for lookup"
        );
        assert!(
            !mgr.has_completed_challenge_for(88, "other"),
            "unbound challenge must not satisfy bound-for lookup for any tag"
        );
    }

    /// Two challenges issued against the same session with different bound
    /// tags must be tracked independently: completing one does not authorise
    /// the other.
    #[test]
    fn test_two_bound_challenges_tracked_independently() {
        let mgr = MfaManager::new(300);
        let pin_a = b"pin-aaaa";
        let pin_b = b"pin-bbbb";
        let ch_a = mgr.issue_challenge_for(
            55,
            "user-two",
            MfaChallengeType::ReenterPin,
            Some(pin_a),
            Some("op_a"),
        );
        let ch_b = mgr.issue_challenge_for(
            55,
            "user-two",
            MfaChallengeType::ReenterPin,
            Some(pin_b),
            Some("op_b"),
        );
        assert_ne!(ch_a.id, ch_b.id, "challenges must have distinct ids");

        // Complete only op_a.
        mgr.verify(&ch_a.id, 55, pin_a).unwrap();
        assert!(mgr.has_completed_challenge_for(55, "op_a"));
        assert!(!mgr.has_completed_challenge_for(55, "op_b"));

        // Now complete op_b.
        mgr.verify(&ch_b.id, 55, pin_b).unwrap();
        assert!(mgr.has_completed_challenge_for(55, "op_a"));
        assert!(mgr.has_completed_challenge_for(55, "op_b"));
        // A third, never-issued tag must still be unauthorised.
        assert!(!mgr.has_completed_challenge_for(55, "op_c"));
    }

    // ------------------------------------------------------------------
    // Audit fix 1.5 + 1.6 regression tests
    // ------------------------------------------------------------------

    /// Audit fix 1.5 — a TOTP code accepted in session A is **rejected**
    /// on replay in session B because the replay cache is keyed by
    /// `(user, step)`, matching RFC 6238 §5.2 (each code accepted at most
    /// once per user globally). An intercepted code therefore cannot be
    /// replayed from a phisher's session.
    #[test]
    fn totp_replay_rejected_across_sessions() {
        let mgr = MfaManager::new(300);
        let user = "cross-sess";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        mgr.register_totp_secret(user, base32_secret).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = generate_totp_code_base32(base32_secret, now, 30, 6).unwrap();
        let code_str = format!("{:06}", code);

        // Session A consumes the code.
        let ch_a = mgr.issue_challenge(101, user, MfaChallengeType::Totp, None);
        assert!(mgr.verify(&ch_a.id, 101, code_str.as_bytes()).is_ok());

        // Session B with the SAME code in the same window MUST be rejected.
        let ch_b = mgr.issue_challenge(202, user, MfaChallengeType::Totp, None);
        assert!(mgr.verify(&ch_b.id, 202, code_str.as_bytes()).is_err());
    }

    /// Audit fix 1.5 -- the verify path requires `session_handle != 0`.
    /// Constructing a challenge with `session_handle = 0` directly and
    /// feeding it into the internal verify path must be rejected.
    #[test]
    fn totp_session_binding_rejects_zero_handle() {
        let mgr = MfaManager::new(300);
        let user = "zero-sess";
        let base32_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        mgr.register_totp_secret(user, base32_secret).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Hand-craft a challenge with session_handle = 0 (bypassing the
        // public issuer which always sets a real handle).
        let bogus = MfaChallenge {
            id: "x".to_string(),
            session_handle: 0,
            user_id: user.to_string(),
            challenge_type: MfaChallengeType::Totp,
            created_at: now,
            expires_at: now + 60,
            expires_at_mono: Instant::now() + Duration::from_secs(60),
            completed: false,
            expected_pin_hash: None,
            salt: [0u8; 16],
            bound_operation: None,
        };
        let res = mgr.verify_totp_response(&bogus, b"000000", now);
        assert!(matches!(res, Err(HsmError::ArgumentsBad)));
    }

    /// Audit fix 1.6 -- evict_expired only removes entries whose
    /// `expires_at <= now`. A challenge that is still in its window must
    /// survive an eviction sweep, while expired challenges must be gone.
    #[test]
    fn evict_expired_keeps_live_drops_expired() {
        // Use a 1-second timeout so we can age past it without sleeping
        // forever. The pin verifier path is fine because we never call
        // verify().
        let mgr = MfaManager::new(1);
        let pin = b"hp1";
        // Challenge 1: will expire (timeout=1).
        let ch_old = mgr.issue_challenge(900, "u", MfaChallengeType::ReenterPin, Some(pin));
        // Manually rewind expires_at into the past for a deterministic test.
        {
            let mut e = mgr.challenges.get_mut(&ch_old.id).unwrap();
            e.expires_at = 1; // far in the past
            mgr.expiry_heap.lock().push(Reverse((1, ch_old.id.clone())));
        }
        // Challenge 2: still live (timeout=1 but pushed with current time).
        let ch_live = mgr.issue_challenge(901, "u", MfaChallengeType::ReenterPin, Some(pin));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        {
            let mut e = mgr.challenges.get_mut(&ch_live.id).unwrap();
            e.expires_at = now + 600;
            mgr.expiry_heap
                .lock()
                .push(Reverse((now + 600, ch_live.id.clone())));
        }

        mgr.evict_expired();

        assert!(
            mgr.challenges.get(&ch_old.id).is_none(),
            "expired challenge must be evicted"
        );
        assert!(
            mgr.challenges.get(&ch_live.id).is_some(),
            "live challenge must survive eviction"
        );
    }
}
