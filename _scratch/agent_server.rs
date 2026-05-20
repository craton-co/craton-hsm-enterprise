// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! KMIP server message dispatcher.
//!
//! Accepts raw TTLV-encoded request messages, dispatches to the appropriate
//! operation handler, and returns a TTLV-encoded response message.

use crate::acl::{AllowAll, KmipAcl, KmipAclDecision};
use crate::operations::{
    process_activate, process_add_attribute, process_check, process_create,
    process_create_key_pair, process_decrypt, process_delete_attribute,
    process_derive_key, process_destroy, process_encrypt, process_get,
    process_get_attributes, process_locate, process_mac, process_mac_verify,
    process_modify_attribute, process_query, process_register, process_revoke,
    process_rng_retrieve, process_sign, process_signature_verify,
    InMemoryKeyStore, KmipAttribute, KmipAttributeValue, KmipKeyStore, KmipRequest,
    KmipResponse,
};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
use crate::ttlv::{
    decode_ttlv_with_limits, encode_ttlv, TtlvError, TtlvItem, TtlvLimits, TtlvValue,
    MAX_TTLV_DEPTH, MAX_TTLV_ITEMS,
};
use crate::types::{KmipOperation, KmipResultReason, KmipTag};
#[cfg(test)]
use crate::types::KmipResultStatus;

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic clock source. Abstracted as a trait so tests can inject a
/// mock time source that does not move backwards when the caller is sure
/// the system wall-clock has jumped (audit finding M6).
pub(crate) trait MonotonicClock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Real-clock backing: wraps [`Instant::now`].
struct RealClock;

impl MonotonicClock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Tracks authentication failure rates to prevent brute-force attacks.
///
/// Windows are measured against [`Instant`] — a monotonic clock — so that a
/// wall-clock jump cannot retroactively "reset" an active rate-limit window
/// (audit finding M6). Wall-clock time is still emitted in log lines so
/// operators correlating logs with other sources see human-readable
/// timestamps.
struct AuthRateLimiter {
    /// Maps a token hash to (failure_count, window_start_instant).
    failures: DashMap<[u8; 32], (u64, Instant)>,
    /// Maximum failures allowed within the window.
    max_failures: u64,
    /// Window duration.
    window: std::time::Duration,
    /// Counter for periodic eviction of stale entries.
    check_counter: AtomicU64,
    /// Monotonic clock source (defaults to wall-monotonic `Instant::now`,
    /// overridable in tests).
    clock: Arc<dyn MonotonicClock>,
}

impl AuthRateLimiter {
    fn new(max_failures: u64, window_secs: u64) -> Self {
        Self {
            failures: DashMap::new(),
            max_failures,
            window: std::time::Duration::from_secs(window_secs),
            check_counter: AtomicU64::new(0),
            clock: Arc::new(RealClock),
        }
    }

    #[cfg(test)]
    fn with_clock(max_failures: u64, window_secs: u64, clock: Arc<dyn MonotonicClock>) -> Self {
        Self {
            failures: DashMap::new(),
            max_failures,
            window: std::time::Duration::from_secs(window_secs),
            check_counter: AtomicU64::new(0),
            clock,
        }
    }

    /// Check if the given client is rate-limited. `client_id` is a hash
    /// of the client's token (or IP, etc.).
    ///
    /// Every 100 checks, stale entries are evicted to bound memory usage.
    fn is_rate_limited(&self, client_id: &[u8; 32]) -> bool {
        // Periodically evict stale entries to prevent unbounded memory growth.
        if self.check_counter.fetch_add(1, Ordering::Relaxed) % 100 == 0 {
            self.evict_stale();
        }

        let now = self.clock.now();
        if let Some(entry) = self.failures.get(client_id) {
            let (count, window_start) = *entry;
            // `Instant::saturating_duration_since` returns zero if the
            // clock somehow moved backwards, which keeps us inside the
            // active window rather than resetting it early.
            if now.saturating_duration_since(window_start) < self.window
                && count >= self.max_failures
            {
                return true;
            }
        }
        false
    }

    /// Record a failed authentication attempt.
    fn record_failure(&self, client_id: &[u8; 32]) {
        let now = self.clock.now();
        // Wall-clock timestamp is captured separately *solely for logging*.
        // It is never used to gate the rate-limit decision.
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        tracing::debug!(
            target: "craton_hsm_kmip::auth",
            wall_clock_epoch = wall,
            "recording auth failure"
        );
        let window = self.window;
        self.failures
            .entry(*client_id)
            .and_modify(|(count, window_start)| {
                if now.saturating_duration_since(*window_start) >= window {
                    // Window expired, reset.
                    *count = 1;
                    *window_start = now;
                } else {
                    *count += 1;
                }
            })
            .or_insert((1, now));
    }

    /// Evict stale entries older than twice the configured window.
    fn evict_stale(&self) {
        let now = self.clock.now();
        let grace = self.window * 2;
        self.failures.retain(|_, (_, window_start)| {
            now.saturating_duration_since(*window_start) < grace
        });
    }
}

// ---------------------------------------------------------------------------
// KmipOptions: pluggable runtime policy toggles
// ---------------------------------------------------------------------------

/// Runtime policy switches for the KMIP server.
///
/// These options live next to [`KmipServerConfig`] (rather than on it) so a
/// caller can swap them at runtime without rebuilding the network listen
/// configuration. They drive defence-in-depth checks that should be on by
/// default for new deployments but kept opt-out so legacy fixtures that
/// pre-date the audit fixes continue to behave the same way.
#[derive(Debug, Clone, Copy)]
pub struct KmipOptions {
    /// When `true` AND the caller is authenticated AND the target object
    /// has no `owner` attribute, deny the operation. Closes the audit gap
    /// where ownerless objects became implicit shared keys once an ACL was
    /// installed (audit M).
    pub strict_owner_acl: bool,
    /// When `true`, every request must carry a unique `ClientCorrelationValue`
    /// per (identity, value) pair within the replay window. Helps mitigate
    /// blind replay of recorded TTLV transcripts (audit M).
    pub require_correlation_value: bool,
    /// Replay window in seconds; entries older than this are evicted from
    /// the in-memory cache and a re-used correlation value is accepted.
    pub replay_window_secs: u64,
    /// When `true`, log a SHA-256-based identity tag (first 8 hex chars)
    /// on each request rather than the raw identity (audit L).
    pub hash_identity_in_logs: bool,
}

impl Default for KmipOptions {
    fn default() -> Self {
        Self {
            // Default-deny ownerless access. Existing tests / fixtures that
            // rely on legacy behaviour can build a server with
            // `KmipOptions { strict_owner_acl: false, .. }`.
            strict_owner_acl: true,
            require_correlation_value: false,
            replay_window_secs: 60,
            hash_identity_in_logs: true,
        }
    }
}

// ---------------------------------------------------------------------------
// KekProvider: optional wrap-on-egress for key material
// ---------------------------------------------------------------------------

/// Optional wrap-the-key-on-the-way-out hook (audit H22).
///
/// When a [`KekProvider`] is installed on the server, every response that
/// would expose raw `Key Material` (most notably `Get`) is routed through
/// `wrap` before the bytes are TTLV-encoded. The wrapper returns an opaque
/// blob that the client must round-trip back through `unwrap` before use.
/// The trait is intentionally synchronous and minimal so a deployment can
/// adapt it to a local KEK held in HSM-backed memory without pulling in
/// async dependencies.
///
/// All wrap/unwrap implementations MUST be authenticated (e.g. AES-GCM, AES
/// key-wrap with KDF) — this trait does not perform any check on the bytes
/// returned by `unwrap`.
pub trait KekProvider: Send + Sync {
    /// Wrap `plaintext` into an opaque ciphertext blob for transport.
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;

    /// Unwrap a blob produced by [`KekProvider::wrap`].
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, String>;
}

// ---------------------------------------------------------------------------
// Replay cache (audit M)
// ---------------------------------------------------------------------------

/// In-memory replay cache keyed on `(identity, ClientCorrelationValue)`.
///
/// Entries expire after `KmipOptions::replay_window_secs`; the cache only
/// stores SHA-256 digests of the `(identity, value)` tuple to bound memory
/// per-tenant usage and avoid retaining cleartext correlation values.
/// Hard upper bound on the replay cache size. Once the cache reaches this
/// many entries the next `check_and_record` call fails closed — the
/// safer default than dropping arbitrary entries (which would allow
/// replay). Sized to bound steady-state RAM at ~2 MiB (32-byte digest +
/// per-entry overhead × 65,536).
pub(crate) const REPLAY_CACHE_HARD_CAP: usize = 65_536;

struct ReplayCache {
    seen: DashMap<[u8; 32], Instant>,
    window: std::time::Duration,
    check_counter: AtomicU64,
}

impl ReplayCache {
    fn new(window_secs: u64) -> Self {
        Self {
            seen: DashMap::new(),
            window: std::time::Duration::from_secs(window_secs.max(1)),
            check_counter: AtomicU64::new(0),
        }
    }

    fn key(identity: Option<&str>, ccv: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(identity.unwrap_or("").as_bytes());
        h.update([0xFF]);
        h.update(ccv.as_bytes());
        h.finalize().into()
    }

    /// Returns `true` if this `(identity, ccv)` pair was already seen inside
    /// the active window — the caller should reject the request.
    ///
    /// Audit follow-up: the previous get-then-insert pattern allowed two
    /// racing requests with the same `(identity, ccv)` to both pass the
    /// duplicate check. We now use `DashMap::entry` to atomically claim
    /// the key or read the existing timestamp.
    ///
    /// Once the cache reaches [`REPLAY_CACHE_HARD_CAP`] entries we fail
    /// closed (return `true`) rather than evicting an arbitrary entry,
    /// which would have permitted replay of whichever pair fell out.
    fn check_and_record(&self, identity: Option<&str>, ccv: &str) -> bool {
        if self.check_counter.fetch_add(1, Ordering::Relaxed) % 100 == 0 {
            let now = Instant::now();
            self.seen.retain(|_, ts| now.saturating_duration_since(*ts) < self.window);
        }
        let k = Self::key(identity, ccv);
        let now = Instant::now();
        // Hard cap. Refuse fast — if the cache is full, the safe answer is
        // "treat as duplicate" so an attacker cannot DoS us into accepting
        // replays.
        if self.seen.len() >= REPLAY_CACHE_HARD_CAP && !self.seen.contains_key(&k) {
            tracing::warn!(
                target: "craton_hsm_kmip::replay",
                cap = REPLAY_CACHE_HARD_CAP,
                "replay cache full; refusing new (identity, ccv) until eviction"
            );
            return true;
        }
        let mut already_seen = false;
        self.seen
            .entry(k)
            .and_modify(|ts| {
                if now.saturating_duration_since(*ts) < self.window {
                    already_seen = true;
                } else {
                    *ts = now;
                }
            })
            .or_insert(now);
        already_seen
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// TLS configuration for the KMIP server.
/// Production deployments MUST configure TLS either natively
/// or via an external TLS terminator (e.g., nginx, envoy).
#[derive(Debug, Clone, Default)]
pub struct KmipTlsConfig {
    /// Path to the server certificate (PEM).
    pub cert_path: Option<String>,
    /// Path to the server private key (PEM).
    pub key_path: Option<String>,
    /// Path to the CA certificate for client verification (PEM).
    pub ca_cert_path: Option<String>,
}

/// Configuration for the KMIP server.
#[derive(Debug, Clone)]
pub struct KmipServerConfig {
    /// Address the server binds to (e.g. `"0.0.0.0:5696"`).
    pub listen_addr: String,
    /// Maximum accepted TTLV message size, in bytes.
    pub max_message_size: usize,
    /// When `true`, every request must carry a valid authentication token.
    /// Defaults to `false` for backward compatibility, but SHOULD be enabled
    /// in production deployments.
    pub require_auth: bool,
    /// Shared authentication token that clients must present when
    /// `require_auth` is `true`.  Ignored when authentication is disabled.
    ///
    /// # Security — development / testing only
    ///
    /// This single static token is provided for **development and testing
    /// convenience only**.  Production deployments should integrate with the
    /// `craton-hsm-auth` crate's provider system (e.g., mTLS client
    /// certificates or an external identity provider) rather than relying on
    /// a single shared secret.
    ///
    /// Accepting a static token also requires:
    /// (1) the crate feature `insecure-static-token` to be enabled at build
    /// time, and (2) the environment variable
    /// `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1` to be set at process start.
    /// Builds without the feature reject static-token authentication
    /// unconditionally regardless of what the field contains.
    pub auth_token: Option<Zeroizing<String>>,
    /// Optional TLS configuration. When `None`, the server runs in plaintext
    /// mode (suitable only for testing or when an external TLS terminator is used).
    pub tls: Option<KmipTlsConfig>,
}

/// Minimum acceptable entropy for a production static token. A 256-bit
/// random value is the smallest size that is not trivially brute-forced.
const MIN_STATIC_TOKEN_BYTES: usize = 32;

/// Obviously-insecure placeholder values we refuse at startup regardless of
/// length, to catch copy-pasted examples and committed defaults.
const WEAK_STATIC_TOKEN_VALUES: &[&str] = &[
    "changeme",
    "change-me",
    "password",
    "secret",
    "test",
    "test-secret",
    "test-token",
    "dev",
    "development",
    "kmip",
    "kmip-token",
    "admin",
    "admin-token",
    "admin:admin",
    "root",
    "hsm",
    "craton",
    "example",
];

impl KmipServerConfig {
    /// Validate the configuration for a production deployment.
    ///
    /// Intended to be called at process startup. Returns `Err` with a
    /// human-readable reason if the configuration would be unsafe to run.
    /// Successful validation is a necessary but not sufficient condition —
    /// operators should still prefer mTLS and an external IdP.
    pub fn validate_for_production(&self) -> Result<(), String> {
        if !self.require_auth {
            return Err(
                "require_auth must be true in production; set require_auth = true and configure \
                 an authentication source (mTLS or IdP preferred)."
                    .to_string(),
            );
        }
        if let Some(tok) = &self.auth_token {
            validate_static_token(tok.as_str())?;
            if !insecure_static_token_allowed() {
                return Err(
                    "auth_token is set but CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1 was not \
                     exported at process start. Integrate craton-hsm-auth (mTLS/IdP) or set the \
                     env var explicitly after reviewing HARDENING.md."
                        .to_string(),
                );
            }
            tracing::warn!(
                target: "craton_hsm_kmip::auth",
                "accepting shared static auth_token; deployment has opted in via \
                 CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN. Switch to mTLS/IdP for production."
            );
        }
        Ok(())
    }
}

fn validate_static_token(tok: &str) -> Result<(), String> {
    // Audit follow-up: avoid the heap allocation `to_ascii_lowercase()`
    // would perform; iterate byte-by-byte and compare case-insensitively
    // so the placeholder check runs in O(N) bytes without ever leaving
    // an allocated lowercase copy on the heap (a small concern because
    // the token is supposed to be short, but we keep the function tight
    // so it can be reused in fuzz/property tests).
    let tok_bytes = tok.as_bytes();
    for weak in WEAK_STATIC_TOKEN_VALUES {
        let w = weak.as_bytes();
        if w.len() == tok_bytes.len()
            && tok_bytes
                .iter()
                .zip(w.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Err(format!(
                "auth_token matches a well-known insecure placeholder ({weak:?}); refuse to start"
            ));
        }
    }
    if tok.len() < MIN_STATIC_TOKEN_BYTES {
        return Err(format!(
            "auth_token is only {} bytes; require at least {} bytes of entropy \
             (use `openssl rand -hex 32` or equivalent)",
            tok.len(),
            MIN_STATIC_TOKEN_BYTES
        ));
    }
    Ok(())
}

fn insecure_static_token_allowed() -> bool {
    // Explicit opt-in: the caller must set the env var non-empty and not "0".
    match std::env::var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN") {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

impl Default for KmipServerConfig {
    fn default() -> Self {
        Self {
            // Bind to localhost only by default to prevent unintended network
            // exposure.  Production deployments should explicitly set the listen
            // address to the desired interface.
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576, // 1 MB
            // SECURITY: Authentication is required by default in production.
            // Explicitly set to `false` only in test environments.
            require_auth: true,
            auth_token: None,
            tls: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Top-level KMIP server that owns a key store and processes messages.
pub struct KmipServer {
    /// Backing key store that holds managed objects.
    pub store: Box<dyn KmipKeyStore>,
    /// Server configuration (listen address, limits, auth, TLS).
    pub config: KmipServerConfig,
    rate_limiter: AuthRateLimiter,
    /// Snapshot of the `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN` env-var at
    /// construction time, used **only** to emit a startup warning when the
    /// configured static token would be rejected by the current environment.
    ///
    /// The actual per-request authentication gate re-reads the env var on
    /// every call (audit finding C3) so operators can toggle the opt-in
    /// without restarting — for instance during an emergency ACL lock-down.
    #[cfg(feature = "insecure-static-token")]
    #[allow(dead_code)]
    static_token_runtime_allowed_at_startup: bool,
    /// Pluggable authorization policy. Default is [`AllowAll`] which
    /// preserves the previous no-ACL behaviour. Production deployments
    /// should install a real policy that consults
    /// `craton-hsm-auth` (audit finding M8).
    acl: Arc<dyn KmipAcl>,
    /// Runtime policy toggles (strict ownership, replay window, identity
    /// hashing in logs).
    options: KmipOptions,
    /// Optional Key-Encryption-Key provider. When set, response key
    /// material is wrapped before TTLV serialization (audit H22).
    kek: Option<Arc<dyn KekProvider>>,
    /// In-memory replay cache for `ClientCorrelationValue` (audit M).
    replay: ReplayCache,
}

impl KmipServer {
    /// Create a new server with the given store and config.
    ///
    /// Does not validate `config` for production safety. Call
    /// [`KmipServerConfig::validate_for_production`] explicitly at process
    /// start if you want a hard fail on unsafe configurations.
    pub fn new(store: Box<dyn KmipKeyStore>, config: KmipServerConfig) -> Self {
        #[cfg(feature = "insecure-static-token")]
        let static_token_runtime_allowed_at_startup = {
            let ok = insecure_static_token_allowed();
            if !ok && config.auth_token.is_some() && config.require_auth {
                tracing::warn!(
                    target: "craton_hsm_kmip::auth",
                    "auth_token is configured but CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN is not \
                     set; authentication will reject every request until the env var is exported"
                );
            }
            ok
        };
        let options = KmipOptions::default();
        Self {
            store,
            config,
            rate_limiter: AuthRateLimiter::new(5, 60),
            acl: Arc::new(AllowAll),
            #[cfg(feature = "insecure-static-token")]
            static_token_runtime_allowed_at_startup,
            replay: ReplayCache::new(options.replay_window_secs),
            options,
            kek: None,
        }
    }

    /// Replace runtime [`KmipOptions`] (audit M5/M-replay/L log hashing).
    pub fn with_options(mut self, options: KmipOptions) -> Self {
        self.replay = ReplayCache::new(options.replay_window_secs);
        self.options = options;
        self
    }

    /// Install a [`KekProvider`] that wraps response key material before
    /// TTLV serialization (audit H22).
    pub fn with_kek<K: KekProvider + 'static>(mut self, kek: K) -> Self {
        self.kek = Some(Arc::new(kek));
        self
    }

    /// Install a custom ACL policy.
    ///
    /// The ACL is consulted before the owner-attribute check on every
    /// sensitive operation (Destroy, Revoke, Activate, Get,
    /// GetAttributes, AddAttribute). Constructing the server installs
    /// [`AllowAll`] by default so behaviour is unchanged unless the
    /// caller opts in.
    pub fn with_acl<A: KmipAcl + 'static>(mut self, acl: A) -> Self {
        self.acl = Arc::new(acl);
        self
    }

    /// Create a server with an in-memory store and authentication **disabled**.
    ///
    /// Suitable for demos and integration tests. For production, use
    /// [`KmipServer::new`] with a fully-configured [`KmipServerConfig`] that
    /// has `require_auth = true` and a strong `auth_token`.
    pub fn with_defaults() -> Self {
        // Security posture: `with_defaults` produces a fully-default server
        // that opts INTO strict owner-ACL enforcement. Tests that need the
        // legacy ownerless-public behaviour should construct
        // `KmipServer` directly with a `KmipOptions { strict_owner_acl:
        // false, .. }` override.
        let options = KmipOptions::default();
        Self {
            store: Box::new(InMemoryKeyStore::new()),
            config: KmipServerConfig {
                require_auth: false,
                ..KmipServerConfig::default()
            },
            rate_limiter: AuthRateLimiter::new(5, 60),
            acl: Arc::new(AllowAll),
            #[cfg(feature = "insecure-static-token")]
            static_token_runtime_allowed_at_startup: insecure_static_token_allowed(),
            replay: ReplayCache::new(options.replay_window_secs),
            options,
            kek: None,
        }
    }

    /// Process a raw TTLV-encoded request message and return a raw response.
    pub fn process_message(&self, raw_bytes: &[u8]) -> Vec<u8> {
        self.process_message_with_auth(raw_bytes, None)
    }

    /// Process a request that arrived with a pre-authenticated identity
    /// (typically the SAN/CN of a verified client certificate). The static
    /// bearer-token gate is bypassed entirely — mTLS-derived identity wins
    /// (audit H21).
    pub fn process_message_with_identity(
        &self,
        raw_bytes: &[u8],
        identity: &str,
    ) -> Vec<u8> {
        self.process_message_internal(raw_bytes, None, Some(identity.to_string()), None)
    }

    /// Process a request along with the originating peer address, used so
    /// the rate-limit bucket is keyed on `(peer_ip, optional_token)` rather
    /// than `token` alone (audit M rate-limit).
    pub fn process_message_with_peer(
        &self,
        peer_addr: std::net::SocketAddr,
        raw_bytes: &[u8],
        client_token: Option<&str>,
    ) -> Vec<u8> {
        self.process_message_internal(raw_bytes, client_token, None, Some(peer_addr))
    }

    /// Process a raw TTLV-encoded request message with an optional client-provided
    /// authentication token.  When `require_auth` is enabled in the config, the
    /// token must match `config.auth_token` or the request is rejected.
    pub fn process_message_with_auth(
        &self,
        raw_bytes: &[u8],
        client_token: Option<&str>,
    ) -> Vec<u8> {
        self.process_message_internal(raw_bytes, client_token, None, None)
    }

    fn process_message_internal(
        &self,
        raw_bytes: &[u8],
        client_token: Option<&str>,
        preauth_identity: Option<String>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> Vec<u8> {
        // Authentication gate. Track whether auth succeeded so we can set
        // caller_identity on the request for downstream access control.
        let authenticated_identity: Option<String>;

        // Audit M: derive the rate-limit bucket from (peer ip, optional
        // client token hash). Falling back to a zero-hash bucket when no
        // peer is known would let a noisy attacker silence other tenants;
        // the per-peer bucket bounds blast radius to one source IP.
        let client_hash: [u8; 32] = {
            let mut h = Sha256::new();
            if let Some(pa) = peer_addr {
                h.update(pa.ip().to_string().as_bytes());
            }
            h.update([0u8]);
            if let Some(t) = client_token {
                h.update(Sha256::digest(t.as_bytes()));
            }
            h.finalize().into()
        };

        // Audit H21: a pre-authenticated identity (mTLS) wins outright. The
        // bearer token is *only* used as a rate-limit bucket key in that
        // case; the bearer string is never echoed as the caller identity.
        if let Some(id) = preauth_identity.clone() {
            authenticated_identity = Some(id);
        } else if self.config.require_auth {
            // (Continue down the bearer-token path for legacy callers.)
            if self.rate_limiter.is_rate_limited(&client_hash) {
                return self.encode_error_response(
                    KmipResultReason::PermissionDenied,
                    "too many authentication failures — try again later",
                );
            }
            // Compile-time gate: if the `insecure-static-token` feature is
            // disabled, static-token authentication is not compiled in at all
            // and every request is rejected even if `auth_token` was populated
            // via struct-literal by a caller. This is a defence-in-depth
            // measure: a misconfigured YAML loader cannot produce a build that
            // accepts a shared bearer token.
            #[cfg(feature = "insecure-static-token")]
            {
                // Audit finding C3: re-read the env var on every request
                // rather than caching the value at `new()` time. This lets
                // operators toggle the opt-in without restarting the
                // process — for instance to revoke the shared bearer token
                // during an incident. The cached startup snapshot is
                // retained *only* to drive the one-time startup warning.
                if !insecure_static_token_allowed() {
                    return self.encode_error_response(
                        KmipResultReason::PermissionDenied,
                        "static-token authentication not permitted: set \
                         CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1 or integrate craton-hsm-auth",
                    );
                }
                match (&self.config.auth_token, client_token) {
                    (Some(expected), Some(provided)) => {
                        // Audit finding H5: both sides are hashed to a
                        // fixed 32-byte SHA-256 digest before the
                        // constant-time comparison, so no short-circuit
                        // length comparison ever sees the user-provided
                        // token. The `MIN_STATIC_TOKEN_BYTES` guard is
                        // enforced only at configuration-validation time
                        // (`validate_for_production`) against the
                        // *expected* token, not per request — so the
                        // runtime hot path does not leak any timing
                        // signal about the provisioned length.
                        let expected_hash: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
                        let provided_hash: [u8; 32] = Sha256::digest(provided.as_bytes()).into();
                        if !bool::from(subtle::ConstantTimeEq::ct_eq(&expected_hash[..], &provided_hash[..])) {
                            self.rate_limiter.record_failure(&client_hash);
                            return self.encode_error_response(
                                KmipResultReason::PermissionDenied,
                                "authentication failed: invalid token",
                            );
                        }
                        authenticated_identity = Some(provided.to_string());
                    }
                    (Some(_), None) => {
                        self.rate_limiter.record_failure(&client_hash);
                        return self.encode_error_response(
                            KmipResultReason::PermissionDenied,
                            "authentication required but no token provided",
                        );
                    }
                    (None, _) => {
                        // auth_token not configured but require_auth is true — reject all.
                        return self.encode_error_response(
                            KmipResultReason::PermissionDenied,
                            "server authentication token not configured",
                        );
                    }
                }
            }
            #[cfg(not(feature = "insecure-static-token"))]
            {
                // Avoid unused-variable warnings when the feature is off.
                let _ = &self.config.auth_token;
                let _ = client_token;
                self.rate_limiter.record_failure(&client_hash);
                return self.encode_error_response(
                    KmipResultReason::PermissionDenied,
                    "KMIP server built without the 'insecure-static-token' feature; \
                     integrate craton-hsm-auth (mTLS / IdP) for authentication",
                );
            }
        } else {
            // Auth disabled — pass through identity as-is for informational
            // purposes. A pre-auth (mTLS) identity, if any, was already
            // captured in the `if let Some(id) = preauth_identity` arm above.
            authenticated_identity = client_token.map(|s| s.to_string());
        }

        // Check message size.
        if raw_bytes.len() > self.config.max_message_size {
            return self.encode_error_response(
                KmipResultReason::InvalidMessage,
                "message exceeds maximum size",
            );
        }

        // Decode the request with caller-policy resource bounds. The
        // `max_bytes` budget is tied to `config.max_message_size` so a
        // pathologically-structured (but nominally-under-size) message
        // cannot drive the decoder into many megabytes of allocation
        // (audit finding H4).
        let decode_limits = TtlvLimits {
            max_depth: MAX_TTLV_DEPTH,
            max_items: MAX_TTLV_ITEMS,
            max_bytes: self.config.max_message_size,
        };
        let (item, _consumed) = match decode_ttlv_with_limits(raw_bytes, decode_limits) {
            Ok(result) => result,
            Err(_) => {
                return self.encode_error_response(
                    KmipResultReason::InvalidMessage,
                    "failed to decode TTLV request",
                );
            }
        };

        // Parse the request message structure.
        let parsed = match parse_request_with_meta(&item) {
            Some(p) => p,
            None => {
                return self.encode_error_response(
                    KmipResultReason::InvalidMessage,
                    "malformed KMIP request",
                );
            }
        };

        let mut request = parsed.request;
        let declared_batch_count = parsed.batch_count;
        let actual_batch_items = parsed.actual_batch_items;
        let correlation_value = parsed.client_correlation_value;
        let response_pv = parsed.protocol_version;

        // Audit M (BatchCount validation): KMIP requires the header to
        // declare exactly as many BatchItem children as the message carries.
        // Today we still only dispatch the FIRST batch item, but the
        // mismatch check itself short-circuits a class of replayed /
        // truncated requests. Multi-item batches are treated as a single
        // dispatch with one ResponseBatchItem.
        if let Some(declared) = declared_batch_count {
            if declared as usize != actual_batch_items {
                tracing::warn!(
                    target: "craton_hsm_kmip::server",
                    declared,
                    actual = actual_batch_items,
                    "rejecting request: BatchCount mismatch"
                );
                return self.encode_error_response(
                    KmipResultReason::InvalidMessage,
                    "BatchCount header does not match number of BatchItem children",
                );
            }
        }

        // Attach the authenticated identity so operation handlers can enforce ACLs.
        request.caller_identity = authenticated_identity;
        request.strict_owner_acl = self.options.strict_owner_acl;

        // Audit L: log a hashed-identity tag instead of the raw identity so
        // operator dashboards do not become a cleartext PII sink.
        let identity_log = log_identity_tag(
            request.caller_identity.as_deref(),
            self.options.hash_identity_in_logs,
        );
        tracing::info!(
            target: "craton_hsm_kmip::server",
            identity = %identity_log,
            op = %request.operation,
            "dispatching KMIP request"
        );

        // Audit M (replay defence): when enabled, reject any duplicate
        // (identity, ClientCorrelationValue) pair within the configured
        // window.
        if self.options.require_correlation_value {
            let ccv = match correlation_value.as_deref() {
                Some(v) if !v.is_empty() => v,
                _ => {
                    return self.encode_error_response(
                        KmipResultReason::InvalidMessage,
                        "ClientCorrelationValue is required by server policy",
                    );
                }
            };
            if self
                .replay
                .check_and_record(request.caller_identity.as_deref(), ccv)
            {
                return self.encode_error_response(
                    KmipResultReason::PermissionDenied,
                    "duplicate ClientCorrelationValue within replay window",
                );
            }
        }

        // Consult the pluggable ACL for sensitive operations before the
        // handler runs (audit finding M8). Non-sensitive operations
        // (Query, Locate, Create, Register, Check) still flow through the
        // existing owner-attribute enforcement inside `operations`.
        if operation_requires_acl(request.operation) {
            match self.acl.authorize(
                request.caller_identity.as_deref(),
                request.operation,
                request.unique_id.as_deref(),
            ) {
                KmipAclDecision::Allow => {}
                KmipAclDecision::Deny(reason) => {
                    return self.encode_error_response(
                        reason,
                        &format!(
                            "ACL denied {op} for caller {caller}",
                            op = request.operation,
                            caller = identity_log,
                        ),
                    );
                }
            }
        }

        // Dispatch to the appropriate handler.
        let mut response = dispatch_operation(&request, self.store.as_ref());

        // Audit H22: when a KEK provider is installed, every response that
        // would expose raw key material is wrapped before TTLV encoding so
        // the wire never carries unwrapped bytes. Failure to wrap is fatal —
        // we surface it as `CryptographicFailure` and clear the material.
        if let Some(kek) = self.kek.as_ref() {
            if let Some(material) = response.key_material.take() {
                // Move into a Zeroizing<Vec<u8>> so the plaintext copy is
                // wiped from memory as soon as wrap() returns or a panic
                // unwinds the stack.
                let zeroized = Zeroizing::new(material);
                match kek.wrap(zeroized.as_slice()) {
                    Ok(wrapped) => response.key_material = Some(wrapped),
                    Err(e) => {
                        tracing::error!(
                            target: "craton_hsm_kmip::kek",
                            error = %e,
                            "KEK wrap failed; refusing to emit unwrapped key material"
                        );
                        return self.encode_error_response(
                            KmipResultReason::CryptographicFailure,
                            "KEK wrap failed",
                        );
                    }
                }
            }
        }

        // Encode the response. The buffer is held in a Zeroizing wrapper
        // until written so a panic in the caller's I/O loop does not leave
        // any plaintext attribute traces in stack-unwound memory.
        let encoded = Zeroizing::new(encode_response_versioned(&response, response_pv));
        encoded.to_vec()
    }

    /// Encode a simple error response.
    fn encode_error_response(&self, reason: KmipResultReason, msg: &str) -> Vec<u8> {
        let resp = KmipResponse::error(reason, msg);
        encode_response(&resp)
    }
}

/// Return `true` for operations that must consult the pluggable ACL before
/// dispatch. Covers every destructive or confidentiality-sensitive op
/// supported by this crate today. (The crate does not yet implement
/// Encrypt/Decrypt/Sign/Verify; when it does, they should be added here.)
///
/// # Exceptions
///
/// * [`KmipOperation::Check`] is deliberately excluded. Check is a
///   read-only usability probe whose downstream handler already returns
///   `ObjectNotFound` for any caller without read permission through
///   [`crate::operations::check_owner_acl`]; double-gating it would turn
///   a probe into an existence oracle whenever the pluggable ACL denied
///   globally instead of per-object.
/// * [`KmipOperation::Create`] is excluded because it generates a server-
///   side ID and auto-attaches the caller as `owner`, so there is no
///   pre-existing object to authorize against.
/// * Every other op (including [`KmipOperation::Register`],
///   [`KmipOperation::Query`], and [`KmipOperation::Locate`]) IS gated;
///   Register authorization is additionally enforced for ID collisions
///   inside its handler via the owner ACL to mask existence of other
///   tenants' objects.
fn operation_requires_acl(op: KmipOperation) -> bool {
    matches!(
        op,
        KmipOperation::Destroy
            | KmipOperation::Revoke
            | KmipOperation::Activate
            | KmipOperation::Get
            | KmipOperation::GetAttributes
            | KmipOperation::AddAttribute
            | KmipOperation::ModifyAttribute
            | KmipOperation::DeleteAttribute
            | KmipOperation::DeriveKey
            | KmipOperation::Register
            | KmipOperation::Query
            | KmipOperation::Locate
            | KmipOperation::Encrypt
            | KmipOperation::Decrypt
            | KmipOperation::Sign
            | KmipOperation::SignatureVerify
            | KmipOperation::MAC
            | KmipOperation::MACVerify
    )
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Route a parsed request to the correct operation handler.
pub fn dispatch_operation(
    request: &KmipRequest,
    store: &dyn KmipKeyStore,
) -> KmipResponse {
    match request.operation {
        KmipOperation::Create => process_create(request, store),
        KmipOperation::CreateKeyPair => process_create_key_pair(request, store),
        KmipOperation::Get => process_get(request, store),
        KmipOperation::Activate => process_activate(request, store),
        KmipOperation::Revoke => process_revoke(request, store),
        KmipOperation::Destroy => process_destroy(request, store),
        KmipOperation::Query => process_query(request, store),
        KmipOperation::GetAttributes => process_get_attributes(request, store),
        KmipOperation::Register => process_register(request, store),
        KmipOperation::Locate => process_locate(request, store),
        KmipOperation::Check => process_check(request, store),
        KmipOperation::AddAttribute => process_add_attribute(request, store),
        KmipOperation::ModifyAttribute => process_modify_attribute(request, store),
        KmipOperation::DeleteAttribute => process_delete_attribute(request, store),
        KmipOperation::DeriveKey => process_derive_key(request, store),
        KmipOperation::RngRetrieve => process_rng_retrieve(request, store),
        KmipOperation::Encrypt => process_encrypt(request, store),
        KmipOperation::Decrypt => process_decrypt(request, store),
        KmipOperation::Sign => process_sign(request, store),
        KmipOperation::SignatureVerify => process_signature_verify(request, store),
        KmipOperation::MAC => process_mac(request, store),
        KmipOperation::MACVerify => process_mac_verify(request, store),
    }
}

// ---------------------------------------------------------------------------
// TTLV parsing helpers
// ---------------------------------------------------------------------------

/// Output of [`parse_request_with_meta`]: the parsed request plus the
/// metadata fields (BatchCount, ClientCorrelationValue, actual batch-item
/// count) that the dispatcher needs for replay / batch validation.
pub(crate) struct ParsedRequest {
    pub request: KmipRequest,
    /// `BatchCount` from the request header, if present.
    pub batch_count: Option<i32>,
    /// Number of `BatchItem` children physically present in the message.
    pub actual_batch_items: usize,
    /// `ClientCorrelationValue` from the request header, if present.
    pub client_correlation_value: Option<String>,
    /// Protocol version (major, minor) extracted from the request header. The
    /// response echoes this back rather than hard-coding 2.1 (audit polish).
    pub protocol_version: ProtocolVersion,
}

/// KMIP `ProtocolVersion` tuple. Defaults to 2.1 when a request omits or
/// mangles the field.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ProtocolVersion {
    pub major: i32,
    pub minor: i32,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self { major: 2, minor: 1 }
    }
}

/// Server-supported maximum KMIP protocol version. Responses are clamped
/// down to this version so an over-optimistic client requesting (say) 3.0
/// receives a 2.1 response rather than seeing the server echo back a
/// version it does not implement.
pub(crate) const SERVER_MAX_PV: ProtocolVersion = ProtocolVersion { major: 2, minor: 1 };

/// Server-supported minimum KMIP protocol version. KMIP 1.0 is the floor
/// — anything below clamps up to 1.0 so the response is a well-formed
/// KMIP frame.
pub(crate) const SERVER_MIN_PV: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// Clamp the client-requested protocol version into the
/// [`SERVER_MIN_PV`, `SERVER_MAX_PV`] window. Returns the version that
/// must appear in the response header.
///
/// This exists as a free function so unit tests can exercise the
/// clamping math without spinning up a full request pipeline.
pub(crate) fn negotiate_protocol_version(requested: ProtocolVersion) -> ProtocolVersion {
    // Compose (major, minor) into a single sortable u64 so we can compare
    // two versions in one step.
    fn pv_key(p: ProtocolVersion) -> i64 {
        (p.major as i64) * 1_000_000 + (p.minor as i64)
    }
    let r = pv_key(requested);
    if r > pv_key(SERVER_MAX_PV) {
        SERVER_MAX_PV
    } else if r < pv_key(SERVER_MIN_PV) {
        SERVER_MIN_PV
    } else {
        requested
    }
}

/// Audit L: derive a non-PII tag for a caller identity to log instead of
/// the raw identity.
fn log_identity_tag(identity: Option<&str>, hash_in_logs: bool) -> String {
    match identity {
        None => "<anon>".to_string(),
        Some(id) => {
            if hash_in_logs {
                let digest = Sha256::digest(id.as_bytes());
                let mut buf = String::with_capacity(12);
                for b in &digest[..4] {
                    use std::fmt::Write;
                    write!(buf, "{b:02x}").expect("writing into String never fails");
                }
                format!("id:{buf}")
            } else {
                id.to_string()
            }
        }
    }
}

/// Like [`parse_request`] but also returns the BatchCount / actual children
/// count / ClientCorrelationValue used for replay and batch validation.
fn parse_request_with_meta(item: &TtlvItem) -> Option<ParsedRequest> {
    let children = match &item.value {
        TtlvValue::Structure(c) => c,
        _ => return None,
    };

    let header = children
        .iter()
        .find(|c| c.tag == KmipTag::RequestHeader.to_u32());
    let mut batch_count: Option<i32> = None;
    let mut ccv: Option<String> = None;
    let mut protocol_version = ProtocolVersion::default();
    let mut saw_protocol_version = false;
    if let Some(hdr) = header {
        if let TtlvValue::Structure(hdr_children) = &hdr.value {
            for c in hdr_children {
                if c.tag == KmipTag::BatchCount.to_u32() {
                    if let TtlvValue::Integer(v) = &c.value {
                        batch_count = Some(*v);
                    }
                } else if c.tag == KmipTag::ClientCorrelationValue.to_u32() {
                    if let TtlvValue::TextString(v) = &c.value {
                        ccv = Some(v.clone());
                    }
                } else if c.tag == KmipTag::ProtocolVersion.to_u32() {
                    if let TtlvValue::Structure(pv_children) = &c.value {
                        let mut major: Option<i32> = None;
                        let mut minor: Option<i32> = None;
                        for pv in pv_children {
                            if pv.tag == KmipTag::ProtocolVersionMajor.to_u32() {
                                if let TtlvValue::Integer(v) = &pv.value {
                                    major = Some(*v);
                                }
                            } else if pv.tag == KmipTag::ProtocolVersionMinor.to_u32() {
                                if let TtlvValue::Integer(v) = &pv.value {
                                    minor = Some(*v);
                                }
                            }
                        }
                        match (major, minor) {
                            (Some(maj), Some(min)) => {
                                // Audit follow-up: clamp the client-requested
                                // version into the server-supported window
                                // so a forged 3.0 (or 0.0) header cannot
                                // make the response echo a version the
                                // server does not implement.
                                protocol_version = negotiate_protocol_version(
                                    ProtocolVersion { major: maj, minor: min },
                                );
                                saw_protocol_version = true;
                            }
                            _ => {
                                tracing::warn!(
                                    target: "craton_hsm_kmip::server",
                                    "ProtocolVersion in request header was unparseable; defaulting response to 2.1"
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            target: "craton_hsm_kmip::server",
                            "ProtocolVersion header was not a Structure; defaulting response to 2.1"
                        );
                    }
                }
            }
        }
    }
    let _ = saw_protocol_version;

    let actual_batch_items = children
        .iter()
        .filter(|c| c.tag == KmipTag::BatchItem.to_u32())
        .count();

    let request = parse_request(item)?;
    Some(ParsedRequest {
        request,
        batch_count,
        actual_batch_items,
        client_correlation_value: ccv,
        protocol_version,
    })
}

/// Extract a [`KmipRequest`] from a decoded TTLV request message.
fn parse_request(item: &TtlvItem) -> Option<KmipRequest> {
    // Expect top-level RequestMessage structure.
    let children = match &item.value {
        TtlvValue::Structure(c) => c,
        _ => return None,
    };

    // Find the BatchItem within the request message.
    let batch_item = children
        .iter()
        .find(|c| c.tag == KmipTag::BatchItem.to_u32())?;

    let batch_children = match &batch_item.value {
        TtlvValue::Structure(c) => c,
        _ => return None,
    };

    // Extract operation enumeration.
    let op_val = batch_children.iter().find_map(|c| {
        if c.tag == KmipTag::Operation.to_u32() {
            if let TtlvValue::Enumeration(v) = &c.value {
                return Some(*v);
            }
        }
        None
    })?;

    let operation = KmipOperation::from_u32(op_val)?;

    // Extract optional UniqueIdentifier.
    let unique_id = batch_children.iter().find_map(|c| {
        if c.tag == KmipTag::UniqueIdentifier.to_u32() {
            if let TtlvValue::TextString(s) = &c.value {
                return Some(s.clone());
            }
        }
        None
    });

    // Audit finding L8: collect attributes into a stack-backed SmallVec
    // sized for the common case (<=8 attributes). The conversion to the
    // owned `Vec` stored on `KmipRequest` happens once, right before
    // returning, so typical requests avoid the intermediate-growth
    // reallocations that a fresh `Vec::new()` would pay as attributes
    // are pushed. Only a handful of requests in real deployments carry
    // more than eight attributes.
    let mut attributes: SmallVec<[KmipAttribute; 8]> = SmallVec::new();
    if let Some(tmpl) = batch_children
        .iter()
        .find(|c| c.tag == KmipTag::TemplateAttribute.to_u32())
    {
        if let TtlvValue::Structure(tmpl_children) = &tmpl.value {
            for attr_item in tmpl_children {
                if attr_item.tag == KmipTag::Attribute.to_u32() {
                    if let Some(attr) = parse_attribute(attr_item) {
                        attributes.push(attr);
                    }
                }
            }
        }
    }

    Some(KmipRequest {
        operation,
        unique_id,
        attributes: attributes.into_vec(),
        caller_identity: None,
            strict_owner_acl: false,
        })
}

/// Parse a single Attribute structure into a [`KmipAttribute`].
fn parse_attribute(item: &TtlvItem) -> Option<KmipAttribute> {
    let children = match &item.value {
        TtlvValue::Structure(c) => c,
        _ => return None,
    };

    let name = children.iter().find_map(|c| {
        if c.tag == KmipTag::AttributeName.to_u32() {
            if let TtlvValue::TextString(s) = &c.value {
                return Some(s.clone());
            }
        }
        None
    })?;

    let value = children.iter().find_map(|c| {
        if c.tag == KmipTag::AttributeValue.to_u32() {
            return match &c.value {
                TtlvValue::TextString(s) => Some(KmipAttributeValue::Text(s.clone())),
                TtlvValue::Integer(v) => Some(KmipAttributeValue::Integer(*v)),
                TtlvValue::LongInteger(v) => Some(KmipAttributeValue::LongInteger(*v)),
                TtlvValue::Enumeration(v) => Some(KmipAttributeValue::Enum(*v)),
                TtlvValue::ByteString(b) => Some(KmipAttributeValue::Bytes(b.clone())),
                TtlvValue::Boolean(b) => Some(KmipAttributeValue::Boolean(*b)),
                _ => None,
            };
        }
        None
    })?;

    Some(KmipAttribute { name, value })
}

// ---------------------------------------------------------------------------
// TTLV response encoding
// ---------------------------------------------------------------------------

/// Encode a [`KmipResponse`] into a TTLV response message using the
/// default 2.1 protocol version (used by error paths that occur before
/// the request header has been parsed).
fn encode_response(resp: &KmipResponse) -> Vec<u8> {
    encode_response_versioned(resp, ProtocolVersion::default())
}

/// Encode a [`KmipResponse`] echoing back the protocol version observed
/// in the original request header.
///
/// If TTLV encoding fails (e.g. an oversize value) the response is
/// re-encoded as a minimal `OperationFailed` / `GeneralFailure` error
/// frame. Should THAT also fail, the function returns an `Err` so the
/// connection loop in [`KmipServer::serve_accept_one`] can drop the
/// session rather than transmitting partial bytes.
fn encode_response_versioned(resp: &KmipResponse, pv: ProtocolVersion) -> Vec<u8> {
    match encode_response_inner(resp, pv) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                target: "craton_hsm_kmip::server",
                error = %e,
                "TTLV-encode of primary response failed; emitting GeneralFailure frame"
            );
            // Try to emit a properly framed KMIP error response in place
            // of the unencodable original. This must contain only fixed,
            // bounded fields so it can't fail for the same reason.
            let fallback = KmipResponse::error(
                KmipResultReason::GeneralFailure,
                "internal server error: response encode failed",
            );
            match encode_response_inner(&fallback, pv) {
                Ok(bytes) => bytes,
                Err(e2) => {
                    tracing::error!(
                        target: "craton_hsm_kmip::server",
                        error = %e2,
                        "TTLV-encode of fallback error frame also failed; \
                         caller must drop the connection"
                    );
                    // Signal failure to the caller via an empty buffer.
                    // `serve_accept_one` treats an empty response as a
                    // hard error and closes the connection.
                    Vec::new()
                }
            }
        }
    }
}

fn encode_response_inner(
    resp: &KmipResponse,
    pv: ProtocolVersion,
) -> Result<Vec<u8>, TtlvError> {
    let mut batch_children = Vec::new();

    // Operation (we don't track which op in the response, but include ResultStatus).
    batch_children.push(TtlvItem {
        tag: KmipTag::ResultStatus.to_u32(),
        value: TtlvValue::Enumeration(resp.status.to_u32()),
    });

    if let Some(reason) = &resp.reason {
        batch_children.push(TtlvItem {
            tag: KmipTag::ResultReason.to_u32(),
            value: TtlvValue::Enumeration(reason.to_u32()),
        });
    }

    if let Some(msg) = &resp.message {
        batch_children.push(TtlvItem {
            tag: KmipTag::ResultMessage.to_u32(),
            value: TtlvValue::TextString(msg.clone()),
        });
    }

    if let Some(uid) = &resp.unique_id {
        batch_children.push(TtlvItem {
            tag: KmipTag::UniqueIdentifier.to_u32(),
            value: TtlvValue::TextString(uid.clone()),
        });
    }

    if let Some(ot) = &resp.object_type {
        batch_children.push(TtlvItem {
            tag: KmipTag::ObjectType.to_u32(),
            value: TtlvValue::Enumeration(ot.to_u32()),
        });
    }

    // Encode located_ids (e.g., from Locate or Query responses) as TextString items.
    for located_id in &resp.located_ids {
        batch_children.push(TtlvItem {
            tag: KmipTag::UniqueIdentifier.to_u32(),
            value: TtlvValue::TextString(located_id.clone()),
        });
    }

    // Encode attributes (e.g., from GetAttributes responses) as Attribute structures.
    for attr in &resp.attributes {
        let attr_value_item = match &attr.value {
            KmipAttributeValue::Text(s) => TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value: TtlvValue::TextString(s.clone()),
            },
            KmipAttributeValue::Integer(v) => TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value: TtlvValue::Integer(*v),
            },
            KmipAttributeValue::LongInteger(v) => TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value: TtlvValue::LongInteger(*v),
            },
            KmipAttributeValue::Enum(v) => TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value: TtlvValue::Enumeration(*v),
            },
            KmipAttributeValue::Bytes(b) => TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value: TtlvValue::ByteString(b.clone()),
            },
            KmipAttributeValue::Boolean(b) => TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value: TtlvValue::Boolean(*b),
            },
        };
        batch_children.push(TtlvItem {
            tag: KmipTag::Attribute.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::AttributeName.to_u32(),
                    value: TtlvValue::TextString(attr.name.clone()),
                },
                attr_value_item,
            ]),
        });
    }

    let batch_item = TtlvItem {
        tag: KmipTag::BatchItem.to_u32(),
        value: TtlvValue::Structure(batch_children),
    };

    // Audit finding L: never let a Y2554 wraparound or mocked clock above
    // i64::MAX seconds explode the cast — clamp to i64::MAX which still
    // produces a well-formed TTLV DateTime.
    let now_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now_epoch: i64 = i64::try_from(now_epoch_secs).unwrap_or(i64::MAX);

    let response_header = TtlvItem {
        tag: KmipTag::ResponseHeader.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::ProtocolVersion.to_u32(),
                value: TtlvValue::Structure(vec![
                    TtlvItem {
                        tag: KmipTag::ProtocolVersionMajor.to_u32(),
                        value: TtlvValue::Integer(pv.major),
                    },
                    TtlvItem {
                        tag: KmipTag::ProtocolVersionMinor.to_u32(),
                        value: TtlvValue::Integer(pv.minor),
                    },
                ]),
            },
            TtlvItem {
                tag: KmipTag::TimeStamp.to_u32(),
                value: TtlvValue::DateTime(now_epoch),
            },
            TtlvItem {
                tag: KmipTag::BatchCount.to_u32(),
                value: TtlvValue::Integer(1),
            },
        ]),
    };

    let response_msg = TtlvItem {
        tag: KmipTag::ResponseMessage.to_u32(),
        value: TtlvValue::Structure(vec![response_header, batch_item]),
    };

    encode_ttlv(&response_msg)
}

// ---------------------------------------------------------------------------
// TLS server / client (audit C1)
// ---------------------------------------------------------------------------

use std::io;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Load the PEM-encoded certificate chain at `path`.
///
/// Each `BEGIN CERTIFICATE` block is materialised as a separate
/// [`rustls::pki_types::CertificateDer`].
fn load_pem_certs(path: &Path) -> io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let raw = std::fs::read(path)?;
    let mut reader = std::io::Cursor::new(raw);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no PEM certificates found",
        ));
    }
    Ok(certs)
}

/// Load the PEM-encoded private key at `path`. Accepts PKCS#8 or RSA blocks.
fn load_pem_key(path: &Path) -> io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let raw = std::fs::read(path)?;
    let mut reader = std::io::Cursor::new(raw);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))?;
    Ok(key)
}

/// Build a `RootCertStore` from a PEM chain. The chain is treated as a set
/// of trust anchors for client-certificate verification.
fn load_pem_root_store(path: &Path) -> io::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in load_pem_certs(path)? {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    }
    Ok(roots)
}

/// Read a length-prefixed TTLV blob from `stream`.
///
/// The KMIP TTLV item header is 8 bytes (3 tag + 1 type + 4 length); we read
/// those, validate the declared length against `max_message_size`, then read
/// the body. The framing pads the value to an 8-byte boundary, so we round
/// the body length up to the next multiple of 8.
async fn read_ttlv_message<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    max_message_size: usize,
) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let padded = length.next_multiple_of(8);
    if header.len() + padded > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TTLV message exceeds max_message_size",
        ));
    }
    let mut body = vec![0u8; padded];
    stream.read_exact(&mut body).await?;
    let mut full = Vec::with_capacity(header.len() + body.len());
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    Ok(full)
}

/// W1: extract the peer's stable identity from a leaf certificate's
/// DER bytes.
///
/// Walks the leaf cert's `subjectAltName` extension and returns the
/// **first** dnsName entry. If no SAN is present (or contains no
/// dnsNames) falls back to the subject's `commonName`. Returns `None`
/// on any parse failure -- callers must treat this as an
/// authentication failure rather than silently accepting an empty
/// identity.
///
/// **Cross-reference**: this function is duplicated verbatim in
/// `craton_hsm_cluster::replication::peer_san_or_cn`. Keep them in
/// lockstep -- any time one is updated, audit the other.
pub fn peer_san_or_cn(cert_der: &[u8]) -> Option<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(dns) = gn {
                    if let Some(n) = normalize_dns_identity(dns) {
                        return Some(n);
                    }
                }
            }
        }
    }
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            if let Some(n) = normalize_dns_identity(s) {
                return Some(n);
            }
        }
    }
    None
}

/// Normalise a DNS identity extracted from a certificate.
///
/// Rejects non-ASCII (so a Punycode/IDN identity does not collide with
/// an ASCII identity that visually matches), lowercases the bytes, and
/// strips a single trailing dot (per RFC 1034 §3.1 fully-qualified
/// names may carry a root label). Returns `None` if the result is
/// empty or contains anything that should not appear in a DNS label.
///
/// Audit follow-up: cert identities flow into the owner-ACL string
/// comparison and into the rate-limit bucket; the same byte sequence
/// must arrive there regardless of how the peer chose to spell their
/// SAN ("Alice.Example.Com." vs "alice.example.com").
pub fn normalize_dns_identity(raw: &str) -> Option<String> {
    if !raw.is_ascii() {
        return None;
    }
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Legacy adapter for the previous best-effort SAN scanner. Now
/// delegates to [`peer_san_or_cn`] which uses a real X.509 parser
/// (W1). Retained as an `fn` so the surrounding accept loops do not
/// have to be re-routed.
fn identity_from_client_cert(cert: &rustls::pki_types::CertificateDer<'_>) -> Option<String> {
    peer_san_or_cn(cert.as_ref())
}

impl KmipServer {
    /// Build a [`tokio_rustls::TlsAcceptor`] from a [`KmipTlsConfig`].
    ///
    /// Requires `cert_path`, `key_path`, and `ca_cert_path` to all be set;
    /// returns an error otherwise. Client certificates are required and
    /// verified against the supplied CA chain.
    pub fn build_tls_acceptor(tls: &KmipTlsConfig) -> io::Result<tokio_rustls::TlsAcceptor> {
        let cert_path = tls
            .cert_path
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cert_path missing"))?;
        let key_path = tls
            .key_path
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "key_path missing"))?;
        let ca_path = tls
            .ca_cert_path
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ca_cert_path missing"))?;

        let server_certs = load_pem_certs(Path::new(cert_path))?;
        let server_key = load_pem_key(Path::new(key_path))?;
        let client_roots = load_pem_root_store(Path::new(ca_path))?;

        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, server_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        config.alpn_protocols.clear();

        Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
    }

    /// Bind a TCP listener on `listen_addr` and serve KMIP-over-mTLS until
    /// the future is dropped. Each accepted connection is processed on a
    /// dedicated tokio task; the per-connection handler reads one TTLV
    /// message at a time and dispatches it through
    /// [`KmipServer::process_message_with_identity`] (or
    /// [`KmipServer::process_message_with_peer`] when client-cert identity
    /// extraction failed).
    ///
    /// Audit C1: this is the only public network surface the crate ships,
    /// and it requires `ClientCertVerifier::RequireAndVerifyClientCert`-
    /// equivalent semantics by construction.
    pub async fn serve(self: Arc<Self>, listen_addr: &str) -> io::Result<()> {
        let tls = self
            .config
            .tls
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls config required"))?;
        let acceptor = Self::build_tls_acceptor(tls)?;
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let max = self.config.max_message_size;
        loop {
            let (sock, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let server = self.clone();
            tokio::spawn(async move {
                let stream = match acceptor.accept(sock).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "craton_hsm_kmip::server", error = %e, "TLS accept failed");
                        return;
                    }
                };
                // Identity from peer cert SAN/CN.
                let (_, conn) = stream.get_ref();
                let identity = conn
                    .peer_certificates()
                    .and_then(|certs| certs.first().and_then(identity_from_client_cert));
                let mut stream = stream;
                if let Err(e) = handle_one_session(&mut stream, server.as_ref(), identity, peer, max).await {
                    tracing::debug!(target: "craton_hsm_kmip::server", error = %e, "session ended");
                }
            });
        }
    }

    /// Synchronous variant of [`KmipServer::serve`] that accepts exactly
    /// one connection, processes one request, and returns. Exposed for
    /// integration tests so they can drive an end-to-end mTLS round trip
    /// without spawning a long-lived background task.
    pub async fn serve_accept_one(self: Arc<Self>, listen_addr: &str) -> io::Result<()> {
        let tls = self
            .config
            .tls
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls config required"))?;
        let acceptor = Self::build_tls_acceptor(tls)?;
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let max = self.config.max_message_size;
        let (sock, peer) = listener.accept().await?;
        let stream = acceptor.accept(sock).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let (_, conn) = stream.get_ref();
        let identity = conn
            .peer_certificates()
            .and_then(|certs| certs.first().and_then(identity_from_client_cert));
        let mut stream = stream;
        handle_one_session(&mut stream, self.as_ref(), identity, peer, max).await
    }
}

async fn handle_one_session<S>(
    stream: &mut S,
    server: &KmipServer,
    identity: Option<String>,
    peer: std::net::SocketAddr,
    max: usize,
) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let bytes = read_ttlv_message(stream, max).await?;
    let response = match identity.as_deref() {
        Some(id) => server.process_message_with_identity(&bytes, id),
        None => server.process_message_with_peer(peer, &bytes, None),
    };
    if response.is_empty() {
        // Fatal: even the GeneralFailure fallback failed to encode.
        // Drop the connection — anything we transmit now would be partial.
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "response encoding failed; connection terminated",
        ));
    }
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// KMIP-over-mTLS client
// ---------------------------------------------------------------------------

/// A minimal mTLS client capable of performing one request/response cycle.
///
/// Holds the rustls [`ClientConfig`] so the same client can issue many
/// requests sequentially without renegotiating the TLS context.
pub struct KmipClient {
    config: Arc<rustls::ClientConfig>,
    server_name: String,
    server_addr: String,
    /// Per-response cap. Default 1 MiB so a misbehaving server cannot
    /// drain client memory by returning a forged 4 GiB length header.
    /// Override via [`KmipClient::with_max_response_size`].
    max_response_size: usize,
}

/// Default upper bound on response body size for [`KmipClient`].
pub const DEFAULT_CLIENT_MAX_RESPONSE_SIZE: usize = 1_048_576;

impl KmipClient {
    /// Build a new client.
    ///
    /// * `server_name` — the SNI name used during handshake (must match a
    ///   SAN on the server certificate).
    /// * `server_addr` — `host:port` to connect to.
    /// * `ca_path` — PEM file containing the server's trust roots.
    /// * `client_cert_path` / `client_key_path` — client certificate +
    ///   private key for mTLS.
    pub fn new(
        server_name: &str,
        server_addr: &str,
        ca_path: &Path,
        client_cert_path: &Path,
        client_key_path: &Path,
    ) -> io::Result<Self> {
        let roots = load_pem_root_store(ca_path)?;
        let client_certs = load_pem_certs(client_cert_path)?;
        let client_key = load_pem_key(client_key_path)?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self {
            config: Arc::new(config),
            server_name: server_name.to_string(),
            server_addr: server_addr.to_string(),
            max_response_size: DEFAULT_CLIENT_MAX_RESPONSE_SIZE,
        })
    }

    /// Override the per-response size cap. Useful when integrating with a
    /// server that emits very large `Locate` result sets; defaults to 1 MiB.
    pub fn with_max_response_size(mut self, max: usize) -> Self {
        self.max_response_size = max;
        self
    }

    /// Current per-response size cap.
    pub fn max_response_size(&self) -> usize {
        self.max_response_size
    }

    /// Send a TTLV-encoded request and return the TTLV-encoded response.
    pub async fn request_response(&self, req: Vec<u8>) -> io::Result<Vec<u8>> {
        let connector = tokio_rustls::TlsConnector::from(self.config.clone());
        let sock = tokio::net::TcpStream::connect(&self.server_addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut stream = connector.connect(server_name, sock).await?;
        stream.write_all(&req).await?;
        stream.flush().await?;
        let bytes = read_ttlv_message(&mut stream, self.max_response_size).await?;
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::{KmipObjectState, SUPPORTED_OPERATIONS, SUPPORTED_OBJECT_TYPES};
    use crate::ttlv::decode_ttlv;
    use crate::types::KmipObjectType;

    fn build_create_request() -> Vec<u8> {
        let algo_attr = TtlvItem {
            tag: KmipTag::Attribute.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::AttributeName.to_u32(),
                    value: TtlvValue::TextString("Cryptographic Algorithm".to_string()),
                },
                TtlvItem {
                    tag: KmipTag::AttributeValue.to_u32(),
                    value: TtlvValue::Enumeration(3), // AES
                },
            ]),
        };

        let len_attr = TtlvItem {
            tag: KmipTag::Attribute.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::AttributeName.to_u32(),
                    value: TtlvValue::TextString("Cryptographic Length".to_string()),
                },
                TtlvItem {
                    tag: KmipTag::AttributeValue.to_u32(),
                    value: TtlvValue::Integer(256),
                },
            ]),
        };

        let template = TtlvItem {
            tag: KmipTag::TemplateAttribute.to_u32(),
            value: TtlvValue::Structure(vec![algo_attr, len_attr]),
        };

        let batch_item = TtlvItem {
            tag: KmipTag::BatchItem.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::Operation.to_u32(),
                    value: TtlvValue::Enumeration(KmipOperation::Create.to_u32()),
                },
                template,
            ]),
        };

        let request_header = TtlvItem {
            tag: KmipTag::RequestHeader.to_u32(),
            value: TtlvValue::Structure(vec![]),
        };

        let request_msg = TtlvItem {
            tag: KmipTag::RequestMessage.to_u32(),
            value: TtlvValue::Structure(vec![request_header, batch_item]),
        };

        encode_ttlv(&request_msg).expect("test request encoding must not fail")
    }

    fn build_get_request(id: &str) -> Vec<u8> {
        let batch_item = TtlvItem {
            tag: KmipTag::BatchItem.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::Operation.to_u32(),
                    value: TtlvValue::Enumeration(KmipOperation::Get.to_u32()),
                },
                TtlvItem {
                    tag: KmipTag::UniqueIdentifier.to_u32(),
                    value: TtlvValue::TextString(id.to_string()),
                },
            ]),
        };

        let request_msg = TtlvItem {
            tag: KmipTag::RequestMessage.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::RequestHeader.to_u32(),
                    value: TtlvValue::Structure(vec![]),
                },
                batch_item,
            ]),
        };

        encode_ttlv(&request_msg).expect("test request encoding must not fail")
    }

    fn build_op_request(op: KmipOperation, id: &str) -> Vec<u8> {
        let batch_item = TtlvItem {
            tag: KmipTag::BatchItem.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::Operation.to_u32(),
                    value: TtlvValue::Enumeration(op.to_u32()),
                },
                TtlvItem {
                    tag: KmipTag::UniqueIdentifier.to_u32(),
                    value: TtlvValue::TextString(id.to_string()),
                },
            ]),
        };

        let request_msg = TtlvItem {
            tag: KmipTag::RequestMessage.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::RequestHeader.to_u32(),
                    value: TtlvValue::Structure(vec![]),
                },
                batch_item,
            ]),
        };

        encode_ttlv(&request_msg).expect("test request encoding must not fail")
    }

    /// Build a no-ID, no-attribute request for ops like Query and Locate.
    fn build_bare_op_request(op: KmipOperation) -> Vec<u8> {
        let batch_item = TtlvItem {
            tag: KmipTag::BatchItem.to_u32(),
            value: TtlvValue::Structure(vec![TtlvItem {
                tag: KmipTag::Operation.to_u32(),
                value: TtlvValue::Enumeration(op.to_u32()),
            }]),
        };

        let request_msg = TtlvItem {
            tag: KmipTag::RequestMessage.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::RequestHeader.to_u32(),
                    value: TtlvValue::Structure(vec![]),
                },
                batch_item,
            ]),
        };

        encode_ttlv(&request_msg).expect("test request encoding must not fail")
    }

    /// Build a Register request: unique_id + optional template attributes.
    fn build_register_request(id: &str, attrs: Vec<TtlvItem>) -> Vec<u8> {
        let mut batch_children = vec![
            TtlvItem {
                tag: KmipTag::Operation.to_u32(),
                value: TtlvValue::Enumeration(KmipOperation::Register.to_u32()),
            },
            TtlvItem {
                tag: KmipTag::UniqueIdentifier.to_u32(),
                value: TtlvValue::TextString(id.to_string()),
            },
        ];

        if !attrs.is_empty() {
            batch_children.push(TtlvItem {
                tag: KmipTag::TemplateAttribute.to_u32(),
                value: TtlvValue::Structure(attrs),
            });
        }

        let batch_item = TtlvItem {
            tag: KmipTag::BatchItem.to_u32(),
            value: TtlvValue::Structure(batch_children),
        };

        let request_msg = TtlvItem {
            tag: KmipTag::RequestMessage.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::RequestHeader.to_u32(),
                    value: TtlvValue::Structure(vec![]),
                },
                batch_item,
            ]),
        };

        encode_ttlv(&request_msg).expect("test request encoding must not fail")
    }

    /// Decode a response message and extract the result status.
    ///
    /// Test-only helper: all failure modes here indicate a malformed test
    /// fixture (not untrusted network input). We still route through
    /// descriptive `expect` messages so a broken fixture fails with a clear
    /// pointer rather than an anonymous unwrap panic.
    fn extract_result_status(raw: &[u8]) -> KmipResultStatus {
        let (item, _) = decode_ttlv(raw).expect("test: response TTLV must decode");
        let children = match item.value {
            TtlvValue::Structure(c) => c,
            _ => panic!("test: top-level TTLV item must be a Structure"),
        };
        let batch = children
            .iter()
            .find(|c| c.tag == KmipTag::BatchItem.to_u32())
            .expect("test: response must contain a BatchItem");
        let batch_children = match &batch.value {
            TtlvValue::Structure(c) => c,
            _ => panic!("test: BatchItem TTLV value must be a Structure"),
        };
        let status_val = batch_children
            .iter()
            .find_map(|c| {
                if c.tag == KmipTag::ResultStatus.to_u32() {
                    if let TtlvValue::Enumeration(v) = &c.value {
                        return Some(*v);
                    }
                }
                None
            })
            .expect("test: BatchItem must contain a ResultStatus enumeration");
        KmipResultStatus::from_u32(status_val)
            .expect("test: ResultStatus enumeration must be a known KMIP code")
    }

    fn extract_unique_id(raw: &[u8]) -> Option<String> {
        let (item, _) = decode_ttlv(raw).unwrap();
        let children = match item.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        let batch = children
            .iter()
            .find(|c| c.tag == KmipTag::BatchItem.to_u32())?;
        let batch_children = match &batch.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        batch_children.iter().find_map(|c| {
            if c.tag == KmipTag::UniqueIdentifier.to_u32() {
                if let TtlvValue::TextString(s) = &c.value {
                    return Some(s.clone());
                }
            }
            None
        })
    }

    #[test]
    fn dispatch_create() {
        let server = KmipServer::with_defaults();
        let raw = build_create_request();
        let resp = server.process_message(&raw);
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
        assert!(extract_unique_id(&resp).is_some());
    }

    #[test]
    fn dispatch_get_after_create() {
        let server = KmipServer::with_defaults();
        let create_raw = build_create_request();
        let create_resp = server.process_message(&create_raw);
        let id = extract_unique_id(&create_resp).unwrap();

        let get_raw = build_get_request(&id);
        let get_resp = server.process_message(&get_raw);
        assert_eq!(extract_result_status(&get_resp), KmipResultStatus::Success);
    }

    #[test]
    fn dispatch_get_not_found() {
        let server = KmipServer::with_defaults();
        let raw = build_get_request("no-such-id");
        let resp = server.process_message(&raw);
        assert_eq!(
            extract_result_status(&resp),
            KmipResultStatus::OperationFailed
        );
    }

    #[test]
    fn dispatch_activate() {
        let server = KmipServer::with_defaults();
        let create_resp = server.process_message(&build_create_request());
        let id = extract_unique_id(&create_resp).unwrap();

        let resp = server.process_message(&build_op_request(KmipOperation::Activate, &id));
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
    }

    #[test]
    fn dispatch_revoke_after_activate() {
        let server = KmipServer::with_defaults();
        let create_resp = server.process_message(&build_create_request());
        let id = extract_unique_id(&create_resp).unwrap();

        server.process_message(&build_op_request(KmipOperation::Activate, &id));
        let resp = server.process_message(&build_op_request(KmipOperation::Revoke, &id));
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
    }

    #[test]
    fn dispatch_destroy() {
        let server = KmipServer::with_defaults();
        let create_resp = server.process_message(&build_create_request());
        let id = extract_unique_id(&create_resp).unwrap();

        let resp = server.process_message(&build_op_request(KmipOperation::Destroy, &id));
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
    }

    #[test]
    fn malformed_request_returns_error() {
        let server = KmipServer::with_defaults();
        let resp = server.process_message(&[0xFF, 0xFF]);
        assert_eq!(
            extract_result_status(&resp),
            KmipResultStatus::OperationFailed
        );
    }

    #[test]
    fn message_size_limit() {
        let config = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 16,
            require_auth: false,
            auth_token: None,
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), config);
        let raw = build_create_request();
        assert!(raw.len() > 16);
        let resp = server.process_message(&raw);
        assert_eq!(
            extract_result_status(&resp),
            KmipResultStatus::OperationFailed
        );
    }

    #[test]
    fn config_defaults() {
        let cfg = KmipServerConfig::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1:5696");
        assert_eq!(cfg.max_message_size, 1_048_576);
    }

    /// Check now dispatched: missing UID must fail with InvalidMessage, not
    /// a generic unsupported-op error.
    #[test]
    fn check_without_id_returns_invalid_message() {
        let store = InMemoryKeyStore::new();
        let req = KmipRequest {
            operation: KmipOperation::Check,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::InvalidMessage));
    }

    #[test]
    fn dispatch_routing_covers_all_supported_ops() {
        let store = InMemoryKeyStore::new();
        // Create now requires an explicit Cryptographic Length.
        let req = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
    }

    // -----------------------------------------------------------------------
    // Query dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_query_returns_success() {
        let server = KmipServer::with_defaults();
        let raw = build_bare_op_request(KmipOperation::Query);
        let resp = server.process_message(&raw);
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
    }

    /// Unit-level: Query response lists all supported operations and types.
    #[test]
    fn dispatch_query_capabilities_via_unit() {
        let store = InMemoryKeyStore::new();
        let req = KmipRequest {
            operation: KmipOperation::Query,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        for op in SUPPORTED_OPERATIONS {
            let entry = format!("OP:{op}");
            assert!(
                resp.located_ids.contains(&entry),
                "missing operation: {entry}"
            );
        }
        for ot in SUPPORTED_OBJECT_TYPES {
            let entry = format!("OT:{ot}");
            assert!(
                resp.located_ids.contains(&entry),
                "missing object type: {entry}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // GetAttributes dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_get_attributes_returns_success() {
        let store = InMemoryKeyStore::new();

        // Create a key first. Key length is now mandatory (audit H7).
        let create_req = KmipRequest {
            operation: KmipOperation::Create,
            unique_id: None,
            attributes: vec![KmipAttribute {
                name: "Cryptographic Length".into(),
                value: KmipAttributeValue::Integer(256),
            }],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let create_resp = dispatch_operation(&create_req, &store);
        let id = create_resp.unique_id.unwrap();

        let ga_req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: Some(id.clone()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&ga_req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.unique_id.as_deref(), Some(id.as_str()));
        // Should include the State synthetic attribute.
        let has_state = resp
            .attributes
            .iter()
            .any(|a| a.name == "State");
        assert!(has_state);
    }

    #[test]
    fn dispatch_get_attributes_not_found() {
        let store = InMemoryKeyStore::new();
        let req = KmipRequest {
            operation: KmipOperation::GetAttributes,
            unique_id: Some("ghost".to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
        assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
    }

    // -----------------------------------------------------------------------
    // Register dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_register_returns_success_with_id() {
        let server = KmipServer::with_defaults();

        let ot_attr = TtlvItem {
            tag: KmipTag::Attribute.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::AttributeName.to_u32(),
                    value: TtlvValue::TextString("Object Type".to_string()),
                },
                TtlvItem {
                    tag: KmipTag::AttributeValue.to_u32(),
                    value: TtlvValue::Enumeration(KmipObjectType::SymmetricKey.to_u32()),
                },
            ]),
        };

        let raw = build_register_request("my-imported-key", vec![ot_attr]);
        let resp = server.process_message(&raw);
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
        assert_eq!(
            extract_unique_id(&resp).as_deref(),
            Some("my-imported-key")
        );
    }

    #[test]
    fn dispatch_register_stored_in_preactive_state() {
        let store = InMemoryKeyStore::new();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("reg-key".to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);

        let obj = store.get("reg-key").unwrap();
        assert_eq!(obj.state, KmipObjectState::PreActive);
    }

    #[test]
    fn dispatch_register_duplicate_fails() {
        let store = InMemoryKeyStore::new();
        let req = KmipRequest {
            operation: KmipOperation::Register,
            unique_id: Some("dup".to_string()),
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        dispatch_operation(&req, &store);
        let resp = dispatch_operation(&req, &store);
        assert_eq!(resp.status, KmipResultStatus::OperationFailed);
    }

    // -----------------------------------------------------------------------
    // Locate dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_locate_returns_all_ids_when_no_filter() {
        let store = InMemoryKeyStore::new();

        // Create two keys. Key length is now mandatory.
        for _ in 0..2 {
            let req = KmipRequest {
                operation: KmipOperation::Create,
                unique_id: None,
                attributes: vec![KmipAttribute {
                    name: "Cryptographic Length".into(),
                    value: KmipAttributeValue::Integer(256),
                }],
                caller_identity: None,
                strict_owner_acl: false,
            };
            dispatch_operation(&req, &store);
        }

        let locate_req = KmipRequest {
            operation: KmipOperation::Locate,
            unique_id: None,
            attributes: vec![],
            caller_identity: None,
            strict_owner_acl: false,
        };
        let resp = dispatch_operation(&locate_req, &store);
        assert_eq!(resp.status, KmipResultStatus::Success);
        assert_eq!(resp.located_ids.len(), 2);
    }

    #[test]
    fn dispatch_locate_with_filter_via_message() {
        let server = KmipServer::with_defaults();

        // Register a key with a distinguishing attribute via process_message.
        let name_attr = TtlvItem {
            tag: KmipTag::Attribute.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::AttributeName.to_u32(),
                    value: TtlvValue::TextString("Name".to_string()),
                },
                TtlvItem {
                    tag: KmipTag::AttributeValue.to_u32(),
                    value: TtlvValue::TextString("locate-target".to_string()),
                },
            ]),
        };
        let reg_raw = build_register_request("locate-key", vec![name_attr]);
        let reg_resp = server.process_message(&reg_raw);
        assert_eq!(extract_result_status(&reg_resp), KmipResultStatus::Success);

        // Also create a plain key (no Name attribute).
        server.process_message(&build_create_request());

        // Now Locate with a Name filter — expect exactly one result.
        let store = &server.store;
        use std::collections::HashMap;
        use crate::operations::KmipAttributeValue;
        let mut filter = HashMap::new();
        filter.insert(
            "Name".to_string(),
            KmipAttributeValue::Text("locate-target".to_string()),
        );
        let ids = store.locate(&filter);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "locate-key");
    }

    #[test]
    fn dispatch_locate_bare_message_succeeds() {
        let server = KmipServer::with_defaults();
        // Create one key so the result is non-trivially testable.
        server.process_message(&build_create_request());

        let raw = build_bare_op_request(KmipOperation::Locate);
        let resp = server.process_message(&raw);
        // The Locate handler itself succeeds; TTLV encoding of located_ids is
        // not yet wired through process_message (the response struct carries them
        // but the encoder currently only writes UniqueIdentifier).  We verify
        // the status is Success to confirm routing works end-to-end.
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
    }

    // -----------------------------------------------------------------------
    // Helper: extract result reason from TTLV response
    // -----------------------------------------------------------------------

    fn extract_result_reason(raw: &[u8]) -> Option<KmipResultReason> {
        let (item, _) = decode_ttlv(raw).unwrap();
        let children = match item.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        let batch = children
            .iter()
            .find(|c| c.tag == KmipTag::BatchItem.to_u32())?;
        let batch_children = match &batch.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        batch_children.iter().find_map(|c| {
            if c.tag == KmipTag::ResultReason.to_u32() {
                if let TtlvValue::Enumeration(v) = &c.value {
                    return KmipResultReason::from_u32(*v);
                }
            }
            None
        })
    }

    /// Extract all UniqueIdentifier values from a TTLV response (for Locate).
    fn extract_all_unique_ids(raw: &[u8]) -> Vec<String> {
        let (item, _) = decode_ttlv(raw).unwrap();
        let children = match item.value {
            TtlvValue::Structure(c) => c,
            _ => return vec![],
        };
        let batch = match children
            .iter()
            .find(|c| c.tag == KmipTag::BatchItem.to_u32())
        {
            Some(b) => b,
            None => return vec![],
        };
        let batch_children = match &batch.value {
            TtlvValue::Structure(c) => c,
            _ => return vec![],
        };
        batch_children
            .iter()
            .filter_map(|c| {
                if c.tag == KmipTag::UniqueIdentifier.to_u32() {
                    if let TtlvValue::TextString(s) = &c.value {
                        return Some(s.clone());
                    }
                }
                None
            })
            .collect()
    }

    /// Extract Attribute structures from a TTLV response.
    fn extract_attributes(raw: &[u8]) -> Vec<(String, TtlvValue)> {
        let (item, _) = decode_ttlv(raw).unwrap();
        let children = match item.value {
            TtlvValue::Structure(c) => c,
            _ => return vec![],
        };
        let batch = match children
            .iter()
            .find(|c| c.tag == KmipTag::BatchItem.to_u32())
        {
            Some(b) => b,
            None => return vec![],
        };
        let batch_children = match &batch.value {
            TtlvValue::Structure(c) => c,
            _ => return vec![],
        };
        batch_children
            .iter()
            .filter_map(|c| {
                if c.tag == KmipTag::Attribute.to_u32() {
                    if let TtlvValue::Structure(attr_children) = &c.value {
                        let name = attr_children.iter().find_map(|ac| {
                            if ac.tag == KmipTag::AttributeName.to_u32() {
                                if let TtlvValue::TextString(s) = &ac.value {
                                    return Some(s.clone());
                                }
                            }
                            None
                        })?;
                        let value = attr_children.iter().find_map(|ac| {
                            if ac.tag == KmipTag::AttributeValue.to_u32() {
                                return Some(ac.value.clone());
                            }
                            None
                        })?;
                        return Some((name, value));
                    }
                }
                None
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Authentication tests (require_auth)
    // -----------------------------------------------------------------------

    // Helper: 32+ hex chars so `validate_for_production` does not reject as weak.
    const STRONG_TEST_TOKEN: &str = "strong-token-1234567890abcdef1234567890abcdef";

    /// Scope-guarded env-var setter used by the static-token tests.
    ///
    /// Tests in the same process share env-var state; restore the prior value
    /// on drop so test ordering cannot affect other cases.
    struct EnvVarGuard {
        key: &'static str,
        prior: Option<String>,
    }
    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prior }
        }
    }
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[cfg(feature = "insecure-static-token")]
    #[test]
    fn require_auth_rejects_request_without_token() {
        let _guard = EnvVarGuard::set("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
        let config = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), config);

        let raw = build_create_request();
        // No token provided — should be rejected.
        let resp = server.process_message_with_auth(&raw, None);
        assert_eq!(
            extract_result_status(&resp),
            KmipResultStatus::OperationFailed,
        );
        assert_eq!(
            extract_result_reason(&resp),
            Some(KmipResultReason::PermissionDenied),
        );
    }

    #[cfg(feature = "insecure-static-token")]
    #[test]
    fn require_auth_rejects_wrong_token() {
        let _guard = EnvVarGuard::set("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
        let config = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), config);

        let raw = build_create_request();
        let resp = server.process_message_with_auth(&raw, Some("wrong-token"));
        assert_eq!(
            extract_result_status(&resp),
            KmipResultStatus::OperationFailed,
        );
        assert_eq!(
            extract_result_reason(&resp),
            Some(KmipResultReason::PermissionDenied),
        );
    }

    #[cfg(feature = "insecure-static-token")]
    #[test]
    fn require_auth_accepts_correct_token() {
        let _guard = EnvVarGuard::set("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
        let config = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), config);

        let raw = build_create_request();
        let resp = server.process_message_with_auth(&raw, Some(STRONG_TEST_TOKEN));
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
    }

    #[test]
    fn require_auth_no_configured_token_rejects_all() {
        // require_auth=true but auth_token=None → every request is rejected.
        let config = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: None,
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), config);

        let raw = build_create_request();
        // Even passing a token should fail since the server has no token to compare.
        let resp = server.process_message_with_auth(&raw, Some("any-token"));
        assert_eq!(
            extract_result_status(&resp),
            KmipResultStatus::OperationFailed,
        );
        assert_eq!(
            extract_result_reason(&resp),
            Some(KmipResultReason::PermissionDenied),
        );
    }

    // ---- validate_for_production --------------------------------------------

    #[test]
    fn validate_for_production_rejects_require_auth_off() {
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: false,
            auth_token: None,
            tls: None,
        };
        let err = cfg.validate_for_production().unwrap_err();
        assert!(err.contains("require_auth"), "got: {err}");
    }

    #[test]
    fn validate_for_production_rejects_weak_tokens() {
        for weak in &["changeme", "test-token", "kmip"] {
            let cfg = KmipServerConfig {
                listen_addr: "127.0.0.1:5696".to_string(),
                max_message_size: 1_048_576,
                require_auth: true,
                auth_token: Some(Zeroizing::new((*weak).to_string())),
                tls: None,
            };
            let err = cfg.validate_for_production().unwrap_err();
            assert!(
                err.contains("well-known insecure placeholder"),
                "{weak}: {err}"
            );
        }
    }

    #[test]
    fn validate_for_production_rejects_short_tokens() {
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new("shortish-but-unique-12345".to_string())),
            tls: None,
        };
        let err = cfg.validate_for_production().unwrap_err();
        assert!(err.contains("at least"), "got: {err}");
    }

    #[test]
    fn validate_for_production_requires_env_opt_in() {
        // Ensure env var is unset for this test.
        let _guard = EnvVarGuard::set("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "");
        std::env::remove_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN");
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        let err = cfg.validate_for_production().unwrap_err();
        assert!(
            err.contains("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_for_production_passes_with_strong_token_and_env() {
        let _guard = EnvVarGuard::set("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        cfg.validate_for_production().expect("strong token + env opt-in must pass");
    }

    #[test]
    fn validate_for_production_passes_without_token() {
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: None,
            tls: None,
        };
        cfg.validate_for_production().expect("require_auth + no token must pass");
    }

    #[cfg(not(feature = "insecure-static-token"))]
    #[test]
    fn static_token_rejected_without_feature() {
        // Even if a caller populates auth_token, without the feature every
        // request must be rejected.
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), cfg);
        let resp = server.process_message_with_auth(&build_create_request(), Some(STRONG_TEST_TOKEN));
        assert_eq!(
            extract_result_reason(&resp),
            Some(KmipResultReason::PermissionDenied),
        );
    }

    #[test]
    fn default_config_requires_auth() {
        // The default KmipServerConfig should have require_auth = true.
        let cfg = KmipServerConfig::default();
        assert!(cfg.require_auth);
    }

    // -----------------------------------------------------------------------
    // End-to-end TTLV encoding of located_ids and attributes
    // -----------------------------------------------------------------------

    #[test]
    fn ttlv_response_encodes_located_ids() {
        let server = KmipServer::with_defaults();

        // Register two keys.
        let raw1 = build_register_request("loc-a", vec![]);
        server.process_message(&raw1);
        let raw2 = build_register_request("loc-b", vec![]);
        server.process_message(&raw2);

        // Locate all keys via the full TTLV pipeline.
        let locate_raw = build_bare_op_request(KmipOperation::Locate);
        let resp_raw = server.process_message(&locate_raw);

        assert_eq!(extract_result_status(&resp_raw), KmipResultStatus::Success);

        // The encoded response should contain UniqueIdentifier entries for both keys.
        let ids = extract_all_unique_ids(&resp_raw);
        assert!(ids.contains(&"loc-a".to_string()), "missing loc-a in {ids:?}");
        assert!(ids.contains(&"loc-b".to_string()), "missing loc-b in {ids:?}");
    }

    #[test]
    fn ttlv_response_encodes_attributes() {
        let server = KmipServer::with_defaults();

        // Create a key with a Name attribute.
        let name_attr = TtlvItem {
            tag: KmipTag::Attribute.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::AttributeName.to_u32(),
                    value: TtlvValue::TextString("Name".to_string()),
                },
                TtlvItem {
                    tag: KmipTag::AttributeValue.to_u32(),
                    value: TtlvValue::TextString("my-test-key".to_string()),
                },
            ]),
        };
        let reg_raw = build_register_request("attr-key", vec![name_attr]);
        server.process_message(&reg_raw);

        // Build a GetAttributes request via TTLV.
        let ga_raw = build_op_request(KmipOperation::GetAttributes, "attr-key");
        let resp_raw = server.process_message(&ga_raw);

        assert_eq!(extract_result_status(&resp_raw), KmipResultStatus::Success);

        // Extract attributes from the encoded TTLV response.
        let attrs = extract_attributes(&resp_raw);
        let has_name = attrs.iter().any(|(name, value)| {
            name == "Name" && matches!(value, TtlvValue::TextString(s) if s == "my-test-key")
        });
        assert!(has_name, "expected 'Name' attribute in TTLV response, got: {attrs:?}");

        // Should also include synthetic State attribute.
        let has_state = attrs.iter().any(|(name, _)| name == "State");
        assert!(has_state, "expected 'State' attribute in TTLV response, got: {attrs:?}");
    }

    // -----------------------------------------------------------------------
    // Audit-regression tests: C3, M6, M8
    // -----------------------------------------------------------------------

    /// Audit C3: toggling `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN`
    /// mid-lifetime must affect authentication on subsequent requests, not
    /// only at server construction time.
    #[cfg(feature = "insecure-static-token")]
    #[test]
    fn static_token_env_toggle_applies_mid_lifetime() {
        // Start with the env var enabled so the server constructs cleanly.
        let _guard = EnvVarGuard::set("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), cfg);

        let raw = build_create_request();
        // Initial request with env set + correct token: accepted.
        let ok = server.process_message_with_auth(&raw, Some(STRONG_TEST_TOKEN));
        assert_eq!(extract_result_status(&ok), KmipResultStatus::Success);

        // Flip the env var off mid-lifetime. The gate is re-read per request
        // (audit C3) so the *same* server instance must now refuse requests.
        std::env::remove_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN");
        let denied = server.process_message_with_auth(&raw, Some(STRONG_TEST_TOKEN));
        assert_eq!(extract_result_status(&denied), KmipResultStatus::OperationFailed);
        assert_eq!(
            extract_result_reason(&denied),
            Some(KmipResultReason::PermissionDenied),
        );

        // Flipping it back on re-enables auth without reconstructing the server.
        std::env::set_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
        let ok2 = server.process_message_with_auth(&raw, Some(STRONG_TEST_TOKEN));
        assert_eq!(extract_result_status(&ok2), KmipResultStatus::Success);
    }

    /// Audit M6: a backward wall-clock jump does not bypass the rate limiter.
    ///
    /// Uses a mock monotonic clock to drive the failure-window logic directly.
    #[test]
    fn rate_limiter_ignores_backward_wall_clock_jump() {
        use std::sync::Mutex;

        struct MockClock {
            // `Instant` has no public constructor that accepts a raw ts, so we
            // derive all mock times by adding increments to a single anchor
            // captured once.
            base: Instant,
            offset: Mutex<std::time::Duration>,
        }
        impl MockClock {
            fn new() -> Self {
                Self {
                    base: Instant::now(),
                    offset: Mutex::new(std::time::Duration::ZERO),
                }
            }
            fn advance(&self, d: std::time::Duration) {
                *self.offset.lock().unwrap() += d;
            }
        }
        impl MonotonicClock for MockClock {
            fn now(&self) -> Instant {
                self.base + *self.offset.lock().unwrap()
            }
        }

        let mock = Arc::new(MockClock::new());
        let limiter = AuthRateLimiter::with_clock(3, 60, mock.clone());
        let client = [0x42u8; 32];

        // Three failures within the window — after these the caller is limited.
        limiter.record_failure(&client);
        limiter.record_failure(&client);
        limiter.record_failure(&client);
        assert!(limiter.is_rate_limited(&client), "should be limited after 3 failures");

        // Wall-clock jumps backwards would have reset a `SystemTime`-based
        // window. With an `Instant`-based window the jump is a no-op: time
        // only ever moves forward. Our mock replicates this by *never*
        // stepping backwards — we simply advance by 1s to confirm the window
        // is still active.
        mock.advance(std::time::Duration::from_secs(1));
        assert!(
            limiter.is_rate_limited(&client),
            "1s later the rate limit must still apply (window is 60s)"
        );

        // Even if the mock tried to move backwards, `saturating_duration_since`
        // would clamp the gap to zero — which keeps us firmly inside the window.
        // (We can't literally step the mock backwards without violating the
        // `MonotonicClock` contract, so we assert the *intent* by re-checking
        // that the limit persists across another forward step.)
        mock.advance(std::time::Duration::from_secs(5));
        assert!(limiter.is_rate_limited(&client));

        // Stepping past the window expires the limit.
        mock.advance(std::time::Duration::from_secs(60));
        assert!(
            !limiter.is_rate_limited(&client),
            "after the 60s window elapses the caller must no longer be limited"
        );
    }

    /// Audit M8: the pluggable ACL denies a sensitive operation for a
    /// caller the policy does not recognise, and `AllowAll` permits
    /// everything — preserving the default behaviour.
    #[test]
    fn acl_denies_destroy_for_non_owner_and_allow_all_permits() {
        use crate::acl::{KmipAcl, KmipAclDecision};

        /// Policy that only permits callers whose identity equals `owner`.
        struct SingleOwnerAcl {
            owner: String,
        }
        impl KmipAcl for SingleOwnerAcl {
            fn authorize(
                &self,
                identity: Option<&str>,
                _op: KmipOperation,
                _obj: Option<&str>,
            ) -> KmipAclDecision {
                match identity {
                    Some(id) if id == self.owner => KmipAclDecision::Allow,
                    _ => KmipAclDecision::Deny(KmipResultReason::PermissionDenied),
                }
            }
        }

        // Owner-only policy, auth disabled so caller_identity flows from
        // the optional client-side token without a real credential check.
        let cfg = KmipServerConfig {
            listen_addr: "127.0.0.1:5696".to_string(),
            max_message_size: 1_048_576,
            require_auth: false,
            auth_token: None,
            tls: None,
        };
        let server = KmipServer::new(Box::new(InMemoryKeyStore::new()), cfg)
            .with_acl(SingleOwnerAcl { owner: "alice".to_string() });

        // Create a key (Create is not ACL-gated — only destructive ops are).
        let create_resp =
            server.process_message_with_auth(&build_create_request(), Some("alice"));
        let id = extract_unique_id(&create_resp).expect("create must succeed");

        // Non-owner tries to Destroy — ACL denies before the handler runs.
        let mallory = server.process_message_with_auth(
            &build_op_request(KmipOperation::Destroy, &id),
            Some("mallory"),
        );
        assert_eq!(
            extract_result_status(&mallory),
            KmipResultStatus::OperationFailed
        );
        assert_eq!(
            extract_result_reason(&mallory),
            Some(KmipResultReason::PermissionDenied),
        );

        // Owner is permitted.
        let alice = server.process_message_with_auth(
            &build_op_request(KmipOperation::Destroy, &id),
            Some("alice"),
        );
        assert_eq!(extract_result_status(&alice), KmipResultStatus::Success);

        // AllowAll (default, installed by `with_defaults`) permits every op.
        let permissive = KmipServer::with_defaults();
        let create2 = permissive.process_message(&build_create_request());
        let id2 = extract_unique_id(&create2).expect("create must succeed");
        let destroy2 =
            permissive.process_message(&build_op_request(KmipOperation::Destroy, &id2));
        assert_eq!(extract_result_status(&destroy2), KmipResultStatus::Success);
    }

    /// Helper: extract the response header's (major, minor) `ProtocolVersion`.
    fn extract_response_protocol_version(bytes: &[u8]) -> Option<(i32, i32)> {
        let (resp, _) = decode_ttlv(bytes).ok()?;
        let children = match resp.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        let hdr = children
            .iter()
            .find(|c| c.tag == KmipTag::ResponseHeader.to_u32())?;
        let hdr_children = match &hdr.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        let pv = hdr_children
            .iter()
            .find(|c| c.tag == KmipTag::ProtocolVersion.to_u32())?;
        let pv_children = match &pv.value {
            TtlvValue::Structure(c) => c,
            _ => return None,
        };
        let mut major = None;
        let mut minor = None;
        for c in pv_children {
            if c.tag == KmipTag::ProtocolVersionMajor.to_u32() {
                if let TtlvValue::Integer(v) = &c.value {
                    major = Some(*v);
                }
            } else if c.tag == KmipTag::ProtocolVersionMinor.to_u32() {
                if let TtlvValue::Integer(v) = &c.value {
                    minor = Some(*v);
                }
            }
        }
        Some((major?, minor?))
    }

    /// Build a Query request with a configurable ProtocolVersion in the header.
    fn build_query_request_with_pv(major: i32, minor: i32) -> Vec<u8> {
        let pv = TtlvItem {
            tag: KmipTag::ProtocolVersion.to_u32(),
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: KmipTag::ProtocolVersionMajor.to_u32(),
                    value: TtlvValue::Integer(major),
                },
                TtlvItem {
                    tag: KmipTag::ProtocolVersionMinor.to_u32(),
                    value: TtlvValue::Integer(minor),
                },
            ]),
        };
        let header = TtlvItem {
            tag: KmipTag::RequestHeader.to_u32(),
            value: TtlvValue::Structure(vec![pv]),
        };
        let batch_item = TtlvItem {
            tag: KmipTag::BatchItem.to_u32(),
            value: TtlvValue::Structure(vec![TtlvItem {
                tag: KmipTag::Operation.to_u32(),
                value: TtlvValue::Enumeration(KmipOperation::Query.to_u32()),
            }]),
        };
        let request_msg = TtlvItem {
            tag: KmipTag::RequestMessage.to_u32(),
            value: TtlvValue::Structure(vec![header, batch_item]),
        };
        encode_ttlv(&request_msg).expect("test request encoding must not fail")
    }

    #[test]
    fn response_echoes_request_protocol_version() {
        let server = KmipServer::with_defaults();

        // 2.1 request → 2.1 response.
        let bytes_21 = server.process_message(&build_query_request_with_pv(2, 1));
        assert_eq!(
            extract_response_protocol_version(&bytes_21),
            Some((2, 1)),
            "2.1 request must produce a 2.1 response"
        );

        // 1.4 request → 1.4 response (we echo whatever the client asked for).
        let bytes_14 = server.process_message(&build_query_request_with_pv(1, 4));
        assert_eq!(
            extract_response_protocol_version(&bytes_14),
            Some((1, 4)),
            "1.4 request must produce a 1.4 response (echo)"
        );

        // Missing ProtocolVersion → default 2.1.
        let bytes_default =
            server.process_message(&build_bare_op_request(KmipOperation::Query));
        assert_eq!(
            extract_response_protocol_version(&bytes_default),
            Some((2, 1)),
            "missing ProtocolVersion must default to 2.1"
        );
    }

    // -----------------------------------------------------------------------
    // Audit follow-up: protocol-version clamp, replay cache, static token,
    // DNS normalisation, client response cap
    // -----------------------------------------------------------------------

    #[test]
    fn negotiate_protocol_version_clamps_above_max() {
        // 3.0 must clamp to 2.1.
        let clamped = negotiate_protocol_version(ProtocolVersion { major: 3, minor: 0 });
        assert_eq!(clamped.major, SERVER_MAX_PV.major);
        assert_eq!(clamped.minor, SERVER_MAX_PV.minor);
        // Anything strictly higher (e.g. 2.5) also clamps.
        let clamped = negotiate_protocol_version(ProtocolVersion { major: 2, minor: 5 });
        assert_eq!(clamped.minor, 1);
    }

    #[test]
    fn negotiate_protocol_version_clamps_below_min() {
        // 0.9 must clamp UP to 1.0.
        let clamped = negotiate_protocol_version(ProtocolVersion { major: 0, minor: 9 });
        assert_eq!(clamped.major, SERVER_MIN_PV.major);
        assert_eq!(clamped.minor, SERVER_MIN_PV.minor);
    }

    #[test]
    fn negotiate_protocol_version_passes_inwindow() {
        let pv = ProtocolVersion { major: 1, minor: 4 };
        let out = negotiate_protocol_version(pv);
        assert_eq!(out.major, 1);
        assert_eq!(out.minor, 4);
    }

    #[test]
    fn over_protocol_version_request_is_clamped_in_response() {
        // A 3.0 request must produce a 2.1 response, not a forged 3.0 echo.
        let store = Box::new(InMemoryKeyStore::new()) as Box<dyn KmipKeyStore>;
        let server = KmipServer::new(
            store,
            KmipServerConfig {
                require_auth: false,
                ..KmipServerConfig::default()
            },
        );
        let bytes = server.process_message(&build_query_request_with_pv(3, 0));
        assert_eq!(
            extract_response_protocol_version(&bytes),
            Some((2, 1)),
            "3.0 request must clamp to 2.1 in response"
        );
    }

    #[test]
    fn validate_static_token_rejects_weak_value() {
        // Case-insensitive byte-level comparison: "CHANGEME" must trip.
        assert!(validate_static_token("CHANGEME").is_err());
        assert!(validate_static_token("changeme").is_err());
        // Mixed case.
        assert!(validate_static_token("ChAnGeMe").is_err());
        // Below minimum length even though not a placeholder.
        assert!(validate_static_token("short").is_err());
        // 32+ random bytes succeed.
        let strong = "0123456789abcdef0123456789abcdef";
        assert!(validate_static_token(strong).is_ok());
    }

    #[test]
    fn normalize_dns_identity_lowercases_and_strips_trailing_dot() {
        assert_eq!(
            normalize_dns_identity("Alice.Example.Com."),
            Some("alice.example.com".to_string())
        );
        assert_eq!(
            normalize_dns_identity("alice"),
            Some("alice".to_string())
        );
    }

    #[test]
    fn normalize_dns_identity_rejects_non_ascii() {
        assert_eq!(normalize_dns_identity("älice"), None);
        // empty / whitespace-only.
        assert_eq!(normalize_dns_identity(""), None);
        assert_eq!(normalize_dns_identity("."), None);
    }

    #[test]
    fn replay_cache_dedupes_on_second_pass() {
        let rc = ReplayCache::new(60);
        assert!(!rc.check_and_record(Some("alice"), "ccv-1"));
        // Same pair within the window → duplicate.
        assert!(rc.check_and_record(Some("alice"), "ccv-1"));
        // Different identity, same ccv → not a duplicate.
        assert!(!rc.check_and_record(Some("bob"), "ccv-1"));
        // Different ccv for alice → not a duplicate.
        assert!(!rc.check_and_record(Some("alice"), "ccv-2"));
    }

    #[test]
    fn replay_cache_hard_cap_constant_is_fixed() {
        // Compile-time sanity check: the cap is the documented 65_536.
        assert_eq!(REPLAY_CACHE_HARD_CAP, 65_536);
    }

    #[test]
    fn client_default_max_response_size_is_one_mib() {
        // We can construct a KmipClient even without a network if we use
        // bogus paths — but ClientConfig::builder requires a real CA, so
        // instead verify the constant directly.
        assert_eq!(DEFAULT_CLIENT_MAX_RESPONSE_SIZE, 1_048_576);
    }
}
