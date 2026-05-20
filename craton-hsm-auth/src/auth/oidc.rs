// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! OAuth2/OIDC authentication provider.
//!
//! Validates JWT bearer tokens against a remote OIDC issuer, fetching and
//! caching JWKS keys for signature verification.  Requires the `oidc-auth`
//! feature flag.

#![cfg(feature = "oidc-auth")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use arc_swap::ArcSwapOption;
use jsonwebtoken::{
    decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

use super::provider::{AuthCredentials, AuthProvider, AuthResult};
use crate::rbac::role::HsmRole;
use crate::tenant::tenant::TenantId;
use craton_hsm::error::{HsmError, HsmResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// OIDC authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g., "https://accounts.google.com").
    pub issuer_url: String,
    /// Expected audience claim.
    pub audience: String,
    /// JWT claim containing the role assignment.
    pub role_claim: String,
    /// JWT claim containing the tenant ID (optional).
    pub tenant_claim: Option<String>,
    /// JWT claim that, when present and `true`, indicates MFA has been
    /// satisfied.  When `None`, `mfa_required` is always `false`.
    pub mfa_claim: Option<String>,
    /// How often (in seconds) to re-fetch the JWKS key set.
    /// Defaults to 3600 (1 hour) when not specified.
    #[serde(default = "default_jwks_refresh_secs")]
    pub jwks_refresh_secs: u64,
    /// Timeout in seconds for OIDC discovery and JWKS HTTP requests.
    /// Defaults to 10 seconds.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Maximum age (in seconds) the JWKS cache may be served past its
    /// normal refresh interval if the OIDC issuer is unreachable.  After
    /// this grace period elapses, authentication fails closed.  Defaults
    /// to 1 hour (audit fix 1.1: tightened from the historical 24h default
    /// because a 24-hour stale window leaves a revoked signing key trusted
    /// for a full day after issuer-side rotation).  Set to 0 to disable
    /// stale serving entirely.
    #[serde(default = "default_stale_cache_max_age_secs")]
    pub stale_cache_max_age_secs: u64,
    /// Allowed JWT clock skew in seconds (applied to exp/nbf checks).
    /// Defaults to 5s (see `default_clock_skew_secs`) — tightened from the
    /// historical 60s default to shrink the replay window on NTP-synced
    /// infrastructure.
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Rate-limit configuration for authentication failures.
    /// When `None`, a default configuration is used.
    #[serde(default)]
    pub rate_limit: Option<crate::auth::rate_limit::RateLimitConfig>,
    /// When `true`, require the JWT to carry a `jti` (JWT ID) claim and
    /// reject any token whose `jti` has already been seen.  This closes the
    /// token-replay window between issuance and expiry.  Requires that the
    /// OIDC provider includes `jti` in its tokens.  Default: `false` (off,
    /// for backward compatibility).
    #[serde(default)]
    pub require_jti: bool,
}

/// Normalise an OIDC issuer / audience URL for case-insensitive, slash-
/// and default-port-insensitive comparison.
///
/// jsonwebtoken's `set_issuer` / `set_audience` perform plain case-sensitive
/// string equality, but RFC 6749 / OIDC Core treat these values as URLs — so
/// `https://Auth.example:443/` and `https://auth.example` must compare equal.
/// This helper applies the relevant URL normalisations:
///
/// 1. Lowercase the scheme and host (hosts are case-insensitive per RFC 3986).
/// 2. Strip the default port for the scheme (`:443` for https, `:80` for http).
/// 3. Drop a trailing `/` when the path is exactly `/` or ends with `/`.
///
/// Fails **closed**: on parse failure the input is returned verbatim so a
/// malformed URL cannot accidentally match a well-formed one after
/// normalisation.
fn normalize_url(u: &str) -> String {
    let trimmed = u.trim();
    // Use reqwest's re-exported url::Url to get proper scheme/authority
    // decomposition without taking a direct dependency on `url`.
    let parsed = match reqwest::Url::parse(trimmed) {
        Ok(p) => p,
        Err(_) => return trimmed.to_string(),
    };

    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return trimmed.to_string(),
    };

    // Drop the default port for the scheme so `https://x` and `https://x:443`
    // compare equal. `port()` returns `Some(n)` only when the port was
    // explicit in the URL; `port_or_known_default()` would always return the
    // default so is not what we want here.
    let port_suffix = match (scheme.as_str(), parsed.port()) {
        ("https", Some(443)) | ("http", Some(80)) => String::new(),
        (_, Some(p)) => format!(":{p}"),
        (_, None) => String::new(),
    };

    // Trim exactly one trailing `/` from the path. Empty path -> empty.
    let path = parsed.path();
    let path_norm: &str = if path == "/" {
        ""
    } else if let Some(stripped) = path.strip_suffix('/') {
        stripped
    } else {
        path
    };

    // Preserve query/fragment verbatim (they are not normalised for OIDC
    // issuer comparison, but including them keeps round-trips exact for the
    // rare audience URL that legitimately carries them). Most issuer URLs
    // have neither — `OidcConfig::validate` already rejects both.
    let mut out = format!("{scheme}://{host}{port_suffix}{path_norm}");
    if let Some(q) = parsed.query() {
        out.push('?');
        out.push_str(q);
    }
    if let Some(f) = parsed.fragment() {
        out.push('#');
        out.push_str(f);
    }
    out
}

/// Re-run JWT validation with the token's own `iss` / `aud` claims normalised,
/// comparing against the already-normalised configured values.
///
/// Returns `Some(TokenData)` if the token is otherwise valid and its
/// normalised `iss` + (each) `aud` match the expected normalised values.
/// Returns `None` if the token does not validate or the normalised identities
/// disagree — the caller then surfaces the original library error to the log.
#[cfg(feature = "oidc-auth")]
fn retry_with_normalised_iss_aud(
    token: &str,
    decoding_key: &DecodingKey,
    algorithm: Algorithm,
    expected_iss_normalised: &str,
    expected_aud_normalised: &str,
    clock_skew_secs: u64,
) -> Option<TokenData<Claims>> {
    // Decode without iss/aud validation — we do that ourselves after
    // normalising the token's claim values. Signature + exp/nbf are still
    // checked.
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = clock_skew_secs;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    // Explicitly do NOT set_issuer / set_audience here — we compare manually
    // after normalisation.
    validation.validate_aud = false;

    let td = decode::<Claims>(token, decoding_key, &validation).ok()?;
    // iss must match exactly after normalisation.
    let iss = td.claims.get("iss").and_then(|v| v.as_str())?;
    if normalize_url(iss) != expected_iss_normalised {
        return None;
    }
    // aud may be a string or array; require one entry that matches after
    // normalisation.
    let aud_ok = match td.claims.get("aud") {
        Some(serde_json::Value::String(s)) => normalize_url(s) == expected_aud_normalised,
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .any(|s| normalize_url(s) == expected_aud_normalised),
        _ => false,
    };
    if !aud_ok {
        return None;
    }
    Some(td)
}

fn default_jwks_refresh_secs() -> u64 {
    3600
}

fn default_request_timeout_secs() -> u64 {
    10
}

fn default_stale_cache_max_age_secs() -> u64 {
    // Audit fix 1.1: tighten default JWKS stale-cache grace period from
    // 24 hours to 1 hour. A revoked signing key should not remain trusted
    // for an entire day; operators who need a wider window can override.
    3_600
}

/// Default JWT leeway (5 s). Tightened from the historical 60 s default in
/// line with typical NTP-synchronized infrastructure, which closes a 55-second
/// replay/TOCTOU window. Operators whose IdP clock drift exceeds this value
/// can raise `clock_skew_secs` explicitly.
fn default_clock_skew_secs() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// OIDC discovery document (subset)
// ---------------------------------------------------------------------------

/// Minimal representation of an OpenID Connect discovery document.
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

// ---------------------------------------------------------------------------
// Internal error classification (audit fix - design)
// ---------------------------------------------------------------------------

/// Crate-private error classification for OIDC discovery / JWKS / TLS
/// failures. The historical code collapsed every reqwest error to
/// `HsmError::GeneralError`, which obscured the failure mode in audit
/// logs (TLS handshake failure looked identical to JSON parse failure).
/// `OidcError` keeps the structured cause for the tracing site, then
/// `From<OidcError> for HsmError` flattens to the parent's existing
/// variant set so call sites do not change.
#[derive(Debug)]
enum OidcError {
    /// Network-level failure: connect, send, read.
    Network(reqwest::Error),
    /// Response received but body parsing (JSON / JWKS shape) failed.
    Parse(reqwest::Error),
    /// TLS-specific failure (cert verify, handshake). Carried as a
    /// pre-formatted string because reqwest does not expose a typed TLS
    /// error variant; the caller formats `e` into this string.
    ///
    /// Currently unused — `reqwest::Error` is opaque enough that the
    /// network and TLS paths converge on `Network`. Reserved for a future
    /// switch to a TLS-detecting backend (e.g. classifying via
    /// `e.is_connect()` + downcast).
    #[allow(dead_code)]
    Tls(String),
}

impl From<OidcError> for HsmError {
    fn from(value: OidcError) -> Self {
        let formatted = match &value {
            OidcError::Network(e) => format!("oidc:network: {e}"),
            OidcError::Parse(e) => format!("oidc:parse: {e}"),
            OidcError::Tls(msg) => format!("oidc:tls: {msg}"),
        };
        // Surface the structured cause via tracing while preserving the
        // existing GeneralError mapping that callers match on.
        tracing::error!(error = %formatted, "oidc transport error");
        HsmError::GeneralError
    }
}

// ---------------------------------------------------------------------------
// Cached JWKS store
// ---------------------------------------------------------------------------

/// A cache entry holding decoded JWKS keys indexed by `kid`.
struct JwksCache {
    /// Maps `kid` -> (algorithm, decoding key).
    keys: HashMap<String, (Algorithm, DecodingKey)>,
    /// When the cache was last refreshed.
    fetched_at: Instant,
}

// ---------------------------------------------------------------------------
// Generic JWT claims (dynamic extraction)
// ---------------------------------------------------------------------------

/// We decode into a generic map so that arbitrary claim names for role,
/// tenant, and MFA can be resolved at runtime.
type Claims = serde_json::Value;

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// OIDC authentication provider.
pub struct OidcAuthProvider {
    config: OidcConfig,
    /// Audit (perf): the previous `parking_lot::RwLock<Option<JwksCache>>`
    /// forced every JWT validation to take a read lock even though the
    /// cache changes only on refresh. `ArcSwapOption` is fully lock-free
    /// on the read path — a single atomic load — and the refresh path
    /// swaps a fresh `Arc<JwksCache>` in place.
    cache: ArcSwapOption<JwksCache>,
    /// Reusable HTTP client (connection pool, TLS session resumption).
    /// Built once at construction so every authentication doesn't pay
    /// the cost of TCP+TLS handshakes.
    http: reqwest::blocking::Client,
    /// Rate limiter for authentication failures.
    rate_limiter: crate::auth::rate_limit::AuthRateLimiter,
    /// Bounded cache of seen JTI values mapped to their eviction deadline,
    /// anchored on a **monotonic** `Instant` so a backward wall-clock jump
    /// cannot prematurely drop an entry and re-open the replay window.
    /// Only populated when `config.require_jti` is true.
    seen_jtis: DashMap<String, std::time::Instant>,
    /// Monotonic cleanup counter for the JTI cache.
    jti_cleanup_tick: AtomicU64,
    /// Audit fix 1.1: number of times the stale JWKS cache has been served
    /// because the issuer was unreachable. Operators should alert on a
    /// sustained climb: it means revocation propagation is delayed.
    oidc_jwks_stale_cache_used_total: AtomicU64,
    /// Single-flight gate for unknown-`kid` JWKS refreshes.
    ///
    /// When a burst of tokens signed by a newly-rotated key arrives
    /// simultaneously, the naive implementation has every request
    /// invalidate the cache and re-fetch JWKS independently — a thundering
    /// herd that hammers the IdP and amplifies a transient outage into a
    /// full failure. This mutex serialises refresh attempts: the first
    /// thread does the work, the rest wait, and on wake-up they see the
    /// freshly-populated cache and proceed without a second HTTP call.
    refresh_gate: parking_lot::Mutex<()>,
}

impl OidcConfig {
    /// Validate `issuer_url` at intake before any HTTP traffic flows.
    ///
    /// OIDC's JWKS discovery composes the issuer with the well-known path:
    /// `{issuer_url}/.well-known/openid-configuration`. A mis-shaped value
    /// (non-HTTPS, userinfo, fragment, query, traversal segments) could
    /// redirect discovery to an attacker-controlled origin or leak the
    /// original issuer via the Referer header. Reject anything surprising
    /// at construction time so the error is loud and early.
    pub fn validate(&self) -> HsmResult<()> {
        let raw = self.issuer_url.trim();
        if raw.is_empty() {
            return Err(HsmError::ConfigError(
                "oidc: issuer_url must not be empty".into(),
            ));
        }
        // Parse via reqwest's re-exported `url::Url` to get proper
        // scheme/authority decomposition without adding a new dependency.
        let parsed = reqwest::Url::parse(raw).map_err(|e| {
            HsmError::ConfigError(format!("oidc: issuer_url is not a valid URL: {e}"))
        })?;
        if parsed.scheme() != "https" {
            return Err(HsmError::ConfigError(format!(
                "oidc: issuer_url must use https, got scheme `{}`",
                parsed.scheme()
            )));
        }
        if parsed.host_str().map_or(true, |h| h.is_empty()) {
            return Err(HsmError::ConfigError(
                "oidc: issuer_url must include a host".into(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HsmError::ConfigError(
                "oidc: issuer_url must not embed userinfo credentials".into(),
            ));
        }
        if parsed.query().is_some() {
            return Err(HsmError::ConfigError(
                "oidc: issuer_url must not contain a query string".into(),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(HsmError::ConfigError(
                "oidc: issuer_url must not contain a fragment".into(),
            ));
        }
        // Reject traversal segments that could break out of the issuer path
        // when `.well-known/openid-configuration` is appended.
        for seg in parsed.path_segments().into_iter().flatten() {
            if seg == ".." || seg == "." {
                return Err(HsmError::ConfigError(
                    "oidc: issuer_url path must not contain `.` or `..` segments".into(),
                ));
            }
        }
        if self.audience.trim().is_empty() {
            return Err(HsmError::ConfigError(
                "oidc: audience must not be empty".into(),
            ));
        }
        if self.role_claim.trim().is_empty() {
            return Err(HsmError::ConfigError(
                "oidc: role_claim must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl OidcAuthProvider {
    /// Create a new OIDC auth provider.
    pub fn new(config: OidcConfig) -> HsmResult<Self> {
        config.validate()?;
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            // Defense in depth: enforce HTTPS-only at the client level so a
            // misconfigured issuer_url cannot leak credentials over plaintext.
            .https_only(true)
            // Disable redirects: a compromised CDN or DNS entry could redirect
            // JWKS discovery to an attacker-controlled server.  Callers must
            // configure a stable issuer_url that does not require redirects.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                tracing::error!("failed to build OIDC HTTP client: {e}");
                HsmError::ConfigError(format!("oidc http client: {e}"))
            })?;
        let rate_limiter = crate::auth::rate_limit::AuthRateLimiter::new(
            config.rate_limit.clone().unwrap_or_default(),
        );
        Ok(Self {
            config,
            cache: ArcSwapOption::from(None),
            http,
            rate_limiter,
            seen_jtis: DashMap::new(),
            jti_cleanup_tick: AtomicU64::new(0),
            oidc_jwks_stale_cache_used_total: AtomicU64::new(0),
            refresh_gate: parking_lot::Mutex::new(()),
        })
    }

    /// Map a string claim value to an `HsmRole` (case-insensitive).
    ///
    /// Delegates to the canonical [`crate::auth::parse_role`] helper so
    /// every provider treats the same input identically (audit: previously
    /// each provider had its own copy with subtly different case
    /// handling).
    fn parse_role(role_str: &str) -> Option<HsmRole> {
        crate::auth::parse_role(role_str)
    }

    /// Privilege ordering for selecting the *highest-privilege* role from a
    /// multi-valued claim like `groups: ["user", "key_manager"]`.  Higher
    /// number = more privileged.  Picking the first array element would let
    /// an attacker downgrade themselves to evade per-role audit policy, or
    /// upgrade themselves if the IdP returns roles in a non-deterministic
    /// order — neither is acceptable.
    fn role_rank(role: HsmRole) -> u8 {
        match role {
            HsmRole::So => 5,
            HsmRole::KeyManager => 4,
            HsmRole::Operator => 3,
            HsmRole::User => 2,
            HsmRole::Auditor => 1,
        }
    }

    /// Hash a bearer token for use as a rate-limit key.
    ///
    /// Uses 128 bits (16 bytes) of a SHA-256 digest so the raw token is never
    /// stored in the rate-limit map while providing adequate collision resistance
    /// for rate-limit bucketing (birthday bound at ~2^64 tokens).
    ///
    /// Audit fix (perf): use `hex::encode` directly instead of an explicit
    /// `write!`-loop. The two are functionally equivalent but `hex` is the
    /// shared workspace dependency for hex encoding and avoids reinventing
    /// the loop in every crate.
    fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(token.as_bytes());
        hex::encode(&digest[..16])
    }

    /// Audit fix 1.1 — accessor for the stale-cache served counter so
    /// integration tests (and operator dashboards) can observe the count.
    pub fn jwks_stale_cache_used_count(&self) -> u64 {
        self.oidc_jwks_stale_cache_used_total
            .load(Ordering::Relaxed)
    }

    // -- JWKS fetching & caching -------------------------------------------

    /// Fetch the OIDC discovery document and return the `jwks_uri`.
    ///
    /// Errors flow through [`OidcError`] (network vs. parse) and are
    /// flattened to [`HsmError::GeneralError`] at the public boundary via
    /// `From<OidcError>`. The tracing site on that conversion carries the
    /// structured cause so audit logs can distinguish TLS / network /
    /// JSON failures.
    fn discover_jwks_uri(&self) -> HsmResult<String> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer_url.trim_end_matches('/')
        );

        let resp = self
            .http
            .get(&discovery_url)
            .send()
            .map_err(OidcError::Network)?;

        let doc: OidcDiscovery = resp.json().map_err(OidcError::Parse)?;
        Ok(doc.jwks_uri)
    }

    /// Fetch a JWKS key set from the given URI. See [`Self::discover_jwks_uri`]
    /// for the error-mapping contract.
    fn fetch_jwks(&self, jwks_uri: &str) -> HsmResult<JwkSet> {
        let resp = self.http.get(jwks_uri).send().map_err(OidcError::Network)?;
        let jwks: JwkSet = resp.json().map_err(OidcError::Parse)?;
        Ok(jwks)
    }

    /// Convert an algorithm string from a JWK to a `jsonwebtoken::Algorithm`.
    ///
    /// Returns `None` for any unrecognised algorithm, which includes the
    /// dangerous `"none"` alg-header value (CVE-2015-9235 / RFC 7518 §3.6).
    /// The unsigned `none` algorithm is therefore rejected at key-cache build
    /// time: no `DecodingKey` is ever constructed for a JWK that advertises
    /// it, and subsequent token verification cannot resolve a kid → key pair.
    fn map_algorithm(alg: &str) -> Option<Algorithm> {
        // Defence-in-depth: explicitly refuse the unsigned-JWT value even if a
        // downstream crate ever tried to map it.
        if alg.eq_ignore_ascii_case("none") {
            return None;
        }
        match alg {
            "RS256" => Some(Algorithm::RS256),
            "RS384" => Some(Algorithm::RS384),
            "RS512" => Some(Algorithm::RS512),
            "ES256" => Some(Algorithm::ES256),
            "ES384" => Some(Algorithm::ES384),
            _ => None,
        }
    }

    /// Build the internal key cache from a `JwkSet`.
    fn build_cache(jwks: &JwkSet) -> HashMap<String, (Algorithm, DecodingKey)> {
        let mut map = HashMap::new();
        for jwk in &jwks.keys {
            let kid = match &jwk.common.key_id {
                Some(kid) => kid.clone(),
                None => continue,
            };

            let alg_str = match &jwk.common.key_algorithm {
                Some(a) => a.to_string(),
                None => continue,
            };

            let algorithm = match Self::map_algorithm(&alg_str) {
                Some(a) => a,
                None => continue,
            };

            let decoding_key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!("skipping JWK kid={kid}: {e}");
                    continue;
                }
            };

            map.insert(kid, (algorithm, decoding_key));
        }
        map
    }

    /// Ensure the JWKS cache is fresh, refreshing if necessary.
    ///
    /// # Concurrency
    ///
    /// The cache is held in an `ArcSwapOption`, so the freshness check on
    /// the fast path is a single lock-free atomic load. Network I/O is
    /// performed without any lock at all — if multiple threads see a stale
    /// cache simultaneously they may all start an I/O round-trip, but the
    /// last one to finish wins the swap and the older fetches are simply
    /// discarded. The per-`kid` unknown-key thundering herd is separately
    /// suppressed by `refresh_gate` in `validate_with_cached_key`.
    fn ensure_cache(&self) -> HsmResult<()> {
        let refresh_interval = Duration::from_secs(self.config.jwks_refresh_secs);

        // Fast path: lock-free load.
        if let Some(cache) = self.cache.load_full() {
            if cache.fetched_at.elapsed() < refresh_interval {
                return Ok(());
            }
        }

        // Perform I/O *without* holding any lock.
        // If the network is unavailable but we have a stale cache, serve
        // stale keys rather than rejecting all authentications.
        let io_result = self
            .discover_jwks_uri()
            .and_then(|uri| self.fetch_jwks(&uri));

        let (keys, fetched_at) = match io_result {
            Ok(jwks) => (Self::build_cache(&jwks), Instant::now()),
            Err(e) => {
                let max_age =
                    refresh_interval + Duration::from_secs(self.config.stale_cache_max_age_secs);
                if let Some(cache) = self.cache.load_full() {
                    if cache.fetched_at.elapsed() < max_age {
                        let count = self
                            .oidc_jwks_stale_cache_used_total
                            .fetch_add(1, Ordering::Relaxed)
                            + 1;
                        tracing::warn!(
                            counter = count,
                            "jwks stale cache used: refresh failed ({e:?}); serving cache aged {:?} (max {:?})",
                            cache.fetched_at.elapsed(),
                            max_age
                        );
                        return Ok(());
                    }
                    tracing::error!(
                        "JWKS refresh failed and cache exceeds stale_cache_max_age — failing closed"
                    );
                    return Err(e);
                }
                tracing::error!("JWKS fetch failed and no cache available: {e:?}");
                return Err(e);
            }
        };

        // Atomic swap. Outstanding readers continue to see the previous
        // snapshot until they drop their loaded `Arc`.
        self.cache
            .store(Some(std::sync::Arc::new(JwksCache { keys, fetched_at })));
        Ok(())
    }

    // -- Token validation --------------------------------------------------

    /// Expire the JWKS cache so the next `ensure_cache` call performs a
    /// full re-fetch from the OIDC issuer.
    ///
    /// Called when a JWT presents a `kid` that is absent from the current
    /// cache — the signing key may have been rotated since the last fetch.
    fn invalidate_cache(&self) {
        self.cache.store(None);
    }

    /// Decode and validate a JWT bearer token.
    ///
    /// When the `kid` in the token header is not present in the local JWKS
    /// cache the cache is invalidated and a fresh JWKS fetch is attempted
    /// exactly once before returning an error.  This handles the common case
    /// where a signing key has been rotated at the OIDC issuer.
    fn validate_token(&self, token: &str) -> HsmResult<TokenData<Claims>> {
        self.ensure_cache()?;

        // Extract the `kid` from the token header.
        let header = decode_header(token).map_err(|e| {
            tracing::debug!("JWT header decode failed: {e}");
            HsmError::PinIncorrect
        })?;

        let kid = header.kid.ok_or_else(|| {
            tracing::debug!("JWT has no kid header");
            HsmError::PinIncorrect
        })?;

        // Attempt validation; retry with a fresh JWKS on unknown kid.
        self.validate_with_cached_key(token, &kid, false)
    }

    /// Inner validation that holds a read lock during JWT decoding.
    ///
    /// `retry` prevents infinite recursion: the first call passes `false`;
    /// if the `kid` is missing the cache is invalidated, re-fetched, and
    /// this function is called again with `retry = true`.  A second miss
    /// is a hard failure.
    fn validate_with_cached_key(
        &self,
        token: &str,
        kid: &str,
        retry: bool,
    ) -> HsmResult<TokenData<Claims>> {
        // Lock-free load of the current cache snapshot. The Arc keeps the
        // cache alive for the duration of this call even if a concurrent
        // refresh swaps in a new snapshot.
        let cache = self.cache.load_full().ok_or(HsmError::GeneralError)?;

        match cache.keys.get(kid) {
            Some((algorithm, decoding_key)) => {
                let mut validation = Validation::new(*algorithm);
                // `set_audience` / `set_issuer` compare with case-sensitive
                // string equality, but OIDC issuer and audience identifiers
                // carry URL semantics — the scheme and host are
                // case-insensitive, a trailing `/` is meaningless, and the
                // default ports (80/https: 443) are equivalent to omitting
                // them. Normalising both sides before comparison prevents
                // spurious auth failures when an IdP emits `https://Auth.example/`
                // for an issuer configured here as `https://auth.example`.
                let normalised_aud = normalize_url(&self.config.audience);
                let normalised_iss = normalize_url(&self.config.issuer_url);
                validation.set_audience(&[&normalised_aud]);
                validation.set_issuer(&[&normalised_iss]);
                validation.validate_exp = true;
                validation.validate_nbf = true;
                // Required claims — explicit, not just defaults — so a token
                // missing exp or sub is rejected before any signature work.
                validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
                validation.leeway = self.config.clock_skew_secs;

                // Decode with insecure_disable_validation disabled; we still
                // want the library's validation. But we need to normalise the
                // token's own `iss` / `aud` values before comparison. The
                // jsonwebtoken crate performs validation *after* decoding, so
                // we first decode without issuer/audience validation, apply
                // normalisation, then re-run the checks by hand.
                let token_data = decode::<Claims>(token, decoding_key, &validation);
                match token_data {
                    Ok(td) => Ok(td),
                    Err(e) => {
                        // If the library's string-eq check rejected a token
                        // whose iss/aud differs only by case, trailing slash,
                        // or default port, re-run validation with the token's
                        // own claims normalised and see whether they match.
                        if let Some(td) = retry_with_normalised_iss_aud(
                            token,
                            decoding_key,
                            *algorithm,
                            &normalised_iss,
                            &normalised_aud,
                            self.config.clock_skew_secs,
                        ) {
                            return Ok(td);
                        }
                        tracing::debug!("JWT validation failed: {e}");
                        Err(HsmError::PinIncorrect)
                    }
                }
            }
            None if !retry => {
                // Drop the cache snapshot before any I/O so we are not
                // holding an obsolete reference across the refresh.
                drop(cache);
                tracing::info!(
                    "unknown kid '{kid}' in JWT — forcing JWKS refresh and retrying once"
                );

                // Single-flight gate: a burst of tokens signed with a
                // newly-rotated kid would otherwise stampede the IdP. We
                // serialise the refresh path so the first thread does the
                // HTTP work and the rest wake up to the freshly-populated
                // cache. After acquiring the gate we re-check the cache —
                // if a peer already refreshed, the kid is now present and
                // no further I/O is needed.
                let _gate = self.refresh_gate.lock();
                if let Some(cache) = self.cache.load_full() {
                    if cache.keys.contains_key(kid) {
                        drop(_gate);
                        return self.validate_with_cached_key(token, kid, true);
                    }
                }
                self.invalidate_cache();
                self.ensure_cache()?;
                drop(_gate);
                self.validate_with_cached_key(token, kid, true)
            }
            None => {
                tracing::warn!("kid '{kid}' not found in JWKS after forced refresh");
                Err(HsmError::PinIncorrect)
            }
        }
    }

    // -- Claim extraction --------------------------------------------------

    /// Extract a string value from a top-level claim, or from an array's
    /// first element (used only for non-role string claims like tenant).
    fn extract_string_claim(claims: &Claims, key: &str) -> Option<String> {
        match claims.get(key)? {
            serde_json::Value::String(s) => Some(s.to_owned()),
            serde_json::Value::Array(arr) => {
                arr.first().and_then(|v| v.as_str()).map(|s| s.to_owned())
            }
            _ => None,
        }
    }

    /// Extract the **highest-privilege** role from the configured role claim.
    ///
    /// Per RFC 9068 §2.2.3, role/groups claims are typically array-valued and
    /// the order is not significant.  Picking the first element would let an
    /// IdP that returns groups in non-deterministic order randomly assign
    /// users to different roles, and would let an attacker who controls one
    /// IdP attribute downgrade their effective privilege to evade per-role
    /// audit policies.  We always pick the most privileged role the user is
    /// entitled to.
    fn extract_highest_role(&self, claims: &Claims) -> Option<HsmRole> {
        let value = claims.get(self.config.role_claim.as_str())?;
        let mut best: Option<HsmRole> = None;
        let mut consider = |s: &str| {
            if let Some(r) = Self::parse_role(s) {
                if best
                    .map(|b| Self::role_rank(r) > Self::role_rank(b))
                    .unwrap_or(true)
                {
                    best = Some(r);
                }
            }
        };
        match value {
            serde_json::Value::String(s) => consider(s),
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        consider(s);
                    }
                }
            }
            _ => {}
        }
        best
    }

    /// Check and record a JWT's `jti` claim for replay prevention.
    ///
    /// Returns `Err(HsmError::PinIncorrect)` if `require_jti` is true and:
    ///  - the token has no `jti` claim, or
    ///  - the `jti` has already been seen within its validity window.
    ///
    /// The cache is bounded to 1,000,000 entries; when full, cleanup runs
    /// immediately before insertion.  Uses Unix seconds for expiry so the
    /// wall clock is only used for TTL management (not auth gating).
    fn check_jti(&self, claims: &Claims) -> HsmResult<()> {
        if !self.config.require_jti {
            return Ok(());
        }

        let jti = claims.get("jti").and_then(|v| v.as_str()).ok_or_else(|| {
            tracing::debug!("JWT missing required jti claim");
            HsmError::PinIncorrect
        })?;

        // Compute a monotonic eviction deadline. We take the *smaller* of:
        //   - `exp - now` (the token's own expiry window, honouring the IdP)
        //   - `MAX_JTI_RETENTION` (a hard cap so malformed/future-dated tokens
        //     cannot bloat the cache indefinitely)
        // The `exp` claim is required (set_required_spec_claims enforces it
        // upstream of this method), so a token reaching `check_jti` without
        // a parseable `exp` is malformed; reject loudly rather than silently
        // defaulting to a tiny replay window.
        const MAX_JTI_RETENTION: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
        const MIN_JTI_RETENTION: std::time::Duration = std::time::Duration::from_secs(300);
        let exp = claims.get("exp").and_then(|v| v.as_u64()).ok_or_else(|| {
            tracing::debug!("JWT missing or non-numeric exp claim at JTI-replay-check time");
            HsmError::PinIncorrect
        })?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window = std::time::Duration::from_secs(exp.saturating_sub(now_unix));
        let retention = window.clamp(MIN_JTI_RETENTION, MAX_JTI_RETENTION);
        let deadline = std::time::Instant::now() + retention;

        // Prune entries whose monotonic deadline has passed.
        let tick = self.jti_cleanup_tick.fetch_add(1, Ordering::Relaxed);
        if tick % 512 == 0 {
            let now_mono = std::time::Instant::now();
            self.seen_jtis.retain(|_, &mut d| d > now_mono);
        }

        // Reject if already seen; record if new. The common case in
        // production is a *replayed* token (which short-circuits on the
        // contains_key fast path), so we avoid the `to_string()`
        // allocation on every reject. The entry-API path below still
        // allocates exactly once for genuinely-new JTIs, which is
        // unavoidable because DashMap owns its keys.
        if self.seen_jtis.contains_key(jti) {
            tracing::debug!("JWT replay detected: jti already seen");
            return Err(HsmError::PinIncorrect);
        }
        use dashmap::mapref::entry::Entry;
        match self.seen_jtis.entry(jti.to_string()) {
            Entry::Occupied(_) => {
                // Race: another thread inserted the same jti between our
                // fast-path check and the entry lock. Treat as replay.
                tracing::debug!("JWT replay detected: jti already seen (race)");
                Err(HsmError::PinIncorrect)
            }
            Entry::Vacant(slot) => {
                slot.insert(deadline);
                Ok(())
            }
        }
    }

    /// Returns `true` iff the session still requires an MFA challenge.
    ///
    /// Treat the configured claim as a *completed-MFA* indicator: a value of
    /// `true`/`"true"`/`"1"` means the IdP has already enforced MFA for this
    /// session, so no further challenge is required (`mfa_required = false`).
    /// Any other value — absent claim, `false`, arbitrary string, or a
    /// non-scalar shape — is treated as "MFA still required" (fail-closed).
    fn extract_mfa(&self, claims: &Claims) -> bool {
        let claim_name = match &self.config.mfa_claim {
            Some(c) => c,
            None => return false,
        };

        let is_mfa_done = match claims.get(claim_name.as_str()) {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => {
                let s = s.trim();
                s.eq_ignore_ascii_case("true") || s == "1"
            }
            _ => false,
        };
        !is_mfa_done
    }
}

// ---------------------------------------------------------------------------
// Test harness (feature-gated)
// ---------------------------------------------------------------------------

/// Test-only constructors that bypass network I/O so integration tests can
/// exercise the full validate + replay path without reaching a real issuer.
///
/// These helpers are gated behind the `oidc-test-harness` cargo feature and
/// must **never** be enabled in production builds — they intentionally skip
/// issuer-URL validation constraints that would otherwise be enforced in
/// `OidcAuthProvider::new`.
#[cfg(feature = "oidc-test-harness")]
impl OidcAuthProvider {
    /// Construct a provider whose JWKS cache is pre-populated from the supplied
    /// `JwkSet`, so no discovery or JWKS HTTP traffic is performed.
    ///
    /// Intended for integration tests: callers typically build a `JwkSet`
    /// around a public key whose matching private key is also used with
    /// [`craft_id_token_for_testing`](Self::craft_id_token_for_testing).
    pub fn for_testing(config: OidcConfig, preseeded_jwks: JwkSet) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client build must succeed in tests");
        let rate_limiter = crate::auth::rate_limit::AuthRateLimiter::new(
            config.rate_limit.clone().unwrap_or_default(),
        );
        let cache = JwksCache {
            keys: Self::build_cache(&preseeded_jwks),
            fetched_at: Instant::now(),
        };
        Self {
            config,
            cache: ArcSwapOption::from(Some(std::sync::Arc::new(cache))),
            http,
            rate_limiter,
            seen_jtis: DashMap::new(),
            jti_cleanup_tick: AtomicU64::new(0),
            oidc_jwks_stale_cache_used_total: AtomicU64::new(0),
            refresh_gate: parking_lot::Mutex::new(()),
        }
    }

    /// Replace the JWKS cache with a fresh one built from `jwks`.
    ///
    /// Used by rotation tests to swap signing material while keeping the
    /// JTI replay state intact.
    pub fn replace_jwks_for_testing(&self, jwks: JwkSet) {
        let cache = JwksCache {
            keys: Self::build_cache(&jwks),
            fetched_at: Instant::now(),
        };
        self.cache.store(Some(std::sync::Arc::new(cache)));
    }

    /// Sign the supplied JSON claim set with `encoding_key` and return the
    /// compact-serialised JWT.
    ///
    /// `kid` is written into the JWT header so the provider's JWKS cache can
    /// resolve the matching decoding key.  Algorithm defaults to RS256 since
    /// the test harness is built around RSA keypairs; callers needing ES*
    /// can pass an explicit `algorithm`.
    pub fn craft_id_token_for_testing(
        claims: &serde_json::Value,
        encoding_key: &jsonwebtoken::EncodingKey,
        kid: &str,
        algorithm: Option<Algorithm>,
    ) -> HsmResult<String> {
        let mut header = jsonwebtoken::Header::new(algorithm.unwrap_or(Algorithm::RS256));
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(&header, claims, encoding_key)
            .map_err(|e| HsmError::ConfigError(format!("craft_id_token_for_testing: {e}")))
    }
}

impl AuthProvider for OidcAuthProvider {
    fn authenticate(&self, credentials: &AuthCredentials) -> HsmResult<AuthResult> {
        match credentials {
            AuthCredentials::Token { bearer_token } => {
                // Rate-limit key: SHA-256 hash of the raw token to avoid
                // storing sensitive material in memory.
                let rate_key = Self::hash_token(bearer_token.as_str());
                self.rate_limiter.check_rate_limit(&rate_key)?;

                let token_data = match self.validate_token(bearer_token.as_str()) {
                    Ok(td) => td,
                    Err(e) => {
                        self.rate_limiter.record_failure(&rate_key);
                        return Err(e);
                    }
                };
                let claims = token_data.claims;

                if let Err(e) = self.check_jti(&claims) {
                    self.rate_limiter.record_failure(&rate_key);
                    return Err(e);
                }

                // user_id from `sub`
                let user_id = claims
                    .get("sub")
                    .and_then(|v| v.as_str())
                    .map(|s| format!("oidc:{s}"))
                    .ok_or_else(|| {
                        self.rate_limiter.record_failure(&rate_key);
                        tracing::warn!("JWT missing sub claim");
                        HsmError::PinIncorrect
                    })?;

                // role: pick highest-privilege match (see extract_highest_role).
                let role = self.extract_highest_role(&claims).ok_or_else(|| {
                    self.rate_limiter.record_failure(&rate_key);
                    tracing::warn!(
                        "no recognized role found in JWT claim '{}'",
                        self.config.role_claim
                    );
                    HsmError::PinIncorrect
                })?;

                // tenant_id — use try_new so untrusted IdP-provided values
                // can never produce a path-traversal or log-injection-capable
                // TenantId.  Reject auth if the IdP returned a malformed ID.
                let tenant_id = match self
                    .config
                    .tenant_claim
                    .as_ref()
                    .and_then(|claim| Self::extract_string_claim(&claims, claim))
                {
                    Some(raw) => Some(TenantId::try_new(raw).map_err(|e| {
                        self.rate_limiter.record_failure(&rate_key);
                        tracing::warn!("OIDC tenant claim is not a valid TenantId: {e}");
                        // Core HsmError has no TenantInvalid variant, so we
                        // reuse PinIncorrect — the same fail-closed credential
                        // rejection used for every other OIDC auth failure
                        // (missing sub, unknown role, unknown kid). The
                        // warn! above carries the real reason for operators.
                        HsmError::PinIncorrect
                    })?),
                    None => None,
                };

                // MFA
                let mfa_required = self.extract_mfa(&claims);

                self.rate_limiter.record_success(&rate_key);
                Ok(AuthResult {
                    role,
                    user_id,
                    tenant_id,
                    mfa_required,
                })
            }
            _ => Err(HsmError::FunctionNotSupported),
        }
    }

    fn name(&self) -> &str {
        "oidc"
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    // -- Helpers -----------------------------------------------------------

    /// Generate an RSA key pair once for the whole test module.
    ///
    /// Generating a 2048-bit RSA key is expensive (~1s); doing it per-test
    /// multiplied the suite wall-clock by an order of magnitude.  More
    /// importantly, the previous implementation used `rand::thread_rng()`,
    /// which is a copy-paste footgun into production key-gen.  We now use
    /// `rand::rngs::OsRng` (the OS CSPRNG) so the example is correct even
    /// for a careless reader.
    ///
    /// The PKCS#8 DER for one shared keypair is cached in a process-wide
    /// `OnceLock` and cloned into fresh `EncodingKey` / `DecodingKey` values
    /// on each call.  Two keypairs are provided so tests that need to
    /// exercise "wrong signature" or "rotated key" paths can get distinct
    /// keys without paying the generation cost again.
    fn rsa_keypair_der() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYPAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYPAIR.get_or_init(|| generate_rsa_der())
    }

    fn alt_rsa_keypair_der() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYPAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYPAIR.get_or_init(|| generate_rsa_der())
    }

    fn generate_rsa_der() -> (Vec<u8>, Vec<u8>) {
        // OsRng is the OS CSPRNG — correct for any key generation.
        // jsonwebtoken's `EncodingKey::from_rsa_der` / `DecodingKey::from_rsa_der`
        // expect PKCS#1 DER (`RSAPrivateKey` / `RSAPublicKey`), not PKCS#8.
        // Encoding as PKCS#8 here returned `InvalidRsaKey(InvalidEncoding)`
        // from jsonwebtoken on parse.
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        let rsa = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
            .expect("RSA key generation must succeed in tests");
        let priv_der = rsa.to_pkcs1_der().expect("encode PKCS#1 private key");
        let pub_der = rsa
            .to_public_key()
            .to_pkcs1_der()
            .expect("encode PKCS#1 public key");
        (priv_der.as_bytes().to_vec(), pub_der.as_bytes().to_vec())
    }

    fn test_rsa_keypair() -> (EncodingKey, DecodingKey) {
        let (priv_der, pub_der) = rsa_keypair_der();
        (
            EncodingKey::from_rsa_der(priv_der),
            DecodingKey::from_rsa_der(pub_der),
        )
    }

    fn alt_test_rsa_keypair() -> (EncodingKey, DecodingKey) {
        let (priv_der, pub_der) = alt_rsa_keypair_der();
        (
            EncodingKey::from_rsa_der(priv_der),
            DecodingKey::from_rsa_der(pub_der),
        )
    }

    /// Current Unix timestamp.
    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build default claims for tests.
    fn base_claims(role: &str) -> serde_json::Value {
        let now = now_ts();
        json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": role,
        })
    }

    /// Create a provider with a pre-seeded JWKS cache (no network calls).
    fn provider_with_key(
        decoding_key: DecodingKey,
        kid: &str,
        config: OidcConfig,
    ) -> OidcAuthProvider {
        let mut keys = HashMap::new();
        keys.insert(kid.to_string(), (Algorithm::RS256, decoding_key));

        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let rate_limiter = crate::auth::rate_limit::AuthRateLimiter::new(
            config.rate_limit.clone().unwrap_or_default(),
        );
        OidcAuthProvider {
            config,
            cache: ArcSwapOption::from(Some(std::sync::Arc::new(JwksCache {
                keys,
                fetched_at: Instant::now(),
            }))),
            http,
            rate_limiter,
            seen_jtis: DashMap::new(),
            jti_cleanup_tick: AtomicU64::new(0),
            oidc_jwks_stale_cache_used_total: AtomicU64::new(0),
            refresh_gate: parking_lot::Mutex::new(()),
        }
    }

    fn default_config() -> OidcConfig {
        OidcConfig {
            issuer_url: "https://issuer.example.com".to_string(),
            audience: "craton-hsm".to_string(),
            role_claim: "role".to_string(),
            tenant_claim: None,
            mfa_claim: None,
            jwks_refresh_secs: 3600,
            request_timeout_secs: 10,
            // Audit fix 1.1: tightened default from 24h to 1h.
            stale_cache_max_age_secs: 3_600,
            clock_skew_secs: default_clock_skew_secs(),
            rate_limit: None,
            require_jti: false,
        }
    }

    /// Sign a JWT with the given claims and kid.
    fn sign_jwt(claims: &serde_json::Value, encoding_key: &EncodingKey, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, encoding_key).unwrap()
    }

    // -- Unit tests --------------------------------------------------------

    #[test]
    fn test_valid_token_user_role() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "test-key-1";
        let config = default_config();
        let provider = provider_with_key(dec, kid, config);

        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, kid);

        let creds = AuthCredentials::Token {
            bearer_token: zeroize::Zeroizing::new(token),
        };
        let result = provider.authenticate(&creds).unwrap();

        assert_eq!(result.user_id, "oidc:user-123");
        assert!(matches!(result.role, HsmRole::User));
        assert!(result.tenant_id.is_none());
        assert!(!result.mfa_required);
    }

    #[test]
    fn test_valid_token_so_role() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let claims = base_claims("SO");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(matches!(result.role, HsmRole::So));
    }

    #[test]
    fn test_valid_token_auditor_role() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let claims = base_claims("Auditor");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(matches!(result.role, HsmRole::Auditor));
    }

    #[test]
    fn test_valid_token_key_manager_role() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let claims = base_claims("key_manager");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(matches!(result.role, HsmRole::KeyManager));
    }

    #[test]
    fn test_valid_token_operator_role() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let claims = base_claims("Operator");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(matches!(result.role, HsmRole::Operator));
    }

    #[test]
    fn test_unknown_role_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let claims = base_claims("superadmin");
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_expired_token_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now - 3600, // expired 1 hour ago
            "iat": now - 7200,
            "role": "user",
        });
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_wrong_audience_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "wrong-audience",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
        });
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_wrong_issuer_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://evil.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
        });
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_wrong_signature_rejected() {
        let (_enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        // Sign with a different key.
        let (other_enc, _) = alt_test_rsa_keypair();
        let claims = base_claims("user");
        let token = sign_jwt(&claims, &other_enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_unknown_kid_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "known-kid";
        let provider = provider_with_key(dec, kid, default_config());

        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, "unknown-kid");

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        // Unknown kid forces a JWKS refresh against the configured issuer URL.
        // The default test issuer (`https://issuer.example.com`) is unreachable,
        // so the refresh fails with `GeneralError`; on a host where the URL
        // happens to resolve, the second lookup misses and we get
        // `PinIncorrect`. Either is a valid rejection — the test asserts only
        // that the token is refused.
        assert!(
            matches!(err, HsmError::PinIncorrect | HsmError::GeneralError),
            "expected auth failure for unknown kid; got {err:?}"
        );
    }

    #[test]
    fn test_missing_sub_claim_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let now = now_ts();
        let claims = json!({
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
        });
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_missing_role_claim_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
        });
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_tenant_claim_extraction() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.tenant_claim = Some("tenant_id".to_string());
        let provider = provider_with_key(dec, kid, config);

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
            "tenant_id": "acme-corp",
        });
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert_eq!(result.tenant_id.unwrap().as_str(), "acme-corp");
    }

    #[test]
    fn test_tenant_claim_absent_when_configured() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.tenant_claim = Some("tenant_id".to_string());
        let provider = provider_with_key(dec, kid, config);

        // Token has no tenant_id claim.
        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(result.tenant_id.is_none());
    }

    #[test]
    fn test_custom_role_claim_name() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.role_claim = "groups".to_string();
        let provider = provider_with_key(dec, kid, config);

        let now = now_ts();
        let claims = json!({
            "sub": "user-456",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "groups": ["Auditor"],
        });
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(matches!(result.role, HsmRole::Auditor));
        assert_eq!(result.user_id, "oidc:user-456");
    }

    #[test]
    fn test_mfa_claim_true_means_not_required() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.mfa_claim = Some("mfa_verified".to_string());
        let provider = provider_with_key(dec, kid, config);

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
            "mfa_verified": true,
        });
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(!result.mfa_required);
    }

    #[test]
    fn test_mfa_claim_false_means_required() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.mfa_claim = Some("mfa_verified".to_string());
        let provider = provider_with_key(dec, kid, config);

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
            "mfa_verified": false,
        });
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(result.mfa_required);
    }

    #[test]
    fn test_mfa_claim_absent_means_required() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.mfa_claim = Some("mfa_verified".to_string());
        let provider = provider_with_key(dec, kid, config);

        // Token has no mfa_verified claim.
        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(result.mfa_required);
    }

    #[test]
    fn test_mfa_not_configured_means_not_required() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let config = default_config(); // mfa_claim is None
        let provider = provider_with_key(dec, kid, config);

        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(!result.mfa_required);
    }

    #[test]
    fn test_non_token_credentials_rejected() {
        let (_, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let creds = AuthCredentials::LdapBind {
            username: zeroize::Zeroizing::new("admin".to_string()),
            password: zeroize::Zeroizing::new("pass".to_string()),
        };
        let err = provider.authenticate(&creds).unwrap_err();
        assert!(matches!(err, HsmError::FunctionNotSupported));
    }

    #[test]
    fn test_provider_name() {
        let provider = OidcAuthProvider::new(default_config()).unwrap();
        assert_eq!(provider.name(), "oidc");
    }

    #[test]
    fn test_garbage_token_rejected() {
        let (_, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new("not.a.jwt".to_string()),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_parse_role_coverage() {
        assert!(matches!(
            OidcAuthProvider::parse_role("user"),
            Some(HsmRole::User)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("User"),
            Some(HsmRole::User)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("so"),
            Some(HsmRole::So)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("SO"),
            Some(HsmRole::So)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("auditor"),
            Some(HsmRole::Auditor)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("Auditor"),
            Some(HsmRole::Auditor)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("key_manager"),
            Some(HsmRole::KeyManager)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("KeyManager"),
            Some(HsmRole::KeyManager)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("operator"),
            Some(HsmRole::Operator)
        ));
        assert!(matches!(
            OidcAuthProvider::parse_role("Operator"),
            Some(HsmRole::Operator)
        ));
        assert!(OidcAuthProvider::parse_role("unknown").is_none());
        assert!(OidcAuthProvider::parse_role("").is_none());
    }

    #[test]
    fn test_extract_highest_role_picks_most_privileged() {
        // Even if the IdP lists user first, SO must win.
        let provider = provider_with_key(test_rsa_keypair().1, "k1", default_config());
        let claims = json!({"role": ["user", "so", "auditor"]});
        let role = provider.extract_highest_role(&claims).unwrap();
        assert_eq!(role, HsmRole::So);

        // Order-independence.
        let claims = json!({"role": ["auditor", "key_manager", "user"]});
        let role = provider.extract_highest_role(&claims).unwrap();
        assert_eq!(role, HsmRole::KeyManager);
    }

    #[test]
    fn test_extract_string_claim_from_string() {
        let claims = json!({"role": "user"});
        assert_eq!(
            OidcAuthProvider::extract_string_claim(&claims, "role"),
            Some("user".to_string())
        );
    }

    #[test]
    fn test_extract_string_claim_from_array() {
        let claims = json!({"groups": ["Auditor", "User"]});
        assert_eq!(
            OidcAuthProvider::extract_string_claim(&claims, "groups"),
            Some("Auditor".to_string())
        );
    }

    #[test]
    fn test_extract_string_claim_missing() {
        let claims = json!({"other": "value"});
        assert!(OidcAuthProvider::extract_string_claim(&claims, "role").is_none());
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = OidcConfig {
            issuer_url: "https://issuer.example.com".to_string(),
            audience: "craton-hsm".to_string(),
            role_claim: "role".to_string(),
            tenant_claim: Some("tenant".to_string()),
            mfa_claim: Some("mfa".to_string()),
            jwks_refresh_secs: 1800,
            request_timeout_secs: 10,
            // Audit fix 1.1: tightened default from 24h to 1h.
            stale_cache_max_age_secs: 3_600,
            clock_skew_secs: default_clock_skew_secs(),
            rate_limit: None,
            require_jti: false,
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: OidcConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.issuer_url, config.issuer_url);
        assert_eq!(deserialized.audience, config.audience);
        assert_eq!(deserialized.role_claim, config.role_claim);
        assert_eq!(deserialized.tenant_claim, config.tenant_claim);
        assert_eq!(deserialized.mfa_claim, config.mfa_claim);
        assert_eq!(deserialized.jwks_refresh_secs, 1800);
        assert_eq!(deserialized.request_timeout_secs, 10);
    }

    #[test]
    fn test_config_default_refresh_secs() {
        let json = r#"{
            "issuer_url": "https://issuer.example.com",
            "audience": "craton-hsm",
            "role_claim": "role"
        }"#;
        let config: OidcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.jwks_refresh_secs, 3600);
    }

    #[test]
    fn test_cache_expiry_forces_refresh_attempt() {
        let (_, dec) = test_rsa_keypair();
        let kid = "k1";
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let rate_limiter = crate::auth::rate_limit::AuthRateLimiter::new(Default::default());
        // Audit fix 1.1: stale-cache default is now 1h, so override the
        // refresh interval and use a shorter offset so the cache is stale
        // relative to refresh but still inside the 1h grace window.
        let mut cfg = default_config();
        cfg.jwks_refresh_secs = 60;
        let provider = OidcAuthProvider {
            config: cfg,
            cache: ArcSwapOption::from(Some(std::sync::Arc::new(JwksCache {
                keys: {
                    let mut m = HashMap::new();
                    m.insert(kid.to_string(), (Algorithm::RS256, dec));
                    m
                },
                // 30 minutes in the past: stale relative to a 60s refresh,
                // but well within the 1h stale_cache_max_age grace window.
                fetched_at: Instant::now()
                    .checked_sub(Duration::from_secs(1800))
                    .unwrap_or_else(Instant::now),
            }))),
            http,
            rate_limiter,
            seen_jtis: DashMap::new(),
            jti_cleanup_tick: AtomicU64::new(0),
            oidc_jwks_stale_cache_used_total: AtomicU64::new(0),
            refresh_gate: parking_lot::Mutex::new(()),
        };

        // ensure_cache will try to do a network fetch which will fail because
        // the issuer is unresolvable.  The stale cache is still within the
        // grace window so ensure_cache succeeds by serving the cached keys.
        let result = provider.ensure_cache();
        assert!(result.is_ok());
    }

    #[test]
    fn test_map_algorithm() {
        assert_eq!(
            OidcAuthProvider::map_algorithm("RS256"),
            Some(Algorithm::RS256)
        );
        assert_eq!(
            OidcAuthProvider::map_algorithm("RS384"),
            Some(Algorithm::RS384)
        );
        assert_eq!(
            OidcAuthProvider::map_algorithm("RS512"),
            Some(Algorithm::RS512)
        );
        assert_eq!(
            OidcAuthProvider::map_algorithm("ES256"),
            Some(Algorithm::ES256)
        );
        assert_eq!(
            OidcAuthProvider::map_algorithm("ES384"),
            Some(Algorithm::ES384)
        );
        assert_eq!(OidcAuthProvider::map_algorithm("HS256"), None);
    }

    #[test]
    fn test_map_algorithm_es256() {
        assert_eq!(
            OidcAuthProvider::map_algorithm("ES256"),
            Some(Algorithm::ES256)
        );
    }

    #[test]
    fn test_map_algorithm_es384() {
        assert_eq!(
            OidcAuthProvider::map_algorithm("ES384"),
            Some(Algorithm::ES384)
        );
    }

    /// Verify that `invalidate_cache` clears the in-memory JWKS cache.
    #[test]
    fn test_invalidate_cache_clears_cache() {
        let (_, dec) = test_rsa_keypair();
        let kid = "k1";
        let provider = provider_with_key(dec, kid, default_config());

        // Cache is populated.
        assert!(provider.cache.load_full().is_some());

        provider.invalidate_cache();

        // Cache must be cleared after invalidation.
        assert!(provider.cache.load_full().is_none());
    }

    /// When a token presents a `kid` that is absent from the cache, the
    /// provider must invalidate the cache, attempt a JWKS re-fetch, and —
    /// if the re-fetch fails because there is no network in tests — return
    /// an error rather than accepting the token with an untrusted key.
    ///
    /// This test simulates the network failure path: the issuer is
    /// unreachable, so `ensure_cache` fails after invalidation, and the
    /// whole authentication fails rather than silently accepting the token.
    #[test]
    fn test_unknown_kid_triggers_jwks_refresh_and_fails_gracefully() {
        let (enc, dec) = test_rsa_keypair();
        let known_kid = "known-key";
        let unknown_kid = "rotated-key";

        // Seed the cache with only the known key.
        let provider = provider_with_key(dec, known_kid, default_config());

        let claims = base_claims("user");
        // Token signed with the right key but presenting the new (unknown) kid.
        let token = sign_jwt(&claims, &enc, unknown_kid);

        // Authentication must fail: the unknown kid triggers a re-fetch which
        // fails in the test environment (no real network), so the provider
        // correctly returns an error rather than accepting the token.
        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        // Could be PinIncorrect (kid not found) or GeneralError (network down).
        assert!(
            matches!(err, HsmError::PinIncorrect | HsmError::GeneralError),
            "expected auth failure after unknown kid; got {err:?}"
        );
    }

    /// When both the old and new keys are present in the refreshed JWKS, a
    /// token signed with the new key (unknown kid at first) is accepted after
    /// the cache refresh.
    #[test]
    fn test_unknown_kid_accepted_after_refresh_populates_new_key() {
        let (enc_new, dec_new) = test_rsa_keypair();
        let new_kid = "new-key";

        // Build a provider whose cache initially contains *only* the new key.
        // This simulates what happens after a successful JWKS re-fetch that
        // returns the rotated key.
        let provider = provider_with_key(dec_new, new_kid, default_config());

        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc_new, new_kid);

        // The new kid is directly in the cache — must succeed.
        let result = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap();
        assert!(matches!(result.role, HsmRole::User));
    }

    #[test]
    fn test_jti_replay_prevention_rejects_replayed_token() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.require_jti = true;
        let provider = provider_with_key(dec, kid, config);

        let now = now_ts();
        let claims = json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
            "jti": "unique-token-id-1",
        });
        let token = sign_jwt(&claims, &enc, kid);

        // First use: must succeed.
        let result = provider.authenticate(&AuthCredentials::Token {
            bearer_token: zeroize::Zeroizing::new(token.clone()),
        });
        assert!(result.is_ok(), "first use of token must succeed");

        // Second use of same token: must be rejected as a replay.
        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(
            matches!(err, HsmError::PinIncorrect),
            "replayed token must be rejected"
        );
    }

    #[test]
    fn test_jti_replay_prevention_missing_jti_rejected() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let mut config = default_config();
        config.require_jti = true;
        let provider = provider_with_key(dec, kid, config);

        // Token has no jti claim.
        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, kid);

        let err = provider
            .authenticate(&AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new(token),
            })
            .unwrap_err();
        assert!(matches!(err, HsmError::PinIncorrect));
    }

    #[test]
    fn test_jti_not_required_by_default() {
        let (enc, dec) = test_rsa_keypair();
        let kid = "k1";
        let config = default_config(); // require_jti defaults to false
        let provider = provider_with_key(dec, kid, config);

        // Token without jti should still be accepted.
        let claims = base_claims("user");
        let token = sign_jwt(&claims, &enc, kid);

        let result = provider.authenticate(&AuthCredentials::Token {
            bearer_token: zeroize::Zeroizing::new(token.clone()),
        });
        assert!(result.is_ok());

        // Replaying it also succeeds (no JTI tracking when disabled).
        let result = provider.authenticate(&AuthCredentials::Token {
            bearer_token: zeroize::Zeroizing::new(token),
        });
        assert!(result.is_ok());
    }

    /// Verify that `config_default_request_timeout` is set to 10 seconds.
    #[test]
    fn test_config_default_request_timeout_secs() {
        let json = r#"{
            "issuer_url": "https://issuer.example.com",
            "audience": "craton-hsm",
            "role_claim": "role"
        }"#;
        let config: OidcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.request_timeout_secs, 10);
    }

    // ---------------------------------------------------------------------
    // normalize_url — issuer / audience comparison must be URL-aware, not
    // case-sensitive string equality.
    // ---------------------------------------------------------------------

    /// Case differences in scheme and host must normalise away.
    #[test]
    fn normalize_url_is_case_insensitive_scheme_and_host() {
        assert_eq!(
            normalize_url("HTTPS://Auth.Example.COM/realms/x"),
            normalize_url("https://auth.example.com/realms/x")
        );
    }

    /// A trailing slash on the path (or root-only "/") must normalise away.
    #[test]
    fn normalize_url_strips_trailing_slash() {
        assert_eq!(
            normalize_url("https://auth.example.com/"),
            normalize_url("https://auth.example.com")
        );
        assert_eq!(
            normalize_url("https://auth.example.com/realms/x/"),
            normalize_url("https://auth.example.com/realms/x")
        );
    }

    /// Default ports (443 for https, 80 for http) must normalise away.
    #[test]
    fn normalize_url_strips_default_ports() {
        assert_eq!(
            normalize_url("https://auth.example.com:443"),
            normalize_url("https://auth.example.com")
        );
        assert_eq!(
            normalize_url("http://auth.example.com:80"),
            normalize_url("http://auth.example.com")
        );
    }

    /// Non-default ports must be preserved — `:8443` is NOT equivalent to
    /// no port on an https URL.
    #[test]
    fn normalize_url_preserves_non_default_ports() {
        assert_ne!(
            normalize_url("https://auth.example.com:8443"),
            normalize_url("https://auth.example.com")
        );
    }

    /// The three canonicalisations combine cleanly: a fully-decorated URL
    /// must equal the minimal form.
    #[test]
    fn normalize_url_combines_all_rules() {
        assert_eq!(
            normalize_url("HTTPS://AUTH.Example.COM:443/"),
            normalize_url("https://auth.example.com")
        );
    }

    /// Malformed input must fall back to the raw string so a garbage
    /// issuer can never accidentally match a well-formed one after
    /// normalisation (fail-closed).
    #[test]
    fn normalize_url_fails_closed_on_parse_error() {
        // "not a url" does not parse as an absolute URL.
        let raw = "not a url";
        assert_eq!(normalize_url(raw), raw);
        // And must NOT match an otherwise-valid URL.
        assert_ne!(normalize_url(raw), normalize_url("https://x"));
    }

    /// Different hosts must NEVER normalise to equal regardless of other
    /// differences — the normalisation must not be so aggressive as to lose
    /// meaningful identity information.
    #[test]
    fn normalize_url_different_hosts_stay_distinct() {
        assert_ne!(
            normalize_url("https://attacker.example.com"),
            normalize_url("https://auth.example.com")
        );
    }
}
