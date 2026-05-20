// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! LDAP/Active Directory authentication provider.
//!
//! Authenticates users by binding to an LDAP directory and mapping
//! group membership to HSM roles.
//!
//! Requires the `ldap-auth` feature flag and the `ldap3` crate.

#[cfg(feature = "ldap-auth")]
mod inner {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Audit finding M9: use `parking_lot::Mutex` instead of `std::sync::Mutex`
    // so a panic while holding a pool slot does not poison the lock and take
    // the whole connection pool offline. `parking_lot` does not track
    // poisoning, which is exactly the behaviour we want for a connection pool
    // where a panicked worker's connection will simply be discarded.
    use parking_lot::Mutex;

    use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
    use serde::{Deserialize, Serialize};

    use crate::auth::provider::{AuthCredentials, AuthProvider, AuthResult};
    use crate::rbac::role::HsmRole;
    use crate::tenant::tenant::TenantId;
    use craton_hsm::error::{HsmError, HsmResult};

    /// TLS mode for the LDAP connection.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum LdapTlsMode {
        /// No TLS (plain LDAP, port 389). Not recommended for production.
        None,
        /// Use LDAPS (TLS from connection start, typically port 636).
        Ldaps,
        /// Use STARTTLS upgrade on a plain connection (port 389).
        StartTls,
    }

    impl Default for LdapTlsMode {
        fn default() -> Self {
            Self::StartTls
        }
    }

    /// LDAP authentication configuration.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LdapConfig {
        /// LDAP server URL (e.g., "ldap://ldap.example.com" or "ldaps://ldap.example.com").
        pub url: String,
        /// Base DN for user searches (e.g., "dc=example,dc=com").
        pub base_dn: String,
        /// Bind DN template. `{}` is replaced with the username (RFC 4514-escaped).
        /// Example: "uid={},ou=users,dc=example,dc=com"
        pub bind_dn_template: String,
        /// Mapping from LDAP group DNs to HSM roles.
        /// Keys are LDAP group DNs (or CN values), values are role names:
        /// "User", "SO", "Auditor", "KeyManager", "Operator".
        /// BTreeMap ensures deterministic iteration order.
        pub role_mapping: BTreeMap<String, String>,
        /// LDAP attribute containing tenant ID (optional).
        /// If set, this attribute is read from the user entry after bind.
        pub tenant_attribute: Option<String>,
        /// TLS mode for the connection.
        #[serde(default)]
        pub tls_mode: LdapTlsMode,
        /// Search filter template for finding the user entry after bind.
        /// `{}` is replaced with the username. Defaults to `(uid={})`.
        #[serde(default = "default_user_filter")]
        pub user_search_filter: String,
        /// Attribute that holds group membership on the user entry.
        /// Defaults to `memberOf`.
        #[serde(default = "default_group_attribute")]
        pub group_attribute: String,
        /// Connection timeout in seconds. Defaults to 10.
        #[serde(default = "default_timeout_secs")]
        pub timeout_secs: u64,
        /// Whether to require MFA for LDAP-authenticated sessions.
        #[serde(default)]
        pub require_mfa: bool,
        /// Number of pooled connections to maintain. Defaults to 4.
        #[serde(default = "default_pool_size")]
        pub pool_size: usize,
        /// Maximum total connections allowed (pool_size + overflow). Defaults
        /// to `pool_size + 2`. When all pool slots are busy and this many
        /// connections are already open, new requests will be rejected rather
        /// than opening unbounded overflow connections.
        #[serde(default)]
        pub max_connections: Option<usize>,
        /// Rate-limit configuration for authentication failures.
        /// When `None`, a default configuration is used.
        #[serde(default)]
        pub rate_limit: Option<crate::auth::rate_limit::RateLimitConfig>,
        /// Audit fix 1.4 -- explicit opt-in for plaintext LDAP. When
        /// `tls_mode = LdapTlsMode::None` the bind credentials traverse
        /// the network in cleartext. The previous build accepted that
        /// configuration with only a tracing warning; an operator who
        /// missed the warning silently lost MFA-grade auth. Validation
        /// now refuses plaintext unless the operator sets this flag.
        #[serde(default)]
        pub allow_plaintext: bool,
    }

    fn default_pool_size() -> usize {
        4
    }

    fn default_user_filter() -> String {
        "(uid={})".to_string()
    }

    fn default_group_attribute() -> String {
        "memberOf".to_string()
    }

    fn default_timeout_secs() -> u64 {
        10
    }

    impl LdapConfig {
        /// Validate that template fields contain exactly one `{}` placeholder.
        ///
        /// A template such as `(uid={})` mistakenly configured as `(uid=*)`
        /// (no placeholder) would silently skip username substitution and
        /// match every entry — effectively a global authentication bypass.
        /// A template with *multiple* `{}` placeholders is equally
        /// suspicious: a username containing RFC 4515 metacharacters
        /// (escaped once) could leak into an unintended field.
        pub fn validate(&self) -> HsmResult<()> {
            fn count(s: &str) -> usize {
                s.matches("{}").count()
            }
            if count(&self.bind_dn_template) != 1 {
                return Err(HsmError::ConfigError(format!(
                    "ldap: bind_dn_template must contain exactly one `{{}}` placeholder, got {}",
                    count(&self.bind_dn_template)
                )));
            }
            if count(&self.user_search_filter) != 1 {
                return Err(HsmError::ConfigError(format!(
                    "ldap: user_search_filter must contain exactly one `{{}}` placeholder, got {}",
                    count(&self.user_search_filter)
                )));
            }
            // Audit fix 1.4: refuse plaintext LDAP unless the operator
            // explicitly opted in. A warn-and-continue policy is too easy
            // to miss in production logs.
            if matches!(self.tls_mode, LdapTlsMode::None) && !self.allow_plaintext {
                return Err(HsmError::ConfigError(
                    "ldap: tls_mode = none requires allow_plaintext = true; \n                     bind credentials would traverse the network in cleartext".into(),
                ));
            }
            Ok(())
        }
    }

    /// Escape special characters in a string for safe use in LDAP filters (RFC 4515).
    ///
    /// RFC 4515 §3 requires the following characters to be replaced with their
    /// hex-escape form inside `AssertionValue` octets: `\`, `*`, `(`, `)`, and
    /// the NUL byte.  Escaping any of these prevents a crafted username from
    /// breaking out of its value position and forging additional filter
    /// components (e.g. `admin*)(uid=*` closing the current AVA and injecting
    /// a wildcard match on uid).
    pub(crate) fn escape_ldap_filter(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for c in input.chars() {
            match c {
                '\\' => out.push_str("\\5c"),
                '*' => out.push_str("\\2a"),
                '(' => out.push_str("\\28"),
                ')' => out.push_str("\\29"),
                '\0' => out.push_str("\\00"),
                _ => out.push(c),
            }
        }
        out
    }

    /// Alias for [`escape_ldap_filter`] exposed under its RFC number so
    /// call sites can document *which* escaping rule they are applying.
    /// Filter-side escaping (RFC 4515) differs from DN-side escaping
    /// (RFC 4514 — see [`escape_dn_value`]).
    #[allow(dead_code)]
    pub(crate) fn escape_rfc4515(input: &str) -> String {
        escape_ldap_filter(input)
    }

    /// Escape a value for safe inclusion in an LDAP Distinguished Name (RFC 4514).
    ///
    /// DN values use different escaping rules from filter values:
    /// - Characters `,`, `+`, `"`, `\`, `<`, `>`, `;` are escaped with `\`
    /// - A leading space or `#` is escaped with `\`
    /// - A trailing space is escaped with `\`
    /// - Null bytes are escaped as `\00`
    ///
    /// This prevents DN injection attacks such as `user,cn=admin`.
    pub(crate) fn escape_dn_value(input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }
        let mut out = String::with_capacity(input.len() + 4);
        let bytes = input.as_bytes();

        for (i, &b) in bytes.iter().enumerate() {
            let c = b as char;
            match c {
                // Always-escaped special characters
                ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                    out.push('\\');
                    out.push(c);
                }
                '\0' => out.push_str("\\00"),
                // Leading space or '#'
                ' ' if i == 0 => out.push_str("\\ "),
                '#' if i == 0 => out.push_str("\\#"),
                // Trailing space
                ' ' if i == bytes.len() - 1 => out.push_str("\\ "),
                _ => out.push(c),
            }
        }
        out
    }

    /// LDAP authentication provider.
    ///
    /// Maintains a pooled connection to the LDAP server (behind a mutex for
    /// thread safety). If the cached connection is stale or broken, a new one
    /// is transparently created.
    pub struct LdapAuthProvider {
        config: LdapConfig,
        /// Pool of cached LDAP connections for concurrent reuse.
        /// Each slot is independently lockable so multiple threads can
        /// take/return connections without contention.
        pub(crate) pool: Vec<Mutex<Option<LdapConn>>>,
        /// Number of connections currently open beyond pool_size (overflow).
        pub(crate) overflow_count: AtomicUsize,
        /// Maximum allowed overflow connections beyond pool_size.
        pub(crate) max_overflow: usize,
        /// Rate limiter for authentication failures.
        rate_limiter: crate::auth::rate_limit::AuthRateLimiter,
    }

    impl LdapAuthProvider {
        /// Create a new LDAP auth provider.
        ///
        /// **Deprecated** since 0.1.3: this constructor panics on invalid
        /// configuration, which is unsuitable for configs that arrive over
        /// the gRPC management API or from operator input. Use
        /// [`Self::try_new`], which returns a `HsmResult`, instead.
        ///
        /// Emits a loud security warning when configured without TLS or
        /// pointed at an `ldap://` URL with `tls_mode = None`, since that
        /// sends bind credentials in plaintext over the network.
        ///
        /// Panics on invalid template configuration (see
        /// [`LdapConfig::validate`]). Misconfiguring the template is a
        /// deployment bug that would cause an authentication bypass, so we
        /// refuse to construct the provider rather than silently serving
        /// requests.
        #[deprecated(
            since = "0.1.3",
            note = "use try_new() which returns Result; new() will be removed in 0.2.0"
        )]
        pub fn new(config: LdapConfig) -> Self {
            Self::try_new(config).expect("LDAP provider constructed with invalid config")
        }

        /// Fallible constructor — the recommended way to build an
        /// [`LdapAuthProvider`].  Returns a [`HsmResult`] on invalid
        /// configuration rather than panicking, so it is safe to call on
        /// configs that originate from runtime sources (operator input,
        /// the gRPC management API, files on disk).
        pub fn try_new(config: LdapConfig) -> HsmResult<Self> {
            config.validate()?;
            if matches!(config.tls_mode, LdapTlsMode::None) {
                tracing::warn!(
                    url = %config.url,
                    "LDAP provider configured WITHOUT TLS — bind credentials will be sent \
                     in plaintext. Set tls_mode to 'starttls' or 'ldaps' for production."
                );
            } else if matches!(config.tls_mode, LdapTlsMode::StartTls)
                && config.url.starts_with("ldaps://")
            {
                tracing::warn!(
                    url = %config.url,
                    "LDAP url is ldaps:// but tls_mode=starttls — STARTTLS over an \
                     already-TLS-wrapped connection will fail; set tls_mode='ldaps'."
                );
            }
            let rate_limiter = crate::auth::rate_limit::AuthRateLimiter::new(
                config.rate_limit.clone().unwrap_or_default(),
            );
            let pool_size = config.pool_size.max(1);
            let max_overflow = config
                .max_connections
                .map(|mc| mc.saturating_sub(pool_size))
                .unwrap_or(2);
            let pool = (0..pool_size).map(|_| Mutex::new(None)).collect();
            Ok(Self {
                config,
                pool,
                overflow_count: AtomicUsize::new(0),
                max_overflow,
                rate_limiter,
            })
        }

        /// Hash a username for safe inclusion in log messages.
        ///
        /// Usernames are PII and may also be sensitive (e.g., email addresses).
        /// We log a short SHA-256 prefix instead of the raw value so operators
        /// can correlate failure events without leaking identities to anyone
        /// who can read the logs.
        fn hashed_username(username: &str) -> String {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(username.as_bytes());
            // 8 bytes = 16 hex chars; collision risk is negligible for log correlation.
            hex::encode(&digest[..8])
        }

        /// Parse a role name string into an `HsmRole`.
        ///
        /// Delegates to the canonical [`crate::auth::parse_role`] helper so
        /// every provider treats the same input identically. The previous
        /// LDAP-local implementation was case-*sensitive* with specific
        /// capitalised variants (`"User"`, `"SO"`, etc.), which silently
        /// rejected the lowercase forms accepted by the cert and OIDC
        /// providers — exactly the kind of inconsistency RBAC must not
        /// tolerate.
        pub(crate) fn parse_role(role_name: &str) -> Option<HsmRole> {
            crate::auth::parse_role(role_name)
        }

        /// Map a list of LDAP group DNs to the highest-priority HSM role.
        ///
        /// Iterates through the configured role_mapping and returns the first
        /// match. The order of iteration is deterministic per HashMap but
        /// callers should configure non-overlapping groups.
        pub(crate) fn map_role(&self, groups: &[String]) -> Option<HsmRole> {
            for (group_dn, role_name) in &self.config.role_mapping {
                if groups.iter().any(|g| g == group_dn) {
                    return Self::parse_role(role_name);
                }
            }
            None
        }

        /// Build connection settings from config.
        fn conn_settings(&self) -> LdapConnSettings {
            let settings = LdapConnSettings::new()
                .set_conn_timeout(std::time::Duration::from_secs(self.config.timeout_secs));

            match self.config.tls_mode {
                LdapTlsMode::StartTls => settings.set_starttls(true),
                // For Ldaps, the URL scheme "ldaps://" handles TLS.
                // For None, no TLS configuration needed.
                _ => settings,
            }
        }

        /// Open a fresh LDAP connection.
        fn open_connection(&self) -> HsmResult<LdapConn> {
            let settings = self.conn_settings();
            LdapConn::with_settings(settings, &self.config.url).map_err(|e| {
                tracing::error!(url = %self.config.url, error = %e, "Failed to connect to LDAP server");
                HsmError::GeneralError
            })
        }

        /// Get a connection, reusing a cached one from any pool slot if available.
        /// Returns the connection and a flag indicating whether it is an
        /// overflow connection (not from a pool slot). Caller must return it
        /// via `return_connection`.
        ///
        /// The method uses a two-pass approach to avoid opening unbounded
        /// connections under contention:
        ///   1. First pass: `try_lock` each slot (non-blocking), take a
        ///      cached connection if available.
        ///   2. If all try_locks failed or all slots were empty, attempt to
        ///      open a new connection — but only if the overflow limit has
        ///      not been reached. This bounds the total number of concurrent
        ///      connections to `pool_size + max_overflow`.
        pub(crate) fn take_connection(&self) -> HsmResult<(LdapConn, bool)> {
            // First pass: non-blocking try_lock on each slot.
            // parking_lot's `try_lock` returns `Option<MutexGuard>` (no
            // poisoning), so a `None` means the slot is currently held by
            // another thread.
            let mut all_locked = true;
            for slot in &self.pool {
                if let Some(mut guard) = slot.try_lock() {
                    all_locked = false;
                    if let Some(conn) = guard.take() {
                        return Ok((conn, false));
                    }
                }
            }

            // If at least one slot was unlockable but empty, or all were
            // contended, we need to open a new connection.  Check the
            // overflow limit first to prevent unbounded growth.
            if all_locked {
                // All slots were contended — do a blocking wait on slot 0
                // so we can reuse a connection rather than creating overflow.
                // parking_lot's `lock` is infallible (no PoisonError), which
                // is what we want: a previous panic must not take the pool
                // permanently offline.
                let mut guard = self.pool[0].lock();
                if let Some(conn) = guard.take() {
                    return Ok((conn, false));
                }
                // Slot was empty even after blocking; fall through to overflow path.
            }

            // Check overflow limit.
            let current = self.overflow_count.load(Ordering::Acquire);
            if current >= self.max_overflow {
                tracing::warn!(
                    pool_size = self.pool.len(),
                    overflow = current,
                    max_overflow = self.max_overflow,
                    "LDAP connection pool exhausted — all slots busy and overflow limit reached"
                );
                return Err(crate::error::connection_pool_exhausted());
            }
            self.overflow_count.fetch_add(1, Ordering::Release);

            match self.open_connection() {
                Ok(conn) => Ok((conn, true)),
                Err(e) => {
                    // Roll back overflow counter on connection failure.
                    self.overflow_count.fetch_sub(1, Ordering::Release);
                    Err(e)
                }
            }
        }

        /// Return a connection to the pool for reuse.
        ///
        /// `is_overflow` must be `true` if the connection was created as an
        /// overflow (not from a pool slot) so the overflow counter is decremented.
        fn return_connection(&self, conn: LdapConn, is_overflow: bool) {
            if is_overflow {
                self.overflow_count.fetch_sub(1, Ordering::Release);
            }
            for slot in &self.pool {
                if let Some(mut guard) = slot.try_lock() {
                    if guard.is_none() {
                        *guard = Some(conn);
                        return;
                    }
                }
            }
            // All slots full -- drop the connection (overflow counter already
            // decremented above if applicable).
        }

        /// Perform the LDAP bind and group search.
        ///
        /// 1. Bind as the user to verify credentials.
        /// 2. Search for the user entry to retrieve group membership and
        ///    optional tenant attribute.
        /// 3. Map groups to an HSM role.
        fn ldap_authenticate(&self, username: &str, password: &str) -> HsmResult<AuthResult> {
            // Use RFC 4514 DN escaping for the bind DN (not filter escaping).
            // Wrap the constructed bind DN in `Zeroizing` so the attacker-
            // controlled username suffix doesn't sit on the stack after the
            // function returns (audit finding H10).
            let dn_safe_username = zeroize::Zeroizing::new(escape_dn_value(username));
            let bind_dn = zeroize::Zeroizing::new(
                self.config
                    .bind_dn_template
                    .replace("{}", dn_safe_username.as_str()),
            );
            // Use RFC 4515 filter escaping for the search filter.
            let escaped_username = zeroize::Zeroizing::new(escape_ldap_filter(username));

            // Try to get a cached connection; if that fails or the bind fails
            // due to a stale connection, open a fresh one and retry once.
            let (mut ldap, is_overflow) = self.take_connection()?;

            let bind_result = ldap.simple_bind(&bind_dn, password);
            let (mut ldap, is_overflow) = match bind_result {
                Ok(res) => {
                    if res.rc != 0 {
                        tracing::warn!(
                            user_hash = %Self::hashed_username(username),
                            rc = res.rc,
                            "LDAP bind failed: invalid credentials"
                        );
                        return Err(HsmError::PinIncorrect);
                    }
                    (ldap, is_overflow)
                }
                Err(_e) => {
                    // Drop the stale connection; if it was overflow, decrement.
                    drop(ldap);
                    if is_overflow {
                        self.overflow_count.fetch_sub(1, Ordering::Release);
                    }
                    tracing::debug!(
                        "LDAP bind failed on cached connection, retrying with fresh connection"
                    );
                    let mut fresh = self.open_connection()?;
                    let res = fresh.simple_bind(&bind_dn, password).map_err(|e| {
                        tracing::error!(error = %e, "LDAP bind failed");
                        HsmError::GeneralError
                    })?;
                    if res.rc != 0 {
                        tracing::warn!(
                            user_hash = %Self::hashed_username(username),
                            rc = res.rc,
                            "LDAP bind failed: invalid credentials"
                        );
                        return Err(HsmError::PinIncorrect);
                    }
                    // Fresh retry connection is not tracked as overflow —
                    // it replaces the one we just dropped.
                    (fresh, false)
                }
            };

            // Search for the user entry to get group membership.
            let search_filter = self
                .config
                .user_search_filter
                .replace("{}", &escaped_username);
            let mut attrs = vec![self.config.group_attribute.as_str()];
            if let Some(ref tenant_attr) = self.config.tenant_attribute {
                attrs.push(tenant_attr.as_str());
            }

            let search_result = ldap
                .search(&self.config.base_dn, Scope::Subtree, &search_filter, attrs)
                .map_err(|e| {
                    tracing::error!(error = %e, "LDAP search failed");
                    HsmError::GeneralError
                })?;

            let (entries, _res) = search_result.success().map_err(|e| {
                tracing::error!(error = %e, "LDAP search result error");
                HsmError::GeneralError
            })?;

            // Return the connection to the pool for reuse. The LDAP connection
            // remains usable after search; unbinding would force a reconnect.
            self.return_connection(ldap, is_overflow);

            if entries.is_empty() {
                tracing::warn!(
                    user_hash = %Self::hashed_username(username),
                    "LDAP user entry not found after successful bind"
                );
                return Err(HsmError::PinIncorrect);
            }

            let entry = SearchEntry::construct(entries[0].clone());

            // Extract groups.
            let groups = entry
                .attrs
                .get(&self.config.group_attribute)
                .cloned()
                .unwrap_or_default();

            // Map groups to role.
            let role = match self.map_role(&groups) {
                Some(role) => role,
                None => {
                    tracing::warn!(
                        user_hash = %Self::hashed_username(username),
                        group_count = groups.len(),
                        "No LDAP group matched any configured role — denying access"
                    );
                    return Err(crate::error::operation_denied());
                }
            };

            // Extract tenant ID if configured.  Validate strictly: an attacker
            // who controls their own directory entry could otherwise inject a
            // path-traversal or log-injection payload via this attribute.
            let tenant_id = match self
                .config
                .tenant_attribute
                .as_ref()
                .and_then(|attr| entry.attrs.get(attr).and_then(|vals| vals.first()).cloned())
            {
                Some(raw) => Some(TenantId::try_new(raw).map_err(|e| {
                    tracing::warn!(
                        user_hash = %Self::hashed_username(username),
                        error = %e,
                        "LDAP tenant attribute is not a valid TenantId"
                    );
                    // The core HsmError enum does not expose a TenantInvalid
                    // variant, so we map directory-side malformed tenant IDs
                    // onto PinIncorrect — the same fail-closed credential
                    // rejection path used for every other auth failure in
                    // this provider. The structured warn! above preserves
                    // the real reason for operator triage.
                    HsmError::PinIncorrect
                })?),
                None => None,
            };

            Ok(AuthResult {
                role,
                user_id: format!("ldap:{}", username),
                tenant_id,
                mfa_required: self.config.require_mfa,
            })
        }
    }

    impl AuthProvider for LdapAuthProvider {
        fn authenticate(&self, credentials: &AuthCredentials) -> HsmResult<AuthResult> {
            match credentials {
                AuthCredentials::LdapBind { username, password } => {
                    let hashed_key = Self::hashed_username(username);
                    self.rate_limiter.check_rate_limit(&hashed_key)?;

                    match self.ldap_authenticate(username.as_str(), password.as_str()) {
                        Ok(result) => {
                            self.rate_limiter.record_success(&hashed_key);
                            Ok(result)
                        }
                        Err(e) => {
                            self.rate_limiter.record_failure(&hashed_key);
                            Err(e)
                        }
                    }
                }
                _ => Err(HsmError::FunctionNotSupported),
            }
        }

        fn name(&self) -> &str {
            "ldap"
        }
    }
}

// Stub module when ldap-auth feature is not enabled.
#[cfg(not(feature = "ldap-auth"))]
mod inner {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize};

    use crate::auth::provider::{AuthCredentials, AuthProvider, AuthResult};
    use craton_hsm::error::{HsmError, HsmResult};

    /// TLS mode for the LDAP connection.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum LdapTlsMode {
        /// Plain LDAP, no TLS.
        None,
        /// LDAPS (TLS from connection start).
        Ldaps,
        /// STARTTLS upgrade on a plain connection.
        StartTls,
    }

    impl Default for LdapTlsMode {
        fn default() -> Self {
            Self::StartTls
        }
    }

    /// LDAP authentication configuration.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LdapConfig {
        /// LDAP server URL.
        pub url: String,
        /// Base DN for user searches.
        pub base_dn: String,
        /// Bind DN template ("uid={},ou=users,dc=example,dc=com").
        pub bind_dn_template: String,
        /// Mapping from LDAP group DN (or CN) to HSM role name.
        pub role_mapping: BTreeMap<String, String>,
        /// LDAP attribute that carries the tenant ID, if any.
        pub tenant_attribute: Option<String>,
        /// TLS mode for the connection.
        #[serde(default)]
        pub tls_mode: LdapTlsMode,
        /// Search filter template for locating the user entry.
        #[serde(default = "default_user_filter")]
        pub user_search_filter: String,
        /// Attribute holding group membership on the user entry.
        #[serde(default = "default_group_attribute")]
        pub group_attribute: String,
        /// Connection timeout in seconds.
        #[serde(default = "default_timeout_secs")]
        pub timeout_secs: u64,
        /// Require MFA for LDAP-authenticated sessions.
        #[serde(default)]
        pub require_mfa: bool,
        /// Number of pooled connections maintained.
        #[serde(default = "default_pool_size")]
        pub pool_size: usize,
        /// Maximum total open connections (pool + overflow).
        #[serde(default)]
        pub max_connections: Option<usize>,
        /// Rate-limit configuration for authentication failures.
        #[serde(default)]
        pub rate_limit: Option<crate::auth::rate_limit::RateLimitConfig>,
        /// Audit fix 1.4 -- explicit opt-in for plaintext LDAP (see the
        /// `ldap-auth`-enabled variant of this struct for rationale).
        #[serde(default)]
        pub allow_plaintext: bool,
    }

    fn default_user_filter() -> String {
        "(uid={})".to_string()
    }

    fn default_group_attribute() -> String {
        "memberOf".to_string()
    }

    fn default_timeout_secs() -> u64 {
        10
    }

    fn default_pool_size() -> usize {
        4
    }

    impl LdapConfig {
        /// Validate template fields contain exactly one `{}` placeholder each.
        /// See the `ldap-auth`-enabled variant of this method for rationale.
        pub fn validate(&self) -> craton_hsm::error::HsmResult<()> {
            fn count(s: &str) -> usize {
                s.matches("{}").count()
            }
            if count(&self.bind_dn_template) != 1 {
                return Err(craton_hsm::error::HsmError::ConfigError(format!(
                    "ldap: bind_dn_template must contain exactly one `{{}}` placeholder, got {}",
                    count(&self.bind_dn_template)
                )));
            }
            if count(&self.user_search_filter) != 1 {
                return Err(craton_hsm::error::HsmError::ConfigError(format!(
                    "ldap: user_search_filter must contain exactly one `{{}}` placeholder, got {}",
                    count(&self.user_search_filter)
                )));
            }
            // Audit fix 1.4: refuse plaintext LDAP unless the operator
            // explicitly opted in.
            if matches!(self.tls_mode, LdapTlsMode::None) && !self.allow_plaintext {
                return Err(craton_hsm::error::HsmError::ConfigError(
                    "ldap: tls_mode = none requires allow_plaintext = true; \n                     bind credentials would traverse the network in cleartext".into(),
                ));
            }
            Ok(())
        }
    }

    /// LDAP authentication provider (stub when `ldap-auth` feature is disabled).
    pub struct LdapAuthProvider {
        _config: LdapConfig,
        _rate_limiter: crate::auth::rate_limit::AuthRateLimiter,
    }

    impl LdapAuthProvider {
        /// Construct the stub LDAP provider; all authentication requests fail
        /// with `FunctionNotSupported` until the `ldap-auth` feature is enabled.
        pub fn new(config: LdapConfig) -> Self {
            let rate_limiter = crate::auth::rate_limit::AuthRateLimiter::new(
                config.rate_limit.clone().unwrap_or_default(),
            );
            Self {
                _config: config,
                _rate_limiter: rate_limiter,
            }
        }
    }

    impl AuthProvider for LdapAuthProvider {
        fn authenticate(&self, _credentials: &AuthCredentials) -> HsmResult<AuthResult> {
            Err(HsmError::FunctionNotSupported)
        }

        fn name(&self) -> &str {
            "ldap"
        }
    }
}

pub use inner::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
// Existing tests still exercise the legacy panicking `new()` constructor.
// They predate the 0.1.3 deprecation; new tests should call `try_new()`.
#[allow(deprecated)]
mod tests {
    use super::*;
    use craton_hsm::error::HsmError;
    use std::collections::BTreeMap;

    /// Helper to build a test config with sensible defaults.
    fn test_config() -> LdapConfig {
        let mut role_mapping = BTreeMap::new();
        role_mapping.insert(
            "cn=hsm-admins,ou=groups,dc=example,dc=com".to_string(),
            "SO".to_string(),
        );
        role_mapping.insert(
            "cn=hsm-operators,ou=groups,dc=example,dc=com".to_string(),
            "Operator".to_string(),
        );
        role_mapping.insert(
            "cn=hsm-auditors,ou=groups,dc=example,dc=com".to_string(),
            "Auditor".to_string(),
        );
        role_mapping.insert(
            "cn=hsm-keymgrs,ou=groups,dc=example,dc=com".to_string(),
            "KeyManager".to_string(),
        );
        role_mapping.insert(
            "cn=hsm-users,ou=groups,dc=example,dc=com".to_string(),
            "User".to_string(),
        );

        LdapConfig {
            url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn_template: "uid={},ou=users,dc=example,dc=com".to_string(),
            role_mapping,
            tenant_attribute: Some("departmentNumber".to_string()),
            tls_mode: LdapTlsMode::None,
            user_search_filter: "(uid={})".to_string(),
            group_attribute: "memberOf".to_string(),
            timeout_secs: 5,
            require_mfa: false,
            pool_size: 4,
            max_connections: None,
            rate_limit: None,
            // Audit fix 1.4: tests intentionally exercise plaintext LDAP
            // for connection-pool / role-mapping coverage. Production
            // configs must NOT set this flag.
            allow_plaintext: true,
        }
    }

    // -----------------------------------------------------------------------
    // Config serialization / deserialization
    // -----------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Template validation — LDAP config {} placeholder guard
    // ------------------------------------------------------------------

    #[test]
    fn validate_accepts_good_templates() {
        let cfg = test_config();
        cfg.validate().expect("well-formed templates must validate");
    }

    /// Audit fix 1.4 -- a config with `tls_mode = None` and the default
    /// `allow_plaintext = false` must be rejected by `validate()`.
    #[test]
    fn validate_rejects_plaintext_without_opt_in() {
        let mut cfg = test_config();
        cfg.allow_plaintext = false; // plaintext NOT explicitly opted in
        cfg.tls_mode = LdapTlsMode::None;
        let err = cfg
            .validate()
            .expect_err("plaintext without opt-in must error");
        match err {
            craton_hsm::error::HsmError::ConfigError(msg) => {
                assert!(
                    msg.contains("allow_plaintext"),
                    "err must mention allow_plaintext: {msg}"
                );
            }
            other => panic!("expected ConfigError, got {other:?}"),
        }
    }

    /// Plaintext is allowed when the operator explicitly opts in.
    #[test]
    fn validate_accepts_plaintext_with_explicit_opt_in() {
        let mut cfg = test_config();
        cfg.tls_mode = LdapTlsMode::None;
        cfg.allow_plaintext = true;
        cfg.validate().expect("plaintext with opt-in must validate");
    }

    /// TLS configurations validate regardless of the opt-in flag because
    /// no plaintext credential would actually traverse the wire.
    #[test]
    fn validate_accepts_tls_modes_regardless_of_opt_in() {
        for mode in [LdapTlsMode::Ldaps, LdapTlsMode::StartTls] {
            let mut cfg = test_config();
            cfg.tls_mode = mode.clone();
            cfg.allow_plaintext = false;
            cfg.validate().expect("non-plaintext modes must validate");
        }
    }

    #[test]
    fn validate_rejects_missing_placeholder_in_bind_dn() {
        let mut cfg = test_config();
        cfg.bind_dn_template = "cn=admin,dc=example,dc=com".to_string();
        let err = cfg.validate().expect_err("must reject: no {} in bind_dn");
        match err {
            HsmError::ConfigError(msg) => assert!(msg.contains("bind_dn_template")),
            other => panic!("expected ConfigError, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_placeholder_in_user_filter() {
        let mut cfg = test_config();
        cfg.user_search_filter = "(objectClass=person)".to_string();
        let err = cfg.validate().expect_err("must reject: no {} in filter");
        match err {
            HsmError::ConfigError(msg) => assert!(msg.contains("user_search_filter")),
            other => panic!("expected ConfigError, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_multiple_placeholders() {
        let mut cfg = test_config();
        cfg.user_search_filter = "(|(uid={})(cn={}))".to_string();
        let err = cfg.validate().expect_err("must reject: two {} in filter");
        match err {
            HsmError::ConfigError(msg) => assert!(msg.contains("user_search_filter")),
            other => panic!("expected ConfigError, got {other:?}"),
        }
    }

    #[cfg(feature = "ldap-auth")]
    #[test]
    fn try_new_propagates_validation_error() {
        let mut cfg = test_config();
        cfg.bind_dn_template = "cn=admin,dc=example,dc=com".to_string();
        assert!(LdapAuthProvider::try_new(cfg).is_err());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: LdapConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.url, config.url);
        assert_eq!(parsed.base_dn, config.base_dn);
        assert_eq!(parsed.bind_dn_template, config.bind_dn_template);
        assert_eq!(parsed.role_mapping.len(), config.role_mapping.len());
        assert_eq!(parsed.tenant_attribute, config.tenant_attribute);
        assert_eq!(parsed.tls_mode, config.tls_mode);
        assert_eq!(parsed.user_search_filter, config.user_search_filter);
        assert_eq!(parsed.group_attribute, config.group_attribute);
        assert_eq!(parsed.timeout_secs, config.timeout_secs);
        assert_eq!(parsed.require_mfa, config.require_mfa);
        assert_eq!(parsed.pool_size, config.pool_size);
        assert_eq!(parsed.max_connections, config.max_connections);
    }

    #[test]
    fn test_config_defaults_applied() {
        let json = r#"{
            "url": "ldap://localhost",
            "base_dn": "dc=test,dc=com",
            "bind_dn_template": "uid={},dc=test,dc=com",
            "role_mapping": {}
        }"#;
        let config: LdapConfig = serde_json::from_str(json).expect("deserialize");

        assert_eq!(config.tls_mode, LdapTlsMode::StartTls);
        assert_eq!(config.user_search_filter, "(uid={})");
        assert_eq!(config.group_attribute, "memberOf");
        assert_eq!(config.timeout_secs, 10);
        assert!(!config.require_mfa);
        assert!(config.tenant_attribute.is_none());
        assert_eq!(config.pool_size, 4);
        assert!(config.max_connections.is_none());
    }

    #[test]
    fn test_config_tls_modes() {
        for (mode_str, expected) in [
            ("\"none\"", LdapTlsMode::None),
            ("\"ldaps\"", LdapTlsMode::Ldaps),
            ("\"starttls\"", LdapTlsMode::StartTls),
        ] {
            let json = format!(
                r#"{{
                    "url": "ldap://localhost",
                    "base_dn": "dc=test,dc=com",
                    "bind_dn_template": "uid={{}},dc=test,dc=com",
                    "role_mapping": {{}},
                    "tls_mode": {}
                }}"#,
                mode_str
            );
            let config: LdapConfig = serde_json::from_str(&json).expect("deserialize tls mode");
            assert_eq!(config.tls_mode, expected);
        }
    }

    #[test]
    fn test_config_with_mfa_required() {
        let json = r#"{
            "url": "ldaps://ldap.corp.example.com",
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn_template": "cn={},ou=people,dc=corp,dc=example,dc=com",
            "role_mapping": {"cn=admins,dc=corp,dc=example,dc=com": "SO"},
            "tls_mode": "ldaps",
            "require_mfa": true
        }"#;
        let config: LdapConfig = serde_json::from_str(json).expect("deserialize");
        assert!(config.require_mfa);
        assert_eq!(config.tls_mode, LdapTlsMode::Ldaps);
    }

    // -----------------------------------------------------------------------
    // Role mapping (tested via LdapAuthProvider::map_role)
    // -----------------------------------------------------------------------

    #[cfg(feature = "ldap-auth")]
    mod role_mapping_tests {
        use super::*;
        use crate::rbac::role::HsmRole;

        #[test]
        fn test_map_role_so() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=hsm-admins,ou=groups,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), Some(HsmRole::So));
        }

        #[test]
        fn test_map_role_operator() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=hsm-operators,ou=groups,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), Some(HsmRole::Operator));
        }

        #[test]
        fn test_map_role_auditor() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=hsm-auditors,ou=groups,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), Some(HsmRole::Auditor));
        }

        #[test]
        fn test_map_role_keymanager() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=hsm-keymgrs,ou=groups,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), Some(HsmRole::KeyManager));
        }

        #[test]
        fn test_map_role_user() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=hsm-users,ou=groups,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), Some(HsmRole::User));
        }

        #[test]
        fn test_map_role_no_match() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=random-group,ou=groups,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), None);
        }

        #[test]
        fn test_map_role_empty_groups() {
            let provider = LdapAuthProvider::new(test_config());
            assert_eq!(provider.map_role(&[]), None);
        }

        #[test]
        fn test_map_role_multiple_groups_returns_first_match() {
            let provider = LdapAuthProvider::new(test_config());
            // User is in multiple groups; we get whichever mapping matches first.
            let groups = vec![
                "cn=unrelated,ou=groups,dc=example,dc=com".to_string(),
                "cn=hsm-operators,ou=groups,dc=example,dc=com".to_string(),
                "cn=hsm-auditors,ou=groups,dc=example,dc=com".to_string(),
            ];
            let role = provider.map_role(&groups);
            assert!(role.is_some());
            // Should be one of the matched roles.
            let r = role.unwrap();
            assert!(r == HsmRole::Operator || r == HsmRole::Auditor);
        }

        #[test]
        fn test_map_role_no_match_returns_none() {
            let provider = LdapAuthProvider::new(test_config());
            let groups = vec!["cn=unrecognized-group,dc=example,dc=com".to_string()];
            assert_eq!(provider.map_role(&groups), None);
        }

        #[test]
        fn test_parse_role_variants() {
            assert_eq!(LdapAuthProvider::parse_role("User"), Some(HsmRole::User));
            assert_eq!(LdapAuthProvider::parse_role("SO"), Some(HsmRole::So));
            assert_eq!(LdapAuthProvider::parse_role("So"), Some(HsmRole::So));
            assert_eq!(
                LdapAuthProvider::parse_role("Auditor"),
                Some(HsmRole::Auditor)
            );
            assert_eq!(
                LdapAuthProvider::parse_role("KeyManager"),
                Some(HsmRole::KeyManager)
            );
            assert_eq!(
                LdapAuthProvider::parse_role("Operator"),
                Some(HsmRole::Operator)
            );
            assert_eq!(LdapAuthProvider::parse_role("invalid"), None);
            assert_eq!(LdapAuthProvider::parse_role(""), None);
        }

        /// Verify that `take_connection` can hand out connections from
        /// different pool slots concurrently (i.e., holding one slot locked
        /// does not block access to others).
        #[test]
        fn test_pool_concurrent_take() {
            let mut config = test_config();
            config.pool_size = 3;
            // Point at a non-routable address so open_connection would fail;
            // we pre-populate the pool instead.
            config.url = "ldap://127.0.0.1:1".to_string();
            config.timeout_secs = 1;

            let provider = LdapAuthProvider::new(config);

            // The pool should have 3 slots, all initially None.
            assert_eq!(provider.pool.len(), 3);

            // Manually lock slot 0 to simulate contention.
            // parking_lot's `lock` returns the guard directly (no Result).
            let _guard = provider.pool[0].lock();

            // take_connection should still succeed by skipping the locked
            // slot and falling through to open_connection (which will fail
            // here since we have no server).  The important assertion is
            // that the method does *not* deadlock or panic due to the held
            // lock on slot 0.
            // We cannot easily pre-fill slots without a real LdapConn, so
            // just verify it reaches open_connection without blocking.
            let result = provider.take_connection();
            // Expected: Err because the server is unreachable, not a deadlock.
            assert!(result.is_err());
        }

        /// Verify that the overflow counter is respected: once max_overflow
        /// is reached, `take_connection` returns an error instead of opening
        /// more connections.
        #[test]
        fn test_pool_overflow_limit_enforced() {
            use std::sync::atomic::Ordering;

            let mut config = test_config();
            config.pool_size = 2;
            config.max_connections = Some(3); // pool=2, overflow=1
            config.url = "ldap://127.0.0.1:1".to_string();
            config.timeout_secs = 1;

            let provider = LdapAuthProvider::new(config);
            assert_eq!(provider.max_overflow, 1);

            // Simulate that one overflow connection is already outstanding.
            provider.overflow_count.store(1, Ordering::Release);

            // All pool slots are empty but unlockable, so take_connection
            // will try to open overflow but should be rejected because
            // overflow_count (1) >= max_overflow (1).
            let result = provider.take_connection();
            assert!(result.is_err(), "should reject when overflow limit reached");
        }

        /// Verify the default max_overflow is 2 when max_connections is None.
        #[test]
        fn test_pool_default_max_overflow() {
            let mut config = test_config();
            config.pool_size = 4;
            config.max_connections = None;

            let provider = LdapAuthProvider::new(config);
            assert_eq!(provider.max_overflow, 2);
        }

        /// Verify custom max_connections config.
        #[test]
        fn test_pool_custom_max_connections() {
            let mut config = test_config();
            config.pool_size = 4;
            config.max_connections = Some(10);

            let provider = LdapAuthProvider::new(config);
            // max_overflow = 10 - 4 = 6
            assert_eq!(provider.max_overflow, 6);
        }

        /// Verify max_connections smaller than pool_size results in 0 overflow.
        #[test]
        fn test_pool_max_connections_saturating() {
            let mut config = test_config();
            config.pool_size = 4;
            config.max_connections = Some(2); // less than pool_size

            let provider = LdapAuthProvider::new(config);
            assert_eq!(provider.max_overflow, 0);
        }

        /// Audit finding M9: verify that a panic in a thread holding a pool
        /// slot lock does *not* poison the pool. With `std::sync::Mutex` this
        /// would permanently take the slot offline; with `parking_lot::Mutex`
        /// the slot must remain usable after the panic unwinds.
        #[test]
        fn test_pool_survives_panic_in_slot_holder() {
            use std::sync::Arc;

            let mut config = test_config();
            config.pool_size = 2;
            config.url = "ldap://127.0.0.1:1".to_string();
            config.timeout_secs = 1;

            let provider = Arc::new(LdapAuthProvider::new(config));

            // Spawn a thread that locks slot 0 and then panics while still
            // holding the guard. `std::sync::Mutex` would mark the slot as
            // poisoned; `parking_lot` does not.
            let p = Arc::clone(&provider);
            let handle = std::thread::spawn(move || {
                let _guard = p.pool[0].lock();
                panic!("simulated worker panic while holding pool slot");
            });
            // Joining a panicked thread yields Err — we only care that it
            // panicked, not the payload.
            assert!(handle.join().is_err());

            // Slot 0 must still be lockable after the panic.
            {
                let guard = provider.pool[0].try_lock();
                assert!(
                    guard.is_some(),
                    "slot 0 should not be poisoned after panic (parking_lot semantics)"
                );
            }
            // And the full `take_connection` path must still be usable — it
            // should fail with a connection error, not a poison error.
            let result = provider.take_connection();
            assert!(result.is_err(), "expected connect failure, not poison");
        }
    }

    // -----------------------------------------------------------------------
    // Credential validation (non-LDAP credentials rejected)
    // -----------------------------------------------------------------------

    #[test]
    fn test_non_ldap_credentials_rejected() {
        use crate::auth::provider::{AuthCredentials, AuthProvider};
        use craton_hsm::error::HsmError;
        use zeroize::Zeroizing;

        let provider = LdapAuthProvider::new(test_config());

        // PIN credentials should be rejected.
        let pin_creds = AuthCredentials::Pin {
            user_type: 1,
            pin: Zeroizing::new(vec![1, 2, 3, 4]),
        };
        let result = provider.authenticate(&pin_creds);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HsmError::FunctionNotSupported
        ));

        // Token credentials should be rejected.
        let token_creds = AuthCredentials::Token {
            bearer_token: zeroize::Zeroizing::new("some.jwt.token".to_string()),
        };
        let result = provider.authenticate(&token_creds);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HsmError::FunctionNotSupported
        ));

        // Certificate credentials should be rejected.
        let cert_creds = AuthCredentials::Certificate {
            cert_chain: vec![vec![0u8; 32]],
        };
        let result = provider.authenticate(&cert_creds);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HsmError::FunctionNotSupported
        ));
    }

    #[test]
    fn test_provider_name() {
        use crate::auth::provider::AuthProvider;

        let provider = LdapAuthProvider::new(test_config());
        assert_eq!(provider.name(), "ldap");
    }

    // -----------------------------------------------------------------------
    // LDAP bind against a non-existent server (integration-style, no mock)
    // -----------------------------------------------------------------------

    #[cfg(feature = "ldap-auth")]
    #[test]
    fn test_ldap_bind_connection_failure() {
        use crate::auth::provider::{AuthCredentials, AuthProvider};
        use craton_hsm::error::HsmError;
        use zeroize::Zeroizing;

        // Use a non-routable address with a short timeout so the test
        // completes quickly. Port 1 is almost certainly not running LDAP.
        let mut config = test_config();
        config.url = "ldap://127.0.0.1:1".to_string();
        config.timeout_secs = 1;

        let provider = LdapAuthProvider::new(config);
        let creds = AuthCredentials::LdapBind {
            username: Zeroizing::new("testuser".to_string()),
            password: Zeroizing::new("testpass".to_string()),
        };

        let result = provider.authenticate(&creds);
        assert!(result.is_err());
        // Connection failure maps to GeneralError.
        assert!(matches!(result.unwrap_err(), HsmError::GeneralError));
    }

    // -----------------------------------------------------------------------
    // Bind DN template substitution
    // -----------------------------------------------------------------------

    #[test]
    fn test_bind_dn_template_substitution() {
        let config = test_config();
        let bind_dn = config.bind_dn_template.replace("{}", "alice");
        assert_eq!(bind_dn, "uid=alice,ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_search_filter_substitution() {
        let config = test_config();
        let filter = config.user_search_filter.replace("{}", "bob");
        assert_eq!(filter, "(uid=bob)");
    }

    // -----------------------------------------------------------------------
    // LdapTlsMode default
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_mode_default() {
        // Secure-by-default: bind credentials must not flow over plaintext
        // unless an operator explicitly opts in by setting tls_mode = "none".
        assert_eq!(LdapTlsMode::default(), LdapTlsMode::StartTls);
    }

    // -----------------------------------------------------------------------
    // LDAP injection prevention
    // -----------------------------------------------------------------------

    #[cfg(feature = "ldap-auth")]
    mod ldap_injection_tests {
        use super::inner::{escape_dn_value, escape_ldap_filter, escape_rfc4515};

        #[test]
        fn test_escape_ldap_filter_normal_input() {
            assert_eq!(escape_ldap_filter("alice"), "alice");
        }

        #[test]
        fn test_escape_ldap_filter_special_chars() {
            assert_eq!(
                escape_ldap_filter("user*)(&(objectClass=*"),
                "user\\2a\\29\\28&\\28objectClass=\\2a"
            );
        }

        #[test]
        fn test_escape_ldap_filter_backslash() {
            assert_eq!(escape_ldap_filter("user\\name"), "user\\5cname");
        }

        #[test]
        fn test_escape_ldap_filter_null_byte() {
            assert_eq!(escape_ldap_filter("admin\0"), "admin\\00");
        }

        #[test]
        fn test_escape_ldap_filter_parentheses() {
            assert_eq!(escape_ldap_filter("(test)"), "\\28test\\29");
        }

        // ------------------------------------------------------------------
        // RFC 4514 DN escaping
        // ------------------------------------------------------------------

        #[test]
        fn test_escape_dn_value_normal() {
            assert_eq!(escape_dn_value("alice"), "alice");
        }

        #[test]
        fn test_escape_dn_value_comma_injection() {
            // A DN injection attempt: "alice,cn=admin" must not alter the DN structure.
            let escaped = escape_dn_value("alice,cn=admin");
            assert_eq!(escaped, "alice\\,cn=admin");
            // The substituted bind DN must not contain an unescaped comma.
            let bind_dn = format!("uid={},ou=users,dc=example,dc=com", escaped);
            assert_eq!(bind_dn, "uid=alice\\,cn=admin,ou=users,dc=example,dc=com");
        }

        #[test]
        fn test_escape_dn_value_plus_injection() {
            assert_eq!(escape_dn_value("a+b"), "a\\+b");
        }

        #[test]
        fn test_escape_dn_value_leading_space() {
            assert_eq!(escape_dn_value(" alice"), "\\ alice");
        }

        #[test]
        fn test_escape_dn_value_leading_hash() {
            assert_eq!(escape_dn_value("#admin"), "\\#admin");
        }

        #[test]
        fn test_escape_dn_value_trailing_space() {
            assert_eq!(escape_dn_value("alice "), "alice\\ ");
        }

        #[test]
        fn test_escape_dn_value_backslash() {
            assert_eq!(escape_dn_value("a\\b"), "a\\\\b");
        }

        #[test]
        fn test_escape_dn_value_double_quote() {
            assert_eq!(escape_dn_value("a\"b"), "a\\\"b");
        }

        #[test]
        fn test_escape_dn_value_semicolon() {
            assert_eq!(escape_dn_value("a;b"), "a\\;b");
        }

        #[test]
        fn test_escape_dn_value_null() {
            assert_eq!(escape_dn_value("a\0b"), "a\\00b");
        }

        #[test]
        fn test_escape_dn_value_empty() {
            assert_eq!(escape_dn_value(""), "");
        }

        // ------------------------------------------------------------------
        // Targeted RFC 4515 injection vectors (Fix 3).
        //
        // Inputs lifted from real pentest write-ups — each one would break
        // filter structure if interpolated raw. The escaped form must never
        // contain an unescaped filter metacharacter.
        // ------------------------------------------------------------------

        #[test]
        fn test_escape_rfc4515_closing_paren_injection() {
            // Classic: close the current AVA and inject a wildcard on uid.
            let escaped = escape_ldap_filter("admin*)(uid=*");
            assert_eq!(escaped, "admin\\2a\\29\\28uid=\\2a");
            // No bare `*`, `(`, or `)` must survive — the filter structure
            // is now safe to interpolate.
            assert!(!escaped.chars().any(|c| matches!(c, '*' | '(' | ')')));
        }

        #[test]
        fn test_escape_rfc4515_trailing_backslash() {
            // A trailing backslash could start an escape that swallows the
            // next filter character, producing an unintended match.
            let escaped = escape_ldap_filter("admin\\");
            assert_eq!(escaped, "admin\\5c");
        }

        #[test]
        fn test_escape_rfc4515_null_byte() {
            // NUL is a valid Unicode char in Rust strings but LDAP filter
            // syntax requires it to be hex-escaped.
            let escaped = escape_ldap_filter("admin\0");
            assert_eq!(escaped, "admin\\00");
            // No literal NUL must survive in the escaped output.
            assert!(!escaped.contains('\0'));
        }

        #[test]
        fn test_escape_rfc4515_alias_matches_canonical() {
            // The RFC-named alias must be behaviourally identical.
            for s in &["admin*)(uid=*", "admin\\", "admin\0", "normal", ""] {
                assert_eq!(
                    escape_rfc4515(s),
                    escape_ldap_filter(s),
                    "mismatch for {s:?}"
                );
            }
        }

        #[test]
        fn test_user_filter_substitution_escapes_injection() {
            // End-to-end check: the substituted filter must be safe even if
            // the username contains the closing-paren injection payload.
            let default_filter = "(uid={})";
            let username = "admin*)(uid=*";
            let substituted = default_filter.replace("{}", &escape_ldap_filter(username));
            assert_eq!(substituted, "(uid=admin\\2a\\29\\28uid=\\2a)");
            // The filter must still be well-formed (balanced parens):
            let opens = substituted.matches('(').count();
            let closes = substituted.matches(')').count();
            assert_eq!(opens, closes, "paren balance broken: {substituted}");
            assert_eq!(opens, 1, "extra parens leaked through: {substituted}");
        }

        // ------------------------------------------------------------------
        // Fix 5: DN template escaping & group-membership mapping inline tests
        // ------------------------------------------------------------------

        #[test]
        fn test_dn_template_substitution_escapes_comma() {
            // The public API uses `escape_dn_value` before replace("{}", …).
            // This test pins the invariant that a `,` in the username cannot
            // split the bind DN into an attacker-controlled RDN.
            let template = "uid={},ou=users,dc=example,dc=com";
            let username = "alice,cn=admin";
            let dn = template.replace("{}", &escape_dn_value(username));
            // The comma after alice is escaped, so it remains a single RDN.
            assert!(dn.starts_with("uid=alice\\,cn=admin,"));
            // There must be exactly 4 unescaped commas (one per RDN
            // separator: after uid=, after ou=users, after dc=example,
            // before the final dc=com RDN).
            let unescaped_commas = dn
                .as_bytes()
                .windows(2)
                .filter(|w| w[1] == b',' && w[0] != b'\\')
                .count()
                + (dn.as_bytes().first().copied() == Some(b',')) as usize;
            assert_eq!(unescaped_commas, 3, "unexpected RDN count in {dn}");
        }

        #[test]
        fn test_dn_template_substitution_escapes_plus() {
            let template = "uid={},dc=example,dc=com";
            let dn = template.replace("{}", &escape_dn_value("a+admin"));
            assert_eq!(dn, "uid=a\\+admin,dc=example,dc=com");
        }

        #[test]
        fn test_dn_template_substitution_with_leading_hash() {
            // RFC 4514 §2.4 reserves a leading '#' for hex-encoded BER values;
            // an unescaped one would make the RDN parse as binary.
            let template = "uid={},dc=example,dc=com";
            let dn = template.replace("{}", &escape_dn_value("#weird"));
            assert_eq!(dn, "uid=\\#weird,dc=example,dc=com");
        }

        /// Test the post-bind group extraction logic end-to-end, using the
        /// same data shape an LDAP server would return (attributes as a
        /// map of name → list of string values).
        #[cfg(feature = "ldap-auth")]
        #[test]
        fn test_group_extraction_post_bind() {
            use super::super::LdapAuthProvider;
            let mut cfg = super::test_config();
            cfg.role_mapping.clear();
            cfg.role_mapping.insert(
                "cn=hsm-admins,ou=groups,dc=example,dc=com".to_string(),
                "SO".to_string(),
            );
            cfg.role_mapping.insert(
                "cn=hsm-users,ou=groups,dc=example,dc=com".to_string(),
                "User".to_string(),
            );
            let provider = LdapAuthProvider::new(cfg);

            // A user that belongs to both groups — the first configured
            // match (iteration order of BTreeMap, so "hsm-admins" < "hsm-users"
            // alphabetically) must win.
            let groups = vec![
                "cn=hsm-admins,ou=groups,dc=example,dc=com".to_string(),
                "cn=hsm-users,ou=groups,dc=example,dc=com".to_string(),
            ];
            let role = provider.map_role(&groups);
            assert!(role.is_some(), "expected role assignment from groups");

            // A user with only an unmapped group must get no role.
            let groups = vec!["cn=random-group,dc=example,dc=com".to_string()];
            assert!(provider.map_role(&groups).is_none());

            // An empty membership list yields no role.
            assert!(provider.map_role(&[]).is_none());
        }

        /// Verify that a username containing DN metacharacters does not slip
        /// through to the filter unescaped even when it contains *both*
        /// filter-side and DN-side specials.
        #[test]
        fn test_mixed_metachars_filter_and_dn_escaped() {
            let user = "a*b,c";
            let filter_part = escape_ldap_filter(user);
            let dn_part = escape_dn_value(user);
            // Filter side: `*` -> \2a, `,` is NOT a filter metachar so
            // left alone.
            assert_eq!(filter_part, "a\\2ab,c");
            // DN side: `,` -> \,, `*` is NOT a DN metachar so left alone.
            assert_eq!(dn_part, "a*b\\,c");
        }
    }
}
