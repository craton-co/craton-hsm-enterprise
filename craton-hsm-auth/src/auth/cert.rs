// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Certificate-based authentication provider.
//!
//! Extends the existing mTLS infrastructure by extracting role and tenant
//! information from the client certificate's Subject DN and SANs.

#[cfg(feature = "cert-auth")]
mod inner {
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};
    use x509_parser::oid_registry::{
        OID_X509_COMMON_NAME, OID_X509_EXT_SUBJECT_ALT_NAME, OID_X509_ORGANIZATIONAL_UNIT,
        OID_X509_ORGANIZATION_NAME,
    };
    use x509_parser::prelude::*;
    use x509_parser::x509::X509Name;

    use crate::auth::provider::{AuthCredentials, AuthProvider, AuthResult};
    use crate::rbac::role::HsmRole;
    use crate::tenant::tenant::TenantId;
    use craton_hsm::error::{HsmError, HsmResult};

    // -----------------------------------------------------------------------
    // CRL fetcher plumbing
    // -----------------------------------------------------------------------

    /// Pluggable fetcher for Certificate Revocation Lists.
    ///
    /// Implementations are expected to retrieve a DER-encoded CRL from a
    /// remote URL and return its raw bytes.  The trait is intentionally
    /// narrow so alternative transports (a local signed mirror, an S3
    /// bucket, a fronting proxy) can be injected without depending on a
    /// specific HTTP client.  Callers must enforce HTTPS-only, bounded
    /// size, and redirect handling inside the implementation — the
    /// generic layer above does not second-guess the transport.
    pub trait CrlFetcher: Send + Sync {
        /// Fetch a CRL by URL.  Returns the DER-encoded CRL on success.
        fn fetch(&self, url: &str) -> HsmResult<Vec<u8>>;
    }

    /// Default no-op fetcher that always returns
    /// [`HsmError::FunctionNotSupported`].
    ///
    /// Used when `CrlConfig::http_fetcher` is left unset.  Keeping the
    /// fetcher field `Option<Arc<dyn CrlFetcher>>` avoids a null check at
    /// every authentication; this impl exists so tests and downstream
    /// code that explicitly want the "fetching disabled" policy can spell
    /// it out rather than rely on `None`.
    pub struct NullCrlFetcher;

    impl CrlFetcher for NullCrlFetcher {
        fn fetch(&self, _url: &str) -> HsmResult<Vec<u8>> {
            Err(HsmError::FunctionNotSupported)
        }
    }

    /// Blocking HTTPS CRL fetcher (feature-gated).
    ///
    /// Deployment expectations:
    /// - Operator provides HTTPS URLs only; `http://`, `file://`, `ftp://`,
    ///   etc. are rejected up front.
    /// - Redirects are disabled: a compromised CDN or DNS entry must not
    ///   be able to divert the revocation check to an attacker server.
    /// - Timeout is capped at 5 seconds so CRL availability problems do
    ///   not stall the authentication path.
    /// - Body is capped at 10 MB; anything larger is treated as hostile.
    ///
    /// Building the fetcher performs a one-time construction of the
    /// `reqwest::blocking::Client`.  Reuse the same instance across many
    /// authentications to benefit from connection pooling.
    #[cfg(feature = "crl-http-fetch")]
    pub struct ReqwestCrlFetcher {
        client: reqwest::blocking::Client,
    }

    #[cfg(feature = "crl-http-fetch")]
    impl ReqwestCrlFetcher {
        /// Maximum CRL body size we will accept.  10 MiB is well above any
        /// real-world CRL and small enough to bound a malicious response.
        pub const MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;

        /// Build a new fetcher with the documented hardened defaults.
        pub fn new() -> HsmResult<Self> {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| {
                    tracing::error!("failed to build CRL HTTP client: {e}");
                    HsmError::GeneralError
                })?;
            Ok(Self { client })
        }
    }

    #[cfg(feature = "crl-http-fetch")]
    impl CrlFetcher for ReqwestCrlFetcher {
        fn fetch(&self, url: &str) -> HsmResult<Vec<u8>> {
            // Reject any non-https scheme early — defence in depth on top
            // of the client's `https_only(true)` so the error is precise
            // and cannot leak a request to an unexpected scheme handler.
            let parsed = reqwest::Url::parse(url).map_err(|e| {
                tracing::error!("CRL URL parse failed: {e}");
                HsmError::ArgumentsBad
            })?;
            if parsed.scheme() != "https" {
                tracing::error!(
                    scheme = parsed.scheme(),
                    "rejected CRL URL: only https is allowed"
                );
                return Err(HsmError::ArgumentsBad);
            }

            let resp = self.client.get(url).send().map_err(|e| {
                // A redirect trips this branch because the client has
                // `Policy::none()`; surface a clear error rather than a
                // generic network failure.
                tracing::error!("CRL fetch failed (possibly due to redirect): {e}");
                HsmError::GeneralError
            })?;

            if !resp.status().is_success() {
                tracing::error!(status = %resp.status(), "CRL fetch returned non-2xx");
                return Err(HsmError::GeneralError);
            }

            // Bound the body. `content_length()` may be absent (or lied
            // about), so we must cap the actual bytes read, not just trust
            // the header. Stream-read through `Read::take(MAX+1)` so an
            // attacker cannot exhaust memory by sending a chunked response
            // that omits Content-Length.
            if let Some(len) = resp.content_length() {
                if len > Self::MAX_BODY_BYTES {
                    tracing::error!(
                        content_length = len,
                        max = Self::MAX_BODY_BYTES,
                        "CRL response exceeds max body size"
                    );
                    return Err(HsmError::ArgumentsBad);
                }
            }
            use std::io::Read;
            // +1 so we can distinguish "exactly MAX" from "over MAX".
            let cap = Self::MAX_BODY_BYTES.saturating_add(1);
            let mut buf = Vec::with_capacity(
                resp.content_length().unwrap_or(0).min(Self::MAX_BODY_BYTES) as usize,
            );
            resp.take(cap).read_to_end(&mut buf).map_err(|e| {
                tracing::error!("CRL body read failed: {e}");
                HsmError::GeneralError
            })?;
            if buf.len() as u64 > Self::MAX_BODY_BYTES {
                tracing::error!(
                    len = buf.len(),
                    max = Self::MAX_BODY_BYTES,
                    "CRL response exceeded max body size while streaming"
                );
                return Err(HsmError::ArgumentsBad);
            }
            Ok(buf)
        }
    }

    /// Certificate authentication configuration.
    ///
    /// # CRL refresh
    ///
    /// [`CertConfig::http_fetcher`] may be set to any implementation of
    /// [`CrlFetcher`].  When the static `revocation.crls` entries are
    /// stale (see `revocation.max_age_secs`) and a fetcher is configured,
    /// `check_revocation` will attempt to refresh the in-memory CRL cache
    /// from `revocation.crl_urls` before deciding revocation status.  The
    /// fetcher is not serialised — it is strictly a runtime hook.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct CertConfig {
        /// Mapping from Subject DN patterns to roles.
        /// Key is a substring match on the Subject DN, value is the role name.
        pub subject_role_mapping: Vec<CertRoleMapping>,
        /// SAN (Subject Alternative Name) attribute for tenant ID extraction.
        pub tenant_san_oid: Option<String>,
        /// DER-encoded trusted root CA certificates. If non-empty, the leaf
        /// certificate must chain to one of these roots.
        #[serde(default)]
        pub trusted_roots: Vec<Vec<u8>>,
        /// Whether to require MFA for certificate-authenticated sessions.
        #[serde(default)]
        pub require_mfa: bool,
        /// Certificate revocation checking configuration.
        #[serde(default)]
        pub revocation: CertRevocationConfig,
        /// Optional CRL fetcher for live refresh.  Skipped by serde because
        /// trait objects are not `Serialize`/`Deserialize`.  Set at runtime
        /// via [`CertConfig::with_http_fetcher`].
        #[serde(skip, default)]
        pub http_fetcher: Option<Arc<dyn CrlFetcher>>,
    }

    impl std::fmt::Debug for CertConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CertConfig")
                .field("subject_role_mapping", &self.subject_role_mapping)
                .field("tenant_san_oid", &self.tenant_san_oid)
                .field("trusted_roots_len", &self.trusted_roots.len())
                .field("require_mfa", &self.require_mfa)
                .field("revocation", &self.revocation)
                .field("http_fetcher", &self.http_fetcher.is_some())
                .finish()
        }
    }

    impl CertConfig {
        /// Attach a [`CrlFetcher`] for live CRL refresh.
        pub fn with_http_fetcher(mut self, fetcher: Arc<dyn CrlFetcher>) -> Self {
            self.http_fetcher = Some(fetcher);
            self
        }
    }

    /// Configuration for certificate revocation checking (CRL-based).
    ///
    /// When enabled, the leaf certificate's serial number is checked against
    /// the provided CRLs.  Static DER blobs in `crls` are always consulted.
    /// Operators who want live refresh can additionally configure
    /// `crl_urls` together with a [`CrlFetcher`] on [`CertConfig`]; see
    /// [`CertAuthProvider::refresh_crls_if_stale`].
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CertRevocationConfig {
        /// Whether revocation checking is enabled.
        #[serde(default)]
        pub enabled: bool,
        /// DER-encoded CRL (Certificate Revocation List) data.
        /// Multiple CRLs can be provided (one per issuing CA).
        #[serde(default)]
        pub crls: Vec<Vec<u8>>,
        /// Optional list of HTTPS URLs to fetch CRL DER from when the
        /// static `crls` entries become stale.  Non-HTTPS URLs are
        /// rejected by [`ReqwestCrlFetcher`] / the `CrlFetcher`
        /// implementation.  Leave empty to disable dynamic refresh.
        #[serde(default)]
        pub crl_urls: Vec<String>,
        /// Operator-enforced CRL freshness SLA, in seconds: the CRL's
        /// `thisUpdate` field must be no older than this value. Independent
        /// from the CRL's own `nextUpdate`, this lets operators shorten
        /// staleness tolerance below whatever the CA publishes. `0` disables
        /// this check (fall back to `nextUpdate` only). Default is 24 hours.
        #[serde(default = "default_crl_max_age_secs")]
        pub max_age_secs: u64,
        /// Whether to require CRLs to carry a `nextUpdate` field. RFC 5280
        /// lists it as optional, but for defensive operation an HSM should
        /// reject CRLs that omit it (a missing `nextUpdate` makes a CRL
        /// effectively eternal). Default `true`.
        #[serde(default = "default_crl_require_next_update")]
        pub require_next_update: bool,
    }

    fn default_crl_max_age_secs() -> u64 {
        86_400
    }

    fn default_crl_require_next_update() -> bool {
        true
    }

    impl Default for CertRevocationConfig {
        fn default() -> Self {
            Self {
                enabled: false,
                crls: Vec::new(),
                crl_urls: Vec::new(),
                max_age_secs: default_crl_max_age_secs(),
                require_next_update: default_crl_require_next_update(),
            }
        }
    }

    /// Maps a certificate subject pattern to an HSM role.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CertRoleMapping {
        /// Substring to match in the certificate Subject DN.
        pub subject_pattern: String,
        /// Role to assign if the pattern matches.
        pub role: String,
    }

    /// Outcome of a single-source revocation pass. Lets the caller chain a
    /// fallback CRL source (static config) when a primary source (runtime
    /// refresh) yields no usable CRL — e.g. every refreshed CRL is expired.
    enum RevocationOutcome {
        /// At least one usable CRL covered the issuer; the cert was found
        /// to be not-revoked.
        Matched,
        /// No CRL in this source was both signature-valid and fresh enough
        /// to make a determination.
        NoUsableCrl,
    }

    /// Extract the SubjectKeyIdentifier bytes from a certificate, if present.
    ///
    /// Used to bind a CRL signer to a specific trusted root by SKI rather
    /// than by Subject DN alone (RFC 5280 §4.2.1.1). The OID for
    /// SubjectKeyIdentifier is 2.5.29.14.
    fn extract_cert_ski<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
        use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;
        cert.extensions()
            .iter()
            .find(|e| e.oid == OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .and_then(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(kid) => Some(kid.0),
                _ => None,
            })
    }

    /// Extract the AuthorityKeyIdentifier (`keyIdentifier` field only) from
    /// a CRL, if present. The OID is 2.5.29.35.
    fn extract_crl_aki(
        crl: &x509_parser::revocation_list::CertificateRevocationList<'_>,
    ) -> Option<Vec<u8>> {
        use x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;
        crl.extensions()
            .iter()
            .find(|e| e.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            .and_then(|ext| match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|kid| kid.0.to_vec())
                }
                _ => None,
            })
    }

    /// Per-trusted-root metadata derived once at construction so the auth
    /// hot path can match a CRL signer by Subject Key Identifier without
    /// re-parsing the root DER on every login.
    struct TrustedRootIndex {
        /// Index into `config.trusted_roots`.
        cfg_idx: usize,
        /// SubjectKeyIdentifier bytes, if the root carries the extension.
        ski: Option<Vec<u8>>,
    }

    /// Certificate-based authentication provider.
    pub struct CertAuthProvider {
        config: CertConfig,
        /// Runtime-refreshed CRL cache.
        ///
        /// Audit (perf): the previous `parking_lot::RwLock` forced every
        /// authentication to take a read lock just to check whether the
        /// runtime-fetched cache was populated. `arc_swap::ArcSwap` is
        /// lock-free on the read path -- callers atomically load the
        /// current `Arc` and the refresher swaps a fresh one in. When
        /// the inner Vec is empty, the static `config.revocation.crls`
        /// is used instead.
        refreshed_crls: arc_swap::ArcSwap<Vec<Vec<u8>>>,
        /// Pre-computed Subject Key Identifier index for each trusted root.
        ///
        /// Audit (perf): the previous `check_revocation` path re-parsed
        /// every trusted-root DER on every authentication just to find the
        /// cert whose SKI matched the CRL's AKI. The DERs do not change
        /// for the provider's lifetime, so we cache the SKI bytes once at
        /// construction and only parse the chosen root's DER when we need
        /// its public key for the actual signature verification.
        root_index: Arc<[TrustedRootIndex]>,
    }

    impl CertAuthProvider {
        /// Create a new cert auth provider.
        pub fn new(config: CertConfig) -> Self {
            // Pre-extract SKI metadata from every trusted root so the
            // per-auth CRL-signer lookup avoids re-parsing the root DER.
            // Roots that fail to parse are still tracked (so subject-DN-only
            // matches continue to work) but flagged with `ski = None`.
            let root_index: Vec<TrustedRootIndex> = config
                .trusted_roots
                .iter()
                .enumerate()
                .map(|(cfg_idx, der)| {
                    let ski = X509Certificate::from_der(der)
                        .ok()
                        .and_then(|(_, c)| extract_cert_ski(&c).map(|s| s.to_vec()));
                    TrustedRootIndex { cfg_idx, ski }
                })
                .collect();
            Self {
                config,
                // Empty Vec means "no runtime refresh yet; use config.crls".
                refreshed_crls: arc_swap::ArcSwap::from_pointee(Vec::new()),
                root_index: Arc::from(root_index.into_boxed_slice()),
            }
        }

        /// Attempt to refresh CRLs via the configured [`CrlFetcher`].
        ///
        /// Returns `Ok(true)` if at least one CRL was successfully fetched
        /// and parsed, `Ok(false)` if no fetcher is configured or no URLs
        /// are configured (no-op), and `Err` if the fetcher exists but
        /// *every* URL failed — in which case the cache is left unchanged
        /// so an authentication in progress continues to see the last
        /// known good CRL rather than an empty set.
        ///
        /// Callers invoke this on a schedule (e.g., once per minute) or
        /// reactively when freshness checks fail; it is not tripped
        /// automatically on the authentication hot path.
        pub fn refresh_crls_if_stale(&self) -> HsmResult<bool> {
            let fetcher = match &self.config.http_fetcher {
                Some(f) => f.clone(),
                None => return Ok(false),
            };
            if self.config.revocation.crl_urls.is_empty() {
                return Ok(false);
            }

            let mut new_crls: Vec<Vec<u8>> = Vec::new();
            let mut errors = 0usize;
            for url in &self.config.revocation.crl_urls {
                match fetcher.fetch(url) {
                    Ok(der) => {
                        // Parse to ensure we only cache well-formed CRLs.
                        match x509_parser::revocation_list::CertificateRevocationList::from_der(
                            &der,
                        ) {
                            Ok(_) => new_crls.push(der),
                            Err(e) => {
                                tracing::error!(url = %url, error = %e, "fetched CRL failed to parse");
                                errors += 1;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(url = %url, error = ?e, "CRL fetch failed");
                        errors += 1;
                    }
                }
            }

            if new_crls.is_empty() {
                // Every URL failed — preserve the existing cache and bubble
                // up a single error so callers can alert.
                tracing::error!(
                    attempted = self.config.revocation.crl_urls.len(),
                    errors,
                    "all CRL refreshes failed; keeping stale cache"
                );
                return Err(HsmError::GeneralError);
            }

            // Audit (perf): swap a fresh Arc in atomically; outstanding
            // readers continue to see the previous snapshot until they
            // drop their loaded handle.
            self.refreshed_crls.store(std::sync::Arc::new(new_crls));
            Ok(true)
        }

        /// Parse the role string into an `HsmRole` variant. Delegates to
        /// the canonical [`crate::auth::parse_role`] helper so every
        /// provider treats the same input identically (audit: previously
        /// each provider had its own copy with subtly different case
        /// handling).
        fn parse_role(role_str: &str) -> Option<HsmRole> {
            crate::auth::parse_role(role_str)
        }

        /// Extract the CN (Common Name) value from an X509Name using structured
        /// RDN access. This avoids the brittleness of string parsing where
        /// commas, equals signs, or quotes inside attribute values would
        /// confuse a naive `split(',')` parser and could be exploited by
        /// crafting a Subject DN that hides one component inside another.
        fn extract_cn(name: &X509Name<'_>) -> Option<String> {
            name.iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        }

        /// Match a role-mapping pattern against the structured Subject Name.
        ///
        /// Pattern syntax:
        /// - `CN=alice`, `OU=Engineering`, `O=Acme` — exact (case-insensitive)
        ///   match against the corresponding RDN attribute value.
        /// - bare value (no `=`) — matches the CN value, case-insensitive.
        ///
        /// Pattern matching uses **structured RDN access** rather than string
        /// parsing, so attribute values containing `,`, `=`, or other DN
        /// metacharacters cannot be used to spoof a different attribute.
        fn match_subject_dn(subject_name: &X509Name<'_>, pattern: &str) -> bool {
            let pattern = pattern.trim();
            if let Some((field, value)) = pattern.split_once('=') {
                let field = field.trim();
                let value = value.trim();
                let oid = match field.to_ascii_uppercase().as_str() {
                    "CN" => &OID_X509_COMMON_NAME,
                    "OU" => &OID_X509_ORGANIZATIONAL_UNIT,
                    "O" => &OID_X509_ORGANIZATION_NAME,
                    _ => return false,
                };
                subject_name.iter_attributes().any(|attr| {
                    attr.attr_type() == oid
                        && attr
                            .as_str()
                            .map(|s| s.eq_ignore_ascii_case(value))
                            .unwrap_or(false)
                })
            } else {
                Self::extract_cn(subject_name)
                    .map(|cn| cn.eq_ignore_ascii_case(pattern))
                    .unwrap_or(false)
            }
        }

        /// Extract a tenant ID from SANs using the configured OID.
        ///
        /// If `tenant_san_oid` is configured, this looks for a SAN of type
        /// `OtherName` whose OID matches, and uses the UTF-8 value as the
        /// tenant ID. As a fallback, it also checks `DirectoryName` SANs and
        /// `RFC822Name`/`DNSName` SANs for domain-based tenant extraction.
        fn extract_tenant_from_sans(
            &self,
            cert: &X509Certificate<'_>,
        ) -> HsmResult<Option<TenantId>> {
            let oid_str = match self.config.tenant_san_oid.as_deref() {
                Some(s) => s,
                None => return Ok(None),
            };

            // Try to find the SubjectAlternativeName extension.
            let san_ext = cert
                .extensions()
                .iter()
                .find(|ext| ext.oid == OID_X509_EXT_SUBJECT_ALT_NAME);

            // Collect every SAN value that maps to a tenant id, deduplicating
            // so a cert that lists the same tenant twice is not flagged as
            // ambiguous, but a cert that lists two distinct tenants is
            // rejected per the multi-tenant-claim policy.
            let mut candidates: Vec<TenantId> = Vec::new();
            let mut push = |t: TenantId| {
                if !candidates.iter().any(|c| c == &t) {
                    candidates.push(t);
                }
            };

            if let Some(ext) = san_ext {
                if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                    for name in &san.general_names {
                        match name {
                            GeneralName::RFC822Name(email) => {
                                if oid_str == "email" || oid_str == "rfc822" {
                                    if let Some((_local, domain)) = email.rsplit_once('@') {
                                        if let Ok(t) = TenantId::try_new(domain) {
                                            push(t);
                                        }
                                    }
                                }
                            }
                            GeneralName::DNSName(dns) => {
                                if oid_str == "dns" {
                                    if let Ok(t) = TenantId::try_new(*dns) {
                                        push(t);
                                    }
                                }
                            }
                            GeneralName::DirectoryName(dir_name) => {
                                if oid_str == "directory" {
                                    if let Some(cn) = dir_name
                                        .iter_common_name()
                                        .next()
                                        .and_then(|c| c.as_str().ok())
                                    {
                                        if let Ok(t) = TenantId::try_new(cn) {
                                            push(t);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            match candidates.len() {
                0 => Ok(None),
                1 => Ok(Some(candidates.remove(0))),
                _ => {
                    tracing::warn!(
                        count = candidates.len(),
                        "certificate asserts multiple distinct tenant SAN values — rejecting as ambiguous"
                    );
                    Err(HsmError::PinIncorrect)
                }
            }
        }

        /// Check if a certificate's serial number appears in any configured CRL.
        ///
        /// Parses each DER-encoded CRL and checks whether the leaf certificate's
        /// serial has been revoked. Returns an error if the cert is revoked.
        fn check_revocation(&self, cert: &X509Certificate<'_>) -> HsmResult<()> {
            if !self.config.revocation.enabled {
                return Ok(());
            }
            let serial = cert.raw_serial();
            let issuer = cert.issuer();

            // Prefer the runtime-refreshed CRL cache when populated;
            // otherwise fall back to the static config. The ArcSwap load
            // is lock-free; `guard` keeps the snapshot alive for the
            // iteration without holding any reader/writer lock.
            let guard = self.refreshed_crls.load();
            // The refreshed cache may itself contain CRLs whose `nextUpdate`
            // has elapsed (the operator may not have called
            // `refresh_crls_if_stale` recently). When every CRL drawn from
            // the refreshed cache is unusable, fall back to the static
            // configuration so a stale refresh does not block all
            // authentication.
            let primary: &[Vec<u8>] = if !guard.is_empty() {
                guard.as_slice()
            } else {
                &self.config.revocation.crls
            };
            let fallback: &[Vec<u8>] = if !guard.is_empty() {
                &self.config.revocation.crls
            } else {
                &[]
            };

            if let RevocationOutcome::Matched =
                self.try_check_revocation(primary, serial, issuer)?
            {
                return Ok(());
            }
            if !fallback.is_empty() {
                tracing::warn!(
                    "All refreshed CRLs unusable for issuer {} — falling back to static config CRLs",
                    issuer
                );
                if let RevocationOutcome::Matched =
                    self.try_check_revocation(fallback, serial, issuer)?
                {
                    return Ok(());
                }
            }
            tracing::error!(
                "Revocation enabled but no usable CRL found for issuer {} — rejecting",
                issuer
            );
            Err(HsmError::PinIncorrect)
        }

        /// One pass of revocation checking against a single CRL source.
        ///
        /// Returns `Matched` if at least one usable CRL covered the issuer
        /// and the cert is not revoked. Returns `NoUsableCrl` if every
        /// matching CRL in `source` was expired/freshness-failed — the
        /// caller may then try a fallback. Returns `Err(...)` for a
        /// definitively-bad CRL (corrupt, mis-signed) or if the cert is
        /// listed on a usable CRL.
        fn try_check_revocation(
            &self,
            source: &[Vec<u8>],
            serial: &[u8],
            issuer: &X509Name<'_>,
        ) -> HsmResult<RevocationOutcome> {
            let mut found_usable = false;
            for crl_der in source {
                let (_, crl) =
                    x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der)
                        .map_err(|e| {
                            tracing::error!("Failed to parse CRL — rejecting authentication: {e}");
                            HsmError::GeneralError
                        })?;

                if crl.issuer() != issuer {
                    continue;
                }

                // Bind the CRL signer to a trusted root by AuthorityKeyId →
                // SubjectKeyId (RFC 5280 §4.2.1.1). Subject DN alone is too
                // weak: two roots can legitimately share a DN across a
                // key-rollover or operator-managed cross-sign.  When the CRL
                // omits AKI (legacy CAs) we fall back to subject-DN match.
                let crl_aki = extract_crl_aki(&crl);
                let mut signer_cfg_idx: Option<usize> = None;
                for r in self.root_index.iter() {
                    if let Some(want_kid) = crl_aki.as_deref() {
                        match r.ski.as_deref() {
                            Some(got_kid) if got_kid == want_kid => {}
                            _ => continue,
                        }
                    }
                    let der = match self.config.trusted_roots.get(r.cfg_idx) {
                        Some(d) => d,
                        None => continue,
                    };
                    let (_, parsed) = match X509Certificate::from_der(der) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if parsed.subject() != crl.issuer() {
                        continue;
                    }
                    signer_cfg_idx = Some(r.cfg_idx);
                    break;
                }

                let signer_cfg_idx = match signer_cfg_idx {
                    Some(idx) => idx,
                    None => {
                        tracing::error!(
                            "CRL issuer {} not bound to any trusted root by AKI/SKI — rejecting",
                            crl.issuer()
                        );
                        return Err(HsmError::PinIncorrect);
                    }
                };
                let signer_der = match self.config.trusted_roots.get(signer_cfg_idx) {
                    Some(d) => d,
                    None => {
                        tracing::error!("Internal: trusted_roots index out of range — rejecting");
                        return Err(HsmError::GeneralError);
                    }
                };
                let (_, signer) = X509Certificate::from_der(signer_der).map_err(|e| {
                    tracing::error!("Failed to re-parse trusted root for CRL verify: {e}");
                    HsmError::GeneralError
                })?;
                if crl.verify_signature(signer.public_key()).is_err() {
                    tracing::error!("CRL signature verification failed — rejecting");
                    return Err(HsmError::PinIncorrect);
                }

                // Freshness failures don't bail the whole function — they
                // mark this single CRL as unusable so the caller can try a
                // fallback (e.g. static config when refreshed is stale).
                let now = x509_parser::time::ASN1Time::now();
                let mut crl_usable = true;
                if crl.last_update() > now {
                    tracing::warn!("CRL thisUpdate is in the future — unusable, may try fallback");
                    crl_usable = false;
                }
                if crl_usable && self.config.revocation.max_age_secs > 0 {
                    let now_secs = now.timestamp();
                    let this_secs = crl.last_update().timestamp();
                    let age_secs = now_secs.saturating_sub(this_secs);
                    if age_secs > self.config.revocation.max_age_secs as i64 {
                        tracing::warn!(
                            "CRL thisUpdate {}s old exceeds configured max_age_secs ({}) — unusable",
                            age_secs,
                            self.config.revocation.max_age_secs
                        );
                        crl_usable = false;
                    }
                }
                if crl_usable {
                    match crl.next_update() {
                        Some(next) => {
                            if next < now {
                                tracing::warn!(
                                    "CRL has expired (nextUpdate in the past) — unusable, may try fallback"
                                );
                                crl_usable = false;
                            }
                        }
                        None => {
                            if self.config.revocation.require_next_update {
                                tracing::warn!(
                                    "CRL omits nextUpdate and require_next_update is set — unusable"
                                );
                                crl_usable = false;
                            }
                        }
                    }
                }

                if crl_usable {
                    found_usable = true;
                    for revoked in crl.iter_revoked_certificates() {
                        if revoked.raw_serial() == serial {
                            tracing::warn!(
                                "Certificate revocation check failed: serial {:?} found in CRL",
                                serial
                            );
                            return Err(HsmError::PinIncorrect);
                        }
                    }
                }
            }

            if found_usable {
                Ok(RevocationOutcome::Matched)
            } else {
                Ok(RevocationOutcome::NoUsableCrl)
            }
        }

        /// Validate that the certificate chain is well-formed:
        /// - Each certificate's issuer matches the next certificate's subject
        /// - Each child certificate's signature is cryptographically verified
        ///   against the parent's public key
        /// - The final certificate in the chain must match a trusted root
        fn validate_chain(&self, cert_chain: &[Vec<u8>]) -> HsmResult<()> {
            if cert_chain.len() == 1 && !self.config.trusted_roots.is_empty() {
                // Single cert must be in trusted roots directly (self-signed trust).
                // For self-signed certs, also verify the signature against its own key.
                let leaf_der = &cert_chain[0];
                let is_trusted = self
                    .config
                    .trusted_roots
                    .iter()
                    .any(|root| root == leaf_der);
                if !is_trusted {
                    tracing::warn!("Certificate chain validation failed: leaf cert not in trusted roots and no intermediates provided");
                    return Err(HsmError::PinIncorrect);
                }
                // Verify the self-signed signature.
                let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| {
                    tracing::error!("Failed to parse leaf certificate: {}", e);
                    HsmError::GeneralError
                })?;
                if leaf.verify_signature(Some(leaf.public_key())).is_err() {
                    tracing::warn!("Self-signed certificate signature verification failed");
                    return Err(HsmError::PinIncorrect);
                }
                // Self-signed trust roots must still clear the revocation
                // check (audit finding H12). Previously we short-circuited
                // to `Ok(())` here, which accepted a revoked self-signed
                // cert as long as a copy was present in `trusted_roots`.
                self.check_revocation(&leaf)?;
                return Ok(());
            }

            // Verify issuer/subject chaining and cryptographic signatures.
            for (i, window) in cert_chain.windows(2).enumerate() {
                let child_der = &window[0];
                let parent_der = &window[1];
                let (_, child) = X509Certificate::from_der(child_der).map_err(|e| {
                    tracing::error!("Failed to parse certificate at index {}: {}", i, e);
                    HsmError::GeneralError
                })?;
                let (_, parent) = X509Certificate::from_der(parent_der).map_err(|e| {
                    tracing::error!("Failed to parse certificate at index {}: {}", i + 1, e);
                    HsmError::GeneralError
                })?;

                // Check that child's issuer matches parent's subject.
                if child.issuer() != parent.subject() {
                    tracing::warn!(
                        "Certificate chain broken at index {}: issuer does not match next cert's subject",
                        i
                    );
                    return Err(HsmError::PinIncorrect);
                }

                // Cryptographically verify child's signature using parent's public key.
                if child.verify_signature(Some(parent.public_key())).is_err() {
                    tracing::warn!(
                        "Certificate signature verification failed at index {}: child not signed by parent",
                        i
                    );
                    return Err(HsmError::PinIncorrect);
                }

                // Check parent validity.
                if !parent.validity().is_valid() {
                    tracing::warn!("Certificate at index {} has expired", i + 1);
                    return Err(HsmError::PinIncorrect);
                }

                // RFC 5280 §4.2.1.9: parent must be a CA (Basic Constraints cA=TRUE).
                // RFC 5280 §4.2.1.3: a conforming CA certificate MUST carry
                // a KeyUsage extension whose keyCertSign bit is set.
                // Strict-PKIX therefore rejects a parent whose KU extension
                // is absent, not just one whose bits are wrong. Accepting a
                // missing-KU parent would let any cert with `cA=TRUE` but
                // no KU sign children, which is exactly the gap §4.2.1.3
                // closes.
                match parent.basic_constraints() {
                    Ok(Some(bc)) if bc.value.ca => {}
                    _ => {
                        tracing::warn!(
                            "Certificate at index {} is not a CA (missing or false Basic Constraints cA)",
                            i + 1
                        );
                        return Err(HsmError::PinIncorrect);
                    }
                }
                match parent.key_usage() {
                    Ok(Some(ku)) => {
                        if !ku.value.key_cert_sign() {
                            tracing::warn!(
                                "Certificate at index {} has KeyUsage but lacks keyCertSign",
                                i + 1
                            );
                            return Err(HsmError::PinIncorrect);
                        }
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "Certificate at index {} is a CA but omits the KeyUsage extension — rejecting per RFC 5280 §4.2.1.3",
                            i + 1
                        );
                        return Err(HsmError::PinIncorrect);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Certificate at index {} has a malformed KeyUsage extension: {} — rejecting",
                            i + 1,
                            e
                        );
                        return Err(HsmError::PinIncorrect);
                    }
                }

                // Enforce path length constraint if present.
                if let Ok(Some(bc)) = parent.basic_constraints() {
                    if let Some(path_len) = bc.value.path_len_constraint {
                        // Number of intermediate CAs between this parent and the leaf.
                        // i is the current child index; intermediates between leaf (0)
                        // and this parent (i+1) is i (children at positions 1..=i are
                        // CAs themselves; the leaf at 0 doesn't count).
                        let intermediates_below = i as u32;
                        if intermediates_below > path_len {
                            tracing::warn!(
                                "Certificate at index {} path length constraint exceeded",
                                i + 1
                            );
                            return Err(HsmError::PinIncorrect);
                        }
                    }
                }
            }

            // Verify the last cert in chain is a trusted root.
            // SAFETY: cert_chain.len() >= 2 was verified above (single-cert
            // path returns early), so last() is guaranteed to yield Some.
            // Using ok_or instead of unwrap so a refactor that reorders
            // the early-return cannot silently produce a panic.
            let root_der = cert_chain.last().ok_or(HsmError::GeneralError)?;
            let is_trusted = self
                .config
                .trusted_roots
                .iter()
                .any(|root| root == root_der);
            if !is_trusted {
                tracing::warn!("Certificate chain validation failed: root not in trusted store");
                return Err(HsmError::PinIncorrect);
            }

            Ok(())
        }
    }

    impl AuthProvider for CertAuthProvider {
        fn authenticate(&self, credentials: &AuthCredentials) -> HsmResult<AuthResult> {
            match credentials {
                AuthCredentials::Certificate { cert_chain } => {
                    if cert_chain.is_empty() {
                        return Err(HsmError::PinIncorrect);
                    }

                    // Parse the leaf (end-entity) certificate.
                    let der = &cert_chain[0];
                    let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
                        tracing::error!("Failed to parse X.509 certificate: {}", e);
                        HsmError::GeneralError
                    })?;

                    // Validate certificate time window.
                    if !cert.validity().is_valid() {
                        tracing::warn!(
                            "Certificate validity check failed: not_before={}, not_after={}",
                            cert.validity().not_before,
                            cert.validity().not_after,
                        );
                        return Err(HsmError::PinIncorrect);
                    }

                    // Validate certificate chain if trusted roots are configured.
                    if !self.config.trusted_roots.is_empty() {
                        self.validate_chain(cert_chain)?;
                    }

                    // RFC 5280 §4.2.1.12 — Extended Key Usage. If the leaf
                    // certificate carries an EKU extension, it MUST include
                    // `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2) — a cert that
                    // advertises only serverAuth or codeSigning has been
                    // minted for a different purpose and must not be
                    // presented as a client credential. When no EKU is
                    // present, RFC 5280 says the cert is valid for any
                    // purpose: we accept but log so operators can pin
                    // clientAuth in their PKI.
                    match cert.extended_key_usage() {
                        Ok(Some(eku)) => {
                            if !eku.value.client_auth && !eku.value.any {
                                tracing::warn!(
                                    "Leaf certificate EKU does not include clientAuth (1.3.6.1.5.5.7.3.2) — rejecting"
                                );
                                return Err(HsmError::PinIncorrect);
                            }
                        }
                        Ok(None) => {
                            tracing::warn!(
                                subject = %cert.subject(),
                                "Leaf certificate has no Extended Key Usage extension — accepting under RFC 5280 'valid for any purpose' but operators should pin clientAuth"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Leaf certificate has a malformed EKU extension — rejecting"
                            );
                            return Err(HsmError::PinIncorrect);
                        }
                    }

                    // Check revocation status against configured CRLs.
                    self.check_revocation(&cert)?;

                    let subject_name = cert.subject();

                    // Extract user_id from CN using structured RDN access.
                    let user_id = Self::extract_cn(subject_name)
                        .unwrap_or_else(|| format!("cert:{}", subject_name));

                    // Match subject against configured role mappings.
                    let mut matched_role: Option<HsmRole> = None;
                    for mapping in &self.config.subject_role_mapping {
                        if Self::match_subject_dn(subject_name, &mapping.subject_pattern) {
                            matched_role = Self::parse_role(&mapping.role);
                            if matched_role.is_some() {
                                break;
                            }
                            tracing::warn!(
                                "Subject DN matched pattern '{}' but role '{}' is not recognized",
                                mapping.subject_pattern,
                                mapping.role
                            );
                        }
                    }

                    let role = matched_role.ok_or_else(|| {
                        tracing::warn!("No role mapping matched for subject DN: {}", subject_name);
                        HsmError::PinIncorrect
                    })?;

                    // Extract tenant ID from SANs if configured. A cert
                    // that asserts multiple distinct tenants returns an
                    // error rather than silently binding to the first one.
                    let tenant_id = self.extract_tenant_from_sans(&cert)?;

                    Ok(AuthResult {
                        role,
                        user_id,
                        tenant_id,
                        mfa_required: self.config.require_mfa,
                    })
                }
                _ => Err(HsmError::FunctionNotSupported),
            }
        }

        fn name(&self) -> &str {
            "certificate"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build a minimal self-signed DER-encoded X.509v3 certificate.
        ///
        /// This constructs the ASN.1 DER by hand to avoid pulling in heavy
        /// certificate-building crates. The certificate uses a 256-bit ECDSA
        /// key on P-256 and includes a SubjectAlternativeName extension with
        /// the specified email address (if provided).
        fn build_test_cert(cn: &str, ou: Option<&str>, email_san: Option<&str>) -> Vec<u8> {
            // We build the certificate manually using DER encoding.
            // This is a minimal X.509v3 structure.

            fn encode_len(len: usize) -> Vec<u8> {
                if len < 0x80 {
                    vec![len as u8]
                } else if len < 0x100 {
                    vec![0x81, len as u8]
                } else {
                    vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
                }
            }

            fn wrap_seq(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x30]; // SEQUENCE tag
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            fn wrap_set(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x31]; // SET tag
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            fn wrap_oid(oid_bytes: &[u8]) -> Vec<u8> {
                let mut out = vec![0x06]; // OID tag
                out.extend(encode_len(oid_bytes.len()));
                out.extend(oid_bytes);
                out
            }

            fn wrap_utf8(s: &str) -> Vec<u8> {
                let mut out = vec![0x0C]; // UTF8String tag
                out.extend(encode_len(s.len()));
                out.extend(s.as_bytes());
                out
            }

            fn wrap_printable(s: &str) -> Vec<u8> {
                let mut out = vec![0x13]; // PrintableString tag
                out.extend(encode_len(s.len()));
                out.extend(s.as_bytes());
                out
            }

            fn wrap_ia5(s: &str) -> Vec<u8> {
                let mut out = vec![0x16]; // IA5String tag
                out.extend(encode_len(s.len()));
                out.extend(s.as_bytes());
                out
            }

            fn wrap_integer(val: &[u8]) -> Vec<u8> {
                let mut out = vec![0x02]; // INTEGER tag
                                          // Add leading zero if high bit set
                if !val.is_empty() && val[0] & 0x80 != 0 {
                    out.extend(encode_len(val.len() + 1));
                    out.push(0x00);
                } else {
                    out.extend(encode_len(val.len()));
                }
                out.extend(val);
                out
            }

            fn wrap_bitstring(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x03]; // BIT STRING tag
                out.extend(encode_len(contents.len() + 1));
                out.push(0x00); // no unused bits
                out.extend(contents);
                out
            }

            fn wrap_octet_string(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x04]; // OCTET STRING tag
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            fn wrap_context(tag: u8, contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0xA0 | tag]; // context-specific constructed
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            fn wrap_implicit_context(tag: u8, contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x80 | tag]; // context-specific primitive
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            // OIDs
            let oid_cn = [0x55, 0x04, 0x03]; // 2.5.4.3
            let oid_ou = [0x55, 0x04, 0x0B]; // 2.5.4.11
            let oid_o = [0x55, 0x04, 0x0A]; // 2.5.4.10
            let oid_c = [0x55, 0x04, 0x06]; // 2.5.4.6
            let oid_ecdsa_sha256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
            let oid_ec_pubkey = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // 1.2.840.10045.2.1
            let oid_p256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
            let oid_san = [0x55, 0x1D, 0x11]; // 2.5.29.17

            // Build subject RDN sequence
            let cn_attr = wrap_seq(&[wrap_oid(&oid_cn), wrap_utf8(cn)].concat());
            let cn_rdn = wrap_set(&cn_attr);

            let mut subject_rdns = cn_rdn.clone();

            if let Some(ou_val) = ou {
                let ou_attr = wrap_seq(&[wrap_oid(&oid_ou), wrap_utf8(ou_val)].concat());
                subject_rdns.extend(wrap_set(&ou_attr));
            }

            let o_attr = wrap_seq(&[wrap_oid(&oid_o), wrap_utf8("TestOrg")].concat());
            subject_rdns.extend(wrap_set(&o_attr));

            let c_attr = wrap_seq(&[wrap_oid(&oid_c), wrap_printable("US")].concat());
            subject_rdns.extend(wrap_set(&c_attr));

            let subject = wrap_seq(&subject_rdns);

            // Use subject as issuer too (self-signed).
            let issuer = subject.clone();

            // Algorithm identifier for ECDSA with SHA-256
            let algo_id = wrap_seq(&[wrap_oid(&oid_ecdsa_sha256)].concat());

            // Version: v3 (2)
            let version = wrap_context(0, &wrap_integer(&[0x02]));

            // Serial number
            let serial = wrap_integer(&[0x01]);

            // Validity: not_before = 2020-01-01, not_after = 2030-12-31
            // UTCTime format: YYMMDDHHMMSSZ
            let not_before = {
                let s = b"200101000000Z";
                let mut out = vec![0x17]; // UTCTime
                out.extend(encode_len(s.len()));
                out.extend(s);
                out
            };
            let not_after = {
                let s = b"301231235959Z";
                let mut out = vec![0x17]; // UTCTime
                out.extend(encode_len(s.len()));
                out.extend(s);
                out
            };
            let validity = wrap_seq(&[not_before, not_after].concat());

            // Generate a real ECDSA P-256 key pair for the certificate.
            use p256::ecdsa::SigningKey;
            use rand::rngs::OsRng;

            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();

            // Encode public key as uncompressed point (0x04 || x || y)
            let pubkey_point = verifying_key.to_encoded_point(false);
            let pubkey_bytes = pubkey_point.as_bytes();

            // SubjectPublicKeyInfo
            let spki_algo = wrap_seq(&[wrap_oid(&oid_ec_pubkey), wrap_oid(&oid_p256)].concat());
            let spki = wrap_seq(&[spki_algo, wrap_bitstring(pubkey_bytes)].concat());

            // Extensions (v3)
            let mut extensions_content = Vec::new();

            // SubjectAlternativeName extension (if email provided)
            if let Some(email) = email_san {
                // rfc822Name is context tag [1] implicit
                let san_value_inner = wrap_implicit_context(1, email.as_bytes());
                let san_value = wrap_seq(&san_value_inner);
                let san_ext =
                    wrap_seq(&[wrap_oid(&oid_san), wrap_octet_string(&san_value)].concat());
                extensions_content.extend(san_ext);
            }

            let mut tbs_parts = Vec::new();
            tbs_parts.extend(&version);
            tbs_parts.extend(&serial);
            tbs_parts.extend(&algo_id);
            tbs_parts.extend(&issuer);
            tbs_parts.extend(&validity);
            tbs_parts.extend(&subject);
            tbs_parts.extend(&spki);

            if !extensions_content.is_empty() {
                let exts = wrap_seq(&extensions_content);
                tbs_parts.extend(wrap_context(3, &exts));
            }

            let tbs_certificate = wrap_seq(&tbs_parts);

            // Sign the TBS certificate
            use p256::ecdsa::signature::Signer;
            let signature: p256::ecdsa::DerSignature = signing_key.sign(&tbs_certificate);
            let sig_bytes = signature.as_bytes();

            // Build the full certificate
            let cert_contents =
                [tbs_certificate, algo_id.clone(), wrap_bitstring(sig_bytes)].concat();

            wrap_seq(&cert_contents)
        }

        /// Build a test certificate that has already expired.
        fn build_expired_cert(cn: &str) -> Vec<u8> {
            fn encode_len(len: usize) -> Vec<u8> {
                if len < 0x80 {
                    vec![len as u8]
                } else if len < 0x100 {
                    vec![0x81, len as u8]
                } else {
                    vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
                }
            }

            fn wrap_seq(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x30];
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            fn wrap_set(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x31];
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            fn wrap_oid(oid_bytes: &[u8]) -> Vec<u8> {
                let mut out = vec![0x06];
                out.extend(encode_len(oid_bytes.len()));
                out.extend(oid_bytes);
                out
            }

            fn wrap_utf8(s: &str) -> Vec<u8> {
                let mut out = vec![0x0C];
                out.extend(encode_len(s.len()));
                out.extend(s.as_bytes());
                out
            }

            fn wrap_printable(s: &str) -> Vec<u8> {
                let mut out = vec![0x13];
                out.extend(encode_len(s.len()));
                out.extend(s.as_bytes());
                out
            }

            fn wrap_integer(val: &[u8]) -> Vec<u8> {
                let mut out = vec![0x02];
                if !val.is_empty() && val[0] & 0x80 != 0 {
                    out.extend(encode_len(val.len() + 1));
                    out.push(0x00);
                } else {
                    out.extend(encode_len(val.len()));
                }
                out.extend(val);
                out
            }

            fn wrap_bitstring(contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0x03];
                out.extend(encode_len(contents.len() + 1));
                out.push(0x00);
                out.extend(contents);
                out
            }

            fn wrap_context(tag: u8, contents: &[u8]) -> Vec<u8> {
                let mut out = vec![0xA0 | tag];
                out.extend(encode_len(contents.len()));
                out.extend(contents);
                out
            }

            let oid_cn = [0x55, 0x04, 0x03];
            let oid_o = [0x55, 0x04, 0x0A];
            let oid_c = [0x55, 0x04, 0x06];
            let oid_ecdsa_sha256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
            let oid_ec_pubkey = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
            let oid_p256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

            let cn_attr = wrap_seq(&[wrap_oid(&oid_cn), wrap_utf8(cn)].concat());
            let cn_rdn = wrap_set(&cn_attr);
            let o_attr = wrap_seq(&[wrap_oid(&oid_o), wrap_utf8("TestOrg")].concat());
            let c_attr = wrap_seq(&[wrap_oid(&oid_c), wrap_printable("US")].concat());

            let subject_rdns = [cn_rdn, wrap_set(&o_attr), wrap_set(&c_attr)].concat();
            let subject = wrap_seq(&subject_rdns);
            let issuer = subject.clone();

            let algo_id = wrap_seq(&wrap_oid(&oid_ecdsa_sha256));
            let version = wrap_context(0, &wrap_integer(&[0x02]));
            let serial = wrap_integer(&[0x02]);

            // Expired: 2010-01-01 to 2015-12-31
            let not_before = {
                let s = b"100101000000Z";
                let mut out = vec![0x17];
                out.extend(encode_len(s.len()));
                out.extend(s);
                out
            };
            let not_after = {
                let s = b"151231235959Z";
                let mut out = vec![0x17];
                out.extend(encode_len(s.len()));
                out.extend(s);
                out
            };
            let validity = wrap_seq(&[not_before, not_after].concat());

            use p256::ecdsa::SigningKey;
            use rand::rngs::OsRng;

            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let pubkey_point = verifying_key.to_encoded_point(false);
            let pubkey_bytes = pubkey_point.as_bytes();

            let spki_algo = wrap_seq(&[wrap_oid(&oid_ec_pubkey), wrap_oid(&oid_p256)].concat());
            let spki = wrap_seq(&[spki_algo, wrap_bitstring(pubkey_bytes)].concat());

            let tbs_parts = [
                version,
                serial,
                algo_id.clone(),
                issuer,
                validity,
                subject,
                spki,
            ]
            .concat();

            let tbs_certificate = wrap_seq(&tbs_parts);

            use p256::ecdsa::signature::Signer;
            let signature: p256::ecdsa::DerSignature = signing_key.sign(&tbs_certificate);
            let sig_bytes = signature.as_bytes();

            let cert_contents = [tbs_certificate, algo_id, wrap_bitstring(sig_bytes)].concat();

            wrap_seq(&cert_contents)
        }

        fn make_config(mappings: Vec<(&str, &str)>, tenant_oid: Option<&str>) -> CertConfig {
            CertConfig {
                subject_role_mapping: mappings
                    .into_iter()
                    .map(|(pattern, role)| CertRoleMapping {
                        subject_pattern: pattern.to_string(),
                        role: role.to_string(),
                    })
                    .collect(),
                tenant_san_oid: tenant_oid.map(|s| s.to_string()),
                trusted_roots: Vec::new(),
                require_mfa: false,
                revocation: CertRevocationConfig::default(),
                http_fetcher: None,
            }
        }

        #[test]
        fn test_authenticate_valid_cert_user_role() {
            let config = make_config(vec![("O=TestOrg", "user")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Alice", None, None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::User);
            assert_eq!(result.user_id, "Alice");
            assert!(result.tenant_id.is_none());
            assert!(!result.mfa_required);
        }

        #[test]
        fn test_authenticate_operator_role_by_ou() {
            let config = make_config(vec![("OU=Operations", "operator")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Bob", Some("Operations"), None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::Operator);
            assert_eq!(result.user_id, "Bob");
        }

        #[test]
        fn test_authenticate_so_role() {
            let config = make_config(vec![("CN=Admin", "so")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Admin", None, None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::So);
        }

        #[test]
        fn test_authenticate_auditor_role() {
            let config = make_config(vec![("OU=Compliance", "auditor")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Carol", Some("Compliance"), None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::Auditor);
        }

        #[test]
        fn test_authenticate_key_manager_role() {
            let config = make_config(vec![("OU=KeyOps", "key_manager")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Dave", Some("KeyOps"), None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::KeyManager);
        }

        #[test]
        fn test_no_matching_role_returns_pin_incorrect() {
            let config = make_config(vec![("OU=NonExistent", "user")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Eve", None, None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let err = provider.authenticate(&creds).unwrap_err();
            assert!(matches!(err, HsmError::PinIncorrect));
        }

        #[test]
        fn test_empty_cert_chain_returns_pin_incorrect() {
            let config = make_config(vec![("TestOrg", "user")], None);
            let provider = CertAuthProvider::new(config);

            let creds = AuthCredentials::Certificate { cert_chain: vec![] };

            let err = provider.authenticate(&creds).unwrap_err();
            assert!(matches!(err, HsmError::PinIncorrect));
        }

        #[test]
        fn test_validate_chain_empty_with_trusted_roots_returns_error() {
            // validate_chain is only called when trusted_roots is non-empty.
            // An empty cert_chain with trusted_roots configured must not panic
            // (previously the `< 2` guard was true for len==0 and cert_chain[0]
            // would panic). Regression test for C-1.
            let cert_der = build_test_cert("TrustedCA", None, None);
            let config = CertConfig {
                subject_role_mapping: vec![CertRoleMapping {
                    subject_pattern: "TestOrg".to_string(),
                    role: "user".to_string(),
                }],
                tenant_san_oid: None,
                trusted_roots: vec![cert_der],
                require_mfa: false,
                revocation: CertRevocationConfig::default(),
                http_fetcher: None,
            };
            let provider = CertAuthProvider::new(config);

            // Empty cert_chain: must not panic, must return an error.
            let creds = AuthCredentials::Certificate { cert_chain: vec![] };
            let err = provider.authenticate(&creds).unwrap_err();
            assert!(matches!(err, HsmError::PinIncorrect));
        }

        #[test]
        fn test_invalid_der_returns_general_error() {
            let config = make_config(vec![("TestOrg", "user")], None);
            let provider = CertAuthProvider::new(config);

            let creds = AuthCredentials::Certificate {
                cert_chain: vec![vec![0xFF, 0xFF, 0xFF]],
            };

            let err = provider.authenticate(&creds).unwrap_err();
            assert!(matches!(err, HsmError::GeneralError));
        }

        #[test]
        fn test_expired_cert_returns_pin_incorrect() {
            let config = make_config(vec![("TestOrg", "user")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_expired_cert("Expired");
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let err = provider.authenticate(&creds).unwrap_err();
            assert!(matches!(err, HsmError::PinIncorrect));
        }

        #[test]
        fn test_wrong_credentials_type_returns_not_supported() {
            let config = make_config(vec![("TestOrg", "user")], None);
            let provider = CertAuthProvider::new(config);

            let creds = AuthCredentials::Token {
                bearer_token: zeroize::Zeroizing::new("some-token".to_string()),
            };

            let err = provider.authenticate(&creds).unwrap_err();
            assert!(matches!(err, HsmError::FunctionNotSupported));
        }

        #[test]
        fn test_first_matching_rule_wins() {
            let config = make_config(
                vec![("O=TestOrg", "auditor"), ("CN=Alice", "operator")],
                None,
            );
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Alice", None, None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            // "TestOrg" matches first since it's in the O= component
            assert_eq!(result.role, HsmRole::Auditor);
        }

        #[test]
        fn test_unrecognized_role_string_skipped() {
            // If the first mapping's role string is invalid, it skips to the next.
            let config = make_config(
                vec![("O=TestOrg", "invalid_role"), ("O=TestOrg", "operator")],
                None,
            );
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Frank", None, None);
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::Operator);
        }

        #[test]
        fn test_provider_name() {
            let config = make_config(vec![], None);
            let provider = CertAuthProvider::new(config);
            assert_eq!(provider.name(), "certificate");
        }

        #[test]
        fn test_extract_cn() {
            // `extract_cn` operates on a structured `X509Name<'_>` rather
            // than a raw string, so we construct a real DER certificate
            // and pull its `subject()` to drive the test.
            let cert_der = build_test_cert("Alice", Some("Eng"), None);
            let (_, parsed) =
                X509Certificate::from_der(&cert_der).expect("self-signed test cert parses");
            assert_eq!(
                CertAuthProvider::extract_cn(parsed.subject()),
                Some("Alice".to_string())
            );

            // CN containing only whitespace must round-trip through the
            // trim() + filter(!is_empty()) chain as `None`.
            let blank_cert = build_test_cert("   ", None, None);
            let (_, blank_parsed) =
                X509Certificate::from_der(&blank_cert).expect("blank-CN test cert parses");
            assert_eq!(CertAuthProvider::extract_cn(blank_parsed.subject()), None);
        }

        #[test]
        fn test_parse_role_variants() {
            assert_eq!(CertAuthProvider::parse_role("user"), Some(HsmRole::User));
            assert_eq!(CertAuthProvider::parse_role("User"), Some(HsmRole::User));
            assert_eq!(CertAuthProvider::parse_role("SO"), Some(HsmRole::So));
            assert_eq!(
                CertAuthProvider::parse_role("security_officer"),
                Some(HsmRole::So)
            );
            assert_eq!(
                CertAuthProvider::parse_role("auditor"),
                Some(HsmRole::Auditor)
            );
            assert_eq!(
                CertAuthProvider::parse_role("KeyManager"),
                Some(HsmRole::KeyManager)
            );
            assert_eq!(
                CertAuthProvider::parse_role("key_manager"),
                Some(HsmRole::KeyManager)
            );
            assert_eq!(
                CertAuthProvider::parse_role("operator"),
                Some(HsmRole::Operator)
            );
            assert_eq!(CertAuthProvider::parse_role("unknown"), None);
        }

        #[test]
        fn test_tenant_extraction_from_email_san() {
            let config = make_config(vec![("O=TestOrg", "user")], Some("email"));
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Alice", None, Some("alice@acme.com"));
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert_eq!(result.role, HsmRole::User);
            assert_eq!(result.user_id, "Alice");
            assert_eq!(
                result.tenant_id.as_ref().map(|t| t.as_str()),
                Some("acme.com")
            );
        }

        #[test]
        fn test_chain_validation_self_signed_in_trusted_roots() {
            let cert_der = build_test_cert("TrustedUser", None, None);
            let config = CertConfig {
                subject_role_mapping: vec![CertRoleMapping {
                    subject_pattern: "O=TestOrg".to_string(),
                    role: "user".to_string(),
                }],
                tenant_san_oid: None,
                trusted_roots: vec![cert_der.clone()],
                require_mfa: false,
                revocation: CertRevocationConfig::default(),
                http_fetcher: None,
            };
            let provider = CertAuthProvider::new(config);

            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };
            let result = provider.authenticate(&creds);
            assert!(result.is_ok());
        }

        #[test]
        fn test_chain_validation_untrusted_cert_rejected() {
            let cert_der = build_test_cert("UntrustedUser", None, None);
            let trusted_cert = build_test_cert("TrustedCA", None, None);
            let config = CertConfig {
                subject_role_mapping: vec![CertRoleMapping {
                    subject_pattern: "TestOrg".to_string(),
                    role: "user".to_string(),
                }],
                tenant_san_oid: None,
                trusted_roots: vec![trusted_cert],
                require_mfa: false,
                revocation: CertRevocationConfig::default(),
                http_fetcher: None,
            };
            let provider = CertAuthProvider::new(config);

            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };
            let result = provider.authenticate(&creds);
            assert!(result.is_err());
        }

        #[test]
        fn test_chain_validation_forged_signature_rejected() {
            // Generate two independently-signed certs — the "child" is NOT
            // signed by the "parent" key, so signature verification must fail.
            let child_der = build_test_cert("Child", None, None);
            let parent_der = build_test_cert("Parent", None, None);

            let config = CertConfig {
                subject_role_mapping: vec![CertRoleMapping {
                    subject_pattern: "TestOrg".to_string(),
                    role: "user".to_string(),
                }],
                tenant_san_oid: None,
                trusted_roots: vec![parent_der.clone()],
                require_mfa: false,
                revocation: CertRevocationConfig::default(),
                http_fetcher: None,
            };
            let provider = CertAuthProvider::new(config);

            let creds = AuthCredentials::Certificate {
                cert_chain: vec![child_der, parent_der],
            };
            // The child cert is self-signed (not signed by parent), so
            // cryptographic verification should fail.
            let result = provider.authenticate(&creds);
            assert!(result.is_err(), "forged chain should be rejected");
        }

        #[test]
        fn test_no_tenant_without_config() {
            let config = make_config(vec![("O=TestOrg", "user")], None);
            let provider = CertAuthProvider::new(config);

            let cert_der = build_test_cert("Alice", None, Some("alice@acme.com"));
            let creds = AuthCredentials::Certificate {
                cert_chain: vec![cert_der],
            };

            let result = provider
                .authenticate(&creds)
                .expect("authentication should succeed");
            assert!(result.tenant_id.is_none());
        }

        // ------------------------------------------------------------------
        // Fix 1: CRL fetcher scaffold tests.
        //
        // These exercise URL validation and wiring without relying on a
        // real network. A tracking fetcher records every URL it is asked
        // to fetch so we can assert the provider forwards the right
        // arguments, and rejects non-HTTPS schemes before the fetcher
        // would ever see them.
        // ------------------------------------------------------------------

        /// Test-only fetcher that records every URL it has been asked to
        /// fetch, and returns a caller-configurable response.
        struct TrackingFetcher {
            calls: std::sync::Mutex<Vec<String>>,
            reject_non_https: bool,
            /// Response to return for a successful fetch.
            response: Vec<u8>,
            /// If true, simulate a redirect by returning an error.
            simulate_redirect: bool,
        }

        impl TrackingFetcher {
            fn new() -> Self {
                Self {
                    calls: std::sync::Mutex::new(Vec::new()),
                    reject_non_https: true,
                    response: Vec::new(),
                    simulate_redirect: false,
                }
            }
        }

        impl CrlFetcher for TrackingFetcher {
            fn fetch(&self, url: &str) -> HsmResult<Vec<u8>> {
                self.calls.lock().unwrap().push(url.to_string());
                if self.reject_non_https && !url.starts_with("https://") {
                    return Err(HsmError::ArgumentsBad);
                }
                if url.starts_with("file://") || url.starts_with("http://") {
                    return Err(HsmError::ArgumentsBad);
                }
                if self.simulate_redirect {
                    return Err(HsmError::GeneralError);
                }
                Ok(self.response.clone())
            }
        }

        #[test]
        fn test_null_crl_fetcher_returns_not_supported() {
            let fetcher = NullCrlFetcher;
            let err = fetcher.fetch("https://example.com/crl.der").unwrap_err();
            assert!(matches!(err, HsmError::FunctionNotSupported));
        }

        #[test]
        fn test_refresh_crls_no_fetcher_is_noop() {
            // Provider without a fetcher configured: refresh returns Ok(false).
            let mut config = make_config(vec![("TestOrg", "user")], None);
            config.revocation.enabled = true;
            config.revocation.crl_urls = vec!["https://example.com/crl.der".to_string()];
            let provider = CertAuthProvider::new(config);

            let refreshed = provider.refresh_crls_if_stale().unwrap();
            assert!(!refreshed, "no fetcher -> refresh is a no-op");
        }

        #[test]
        fn test_refresh_crls_no_urls_is_noop() {
            let mut config = make_config(vec![("TestOrg", "user")], None);
            config.revocation.enabled = true;
            // No URLs configured.
            let tracker = Arc::new(TrackingFetcher::new());
            config.http_fetcher = Some(tracker.clone());
            let provider = CertAuthProvider::new(config);

            let refreshed = provider.refresh_crls_if_stale().unwrap();
            assert!(!refreshed);
            assert!(
                tracker.calls.lock().unwrap().is_empty(),
                "fetcher must not be called when no URLs are configured"
            );
        }

        #[test]
        fn test_refresh_crls_non_https_url_rejected_by_fetcher() {
            // The provider forwards the URL to the fetcher, which must
            // reject non-HTTPS schemes. Because every URL fails, the
            // refresh itself errors rather than silently leaving an empty
            // cache — fail-closed on total failure.
            let mut config = make_config(vec![("TestOrg", "user")], None);
            config.revocation.enabled = true;
            config.revocation.crl_urls = vec![
                "http://example.com/crl.der".to_string(),
                "file:///etc/passwd".to_string(),
                "ftp://example.com/crl.der".to_string(),
            ];
            let tracker = Arc::new(TrackingFetcher::new());
            config.http_fetcher = Some(tracker.clone());
            let provider = CertAuthProvider::new(config);

            let err = provider.refresh_crls_if_stale().unwrap_err();
            assert!(matches!(err, HsmError::GeneralError));

            let calls = tracker.calls.lock().unwrap().clone();
            assert_eq!(calls.len(), 3, "each URL must be attempted once");
            assert!(calls.iter().any(|u| u.starts_with("http://")));
            assert!(calls.iter().any(|u| u.starts_with("file://")));
            assert!(calls.iter().any(|u| u.starts_with("ftp://")));
        }

        #[test]
        fn test_refresh_crls_simulated_redirect_rejected() {
            // A fetcher that reports redirect-style errors (our hardened
            // HTTPS fetcher returns an error on redirect because the
            // policy is `Policy::none()`).  Every URL fails ->
            // refresh_crls_if_stale must return Err and leave the cache
            // untouched.
            let mut config = make_config(vec![("TestOrg", "user")], None);
            config.revocation.enabled = true;
            config.revocation.crl_urls = vec!["https://redirect.example.com/crl.der".to_string()];
            let mut t = TrackingFetcher::new();
            t.simulate_redirect = true;
            let tracker = Arc::new(t);
            config.http_fetcher = Some(tracker.clone());
            let provider = CertAuthProvider::new(config);

            let err = provider.refresh_crls_if_stale().unwrap_err();
            assert!(matches!(err, HsmError::GeneralError));
            assert_eq!(tracker.calls.lock().unwrap().len(), 1);
        }

        #[test]
        fn test_refresh_crls_rejects_unparseable_der() {
            // Successful HTTP response but the bytes are not a valid CRL —
            // the provider must reject them rather than trust arbitrary
            // bytes as a CRL (a malicious mirror could respond with garbage
            // to "clear" revocation state).
            let mut config = make_config(vec![("TestOrg", "user")], None);
            config.revocation.enabled = true;
            config.revocation.crl_urls = vec!["https://example.com/crl.der".to_string()];
            let mut t = TrackingFetcher::new();
            t.response = vec![0xde, 0xad, 0xbe, 0xef]; // not a CRL
            let tracker = Arc::new(t);
            config.http_fetcher = Some(tracker);
            let provider = CertAuthProvider::new(config);

            let err = provider.refresh_crls_if_stale().unwrap_err();
            assert!(matches!(err, HsmError::GeneralError));
        }

        #[test]
        fn test_null_fetcher_wired_through_provider() {
            // Wire the NullCrlFetcher as the configured fetcher.  Every
            // fetch returns FunctionNotSupported, so the refresh errors.
            let mut config = make_config(vec![("TestOrg", "user")], None);
            config.revocation.enabled = true;
            config.revocation.crl_urls = vec!["https://example.com/crl.der".to_string()];
            config.http_fetcher = Some(Arc::new(NullCrlFetcher));
            let provider = CertAuthProvider::new(config);

            let err = provider.refresh_crls_if_stale().unwrap_err();
            assert!(matches!(err, HsmError::GeneralError));
        }

        #[test]
        fn test_with_http_fetcher_builder() {
            let config = make_config(vec![("TestOrg", "user")], None);
            let config = config.with_http_fetcher(Arc::new(NullCrlFetcher));
            assert!(config.http_fetcher.is_some());
        }

        #[cfg(feature = "crl-http-fetch")]
        #[test]
        fn test_reqwest_crl_fetcher_rejects_non_https_scheme() {
            // The hardened HTTPS fetcher must refuse any non-HTTPS URL up
            // front — even if the client's https_only(true) would also
            // catch it later, we want the precise ArgumentsBad error.
            let fetcher = ReqwestCrlFetcher::new().expect("build fetcher");
            let err = fetcher
                .fetch("http://example.com/crl.der")
                .expect_err("http must be rejected");
            assert!(matches!(err, HsmError::ArgumentsBad));
            let err = fetcher
                .fetch("file:///etc/passwd")
                .expect_err("file:// must be rejected");
            assert!(matches!(err, HsmError::ArgumentsBad));
            let err = fetcher
                .fetch("ftp://example.com/crl.der")
                .expect_err("ftp must be rejected");
            assert!(matches!(err, HsmError::ArgumentsBad));
        }
    }
}

#[cfg(feature = "cert-auth")]
pub use inner::*;

// When cert-auth feature is not enabled, provide stub types so the module
// still compiles and downstream code can reference the types conditionally.
#[cfg(not(feature = "cert-auth"))]
mod stub {
    use serde::{Deserialize, Serialize};

    use crate::auth::provider::{AuthCredentials, AuthProvider, AuthResult};
    use craton_hsm::error::{HsmError, HsmResult};

    /// Certificate authentication configuration.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CertConfig {
        /// Mapping from Subject DN patterns to roles.
        pub subject_role_mapping: Vec<CertRoleMapping>,
        /// SAN (Subject Alternative Name) attribute for tenant ID extraction.
        pub tenant_san_oid: Option<String>,
        /// DER-encoded trusted root CA certificates. If non-empty, the leaf
        /// certificate must chain to one of these roots.
        #[serde(default)]
        pub trusted_roots: Vec<Vec<u8>>,
        /// Whether to require MFA for certificate-authenticated sessions.
        #[serde(default)]
        pub require_mfa: bool,
        /// Certificate revocation checking configuration.
        #[serde(default)]
        pub revocation: CertRevocationConfig,
    }

    /// Configuration for certificate revocation checking (stub).
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct CertRevocationConfig {
        /// When `true`, revocation checking is performed during certificate validation.
        #[serde(default)]
        pub enabled: bool,
        /// Static CRLs to consult, each encoded as DER bytes.
        #[serde(default)]
        pub crls: Vec<Vec<u8>>,
        /// HTTPS URLs from which fresh CRLs are fetched.
        #[serde(default)]
        pub crl_urls: Vec<String>,
        /// Maximum age, in seconds, that a CRL may have since `thisUpdate` before
        /// it is considered stale.
        #[serde(default)]
        pub max_age_secs: u64,
        /// Reject CRLs that do not carry a `nextUpdate` field.
        #[serde(default)]
        pub require_next_update: bool,
    }

    /// Maps a certificate subject pattern to an HSM role.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CertRoleMapping {
        /// Substring to match in the certificate Subject DN.
        pub subject_pattern: String,
        /// Role to assign if the pattern matches.
        pub role: String,
    }

    /// Certificate-based authentication provider (stub — enable `cert-auth` feature).
    pub struct CertAuthProvider {
        _config: CertConfig,
    }

    impl CertAuthProvider {
        /// Create a new cert auth provider.
        pub fn new(config: CertConfig) -> Self {
            Self { _config: config }
        }
    }

    impl AuthProvider for CertAuthProvider {
        fn authenticate(&self, _credentials: &AuthCredentials) -> HsmResult<AuthResult> {
            Err(HsmError::FunctionNotSupported)
        }

        fn name(&self) -> &str {
            "certificate"
        }
    }
}

#[cfg(not(feature = "cert-auth"))]
pub use stub::*;
