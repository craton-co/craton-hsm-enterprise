// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Azure Key Vault REST API compatibility shim for Craton HSM.
//!
//! Maps Azure Key Vault operations (key management, cryptographic operations)
//! to local Craton HSM operations.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
use rand::RngCore;
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
use zeroize::ZeroizeOnDrop;

/// Errors from the Azure Key Vault shim.
#[derive(Debug, Clone)]
pub enum AzureKvError {
    /// The requested key was not found.
    KeyNotFound(String),
    /// The key already exists.
    KeyAlreadyExists(String),
    /// The key is in soft-deleted state and cannot be used until recovered.
    KeySoftDeleted(String),
    /// Invalid parameter.
    InvalidParameter(String),
    /// Operation not supported for this key type.
    UnsupportedOperation(String),
    /// Authentication failed (e.g. wrap-key tag mismatch).
    AuthenticationFailed(String),
    /// Caller's identity is recognised but the policy denied the operation.
    /// Distinct from `InvalidParameter` so calling code can tell an auth
    /// failure from a validation failure (audit finding M, ACL error class).
    PermissionDenied(String),
    /// Internal error.
    Internal(String),
}

impl fmt::Display for AzureKvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AzureKvError::KeyNotFound(k) => write!(f, "key not found: {}", k.escape_debug()),
            AzureKvError::KeyAlreadyExists(k) => {
                write!(f, "key already exists: {}", k.escape_debug())
            }
            AzureKvError::KeySoftDeleted(k) => write!(f, "key soft-deleted: {}", k.escape_debug()),
            AzureKvError::InvalidParameter(msg) => {
                write!(f, "invalid parameter: {}", msg.escape_debug())
            }
            AzureKvError::UnsupportedOperation(msg) => {
                write!(f, "unsupported operation: {}", msg.escape_debug())
            }
            AzureKvError::AuthenticationFailed(msg) => {
                write!(f, "authentication failed: {}", msg.escape_debug())
            }
            AzureKvError::PermissionDenied(msg) => {
                write!(f, "permission denied: {}", msg.escape_debug())
            }
            AzureKvError::Internal(msg) => write!(f, "internal error: {}", msg.escape_debug()),
        }
    }
}

impl std::error::Error for AzureKvError {}

/// Result alias for Azure Key Vault shim operations.
pub type AzureResult<T> = std::result::Result<T, AzureKvError>;

/// Configuration for the Azure Key Vault compatibility shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureKvConfig {
    /// Name of the Key Vault.
    pub vault_name: String,
    /// Azure subscription ID.
    pub subscription_id: String,
    /// Resource group name.
    pub resource_group: String,
    /// Azure region.
    #[serde(default = "default_location")]
    pub location: Cow<'static, str>,
    /// Soft-delete retention period in seconds.
    #[serde(default = "default_retention")]
    pub soft_delete_retention_seconds: u64,
    /// DNS suffix used to build per-key URLs. Defaults to
    /// `.vault.azure.net` (audit finding M, dns_suffix TLD). Use
    /// `.vault.usgovcloudapi.net` for US Government or `.vault.azure.cn` for
    /// Azure China.
    #[serde(default = "default_dns_suffix")]
    pub dns_suffix: Cow<'static, str>,
}

fn default_location() -> Cow<'static, str> {
    Cow::Borrowed("eastus")
}

fn default_retention() -> u64 {
    7 * 24 * 60 * 60 // 7 days
}

fn default_dns_suffix() -> Cow<'static, str> {
    Cow::Borrowed(".vault.azure.net")
}

/// Azure Key Vault key types (HSM-backed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AzureKeyType {
    /// RSA key stored in HSM.
    RsaHsm,
    /// Elliptic curve key stored in HSM.
    EcHsm,
    /// Symmetric octet key stored in HSM.
    OctHsm,
}

impl AzureKeyType {
    /// Returns the Azure Key Vault wire-format string for this key type.
    pub fn wire_name(&self) -> &'static str {
        match self {
            AzureKeyType::RsaHsm => "RSA-HSM",
            AzureKeyType::EcHsm => "EC-HSM",
            AzureKeyType::OctHsm => "oct-HSM",
        }
    }

    /// Whether this key type supports `Encrypt`/`Decrypt`/`WrapKey`.
    fn supports_encrypt(self) -> bool {
        matches!(self, AzureKeyType::RsaHsm | AzureKeyType::OctHsm)
    }

    /// Whether this key type supports `Sign`/`Verify`.
    fn supports_sign(self) -> bool {
        matches!(self, AzureKeyType::RsaHsm | AzureKeyType::EcHsm)
    }
}

/// Validate an Azure key size for the given key type.
fn validate_key_size(kty: AzureKeyType, size: Option<u32>) -> AzureResult<()> {
    match (kty, size) {
        (AzureKeyType::RsaHsm, Some(s)) => {
            if !matches!(s, 2048 | 3072 | 4096) {
                return Err(AzureKvError::InvalidParameter(format!(
                    "RSA key size {s} not in {{2048, 3072, 4096}}"
                )));
            }
        }
        (AzureKeyType::OctHsm, Some(s)) => {
            if !matches!(s, 128 | 192 | 256) {
                return Err(AzureKvError::InvalidParameter(format!(
                    "oct key size {s} not in {{128, 192, 256}}"
                )));
            }
        }
        (AzureKeyType::EcHsm, Some(s)) => {
            if !matches!(s, 256 | 384 | 521) {
                return Err(AzureKvError::InvalidParameter(format!(
                    "EC key size {s} not in {{256, 384, 521}}"
                )));
            }
        }
        (_, None) => {}
    }
    Ok(())
}

/// Validate an algorithm name against a known whitelist for the given operation.
fn validate_algorithm(op: &str, algorithm: &str) -> AzureResult<()> {
    let allowed: &[&str] = match op {
        "sign" => &[
            "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256",
        ],
        "encrypt" | "decrypt" => &["RSA-OAEP", "RSA-OAEP-256", "RSA1_5", "A256GCM", "A128GCM"],
        "wrap" => &["RSA-OAEP", "RSA-OAEP-256", "A256KW"],
        _ => &[],
    };
    if !allowed.contains(&algorithm) {
        return Err(AzureKvError::InvalidParameter(format!(
            "algorithm '{}' not supported for {op}",
            algorithm.escape_debug()
        )));
    }
    Ok(())
}

/// Return `true` if `algorithm` names an AEAD-shaped mechanism that the mock
/// cannot actually implement.
///
/// Audit foot-gun: the mock backends execute Encrypt/Decrypt via an
/// XOR-stream + HMAC tag. That's authenticated but it is **not** AES-GCM, and
/// callers asking for `A256GCM` would silently get the XOR mock and assume
/// they had an AEAD. Refuse the mechanism rather than downgrade it.
fn is_aead_shaped_algorithm(algorithm: &str) -> bool {
    matches!(algorithm, "A256GCM" | "A128GCM")
}

/// Azure Key Vault operations mapped to Craton HSM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AzureKvOperation {
    /// Create a new key.
    CreateKey {
        /// Key name.
        name: String,
        /// Key type.
        kty: AzureKeyType,
        /// Optional key size in bits.
        key_size: Option<u32>,
    },
    /// Get an existing key.
    GetKey {
        /// Key name.
        name: String,
        /// Optional specific version.
        version: Option<String>,
    },
    /// List all (live) keys in the vault.
    ListKeys,
    /// List soft-deleted keys.
    ListDeletedKeys,
    /// Soft-delete a key.
    DeleteKey {
        /// Key name.
        name: String,
    },
    /// Recover a soft-deleted key.
    RecoverKey {
        /// Key name.
        name: String,
    },
    /// Permanently purge a soft-deleted key.
    PurgeKey {
        /// Key name.
        name: String,
    },
    /// Backup a key (returns an opaque, authenticated blob).
    BackupKey {
        /// Key name.
        name: String,
    },
    /// Restore a previously backed-up key.
    RestoreKey {
        /// Backup blob bytes.
        blob: Vec<u8>,
    },
    /// Sign data using a key.
    Sign {
        /// Key name.
        name: String,
        /// Signing algorithm (e.g. "RS256", "ES256").
        algorithm: String,
        /// Base64-encoded value to sign.
        value_b64: String,
    },
    /// Verify a signature.
    Verify {
        /// Key name.
        name: String,
        /// Algorithm used for signing.
        algorithm: String,
        /// Base64-encoded digest.
        digest_b64: String,
        /// Base64-encoded signature.
        signature_b64: String,
    },
    /// Encrypt data using a key.
    Encrypt {
        /// Key name.
        name: String,
        /// Encryption algorithm.
        algorithm: String,
        /// Base64-encoded value to encrypt.
        value_b64: String,
    },
    /// Decrypt data using a key.
    Decrypt {
        /// Key name.
        name: String,
        /// Encryption algorithm.
        algorithm: String,
        /// Base64-encoded ciphertext.
        value_b64: String,
    },
    /// Wrap (encrypt) a key using another key.
    WrapKey {
        /// Wrapping key name.
        name: String,
        /// Wrapping algorithm.
        algorithm: String,
        /// Base64-encoded key material to wrap.
        value_b64: String,
    },
    /// Unwrap (decrypt) a wrapped key.
    UnwrapKey {
        /// Wrapping key name.
        name: String,
        /// Wrapping algorithm.
        algorithm: String,
        /// Base64-encoded wrapped key.
        value_b64: String,
    },
}

/// Response from Azure Key Vault shim operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureKvResponse {
    /// JSON response body.
    pub value: serde_json::Value,
}

/// Trait for Azure Key Vault shim implementations.
pub trait AzureKvShim: Send + Sync {
    /// Process an Azure Key Vault operation.
    fn process(&self, op: AzureKvOperation) -> AzureResult<AzureKvResponse>;
}

/// Logical identity carried alongside an Azure Key Vault request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureIdentity {
    /// Authenticated principal (AAD object id, service principal).
    pub principal: String,
}

impl AzureIdentity {
    /// Construct a new identity.
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
        }
    }
    /// Anonymous default identity.
    pub fn anonymous() -> Self {
        Self {
            principal: String::new(),
        }
    }
}

/// Coarse operation classes for [`AzureKvAcl`] gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureOp {
    /// Key lifecycle (`CreateKey`, `DeleteKey`, `RecoverKey`, `PurgeKey`,
    /// `BackupKey`, `RestoreKey`).
    Manage,
    /// Read metadata / list (`GetKey`, `ListKeys`, `ListDeletedKeys`).
    Read,
    /// Crypto ops (`Encrypt`, `Decrypt`, `WrapKey`, `UnwrapKey`).
    Crypto,
    /// Signing ops (`Sign`, `Verify`).
    Sign,
}

/// Per-key ACL for the Azure Key Vault shim.
pub trait AzureKvAcl: Send + Sync {
    /// Return `true` if `identity` may perform `op` on `key_id`.
    fn check(&self, identity: &AzureIdentity, key_id: &str, op: AzureOp) -> bool;
}

/// Permissive ACL kept for callers that explicitly opt in. **NOT the
/// default** — see [`DenyAllAzureAcl`]. Audit finding H20 changed the default
/// to fail-closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAzureAcl;

impl AzureKvAcl for AllowAllAzureAcl {
    fn check(&self, _: &AzureIdentity, _: &str, _: AzureOp) -> bool {
        true
    }
}

/// Default deny-all ACL (audit finding H20). The mock vault ships with this
/// installed; embedders must opt in to a permissive policy via
/// [`MockAzureKvShim::with_acl`] or [`MockAzureKvShim::permissive_for_tests`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllAzureAcl;

impl AzureKvAcl for DenyAllAzureAcl {
    fn check(&self, _: &AzureIdentity, _: &str, _: AzureOp) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Maximum length permitted for any URL component (vault, key name, version).
const AZURE_MAX_COMPONENT_LEN: usize = 127;

/// Validate that a string contains only Azure-safe URL component characters.
///
/// Uses an allow-list (`A-Z`, `a-z`, `0-9`, `.`, `_`, `-`) rather than a
/// deny-list — this is the only safe approach for URL building.
fn validate_url_component(value: &str, name: &str) -> AzureResult<()> {
    if value.is_empty() {
        return Err(AzureKvError::InvalidParameter(format!(
            "{name} must not be empty"
        )));
    }
    if value.len() > AZURE_MAX_COMPONENT_LEN {
        return Err(AzureKvError::InvalidParameter(format!(
            "{name} exceeds {AZURE_MAX_COMPONENT_LEN} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return Err(AzureKvError::InvalidParameter(format!(
            "{name} contains characters outside [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// Build an Azure Key Vault key ID URL using the default
/// `.vault.azure.net` DNS suffix.
///
/// Components are validated against an allow-list of `[A-Za-z0-9._-]` and
/// length-bounded. This is the only public function for constructing key IDs;
/// all internal callers route through it to ensure consistent validation.
pub fn azure_key_id(vault_name: &str, key_name: &str, version: &str) -> AzureResult<String> {
    azure_key_id_with_suffix(vault_name, key_name, version, ".vault.azure.net")
}

/// Build an Azure Key Vault key ID URL with an explicit DNS suffix
/// (audit finding M, dns_suffix configurability). The suffix is validated as
/// a URL component itself; pass e.g. `.vault.usgovcloudapi.net` for Azure
/// Government or `.vault.azure.cn` for Azure China. The suffix MUST start
/// with a `.` so the result is a well-formed FQDN.
pub fn azure_key_id_with_suffix(
    vault_name: &str,
    key_name: &str,
    version: &str,
    dns_suffix: &str,
) -> AzureResult<String> {
    validate_url_component(vault_name, "vault_name")?;
    validate_url_component(key_name, "key_name")?;
    validate_url_component(version, "version")?;
    validate_dns_suffix(dns_suffix)?;
    let host_tail = dns_suffix.trim_start_matches('.');
    Ok(format!(
        "https://{vault_name}.{host_tail}/keys/{key_name}/{version}"
    ))
}

/// Validate that `dns_suffix` is a leading-`.` host suffix made of safe
/// hostname characters. Rejects empty input, missing leading dot, and any
/// byte outside `[A-Za-z0-9.-]`.
fn validate_dns_suffix(dns_suffix: &str) -> AzureResult<()> {
    if !dns_suffix.starts_with('.') {
        return Err(AzureKvError::InvalidParameter(
            "dns_suffix must start with '.'".into(),
        ));
    }
    if dns_suffix.len() < 2 || dns_suffix.len() > AZURE_MAX_COMPONENT_LEN {
        return Err(AzureKvError::InvalidParameter(format!(
            "dns_suffix length must be in [2, {AZURE_MAX_COMPONENT_LEN}]"
        )));
    }
    if !dns_suffix
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
    {
        return Err(AzureKvError::InvalidParameter(
            "dns_suffix contains characters outside [A-Za-z0-9.-]".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

/// Maximum base64 input length for crypto operations.
const AZURE_MAX_VALUE_LEN: usize = 128 * 1024;

/// Internal key entry in the mock Azure Key Vault.
///
/// Audit foot-gun (perf): the previous design re-derived the `SIGN`,
/// `WRAP-AUTH` and `WRAP-ENC` HKDF sub-keys on every Encrypt/Decrypt/Wrap
/// call. The sub-keys are now cached behind `OnceLock` so HKDF only runs
/// the first time each one is needed for the lifetime of the key.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
#[derive(ZeroizeOnDrop)]
struct MockAzureKey {
    #[zeroize(skip)]
    name: String,
    #[zeroize(skip)]
    kty: AzureKeyType,
    #[zeroize(skip)]
    key_size: Option<u32>,
    #[zeroize(skip)]
    version: String,
    /// Audit finding (created stamp drifts on every read): set once at
    /// insert time and never mutated, so two `GetKey` calls on the same
    /// key return the same `created` value.
    #[zeroize(skip)]
    created_at: u64,
    #[zeroize(skip)]
    deleted_at: Option<u64>,
    secret: [u8; 32],
    /// Cached `SIGN` HKDF sub-key (audit foot-gun: perf).
    #[zeroize(skip)]
    subkey_sign: std::sync::OnceLock<[u8; 32]>,
    /// Cached `WRAP-AUTH` HKDF sub-key (audit foot-gun: perf).
    #[zeroize(skip)]
    subkey_wrap_auth: std::sync::OnceLock<[u8; 32]>,
    /// Cached `WRAP-ENC` HKDF sub-key (audit foot-gun: perf).
    #[zeroize(skip)]
    subkey_wrap_enc: std::sync::OnceLock<[u8; 32]>,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockAzureKey {
    fn key_id(&self, vault_name: &str, dns_suffix: &str) -> AzureResult<String> {
        azure_key_id_with_suffix(vault_name, &self.name, &self.version, dns_suffix)
    }

    /// Return the cached `SIGN` HKDF sub-key, deriving it on first call.
    fn sign_subkey(&self) -> &[u8; 32] {
        self.subkey_sign
            .get_or_init(|| crate::mock_crypto::subkey(&self.secret, b"SIGN"))
    }

    /// Return the cached `WRAP-AUTH` HKDF sub-key, deriving it on first call.
    fn wrap_auth_subkey(&self) -> &[u8; 32] {
        self.subkey_wrap_auth
            .get_or_init(|| crate::mock_crypto::subkey(&self.secret, b"WRAP-AUTH"))
    }

    /// Return the cached `WRAP-ENC` HKDF sub-key, deriving it on first call.
    fn wrap_enc_subkey(&self) -> &[u8; 32] {
        self.subkey_wrap_enc
            .get_or_init(|| crate::mock_crypto::subkey(&self.secret, b"WRAP-ENC"))
    }

    /// Build a JSON view of the key.
    ///
    /// Audit finding (stale-time stub): the previous implementation hardcoded
    /// `1_700_000_000` for both `created` and `updated`, so two keys created
    /// seconds apart looked indistinguishable. The next iteration used
    /// [`SystemTime::now`] for both fields, which drifted on every read.
    /// Now `created` comes from `self.created_at` (set once at insert) and
    /// `updated` falls back to that value unless the key has been
    /// soft-deleted (in which case `deleted_at` wins, matching the real
    /// Azure semantic of "last lifecycle change").
    fn to_json(&self, vault_name: &str, dns_suffix: &str) -> AzureResult<serde_json::Value> {
        Ok(serde_json::json!({
            "key": {
                "kid": self.key_id(vault_name, dns_suffix)?,
                "kty": self.kty.wire_name(),
                "key_size": self.key_size,
            },
            "attributes": {
                "enabled": self.deleted_at.is_none(),
                "created": self.created_at,
                "updated": self.deleted_at.unwrap_or(self.created_at),
                "recoverable": self.deleted_at.is_some(),
            }
        }))
    }
}

/// Mock Azure Key Vault shim for testing and local development.
///
/// Uses HMAC-SHA256 over per-key random material for crypto operations and
/// supports the full lifecycle including soft-delete, recover, purge, and
/// backup/restore. Vault name is stored once and shared by reference.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
pub struct MockAzureKvShim {
    config: AzureKvConfig,
    keys: DashMap<String, MockAzureKey>,
    next_version: AtomicU64,
    acl: std::sync::Arc<dyn AzureKvAcl>,
    default_identity: AzureIdentity,
    /// Optional vault-wide master key seeded at construction. **Required**
    /// for `RestoreKey` to function (audit finding H19): without it, the
    /// restore path used to authenticate the blob with its own embedded
    /// secret, which is trivially forgeable. Now restore HMACs the blob
    /// under a sub-key derived from this master.
    master_key: Option<[u8; 32]>,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockAzureKvShim {
    /// Create a new mock shim from a configuration object.
    ///
    /// `RestoreKey` will fail-closed until [`Self::with_master_key`] /
    /// [`Self::new_with_master_key`] is used to seed a vault-wide master
    /// secret (audit finding H19).
    pub fn new(config: AzureKvConfig) -> AzureResult<Self> {
        crate::mock_guard::check("azure_shim::MockAzureKvShim");
        // Validate vault name and dns_suffix eagerly so misconfigurations
        // fail at startup, not at the first request (audit finding L: avoid
        // expect-panics).
        validate_url_component(&config.vault_name, "vault_name").map_err(|_| {
            AzureKvError::InvalidParameter("vault_name must be a valid URL component".into())
        })?;
        validate_dns_suffix(&config.dns_suffix)?;
        info!(vault = %config.vault_name, "mock Azure KV shim created");
        Ok(Self {
            config,
            keys: DashMap::new(),
            next_version: AtomicU64::new(1),
            // Audit finding H20: default to deny-all.
            acl: std::sync::Arc::new(DenyAllAzureAcl),
            default_identity: AzureIdentity::anonymous(),
            master_key: None,
        })
    }

    /// Convenience: like [`Self::new`] but seeds the vault-wide master key
    /// in one step. Audit finding H19.
    pub fn new_with_master_key(config: AzureKvConfig, master_key: [u8; 32]) -> AzureResult<Self> {
        let mut s = Self::new(config)?;
        s.master_key = Some(master_key);
        Ok(s)
    }

    /// Seed (or replace) the vault-wide master key. Audit finding H19.
    pub fn with_master_key(mut self, master_key: [u8; 32]) -> Self {
        self.master_key = Some(master_key);
        self
    }

    /// Install the legacy permissive ACL **and** a non-anonymous default
    /// identity. Test-only helper (audit finding H20).
    #[cfg(any(test, feature = "permissive-for-tests"))]
    pub fn permissive_for_tests(self) -> Self {
        self.with_acl(std::sync::Arc::new(AllowAllAzureAcl))
            .with_default_identity(AzureIdentity::new("test-suite"))
    }

    /// Replace the ACL implementation.
    pub fn with_acl(mut self, acl: std::sync::Arc<dyn AzureKvAcl>) -> Self {
        self.acl = acl;
        self
    }

    /// Override the default identity used by [`AzureKvShim::process`].
    pub fn with_default_identity(mut self, identity: AzureIdentity) -> Self {
        self.default_identity = identity;
        self
    }

    /// Process an operation on behalf of an explicitly provided identity.
    pub fn process_as(
        &self,
        identity: &AzureIdentity,
        op: AzureKvOperation,
    ) -> AzureResult<AzureKvResponse> {
        let (class, key_id) = Self::classify(&op);
        if !self.acl.check(identity, key_id, class) {
            // Audit finding M (ACL error class): use a dedicated
            // `PermissionDenied` variant so embedders can distinguish auth
            // failures from validation failures (which still surface as
            // `InvalidParameter`).
            return Err(AzureKvError::PermissionDenied(format!(
                "azure ACL denied {class:?} on {}",
                key_id.escape_debug()
            )));
        }
        self.dispatch(op)
    }

    fn classify(op: &AzureKvOperation) -> (AzureOp, &str) {
        match op {
            AzureKvOperation::CreateKey { name, .. }
            | AzureKvOperation::DeleteKey { name }
            | AzureKvOperation::RecoverKey { name }
            | AzureKvOperation::PurgeKey { name }
            | AzureKvOperation::BackupKey { name } => (AzureOp::Manage, name.as_str()),
            AzureKvOperation::RestoreKey { .. } => (AzureOp::Manage, ""),
            AzureKvOperation::GetKey { name, .. } => (AzureOp::Read, name.as_str()),
            AzureKvOperation::ListKeys | AzureKvOperation::ListDeletedKeys => (AzureOp::Read, ""),
            AzureKvOperation::Encrypt { name, .. }
            | AzureKvOperation::Decrypt { name, .. }
            | AzureKvOperation::WrapKey { name, .. }
            | AzureKvOperation::UnwrapKey { name, .. } => (AzureOp::Crypto, name.as_str()),
            AzureKvOperation::Sign { name, .. } | AzureKvOperation::Verify { name, .. } => {
                (AzureOp::Sign, name.as_str())
            }
        }
    }

    /// Convenience constructor for tests. Audit finding: previously panicked
    /// via `.expect(...)` on a constructor error; now returns the underlying
    /// [`AzureResult`] so callers can propagate validation failures (e.g.
    /// invalid vault name) the same way `Self::new` does.
    pub fn with_vault_name(vault_name: &str) -> AzureResult<Self> {
        Self::new(AzureKvConfig {
            vault_name: vault_name.to_string(),
            subscription_id: "sub-test".to_string(),
            resource_group: "rg-test".to_string(),
            location: default_location(),
            soft_delete_retention_seconds: default_retention(),
            dns_suffix: default_dns_suffix(),
        })
    }

    fn gen_version(&self) -> String {
        let v = self.next_version.fetch_add(1, Ordering::Relaxed);
        format!("{v:032x}")
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn validate_value_b64(value: &str) -> AzureResult<()> {
        if value.len() > AZURE_MAX_VALUE_LEN {
            return Err(AzureKvError::InvalidParameter(format!(
                "value exceeds {AZURE_MAX_VALUE_LEN} bytes"
            )));
        }
        if !value
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='))
        {
            return Err(AzureKvError::InvalidParameter(
                "value contains non-base64 characters".into(),
            ));
        }
        Ok(())
    }

    /// Sign with a pre-derived `SIGN` sub-key. Audit foot-gun (perf): the
    /// caller passes the cached sub-key (see [`MockAzureKey::sign_subkey`])
    /// so a single HKDF derivation is amortised across every Sign call.
    fn hmac_sign_with_sub(sub: &[u8; 32], algorithm: &str, value: &str) -> [u8; 32] {
        crate::mock_crypto::hmac_sign(sub, algorithm.as_bytes(), value.as_bytes())
    }

    /// Authenticate a wrapped/encrypted blob with a pre-derived `WRAP-AUTH`
    /// sub-key. See [`MockAzureKey::wrap_auth_subkey`].
    ///
    /// Audit finding (MAC over base64): `body` is the **raw** ciphertext /
    /// wrap-blob bytes. Base64 is a transport encoding; keep it out of the
    /// MAC.
    fn wrap_tag_with_sub(sub: &[u8; 32], algorithm: &str, body: &[u8]) -> [u8; 32] {
        crate::mock_crypto::hmac_sign(sub, algorithm.as_bytes(), body)
    }

    /// XOR-stream keyed on a pre-derived `WRAP-ENC` sub-key. See
    /// [`MockAzureKey::wrap_enc_subkey`].
    fn xor_stream_with_sub(sub: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> AzureResult<Vec<u8>> {
        crate::mock_crypto::xor_stream(sub, nonce, data)
            .map_err(|()| AzureKvError::Internal("xor counter overflow".into()))
    }

    fn b64_encode(bytes: &[u8]) -> String {
        crate::mock_crypto::b64_encode(bytes)
    }

    fn b64_decode(input: &str) -> AzureResult<Vec<u8>> {
        crate::mock_crypto::b64_decode(input)
            .map_err(|()| AzureKvError::InvalidParameter("invalid base64 character".into()))
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl AzureKvShim for MockAzureKvShim {
    fn process(&self, op: AzureKvOperation) -> AzureResult<AzureKvResponse> {
        let identity = self.default_identity.clone();
        self.process_as(&identity, op)
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockAzureKvShim {
    fn dispatch(&self, op: AzureKvOperation) -> AzureResult<AzureKvResponse> {
        let vault_name = &self.config.vault_name;
        let dns_suffix = &self.config.dns_suffix;
        let map = &self.keys;
        match op {
            AzureKvOperation::CreateKey {
                name,
                kty,
                key_size,
            } => {
                validate_url_component(&name, "name")?;
                validate_key_size(kty, key_size)?;
                use dashmap::mapref::entry::Entry;
                match map.entry(name.clone()) {
                    Entry::Occupied(e) => {
                        if e.get().deleted_at.is_some() {
                            return Err(AzureKvError::KeySoftDeleted(name));
                        }
                        Err(AzureKvError::KeyAlreadyExists(name))
                    }
                    Entry::Vacant(v) => {
                        let version = self.gen_version();
                        let mut secret = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut secret);
                        let key = MockAzureKey {
                            name: name.clone(),
                            kty,
                            key_size,
                            version,
                            // Audit finding: capture creation time once at
                            // insert; never recomputed on subsequent reads.
                            created_at: Self::now(),
                            deleted_at: None,
                            secret,
                            subkey_sign: std::sync::OnceLock::new(),
                            subkey_wrap_auth: std::sync::OnceLock::new(),
                            subkey_wrap_enc: std::sync::OnceLock::new(),
                        };
                        let json = key.to_json(vault_name, dns_suffix)?;
                        v.insert(key);
                        info!(name = %name, kty = kty.wire_name(), "CreateKey");
                        Ok(AzureKvResponse { value: json })
                    }
                }
            }
            AzureKvOperation::GetKey { name, version } => {
                validate_url_component(&name, "name")?;
                let entry = map
                    .get(&name)
                    .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                if entry.deleted_at.is_some() {
                    return Err(AzureKvError::KeySoftDeleted(name));
                }
                if let Some(ref v) = version {
                    validate_url_component(v, "version")?;
                    if *v != entry.version {
                        return Err(AzureKvError::KeyNotFound(format!("{name}/{v}")));
                    }
                }
                Ok(AzureKvResponse {
                    value: entry.to_json(vault_name, dns_suffix)?,
                })
            }
            AzureKvOperation::ListKeys => {
                let mut list = Vec::new();
                for entry in map.iter() {
                    if entry.value().deleted_at.is_none() {
                        list.push(entry.value().to_json(vault_name, dns_suffix)?);
                    }
                }
                Ok(AzureKvResponse {
                    value: serde_json::json!({ "value": list }),
                })
            }
            AzureKvOperation::ListDeletedKeys => {
                let mut list = Vec::new();
                for entry in map.iter() {
                    if entry.value().deleted_at.is_some() {
                        list.push(entry.value().to_json(vault_name, dns_suffix)?);
                    }
                }
                Ok(AzureKvResponse {
                    value: serde_json::json!({ "value": list }),
                })
            }
            AzureKvOperation::DeleteKey { name } => {
                validate_url_component(&name, "name")?;
                // Audit finding (write lock held across now() syscall):
                // compute the timestamp *before* taking the shard write lock
                // so the lock window stays bounded to a few-byte memcopy and
                // a single JSON build.
                let now = Self::now();
                let mut entry = map
                    .get_mut(&name)
                    .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                if entry.deleted_at.is_some() {
                    return Err(AzureKvError::KeySoftDeleted(name));
                }
                entry.deleted_at = Some(now);
                let mut json = entry.to_json(vault_name, dns_suffix)?;
                json["deletedDate"] = serde_json::json!(now);
                json["scheduledPurgeDate"] =
                    serde_json::json!(now + self.config.soft_delete_retention_seconds);
                info!(name = %name, "DeleteKey (soft)");
                Ok(AzureKvResponse { value: json })
            }
            AzureKvOperation::RecoverKey { name } => {
                validate_url_component(&name, "name")?;
                // Audit finding: nothing here needs a syscall under the
                // lock, but we still drop the guard before we log so
                // tracing layers cannot stall a shard.
                let mut entry = map
                    .get_mut(&name)
                    .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                if entry.deleted_at.is_none() {
                    return Err(AzureKvError::InvalidParameter(format!(
                        "key {name} is not deleted"
                    )));
                }
                entry.deleted_at = None;
                let json = entry.to_json(vault_name, dns_suffix)?;
                drop(entry);
                info!(name = %name, "RecoverKey");
                Ok(AzureKvResponse { value: json })
            }
            AzureKvOperation::PurgeKey { name } => {
                validate_url_component(&name, "name")?;
                // Atomic check-and-remove via remove_if so we never hold a
                // shard lock across two operations on the same key.
                let removed = map.remove_if(&name, |_, k| k.deleted_at.is_some());
                match removed {
                    Some(_) => {
                        info!(name = %name, "PurgeKey");
                        Ok(AzureKvResponse {
                            value: serde_json::json!({ "purged": name }),
                        })
                    }
                    None => {
                        if map.contains_key(&name) {
                            Err(AzureKvError::InvalidParameter(format!(
                                "key {name} must be soft-deleted before purge"
                            )))
                        } else {
                            Err(AzureKvError::KeyNotFound(name))
                        }
                    }
                }
            }
            AzureKvOperation::BackupKey { name } => {
                validate_url_component(&name, "name")?;
                // Audit finding H19: backup blob authentication MUST come
                // from a vault-wide master key, not from the key itself —
                // otherwise an attacker who can supply both the secret and
                // the tag (i.e. anyone fabricating a blob) is also the
                // verifier.
                let master = self.master_key.ok_or_else(|| {
                    AzureKvError::InvalidParameter("backup/restore not configured".into())
                })?;
                // Audit finding (MAC over base64 of body): clone the key
                // fields out under the guard, drop the guard before HMAC,
                // and compute the MAC over the **raw** blob bytes. The
                // previous code base64-encoded the body purely so the MAC
                // input matched a particular log line; base64 is a
                // transport encoding and has no business inside the MAC.
                let (name_bytes, ver_bytes, kty, key_size, secret) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    (
                        entry.name.as_bytes().to_vec(),
                        entry.version.as_bytes().to_vec(),
                        entry.kty,
                        entry.key_size,
                        zeroize::Zeroizing::new(entry.secret),
                    )
                };
                // Backup format: name_len(2) || name || version_len(2) || version
                //                || kty(1) || key_size(4) || secret(32) || tag(32)
                let mut blob = Vec::new();
                blob.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                blob.extend_from_slice(&name_bytes);
                blob.extend_from_slice(&(ver_bytes.len() as u16).to_be_bytes());
                blob.extend_from_slice(&ver_bytes);
                blob.push(match kty {
                    AzureKeyType::RsaHsm => 1,
                    AzureKeyType::EcHsm => 2,
                    AzureKeyType::OctHsm => 3,
                });
                blob.extend_from_slice(&key_size.unwrap_or(0).to_be_bytes());
                blob.extend_from_slice(&*secret);
                let backup_sub = crate::mock_crypto::subkey(&master, b"BACKUP");
                let tag = crate::mock_crypto::hmac_sign(&backup_sub, b"BACKUP", &blob);
                blob.extend_from_slice(&tag);
                Ok(AzureKvResponse {
                    value: serde_json::json!({ "value": blob }),
                })
            }
            AzureKvOperation::RestoreKey { blob } => {
                // Audit finding H19: reject restore unless a vault-wide
                // master key was seeded at construction. Without it the
                // tag would be self-authenticating and any attacker with a
                // backup-blob format could fabricate "restored" keys.
                let master = self.master_key.ok_or_else(|| {
                    AzureKvError::InvalidParameter("backup/restore not configured".into())
                })?;
                // Audit finding (CRIT — MAC-then-decrypt order): the
                // previous code parsed attacker-controlled length fields
                // *before* verifying the MAC, so a malformed blob could
                // panic / mis-index in the parser even though the MAC
                // was wrong. Re-order to: MAC the entire body first
                // (everything except the trailing 32-byte tag), reject
                // on mismatch, *then* parse.
                //
                // MAC input is now over the **raw** body bytes, matching
                // BackupKey above (previously the body was b64-encoded
                // before MACing, which served no purpose).
                if blob.len() < 2 + 2 + 1 + 4 + 32 + 32 {
                    return Err(AzureKvError::InvalidParameter(
                        "backup blob too short".into(),
                    ));
                }
                let tag_offset = blob.len() - 32;
                let body = &blob[..tag_offset];
                let tag = &blob[tag_offset..];
                let backup_sub = crate::mock_crypto::subkey(&master, b"BACKUP");
                let expected = crate::mock_crypto::hmac_sign(&backup_sub, b"BACKUP", body);
                let ok: bool = expected.as_slice().ct_eq(tag).into();
                if !ok {
                    return Err(AzureKvError::AuthenticationFailed(
                        "backup blob tag mismatch".into(),
                    ));
                }
                // MAC verified — every byte from here on is trusted.
                let mut p = 0;
                let nlen = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
                p += 2;
                if p + nlen > body.len() {
                    return Err(AzureKvError::InvalidParameter(
                        "name length out of bounds".into(),
                    ));
                }
                let name = String::from_utf8(body[p..p + nlen].to_vec())
                    .map_err(|_| AzureKvError::InvalidParameter("name not utf-8".into()))?;
                p += nlen;
                if p + 2 > body.len() {
                    return Err(AzureKvError::InvalidParameter(
                        "version header missing".into(),
                    ));
                }
                let vlen = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
                p += 2;
                if p + vlen + 1 + 4 + 32 > body.len() {
                    return Err(AzureKvError::InvalidParameter(
                        "version length out of bounds".into(),
                    ));
                }
                let version = String::from_utf8(body[p..p + vlen].to_vec())
                    .map_err(|_| AzureKvError::InvalidParameter("version not utf-8".into()))?;
                p += vlen;
                let kty = match body[p] {
                    1 => AzureKeyType::RsaHsm,
                    2 => AzureKeyType::EcHsm,
                    3 => AzureKeyType::OctHsm,
                    _ => return Err(AzureKvError::InvalidParameter("unknown kty byte".into())),
                };
                p += 1;
                let size_raw = u32::from_be_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
                let key_size = if size_raw == 0 { None } else { Some(size_raw) };
                p += 4;
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&body[p..p + 32]);
                validate_url_component(&name, "name")?;
                validate_url_component(&version, "version")?;
                use dashmap::mapref::entry::Entry;
                match map.entry(name.clone()) {
                    Entry::Occupied(_) => Err(AzureKvError::KeyAlreadyExists(name)),
                    Entry::Vacant(v) => {
                        let key = MockAzureKey {
                            name: name.clone(),
                            kty,
                            key_size,
                            version,
                            // Restored keys get a fresh `created_at`. We do
                            // not carry the original creation timestamp in
                            // the backup format (yet); marking restore time
                            // is closer to Azure semantics anyway.
                            created_at: Self::now(),
                            deleted_at: None,
                            secret,
                            subkey_sign: std::sync::OnceLock::new(),
                            subkey_wrap_auth: std::sync::OnceLock::new(),
                            subkey_wrap_enc: std::sync::OnceLock::new(),
                        };
                        let json = key.to_json(vault_name, dns_suffix)?;
                        v.insert(key);
                        Ok(AzureKvResponse { value: json })
                    }
                }
            }
            AzureKvOperation::Sign {
                name,
                algorithm,
                value_b64,
            } => {
                validate_url_component(&name, "name")?;
                validate_algorithm("sign", &algorithm)?;
                Self::validate_value_b64(&value_b64)?;
                // Audit finding (DashMap lock held across HMAC): clone the
                // cached `SIGN` sub-key + kid out under the guard, then drop
                // it. Audit foot-gun (perf): the sub-key is cached on
                // `MockAzureKey`'s `OnceLock` so HKDF only runs the first
                // time it is needed for this key.
                let (sub, kid) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    if entry.deleted_at.is_some() {
                        return Err(AzureKvError::KeySoftDeleted(name));
                    }
                    if !entry.kty.supports_sign() {
                        return Err(AzureKvError::UnsupportedOperation(format!(
                            "{} does not support sign",
                            entry.kty.wire_name()
                        )));
                    }
                    (
                        zeroize::Zeroizing::new(*entry.sign_subkey()),
                        entry.key_id(vault_name, dns_suffix)?,
                    )
                };
                let sig = Self::hmac_sign_with_sub(&sub, &algorithm, &value_b64);
                debug!(name = %name, algorithm = %algorithm, "Sign");
                Ok(AzureKvResponse {
                    value: serde_json::json!({
                        "kid": kid,
                        "value": Self::b64_encode(&sig),
                    }),
                })
            }
            AzureKvOperation::Verify {
                name,
                algorithm,
                digest_b64,
                signature_b64,
            } => {
                validate_url_component(&name, "name")?;
                validate_algorithm("sign", &algorithm)?;
                Self::validate_value_b64(&digest_b64)?;
                Self::validate_value_b64(&signature_b64)?;
                // Audit finding (DashMap lock held across HMAC): copy the
                // cached `SIGN` sub-key + kid out under the guard.
                let (sub, kid) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    if entry.deleted_at.is_some() {
                        return Err(AzureKvError::KeySoftDeleted(name));
                    }
                    (
                        zeroize::Zeroizing::new(*entry.sign_subkey()),
                        entry.key_id(vault_name, dns_suffix)?,
                    )
                };
                let expected = Self::hmac_sign_with_sub(&sub, &algorithm, &digest_b64);
                let provided = Self::b64_decode(&signature_b64)?;
                let valid: bool = expected.as_slice().ct_eq(&provided).into();
                if !valid {
                    warn!(name = %name, "Verify mismatch");
                }
                Ok(AzureKvResponse {
                    value: serde_json::json!({
                        "kid": kid,
                        "value": valid,
                    }),
                })
            }
            AzureKvOperation::Encrypt {
                name,
                algorithm,
                value_b64,
            } => {
                validate_url_component(&name, "name")?;
                validate_algorithm("encrypt", &algorithm)?;
                // Audit foot-gun (AEAD-shaped mechanism silently downgraded
                // to XOR): refuse `A*GCM` outright. The mock has no real GCM
                // implementation and the previous code would happily execute
                // an XOR-stream + HMAC tag under the AEAD wire name. See
                // `is_aead_shaped_algorithm` for rationale.
                if is_aead_shaped_algorithm(&algorithm) {
                    return Err(AzureKvError::UnsupportedOperation(format!(
                        "algorithm '{}' is AEAD-shaped; the mock Azure Key Vault \
                         shim does not implement authenticated encryption — \
                         wire this up against a real AES-GCM backend",
                        algorithm.escape_debug()
                    )));
                }
                Self::validate_value_b64(&value_b64)?;
                // Audit finding (DashMap lock held across HMAC): copy the
                // cached `WRAP-AUTH` + `WRAP-ENC` sub-keys and `kid` out
                // under the guard, then drop it. Audit foot-gun (perf): the
                // sub-keys are cached on `MockAzureKey`'s `OnceLock` so HKDF
                // runs at most once per sub-key per key.
                let (sub_auth, sub_enc, kid) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    if entry.deleted_at.is_some() {
                        return Err(AzureKvError::KeySoftDeleted(name));
                    }
                    if !entry.kty.supports_encrypt() {
                        return Err(AzureKvError::UnsupportedOperation(format!(
                            "{} does not support encrypt",
                            entry.kty.wire_name()
                        )));
                    }
                    (
                        zeroize::Zeroizing::new(*entry.wrap_auth_subkey()),
                        zeroize::Zeroizing::new(*entry.wrap_enc_subkey()),
                        entry.key_id(vault_name, dns_suffix)?,
                    )
                };
                let plaintext = Self::b64_decode(&value_b64)?;
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let mut ct = nonce.to_vec();
                ct.extend_from_slice(&Self::xor_stream_with_sub(&sub_enc, &nonce, &plaintext)?);
                // Audit H18: tag with the dedicated `WRAP-AUTH` sub-key.
                // Audit finding (MAC over base64): MAC raw ciphertext.
                let tag = Self::wrap_tag_with_sub(&sub_auth, &algorithm, &ct);
                ct.extend_from_slice(&tag);
                Ok(AzureKvResponse {
                    value: serde_json::json!({
                        "kid": kid,
                        "value": Self::b64_encode(&ct),
                    }),
                })
            }
            AzureKvOperation::Decrypt {
                name,
                algorithm,
                value_b64,
            } => {
                validate_url_component(&name, "name")?;
                validate_algorithm("decrypt", &algorithm)?;
                // Audit foot-gun: see Encrypt arm above — refuse AEAD-shaped
                // mechanisms on the inverse path too.
                if is_aead_shaped_algorithm(&algorithm) {
                    return Err(AzureKvError::UnsupportedOperation(format!(
                        "algorithm '{}' is AEAD-shaped; the mock Azure Key Vault \
                         shim does not implement authenticated decryption",
                        algorithm.escape_debug()
                    )));
                }
                Self::validate_value_b64(&value_b64)?;
                // Audit finding (DashMap lock held across HMAC): copy the
                // cached `WRAP-AUTH` + `WRAP-ENC` sub-keys and `kid` out
                // under the guard.
                let (sub_auth, sub_enc, kid) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    if entry.deleted_at.is_some() {
                        return Err(AzureKvError::KeySoftDeleted(name));
                    }
                    (
                        zeroize::Zeroizing::new(*entry.wrap_auth_subkey()),
                        zeroize::Zeroizing::new(*entry.wrap_enc_subkey()),
                        entry.key_id(vault_name, dns_suffix)?,
                    )
                };
                let blob = Self::b64_decode(&value_b64)?;
                if blob.len() < 12 + 32 {
                    return Err(AzureKvError::InvalidParameter(
                        "ciphertext too short".into(),
                    ));
                }
                let tag_offset = blob.len() - 32;
                let (body, tag) = blob.split_at(tag_offset);
                // Audit finding (MAC over base64): MAC raw body bytes.
                let expected = Self::wrap_tag_with_sub(&sub_auth, &algorithm, body);
                let ok: bool = expected.as_slice().ct_eq(tag).into();
                if !ok {
                    return Err(AzureKvError::AuthenticationFailed(
                        "ciphertext tag mismatch".into(),
                    ));
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&body[..12]);
                let plaintext = Self::xor_stream_with_sub(&sub_enc, &nonce, &body[12..])?;
                Ok(AzureKvResponse {
                    value: serde_json::json!({
                        "kid": kid,
                        "value": Self::b64_encode(&plaintext),
                    }),
                })
            }
            AzureKvOperation::WrapKey {
                name,
                algorithm,
                value_b64,
            } => {
                validate_url_component(&name, "name")?;
                validate_algorithm("wrap", &algorithm)?;
                Self::validate_value_b64(&value_b64)?;
                let (sub_auth, sub_enc, kid) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    if entry.deleted_at.is_some() {
                        return Err(AzureKvError::KeySoftDeleted(name));
                    }
                    (
                        zeroize::Zeroizing::new(*entry.wrap_auth_subkey()),
                        zeroize::Zeroizing::new(*entry.wrap_enc_subkey()),
                        entry.key_id(vault_name, dns_suffix)?,
                    )
                };
                let raw = Self::b64_decode(&value_b64)?;
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let mut wrapped = nonce.to_vec();
                wrapped.extend_from_slice(&Self::xor_stream_with_sub(&sub_enc, &nonce, &raw)?);
                // Audit finding (MAC over base64): MAC raw wrapped bytes.
                let tag = Self::wrap_tag_with_sub(&sub_auth, &algorithm, &wrapped);
                wrapped.extend_from_slice(&tag);
                Ok(AzureKvResponse {
                    value: serde_json::json!({
                        "kid": kid,
                        "value": Self::b64_encode(&wrapped),
                    }),
                })
            }
            AzureKvOperation::UnwrapKey {
                name,
                algorithm,
                value_b64,
            } => {
                validate_url_component(&name, "name")?;
                validate_algorithm("wrap", &algorithm)?;
                Self::validate_value_b64(&value_b64)?;
                let (sub_auth, sub_enc, kid) = {
                    let entry = map
                        .get(&name)
                        .ok_or_else(|| AzureKvError::KeyNotFound(name.clone()))?;
                    if entry.deleted_at.is_some() {
                        return Err(AzureKvError::KeySoftDeleted(name));
                    }
                    (
                        zeroize::Zeroizing::new(*entry.wrap_auth_subkey()),
                        zeroize::Zeroizing::new(*entry.wrap_enc_subkey()),
                        entry.key_id(vault_name, dns_suffix)?,
                    )
                };
                let blob = Self::b64_decode(&value_b64)?;
                if blob.len() < 12 + 32 {
                    return Err(AzureKvError::InvalidParameter(
                        "wrapped key too short".into(),
                    ));
                }
                let tag_offset = blob.len() - 32;
                let (body, tag) = blob.split_at(tag_offset);
                // Audit finding (MAC over base64): MAC raw body bytes.
                let expected = Self::wrap_tag_with_sub(&sub_auth, &algorithm, body);
                let ok: bool = expected.as_slice().ct_eq(tag).into();
                if !ok {
                    return Err(AzureKvError::AuthenticationFailed(
                        "wrap tag mismatch".into(),
                    ));
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&body[..12]);
                let plaintext = Self::xor_stream_with_sub(&sub_enc, &nonce, &body[12..])?;
                Ok(AzureKvResponse {
                    value: serde_json::json!({
                        "kid": kid,
                        "value": Self::b64_encode(&plaintext),
                    }),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Audit finding (test-module ACL shadows module-level one): renamed to
    /// `LocalDenyAllAzureAcl` so the module-level [`DenyAllAzureAcl`] stays
    /// importable from tests.
    struct LocalDenyAllAzureAcl;
    impl AzureKvAcl for LocalDenyAllAzureAcl {
        fn check(&self, _: &AzureIdentity, _: &str, _: AzureOp) -> bool {
            false
        }
    }

    #[test]
    fn azure_acl_denies_unauthorized_caller() {
        crate::_enable_mock_for_tests();
        let shim = MockAzureKvShim::with_vault_name("locked-vault")
            .unwrap()
            .with_acl(Arc::new(LocalDenyAllAzureAcl));
        let err = shim
            .process_as(
                &AzureIdentity::new("mallory"),
                AzureKvOperation::CreateKey {
                    name: "forbidden".into(),
                    kty: AzureKeyType::RsaHsm,
                    key_size: Some(2048),
                },
            )
            .unwrap_err();
        assert!(matches!(err, AzureKvError::PermissionDenied(_)));
    }

    fn make_shim() -> MockAzureKvShim {
        crate::_enable_mock_for_tests();
        // Audit H20: default ACL is now deny-all; opt the test suite into
        // the legacy permissive behaviour. Seed a master key so backup /
        // restore tests still work (audit H19).
        MockAzureKvShim::with_vault_name("my-vault")
            .unwrap()
            .permissive_for_tests()
            .with_master_key([0x42u8; 32])
    }

    fn create_default(shim: &MockAzureKvShim, name: &str, kty: AzureKeyType) -> String {
        let resp = shim
            .process(AzureKvOperation::CreateKey {
                name: name.to_string(),
                kty,
                key_size: match kty {
                    AzureKeyType::RsaHsm => Some(2048),
                    AzureKeyType::OctHsm => Some(256),
                    AzureKeyType::EcHsm => Some(256),
                },
            })
            .unwrap();
        resp.value["key"]["kid"].as_str().unwrap().to_string()
    }

    #[test]
    fn create_key_returns_wire_kty() {
        let shim = make_shim();
        let resp = shim
            .process(AzureKvOperation::CreateKey {
                name: "k1".into(),
                kty: AzureKeyType::RsaHsm,
                key_size: Some(2048),
            })
            .unwrap();
        assert_eq!(resp.value["key"]["kty"], "RSA-HSM");
    }

    #[test]
    fn create_duplicate_key_rejected() {
        let shim = make_shim();
        create_default(&shim, "dup", AzureKeyType::RsaHsm);
        let err = shim
            .process(AzureKvOperation::CreateKey {
                name: "dup".into(),
                kty: AzureKeyType::RsaHsm,
                key_size: Some(2048),
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::KeyAlreadyExists(_)));
    }

    #[test]
    fn create_key_invalid_size_rejected() {
        let shim = make_shim();
        let err = shim
            .process(AzureKvOperation::CreateKey {
                name: "bad".into(),
                kty: AzureKeyType::RsaHsm,
                key_size: Some(1024),
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::InvalidParameter(_)));
    }

    #[test]
    fn get_nonexistent_key() {
        let shim = make_shim();
        let err = shim
            .process(AzureKvOperation::GetKey {
                name: "missing".into(),
                version: None,
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::KeyNotFound(_)));
    }

    #[test]
    fn list_keys_excludes_deleted() {
        let shim = make_shim();
        create_default(&shim, "live", AzureKeyType::RsaHsm);
        create_default(&shim, "gone", AzureKeyType::RsaHsm);
        shim.process(AzureKvOperation::DeleteKey {
            name: "gone".into(),
        })
        .unwrap();
        let live = shim.process(AzureKvOperation::ListKeys).unwrap();
        assert_eq!(live.value["value"].as_array().unwrap().len(), 1);
        let deleted = shim.process(AzureKvOperation::ListDeletedKeys).unwrap();
        assert_eq!(deleted.value["value"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn soft_delete_then_recover() {
        let shim = make_shim();
        create_default(&shim, "rec", AzureKeyType::RsaHsm);
        shim.process(AzureKvOperation::DeleteKey { name: "rec".into() })
            .unwrap();
        // GetKey on a soft-deleted key fails.
        let err = shim
            .process(AzureKvOperation::GetKey {
                name: "rec".into(),
                version: None,
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::KeySoftDeleted(_)));
        // Recover.
        shim.process(AzureKvOperation::RecoverKey { name: "rec".into() })
            .unwrap();
        // GetKey now succeeds.
        let resp = shim
            .process(AzureKvOperation::GetKey {
                name: "rec".into(),
                version: None,
            })
            .unwrap();
        assert!(resp.value["key"]["kid"].as_str().is_some());
    }

    #[test]
    fn purge_requires_soft_delete() {
        let shim = make_shim();
        create_default(&shim, "p", AzureKeyType::RsaHsm);
        let err = shim
            .process(AzureKvOperation::PurgeKey { name: "p".into() })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::InvalidParameter(_)));
        shim.process(AzureKvOperation::DeleteKey { name: "p".into() })
            .unwrap();
        shim.process(AzureKvOperation::PurgeKey { name: "p".into() })
            .unwrap();
        // After purge, listing deleted should be empty.
        let deleted = shim.process(AzureKvOperation::ListDeletedKeys).unwrap();
        assert_eq!(deleted.value["value"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn backup_restore_roundtrip() {
        let shim = make_shim();
        create_default(&shim, "bk", AzureKeyType::RsaHsm);
        let backup = shim
            .process(AzureKvOperation::BackupKey { name: "bk".into() })
            .unwrap();
        let blob: Vec<u8> = backup.value["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        // Purge so the slot is free.
        shim.process(AzureKvOperation::DeleteKey { name: "bk".into() })
            .unwrap();
        shim.process(AzureKvOperation::PurgeKey { name: "bk".into() })
            .unwrap();
        let restore = shim.process(AzureKvOperation::RestoreKey { blob }).unwrap();
        assert!(restore.value["key"]["kid"].as_str().is_some());
    }

    #[test]
    fn restore_tampered_blob_rejected() {
        let shim = make_shim();
        create_default(&shim, "tk", AzureKeyType::RsaHsm);
        let backup = shim
            .process(AzureKvOperation::BackupKey { name: "tk".into() })
            .unwrap();
        let mut blob: Vec<u8> = backup.value["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        // Need an empty slot to attempt restore — purge the original.
        shim.process(AzureKvOperation::DeleteKey { name: "tk".into() })
            .unwrap();
        shim.process(AzureKvOperation::PurgeKey { name: "tk".into() })
            .unwrap();
        let err = shim
            .process(AzureKvOperation::RestoreKey { blob })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::AuthenticationFailed(_)));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let shim = make_shim();
        create_default(&shim, "s", AzureKeyType::EcHsm);
        let sig = shim
            .process(AzureKvOperation::Sign {
                name: "s".into(),
                algorithm: "ES256".into(),
                value_b64: "dGVzdA==".into(),
            })
            .unwrap();
        let v = sig.value["value"].as_str().unwrap().to_string();
        let verify = shim
            .process(AzureKvOperation::Verify {
                name: "s".into(),
                algorithm: "ES256".into(),
                digest_b64: "dGVzdA==".into(),
                signature_b64: v,
            })
            .unwrap();
        assert_eq!(verify.value["value"], true);
    }

    #[test]
    fn sign_unsupported_kty_rejected() {
        let shim = make_shim();
        create_default(&shim, "oct", AzureKeyType::OctHsm);
        let err = shim
            .process(AzureKvOperation::Sign {
                name: "oct".into(),
                algorithm: "RS256".into(),
                value_b64: "dGVzdA==".into(),
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::UnsupportedOperation(_)));
    }

    #[test]
    fn sign_unknown_algorithm_rejected() {
        let shim = make_shim();
        create_default(&shim, "x", AzureKeyType::RsaHsm);
        let err = shim
            .process(AzureKvOperation::Sign {
                name: "x".into(),
                algorithm: "FAKE".into(),
                value_b64: "dGVzdA==".into(),
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::InvalidParameter(_)));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let shim = make_shim();
        create_default(&shim, "ed", AzureKeyType::RsaHsm);
        let enc = shim
            .process(AzureKvOperation::Encrypt {
                name: "ed".into(),
                algorithm: "RSA-OAEP".into(),
                value_b64: "aGVsbG8=".into(),
            })
            .unwrap();
        let ct = enc.value["value"].as_str().unwrap().to_string();
        let dec = shim
            .process(AzureKvOperation::Decrypt {
                name: "ed".into(),
                algorithm: "RSA-OAEP".into(),
                value_b64: ct,
            })
            .unwrap();
        assert_eq!(dec.value["value"], "aGVsbG8=");
    }

    #[test]
    fn decrypt_tampered_rejected() {
        let shim = make_shim();
        create_default(&shim, "tt", AzureKeyType::RsaHsm);
        let enc = shim
            .process(AzureKvOperation::Encrypt {
                name: "tt".into(),
                algorithm: "RSA-OAEP".into(),
                value_b64: "aGVsbG8=".into(),
            })
            .unwrap();
        let ct_b64 = enc.value["value"].as_str().unwrap().to_string();
        // Decode, flip a byte inside the tag region (last 32 bytes), re-encode.
        let mut raw = MockAzureKvShim::b64_decode(&ct_b64).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered_b64 = MockAzureKvShim::b64_encode(&raw);
        let err = shim
            .process(AzureKvOperation::Decrypt {
                name: "tt".into(),
                algorithm: "RSA-OAEP".into(),
                value_b64: tampered_b64,
            })
            .unwrap_err();
        assert!(matches!(err, AzureKvError::AuthenticationFailed(_)));
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let shim = make_shim();
        create_default(&shim, "w", AzureKeyType::RsaHsm);
        let wrap = shim
            .process(AzureKvOperation::WrapKey {
                name: "w".into(),
                algorithm: "RSA-OAEP".into(),
                value_b64: "a2V5bWF0ZXJpYWw=".into(),
            })
            .unwrap();
        let wrapped = wrap.value["value"].as_str().unwrap().to_string();
        let unwrap = shim
            .process(AzureKvOperation::UnwrapKey {
                name: "w".into(),
                algorithm: "RSA-OAEP".into(),
                value_b64: wrapped,
            })
            .unwrap();
        assert_eq!(unwrap.value["value"], "a2V5bWF0ZXJpYWw=");
    }

    #[test]
    fn key_id_format_and_validation() {
        assert_eq!(
            azure_key_id("test-vault", "my-key", "abc123").unwrap(),
            "https://test-vault.vault.azure.net/keys/my-key/abc123"
        );
        assert!(azure_key_id("bad/vault", "key", "v1").is_err());
        assert!(azure_key_id("vault", "key?name", "v1").is_err());
        assert!(azure_key_id("vault", "key", "v1#frag").is_err());
        assert!(azure_key_id("vault", "key", "v 1").is_err()); // whitespace
        assert!(azure_key_id("vault", "key", "v\n1").is_err()); // newline
        assert!(azure_key_id("", "key", "v1").is_err());
    }

    #[test]
    fn key_id_length_bounded() {
        let big = "a".repeat(AZURE_MAX_COMPONENT_LEN + 1);
        assert!(azure_key_id(&big, "k", "v").is_err());
    }

    #[test]
    fn key_type_wire_name_format() {
        assert_eq!(AzureKeyType::RsaHsm.wire_name(), "RSA-HSM");
        assert_eq!(AzureKeyType::EcHsm.wire_name(), "EC-HSM");
        assert_eq!(AzureKeyType::OctHsm.wire_name(), "oct-HSM");
    }

    #[test]
    fn config_defaults() {
        let json = r#"{"vault_name":"v","subscription_id":"s","resource_group":"rg"}"#;
        let cfg: AzureKvConfig = serde_json::from_str(json).unwrap();
        assert_eq!(&*cfg.location, "eastus");
        assert_eq!(cfg.soft_delete_retention_seconds, 7 * 86400);
    }

    #[test]
    fn full_lifecycle() {
        let shim = make_shim();
        create_default(&shim, "lc", AzureKeyType::RsaHsm);
        shim.process(AzureKvOperation::DeleteKey { name: "lc".into() })
            .unwrap();
        shim.process(AzureKvOperation::RecoverKey { name: "lc".into() })
            .unwrap();
        shim.process(AzureKvOperation::DeleteKey { name: "lc".into() })
            .unwrap();
        shim.process(AzureKvOperation::PurgeKey { name: "lc".into() })
            .unwrap();
    }

    #[test]
    fn error_display_escapes_control_chars() {
        let err = AzureKvError::KeyNotFound("evil\nname".into());
        assert!(!err.to_string().contains('\n'));
    }

    #[test]
    fn b64_roundtrip() {
        let original = b"hello world";
        let enc = MockAzureKvShim::b64_encode(original);
        let dec = MockAzureKvShim::b64_decode(&enc).unwrap();
        assert_eq!(dec, original);
    }
}
