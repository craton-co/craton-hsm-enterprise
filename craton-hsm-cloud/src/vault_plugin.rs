// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! HashiCorp Vault Transit secrets engine backend plugin for Craton HSM.
//!
//! Maps Vault transit API operations (encrypt, decrypt, sign, verify, key
//! management) to Craton HSM key operations.
//!
//! The mock backend uses HMAC-SHA256 over per-key random material rather
//! than fake string concatenation. This is still **not production grade** —
//! there is no AEAD, no real RSA/ECDSA — but it is unforgeable by parties
//! who do not hold the key.
//!
//! # Release-build protection (audit findings M3/M4/M5)
//!
//! In addition to the `mock-insecure-do-not-ship` Cargo feature and the
//! `CRATON_HSM_ALLOW_MOCK=1` runtime env gate, release builds require
//! `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1`. Mock key material is capped at
//! [`crate::mock_guard::MAX_MOCK_KEY_BYTES`] (32 bytes) — see
//! [`crate::mock_guard`] for details.
//!
//! # Key-name validation (audit finding L4)
//!
//! Every request carrying a `key_name`/`name` string is checked by
//! [`validate_vault_key_name`]: empty, NUL-containing, `/`-prefixed, or
//! oversize names (`> MAX_VAULT_KEY_NAME_LEN` bytes) are rejected before any
//! backend state is consulted.

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
use rand::RngCore;
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
use zeroize::ZeroizeOnDrop;

/// Errors from the Vault transit backend.
#[derive(Debug, Clone)]
pub enum VaultError {
    /// The requested key was not found.
    KeyNotFound(String),
    /// The key already exists.
    KeyExists(String),
    /// Invalid ciphertext format.
    InvalidCiphertext(String),
    /// Operation not permitted by policy.
    PermissionDenied(String),
    /// Invalid request parameters.
    InvalidRequest(String),
    /// Authentication / integrity check failed.
    AuthenticationFailed(String),
    /// Internal backend error.
    Internal(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::KeyNotFound(k) => write!(f, "key not found: {}", k.escape_debug()),
            VaultError::KeyExists(k) => write!(f, "key already exists: {}", k.escape_debug()),
            VaultError::InvalidCiphertext(msg) => {
                write!(f, "invalid ciphertext: {}", msg.escape_debug())
            }
            VaultError::PermissionDenied(msg) => {
                write!(f, "permission denied: {}", msg.escape_debug())
            }
            VaultError::InvalidRequest(msg) => {
                write!(f, "invalid request: {}", msg.escape_debug())
            }
            VaultError::AuthenticationFailed(msg) => {
                write!(f, "authentication failed: {}", msg.escape_debug())
            }
            VaultError::Internal(msg) => write!(f, "internal error: {}", msg.escape_debug()),
        }
    }
}

impl std::error::Error for VaultError {}

/// Result alias for Vault transit operations.
pub type VaultResult<T> = std::result::Result<T, VaultError>;

/// Key types supported by the transit backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultKeyType {
    /// AES-256-GCM with 96-bit nonce.
    Aes256Gcm96,
    /// AES-128-GCM with 96-bit nonce.
    Aes128Gcm96,
    /// RSA-OAEP with 2048-bit key.
    RsaOaep2048,
    /// RSA-OAEP with 4096-bit key.
    RsaOaep4096,
    /// ECDSA with P-256 curve.
    EcdsaP256,
    /// ECDSA with P-384 curve.
    EcdsaP384,
}

impl VaultKeyType {
    /// Wire-format string used by the Vault transit API.
    pub fn wire_name(self) -> &'static str {
        match self {
            VaultKeyType::Aes256Gcm96 => "aes256-gcm96",
            VaultKeyType::Aes128Gcm96 => "aes128-gcm96",
            VaultKeyType::RsaOaep2048 => "rsa-2048",
            VaultKeyType::RsaOaep4096 => "rsa-4096",
            VaultKeyType::EcdsaP256 => "ecdsa-p256",
            VaultKeyType::EcdsaP384 => "ecdsa-p384",
        }
    }

    /// Whether the key type supports symmetric encryption operations.
    pub fn supports_encrypt(self) -> bool {
        matches!(
            self,
            VaultKeyType::Aes256Gcm96
                | VaultKeyType::Aes128Gcm96
                | VaultKeyType::RsaOaep2048
                | VaultKeyType::RsaOaep4096
        )
    }

    /// Whether the key type supports signing.
    pub fn supports_sign(self) -> bool {
        matches!(
            self,
            VaultKeyType::EcdsaP256
                | VaultKeyType::EcdsaP384
                | VaultKeyType::RsaOaep2048
                | VaultKeyType::RsaOaep4096
        )
    }
}

/// Configuration for the Vault transit backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransitConfig {
    /// Address of the Craton HSM instance.
    pub hsm_addr: String,
    /// Default key type for new keys.
    pub default_key_type: VaultKeyType,
    /// Automatic key rotation period in seconds. When non-zero, the backend
    /// will rotate keys older than this period on the next operation.
    pub auto_rotate_period: Option<u64>,
    /// Minimum key version allowed for decryption.
    #[serde(default = "default_min_decryption_version")]
    pub min_decryption_version: u32,
    /// Minimum key version allowed for encryption.
    #[serde(default)]
    pub min_encryption_version: u32,
    /// Whether key deletion is allowed.
    #[serde(default)]
    pub deletion_allowed: bool,
}

fn default_min_decryption_version() -> u32 {
    1
}

/// Request types for the Vault transit backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultTransitRequest {
    /// Encrypt plaintext using a named key.
    Encrypt {
        /// Name of the encryption key.
        key_name: String,
        /// Base64-encoded plaintext.
        plaintext_b64: String,
        /// Optional context for convergent encryption.
        context: Option<Vec<u8>>,
    },
    /// Decrypt ciphertext using a named key.
    Decrypt {
        /// Name of the encryption key.
        key_name: String,
        /// Vault-formatted ciphertext (vault:v{n}:{b64}).
        ciphertext: String,
        /// Optional context for convergent decryption.
        context: Option<Vec<u8>>,
    },
    /// Re-encrypt ciphertext under the latest key version.
    Rewrap {
        /// Name of the encryption key.
        key_name: String,
        /// Existing Vault-formatted ciphertext to re-wrap.
        ciphertext: String,
        /// Optional context (must match the original encryption).
        context: Option<Vec<u8>>,
    },
    /// Sign input data using a named key.
    Sign {
        /// Name of the signing key.
        key_name: String,
        /// Base64-encoded input data.
        input_b64: String,
        /// Hash algorithm to use (e.g. "sha2-256").
        hash_algorithm: String,
    },
    /// Verify a signature against input data.
    Verify {
        /// Name of the signing key.
        key_name: String,
        /// Base64-encoded input data.
        input_b64: String,
        /// The signature to verify.
        signature: String,
        /// Hash algorithm used for signing.
        hash_algorithm: String,
    },
    /// Generate a high-entropy data key (encrypted under a transit key).
    DataKey {
        /// Name of the wrapping key.
        key_name: String,
        /// Whether to also return the plaintext (Vault `plaintext` mode).
        plaintext: bool,
        /// Number of bits requested (128, 256, or 512).
        bits: u32,
    },
    /// Compute a hash of input data.
    Hash {
        /// Hash algorithm to use.
        algorithm: String,
        /// Base64-encoded input.
        input_b64: String,
    },
    /// Compute an HMAC of input data using a named key.
    Hmac {
        /// Name of the key.
        key_name: String,
        /// Base64-encoded input.
        input_b64: String,
        /// Hash algorithm.
        algorithm: String,
    },
    /// Generate cryptographically secure random bytes.
    Random {
        /// Number of bytes to return.
        bytes: usize,
    },
    /// Export a key version (only permitted for exportable keys).
    ExportKey {
        /// Key name.
        name: String,
        /// Optional version.  If `None`, returns the latest version.
        version: Option<u32>,
    },
    /// List all key names in the backend.
    ListKeys,
    /// Read metadata for a single key.
    ReadKey {
        /// Key name.
        name: String,
    },
    /// Delete a key (only permitted when `deletion_allowed = true`).
    DeleteKey {
        /// Key name.
        name: String,
    },
    /// Create a new named key.
    CreateKey {
        /// Name for the new key.
        name: String,
        /// Type of key to create.
        key_type: VaultKeyType,
        /// Whether the key can be exported.
        exportable: bool,
    },
    /// Rotate a named key to a new version.
    RotateKey {
        /// Name of the key to rotate.
        name: String,
    },
}

/// Response from the Vault transit backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransitResponse {
    /// Response payload as ordered key-value data.
    pub data: serde_json::Map<String, Value>,
    /// Optional warnings about the operation.
    pub warnings: Option<Vec<String>>,
}

impl VaultTransitResponse {
    fn new() -> Self {
        Self {
            data: serde_json::Map::new(),
            warnings: None,
        }
    }
    fn with(mut self, key: &str, value: Value) -> Self {
        self.data.insert(key.to_string(), value);
        self
    }
}

/// Trait for Vault transit backend implementations.
pub trait VaultTransitBackend: Send + Sync {
    /// Handle a transit API request and return a response.
    fn handle_request(&self, req: VaultTransitRequest) -> VaultResult<VaultTransitResponse>;
}

/// Logical identity carried alongside a Vault transit request.
///
/// The embedding binary is expected to authenticate the caller at the
/// transport layer (mTLS, bearer token, OIDC) and materialise the result as a
/// [`VaultIdentity`] before dispatching into the mock backend. The identity
/// string is opaque to this crate and passed verbatim to [`VaultAcl::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultIdentity {
    /// Authenticated principal name (user, service account, token alias).
    pub principal: String,
}

impl VaultIdentity {
    /// Construct a new identity from an already-authenticated principal.
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
        }
    }

    /// Convenience anonymous identity, used in the ACL tests.
    pub fn anonymous() -> Self {
        Self {
            principal: String::new(),
        }
    }
}

/// Operation classes over which a [`VaultAcl`] policy can gate access.
///
/// These correspond 1:1 to the request arms in [`VaultTransitRequest`] but
/// are coarser-grained so a policy does not have to track every new request
/// kind as it is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOp {
    /// Read key metadata / list keys.
    Read,
    /// Create, rotate, delete keys.
    Manage,
    /// Encrypt / decrypt / rewrap / data-key.
    Crypto,
    /// Sign / verify.
    Sign,
    /// HMAC / hash / random.
    Hash,
    /// Export raw key material (exportable keys only).
    Export,
}

/// Pluggable per-key ACL consulted by [`VaultTransitBackend::handle_request`]
/// before any key operation touches backend state.
///
/// Audit finding H: the mock Vault backend authenticated nothing — any
/// caller with a handle could read or manipulate any key. Production
/// deployments wire this trait up to `craton-hsm-auth` (or the embedder's
/// own policy engine); the built-in [`AllowAllVaultAcl`] preserves the
/// previous behaviour for existing tests and mock usage.
pub trait VaultAcl: Send + Sync {
    /// Return `true` if `identity` is permitted to perform `op` on `key_id`.
    ///
    /// The backend consults this before every key-scoped operation. A
    /// `false` result surfaces as [`VaultError::PermissionDenied`] without
    /// leaking whether the key exists.
    fn check(&self, identity: &VaultIdentity, key_id: &str, op: VaultOp) -> bool;
}

/// Permissive ACL kept for callers that explicitly opt in. **NOT the
/// default** — see [`DenyAllVaultAcl`]. Audit finding H20 changed the
/// default to fail-closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllVaultAcl;

impl VaultAcl for AllowAllVaultAcl {
    fn check(&self, _identity: &VaultIdentity, _key_id: &str, _op: VaultOp) -> bool {
        true
    }
}

/// Default deny-all ACL (audit finding H20). The mock backend ships with
/// this installed; embedders must opt in via [`MockVaultBackend::with_acl`]
/// or [`MockVaultBackend::permissive_for_tests`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllVaultAcl;

impl VaultAcl for DenyAllVaultAcl {
    fn check(&self, _identity: &VaultIdentity, _key_id: &str, _op: VaultOp) -> bool {
        false
    }
}

/// Trait stub for the future "talk to a real Craton HSM at the configured
/// `hsm_addr`" client. Production deployments will implement this against a
/// real RPC transport; the mock backend logs `would connect to hsm_addr` at
/// construction so misconfigured addresses surface in dev environments
/// without forcing every embedder to wire up real IO.
pub trait HsmAddrClient: Send + Sync {
    /// The configured HSM address as a string. Used by the mock backend for
    /// logging and by real implementations to (eventually) establish the
    /// transport.
    fn hsm_addr(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

/// Maximum ciphertext string length accepted by `parse_vault_ciphertext`.
pub const MAX_VAULT_CIPHERTEXT_LEN: usize = 128 * 1024;
/// Maximum input bytes for HMAC/Sign/Hash mock operations.
pub const MAX_VAULT_INPUT_LEN: usize = 1024 * 1024;
/// Maximum bytes returned by `Random`.
pub const MAX_VAULT_RANDOM_BYTES: usize = 64 * 1024;
/// Maximum byte length of a Vault transit key name. Vault's own implementation
/// imposes no hard limit, which in this mock backend turns into an unbounded
/// allocation / log-injection vector (audit finding L4). 256 bytes is well
/// above any legitimate key name we've seen in production deployments.
pub const MAX_VAULT_KEY_NAME_LEN: usize = 256;

/// Reject key names that are empty, too long, or contain structural
/// characters that would break filesystem-backed storage, HTTP routing, or
/// log sinks. Audit finding L4.
///
/// Disallowed:
/// - length 0 or greater than [`MAX_VAULT_KEY_NAME_LEN`]
/// - embedded NUL bytes (log-injection, C-string truncation)
/// - a leading `/` (path-traversal against potential future filesystem backends)
pub fn validate_vault_key_name(name: &str) -> VaultResult<()> {
    if name.is_empty() {
        return Err(VaultError::InvalidRequest("name must not be empty".into()));
    }
    if name.len() > MAX_VAULT_KEY_NAME_LEN {
        return Err(VaultError::InvalidRequest(format!(
            "name exceeds {MAX_VAULT_KEY_NAME_LEN} bytes"
        )));
    }
    if name.contains('\0') {
        return Err(VaultError::InvalidRequest(
            "name must not contain NUL bytes".into(),
        ));
    }
    if name.starts_with('/') {
        return Err(VaultError::InvalidRequest(
            "name must not start with '/'".into(),
        ));
    }
    Ok(())
}

/// Parse Vault versioned ciphertext format: `vault:v{version}:{base64_ciphertext}`.
pub fn parse_vault_ciphertext(ct: &str) -> VaultResult<(u32, String)> {
    if ct.len() > MAX_VAULT_CIPHERTEXT_LEN {
        return Err(VaultError::InvalidCiphertext(format!(
            "ciphertext exceeds maximum allowed length ({MAX_VAULT_CIPHERTEXT_LEN} bytes)"
        )));
    }

    // Allocation-free splitn — destructure into three Options.
    let mut it = ct.splitn(3, ':');
    let prefix = it.next();
    let version_str = it.next();
    let payload = it.next();
    let (prefix, version_str, payload) = match (prefix, version_str, payload) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            return Err(VaultError::InvalidCiphertext(
                "expected vault:v{n}:{b64}".into(),
            ))
        }
    };
    if prefix != "vault" {
        return Err(VaultError::InvalidCiphertext(
            "expected vault:v{n}:{b64}".into(),
        ));
    }
    let version_str = version_str
        .strip_prefix('v')
        .ok_or_else(|| VaultError::InvalidCiphertext("missing 'v' prefix on version".into()))?;
    let version: u32 = version_str
        .parse()
        .map_err(|_| VaultError::InvalidCiphertext("invalid version number".into()))?;

    if !payload
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='))
    {
        return Err(VaultError::InvalidCiphertext(
            "base64 payload contains invalid characters".into(),
        ));
    }

    Ok((version, payload.to_string()))
}

/// Format ciphertext in Vault's versioned format.
pub fn format_vault_ciphertext(version: u32, b64_ciphertext: &str) -> String {
    format!("vault:v{version}:{b64_ciphertext}")
}

/// Per-version key material for the mock backend.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
#[derive(ZeroizeOnDrop)]
struct MockKeyVersion {
    bytes: [u8; 32],
    #[zeroize(skip)]
    created_at: u64,
}

/// Internal key entry stored by the mock backend.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
struct MockKeyEntry {
    key_type: VaultKeyType,
    exportable: bool,
    /// Append-only versions list under a single RwLock — much cheaper than a
    /// per-key DashMap.
    versions: RwLock<Vec<MockKeyVersion>>,
    latest_version: AtomicU32,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockKeyEntry {
    fn new(key_type: VaultKeyType, exportable: bool) -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            key_type,
            exportable,
            versions: RwLock::new(vec![MockKeyVersion {
                bytes,
                created_at: now,
            }]),
            latest_version: AtomicU32::new(1),
        }
    }

    fn rotate(&self) -> u32 {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut versions = self.versions.write();
        versions.push(MockKeyVersion {
            bytes,
            created_at: now,
        });
        let new = versions.len() as u32;
        self.latest_version.store(new, Ordering::Relaxed);
        new
    }

    fn material(&self, version: u32) -> Option<[u8; 32]> {
        let versions = self.versions.read();
        versions
            .get(version.checked_sub(1)? as usize)
            .map(|v| v.bytes)
    }

    fn latest(&self) -> u32 {
        self.latest_version.load(Ordering::Relaxed)
    }
}

/// Mock Vault transit backend for testing and local development.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
pub struct MockVaultBackend {
    keys: DashMap<String, MockKeyEntry>,
    config: VaultTransitConfig,
    acl: std::sync::Arc<dyn VaultAcl>,
    /// Identity used by [`VaultTransitBackend::handle_request`] when the
    /// caller did not provide one. Embedders that wire up real auth should
    /// use [`MockVaultBackend::handle_request_as`] to pass the authenticated
    /// principal in per-request.
    default_identity: VaultIdentity,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockVaultBackend {
    /// Test-only constructor that pins `hsm_addr` to `https://localhost`.
    ///
    /// Audit finding (foot-gun: hardcoded localhost leaks into binaries): the
    /// previous `MockVaultBackend::new()` baked `https://localhost` into the
    /// default config so any caller that copy-pasted from an example ended up
    /// with the wrong `hsm_addr` in production. The constructor is now
    /// **renamed** (no `Default`-shaped `new()` exists any more), gated to
    /// tests + the insecure-mock feature, and explicitly named to surface its
    /// intent. Production embedders must call [`Self::with_config`] with an
    /// address from their own configuration source.
    pub fn with_localhost_addr_for_tests() -> Self {
        Self::with_config(VaultTransitConfig {
            hsm_addr: "https://localhost".to_string(),
            default_key_type: VaultKeyType::Aes256Gcm96,
            auto_rotate_period: None,
            min_decryption_version: default_min_decryption_version(),
            min_encryption_version: 0,
            deletion_allowed: false,
        })
    }

    /// Create a mock backend with the given configuration. The ACL defaults
    /// to [`DenyAllVaultAcl`] (audit finding H20); use [`Self::with_acl`] to
    /// swap it for a real policy or [`Self::permissive_for_tests`] for the
    /// legacy permissive behaviour.
    pub fn with_config(config: VaultTransitConfig) -> Self {
        crate::mock_guard::check("vault_plugin::MockVaultBackend");
        // Audit finding "Unused hsm_addr": surface the configured address at
        // construction time so misconfigurations are visible in logs even
        // before any request lands. The real `HsmAddrClient` impl is the
        // job of the production binary, but logging the address here is a
        // no-cost reminder that nothing actually connects.
        info!(
            hsm = %config.hsm_addr,
            "mock Vault backend created (would connect to hsm_addr)"
        );
        Self {
            keys: DashMap::new(),
            config,
            acl: std::sync::Arc::new(DenyAllVaultAcl),
            default_identity: VaultIdentity::anonymous(),
        }
    }

    /// Install the legacy permissive ACL **and** a non-anonymous default
    /// identity. Test-only helper (audit finding H20).
    #[cfg(any(test, feature = "permissive-for-tests"))]
    pub fn permissive_for_tests(self) -> Self {
        self.with_acl(std::sync::Arc::new(AllowAllVaultAcl))
            .with_default_identity(VaultIdentity::new("test-suite"))
    }

    /// Replace the backend's ACL implementation. Intended for production
    /// embedders and for the `vault_acl_denies_unauthorized_caller` test.
    pub fn with_acl(mut self, acl: std::sync::Arc<dyn VaultAcl>) -> Self {
        self.acl = acl;
        self
    }

    /// Override the default identity used by [`handle_request`]. Callers
    /// that do per-request auth should prefer [`Self::handle_request_as`].
    pub fn with_default_identity(mut self, identity: VaultIdentity) -> Self {
        self.default_identity = identity;
        self
    }

    /// Handle a request on behalf of an explicitly provided identity. This
    /// is the entry point embedders should use once they have authenticated
    /// the caller; the trait-dispatched [`VaultTransitBackend::handle_request`]
    /// falls back to `self.default_identity`.
    pub fn handle_request_as(
        &self,
        identity: &VaultIdentity,
        req: VaultTransitRequest,
    ) -> VaultResult<VaultTransitResponse> {
        self.dispatch(identity, req)
    }

    /// Classify a request into the coarse [`VaultOp`] used by [`VaultAcl`].
    fn op_for(req: &VaultTransitRequest) -> VaultOp {
        match req {
            VaultTransitRequest::ListKeys | VaultTransitRequest::ReadKey { .. } => VaultOp::Read,
            VaultTransitRequest::CreateKey { .. }
            | VaultTransitRequest::RotateKey { .. }
            | VaultTransitRequest::DeleteKey { .. } => VaultOp::Manage,
            VaultTransitRequest::Encrypt { .. }
            | VaultTransitRequest::Decrypt { .. }
            | VaultTransitRequest::Rewrap { .. }
            | VaultTransitRequest::DataKey { .. } => VaultOp::Crypto,
            VaultTransitRequest::Sign { .. } | VaultTransitRequest::Verify { .. } => VaultOp::Sign,
            VaultTransitRequest::Hmac { .. }
            | VaultTransitRequest::Hash { .. }
            | VaultTransitRequest::Random { .. } => VaultOp::Hash,
            VaultTransitRequest::ExportKey { .. } => VaultOp::Export,
        }
    }

    /// Extract the key name a request is scoped to, if any.
    fn key_name_of(req: &VaultTransitRequest) -> Option<&str> {
        match req {
            VaultTransitRequest::Encrypt { key_name, .. }
            | VaultTransitRequest::Decrypt { key_name, .. }
            | VaultTransitRequest::Rewrap { key_name, .. }
            | VaultTransitRequest::Sign { key_name, .. }
            | VaultTransitRequest::Verify { key_name, .. }
            | VaultTransitRequest::DataKey { key_name, .. }
            | VaultTransitRequest::Hmac { key_name, .. } => Some(key_name),
            VaultTransitRequest::CreateKey { name, .. }
            | VaultTransitRequest::RotateKey { name }
            | VaultTransitRequest::DeleteKey { name }
            | VaultTransitRequest::ReadKey { name }
            | VaultTransitRequest::ExportKey { name, .. } => Some(name),
            VaultTransitRequest::ListKeys
            | VaultTransitRequest::Hash { .. }
            | VaultTransitRequest::Random { .. } => None,
        }
    }

    fn validate_input(input: &str) -> VaultResult<()> {
        if input.len() > MAX_VAULT_INPUT_LEN {
            return Err(VaultError::InvalidRequest(format!(
                "input exceeds {MAX_VAULT_INPUT_LEN} bytes"
            )));
        }
        if !input
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='))
        {
            return Err(VaultError::InvalidRequest(
                "input is not valid base64".into(),
            ));
        }
        Ok(())
    }

    fn validate_hash_algorithm(alg: &str) -> VaultResult<()> {
        if matches!(alg, "sha2-224" | "sha2-256" | "sha2-384" | "sha2-512") {
            Ok(())
        } else {
            Err(VaultError::InvalidRequest(format!(
                "unsupported hash algorithm: {}",
                alg.escape_debug()
            )))
        }
    }

    /// HMAC under the per-version key, label-separated by `algorithm`.
    /// Delegates to the shared mock-crypto helper (audit finding DESIGN).
    fn hmac(secret: &[u8; 32], algorithm: &str, value: &[u8]) -> [u8; 32] {
        crate::mock_crypto::hmac_sign(secret, algorithm.as_bytes(), value)
    }

    /// Sign with the per-version `SIGN` sub-key (audit finding H18 spirit:
    /// keep signing material distinct from authentication / encryption
    /// material).
    fn sign_hmac(secret: &[u8; 32], label: &[u8], value: &[u8]) -> [u8; 32] {
        let sub = crate::mock_crypto::subkey(secret, b"SIGN");
        crate::mock_crypto::hmac_sign(&sub, label, value)
    }

    /// Authenticate a ciphertext blob with the dedicated `WRAP-AUTH`
    /// sub-key (audit finding H18).
    fn ct_tag(secret: &[u8; 32], label: &[u8], body: &[u8]) -> [u8; 32] {
        let sub = crate::mock_crypto::subkey(secret, b"WRAP-AUTH");
        crate::mock_crypto::hmac_sign(&sub, label, body)
    }

    /// Mock-only XOR stream cipher (not for production use — the vault
    /// transit mock is only reachable via `CRATON_HSM_ALLOW_MOCK=1`).
    ///
    /// Counter-overflow safety: the counter is a `u64` and uses
    /// `checked_add` (audit finding M, saturating counter); on overflow the
    /// function aborts with [`VaultError::Internal`] rather than silently
    /// reusing keystream blocks under a wrapped counter.
    fn xor_stream(secret: &[u8; 32], context: &[u8], data: &[u8]) -> VaultResult<Vec<u8>> {
        // Note: vault uses its own per-key context in stream_ctx, so we
        // re-derive a sub-key under the same `WRAP-ENC` label that the
        // other shims use (audit H18 spirit — keep confidentiality material
        // separate from the per-version master).
        let sub = crate::mock_crypto::subkey(secret, b"WRAP-ENC");
        crate::mock_crypto::xor_stream(&sub, context, data)
            .map_err(|()| VaultError::Internal("xor counter overflow".into()))
    }

    fn b64_encode(bytes: &[u8]) -> String {
        crate::mock_crypto::b64_encode(bytes)
    }

    fn b64_decode(input: &str) -> VaultResult<Vec<u8>> {
        crate::mock_crypto::b64_decode(input)
            .map_err(|()| VaultError::InvalidRequest("invalid base64".into()))
    }

    fn build_ciphertext(
        secret: &[u8; 32],
        context: &Option<Vec<u8>>,
        plaintext: &[u8],
        version: u32,
    ) -> VaultResult<String> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ctx = context.clone().unwrap_or_default();
        let mut blob = nonce.to_vec();
        // Use a fixed-width u64 length so the wire format does not change
        // between 32- and 64-bit hosts.
        let ctx_len_u64: u64 = ctx
            .len()
            .try_into()
            .map_err(|_| VaultError::Internal("context length exceeds u64".into()))?;
        blob.extend_from_slice(&ctx_len_u64.to_be_bytes());
        blob.extend_from_slice(&ctx);
        let stream_ctx = {
            let mut h = Sha256::new();
            h.update(&nonce);
            h.update(&ctx);
            h.finalize()
        };
        blob.extend_from_slice(&Self::xor_stream(secret, &stream_ctx, plaintext)?);
        // Audit H18: authenticate with the dedicated `WRAP-AUTH` sub-key
        // (separate from SIGN and from the per-version master).
        let tag = Self::ct_tag(secret, b"VAULT-TRANSIT", &blob);
        blob.extend_from_slice(&tag);
        Ok(format_vault_ciphertext(version, &Self::b64_encode(&blob)))
    }

    fn open_ciphertext(
        secret: &[u8; 32],
        context: &Option<Vec<u8>>,
        b64_blob: &str,
    ) -> VaultResult<Vec<u8>> {
        let blob = Self::b64_decode(b64_blob)
            .map_err(|_| VaultError::InvalidCiphertext("base64 decode failed".into()))?;
        if blob.len() < 12 + 8 + 32 {
            return Err(VaultError::InvalidCiphertext("blob too short".into()));
        }
        let tag_offset = blob.len() - 32;
        let body = &blob[..tag_offset];
        let tag = &blob[tag_offset..];
        let expected = Self::ct_tag(secret, b"VAULT-TRANSIT", body);
        let ok: bool = expected.as_slice().ct_eq(tag).into();
        if !ok {
            return Err(VaultError::AuthenticationFailed(
                "ciphertext tag mismatch".into(),
            ));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&body[..12]);
        // Audit M (saturating counter / overflow): use checked_add at the
        // boundary instead of relying on `as usize` cast wrap.
        let ctx_len_u64 = u64::from_be_bytes(body[12..20].try_into().unwrap());
        let ctx_len = usize::try_from(ctx_len_u64)
            .map_err(|_| VaultError::InvalidCiphertext("context length exceeds usize".into()))?;
        let ctx_end = 20usize
            .checked_add(ctx_len)
            .ok_or_else(|| VaultError::InvalidCiphertext("context length overflow".into()))?;
        if ctx_end > body.len() {
            return Err(VaultError::InvalidCiphertext(
                "context length out of bounds".into(),
            ));
        }
        let stored_ctx = &body[20..ctx_end];
        let provided_ctx = context.clone().unwrap_or_default();
        if stored_ctx != provided_ctx.as_slice() {
            return Err(VaultError::AuthenticationFailed("context mismatch".into()));
        }
        let stream_ctx = {
            let mut h = Sha256::new();
            h.update(&nonce);
            h.update(stored_ctx);
            h.finalize()
        };
        Self::xor_stream(secret, &stream_ctx, &body[ctx_end..])
    }
}

// Audit finding (foot-gun: hardcoded localhost leaks into binaries): there is
// intentionally no `impl Default for MockVaultBackend` any more. A `Default`
// impl would bake a hidden `hsm_addr` into every caller exactly like the old
// `new()` did. Embedders construct via [`MockVaultBackend::with_config`] with
// an address from their own configuration; tests use
// [`MockVaultBackend::with_localhost_addr_for_tests`].

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl VaultTransitBackend for MockVaultBackend {
    fn handle_request(&self, req: VaultTransitRequest) -> VaultResult<VaultTransitResponse> {
        let identity = self.default_identity.clone();
        self.dispatch(&identity, req)
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockVaultBackend {
    fn dispatch(
        &self,
        identity: &VaultIdentity,
        req: VaultTransitRequest,
    ) -> VaultResult<VaultTransitResponse> {
        // Per-key ACL (audit finding H): consult before any state is touched.
        // For unscoped requests (ListKeys, Hash, Random) we pass "" as the
        // object id so policies can still gate them at the class level.
        let op = Self::op_for(&req);
        let key_for_acl = Self::key_name_of(&req).unwrap_or("");
        if !self.acl.check(identity, key_for_acl, op) {
            return Err(VaultError::PermissionDenied(format!(
                "vault ACL denied {op:?} on {}",
                key_for_acl.escape_debug()
            )));
        }

        // Audit finding L4: validate every key-name-carrying request up-front
        // so the downstream arms never see a pathological name (too long,
        // NUL-injected, or leading-slash path-traversal).
        match &req {
            VaultTransitRequest::Encrypt { key_name, .. }
            | VaultTransitRequest::Decrypt { key_name, .. }
            | VaultTransitRequest::Rewrap { key_name, .. }
            | VaultTransitRequest::Sign { key_name, .. }
            | VaultTransitRequest::Verify { key_name, .. }
            | VaultTransitRequest::DataKey { key_name, .. }
            | VaultTransitRequest::Hmac { key_name, .. } => {
                validate_vault_key_name(key_name)?;
            }
            VaultTransitRequest::CreateKey { name, .. }
            | VaultTransitRequest::RotateKey { name }
            | VaultTransitRequest::DeleteKey { name }
            | VaultTransitRequest::ReadKey { name }
            | VaultTransitRequest::ExportKey { name, .. } => {
                validate_vault_key_name(name)?;
            }
            // The following requests don't take a key name.
            VaultTransitRequest::ListKeys
            | VaultTransitRequest::Hash { .. }
            | VaultTransitRequest::Random { .. } => {}
        }

        match req {
            VaultTransitRequest::CreateKey {
                name,
                key_type,
                exportable,
            } => {
                // `validate_vault_key_name` above already enforced non-empty,
                // bounded length, no NUL, no leading slash.
                use dashmap::mapref::entry::Entry;
                match self.keys.entry(name.clone()) {
                    Entry::Occupied(_) => Err(VaultError::KeyExists(name)),
                    Entry::Vacant(v) => {
                        v.insert(MockKeyEntry::new(key_type, exportable));
                        info!(name = %name, kty = key_type.wire_name(), "CreateKey");
                        Ok(VaultTransitResponse::new()
                            .with("name", Value::String(name))
                            .with("type", Value::String(key_type.wire_name().to_string()))
                            .with("exportable", Value::Bool(exportable))
                            .with("latest_version", Value::from(1u32)))
                    }
                }
            }
            VaultTransitRequest::RotateKey { name } => {
                let entry = self
                    .keys
                    .get(&name)
                    .ok_or_else(|| VaultError::KeyNotFound(name.clone()))?;
                let new_ver = entry.rotate();
                info!(name = %name, latest_version = new_ver, "RotateKey");
                Ok(VaultTransitResponse::new()
                    .with("name", Value::String(name))
                    .with("latest_version", Value::from(new_ver)))
            }
            VaultTransitRequest::DeleteKey { name } => {
                if !self.config.deletion_allowed {
                    return Err(VaultError::PermissionDenied(
                        "key deletion is not allowed by policy".into(),
                    ));
                }
                self.keys
                    .remove(&name)
                    .ok_or_else(|| VaultError::KeyNotFound(name.clone()))?;
                info!(name = %name, "DeleteKey");
                Ok(VaultTransitResponse::new().with("deleted", Value::String(name)))
            }
            VaultTransitRequest::ListKeys => {
                let mut names: Vec<String> = self.keys.iter().map(|e| e.key().clone()).collect();
                names.sort();
                Ok(VaultTransitResponse::new().with(
                    "keys",
                    Value::Array(names.into_iter().map(Value::String).collect()),
                ))
            }
            VaultTransitRequest::ReadKey { name } => {
                let entry = self
                    .keys
                    .get(&name)
                    .ok_or_else(|| VaultError::KeyNotFound(name.clone()))?;
                Ok(VaultTransitResponse::new()
                    .with("name", Value::String(name))
                    .with(
                        "type",
                        Value::String(entry.key_type.wire_name().to_string()),
                    )
                    .with("exportable", Value::Bool(entry.exportable))
                    .with("latest_version", Value::from(entry.latest()))
                    .with(
                        "min_decryption_version",
                        Value::from(self.config.min_decryption_version),
                    )
                    .with(
                        "min_encryption_version",
                        Value::from(self.config.min_encryption_version),
                    ))
            }
            VaultTransitRequest::ExportKey { name, version } => {
                let entry = self
                    .keys
                    .get(&name)
                    .ok_or_else(|| VaultError::KeyNotFound(name.clone()))?;
                if !entry.exportable {
                    return Err(VaultError::PermissionDenied(format!(
                        "key {name} is not exportable"
                    )));
                }
                let v = version.unwrap_or_else(|| entry.latest());
                let bytes = entry
                    .material(v)
                    .ok_or_else(|| VaultError::InvalidRequest(format!("no version {v}")))?;
                let mut versions_map = serde_json::Map::new();
                versions_map.insert(v.to_string(), Value::String(Self::b64_encode(&bytes)));
                Ok(VaultTransitResponse::new()
                    .with("name", Value::String(name))
                    .with("keys", Value::Object(versions_map)))
            }
            VaultTransitRequest::Encrypt {
                key_name,
                plaintext_b64,
                context,
            } => {
                Self::validate_input(&plaintext_b64)?;
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                if !entry.key_type.supports_encrypt() {
                    return Err(VaultError::InvalidRequest(format!(
                        "{} does not support encryption",
                        entry.key_type.wire_name()
                    )));
                }
                // Audit foot-gun (AEAD-shaped name silently downgraded to
                // XOR): the only symmetric key types the mock supports are
                // `aes256-gcm96` / `aes128-gcm96`, but the underlying mock
                // primitive is XOR-stream + HMAC tag, NOT real AES-GCM. We
                // cannot refuse the request here without gutting the entire
                // mock test surface, so we surface a one-shot warning on the
                // first call instead. The runtime mock-gate (see
                // `crate::mock_guard::check`) already prevents this code path
                // from running in a production binary, so the warning is
                // belt-and-suspenders for accidental dev-band misuse.
                if matches!(
                    entry.key_type,
                    VaultKeyType::Aes256Gcm96 | VaultKeyType::Aes128Gcm96
                ) {
                    static WARNED: std::sync::Once = std::sync::Once::new();
                    WARNED.call_once(|| {
                        tracing::warn!(
                            key_type = %entry.key_type.wire_name(),
                            "mock Vault Encrypt: key type names AES-GCM but the mock \
                             implementation is XOR-stream + HMAC tag (non-AEAD). \
                             Do NOT rely on this for confidentiality."
                        );
                    });
                }
                let ver = entry.latest();
                if self.config.min_encryption_version > 0
                    && ver < self.config.min_encryption_version
                {
                    return Err(VaultError::PermissionDenied(format!(
                        "key version {ver} below minimum encryption version {}",
                        self.config.min_encryption_version
                    )));
                }
                let secret = entry
                    .material(ver)
                    .ok_or_else(|| VaultError::Internal("missing key material".into()))?;
                let plaintext = Self::b64_decode(&plaintext_b64)?;
                let ct = Self::build_ciphertext(&secret, &context, &plaintext, ver)?;
                debug!(name = %key_name, version = ver, "Encrypt");
                Ok(VaultTransitResponse::new().with("ciphertext", Value::String(ct)))
            }
            VaultTransitRequest::Decrypt {
                key_name,
                ciphertext,
                context,
            } => {
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                let (version, payload) = parse_vault_ciphertext(&ciphertext)?;
                if version < self.config.min_decryption_version {
                    return Err(VaultError::PermissionDenied(format!(
                        "ciphertext version {version} below minimum decryption version {}",
                        self.config.min_decryption_version
                    )));
                }
                let secret = entry.material(version).ok_or_else(|| {
                    VaultError::InvalidCiphertext(format!("no key version {version}"))
                })?;
                let plaintext = Self::open_ciphertext(&secret, &context, &payload)?;
                debug!(name = %key_name, version, "Decrypt");
                Ok(VaultTransitResponse::new()
                    .with("plaintext", Value::String(Self::b64_encode(&plaintext))))
            }
            VaultTransitRequest::Rewrap {
                key_name,
                ciphertext,
                context,
            } => {
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                let (version, payload) = parse_vault_ciphertext(&ciphertext)?;
                let old_secret = entry.material(version).ok_or_else(|| {
                    VaultError::InvalidCiphertext(format!("no key version {version}"))
                })?;
                let plaintext = Self::open_ciphertext(&old_secret, &context, &payload)?;
                let new_ver = entry.latest();
                let new_secret = entry
                    .material(new_ver)
                    .ok_or_else(|| VaultError::Internal("missing latest material".into()))?;
                let new_ct = Self::build_ciphertext(&new_secret, &context, &plaintext, new_ver)?;
                info!(name = %key_name, from = version, to = new_ver, "Rewrap");
                Ok(VaultTransitResponse::new().with("ciphertext", Value::String(new_ct)))
            }
            VaultTransitRequest::Sign {
                key_name,
                input_b64,
                hash_algorithm,
            } => {
                Self::validate_input(&input_b64)?;
                Self::validate_hash_algorithm(&hash_algorithm)?;
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                if !entry.key_type.supports_sign() {
                    return Err(VaultError::InvalidRequest(format!(
                        "{} does not support signing",
                        entry.key_type.wire_name()
                    )));
                }
                let ver = entry.latest();
                let secret = entry
                    .material(ver)
                    .ok_or_else(|| VaultError::Internal("missing key material".into()))?;
                let input = Self::b64_decode(&input_b64)?;
                let mut buf = hash_algorithm.as_bytes().to_vec();
                buf.push(0);
                buf.extend_from_slice(&input);
                let raw = Self::sign_hmac(&secret, b"SIGN", &buf);
                let sig = format!("vault:v{ver}:{}", Self::b64_encode(&raw));
                debug!(name = %key_name, "Sign");
                Ok(VaultTransitResponse::new().with("signature", Value::String(sig)))
            }
            VaultTransitRequest::Verify {
                key_name,
                input_b64,
                signature,
                hash_algorithm,
            } => {
                Self::validate_input(&input_b64)?;
                Self::validate_hash_algorithm(&hash_algorithm)?;
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                let (version, payload) = parse_vault_ciphertext(&signature).map_err(|_| {
                    VaultError::InvalidRequest("signature is not vault format".into())
                })?;
                let secret = entry.material(version).ok_or_else(|| {
                    VaultError::InvalidRequest(format!("no key version {version}"))
                })?;
                let input = Self::b64_decode(&input_b64)?;
                let mut buf = hash_algorithm.as_bytes().to_vec();
                buf.push(0);
                buf.extend_from_slice(&input);
                let expected = Self::sign_hmac(&secret, b"SIGN", &buf);
                let provided = Self::b64_decode(&payload)?;
                let valid: bool = expected.as_slice().ct_eq(&provided).into();
                if !valid {
                    warn!(name = %key_name, "Verify mismatch");
                }
                Ok(VaultTransitResponse::new().with("valid", Value::Bool(valid)))
            }
            VaultTransitRequest::DataKey {
                key_name,
                plaintext,
                bits,
            } => {
                if !matches!(bits, 128 | 256 | 512) {
                    return Err(VaultError::InvalidRequest(
                        "bits must be 128, 256, or 512".into(),
                    ));
                }
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                if !entry.key_type.supports_encrypt() {
                    return Err(VaultError::InvalidRequest(format!(
                        "{} does not support encryption",
                        entry.key_type.wire_name()
                    )));
                }
                let ver = entry.latest();
                let secret = entry
                    .material(ver)
                    .ok_or_else(|| VaultError::Internal("missing material".into()))?;
                let mut data_key = vec![0u8; (bits / 8) as usize];
                rand::thread_rng().fill_bytes(&mut data_key);
                let ct = Self::build_ciphertext(&secret, &None, &data_key, ver)?;
                let mut resp = VaultTransitResponse::new().with("ciphertext", Value::String(ct));
                if plaintext {
                    resp = resp.with("plaintext", Value::String(Self::b64_encode(&data_key)));
                }
                Ok(resp)
            }
            VaultTransitRequest::Hash {
                algorithm,
                input_b64,
            } => {
                Self::validate_input(&input_b64)?;
                Self::validate_hash_algorithm(&algorithm)?;
                let input = Self::b64_decode(&input_b64)?;
                // Audit finding: the previous implementation returned a
                // SHA-256 tagged with the algorithm name for `sha2-224 / 384
                // / 512`, which **looked** legitimate but was structurally
                // wrong (digest length doesn't even match the requested
                // algorithm). Compute the real digest for each variant — the
                // `sha2` crate already vendors all four.
                let digest: Vec<u8> = match algorithm.as_str() {
                    "sha2-224" => {
                        let mut h = Sha224::new();
                        h.update(&input);
                        h.finalize().to_vec()
                    }
                    "sha2-256" => {
                        let mut h = Sha256::new();
                        h.update(&input);
                        h.finalize().to_vec()
                    }
                    "sha2-384" => {
                        let mut h = Sha384::new();
                        h.update(&input);
                        h.finalize().to_vec()
                    }
                    "sha2-512" => {
                        let mut h = Sha512::new();
                        h.update(&input);
                        h.finalize().to_vec()
                    }
                    // `validate_hash_algorithm` already rejects anything
                    // else; unreachable but kept for fail-closed safety.
                    other => {
                        return Err(VaultError::InvalidRequest(format!(
                            "unsupported hash algorithm: {}",
                            other.escape_debug()
                        )));
                    }
                };
                Ok(VaultTransitResponse::new()
                    .with("sum", Value::String(Self::b64_encode(&digest))))
            }
            VaultTransitRequest::Hmac {
                key_name,
                input_b64,
                algorithm,
            } => {
                Self::validate_input(&input_b64)?;
                Self::validate_hash_algorithm(&algorithm)?;
                let entry = self
                    .keys
                    .get(&key_name)
                    .ok_or_else(|| VaultError::KeyNotFound(key_name.clone()))?;
                let ver = entry.latest();
                let secret = entry
                    .material(ver)
                    .ok_or_else(|| VaultError::Internal("missing material".into()))?;
                let input = Self::b64_decode(&input_b64)?;
                let mac = Self::hmac(&secret, &algorithm, &input);
                Ok(VaultTransitResponse::new().with(
                    "hmac",
                    Value::String(format!("vault:v{ver}:{}", Self::b64_encode(&mac))),
                ))
            }
            VaultTransitRequest::Random { bytes } => {
                if bytes > MAX_VAULT_RANDOM_BYTES {
                    return Err(VaultError::InvalidRequest(format!(
                        "bytes exceeds {MAX_VAULT_RANDOM_BYTES}"
                    )));
                }
                let mut out = vec![0u8; bytes];
                rand::thread_rng().fill_bytes(&mut out);
                Ok(VaultTransitResponse::new()
                    .with("random_bytes", Value::String(Self::b64_encode(&out))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_backend() -> MockVaultBackend {
        crate::_enable_mock_for_tests();
        // Audit H20: default ACL is now deny-all; flip the test suite over
        // to the permissive helper that mirrors legacy behaviour.
        // Audit (foot-gun): there is no `MockVaultBackend::new()` any more —
        // use the explicit test-only localhost constructor.
        MockVaultBackend::with_localhost_addr_for_tests().permissive_for_tests()
    }

    /// ACL that denies everything. Used by
    /// `vault_acl_denies_unauthorized_caller`.
    struct DenyAllAcl;
    impl VaultAcl for DenyAllAcl {
        fn check(&self, _: &VaultIdentity, _: &str, _: VaultOp) -> bool {
            false
        }
    }

    #[test]
    fn vault_acl_denies_unauthorized_caller() {
        crate::_enable_mock_for_tests();
        let backend =
            MockVaultBackend::with_localhost_addr_for_tests().with_acl(Arc::new(DenyAllAcl));
        let err = backend
            .handle_request_as(
                &VaultIdentity::new("mallory"),
                VaultTransitRequest::CreateKey {
                    name: "forbidden".into(),
                    key_type: VaultKeyType::Aes256Gcm96,
                    exportable: false,
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, VaultError::PermissionDenied(_)),
            "expected PermissionDenied, got {err:?}"
        );
        // Verify the key was never created — the ACL must short-circuit
        // before any state is mutated.
        let list =
            backend.handle_request_as(&VaultIdentity::new("root"), VaultTransitRequest::ListKeys);
        // root's Read is also denied — sanity-check that too.
        assert!(matches!(list.unwrap_err(), VaultError::PermissionDenied(_)));
    }

    #[test]
    fn create_key() {
        let backend = make_backend();
        let resp = backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "k".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        assert_eq!(resp.data["name"], "k");
        assert_eq!(resp.data["type"], "aes256-gcm96");
    }

    #[test]
    fn create_duplicate_key() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "dup".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "dup".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::KeyExists(_)));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "ed".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let enc = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "ed".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap();
        let ct = enc.data["ciphertext"].as_str().unwrap().to_string();
        assert!(ct.starts_with("vault:v1:"));
        let dec = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "ed".into(),
                ciphertext: ct,
                context: None,
            })
            .unwrap();
        assert_eq!(dec.data["plaintext"], "aGVsbG8=");
    }

    #[test]
    fn convergent_context_required_for_decrypt() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "cv".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let enc = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "cv".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: Some(b"app=billing".to_vec()),
            })
            .unwrap();
        let ct = enc.data["ciphertext"].as_str().unwrap().to_string();
        // Wrong context fails.
        let err = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "cv".into(),
                ciphertext: ct.clone(),
                context: Some(b"app=other".to_vec()),
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::AuthenticationFailed(_)));
        // No context fails.
        let err = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "cv".into(),
                ciphertext: ct.clone(),
                context: None,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::AuthenticationFailed(_)));
        // Correct context succeeds.
        let dec = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "cv".into(),
                ciphertext: ct,
                context: Some(b"app=billing".to_vec()),
            })
            .unwrap();
        assert_eq!(dec.data["plaintext"], "aGVsbG8=");
    }

    #[test]
    fn key_rotation_version_bump_and_rewrap() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "rot".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let enc1 = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "rot".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap();
        let ct1 = enc1.data["ciphertext"].as_str().unwrap().to_string();
        backend
            .handle_request(VaultTransitRequest::RotateKey { name: "rot".into() })
            .unwrap();
        // Old ciphertext still decrypts.
        let dec_old = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "rot".into(),
                ciphertext: ct1.clone(),
                context: None,
            })
            .unwrap();
        assert_eq!(dec_old.data["plaintext"], "aGVsbG8=");
        // Rewrap to v2.
        let rewrap = backend
            .handle_request(VaultTransitRequest::Rewrap {
                key_name: "rot".into(),
                ciphertext: ct1,
                context: None,
            })
            .unwrap();
        let ct2 = rewrap.data["ciphertext"].as_str().unwrap();
        assert!(ct2.starts_with("vault:v2:"));
    }

    #[test]
    fn rotate_nonexistent_key() {
        let backend = make_backend();
        let err = backend
            .handle_request(VaultTransitRequest::RotateKey {
                name: "nope".into(),
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::KeyNotFound(_)));
    }

    #[test]
    fn delete_key_requires_policy() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "del".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::DeleteKey { name: "del".into() })
            .unwrap_err();
        assert!(matches!(err, VaultError::PermissionDenied(_)));

        let cfg = VaultTransitConfig {
            hsm_addr: "x".into(),
            default_key_type: VaultKeyType::Aes256Gcm96,
            auto_rotate_period: None,
            min_decryption_version: 1,
            min_encryption_version: 0,
            deletion_allowed: true,
        };
        let backend = MockVaultBackend::with_config(cfg).permissive_for_tests();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "del".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        backend
            .handle_request(VaultTransitRequest::DeleteKey { name: "del".into() })
            .unwrap();
    }

    #[test]
    fn list_and_read_key() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "a".into(),
                key_type: VaultKeyType::EcdsaP256,
                exportable: true,
            })
            .unwrap();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "b".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let list = backend
            .handle_request(VaultTransitRequest::ListKeys)
            .unwrap();
        let names = list.data["keys"].as_array().unwrap();
        assert_eq!(names.len(), 2);
        let read = backend
            .handle_request(VaultTransitRequest::ReadKey { name: "a".into() })
            .unwrap();
        assert_eq!(read.data["type"], "ecdsa-p256");
        assert_eq!(read.data["exportable"], true);
    }

    #[test]
    fn export_key_requires_exportable_flag() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "ne".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::ExportKey {
                name: "ne".into(),
                version: None,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::PermissionDenied(_)));

        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "ex".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: true,
            })
            .unwrap();
        let resp = backend
            .handle_request(VaultTransitRequest::ExportKey {
                name: "ex".into(),
                version: None,
            })
            .unwrap();
        assert_eq!(resp.data["name"], "ex");
        assert!(resp.data["keys"]["1"].as_str().is_some());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "sk".into(),
                key_type: VaultKeyType::EcdsaP256,
                exportable: false,
            })
            .unwrap();
        let sig = backend
            .handle_request(VaultTransitRequest::Sign {
                key_name: "sk".into(),
                input_b64: "bXNn".into(),
                hash_algorithm: "sha2-256".into(),
            })
            .unwrap();
        let s = sig.data["signature"].as_str().unwrap().to_string();
        let verify = backend
            .handle_request(VaultTransitRequest::Verify {
                key_name: "sk".into(),
                input_b64: "bXNn".into(),
                signature: s,
                hash_algorithm: "sha2-256".into(),
            })
            .unwrap();
        assert_eq!(verify.data["valid"], true);
    }

    #[test]
    fn verify_bad_signature() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "sk2".into(),
                key_type: VaultKeyType::EcdsaP384,
                exportable: false,
            })
            .unwrap();
        let verify = backend
            .handle_request(VaultTransitRequest::Verify {
                key_name: "sk2".into(),
                input_b64: "bXNn".into(),
                signature: "vault:v1:AAAA".into(),
                hash_algorithm: "sha2-256".into(),
            })
            .unwrap();
        assert_eq!(verify.data["valid"], false);
    }

    #[test]
    fn sign_unsupported_kty() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "aes".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::Sign {
                key_name: "aes".into(),
                input_b64: "bXNn".into(),
                hash_algorithm: "sha2-256".into(),
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn sign_invalid_hash_algorithm() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "sk3".into(),
                key_type: VaultKeyType::EcdsaP256,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::Sign {
                key_name: "sk3".into(),
                input_b64: "bXNn".into(),
                hash_algorithm: "made-up".into(),
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn data_key_returns_ciphertext_and_optional_plaintext() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "kek".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let resp = backend
            .handle_request(VaultTransitRequest::DataKey {
                key_name: "kek".into(),
                plaintext: true,
                bits: 256,
            })
            .unwrap();
        assert!(resp.data["ciphertext"]
            .as_str()
            .unwrap()
            .starts_with("vault:v1:"));
        assert!(resp.data.contains_key("plaintext"));
    }

    #[test]
    fn data_key_invalid_bits() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "kek2".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::DataKey {
                key_name: "kek2".into(),
                plaintext: false,
                bits: 100,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn hash_returns_sha256() {
        let backend = make_backend();
        let resp = backend
            .handle_request(VaultTransitRequest::Hash {
                algorithm: "sha2-256".into(),
                input_b64: "aGVsbG8=".into(),
            })
            .unwrap();
        let sum = resp.data["sum"].as_str().unwrap();
        let bytes = MockVaultBackend::b64_decode(sum).unwrap();
        // SHA-256 of "hello"
        let expected =
            hex_to_bytes("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(bytes, expected);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_request() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "h".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let resp = backend
            .handle_request(VaultTransitRequest::Hmac {
                key_name: "h".into(),
                input_b64: "aGVsbG8=".into(),
                algorithm: "sha2-256".into(),
            })
            .unwrap();
        assert!(resp.data["hmac"].as_str().unwrap().starts_with("vault:v1:"));
    }

    #[test]
    fn random_returns_n_bytes() {
        let backend = make_backend();
        let resp = backend
            .handle_request(VaultTransitRequest::Random { bytes: 16 })
            .unwrap();
        let s = resp.data["random_bytes"].as_str().unwrap();
        let bytes = MockVaultBackend::b64_decode(s).unwrap();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn random_oversized_rejected() {
        let backend = make_backend();
        let err = backend
            .handle_request(VaultTransitRequest::Random {
                bytes: MAX_VAULT_RANDOM_BYTES + 1,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn parse_vault_ciphertext_valid() {
        let (ver, payload) = parse_vault_ciphertext("vault:v3:YWJj").unwrap();
        assert_eq!(ver, 3);
        assert_eq!(payload, "YWJj");
    }

    #[test]
    fn parse_vault_ciphertext_invalid_prefix() {
        assert!(matches!(
            parse_vault_ciphertext("notvalid:v1:abc").unwrap_err(),
            VaultError::InvalidCiphertext(_)
        ));
    }

    #[test]
    fn parse_vault_ciphertext_no_version_prefix() {
        assert!(matches!(
            parse_vault_ciphertext("vault:1:abc").unwrap_err(),
            VaultError::InvalidCiphertext(_)
        ));
    }

    #[test]
    fn format_vault_ciphertext_basic() {
        assert_eq!(format_vault_ciphertext(5, "c2VjcmV0"), "vault:v5:c2VjcmV0");
    }

    #[test]
    fn config_serialization() {
        let cfg = VaultTransitConfig {
            hsm_addr: "http://localhost:8200".into(),
            default_key_type: VaultKeyType::Aes256Gcm96,
            auto_rotate_period: Some(86400),
            min_decryption_version: 1,
            min_encryption_version: 0,
            deletion_allowed: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: VaultTransitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hsm_addr, "http://localhost:8200");
    }

    #[test]
    fn decrypt_below_min_decryption_version() {
        let cfg = VaultTransitConfig {
            hsm_addr: "x".into(),
            default_key_type: VaultKeyType::Aes256Gcm96,
            auto_rotate_period: None,
            min_decryption_version: 3,
            min_encryption_version: 0,
            deletion_allowed: false,
        };
        let backend = MockVaultBackend::with_config(cfg).permissive_for_tests();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "v".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        // Rotate to version 3 so we have a real v3 to encrypt under.
        backend
            .handle_request(VaultTransitRequest::RotateKey { name: "v".into() })
            .unwrap();
        backend
            .handle_request(VaultTransitRequest::RotateKey { name: "v".into() })
            .unwrap();
        let enc = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "v".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap();
        let ct = enc.data["ciphertext"].as_str().unwrap().to_string();
        // Forge a v1 ciphertext header on top of the v3 payload to test the
        // version policy without producing real v1 material.
        let payload = ct.strip_prefix("vault:v3:").unwrap();
        let v1 = format!("vault:v1:{payload}");
        let err = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "v".into(),
                ciphertext: v1,
                context: None,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::PermissionDenied(_)));
    }

    #[test]
    fn encrypt_below_min_encryption_version() {
        let cfg = VaultTransitConfig {
            hsm_addr: "x".into(),
            default_key_type: VaultKeyType::Aes256Gcm96,
            auto_rotate_period: None,
            min_decryption_version: 1,
            min_encryption_version: 3,
            deletion_allowed: false,
        };
        let backend = MockVaultBackend::with_config(cfg).permissive_for_tests();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "e".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let err = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "e".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::PermissionDenied(_)));
        backend
            .handle_request(VaultTransitRequest::RotateKey { name: "e".into() })
            .unwrap();
        backend
            .handle_request(VaultTransitRequest::RotateKey { name: "e".into() })
            .unwrap();
        let enc = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "e".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap();
        assert!(enc.data["ciphertext"]
            .as_str()
            .unwrap()
            .starts_with("vault:v3:"));
    }

    #[test]
    fn ciphertext_oversized_rejected() {
        let big = format!("vault:v1:{}", "A".repeat(MAX_VAULT_CIPHERTEXT_LEN));
        assert!(matches!(
            parse_vault_ciphertext(&big).unwrap_err(),
            VaultError::InvalidCiphertext(_)
        ));
    }

    #[test]
    fn ciphertext_invalid_base64_chars_rejected() {
        assert!(matches!(
            parse_vault_ciphertext("vault:v1:abc def").unwrap_err(),
            VaultError::InvalidCiphertext(_)
        ));
        assert!(matches!(
            parse_vault_ciphertext("vault:v1:abc\x00def").unwrap_err(),
            VaultError::InvalidCiphertext(_)
        ));
    }

    #[test]
    fn ciphertext_valid_base64_chars_accepted() {
        let ct = parse_vault_ciphertext("vault:v2:aGVsbG8+/=").unwrap();
        assert_eq!(ct.0, 2);
        assert_eq!(ct.1, "aGVsbG8+/=");
    }

    #[test]
    fn config_defaults() {
        let json = r#"{"hsm_addr":"http://hsm","default_key_type":"Aes256Gcm96"}"#;
        let cfg: VaultTransitConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.min_decryption_version, 1);
    }

    #[test]
    fn error_display_escapes_control_chars() {
        let err = VaultError::KeyNotFound("evil\nname".into());
        assert!(!err.to_string().contains('\n'));
    }

    // Audit finding L4: key-name validation.

    #[test]
    fn key_name_too_long_rejected() {
        let backend = make_backend();
        let long = "a".repeat(MAX_VAULT_KEY_NAME_LEN + 1);
        let err = backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: long,
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn key_name_with_nul_rejected() {
        let backend = make_backend();
        let err = backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "evil\0name".to_string(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn key_name_with_leading_slash_rejected() {
        let backend = make_backend();
        let err = backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "/etc/passwd".to_string(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn key_name_validation_applies_to_encrypt() {
        let backend = make_backend();
        let err = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "/bad".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn key_name_validation_applies_to_rotate_and_read() {
        let backend = make_backend();
        let err = backend
            .handle_request(VaultTransitRequest::RotateKey {
                name: "a\0b".into(),
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
        let err = backend
            .handle_request(VaultTransitRequest::ReadKey {
                name: "a".repeat(MAX_VAULT_KEY_NAME_LEN + 1),
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidRequest(_)));
    }

    #[test]
    fn key_name_boundary_accepted() {
        let backend = make_backend();
        let exactly_max = "a".repeat(MAX_VAULT_KEY_NAME_LEN);
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: exactly_max,
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
    }

    #[test]
    fn ciphertext_tag_tamper_detected() {
        let backend = make_backend();
        backend
            .handle_request(VaultTransitRequest::CreateKey {
                name: "t".into(),
                key_type: VaultKeyType::Aes256Gcm96,
                exportable: false,
            })
            .unwrap();
        let enc = backend
            .handle_request(VaultTransitRequest::Encrypt {
                key_name: "t".into(),
                plaintext_b64: "aGVsbG8=".into(),
                context: None,
            })
            .unwrap();
        let mut ct = enc.data["ciphertext"].as_str().unwrap().to_string();
        // Tweak the last char of the base64 payload to invalidate the tag.
        let last = ct.pop().unwrap();
        let tweaked = if last == 'A' { 'B' } else { 'A' };
        ct.push(tweaked);
        let err = backend
            .handle_request(VaultTransitRequest::Decrypt {
                key_name: "t".into(),
                ciphertext: ct,
                context: None,
            })
            .unwrap_err();
        assert!(matches!(err, VaultError::AuthenticationFailed(_)));
    }
}
