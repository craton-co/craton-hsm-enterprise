// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! AWS CloudHSM API compatibility shim for Craton HSM.
//!
//! Maps AWS CloudHSM API operations to local Craton HSM operations,
//! enabling workloads written for AWS CloudHSM to run against Craton HSM.
//!
//! The mock implementation in this module uses HMAC-SHA256 over per-key
//! random material for both signing and (XOR-stream) encryption. This is
//! still **not production grade** — there is no AEAD, no real RSA/ECDSA, and
//! key material is held in process memory — but it is at least unforgeable
//! by parties who do not hold the key.
//!
//! # Release-build protection (audit findings M3/M4/M5)
//!
//! The mock is gated behind the `mock-insecure-do-not-ship` Cargo feature and
//! behind a runtime `CRATON_HSM_ALLOW_MOCK=1` env var enforced by
//! [`crate::mock_guard::check`]. In addition, **release builds** require a
//! second env var, `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1`, before a mock
//! backend will construct. Mock key material is also capped at
//! [`crate::mock_guard::MAX_MOCK_KEY_BYTES`] (32 bytes) so the blast radius of
//! an accidental production deployment stays bounded to what the fake AEAD
//! can stretch.

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
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors from the AWS HSM shim.
#[derive(Debug, Clone)]
pub enum AwsHsmError {
    /// The requested HSM was not found.
    HsmNotFound(String),
    /// The requested key was not found.
    KeyNotFound(String),
    /// The HSM already exists.
    HsmAlreadyExists(String),
    /// The key already exists with the given label.
    KeyAlreadyExists(String),
    /// Invalid parameter.
    InvalidParameter(String),
    /// Unsupported mechanism.
    UnsupportedMechanism(String),
    /// Caller's identity is recognised but the policy denied the operation.
    /// Distinct from `InvalidParameter` so calling code can tell an auth
    /// failure from a validation failure (audit finding M, ACL error class).
    PermissionDenied(String),
    /// Internal error.
    Internal(String),
}

impl fmt::Display for AwsHsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use `escape_debug` so attacker-controlled labels can never inject
        // newlines or terminal control sequences into log sinks.
        match self {
            AwsHsmError::HsmNotFound(id) => write!(f, "HSM not found: {}", id.escape_debug()),
            AwsHsmError::KeyNotFound(id) => write!(f, "key not found: {}", id.escape_debug()),
            AwsHsmError::HsmAlreadyExists(id) => {
                write!(f, "HSM already exists: {}", id.escape_debug())
            }
            AwsHsmError::KeyAlreadyExists(id) => {
                write!(f, "key already exists: {}", id.escape_debug())
            }
            AwsHsmError::InvalidParameter(msg) => {
                write!(f, "invalid parameter: {}", msg.escape_debug())
            }
            AwsHsmError::UnsupportedMechanism(msg) => {
                write!(f, "unsupported mechanism: {}", msg.escape_debug())
            }
            AwsHsmError::PermissionDenied(msg) => {
                write!(f, "permission denied: {}", msg.escape_debug())
            }
            AwsHsmError::Internal(msg) => write!(f, "internal error: {}", msg.escape_debug()),
        }
    }
}

impl std::error::Error for AwsHsmError {}

/// Result alias for AWS HSM shim operations. Renamed from `Result` so
/// downstream `use craton_hsm_cloud::aws_shim::*;` does not collide with
/// `std::result::Result`.
pub type AwsResult<T> = std::result::Result<T, AwsHsmError>;

/// Configuration for the AWS CloudHSM compatibility shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsHsmConfig {
    /// Cluster identifier.
    pub cluster_id: String,
    /// AWS region.
    pub region: Cow<'static, str>,
    /// HSM instance type.
    #[serde(default = "default_hsm_type")]
    pub hsm_type: Cow<'static, str>,
}

fn default_hsm_type() -> Cow<'static, str> {
    Cow::Borrowed("craton-hsm.medium")
}

/// Mechanisms accepted by the shim. Real AWS CloudHSM advertises a much
/// larger set; this enum covers the subset implemented by the mock backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AwsMechanism {
    /// SHA-256 with RSA PKCS#1 v1.5.
    Sha256RsaPkcs,
    /// SHA-384 with RSA PKCS#1 v1.5.
    Sha384RsaPkcs,
    /// SHA-256 with ECDSA.
    Ecdsa,
    /// AES-GCM (used here as XOR-stream — see module docs).
    AesGcm,
    /// AES key wrap (RFC 3394).
    AesKeyWrap,
}

impl AwsMechanism {
    /// Wire-format string used by the AWS CloudHSM API.
    pub fn wire_name(self) -> &'static str {
        match self {
            AwsMechanism::Sha256RsaPkcs => "SHA256_RSA_PKCS",
            AwsMechanism::Sha384RsaPkcs => "SHA384_RSA_PKCS",
            AwsMechanism::Ecdsa => "ECDSA",
            AwsMechanism::AesGcm => "AES_GCM",
            AwsMechanism::AesKeyWrap => "AES_KEY_WRAP",
        }
    }

    /// Parse a wire-format mechanism string.
    pub fn from_wire(s: &str) -> AwsResult<Self> {
        Ok(match s {
            "SHA256_RSA_PKCS" => AwsMechanism::Sha256RsaPkcs,
            "SHA384_RSA_PKCS" => AwsMechanism::Sha384RsaPkcs,
            "ECDSA" => AwsMechanism::Ecdsa,
            "AES_GCM" => AwsMechanism::AesGcm,
            "AES_KEY_WRAP" => AwsMechanism::AesKeyWrap,
            other => return Err(AwsHsmError::UnsupportedMechanism(other.to_string())),
        })
    }
}

/// AWS CloudHSM API operations mapped to Craton HSM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AwsHsmOperation {
    /// Initialize the cluster (mock: no-op).
    InitializeCluster,
    /// Create a new HSM instance.
    CreateHsm {
        /// Availability zone for the HSM.
        availability_zone: String,
    },
    /// Delete an existing HSM.
    DeleteHsm {
        /// Identifier of the HSM to delete.
        hsm_id: String,
    },
    /// List HSMs in the cluster.
    ListHsms,
    /// Describe all clusters.
    DescribeClusters,
    /// Create a cryptographic key.
    CreateKey {
        /// Key type (e.g. "AES", "RSA").
        key_type: String,
        /// Human-readable label for the key.
        label: String,
        /// Optional explicit HSM to bind the key to.
        hsm_id: Option<String>,
    },
    /// Delete a cryptographic key.
    DeleteKey {
        /// Identifier of the key to delete.
        key_id: String,
    },
    /// List all keys in the cluster.
    ListKeys,
    /// Retrieve attributes for a key (label, type, hsm_id).
    GetKeyAttributes {
        /// Identifier of the key to inspect.
        key_id: String,
    },
    /// Sign a message using a key.
    Sign {
        /// Key identifier for signing.
        key_id: String,
        /// Raw message bytes to sign.
        message: Vec<u8>,
        /// Signing mechanism.
        mechanism: AwsMechanism,
    },
    /// Verify a signature against a message.
    Verify {
        /// Key identifier for verification.
        key_id: String,
        /// Original message bytes.
        message: Vec<u8>,
        /// Signature bytes to verify.
        signature: Vec<u8>,
        /// Signing mechanism used.
        mechanism: AwsMechanism,
    },
    /// Wrap (encrypt) a key under another key.
    WrapKey {
        /// Identifier of the wrapping (KEK) key.
        wrapping_key_id: String,
        /// Identifier of the key to wrap.
        target_key_id: String,
        /// Wrapping mechanism.
        mechanism: AwsMechanism,
    },
    /// Unwrap (decrypt) a previously wrapped key.
    UnwrapKey {
        /// Identifier of the wrapping (KEK) key.
        wrapping_key_id: String,
        /// Wrapped key bytes.
        wrapped_bytes: Vec<u8>,
        /// Label for the new unwrapped key.
        label: String,
        /// Wrapping mechanism.
        mechanism: AwsMechanism,
    },
    /// Generate cryptographically secure random bytes.
    GenerateRandom {
        /// Number of bytes requested.
        length: usize,
    },
}

/// Response from AWS CloudHSM shim operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsHsmResponse {
    /// HTTP-like status code (200 = success).
    pub status: i32,
    /// Response payload as JSON.
    pub data: serde_json::Value,
}

/// Trait for AWS CloudHSM shim implementations. Implementations must be
/// `Send + Sync` so they can be shared via `Arc` across threads.
pub trait AwsHsmShim: Send + Sync {
    /// Process an AWS CloudHSM API operation.
    fn process(&self, op: AwsHsmOperation) -> AwsResult<AwsHsmResponse>;
}

/// Logical identity carried alongside an AWS CloudHSM shim request.
///
/// The embedding binary authenticates the caller at the transport layer
/// (SigV4, mTLS) and materialises the result as [`AwsIdentity`] before
/// dispatching into the shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsIdentity {
    /// Authenticated principal ARN / user id.
    pub principal: String,
}

impl AwsIdentity {
    /// Construct a new identity.
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
        }
    }

    /// Convenience anonymous identity, used in ACL tests.
    pub fn anonymous() -> Self {
        Self {
            principal: String::new(),
        }
    }
}

/// Coarse operation classes over which an [`AwsHsmAcl`] policy can gate
/// access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsOp {
    /// Cluster / HSM lifecycle (`CreateHsm`, `DeleteHsm`, `InitializeCluster`).
    Admin,
    /// Read-only observability (`ListHsms`, `DescribeClusters`, `ListKeys`,
    /// `GetKeyAttributes`).
    Read,
    /// Key lifecycle (`CreateKey`, `DeleteKey`).
    Manage,
    /// Cryptographic operations bound to a specific key
    /// (`Sign`, `Verify`, `WrapKey`, `UnwrapKey`).
    Crypto,
    /// Non-key-scoped random generation.
    Random,
}

/// Pluggable per-key ACL for the AWS CloudHSM shim. Consulted before every
/// request touches backend state (audit finding H). The default
/// [`AllowAllAwsAcl`] preserves the previous behaviour.
pub trait AwsHsmAcl: Send + Sync {
    /// Return `true` if `identity` may perform `op` on `key_id`.
    ///
    /// `key_id` is `""` for operations that do not name a key (`ListHsms`,
    /// `GenerateRandom`, etc.) — a policy can still class-gate those.
    fn check(&self, identity: &AwsIdentity, key_id: &str, op: AwsOp) -> bool;
}

/// Permissive ACL kept for callers that explicitly opt in. **NOT the
/// default** — see [`DenyAllAwsAcl`]. Audit finding H20 changed the default
/// to fail-closed; this type is now opt-in via [`MockAwsHsmShim::with_acl`]
/// or, in tests, via [`MockAwsHsmShim::permissive_for_tests`].
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAwsAcl;

impl AwsHsmAcl for AllowAllAwsAcl {
    fn check(&self, _: &AwsIdentity, _: &str, _: AwsOp) -> bool {
        true
    }
}

/// Default deny-all ACL (audit finding H20). The mock shim ships with this
/// installed; embedders must call [`MockAwsHsmShim::with_acl`] to install a
/// real policy or [`MockAwsHsmShim::permissive_for_tests`] to opt in to the
/// legacy permissive behaviour.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllAwsAcl;

impl AwsHsmAcl for DenyAllAwsAcl {
    fn check(&self, _: &AwsIdentity, _: &str, _: AwsOp) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

/// Hard upper bound on a single `Sign`/`Verify` payload. Anything larger is
/// rejected to keep the mock backend from being trivially DoS'd.
const MAX_AWS_PAYLOAD_BYTES: usize = 1 * 1024 * 1024; // 1 MiB
/// Hard upper bound on `GenerateRandom` request length.
const MAX_AWS_RANDOM_BYTES: usize = 64 * 1024;

/// Per-key state for the mock AWS HSM.
///
/// Audit foot-gun (perf): the previous design re-derived `SIGN`, `WRAP-AUTH`
/// and `WRAP-ENC` HKDF sub-keys on every operation, which means Wrap/Unwrap
/// paid TWO `HKDF-SHA256::expand` runs per call. Subkeys are now cached
/// next to the master secret behind `OnceLock` so the HKDF cost is paid at
/// most once per key per process lifetime. `OnceLock` also keeps the
/// derivation lazy, so the cost only materialises if the operation that
/// needs it ever fires.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
#[derive(ZeroizeOnDrop)]
struct MockKey {
    #[zeroize(skip)]
    key_type: String,
    #[zeroize(skip)]
    label: String,
    #[zeroize(skip)]
    hsm_id: String,
    /// 32-byte random material used as the HMAC key.
    secret: [u8; 32],
    /// Cached `SIGN` HKDF sub-key. See struct docs.
    #[zeroize(skip)]
    subkey_sign: std::sync::OnceLock<[u8; 32]>,
    /// Cached `WRAP-AUTH` HKDF sub-key. See struct docs.
    #[zeroize(skip)]
    subkey_wrap_auth: std::sync::OnceLock<[u8; 32]>,
    /// Cached `WRAP-ENC` HKDF sub-key. See struct docs.
    #[zeroize(skip)]
    subkey_wrap_enc: std::sync::OnceLock<[u8; 32]>,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockKey {
    /// Return the cached `SIGN` sub-key, deriving it on first call.
    fn sign_subkey(&self) -> &[u8; 32] {
        self.subkey_sign
            .get_or_init(|| crate::mock_crypto::subkey(&self.secret, b"SIGN"))
    }

    /// Return the cached `WRAP-AUTH` sub-key, deriving it on first call.
    fn wrap_auth_subkey(&self) -> &[u8; 32] {
        self.subkey_wrap_auth
            .get_or_init(|| crate::mock_crypto::subkey(&self.secret, b"WRAP-AUTH"))
    }

    /// Return the cached `WRAP-ENC` sub-key, deriving it on first call.
    fn wrap_enc_subkey(&self) -> &[u8; 32] {
        self.subkey_wrap_enc
            .get_or_init(|| crate::mock_crypto::subkey(&self.secret, b"WRAP-ENC"))
    }
}

/// Mock AWS CloudHSM shim for testing and local development.
///
/// Backed by HMAC-SHA256 over per-key random material. Key material lives
/// in process memory and is zeroised on drop.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
pub struct MockAwsHsmShim {
    config: AwsHsmConfig,
    hsms: DashMap<String, String>, // hsm_id -> availability_zone
    keys: DashMap<String, MockKey>,
    /// Reverse index of label -> key_id used for `KeyAlreadyExists` checks.
    labels: DashMap<String, String>,
    next_id: AtomicU64,
    acl: std::sync::Arc<dyn AwsHsmAcl>,
    default_identity: AwsIdentity,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockAwsHsmShim {
    /// Create a new mock shim from a configuration object.
    ///
    /// # Panics
    ///
    /// Panics unless the runtime opt-in `CRATON_HSM_ALLOW_MOCK=1` is set. This
    /// is the second line of defence behind the `mock-insecure-do-not-ship`
    /// Cargo feature.
    pub fn new(config: AwsHsmConfig) -> Self {
        crate::mock_guard::check("aws_shim::MockAwsHsmShim");
        info!(cluster_id = %config.cluster_id, region = %config.region, "mock AWS HSM shim created");
        Self {
            config,
            hsms: DashMap::new(),
            keys: DashMap::new(),
            labels: DashMap::new(),
            next_id: AtomicU64::new(1),
            // Audit finding H20: default to deny-all. Embedders opt into a
            // permissive policy via `with_acl` or `permissive_for_tests`.
            acl: std::sync::Arc::new(DenyAllAwsAcl),
            default_identity: AwsIdentity::anonymous(),
        }
    }

    /// Install the legacy permissive ACL **and** a non-anonymous default
    /// identity. Test-only helper (audit finding H20).
    #[cfg(any(test, feature = "permissive-for-tests"))]
    pub fn permissive_for_tests(self) -> Self {
        self.with_acl(std::sync::Arc::new(AllowAllAwsAcl))
            .with_default_identity(AwsIdentity::new("test-suite"))
    }

    /// Replace the ACL implementation. Intended for production embedders and
    /// for the `aws_acl_denies_unauthorized_caller` test.
    pub fn with_acl(mut self, acl: std::sync::Arc<dyn AwsHsmAcl>) -> Self {
        self.acl = acl;
        self
    }

    /// Override the default identity used by [`AwsHsmShim::process`].
    pub fn with_default_identity(mut self, identity: AwsIdentity) -> Self {
        self.default_identity = identity;
        self
    }

    /// Process an operation on behalf of an explicitly provided identity.
    pub fn process_as(
        &self,
        identity: &AwsIdentity,
        op: AwsHsmOperation,
    ) -> AwsResult<AwsHsmResponse> {
        let (class, key_id) = Self::classify(&op);
        if !self.acl.check(identity, key_id, class) {
            // Audit finding M (ACL error class): surface a dedicated
            // `PermissionDenied` so callers can distinguish auth failures
            // from validation failures. The error message intentionally
            // contains no caller-supplied label material — only the class
            // and the (already escaped) `key_id`.
            return Err(AwsHsmError::PermissionDenied(format!(
                "aws ACL denied {class:?} on {}",
                key_id.escape_debug()
            )));
        }
        self.dispatch(op)
    }

    fn classify(op: &AwsHsmOperation) -> (AwsOp, &str) {
        match op {
            AwsHsmOperation::InitializeCluster
            | AwsHsmOperation::CreateHsm { .. }
            | AwsHsmOperation::DeleteHsm { .. } => (AwsOp::Admin, ""),
            AwsHsmOperation::ListHsms
            | AwsHsmOperation::DescribeClusters
            | AwsHsmOperation::ListKeys => (AwsOp::Read, ""),
            AwsHsmOperation::GetKeyAttributes { key_id } => (AwsOp::Read, key_id.as_str()),
            // Audit finding (CreateKey ACL keyed on label): the previous
            // implementation passed `label` into the ACL `key_id` slot, but
            // `label` is attacker-supplied and the real key id has not yet
            // been allocated. Pass an empty `key_id` so policies treat
            // `CreateKey` as a class-level gate (the `AwsOp::Manage` class
            // already conveys "this is a key-lifecycle write"); embedders
            // that need finer control should re-check post-allocation by
            // calling `process_as` again with a `GetKeyAttributes`-class
            // policy on the returned id, or by wrapping the shim.
            AwsHsmOperation::CreateKey { .. } => (AwsOp::Manage, ""),
            AwsHsmOperation::DeleteKey { key_id } => (AwsOp::Manage, key_id.as_str()),
            AwsHsmOperation::Sign { key_id, .. } | AwsHsmOperation::Verify { key_id, .. } => {
                (AwsOp::Crypto, key_id.as_str())
            }
            AwsHsmOperation::WrapKey {
                wrapping_key_id, ..
            }
            | AwsHsmOperation::UnwrapKey {
                wrapping_key_id, ..
            } => (AwsOp::Crypto, wrapping_key_id.as_str()),
            AwsHsmOperation::GenerateRandom { .. } => (AwsOp::Random, ""),
        }
    }

    /// Convenience constructor for tests.
    pub fn with_cluster_id(cluster_id: &str) -> Self {
        Self::new(AwsHsmConfig {
            cluster_id: cluster_id.to_string(),
            region: Cow::Borrowed("us-east-1"),
            hsm_type: default_hsm_type(),
        })
    }

    fn next_id(&self, prefix: &str) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id:08x}")
    }

    fn pick_hsm(&self, requested: Option<String>) -> AwsResult<String> {
        match requested {
            Some(id) => {
                if !self.hsms.contains_key(&id) {
                    return Err(AwsHsmError::HsmNotFound(id));
                }
                Ok(id)
            }
            None => self
                .hsms
                .iter()
                .next()
                .map(|e| e.key().clone())
                .ok_or_else(|| AwsHsmError::Internal("no HSMs available in cluster".into())),
        }
    }

    fn validate_payload(bytes: &[u8]) -> AwsResult<()> {
        if bytes.len() > MAX_AWS_PAYLOAD_BYTES {
            return Err(AwsHsmError::InvalidParameter(format!(
                "payload exceeds {MAX_AWS_PAYLOAD_BYTES} bytes"
            )));
        }
        Ok(())
    }

    /// Compute a short, log-safe digest of a label so audit lines can
    /// correlate collisions without leaking the label string itself
    /// (audit finding M, CreateKey label-leak).
    fn label_audit_hash(label: &str) -> String {
        let mut h = Sha256::new();
        h.update(label.as_bytes());
        let d = h.finalize();
        let mut s = String::with_capacity(16);
        for b in &d[..8] {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    /// Sign a message with the pre-derived `SIGN` sub-key. Callers must pass
    /// the cached sub-key (see [`MockKey::sign_subkey`]) so a single HKDF
    /// derivation is amortised across every call for the lifetime of the key
    /// (audit foot-gun: HKDF was previously re-derived per call).
    fn hmac_sign_with_sub(sub: &[u8; 32], mechanism: AwsMechanism, message: &[u8]) -> [u8; 32] {
        crate::mock_crypto::hmac_sign(sub, mechanism.wire_name().as_bytes(), message)
    }

    /// Authenticate a wrapped-key blob with the cached `WRAP-AUTH` sub-key.
    /// See [`MockKey::wrap_auth_subkey`].
    fn wrap_tag_with_sub(sub: &[u8; 32], body: &[u8]) -> [u8; 32] {
        crate::mock_crypto::hmac_sign(sub, AwsMechanism::AesKeyWrap.wire_name().as_bytes(), body)
    }

    /// XOR-stream keyed on the cached `WRAP-ENC` sub-key. See
    /// [`MockKey::wrap_enc_subkey`].
    fn xor_stream_with_sub(sub: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> AwsResult<Vec<u8>> {
        crate::mock_crypto::xor_stream(sub, nonce, data)
            .map_err(|()| AwsHsmError::Internal("xor counter overflow".into()))
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl AwsHsmShim for MockAwsHsmShim {
    fn process(&self, op: AwsHsmOperation) -> AwsResult<AwsHsmResponse> {
        let identity = self.default_identity.clone();
        self.process_as(&identity, op)
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl MockAwsHsmShim {
    fn dispatch(&self, op: AwsHsmOperation) -> AwsResult<AwsHsmResponse> {
        match op {
            AwsHsmOperation::InitializeCluster => {
                debug!(cluster_id = %self.config.cluster_id, "InitializeCluster");
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "ClusterId": self.config.cluster_id,
                        "State": "INITIALIZED",
                    }),
                })
            }
            AwsHsmOperation::CreateHsm { availability_zone } => {
                let hsm_id = self.next_id("hsm");
                self.hsms.insert(hsm_id.clone(), availability_zone.clone());
                info!(hsm_id = %hsm_id, az = %availability_zone, "CreateHsm");
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "HsmId": hsm_id,
                        "AvailabilityZone": availability_zone,
                        "State": "ACTIVE",
                        "ClusterId": self.config.cluster_id,
                        "HsmType": &*self.config.hsm_type,
                    }),
                })
            }
            AwsHsmOperation::DeleteHsm { hsm_id } => {
                self.hsms
                    .remove(&hsm_id)
                    .ok_or_else(|| AwsHsmError::HsmNotFound(hsm_id.clone()))?;
                // Cascade-delete keys bound to the removed HSM.
                let to_remove: Vec<(String, String)> = self
                    .keys
                    .iter()
                    .filter(|e| e.value().hsm_id == hsm_id)
                    .map(|e| (e.key().clone(), e.value().label.clone()))
                    .collect();
                let removed_keys = to_remove.len();
                for (k, label) in to_remove {
                    self.keys.remove(&k);
                    self.labels.remove(&label);
                }
                info!(hsm_id = %hsm_id, cascaded_keys = removed_keys, "DeleteHsm");
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "HsmId": hsm_id,
                        "State": "DELETED",
                        "CascadedKeys": removed_keys,
                    }),
                })
            }
            AwsHsmOperation::ListHsms => {
                // Snapshot before building JSON to release shard locks early.
                let snapshot: Vec<(String, String)> = self
                    .hsms
                    .iter()
                    .map(|e| (e.key().clone(), e.value().clone()))
                    .collect();
                let list: Vec<serde_json::Value> = snapshot
                    .into_iter()
                    .map(|(id, az)| {
                        serde_json::json!({
                            "HsmId": id,
                            "AvailabilityZone": az,
                            "State": "ACTIVE",
                        })
                    })
                    .collect();
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({ "Hsms": list }),
                })
            }
            AwsHsmOperation::DescribeClusters => {
                let snapshot: Vec<(String, String)> = self
                    .hsms
                    .iter()
                    .map(|e| (e.key().clone(), e.value().clone()))
                    .collect();
                let hsm_list: Vec<serde_json::Value> = snapshot
                    .into_iter()
                    .map(|(id, az)| {
                        serde_json::json!({
                            "HsmId": id,
                            "AvailabilityZone": az,
                            "State": "ACTIVE",
                        })
                    })
                    .collect();
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "Clusters": [{
                            "ClusterId": self.config.cluster_id,
                            "State": "ACTIVE",
                            "Hsms": hsm_list,
                        }],
                    }),
                })
            }
            AwsHsmOperation::CreateKey {
                key_type,
                label,
                hsm_id,
            } => {
                // Constant-time-ordered validation (audit L timing): perform
                // every check that does not depend on internal state first
                // and in the same order, regardless of which one fails.
                let label_empty = label.is_empty();
                let bound_hsm = self.pick_hsm(hsm_id)?;
                if label_empty {
                    return Err(AwsHsmError::InvalidParameter(
                        "label must not be empty".into(),
                    ));
                }
                // Audit M (CreateKey label-leak): never echo the caller-
                // provided label back in the error string. Surface a hashed
                // label to the audit log instead and return a static error.
                let label_hash = Self::label_audit_hash(&label);
                if self.labels.contains_key(&label) {
                    debug!(label_sha256 = %label_hash, "CreateKey: label collision");
                    return Err(AwsHsmError::KeyAlreadyExists(String::new()));
                }
                let key_id = self.next_id("key");
                let mut secret = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut secret);
                let entry = MockKey {
                    key_type: key_type.clone(),
                    label: label.clone(),
                    hsm_id: bound_hsm.clone(),
                    secret,
                    subkey_sign: std::sync::OnceLock::new(),
                    subkey_wrap_auth: std::sync::OnceLock::new(),
                    subkey_wrap_enc: std::sync::OnceLock::new(),
                };
                // Race-window check: a competing CreateKey with the same label
                // could have inserted between contains_key and now.  Use the
                // reverse index entry API to atomically reject duplicates.
                use dashmap::mapref::entry::Entry;
                match self.labels.entry(label.clone()) {
                    Entry::Occupied(_) => {
                        // Drop entry to zeroise secret immediately.
                        drop(entry);
                        debug!(label_sha256 = %label_hash, "CreateKey: race-window label collision");
                        return Err(AwsHsmError::KeyAlreadyExists(String::new()));
                    }
                    Entry::Vacant(v) => {
                        v.insert(key_id.clone());
                        self.keys.insert(key_id.clone(), entry);
                    }
                }
                info!(key_id = %key_id, key_type = %key_type, "CreateKey");
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "KeyId": key_id,
                        "KeyType": key_type,
                        "Label": label,
                        "HsmId": bound_hsm,
                    }),
                })
            }
            AwsHsmOperation::DeleteKey { key_id } => {
                let (_, removed) = self
                    .keys
                    .remove(&key_id)
                    .ok_or_else(|| AwsHsmError::KeyNotFound(key_id.clone()))?;
                self.labels.remove(&removed.label);
                info!(key_id = %key_id, "DeleteKey");
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "KeyId": key_id,
                        "Deleted": true,
                    }),
                })
            }
            AwsHsmOperation::ListKeys => {
                let snapshot: Vec<(String, String, String, String)> = self
                    .keys
                    .iter()
                    .map(|e| {
                        (
                            e.key().clone(),
                            e.value().key_type.clone(),
                            e.value().label.clone(),
                            e.value().hsm_id.clone(),
                        )
                    })
                    .collect();
                let list: Vec<serde_json::Value> = snapshot
                    .into_iter()
                    .map(|(id, kt, label, hsm)| {
                        serde_json::json!({
                            "KeyId": id,
                            "KeyType": kt,
                            "Label": label,
                            "HsmId": hsm,
                        })
                    })
                    .collect();
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({ "Keys": list }),
                })
            }
            AwsHsmOperation::GetKeyAttributes { key_id } => {
                let entry = self
                    .keys
                    .get(&key_id)
                    .ok_or_else(|| AwsHsmError::KeyNotFound(key_id.clone()))?;
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "KeyId": key_id,
                        "KeyType": entry.key_type,
                        "Label": entry.label,
                        "HsmId": entry.hsm_id,
                    }),
                })
            }
            AwsHsmOperation::Sign {
                key_id,
                message,
                mechanism,
            } => {
                Self::validate_payload(&message)?;
                // Audit finding (DashMap lock held across HMAC compute):
                // clone the cached `SIGN` sub-key out under the guard, then
                // drop the guard. Audit foot-gun (perf): the sub-key is
                // cached on `MockKey` via `OnceLock`, so the HKDF derivation
                // only fires on the first call for this key.
                let sub = {
                    let entry = self
                        .keys
                        .get(&key_id)
                        .ok_or_else(|| AwsHsmError::KeyNotFound(key_id.clone()))?;
                    zeroize::Zeroizing::new(*entry.sign_subkey())
                };
                let sig = Self::hmac_sign_with_sub(&sub, mechanism, &message);
                debug!(key_id = %key_id, mechanism = mechanism.wire_name(), "Sign");
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "KeyId": key_id,
                        "Mechanism": mechanism.wire_name(),
                        "Signature": sig,
                    }),
                })
            }
            AwsHsmOperation::Verify {
                key_id,
                message,
                signature,
                mechanism,
            } => {
                Self::validate_payload(&message)?;
                // See `Sign` above: extract the cached `SIGN` sub-key under
                // the guard so the HKDF cost is amortised.
                let sub = {
                    let entry = self
                        .keys
                        .get(&key_id)
                        .ok_or_else(|| AwsHsmError::KeyNotFound(key_id.clone()))?;
                    zeroize::Zeroizing::new(*entry.sign_subkey())
                };
                let expected = Self::hmac_sign_with_sub(&sub, mechanism, &message);
                let valid: bool = expected.as_slice().ct_eq(&signature).into();
                if !valid {
                    warn!(key_id = %key_id, "Verify: signature mismatch");
                }
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "KeyId": key_id,
                        "Mechanism": mechanism.wire_name(),
                        "Valid": valid,
                    }),
                })
            }
            AwsHsmOperation::WrapKey {
                wrapping_key_id,
                target_key_id,
                mechanism,
            } => {
                // Audit foot-gun: previously this arm accepted
                // `AwsMechanism::AesGcm` and executed it via the same XOR-
                // stream + HMAC tag path as `AesKeyWrap`. Callers asking for
                // AES-GCM got a **non-AEAD** mock and would not notice. The
                // mock has no real GCM implementation, so refuse the
                // mechanism instead of silently downgrading it.
                if matches!(mechanism, AwsMechanism::AesGcm) {
                    return Err(AwsHsmError::UnsupportedMechanism(format!(
                        "{} is AEAD-shaped; the mock AWS shim does not implement \
                         authenticated encryption — use a real AES-GCM backend or \
                         request {} for the mock",
                        mechanism.wire_name(),
                        AwsMechanism::AesKeyWrap.wire_name()
                    )));
                }
                if !matches!(mechanism, AwsMechanism::AesKeyWrap) {
                    return Err(AwsHsmError::UnsupportedMechanism(format!(
                        "{} not valid for WrapKey",
                        mechanism.wire_name()
                    )));
                }
                // Audit finding (DashMap lock held across HMAC/xor): clone
                // the cached sub-keys + target secret into zeroising locals
                // first, then drop the guards before touching the keystream.
                // Holding both shard guards over the keystream computation
                // also creates a multi-shard hold pattern that could deadlock
                // against a future writer.
                //
                // Audit foot-gun (perf): we pull the `WRAP-AUTH` and
                // `WRAP-ENC` sub-keys from `MockKey`'s `OnceLock` cache, so
                // HKDF only runs the first time this KEK is touched. Prior
                // code derived both sub-keys per call.
                let (kek_sub_auth, kek_sub_enc) = {
                    let kek = self
                        .keys
                        .get(&wrapping_key_id)
                        .ok_or_else(|| AwsHsmError::KeyNotFound(wrapping_key_id.clone()))?;
                    (
                        zeroize::Zeroizing::new(*kek.wrap_auth_subkey()),
                        zeroize::Zeroizing::new(*kek.wrap_enc_subkey()),
                    )
                };
                let target_secret = {
                    let target = self
                        .keys
                        .get(&target_key_id)
                        .ok_or_else(|| AwsHsmError::KeyNotFound(target_key_id.clone()))?;
                    zeroize::Zeroizing::new(target.secret)
                };
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let mut wrapped = nonce.to_vec();
                wrapped.extend_from_slice(&Self::xor_stream_with_sub(
                    &kek_sub_enc,
                    &nonce,
                    &*target_secret,
                )?);
                // Audit H18: tag with the dedicated `WRAP-AUTH` sub-key so a
                // valid wrap tag is never also a valid Sign output for the
                // same body.
                let tag = Self::wrap_tag_with_sub(&kek_sub_auth, &wrapped);
                wrapped.extend_from_slice(&tag);
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "WrappingKeyId": wrapping_key_id,
                        "TargetKeyId": target_key_id,
                        "WrappedKey": wrapped,
                        "Mechanism": mechanism.wire_name(),
                    }),
                })
            }
            AwsHsmOperation::UnwrapKey {
                wrapping_key_id,
                wrapped_bytes,
                label,
                mechanism,
            } => {
                // Audit foot-gun (matched WrapKey): refuse AEAD-shaped
                // mechanisms here too so a caller cannot ask for AES-GCM and
                // silently receive a non-authenticated XOR-stream unwrap.
                if matches!(mechanism, AwsMechanism::AesGcm) {
                    return Err(AwsHsmError::UnsupportedMechanism(format!(
                        "{} is AEAD-shaped; the mock AWS shim does not implement \
                         authenticated encryption — use a real AES-GCM backend or \
                         request {} for the mock",
                        mechanism.wire_name(),
                        AwsMechanism::AesKeyWrap.wire_name()
                    )));
                }
                if !matches!(mechanism, AwsMechanism::AesKeyWrap) {
                    return Err(AwsHsmError::UnsupportedMechanism(format!(
                        "{} not valid for UnwrapKey",
                        mechanism.wire_name()
                    )));
                }
                // Audit finding (DashMap lock held across HMAC/xor): copy
                // the cached sub-keys and `hsm_id` out under the guard, then
                // drop the guard before the keystream + tag work.
                //
                // Audit foot-gun (perf): the `WRAP-AUTH` / `WRAP-ENC`
                // sub-keys come from `MockKey`'s `OnceLock` cache so HKDF
                // only runs once per KEK regardless of how many
                // wrap/unwrap calls cross this code path.
                let (kek_sub_auth, kek_sub_enc, bound_hsm) = {
                    let kek = self
                        .keys
                        .get(&wrapping_key_id)
                        .ok_or_else(|| AwsHsmError::KeyNotFound(wrapping_key_id.clone()))?;
                    (
                        zeroize::Zeroizing::new(*kek.wrap_auth_subkey()),
                        zeroize::Zeroizing::new(*kek.wrap_enc_subkey()),
                        kek.hsm_id.clone(),
                    )
                };
                if wrapped_bytes.len() < 12 + 32 {
                    return Err(AwsHsmError::InvalidParameter(
                        "wrapped blob too short".into(),
                    ));
                }
                let tag_offset = wrapped_bytes.len() - 32;
                let (body, tag) = wrapped_bytes.split_at(tag_offset);
                let expected_tag = Self::wrap_tag_with_sub(&kek_sub_auth, body);
                let tag_ok: bool = expected_tag.as_slice().ct_eq(tag).into();
                if !tag_ok {
                    return Err(AwsHsmError::InvalidParameter(
                        "wrapped key authentication failed".into(),
                    ));
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&body[..12]);
                let plaintext = Self::xor_stream_with_sub(&kek_sub_enc, &nonce, &body[12..])?;
                if plaintext.len() != 32 {
                    return Err(AwsHsmError::InvalidParameter(
                        "unwrapped key has invalid length".into(),
                    ));
                }
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&plaintext);
                // Drop the heap copy of the unwrapped material early — the
                // canonical copy now lives in `secret` and will be moved into
                // the new MockKey below.
                drop(plaintext);
                let key_id = self.next_id("key");
                use dashmap::mapref::entry::Entry;
                match self.labels.entry(label.clone()) {
                    Entry::Occupied(_) => {
                        // Zeroise the unwrapped material we are about to drop.
                        let mut z = secret;
                        z.zeroize();
                        let label_hash = Self::label_audit_hash(&label);
                        debug!(label_sha256 = %label_hash, "UnwrapKey: label collision");
                        return Err(AwsHsmError::KeyAlreadyExists(String::new()));
                    }
                    Entry::Vacant(v) => {
                        v.insert(key_id.clone());
                    }
                }
                self.keys.insert(
                    key_id.clone(),
                    MockKey {
                        key_type: "AES".to_string(),
                        label: label.clone(),
                        hsm_id: bound_hsm.clone(),
                        secret,
                        subkey_sign: std::sync::OnceLock::new(),
                        subkey_wrap_auth: std::sync::OnceLock::new(),
                        subkey_wrap_enc: std::sync::OnceLock::new(),
                    },
                );
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({
                        "KeyId": key_id,
                        "Label": label,
                        "HsmId": bound_hsm,
                    }),
                })
            }
            AwsHsmOperation::GenerateRandom { length } => {
                if length > MAX_AWS_RANDOM_BYTES {
                    return Err(AwsHsmError::InvalidParameter(format!(
                        "length exceeds {MAX_AWS_RANDOM_BYTES} bytes"
                    )));
                }
                let mut bytes = vec![0u8; length];
                rand::thread_rng().fill_bytes(&mut bytes);
                Ok(AwsHsmResponse {
                    status: 200,
                    data: serde_json::json!({ "Random": bytes }),
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
    /// `LocalDenyAllAwsAcl` so the module-level [`DenyAllAwsAcl`] stays
    /// visible to test code. Using the local variant keeps the test focused
    /// on policy *behaviour* rather than the specific type.
    struct LocalDenyAllAwsAcl;
    impl AwsHsmAcl for LocalDenyAllAwsAcl {
        fn check(&self, _: &AwsIdentity, _: &str, _: AwsOp) -> bool {
            false
        }
    }

    #[test]
    fn aws_acl_denies_unauthorized_caller() {
        crate::_enable_mock_for_tests();
        let shim =
            MockAwsHsmShim::with_cluster_id("cluster-acl").with_acl(Arc::new(LocalDenyAllAwsAcl));
        // Even admin-class operations are denied.
        let err = shim
            .process_as(
                &AwsIdentity::new("mallory"),
                AwsHsmOperation::CreateHsm {
                    availability_zone: "us-east-1a".into(),
                },
            )
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::PermissionDenied(_)));
        // List is also denied.
        let err = shim
            .process_as(&AwsIdentity::new("eve"), AwsHsmOperation::ListHsms)
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::PermissionDenied(_)));
    }

    /// Audit finding (CreateKey ACL keyed on label): the policy must not
    /// receive the attacker-controlled `label` in the ACL `key_id` slot.
    /// This test installs a policy that explicitly inspects what gets
    /// passed in and refuses any non-empty key_id for `CreateKey`.
    #[test]
    fn create_key_acl_receives_empty_key_id() {
        crate::_enable_mock_for_tests();
        struct AssertEmpty;
        impl AwsHsmAcl for AssertEmpty {
            fn check(&self, _id: &AwsIdentity, key_id: &str, op: AwsOp) -> bool {
                if matches!(op, AwsOp::Manage) {
                    // CreateKey/DeleteKey both land here; DeleteKey passes
                    // a real key_id, CreateKey must pass empty.
                    return !key_id.contains("ATTACKER-LABEL");
                }
                true
            }
        }
        let shim = MockAwsHsmShim::with_cluster_id("cluster-key-acl")
            .with_acl(Arc::new(AssertEmpty))
            .with_default_identity(AwsIdentity::new("tester"));
        shim.process(AwsHsmOperation::CreateHsm {
            availability_zone: "us-east-1a".into(),
        })
        .unwrap();
        // The policy must NOT see "ATTACKER-LABEL" in the key_id slot.
        shim.process(AwsHsmOperation::CreateKey {
            key_type: "AES".into(),
            label: "ATTACKER-LABEL".into(),
            hsm_id: None,
        })
        .unwrap();
    }

    fn make_shim() -> MockAwsHsmShim {
        crate::_enable_mock_for_tests();
        // Audit H20: the default ACL is now deny-all; flip the existing
        // tests over to the permissive helper that mirrors the legacy
        // behaviour.
        let shim = MockAwsHsmShim::with_cluster_id("cluster-test-001").permissive_for_tests();
        // Pre-create one HSM for tests that go straight to CreateKey.
        shim.process(AwsHsmOperation::CreateHsm {
            availability_zone: "us-east-1a".to_string(),
        })
        .unwrap();
        shim
    }

    #[test]
    fn initialize_cluster() {
        let shim = make_shim();
        let resp = shim.process(AwsHsmOperation::InitializeCluster).unwrap();
        assert_eq!(resp.data["State"], "INITIALIZED");
    }

    #[test]
    fn create_and_delete_hsm() {
        let shim = make_shim();
        let resp = shim
            .process(AwsHsmOperation::CreateHsm {
                availability_zone: "us-west-2b".to_string(),
            })
            .unwrap();
        let hsm_id = resp.data["HsmId"].as_str().unwrap().to_string();
        let del = shim
            .process(AwsHsmOperation::DeleteHsm {
                hsm_id: hsm_id.clone(),
            })
            .unwrap();
        assert_eq!(del.data["State"], "DELETED");
    }

    #[test]
    fn delete_hsm_cascades_keys() {
        let shim = make_shim();
        // Find the bootstrap HSM id.
        let hsms = shim.process(AwsHsmOperation::ListHsms).unwrap();
        let hsm_id = hsms.data["Hsms"][0]["HsmId"].as_str().unwrap().to_string();
        shim.process(AwsHsmOperation::CreateKey {
            key_type: "AES".into(),
            label: "k1".into(),
            hsm_id: Some(hsm_id.clone()),
        })
        .unwrap();
        shim.process(AwsHsmOperation::DeleteHsm {
            hsm_id: hsm_id.clone(),
        })
        .unwrap();
        // Key must be gone.
        let list = shim.process(AwsHsmOperation::ListKeys).unwrap();
        assert_eq!(list.data["Keys"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn delete_nonexistent_hsm() {
        let shim = make_shim();
        let err = shim
            .process(AwsHsmOperation::DeleteHsm {
                hsm_id: "hsm-nope".into(),
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::HsmNotFound(_)));
    }

    #[test]
    fn list_hsms_and_describe_clusters() {
        let shim = make_shim();
        let list = shim.process(AwsHsmOperation::ListHsms).unwrap();
        assert_eq!(list.data["Hsms"].as_array().unwrap().len(), 1);
        let desc = shim.process(AwsHsmOperation::DescribeClusters).unwrap();
        assert_eq!(desc.data["Clusters"][0]["ClusterId"], "cluster-test-001");
    }

    #[test]
    fn create_key_requires_label() {
        let shim = make_shim();
        let err = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "".into(),
                hsm_id: None,
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::InvalidParameter(_)));
    }

    #[test]
    fn create_key_duplicate_label_rejected() {
        let shim = make_shim();
        shim.process(AwsHsmOperation::CreateKey {
            key_type: "AES".into(),
            label: "dup".into(),
            hsm_id: None,
        })
        .unwrap();
        let err = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "RSA".into(),
                label: "dup".into(),
                hsm_id: None,
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::KeyAlreadyExists(_)));
    }

    #[test]
    fn create_key_unknown_hsm() {
        let shim = make_shim();
        let err = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "k".into(),
                hsm_id: Some("hsm-nope".into()),
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::HsmNotFound(_)));
    }

    #[test]
    fn delete_key_lifecycle() {
        let shim = make_shim();
        let create = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "RSA".into(),
                label: "rsa-1".into(),
                hsm_id: None,
            })
            .unwrap();
        let id = create.data["KeyId"].as_str().unwrap().to_string();
        shim.process(AwsHsmOperation::DeleteKey { key_id: id.clone() })
            .unwrap();
        // Label should be reusable after delete.
        shim.process(AwsHsmOperation::CreateKey {
            key_type: "RSA".into(),
            label: "rsa-1".into(),
            hsm_id: None,
        })
        .unwrap();
    }

    #[test]
    fn delete_nonexistent_key() {
        let shim = make_shim();
        let err = shim
            .process(AwsHsmOperation::DeleteKey {
                key_id: "key-nope".into(),
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::KeyNotFound(_)));
    }

    #[test]
    fn list_keys_and_attributes() {
        let shim = make_shim();
        let create = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "L".into(),
                hsm_id: None,
            })
            .unwrap();
        let id = create.data["KeyId"].as_str().unwrap().to_string();
        let list = shim.process(AwsHsmOperation::ListKeys).unwrap();
        assert_eq!(list.data["Keys"].as_array().unwrap().len(), 1);
        let attrs = shim
            .process(AwsHsmOperation::GetKeyAttributes { key_id: id.clone() })
            .unwrap();
        assert_eq!(attrs.data["KeyType"], "AES");
        assert_eq!(attrs.data["Label"], "L");
    }

    #[test]
    fn sign_verify_roundtrip_with_hmac() {
        let shim = make_shim();
        let create = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "RSA".into(),
                label: "sig".into(),
                hsm_id: None,
            })
            .unwrap();
        let id = create.data["KeyId"].as_str().unwrap().to_string();
        let msg = vec![1u8, 2, 3, 4];
        let sig_resp = shim
            .process(AwsHsmOperation::Sign {
                key_id: id.clone(),
                message: msg.clone(),
                mechanism: AwsMechanism::Sha256RsaPkcs,
            })
            .unwrap();
        let sig: Vec<u8> = sig_resp.data["Signature"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        let verify = shim
            .process(AwsHsmOperation::Verify {
                key_id: id,
                message: msg,
                signature: sig,
                mechanism: AwsMechanism::Sha256RsaPkcs,
            })
            .unwrap();
        assert_eq!(verify.data["Valid"], true);
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let shim = make_shim();
        let create = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "RSA".into(),
                label: "sig2".into(),
                hsm_id: None,
            })
            .unwrap();
        let id = create.data["KeyId"].as_str().unwrap().to_string();
        let resp = shim
            .process(AwsHsmOperation::Verify {
                key_id: id,
                message: vec![1, 2, 3],
                signature: vec![0u8; 32],
                mechanism: AwsMechanism::Sha256RsaPkcs,
            })
            .unwrap();
        assert_eq!(resp.data["Valid"], false);
    }

    #[test]
    fn sign_payload_too_large_rejected() {
        let shim = make_shim();
        let create = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "RSA".into(),
                label: "big".into(),
                hsm_id: None,
            })
            .unwrap();
        let id = create.data["KeyId"].as_str().unwrap().to_string();
        let big = vec![0u8; MAX_AWS_PAYLOAD_BYTES + 1];
        let err = shim
            .process(AwsHsmOperation::Sign {
                key_id: id,
                message: big,
                mechanism: AwsMechanism::Sha256RsaPkcs,
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::InvalidParameter(_)));
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let shim = make_shim();
        let kek = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "kek".into(),
                hsm_id: None,
            })
            .unwrap();
        let target = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "target".into(),
                hsm_id: None,
            })
            .unwrap();
        let wrap = shim
            .process(AwsHsmOperation::WrapKey {
                wrapping_key_id: kek.data["KeyId"].as_str().unwrap().to_string(),
                target_key_id: target.data["KeyId"].as_str().unwrap().to_string(),
                mechanism: AwsMechanism::AesKeyWrap,
            })
            .unwrap();
        let wrapped: Vec<u8> = wrap.data["WrappedKey"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        let unwrap = shim
            .process(AwsHsmOperation::UnwrapKey {
                wrapping_key_id: kek.data["KeyId"].as_str().unwrap().to_string(),
                wrapped_bytes: wrapped,
                label: "unwrapped".into(),
                mechanism: AwsMechanism::AesKeyWrap,
            })
            .unwrap();
        assert_eq!(unwrap.data["Label"], "unwrapped");
    }

    #[test]
    fn unwrap_tampered_blob_rejected() {
        let shim = make_shim();
        let kek = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "kek2".into(),
                hsm_id: None,
            })
            .unwrap();
        let target = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "tgt2".into(),
                hsm_id: None,
            })
            .unwrap();
        let wrap = shim
            .process(AwsHsmOperation::WrapKey {
                wrapping_key_id: kek.data["KeyId"].as_str().unwrap().to_string(),
                target_key_id: target.data["KeyId"].as_str().unwrap().to_string(),
                mechanism: AwsMechanism::AesKeyWrap,
            })
            .unwrap();
        let mut wrapped: Vec<u8> = wrap.data["WrappedKey"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        // Flip one byte in the middle of the body.
        wrapped[20] ^= 0xff;
        let err = shim
            .process(AwsHsmOperation::UnwrapKey {
                wrapping_key_id: kek.data["KeyId"].as_str().unwrap().to_string(),
                wrapped_bytes: wrapped,
                label: "tampered".into(),
                mechanism: AwsMechanism::AesKeyWrap,
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::InvalidParameter(_)));
    }

    #[test]
    fn wrap_with_invalid_mechanism_rejected() {
        let shim = make_shim();
        let kek = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "kek3".into(),
                hsm_id: None,
            })
            .unwrap();
        let target = shim
            .process(AwsHsmOperation::CreateKey {
                key_type: "AES".into(),
                label: "tgt3".into(),
                hsm_id: None,
            })
            .unwrap();
        let err = shim
            .process(AwsHsmOperation::WrapKey {
                wrapping_key_id: kek.data["KeyId"].as_str().unwrap().to_string(),
                target_key_id: target.data["KeyId"].as_str().unwrap().to_string(),
                mechanism: AwsMechanism::Sha256RsaPkcs,
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::UnsupportedMechanism(_)));
    }

    #[test]
    fn generate_random_returns_n_bytes() {
        let shim = make_shim();
        let resp = shim
            .process(AwsHsmOperation::GenerateRandom { length: 32 })
            .unwrap();
        let bytes = resp.data["Random"].as_array().unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn generate_random_too_large_rejected() {
        let shim = make_shim();
        let err = shim
            .process(AwsHsmOperation::GenerateRandom {
                length: MAX_AWS_RANDOM_BYTES + 1,
            })
            .unwrap_err();
        assert!(matches!(err, AwsHsmError::InvalidParameter(_)));
    }

    #[test]
    fn mechanism_wire_name_roundtrip() {
        for m in [
            AwsMechanism::Sha256RsaPkcs,
            AwsMechanism::Sha384RsaPkcs,
            AwsMechanism::Ecdsa,
            AwsMechanism::AesGcm,
            AwsMechanism::AesKeyWrap,
        ] {
            assert_eq!(AwsMechanism::from_wire(m.wire_name()).unwrap(), m);
        }
    }

    #[test]
    fn mechanism_from_wire_unknown() {
        let err = AwsMechanism::from_wire("FROBNICATE_SHA9").unwrap_err();
        assert!(matches!(err, AwsHsmError::UnsupportedMechanism(_)));
    }

    #[test]
    fn config_defaults() {
        let json = r#"{"cluster_id":"c-1","region":"us-east-1"}"#;
        let cfg: AwsHsmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(&*cfg.hsm_type, "craton-hsm.medium");
    }

    #[test]
    fn error_display_escapes_control_chars() {
        let err = AwsHsmError::KeyNotFound("evil\nkey".into());
        let s = err.to_string();
        assert!(!s.contains('\n'));
    }
}
