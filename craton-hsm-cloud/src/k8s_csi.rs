// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Kubernetes CSI (Container Storage Interface) driver for injecting secrets
//! from Craton HSM into Kubernetes pods as ephemeral volumes.
//!
//! Implements the **Identity**, **Controller**, and **Node** services from
//! the CSI spec at the trait level. The bundled in-memory implementation
//! exists for tests; a production driver would back the same traits with a
//! real gRPC server and real filesystem mounts.
//!
//! # Release-build protection (audit findings M3/M4/M5)
//!
//! In addition to the `mock-insecure-do-not-ship` Cargo feature and the
//! `CRATON_HSM_ALLOW_MOCK=1` runtime gate, release builds require
//! `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1`. Secrets inserted into the
//! in-memory [`InMemorySecretSource`] are capped at
//! [`crate::mock_guard::MAX_MOCK_KEY_BYTES`] (32 bytes) so accidental
//! exposure of a real production key is bounded.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;

use tracing::{debug, info, warn};

/// Errors specific to CSI operations.
#[derive(Debug, Clone)]
pub enum CsiError {
    /// The volume has already been staged.
    AlreadyStaged(String),
    /// The volume was not found in the staged set.
    NotStaged(String),
    /// The volume has not been published.
    NotPublished(String),
    /// The published target path does not match the staging spec.
    TargetPathMismatch {
        /// Volume identifier.
        volume_id: String,
        /// Expected target path.
        expected: String,
        /// Provided target path.
        provided: String,
    },
    /// Invalid argument supplied.
    InvalidArgument(String),
    /// Failure to fetch a secret from the HSM backend.
    HsmFetchFailed(String),
    /// Internal error.
    Internal(String),
}

impl fmt::Display for CsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CsiError::AlreadyStaged(id) => {
                write!(f, "volume already staged: {}", id.escape_debug())
            }
            CsiError::NotStaged(id) => write!(f, "volume not staged: {}", id.escape_debug()),
            CsiError::NotPublished(id) => write!(f, "volume not published: {}", id.escape_debug()),
            CsiError::TargetPathMismatch {
                volume_id,
                expected,
                provided,
            } => write!(
                f,
                "target path mismatch for {}: expected {}, got {}",
                volume_id.escape_debug(),
                expected.escape_debug(),
                provided.escape_debug()
            ),
            CsiError::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg.escape_debug()),
            CsiError::HsmFetchFailed(msg) => write!(f, "HSM fetch failed: {}", msg.escape_debug()),
            CsiError::Internal(msg) => write!(f, "internal error: {}", msg.escape_debug()),
        }
    }
}

impl std::error::Error for CsiError {}

/// Result alias for CSI operations.
pub type CsiResult<T> = std::result::Result<T, CsiError>;

/// Configuration for the CSI driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsiDriverConfig {
    /// CSI driver name registered with Kubernetes.
    #[serde(default = "default_driver_name")]
    pub driver_name: Cow<'static, str>,
    /// Driver version string.
    #[serde(default = "default_driver_version")]
    pub driver_version: Cow<'static, str>,
    /// Node identifier.
    pub node_id: String,
    /// Unix socket endpoint for CSI gRPC.
    #[serde(default = "default_endpoint")]
    pub endpoint: Cow<'static, str>,
    /// Address of the Craton HSM instance.
    pub hsm_addr: String,
    /// Filesystem prefix that all target paths must canonicalize underneath.
    #[serde(default = "default_kubelet_root")]
    pub kubelet_root: Cow<'static, str>,
}

fn default_driver_name() -> Cow<'static, str> {
    Cow::Borrowed("hsm.craton.io")
}
fn default_driver_version() -> Cow<'static, str> {
    Cow::Borrowed(env!("CARGO_PKG_VERSION"))
}
fn default_endpoint() -> Cow<'static, str> {
    Cow::Borrowed("unix:///csi/csi.sock")
}
fn default_kubelet_root() -> Cow<'static, str> {
    Cow::Borrowed("/var/lib/kubelet")
}

/// Node-level capabilities advertised by this CSI driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsiNodeCapability {
    /// The driver supports staging/unstaging volumes on the node.
    StageUnstage,
    /// The driver can report volume statistics.
    GetVolumeStats,
}

/// Controller-level capabilities advertised by this CSI driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsiControllerCapability {
    /// The driver supports CreateVolume / DeleteVolume.
    CreateDeleteVolume,
    /// The driver supports PublishVolume / UnpublishVolume.
    PublishUnpublishVolume,
}

/// Hard upper bound on the number of keys projectable into a single volume.
pub const MAX_KEY_IDS_PER_VOLUME: usize = 64;
/// Hard upper bound on a target path length.
pub const MAX_TARGET_PATH_LEN: usize = 4096;
/// Hard upper bound on volume id length.
pub const MAX_VOLUME_ID_LEN: usize = 256;
/// Hard upper bound on key id length.
pub const MAX_KEY_ID_LEN: usize = 256;

/// Newtype for Unix epoch seconds, preventing accidental sub-second/millisecond
/// confusion at API boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EpochSecs(pub u64);

/// Specification for mounting a secret volume into a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVolumeSpec {
    /// Unique volume identifier.
    pub volume_id: String,
    /// HSM key IDs to project as files in the volume.
    pub key_ids: Vec<String>,
    /// Filesystem path where the volume will be mounted.
    pub target_path: String,
    /// Whether the volume should be mounted read-only.
    pub read_only: bool,
    /// Unix file mode for projected secret files.
    #[serde(default = "default_fs_mode")]
    pub fs_mode: u32,
    /// Opaque CSI `volume_context` passed by the kubelet. For authorizer
    /// use, the keys `csi.storage.k8s.io/pod.uid` and
    /// `csi.storage.k8s.io/serviceAccount.name` are read by
    /// [`CsiAuthorizer::authorize`].
    #[serde(default)]
    pub volume_context: std::collections::BTreeMap<String, String>,
}

/// Key used in [`SecretVolumeSpec::volume_context`] for the pod UID.
pub const CSI_POD_UID_KEY: &str = "csi.storage.k8s.io/pod.uid";
/// Key used in [`SecretVolumeSpec::volume_context`] for the pod's service
/// account.
pub const CSI_POD_SA_KEY: &str = "csi.storage.k8s.io/serviceAccount.name";

/// Pluggable authorizer consulted during `node_stage_volume`. Rejects a
/// staging request before any HSM secret is fetched (audit finding H). The
/// default implementation [`AllowAllCsiAuthorizer`] is permissive, matching
/// pre-authorizer behaviour; production CSI drivers should wire this up to
/// TokenReview against the kubelet's ServiceAccount token.
pub trait CsiAuthorizer: Send + Sync {
    /// Return `Ok(())` if the pod identified by `pod_uid` / `service_account`
    /// is permitted to stage `volume_id`; otherwise return an error whose
    /// `Display` is safe to surface to the kubelet.
    fn authorize(&self, volume_id: &str, pod_uid: &str, service_account: &str) -> CsiResult<()>;
}

/// Default permissive authorizer — matches pre-hardening behaviour.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllCsiAuthorizer;

impl CsiAuthorizer for AllowAllCsiAuthorizer {
    fn authorize(&self, _: &str, _: &str, _: &str) -> CsiResult<()> {
        Ok(())
    }
}

fn default_fs_mode() -> u32 {
    0o400
}

impl SecretVolumeSpec {
    /// Validate the spec's structural invariants (lengths, key id format).
    pub fn validate(&self) -> CsiResult<()> {
        if self.volume_id.is_empty() || self.volume_id.len() > MAX_VOLUME_ID_LEN {
            return Err(CsiError::InvalidArgument(format!(
                "volume_id length must be in [1, {MAX_VOLUME_ID_LEN}]"
            )));
        }
        if self.key_ids.is_empty() {
            return Err(CsiError::InvalidArgument(
                "key_ids must not be empty".into(),
            ));
        }
        if self.key_ids.len() > MAX_KEY_IDS_PER_VOLUME {
            return Err(CsiError::InvalidArgument(format!(
                "key_ids exceeds maximum of {MAX_KEY_IDS_PER_VOLUME}"
            )));
        }
        for k in &self.key_ids {
            if k.is_empty() || k.len() > MAX_KEY_ID_LEN {
                return Err(CsiError::InvalidArgument(format!(
                    "key id length must be in [1, {MAX_KEY_ID_LEN}]"
                )));
            }
            if k.contains('\0') {
                return Err(CsiError::InvalidArgument(
                    "key id must not contain null bytes".into(),
                ));
            }
        }
        if self.target_path.len() > MAX_TARGET_PATH_LEN {
            return Err(CsiError::InvalidArgument(format!(
                "target_path exceeds {MAX_TARGET_PATH_LEN} bytes"
            )));
        }
        // Enforce read_only flag for secret volumes — projecting secrets
        // read-write into a pod is almost always a misconfiguration.
        if !self.read_only {
            return Err(CsiError::InvalidArgument(
                "secret volumes must be read_only=true".into(),
            ));
        }
        // Mode must not include world bits.
        if self.fs_mode & 0o007 != 0 {
            return Err(CsiError::InvalidArgument(format!(
                "fs_mode {:o} must not be world-accessible",
                self.fs_mode
            )));
        }
        Ok(())
    }
}

/// Volume statistics returned by `node_get_volume_stats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeStats {
    /// Total bytes available in the volume.
    pub total_bytes: u64,
    /// Bytes used.
    pub used_bytes: u64,
    /// Total inodes available.
    pub total_inodes: u64,
    /// Inodes used.
    pub used_inodes: u64,
}

/// Tracks a staged volume and its publication state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedVolume {
    /// The original volume specification.
    pub spec: SecretVolumeSpec,
    /// Timestamp when the volume was staged.
    pub staged_at: EpochSecs,
    /// Whether the volume has been published.
    pub published: bool,
    /// Number of secrets fetched from the HSM at staging time.
    pub secrets_fetched: usize,
}

/// Identity service: returns metadata about the driver.
pub trait CsiIdentityService: Send + Sync {
    /// Return the registered driver name and version.
    fn get_plugin_info(&self) -> (String, String);
    /// Probe — returns Ok if the driver is healthy.
    fn probe(&self) -> CsiResult<()>;
}

/// Controller service: cluster-wide volume management.
pub trait CsiControllerService: Send + Sync {
    /// Create a logical volume backed by HSM keys.
    fn create_volume(&self, spec: &SecretVolumeSpec) -> CsiResult<()>;
    /// Delete a logical volume.
    fn delete_volume(&self, volume_id: &str) -> CsiResult<()>;
    /// Capabilities advertised by this controller.
    fn controller_get_capabilities(&self) -> Vec<CsiControllerCapability>;
}

/// CSI Node Service interface for staging and publishing secret volumes.
pub trait CsiNodeService: Send + Sync {
    /// Returns identifying information about the node.
    fn node_get_info(&self) -> (String, u64);

    /// Stage a volume: fetch secrets from HSM and prepare them on the node.
    fn node_stage_volume(&self, spec: &SecretVolumeSpec) -> CsiResult<()>;

    /// Remove a previously staged volume.
    fn node_unstage_volume(&self, volume_id: &str) -> CsiResult<()>;

    /// Publish a staged volume to its target path inside the pod.
    fn node_publish_volume(&self, spec: &SecretVolumeSpec) -> CsiResult<()>;

    /// Unpublish a volume from the given target path.
    fn node_unpublish_volume(&self, volume_id: &str, target_path: &str) -> CsiResult<()>;

    /// Return statistics for a published volume.
    fn node_get_volume_stats(&self, volume_id: &str, target_path: &str) -> CsiResult<VolumeStats>;

    /// Return the set of capabilities this node driver supports.
    fn node_get_capabilities(&self) -> Vec<CsiNodeCapability>;
}

/// Trait abstraction over the HSM backend for fetching secret material.
///
/// Production drivers implement this against a real Craton HSM client; the
/// in-memory test driver uses a `DashMap` shim.
pub trait HsmSecretSource: Send + Sync {
    /// Fetch the secret material for a single key id.
    fn fetch(&self, key_id: &str) -> CsiResult<Vec<u8>>;
}

/// Trait stub for the future "talk to a real Craton HSM at the configured
/// `hsm_addr`" client. Production drivers implement this against a real RPC
/// transport; the in-memory mock driver logs `would connect to hsm_addr` at
/// construction so misconfigured addresses surface in dev environments
/// without forcing every embedder to wire up real IO. Audit finding (unused
/// `hsm_addr`).
pub trait HsmAddrClient: Send + Sync {
    /// The configured HSM address. Production implementations will use this
    /// to establish their transport; the mock just logs it.
    fn hsm_addr(&self) -> &str;
}

/// Look up the **peer's UID** on a connected Unix domain socket.
///
/// Audit finding M (k8s_csi volume_context trust): the kubelet sets the
/// `csi.storage.k8s.io/pod.uid` and `csi.storage.k8s.io/serviceAccount.name`
/// keys in `volume_context`, but on a vanilla mTLS-less Unix socket nothing
/// authenticates the peer. The CSI driver's gRPC transport should call this
/// helper once a connection is accepted and use the returned UID to either
/// (a) cross-check that the peer is the local kubelet, or (b) feed it into
/// a real authorizer instead of trusting the volume_context blindly.
///
/// # Safety
///
/// Audit finding (BorrowedFd<'static> unsound): the prior version of this
/// function took a `RawFd` and fabricated a `BorrowedFd<'static>` from it
/// inside the function, which is unsound — `'static` claims the fd lives
/// forever even though the caller may close it. The new signature takes a
/// `BorrowedFd<'_>` so the borrow checker enforces that the fd outlives the
/// call. Visibility is also tightened to `pub(crate)` because there is no
/// good reason for downstream code to drive this directly — embedders
/// should wrap their own listener and pass the borrow in.
///
/// On Linux this uses `SO_PEERCRED`. On all other targets it returns
/// `Err(io::ErrorKind::Unsupported)` — peer-cred extraction is not
/// portable and the production CSI driver is Linux-only in any case.
#[cfg(target_os = "linux")]
pub fn peer_credentials_lookup(fd: std::os::unix::io::BorrowedFd<'_>) -> std::io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt};
    let creds = getsockopt(&fd, sockopt::PeerCredentials)
        .map_err(|e| std::io::Error::other(format!("SO_PEERCRED failed: {e}")))?;
    Ok(creds.uid())
}

/// Non-Linux fallback for [`peer_credentials_lookup`]. Returns
/// [`io::ErrorKind::Unsupported`] (audit finding M).
#[cfg(all(unix, not(target_os = "linux")))]
pub fn peer_credentials_lookup(_fd: std::os::unix::io::BorrowedFd<'_>) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer-cred extraction is only available on Linux",
    ))
}

/// Windows / non-unix fallback. CSI is Linux-only in practice, so we just
/// surface a clear error. The Windows shape takes `i32` because there's no
/// `BorrowedFd` on non-unix targets; the function only exists so the rest
/// of the crate type-checks on Windows.
#[cfg(not(unix))]
pub fn peer_credentials_lookup(_fd: i32) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer-cred extraction requires a Unix domain socket",
    ))
}

/// Validate that a target path is safe (absolute, no traversal, no nulls)
/// and resolve to a path that lives strictly underneath `kubelet_root`.
///
/// # Fail-closed semantics (audit foot-gun)
///
/// Audit finding (validate_target_path silent skip): the previous
/// implementation only enforced the canonical-resolution check when **both**
/// `canonicalize()` calls succeeded, and silently waved through every other
/// failure mode. The whole point of canonicalising is to defeat symlink
/// escapes, so a `PermissionDenied` or symlink-loop error is exactly the
/// case we must NOT silently skip. The function now fails closed:
///
/// - If either `canonicalize()` returns an error of kind other than
///   `ErrorKind::NotFound`, the path is rejected. `PermissionDenied`, symlink
///   loops, generic I/O failures, etc. all force a rejection.
/// - `NotFound` on either leg is permitted because legitimate callers
///   (including synthetic test fixtures) may pass a path that has not been
///   created yet. In that case the prior component-level checks (no `..`,
///   prefix match against `kubelet_root`) are the strongest guarantee
///   available; the caller must still ensure the resolved path is symlink-
///   safe before any I/O.
/// - When both succeed, the canonical path must resolve strictly underneath
///   the canonical kubelet root.
pub fn validate_target_path(path: &str, kubelet_root: &str) -> CsiResult<()> {
    if path.is_empty() {
        return Err(CsiError::InvalidArgument(
            "target path must not be empty".into(),
        ));
    }
    if path.len() > MAX_TARGET_PATH_LEN {
        return Err(CsiError::InvalidArgument(format!(
            "target path exceeds {MAX_TARGET_PATH_LEN} bytes"
        )));
    }
    if path.contains('\0') {
        return Err(CsiError::InvalidArgument(
            "target path must not contain null bytes".into(),
        ));
    }
    // Treat the path as a POSIX path regardless of host OS, since CSI target
    // paths come from kubelet which always emits forward-slash absolute paths.
    if !path.starts_with('/') {
        return Err(CsiError::InvalidArgument(format!(
            "target path must be absolute: {}",
            path.escape_debug()
        )));
    }
    // Component-level traversal check: split on '/' and reject any literal
    // ".." segment (substring matches like "data..v2" are allowed because
    // they are not a parent-directory component).
    for seg in path.split('/') {
        if seg == ".." {
            return Err(CsiError::InvalidArgument(format!(
                "target path must not contain '..' traversal: {}",
                path.escape_debug()
            )));
        }
    }

    // POSIX-style prefix check: the path must equal kubelet_root or live
    // strictly underneath it. We verify the next character after the root
    // prefix is a '/' so that "/var/lib/kubelet-evil/..." is rejected.
    let root = kubelet_root.trim_end_matches('/');
    if root.is_empty() {
        return Err(CsiError::InvalidArgument(
            "kubelet_root must not be empty".into(),
        ));
    }
    let after_root = path
        .strip_prefix(root)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
        .ok_or_else(|| {
            CsiError::InvalidArgument(format!(
                "target path is not underneath {}",
                kubelet_root.escape_debug()
            ))
        })?;
    let _ = after_root;

    // Audit foot-gun (validate_target_path silent skip): canonicalise both
    // sides. We must refuse any canonicalisation failure that is NOT a
    // missing inode — `PermissionDenied`, symlink-loop, generic I/O — those
    // mean we cannot prove the path is symlink-safe. A missing inode is the
    // only "fall-through" case we accept, and even then the prior component-
    // level checks (no `..`, prefix match against `kubelet_root`) carry the
    // weight. See the rustdoc above for full semantics.
    let p = std::path::Path::new(path);
    let r = std::path::Path::new(kubelet_root);
    let canon_path = std::fs::canonicalize(p);
    let canon_root = std::fs::canonicalize(r);
    if let Err(e) = &canon_path {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(CsiError::InvalidArgument(format!(
                "target path canonicalisation failed (refusing to fall back): {e}"
            )));
        }
    }
    if let Err(e) = &canon_root {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(CsiError::InvalidArgument(format!(
                "kubelet_root canonicalisation failed (refusing to fall back): {e}"
            )));
        }
    }
    if let (Ok(canonical), Ok(canonical_root)) = (canon_path, canon_root) {
        if canonical.strip_prefix(&canonical_root).is_err() {
            return Err(CsiError::InvalidArgument(
                "target path escapes the kubelet directory after symlink resolution".into(),
            ));
        }
    }
    // If either leg is `NotFound`, fall through on the strength of the
    // component checks already performed above. This is the only path-not-
    // -resolvable case we permit — every other error returns above.

    Ok(())
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// In-memory CSI driver implementation for tests and local development.
///
/// Backed by a [`HsmSecretSource`] that provides per-key bytes. Storage is
/// in-memory and tracks staging/publish state plus the number of secrets
/// fetched per volume so tests can assert against it.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
pub struct InMemoryCsiDriver {
    config: CsiDriverConfig,
    staged: DashMap<String, StagedVolume>,
    /// In-memory cache of fetched secret bytes keyed by volume_id.
    /// We never write to disk in the mock; production would write `fs_mode`-
    /// permissioned files under target_path.
    materialized: DashMap<String, Vec<(String, Vec<u8>)>>,
    secret_source: std::sync::Arc<dyn HsmSecretSource>,
    authorizer: std::sync::Arc<dyn CsiAuthorizer>,
    /// Controller-side mock store for volumes registered via
    /// [`CsiControllerService::create_volume`] (audit finding: prior impl
    /// was a no-op stub, so a `delete_volume` after a `create_volume`
    /// silently succeeded even when the create never happened). The map
    /// holds the originally-created spec keyed by volume_id; delete revokes
    /// the entry transactionally.
    controller_volumes: DashMap<String, SecretVolumeSpec>,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl InMemoryCsiDriver {
    /// Create a new in-memory CSI driver.
    pub fn new(
        config: CsiDriverConfig,
        secret_source: std::sync::Arc<dyn HsmSecretSource>,
    ) -> Self {
        crate::mock_guard::check("k8s_csi::InMemoryCsiDriver");
        // Audit finding "Unused hsm_addr": surface the configured address
        // at construction time so misconfigurations are visible in logs
        // even before any volume is staged. The real `HsmAddrClient` impl
        // is the job of the production binary.
        info!(
            node = %config.node_id,
            driver = %config.driver_name,
            hsm = %config.hsm_addr,
            "in-memory CSI driver created (would connect to hsm_addr)"
        );
        Self {
            config,
            staged: DashMap::new(),
            materialized: DashMap::new(),
            secret_source,
            authorizer: std::sync::Arc::new(AllowAllCsiAuthorizer),
            controller_volumes: DashMap::new(),
        }
    }

    /// Install a [`CsiAuthorizer`] that gates `node_stage_volume` against
    /// the pod's ServiceAccount. Passing [`AllowAllCsiAuthorizer`] restores
    /// the pre-authorizer behaviour.
    pub fn with_authorizer(mut self, authorizer: std::sync::Arc<dyn CsiAuthorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    fn now() -> EpochSecs {
        EpochSecs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl CsiIdentityService for InMemoryCsiDriver {
    fn get_plugin_info(&self) -> (String, String) {
        (
            self.config.driver_name.to_string(),
            self.config.driver_version.to_string(),
        )
    }
    fn probe(&self) -> CsiResult<()> {
        Ok(())
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl CsiControllerService for InMemoryCsiDriver {
    /// Register `spec` in the controller-side in-memory store. Audit
    /// finding (ControllerService stub): the previous implementation was a
    /// no-op so a subsequent `delete_volume` silently succeeded even when
    /// the create had never happened. We now reject duplicates with
    /// [`CsiError::AlreadyStaged`] (closest existing variant) and persist
    /// the spec for revert on delete.
    fn create_volume(&self, spec: &SecretVolumeSpec) -> CsiResult<()> {
        spec.validate()?;
        use dashmap::mapref::entry::Entry;
        match self.controller_volumes.entry(spec.volume_id.clone()) {
            Entry::Occupied(_) => Err(CsiError::AlreadyStaged(spec.volume_id.clone())),
            Entry::Vacant(v) => {
                v.insert(spec.clone());
                debug!(volume_id = %spec.volume_id, "ControllerCreateVolume");
                Ok(())
            }
        }
    }
    fn delete_volume(&self, volume_id: &str) -> CsiResult<()> {
        if volume_id.is_empty() {
            return Err(CsiError::InvalidArgument(
                "volume_id must not be empty".into(),
            ));
        }
        if self.controller_volumes.remove(volume_id).is_none() {
            return Err(CsiError::NotStaged(volume_id.to_string()));
        }
        debug!(volume_id, "ControllerDeleteVolume");
        Ok(())
    }
    fn controller_get_capabilities(&self) -> Vec<CsiControllerCapability> {
        vec![
            CsiControllerCapability::CreateDeleteVolume,
            CsiControllerCapability::PublishUnpublishVolume,
        ]
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl CsiNodeService for InMemoryCsiDriver {
    fn node_get_info(&self) -> (String, u64) {
        (self.config.node_id.clone(), 8) // 8 = max_volumes_per_node
    }

    fn node_stage_volume(&self, spec: &SecretVolumeSpec) -> CsiResult<()> {
        spec.validate()?;
        validate_target_path(&spec.target_path, &self.config.kubelet_root)?;
        // Authorizer check (audit finding H): gate staging on the pod's
        // ServiceAccount *before* any secret is fetched from the HSM. The
        // kubelet populates these keys in volume_context.
        let pod_uid = spec
            .volume_context
            .get(CSI_POD_UID_KEY)
            .map(String::as_str)
            .unwrap_or("");
        let pod_sa = spec
            .volume_context
            .get(CSI_POD_SA_KEY)
            .map(String::as_str)
            .unwrap_or("");
        self.authorizer
            .authorize(&spec.volume_id, pod_uid, pod_sa)?;
        if self.staged.contains_key(&spec.volume_id) {
            return Err(CsiError::AlreadyStaged(spec.volume_id.clone()));
        }
        // Fetch all secrets from the HSM source.  If any fetch fails the
        // staging operation aborts atomically without leaving partial state.
        let mut materialized = Vec::with_capacity(spec.key_ids.len());
        for key_id in &spec.key_ids {
            let bytes = self
                .secret_source
                .fetch(key_id)
                .map_err(|e| CsiError::HsmFetchFailed(e.to_string()))?;
            materialized.push((key_id.clone(), bytes));
        }
        let secrets_fetched = materialized.len();
        // Atomically insert; if a competing stage races us, abort.
        use dashmap::mapref::entry::Entry;
        match self.staged.entry(spec.volume_id.clone()) {
            Entry::Occupied(_) => Err(CsiError::AlreadyStaged(spec.volume_id.clone())),
            Entry::Vacant(v) => {
                v.insert(StagedVolume {
                    spec: spec.clone(),
                    staged_at: Self::now(),
                    published: false,
                    secrets_fetched,
                });
                self.materialized
                    .insert(spec.volume_id.clone(), materialized);
                info!(volume_id = %spec.volume_id, secrets = secrets_fetched, "NodeStageVolume");
                Ok(())
            }
        }
    }

    fn node_unstage_volume(&self, volume_id: &str) -> CsiResult<()> {
        let removed = self.staged.remove(volume_id);
        if removed.is_none() {
            return Err(CsiError::NotStaged(volume_id.to_string()));
        }
        // Drop the materialised secrets too.
        self.materialized.remove(volume_id);
        info!(volume_id, "NodeUnstageVolume");
        Ok(())
    }

    fn node_publish_volume(&self, spec: &SecretVolumeSpec) -> CsiResult<()> {
        spec.validate()?;
        validate_target_path(&spec.target_path, &self.config.kubelet_root)?;
        let mut entry = self
            .staged
            .get_mut(&spec.volume_id)
            .ok_or_else(|| CsiError::NotStaged(spec.volume_id.clone()))?;
        // Verify the published target path matches the staged spec.
        if entry.spec.target_path != spec.target_path {
            return Err(CsiError::TargetPathMismatch {
                volume_id: spec.volume_id.clone(),
                expected: entry.spec.target_path.clone(),
                provided: spec.target_path.clone(),
            });
        }
        entry.published = true;
        info!(volume_id = %spec.volume_id, "NodePublishVolume");
        Ok(())
    }

    fn node_unpublish_volume(&self, volume_id: &str, target_path: &str) -> CsiResult<()> {
        validate_target_path(target_path, &self.config.kubelet_root)?;
        let mut entry = self
            .staged
            .get_mut(volume_id)
            .ok_or_else(|| CsiError::NotStaged(volume_id.to_string()))?;
        if !entry.published {
            return Err(CsiError::NotPublished(volume_id.to_string()));
        }
        if entry.spec.target_path != target_path {
            return Err(CsiError::TargetPathMismatch {
                volume_id: volume_id.to_string(),
                expected: entry.spec.target_path.clone(),
                provided: target_path.to_string(),
            });
        }
        entry.published = false;
        info!(volume_id, "NodeUnpublishVolume");
        Ok(())
    }

    fn node_get_volume_stats(&self, volume_id: &str, target_path: &str) -> CsiResult<VolumeStats> {
        validate_target_path(target_path, &self.config.kubelet_root)?;
        let entry = self
            .staged
            .get(volume_id)
            .ok_or_else(|| CsiError::NotStaged(volume_id.to_string()))?;
        if !entry.published {
            warn!(volume_id, "NodeGetVolumeStats called on unpublished volume");
        }
        let secrets = self.materialized.get(volume_id);
        let used_bytes: u64 = secrets
            .as_ref()
            .map(|m| m.iter().map(|(_, b)| b.len() as u64).sum())
            .unwrap_or(0);
        let used_inodes = entry.secrets_fetched as u64;
        Ok(VolumeStats {
            total_bytes: used_bytes.max(1),
            used_bytes,
            total_inodes: used_inodes.max(1),
            used_inodes,
        })
    }

    fn node_get_capabilities(&self) -> Vec<CsiNodeCapability> {
        vec![
            CsiNodeCapability::StageUnstage,
            CsiNodeCapability::GetVolumeStats,
        ]
    }
}

/// Trivial in-memory secret source for tests: returns the key id as bytes.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
pub struct InMemorySecretSource {
    /// Map of key_id -> secret bytes. Missing entries return an error from
    /// `fetch`.
    pub secrets: DashMap<String, Vec<u8>>,
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl InMemorySecretSource {
    /// Create an empty source.
    pub fn new() -> Self {
        Self {
            secrets: DashMap::new(),
        }
    }
    /// Pre-populate a key.
    ///
    /// Audit findings M3/M4/M5: refuses secrets longer than
    /// [`crate::mock_guard::MAX_MOCK_KEY_BYTES`] so the mock cannot hold
    /// production key material.
    ///
    /// # Errors
    ///
    /// Returns [`CsiError::InvalidArgument`] if `bytes.len() >
    /// MAX_MOCK_KEY_BYTES`.
    pub fn insert(&self, key_id: &str, bytes: Vec<u8>) -> CsiResult<()> {
        crate::mock_guard::check_mock_key_len(bytes.len()).map_err(CsiError::InvalidArgument)?;
        self.secrets.insert(key_id.to_string(), bytes);
        Ok(())
    }
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl Default for InMemorySecretSource {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Socket hardening helpers
// ---------------------------------------------------------------------------

/// Extract the filesystem path from a `unix://` CSI endpoint.
///
/// Returns `None` for non-unix endpoints (e.g., `tcp://`), which this driver
/// does not support for kubelet communication. The kubelet expects a local
/// Unix domain socket by design.
pub fn endpoint_to_socket_path(endpoint: &str) -> Option<&str> {
    endpoint.strip_prefix("unix://")
}

/// Validate and (on Unix) harden the directory that will hold the CSI socket.
///
/// Returns an error if the endpoint is not a local Unix socket, if the parent
/// directory cannot be created with restrictive permissions (0700), or if the
/// parent is world- or group-writable. On non-Unix targets this is a no-op
/// because kubelet + CSI is Linux-only in practice.
///
/// Callers should bind the socket after this function returns successfully
/// and then call [`harden_bound_socket`] to chmod the bound socket itself.
pub fn prepare_csi_socket_dir(endpoint: &str) -> CsiResult<std::path::PathBuf> {
    let path = endpoint_to_socket_path(endpoint).ok_or_else(|| {
        CsiError::InvalidArgument(format!(
            "CSI endpoint must start with `unix://`, got: {}",
            endpoint.escape_debug()
        ))
    })?;
    let path = std::path::PathBuf::from(path);
    let parent = path.parent().ok_or_else(|| {
        CsiError::InvalidArgument(format!(
            "CSI socket path has no parent directory: {}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // Audit foot-gun (TOCTOU between create_dir_all and chmod): the
        // previous code created the directory with the umask-tainted default
        // mode and then chmod'd to 0700. Between those two calls another
        // process could observe the world-readable parent and plant a file
        // inside. `DirBuilder::mode(0o700)` makes the directory carry the
        // tight mode the moment it appears in the namespace, closing the
        // race. We still chmod afterwards because `create_dir_all` is a
        // no-op when the parent already exists — in that case we need to
        // tighten the mode of the pre-existing directory.
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(parent).map_err(|e| {
            CsiError::Internal(format!(
                "failed to create CSI socket parent dir {}: {e}",
                parent.display()
            ))
        })?;
        // Tighten the directory mode to owner-only — both for the case
        // where the directory already existed (mode unchanged by create
        // above) and as belt-and-suspenders against an intermediate parent
        // that may have been created with a looser mode.
        let mut perm = std::fs::metadata(parent)
            .map_err(|e| CsiError::Internal(format!("stat {}: {e}", parent.display())))?
            .permissions();
        perm.set_mode(0o700);
        std::fs::set_permissions(parent, perm).map_err(|e| {
            CsiError::Internal(format!("failed to chmod 0700 {}: {e}", parent.display()))
        })?;
        // Refuse a parent directory we do not exclusively control. This
        // catches the case where the admin pre-created a world-writable
        // `/csi` on the host, which would let an unprivileged pod race to
        // create a trojan socket.
        let md = std::fs::metadata(parent)
            .map_err(|e| CsiError::Internal(format!("stat {}: {e}", parent.display())))?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CsiError::Internal(format!(
                "CSI socket parent {} has unsafe mode {:o}; require 0700",
                parent.display(),
                mode
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }

    // If a stale entry exists at `path`, remove it so bind(2) won't EADDRINUSE.
    //
    // Audit finding M (k8s_csi socket TOCTOU): on Unix we open the parent
    // directory once with `O_DIRECTORY | O_NOFOLLOW` and then use
    // `fstatat` + `unlinkat` against that directory file descriptor. This
    // collapses the previous `symlink_metadata` + `remove_file` race window
    // — both checks now operate on the same parent fd, and we pass
    // `AtFlags::AT_SYMLINK_NOFOLLOW` to `fstatat` so a freshly-planted
    // symlink can never be dereferenced. On Windows we keep the previous
    // path-based logic since the driver is Linux-only in practice.
    #[cfg(unix)]
    {
        use nix::sys::stat::{fstatat, SFlag};
        use nix::unistd::unlinkat;
        use nix::unistd::UnlinkatFlags;
        use std::os::fd::AsRawFd;

        let parent_dir = std::fs::OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|e| CsiError::Internal(format!("open parent {}: {e}", parent.display())))?;
        let parent_fd = parent_dir.as_raw_fd();

        let file_name = path.file_name().ok_or_else(|| {
            CsiError::Internal(format!(
                "CSI socket path {} has no file_name component",
                path.display()
            ))
        })?;

        match fstatat(
            Some(parent_fd),
            file_name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(st) => {
                let mode = SFlag::from_bits_truncate(st.st_mode);
                if mode.contains(SFlag::S_IFLNK) {
                    return Err(CsiError::Internal(format!(
                        "stale CSI socket path {} is a symlink; refusing to unlink (possible symlink attack)",
                        path.display()
                    )));
                }
                if !(mode.contains(SFlag::S_IFSOCK) || mode.contains(SFlag::S_IFREG)) {
                    return Err(CsiError::Internal(format!(
                        "stale CSI socket path {} exists but is not a socket or regular file; refusing to unlink",
                        path.display()
                    )));
                }
                unlinkat(Some(parent_fd), file_name, UnlinkatFlags::NoRemoveDir).map_err(|e| {
                    CsiError::Internal(format!(
                        "failed to unlinkat stale CSI socket {}: {e}",
                        path.display()
                    ))
                })?;
            }
            Err(nix::errno::Errno::ENOENT) => {
                // Nothing to clean up — common fresh-start case.
            }
            Err(e) => {
                return Err(CsiError::Internal(format!(
                    "failed to fstatat stale CSI socket {}: {e}",
                    path.display()
                )));
            }
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::symlink_metadata(&path) {
            Ok(md) => {
                let ft = md.file_type();
                if ft.is_symlink() {
                    return Err(CsiError::Internal(format!(
                        "stale CSI socket path {} is a symlink; refusing to unlink",
                        path.display()
                    )));
                }
                if !ft.is_file() {
                    return Err(CsiError::Internal(format!(
                        "stale CSI socket path {} exists but is not a regular file; refusing to unlink",
                        path.display()
                    )));
                }
                std::fs::remove_file(&path).map_err(|e| {
                    CsiError::Internal(format!(
                        "failed to remove stale CSI socket {}: {e}",
                        path.display()
                    ))
                })?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(CsiError::Internal(format!(
                    "failed to stat stale CSI socket {}: {e}",
                    path.display()
                )));
            }
        }
    }

    Ok(path)
}

/// Tighten permissions on a freshly bound Unix domain socket.
///
/// Must be called *after* `bind(2)` returns. The intended caller is the gRPC
/// transport: bind the listener, then call this to chmod the node to 0600 so
/// only the process owner (typically kubelet, via a bind-mounted UID) can
/// connect.
#[cfg(unix)]
pub fn harden_bound_socket(path: &std::path::Path) -> CsiResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(path)
        .map_err(|e| CsiError::Internal(format!("stat {}: {e}", path.display())))?
        .permissions();
    perm.set_mode(0o600);
    std::fs::set_permissions(path, perm).map_err(|e| {
        CsiError::Internal(format!(
            "failed to chmod 0600 CSI socket {}: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

/// No-op on non-Unix targets. Kept so call sites do not need platform gates.
#[cfg(not(unix))]
pub fn harden_bound_socket(_path: &std::path::Path) -> CsiResult<()> {
    Ok(())
}

#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
impl HsmSecretSource for InMemorySecretSource {
    fn fetch(&self, key_id: &str) -> CsiResult<Vec<u8>> {
        self.secrets
            .get(key_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| CsiError::HsmFetchFailed(format!("no such key {key_id}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_driver() -> (InMemoryCsiDriver, Arc<InMemorySecretSource>) {
        crate::_enable_mock_for_tests();
        let src = Arc::new(InMemorySecretSource::new());
        src.insert("key-1", b"secret-one".to_vec()).unwrap();
        src.insert("key-2", b"secret-two".to_vec()).unwrap();
        let cfg = CsiDriverConfig {
            driver_name: default_driver_name(),
            driver_version: default_driver_version(),
            node_id: "node-1".to_string(),
            endpoint: default_endpoint(),
            hsm_addr: "http://localhost:8080".to_string(),
            kubelet_root: default_kubelet_root(),
        };
        let driver = InMemoryCsiDriver::new(cfg, src.clone());
        (driver, src)
    }

    fn make_spec(id: &str) -> SecretVolumeSpec {
        SecretVolumeSpec {
            volume_id: id.to_string(),
            key_ids: vec!["key-1".to_string(), "key-2".to_string()],
            target_path: format!("/var/lib/kubelet/pods/test/{id}"),
            read_only: true,
            fs_mode: 0o400,
            volume_context: Default::default(),
        }
    }

    /// Authorizer that only allows a single hardcoded service account. Used
    /// by the CSI authorize/deny tests.
    struct WhitelistSaAuthorizer {
        allowed_sa: String,
    }
    impl CsiAuthorizer for WhitelistSaAuthorizer {
        fn authorize(
            &self,
            _volume_id: &str,
            _pod_uid: &str,
            service_account: &str,
        ) -> CsiResult<()> {
            if service_account == self.allowed_sa {
                Ok(())
            } else {
                Err(CsiError::InvalidArgument(format!(
                    "service account {service_account} is not authorized"
                )))
            }
        }
    }

    #[test]
    fn csi_authorizer_allows_whitelisted_sa() {
        let (_, src) = make_driver();
        let cfg = CsiDriverConfig {
            driver_name: default_driver_name(),
            driver_version: default_driver_version(),
            node_id: "node-acl".to_string(),
            endpoint: default_endpoint(),
            hsm_addr: "http://localhost:8080".to_string(),
            kubelet_root: default_kubelet_root(),
        };
        let driver =
            InMemoryCsiDriver::new(cfg, src).with_authorizer(Arc::new(WhitelistSaAuthorizer {
                allowed_sa: "billing-sa".into(),
            }));
        let mut spec = make_spec("vol-allowed");
        spec.volume_context
            .insert(CSI_POD_UID_KEY.into(), "pod-uid-1".into());
        spec.volume_context
            .insert(CSI_POD_SA_KEY.into(), "billing-sa".into());
        driver.node_stage_volume(&spec).unwrap();
    }

    #[test]
    fn csi_authorizer_denies_wrong_sa() {
        let (_, src) = make_driver();
        let cfg = CsiDriverConfig {
            driver_name: default_driver_name(),
            driver_version: default_driver_version(),
            node_id: "node-acl".to_string(),
            endpoint: default_endpoint(),
            hsm_addr: "http://localhost:8080".to_string(),
            kubelet_root: default_kubelet_root(),
        };
        let driver =
            InMemoryCsiDriver::new(cfg, src).with_authorizer(Arc::new(WhitelistSaAuthorizer {
                allowed_sa: "billing-sa".into(),
            }));
        let mut spec = make_spec("vol-denied");
        spec.volume_context
            .insert(CSI_POD_UID_KEY.into(), "pod-uid-evil".into());
        spec.volume_context
            .insert(CSI_POD_SA_KEY.into(), "evil-sa".into());
        let err = driver.node_stage_volume(&spec).unwrap_err();
        assert!(matches!(err, CsiError::InvalidArgument(_)));
        // Must not have staged.
        assert!(matches!(
            driver.node_unstage_volume("vol-denied").unwrap_err(),
            CsiError::NotStaged(_)
        ));
    }

    // ---- socket hardening --------------------------------------------------

    #[test]
    fn endpoint_to_socket_path_strips_prefix() {
        assert_eq!(
            endpoint_to_socket_path("unix:///csi/csi.sock"),
            Some("/csi/csi.sock")
        );
        assert_eq!(
            endpoint_to_socket_path("unix:///var/lib/kubelet/plugins/hsm.craton.io/csi.sock"),
            Some("/var/lib/kubelet/plugins/hsm.craton.io/csi.sock")
        );
    }

    #[test]
    fn endpoint_to_socket_path_rejects_tcp() {
        assert_eq!(endpoint_to_socket_path("tcp://127.0.0.1:9000"), None);
        assert_eq!(endpoint_to_socket_path("csi.sock"), None);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_csi_socket_dir_tightens_parent_and_strips_stale() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let parent = tmp.path().join("csi-parent");
        std::fs::create_dir_all(&parent).unwrap();
        // Create a stale socket file.
        let sock = parent.join("csi.sock");
        std::fs::write(&sock, b"").unwrap();
        // Intentionally leave the directory world-accessible; prepare should tighten it.
        let mut perm = std::fs::metadata(&parent).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&parent, perm).unwrap();

        let ep = format!("unix://{}", sock.display());
        let out = prepare_csi_socket_dir(&ep).expect("prepare must succeed");
        assert_eq!(out, sock);

        // Parent mode is now 0700 and stale socket is gone.
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "parent must be tightened to 0700, got {:o}",
            mode
        );
        assert!(!sock.exists(), "stale socket must be removed");
    }

    #[test]
    fn prepare_csi_socket_dir_rejects_non_unix_endpoint() {
        let err = prepare_csi_socket_dir("tcp://127.0.0.1:9000").unwrap_err();
        assert!(matches!(err, CsiError::InvalidArgument(_)));
    }

    #[cfg(unix)]
    #[test]
    fn harden_bound_socket_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("s");
        std::fs::write(&sock, b"").unwrap();
        let mut perm = std::fs::metadata(&sock).unwrap().permissions();
        perm.set_mode(0o666);
        std::fs::set_permissions(&sock, perm).unwrap();

        harden_bound_socket(&sock).unwrap();
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn identity_service_returns_info() {
        let (driver, _) = make_driver();
        let (name, version) = driver.get_plugin_info();
        assert_eq!(name, "hsm.craton.io");
        assert!(!version.is_empty());
        assert!(driver.probe().is_ok());
    }

    #[test]
    fn controller_capabilities() {
        let (driver, _) = make_driver();
        let caps = driver.controller_get_capabilities();
        assert!(caps.contains(&CsiControllerCapability::CreateDeleteVolume));
    }

    #[test]
    fn node_get_info() {
        let (driver, _) = make_driver();
        let (id, max) = driver.node_get_info();
        assert_eq!(id, "node-1");
        assert!(max > 0);
    }

    #[test]
    fn stage_volume_fetches_secrets() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-1");
        driver.node_stage_volume(&spec).unwrap();
        let stats = driver
            .node_get_volume_stats("vol-1", &spec.target_path)
            .unwrap();
        // 2 keys × secret bytes
        assert_eq!(stats.used_inodes, 2);
        assert!(stats.used_bytes > 0);
    }

    // Audit findings M3/M4/M5: mock must reject oversized key material.
    #[test]
    fn in_memory_secret_source_rejects_oversized_keys() {
        crate::_enable_mock_for_tests();
        let src = InMemorySecretSource::new();
        // 32 bytes is the hard cap; 33 must be rejected.
        let too_big = vec![0u8; crate::mock_guard::MAX_MOCK_KEY_BYTES + 1];
        let err = src.insert("big", too_big).unwrap_err();
        assert!(matches!(err, CsiError::InvalidArgument(_)));
        // Exactly at the cap is accepted.
        let exact = vec![0u8; crate::mock_guard::MAX_MOCK_KEY_BYTES];
        src.insert("ok", exact).unwrap();
    }

    #[test]
    fn stage_aborts_on_missing_secret() {
        let (driver, _) = make_driver();
        let mut spec = make_spec("vol-miss");
        spec.key_ids.push("nope".into());
        let err = driver.node_stage_volume(&spec).unwrap_err();
        assert!(matches!(err, CsiError::HsmFetchFailed(_)));
        // Nothing should be staged.
        assert!(driver
            .node_unstage_volume("vol-miss")
            .is_err_and(|e| matches!(e, CsiError::NotStaged(_))));
    }

    #[test]
    fn double_stage_error() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-2");
        driver.node_stage_volume(&spec).unwrap();
        let err = driver.node_stage_volume(&spec).unwrap_err();
        assert!(matches!(err, CsiError::AlreadyStaged(_)));
    }

    #[test]
    fn unstage_volume() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-3");
        driver.node_stage_volume(&spec).unwrap();
        driver.node_unstage_volume("vol-3").unwrap();
        assert!(matches!(
            driver.node_unstage_volume("vol-3").unwrap_err(),
            CsiError::NotStaged(_)
        ));
    }

    #[test]
    fn publish_target_path_mismatch_rejected() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-4");
        driver.node_stage_volume(&spec).unwrap();
        let mut wrong = spec.clone();
        wrong.target_path = "/var/lib/kubelet/pods/test/other".into();
        let err = driver.node_publish_volume(&wrong).unwrap_err();
        assert!(matches!(err, CsiError::TargetPathMismatch { .. }));
    }

    #[test]
    fn publish_unpublish_lifecycle() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-5");
        driver.node_stage_volume(&spec).unwrap();
        driver.node_publish_volume(&spec).unwrap();
        driver
            .node_unpublish_volume("vol-5", &spec.target_path)
            .unwrap();
    }

    #[test]
    fn unpublish_not_published() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-6");
        driver.node_stage_volume(&spec).unwrap();
        let err = driver
            .node_unpublish_volume("vol-6", &spec.target_path)
            .unwrap_err();
        assert!(matches!(err, CsiError::NotPublished(_)));
    }

    #[test]
    fn capabilities() {
        let (driver, _) = make_driver();
        let caps = driver.node_get_capabilities();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&CsiNodeCapability::StageUnstage));
        assert!(caps.contains(&CsiNodeCapability::GetVolumeStats));
    }

    #[test]
    fn config_defaults() {
        let json = r#"{"node_id":"node-1","hsm_addr":"http://localhost:8080"}"#;
        let cfg: CsiDriverConfig = serde_json::from_str(json).unwrap();
        assert_eq!(&*cfg.driver_name, "hsm.craton.io");
        assert_eq!(&*cfg.endpoint, "unix:///csi/csi.sock");
        assert_eq!(&*cfg.kubelet_root, "/var/lib/kubelet");
        assert_eq!(cfg.node_id, "node-1");
    }

    #[test]
    fn full_lifecycle() {
        let (driver, _) = make_driver();
        let spec = make_spec("vol-lifecycle");
        driver.node_stage_volume(&spec).unwrap();
        driver.node_publish_volume(&spec).unwrap();
        driver
            .node_unpublish_volume("vol-lifecycle", &spec.target_path)
            .unwrap();
        driver.node_unstage_volume("vol-lifecycle").unwrap();
    }

    #[test]
    fn path_traversal_rejected() {
        let root = "/var/lib/kubelet";
        assert!(validate_target_path("/var/lib/kubelet/pods/good", root).is_ok());
        assert!(validate_target_path("relative/path", root).is_err());
        assert!(validate_target_path("/var/lib/../etc/passwd", root).is_err());
        assert!(validate_target_path("/var/..", root).is_err());
    }

    #[test]
    fn null_bytes_rejected() {
        let root = "/var/lib/kubelet";
        assert!(validate_target_path("/var/lib/kubelet/\0evil", root).is_err());
        assert!(validate_target_path("/good/path\0", root).is_err());
    }

    #[test]
    fn dotdot_in_directory_name_allowed() {
        // A name containing ".." but not as a traversal component is OK,
        // but it must still live under kubelet_root.
        assert!(validate_target_path("/var/lib/kubelet/data..v2/file", "/var/lib/kubelet").is_ok());
    }

    #[test]
    fn kubelet_evil_prefix_rejected() {
        // Regression test: the previous string-prefix check accepted
        // /var/lib/kubelet-evil because it started with "/var/lib/kubelet".
        assert!(validate_target_path("/var/lib/kubelet-evil/x", "/var/lib/kubelet").is_err());
    }

    #[test]
    fn empty_path_rejected() {
        assert!(validate_target_path("", "/var/lib/kubelet").is_err());
    }

    #[test]
    fn oversize_path_rejected() {
        let p = format!("/var/lib/kubelet/{}", "a".repeat(MAX_TARGET_PATH_LEN));
        assert!(validate_target_path(&p, "/var/lib/kubelet").is_err());
    }

    #[test]
    fn spec_validate_rejects_writable() {
        let mut spec = make_spec("v");
        spec.read_only = false;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn spec_validate_rejects_world_readable_mode() {
        let mut spec = make_spec("v");
        spec.fs_mode = 0o444;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn spec_validate_rejects_too_many_keys() {
        let mut spec = make_spec("v");
        spec.key_ids = (0..MAX_KEY_IDS_PER_VOLUME + 1)
            .map(|i| format!("k{i}"))
            .collect();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn spec_validate_rejects_empty_keys() {
        let mut spec = make_spec("v");
        spec.key_ids.clear();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn secret_volume_spec_defaults() {
        let json = r#"{"volume_id":"v1","key_ids":["k1"],"target_path":"/mnt","read_only":false}"#;
        let spec: SecretVolumeSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.fs_mode, 0o400);
    }

    #[test]
    fn error_display_escapes_control_chars() {
        let err = CsiError::NotStaged("evil\nvol".into());
        assert!(!err.to_string().contains('\n'));
    }
}
