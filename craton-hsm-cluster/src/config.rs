// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Cluster configuration types with serde defaults.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// How key-material changes are replicated across the cluster.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationMode {
    /// Wait for all peers to acknowledge before returning success.
    #[default]
    Synchronous,
    /// Fire-and-forget — the leader does not wait for peer acknowledgement.
    Asynchronous,
    /// Wait for a majority of peers to acknowledge.
    SemiSynchronous,
}

/// Configuration for a single peer node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Unique identifier for the peer node.
    pub node_id: String,
    /// Network address (host:port) of the peer.
    pub addr: String,
}

/// Top-level cluster configuration.
///
/// All fields carry serde defaults so that an empty JSON object is sufficient
/// to create a valid configuration with sensible values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique node identifier.
    #[serde(default)]
    pub node_id: String,

    /// Address (host:port) this node listens on for cluster traffic.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// List of peer nodes in the cluster.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,

    /// Replication strategy. Default: `Synchronous`.
    #[serde(default)]
    pub replication_mode: ReplicationMode,

    /// Milliseconds before a follower starts a new election. Default: 1000.
    #[serde(default = "default_election_timeout_ms")]
    pub election_timeout_ms: u64,

    /// Milliseconds between leader heartbeats. Default: 300.
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,

    /// Number of log entries between automatic snapshots. Default: 10000.
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval: u64,

    /// Maximum number of log entries to retain. Default: 100000.
    #[serde(default = "default_max_log_entries")]
    pub max_log_entries: usize,

    /// Maximum age in milliseconds for incoming cluster messages. Default: 30000 (30 seconds).
    /// Messages older than this are rejected as potential replays.
    #[serde(default = "default_max_message_age_ms")]
    pub max_message_age_ms: u64,

    /// Maximum clock skew (ms) tolerated for messages timestamped in the
    /// future. Raft clusters must run NTP/PTP; anything beyond this window is
    /// treated as replay or forgery. Defaults to 1000 ms. Must be strictly
    /// less than `max_message_age_ms / 2` so a crafted future-dated message
    /// cannot survive long enough to be re-admitted after a clock regression.
    #[serde(default = "default_max_future_skew_ms")]
    pub max_future_skew_ms: u64,

    /// Hex-encoded 32-byte cluster shared secret used to authenticate Raft RPCs.
    /// **MUST** be set in production.  When unset, all incoming RPCs are rejected.
    ///
    /// Prefer [`cluster_secret_file`](Self::cluster_secret_file) or
    /// [`cluster_secret_env`](Self::cluster_secret_env) in production — writing
    /// the key inline in a config file means it ends up in backups, config-
    /// management systems, and shell history (audit finding M5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_secret_hex: Option<String>,

    /// Path to a file whose contents are the hex-encoded 32-byte cluster
    /// secret.  On Unix the file must be mode `0600` (or stricter); a
    /// world-readable or group-readable file is rejected.
    ///
    /// Takes precedence over [`cluster_secret_env`](Self::cluster_secret_env)
    /// and [`cluster_secret_hex`](Self::cluster_secret_hex) when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_secret_file: Option<PathBuf>,

    /// Name of an environment variable whose value is the hex-encoded 32-byte
    /// cluster secret.  Useful in container orchestrators where secrets are
    /// injected via env.
    ///
    /// Takes precedence over [`cluster_secret_hex`](Self::cluster_secret_hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_secret_env: Option<String>,

    /// Allow the cluster to operate without a `cluster_secret_hex`.
    ///
    /// When `false` (the default), startup will fail if no cluster secret is
    /// configured — this is the **fail-closed** behavior expected in
    /// production.  Set to `true` only for development or testing to fall back
    /// to unauthenticated SHA-256 checksums.
    #[serde(default)]
    pub allow_insecure: bool,

    /// Per-peer token-bucket capacity for inbound `RequestVote` RPCs.
    ///
    /// Follows the classic token-bucket model (see Tanenbaum, _Computer
    /// Networks_ §5.3.2): each peer starts with `capacity` tokens; each
    /// accepted vote consumes one; tokens refill at
    /// [`vote_rate_limit_refill_interval_ms`](Self::vote_rate_limit_refill_interval_ms).
    /// RPCs received with an empty bucket are dropped silently — the RPC
    /// site deliberately does not respond so a malicious peer gets no
    /// liveness signal from having hit the limit.  Default: 3.
    #[serde(default = "default_vote_rate_limit_capacity")]
    pub vote_rate_limit_capacity: u32,

    /// Milliseconds between token refills for the vote rate limiter.
    /// Default: 5000 (one token every 5 seconds).
    #[serde(default = "default_vote_rate_limit_refill_ms")]
    pub vote_rate_limit_refill_interval_ms: u64,

    /// Minimum interval, in milliseconds, between successive membership-
    /// change (`ConfigChange`) entries replicated to any *single* peer
    /// (Fix 3).
    ///
    /// Rationale: `ConfigChange` entries alter the voter set and therefore
    /// the quorum.  A rogue leader — or a bug in the orchestration layer —
    /// could in principle blast a burst of back-to-back add/remove entries
    /// at an individual follower, shrinking the quorum faster than
    /// operators can react.  Rate-limiting the *per-peer* delivery of
    /// ConfigChange entries gives the cluster a minimum observation
    /// window after each membership edit.
    ///
    /// Default: `500` (ms).  Non-ConfigChange AppendEntries traffic is
    /// unaffected.
    #[serde(default = "default_min_config_change_interval_ms")]
    pub min_config_change_interval_ms: u64,

    /// Rolling-upgrade compatibility flag for the reply-MAC domain
    /// prefix normalization (audit fix: single-byte
    /// `DOMAIN_REPLY_*` constants replacing the legacy two-byte
    /// `[DOMAIN_REPLY_LEGACY, <kind>]` prefix).
    ///
    /// When `true` (the default for one release cycle), the verifier
    /// accepts replies signed under EITHER the new single-byte tag
    /// OR the legacy two-byte prefix. This lets a mixed-version
    /// cluster roll forward node-by-node without a coordinated
    /// drain-and-restart. Every legacy-prefix acceptance bumps the
    /// `legacy_reply_hmac_accepts` counter and emits a warning so
    /// operators can observe pre-normalization peers.
    ///
    /// Set to `false` once every node in the cluster is on a build
    /// that emits the new single-byte prefix, to harden against a
    /// future tag-downgrade.
    ///
    /// **Sunset**: this field, the legacy `compute_*_reply_hmac_legacy`
    /// helpers, and the `DOMAIN_REPLY_LEGACY` constant must be removed
    /// two releases after the cut-over so mixed-version traffic
    /// cannot silently regress to the longer prefix.
    #[serde(default = "default_legacy_reply_hmac_tags")]
    pub legacy_reply_hmac_tags: bool,
}

impl ClusterConfig {
    /// Validate the configuration, returning an error if any required fields
    /// are missing or invalid.
    ///
    /// Validation rules:
    /// - `node_id` must be non-empty.
    /// - `listen_addr` must contain a `:` (rough host:port check).
    /// - All `peers[*].node_id` must be unique and distinct from `node_id`.
    /// - All peer addresses must contain a `:`.
    /// - `election_timeout_ms` and `heartbeat_interval_ms` must be > 0.
    /// - `heartbeat_interval_ms < election_timeout_ms` (Raft safety).
    /// - `max_log_entries > 0`, `snapshot_interval > 0`, `max_message_age_ms > 0`.
    /// - If present, `cluster_secret_hex` must decode to exactly 32 bytes.
    /// Return `true` if any cluster-secret source is configured (inline,
    /// file, or env var). Used by `validate` and by the startup gate.
    fn has_any_cluster_secret(&self) -> bool {
        self.cluster_secret_hex.is_some()
            || self.cluster_secret_file.is_some()
            || self.cluster_secret_env.is_some()
    }

    /// Validate the cluster configuration for obvious misconfigurations.
    ///
    /// Returns `Err` with a human-readable reason when a required field is
    /// missing or carries a value that would be rejected at runtime.
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.is_empty() {
            return Err("node_id must not be empty".to_string());
        }
        if !self.listen_addr.contains(':') {
            return Err(format!(
                "listen_addr {:?} is not host:port",
                self.listen_addr
            ));
        }
        if self.election_timeout_ms == 0 {
            return Err("election_timeout_ms must be > 0".to_string());
        }
        if self.heartbeat_interval_ms == 0 {
            return Err("heartbeat_interval_ms must be > 0".to_string());
        }
        if self.heartbeat_interval_ms >= self.election_timeout_ms {
            return Err(format!(
                "heartbeat_interval_ms ({}) must be < election_timeout_ms ({})",
                self.heartbeat_interval_ms, self.election_timeout_ms
            ));
        }
        if self.max_log_entries == 0 {
            return Err("max_log_entries must be > 0".to_string());
        }
        if self.snapshot_interval == 0 {
            return Err("snapshot_interval must be > 0".to_string());
        }
        if self.max_message_age_ms == 0 {
            return Err("max_message_age_ms must be > 0".to_string());
        }
        if self.max_future_skew_ms == 0 {
            return Err("max_future_skew_ms must be > 0".to_string());
        }
        // Guarantee the freshness window is asymmetric enough that a future-
        // dated message cannot be accepted, time-evicted from the replay
        // cache, and then re-admitted after a clock regression.
        if self.max_future_skew_ms * 2 >= self.max_message_age_ms {
            return Err(format!(
                "max_future_skew_ms ({}) must be < max_message_age_ms ({}) / 2",
                self.max_future_skew_ms, self.max_message_age_ms
            ));
        }

        let mut seen = HashSet::new();
        for peer in &self.peers {
            if peer.node_id.is_empty() {
                return Err("peer node_id must not be empty".to_string());
            }
            if peer.node_id == self.node_id {
                return Err(format!(
                    "peer {:?} duplicates this node's node_id",
                    peer.node_id
                ));
            }
            if !seen.insert(&peer.node_id) {
                return Err(format!("duplicate peer node_id {:?}", peer.node_id));
            }
            if !peer.addr.contains(':') {
                return Err(format!(
                    "peer {:?} addr {:?} is not host:port",
                    peer.node_id, peer.addr
                ));
            }
        }

        if let Some(hex) = &self.cluster_secret_hex {
            let bytes = decode_hex(hex).map_err(|e| format!("cluster_secret_hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "cluster_secret_hex must decode to exactly 32 bytes (got {})",
                    bytes.len()
                ));
            }
        }
        if let Some(var) = &self.cluster_secret_env {
            if var.is_empty() {
                return Err("cluster_secret_env must be a non-empty variable name".to_string());
            }
        }
        // `cluster_secret_file` is only read at `decoded_cluster_secret`
        // time — we do not enforce its presence here so that a config can
        // be validated ahead of provisioning the file.

        if !self.has_any_cluster_secret() && !self.allow_insecure {
            return Err("no cluster secret configured (cluster_secret_hex / \
                 cluster_secret_file / cluster_secret_env) and allow_insecure \
                 is false — refusing to start in unauthenticated mode. Set a \
                 cluster secret for production use or set allow_insecure to \
                 true for development."
                .to_string());
        }

        Ok(())
    }

    /// Decode the configured cluster secret into a zeroizing 32-byte key.
    ///
    /// Sources are tried in priority order:
    /// 1. [`cluster_secret_file`](Self::cluster_secret_file) — contents of a
    ///    file on disk (Unix permissions validated).
    /// 2. [`cluster_secret_env`](Self::cluster_secret_env) — value of an
    ///    environment variable.
    /// 3. [`cluster_secret_hex`](Self::cluster_secret_hex) — inline.
    ///
    /// Returns `None` when no source is configured.  The returned buffer is
    /// wiped from memory when dropped.
    pub fn decoded_cluster_secret(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        // 1. File on disk (highest priority).
        if let Some(path) = &self.cluster_secret_file {
            check_secret_file_permissions(path)?;
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cluster_secret_file: cannot read {}: {e}", path.display()))?;
            // The file may contain a trailing newline; trim whitespace so
            // `echo -n KEY > file` and `echo KEY > file` both work.
            let trimmed = raw.trim();
            let bytes = decode_hex(trimmed).map_err(|e| format!("cluster_secret_file: {e}"))?;
            return decode_32(&bytes, "cluster_secret_file");
        }

        // 2. Environment variable.
        if let Some(var) = &self.cluster_secret_env {
            // Operator warning: on Unix, process environment is visible via
            // `/proc/<pid>/environ` to anyone running as the same user (or
            // root); on Windows it's visible to same-user processes via
            // `GetEnvironmentStrings`. For that reason `cluster_secret_file`
            // (which is permission-checked 0600) is strongly preferred. We
            // emit a one-shot warning here so the preference is surfaced on
            // every startup that reads from env.
            tracing::warn!(
                target: "craton_hsm_cluster",
                var = %var,
                "cluster_secret_env: reading cluster secret from process environment; \
                 prefer cluster_secret_file (permission-checked) in production — \
                 env-var values are exposed via /proc/<pid>/environ on Unix and \
                 to same-user processes on Windows"
            );
            let raw = std::env::var(var)
                .map_err(|e| format!("cluster_secret_env: cannot read env var {var}: {e}"))?;
            let bytes = decode_hex(raw.trim()).map_err(|e| format!("cluster_secret_env: {e}"))?;
            // Scrub the copy in `raw` as a belt-and-braces measure — the
            // allocator won't zero it on drop.
            let _ = Zeroizing::new(raw);
            return decode_32(&bytes, "cluster_secret_env");
        }

        // 3. Inline hex.
        let Some(hex) = &self.cluster_secret_hex else {
            return Ok(None);
        };
        let bytes = decode_hex(hex).map_err(|e| format!("cluster_secret_hex: {e}"))?;
        decode_32(&bytes, "cluster_secret_hex")
    }
}

/// Verify a cluster-secret file has sufficiently restrictive permissions.
/// On Unix we require mode `0600` or `0400`; any "group" or "other" bit set
/// is rejected. On non-Unix platforms we only verify readability.
fn check_secret_file_permissions(path: &std::path::Path) -> Result<(), String> {
    let md = std::fs::metadata(path)
        .map_err(|e| format!("cluster_secret_file: cannot stat {}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!(
            "cluster_secret_file: {} is not a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode();
        // Disallow any group or other permissions. The owner may read and
        // optionally write.
        if mode & 0o077 != 0 {
            return Err(format!(
                "cluster_secret_file: {} has permissions {:o} — expected 0600 \
                 or 0400 (no group/other access)",
                path.display(),
                mode & 0o777
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = md;
    }
    Ok(())
}

fn decode_32(bytes: &[u8], label: &str) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "{label} must decode to exactly 32 bytes (got {})",
            bytes.len()
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(bytes);
    Ok(Some(out))
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            listen_addr: default_listen_addr(),
            peers: Vec::new(),
            replication_mode: ReplicationMode::default(),
            election_timeout_ms: default_election_timeout_ms(),
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            snapshot_interval: default_snapshot_interval(),
            max_log_entries: default_max_log_entries(),
            max_message_age_ms: default_max_message_age_ms(),
            max_future_skew_ms: default_max_future_skew_ms(),
            cluster_secret_hex: None,
            cluster_secret_file: None,
            cluster_secret_env: None,
            allow_insecure: false,
            vote_rate_limit_capacity: default_vote_rate_limit_capacity(),
            vote_rate_limit_refill_interval_ms: default_vote_rate_limit_refill_ms(),
            min_config_change_interval_ms: default_min_config_change_interval_ms(),
            legacy_reply_hmac_tags: default_legacy_reply_hmac_tags(),
        }
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1:9443".to_string()
}

fn default_election_timeout_ms() -> u64 {
    1000
}

fn default_heartbeat_interval_ms() -> u64 {
    300
}

fn default_snapshot_interval() -> u64 {
    10000
}

fn default_max_log_entries() -> usize {
    100000
}

fn default_max_future_skew_ms() -> u64 {
    1_000
}

fn default_max_message_age_ms() -> u64 {
    30_000
}

fn default_vote_rate_limit_capacity() -> u32 {
    3
}

fn default_vote_rate_limit_refill_ms() -> u64 {
    5_000
}

fn default_min_config_change_interval_ms() -> u64 {
    500
}

/// Rolling-upgrade compat default: accept legacy two-byte reply-MAC
/// prefixes for one release cycle. See the field doc on
/// [`ClusterConfig::legacy_reply_hmac_tags`].
fn default_legacy_reply_hmac_tags() -> bool {
    true
}

/// Hex-decode (lower or upper case) into a zeroizing byte vector.
fn decode_hex(s: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character {:?}", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_cfg() -> ClusterConfig {
        ClusterConfig {
            node_id: "n1".into(),
            allow_insecure: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_defaults() {
        let cfg = ClusterConfig::default();
        assert!(cfg.node_id.is_empty());
        assert_eq!(cfg.listen_addr, "127.0.0.1:9443");
        assert!(cfg.peers.is_empty());
        assert_eq!(cfg.replication_mode, ReplicationMode::Synchronous);
        assert_eq!(cfg.election_timeout_ms, 1000);
        assert_eq!(cfg.heartbeat_interval_ms, 300);
        assert_eq!(cfg.snapshot_interval, 10000);
        assert_eq!(cfg.max_log_entries, 100000);
        assert_eq!(cfg.max_message_age_ms, 30_000);
        assert!(cfg.cluster_secret_hex.is_none());
        assert!(!cfg.allow_insecure);
        // Vote rate-limiter defaults.
        assert_eq!(cfg.vote_rate_limit_capacity, 3);
        assert_eq!(cfg.vote_rate_limit_refill_interval_ms, 5_000);
    }

    #[test]
    fn test_vote_rate_limit_defaults_via_serde() {
        // Missing keys in the JSON must still decode to the documented
        // defaults.
        let cfg: ClusterConfig = serde_json::from_str(r#"{"node_id":"n1"}"#).unwrap();
        assert_eq!(cfg.vote_rate_limit_capacity, 3);
        assert_eq!(cfg.vote_rate_limit_refill_interval_ms, 5_000);
    }

    #[test]
    fn test_validate_empty_node_id() {
        let cfg = ClusterConfig::default();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_good() {
        good_cfg().validate().unwrap();
    }

    #[test]
    fn test_validate_listen_addr_no_port() {
        let mut cfg = good_cfg();
        cfg.listen_addr = "localhost".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_heartbeat_must_be_less_than_election() {
        let mut cfg = good_cfg();
        cfg.heartbeat_interval_ms = 1000;
        cfg.election_timeout_ms = 1000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_zero_timeouts_rejected() {
        let mut cfg = good_cfg();
        cfg.election_timeout_ms = 0;
        assert!(cfg.validate().is_err());
        cfg = good_cfg();
        cfg.heartbeat_interval_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_duplicate_peer_id_rejected() {
        let mut cfg = good_cfg();
        cfg.peers = vec![
            PeerConfig {
                node_id: "n2".into(),
                addr: "10.0.0.2:9443".into(),
            },
            PeerConfig {
                node_id: "n2".into(),
                addr: "10.0.0.3:9443".into(),
            },
        ];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_self_in_peers_rejected() {
        let mut cfg = good_cfg();
        cfg.peers = vec![PeerConfig {
            node_id: "n1".into(),
            addr: "10.0.0.1:9443".into(),
        }];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_peer_addr_no_port() {
        let mut cfg = good_cfg();
        cfg.peers = vec![PeerConfig {
            node_id: "n2".into(),
            addr: "no-port".into(),
        }];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_secret_hex_wrong_length() {
        let mut cfg = good_cfg();
        cfg.cluster_secret_hex = Some("ab".into());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_secret_hex_invalid_char() {
        let mut cfg = good_cfg();
        cfg.cluster_secret_hex = Some("zz".repeat(32));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_decoded_secret_some() {
        let mut cfg = good_cfg();
        cfg.cluster_secret_hex = Some("ab".repeat(32));
        let s = cfg.decoded_cluster_secret().unwrap().unwrap();
        assert_eq!(s.len(), 32);
        assert_eq!(s[0], 0xAB);
    }

    #[test]
    fn test_decoded_secret_none() {
        let cfg = good_cfg();
        assert!(cfg.decoded_cluster_secret().unwrap().is_none());
    }

    #[test]
    fn test_replication_mode_default() {
        assert_eq!(ReplicationMode::default(), ReplicationMode::Synchronous);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let cfg = ClusterConfig {
            node_id: "node-1".to_string(),
            listen_addr: "0.0.0.0:9443".to_string(),
            peers: vec![PeerConfig {
                node_id: "node-2".to_string(),
                addr: "10.0.0.2:9443".to_string(),
            }],
            replication_mode: ReplicationMode::SemiSynchronous,
            election_timeout_ms: 2000,
            heartbeat_interval_ms: 500,
            snapshot_interval: 5000,
            max_log_entries: 50000,
            max_message_age_ms: 15_000,
            cluster_secret_hex: Some("00".repeat(32)),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let de: ClusterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(de.node_id, "node-1");
        assert_eq!(de.peers.len(), 1);
        assert_eq!(de.replication_mode, ReplicationMode::SemiSynchronous);
        assert_eq!(
            de.cluster_secret_hex.as_deref(),
            Some("00".repeat(32).as_str())
        );
        de.validate().unwrap();
    }

    #[test]
    fn test_deserialize_empty_json() {
        let cfg: ClusterConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.node_id.is_empty());
    }

    #[test]
    fn test_peer_config_equality() {
        let a = PeerConfig {
            node_id: "p1".to_string(),
            addr: "10.0.0.1:9443".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_decode_hex_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn test_decode_hex_mixed_case() {
        let v = decode_hex("AbCdEf").unwrap();
        assert_eq!(&v[..], &[0xAB, 0xCD, 0xEF]);
    }

    // -- allow_insecure / fail-closed tests --

    #[test]
    fn test_default_config_no_secret_fails_validation() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            // allow_insecure defaults to false, cluster_secret_hex defaults to None
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("allow_insecure"),
            "error should mention allow_insecure: {err}"
        );
    }

    #[test]
    fn test_config_with_secret_succeeds() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_hex: Some("ab".repeat(32)),
            // allow_insecure is false — should still pass because a secret is present
            ..Default::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn test_config_allow_insecure_no_secret_succeeds() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            allow_insecure: true,
            // No secret — but allow_insecure is true, so validation passes
            ..Default::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn test_allow_insecure_defaults_to_false_in_serde() {
        let cfg: ClusterConfig = serde_json::from_str(r#"{"node_id":"n1"}"#).unwrap();
        assert!(!cfg.allow_insecure);
    }

    #[test]
    fn test_allow_insecure_roundtrips_through_serde() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            allow_insecure: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let de: ClusterConfig = serde_json::from_str(&json).unwrap();
        assert!(de.allow_insecure);
    }

    // ---------------------------------------------------------------------
    // M5 — cluster_secret_file / cluster_secret_env precedence & checks
    // ---------------------------------------------------------------------

    #[test]
    fn test_secret_env_loads_and_decodes() {
        // Use a process-unique env var to avoid collisions with other tests.
        let var = "CRATON_HSM_TEST_CLUSTER_SECRET_ENV_1";
        // SAFETY: single-threaded test-env mutation.
        std::env::set_var(var, "cd".repeat(32));
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_env: Some(var.into()),
            ..Default::default()
        };
        let s = cfg.decoded_cluster_secret().unwrap().unwrap();
        assert_eq!(s[0], 0xCD);
        std::env::remove_var(var);
    }

    #[test]
    fn test_secret_env_missing_is_error() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_env: Some("CRATON_HSM_TEST_DEFINITELY_NOT_SET".into()),
            ..Default::default()
        };
        assert!(cfg.decoded_cluster_secret().is_err());
    }

    #[test]
    fn test_secret_file_wins_over_env_and_inline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.hex");
        // Write "ef" * 32 = 32-byte secret, all 0xEF.
        std::fs::write(&path, "ef".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let var = "CRATON_HSM_TEST_CLUSTER_SECRET_ENV_2";
        std::env::set_var(var, "ab".repeat(32));
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_file: Some(path),
            cluster_secret_env: Some(var.into()),
            cluster_secret_hex: Some("00".repeat(32)),
            ..Default::default()
        };
        let s = cfg.decoded_cluster_secret().unwrap().unwrap();
        // File should win → 0xEF, not 0xAB or 0x00.
        assert_eq!(s[0], 0xEF);
        std::env::remove_var(var);
    }

    #[test]
    fn test_secret_file_trailing_whitespace_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.hex");
        std::fs::write(&path, format!("{}\n", "12".repeat(32))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_file: Some(path),
            ..Default::default()
        };
        let s = cfg.decoded_cluster_secret().unwrap().unwrap();
        assert_eq!(s[0], 0x12);
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_file_world_readable_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-perms.hex");
        std::fs::write(&path, "ab".repeat(32)).unwrap();
        // 0644 — group & other readable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_file: Some(path),
            ..Default::default()
        };
        let err = cfg.decoded_cluster_secret().unwrap_err();
        assert!(
            err.contains("permissions"),
            "error should mention permissions: {err}"
        );
    }

    #[test]
    fn test_validate_passes_when_only_secret_file_set() {
        // `validate` should accept any of the three sources as sufficient
        // evidence that a secret is configured.
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_file: Some("/dev/null".into()),
            ..Default::default()
        };
        cfg.validate()
            .expect("secret_file should satisfy fail-closed check");
    }

    #[test]
    fn test_validate_rejects_empty_env_var_name() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            cluster_secret_env: Some("".into()),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
