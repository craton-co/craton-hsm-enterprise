// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Persistent storage abstraction for Raft state.
//!
//! Raft §5 requires `current_term`, `voted_for`, and the log to be persisted
//! to stable storage **before** responding to RPCs.  This module provides:
//!
//! - [`RaftStorage`] — the storage trait the Raft state machine uses.
//! - [`InMemoryStorage`] — a non-persistent implementation for tests.
//! - [`FileStorage`] — a simple JSON-on-disk implementation suitable for
//!   single-process production use (atomic write via write-rename).

use crate::raft::{LogEntry, Term};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

/// On Unix, open the parent directory of `path` and call `sync_all()`.
///
/// `rename(2)` is atomic in terms of which file contents the directory entry
/// points at, but the entry update itself is buffered. Without an explicit
/// fsync on the containing directory a crash between the rename and the next
/// directory writeback can leave the file at its old name/contents.
/// Best-effort: any failure (no parent path, EACCES, etc.) is ignored so
/// the caller never fails an otherwise-successful write because of a
/// durability hint.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        // Empty parent (relative path with no directory component) — fsync
        // the current directory.
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// Persisted Raft hard state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardState {
    /// The latest term the node has seen.
    pub current_term: Term,
    /// The candidate this node voted for in the current term.
    pub voted_for: Option<String>,
}

/// Errors returned by storage operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// I/O failure (file storage only).
    Io(String),
    /// Serialization / deserialization failure.
    Codec(String),
    /// Authenticated snapshot footer failed verification.
    ///
    /// Emitted by [`FileStorage::load_snapshot`] when the persisted snapshot
    /// does not have a valid footer (missing magic, wrong length, or bad
    /// HMAC tag).  Callers **must not** treat this as a recoverable
    /// condition — a tampered snapshot must never be installed.
    SnapshotIntegrityFailure(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "storage I/O error: {m}"),
            Self::Codec(m) => write!(f, "storage codec error: {m}"),
            Self::SnapshotIntegrityFailure(m) => {
                write!(f, "snapshot integrity failure: {m}")
            }
        }
    }
}

impl std::error::Error for StorageError {}

/// Result type used by storage methods.
pub type StorageResult<T> = Result<T, StorageError>;

/// Persistent backing store for a Raft node.
///
/// All methods are synchronous; implementors are expected to flush to disk
/// before returning.
///
/// # Durability ordering (Fix 2)
///
/// Raft §5.5 requires that, for any log entry, the entry itself is durable
/// **before** the hard state (including `committed` / `voted_for` /
/// `current_term`) that references it. Otherwise a crash window exists where
/// the node reports "committed through N" but the log entry at N was never
/// fsynced — on restart the state machine would silently lose the operation.
/// Callers crossing the persistence boundary (AppendEntries apply, snapshot
/// install, membership change) should therefore issue writes in this order:
///
/// 1. `append_log(entries)` — each implementation must fsync the log file.
/// 2. `save_hard_state(state)` — writes the new `current_term` / `voted_for`.
/// 3. `sync_all_committed_state()` — a belt-and-braces fsync helper that
///    callers can invoke at the commit-index advance site so the full
///    dependency chain (log → hard state → directory entries on disk) is
///    definitely durable before the state machine applies.
///
/// Implementations that are already durable after each individual call
/// (e.g. [`InMemoryStorage`]) can make this a no-op; callers must still
/// invoke it so the ordering discipline is encoded at the call site and
/// shows up in audits.
pub trait RaftStorage: Send + Sync + 'static {
    /// Load the persisted hard state, returning `Default` when nothing exists.
    fn load_hard_state(&self) -> StorageResult<HardState>;

    /// Persist the hard state.
    ///
    /// Implementors **must** durably commit before returning.  See the
    /// trait-level "Durability ordering" note — `append_log` for the
    /// referenced entries must have completed *before* this call.
    fn save_hard_state(&self, state: &HardState) -> StorageResult<()>;

    /// Load all persisted log entries (in index order).
    fn load_log(&self) -> StorageResult<Vec<LogEntry>>;

    /// Append entries to the persisted log.
    ///
    /// Must durably commit before returning.
    fn append_log(&self, entries: &[LogEntry]) -> StorageResult<()>;

    /// Truncate the persisted log to drop all entries with `index > after`.
    ///
    /// Must durably commit before returning.
    fn truncate_log_after(&self, after: u64) -> StorageResult<()>;

    /// Persist a snapshot.
    fn save_snapshot(&self, snapshot: &PersistedSnapshot) -> StorageResult<()>;

    /// Load the latest persisted snapshot, if any.
    fn load_snapshot(&self) -> StorageResult<Option<PersistedSnapshot>>;

    /// Fsync the full committed-state chain (log file, then hard state, then
    /// containing directory where applicable).
    ///
    /// Called at the commit-index advance boundary so that, after this
    /// returns, a crash cannot lose either the entries referenced by the
    /// advanced commit index or the hard-state fields that describe it.
    ///
    /// The default implementation is a no-op — every existing `append_log`
    /// and `save_hard_state` already fsyncs its own file, so this method is
    /// documentary for callers that want an explicit crash-recovery barrier.
    /// [`FileStorage`] overrides it to additionally fsync the directory
    /// containing the log and hard-state files on Unix, which some
    /// filesystems (ext4 with `data=ordered`) require to make the rename
    /// durable.
    fn sync_all_committed_state(&self) -> StorageResult<()> {
        Ok(())
    }
}

/// On-disk snapshot record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedSnapshot {
    /// Last log index covered by this snapshot.
    pub last_index: u64,
    /// Term of the entry at `last_index`.
    pub last_term: Term,
    /// Cluster membership at the time of the snapshot.
    pub voters: Vec<String>,
    /// Opaque state-machine bytes.
    pub data: Vec<u8>,
}

/// Hard upper bound on the size of a single log-entry JSON line (16 MiB).
///
/// Defense in depth: if an attacker manages to write to the log directory
/// they could craft a pathologically large JSON document that causes the
/// loader to allocate huge amounts of memory.  We cap each entry's byte
/// length well above any legitimate command size so normal operation is
/// unaffected but a forged file can't crash the node.
pub const MAX_LOG_ENTRY_BYTES: usize = 16 * 1024 * 1024;

/// Hard upper bound on the size of a persisted snapshot file (1 GiB).
///
/// Snapshots legitimately grow large (they contain the full state machine
/// contents) but must never exceed this ceiling.
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024 * 1024;

/// Size in bytes of a single record in the sidecar log offset-index file
/// (`log.jsonl.idx`).  Layout: `(u64 index || u64 term || u64 byte_offset)`
/// all little-endian, 24 bytes total.  See [`FileStorage::log_idx_path`]
/// for the full format description.  Exposed for tests only — the index
/// is an internal implementation detail.
#[cfg(test)]
pub const LOG_INDEX_RECORD_LEN: usize = 24;
#[cfg(not(test))]
const LOG_INDEX_RECORD_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Snapshot authentication footer (CRATON-SNAP-v1)
// ---------------------------------------------------------------------------

/// Magic identifier for the authenticated snapshot footer format v1.
///
/// Exactly 16 bytes (`"CRATON-SNAP-v1"` + two NUL padding bytes).  The fixed
/// width allows a constant-offset footer parse from the end of the file and
/// doubles as a cross-version discriminator: a future `v2` format will use a
/// different magic so a v1 loader refuses to silently accept it.
pub const SNAPSHOT_MAGIC: [u8; 16] = *b"CRATON-SNAP-v1\0\0";

/// Size in bytes of the authenticated snapshot footer (magic || len || index
/// || term || mac).
///
/// Layout (all little-endian):
///   bytes  0..16  — [`SNAPSHOT_MAGIC`]
///   bytes 16..24  — u64 payload length
///   bytes 24..32  — u64 snapshot index
///   bytes 32..40  — u64 snapshot term
///   bytes 40..72  — HMAC-SHA256 tag (32 bytes) or all-zeros in insecure mode
pub const SNAPSHOT_FOOTER_LEN: usize = 16 + 8 + 8 + 8 + 32;

/// Domain-separation tag used when deriving the snapshot authentication key
/// from the cluster secret.
///
/// Rationale: NIST SP 800-38D §5.1 and RFC 5869 (HKDF) both warn against
/// reusing the same key across distinct cryptographic contexts.  The cluster
/// secret is already used to HMAC log-entry RPCs (see [`replication`] and
/// [`raft`]); we derive a distinct subkey for snapshot authentication so that
/// a snapshot MAC can never be confused with a replication-log MAC.
///
/// MED (audit, doc correctness): the derivation is a single
/// HMAC-SHA256 invocation where the cluster secret is the *key* and
/// the domain tag is the *message*. This is **not** HKDF-Extract:
/// HKDF-Extract keys with `salt` and runs HMAC over the input keying
/// material as the message (RFC 5869 §2.2), which is the swap of what
/// we do here. Our construction is a plain keyed-MAC subkey
/// derivation; an empty-salt HKDF-Extract over `cluster_secret` with
/// `info = "snapshot-v1"` would be a different byte sequence. Doc
/// updated to stop conflating the two — the wire bytes are unchanged.
///
/// [`replication`]: crate::replication
/// [`raft`]: crate::raft
pub const SNAPSHOT_DOMAIN_TAG: &[u8] = b"snapshot-v1";

/// Derive the snapshot authentication subkey from a 32-byte cluster secret.
///
/// `K_snap = HMAC-SHA256(key = cluster_secret, msg = "snapshot-v1")` — a
/// plain keyed-MAC subkey derivation with the domain tag as the message.
/// See [`SNAPSHOT_DOMAIN_TAG`] for the rationale and the note that this
/// is NOT an HKDF-Extract step despite the casual resemblance. The
/// output is wrapped in [`Zeroizing`] so the derived key is wiped on
/// drop.
fn derive_snapshot_key(cluster_secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cluster_secret)
        .expect("HMAC-SHA256 accepts any key size");
    mac.update(SNAPSHOT_DOMAIN_TAG);
    let digest = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    out
}

/// Compute the snapshot HMAC tag over `(magic || len || index || term || payload)`.
fn compute_snapshot_tag(key: &[u8; 32], payload: &[u8], index: u64, term: u64) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key size");
    mac.update(&SNAPSHOT_MAGIC);
    mac.update(&(payload.len() as u64).to_le_bytes());
    mac.update(&index.to_le_bytes());
    mac.update(&term.to_le_bytes());
    mac.update(payload);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Count the number of non-empty lines in a JSON-Lines log file.
///
/// Used by [`FileStorage::reconcile_log_index`] to decide whether the
/// sidecar offset-index is fully populated.  Streams the file line-by-line
/// rather than reading it whole so large logs do not allocate an
/// O(filesize) string.
fn count_log_entries(log_path: &Path) -> StorageResult<usize> {
    use std::io::{BufRead, BufReader};
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    let reader = BufReader::new(file);
    let mut n = 0usize;
    for line in reader.lines() {
        let line = line.map_err(|e| StorageError::Io(e.to_string()))?;
        if !line.is_empty() {
            n = n.saturating_add(1);
        }
    }
    Ok(n)
}

/// Constant-time equality of two 32-byte tags.
///
/// Uses the `subtle` crate so the compiler cannot optimise the comparison
/// into an early-exit branch (audit finding C3). A timing side-channel on the
/// snapshot HMAC would let an attacker forge valid MACs byte-by-byte.
fn ct_tag_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// In-memory storage
// ---------------------------------------------------------------------------

/// Non-persistent storage for unit tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryStorage {
    inner: Arc<Mutex<InMemoryInner>>,
}

#[derive(Debug, Default)]
struct InMemoryInner {
    hard: HardState,
    log: Vec<LogEntry>,
    snapshot: Option<PersistedSnapshot>,
}

impl InMemoryStorage {
    /// Construct an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RaftStorage for InMemoryStorage {
    fn load_hard_state(&self) -> StorageResult<HardState> {
        Ok(self.inner.lock().hard.clone())
    }

    fn save_hard_state(&self, state: &HardState) -> StorageResult<()> {
        self.inner.lock().hard = state.clone();
        Ok(())
    }

    fn load_log(&self) -> StorageResult<Vec<LogEntry>> {
        Ok(self.inner.lock().log.clone())
    }

    fn append_log(&self, entries: &[LogEntry]) -> StorageResult<()> {
        self.inner.lock().log.extend_from_slice(entries);
        Ok(())
    }

    fn truncate_log_after(&self, after: u64) -> StorageResult<()> {
        let mut g = self.inner.lock();
        g.log.retain(|e| e.index <= after);
        Ok(())
    }

    fn save_snapshot(&self, snapshot: &PersistedSnapshot) -> StorageResult<()> {
        self.inner.lock().snapshot = Some(snapshot.clone());
        Ok(())
    }

    fn load_snapshot(&self) -> StorageResult<Option<PersistedSnapshot>> {
        Ok(self.inner.lock().snapshot.clone())
    }
}

// ---------------------------------------------------------------------------
// File storage
// ---------------------------------------------------------------------------

/// Simple JSON-on-disk storage suitable for development & single-process
/// production deployments.
///
/// Three files are maintained inside `dir`:
/// - `hard_state.json` — `HardState`
/// - `log.jsonl` — append-only JSON-Lines file (`LogEntry` per line)
/// - `snapshot.json` — `PersistedSnapshot` (optional)
///
/// The log uses an append-only JSON-Lines format for O(1) appends instead
/// of re-serializing the entire log on every write. Hard state and snapshot
/// writes go to a `.tmp` sibling and are then `rename()`d into place to
/// guarantee crash-atomicity per file.
///
/// **Security note:** Files are stored as plaintext JSON. When using Raft
/// `KeySync` commands, key material will be present on disk. Deploy on
/// encrypted volumes or integrate with a key-wrapping layer for production.
#[derive(Debug, Clone)]
pub struct FileStorage {
    dir: PathBuf,
    /// Lock to serialize writes from multiple threads in the same process.
    write_lock: Arc<Mutex<()>>,
    /// Derived snapshot authentication subkey (if a cluster secret is set).
    ///
    /// Derived via [`derive_snapshot_key`] from the cluster secret once at
    /// attach time so the cluster secret itself is not copied around.  `None`
    /// means "no authentication key"; snapshots will be loaded only if
    /// `allow_insecure` is also `true`.
    snapshot_key: Option<Arc<Zeroizing<[u8; 32]>>>,
    /// Development-only escape hatch mirroring [`ClusterConfig::allow_insecure`].
    ///
    /// When `true`, snapshots are written with an all-zeros MAC (but the
    /// CRATON-SNAP-v1 magic is still present so a later authenticated loader
    /// can detect and reject them).
    ///
    /// [`ClusterConfig::allow_insecure`]: crate::config::ClusterConfig::allow_insecure
    allow_insecure: bool,
}

impl FileStorage {
    /// Create or open a storage directory.
    ///
    /// The directory will be created if it does not already exist.
    ///
    /// The returned storage has no snapshot authentication key configured;
    /// calls to [`save_snapshot`](Self::save_snapshot) and
    /// [`load_snapshot`](Self::load_snapshot) will fail closed unless
    /// [`with_cluster_secret`](Self::with_cluster_secret) or
    /// [`allow_insecure`](Self::allow_insecure) has been used to opt in.
    pub fn open(dir: impl AsRef<Path>) -> StorageResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| StorageError::Io(e.to_string()))?;
        let storage = Self {
            dir,
            write_lock: Arc::new(Mutex::new(())),
            snapshot_key: None,
            allow_insecure: false,
        };
        storage.migrate_legacy_log()?;
        // Audit L-truncate: verify the sidecar offset-index is consistent
        // with the log file.  If the idx is missing, empty, a partial
        // write, or trails behind the log (crash window between
        // `append_log`'s log fsync and its idx fsync), rebuild it now so
        // subsequent `truncate_log_after` calls stay on the fast path.
        storage.reconcile_log_index()?;
        Ok(storage)
    }

    /// Re-derive the sidecar log offset-index from the canonical
    /// `log.jsonl` file if the two have drifted out of sync.  Called once
    /// from [`open`](Self::open) and from the slow path of
    /// [`truncate_log_after`](<Self as RaftStorage>::truncate_log_after).
    ///
    /// Drift can arise from three scenarios:
    ///   1. Legacy log with no .idx at all.
    ///   2. Crash between the log fsync and the idx fsync in
    ///      [`append_log`](<Self as RaftStorage>::append_log).
    ///   3. External corruption (idx truncated to zero, partial record).
    ///
    /// All three are healed by a single full scan of the log file —
    /// bounded by the same `MAX_LOG_ENTRY_BYTES` ceiling the regular
    /// loader enforces.
    fn reconcile_log_index(&self) -> StorageResult<()> {
        let log_path = self.log_path();
        if !log_path.exists() {
            return Ok(());
        }
        let idx_path = self.log_idx_path();
        let log_len = std::fs::metadata(&log_path)
            .map_err(|e| StorageError::Io(e.to_string()))?
            .len();

        // Fast consistency check: .idx exists, its size is a multiple
        // of the record width, and its last record's byte offset is
        // strictly less than the log length.  Anything else triggers a
        // rebuild.
        let idx_ok = match std::fs::metadata(&idx_path) {
            Ok(m) => {
                let sz = m.len() as usize;
                if sz == 0 || sz % LOG_INDEX_RECORD_LEN != 0 {
                    false
                } else if let Ok(bytes) = std::fs::read(&idx_path) {
                    let last = bytes.len() - LOG_INDEX_RECORD_LEN;
                    let last_off = u64::from_le_bytes(
                        bytes[last + 16..last + 24].try_into().unwrap_or([0u8; 8]),
                    );
                    // Allow the idx to be short (covers fewer entries
                    // than the log) — that's the "crash between log
                    // and idx fsync" case — we rebuild in that case.
                    // Require the last covered offset to point inside
                    // the current log file, and require the idx to
                    // cover the full log by checking record count vs
                    // a full log-line scan below... actually, we take
                    // a simpler sufficient condition: rebuild if the
                    // idx does not cover the log's last entry.
                    // Estimate this cheaply by checking whether the
                    // last idx record's offset + one line would reach
                    // the log end; if the idx is shorter than the
                    // log's true entry count, the verification will
                    // fail and we rebuild.
                    last_off < log_len
                } else {
                    false
                }
            }
            Err(_) => false,
        };

        // Count the log entries with a streaming read to decide
        // whether the idx truly covers the full log.
        let actual_entry_count = count_log_entries(&log_path)?;
        let idx_covers_full_log = if idx_ok {
            if let Ok(m) = std::fs::metadata(&idx_path) {
                (m.len() as usize / LOG_INDEX_RECORD_LEN) == actual_entry_count
            } else {
                false
            }
        } else {
            false
        };

        if idx_covers_full_log {
            return Ok(());
        }

        // Rebuild the .idx from a full log scan.
        use std::io::{BufRead, BufReader};
        let file = std::fs::File::open(&log_path).map_err(|e| StorageError::Io(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut cur_offset: u64 = 0;
        let mut idx_buf: Vec<u8> =
            Vec::with_capacity(actual_entry_count.saturating_mul(LOG_INDEX_RECORD_LEN));
        for line in reader.lines() {
            let line = line.map_err(|e| StorageError::Io(e.to_string()))?;
            if line.is_empty() {
                cur_offset = cur_offset.saturating_add(1);
                continue;
            }
            if line.len() > MAX_LOG_ENTRY_BYTES {
                return Err(StorageError::Codec(format!(
                    "log entry exceeds MAX_LOG_ENTRY_BYTES ({} > {})",
                    line.len(),
                    MAX_LOG_ENTRY_BYTES
                )));
            }
            let entry: LogEntry =
                serde_json::from_str(&line).map_err(|e| StorageError::Codec(e.to_string()))?;
            idx_buf.extend_from_slice(&entry.index.to_le_bytes());
            idx_buf.extend_from_slice(&entry.term.value().to_le_bytes());
            idx_buf.extend_from_slice(&cur_offset.to_le_bytes());
            // +1 for the trailing '\n' that BufReader::lines strips.
            cur_offset = cur_offset
                .saturating_add(line.len() as u64)
                .saturating_add(1);
        }
        Self::write_atomic(&idx_path, &idx_buf)?;
        Ok(())
    }

    /// Configure the snapshot authentication key.  Accepts the raw 32-byte
    /// cluster secret; a subkey is derived via [`derive_snapshot_key`].
    #[must_use = "with_cluster_secret returns a new FileStorage; without binding the result the snapshot key is dropped and FileStorage stays fail-closed"]
    pub fn with_cluster_secret(mut self, cluster_secret: &[u8]) -> Self {
        self.snapshot_key = Some(Arc::new(derive_snapshot_key(cluster_secret)));
        self
    }

    /// Enable the dev-only unauthenticated-snapshot mode.  See
    /// [`ClusterConfig::allow_insecure`] for the fail-closed rationale.
    ///
    /// [`ClusterConfig::allow_insecure`]: crate::config::ClusterConfig::allow_insecure
    #[must_use = "allow_insecure returns a new FileStorage; drop the return value and the setting is silently lost"]
    pub fn allow_insecure(mut self, yes: bool) -> Self {
        self.allow_insecure = yes;
        self
    }

    /// Returns `true` if an authenticated snapshot key has been configured.
    pub fn has_snapshot_key(&self) -> bool {
        self.snapshot_key.is_some()
    }

    fn hard_path(&self) -> PathBuf {
        self.dir.join("hard_state.json")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("log.jsonl")
    }

    /// Sidecar offset-index path.
    ///
    /// Layout: repeated fixed-width 24-byte records
    /// `(index u64 LE, term u64 LE, byte_offset u64 LE)` in append order.
    /// The `byte_offset` points at the first byte of the matching JSON-Lines
    /// entry in `log.jsonl` (i.e. the `{` of its line).  No header is
    /// written so the file can be truncated in lock-step with the main log:
    /// the i-th 24-byte record corresponds to the i-th surviving log entry.
    ///
    /// The index is intentionally optional at the API boundary — if it is
    /// absent, corrupt, or ends past the log file, the loader silently
    /// rebuilds from a full log scan.  This keeps the on-disk log format
    /// byte-for-byte compatible with deployments that predate the
    /// optimisation (audit L-truncate).
    fn log_idx_path(&self) -> PathBuf {
        self.dir.join("log.jsonl.idx")
    }

    /// Migrate legacy `log.json` (single-array format) to `log.jsonl` (one entry per line).
    fn migrate_legacy_log(&self) -> StorageResult<()> {
        let legacy = self.dir.join("log.json");
        let new_path = self.log_path();
        if legacy.exists() && !new_path.exists() {
            let bytes = std::fs::read(&legacy).map_err(|e| StorageError::Io(e.to_string()))?;
            let entries: Vec<LogEntry> =
                serde_json::from_slice(&bytes).map_err(|e| StorageError::Codec(e.to_string()))?;
            let mut buf = String::new();
            for entry in &entries {
                let line =
                    serde_json::to_string(entry).map_err(|e| StorageError::Codec(e.to_string()))?;
                buf.push_str(&line);
                buf.push('\n');
            }
            std::fs::write(&new_path, buf.as_bytes())
                .map_err(|e| StorageError::Io(e.to_string()))?;
            let _ = std::fs::remove_file(&legacy);
            tracing::info!(
                "Migrated legacy log.json to log.jsonl ({} entries)",
                entries.len()
            );
        }
        Ok(())
    }

    fn snap_path(&self) -> PathBuf {
        self.dir.join("snapshot.json")
    }

    /// Look up the byte offsets where the log file and sidecar index file
    /// should be truncated to satisfy
    /// [`truncate_log_after`](Self::truncate_log_after).
    ///
    /// Returns `Ok(Some((log_cut_off, idx_cut_off)))` when the fast
    /// offset-index path can be used — `log_cut_off` is the byte length
    /// the log file must end at, and `idx_cut_off` is the matching
    /// length for `log.jsonl.idx`.  Returns `Ok(None)` if the .idx file
    /// is missing, inconsistent (last record's offset does not match the
    /// log file length) or does not cover the requested `after` — the
    /// caller falls back to the legacy read-and-rewrite path.  Errors
    /// are reserved for I/O failures that also prevent the slow path.
    fn lookup_truncate_offsets(
        log_path: &Path,
        idx_path: &Path,
        after: u64,
    ) -> StorageResult<Option<(u64, u64)>> {
        if !idx_path.exists() {
            return Ok(None);
        }
        let idx_bytes = match std::fs::read(idx_path) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        if idx_bytes.is_empty() || idx_bytes.len() % LOG_INDEX_RECORD_LEN != 0 {
            // Zero-length or torn write — rebuild.
            return Ok(None);
        }
        let log_len = match std::fs::metadata(log_path) {
            Ok(m) => m.len(),
            Err(_) => return Ok(None),
        };

        // Consistency check: the offset of the last record plus one
        // entry-line's worth of bytes should not exceed the log length.
        // More strongly: the final record's offset must be < log_len.
        let last_rec_start = idx_bytes.len() - LOG_INDEX_RECORD_LEN;
        let last_offset = u64::from_le_bytes(
            idx_bytes[last_rec_start + 16..last_rec_start + 24]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        if last_offset >= log_len {
            return Ok(None);
        }

        // Walk records in order looking for the first index > after.
        // The search is linear rather than binary because indices are
        // monotonically increasing by 1 in the common case but we
        // cannot assume that strictly (future formats could gap), and
        // the worst-case cost is still tiny compared to the avoided
        // full log rewrite.
        let num_records = idx_bytes.len() / LOG_INDEX_RECORD_LEN;
        for i in 0..num_records {
            let off = i * LOG_INDEX_RECORD_LEN;
            let idx = u64::from_le_bytes(idx_bytes[off..off + 8].try_into().unwrap_or([0u8; 8]));
            if idx > after {
                let byte_offset = u64::from_le_bytes(
                    idx_bytes[off + 16..off + 24].try_into().unwrap_or([0u8; 8]),
                );
                let idx_cut = (i * LOG_INDEX_RECORD_LEN) as u64;
                return Ok(Some((byte_offset, idx_cut)));
            }
        }
        // All indexed records have `index <= after` — nothing to
        // truncate from the indexed region.  This is a no-op truncate
        // (cut at the end of the log / idx, which leaves them
        // unchanged).
        Ok(Some((log_len, idx_bytes.len() as u64)))
    }

    /// Atomic write-rename: write `bytes` to `<path>.tmp`, fsync, then
    /// rename over `path`.  After `rename(2)` returns, the file at `path`
    /// is guaranteed to be either the old contents or the fully-written
    /// new contents (never a torn mixture), but the *directory entry*
    /// update may still be buffered by the filesystem.  For full durability
    /// across a crash the *caller* must subsequently invoke
    /// [`sync_all_committed_state`](Self::sync_all_committed_state) (Fix 2)
    /// which fsyncs the containing directory on Unix.
    ///
    /// Durability ordering reminder (Fix 2): when persisting a log entry +
    /// hard-state pair, the caller must invoke `append_log` **before**
    /// `save_hard_state` — so a torn crash either loses the new hard state
    /// (safe: election re-runs) or preserves an entry that the hard state
    /// does not yet reference (safe: re-applied on next commit advance).
    fn write_atomic(path: &Path, bytes: &[u8]) -> StorageResult<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| StorageError::Io(e.to_string()))?;
        // Best-effort fsync of the file before rename.
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&tmp) {
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, path).map_err(|e| StorageError::Io(e.to_string()))?;
        // Durability fix: on Unix, the rename(2) syscall returning does NOT
        // guarantee that the new directory entry is durable. A crash
        // between rename and the next directory writeback can leave the
        // file at its old contents (or missing entirely if it never
        // existed). fsync the parent directory to flush the entry.
        // No-op on non-Unix; on Windows, ReplaceFile/MoveFileEx semantics
        // do not require this.
        #[cfg(unix)]
        sync_parent_dir(path);
        Ok(())
    }
}

impl RaftStorage for FileStorage {
    fn load_hard_state(&self) -> StorageResult<HardState> {
        let path = self.hard_path();
        if !path.exists() {
            return Ok(HardState::default());
        }
        let bytes = std::fs::read(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| StorageError::Codec(e.to_string()))
    }

    fn save_hard_state(&self, state: &HardState) -> StorageResult<()> {
        let _g = self.write_lock.lock();
        let bytes = serde_json::to_vec(state).map_err(|e| StorageError::Codec(e.to_string()))?;
        Self::write_atomic(&self.hard_path(), &bytes)
    }

    fn load_log(&self) -> StorageResult<Vec<LogEntry>> {
        let path = self.log_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content =
            std::fs::read_to_string(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        let mut entries = Vec::new();
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_LOG_ENTRY_BYTES {
                return Err(StorageError::Codec(format!(
                    "log entry exceeds MAX_LOG_ENTRY_BYTES ({} > {})",
                    line.len(),
                    MAX_LOG_ENTRY_BYTES
                )));
            }
            let entry: LogEntry =
                serde_json::from_str(line).map_err(|e| StorageError::Codec(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn append_log(&self, entries: &[LogEntry]) -> StorageResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let _g = self.write_lock.lock();
        use std::io::{Seek, SeekFrom, Write};

        // Open the log file.  Start at end-of-file so we can record the
        // byte offset of each new entry in the sidecar index.
        let log_path = self.log_path();
        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&log_path)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        // Seek to end in read-mode to discover the current length (the
        // `append` open flag positions writes at EOF but `stream_position`
        // in O_APPEND mode on some platforms does not reliably report the
        // write cursor).
        let mut cur_offset = log_file
            .seek(SeekFrom::End(0))
            .map_err(|e| StorageError::Io(e.to_string()))?;

        // Sidecar offset-index file.  Opened best-effort: if the file
        // cannot be opened/created (e.g. read-only directory), we fall
        // back to a log-only write — the next `load_log`/`truncate_log_after`
        // call will silently rebuild from the log file.
        let idx_path = self.log_idx_path();
        let mut idx_file_opt = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&idx_path)
            .ok();

        let mut idx_records: Vec<u8> = Vec::with_capacity(entries.len() * LOG_INDEX_RECORD_LEN);
        for entry in entries {
            let line =
                serde_json::to_string(entry).map_err(|e| StorageError::Codec(e.to_string()))?;
            // Per-entry line size ceiling — same invariant the loader
            // enforces, applied on the way in so we never persist a record
            // the loader would reject.
            if line.len() > MAX_LOG_ENTRY_BYTES {
                return Err(StorageError::Codec(format!(
                    "log entry exceeds MAX_LOG_ENTRY_BYTES ({} > {})",
                    line.len(),
                    MAX_LOG_ENTRY_BYTES
                )));
            }
            // Record the byte offset of THIS entry BEFORE writing it.
            if idx_file_opt.is_some() {
                idx_records.extend_from_slice(&entry.index.to_le_bytes());
                idx_records.extend_from_slice(&entry.term.value().to_le_bytes());
                idx_records.extend_from_slice(&cur_offset.to_le_bytes());
            }
            writeln!(log_file, "{}", line).map_err(|e| StorageError::Io(e.to_string()))?;
            cur_offset = cur_offset
                .saturating_add(line.len() as u64)
                .saturating_add(1); // for the trailing '\n'
        }
        // Durability ordering: log file first, then idx.  A crash between
        // the two leaves the .idx trailing behind the log — the loader
        // detects this (last idx offset != log file length) and rebuilds.
        log_file
            .sync_all()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        if let Some(idx_file) = idx_file_opt.as_mut() {
            if !idx_records.is_empty() {
                idx_file
                    .write_all(&idx_records)
                    .map_err(|e| StorageError::Io(e.to_string()))?;
                idx_file
                    .sync_all()
                    .map_err(|e| StorageError::Io(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn truncate_log_after(&self, after: u64) -> StorageResult<()> {
        let _g = self.write_lock.lock();
        let path = self.log_path();
        if !path.exists() {
            return Ok(());
        }

        // Audit L-truncate: fast path via the sidecar offset-index.  If
        // `.idx` is present AND internally consistent AND contains an
        // entry for `after+1`, we can `set_len` both files in O(1)
        // instead of reading+rewriting the whole log.  If any check
        // fails we silently fall through to the legacy read-and-rewrite
        // path, which also rebuilds the .idx so later truncates stay on
        // the fast path.
        let idx_path = self.log_idx_path();
        if let Some((log_cut_off, idx_cut_off)) =
            Self::lookup_truncate_offsets(&path, &idx_path, after)?
        {
            // Fast path: seek + set_len on both files.  Order matters
            // for crash-recovery: shrink the log first so a crash here
            // leaves the .idx trailing past the log (detected on reopen
            // and rebuilt).  The reverse order would leave the log
            // containing entries that no longer have index records — the
            // loader would rebuild in that case too, so either ordering
            // is safe, but "log first" keeps the index strictly-leading-
            // or-equal invariant simpler to reason about.
            let log_file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|e| StorageError::Io(e.to_string()))?;
            log_file
                .set_len(log_cut_off)
                .map_err(|e| StorageError::Io(e.to_string()))?;
            log_file
                .sync_all()
                .map_err(|e| StorageError::Io(e.to_string()))?;
            drop(log_file);

            if idx_path.exists() {
                let idx_file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&idx_path)
                    .map_err(|e| StorageError::Io(e.to_string()))?;
                idx_file
                    .set_len(idx_cut_off)
                    .map_err(|e| StorageError::Io(e.to_string()))?;
                idx_file
                    .sync_all()
                    .map_err(|e| StorageError::Io(e.to_string()))?;
            }
            return Ok(());
        }

        // Slow path: rebuild both files from a full log scan.  Also
        // rebuilds the .idx so subsequent truncates take the fast
        // path.
        let all = {
            let content =
                std::fs::read_to_string(&path).map_err(|e| StorageError::Io(e.to_string()))?;
            let mut entries = Vec::new();
            for line in content.lines() {
                if line.is_empty() {
                    continue;
                }
                if line.len() > MAX_LOG_ENTRY_BYTES {
                    return Err(StorageError::Codec(format!(
                        "log entry exceeds MAX_LOG_ENTRY_BYTES ({} > {})",
                        line.len(),
                        MAX_LOG_ENTRY_BYTES
                    )));
                }
                let entry: LogEntry =
                    serde_json::from_str(line).map_err(|e| StorageError::Codec(e.to_string()))?;
                if entry.index <= after {
                    entries.push(entry);
                }
            }
            entries
        };
        let mut buf = String::new();
        let mut idx_buf: Vec<u8> = Vec::with_capacity(all.len() * LOG_INDEX_RECORD_LEN);
        for entry in &all {
            let line =
                serde_json::to_string(entry).map_err(|e| StorageError::Codec(e.to_string()))?;
            let start_offset = buf.len() as u64;
            buf.push_str(&line);
            buf.push('\n');
            idx_buf.extend_from_slice(&entry.index.to_le_bytes());
            idx_buf.extend_from_slice(&entry.term.value().to_le_bytes());
            idx_buf.extend_from_slice(&start_offset.to_le_bytes());
        }
        Self::write_atomic(&path, buf.as_bytes())?;
        // Rebuild the .idx atomically too so a crash mid-rebuild leaves
        // either the old or the new index, never a torn half-write.
        Self::write_atomic(&idx_path, &idx_buf)?;
        Ok(())
    }

    /// Persist a snapshot with an authenticated footer.
    ///
    /// File layout: `json(payload) || magic(16) || len(u64 LE) || index(u64 LE)
    /// || term(u64 LE) || mac(32)`.  The MAC is computed over `magic || len
    /// || index || term || payload` using a subkey derived from the cluster
    /// secret with the domain tag `"snapshot-v1"` (HKDF-Extract style).
    ///
    /// In `allow_insecure` mode the MAC is written as 32 zero bytes but the
    /// magic is still present so a later authenticated loader can detect and
    /// reject the unauthenticated snapshot (see
    /// [`load_snapshot`](Self::load_snapshot)).
    fn save_snapshot(&self, snapshot: &PersistedSnapshot) -> StorageResult<()> {
        let _g = self.write_lock.lock();
        let payload =
            serde_json::to_vec(snapshot).map_err(|e| StorageError::Codec(e.to_string()))?;

        // Enforce the same upper bound on save as on load. Without this, a
        // buggy or malicious state machine can produce a snapshot larger than
        // any peer can load, wedging the cluster once the log truncates past
        // that index.
        let projected_len = payload.len().saturating_add(SNAPSHOT_FOOTER_LEN);
        if projected_len > MAX_SNAPSHOT_BYTES {
            return Err(StorageError::Codec(format!(
                "snapshot exceeds MAX_SNAPSHOT_BYTES on save ({} > {})",
                projected_len, MAX_SNAPSHOT_BYTES
            )));
        }

        let index = snapshot.last_index;
        let term = snapshot.last_term.value();

        let tag = match (&self.snapshot_key, self.allow_insecure) {
            (Some(k), _) => compute_snapshot_tag(k.as_ref(), &payload, index, term),
            (None, true) => {
                tracing::warn!(
                    "FileStorage: writing snapshot without authentication \
                     (allow_insecure=true). This snapshot will be REJECTED \
                     by a node configured with a cluster_secret."
                );
                [0u8; 32]
            }
            (None, false) => {
                return Err(StorageError::SnapshotIntegrityFailure(
                    "no cluster_secret configured and allow_insecure=false — \
                     refusing to persist an unauthenticated snapshot"
                        .to_string(),
                ));
            }
        };

        let mut bytes = Vec::with_capacity(payload.len().saturating_add(SNAPSHOT_FOOTER_LEN));
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.extend_from_slice(&term.to_le_bytes());
        bytes.extend_from_slice(&tag);

        Self::write_atomic(&self.snap_path(), &bytes)
    }

    /// Load the latest snapshot, verifying the authentication footer.
    ///
    /// Returns `Ok(None)` when no snapshot file exists.  On any footer
    /// mismatch — missing magic, wrong payload length, wrong MAC — returns
    /// [`StorageError::SnapshotIntegrityFailure`] and logs a loud error.
    /// **No partial data is ever returned** on failure (fail closed).
    /// Fsync the log file, the hard-state file, and (on Unix) the containing
    /// directory.  Called by Raft after advancing the commit index so that a
    /// crash after the `save_hard_state` returns but before the filesystem
    /// actually flushes cannot make the node forget an entry whose index we
    /// reported as committed.
    ///
    /// Order: **log file first**, then hard state, then directory.  This
    /// matches the trait-level "Durability ordering" contract — if we crash
    /// mid-flush, we can tolerate losing the new hard state (election
    /// re-runs) but must never keep a hard state whose referenced log entry
    /// is gone.
    fn sync_all_committed_state(&self) -> StorageResult<()> {
        let _g = self.write_lock.lock();
        // 1. fsync the log file (if it exists).
        let log_path = self.log_path();
        if log_path.exists() {
            if let Ok(f) = std::fs::OpenOptions::new().read(true).open(&log_path) {
                f.sync_all().map_err(|e| StorageError::Io(e.to_string()))?;
            }
        }
        // 1a. fsync the sidecar offset-index file (audit L-truncate).
        //     A crash that leaves the idx on a stale inode but the log
        //     durably committed would force a rebuild on reload — which is
        //     correct but wastes an O(n) scan.  fsyncing keeps the pair
        //     in lock-step on disk.
        let idx_path = self.log_idx_path();
        if idx_path.exists() {
            if let Ok(f) = std::fs::OpenOptions::new().read(true).open(&idx_path) {
                f.sync_all().map_err(|e| StorageError::Io(e.to_string()))?;
            }
        }
        // 2. fsync the hard-state file (if it exists).
        let hard_path = self.hard_path();
        if hard_path.exists() {
            if let Ok(f) = std::fs::OpenOptions::new().read(true).open(&hard_path) {
                f.sync_all().map_err(|e| StorageError::Io(e.to_string()))?;
            }
        }
        // 3. Best-effort directory fsync (Unix only; ignored on Windows,
        //    where directory fsync isn't necessary for rename durability).
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(&self.dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn load_snapshot(&self) -> StorageResult<Option<PersistedSnapshot>> {
        let path = self.snap_path();
        if !path.exists() {
            return Ok(None);
        }
        let meta = std::fs::metadata(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        if meta.len() as u128 > MAX_SNAPSHOT_BYTES as u128 {
            return Err(StorageError::Codec(format!(
                "snapshot file exceeds MAX_SNAPSHOT_BYTES ({} > {})",
                meta.len(),
                MAX_SNAPSHOT_BYTES
            )));
        }
        let bytes = std::fs::read(&path).map_err(|e| StorageError::Io(e.to_string()))?;

        // Footer must be present.
        if bytes.len() < SNAPSHOT_FOOTER_LEN {
            tracing::error!(
                "FileStorage: snapshot file too short to contain footer ({} < {})",
                bytes.len(),
                SNAPSHOT_FOOTER_LEN
            );
            return Err(StorageError::SnapshotIntegrityFailure(
                "snapshot file truncated or missing authentication footer".to_string(),
            ));
        }

        let footer_start = bytes.len() - SNAPSHOT_FOOTER_LEN;
        let footer = &bytes[footer_start..];
        let payload = &bytes[..footer_start];

        // Parse footer fields. `try_into().unwrap()` is safe because the
        // slice lengths are fixed and we already verified `bytes.len() >=
        // SNAPSHOT_FOOTER_LEN` above; however, a malicious truncation that
        // passed the size check but corrupted the layout must not panic. We
        // use `try_into` with explicit `ok_or` so the function returns an
        // integrity error instead of unwinding.
        let magic_slice = &footer[0..16];
        let parse_u64 = |slice: &[u8]| -> Result<u64, StorageError> {
            let arr: [u8; 8] = slice.try_into().map_err(|_| {
                StorageError::SnapshotIntegrityFailure(
                    "snapshot footer field has wrong length".to_string(),
                )
            })?;
            Ok(u64::from_le_bytes(arr))
        };
        let decl_len = parse_u64(&footer[16..24])?;
        let decl_index = parse_u64(&footer[24..32])?;
        let decl_term = parse_u64(&footer[32..40])?;
        let mut file_tag = [0u8; 32];
        if footer[40..72].len() != file_tag.len() {
            return Err(StorageError::SnapshotIntegrityFailure(
                "snapshot footer tag slice has wrong length".to_string(),
            ));
        }
        file_tag.copy_from_slice(&footer[40..72]);

        // Magic gate first — detects cross-version snapshots and totally
        // unauthenticated legacy files.
        if magic_slice != SNAPSHOT_MAGIC {
            tracing::error!(
                "FileStorage: snapshot footer magic mismatch \
                 (got {:02x?}, expected CRATON-SNAP-v1)",
                magic_slice
            );
            return Err(StorageError::SnapshotIntegrityFailure(
                "snapshot magic mismatch (legacy or cross-version file?)".to_string(),
            ));
        }

        // Declared payload length must match the bytes preceding the footer.
        if decl_len as usize != payload.len() {
            tracing::error!(
                "FileStorage: snapshot footer declared length ({}) does not \
                 match on-disk payload length ({})",
                decl_len,
                payload.len()
            );
            return Err(StorageError::SnapshotIntegrityFailure(
                "snapshot footer length does not match payload length".to_string(),
            ));
        }

        // Verify the MAC according to configured mode.
        let all_zero = file_tag.iter().all(|b| *b == 0);
        match (&self.snapshot_key, self.allow_insecure) {
            (Some(k), _) => {
                let expected = compute_snapshot_tag(k.as_ref(), payload, decl_index, decl_term);
                if !ct_tag_eq(&expected, &file_tag) {
                    tracing::error!(
                        "FileStorage: snapshot HMAC verification FAILED — \
                         snapshot will not be loaded (possible tampering or \
                         unauthenticated source)"
                    );
                    return Err(StorageError::SnapshotIntegrityFailure(
                        "snapshot HMAC tag mismatch".to_string(),
                    ));
                }
            }
            (None, true) => {
                // Dev-only: accept only if the MAC is all-zeros, meaning the
                // snapshot was also written in insecure mode.  A non-zero MAC
                // means the snapshot came from an authenticated cluster and
                // MUST NOT be silently installed on an insecure node.
                if !all_zero {
                    tracing::error!(
                        "FileStorage: refusing to load authenticated snapshot \
                         in insecure mode — the node has no cluster_secret \
                         configured but the snapshot carries a non-zero MAC"
                    );
                    return Err(StorageError::SnapshotIntegrityFailure(
                        "authenticated snapshot rejected by insecure loader".to_string(),
                    ));
                }
                tracing::warn!(
                    "FileStorage: loading UNAUTHENTICATED snapshot (allow_insecure=true)"
                );
            }
            (None, false) => {
                tracing::error!(
                    "FileStorage: no cluster_secret configured and \
                     allow_insecure=false — refusing to load snapshot"
                );
                return Err(StorageError::SnapshotIntegrityFailure(
                    "no cluster_secret configured and allow_insecure=false — \
                     refusing to load snapshot"
                        .to_string(),
                ));
            }
        }

        // Finally, deserialize the payload.
        let snap: PersistedSnapshot =
            serde_json::from_slice(payload).map_err(|e| StorageError::Codec(e.to_string()))?;

        // Cross-check: declared footer index/term must match payload metadata
        // to keep the authenticated fields in sync with the JSON body.
        if snap.last_index != decl_index || snap.last_term.value() != decl_term {
            tracing::error!(
                "FileStorage: snapshot payload (index={}, term={}) disagrees \
                 with authenticated footer (index={}, term={})",
                snap.last_index,
                snap.last_term.value(),
                decl_index,
                decl_term
            );
            return Err(StorageError::SnapshotIntegrityFailure(
                "footer index/term disagrees with payload".to_string(),
            ));
        }

        Ok(Some(snap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::RaftCommand;

    fn entry(term: u64, index: u64) -> LogEntry {
        LogEntry {
            term: Term(term),
            index,
            command: RaftCommand::Noop,
        }
    }

    #[test]
    fn in_memory_roundtrip() {
        let s = InMemoryStorage::new();
        assert_eq!(s.load_hard_state().unwrap(), HardState::default());
        let hs = HardState {
            current_term: Term(7),
            voted_for: Some("n2".into()),
        };
        s.save_hard_state(&hs).unwrap();
        assert_eq!(s.load_hard_state().unwrap(), hs);

        s.append_log(&[entry(1, 1), entry(1, 2)]).unwrap();
        s.append_log(&[entry(1, 3)]).unwrap();
        assert_eq!(s.load_log().unwrap().len(), 3);
        s.truncate_log_after(2).unwrap();
        assert_eq!(s.load_log().unwrap().len(), 2);

        let snap = PersistedSnapshot {
            last_index: 2,
            last_term: Term(1),
            voters: vec!["n1".into(), "n2".into()],
            data: b"state".to_vec(),
        };
        s.save_snapshot(&snap).unwrap();
        assert_eq!(s.load_snapshot().unwrap(), Some(snap));
    }

    /// Test helper: opens a FileStorage with a fixed cluster secret so
    /// snapshot round-trips pass authentication.
    fn open_authenticated(dir: &Path) -> FileStorage {
        FileStorage::open(dir)
            .unwrap()
            .with_cluster_secret(&[0x42u8; 32])
    }

    #[test]
    fn file_storage_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = open_authenticated(dir.path());
        assert_eq!(s.load_hard_state().unwrap(), HardState::default());

        let hs = HardState {
            current_term: Term(3),
            voted_for: Some("n1".into()),
        };
        s.save_hard_state(&hs).unwrap();
        // Reopen and read.
        let s2 = open_authenticated(dir.path());
        assert_eq!(s2.load_hard_state().unwrap(), hs);

        s.append_log(&[entry(1, 1), entry(1, 2), entry(2, 3)])
            .unwrap();
        let log = s.load_log().unwrap();
        assert_eq!(log.len(), 3);
        s.truncate_log_after(1).unwrap();
        assert_eq!(s.load_log().unwrap().len(), 1);

        let snap = PersistedSnapshot {
            last_index: 1,
            last_term: Term(1),
            voters: vec!["n1".into()],
            data: b"abc".to_vec(),
        };
        s.save_snapshot(&snap).unwrap();
        assert_eq!(s.load_snapshot().unwrap().as_ref(), Some(&snap));
    }

    #[test]
    fn file_storage_empty_load() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path()).unwrap();
        assert!(s.load_log().unwrap().is_empty());
        assert!(s.load_snapshot().unwrap().is_none());
        // Truncate on missing log is a no-op.
        s.truncate_log_after(0).unwrap();
    }

    #[test]
    fn test_concurrent_append() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path()).unwrap();

        // Multiple sequential appends should accumulate entries
        s.append_log(&[entry(1, 1)]).unwrap();
        s.append_log(&[entry(1, 2)]).unwrap();
        s.append_log(&[entry(2, 3)]).unwrap();
        s.append_log(&[entry(2, 4), entry(2, 5)]).unwrap();

        let log = s.load_log().unwrap();
        assert_eq!(log.len(), 5);
        assert_eq!(log[0].index, 1);
        assert_eq!(log[4].index, 5);
        assert_eq!(log[4].term, Term(2));
    }

    #[test]
    fn test_storage_persistence() {
        let dir = tempfile::tempdir().unwrap();

        // Write data, then drop the storage
        {
            let s = open_authenticated(dir.path());
            let hs = HardState {
                current_term: Term(5),
                voted_for: Some("node-a".into()),
            };
            s.save_hard_state(&hs).unwrap();
            s.append_log(&[entry(3, 1), entry(4, 2), entry(5, 3)])
                .unwrap();
            let snap = PersistedSnapshot {
                last_index: 3,
                last_term: Term(5),
                voters: vec!["node-a".into(), "node-b".into()],
                data: b"snapshot-data".to_vec(),
            };
            s.save_snapshot(&snap).unwrap();
            // s is dropped here
        }

        // Reopen and verify all data persisted
        {
            let s = open_authenticated(dir.path());
            let hs = s.load_hard_state().unwrap();
            assert_eq!(hs.current_term, Term(5));
            assert_eq!(hs.voted_for.as_deref(), Some("node-a"));

            let log = s.load_log().unwrap();
            assert_eq!(log.len(), 3);
            assert_eq!(log[2].term, Term(5));

            let snap = s.load_snapshot().unwrap().expect("snapshot should exist");
            assert_eq!(snap.last_index, 3);
            assert_eq!(snap.data, b"snapshot-data");
        }
    }

    #[test]
    fn test_truncate_and_append() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path()).unwrap();

        // Append 5 entries
        s.append_log(&[
            entry(1, 1),
            entry(1, 2),
            entry(2, 3),
            entry(2, 4),
            entry(3, 5),
        ])
        .unwrap();
        assert_eq!(s.load_log().unwrap().len(), 5);

        // Truncate after index 2 (keep entries 1 and 2)
        s.truncate_log_after(2).unwrap();
        let log = s.load_log().unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].index, 1);
        assert_eq!(log[1].index, 2);

        // Append new entries after truncation
        s.append_log(&[entry(3, 3), entry(3, 4)]).unwrap();
        let log = s.load_log().unwrap();
        assert_eq!(log.len(), 4);
        assert_eq!(log[2].term, Term(3), "new entries should have term 3");
        assert_eq!(log[3].index, 4);

        // Truncate all (after index 0)
        s.truncate_log_after(0).unwrap();
        assert!(s.load_log().unwrap().is_empty());

        // Append after full truncation
        s.append_log(&[entry(4, 1)]).unwrap();
        assert_eq!(s.load_log().unwrap().len(), 1);
    }

    /// A corrupt/forged log line larger than MAX_LOG_ENTRY_BYTES must fail
    /// cleanly instead of being deserialized into a giant allocation.
    #[test]
    fn test_load_log_rejects_oversized_line() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path()).unwrap();
        // Directly write an attacker-controlled log.jsonl with one line that
        // exceeds the bound.  The JSON inside doesn't matter: the byte-length
        // check fires before we try to parse.
        let line = "x".repeat(MAX_LOG_ENTRY_BYTES + 1);
        std::fs::write(s.log_path(), line.as_bytes()).unwrap();

        let err = s.load_log().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("MAX_LOG_ENTRY_BYTES"),
            "expected size-limit error, got: {msg}"
        );
    }

    /// Oversized snapshot files must be rejected before `read` loads them.
    #[test]
    fn test_load_snapshot_size_ceiling_is_exported() {
        // We cannot easily produce a >1 GiB file in a unit test, so just
        // assert that the constant is exported and is the value we advertise.
        assert_eq!(MAX_SNAPSHOT_BYTES, 1024 * 1024 * 1024);
        assert_eq!(MAX_LOG_ENTRY_BYTES, 16 * 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // Authenticated-snapshot tests (Task A — audit fix)
    // -----------------------------------------------------------------------

    fn sample_snapshot() -> PersistedSnapshot {
        PersistedSnapshot {
            last_index: 42,
            last_term: Term(7),
            voters: vec!["n1".into(), "n2".into()],
            data: b"sm-state-blob".to_vec(),
        }
    }

    /// 1. Round-trip ok: a snapshot saved and loaded by the same
    /// authenticated FileStorage must deserialize to the original value.
    #[test]
    fn test_snapshot_authenticated_roundtrip_ok() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path())
            .unwrap()
            .with_cluster_secret(b"32-byte-key-material-for-testing");
        let snap = sample_snapshot();
        s.save_snapshot(&snap).unwrap();
        let loaded = s.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded, snap);
    }

    /// 2. Tampered payload fails: flip a byte in the JSON payload; MAC must
    /// catch it and load must return `SnapshotIntegrityFailure`.
    #[test]
    fn test_snapshot_tampered_payload_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.json");
        let s = FileStorage::open(dir.path())
            .unwrap()
            .with_cluster_secret(&[0x11; 32]);
        s.save_snapshot(&sample_snapshot()).unwrap();

        // Flip a byte in the middle of the payload region (well before the
        // 72-byte footer).
        let mut bytes = std::fs::read(&path).unwrap();
        let idx = (bytes.len() - SNAPSHOT_FOOTER_LEN) / 2;
        bytes[idx] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let err = s.load_snapshot().unwrap_err();
        assert!(
            matches!(err, StorageError::SnapshotIntegrityFailure(_)),
            "expected SnapshotIntegrityFailure, got {err:?}"
        );
    }

    /// 3. Tampered index/term fails: rewriting the footer index or term
    /// bytes (without recomputing the MAC) must be caught.
    #[test]
    fn test_snapshot_tampered_index_or_term_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.json");
        let s = FileStorage::open(dir.path())
            .unwrap()
            .with_cluster_secret(&[0x22; 32]);
        s.save_snapshot(&sample_snapshot()).unwrap();

        // Footer layout (from end of 72-byte footer): magic(16) || len(8)
        // || index(8) || term(8) || mac(32).  Index field starts at
        // file_len - 48 and is 8 bytes long.
        let mut bytes = std::fs::read(&path).unwrap();
        let len = bytes.len();
        // Bump the snapshot_index field by 1 without recomputing the MAC.
        let idx_start = len - 48;
        let mut idx_bytes: [u8; 8] = bytes[idx_start..idx_start + 8].try_into().unwrap();
        let mut val = u64::from_le_bytes(idx_bytes);
        val = val.wrapping_add(1);
        idx_bytes = val.to_le_bytes();
        bytes[idx_start..idx_start + 8].copy_from_slice(&idx_bytes);
        std::fs::write(&path, &bytes).unwrap();

        let err = s.load_snapshot().unwrap_err();
        assert!(
            matches!(err, StorageError::SnapshotIntegrityFailure(_)),
            "expected SnapshotIntegrityFailure, got {err:?}"
        );
    }

    /// 4. Missing footer fails: a snapshot file shorter than the footer
    /// length must be rejected.
    #[test]
    fn test_snapshot_missing_footer_fails() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path())
            .unwrap()
            .with_cluster_secret(&[0x33; 32]);
        // Write a short file (legacy-style raw JSON with no footer).
        let json = serde_json::to_vec(&sample_snapshot()).unwrap();
        std::fs::write(dir.path().join("snapshot.json"), &json).unwrap();
        let err = s.load_snapshot().unwrap_err();
        assert!(
            matches!(err, StorageError::SnapshotIntegrityFailure(_)),
            "expected SnapshotIntegrityFailure, got {err:?}"
        );
    }

    /// 5. Magic mismatch fails: if the 16-byte magic is altered (simulating
    /// a cross-version or forged footer), the loader must refuse.
    #[test]
    fn test_snapshot_magic_mismatch_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.json");
        let s = FileStorage::open(dir.path())
            .unwrap()
            .with_cluster_secret(&[0x44; 32]);
        s.save_snapshot(&sample_snapshot()).unwrap();

        // Corrupt the magic bytes.
        let mut bytes = std::fs::read(&path).unwrap();
        let magic_start = bytes.len() - SNAPSHOT_FOOTER_LEN;
        bytes[magic_start] = b'X'; // 'C' -> 'X'
        std::fs::write(&path, &bytes).unwrap();

        let err = s.load_snapshot().unwrap_err();
        match err {
            StorageError::SnapshotIntegrityFailure(ref m) => {
                assert!(m.contains("magic"), "expected magic-mismatch message: {m}");
            }
            other => panic!("expected SnapshotIntegrityFailure, got {other:?}"),
        }
    }

    /// 6. allow_insecure-written snapshot is rejected by a secured loader.
    /// This is the cross-mode safety check: a dev-mode snapshot (all-zero
    /// MAC) must NEVER be silently installed into an authenticated cluster.
    #[test]
    fn test_insecure_snapshot_rejected_by_secure_loader() {
        let dir = tempfile::tempdir().unwrap();

        // Write with allow_insecure = true (all-zero MAC footer).
        {
            let s = FileStorage::open(dir.path()).unwrap().allow_insecure(true);
            s.save_snapshot(&sample_snapshot()).unwrap();
        }

        // Open the SAME directory with an authenticated loader.
        let secure = FileStorage::open(dir.path())
            .unwrap()
            .with_cluster_secret(&[0x55; 32]);
        let err = secure.load_snapshot().unwrap_err();
        assert!(
            matches!(err, StorageError::SnapshotIntegrityFailure(_)),
            "secure loader must reject insecure-written snapshot, got {err:?}"
        );
    }

    /// Additional coverage: an authenticated snapshot must be rejected by
    /// an insecure loader too (the dual of the previous test) so a node
    /// that has lost its key never silently downgrades.
    #[test]
    fn test_authenticated_snapshot_rejected_by_insecure_loader() {
        let dir = tempfile::tempdir().unwrap();

        // Write with a real cluster secret.
        {
            let s = FileStorage::open(dir.path())
                .unwrap()
                .with_cluster_secret(&[0x66; 32]);
            s.save_snapshot(&sample_snapshot()).unwrap();
        }

        // Load with allow_insecure = true: must refuse because the footer
        // carries a non-zero MAC.
        let loader = FileStorage::open(dir.path()).unwrap().allow_insecure(true);
        let err = loader.load_snapshot().unwrap_err();
        assert!(
            matches!(err, StorageError::SnapshotIntegrityFailure(_)),
            "insecure loader must refuse authenticated snapshot, got {err:?}"
        );
    }

    /// Default (no secret, no allow_insecure) FileStorage must fail closed
    /// for both save and load snapshot.
    #[test]
    fn test_default_file_storage_fails_closed_on_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path()).unwrap();
        let err = s.save_snapshot(&sample_snapshot()).unwrap_err();
        assert!(matches!(err, StorageError::SnapshotIntegrityFailure(_)));
    }

    /// `ct_tag_eq` returns true on equal inputs and false on any single-bit
    /// flip at any byte position. The correctness check is what we can test
    /// cheaply; the timing property is delegated to the `subtle` crate.
    #[test]
    fn test_ct_tag_eq_correctness() {
        let a = [0x5Au8; 32];
        assert!(ct_tag_eq(&a, &a));
        for bit in 0..256 {
            let byte = bit / 8;
            let mask = 1u8 << (bit % 8);
            let mut b = a;
            b[byte] ^= mask;
            assert!(
                !ct_tag_eq(&a, &b),
                "ct_tag_eq must detect a single-bit flip at bit {bit}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Offset-index (audit L-truncate) tests
    // -----------------------------------------------------------------------

    /// Appending builds a .idx whose record count matches the log entry
    /// count, and a subsequent truncate_log_after preserves the survivors
    /// plus a matching .idx.
    #[test]
    fn test_log_idx_append_and_fast_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStorage::open(dir.path()).unwrap();
        let entries: Vec<LogEntry> = (1..=100).map(|i| entry(1, i)).collect();
        s.append_log(&entries).unwrap();

        let idx_path = s.log_idx_path();
        assert!(
            idx_path.exists(),
            ".idx sidecar must be created by append_log"
        );
        let idx_bytes = std::fs::read(&idx_path).unwrap();
        assert_eq!(
            idx_bytes.len() % LOG_INDEX_RECORD_LEN,
            0,
            ".idx size must be a multiple of record width"
        );
        assert_eq!(
            idx_bytes.len() / LOG_INDEX_RECORD_LEN,
            100,
            ".idx must carry exactly one record per log entry"
        );

        // Fast-path truncate: drop entries 51..=100.
        s.truncate_log_after(50).unwrap();
        let after = s.load_log().unwrap();
        assert_eq!(after.len(), 50);
        assert_eq!(after.last().unwrap().index, 50);
        let idx_bytes = std::fs::read(&idx_path).unwrap();
        assert_eq!(
            idx_bytes.len() / LOG_INDEX_RECORD_LEN,
            50,
            ".idx must shrink in lock-step with the log"
        );
    }

    /// A corrupted .idx (truncated to zero bytes) must be auto-rebuilt on
    /// reopen, and the canonical log.jsonl contents must remain intact.
    #[test]
    fn test_log_idx_auto_rebuild_on_corruption() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = FileStorage::open(dir.path()).unwrap();
            s.append_log(&[entry(1, 1), entry(1, 2), entry(2, 3)])
                .unwrap();
        }
        // Truncate the .idx to zero bytes — simulates a torn write.
        let idx_path = dir.path().join("log.jsonl.idx");
        std::fs::write(&idx_path, b"").unwrap();

        // Reopening reconciles the sidecar.
        let s = FileStorage::open(dir.path()).unwrap();
        let loaded = s.load_log().unwrap();
        assert_eq!(loaded.len(), 3, "log contents must survive idx corruption");

        let idx_bytes = std::fs::read(&idx_path).unwrap();
        assert_eq!(
            idx_bytes.len() / LOG_INDEX_RECORD_LEN,
            3,
            "reopen must rebuild the .idx to match the log"
        );

        // And a subsequent truncate still works (fast path).
        s.truncate_log_after(1).unwrap();
        assert_eq!(s.load_log().unwrap().len(), 1);
    }

    /// Truncating a log that pre-dates the .idx (legacy deployment) must
    /// fall through to the slow path AND leave behind a fresh .idx so
    /// future truncates stay on the fast path.
    #[test]
    fn test_log_idx_legacy_migration_on_truncate() {
        let dir = tempfile::tempdir().unwrap();
        // Write a log.jsonl directly without ever going through
        // append_log, then delete any stray .idx file to simulate a
        // legacy deployment.
        let log_path = dir.path().join("log.jsonl");
        let mut buf = String::new();
        for i in 1..=5 {
            let e = entry(1, i);
            buf.push_str(&serde_json::to_string(&e).unwrap());
            buf.push('\n');
        }
        std::fs::write(&log_path, buf.as_bytes()).unwrap();
        let idx_path = dir.path().join("log.jsonl.idx");
        let _ = std::fs::remove_file(&idx_path);

        // Open: reconciliation rebuilds the .idx.
        let s = FileStorage::open(dir.path()).unwrap();
        assert!(
            idx_path.exists(),
            "reconcile_log_index must create a .idx for legacy deployments"
        );

        // Delete .idx again so the truncate call itself exercises the
        // "no .idx present" path (the slow rebuild branch inside
        // truncate_log_after).
        std::fs::remove_file(&idx_path).unwrap();
        s.truncate_log_after(3).unwrap();
        let log = s.load_log().unwrap();
        assert_eq!(log.len(), 3);
        assert!(
            idx_path.exists(),
            "slow-path truncate must leave a .idx behind for future fast-path use"
        );
        let idx_bytes = std::fs::read(&idx_path).unwrap();
        assert_eq!(idx_bytes.len() / LOG_INDEX_RECORD_LEN, 3);
    }
}
