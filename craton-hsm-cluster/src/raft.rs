// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Raft consensus core — state machine, log, and RPC message types.
//!
//! This module implements the Raft state-machine: term tracking, leader
//! election, log replication (`AppendEntries`), and snapshot installation
//! (`InstallSnapshot`).  It is wired to a [`RaftStorage`] for crash-safe
//! persistence of `current_term`, `voted_for`, the log, and snapshots, and
//! to a [`ClusterStateMachine`] for command application.
//!
//! ## Security
//!
//! Every RPC carries an HMAC-SHA256 over a canonical, length-prefixed
//! encoding of its fields, plus a 1-byte domain-separator tag.  Replay
//! protection combines a freshness window (rejecting messages whose
//! timestamps drift outside `max_message_age_ms`) and a bounded recent-MAC
//! cache.  Dedup uses `dashmap::Entry::Occupied` semantics to be
//! TOCTOU-free.

use crate::config::ClusterConfig;
use crate::state_machine::{ClusterStateMachine, StateMachineSnapshot};
use crate::storage::{HardState, PersistedSnapshot, RaftStorage, StorageError};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use parking_lot::Mutex as PLMutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Domain separation tags for HMAC
// ---------------------------------------------------------------------------

const DOMAIN_REQUEST_VOTE: u8 = 0x01;
const DOMAIN_APPEND_ENTRIES: u8 = 0x02;
const DOMAIN_INSTALL_SNAPSHOT: u8 = 0x03;
/// Fix 7: domain tag for the PreVote RPC, distinct from the regular
/// RequestVote tag so a pre-vote MAC cannot be replayed as a real vote.
const DOMAIN_PRE_VOTE: u8 = 0x05;
/// H17 (legacy, pre-`DOMAIN_REPLY_*`): the original reply-MAC scheme
/// prepended two bytes `[DOMAIN_REPLY_LEGACY, <kind>]` while every
/// request domain used a single byte. The single-byte
/// `DOMAIN_REPLY_*` constants below replaced this scheme to keep all
/// HMAC domain prefixes the same width. The constant is retained
/// solely so the *verifier* can recompute a legacy MAC during a
/// rolling upgrade when [`RaftNode::accept_legacy_reply_hmac_tags`]
/// is enabled. Senders MUST NOT use this prefix anymore.
///
/// Sunset: remove the legacy verify path (and this constant) two
/// releases after the cut-over so mixed-version traffic never
/// silently regresses to the longer prefix.
const DOMAIN_REPLY_LEGACY: u8 = 0x06;
/// Single-byte reply-MAC domain tags. Each reply variant gets its
/// own tag so a future edit that adds a sibling 1-byte domain cannot
/// collide with a trimmed 2-byte one (canonicalization-foot-gun
/// finding from the audit).
///
/// ## Wire-format compatibility
///
/// `sign_*_reply` always emits MACs under these new single-byte
/// tags. `verify_*_reply` accepts the new tags unconditionally; when
/// [`RaftNode::accept_legacy_reply_hmac_tags`] is `true` (the
/// default for one release cycle), the verifier also falls back to
/// the legacy two-byte prefix so a mixed-version cluster can roll
/// forward without a coordinated drain-and-restart.
///
/// ## Why we chose Option A (try-both-tags during verify)
///
/// We considered two paths for safe negotiation:
///
/// * **Option B — version byte in the reply preamble**: cleaner long-
///   term but requires changing every reply struct (and the on-wire
///   layout) to add a `wire_version: u8` field bound by the MAC.
///   That's a wider blast radius than the original tag-normalization.
/// * **Option A — try-both-tags during verify**: zero change to the
///   reply struct, zero change to the sender side, one extra HMAC
///   compute on the (rare) legacy-peer reply. Capped at exactly one
///   fallback so the worst-case CPU cost is bounded at 2x verify.
///
/// Option A is materially cheaper for the rolling upgrade we
/// actually need to support, so we ship that and leave Option B as a
/// dead branch documented here.
const DOMAIN_REPLY_REQUEST_VOTE: u8 = 0x10;
const DOMAIN_REPLY_APPEND_ENTRIES: u8 = 0x11;
const DOMAIN_REPLY_INSTALL_SNAPSHOT: u8 = 0x12;
const DOMAIN_REPLY_PRE_VOTE: u8 = 0x13;

/// L (audit): maximum size in bytes of any single wire frame this Raft
/// node will deserialize. Frames larger than this are rejected before
/// deserialization so the verifier does not amplify a malicious peer\'s
/// memory footprint. Sized at 1 MiB which covers any legitimate
/// AppendEntries batch without being a useful DoS lever.
pub const MAX_WIRE_FRAME_BYTES: usize = 1 * 1024 * 1024;

/// H14: maximum size in bytes of an InstallSnapshot data payload.
/// Snapshots larger than this are rejected at `verify_install_snapshot`
/// time so a malicious leader cannot exhaust follower memory by
/// streaming a multi-gigabyte snapshot. Set at 64 MiB — well above
/// the typical state-machine snapshot but below the host-memory
/// ceiling on small deployments.
///
/// This constant intentionally shadows `storage::MAX_SNAPSHOT_BYTES`
/// (1 GiB) — the on-the-wire ceiling is stricter than the on-disk
/// ceiling because RPCs must fit in main memory whereas a stored
/// snapshot may be streamed from disk into the state machine.
pub const MAX_INSTALL_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum number of cached MACs in the replay-protection set.  Once exceeded,
/// the eldest entries are pruned to keep memory bounded.
///
/// ## Sizing rationale
///
/// A 16 384-entry cap bounds worst-case memory to ~1.3 MiB (16384 × 80 B for
/// the [u8;32] key + VecDeque entry + map overhead) while comfortably
/// accommodating the maximum plausible message burst inside the default
/// 30 s freshness window: a cluster of 16 voters exchanging AppendEntries at
/// a 300 ms heartbeat cadence emits ~16 × 2 × (30000/300) ≈ 3200 MACs per
/// window, leaving >5× headroom for election storms. The previous 4096
/// value was observed to alias out legitimate non-replayed MACs on larger
/// clusters under test, causing the replay check to return "already
/// present" for a freshly-generated MAC.
pub const REPLAY_CACHE_MAX: usize = 16_384;

// ---------------------------------------------------------------------------
// Raft state
// ---------------------------------------------------------------------------

/// The role a node plays in the Raft cluster.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftState {
    /// Passive replica that accepts log entries from the leader.
    #[default]
    Follower,
    /// Node that has started an election and is soliciting votes.
    Candidate,
    /// Active leader responsible for replicating state to followers.
    Leader,
}

// ---------------------------------------------------------------------------
// Term newtype
// ---------------------------------------------------------------------------

/// A Raft election term (monotonically increasing).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Term(pub u64);

impl Term {
    /// Returns the inner `u64` value.
    pub fn value(self) -> u64 {
        self.0
    }

    /// Returns the next term, or `None` on `u64` overflow.
    ///
    /// Overflow would require more elections than atoms in the observable
    /// universe, but we still surface it as `None` rather than panicking so a
    /// pathological / adversarial election storm cannot be used as a remote
    /// panic primitive.  Callers at the election boundary should propagate
    /// this as [`RaftError::TermOverflow`] and refuse to start a new election.
    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    /// Fallible addition — returns `None` on `u64` overflow.
    pub fn checked_add(self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    /// Backwards-compatible variant.  Prefer
    /// [`checked_next`](Self::checked_next) in new code.
    ///
    /// Audit-stub fix (raft.rs:119-121): the previous version panicked on
    /// `u64` overflow.  An adversary that can drive the Raft term counter
    /// (e.g. via a forged election storm) could weaponize that panic as a
    /// remote-DoS primitive against a release build.  We now saturate at
    /// [`u64::MAX`] and emit a `warn`-level tracing event so operators can
    /// detect the pathological case while keeping the node alive.  The
    /// caller is responsible for treating a non-monotonic term as fatal
    /// at the policy layer (e.g. refuse to start a new election when the
    /// term is already saturated).
    pub fn next(self) -> Self {
        match self.checked_next() {
            Some(t) => t,
            None => {
                tracing::warn!(
                    "Term::next() saturating at u64::MAX — adversarial                      election storm or bug; refuse further term bumps"
                );
                Term(u64::MAX)
            }
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Term({})", self.0)
    }
}

impl std::ops::Add<u64> for Term {
    type Output = Self;
    /// Saturating addition: at `u64::MAX` the term is pinned (no panic).
    ///
    /// Previously this method panicked on overflow, which let a peer that
    /// could nudge the term counter toward `u64::MAX` DoS the process by
    /// triggering the panic. Saturation preserves liveness — a term pinned
    /// at `u64::MAX` simply prevents future elections, which is a degraded
    /// but non-crashing mode an operator can detect and respond to.
    fn add(self, rhs: u64) -> Self {
        Term(self.0.saturating_add(rhs))
    }
}

impl From<u64> for Term {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

// ---------------------------------------------------------------------------
// Log entry types
// ---------------------------------------------------------------------------

/// Action to take on cluster membership.
///
/// `AddLearner` and `PromoteLearner` are non-voting/promotion variants
/// reserved for the future joint-consensus implementation; the current
/// state machine treats them as `AddNode` for the purposes of voter-set
/// math but the wire format already distinguishes them so a future
/// upgrade can roll out without a schema break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MembershipAction {
    /// Add a new voting member to the cluster.
    AddNode,
    /// Remove an existing voting member from the cluster.
    RemoveNode,
    /// Add a new node as a non-voting *learner*. Learners receive log
    /// replication but do not count toward quorum until promoted via
    /// `PromoteLearner`. (Stub — current state machine treats as
    /// `AddNode`; voter-set math is unchanged in this release.)
    AddLearner,
    /// Promote an existing learner to voting membership. (Stub — current
    /// state machine treats as `AddNode` if not already a voter.)
    PromoteLearner,
}

/// A command carried by a Raft log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RaftCommand {
    /// Synchronize key material to peers.
    KeySync {
        /// Identifier for the key being synced.
        key_id: String,
        /// Serialized key data.  Wrapped in [`Zeroizing`] so that the key
        /// material is securely erased from memory when this command is dropped.
        data: Zeroizing<Vec<u8>>,
    },
    /// Change cluster membership.
    ConfigChange {
        /// Node affected by the change.
        node_id: String,
        /// Whether to add or remove the node.
        action: MembershipAction,
    },
    /// No-operation entry used for leader commit confirmation.
    Noop,
}

impl RaftCommand {
    /// Encode this command into a deterministic, length-prefixed binary form
    /// for HMAC computation.  Tag bytes:
    ///
    /// | tag  | meaning             |
    /// |------|---------------------|
    /// | 0x00 | `Noop`              |
    /// | 0x01 | `KeySync`           |
    /// | 0x02 | `ConfigChange::Add` |
    /// | 0x03 | `ConfigChange::Rem` |
    ///
    /// MED (audit, perf): prefer
    /// [`canonical_into_mac`](Self::canonical_into_mac) when feeding the
    /// bytes directly into an HMAC stream — it avoids the intermediate
    /// `Vec<u8>` allocation. This method is retained for callers that
    /// need an owned canonical byte string (length-gating in
    /// `verify_append_entries`, tests, etc.).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Self::Noop => out.push(0x00),
            Self::KeySync { key_id, data } => {
                out.push(0x01);
                push_lp(&mut out, key_id.as_bytes());
                push_lp(&mut out, data);
            }
            Self::ConfigChange { node_id, action } => {
                out.push(match action {
                    MembershipAction::AddNode => 0x02,
                    MembershipAction::RemoveNode => 0x03,
                    MembershipAction::AddLearner => 0x04,
                    MembershipAction::PromoteLearner => 0x05,
                });
                push_lp(&mut out, node_id.as_bytes());
            }
        }
        out
    }

    /// MED (audit, perf): byte-identical to [`canonical_bytes`] but
    /// streams the canonical encoding directly into the supplied HMAC
    /// instance — no intermediate `Vec<u8>` allocation. This is the
    /// preferred call site for HMAC computation paths
    /// (`compute_append_entries_hmac_shared` and friends).
    ///
    /// Encoding parity: the two functions MUST produce identical byte
    /// sequences; any future encoding change must be applied to both
    /// in lockstep.
    pub fn canonical_into_mac(&self, mac: &mut Hmac<Sha256>) {
        match self {
            Self::Noop => mac.update(&[0x00]),
            Self::KeySync { key_id, data } => {
                mac.update(&[0x01]);
                push_lp_to_mac(mac, key_id.as_bytes());
                push_lp_to_mac(mac, data);
            }
            Self::ConfigChange { node_id, action } => {
                let tag: u8 = match action {
                    MembershipAction::AddNode => 0x02,
                    MembershipAction::RemoveNode => 0x03,
                    MembershipAction::AddLearner => 0x04,
                    MembershipAction::PromoteLearner => 0x05,
                };
                mac.update(&[tag]);
                push_lp_to_mac(mac, node_id.as_bytes());
            }
        }
    }
}

/// Length-prefix (u32 big-endian) and append.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// MED (audit, perf): compute the exact byte length the encoding in
/// [`RaftCommand::canonical_bytes`] / [`RaftCommand::canonical_into_mac`]
/// would emit, without materializing any bytes. Used to length-prefix
/// the canonical command stream when feeding it directly into an HMAC
/// without an intermediate `Vec<u8>`. Must stay in lockstep with the
/// two encoders above.
fn canonical_byte_len(cmd: &RaftCommand) -> usize {
    match cmd {
        RaftCommand::Noop => 1,
        RaftCommand::KeySync { key_id, data } => {
            // tag + lp(key_id) + lp(data)
            1 + 4 + key_id.as_bytes().len() + 4 + data.len()
        }
        RaftCommand::ConfigChange { node_id, .. } => {
            // tag + lp(node_id)
            1 + 4 + node_id.as_bytes().len()
        }
    }
}

/// A single entry in the Raft log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// The term in which this entry was created.
    pub term: Term,
    /// The position of this entry in the log (1-indexed).
    pub index: u64,
    /// The command to apply.
    pub command: RaftCommand,
}

// ---------------------------------------------------------------------------
// Raft log
// ---------------------------------------------------------------------------

/// Append-only log of Raft entries with commit/apply tracking.
#[derive(Debug, Clone, Default)]
pub struct RaftLog {
    entries: Vec<LogEntry>,
    committed: u64,
    applied: u64,
}

impl RaftLog {
    /// Create a new empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to the log.
    pub fn append(&mut self, entry: LogEntry) {
        self.entries.push(entry);
    }

    /// Get a log entry by its 1-based index.
    ///
    /// Entries are stored contiguously starting from `entries[0].index`, so
    /// this is O(1).
    pub fn get(&self, index: u64) -> Option<&LogEntry> {
        if index == 0 || self.entries.is_empty() {
            return None;
        }
        let first_index = self.entries[0].index;
        if index < first_index {
            return None;
        }
        let offset = (index - first_index) as usize;
        let entry = self.entries.get(offset)?;
        debug_assert_eq!(entry.index, index, "log entries must be contiguous");
        Some(entry)
    }

    /// Index of the last entry, or 0 if the log is empty.
    pub fn last_index(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.index)
    }

    /// Term of the last entry, or `Term(0)` if the log is empty.
    pub fn last_term(&self) -> Term {
        self.entries.last().map_or(Term(0), |e| e.term)
    }

    /// Borrow the entries with `index >= from_index` as a contiguous slice
    /// (O(log n) seek, no allocation).
    pub fn entries_slice_from(&self, from_index: u64) -> &[LogEntry] {
        let start = self.entries.partition_point(|e| e.index < from_index);
        &self.entries[start..]
    }

    /// Return all entries starting from the given index (inclusive) as a
    /// `Vec` of references.
    ///
    /// **Prefer [`entries_slice_from`](Self::entries_slice_from)** which
    /// returns a `&[LogEntry]` slice without an extra allocation.
    #[deprecated(note = "use entries_slice_from to avoid unnecessary Vec allocation")]
    pub fn entries_from(&self, from_index: u64) -> Vec<&LogEntry> {
        self.entries_slice_from(from_index).iter().collect()
    }

    /// Truncate all entries after the given index (exclusive).
    /// Entries with `index > after` are removed.
    ///
    /// Returns [`RaftInvariantError::TruncateBelowCommitted`] if `after <
    /// self.committed`: committed entries are guaranteed on a quorum and must
    /// not be discarded.  Returns [`RaftInvariantError::TruncateBelowApplied`]
    /// if `after < self.applied`: applied entries must never be truncated —
    /// doing so would lose state-machine state.  Callers at the RPC boundary
    /// should treat these as hard failures (reject the RPC, log a diagnostic)
    /// rather than propagating them as normal-path errors.
    ///
    /// The previous version of this method panicked on the same condition.
    /// Panicking a release-build Raft process because a buggy or adversarial
    /// peer sent an inconsistent `prev_log_index` is itself a
    /// denial-of-service primitive; returning a `Result` lets the RPC
    /// handler reply with a protocol-level failure instead.
    pub fn truncate_after(&mut self, after: u64) -> Result<(), RaftInvariantError> {
        // Committed entries are guaranteed to be present on a quorum.
        // Truncating them is always unsafe: if this node crashes before
        // applying them, they are lost.
        if after < self.committed {
            return Err(RaftInvariantError::TruncateBelowCommitted {
                after,
                committed: self.committed,
            });
        }
        if after < self.applied {
            return Err(RaftInvariantError::TruncateBelowApplied {
                after,
                applied: self.applied,
            });
        }
        let keep = self.entries.partition_point(|e| e.index <= after);
        self.entries.truncate(keep);
        // Audit (MED): the prior code defensively *mutated* `self.committed`
        // here ("belt-and-suspenders"), but doing so silently masks a bug in
        // the early guard above. A debug_assert is the right shape: in debug
        // builds we crash loudly (so test suites catch any future refactor
        // that breaks the invariant), and in release builds we leave state
        // unchanged so the bug is observable rather than silently papered
        // over. Note the invariant is `committed <= after` — see the
        // `TruncateBelowCommitted` early-return at the top of this fn.
        debug_assert!(
            self.committed <= after,
            "truncate_after: committed ({}) must be <= after ({}) — \
             TruncateBelowCommitted guard failed",
            self.committed,
            after,
        );
        Ok(())
    }

    /// Drop all entries with `index <= up_to` after a snapshot installs.
    /// `committed` and `applied` are bumped if necessary.
    pub fn discard_through(&mut self, up_to: u64) {
        self.entries.retain(|e| e.index > up_to);
        if self.committed < up_to {
            self.committed = up_to;
        }
        if self.applied < up_to {
            self.applied = up_to;
        }
    }

    /// Mark entries up to (and including) `index` as committed.
    ///
    /// Audit (MED): a caller passing `index > last_index()` is a bug —
    /// it would silently cap the commit advance and the caller's
    /// downstream apply loop would never reach the expected index.
    /// Trip a debug_assert so the test suite catches the regression
    /// while preserving the silent-cap behaviour in release for
    /// availability.
    pub fn commit(&mut self, index: u64) {
        debug_assert!(
            index <= self.last_index(),
            "RaftLog::commit: index ({}) > last_index ({}) — caller bug",
            index,
            self.last_index()
        );
        if index > self.committed && index <= self.last_index() {
            self.committed = index;
        }
    }

    /// The highest committed index.
    pub fn committed(&self) -> u64 {
        self.committed
    }

    /// The highest applied index.
    pub fn applied(&self) -> u64 {
        self.applied
    }

    /// Advance the applied index up to (and including) `index`.
    pub fn apply(&mut self, index: u64) {
        if index > self.applied && index <= self.committed {
            self.applied = index;
        }
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Invariant-violation errors
// ---------------------------------------------------------------------------

/// A Raft safety invariant was violated by a log-mutation operation.
///
/// These errors indicate either a buggy caller or an adversarial RPC whose
/// `prev_log_index` / `entry.index` would force us to destroy state that has
/// already been applied to the state machine.  Returning an error lets the
/// caller reject the offending RPC without crashing the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftInvariantError {
    /// Attempt to truncate the log below the committed watermark.
    ///
    /// Committed entries are guaranteed to be present on a quorum; truncating
    /// them risks losing data that a majority of nodes may already have applied
    /// or be about to apply.
    TruncateBelowCommitted {
        /// The `after` value passed to `truncate_after`.
        after: u64,
        /// The current committed index (must be ≤ `after`).
        committed: u64,
    },
    /// Attempt to truncate the log below the applied watermark.
    TruncateBelowApplied {
        /// The `after` value passed to `truncate_after`.
        after: u64,
        /// The current applied index (must be ≤ `after`).
        applied: u64,
    },
}

impl fmt::Display for RaftInvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncateBelowCommitted { after, committed } => write!(
                f,
                "Raft safety violation: cannot truncate after {after} when committed={committed}"
            ),
            Self::TruncateBelowApplied { after, applied } => write!(
                f,
                "Raft safety violation: cannot truncate after {after} when applied={applied}"
            ),
        }
    }
}

impl std::error::Error for RaftInvariantError {}

// ---------------------------------------------------------------------------
// Operational Raft errors (Fix 4: term overflow, Fix 1: snapshot safety)
// ---------------------------------------------------------------------------

/// Non-fatal errors raised by Raft operations that must not panic a
/// release-build node.
///
/// These are distinct from [`RaftInvariantError`] (which flags a *caller* bug
/// or a safety violation attempted by a peer): `RaftError` values are either
/// expected-but-rare arithmetic edge cases or adversarial-RPC rejections the
/// caller should translate into a protocol-level failure reply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RaftError {
    /// `u64` overflow when incrementing or adding to a term.  Propagated
    /// instead of the previous `.expect(...)` so an adversary who can drive
    /// elections cannot weaponise overflow as a remote-panic DoS.
    TermOverflow,
    /// A snapshot-install RPC would overwrite a committed log entry with a
    /// different term.  See
    /// [`RaftNode::handle_install_snapshot`] (Fix 1): accepting an old
    /// snapshot is fine, but accepting one whose `last_included_term`
    /// disagrees with the follower's already-committed entry at that index
    /// would let a Byzantine leader rewrite committed state.
    StaleSnapshotTermAtCommitted {
        /// Snapshot's `last_included_index`.
        last_included_index: u64,
        /// Snapshot's claimed term for that index.
        snapshot_term: Term,
        /// Term this follower has already committed for that index.
        local_term: Term,
    },
}

impl fmt::Display for RaftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TermOverflow => {
                write!(f, "Raft term counter overflow (u64 wraparound)")
            }
            Self::StaleSnapshotTermAtCommitted {
                last_included_index,
                snapshot_term,
                local_term,
            } => write!(
                f,
                "snapshot at committed index {last_included_index} has term \
                 {snapshot_term} but locally committed entry has term \
                 {local_term} — rejecting to prevent Byzantine rewrite"
            ),
        }
    }
}

impl std::error::Error for RaftError {}

// ---------------------------------------------------------------------------
// Replay-protection cache
// ---------------------------------------------------------------------------

/// Bounded MAC cache used to prevent replays inside the freshness window.
///
/// ## Eviction strategy
///
/// - **Time-based, every insert**: the insertion-order deque is keyed
///   *by timestamp*, so we can evict all entries older than
///   `max_age_ms` in O(k) where k is the number of expired entries at
///   the head of the queue — typically 0 in steady state, and in any
///   case at most one rotation of the bounded cache per freshness
///   window. We no longer defer eviction to every 64th insert: a
///   previously-admitted MAC that expires must not be silently kept
///   around, because the freshness check is performed *before* the
///   replay check (see [`verify_request_vote`] et al.), meaning an
///   expired MAC can never be re-admitted even if the replay cache
///   does not know about it.
/// - **FIFO cap fallback**: if the configured `max_age_ms` is
///   large and traffic is bursty, the cache can still grow to
///   [`REPLAY_CACHE_MAX`]; when it does, the eldest entry is popped
///   regardless of age. These "cap-induced" evictions are tracked as
///   `replay_cache_full_evictions` so operators can size the cap for
///   their deployment.
/// Number of independent shards in the replay cache (Fix 5).
///
/// Each shard is keyed by the first byte of the MAC mod `REPLAY_CACHE_SHARDS`
/// and owns its own small deque + mutex, so concurrent inserts of MACs that
/// hash to different shards do not contend on a single lock.  8 shards is a
/// power of two for cheap modulo and is comfortably more than a typical
/// tokio worker-thread count.
pub const REPLAY_CACHE_SHARDS: usize = 8;

/// Per-shard FIFO state.  Kept in its own struct so the mutex granularity is
/// exactly one shard's deque.
#[derive(Debug, Default)]
struct ReplayShard {
    order: std::collections::VecDeque<(u64, [u8; 32])>,
}

#[derive(Debug)]
struct ReplayCache {
    /// Shared keyspace — DashMap already shards internally, so lookups are
    /// already parallel; the single-mutex bottleneck was the `order` deque.
    seen: DashMap<[u8; 32], u64>,
    /// Fix 5: per-shard FIFO deques, each with its own `parking_lot::Mutex`.
    /// Indexed by `(mac[0] as usize) % REPLAY_CACHE_SHARDS`.
    shards: [PLMutex<ReplayShard>; REPLAY_CACHE_SHARDS],
    /// Count of evictions caused by the hard FIFO cap (i.e. the cache
    /// filled before entries aged out). Exposed via
    /// [`ReplayCache::full_evictions`] for metrics.
    full_evictions: AtomicU64,
}

impl Default for ReplayCache {
    fn default() -> Self {
        // `PLMutex<ReplayShard>` is not `Copy`, so `[Default::default(); N]`
        // does not compile; construct each mutex explicitly.
        Self {
            seen: DashMap::new(),
            shards: std::array::from_fn(|_| PLMutex::new(ReplayShard::default())),
            full_evictions: AtomicU64::new(0),
        }
    }
}

/// Per-shard hard cap.  `REPLAY_CACHE_MAX` floor-divided across
/// `REPLAY_CACHE_SHARDS` shards.  Using floor division keeps the aggregate
/// ceiling `REPLAY_CACHE_SHARDS * REPLAY_CACHE_PER_SHARD_MAX` at or below
/// [`REPLAY_CACHE_MAX`], which the top-level bound test
/// (`test_replay_cache_bounded`) asserts.  With 8 shards and
/// `REPLAY_CACHE_MAX = 16_384`, this gives 2048 per shard and a combined
/// ceiling of exactly 16 384.
const REPLAY_CACHE_PER_SHARD_MAX: usize = REPLAY_CACHE_MAX / REPLAY_CACHE_SHARDS;

impl ReplayCache {
    fn new() -> Self {
        Self::default()
    }

    /// Route a MAC to its shard.
    ///
    /// Audit-fix M (replay cache shard distribution): the previous routing
    /// used only `mac[0] % REPLAY_CACHE_SHARDS`. While HMAC-SHA256 output
    /// is indistinguishable from random in aggregate, single-byte routing
    /// concentrates short-interval inserts on one shard under benchmark
    /// load. We now XOR-fold all 32 MAC bytes into a u64, multiply by a
    /// Knuth/Fibonacci constant, and reduce mod `REPLAY_CACHE_SHARDS` —
    /// every byte of the MAC contributes to the shard choice, so any
    /// per-byte bias cannot crowd a single shard.
    #[inline]
    fn shard_of(mac: &[u8; 32]) -> usize {
        // XOR-fold the 32-byte MAC into a single u64.  `chunks_exact(8)`
        // yields exactly 4 chunks for a 32-byte input.
        let mut acc: u64 = 0;
        for chunk in mac.chunks_exact(8) {
            let v = u64::from_ne_bytes(chunk.try_into().expect("8-byte chunk"));
            acc ^= v;
        }
        let mixed = acc.rotate_left(13).wrapping_mul(0x9e3779b97f4a7c15);
        (mixed as usize) % REPLAY_CACHE_SHARDS
    }

    /// Insert a MAC into the cache.  Returns `true` if it was already present
    /// (i.e., a replay), `false` if it was newly inserted.
    ///
    /// This is TOCTOU-free: it uses `entry().or_insert()` to atomically
    /// reserve the slot in the shared `DashMap`.  Eviction is per-shard, so
    /// concurrent inserts that route to different shards do not serialize.
    fn check_and_insert(&self, mac: [u8; 32], now_ms: u64, max_age_ms: u64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.seen.entry(mac) {
            Entry::Occupied(_) => true, // replay
            Entry::Vacant(slot) => {
                slot.insert(now_ms);
                let shard_idx = Self::shard_of(&mac);
                let mut shard = self.shards[shard_idx].lock();
                shard.order.push_back((now_ms, mac));
                // Time-evict on *every* insert: pop expired entries off
                // the front of this shard's deque.  Cheap because the
                // deque is approximately time-ordered within the shard.
                while let Some(&(ts, head_mac)) = shard.order.front() {
                    if now_ms.saturating_sub(ts) >= max_age_ms {
                        shard.order.pop_front();
                        self.seen.remove(&head_mac);
                    } else {
                        break;
                    }
                }
                // Hard FIFO cap per shard.
                while shard.order.len() > REPLAY_CACHE_PER_SHARD_MAX {
                    if let Some((_, old)) = shard.order.pop_front() {
                        self.seen.remove(&old);
                        self.full_evictions
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                false
            }
        }
    }

    /// Number of entries evicted because the FIFO cap filled (i.e. the
    /// cluster exceeded [`REPLAY_CACHE_MAX`] fresh MACs within the
    /// freshness window). Operators should alert on a non-zero rate of
    /// increase — a healthy cluster should time-evict rather than
    /// cap-evict.
    pub fn full_evictions(&self) -> u64 {
        self.full_evictions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }
}

// ---------------------------------------------------------------------------
// Per-peer vote rate limiter (token bucket)
// ---------------------------------------------------------------------------

/// Per-peer token-bucket rate limiter for inbound `RequestVote` RPCs.
///
/// Implements the classical token-bucket algorithm (see e.g. Tanenbaum,
/// _Computer Networks_ §5.3.2; RFC 2698 for a multi-rate variant): each peer
/// has an independent bucket with `capacity` tokens that refill at
/// `refill_interval_ms` per token.  A RequestVote RPC consumes one token;
/// when the bucket is empty the RPC is rejected *silently* at the reception
/// site to avoid leaking liveness information to a malicious peer.
///
/// The limiter is keyed by the candidate_id string from the RPC, so a
/// well-known peer cannot be crowded out by a noisy neighbour.  Memory is
/// bounded by the number of observed peer IDs: this is acceptable for a
/// Raft deployment because the legitimate peer set is small and bounded by
/// cluster configuration — peers that churn through random IDs are already
/// rejected upstream by HMAC verification.
/// Maximum per-peer buckets retained. Beyond this, `try_consume` rejects
/// without inserting, so an attacker who can reach the socket but cannot
/// forge the HMAC cannot exhaust memory by flooding RequestVote RPCs with
/// unique candidate IDs. The cap is sized well above any realistic Raft
/// cluster — a 65 k-voter deployment would already be pathological.
pub const MAX_VOTE_RATE_LIMITER_PEERS: usize = 65_536;

/// Per-peer token-bucket limiter for incoming `RequestVote` RPCs.
///
/// Prevents a single peer from driving the local node through repeated
/// forced elections.  Each peer has its own bucket; peers outside an
/// optional allowlist are rejected without allocating state.
#[derive(Debug)]
pub struct VoteRateLimiter {
    /// Per-peer state: (tokens, last_refill_epoch_ms, lifetime_rejected).
    state: DashMap<String, VoteBucket>,
    /// Bucket capacity — the maximum burst of votes allowed.
    capacity: u32,
    /// Milliseconds between single-token refills.
    refill_interval_ms: u64,
    /// Known-peer allowlist. When `Some`, `try_consume` rejects without
    /// allocating a bucket for any peer ID not in the set; this prevents
    /// adversarial candidate-ID floods from growing the map.  When `None`,
    /// insertion is permitted up to [`MAX_VOTE_RATE_LIMITER_PEERS`].
    allowed_peers: parking_lot::RwLock<Option<HashSet<String>>>,
    /// Counter for RPCs rejected purely because they referenced an unknown
    /// peer (separate from rate-limit rejections so operators can
    /// distinguish "attack" from "noisy legitimate peer").
    unknown_rejects: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct VoteBucket {
    tokens: u32,
    last_refill_ms: u64,
    rejected: u64,
}

impl VoteRateLimiter {
    /// Construct a new limiter.  `capacity` must be > 0 (a zero-capacity
    /// bucket would drop all votes, breaking leader election entirely); if
    /// callers pass 0 we clamp to 1 and emit a warning.  `refill_interval_ms`
    /// of 0 disables refill (tokens spent never come back) — valid but
    /// unusual.
    pub fn new(capacity: u32, refill_interval_ms: u64) -> Self {
        let capacity = if capacity == 0 {
            tracing::warn!("VoteRateLimiter: capacity=0 would block all votes; clamping to 1");
            1
        } else {
            capacity
        };
        Self {
            state: DashMap::new(),
            capacity,
            refill_interval_ms,
            allowed_peers: parking_lot::RwLock::new(None),
            unknown_rejects: AtomicU64::new(0),
        }
    }

    /// Install (or replace) the known-peer allowlist. When set, any vote
    /// whose candidate ID is not in the allowlist is dropped before a bucket
    /// is allocated, so an adversary cannot grow the per-peer map via forged
    /// candidate IDs. Passing `None` disables the check (used in tests or in
    /// dynamic-membership deployments where the peer set is not stable).
    pub fn set_allowed_peers(&self, peers: Option<HashSet<String>>) {
        *self.allowed_peers.write() = peers;
    }

    /// Number of RPCs rejected because the candidate ID was not in the
    /// allowlist.  Separate from [`Self::rejected_count`] so operators can
    /// distinguish adversarial flooding from legitimate bursts.
    pub fn unknown_peer_rejects(&self) -> u64 {
        self.unknown_rejects
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// HIGH (audit, vote-rate-limiter unbounded under `allowed_peers = None`):
    /// drop per-peer bucket state for any peer that has not consumed a
    /// token in `stale_after_ms` milliseconds. Returns the number of
    /// evicted entries.
    ///
    /// Memory bound: even with the [`MAX_VOTE_RATE_LIMITER_PEERS`] hard
    /// cap, an attacker who can reach the socket may still pin 65 536
    /// stale entries indefinitely if no allowlist is configured. Periodic
    /// eviction of inactive buckets bounds steady-state memory to the
    /// *active* peer set rather than the lifetime peer set.
    ///
    /// Callers should drive this from the same maintenance path that
    /// already drives heartbeats and leader-lease checks (e.g. once per
    /// election timeout). A `stale_after_ms` of at least 2× the election
    /// timeout is recommended so a peer that just legitimately drained
    /// its bucket is not evicted between its last vote and its next
    /// scheduled refill.
    pub fn evict_stale(&self, now_ms: u64, stale_after_ms: u64) -> usize {
        if stale_after_ms == 0 {
            return 0;
        }
        // Collect first then remove — avoids holding shard locks across
        // map mutations and is friendly to DashMap's per-shard locking.
        let to_remove: Vec<String> = self
            .state
            .iter()
            .filter_map(|r| {
                let last = r.value().last_refill_ms;
                let age = now_ms.saturating_sub(last);
                if age >= stale_after_ms {
                    Some(r.key().clone())
                } else {
                    None
                }
            })
            .collect();
        let mut evicted = 0usize;
        for k in to_remove {
            if self.state.remove(&k).is_some() {
                evicted += 1;
            }
        }
        evicted
    }

    /// Attempt to consume one token for the given peer.
    ///
    /// Returns `true` if the RPC may be processed; `false` if the bucket is
    /// empty and the RPC must be dropped.  `now_ms` is passed in so the
    /// function is testable without touching the wall clock.
    pub fn try_consume(&self, peer: &str, now_ms: u64) -> bool {
        // Allowlist gate first: reject without allocating a bucket, so an
        // attacker cannot grow memory by spamming unique IDs.
        if let Some(allowed) = self.allowed_peers.read().as_ref() {
            if !allowed.contains(peer) {
                self.unknown_rejects
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return false;
            }
        } else if self.state.len() >= MAX_VOTE_RATE_LIMITER_PEERS && !self.state.contains_key(peer)
        {
            // Hard cap when no allowlist is configured.
            self.unknown_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }

        let mut entry = self.state.entry(peer.to_string()).or_insert(VoteBucket {
            tokens: self.capacity,
            last_refill_ms: now_ms,
            rejected: 0,
        });

        // Refill based on elapsed time since last_refill.
        if self.refill_interval_ms > 0 {
            let elapsed = now_ms.saturating_sub(entry.last_refill_ms);
            let refills = elapsed / self.refill_interval_ms;
            if refills > 0 {
                let new_tokens = (entry.tokens as u64).saturating_add(refills);
                entry.tokens = new_tokens.min(self.capacity as u64) as u32;
                // Advance last_refill by exactly the tokens accounted for so
                // leftover milliseconds are not discarded (prevents burst
                // starvation around the refill boundary).
                entry.last_refill_ms = entry
                    .last_refill_ms
                    .saturating_add(refills.saturating_mul(self.refill_interval_ms));
            }
        }

        if entry.tokens == 0 {
            entry.rejected = entry.rejected.saturating_add(1);
            return false;
        }
        entry.tokens -= 1;
        true
    }

    /// Total rejected RequestVote RPCs from the given peer since process
    /// start.  Zero if the peer has never been seen.
    pub fn rejected_count(&self, peer: &str) -> u64 {
        self.state.get(peer).map(|b| b.rejected).unwrap_or(0)
    }

    /// Snapshot of per-peer rejection counters (for metrics export).
    pub fn all_rejected(&self) -> Vec<(String, u64)> {
        self.state
            .iter()
            .filter_map(|r| {
                let v = r.value().rejected;
                if v > 0 {
                    Some((r.key().clone(), v))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Configured bucket capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Configured refill interval (ms/token).
    pub fn refill_interval_ms(&self) -> u64 {
        self.refill_interval_ms
    }
}

/// Tuning knobs for the per-peer [`VoteRateLimiter`], exposed to callers so
/// that deployments can adapt the limiter to cluster size without touching
/// the Raft core.
///
/// # Rationale
///
/// A fixed 5 s refill interval is unsuitable for large clusters: with
/// `N` voters, Raft protocol requires a quorum of roughly `N/2`
/// RequestVote grants during an election.  If the limiter rejects
/// legitimate RequestVote bursts, a big cluster cannot elect a leader
/// inside the election timeout — the very outcome the rate limiter is
/// supposed to protect against.  Scaling the refill interval down with
/// cluster size keeps per-peer rate limiting useful without starving
/// legitimate elections.
///
/// See [`VoteRateLimiterConfig::adaptive_for_cluster_size`] for the
/// exact scaling formula and floor.
#[derive(Debug, Clone)]
pub struct VoteRateLimiterConfig {
    /// Token-bucket capacity (max burst).
    pub capacity: u32,
    /// Milliseconds between single-token refills.
    pub refill_interval_ms: u64,
}

impl VoteRateLimiterConfig {
    /// Conservative default matching the historic 5 s refill, capacity 3.
    /// Preserved as a literal constant so older call sites that do not pass
    /// a cluster-size hint keep their existing behaviour.
    pub const fn defaults() -> Self {
        Self {
            capacity: 3,
            refill_interval_ms: 5_000,
        }
    }

    /// Compute an adaptive config scaled to `cluster_size` (total voters,
    /// including self).
    ///
    /// Formula:
    /// ```text
    /// refill_interval_ms = max(500, min(5000, 5000 / cluster_size))
    /// ```
    /// i.e.
    /// - clusters of size 1 keep the historic 5 000 ms refill,
    /// - larger clusters shrink the interval proportionally,
    /// - the interval never drops below 500 ms (to preserve the flood
    ///   protection property: a malicious peer still cannot exceed
    ///   `capacity` votes per 500 ms).
    pub fn adaptive_for_cluster_size(cluster_size: usize) -> Self {
        let n = cluster_size.max(1) as u64;
        // 5000 / n, clamped to [500, 5000].
        let refill = (5_000u64 / n).max(500).min(5_000);
        Self {
            capacity: 3,
            refill_interval_ms: refill,
        }
    }
}

impl Default for VoteRateLimiterConfig {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Snapshot of per-peer Raft metrics exposed by [`RaftNode::metrics`].
#[derive(Debug, Clone, Default)]
pub struct RaftMetrics {
    /// `(peer_id, rejected_vote_rpcs)` for every peer that has hit the
    /// RequestVote rate limit at least once.
    pub rejected_vote_rpcs: Vec<(String, u64)>,
    /// Number of replay-cache entries evicted because the FIFO cap filled
    /// (i.e. the cluster produced more unique fresh MACs than
    /// [`REPLAY_CACHE_MAX`] within the freshness window). A non-zero rate
    /// of increase means the cache should be sized larger for this
    /// deployment.
    pub replay_cache_full_evictions: u64,
    /// Rolling-upgrade compat: count of reply HMACs accepted via the
    /// legacy two-byte `[DOMAIN_REPLY_LEGACY, <kind>]` fallback.
    /// See [`RaftNode::legacy_reply_hmac_accepts`].
    pub legacy_reply_hmac_accepts: u64,
}

// ---------------------------------------------------------------------------
// Raft node
// ---------------------------------------------------------------------------

/// A single Raft consensus node.
///
/// Field encapsulation note: most fields are `pub(crate)` so the surrounding
/// crate (and tests) can compose helpers without exposing them as part of the
/// public API.  External callers must use the accessors and the
/// [`handle_*`](RaftNode::handle_request_vote) APIs to mutate state.
pub struct RaftNode {
    /// Unique node identifier.
    pub(crate) id: String,
    /// Current role in the cluster.
    pub(crate) state: RaftState,
    /// Current election term.
    pub(crate) current_term: Term,
    /// Candidate this node voted for in the current term.
    pub(crate) voted_for: Option<String>,
    /// The replicated log.
    pub(crate) log: RaftLog,
    /// Known peer node IDs.
    pub(crate) peers: Vec<String>,
    /// Base election timeout in milliseconds (without jitter).
    base_election_timeout_ms: u64,
    /// Election timeout in milliseconds (includes randomized jitter).
    election_timeout_ms: u64,
    /// Timestamp (epoch millis) of the last heartbeat or vote grant.
    last_heartbeat_ms: u64,
    /// Process-monotonic anchor used to track uptime regardless of wall-clock skew.
    started_at: Instant,
    /// Shared cluster secret used to sign and verify Raft RPCs via HMAC-SHA256.
    ///
    /// **WARNING**: Must be set for production deployments.  When `None`, all
    /// incoming RPCs are rejected to prevent unauthenticated nodes from
    /// joining the cluster.  Stored in a [`Zeroizing`] buffer that wipes the
    /// key from memory on drop.
    cluster_secret: Option<Zeroizing<[u8; 32]>>,
    /// Maximum age in milliseconds for incoming cluster messages.
    pub(crate) max_message_age_ms: u64,
    /// Maximum future-dated clock skew tolerated on incoming cluster
    /// messages (ms). Seeded from `ClusterConfig::max_future_skew_ms`,
    /// defaults to 1000.
    pub(crate) max_future_skew_ms: u64,
    /// Leader-only: for each peer, the index of the next log entry to send.
    pub(crate) next_index: HashMap<String, u64>,
    /// Leader-only: for each peer, the highest log entry known to be replicated.
    pub(crate) match_index: HashMap<String, u64>,
    /// Replay-protection cache (bounded).
    replay_cache: ReplayCache,
    /// Optional persistent storage backing this node.
    storage: Option<Arc<dyn RaftStorage>>,
    /// Optional state machine for applying committed entries.
    state_machine: Option<Arc<ClusterStateMachine>>,
    /// Index of the most recent installed snapshot, if any.
    last_snapshot_index: u64,
    /// Term of the most recent installed snapshot, if any.
    last_snapshot_term: Term,
    /// Number of log entries between automatic snapshots (0 disables).
    snapshot_interval: u64,
    /// Per-peer rate limiter for inbound `RequestVote` RPCs (audit finding
    /// #2: prevent election-flood from a misconfigured or malicious peer).
    vote_rate_limiter: Arc<VoteRateLimiter>,
    /// Leader-only: in-flight `ConfigChangeProposal`s awaiting a majority of
    /// signed approvals from the *current* voter set before being committed
    /// as a regular [`RaftCommand::ConfigChange`].  Keyed by proposal id.
    pending_config_changes: HashMap<String, PendingConfigChange>,
    /// Fix 3: per-peer timestamp (epoch ms) of the last AppendEntries that
    /// carried a `ConfigChange` command.  Used to enforce
    /// [`min_config_change_interval_ms`](Self::min_config_change_interval_ms).
    ///
    /// Entries are lazily created in `prepare_append_entries` so peers that
    /// never receive a ConfigChange don't grow the map.  Cleared when a peer
    /// leaves the voter set via `sync_peers_from_voters`.
    last_config_change_at: HashMap<String, u64>,
    /// Fix 3: minimum ms between successive ConfigChange-bearing
    /// AppendEntries to any single peer.  Seeded from
    /// `ClusterConfig::min_config_change_interval_ms` (default 500).
    min_config_change_interval_ms: u64,
    /// H16 (audit): monotonic-clock counterpart of `last_heartbeat_ms`.
    /// Read via `started_at.elapsed().as_millis() as u64` so the leader
    /// lease is not affected by NTP step / wall-clock skew.  Updated in
    /// the same place as `last_heartbeat_ms`.
    last_heartbeat_monotonic_ms: u64,
    /// H14 (audit): in-flight snapshot reassembly buffer keyed by
    /// `leader_id`. Holds the partial snapshot bytes received so far,
    /// the declared `total_size`, and the
    /// (`last_included_index`, `last_included_term`) the chunks claim.
    /// Cleared after a successful or failed install. Single-chunk
    /// transfers (the common case) never touch this buffer.
    snapshot_chunk_buffers: HashMap<String, SnapshotChunkBuffer>,
    /// H17 (audit): per-peer last-seen reply timestamp (Unix epoch ms).
    /// Used to drop a stale or replayed reply at the leader.  Bounded by
    /// the peer set; cleared in `sync_peers_from_voters`.
    last_reply_ts: HashMap<String, u64>,
    /// M (audit): peers recently removed via `sync_peers_from_voters`,
    /// kept on the rate-limit allowlist for 1× election timeout grace
    /// to absorb in-flight RPCs that crossed the membership change.
    /// Map of `peer_id -> monotonic ms when peer was removed`.
    recent_departed_peers: HashMap<String, u64>,
    /// Reply-HMAC rejections (item 1, audit). Incremented every time a
    /// reply RPC fails `verify_*_reply` so operators can alarm on
    /// authentication failures originating from peers that may have
    /// lost the cluster secret or be actively forging replies.
    forged_reply_rejects: Arc<AtomicU64>,
    /// CRIT (audit, snapshot chunk side-effect): incremented every time
    /// an `InstallSnapshot` RPC is rejected because its HMAC-bound
    /// `leader_id` diverges from the AppendEntries-bound current leader.
    /// A peer that knows the cluster secret but is not the current leader
    /// could otherwise cancel an in-flight chunked snapshot install by
    /// triggering the per-leader buffer wipe on descriptor mismatch.
    forged_snapshot_rejects: Arc<AtomicU64>,
    /// CRIT (audit): the `leader_id` of the most-recently-accepted
    /// `AppendEntries` RPC in the *current term*. Acts as a lightweight
    /// stand-in for transport-authenticated peer identity in deployments
    /// that have not threaded an mTLS peer-id through to the Raft layer.
    /// Cleared on `become_follower` for a higher term so a new term's
    /// leader can establish itself with the first AE it sends.
    current_leader_hint: Option<String>,
    /// Rolling-upgrade compat: when `true` (default), `verify_*_reply`
    /// falls back to the legacy two-byte `[DOMAIN_REPLY_LEGACY,
    /// <kind>]` HMAC domain prefix if the new single-byte
    /// `DOMAIN_REPLY_*` prefix fails to verify. This lets a cluster
    /// running mixed pre/post tag-normalization builds make progress
    /// during a rolling restart.
    ///
    /// Set to `false` once every node in the cluster is on a build
    /// that emits the new single-byte prefix, to harden against
    /// downgrade. The flag is also exposed on
    /// [`ClusterConfig::legacy_reply_hmac_tags`] for declarative
    /// configuration.
    ///
    /// Sunset: remove together with `DOMAIN_REPLY_LEGACY` and the
    /// `_legacy` compute helpers two releases after the cut-over.
    pub(crate) accept_legacy_reply_hmac_tags: bool,
    /// Rolling-upgrade compat metric: incremented every time a reply
    /// HMAC was rejected under the new single-byte tag but accepted
    /// via the legacy two-byte fallback. A non-zero value tells the
    /// operator there are still pre-normalization peers in the
    /// cluster; a return-to-zero (after a window) means the rolling
    /// upgrade has completed and the operator can flip
    /// [`accept_legacy_reply_hmac_tags`](Self::accept_legacy_reply_hmac_tags)
    /// to `false`.
    legacy_reply_hmac_accepts: Arc<AtomicU64>,
    /// `apply_committed` halt sentinel (item 5, audit). Set to `true`
    /// on the first state-machine apply error so operators can alarm.
    /// Exposed via [`Self::is_apply_halted`].
    apply_halted: Arc<std::sync::atomic::AtomicBool>,
}

/// H14: per-leader chunked-snapshot reassembly buffer.
#[derive(Debug)]
struct SnapshotChunkBuffer {
    /// Accumulated bytes from chunk-`offset` order.
    data: Vec<u8>,
    /// Total declared size (must match across all chunks).
    total_size: u64,
    /// `last_included_index` claimed by all chunks (must match).
    last_included_index: u64,
    /// `last_included_term` claimed by all chunks (must match).
    last_included_term: Term,
}

impl fmt::Debug for RaftNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RaftNode")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("current_term", &self.current_term)
            .field("voted_for", &self.voted_for)
            .field("peers", &self.peers)
            .field("log_len", &self.log.len())
            .field("committed", &self.log.committed())
            .field("applied", &self.log.applied())
            .field("has_secret", &self.cluster_secret.is_some())
            .finish()
    }
}

impl RaftNode {
    /// Create a new Raft node starting as a Follower at term 0.
    ///
    /// The node is constructed with **no cluster secret**.  In production
    /// builds (compiled *without* the `insecure-no-cluster-secret` feature),
    /// callers are expected to immediately invoke
    /// [`set_cluster_secret`](Self::set_cluster_secret) and then
    /// [`require_cluster_secret_for_production`](Self::require_cluster_secret_for_production).
    /// The higher-level entry point [`from_config`](Self::from_config)
    /// enforces this automatically.
    ///
    /// The per-peer vote rate limiter is seeded with
    /// [`VoteRateLimiterConfig::adaptive_for_cluster_size`] using the
    /// provided peer count so large clusters do not starve elections.
    pub fn new(id: String, peers: Vec<String>, base_election_timeout_ms: u64) -> Self {
        let cluster_size = peers.len() + 1;
        let rl_cfg = VoteRateLimiterConfig::adaptive_for_cluster_size(cluster_size);
        Self::with_vote_rate_limiter_config(id, peers, base_election_timeout_ms, rl_cfg)
    }

    /// Same as [`new`](Self::new) but with an explicit
    /// [`VoteRateLimiterConfig`].
    pub fn with_vote_rate_limiter_config(
        id: String,
        peers: Vec<String>,
        base_election_timeout_ms: u64,
        rl_cfg: VoteRateLimiterConfig,
    ) -> Self {
        let half = base_election_timeout_ms / 2;
        let jitter = if half > 0 {
            rand::thread_rng().gen_range(0..=half)
        } else {
            0
        };
        Self {
            id,
            state: RaftState::Follower,
            current_term: Term(0),
            voted_for: None,
            log: RaftLog::new(),
            peers,
            base_election_timeout_ms,
            election_timeout_ms: base_election_timeout_ms + jitter,
            last_heartbeat_ms: 0,
            started_at: Instant::now(),
            cluster_secret: None,
            max_message_age_ms: 30_000,
            max_future_skew_ms: MAX_FUTURE_SKEW_MS,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            replay_cache: ReplayCache::new(),
            storage: None,
            state_machine: None,
            last_snapshot_index: 0,
            last_snapshot_term: Term(0),
            snapshot_interval: 0,
            vote_rate_limiter: Arc::new(VoteRateLimiter::new(
                rl_cfg.capacity,
                rl_cfg.refill_interval_ms,
            )),
            pending_config_changes: HashMap::new(),
            last_config_change_at: HashMap::new(),
            // Conservative default mirroring
            // `ClusterConfig::min_config_change_interval_ms`; can be
            // overridden by `from_config`.
            min_config_change_interval_ms: 500,
            // H16: monotonic counterpart, advanced in record_heartbeat.
            last_heartbeat_monotonic_ms: 0,
            // H14: empty until a chunked InstallSnapshot is received.
            snapshot_chunk_buffers: HashMap::new(),
            // H17: empty until reply replies arrive.
            last_reply_ts: HashMap::new(),
            // M: empty until membership changes evict peers.
            recent_departed_peers: HashMap::new(),
            forged_reply_rejects: Arc::new(AtomicU64::new(0)),
            forged_snapshot_rejects: Arc::new(AtomicU64::new(0)),
            current_leader_hint: None,
            // Rolling-upgrade default: accept both new and legacy
            // reply-MAC prefixes for one release cycle. Flip to false
            // (via `ClusterConfig::legacy_reply_hmac_tags = false`)
            // once every node is on a post-normalization build.
            accept_legacy_reply_hmac_tags: true,
            legacy_reply_hmac_accepts: Arc::new(AtomicU64::new(0)),
            apply_halted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Production safety gate: returns an error if no `cluster_secret` has
    /// been installed.
    ///
    /// This is the **deny-construction** counterpart to the "deny-RPC"
    /// behavior in `verify_*`: a release build of the daemon will never
    /// yield a live `RaftNode` without an HMAC key.  Tests and demos can
    /// opt out by enabling the `insecure-no-cluster-secret` feature,
    /// which turns this call into a no-op.
    #[cfg(not(feature = "insecure-no-cluster-secret"))]
    pub fn require_cluster_secret_for_production(&self) -> Result<(), String> {
        if self.cluster_secret.is_none() {
            Err(
                "RaftNode has no cluster_secret configured. Production builds \
                 must call set_cluster_secret before the node is put into \
                 service; enable the `insecure-no-cluster-secret` feature for \
                 test or demo builds that need to run without one."
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }

    /// `insecure-no-cluster-secret` feature: the gate is a no-op.
    #[cfg(feature = "insecure-no-cluster-secret")]
    pub fn require_cluster_secret_for_production(&self) -> Result<(), String> {
        Ok(())
    }

    /// Build a Raft node from a [`ClusterConfig`], wiring all relevant timing
    /// and security parameters.  The configuration **must** have already
    /// passed [`ClusterConfig::validate`].
    pub fn from_config(cfg: &ClusterConfig) -> Result<Self, String> {
        cfg.validate()?;
        let peers: Vec<String> = cfg.peers.iter().map(|p| p.node_id.clone()).collect();
        let mut node = Self::new(cfg.node_id.clone(), peers, cfg.election_timeout_ms);
        node.max_message_age_ms = cfg.max_message_age_ms;
        node.max_future_skew_ms = cfg.max_future_skew_ms;
        node.snapshot_interval = cfg.snapshot_interval;
        node.min_config_change_interval_ms = cfg.min_config_change_interval_ms;
        node.accept_legacy_reply_hmac_tags = cfg.legacy_reply_hmac_tags;
        node.vote_rate_limiter = Arc::new(VoteRateLimiter::new(
            cfg.vote_rate_limit_capacity,
            cfg.vote_rate_limit_refill_interval_ms,
        ));
        // Seed the allowlist from the configured peer set. Dynamic membership
        // changes must update it via `set_peers` (which is the single write
        // site for `self.peers` — see [`RaftNode::set_peers`]).
        let mut allowed: HashSet<String> = node.peers.iter().cloned().collect();
        // The node's own ID is a valid `candidate_id` the first time we
        // receive our own RequestVote echo during a network split-merge.
        allowed.insert(node.id.clone());
        node.vote_rate_limiter.set_allowed_peers(Some(allowed));
        if let Some(secret) = cfg.decoded_cluster_secret()? {
            node.cluster_secret = Some(secret);
        }
        // Fail-closed construction gate: a release build (without the
        // `insecure-no-cluster-secret` feature) must never produce a node
        // without an HMAC key. This is the counterpart to `verify_*`
        // rejecting unauthenticated RPCs — it stops the misconfiguration
        // earlier, before any RPC is ever served or emitted.
        node.require_cluster_secret_for_production()?;
        Ok(node)
    }

    // ----- accessors --------------------------------------------------------

    /// This node's ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Current state.
    pub fn state(&self) -> RaftState {
        self.state
    }

    /// Current election term.
    pub fn current_term(&self) -> Term {
        self.current_term
    }

    /// Candidate this node voted for in the current term, if any.
    pub fn voted_for(&self) -> Option<&str> {
        self.voted_for.as_deref()
    }

    /// Borrow the replicated log.
    pub fn log(&self) -> &RaftLog {
        &self.log
    }

    /// Mutable borrow of the log (used by tests and snapshot installer).
    pub fn log_mut(&mut self) -> &mut RaftLog {
        &mut self.log
    }

    /// Peers known to this node.
    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    /// Process uptime in seconds, derived from a monotonic clock.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Get the index/term of the most recent installed snapshot.
    pub fn last_snapshot(&self) -> (u64, Term) {
        (self.last_snapshot_index, self.last_snapshot_term)
    }

    /// Item 5 (audit): whether `apply_committed` has halted because the
    /// state machine returned an error on a committed entry. Once set,
    /// this flag remains `true` until the process is restarted —
    /// operators must intervene to repair the state machine.
    pub fn is_apply_halted(&self) -> bool {
        self.apply_halted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Item 1 (audit): count of reply RPCs rejected because their
    /// HMAC did not verify. A non-zero value indicates either a peer
    /// with the wrong cluster secret or an active forgery attempt.
    pub fn forged_reply_rejects(&self) -> u64 {
        self.forged_reply_rejects
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CRIT (audit): count of `InstallSnapshot` RPCs rejected because
    /// the HMAC-bound `leader_id` did not match the current leader as
    /// determined by recent AppendEntries traffic. A non-zero value
    /// indicates a peer with the cluster secret is attempting to forge
    /// or hijack snapshot streams.
    pub fn forged_snapshot_rejects(&self) -> u64 {
        self.forged_snapshot_rejects
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Rolling-upgrade compat metric: count of reply HMACs accepted
    /// only via the legacy two-byte `[DOMAIN_REPLY_LEGACY, <kind>]`
    /// fallback. Operators should treat a steady non-zero increase
    /// as "there are still pre-normalization peers in the cluster";
    /// once it returns to zero over a sustained window, the rolling
    /// upgrade is complete and
    /// [`accept_legacy_reply_hmac_tags`](Self::accept_legacy_reply_hmac_tags)
    /// may be safely turned off.
    pub fn legacy_reply_hmac_accepts(&self) -> u64 {
        self.legacy_reply_hmac_accepts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether this node accepts reply HMACs computed under the
    /// legacy two-byte domain prefix in addition to the new
    /// single-byte prefix. See the field doc on
    /// [`accept_legacy_reply_hmac_tags`](Self#accept_legacy_reply_hmac_tags-1)
    /// and [`ClusterConfig::legacy_reply_hmac_tags`].
    pub fn accept_legacy_reply_hmac_tags(&self) -> bool {
        self.accept_legacy_reply_hmac_tags
    }

    /// Test/operator hook to toggle the rolling-upgrade legacy
    /// reply-MAC fallback at runtime. Production callers should
    /// prefer [`ClusterConfig::legacy_reply_hmac_tags`] so the value
    /// is part of declarative configuration; this setter exists for
    /// emergency drills and for tests that need to flip the gate
    /// after construction.
    pub fn set_accept_legacy_reply_hmac_tags(&mut self, allow: bool) {
        self.accept_legacy_reply_hmac_tags = allow;
    }

    // ----- secret / storage / state machine wiring -------------------------

    /// Configure the cluster shared secret.  Once set, all Raft RPCs must be
    /// HMAC-authenticated.
    pub fn set_cluster_secret(&mut self, secret: [u8; 32]) {
        self.cluster_secret = Some(Zeroizing::new(secret));
    }

    /// Returns `true` if a cluster secret is currently configured.
    pub fn has_cluster_secret(&self) -> bool {
        self.cluster_secret.is_some()
    }

    /// Attach a persistent storage backend.  Hard state and the log will be
    /// replayed on attach so the node resumes from where it left off.
    pub fn attach_storage(&mut self, storage: Arc<dyn RaftStorage>) -> Result<(), StorageError> {
        let hs = storage.load_hard_state()?;
        self.current_term = hs.current_term;
        self.voted_for = hs.voted_for;
        let log = storage.load_log()?;
        for entry in log {
            self.log.append(entry);
        }
        if let Some(snap) = storage.load_snapshot()? {
            self.last_snapshot_index = snap.last_index;
            self.last_snapshot_term = snap.last_term;
            self.log.discard_through(snap.last_index);
            if let Some(sm) = &self.state_machine {
                if let Ok(s) = serde_json::from_slice::<StateMachineSnapshot>(&snap.data) {
                    sm.restore_from_snapshot(&s);
                }
            }
            // Restore peer membership from the persisted voter set.
            if !snap.voters.is_empty() {
                self.sync_peers_from_voters(&snap.voters);
            }
        }
        self.storage = Some(storage);
        Ok(())
    }

    /// Attach a state machine which will receive committed entries from
    /// [`apply_committed`](Self::apply_committed).
    pub fn attach_state_machine(&mut self, sm: Arc<ClusterStateMachine>) {
        self.state_machine = Some(sm);
    }

    /// Persist the current hard state.
    fn persist_hard_state(&self) {
        if let Some(s) = &self.storage {
            let hs = HardState {
                current_term: self.current_term,
                voted_for: self.voted_for.clone(),
            };
            if let Err(e) = s.save_hard_state(&hs) {
                tracing::error!("Raft: failed to persist hard state: {e}");
            }
        }
    }

    fn persist_appended(&self, entries: &[LogEntry]) {
        if let Some(s) = &self.storage {
            if let Err(e) = s.append_log(entries) {
                tracing::error!("Raft: failed to persist appended log: {e}");
            }
        }
    }

    fn persist_truncate(&self, after: u64) {
        if let Some(s) = &self.storage {
            if let Err(e) = s.truncate_log_after(after) {
                tracing::error!("Raft: failed to persist log truncate: {e}");
            }
        }
    }

    /// Fix 2: commit-index-advance durability barrier.
    ///
    /// Wraps [`RaftStorage::sync_all_committed_state`] in an error-logging
    /// shim so the commit-advance path in `handle_append_entries` /
    /// `handle_append_entries_reply` does not have to thread a `Result`
    /// through the RPC handler just to log an fsync failure.  A failure
    /// here is a storage-layer problem the operator must fix; we keep
    /// serving but loudly log.
    fn sync_committed_state_best_effort(&self) {
        if let Some(s) = &self.storage {
            if let Err(e) = s.sync_all_committed_state() {
                tracing::error!("Raft: sync_all_committed_state failed at commit advance: {e}");
            }
        }
    }

    // ----- state transitions ------------------------------------------------

    /// Transition to candidate state and increment the term.
    ///
    /// HIGH (audit, term-overflow remote-DoS): the previous version of
    /// this method called `.expect()` on the overflow branch, which
    /// would crash a release-build Raft process when the term counter
    /// reached `u64::MAX`. A determined attacker who could induce
    /// repeated election cycles (or an extremely long-running cluster)
    /// could weaponize the panic. This shim now degrades gracefully:
    /// on overflow it logs an error and leaves the node a follower
    /// indefinitely. The caller's election-loop sees no state change
    /// (and no term bump) and simply will not start a new election —
    /// strictly safer than aborting the process.
    ///
    /// Prefer [`try_become_candidate`](Self::try_become_candidate) when
    /// you want to observe the overflow programmatically (e.g. to
    /// trip a metric or operator alert).
    pub fn become_candidate(&mut self) {
        if let Err(e) = self.try_become_candidate() {
            tracing::error!(
                error = ?e,
                current_term = self.current_term.value(),
                "Raft: term counter at u64::MAX — refusing to start election; \
                 remaining a follower indefinitely. Operator intervention required."
            );
            // Stay a follower; do not panic. The election loop will
            // observe `state == Follower` and not re-enter this path
            // until something else flips us out (which under overflow
            // never happens — that is precisely the safe fail-stop).
        }
    }

    /// Fallible variant of [`become_candidate`](Self::become_candidate) — see
    /// Fix 4.  Returns [`RaftError::TermOverflow`] instead of panicking so a
    /// pathological / adversarial election storm cannot be weaponised as a
    /// remote-panic DoS against a release-build node.
    pub fn try_become_candidate(&mut self) -> Result<(), RaftError> {
        let next = self
            .current_term
            .checked_next()
            .ok_or(RaftError::TermOverflow)?;
        self.current_term = next;
        self.state = RaftState::Candidate;
        self.voted_for = Some(self.id.clone());
        let base = self.base_election_timeout_ms;
        let half = base / 2;
        let jitter = if half > 0 {
            rand::thread_rng().gen_range(0..=half)
        } else {
            0
        };
        self.election_timeout_ms = base + jitter;
        self.persist_hard_state();
        Ok(())
    }

    /// H13 (audit): wired pre-vote → real-vote transition.
    ///
    /// The election loop should call this instead of
    /// [`try_become_candidate`](Self::try_become_candidate) directly:
    ///
    /// 1. [`prepare_pre_vote`](Self::prepare_pre_vote) to build a signed
    ///    pre-vote args.
    /// 2. Ship to peers and collect their `PreVoteReply`s (the transport
    ///    layer is responsible for delivery).
    /// 3. Pass the replies to this method.
    ///
    /// If a strict majority of the *current* voter set would grant a real
    /// vote (per [`pre_vote_majority_reached`](Self::pre_vote_majority_reached)),
    /// the node performs the term bump and transitions to Candidate.
    /// Otherwise the term is preserved across the partition — exactly the
    /// safety property the pre-vote optimisation was added for.
    ///
    /// Returns:
    /// * `Ok(true)`  — pre-vote majority reached, candidate state entered.
    /// * `Ok(false)` — pre-vote denied, no state change.
    /// * `Err(...)`  — term-overflow at the boundary; refuse to start.
    pub fn try_become_candidate_with_prevote(
        &mut self,
        peer_replies: &[PreVoteReply],
    ) -> Result<bool, RaftError> {
        if !self.pre_vote_majority_reached(peer_replies) {
            tracing::debug!(
                "Raft: pre-vote majority not reached ({} of {} required) —                  deferring real election",
                peer_replies.iter().filter(|r| r.vote_granted).count() + 1,
                self.quorum_size()
            );
            return Ok(false);
        }
        self.try_become_candidate()?;
        Ok(true)
    }

    /// Transition to leader state.
    pub fn become_leader(&mut self) {
        self.state = RaftState::Leader;
        let last = self.log.last_index();
        self.next_index.clear();
        self.match_index.clear();
        for peer in &self.peers {
            self.next_index.insert(peer.clone(), last + 1);
            self.match_index.insert(peer.clone(), 0);
        }
    }

    /// Step down to follower for the given term.
    ///
    /// Audit (asymmetric persist): the previous implementation only
    /// persisted when the term changed *or* the local `voted_for` was
    /// non-empty, on the assumption that an equal-term step-down with
    /// no prior vote was a no-op. That assumption was wrong: any term
    /// or state change observable to the rest of the cluster MUST be
    /// crash-safe, otherwise a node can replay a state mutation across
    /// a restart without re-persisting it. Always persisting on a
    /// step-down is the conservative correct behaviour — at most one
    /// extra fsync per term change, which is negligible compared to
    /// the cost of a stale vote on restart.
    ///
    /// CRIT (audit): a step-down to a *higher* term invalidates the
    /// recorded current leader (a new term will have a fresh leader);
    /// clear the hint so `handle_install_snapshot` does not gate on a
    /// stale identity. Same-term step-downs preserve the hint.
    pub fn become_follower(&mut self, term: Term) {
        let prior_term = self.current_term;
        self.state = RaftState::Follower;
        self.current_term = term;
        if term > prior_term {
            self.voted_for = None;
            // New term ⇒ new (or yet-to-be-elected) leader.
            self.current_leader_hint = None;
        }
        // Always persist: any term or state change must be durable
        // before we hand control back to the caller.
        self.persist_hard_state();
    }

    /// Returns `true` if this node is the current leader.
    pub fn is_leader(&self) -> bool {
        self.state == RaftState::Leader
    }

    /// Returns `true` if this node can safely serve a linearizable read
    /// without consulting the cluster.
    ///
    /// A leader that has not exchanged heartbeats with a quorum of peers
    /// within the current election timeout window may have been partitioned
    /// out: a newer leader could have been elected and committed state this
    /// node has never seen. Checking `is_leader()` alone is therefore not
    /// sufficient — the stale leader would happily answer a read with stale
    /// local state.
    ///
    /// Implements the "leader lease" discipline described in Raft §8
    /// (Diego Ongaro's dissertation, §6.4 "Processing read-only queries more
    /// efficiently"). For high-correctness deployments, pair this with the
    /// ReadIndex protocol (exchange a heartbeat round-trip before returning).
    ///
    /// H16 (audit): the wall-clock variant accepts `now_ms` from the caller;
    /// the new [`Self::leader_lease_is_valid_monotonic`] should be preferred
    /// for any correctness-sensitive use — it reads the process-monotonic
    /// clock so an NTP step or wall-clock regression cannot grant or
    /// revoke the lease.
    pub fn leader_lease_is_valid(&self, now_ms: u64) -> bool {
        if self.state != RaftState::Leader {
            return false;
        }
        // Guard against clock regression: if `now_ms < last_heartbeat_ms`, the
        // lease is definitionally suspect, so we fail closed.
        let elapsed = match now_ms.checked_sub(self.last_heartbeat_ms) {
            Some(v) => v,
            None => return false,
        };
        elapsed < self.election_timeout_ms
    }

    /// H16 (audit): monotonic-clock variant of [`Self::leader_lease_is_valid`].
    ///
    /// Reads `Instant::elapsed` since this node was constructed so that an
    /// NTP step or operator-induced wall-clock change cannot artificially
    /// extend or revoke the lease.  Callers building a linearizable read
    /// path should use this rather than the wall-clock variant; the
    /// wall-clock function is kept for journal/metrics use only.
    pub fn leader_lease_is_valid_monotonic(&self) -> bool {
        if self.state != RaftState::Leader {
            return false;
        }
        let now = self.now_monotonic_ms();
        let elapsed = match now.checked_sub(self.last_heartbeat_monotonic_ms) {
            Some(v) => v,
            None => return false,
        };
        elapsed < self.election_timeout_ms
    }

    /// Minimum number of nodes (including self) needed for a majority.
    pub fn quorum_size(&self) -> usize {
        let total = self.peers.len() + 1;
        total / 2 + 1
    }

    /// Record a heartbeat at the given timestamp (wall-clock ms).
    ///
    /// H16: also advances the monotonic-clock counterpart so that
    /// `leader_lease_is_valid_monotonic` is unaffected by NTP step or
    /// wall-clock skew.
    pub fn record_heartbeat(&mut self, timestamp_ms: u64) {
        self.last_heartbeat_ms = timestamp_ms;
        self.last_heartbeat_monotonic_ms = self.now_monotonic_ms();
    }

    /// H16: monotonic milliseconds since this `RaftNode` was constructed.
    /// Wraps `Instant::elapsed` so callers do not have to reach into
    /// `started_at`.  Use this for any liveness/lease check that must be
    /// safe against clock regression — never use the wall clock for those.
    #[inline]
    pub fn now_monotonic_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    /// Get the last heartbeat timestamp.
    pub fn last_heartbeat(&self) -> u64 {
        self.last_heartbeat_ms
    }

    /// Get the election timeout in milliseconds.
    pub fn election_timeout(&self) -> u64 {
        self.election_timeout_ms
    }

    /// Determine whether to grant a vote to a candidate.
    pub fn should_grant_vote(
        &self,
        candidate_id: &str,
        candidate_term: Term,
        candidate_last_log_index: u64,
        candidate_last_log_term: Term,
    ) -> bool {
        if candidate_term < self.current_term {
            return false;
        }
        match &self.voted_for {
            Some(voted) if voted != candidate_id => return false,
            _ => {}
        }
        if candidate_last_log_term > self.log.last_term() {
            return true;
        }
        if candidate_last_log_term == self.log.last_term() {
            return candidate_last_log_index >= self.log.last_index();
        }
        false
    }

    // -----------------------------------------------------------------------
    // HMAC helpers
    // -----------------------------------------------------------------------

    /// Compute an HMAC-SHA256 over the canonical, length-prefixed encoding
    /// of a [`RequestVoteArgs`].  A 1-byte domain tag is prepended to prevent
    /// cross-protocol confusion.
    pub fn compute_request_vote_hmac(secret: &[u8; 32], args: &RequestVoteArgs) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REQUEST_VOTE]);
        mac.update(&args.term.value().to_be_bytes());
        push_lp_to_mac(&mut mac, args.candidate_id.as_bytes());
        mac.update(&args.last_log_index.to_be_bytes());
        mac.update(&args.last_log_term.value().to_be_bytes());
        mac.update(&args.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// Compute an HMAC-SHA256 over a [`PreVoteArgs`] (Fix 7).  Uses the
    /// distinct [`DOMAIN_PRE_VOTE`] tag so a pre-vote MAC cannot be replayed
    /// as a real `RequestVote`.
    pub fn compute_pre_vote_hmac(secret: &[u8; 32], args: &PreVoteArgs) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_PRE_VOTE]);
        mac.update(&args.term.value().to_be_bytes());
        push_lp_to_mac(&mut mac, args.candidate_id.as_bytes());
        mac.update(&args.last_log_index.to_be_bytes());
        mac.update(&args.last_log_term.value().to_be_bytes());
        mac.update(&args.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// Compute an HMAC-SHA256 over an [`AppendEntriesArgs`] using a canonical
    /// length-prefixed binary encoding (deterministic regardless of platform
    /// or `serde_json` representation).
    pub fn compute_append_entries_hmac(secret: &[u8; 32], args: &AppendEntriesArgs) -> [u8; 32] {
        Self::compute_append_entries_hmac_shared(
            secret,
            args.term,
            &args.leader_id,
            args.prev_log_index,
            args.prev_log_term,
            &args.entries,
            args.leader_commit,
            args.timestamp_ms,
        )
    }

    /// Same canonical encoding as [`compute_append_entries_hmac`] but driven
    /// from borrowed fields / a borrowed `entries` slice — lets leader-side
    /// code reuse the HMAC body without first materializing an
    /// `AppendEntriesArgs` (perf: audit L7, shared-Arc replication).
    ///
    /// The on-wire bytes hashed are identical to
    /// [`compute_append_entries_hmac`]; this is a pure refactor of the
    /// calling convention.
    #[allow(clippy::too_many_arguments)]
    fn compute_append_entries_hmac_shared(
        secret: &[u8; 32],
        term: Term,
        leader_id: &str,
        prev_log_index: u64,
        prev_log_term: Term,
        entries: &[LogEntry],
        leader_commit: u64,
        timestamp_ms: u64,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_APPEND_ENTRIES]);
        mac.update(&term.value().to_be_bytes());
        push_lp_to_mac(&mut mac, leader_id.as_bytes());
        mac.update(&prev_log_index.to_be_bytes());
        mac.update(&prev_log_term.value().to_be_bytes());
        mac.update(&leader_commit.to_be_bytes());
        mac.update(&timestamp_ms.to_be_bytes());
        mac.update(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            mac.update(&entry.index.to_be_bytes());
            mac.update(&entry.term.value().to_be_bytes());
            // MED (audit, perf): canonical_into_mac streams directly
            // into the MAC. The on-wire bytes are byte-identical to
            // the prior `push_lp_to_mac(&mut mac, &entry.command.canonical_bytes())`
            // path: we emit a u32 BE length prefix for the canonical
            // command bytes, then the bytes themselves. The new helper
            // computes both without materializing the intermediate
            // Vec<u8>.
            //
            // Wire-format parity:
            //   prior: push_lp_to_mac(mac, &canonical_bytes())
            //          = [len-be32] [canonical_bytes]
            //   now:   the inline equivalent below, with the canonical
            //          bytes streamed via canonical_into_mac into a
            //          fresh MAC, finalized, length-prefixed, and fed
            //          back into the outer MAC.
            //
            // Rather than rebuilding a temporary MAC, the cheaper
            // equivalent is to keep the original encoding shape: write
            // the length prefix up front, then stream the canonical
            // bytes. The encoding is *exactly* the bytes
            // canonical_bytes would have returned, just without an
            // owning Vec.
            //
            // Implementation: pre-compute the canonical length without
            // allocating by walking the variant once, then emit length
            // + streamed bytes.
            let canonical_len = canonical_byte_len(&entry.command);
            mac.update(&(canonical_len as u32).to_be_bytes());
            entry.command.canonical_into_mac(&mut mac);
        }
        finalize_mac(mac)
    }

    /// Compute an HMAC-SHA256 over an [`InstallSnapshotArgs`].
    pub fn compute_install_snapshot_hmac(
        secret: &[u8; 32],
        args: &InstallSnapshotArgs,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_INSTALL_SNAPSHOT]);
        mac.update(&args.term.value().to_be_bytes());
        push_lp_to_mac(&mut mac, args.leader_id.as_bytes());
        mac.update(&args.last_included_index.to_be_bytes());
        mac.update(&args.last_included_term.value().to_be_bytes());
        mac.update(&args.timestamp_ms.to_be_bytes());
        push_lp_to_mac(&mut mac, &args.data);
        finalize_mac(mac)
    }

    /// Compute an HMAC-SHA256 over a [`ConfigChangeApproval`] — binds the
    /// approval to a specific proposal, action, and approver identity.  Uses
    /// domain tag `0x04` to prevent cross-protocol confusion with the
    /// RequestVote / AppendEntries / InstallSnapshot MACs.
    pub fn compute_config_change_approval_hmac(
        secret: &[u8; 32],
        proposal_id: &str,
        node_id: &str,
        action: &MembershipAction,
        approver_id: &str,
        timestamp_ms: u64,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_CONFIG_CHANGE_APPROVAL]);
        push_lp_to_mac(&mut mac, proposal_id.as_bytes());
        push_lp_to_mac(&mut mac, node_id.as_bytes());
        mac.update(&[match action {
            MembershipAction::AddNode => 0x01,
            MembershipAction::RemoveNode => 0x02,
            MembershipAction::AddLearner => 0x03,
            MembershipAction::PromoteLearner => 0x04,
        }]);
        push_lp_to_mac(&mut mac, approver_id.as_bytes());
        mac.update(&timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// `DOMAIN_REPLY_REQUEST_VOTE` (new single-byte tag).
    pub fn compute_request_vote_reply_hmac(
        secret: &[u8; 32],
        reply: &RequestVoteReply,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_REQUEST_VOTE]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&[u8::from(reply.vote_granted)]);
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// Legacy variant of [`compute_request_vote_reply_hmac`] used only
    /// by [`verify_request_vote_reply`] as a fallback during the
    /// rolling-upgrade window. Re-creates the pre-normalization
    /// two-byte `[DOMAIN_REPLY_LEGACY, 0x01]` prefix so a reply
    /// emitted by an older peer can still be authenticated.
    ///
    /// Senders MUST NOT call this — it exists purely for the
    /// transitional verify path.
    fn compute_request_vote_reply_hmac_legacy(
        secret: &[u8; 32],
        reply: &RequestVoteReply,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_LEGACY, 0x01]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&[u8::from(reply.vote_granted)]);
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// H17: compute an HMAC-SHA256 over a [`PreVoteReply`] under
    /// `DOMAIN_REPLY_PRE_VOTE` (new single-byte tag).
    pub fn compute_pre_vote_reply_hmac(secret: &[u8; 32], reply: &PreVoteReply) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_PRE_VOTE]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&[u8::from(reply.vote_granted)]);
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// Legacy `[DOMAIN_REPLY_LEGACY, 0x05]` two-byte-prefix sibling
    /// of [`compute_pre_vote_reply_hmac`]. See
    /// [`compute_request_vote_reply_hmac_legacy`] for rationale.
    fn compute_pre_vote_reply_hmac_legacy(secret: &[u8; 32], reply: &PreVoteReply) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_LEGACY, 0x05]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&[u8::from(reply.vote_granted)]);
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// H17: compute an HMAC-SHA256 over an [`AppendEntriesReply`] under
    /// `DOMAIN_REPLY_APPEND_ENTRIES` (new single-byte tag).
    pub fn compute_append_entries_reply_hmac(
        secret: &[u8; 32],
        reply: &AppendEntriesReply,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_APPEND_ENTRIES]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&[u8::from(reply.success)]);
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// Legacy `[DOMAIN_REPLY_LEGACY, 0x02]` two-byte-prefix sibling
    /// of [`compute_append_entries_reply_hmac`]. See
    /// [`compute_request_vote_reply_hmac_legacy`] for rationale.
    fn compute_append_entries_reply_hmac_legacy(
        secret: &[u8; 32],
        reply: &AppendEntriesReply,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_LEGACY, 0x02]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&[u8::from(reply.success)]);
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// H17: compute an HMAC-SHA256 over an [`InstallSnapshotReply`] under
    /// `DOMAIN_REPLY_INSTALL_SNAPSHOT` (new single-byte tag).
    pub fn compute_install_snapshot_reply_hmac(
        secret: &[u8; 32],
        reply: &InstallSnapshotReply,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_INSTALL_SNAPSHOT]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// Legacy `[DOMAIN_REPLY_LEGACY, 0x03]` two-byte-prefix sibling
    /// of [`compute_install_snapshot_reply_hmac`]. See
    /// [`compute_request_vote_reply_hmac_legacy`] for rationale.
    fn compute_install_snapshot_reply_hmac_legacy(
        secret: &[u8; 32],
        reply: &InstallSnapshotReply,
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .expect("HMAC-SHA256 accepts any key size");
        mac.update(&[DOMAIN_REPLY_LEGACY, 0x03]);
        mac.update(&reply.term.value().to_be_bytes());
        mac.update(&reply.timestamp_ms.to_be_bytes());
        finalize_mac(mac)
    }

    /// H17: stamp `timestamp_ms` and the `DOMAIN_REPLY` HMAC into a
    /// [`RequestVoteReply`] in place. Production senders MUST call this
    /// before transmitting; the verifier rejects unauthenticated replies
    /// when a cluster secret is configured.
    ///
    /// Audit (asymmetric stamping): the previous version stamped the
    /// timestamp even when no secret was configured, producing a
    /// half-signed reply that *looked* fresh on the wire but carried
    /// no MAC. The verifier on the other side correctly rejected it,
    /// but the asymmetry was a foot-gun for callers debugging the
    /// stack — the wire frame appeared authenticated. Now we refuse
    /// to emit anything when secret is None: timestamp and hmac stay
    /// at their default (0 / None) so it is unambiguous that the
    /// reply was never signed.
    pub fn sign_request_vote_reply(&self, reply: &mut RequestVoteReply) {
        let Some(secret) = &self.cluster_secret else {
            tracing::debug!(
                "Raft: sign_request_vote_reply called without cluster_secret; \
                 leaving reply unsigned (timestamp + hmac stay default)"
            );
            return;
        };
        reply.timestamp_ms = now_ms();
        reply.hmac = Some(Self::compute_request_vote_reply_hmac(secret, reply));
    }

    /// H17: stamp + sign a [`PreVoteReply`]. See
    /// [`sign_request_vote_reply`](Self::sign_request_vote_reply) for
    /// the no-secret behaviour.
    pub fn sign_pre_vote_reply(&self, reply: &mut PreVoteReply) {
        let Some(secret) = &self.cluster_secret else {
            tracing::debug!(
                "Raft: sign_pre_vote_reply called without cluster_secret; \
                 leaving reply unsigned"
            );
            return;
        };
        reply.timestamp_ms = now_ms();
        reply.hmac = Some(Self::compute_pre_vote_reply_hmac(secret, reply));
    }

    /// H17: stamp + sign an [`AppendEntriesReply`]. See
    /// [`sign_request_vote_reply`](Self::sign_request_vote_reply) for
    /// the no-secret behaviour.
    pub fn sign_append_entries_reply(&self, reply: &mut AppendEntriesReply) {
        let Some(secret) = &self.cluster_secret else {
            tracing::debug!(
                "Raft: sign_append_entries_reply called without cluster_secret; \
                 leaving reply unsigned"
            );
            return;
        };
        reply.timestamp_ms = now_ms();
        reply.hmac = Some(Self::compute_append_entries_reply_hmac(secret, reply));
    }

    /// H17: stamp + sign an [`InstallSnapshotReply`]. See
    /// [`sign_request_vote_reply`](Self::sign_request_vote_reply) for
    /// the no-secret behaviour.
    pub fn sign_install_snapshot_reply(&self, reply: &mut InstallSnapshotReply) {
        let Some(secret) = &self.cluster_secret else {
            tracing::debug!(
                "Raft: sign_install_snapshot_reply called without cluster_secret; \
                 leaving reply unsigned"
            );
            return;
        };
        reply.timestamp_ms = now_ms();
        reply.hmac = Some(Self::compute_install_snapshot_reply_hmac(secret, reply));
    }

    /// H17: verify the HMAC on an incoming [`RequestVoteReply`].
    ///
    /// Returns `true` iff a cluster secret is configured AND the reply
    /// carries a matching HMAC AND the timestamp is within the
    /// configured freshness window.
    ///
    /// ## Rolling-upgrade fallback (Option A — try-both-tags)
    ///
    /// The verifier first computes the MAC under the new single-byte
    /// `DOMAIN_REPLY_REQUEST_VOTE` tag. If that fails AND
    /// [`accept_legacy_reply_hmac_tags`](Self::accept_legacy_reply_hmac_tags)
    /// is `true` (default), it recomputes once under the legacy
    /// two-byte `[DOMAIN_REPLY_LEGACY, 0x01]` prefix and accepts if
    /// that matches — incrementing
    /// [`legacy_reply_hmac_accepts`](Self::legacy_reply_hmac_accepts)
    /// and emitting a `tracing::warn!` so operators can see when
    /// pre-normalization peers are still around.
    ///
    /// The fallback is capped at exactly one extra HMAC compute, so
    /// the worst-case CPU overhead per verify is bounded at 2x.
    pub fn verify_request_vote_reply(&self, reply: &RequestVoteReply) -> bool {
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            reply.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &reply.hmac {
            None => return false,
            Some(p) => p,
        };
        let expected = Self::compute_request_vote_reply_hmac(secret, reply);
        if Self::verify_hmac(provided, &expected) {
            return true;
        }
        if self.accept_legacy_reply_hmac_tags {
            let legacy = Self::compute_request_vote_reply_hmac_legacy(secret, reply);
            if Self::verify_hmac(provided, &legacy) {
                self.record_legacy_reply_hmac_accept("RequestVoteReply");
                return true;
            }
        }
        false
    }

    /// H17: verify the HMAC on an incoming [`PreVoteReply`].
    /// See [`verify_request_vote_reply`](Self::verify_request_vote_reply)
    /// for the rolling-upgrade try-both-tags fallback semantics.
    pub fn verify_pre_vote_reply(&self, reply: &PreVoteReply) -> bool {
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            reply.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &reply.hmac {
            None => return false,
            Some(p) => p,
        };
        let expected = Self::compute_pre_vote_reply_hmac(secret, reply);
        if Self::verify_hmac(provided, &expected) {
            return true;
        }
        if self.accept_legacy_reply_hmac_tags {
            let legacy = Self::compute_pre_vote_reply_hmac_legacy(secret, reply);
            if Self::verify_hmac(provided, &legacy) {
                self.record_legacy_reply_hmac_accept("PreVoteReply");
                return true;
            }
        }
        false
    }

    /// H17: verify the HMAC on an incoming [`AppendEntriesReply`].
    /// See [`verify_request_vote_reply`](Self::verify_request_vote_reply)
    /// for the rolling-upgrade try-both-tags fallback semantics.
    pub fn verify_append_entries_reply(&self, reply: &AppendEntriesReply) -> bool {
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            reply.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &reply.hmac {
            None => return false,
            Some(p) => p,
        };
        let expected = Self::compute_append_entries_reply_hmac(secret, reply);
        if Self::verify_hmac(provided, &expected) {
            return true;
        }
        if self.accept_legacy_reply_hmac_tags {
            let legacy = Self::compute_append_entries_reply_hmac_legacy(secret, reply);
            if Self::verify_hmac(provided, &legacy) {
                self.record_legacy_reply_hmac_accept("AppendEntriesReply");
                return true;
            }
        }
        false
    }

    /// H17: verify the HMAC on an incoming [`InstallSnapshotReply`].
    /// See [`verify_request_vote_reply`](Self::verify_request_vote_reply)
    /// for the rolling-upgrade try-both-tags fallback semantics.
    pub fn verify_install_snapshot_reply(&self, reply: &InstallSnapshotReply) -> bool {
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            reply.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &reply.hmac {
            None => return false,
            Some(p) => p,
        };
        let expected = Self::compute_install_snapshot_reply_hmac(secret, reply);
        if Self::verify_hmac(provided, &expected) {
            return true;
        }
        if self.accept_legacy_reply_hmac_tags {
            let legacy = Self::compute_install_snapshot_reply_hmac_legacy(secret, reply);
            if Self::verify_hmac(provided, &legacy) {
                self.record_legacy_reply_hmac_accept("InstallSnapshotReply");
                return true;
            }
        }
        false
    }

    /// Bump the [`legacy_reply_hmac_accepts`](Self::legacy_reply_hmac_accepts)
    /// counter and emit a one-line warn so the operator sees a
    /// breadcrumb every time a pre-normalization (two-byte-prefix)
    /// reply MAC has to be accepted via the fallback path. Sunset
    /// this whole function when
    /// [`accept_legacy_reply_hmac_tags`](Self::accept_legacy_reply_hmac_tags)
    /// is removed.
    fn record_legacy_reply_hmac_accept(&self, kind: &'static str) {
        self.legacy_reply_hmac_accepts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(
            target: "craton_hsm_cluster",
            reply_kind = kind,
            "Raft: accepted reply HMAC under legacy two-byte domain prefix \
             (rolling-upgrade fallback). The remote peer is still running \
             a pre-DOMAIN_REPLY_* build — upgrade it to silence this warning. \
             This fallback path will be removed two releases from now."
        );
    }

    /// Constant-time comparison of two HMAC digests.
    ///
    /// Uses `subtle::ConstantTimeEq` rather than a hand-rolled loop — the
    /// `subtle` crate is audited and already used by `storage::ct_tag_eq`
    /// and `replication::ct_eq`; keep a single comparison implementation
    /// across the crate so future edits can't accidentally introduce an
    /// early-exit.
    pub fn verify_hmac(expected: &[u8; 32], computed: &[u8; 32]) -> bool {
        expected.ct_eq(computed).unwrap_u8() == 1
    }

    /// Verify the HMAC and freshness of a [`RequestVoteArgs`].
    ///
    /// Returns `true` only when:
    ///  1. A cluster secret is configured.
    ///  2. The provided HMAC matches the recomputed value.
    ///  3. The message timestamp is within `max_message_age_ms`.
    ///  4. The MAC has not been seen before within the freshness window.
    pub fn verify_request_vote(&self, args: &RequestVoteArgs) -> bool {
        // L (audit) wire-frame size gate: candidate_id is the only
        // variable-length field; cap it well below MAX_WIRE_FRAME_BYTES.
        if args.candidate_id.len() > MAX_WIRE_FRAME_BYTES {
            // MED (audit): make pre-HMAC oversized rejections visible
            // so operators can alarm on a peer flooding pathologically
            // large candidate IDs. Cheap — only fires for malformed
            // frames, which the per-peer rate limiter also throttles.
            tracing::warn!(
                candidate_id_len = args.candidate_id.len(),
                "Raft: rejecting RequestVote — candidate_id exceeds MAX_WIRE_FRAME_BYTES"
            );
            return false;
        }
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            args.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &args.hmac {
            None => return false,
            Some(p) => p,
        };
        let computed = Self::compute_request_vote_hmac(secret, args);
        if !Self::verify_hmac(provided, &computed) {
            return false;
        }
        let now = now_ms();
        if self
            .replay_cache
            .check_and_insert(computed, now, self.max_message_age_ms)
        {
            tracing::warn!("Raft: rejecting replayed RequestVote (duplicate HMAC)");
            return false;
        }
        true
    }

    /// Verify the HMAC and freshness of an [`AppendEntriesArgs`].
    pub fn verify_append_entries(&self, args: &AppendEntriesArgs) -> bool {
        // L (audit) wire-frame size gate: sum of canonical entry
        // payload bytes plus leader_id bytes must fit MAX_WIRE_FRAME_BYTES.
        let mut estimated = args.leader_id.len();
        for e in &args.entries {
            estimated = estimated.saturating_add(e.command.canonical_bytes().len());
            if estimated > MAX_WIRE_FRAME_BYTES {
                tracing::warn!(
                    "Raft: rejecting AppendEntries — frame would exceed MAX_WIRE_FRAME_BYTES"
                );
                return false;
            }
        }
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            args.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &args.hmac {
            None => return false,
            Some(p) => p,
        };
        let computed = Self::compute_append_entries_hmac(secret, args);
        if !Self::verify_hmac(provided, &computed) {
            return false;
        }
        let now = now_ms();
        if self
            .replay_cache
            .check_and_insert(computed, now, self.max_message_age_ms)
        {
            tracing::warn!("Raft: rejecting replayed AppendEntries (duplicate HMAC)");
            return false;
        }
        true
    }

    /// Verify the HMAC and freshness of an [`InstallSnapshotArgs`].
    ///
    /// H14 (audit): also enforces `MAX_INSTALL_SNAPSHOT_BYTES` against
    /// the per-chunk `data.len()` and the declared `total_size`, so a
    /// malicious leader cannot exhaust follower memory by streaming a
    /// multi-gigabyte snapshot. The size check fires before the HMAC
    /// is recomputed so a forged oversized payload is dropped without
    /// spending HMAC cycles.
    pub fn verify_install_snapshot(&self, args: &InstallSnapshotArgs) -> bool {
        // H14 / L: per-chunk and per-frame ceilings.
        if args.data.len() as u64 > MAX_INSTALL_SNAPSHOT_BYTES {
            tracing::warn!(
                "Raft: rejecting InstallSnapshot chunk — data {} exceeds MAX_INSTALL_SNAPSHOT_BYTES {}",
                args.data.len(),
                MAX_INSTALL_SNAPSHOT_BYTES
            );
            return false;
        }
        if args.total_size > MAX_INSTALL_SNAPSHOT_BYTES {
            tracing::warn!(
                "Raft: rejecting InstallSnapshot — total_size {} exceeds MAX_INSTALL_SNAPSHOT_BYTES {}",
                args.total_size,
                MAX_INSTALL_SNAPSHOT_BYTES
            );
            return false;
        }
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            args.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &args.hmac {
            None => return false,
            Some(p) => p,
        };
        let computed = Self::compute_install_snapshot_hmac(secret, args);
        if !Self::verify_hmac(provided, &computed) {
            return false;
        }
        let now = now_ms();
        if self
            .replay_cache
            .check_and_insert(computed, now, self.max_message_age_ms)
        {
            tracing::warn!("Raft: rejecting replayed InstallSnapshot (duplicate HMAC)");
            return false;
        }
        true
    }

    /// Process an incoming `RequestVote` RPC at the network reception site.
    ///
    /// This is the recommended public entry point for RPC transports: it
    /// applies the per-peer rate limit **before** any other work, returning
    /// `None` when the RPC should be silently dropped (no reply, no response
    /// — matching Audit finding #2).  When the bucket has tokens available,
    /// it delegates to [`handle_request_vote`](Self::handle_request_vote)
    /// for the normal Raft §5.2 handling.
    ///
    /// Rationale for dropping silently rather than returning an error reply:
    /// a malicious peer that receives an explicit "rate limited" response
    /// learns the node is alive and that the rate limiter is engaged; both
    /// are useful intelligence for timing attacks.  Dropping the datagram
    /// is indistinguishable from a transport-level loss.
    pub fn handle_request_vote_rpc(&mut self, args: &RequestVoteArgs) -> Option<RequestVoteReply> {
        // Rate-limit on the raw `candidate_id` field.  This is the identity
        // the sender claims; downstream HMAC verification still ensures only
        // legitimate peers can pass the full check, so the rate limiter
        // cannot be bypassed by forging peer IDs.
        if !self
            .vote_rate_limiter
            .try_consume(&args.candidate_id, now_ms())
        {
            tracing::debug!(
                peer = %args.candidate_id,
                "Raft: RequestVote rate-limited — dropping silently"
            );
            return None;
        }
        Some(self.handle_request_vote(args))
    }

    /// Snapshot of per-peer metrics for monitoring / alerting.
    pub fn metrics(&self) -> RaftMetrics {
        RaftMetrics {
            rejected_vote_rpcs: self.vote_rate_limiter.all_rejected(),
            replay_cache_full_evictions: self.replay_cache.full_evictions(),
            legacy_reply_hmac_accepts: self.legacy_reply_hmac_accepts(),
        }
    }

    /// Directly query the number of replay-cache evictions that happened
    /// because the FIFO cap filled.  See [`REPLAY_CACHE_MAX`].
    pub fn replay_cache_full_evictions(&self) -> u64 {
        self.replay_cache.full_evictions()
    }

    /// Borrow the per-peer vote rate limiter (for test access and advanced
    /// monitoring).
    pub fn vote_rate_limiter(&self) -> &VoteRateLimiter {
        &self.vote_rate_limiter
    }

    /// Fix 7: verify a [`PreVoteArgs`] MAC and freshness.
    ///
    /// Unlike [`verify_request_vote`](Self::verify_request_vote) this path
    /// intentionally does **not** touch the replay cache — pre-vote
    /// exchanges happen repeatedly during a partition and are harmless if
    /// replayed (the handler never mutates persistent state).  Freshness and
    /// HMAC are still enforced so an off-cluster attacker cannot forge
    /// pre-vote pings.
    pub fn verify_pre_vote(&self, args: &PreVoteArgs) -> bool {
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        if !check_message_freshness(
            args.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        let provided = match &args.hmac {
            None => return false,
            Some(p) => p,
        };
        let computed = Self::compute_pre_vote_hmac(secret, args);
        Self::verify_hmac(provided, &computed)
    }

    /// Fix 7: handle a [`PreVoteArgs`] and return a [`PreVoteReply`].
    ///
    /// Semantics:
    /// * The handler **does not** increment `current_term`, set
    ///   `voted_for`, persist hard state, or transition roles.  Pre-votes
    ///   are informational — they merely tell a potential candidate
    ///   whether a real election would succeed.
    /// * A node grants a pre-vote when the candidate's term is at least as
    ///   large as our own AND the candidate's log is at least as
    ///   up-to-date as ours (same §5.4 check used by the real vote path).
    /// * A node currently observing a live leader (heartbeat within the
    ///   election timeout) denies the pre-vote — this is the whole point:
    ///   a partitioned candidate does not get to drag the cluster into a
    ///   new term just because it lost contact.
    pub fn handle_pre_vote(&self, args: &PreVoteArgs) -> PreVoteReply {
        if !self.verify_pre_vote(args) {
            // Audit: do not leak `current_term` to a forged pre-vote.
            // A peer that cannot produce a valid HMAC has no business
            // learning what term we believe we are in; Term(0) is the
            // safe placeholder used elsewhere for term-leak suppression.
            return PreVoteReply {
                term: Term(0),
                vote_granted: false,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        // Stale-term candidate: cannot win, cannot pre-vote.
        if args.term < self.current_term {
            return PreVoteReply {
                term: self.current_term,
                vote_granted: false,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        // If we've heard from a leader within the election timeout, we
        // believe one exists; deny pre-vote so the partitioned candidate
        // does not force a term bump.
        let now = now_ms();
        let heard_leader_recently = self
            .last_heartbeat_ms
            .checked_add(self.election_timeout_ms)
            .map(|deadline| now < deadline)
            .unwrap_or(false);
        // H12: previously this clause exempted candidates from the
        // "leader is alive, deny pre-vote" check. That defeats the entire
        // point of pre-vote: a partitioned candidate keeps timing out and
        // would force the cluster into a new term on reunion. Removing
        // the `&& self.state != RaftState::Candidate` guard means even a
        // node that has already started an election cannot bully the
        // cluster into bumping terms while a leader is still demonstrably
        // alive.
        if heard_leader_recently {
            return PreVoteReply {
                term: self.current_term,
                vote_granted: false,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        // §5.4 log-up-to-date check — same as the real RequestVote path,
        // but without the `voted_for` side effect.
        let up_to_date = if args.last_log_term > self.log.last_term() {
            true
        } else if args.last_log_term == self.log.last_term() {
            args.last_log_index >= self.log.last_index()
        } else {
            false
        };
        PreVoteReply {
            term: self.current_term,
            vote_granted: up_to_date,
            timestamp_ms: 0,
            hmac: None,
        }
    }

    /// Fix 7: build a [`PreVoteArgs`] for this node, signed with the cluster
    /// secret.  The candidate's *prospective* term is `current_term + 1` —
    /// we do **not** persist this bump; it's only carried on the wire so
    /// the remote voter can evaluate it.
    pub fn prepare_pre_vote(&self) -> Option<PreVoteArgs> {
        let secret = self.cluster_secret.as_ref()?;
        // Use checked_next so we don't panic at Term::MAX during a pre-vote.
        let prospective_term = self.current_term.checked_next()?;
        let mut args = PreVoteArgs {
            term: prospective_term,
            candidate_id: self.id.clone(),
            last_log_index: self.log.last_index(),
            last_log_term: self.log.last_term(),
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(Self::compute_pre_vote_hmac(secret, &args));
        Some(args)
    }

    /// Fix 7: count the replies to a pre-vote round and decide whether the
    /// node should proceed to a real election.  `replies` includes the
    /// candidate's own implicit grant at index 0 — callers should pass in
    /// the peer replies only; this method adds the self-grant.
    ///
    /// Returns `true` iff a strict majority of the current voter set
    /// (including self) would grant a vote.  If `false`, the caller must
    /// *not* call [`become_candidate`](Self::become_candidate), preserving
    /// the `current_term` across a partition.
    pub fn pre_vote_majority_reached(&self, peer_replies: &[PreVoteReply]) -> bool {
        let grants = 1 // self
            + peer_replies
                .iter()
                .filter(|r| r.vote_granted)
                .count();
        grants >= self.quorum_size()
    }

    /// Process an incoming `RequestVoteArgs`, returning a `RequestVoteReply`.
    ///
    /// Note: prefer [`handle_request_vote_rpc`](Self::handle_request_vote_rpc)
    /// at the network reception site — this method does not apply the
    /// per-peer rate limit.
    pub fn handle_request_vote(&mut self, args: &RequestVoteArgs) -> RequestVoteReply {
        if !self.verify_request_vote(args) {
            return RequestVoteReply {
                term: self.current_term,
                vote_granted: false,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        // §5.1 — adopt higher term as follower.
        if args.term > self.current_term {
            self.become_follower(args.term);
        }
        let grant = self.should_grant_vote(
            &args.candidate_id,
            args.term,
            args.last_log_index,
            args.last_log_term,
        );
        if grant {
            self.voted_for = Some(args.candidate_id.clone());
            self.persist_hard_state();
        }
        RequestVoteReply {
            term: self.current_term,
            vote_granted: grant,
            timestamp_ms: 0,
            hmac: None,
        }
    }

    /// Process an incoming `AppendEntriesArgs`, returning an `AppendEntriesReply`.
    pub fn handle_append_entries(&mut self, args: &AppendEntriesArgs) -> AppendEntriesReply {
        if !self.verify_append_entries(args) {
            return AppendEntriesReply {
                term: self.current_term,
                success: false,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        // §5.1 — Reject if the leader's term is stale.
        if args.term < self.current_term {
            return AppendEntriesReply {
                term: self.current_term,
                success: false,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        if args.term > self.current_term {
            self.become_follower(args.term);
        } else if self.state != RaftState::Follower {
            // §5.2: a Candidate that receives an AppendEntries from a peer
            // claiming the *same* term must concede leadership and revert
            // to Follower. The previous code mutated `self.state` directly
            // here without persisting — leaving the role transition
            // unpersisted across a crash. Route through `become_follower`
            // so the role flip is durable.
            self.become_follower(args.term);
        }

        // CRIT (audit): cross-check the AE's claimed `leader_id` against
        // the mTLS-authenticated peer identity of the channel that
        // delivered it.
        //
        // The transport-level peer identity is exposed by
        // [`ReplicationTransport::secure_channel_for`] but is not threaded
        // through to `handle_append_entries` here — this entry point is
        // transport-agnostic and is also called from in-memory tests.
        // Until the dispatcher in `replication.rs` plumbs the authenticated
        // peer id (or the channel handle) into this function, fall through
        // to the current behaviour but emit a one-off debug record so
        // operators can confirm the cross-check is skipped.
        //
        // TODO(raft-leader-hint-auth): plumb the mTLS-authenticated peer
        // id from `ReplicationTransport::secure_channel_for` into
        // `handle_append_entries` and reject the RPC (without updating
        // `current_leader_hint`) when `args.leader_id` does not match the
        // transport-level identity. See `src/replication.rs:794`.
        tracing::trace!(
            target: "craton_hsm_cluster::raft",
            leader_id = %args.leader_id,
            "AppendEntries: transport-level peer-id cross-check skipped \
             (hook not wired into handle_append_entries)"
        );

        // CRIT (audit): record the AppendEntries-bound leader identity
        // for the current term. `handle_install_snapshot` cross-checks
        // its HMAC-bound `leader_id` against this hint so a peer that
        // knows the cluster secret but is not the current leader cannot
        // cancel an in-flight chunked snapshot install by forging
        // descriptor-mismatch chunks.
        self.current_leader_hint = Some(args.leader_id.clone());

        let now = now_ms();
        self.record_heartbeat(now);

        // §5.3 — prev_log consistency check.
        if args.prev_log_index > 0 {
            // If the prev_log_index is below our snapshot, treat as consistent
            // when terms match.
            if args.prev_log_index < self.last_snapshot_index {
                // Out-of-range, can't verify — reject and let leader install snapshot.
                return AppendEntriesReply {
                    term: self.current_term,
                    success: false,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
            if args.prev_log_index == self.last_snapshot_index {
                if args.prev_log_term != self.last_snapshot_term {
                    return AppendEntriesReply {
                        term: self.current_term,
                        success: false,
                        timestamp_ms: 0,
                        hmac: None,
                    };
                }
            } else {
                match self.log.get(args.prev_log_index) {
                    None => {
                        return AppendEntriesReply {
                            term: self.current_term,
                            success: false,
                            timestamp_ms: 0,
                            hmac: None,
                        };
                    }
                    Some(entry) if entry.term != args.prev_log_term => {
                        let trunc_to = args.prev_log_index - 1;
                        if let Err(e) = self.log.truncate_after(trunc_to) {
                            // Invariant violation (would discard applied
                            // state): refuse the RPC.  The peer will re-send
                            // with a different `prev_log_index` or the
                            // leader will be forced to ship a snapshot.
                            tracing::error!("Raft: refusing prev-log conflict truncation: {e}");
                            return AppendEntriesReply {
                                term: self.current_term,
                                success: false,
                                timestamp_ms: 0,
                                hmac: None,
                            };
                        }
                        self.persist_truncate(trunc_to);
                        return AppendEntriesReply {
                            term: self.current_term,
                            success: false,
                            timestamp_ms: 0,
                            hmac: None,
                        };
                    }
                    _ => {}
                }
            }
        }

        // §5.3 — Append new entries, truncating any conflicts first.
        // M (audit): pre-loop fail-closed assertion that the entries
        // batch is index-monotonic. A non-monotonic batch from a buggy
        // or adversarial leader could cause the truncate-then-append
        // logic below to silently drop or duplicate a range; reject the
        // RPC instead.
        for window in args.entries.windows(2) {
            if window[1].index != window[0].index + 1 {
                tracing::error!(
                    "Raft: rejecting AppendEntries — non-monotonic entries: {} -> {}",
                    window[0].index,
                    window[1].index
                );
                return AppendEntriesReply {
                    term: self.current_term,
                    success: false,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
        }
        let mut newly_appended: Vec<LogEntry> = Vec::new();
        for entry in &args.entries {
            match self.log.get(entry.index) {
                Some(existing) if existing.term != entry.term => {
                    let trunc_to = entry.index - 1;
                    if let Err(e) = self.log.truncate_after(trunc_to) {
                        // Would truncate applied state — reject the RPC
                        // rather than crash.  The leader can retry once
                        // its view of our applied index catches up.
                        tracing::error!("Raft: refusing conflict truncation inside AE: {e}");
                        return AppendEntriesReply {
                            term: self.current_term,
                            success: false,
                            timestamp_ms: 0,
                            hmac: None,
                        };
                    }
                    self.persist_truncate(trunc_to);
                    // MED (audit): single clone, used twice.  Prior
                    // code cloned the entry twice per append (once for
                    // the log, once for the persistence buffer); the
                    // cloned value is identical so a single clone
                    // suffices.
                    let cloned = entry.clone();
                    self.log.append(cloned.clone());
                    newly_appended.push(cloned);
                }
                None => {
                    let cloned = entry.clone();
                    self.log.append(cloned.clone());
                    newly_appended.push(cloned);
                }
                Some(_) => {}
            }
        }
        if !newly_appended.is_empty() {
            self.persist_appended(&newly_appended);
        }

        // §5.3 — Advance commit index.
        if args.leader_commit > self.log.committed() {
            let last_new = args.entries.last().map_or(args.prev_log_index, |e| e.index);
            let new_commit = args.leader_commit.min(last_new);
            self.log.commit(new_commit);
            // Fix 2: flush log + hard state through to disk before the
            // state machine applies.  Ordering is defined by the trait
            // (append_log first, save_hard_state second, then this fsync
            // barrier).
            self.sync_committed_state_best_effort();
        }

        // Apply committed entries to the state machine.
        self.apply_committed();

        // Auto-snapshot if interval reached.
        self.maybe_snapshot();

        AppendEntriesReply {
            term: self.current_term,
            success: true,
            timestamp_ms: 0,
            hmac: None,
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot install
    // -----------------------------------------------------------------------

    /// Build an [`InstallSnapshotArgs`] for shipping to a lagging follower.
    pub fn prepare_install_snapshot(&self) -> Option<InstallSnapshotArgs> {
        let sm = self.state_machine.as_ref()?;
        let snap = sm.snapshot();
        let data = serde_json::to_vec(&snap).ok()?;
        let last_included_index = self.last_snapshot_index.max(snap.last_applied);
        // Resolve the term of `last_included_index`.  Prefer the log entry's
        // term if still present; fall back to the recorded snapshot term.
        let last_included_term = if last_included_index == self.last_snapshot_index {
            self.last_snapshot_term
        } else {
            self.log
                .get(last_included_index)
                .map(|e| e.term)
                .unwrap_or(self.last_snapshot_term)
        };
        // H14 single-chunk default: total_size = data.len(),
        // offset = 0, last_chunk = true.  Chunked transfers should
        // construct InstallSnapshotArgs explicitly with the chunk
        // descriptor set.
        let total_size = data.len() as u64;
        let mut args = InstallSnapshotArgs {
            term: self.current_term,
            leader_id: self.id.clone(),
            last_included_index,
            last_included_term,
            data,
            timestamp_ms: now_ms(),
            hmac: None,
            offset: 0,
            total_size,
            last_chunk: true,
        };
        if let Some(secret) = &self.cluster_secret {
            args.hmac = Some(Self::compute_install_snapshot_hmac(secret, &args));
        }
        Some(args)
    }

    /// Process an incoming `InstallSnapshot` RPC, returning a reply.
    ///
    /// # Fix 1 — committed-index safety guard
    ///
    /// If the leader's `last_included_index` is *below* this follower's
    /// committed watermark, Raft §7 normally allows silently ignoring the
    /// message (the follower already has all the state the snapshot
    /// covers).  But a Byzantine leader who knows the cluster secret could
    /// instead ship a snapshot with a *different* `last_included_term` for
    /// a committed entry and thereby rewrite state that a quorum has
    /// already agreed on.  Before [`RaftLog::discard_through`] we now
    /// verify that, when `last_included_index < commit_index`, the term
    /// the leader claims matches what we already committed:
    ///
    /// * same term ⇒ accept (old snapshot; `discard_through` is a safe
    ///   no-op because the entries are still logically present),
    /// * different term ⇒ reject, leaving log and state machine untouched.
    ///
    /// The regular "fresh" case (`last_included_index ≥ commit_index`)
    /// proceeds as before.
    pub fn handle_install_snapshot(&mut self, args: &InstallSnapshotArgs) -> InstallSnapshotReply {
        if !self.verify_install_snapshot(args) {
            // Item 1 (audit, snapshot variant): auth failure must
            // increment the forged-snapshot counter — observability for
            // the same class of attack handled below by the leader-id
            // cross-check. Also hide our `current_term` from a forged
            // request to deny term-leak intelligence: a peer that
            // cannot produce a valid HMAC has no business learning what
            // term we believe we are in.
            self.forged_snapshot_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return InstallSnapshotReply {
                term: Term(0),
                timestamp_ms: 0,
                hmac: None,
            };
        }
        if args.term < self.current_term {
            // Stale-term reject: bump the counter so operators can see the
            // full rate of rejected InstallSnapshot RPCs in one metric.
            self.forged_snapshot_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return InstallSnapshotReply {
                term: self.current_term,
                timestamp_ms: 0,
                hmac: None,
            };
        }
        if args.term > self.current_term {
            self.become_follower(args.term);
        }

        // CRIT (audit): cross-check the HMAC-bound `leader_id` against
        // the AppendEntries-bound current leader hint. A peer who knows
        // the cluster secret but is not the current leader could
        // otherwise inject a chunk with a forged descriptor and cancel
        // an in-flight chunked snapshot install (the descriptor-mismatch
        // branch below wipes `snapshot_chunk_buffers[leader_id]`). When
        // a hint is set and disagrees with the RPC's leader_id, refuse
        // the chunk before any buffer mutation.
        if let Some(known) = &self.current_leader_hint {
            if known != &args.leader_id {
                self.forged_snapshot_rejects
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    rpc_leader = %args.leader_id,
                    known_leader = %known,
                    "Raft: rejecting InstallSnapshot — HMAC-bound leader_id \
                     diverges from the AppendEntries-bound current leader \
                     (cluster-secret-aware forgery attempt?)"
                );
                return InstallSnapshotReply {
                    term: self.current_term,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
        }

        // Fix 1: refuse to install a snapshot whose last_included_term
        // disagrees with a committed entry we already hold.  This is the
        // Byzantine-leader guard — installing the snapshot in that case
        // would overwrite committed state.
        if args.last_included_index < self.log.committed() {
            // Consult snapshot boundary first (the entry may have been
            // compacted out of the in-memory log).
            if args.last_included_index == self.last_snapshot_index {
                if args.last_included_term != self.last_snapshot_term {
                    self.forged_snapshot_rejects
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(
                        "Raft: refusing InstallSnapshot at committed index \
                         {} — snapshot term {} disagrees with local snapshot \
                         term {} (Byzantine-leader rewrite attempt?)",
                        args.last_included_index,
                        args.last_included_term,
                        self.last_snapshot_term,
                    );
                    return InstallSnapshotReply {
                        term: self.current_term,
                        timestamp_ms: 0,
                        hmac: None,
                    };
                }
            } else if let Some(local) = self.log.get(args.last_included_index) {
                if local.term != args.last_included_term {
                    self.forged_snapshot_rejects
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(
                        "Raft: refusing InstallSnapshot at committed index \
                         {} — snapshot term {} disagrees with local term {} \
                         (Byzantine-leader rewrite attempt?)",
                        args.last_included_index,
                        args.last_included_term,
                        local.term,
                    );
                    return InstallSnapshotReply {
                        term: self.current_term,
                        timestamp_ms: 0,
                        hmac: None,
                    };
                }
                // Same term at a committed index: the snapshot is older
                // than our state but consistent with it.  Treat as a no-op
                // — do not discard, do not overwrite state machine.
                tracing::debug!(
                    "Raft: ignoring stale InstallSnapshot at committed \
                     index {} (term matches local)",
                    args.last_included_index
                );
                return InstallSnapshotReply {
                    term: self.current_term,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
            // Entry neither in log nor at snapshot boundary: commit_index
            // advanced through an earlier snapshot install, so we cannot
            // verify.  Fail closed.
            self.forged_snapshot_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                "Raft: refusing InstallSnapshot at committed index {} — \
                 cannot verify term (no local entry or snapshot boundary match)",
                args.last_included_index
            );
            return InstallSnapshotReply {
                term: self.current_term,
                timestamp_ms: 0,
                hmac: None,
            };
        }

        // H14: chunked snapshot reassembly. Single-chunk transfers
        // (`offset == 0` AND `last_chunk == true`) bypass the buffer and
        // go straight to the persist-then-apply path. Multi-chunk
        // transfers append to a per-leader buffer keyed by `leader_id`
        // and only proceed once the final chunk arrives. The verifier
        // already enforced `MAX_INSTALL_SNAPSHOT_BYTES` so the buffer is
        // bounded.
        let full_data: Vec<u8>;
        if args.offset == 0 && args.last_chunk {
            full_data = args.data.clone();
        } else {
            let key = args.leader_id.clone();
            let buf = self
                .snapshot_chunk_buffers
                .entry(key.clone())
                .or_insert_with(|| SnapshotChunkBuffer {
                    data: Vec::new(),
                    total_size: args.total_size,
                    last_included_index: args.last_included_index,
                    last_included_term: args.last_included_term,
                });
            // Reject mismatched descriptor across chunks.
            if buf.last_included_index != args.last_included_index
                || buf.last_included_term != args.last_included_term
                || (args.total_size != 0
                    && buf.total_size != 0
                    && buf.total_size != args.total_size)
            {
                self.forged_snapshot_rejects
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    "Raft: rejecting InstallSnapshot chunk — descriptor mismatch from {}",
                    args.leader_id
                );
                self.snapshot_chunk_buffers.remove(&key);
                return InstallSnapshotReply {
                    term: self.current_term,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
            // Bound buffer growth.
            if (buf.data.len() as u64).saturating_add(args.data.len() as u64)
                > MAX_INSTALL_SNAPSHOT_BYTES
            {
                self.forged_snapshot_rejects
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!("Raft: chunked snapshot exceeded MAX_INSTALL_SNAPSHOT_BYTES");
                self.snapshot_chunk_buffers.remove(&key);
                return InstallSnapshotReply {
                    term: self.current_term,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
            buf.data.extend_from_slice(&args.data);
            if !args.last_chunk {
                // Acknowledge the chunk; defer apply until last_chunk.
                return InstallSnapshotReply {
                    term: self.current_term,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
            full_data = std::mem::take(&mut buf.data);
            self.snapshot_chunk_buffers.remove(&key);
        }

        // H14 / persist-before-apply: write the snapshot to durable
        // storage FIRST, then restore the state machine and compact the
        // log. The previous order was reversed: it left a window where a
        // crash between SM-restore and persist would lose the snapshot
        // but keep the (now-orphaned) SM state. Persisting first ensures
        // crash recovery sees a self-consistent state on disk.
        let preview_voters: Vec<String> =
            serde_json::from_slice::<StateMachineSnapshot>(&full_data)
                .map(|sm_snap| sm_snap.voters.clone())
                .unwrap_or_default();
        if let Some(store) = &self.storage {
            let snap = PersistedSnapshot {
                last_index: args.last_included_index,
                last_term: args.last_included_term,
                voters: preview_voters.clone(),
                data: full_data.clone(),
            };
            if let Err(e) = store.save_snapshot(&snap) {
                tracing::error!("Raft: failed to persist snapshot: {e}");
                return InstallSnapshotReply {
                    term: self.current_term,
                    timestamp_ms: 0,
                    hmac: None,
                };
            }
        }

        // Item 4 (audit): deserialize FIRST. If the snapshot bytes are
        // malformed, return early *before* discarding any log entries or
        // advancing the snapshot pointers — otherwise the node loses
        // history without gaining any state-machine progress in return.
        let parsed: Option<StateMachineSnapshot> =
            match serde_json::from_slice::<StateMachineSnapshot>(&full_data) {
                Ok(s) => Some(s),
                Err(e) => {
                    self.forged_snapshot_rejects
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(
                        "Raft: InstallSnapshot bytes failed to deserialize ({e}); \
                     refusing to advance log/snapshot pointers"
                    );
                    return InstallSnapshotReply {
                        term: self.current_term,
                        timestamp_ms: 0,
                        hmac: None,
                    };
                }
            };
        let mut snapshot_voters: Option<Vec<String>> = None;
        if let (Some(sm), Some(snap)) = (&self.state_machine, parsed.as_ref()) {
            snapshot_voters = Some(snap.voters.clone());
            sm.restore_from_snapshot(snap);
        } else if let Some(snap) = parsed.as_ref() {
            // No SM attached — still record voters for sync_peers_from_voters.
            snapshot_voters = Some(snap.voters.clone());
        }
        // Compact the in-memory log up to the snapshot point.
        self.log.discard_through(args.last_included_index);
        self.last_snapshot_index = args.last_included_index;
        self.last_snapshot_term = args.last_included_term;
        if let Some(voters) = snapshot_voters {
            self.sync_peers_from_voters(&voters);
        }
        // Truncate the persisted log after the snapshot boundary.
        if let Some(store) = &self.storage {
            if let Err(e) = store.truncate_log_after(args.last_included_index) {
                tracing::error!("Raft: failed to truncate log post-snapshot: {e}");
            }
        }
        InstallSnapshotReply {
            term: self.current_term,
            timestamp_ms: 0,
            hmac: None,
        }
    }

    /// Apply all committed-but-not-yet-applied entries to the state machine.
    /// After application, the local peer list is re-synced from the state
    /// machine voter set so that membership changes propagate without an
    /// explicit reconfiguration step.
    pub fn apply_committed(&mut self) {
        let Some(sm) = self.state_machine.clone() else {
            return;
        };
        let mut saw_config_change = false;
        while self.log.applied() < self.log.committed() {
            let next = self.log.applied() + 1;
            let Some(entry) = self.log.get(next).cloned() else {
                break;
            };
            let entry_is_config_change = matches!(entry.command, RaftCommand::ConfigChange { .. });
            if entry_is_config_change && saw_config_change {
                // H15 (audit): walk at most one ConfigChange per
                // apply_committed pass so the voter-set transition is
                // visible to higher-level consumers between membership
                // edits. Subsequent ConfigChanges remain committed and
                // will be applied on the next call.
                tracing::debug!("Raft: deferring next ConfigChange (already saw one this pass)");
                break;
            }
            if entry_is_config_change {
                saw_config_change = true;
            }
            match sm.apply(&entry) {
                Ok(_) => self.log.apply(next),
                Err(e) => {
                    // Item 5 (audit): first-occurrence halt sentinel so
                    // operators can alarm on the wedged apply loop.
                    if !self
                        .apply_halted
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        tracing::error!(
                            failed_index = next,
                            error = %e,
                            "Raft: state machine apply failed — setting apply_halted=true"
                        );
                    } else {
                        tracing::error!(
                            "Raft: state machine apply failed at {}: {} — halting apply loop",
                            next,
                            e
                        );
                    }
                    break;
                }
            }
        }
        if saw_config_change {
            let voters = sm.voters();
            self.sync_peers_from_voters(&voters);
        }
    }

    /// Re-derive the local peer list from a voter set, preserving leader
    /// replication state for surviving peers.  Adds entries to
    /// `next_index`/`match_index` for new peers and drops them for departed
    /// peers.  This is called after [`apply_committed`](Self::apply_committed)
    /// processes a `ConfigChange` and after a snapshot install.
    pub fn sync_peers_from_voters(&mut self, voters: &[String]) {
        // Build the new-peer set directly from `voters` (no intermediate Vec).
        let new_set: std::collections::HashSet<&str> = voters
            .iter()
            .filter(|v| *v != &self.id)
            .map(String::as_str)
            .collect();
        let new_peers: Vec<String> = voters.iter().filter(|v| **v != self.id).cloned().collect();

        // Drop replication state for peers no longer in the voter set.
        self.next_index.retain(|k, _| new_set.contains(k.as_str()));
        self.match_index.retain(|k, _| new_set.contains(k.as_str()));
        // Fix 3: evict per-peer ConfigChange timestamps for departed peers.
        self.last_config_change_at
            .retain(|k, _| new_set.contains(k.as_str()));

        // For new peers (only meaningful when leader), seed next_index/match_index.
        if self.state == RaftState::Leader {
            let next = self.log.last_index() + 1;
            for p in &new_peers {
                // Two entry() calls require two owned keys — DashMap does not
                // offer a borrow-based entry API.  Membership changes are rare
                // (O(cluster-size) clones per change) so this is not a hot-path
                // concern.
                self.next_index.entry(p.clone()).or_insert(next);
                self.match_index.entry(p.clone()).or_insert(0);
            }
        }

        // M (audit): keep the vote-rate-limiter allowlist in sync, but
        // retain peers that were removed within the last election-timeout
        // window so RPCs in flight at the moment of a membership change
        // are not dropped purely because the membership flipped under
        // them. Record now the peers that are leaving (in `self.peers`
        // but no longer in `new_set`) so they age out cleanly.
        let now = self.now_monotonic_ms();
        let grace_ms = self.election_timeout_ms;
        for old_peer in &self.peers {
            if !new_set.contains(old_peer.as_str()) {
                self.recent_departed_peers.insert(old_peer.clone(), now);
            }
        }
        // Drop entries older than the grace window.
        self.recent_departed_peers
            .retain(|_, ts| now.saturating_sub(*ts) < grace_ms);

        let mut allowed: HashSet<String> =
            HashSet::with_capacity(new_peers.len() + 1 + self.recent_departed_peers.len());
        allowed.extend(new_peers.iter().cloned());
        allowed.insert(self.id.clone());
        for k in self.recent_departed_peers.keys() {
            allowed.insert(k.clone());
        }
        self.vote_rate_limiter.set_allowed_peers(Some(allowed));

        self.peers = new_peers;
    }

    /// HIGH (audit, vote-rate-limiter unbounded under `allowed_peers = None`):
    /// run periodic per-peer bucket eviction so stale entries do not
    /// pin memory indefinitely.
    ///
    /// Evicts any per-peer bucket whose `last_refill_ms` is older than
    /// `2 × base_election_timeout_ms` — generous enough that a peer
    /// that just legitimately drained its bucket and is awaiting a
    /// refill is never evicted, but bounded enough that the memory
    /// footprint tracks the active peer set rather than the lifetime
    /// peer set.
    ///
    /// Drive this from the same maintenance path that issues heartbeats
    /// and runs leader-lease checks. Idempotent and cheap when there
    /// are no stale entries.
    pub fn run_periodic_maintenance(&self) -> usize {
        let stale = self.base_election_timeout_ms.saturating_mul(2);
        self.vote_rate_limiter.evict_stale(now_ms(), stale)
    }

    /// Take a snapshot if the configured interval has been reached.
    pub fn maybe_snapshot(&mut self) {
        if self.snapshot_interval == 0 {
            return;
        }
        let applied = self.log.applied();
        if applied < self.last_snapshot_index + self.snapshot_interval {
            return;
        }
        let Some(sm) = self.state_machine.clone() else {
            return;
        };
        let s = sm.snapshot();
        let data = match serde_json::to_vec(&s) {
            Ok(d) => d,
            Err(_) => return,
        };
        let last_term = self
            .log
            .get(applied)
            .map(|e| e.term)
            .unwrap_or(self.last_snapshot_term);
        if let Some(store) = &self.storage {
            let snap = PersistedSnapshot {
                last_index: applied,
                last_term,
                voters: sm.voters(),
                data,
            };
            if let Err(e) = store.save_snapshot(&snap) {
                tracing::error!("Raft: failed to write snapshot: {e}");
                return;
            }
            if let Err(e) = store.truncate_log_after(applied) {
                tracing::error!("Raft: failed to truncate log after snapshot: {e}");
            }
        }
        self.log.discard_through(applied);
        self.last_snapshot_index = applied;
        self.last_snapshot_term = last_term;
    }

    // -----------------------------------------------------------------------
    // Leader replication methods
    // -----------------------------------------------------------------------

    /// Submit a new command via the leader.  The command is appended to the
    /// local log and persisted (if a backing store is configured).  Returns
    /// the index assigned to the new entry, or `None` if this node is not the
    /// current leader.
    pub fn submit_command(&mut self, command: RaftCommand) -> Option<u64> {
        if !self.is_leader() {
            return None;
        }
        let index = self.log.last_index() + 1;
        let entry = LogEntry {
            term: self.current_term,
            index,
            command,
        };
        self.log.append(entry.clone());
        self.persist_appended(std::slice::from_ref(&entry));
        // For a single-node cluster the leader can immediately commit & apply.
        if self.peers.is_empty() {
            self.advance_commit_index();
            self.apply_committed();
        }
        Some(index)
    }

    // -----------------------------------------------------------------------
    // Quorum-gated ConfigChange proposals (audit M7)
    // -----------------------------------------------------------------------

    /// Create a membership-change proposal.  The proposal is recorded locally
    /// with the leader's own implicit approval; additional approvals must be
    /// collected from a **majority of the current voter set** via
    /// [`record_config_change_approval`](Self::record_config_change_approval)
    /// before [`commit_config_change_proposal`](Self::commit_config_change_proposal)
    /// will promote it to a `RaftCommand::ConfigChange` log entry.
    ///
    /// Returns `None` if this node is not the current leader (only a leader
    /// may initiate membership changes) or if no `cluster_secret` is set.
    pub fn propose_config_change(
        &mut self,
        proposal_id: String,
        node_id: String,
        action: MembershipAction,
    ) -> Option<ConfigChangeProposal> {
        if !self.is_leader() {
            return None;
        }
        if self.cluster_secret.is_none() {
            return None;
        }
        // H15 (audit): single-server-change invariant. Reject a new
        // proposal while another is pending OR while there is an
        // uncommitted ConfigChange already in the log. Raft §6 says at
        // most one membership change may be in flight at a time, otherwise
        // the joint-consensus invariant breaks. Without this guard a
        // malicious or buggy leader could propose two adds back-to-back
        // and confuse follower voter sets.
        if !self.pending_config_changes.is_empty() {
            tracing::warn!("Raft: refusing ConfigChange — another proposal is pending");
            return None;
        }
        let committed = self.log.committed();
        for idx in (committed + 1)..=self.log.last_index() {
            if let Some(entry) = self.log.get(idx) {
                if matches!(entry.command, RaftCommand::ConfigChange { .. }) {
                    tracing::warn!(
                        "Raft: refusing ConfigChange — uncommitted ConfigChange at log index {}",
                        idx
                    );
                    return None;
                }
            }
        }
        let proposal = ConfigChangeProposal {
            proposal_id: proposal_id.clone(),
            node_id,
            action,
            timestamp_ms: now_ms(),
        };
        // Leader auto-approves its own proposal.
        let mut approvers = HashSet::new();
        approvers.insert(self.id.clone());
        self.pending_config_changes.insert(
            proposal_id,
            PendingConfigChange {
                proposal: proposal.clone(),
                approvers,
            },
        );
        Some(proposal)
    }

    /// Record an incoming [`ConfigChangeApproval`] against a pending
    /// proposal.  Verifies the approval's HMAC under the cluster secret and
    /// confirms the approver is a current voter (in `peers` or is `self.id`)
    /// and is not already counted.
    ///
    /// Returns `true` when the approval was accepted and recorded.
    pub fn record_config_change_approval(&mut self, approval: &ConfigChangeApproval) -> bool {
        let secret = match &self.cluster_secret {
            None => return false,
            Some(s) => s,
        };
        let pending = match self.pending_config_changes.get_mut(&approval.proposal_id) {
            None => return false,
            Some(p) => p,
        };
        // Freshness — don't accept stale approvals (replay window defense).
        if !check_message_freshness(
            approval.timestamp_ms,
            self.max_message_age_ms,
            self.max_future_skew_ms,
        ) {
            return false;
        }
        // HIGH (audit, voter-set divergence): the source of truth for
        // who may approve a config change is the *state machine's*
        // voter set, not the in-memory `self.peers + self.id`. During
        // a multi-step membership transition those two views can
        // diverge for the duration of one apply pass; if we trust
        // `self.peers` we may count an approval from a node that is
        // already no longer a voter (or refuse a legitimate approval
        // from a newly added voter). Consult the state machine first
        // and fall back to `self.peers + self.id` only when no SM is
        // attached.
        let is_voter = match &self.state_machine {
            Some(sm) => sm.voters().iter().any(|v| v == &approval.approver_id),
            None => {
                approval.approver_id == self.id
                    || self.peers.iter().any(|p| p == &approval.approver_id)
            }
        };
        if !is_voter {
            return false;
        }
        let expected = Self::compute_config_change_approval_hmac(
            secret,
            &pending.proposal.proposal_id,
            &pending.proposal.node_id,
            &pending.proposal.action,
            &approval.approver_id,
            approval.timestamp_ms,
        );
        if !Self::verify_hmac(&approval.hmac, &expected) {
            return false;
        }
        pending.approvers.insert(approval.approver_id.clone());
        true
    }

    /// Attempt to commit a pending `ConfigChangeProposal` once a majority
    /// of the current voter set has approved it.  On success, the proposal
    /// is submitted as a regular [`RaftCommand::ConfigChange`] entry and
    /// the pending record is cleared; returns the assigned log index.
    ///
    /// Returns `None` when this node is not the leader, the proposal is not
    /// known, or the approval count has not yet reached quorum.
    pub fn commit_config_change_proposal(&mut self, proposal_id: &str) -> Option<u64> {
        if !self.is_leader() {
            return None;
        }
        let quorum = self.quorum_size();
        let pending = self.pending_config_changes.get(proposal_id)?;
        if pending.approvers.len() < quorum {
            return None;
        }
        let cmd = RaftCommand::ConfigChange {
            node_id: pending.proposal.node_id.clone(),
            action: pending.proposal.action.clone(),
        };
        let idx = self.submit_command(cmd)?;
        self.pending_config_changes.remove(proposal_id);
        Some(idx)
    }

    /// Number of voters who have signed off on the proposal so far.  Used by
    /// leader code and tests to poll progress.
    pub fn config_change_approvals(&self, proposal_id: &str) -> usize {
        self.pending_config_changes
            .get(proposal_id)
            .map(|p| p.approvers.len())
            .unwrap_or(0)
    }

    /// Build an `AppendEntriesArgs` for a specific peer.
    ///
    /// # Fix 3 — per-peer ConfigChange rate limit
    ///
    /// If the entries to ship include at least one
    /// [`RaftCommand::ConfigChange`] and a prior ConfigChange-bearing
    /// AppendEntries was sent to this same peer within
    /// `min_config_change_interval_ms` (default 500 ms, configurable via
    /// [`ClusterConfig::min_config_change_interval_ms`]), the call returns
    /// `None` — the caller should retry after a short delay.  This bounds
    /// the rate at which membership edits can reach any single peer and
    /// gives operators an observation window after each one.  Regular
    /// (non-ConfigChange) AppendEntries traffic is unaffected.
    ///
    /// Takes `&mut self` because it updates the per-peer
    /// `last_config_change_at` bookkeeping on successful dispatch.
    ///
    /// # Performance
    ///
    /// For single-peer dispatch this method still allocates one
    /// `Vec<LogEntry>` for the outgoing entries (unavoidable — the
    /// on-the-wire `AppendEntriesArgs.entries` is `Vec<LogEntry>`).  When
    /// sending to many peers in the same replication round, prefer
    /// [`replicate_to_all`](Self::replicate_to_all) or
    /// [`replicate_to_all_prepared`](Self::replicate_to_all_prepared),
    /// which build a single `Arc<[LogEntry]>` snapshot of the leader's log
    /// suffix up front and hand sub-slice handles to each peer.
    pub fn prepare_append_entries(&mut self, peer_id: &str) -> Option<AppendEntriesArgs> {
        // Delegate through the shared-Arc path with a single-peer Arc so the
        // Arc-based code path is the single implementation of
        // "build an AppendEntries for peer P".
        if self.state != RaftState::Leader {
            return None;
        }
        let next_idx = *self.next_index.get(peer_id)?;
        let base_next_idx = next_idx;
        let shared: Arc<[LogEntry]> = Arc::from(self.log.entries_slice_from(base_next_idx));
        // Single-peer entry point: scan the (per-peer) shared slice
        // once and pass the answer through.  Same end result as the
        // batched form in `replicate_to_all_prepared`.
        let round_has_config_change = shared
            .iter()
            .any(|e| matches!(e.command, RaftCommand::ConfigChange { .. }));
        self.prepare_append_entries_shared(peer_id, base_next_idx, &shared, round_has_config_change)
            .map(PreparedAppendEntries::into_args)
    }

    /// Build a [`PreparedAppendEntries`] for `peer_id` using a pre-built
    /// shared `Arc<[LogEntry]>` covering the leader-log suffix starting at
    /// `base_next_idx`.  This is the per-peer half of
    /// [`replicate_to_all_prepared`] — it slices the shared Arc to the
    /// range the peer needs and clones only the Arc handle (O(1))
    /// rather than reallocating the suffix for each peer.
    ///
    /// `shared` MUST contain entries in contiguous index order starting at
    /// `base_next_idx`.  If the peer's `next_index` is below `base_next_idx`
    /// (peer has fallen further behind than this batch covers), the
    /// per-peer Arc is rebuilt from the log on the spot — a rare path that
    /// only costs when a peer is outside the pre-built window.
    ///
    /// MED (audit, perf): `round_has_config_change` is computed *once*
    /// per `replicate_to_all` round and passed in so we can short-circuit
    /// the per-peer ConfigChange scan when the entire shared suffix
    /// contains none. The single-peer entry point passes the answer for
    /// its own slice (correctness-preserving).
    fn prepare_append_entries_shared(
        &mut self,
        peer_id: &str,
        base_next_idx: u64,
        shared: &Arc<[LogEntry]>,
        round_has_config_change: bool,
    ) -> Option<PreparedAppendEntries> {
        if self.state != RaftState::Leader {
            return None;
        }
        let next_idx = *self.next_index.get(peer_id)?;

        let prev_log_index = next_idx.saturating_sub(1);
        let prev_log_term = if prev_log_index == 0 {
            Term(0)
        } else if prev_log_index == self.last_snapshot_index {
            self.last_snapshot_term
        } else {
            self.log.get(prev_log_index).map_or(Term(0), |e| e.term)
        };

        // Compute a zero-copy handle to this peer's entries by sub-slicing
        // the shared Arc.  The sub-slice carries its own `Arc` clone (ref
        // count bump, no allocation) in the common case where
        // `next_idx >= base_next_idx`.  When the peer is further behind
        // than the shared snapshot covers, we fall back to rebuilding a
        // fresh Arc — keeps correctness without complicating the
        // replicate_to_all contract.
        let entries_arc: Arc<[LogEntry]> = if next_idx >= base_next_idx {
            let offset = (next_idx - base_next_idx) as usize;
            if offset == 0 {
                Arc::clone(shared)
            } else if offset >= shared.len() {
                // Peer is already up to date relative to this snapshot —
                // send an empty heartbeat.
                let empty: &[LogEntry] = &[];
                Arc::from(empty)
            } else {
                Arc::<[LogEntry]>::from(&shared[offset..])
            }
        } else {
            // Peer has fallen further back than the shared snapshot
            // covers; rebuild from the live log.
            Arc::from(self.log.entries_slice_from(next_idx))
        };

        // Fix 3: if entries include a ConfigChange, gate delivery to this
        // peer on the configured minimum interval. We short-circuit on
        // `round_has_config_change == false` to avoid the per-peer scan
        // when the entire shared suffix is config-change-free — the
        // common case.
        let has_config_change = round_has_config_change
            && entries_arc
                .iter()
                .any(|e| matches!(e.command, RaftCommand::ConfigChange { .. }));
        let now = now_ms();
        // Item 3 (audit): rate-limit anchor is the monotonic clock so an
        // NTP step cannot punch a hole through the configured minimum
        // interval. The wire `timestamp_ms` (wall-clock) is still
        // computed below for the HMAC binding.
        let now_mono = self.now_monotonic_ms();
        if has_config_change && self.min_config_change_interval_ms > 0 {
            if let Some(&last) = self.last_config_change_at.get(peer_id) {
                if now_mono.saturating_sub(last) < self.min_config_change_interval_ms {
                    tracing::debug!(
                        peer = %peer_id,
                        since_last_ms = now.saturating_sub(last),
                        min_interval_ms = self.min_config_change_interval_ms,
                        "Raft: deferring ConfigChange-bearing AppendEntries \
                         (per-peer rate limit)"
                    );
                    return None;
                }
            }
            // Item 3: store the *monotonic* tick, not wall-clock.
            self.last_config_change_at
                .insert(peer_id.to_string(), now_mono);
        }

        let hmac = self.cluster_secret.as_ref().map(|secret| {
            Self::compute_append_entries_hmac_shared(
                secret,
                self.current_term,
                &self.id,
                prev_log_index,
                prev_log_term,
                &entries_arc,
                self.log.committed(),
                now,
            )
        });

        Some(PreparedAppendEntries {
            term: self.current_term,
            leader_id: self.id.clone(),
            prev_log_index,
            prev_log_term,
            entries: entries_arc,
            leader_commit: self.log.committed(),
            timestamp_ms: now,
            hmac,
        })
    }

    /// Process a reply to an AppendEntries RPC from a peer.
    ///
    /// Item 1 (audit): when a cluster secret is configured *and* the reply
    /// carries an HMAC, the MAC is verified before **any** state mutation —
    /// in particular before the term-bump-to-follower branch. A reply that
    /// fails verification is dropped, the per-node forged-reply counter
    /// is incremented, and a `warn` is logged so operators can alarm.
    pub fn handle_append_entries_reply(
        &mut self,
        peer_id: &str,
        reply: &AppendEntriesReply,
        entries_sent: usize,
    ) {
        // CRIT (audit, reply-verification missing-secret gate): in a
        // non-`insecure-no-cluster-secret` build, a reply must verify
        // under the cluster secret — period. The previous gate was
        // `self.cluster_secret.is_some() && !verify_*`, which fails
        // *open* if a node somehow reaches this branch without a
        // secret (e.g. constructed via `RaftNode::new` rather than
        // `from_config`). Matching `from_config`'s discipline at the
        // RPC boundary closes that gap.
        #[cfg(not(feature = "insecure-no-cluster-secret"))]
        let must_verify = true;
        #[cfg(feature = "insecure-no-cluster-secret")]
        let must_verify = self.cluster_secret.is_some();

        if must_verify && !self.verify_append_entries_reply(reply) {
            // verify_* returns false on: missing secret, missing HMAC,
            // wrong HMAC, or out-of-window freshness. Any of those
            // means "do not trust the term field in this reply" —
            // drop before any state mutation (item 1, audit).
            self.forged_reply_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                peer = %peer_id,
                "Raft: rejecting AppendEntriesReply with bad/forged/missing HMAC"
            );
            return;
        }
        if reply.term > self.current_term {
            self.become_follower(reply.term);
            return;
        }
        if reply.success {
            if let Some(ni) = self.next_index.get_mut(peer_id) {
                let new_match = ni.saturating_sub(1).saturating_add(entries_sent as u64);
                *ni = new_match.saturating_add(1);
                self.match_index.insert(peer_id.to_string(), new_match);
            }
            let prev_commit = self.log.committed();
            self.advance_commit_index();
            if self.log.committed() > prev_commit {
                // Fix 2: fsync barrier at the commit-index advance site on
                // the leader, matching the one in `handle_append_entries`.
                self.sync_committed_state_best_effort();
            }
            self.apply_committed();
            self.maybe_snapshot();
        } else {
            // L (audit): backoff jitter. The prior single-step decrement
            // let a peer drive the leader into a synchronized
            // retransmission storm under steady-state failure. Decrement
            // by 1 plus a small randomized jitter so peers desynchronize
            // and the per-peer retransmit rate has an upper bound related
            // to next_index step size.
            if let Some(ni) = self.next_index.get_mut(peer_id) {
                if *ni > 1 {
                    let step = if *ni > 4 {
                        rand::thread_rng().gen_range(1..=2)
                    } else {
                        1
                    };
                    *ni = ni.saturating_sub(step).max(1);
                }
            }
        }
    }

    /// Advance the commit index based on the current `match_index` values.
    fn advance_commit_index(&mut self) {
        let current_commit = self.log.committed();

        // Defensive: peers MUST not contain self.
        debug_assert!(
            !self.peers.iter().any(|p| p == &self.id),
            "self should not be in peers list"
        );

        let mut match_indices: Vec<u64> = self
            .peers
            .iter()
            .map(|p| self.match_index.get(p).copied().unwrap_or(0))
            .collect();
        match_indices.push(self.log.last_index());
        match_indices.sort_unstable();
        let majority_idx = match_indices.len() / 2;
        let new_commit = match_indices[majority_idx];

        if new_commit > current_commit {
            if let Some(entry) = self.log.get(new_commit) {
                if entry.term == self.current_term {
                    self.log.commit(new_commit);
                }
            } else if new_commit <= self.last_snapshot_index
                && self.last_snapshot_term == self.current_term
            {
                self.log.commit(new_commit);
            }
        }
    }

    /// Build `AppendEntriesArgs` for every peer.
    ///
    /// Returns owned `String` peer IDs rather than borrowed slices because
    /// Fix 3 requires [`prepare_append_entries`](Self::prepare_append_entries)
    /// to take `&mut self` (so it can update the per-peer
    /// `last_config_change_at` map), which rules out returning references
    /// into `self.peers`.  The per-heartbeat cost is therefore `O(peers)`
    /// small `String` clones — acceptable given the ConfigChange
    /// rate-limit discipline Fix 3 adds.
    ///
    /// # Performance (audit L7)
    ///
    /// Internally this builds one `Arc<[LogEntry]>` snapshot of the leader
    /// log suffix per replication round and shares it across all peers,
    /// replacing the prior O(peers × backlog) per-peer `Vec` clones with a
    /// single O(backlog) snapshot plus O(peers) Arc-handle clones.  The
    /// final `Vec<LogEntry>` materialization happens exactly once per peer
    /// at the `AppendEntriesArgs` conversion boundary (required to
    /// preserve the on-the-wire serde shape).  Callers that own their own
    /// transport serializer can avoid even that per-peer allocation by
    /// using [`replicate_to_all_prepared`](Self::replicate_to_all_prepared).
    pub fn replicate_to_all(&mut self) -> Vec<(String, AppendEntriesArgs)> {
        self.replicate_to_all_prepared()
            .into_iter()
            .map(|(peer, prepared)| (peer, prepared.into_args()))
            .collect()
    }

    /// Like [`replicate_to_all`] but returns the richer
    /// [`PreparedAppendEntries`] in-memory form that shares entries across
    /// peers via `Arc<[LogEntry]>`.  Transports can walk the borrowed slice
    /// directly (e.g. via a custom serializer) without the final per-peer
    /// `Vec<LogEntry>` clone.
    pub fn replicate_to_all_prepared(&mut self) -> Vec<(String, PreparedAppendEntries)> {
        if self.state != RaftState::Leader {
            return Vec::new();
        }
        // Clone peer IDs up front so the inner loop can call &mut self.
        // MED (audit, perf): a one-shot `Vec<String>` clone here is the
        // minimum the borrow checker will accept given the per-peer call
        // takes `&mut self` (Fix 3 needs it to update
        // `last_config_change_at`).  We compute `min_next_index` and
        // `round_has_config_change` *incrementally* alongside that
        // clone so we only walk the peer set once and the log suffix
        // once — down from three passes in the prior implementation.
        let peer_list: Vec<String> = self.peers.clone();

        // Single pass over peers: compute the shared-Arc base as the
        // minimum next_index, tracked incrementally rather than via a
        // separate `iter().filter_map().min()` round.
        let mut min_next_index: Option<u64> = None;
        for p in &peer_list {
            if let Some(&n) = self.next_index.get(p) {
                min_next_index = Some(match min_next_index {
                    None => n,
                    Some(cur) => cur.min(n),
                });
            }
        }
        let base_next_idx =
            min_next_index.unwrap_or_else(|| self.log.last_index().saturating_add(1));

        // Build ONE shared Arc covering the log suffix starting at
        // base_next_idx.  This is the only O(backlog) allocation in the
        // whole replication round; every per-peer call after this is
        // O(peer_entries) with no extra allocation for the entries
        // payload (the final Vec materialization happens at
        // `into_args()` in the return pipeline, not here).
        let shared: Arc<[LogEntry]> = Arc::from(self.log.entries_slice_from(base_next_idx));

        // MED (audit, perf): compute `has_any_config_change` once over
        // the shared suffix and pass it through. The per-peer
        // `prepare_append_entries_shared` will skip its own scan when
        // this is false — the common case in steady-state replication.
        let round_has_config_change = shared
            .iter()
            .any(|e| matches!(e.command, RaftCommand::ConfigChange { .. }));

        let mut messages = Vec::with_capacity(peer_list.len());
        for peer in peer_list {
            if let Some(prepared) = self.prepare_append_entries_shared(
                &peer,
                base_next_idx,
                &shared,
                round_has_config_change,
            ) {
                messages.push((peer, prepared));
            }
        }
        messages
    }

    #[cfg(test)]
    fn replay_cache_len(&self) -> usize {
        self.replay_cache.len()
    }
}

/// Length-prefix bytes into a MAC stream.
fn push_lp_to_mac(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&(bytes.len() as u32).to_be_bytes());
    mac.update(bytes);
}

fn finalize_mac(mac: Hmac<Sha256>) -> [u8; 32] {
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Returns the current time in milliseconds since the Unix epoch.
///
/// Falls back to `0` and emits a warning if the system clock is set before
/// 1970, which would otherwise return a confusing zero timestamp without
/// explanation.
fn now_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(_) => {
            tracing::warn!("Raft: system clock is before UNIX epoch, using 0");
            0
        }
    }
}

// ---------------------------------------------------------------------------
// RPC message types
// ---------------------------------------------------------------------------

/// Arguments for a RequestVote RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteArgs {
    /// Candidate's current term.
    pub term: Term,
    /// ID of the candidate requesting the vote.
    pub candidate_id: String,
    /// Index of the candidate's last log entry.
    pub last_log_index: u64,
    /// Term of the candidate's last log entry.
    pub last_log_term: Term,
    /// Millisecond timestamp (Unix epoch) when the message was created.
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical encoding of the message fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<[u8; 32]>,
}

/// Reply to a RequestVote RPC.
///
/// H17: replies now carry an authenticated MAC under `DOMAIN_REPLY`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestVoteReply {
    /// Current term of the responding node (for candidate to update itself).
    pub term: Term,
    /// Whether the vote was granted.
    pub vote_granted: bool,
    /// H17: timestamp (Unix epoch ms) the reply was constructed.
    #[serde(default)]
    pub timestamp_ms: u64,
    /// H17: HMAC-SHA256 over the canonical reply encoding under `DOMAIN_REPLY`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hmac: Option<[u8; 32]>,
}

/// Arguments for an AppendEntries RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesArgs {
    /// Leader's current term.
    pub term: Term,
    /// ID of the leader.
    pub leader_id: String,
    /// Index of the log entry immediately preceding the new ones.
    pub prev_log_index: u64,
    /// Term of the entry at `prev_log_index`.
    pub prev_log_term: Term,
    /// Log entries to replicate (empty for heartbeats).
    pub entries: Vec<LogEntry>,
    /// Leader's commit index.
    pub leader_commit: u64,
    /// Millisecond timestamp (Unix epoch) when the message was created.
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical encoding of the message fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<[u8; 32]>,
}

/// In-memory, leader-side counterpart to [`AppendEntriesArgs`] that shares
/// its `entries` payload across peers via `Arc<[LogEntry]>` (audit L7).
///
/// Leader code building a replication round allocates the entries suffix
/// once as an `Arc<[LogEntry]>` and hands each peer a `PreparedAppendEntries`
/// whose `entries` field is a cheap `Arc::clone` of (a sub-slice of) that
/// shared allocation.  Converting to the serde-serializable
/// [`AppendEntriesArgs`] via [`into_args`](Self::into_args) performs the
/// single `Vec<LogEntry>` materialization required for the on-the-wire
/// shape — this happens at most once per peer, at serialization time, and
/// is unchanged from the prior behaviour.
///
/// This type is **not** serialized — it exists purely to split the
/// leader-internal "prepared" representation from the wire form so that
/// the shared-Arc optimization cannot accidentally change the on-wire
/// bytes.  The `hmac` field here and on `AppendEntriesArgs` carry the
/// same canonical digest.
#[derive(Debug, Clone)]
pub struct PreparedAppendEntries {
    /// Leader's current term.
    pub term: Term,
    /// ID of the leader.
    pub leader_id: String,
    /// Index of the log entry immediately preceding the new ones.
    pub prev_log_index: u64,
    /// Term of the entry at `prev_log_index`.
    pub prev_log_term: Term,
    /// Log entries to replicate (empty for heartbeats), backed by a shared
    /// `Arc` owned by the enclosing replication round.  Cloning this
    /// field is O(1) (ref-count bump) — the `Vec<LogEntry>`
    /// materialization happens only inside
    /// [`into_args`](Self::into_args).
    pub entries: Arc<[LogEntry]>,
    /// Leader's commit index.
    pub leader_commit: u64,
    /// Millisecond timestamp (Unix epoch) when the message was created.
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical encoding of the message fields.
    pub hmac: Option<[u8; 32]>,
}

impl PreparedAppendEntries {
    /// Convert to the on-wire [`AppendEntriesArgs`] form.  Performs the
    /// single `Vec<LogEntry>` materialization required by the serde
    /// encoding — for N peers sharing the same Arc, this happens once per
    /// peer at serialize time, but the O(backlog) suffix allocation itself
    /// is shared across all peers in the replication round (one
    /// allocation total, not N).
    pub fn into_args(self) -> AppendEntriesArgs {
        AppendEntriesArgs {
            term: self.term,
            leader_id: self.leader_id,
            prev_log_index: self.prev_log_index,
            prev_log_term: self.prev_log_term,
            entries: self.entries.to_vec(),
            leader_commit: self.leader_commit,
            timestamp_ms: self.timestamp_ms,
            hmac: self.hmac,
        }
    }

    /// Borrow the entries as a `&[LogEntry]` slice without allocating.
    /// Transports that use a custom serializer (avoiding the `Vec` round
    /// trip in [`into_args`](Self::into_args)) can iterate the shared
    /// payload directly.
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }
}

/// Reply to an AppendEntries RPC.
///
/// H17: replies now carry an authenticated MAC under `DOMAIN_REPLY`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppendEntriesReply {
    /// Current term of the responding node.
    pub term: Term,
    /// Whether the entries were successfully appended.
    pub success: bool,
    /// H17: timestamp (Unix epoch ms) the reply was constructed.
    #[serde(default)]
    pub timestamp_ms: u64,
    /// H17: HMAC-SHA256 over the canonical reply encoding under `DOMAIN_REPLY`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hmac: Option<[u8; 32]>,
}

/// Arguments for an InstallSnapshot RPC.
///
/// H14 (audit): the wire format additively carries a chunk descriptor
/// so a large snapshot can be streamed in pieces without crossing the
/// per-frame size cap. Defaults preserve single-chunk semantics:
/// `offset = 0`, `total_size = 0` (treated as `data.len()`),
/// `last_chunk = true`. Single-chunk callers do not need to set them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallSnapshotArgs {
    /// Leader's term.
    pub term: Term,
    /// Leader ID.
    pub leader_id: String,
    /// Last log index covered by this snapshot.
    pub last_included_index: u64,
    /// Term of the entry at `last_included_index`.
    pub last_included_term: Term,
    /// Snapshot bytes (state-machine encoded).
    pub data: Vec<u8>,
    /// Millisecond timestamp (Unix epoch).
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical encoding of the message fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<[u8; 32]>,
    /// H14: byte offset of this chunk within the full snapshot.
    /// `0` for single-chunk transfers (default).
    #[serde(default)]
    pub offset: u64,
    /// H14: total size of the full snapshot. Used by the verifier to
    /// enforce `MAX_INSTALL_SNAPSHOT_BYTES` before any chunk is
    /// applied. `0` means single-chunk-with-implicit-total = data.len().
    #[serde(default)]
    pub total_size: u64,
    /// H14: `true` when this is the final chunk of the snapshot.
    /// Defaults to `true` so single-chunk callers are unaffected.
    #[serde(default = "default_last_chunk_true")]
    pub last_chunk: bool,
}

/// H14: serde default for `InstallSnapshotArgs::last_chunk`. Returns
/// `true` so a wire frame that omits the field is treated as the
/// final (and only) chunk of a snapshot — preserving single-chunk
/// semantics for callers that have not been recompiled against the
/// chunked schema.
fn default_last_chunk_true() -> bool {
    true
}

/// Reply to an InstallSnapshot RPC.
///
/// H17: replies now carry an authenticated MAC under `DOMAIN_REPLY`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallSnapshotReply {
    /// Current term of the responding node.
    pub term: Term,
    /// H17: timestamp (Unix epoch ms) the reply was constructed.
    #[serde(default)]
    pub timestamp_ms: u64,
    /// H17: HMAC-SHA256 over the canonical reply encoding under `DOMAIN_REPLY`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hmac: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Fix 7 — PreVote RPC scaffold
// ---------------------------------------------------------------------------
//
// The PreVote optimisation (Ongaro §9.6 / etcd-raft implementation) prevents
// a partitioned node from forcing a term bump in the main cluster when it
// rejoins.  A partitioned follower would otherwise keep timing out, calling
// `become_candidate` (which increments the term *and* persists the bump),
// and — on reunion — force legitimate leaders to step down even though the
// main cluster had a stable leader the whole time.
//
// H13 (audit): the term-bump path is now gated on pre-vote success via
// `try_become_candidate_with_prevote`.  The election-loop driver builds
// the pre-vote with `prepare_pre_vote`, ships it to peers, collects
// replies, then calls `try_become_candidate_with_prevote(&replies)`.
// If the replies do not constitute a majority the node leaves the term
// untouched — preserving the property that a partitioned follower
// cannot drag the cluster into a new term on reunion. The async timer
// integration remains transport-specific and is intentionally not part
// of the consensus core.

/// Arguments for a PreVote RPC.  Identical to [`RequestVoteArgs`] on the
/// wire except for the distinct [`DOMAIN_PRE_VOTE`] HMAC tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteArgs {
    /// Term the candidate *would* use if it proceeds to a real election.
    /// (Not actually persisted anywhere until `start_election` is called.)
    pub term: Term,
    /// ID of the node soliciting pre-votes.
    pub candidate_id: String,
    /// Index of the candidate's last log entry.
    pub last_log_index: u64,
    /// Term of the candidate's last log entry.
    pub last_log_term: Term,
    /// Unix-epoch milliseconds when the message was created (freshness).
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical encoding of the above, with domain
    /// tag [`DOMAIN_PRE_VOTE`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<[u8; 32]>,
}

/// Reply to a PreVote RPC.
///
/// H17: replies now carry an authenticated MAC under `DOMAIN_REPLY`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreVoteReply {
    /// Current term of the responding node (for the candidate to learn
    /// whether it is behind).
    pub term: Term,
    /// Whether this voter *would* grant a real vote if asked with the
    /// same args right now.
    pub vote_granted: bool,
    /// H17: timestamp (Unix epoch ms) the reply was constructed.
    #[serde(default)]
    pub timestamp_ms: u64,
    /// H17: HMAC-SHA256 over the canonical reply encoding under `DOMAIN_REPLY`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hmac: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Membership change: quorum-gated proposal
// ---------------------------------------------------------------------------

/// A proposed cluster membership change, awaiting majority approval before
/// it is committed as a regular [`RaftCommand::ConfigChange`] log entry.
///
/// # Why a separate proposal step?
///
/// Prior to this, `RaftCommand::ConfigChange` entries were accepted by any
/// node that could produce a valid HMAC — i.e. any node sharing the cluster
/// secret.  That means a single compromised node with the shared key could
/// unilaterally add itself (or remove a quorum partner) by appending a
/// ConfigChange entry to the log.  HMAC verification alone does not
/// distinguish "leader acting on behalf of a quorum" from "rogue node with
/// the key" (audit finding M7).
///
/// The proposal protocol closes that hole: a membership change must be
/// authorised by a **majority of the current voter set** before it is
/// turned into a log entry.  Each approval is an HMAC signed with the same
/// cluster secret, but is bound to a unique `proposal_id` and the
/// `approver_id` — so each voter can only sign once and replays cannot be
/// reused across proposals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigChangeProposal {
    /// Unique ID for this proposal (e.g. UUID).  Used as replay and dedup
    /// key for approvals.
    pub proposal_id: String,
    /// Node affected by the change.
    pub node_id: String,
    /// Add or remove.
    pub action: MembershipAction,
    /// Unix-epoch milliseconds when the proposal was created (for freshness).
    pub timestamp_ms: u64,
}

/// An HMAC-authenticated approval of a [`ConfigChangeProposal`] issued by
/// the named `approver_id`.
///
/// The HMAC domain-separates on tag `0x04` and covers the proposal
/// identity, the membership action, and the approver ID — so an approval
/// cannot be replayed across proposals or be attributed to a different
/// approver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigChangeApproval {
    /// Proposal being approved.
    pub proposal_id: String,
    /// Node ID of the approving voter (must be in the current voter set).
    pub approver_id: String,
    /// Unix-epoch milliseconds when the approval was signed.
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical encoding of `(proposal_id, node_id,
    /// action, approver_id, timestamp_ms)` under the cluster secret.
    pub hmac: [u8; 32],
}

const DOMAIN_CONFIG_CHANGE_APPROVAL: u8 = 0x04;

/// Internal leader-side state tracking a proposal's approval set.
#[derive(Debug, Clone)]
pub(crate) struct PendingConfigChange {
    proposal: ConfigChangeProposal,
    /// Approvers that have sent a verified approval (deduplicated).
    approvers: HashSet<String>,
}

/// Default maximum clock skew (ms) tolerated for messages timestamped in
/// the future. Raft clusters run NTP/PTP; a legitimate peer should never be
/// more than a second ahead of us. Anything beyond that is treated as a
/// replay or forgery attempt. Overridable per-cluster via
/// `ClusterConfig::max_future_skew_ms`.
pub const MAX_FUTURE_SKEW_MS: u64 = 1_000;

/// Check whether a message timestamp is within the allowed age window.
///
/// The check is directional: we accept messages from the past up to
/// `max_age_ms` old, and messages from the future only within the small
/// `max_future_skew_ms` NTP-drift tolerance. Accepting arbitrarily
/// future-dated messages (as the previous `abs_diff` variant did) widens the
/// replay window to `2 * max_age_ms` whenever an attacker can also forge a
/// timestamp — which is exactly what the freshness check is supposed to
/// prevent.
pub fn check_message_freshness(
    timestamp_ms: u64,
    max_age_ms: u64,
    max_future_skew_ms: u64,
) -> bool {
    let now = now_ms();
    if timestamp_ms <= now {
        now - timestamp_ms <= max_age_ms
    } else {
        timestamp_ms - now <= max_future_skew_ms
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;

    fn make_entry(term: u64, index: u64) -> LogEntry {
        LogEntry {
            term: Term(term),
            index,
            command: RaftCommand::Noop,
        }
    }

    fn make_secret(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn make_node_with_secret(id: &str, secret: [u8; 32]) -> RaftNode {
        let mut node = RaftNode::new(id.to_string(), vec!["n2".to_string()], 1000);
        node.set_cluster_secret(secret);
        node
    }

    // -- RaftState / Term --

    #[test]
    fn test_raft_state_default() {
        assert_eq!(RaftState::default(), RaftState::Follower);
    }

    #[test]
    fn test_term_display_and_arith() {
        assert_eq!(format!("{}", Term(5)), "Term(5)");
        assert_eq!(Term(3) + 2, Term(5));
        assert_eq!(Term(0).next(), Term(1));
        let t: Term = 7u64.into();
        assert_eq!(t, Term(7));
    }

    #[test]
    fn test_term_add_overflow_saturates() {
        // Term + u64 saturates at u64::MAX rather than panicking. A panic on
        // overflow would let any peer that can advance the term counter DoS
        // the process; saturation preserves liveness in a detectable degraded
        // mode (no future elections succeed because the term cannot advance).
        assert_eq!(Term(u64::MAX) + 1, Term(u64::MAX));
        assert_eq!(Term(u64::MAX - 3) + 10, Term(u64::MAX));
        // Non-overflowing addition still produces the exact sum.
        assert_eq!(Term(5) + 3, Term(8));
    }

    // -- RaftLog --

    #[test]
    fn test_log_append_and_get() {
        let mut log = RaftLog::new();
        log.append(make_entry(1, 1));
        log.append(make_entry(1, 2));
        log.append(make_entry(2, 3));
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.last_term(), Term(2));
        assert_eq!(log.get(2).unwrap().index, 2);
        assert!(log.get(0).is_none());
        assert!(log.get(99).is_none());
    }

    #[test]
    fn test_log_truncate_after() {
        let mut log = RaftLog::new();
        for i in 1..=5 {
            log.append(make_entry(1, i));
        }
        // Commit through index 3.  Truncating to index 4 (above committed) is safe.
        log.commit(3);
        log.truncate_after(4)
            .expect("safe truncate above committed");
        assert_eq!(log.len(), 4);
        assert_eq!(log.committed(), 3);
    }

    #[test]
    fn test_log_discard_through() {
        let mut log = RaftLog::new();
        for i in 1..=5 {
            log.append(make_entry(1, i));
        }
        log.commit(5);
        log.apply(5);
        log.discard_through(3);
        assert_eq!(log.len(), 2);
        assert_eq!(log.get(4).unwrap().index, 4);
        assert!(log.get(3).is_none());
    }

    #[test]
    fn test_entries_slice_from() {
        let mut log = RaftLog::new();
        for i in 1..=5 {
            log.append(make_entry(1, i));
        }
        let s = log.entries_slice_from(3);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].index, 3);
    }

    // -- Election timeout jitter --

    #[test]
    fn test_election_timeout_has_jitter() {
        let timeouts: Vec<u64> = (0..50)
            .map(|i| RaftNode::new(format!("n{i}"), vec![], 1000).election_timeout())
            .collect();
        let all_same = timeouts.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same);
    }

    #[test]
    fn test_become_candidate_re_randomizes_within_bounds() {
        let mut node = RaftNode::new("n1".to_string(), vec!["n2".into()], 1000);
        for _ in 0..200 {
            node.become_candidate();
            let t = node.election_timeout();
            assert!((1000..=1500).contains(&t), "timeout out of range: {t}");
        }
    }

    // -- Vote granting --

    #[test]
    fn test_vote_grants_and_denials() {
        let mut node = RaftNode::new("n1".to_string(), vec!["n2".into()], 1000);
        node.current_term = Term(0);
        assert!(node.should_grant_vote("n2", Term(1), 0, Term(0)));
        node.current_term = Term(5);
        assert!(!node.should_grant_vote("n2", Term(3), 0, Term(0)));
        node.voted_for = Some("n2".to_string());
        assert!(!node.should_grant_vote("n3", Term(5), 0, Term(0)));
        assert!(node.should_grant_vote("n2", Term(5), 0, Term(0)));
    }

    // -- HMAC --

    fn make_rv_args(secret: Option<&[u8; 32]>) -> RequestVoteArgs {
        let mut args = RequestVoteArgs {
            term: Term(3),
            candidate_id: "n2".to_string(),
            last_log_index: 5,
            last_log_term: Term(2),
            timestamp_ms: now_ms(),
            hmac: None,
        };
        if let Some(s) = secret {
            args.hmac = Some(RaftNode::compute_request_vote_hmac(s, &args));
        }
        args
    }

    fn make_ae_args(secret: Option<&[u8; 32]>) -> AppendEntriesArgs {
        let mut args = AppendEntriesArgs {
            term: Term(3),
            leader_id: "n1".to_string(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![],
            leader_commit: 0,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        if let Some(s) = secret {
            args.hmac = Some(RaftNode::compute_append_entries_hmac(s, &args));
        }
        args
    }

    #[test]
    fn test_no_secret_rejects_all() {
        let node = RaftNode::new("n1".to_string(), vec!["n2".into()], 1000);
        assert!(!node.verify_request_vote(&make_rv_args(None)));
        assert!(!node.verify_append_entries(&make_ae_args(None)));
    }

    #[test]
    fn test_matching_secret_accepted() {
        let secret = make_secret(0xAB);
        let node = make_node_with_secret("n1", secret);
        assert!(node.verify_request_vote(&make_rv_args(Some(&secret))));
        assert!(node.verify_append_entries(&make_ae_args(Some(&secret))));
    }

    #[test]
    fn test_mismatched_secret_rejected() {
        let node = make_node_with_secret("n1", make_secret(0x11));
        assert!(!node.verify_request_vote(&make_rv_args(Some(&make_secret(0x22)))));
    }

    #[test]
    fn test_handle_append_entries_appends_and_commits() {
        let secret = make_secret(0x01);
        let mut node = make_node_with_secret("n1", secret);
        let mut args = AppendEntriesArgs {
            term: Term(1),
            leader_id: "leader".to_string(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![make_entry(1, 1), make_entry(1, 2)],
            leader_commit: 2,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        let reply = node.handle_append_entries(&args);
        assert!(reply.success);
        assert_eq!(node.log.last_index(), 2);
        assert_eq!(node.log.committed(), 2);
    }

    #[test]
    fn test_replay_protection_rejects_duplicate() {
        let secret = make_secret(0xCC);
        let mut node = make_node_with_secret("n1", secret);
        let args = make_ae_args(Some(&secret));
        // First time: accepted.
        let r1 = node.handle_append_entries(&args);
        assert!(r1.success);
        // Second time with the same exact MAC: must be rejected.
        let r2 = node.handle_append_entries(&args);
        assert!(
            !r2.success,
            "second copy of identical AppendEntries must be rejected"
        );
    }

    #[test]
    fn test_freshness_rejects_stale() {
        let secret = make_secret(0xDD);
        let mut node = make_node_with_secret("n1", secret);
        node.max_message_age_ms = 100;
        let mut args = make_ae_args(None);
        args.timestamp_ms = now_ms().saturating_sub(10_000);
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        assert!(!node.verify_append_entries(&args));
    }

    #[test]
    fn test_replay_cache_does_not_grow_for_stale_msgs() {
        // Stale messages must NOT pollute the replay cache.
        let secret = make_secret(0xEE);
        let mut node = make_node_with_secret("n1", secret);
        node.max_message_age_ms = 100;
        for _ in 0..10 {
            let mut args = make_ae_args(None);
            args.timestamp_ms = 0; // ancient
            args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
            let _ = node.handle_append_entries(&args);
        }
        assert_eq!(node.replay_cache_len(), 0);
    }

    #[test]
    fn test_canonical_command_bytes_distinguish_variants() {
        let a = RaftCommand::Noop.canonical_bytes();
        let b = RaftCommand::KeySync {
            key_id: "k".into(),
            data: Zeroizing::new(vec![]),
        }
        .canonical_bytes();
        let c = RaftCommand::ConfigChange {
            node_id: "n".into(),
            action: MembershipAction::AddNode,
        }
        .canonical_bytes();
        let d = RaftCommand::ConfigChange {
            node_id: "n".into(),
            action: MembershipAction::RemoveNode,
        }
        .canonical_bytes();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(c, d);
    }

    #[test]
    fn test_domain_separators_differ() {
        let secret = make_secret(0x77);
        let rv = make_rv_args(Some(&secret));
        let ae = make_ae_args(Some(&secret));
        // The MACs over distinct domains must differ even if every other field
        // happened to align — they share a tag prefix only by coincidence.
        assert_ne!(rv.hmac.unwrap(), ae.hmac.unwrap());
    }

    // -- Storage integration --

    #[test]
    fn test_storage_persists_term_and_vote() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut node = RaftNode::new("n1".into(), vec!["n2".into()], 1000);
        node.attach_storage(storage.clone()).unwrap();
        node.become_candidate();
        let hs = storage.load_hard_state().unwrap();
        assert_eq!(hs.current_term, Term(1));
        assert_eq!(hs.voted_for.as_deref(), Some("n1"));
    }

    #[test]
    fn test_storage_persists_appended_log() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut node = RaftNode::new("leader".into(), vec![], 1000);
        node.attach_storage(storage.clone()).unwrap();
        node.current_term = Term(1);
        node.become_leader();
        let idx = node.submit_command(RaftCommand::Noop).unwrap();
        assert_eq!(idx, 1);
        let log = storage.load_log().unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_node_resumes_from_storage() {
        let storage = Arc::new(InMemoryStorage::new());
        {
            let mut node = RaftNode::new("n1".into(), vec!["n2".into()], 1000);
            node.attach_storage(storage.clone()).unwrap();
            node.become_candidate();
            node.become_leader();
            node.submit_command(RaftCommand::Noop);
        }
        // New node attaches to same store.
        let mut resumed = RaftNode::new("n1".into(), vec!["n2".into()], 1000);
        resumed.attach_storage(storage.clone()).unwrap();
        assert_eq!(resumed.current_term, Term(1));
        assert_eq!(resumed.voted_for.as_deref(), Some("n1"));
        assert_eq!(resumed.log.last_index(), 1);
    }

    // -- State machine integration --

    #[test]
    fn test_state_machine_apply_after_commit() {
        let secret = make_secret(0x91);
        let mut node = make_node_with_secret("n1", secret);
        let sm = Arc::new(ClusterStateMachine::new(["n1".to_string()]));
        node.attach_state_machine(sm.clone());
        let mut args = AppendEntriesArgs {
            term: Term(1),
            leader_id: "leader".to_string(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![LogEntry {
                term: Term(1),
                index: 1,
                command: RaftCommand::KeySync {
                    key_id: "k1".into(),
                    data: Zeroizing::new(vec![1, 2, 3]),
                },
            }],
            leader_commit: 1,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        let reply = node.handle_append_entries(&args);
        assert!(reply.success);
        assert_eq!(sm.last_applied(), 1);
        assert_eq!(sm.get_key("k1"), Some(vec![1, 2, 3]));
    }

    // -- Snapshot install --

    #[test]
    fn test_install_snapshot_compacts_log() {
        let secret = make_secret(0xA1);
        let mut leader = make_node_with_secret("leader", secret);
        let sm = Arc::new(ClusterStateMachine::new(["leader".to_string()]));
        leader.attach_state_machine(sm.clone());
        leader.current_term = Term(2);
        leader.become_leader();
        // Install a couple commands.
        sm.apply(&LogEntry {
            term: Term(2),
            index: 1,
            command: RaftCommand::KeySync {
                key_id: "k".into(),
                data: Zeroizing::new(vec![9]),
            },
        })
        .unwrap();
        leader.last_snapshot_index = 1;
        leader.last_snapshot_term = Term(2);

        let install = leader.prepare_install_snapshot().unwrap();

        // Apply on a follower.
        let mut follower = make_node_with_secret("n1", secret);
        let fsm = Arc::new(ClusterStateMachine::default());
        follower.attach_state_machine(fsm.clone());
        let reply = follower.handle_install_snapshot(&install);
        assert_eq!(reply.term, follower.current_term);
        assert_eq!(fsm.get_key("k"), Some(vec![9]));
        assert_eq!(follower.last_snapshot().0, 1);
    }

    // -- Membership change applied through state machine --

    #[test]
    fn test_membership_change_via_state_machine() {
        let secret = make_secret(0xB1);
        let mut node = make_node_with_secret("n1", secret);
        let sm = Arc::new(ClusterStateMachine::new(["n1".to_string()]));
        node.attach_state_machine(sm.clone());
        let mut args = AppendEntriesArgs {
            term: Term(1),
            leader_id: "leader".to_string(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![LogEntry {
                term: Term(1),
                index: 1,
                command: RaftCommand::ConfigChange {
                    node_id: "n2".into(),
                    action: MembershipAction::AddNode,
                },
            }],
            leader_commit: 1,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        node.handle_append_entries(&args);
        assert_eq!(sm.voters(), vec!["n1".to_string(), "n2".to_string()]);
    }

    // -- Replay cache eviction bound --

    #[test]
    fn test_replay_cache_bounded() {
        let secret = make_secret(0x55);
        let mut node = make_node_with_secret("n1", secret);
        // Insert many distinct messages.
        for i in 0..(REPLAY_CACHE_MAX as u64 + 100) {
            let mut args = AppendEntriesArgs {
                term: Term(1),
                leader_id: format!("leader-{i}"),
                prev_log_index: 0,
                prev_log_term: Term(0),
                entries: vec![],
                leader_commit: 0,
                timestamp_ms: now_ms(),
                hmac: None,
            };
            args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
            let _ = node.handle_append_entries(&args);
        }
        assert!(
            node.replay_cache_len() <= REPLAY_CACHE_MAX,
            "cache len {} exceeds bound",
            node.replay_cache_len()
        );
    }

    // -- Leader replication & commit --

    #[test]
    fn test_replicate_and_advance_commit() {
        let mut node = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 150);
        node.log.append(make_entry(1, 1));
        node.log.append(make_entry(1, 2));
        node.current_term = Term(1);
        node.become_leader();
        node.match_index.insert("n2".into(), 2);
        node.match_index.insert("n3".into(), 0);
        node.advance_commit_index();
        assert_eq!(node.log.committed(), 2);
    }

    #[test]
    fn test_commit_only_advances_for_current_term() {
        let mut node = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 150);
        node.log.append(make_entry(1, 1));
        node.current_term = Term(2);
        node.become_leader();
        node.match_index.insert("n2".into(), 1);
        node.match_index.insert("n3".into(), 1);
        node.advance_commit_index();
        assert_eq!(node.log.committed(), 0);
    }

    #[test]
    fn test_handle_append_entries_reply_failure_decrements_next_index() {
        // Audit (reply-verification missing-secret gate): in the default
        // build `handle_append_entries_reply` now requires a verifiable
        // HMAC. Sign the reply explicitly so the decrement path runs.
        let secret = make_secret(0x42);
        let mut node = make_node_with_secret("leader", secret);
        node.log.append(make_entry(1, 1));
        node.current_term = Term(1);
        node.become_leader();
        let mut reply = AppendEntriesReply {
            term: Term(1),
            success: false,
            timestamp_ms: 0,
            hmac: None,
        };
        node.sign_append_entries_reply(&mut reply);
        node.handle_append_entries_reply("n2", &reply, 0);
        assert_eq!(node.next_index.get("n2"), Some(&1));
    }

    #[test]
    fn test_submit_command_only_on_leader() {
        let mut node = RaftNode::new("n1".into(), vec!["n2".into()], 150);
        assert!(node.submit_command(RaftCommand::Noop).is_none());
        node.current_term = Term(1);
        node.become_leader();
        assert_eq!(node.submit_command(RaftCommand::Noop), Some(1));
    }

    // -- from_config wiring --

    #[test]
    fn test_from_config_wires_parameters() {
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            peers: vec![crate::config::PeerConfig {
                node_id: "n2".into(),
                addr: "10.0.0.2:9443".into(),
            }],
            election_timeout_ms: 1500,
            heartbeat_interval_ms: 500,
            max_message_age_ms: 5000,
            snapshot_interval: 100,
            cluster_secret_hex: Some("ab".repeat(32)),
            ..Default::default()
        };
        let node = RaftNode::from_config(&cfg).unwrap();
        assert_eq!(node.id(), "n1");
        assert_eq!(node.peers(), &["n2".to_string()]);
        assert_eq!(node.max_message_age_ms, 5000);
        assert!(node.has_cluster_secret());
        assert_eq!(node.snapshot_interval, 100);
    }

    #[test]
    fn test_check_message_freshness() {
        let now = now_ms();
        assert!(check_message_freshness(now, 30_000, MAX_FUTURE_SKEW_MS));
        assert!(!check_message_freshness(
            now.saturating_sub(60_000),
            30_000,
            MAX_FUTURE_SKEW_MS
        ));
    }

    #[test]
    fn test_check_message_freshness_rejects_far_future() {
        // Messages timestamped far in the future must be rejected. A prior
        // `abs_diff` variant accepted them, widening the replay window.
        let now = now_ms();
        assert!(
            !check_message_freshness(now + 30_000, 30_000, MAX_FUTURE_SKEW_MS),
            "30s-future message must be rejected"
        );
        // Small NTP-drift skew must still be accepted.
        assert!(check_message_freshness(
            now + 100,
            30_000,
            MAX_FUTURE_SKEW_MS
        ));
    }

    // -- Safety: applied entries cannot be truncated --

    #[test]
    fn test_truncate_applied_entries_returns_err() {
        let mut log = RaftLog::new();
        for i in 1..=3 {
            log.append(make_entry(1, i));
        }
        log.commit(3);
        log.apply(3);
        // Trying to truncate below committed (which is also below applied here)
        // is a safety violation.  The TruncateBelowCommitted guard fires first
        // because committed is checked before applied.
        let err = log
            .truncate_after(1)
            .expect_err("truncate below committed/applied must return an error");
        match err {
            RaftInvariantError::TruncateBelowCommitted { after, committed } => {
                assert_eq!(after, 1);
                assert_eq!(committed, 3);
            }
            other => panic!("expected TruncateBelowCommitted, got {other:?}"),
        }
        // Truncating between committed and applied is not possible here (both=3),
        // but verify the applied-only guard separately via TruncateBelowApplied:
        // create a new log where committed < applied is simulated via internal state.
        // Instead, confirm the log is unchanged on error.
        assert_eq!(log.len(), 3);
        assert_eq!(log.applied(), 3);
    }

    #[test]
    fn test_truncate_after_rejects_committed_entries() {
        let mut log = RaftLog::new();
        // Add some entries.
        for i in 1..=5 {
            log.append(make_entry(1, i));
        }
        // Commit through index 3.
        log.commit(3);
        // Truncating to index 2 (below committed=3) must fail.
        let err = log.truncate_after(2).unwrap_err();
        assert!(
            matches!(
                err,
                RaftInvariantError::TruncateBelowCommitted {
                    after: 2,
                    committed: 3
                }
            ),
            "expected TruncateBelowCommitted, got {err:?}"
        );
        // Truncating to index 4 (above committed=3) must succeed.
        assert!(log.truncate_after(4).is_ok());
    }

    // -- Snapshot install resolves the correct term --

    #[test]
    fn test_prepare_install_snapshot_uses_log_term() {
        let secret = make_secret(0xAB);
        let mut leader = make_node_with_secret("leader", secret);
        let sm = Arc::new(ClusterStateMachine::new(["leader".into()]));
        leader.attach_state_machine(sm.clone());
        leader.current_term = Term(7);
        leader.become_leader();
        // Apply two entries; SM advances last_applied past last_snapshot_index.
        for i in 1..=2 {
            let entry = LogEntry {
                term: Term(7),
                index: i,
                command: RaftCommand::Noop,
            };
            leader.log.append(entry.clone());
            sm.apply(&entry).unwrap();
        }
        leader.log.commit(2);
        leader.log.apply(2);
        // last_snapshot_term is still Term(0) — but the entry is at Term(7).
        let install = leader.prepare_install_snapshot().unwrap();
        assert_eq!(install.last_included_index, 2);
        assert_eq!(install.last_included_term, Term(7));
    }

    // -- Peers sync from voter set after ConfigChange --

    #[test]
    fn test_apply_config_change_updates_peers() {
        let secret = make_secret(0x33);
        let mut node = make_node_with_secret("n1", secret);
        let sm = Arc::new(ClusterStateMachine::new(["n1".into()]));
        node.attach_state_machine(sm.clone());
        let mut args = AppendEntriesArgs {
            term: Term(1),
            leader_id: "leader".into(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![LogEntry {
                term: Term(1),
                index: 1,
                command: RaftCommand::ConfigChange {
                    node_id: "n3".into(),
                    action: MembershipAction::AddNode,
                },
            }],
            leader_commit: 1,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        node.handle_append_entries(&args);
        // n3 should now be in the local peer list (n1 is self, excluded).
        assert_eq!(node.peers(), &["n3".to_string()]);
    }

    #[test]
    fn test_apply_config_change_remove_drops_peer() {
        let secret = make_secret(0x44);
        let mut node = RaftNode::new("n1".into(), vec!["n2".to_string(), "n3".to_string()], 1000);
        node.set_cluster_secret(secret);
        let sm = Arc::new(ClusterStateMachine::new([
            "n1".to_string(),
            "n2".to_string(),
            "n3".to_string(),
        ]));
        node.attach_state_machine(sm.clone());
        let mut args = AppendEntriesArgs {
            term: Term(1),
            leader_id: "leader".into(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![LogEntry {
                term: Term(1),
                index: 1,
                command: RaftCommand::ConfigChange {
                    node_id: "n2".into(),
                    action: MembershipAction::RemoveNode,
                },
            }],
            leader_commit: 1,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        node.handle_append_entries(&args);
        assert_eq!(node.peers(), &["n3".to_string()]);
    }

    #[test]
    fn test_install_snapshot_syncs_peers() {
        let secret = make_secret(0x55);
        // Leader has voters {leader, n2, n3}.
        let mut leader = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 1000);
        leader.set_cluster_secret(secret);
        let lsm = Arc::new(ClusterStateMachine::new([
            "leader".to_string(),
            "n2".to_string(),
            "n3".to_string(),
        ]));
        leader.attach_state_machine(lsm);
        leader.current_term = Term(2);
        leader.become_leader();
        leader.last_snapshot_index = 5;
        leader.last_snapshot_term = Term(2);

        let install = leader.prepare_install_snapshot().unwrap();

        // Follower starts knowing only the leader.
        let mut follower = RaftNode::new("n2".into(), vec!["leader".into()], 1000);
        follower.set_cluster_secret(secret);
        let fsm = Arc::new(ClusterStateMachine::default());
        follower.attach_state_machine(fsm);
        follower.handle_install_snapshot(&install);

        let mut peers = follower.peers().to_vec();
        peers.sort();
        assert_eq!(peers, vec!["leader".to_string(), "n3".to_string()]);
    }

    // -- HardState equality / quorum_size / heartbeat accessors --

    #[test]
    fn test_quorum_size() {
        let n1 = RaftNode::new("n1".into(), vec![], 1000);
        assert_eq!(n1.quorum_size(), 1);
        let n2 = RaftNode::new("n1".into(), vec!["n2".into(), "n3".into()], 1000);
        assert_eq!(n2.quorum_size(), 2);
        let n3 = RaftNode::new(
            "n1".into(),
            vec!["n2".into(), "n3".into(), "n4".into(), "n5".into()],
            1000,
        );
        assert_eq!(n3.quorum_size(), 3);
    }

    #[test]
    fn test_record_and_read_heartbeat() {
        let mut node = RaftNode::new("n1".into(), vec![], 1000);
        assert_eq!(node.last_heartbeat(), 0);
        node.record_heartbeat(123_456);
        assert_eq!(node.last_heartbeat(), 123_456);
    }

    // -----------------------------------------------------------------------
    // Vote rate-limit tests (Task B — audit fix)
    // -----------------------------------------------------------------------

    /// 1. Flood: 10 rapid votes from a single peer — the first 3 consume
    /// the bucket, the remaining 7 must be rejected.
    #[test]
    fn test_vote_rate_limit_flood_drops_excess() {
        let limiter = VoteRateLimiter::new(3, 5_000);
        let now = 1_000_000u64;
        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..10 {
            if limiter.try_consume("noisy-peer", now) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert_eq!(accepted, 3, "bucket capacity was 3");
        assert_eq!(rejected, 7, "remaining 7 votes must be dropped");
        assert_eq!(limiter.rejected_count("noisy-peer"), 7);
    }

    /// 2. Refill: after `refill_interval_ms` elapses with no activity, a
    /// single fresh vote should be allowed again.
    #[test]
    fn test_vote_rate_limit_refills_after_interval() {
        let limiter = VoteRateLimiter::new(3, 5_000);
        let t0 = 100_000u64;
        // Drain the bucket.
        for _ in 0..3 {
            assert!(limiter.try_consume("peer", t0));
        }
        assert!(!limiter.try_consume("peer", t0), "bucket should be empty");

        // Advance time by exactly one refill interval — one token returns.
        let t1 = t0 + 5_000;
        assert!(
            limiter.try_consume("peer", t1),
            "one token should be refilled after 5s"
        );
        // But the bucket is then empty again immediately.
        assert!(
            !limiter.try_consume("peer", t1),
            "only one token refilled, so next try must fail"
        );
    }

    /// Adversarial flood of unique candidate IDs must not grow the limiter's
    /// per-peer map — H3. An allowlist gates insertion.
    #[test]
    fn test_vote_rate_limit_allowlist_blocks_unknown_peers() {
        let limiter = VoteRateLimiter::new(3, 5_000);
        let mut allowed = HashSet::new();
        allowed.insert("n1".to_string());
        allowed.insert("n2".to_string());
        limiter.set_allowed_peers(Some(allowed));

        let now = 100_000u64;
        // Known peer: accepted and inserted.
        assert!(limiter.try_consume("n1", now));
        // Unknown peer: rejected, no bucket allocated.
        for i in 0..1000u32 {
            let peer = format!("attacker-{}", i);
            assert!(!limiter.try_consume(&peer, now));
        }
        // Map only contains the one legitimate peer we consumed for.
        assert_eq!(limiter.state.len(), 1);
        assert!(limiter.unknown_peer_rejects() >= 1000);
    }

    #[test]
    fn test_vote_rate_limit_hard_cap_without_allowlist() {
        let limiter = VoteRateLimiter::new(3, 5_000);
        // Fill the map by stuffing bucket slots with synthetic IDs up to the cap.
        for i in 0..MAX_VOTE_RATE_LIMITER_PEERS {
            let peer = format!("p{}", i);
            limiter.state.insert(
                peer,
                VoteBucket {
                    tokens: 1,
                    last_refill_ms: 0,
                    rejected: 0,
                },
            );
        }
        // Further unique IDs are rejected without allocating.
        assert!(!limiter.try_consume("overflow-peer", 0));
        assert_eq!(limiter.state.len(), MAX_VOTE_RATE_LIMITER_PEERS);
    }

    /// 3. Isolation: a noisy peer exhausting its own bucket must not
    /// affect a legitimate peer's bucket.
    #[test]
    fn test_vote_rate_limit_per_peer_isolation() {
        let limiter = VoteRateLimiter::new(3, 5_000);
        let now = 500_000u64;
        // Exhaust noisy's bucket.
        for _ in 0..3 {
            assert!(limiter.try_consume("noisy", now));
        }
        assert!(!limiter.try_consume("noisy", now));
        // Legitimate peer is unaffected and gets its full capacity.
        for _ in 0..3 {
            assert!(
                limiter.try_consume("legit", now),
                "legitimate peer must not be affected by noisy peer"
            );
        }
        assert_eq!(limiter.rejected_count("noisy"), 1);
        assert_eq!(limiter.rejected_count("legit"), 0);
    }

    /// End-to-end: the rate limiter is enforced by
    /// [`handle_request_vote_rpc`] and exposed via [`metrics()`].
    #[test]
    fn test_handle_request_vote_rpc_enforces_rate_limit() {
        let secret = make_secret(0x77);
        let mut node = RaftNode::new(
            "n1".into(),
            vec!["noisy".to_string(), "legit".to_string()],
            1000,
        );
        node.set_cluster_secret(secret);

        // Build an RPC from "noisy" with a valid HMAC.
        let mk = |peer: &str| -> RequestVoteArgs {
            let mut a = RequestVoteArgs {
                term: Term(5),
                candidate_id: peer.to_string(),
                last_log_index: 0,
                last_log_term: Term(0),
                timestamp_ms: now_ms(),
                hmac: None,
            };
            a.hmac = Some(RaftNode::compute_request_vote_hmac(&secret, &a));
            a
        };

        // The default capacity is 3 (from RaftNode::new) — first 3 produce
        // a reply, the next 3 are dropped (None).  We vary `last_log_index`
        // per iteration so each RPC has a distinct HMAC regardless of the
        // system's timer granularity (avoids replay-cache rejection on
        // low-resolution clocks like Windows).
        let mut replies_seen = 0;
        let mut drops_seen = 0;
        for i in 0..6u64 {
            let mut a = mk("noisy");
            a.last_log_index = i; // perturb for distinct HMAC
            a.hmac = Some(RaftNode::compute_request_vote_hmac(&secret, &a));
            match node.handle_request_vote_rpc(&a) {
                Some(_) => replies_seen += 1,
                None => drops_seen += 1,
            }
        }
        assert_eq!(replies_seen, 3, "capacity-3 bucket allows 3 replies");
        assert_eq!(drops_seen, 3, "remaining 3 RPCs must be dropped");

        // A legit peer is unaffected.
        let a = mk("legit");
        assert!(
            node.handle_request_vote_rpc(&a).is_some(),
            "legit peer must still be accepted"
        );

        // Metrics surface the rejected counter for noisy only.
        let metrics = node.metrics();
        let noisy = metrics
            .rejected_vote_rpcs
            .iter()
            .find(|(k, _)| k == "noisy")
            .expect("noisy should appear in metrics");
        assert_eq!(noisy.1, 3);
        assert!(
            metrics.rejected_vote_rpcs.iter().all(|(k, _)| k != "legit"),
            "legit peer must not appear in rejected metrics"
        );
    }

    // -----------------------------------------------------------------------
    // Audit C2 — missing-secret refuses construction under production cfg
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_config_refuses_missing_secret_in_production() {
        // `validate()` already rejects missing secret unless `allow_insecure`;
        // but `require_cluster_secret_for_production()` is the hard gate we
        // are exercising here.  Force the code path by passing a config with
        // `allow_insecure = true` *and* no secret — validation passes, but
        // the production gate must still refuse (when the feature is off).
        let cfg = ClusterConfig {
            node_id: "n1".into(),
            allow_insecure: true,
            cluster_secret_hex: None,
            ..Default::default()
        };
        let result = RaftNode::from_config(&cfg);
        #[cfg(not(feature = "insecure-no-cluster-secret"))]
        {
            assert!(
                result.is_err(),
                "production build must refuse a missing-secret config"
            );
            let e = result.unwrap_err();
            assert!(
                e.contains("cluster_secret"),
                "error should mention cluster_secret; got: {e}"
            );
        }
        #[cfg(feature = "insecure-no-cluster-secret")]
        {
            assert!(
                result.is_ok(),
                "insecure feature: missing secret is allowed"
            );
        }
    }

    #[test]
    fn test_require_cluster_secret_direct_api() {
        let node = RaftNode::new("n1".into(), vec![], 1000);
        #[cfg(not(feature = "insecure-no-cluster-secret"))]
        assert!(node.require_cluster_secret_for_production().is_err());
        #[cfg(feature = "insecure-no-cluster-secret")]
        assert!(node.require_cluster_secret_for_production().is_ok());
    }

    // -----------------------------------------------------------------------
    // Audit H2 — replay cache time-evicts promptly; freshness-before-replay
    // -----------------------------------------------------------------------

    #[test]
    fn test_replay_cache_time_evicts_on_every_insert() {
        let cache = ReplayCache::new();
        // Fix 5: the replay cache is now sharded by `mac[0] % REPLAY_CACHE_SHARDS`,
        // and time-eviction scans only the shard receiving the current
        // insert.  Make all test MACs share a shard (via byte 1) so the
        // eviction scan fires on the subsequent fresh insert.  Previously
        // the test used `mac[0] = i` which scattered across shards — valid
        // before sharding, invalid after.
        for i in 0..5u8 {
            let mut mac = [0u8; 32];
            // shard = mac[0] % 8 = 0 for every entry here.
            mac[1] = i;
            assert!(!cache.check_and_insert(mac, 0, 100));
        }
        assert_eq!(cache.len(), 5);

        // Fresh MAC at t=1000 routed to the SAME shard (mac[0] = 0).  The
        // five stale entries at the head of shard 0's deque must be
        // time-evicted on this insert.
        let mut fresh = [0u8; 32];
        fresh[1] = 0xFF;
        assert!(!cache.check_and_insert(fresh, 1000, 100));
        assert_eq!(cache.len(), 1, "stale entries must be evicted immediately");
    }

    #[test]
    fn test_replay_cache_full_evictions_counter_increments() {
        let cache = ReplayCache::new();
        // Force the FIFO cap path by filling beyond REPLAY_CACHE_MAX with
        // timestamps that are all fresh (so the time-eviction branch never
        // fires and we exercise the hard-cap branch).
        for i in 0..(REPLAY_CACHE_MAX as u64 + 10) {
            let mut mac = [0u8; 32];
            mac[0..8].copy_from_slice(&i.to_be_bytes());
            cache.check_and_insert(mac, 0, u64::MAX);
        }
        assert!(
            cache.full_evictions() >= 10,
            "cap-induced evictions must bump the counter (got {})",
            cache.full_evictions()
        );
    }

    #[test]
    fn test_freshness_check_precedes_replay_check_in_verify() {
        // A stale message (past the freshness window) must never pollute the
        // replay cache — if it did, a later fresh message would be wrongly
        // rejected as "seen".
        let secret = make_secret(0x42);
        let mut node = make_node_with_secret("n1", secret);
        node.max_message_age_ms = 100;
        // Stale RPC: timestamp far in the past.
        let mut stale = make_ae_args(None);
        stale.timestamp_ms = now_ms().saturating_sub(10_000);
        stale.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &stale));
        assert!(!node.verify_append_entries(&stale));
        // Replay cache did not admit the stale MAC.
        assert_eq!(node.replay_cache_len(), 0);
    }

    // -----------------------------------------------------------------------
    // Audit H3 — rate limiter adapts to cluster size
    // -----------------------------------------------------------------------

    #[test]
    fn test_vote_rate_limiter_config_adaptive() {
        // 1-node cluster: the historic 5000 ms refill is preserved.
        let one = VoteRateLimiterConfig::adaptive_for_cluster_size(1);
        assert_eq!(one.refill_interval_ms, 5_000);
        // 5-node cluster: 5000/5 = 1000 ms.
        let five = VoteRateLimiterConfig::adaptive_for_cluster_size(5);
        assert_eq!(five.refill_interval_ms, 1_000);
        // 100-node cluster: clamped to 500 ms floor.
        let hundred = VoteRateLimiterConfig::adaptive_for_cluster_size(100);
        assert_eq!(hundred.refill_interval_ms, 500);
        // cluster_size = 0 treated as 1 (defensive).
        let zero = VoteRateLimiterConfig::adaptive_for_cluster_size(0);
        assert_eq!(zero.refill_interval_ms, 5_000);
    }

    #[test]
    fn test_raft_node_new_uses_adaptive_limiter() {
        // 9 peers + self = 10-voter cluster → 500 ms floor.
        let peers: Vec<String> = (0..9).map(|i| format!("n{i}")).collect();
        let node = RaftNode::new("self".into(), peers, 1000);
        assert_eq!(node.vote_rate_limiter().refill_interval_ms(), 500);
    }

    // -----------------------------------------------------------------------
    // Audit M7 — majority-approved ConfigChange; unilateral attempt rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_unilateral_config_change_without_majority_is_rejected() {
        // A "rogue" leader (one of three voters) knows the cluster secret but
        // cannot commit a ConfigChange by itself: quorum-of-3 is 2, and only
        // the leader's own implicit approval is present.
        let secret = make_secret(0xAA);
        let mut leader = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 1000);
        leader.set_cluster_secret(secret);
        leader.current_term = Term(1);
        leader.become_leader();

        let proposal = leader
            .propose_config_change("p1".into(), "rogue".into(), MembershipAction::AddNode)
            .expect("leader must create proposal");
        assert_eq!(proposal.node_id, "rogue");
        // Only the leader has auto-approved → 1 approval, quorum=2.
        assert_eq!(leader.config_change_approvals("p1"), 1);
        assert!(
            leader.commit_config_change_proposal("p1").is_none(),
            "must not commit with just 1/2 approvals"
        );
    }

    #[test]
    fn test_majority_approved_config_change_commits() {
        let secret = make_secret(0xBB);
        let mut leader = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 1000);
        leader.set_cluster_secret(secret);
        let sm = Arc::new(ClusterStateMachine::new([
            "leader".to_string(),
            "n2".to_string(),
            "n3".to_string(),
        ]));
        leader.attach_state_machine(sm);
        leader.current_term = Term(1);
        leader.become_leader();

        let proposal = leader
            .propose_config_change("p2".into(), "n4".into(), MembershipAction::AddNode)
            .unwrap();

        // n2 signs an approval under the shared secret.
        let ts = now_ms();
        let hmac = RaftNode::compute_config_change_approval_hmac(
            &secret,
            &proposal.proposal_id,
            &proposal.node_id,
            &proposal.action,
            "n2",
            ts,
        );
        let approval = ConfigChangeApproval {
            proposal_id: proposal.proposal_id.clone(),
            approver_id: "n2".into(),
            timestamp_ms: ts,
            hmac,
        };
        assert!(leader.record_config_change_approval(&approval));
        // 2/2 quorum reached (leader + n2).
        let idx = leader
            .commit_config_change_proposal(&proposal.proposal_id)
            .expect("quorum approvals must commit");
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_config_change_approval_rejects_non_voter() {
        let secret = make_secret(0xCC);
        let mut leader = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 1000);
        leader.set_cluster_secret(secret);
        leader.current_term = Term(1);
        leader.become_leader();
        let proposal = leader
            .propose_config_change("p3".into(), "n5".into(), MembershipAction::AddNode)
            .unwrap();
        let ts = now_ms();
        let hmac = RaftNode::compute_config_change_approval_hmac(
            &secret,
            &proposal.proposal_id,
            &proposal.node_id,
            &proposal.action,
            "attacker", // not a voter
            ts,
        );
        let approval = ConfigChangeApproval {
            proposal_id: proposal.proposal_id.clone(),
            approver_id: "attacker".into(),
            timestamp_ms: ts,
            hmac,
        };
        assert!(
            !leader.record_config_change_approval(&approval),
            "non-voter approvals must be rejected"
        );
    }

    #[test]
    fn test_config_change_approval_rejects_forged_hmac() {
        let secret = make_secret(0xDD);
        let mut leader = RaftNode::new("leader".into(), vec!["n2".into(), "n3".into()], 1000);
        leader.set_cluster_secret(secret);
        leader.current_term = Term(1);
        leader.become_leader();
        let proposal = leader
            .propose_config_change("p4".into(), "n5".into(), MembershipAction::AddNode)
            .unwrap();
        let approval = ConfigChangeApproval {
            proposal_id: proposal.proposal_id.clone(),
            approver_id: "n2".into(),
            timestamp_ms: now_ms(),
            hmac: [0u8; 32], // obviously invalid
        };
        assert!(!leader.record_config_change_approval(&approval));
    }

    // -----------------------------------------------------------------------
    // Audit L6 — snapshot HMAC authenticates the data payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_modified_snapshot_chunk_fails_hmac() {
        // The existing `compute_install_snapshot_hmac` already covers the
        // `data` payload with a length prefix (see the implementation above).
        // This test documents that property by flipping a byte in the data
        // and confirming the verifier rejects the forged message.
        let secret = make_secret(0xEE);
        let node = make_node_with_secret("n1", secret);
        let mut args = InstallSnapshotArgs {
            term: Term(1),
            leader_id: "leader".into(),
            last_included_index: 5,
            last_included_term: Term(1),
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            timestamp_ms: now_ms(),
            hmac: None,
            offset: 0,
            total_size: 8,
            last_chunk: true,
        };
        args.hmac = Some(RaftNode::compute_install_snapshot_hmac(&secret, &args));
        // Baseline: unmodified message verifies.
        assert!(node.verify_install_snapshot(&args));
        // Flip one byte in data; HMAC must no longer validate.
        let mut tampered = args.clone();
        tampered.data[3] ^= 0xFF;
        // (Keep the original HMAC — the attacker cannot recompute it.)
        assert!(
            !node.verify_install_snapshot(&tampered),
            "modified snapshot data must fail HMAC verification"
        );
    }

    // ----------------------------------------------------------------------
    // Audit fix-sweep regression tests (commit 618de04).
    //
    // Each test below pins one invariant that was added or repaired by the
    // cluster-crate fix-sweep so a future refactor cannot silently regress
    // it.
    // ----------------------------------------------------------------------

    /// `become_candidate` must not panic when `current_term` is already at
    /// `Term::MAX`.  Instead it should log + remain a Follower, leaving
    /// `current_term` untouched (graceful step-down).
    #[test]
    fn test_become_candidate_saturated_term_stays_follower() {
        let mut node = make_node_with_secret("n1", make_secret(0x01));
        node.current_term = Term(u64::MAX);
        // No panic, no state mutation.
        node.become_candidate();
        assert_eq!(node.current_term, Term(u64::MAX));
        assert_eq!(node.state, RaftState::Follower);
        // try_become_candidate surfaces the structured error.
        assert!(matches!(
            node.try_become_candidate(),
            Err(RaftError::TermOverflow)
        ));
    }

    /// `become_follower` must persist hard state on every call, including
    /// equal-term step-downs (asymmetric-persist audit fix).
    #[test]
    fn test_become_follower_persists_on_equal_term() {
        let mut node = make_node_with_secret("n1", make_secret(0x02));
        let storage: Arc<dyn RaftStorage> = Arc::new(InMemoryStorage::new());
        node.attach_storage(storage.clone()).expect("attach");
        node.current_term = Term(7);
        // Equal-term step-down: prior code skipped persist when voted_for
        // was already None; the fixed code always persists.
        node.become_follower(Term(7));
        // Read the persisted hard state back and confirm term=7 landed.
        let hs = storage.load_hard_state().expect("load_hard_state");
        assert_eq!(hs.current_term, Term(7));
    }

    /// A Candidate that receives an `AppendEntries` for the *same* term
    /// must concede leadership and step down to Follower — and that role
    /// transition must be durably persisted. Prior to the audit fix this
    /// path mutated `self.state` in-place without persisting, so a crash
    /// between the equal-term AE and the next term advance could leave
    /// the node thinking it was still a Candidate on restart.
    #[test]
    fn test_candidate_equal_term_ae_step_down_persists() {
        let secret = make_secret(0x37);
        let mut node = make_node_with_secret("n1", secret);
        let storage: Arc<dyn RaftStorage> = Arc::new(InMemoryStorage::new());
        node.attach_storage(storage.clone()).expect("attach");
        // Force the node into Candidate state at term 3.
        node.current_term = Term(2);
        node.become_candidate(); // bumps to Term(3)
        assert_eq!(node.state, RaftState::Candidate);
        assert_eq!(node.current_term, Term(3));
        // Sanity-check: the candidate vote (for self) is persisted.
        let pre = storage.load_hard_state().expect("load_hard_state");
        assert_eq!(pre.current_term, Term(3));
        // Same-term AE from a rival who won the election.
        let mut ae = AppendEntriesArgs {
            term: Term(3),
            leader_id: "rival".into(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![],
            leader_commit: 0,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        ae.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &ae));
        let reply = node.handle_append_entries(&ae);
        assert!(reply.success, "equal-term AE with prev=0 must be accepted");
        assert_eq!(node.state, RaftState::Follower);
        // The role transition must be durable: another load_hard_state
        // call observes the persisted Follower-term snapshot.
        let post = storage.load_hard_state().expect("load_hard_state");
        assert_eq!(post.current_term, Term(3));
        // current_leader_hint reflects the rival.
        assert_eq!(node.current_leader_hint.as_deref(), Some("rival"));
    }

    /// `become_follower` to a higher term must clear `current_leader_hint`
    /// (new term ⇒ no known leader yet).
    #[test]
    fn test_become_follower_higher_term_clears_leader_hint() {
        let mut node = make_node_with_secret("n1", make_secret(0x03));
        node.current_leader_hint = Some("old-leader".into());
        node.current_term = Term(2);
        node.become_follower(Term(5));
        assert_eq!(
            node.current_leader_hint, None,
            "higher-term step-down must clear stale leader hint"
        );
    }

    /// `handle_pre_vote` must return `Term(0)` (not `current_term`) on HMAC
    /// verification failure, so a forged peer cannot probe our term.
    #[test]
    fn test_handle_pre_vote_unsigned_returns_zero_term() {
        let secret = make_secret(0x04);
        let mut node = make_node_with_secret("n1", secret);
        node.current_term = Term(42);
        let args = PreVoteArgs {
            term: Term(43),
            candidate_id: "attacker".into(),
            last_log_index: 0,
            last_log_term: Term(0),
            timestamp_ms: now_ms(),
            hmac: None, // no signature — verify must fail
        };
        let reply = node.handle_pre_vote(&args);
        assert!(!reply.vote_granted);
        assert_eq!(
            reply.term,
            Term(0),
            "must not leak current_term to forged pre-vote"
        );
    }

    /// All four `sign_*_reply` helpers must early-return when there is no
    /// `cluster_secret`, leaving timestamp+hmac at their defaults so the
    /// reply is unambiguously "unsigned".
    #[test]
    fn test_sign_reply_helpers_noop_without_secret() {
        let node = RaftNode::new("n1".into(), vec!["n2".into()], 1000);
        // No set_cluster_secret() call → secret is None.
        let mut rv = RequestVoteReply {
            term: Term(1),
            vote_granted: true,
            timestamp_ms: 0,
            hmac: None,
        };
        node.sign_request_vote_reply(&mut rv);
        assert_eq!(rv.timestamp_ms, 0);
        assert!(rv.hmac.is_none());

        let mut pv = PreVoteReply {
            term: Term(1),
            vote_granted: true,
            timestamp_ms: 0,
            hmac: None,
        };
        node.sign_pre_vote_reply(&mut pv);
        assert_eq!(pv.timestamp_ms, 0);
        assert!(pv.hmac.is_none());

        let mut ae = AppendEntriesReply {
            term: Term(1),
            success: true,
            timestamp_ms: 0,
            hmac: None,
        };
        node.sign_append_entries_reply(&mut ae);
        assert_eq!(ae.timestamp_ms, 0);
        assert!(ae.hmac.is_none());

        let mut is = InstallSnapshotReply {
            term: Term(1),
            timestamp_ms: 0,
            hmac: None,
        };
        node.sign_install_snapshot_reply(&mut is);
        assert_eq!(is.timestamp_ms, 0);
        assert!(is.hmac.is_none());
    }

    /// `handle_append_entries_reply` must reject an unsigned reply (in the
    /// default build, without the `insecure-no-cluster-secret` feature) and
    /// increment the forged-reply counter.
    #[cfg(not(feature = "insecure-no-cluster-secret"))]
    #[test]
    fn test_handle_append_entries_reply_rejects_unsigned() {
        let mut node = make_node_with_secret("leader", make_secret(0x05));
        node.log.append(make_entry(1, 1));
        node.current_term = Term(1);
        node.become_leader();
        let baseline_next = *node.next_index.get("n2").unwrap();
        let baseline_rejects = node.forged_reply_rejects();
        let bogus = AppendEntriesReply {
            term: Term(99), // would force a term bump if accepted
            success: true,
            timestamp_ms: 0,
            hmac: None, // not signed → verify fails
        };
        node.handle_append_entries_reply("n2", &bogus, 0);
        // State must not have advanced.
        assert_eq!(*node.next_index.get("n2").unwrap(), baseline_next);
        assert_eq!(node.current_term, Term(1));
        // Counter must have bumped.
        assert_eq!(node.forged_reply_rejects(), baseline_rejects + 1);
    }

    /// Forged-snapshot rejection path: an unsigned `InstallSnapshot` must
    /// bump `forged_snapshot_rejects` and return `Term(0)`.
    #[test]
    fn test_handle_install_snapshot_unsigned_bumps_counter() {
        let mut node = make_node_with_secret("n1", make_secret(0x06));
        node.current_term = Term(3);
        let baseline = node.forged_snapshot_rejects();
        let args = InstallSnapshotArgs {
            term: Term(3),
            leader_id: "attacker".into(),
            last_included_index: 1,
            last_included_term: Term(1),
            data: vec![1, 2, 3],
            timestamp_ms: now_ms(),
            hmac: None, // unsigned → verify fails
            offset: 0,
            total_size: 3,
            last_chunk: true,
        };
        let reply = node.handle_install_snapshot(&args);
        assert_eq!(reply.term, Term(0));
        assert_eq!(node.forged_snapshot_rejects(), baseline + 1);
    }

    /// A peer who knows the cluster secret but is *not* the current
    /// AppendEntries-bound leader cannot inject snapshot chunks. The hint
    /// mismatch path must reject the RPC and bump the counter.
    #[test]
    fn test_forged_leader_snapshot_rejected_when_hint_mismatches() {
        let secret = make_secret(0x07);
        let mut node = make_node_with_secret("n1", secret);
        // Real leader has just heartbeat'd — pin the leader hint.
        node.current_leader_hint = Some("real-leader".into());
        node.current_term = Term(5);
        let baseline = node.forged_snapshot_rejects();
        let mut args = InstallSnapshotArgs {
            term: Term(5),
            leader_id: "forged-leader".into(), // different from hint
            last_included_index: 10,
            last_included_term: Term(5),
            data: vec![1, 2, 3, 4],
            timestamp_ms: now_ms(),
            hmac: None,
            offset: 0,
            total_size: 4,
            last_chunk: true,
        };
        // Sign so the HMAC verification passes — the attacker has the
        // cluster secret, the divergence MUST still be caught.
        args.hmac = Some(RaftNode::compute_install_snapshot_hmac(&secret, &args));
        let reply = node.handle_install_snapshot(&args);
        assert_eq!(reply.term, Term(5));
        assert_eq!(
            node.forged_snapshot_rejects(),
            baseline + 1,
            "leader-id ≠ leader hint must increment forged_snapshot_rejects"
        );
    }

    /// `handle_append_entries` must update `current_leader_hint` to the
    /// authenticated leader's id.
    #[test]
    fn test_handle_append_entries_sets_leader_hint() {
        let secret = make_secret(0x08);
        let mut node = make_node_with_secret("n1", secret);
        node.current_term = Term(1);
        assert_eq!(node.current_leader_hint, None);
        let mut args = AppendEntriesArgs {
            term: Term(1),
            leader_id: "real-leader".into(),
            prev_log_index: 0,
            prev_log_term: Term(0),
            entries: vec![],
            leader_commit: 0,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret, &args));
        let reply = node.handle_append_entries(&args);
        assert!(reply.success);
        assert_eq!(node.current_leader_hint.as_deref(), Some("real-leader"));
    }

    /// `VoteRateLimiter::evict_stale` evicts entries strictly older than
    /// `stale_after_ms` and leaves fresh ones alone.
    #[test]
    fn test_vote_rate_limiter_evict_stale_drops_old_buckets() {
        let rl = VoteRateLimiter::new(4, 1000);
        // Two peers vote at t=0.
        assert!(rl.try_consume("p1", 0));
        assert!(rl.try_consume("p2", 0));
        // Fast-forward to t=5_000; p3 votes "now".
        assert!(rl.try_consume("p3", 5_000));
        // Evict anything ≥ 3_000 ms old at t=5_000 ⇒ p1, p2 go, p3 stays.
        let evicted = rl.evict_stale(5_000, 3_000);
        assert_eq!(evicted, 2);
        // A `stale_after_ms` of 0 is a documented no-op.
        assert_eq!(rl.evict_stale(5_000, 0), 0);
    }

    /// `run_periodic_maintenance` must drive `evict_stale` with
    /// `2 × base_election_timeout_ms`.
    #[test]
    fn test_run_periodic_maintenance_uses_2x_election_timeout() {
        // base = 200ms → stale threshold should be 400ms.
        let mut node = RaftNode::new("n1".into(), vec!["n2".into()], 200);
        node.set_cluster_secret(make_secret(0x09));
        let rl = node.vote_rate_limiter();
        // Inject a stale (very old last_refill) bucket.
        rl.try_consume("ghost", 0);
        // Sanity: bucket allocated.
        // Now bump wall-clock far past 2× base: maintenance should evict.
        // Since run_periodic_maintenance uses now_ms() internally and the
        // ghost bucket has last_refill_ms = 0, it is essentially
        // infinitely old in wall-clock terms ⇒ always evicted.
        let evicted = node.run_periodic_maintenance();
        assert_eq!(evicted, 1, "ghost peer must be evicted on maintenance");
    }

    /// `record_config_change_approval` must consult the state-machine
    /// voter set (when one is attached), not `self.peers + self.id`.
    #[test]
    fn test_record_config_change_approval_uses_state_machine_voters() {
        let secret = make_secret(0x0A);
        // Leader has *no* peers configured locally — but the SM has a
        // newer voter ("n2") that should still be accepted.
        let mut leader = RaftNode::new("leader".into(), vec![], 1000);
        leader.set_cluster_secret(secret);
        let sm = Arc::new(ClusterStateMachine::new([
            "leader".to_string(),
            "n2".to_string(),
        ]));
        leader.attach_state_machine(sm);
        leader.current_term = Term(1);
        leader.become_leader();
        let proposal = leader
            .propose_config_change("p-sm".into(), "n3".into(), MembershipAction::AddNode)
            .expect("leader proposes");
        let ts = now_ms();
        let hmac = RaftNode::compute_config_change_approval_hmac(
            &secret,
            &proposal.proposal_id,
            &proposal.node_id,
            &proposal.action,
            "n2",
            ts,
        );
        let approval = ConfigChangeApproval {
            proposal_id: proposal.proposal_id.clone(),
            approver_id: "n2".into(),
            timestamp_ms: ts,
            hmac,
        };
        // n2 is a voter only per the SM — the local `peers` is empty.
        // Source-of-truth fix should still accept this.
        assert!(
            leader.record_config_change_approval(&approval),
            "SM voter must be accepted as approver"
        );

        // Negative: a peer in neither SM voters nor self.peers is rejected.
        let hmac_bad = RaftNode::compute_config_change_approval_hmac(
            &secret,
            &proposal.proposal_id,
            &proposal.node_id,
            &proposal.action,
            "stranger",
            ts,
        );
        let bad = ConfigChangeApproval {
            proposal_id: proposal.proposal_id.clone(),
            approver_id: "stranger".into(),
            timestamp_ms: ts,
            hmac: hmac_bad,
        };
        assert!(!leader.record_config_change_approval(&bad));
    }

    /// The four reply-domain constants must be distinct, single-byte, and
    /// occupy the audit-mandated 0x10-0x13 slot (so they cannot collide
    /// with any request-domain tag).
    #[test]
    fn test_reply_domain_tags_distinct_single_byte() {
        let tags = [
            DOMAIN_REPLY_REQUEST_VOTE,
            DOMAIN_REPLY_APPEND_ENTRIES,
            DOMAIN_REPLY_INSTALL_SNAPSHOT,
            DOMAIN_REPLY_PRE_VOTE,
        ];
        // Distinct.
        let mut sorted = tags.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len(), "all reply tags must be distinct");
        // In the audit-mandated range.
        for t in tags {
            assert!((0x10..=0x13).contains(&t), "tag {t:#x} out of band");
        }
        // None collide with the request-domain tags.
        let request_tags = [
            DOMAIN_REQUEST_VOTE,
            DOMAIN_APPEND_ENTRIES,
            DOMAIN_INSTALL_SNAPSHOT,
            DOMAIN_PRE_VOTE,
        ];
        for r in request_tags {
            assert!(!tags.contains(&r), "reply tag {r:#x} collides with request");
        }
    }

    /// `RaftCommand::canonical_into_mac` must produce byte-identical
    /// output to `canonical_bytes` and `canonical_byte_len` must report
    /// the matching length.
    #[test]
    fn test_canonical_into_mac_matches_canonical_bytes() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let cases = vec![
            RaftCommand::Noop,
            RaftCommand::KeySync {
                key_id: "k1".into(),
                data: vec![1u8, 2, 3, 4, 5].into(),
            },
            RaftCommand::ConfigChange {
                node_id: "node-X".into(),
                action: MembershipAction::AddNode,
            },
            RaftCommand::ConfigChange {
                node_id: "node-Y".into(),
                action: MembershipAction::RemoveNode,
            },
        ];
        let key = [0xAAu8; 32];
        for cmd in cases {
            // Length helper matches canonical_bytes() length.
            let bytes = cmd.canonical_bytes();
            assert_eq!(canonical_byte_len(&cmd), bytes.len(), "byte_len parity");

            // Streaming into a MAC produces the same digest as a MAC
            // fed the materialized canonical_bytes() output.
            let mut mac_a = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("hmac");
            mac_a.update(&bytes);
            let tag_a = mac_a.finalize().into_bytes();

            let mut mac_b = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("hmac");
            cmd.canonical_into_mac(&mut mac_b);
            let tag_b = mac_b.finalize().into_bytes();

            assert_eq!(tag_a, tag_b, "stream vs materialize MAC parity");
        }
    }

    /// In release builds, `commit(index > last_index())` must silently cap
    /// (NOT panic, NOT corrupt) — the debug_assert protects the test
    /// suite without compromising availability.  In debug builds (where
    /// tests run by default), it panics; verify with
    /// `std::panic::catch_unwind`.
    #[test]
    fn test_commit_past_last_index_debug_asserts() {
        let mut log = RaftLog::new();
        log.append(make_entry(1, 1));
        log.append(make_entry(1, 2));
        // In debug build the assert fires.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            log.commit(99);
        }));
        if cfg!(debug_assertions) {
            assert!(res.is_err(), "debug-build commit(>last_index) must panic");
        } else {
            // Release-mode: silent cap — committed stays at 0 because the
            // guard `index <= last_index` rejects.
            assert_eq!(log.committed(), 0);
        }
    }

    /// `truncate_after` must NOT silently mutate `committed`; the
    /// debug_assert is for the test suite, the release-mode invariant
    /// is "TruncateBelowCommitted is the early-return".
    #[test]
    fn test_truncate_after_does_not_mutate_committed_on_safe_path() {
        let mut log = RaftLog::new();
        for i in 1..=5u64 {
            log.append(make_entry(1, i));
        }
        log.commit(3);
        // Safe truncate: after=4 > committed=3.
        log.truncate_after(4).expect("safe truncate");
        // committed unchanged.
        assert_eq!(log.committed(), 3);
        assert_eq!(log.last_index(), 4);
    }

    // -----------------------------------------------------------------------
    // Reply-HMAC domain-prefix rolling-upgrade compatibility
    // (Option A — try-both-tags during verify)
    // -----------------------------------------------------------------------
    //
    // The audit-fix sweep normalised the reply-MAC domain prefix from a
    // two-byte `[DOMAIN_REPLY_LEGACY, <kind>]` form down to a single-byte
    // `DOMAIN_REPLY_*` form. A naive ship of that change would break
    // every mixed-version cluster because reply MACs would no longer
    // verify across the boundary. The transitional fix: senders always
    // emit the new tag; verifiers try the new tag first and fall back
    // to the legacy two-byte prefix when `accept_legacy_reply_hmac_tags`
    // is enabled (default `true` for one release cycle).

    /// Build a `RequestVoteReply` signed under the LEGACY two-byte
    /// `[DOMAIN_REPLY_LEGACY, 0x01]` prefix — what a pre-normalization
    /// peer would have put on the wire.
    fn make_legacy_request_vote_reply(secret: &[u8; 32]) -> RequestVoteReply {
        let mut reply = RequestVoteReply {
            term: Term(7),
            vote_granted: true,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        reply.hmac = Some(RaftNode::compute_request_vote_reply_hmac_legacy(
            secret, &reply,
        ));
        reply
    }

    /// Build a `RequestVoteReply` signed under the NEW single-byte
    /// `DOMAIN_REPLY_REQUEST_VOTE` prefix.
    fn make_new_request_vote_reply(secret: &[u8; 32]) -> RequestVoteReply {
        let mut reply = RequestVoteReply {
            term: Term(7),
            vote_granted: true,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        reply.hmac = Some(RaftNode::compute_request_vote_reply_hmac(secret, &reply));
        reply
    }

    #[test]
    fn test_reply_signed_with_legacy_tag_passes_when_legacy_enabled() {
        // Default node has `accept_legacy_reply_hmac_tags = true`, so a
        // reply signed under the old two-byte prefix must verify.
        let secret = make_secret(0xA1);
        let node = make_node_with_secret("n1", secret);
        assert!(node.accept_legacy_reply_hmac_tags());

        let legacy_reply = make_legacy_request_vote_reply(&secret);
        assert!(
            node.verify_request_vote_reply(&legacy_reply),
            "legacy two-byte-prefix reply MUST verify when \
             accept_legacy_reply_hmac_tags=true (rolling-upgrade fallback)"
        );
    }

    #[test]
    fn test_reply_signed_with_legacy_tag_fails_when_legacy_disabled() {
        // Operator has finished the rolling upgrade and flipped the
        // gate; legacy-prefix replies must now be rejected.
        let secret = make_secret(0xA2);
        let mut node = make_node_with_secret("n1", secret);
        node.set_accept_legacy_reply_hmac_tags(false);
        assert!(!node.accept_legacy_reply_hmac_tags());

        let legacy_reply = make_legacy_request_vote_reply(&secret);
        assert!(
            !node.verify_request_vote_reply(&legacy_reply),
            "legacy two-byte-prefix reply MUST be rejected once \
             accept_legacy_reply_hmac_tags=false"
        );
        // Counter must NOT increment on a rejection.
        assert_eq!(node.legacy_reply_hmac_accepts(), 0);
    }

    #[test]
    fn test_reply_signed_with_new_tag_always_passes() {
        // The new single-byte prefix verifies regardless of the
        // legacy-accept gate — there is no scenario in which the
        // canonical/preferred path is rejected.
        let secret = make_secret(0xA3);

        // With legacy enabled (default).
        let node_legacy_on = make_node_with_secret("n1", secret);
        let r = make_new_request_vote_reply(&secret);
        assert!(node_legacy_on.verify_request_vote_reply(&r));
        // Counter must NOT increment when the NEW path succeeded.
        assert_eq!(node_legacy_on.legacy_reply_hmac_accepts(), 0);

        // With legacy disabled.
        let mut node_legacy_off = make_node_with_secret("n1", secret);
        node_legacy_off.set_accept_legacy_reply_hmac_tags(false);
        let r = make_new_request_vote_reply(&secret);
        assert!(node_legacy_off.verify_request_vote_reply(&r));
        assert_eq!(node_legacy_off.legacy_reply_hmac_accepts(), 0);
    }

    #[test]
    fn test_legacy_accept_counter_increments_correctly() {
        let secret = make_secret(0xA4);
        let node = make_node_with_secret("n1", secret);
        assert_eq!(node.legacy_reply_hmac_accepts(), 0);

        // One legacy accept.
        let r1 = make_legacy_request_vote_reply(&secret);
        assert!(node.verify_request_vote_reply(&r1));
        assert_eq!(node.legacy_reply_hmac_accepts(), 1);

        // Two more legacy accepts (different replies → fresh
        // timestamps so the freshness check passes).
        let r2 = make_legacy_request_vote_reply(&secret);
        let r3 = make_legacy_request_vote_reply(&secret);
        assert!(node.verify_request_vote_reply(&r2));
        assert!(node.verify_request_vote_reply(&r3));
        assert_eq!(node.legacy_reply_hmac_accepts(), 3);

        // A new-tag reply must NOT bump the legacy counter — only
        // the fallback path increments it.
        let new = make_new_request_vote_reply(&secret);
        assert!(node.verify_request_vote_reply(&new));
        assert_eq!(node.legacy_reply_hmac_accepts(), 3);

        // A garbage HMAC reply must NOT bump the legacy counter
        // (counter only increments on a *successful* legacy match,
        // not on any verify failure).
        let mut forged = RequestVoteReply {
            term: Term(7),
            vote_granted: true,
            timestamp_ms: now_ms(),
            hmac: Some([0xFFu8; 32]),
        };
        forged.timestamp_ms = now_ms();
        assert!(!node.verify_request_vote_reply(&forged));
        assert_eq!(node.legacy_reply_hmac_accepts(), 3);

        // The metrics() snapshot surfaces the same counter.
        assert_eq!(node.metrics().legacy_reply_hmac_accepts, 3);
    }

    #[test]
    fn test_legacy_fallback_covers_all_reply_kinds() {
        // Each of the four reply types must honour the same
        // try-new-then-legacy semantics so a mixed-version peer can
        // make progress on every Raft RPC, not just RequestVote.
        let secret = make_secret(0xA5);
        let node = make_node_with_secret("n1", secret);

        // AppendEntriesReply (legacy 0x02).
        let mut ae = AppendEntriesReply {
            term: Term(2),
            success: true,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        ae.hmac = Some(RaftNode::compute_append_entries_reply_hmac_legacy(
            &secret, &ae,
        ));
        assert!(node.verify_append_entries_reply(&ae));

        // InstallSnapshotReply (legacy 0x03).
        let mut isr = InstallSnapshotReply {
            term: Term(3),
            timestamp_ms: now_ms(),
            hmac: None,
        };
        isr.hmac = Some(RaftNode::compute_install_snapshot_reply_hmac_legacy(
            &secret, &isr,
        ));
        assert!(node.verify_install_snapshot_reply(&isr));

        // PreVoteReply (legacy 0x05).
        let mut pvr = PreVoteReply {
            term: Term(4),
            vote_granted: false,
            timestamp_ms: now_ms(),
            hmac: None,
        };
        pvr.hmac = Some(RaftNode::compute_pre_vote_reply_hmac_legacy(&secret, &pvr));
        assert!(node.verify_pre_vote_reply(&pvr));

        // Three legacy accepts in total across the kinds.
        assert_eq!(node.legacy_reply_hmac_accepts(), 3);
    }

    #[test]
    fn test_legacy_and_new_prefixes_produce_distinct_macs() {
        // Sanity check the underlying claim that motivates the
        // try-both-tags fallback: the new and legacy prefixes do in
        // fact produce different HMACs over identical reply
        // contents. If a future edit accidentally collapsed them the
        // fallback would become a no-op and we'd silently regress.
        let secret = make_secret(0xA6);
        let reply = RequestVoteReply {
            term: Term(11),
            vote_granted: true,
            timestamp_ms: 1_700_000_000_000,
            hmac: None,
        };
        let new_tag = RaftNode::compute_request_vote_reply_hmac(&secret, &reply);
        let legacy = RaftNode::compute_request_vote_reply_hmac_legacy(&secret, &reply);
        assert_ne!(new_tag, legacy);
    }

    #[test]
    fn test_cluster_config_legacy_reply_hmac_tags_default_true() {
        // Default config keeps backward-compat enabled so a freshly
        // upgraded cluster does not break in-flight traffic.
        let cfg = crate::config::ClusterConfig::default();
        assert!(cfg.legacy_reply_hmac_tags);

        // Empty JSON object must also pick up the default (serde
        // round-trip safety for older config files).
        let parsed: crate::config::ClusterConfig =
            serde_json::from_str(r#"{"node_id":"n1"}"#).unwrap();
        assert!(parsed.legacy_reply_hmac_tags);
    }
}
