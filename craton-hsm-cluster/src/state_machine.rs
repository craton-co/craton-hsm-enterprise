// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Replicated state machine — applies committed Raft commands.
//!
//! The state machine handles the three command variants emitted by the Raft
//! log:
//!
//! - [`RaftCommand::KeySync`] — installs / replaces a key blob in the local
//!   key table.
//! - [`RaftCommand::ConfigChange`] — adds or removes a node from the cluster
//!   membership set.
//! - [`RaftCommand::Noop`] — committed at leader transition; no state change.
//!
//! [`ClusterStateMachine`] is intentionally pure: it owns its own membership
//! and key map and applies entries in strict log order.  Snapshotting is
//! supported via [`snapshot`](ClusterStateMachine::snapshot) and
//! [`restore_from_snapshot`](ClusterStateMachine::restore_from_snapshot).

use crate::raft::{LogEntry, MembershipAction, RaftCommand};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Snapshot of the state machine — the unit of compaction sent to lagging
/// followers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StateMachineSnapshot {
    /// Highest log index that has been applied.
    pub last_applied: u64,
    /// Cluster membership at this snapshot.
    pub voters: Vec<String>,
    /// Key blobs (`key_id` → bytes).
    pub keys: BTreeMap<String, Vec<u8>>,
}

/// Result of applying a single committed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyOutcome {
    /// A no-op entry — nothing happened.
    Noop,
    /// A key was installed / replaced.
    KeyInstalled {
        /// Identifier of the installed key.
        key_id: String,
        /// Size in bytes of the installed key material.
        bytes: usize,
    },
    /// A node was added to the cluster.
    NodeAdded(String),
    /// A node was removed from the cluster.
    NodeRemoved(String),
}

/// Errors that can occur during state machine application.
#[derive(Debug)]
pub enum ApplyError {
    /// The entry was applied out of order (gap in indices).
    OutOfOrder {
        /// Index the state machine was expecting next.
        expected: u64,
        /// Index actually presented to `apply`.
        got: u64,
    },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfOrder { expected, got } => {
                write!(
                    f,
                    "entry applied out of order: expected {expected}, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for ApplyError {}

/// Concurrent, in-process replicated state machine.
#[derive(Debug, Default)]
pub struct ClusterStateMachine {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    last_applied: u64,
    voters: BTreeSet<String>,
    keys: BTreeMap<String, Vec<u8>>,
}

impl ClusterStateMachine {
    /// Construct an empty state machine with the given initial voter set.
    pub fn new(initial_voters: impl IntoIterator<Item = String>) -> Self {
        Self {
            inner: RwLock::new(Inner {
                last_applied: 0,
                voters: initial_voters.into_iter().collect(),
                keys: BTreeMap::new(),
            }),
        }
    }

    /// Highest log index that has been applied.
    pub fn last_applied(&self) -> u64 {
        self.inner.read().last_applied
    }

    /// Current cluster voter set (sorted).
    pub fn voters(&self) -> Vec<String> {
        self.inner.read().voters.iter().cloned().collect()
    }

    /// Returns `true` if the named key is currently installed.
    pub fn contains_key(&self, key_id: &str) -> bool {
        self.inner.read().keys.contains_key(key_id)
    }

    /// Number of installed keys.
    pub fn key_count(&self) -> usize {
        self.inner.read().keys.len()
    }

    /// Get a clone of a key's bytes, if installed.
    pub fn get_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.inner.read().keys.get(key_id).cloned()
    }

    /// Apply a single committed log entry.
    ///
    /// Entries must be applied in strict order — `entry.index` must equal
    /// `last_applied + 1`, otherwise [`ApplyError::OutOfOrder`] is returned
    /// and no state changes.
    pub fn apply(&self, entry: &LogEntry) -> Result<ApplyOutcome, ApplyError> {
        let mut g = self.inner.write();
        let expected = g.last_applied + 1;
        if entry.index != expected {
            return Err(ApplyError::OutOfOrder {
                expected,
                got: entry.index,
            });
        }
        let outcome = match &entry.command {
            RaftCommand::Noop => ApplyOutcome::Noop,
            RaftCommand::KeySync { key_id, data } => {
                let bytes = data.len();
                g.keys.insert(key_id.clone(), (**data).clone());
                ApplyOutcome::KeyInstalled {
                    key_id: key_id.clone(),
                    bytes,
                }
            }
            RaftCommand::ConfigChange { node_id, action } => match action {
                // Stub: AddLearner/PromoteLearner currently behave like
                // AddNode for the voter-set state machine. The wire
                // format already distinguishes them so a future
                // joint-consensus upgrade can roll out additively.
                MembershipAction::AddNode
                | MembershipAction::AddLearner
                | MembershipAction::PromoteLearner => {
                    g.voters.insert(node_id.clone());
                    ApplyOutcome::NodeAdded(node_id.clone())
                }
                MembershipAction::RemoveNode => {
                    g.voters.remove(node_id);
                    ApplyOutcome::NodeRemoved(node_id.clone())
                }
            },
        };
        g.last_applied = entry.index;
        Ok(outcome)
    }

    /// Apply many entries in order, stopping at the first error.
    ///
    /// Returns the number of entries successfully applied.
    pub fn apply_batch(&self, entries: &[LogEntry]) -> Result<usize, ApplyError> {
        for (i, e) in entries.iter().enumerate() {
            self.apply(e).map_err(|err| {
                tracing::error!("state machine apply failed at index {}: {}", e.index, err);
                err
            })?;
            let _ = i;
        }
        Ok(entries.len())
    }

    /// Capture a serializable snapshot of the current state.
    pub fn snapshot(&self) -> StateMachineSnapshot {
        let g = self.inner.read();
        StateMachineSnapshot {
            last_applied: g.last_applied,
            voters: g.voters.iter().cloned().collect(),
            keys: g.keys.clone(),
        }
    }

    /// Replace the in-memory state from a snapshot.
    pub fn restore_from_snapshot(&self, snap: &StateMachineSnapshot) {
        let mut g = self.inner.write();
        g.last_applied = snap.last_applied;
        g.voters = snap.voters.iter().cloned().collect();
        g.keys = snap.keys.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::Term;
    use zeroize::Zeroizing;

    fn entry(idx: u64, cmd: RaftCommand) -> LogEntry {
        LogEntry {
            term: Term(1),
            index: idx,
            command: cmd,
        }
    }

    #[test]
    fn apply_noop() {
        let sm = ClusterStateMachine::new(["n1".to_string()]);
        let out = sm.apply(&entry(1, RaftCommand::Noop)).unwrap();
        assert_eq!(out, ApplyOutcome::Noop);
        assert_eq!(sm.last_applied(), 1);
    }

    #[test]
    fn apply_key_sync_installs_key() {
        let sm = ClusterStateMachine::default();
        let out = sm
            .apply(&entry(
                1,
                RaftCommand::KeySync {
                    key_id: "k1".into(),
                    data: Zeroizing::new(vec![1, 2, 3]),
                },
            ))
            .unwrap();
        assert!(matches!(
            out,
            ApplyOutcome::KeyInstalled { ref key_id, bytes: 3 } if key_id == "k1"
        ));
        assert!(sm.contains_key("k1"));
        assert_eq!(sm.get_key("k1"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn apply_key_sync_replaces_existing() {
        let sm = ClusterStateMachine::default();
        sm.apply(&entry(
            1,
            RaftCommand::KeySync {
                key_id: "k".into(),
                data: Zeroizing::new(vec![0]),
            },
        ))
        .unwrap();
        sm.apply(&entry(
            2,
            RaftCommand::KeySync {
                key_id: "k".into(),
                data: Zeroizing::new(vec![9, 9]),
            },
        ))
        .unwrap();
        assert_eq!(sm.get_key("k"), Some(vec![9, 9]));
        assert_eq!(sm.key_count(), 1);
    }

    #[test]
    fn apply_config_change_add_remove() {
        let sm = ClusterStateMachine::new(["n1".to_string()]);
        sm.apply(&entry(
            1,
            RaftCommand::ConfigChange {
                node_id: "n2".into(),
                action: MembershipAction::AddNode,
            },
        ))
        .unwrap();
        assert_eq!(sm.voters(), vec!["n1".to_string(), "n2".to_string()]);

        sm.apply(&entry(
            2,
            RaftCommand::ConfigChange {
                node_id: "n1".into(),
                action: MembershipAction::RemoveNode,
            },
        ))
        .unwrap();
        assert_eq!(sm.voters(), vec!["n2".to_string()]);
    }

    #[test]
    fn out_of_order_rejected() {
        let sm = ClusterStateMachine::default();
        sm.apply(&entry(1, RaftCommand::Noop)).unwrap();
        let err = sm.apply(&entry(3, RaftCommand::Noop)).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::OutOfOrder {
                expected: 2,
                got: 3
            }
        ));
        // last_applied unchanged.
        assert_eq!(sm.last_applied(), 1);
    }

    #[test]
    fn snapshot_roundtrip() {
        let sm = ClusterStateMachine::new(["n1".to_string()]);
        sm.apply(&entry(
            1,
            RaftCommand::KeySync {
                key_id: "k".into(),
                data: Zeroizing::new(vec![7]),
            },
        ))
        .unwrap();
        sm.apply(&entry(
            2,
            RaftCommand::ConfigChange {
                node_id: "n2".into(),
                action: MembershipAction::AddNode,
            },
        ))
        .unwrap();
        let snap = sm.snapshot();

        let sm2 = ClusterStateMachine::default();
        sm2.restore_from_snapshot(&snap);
        assert_eq!(sm2.last_applied(), 2);
        assert_eq!(sm2.get_key("k"), Some(vec![7]));
        assert_eq!(sm2.voters(), vec!["n1".to_string(), "n2".to_string()]);
    }

    #[test]
    fn batch_apply_stops_on_error() {
        let sm = ClusterStateMachine::default();
        let entries = vec![
            entry(1, RaftCommand::Noop),
            // gap — should fail.
            entry(3, RaftCommand::Noop),
        ];
        let r = sm.apply_batch(&entries);
        assert!(r.is_err());
        assert_eq!(sm.last_applied(), 1);
    }
}
