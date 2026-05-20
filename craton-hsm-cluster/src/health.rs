// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Cluster health monitoring — node and cluster health checks, split-brain detection.

use crate::raft::{RaftNode, RaftState, Term};

/// Health snapshot for a single node.
#[derive(Debug, Clone)]
pub struct NodeHealth {
    /// Unique node identifier.
    pub node_id: String,
    /// Current Raft state.
    pub state: RaftState,
    /// Current election term.
    pub term: u64,
    /// Timestamp (epoch millis) of the last heartbeat.
    pub last_heartbeat: u64,
    /// Index of the last log entry.
    pub log_index: u64,
    /// Node uptime in seconds (monotonic).
    pub uptime_secs: u64,
}

/// Health snapshot for the entire cluster.
#[derive(Debug, Clone)]
pub struct ClusterHealth {
    /// Health information for each node.
    pub nodes: Vec<NodeHealth>,
    /// ID of the current leader, if any.
    pub leader_id: Option<String>,
    /// Whether the cluster is considered healthy (has a leader and quorum).
    pub healthy: bool,
    /// Whether a quorum of nodes is reachable.
    pub quorum_met: bool,
}

/// Returns `true` if `reachable` nodes out of `total` are sufficient for quorum.
///
/// Quorum requires a strict majority: `reachable >= total / 2 + 1`.
/// A cluster of 0 nodes never meets quorum.
pub fn quorum_met(reachable: usize, total: usize) -> bool {
    if total == 0 {
        return false;
    }
    reachable > total / 2
}

/// Health checker that inspects Raft nodes and produces health reports.
#[derive(Debug, Default)]
pub struct HealthChecker {}

impl HealthChecker {
    /// Create a new health checker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Produce a health snapshot for a single node.
    pub fn check_node(&self, node: &RaftNode) -> NodeHealth {
        NodeHealth {
            node_id: node.id().to_string(),
            state: node.state(),
            term: node.current_term().value(),
            last_heartbeat: node.last_heartbeat(),
            log_index: node.log().last_index(),
            uptime_secs: node.uptime_secs(),
        }
    }

    /// Produce a health snapshot for the entire cluster.
    pub fn check_cluster(&self, nodes: &[RaftNode]) -> ClusterHealth {
        self.check_cluster_with_total(nodes, nodes.len())
    }

    /// Produce a health snapshot when the full cluster size is known but some
    /// nodes may be unreachable (i.e., not included in `nodes`).
    ///
    /// Sanity check: `total_cluster_size` is clamped to be at least the number
    /// of supplied nodes — a buggy or malicious caller cannot fabricate a
    /// healthy single-node report from a partial slice.
    pub fn check_cluster_with_total(
        &self,
        nodes: &[RaftNode],
        total_cluster_size: usize,
    ) -> ClusterHealth {
        let total_cluster_size = total_cluster_size.max(nodes.len());
        let node_healths: Vec<NodeHealth> = nodes.iter().map(|n| self.check_node(n)).collect();

        // Group leaders by term — true split-brain is two leaders in the SAME term.
        let leader_terms: Vec<u64> = node_healths
            .iter()
            .filter(|h| h.state == RaftState::Leader)
            .map(|h| h.term)
            .collect();

        // Pick the leader with the highest term as the canonical leader.
        let canonical_leader = node_healths
            .iter()
            .filter(|h| h.state == RaftState::Leader)
            .max_by_key(|h| h.term)
            .map(|h| (h.node_id.clone(), h.term));

        let same_term_count = canonical_leader
            .as_ref()
            .map(|(_, t)| leader_terms.iter().filter(|&&x| x == *t).count())
            .unwrap_or(0);

        let leader_id = match (&canonical_leader, same_term_count) {
            (Some((id, _)), 1) => Some(id.clone()),
            _ => None,
        };

        let reachable = nodes.len();
        let quorum_met = quorum_met(reachable, total_cluster_size);
        let healthy = leader_id.is_some() && quorum_met;

        ClusterHealth {
            nodes: node_healths,
            leader_id,
            healthy,
            quorum_met,
        }
    }

    /// Detect split-brain: returns `true` only if multiple nodes claim to be
    /// leader in the **same** term (true Raft safety violation).
    ///
    /// Brief multi-leader windows during a leader transition use distinct
    /// terms and are not flagged.
    pub fn is_split_brain(&self, nodes: &[RaftNode]) -> bool {
        let mut terms: Vec<Term> = nodes
            .iter()
            .filter(|n| n.state() == RaftState::Leader)
            .map(|n| n.current_term())
            .collect();
        if terms.len() < 2 {
            return false;
        }
        terms.sort();
        terms.windows(2).any(|w| w[0] == w[1])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, peers: &[&str]) -> RaftNode {
        RaftNode::new(
            id.to_string(),
            peers.iter().map(|s| s.to_string()).collect(),
            1000,
        )
    }

    #[test]
    fn test_quorum_met_function() {
        assert!(!quorum_met(0, 1));
        assert!(quorum_met(1, 1));
        assert!(!quorum_met(1, 3));
        assert!(quorum_met(2, 3));
        assert!(!quorum_met(2, 5));
        assert!(quorum_met(3, 5));
        assert!(quorum_met(4, 7));
        assert!(!quorum_met(3, 7));
        assert!(!quorum_met(0, 0));
    }

    #[test]
    fn test_check_cluster_with_partial_nodes() {
        let checker = HealthChecker::new();
        let n1 = make_node("n1", &["n2", "n3", "n4", "n5"]);
        let n2 = make_node("n2", &["n1", "n3", "n4", "n5"]);
        let health = checker.check_cluster_with_total(&[n1, n2], 5);
        assert!(!health.quorum_met);
    }

    #[test]
    fn test_total_clamped_to_supplied_nodes() {
        // A caller passing total=1 with 5 supplied nodes can't fake quorum.
        let checker = HealthChecker::new();
        let nodes: Vec<RaftNode> = (0..5).map(|i| make_node(&format!("n{i}"), &[])).collect();
        let h = checker.check_cluster_with_total(&nodes, 1);
        // total_cluster_size is clamped up to 5, so reachability=5 of 5 — quorum met.
        assert!(h.quorum_met);
    }

    #[test]
    fn test_check_node_follower() {
        let checker = HealthChecker::new();
        let node = make_node("n1", &["n2", "n3"]);
        let health = checker.check_node(&node);
        assert_eq!(health.node_id, "n1");
        assert_eq!(health.state, RaftState::Follower);
        assert_eq!(health.term, 0);
    }

    #[test]
    fn test_healthy_cluster() {
        let checker = HealthChecker::new();
        let mut n1 = make_node("n1", &["n2", "n3"]);
        n1.become_candidate();
        n1.become_leader();
        let n2 = make_node("n2", &["n1", "n3"]);
        let n3 = make_node("n3", &["n1", "n2"]);
        let health = checker.check_cluster(&[n1, n2, n3]);
        assert!(health.healthy);
        assert_eq!(health.leader_id, Some("n1".into()));
    }

    #[test]
    fn test_no_leader() {
        let checker = HealthChecker::new();
        let n1 = make_node("n1", &["n2", "n3"]);
        let n2 = make_node("n2", &["n1", "n3"]);
        let n3 = make_node("n3", &["n1", "n2"]);
        let health = checker.check_cluster(&[n1, n2, n3]);
        assert!(!health.healthy);
        assert_eq!(health.leader_id, None);
    }

    #[test]
    fn test_split_brain_same_term_detected() {
        let checker = HealthChecker::new();
        let mut n1 = make_node("n1", &["n2", "n3"]);
        n1.become_candidate(); // term 1
        n1.become_leader();
        let mut n2 = make_node("n2", &["n1", "n3"]);
        n2.become_candidate(); // also term 1
        n2.become_leader();
        let n3 = make_node("n3", &["n1", "n2"]);
        assert!(checker.is_split_brain(&[n1, n2, n3]));
    }

    #[test]
    fn test_no_split_brain_different_terms() {
        // Brief leader transition: old leader at term 1, new leader at term 2.
        let checker = HealthChecker::new();
        let mut n1 = make_node("n1", &["n2", "n3"]);
        n1.become_candidate(); // term 1
        n1.become_leader();

        let mut n2 = make_node("n2", &["n1", "n3"]);
        n2.become_candidate(); // term 1
        n2.become_candidate(); // term 2
        n2.become_leader();
        let n3 = make_node("n3", &["n1", "n2"]);
        assert!(!checker.is_split_brain(&[n1, n2, n3]));
    }

    #[test]
    fn test_check_cluster_picks_higher_term_leader() {
        let checker = HealthChecker::new();
        let mut old_leader = make_node("n1", &["n2", "n3"]);
        old_leader.become_candidate(); // term 1
        old_leader.become_leader();
        let mut new_leader = make_node("n2", &["n1", "n3"]);
        new_leader.become_candidate();
        new_leader.become_candidate(); // term 2
        new_leader.become_leader();
        let n3 = make_node("n3", &["n1", "n2"]);
        let h = checker.check_cluster(&[old_leader, new_leader, n3]);
        // Two leaders in different terms — pick the higher-term leader, cluster healthy.
        assert_eq!(h.leader_id, Some("n2".into()));
        assert!(h.healthy);
    }

    #[test]
    fn test_single_node_cluster() {
        let checker = HealthChecker::new();
        let mut n1 = make_node("n1", &[]);
        n1.become_candidate();
        n1.become_leader();
        let h = checker.check_cluster(&[n1]);
        assert!(h.healthy);
    }
}
