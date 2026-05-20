// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Construct a single-node Raft cluster, become leader, propose a
//! `Noop` log entry, and assert it is committed and applied.
//!
//! This is the minimal "does Raft work at all?" smoke test. With an
//! empty peer list, `submit_command` short-circuits commit and apply
//! locally — no networking, no transport, no peer goroutines.
//!
//! Run with:
//!
//! ```text
//! cargo run --example single_node -p craton-hsm-cluster
//! ```
//!
//! The cluster secret is set explicitly so this example does NOT need
//! the `insecure-no-cluster-secret` feature flag.

use std::sync::Arc;

use craton_hsm_cluster::raft::{RaftCommand, RaftNode};
use craton_hsm_cluster::state_machine::ClusterStateMachine;

fn main() {
    let node_id = "single-node".to_string();
    let peers: Vec<String> = Vec::new(); // peers = self only
    let base_election_timeout_ms = 1_000;

    let mut node = RaftNode::new(node_id.clone(), peers, base_election_timeout_ms);

    // Production builds require a 32-byte cluster HMAC secret before
    // any RPC verification will accept traffic. For a freestanding
    // example we install a deterministic test secret so we don't have
    // to enable `insecure-no-cluster-secret`.
    let cluster_secret = [0x42u8; 32];
    node.set_cluster_secret(cluster_secret);
    node.require_cluster_secret_for_production()
        .expect("cluster secret is installed");

    // Attach an in-memory state machine so `apply_committed` can move
    // `applied` past `committed`. Without a state machine, log entries
    // commit but the apply loop never advances — see `RaftNode::apply_committed`.
    let sm = Arc::new(ClusterStateMachine::new([node_id.clone()]));
    node.attach_state_machine(sm.clone());

    // Drive the node into Leader via the public election helpers.
    // `try_become_candidate` bumps the term and self-votes; with no
    // other peers there is nothing to wait for, so we can promote to
    // Leader immediately.
    node.try_become_candidate()
        .expect("term bump must not overflow");
    node.become_leader();
    assert!(node.is_leader(), "single node must be leader");

    // Submit a Noop entry. With `peers.is_empty()` the leader commits
    // and applies it immediately inside `submit_command`.
    let idx = node
        .submit_command(RaftCommand::Noop)
        .expect("leader must accept submit_command");
    assert_eq!(idx, 1, "first entry should land at index 1");
    assert_eq!(
        node.log().committed(),
        1,
        "Noop must commit on a single-node leader"
    );
    assert_eq!(
        node.log().applied(),
        1,
        "Noop must apply on a single-node leader"
    );
    assert_eq!(
        sm.last_applied(),
        1,
        "state machine must observe the applied entry"
    );

    println!(
        "OK: single-node Raft proposed and applied Noop at index {} (term {:?})",
        idx,
        node.current_term(),
    );
}
