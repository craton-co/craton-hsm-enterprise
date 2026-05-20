// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Jepsen-lite (item 7, audit): a tiny deterministic three-node scenario
//! that exercises the partition-heal log-overwrite property end-to-end.
//!
//! Goals:
//!   * Three nodes {n1, n2, n3}, all with the same cluster secret.
//!   * Elect `n1` as leader, append two uncommitted entries on the
//!     leader only (peers partitioned away).
//!   * Partition heals — a higher-term leader emerges on the majority
//!     side {n2, n3} and propagates its own log.
//!   * The original leader's uncommitted tail must be overwritten.
//!
//! This is the smallest end-to-end check that the
//! `truncate_after` / `become_follower` / `handle_append_entries`
//! interaction does the right thing under partition heal. Larger
//! invariants are covered by `split_brain.rs`.

use craton_hsm_cluster::raft::{
    AppendEntriesArgs, LogEntry, RaftCommand, RaftNode, RaftState, Term,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_node(id: &str, peers: &[&str]) -> RaftNode {
    let mut n = RaftNode::new(
        id.to_string(),
        peers.iter().map(|s| s.to_string()).collect(),
        1_000,
    );
    n.set_cluster_secret([0x42u8; 32]);
    n
}

fn signed_ae(
    leader: &RaftNode,
    leader_id: &str,
    term: Term,
    prev_log_index: u64,
    prev_log_term: Term,
    entries: Vec<LogEntry>,
    leader_commit: u64,
) -> AppendEntriesArgs {
    let mut args = AppendEntriesArgs {
        term,
        leader_id: leader_id.to_string(),
        prev_log_index,
        prev_log_term,
        entries,
        leader_commit,
        timestamp_ms: now_ms(),
        hmac: None,
    };
    // Sign with the leader's secret (matches make_node).
    let secret: [u8; 32] = [0x42u8; 32];
    let mac = RaftNode::compute_append_entries_hmac(&secret, &args);
    args.hmac = Some(mac);
    let _ = leader; // silence unused; we sign with the shared cluster secret
    args
}

#[test]
fn jepsen_lite_partition_overwrites_uncommitted_tail() {
    // Three nodes: n1 starts as leader, then n2 takes over.
    let mut n1 = make_node("n1", &["n2", "n3"]);
    let mut n3 = make_node("n3", &["n1", "n2"]);

    // ---- phase 1 ----------------------------------------------------------
    // n1 wins term 1 unilaterally (we drive the state machine, since
    // election orchestration is covered by split_brain.rs).
    n1.try_become_candidate().expect("term bump");
    assert_eq!(n1.state(), RaftState::Candidate);
    n1.become_leader();
    assert_eq!(n1.current_term(), Term(1));
    assert_eq!(n1.state(), RaftState::Leader);

    // Leader appends two uncommitted entries that NEVER reach peers
    // (simulating the network partition during the write).
    n1.log_mut().append(LogEntry {
        term: Term(1),
        index: 1,
        command: RaftCommand::Noop,
    });
    n1.log_mut().append(LogEntry {
        term: Term(1),
        index: 2,
        command: RaftCommand::Noop,
    });
    assert_eq!(n1.log().last_index(), 2);
    assert_eq!(n1.log().committed(), 0, "writes are uncommitted");

    // ---- phase 2 ----------------------------------------------------------
    // Partition heals. A new leader (n2) on the majority side has won
    // term 2 and replicated its own single Noop. We model that by
    // sending n1 an AppendEntries from n2 at term 2 carrying a single
    // entry at index 1 with term 2.
    let dummy_signer = make_node("signer", &[]); // shares the same secret
    let take_over = signed_ae(
        &dummy_signer,
        "n2",
        Term(2),
        0,
        Term(0),
        vec![LogEntry {
            term: Term(2),
            index: 1,
            command: RaftCommand::Noop,
        }],
        0,
    );

    // n1 (still thinks it's leader at term 1) receives the higher-term
    // AE. Per Raft §5.1 it MUST: bump to term 2, become Follower, and
    // truncate its conflicting suffix.
    let reply = n1.handle_append_entries(&take_over);
    assert!(reply.success, "AE from higher-term leader must succeed");
    assert_eq!(
        n1.current_term(),
        Term(2),
        "term must follow the new leader"
    );
    assert_eq!(n1.state(), RaftState::Follower);

    // The critical invariant: n1's previous index-2 entry is gone, and
    // its index-1 entry has been overwritten with the new term.
    assert_eq!(
        n1.log().last_index(),
        1,
        "uncommitted tail must be truncated"
    );
    let e1 = n1.log().get(1).expect("entry 1 present");
    assert_eq!(e1.term, Term(2), "index 1 must carry the new leader's term");

    // n3 (a fresh follower) accepts the same AE without surprise.
    let take_over_for_n3 = signed_ae(
        &dummy_signer,
        "n2",
        Term(2),
        0,
        Term(0),
        vec![LogEntry {
            term: Term(2),
            index: 1,
            command: RaftCommand::Noop,
        }],
        0,
    );
    let r3 = n3.handle_append_entries(&take_over_for_n3);
    assert!(r3.success);
    assert_eq!(n3.current_term(), Term(2));
}
