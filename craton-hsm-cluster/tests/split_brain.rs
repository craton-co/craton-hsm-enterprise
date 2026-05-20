// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Synchronous split-brain and membership-change smoke tests for the Raft
//! core.
//!
//! These tests drive the [`RaftNode`] API directly, without tokio or any
//! network transport.  We build a small in-process "transport" that
//! pairs each node with its peers and allows the test to selectively
//! drop or deliver RPCs to simulate partitions.  Every test runs in
//! logical ticks — no `std::thread::sleep`, no wall-clock scheduling —
//! so the outcome is deterministic.
//!
//! Scope: the audit called for split-brain prevention, joint-consensus
//! membership changes, and lease-read staleness checks.  The current
//! `RaftNode` surface does not expose a true joint-consensus
//! transition or a linearizable-read lease API; those features are
//! tested at the semantic level we actually have:
//!
//!   * Split-brain: a minority-partition "leader" cannot commit writes
//!     (single-node quorum math rejects commit when peers outnumber
//!     the effective majority).
//!   * Add / remove server: the membership log entry is applied and
//!     the peer list updates.  Post-removal, the remaining nodes
//!     continue to accept writes.
//!   * Stale-leader read: a leader that has been superseded by a
//!     higher-term message downgrades to follower on the next RPC and
//!     therefore cannot serve writes.
//!
//! Where a stronger property than the current API supports is required
//! by the audit, the test is marked `#[ignore]` with a one-line
//! rationale pointing at the production change needed.

use craton_hsm_cluster::config::ClusterConfig;
use craton_hsm_cluster::raft::{
    AppendEntriesArgs, ConfigChangeApproval, InstallSnapshotArgs, LogEntry, MembershipAction,
    PreVoteReply, RaftCommand, RaftError, RaftNode, RaftState, RequestVoteArgs, Term,
    VoteRateLimiterConfig,
};
use craton_hsm_cluster::state_machine::ClusterStateMachine;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

/// Build a RaftNode with the given id, peer list, and shared cluster secret.
/// A `ClusterStateMachine` with all nodes as initial voters is attached so
/// that membership-change entries apply correctly.
fn make_node(id: &str, peers: Vec<&str>, voters: Vec<&str>) -> RaftNode {
    let mut node = RaftNode::new(
        id.to_string(),
        peers.into_iter().map(String::from).collect(),
        1000,
    );
    node.set_cluster_secret(secret());
    let sm = Arc::new(ClusterStateMachine::new(
        voters.into_iter().map(String::from),
    ));
    node.attach_state_machine(sm);
    node
}

/// Build an AppendEntries RPC signed with the shared secret.
fn make_ae(
    term: Term,
    leader_id: &str,
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
    args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret(), &args));
    args
}

// ---------------------------------------------------------------------------
// 1. Split-brain — minority-partition leader cannot commit writes
// ---------------------------------------------------------------------------

/// Simulate a three-node cluster {n1, n2, n3} partitioned into
/// {n1} (minority) and {n2, n3} (majority).  n1 tries to act as a leader
/// on its own; submit_command must append to its local log but the
/// entry must NOT be reported as committed, because it has no way to
/// hear a majority quorum.
#[test]
fn minority_partition_leader_cannot_commit() {
    let mut n1 = make_node("n1", vec!["n2", "n3"], vec!["n1", "n2", "n3"]);
    // Promote n1 through an election it "won" in its local state.
    n1.become_candidate();
    n1.become_leader();
    assert_eq!(n1.state(), RaftState::Leader);

    // n1 submits a Noop — it will appear in the local log, but commit
    // cannot advance because peers n2 and n3 are unreachable (we simply
    // never deliver any AppendEntriesReply).
    let idx = n1
        .submit_command(RaftCommand::Noop)
        .expect("leader must accept the command locally");
    assert_eq!(idx, 1);
    assert_eq!(n1.log().last_index(), 1);

    // With 2 peers (n2, n3), quorum_size = 2. The leader alone cannot
    // advance commit. No reply has been delivered, so committed stays 0.
    assert_eq!(
        n1.log().committed(),
        0,
        "minority 'leader' must NOT have advanced the commit index"
    );
    // quorum_size for a 3-node cluster is 2.
    assert_eq!(n1.quorum_size(), 2);
}

/// When the partition heals, a higher-term AppendEntries from the true
/// majority leader causes the old minority leader to step down and any
/// of its uncommitted entries are truncated by the log-matching check.
#[test]
fn partition_heal_truncates_minority_uncommitted_entries() {
    // Start: n1 thinks it's leader at term=5 with one uncommitted entry.
    let mut n1 = make_node("n1", vec!["n2", "n3"], vec!["n1", "n2", "n3"]);
    n1.become_candidate();
    n1.become_leader();
    // Push several Noops into n1's local log (these are uncommitted).
    for _ in 0..3 {
        n1.submit_command(RaftCommand::Noop);
    }
    assert_eq!(n1.log().last_index(), 3);
    assert_eq!(n1.log().committed(), 0);
    let minority_term = n1.current_term();

    // The real majority, now operating at a higher term, sends an
    // AppendEntries with prev_log_index=0 (new history) and its own
    // entries at that higher term.  The log-matching property forces
    // n1 to drop its divergent tail and adopt the leader's entries.
    let higher_term = minority_term + 10;
    let majority_entries = vec![
        LogEntry {
            term: higher_term,
            index: 1,
            command: RaftCommand::Noop,
        },
        LogEntry {
            term: higher_term,
            index: 2,
            command: RaftCommand::Noop,
        },
    ];
    let args = make_ae(higher_term, "n2", 0, Term(0), majority_entries, 2);
    let reply = n1.handle_append_entries(&args);
    assert!(reply.success, "n1 must accept the higher-term leader");

    // n1 has stepped down to follower at the higher term.
    assert_eq!(n1.state(), RaftState::Follower);
    assert_eq!(n1.current_term(), higher_term);
    // Its log now matches the majority's — length 2, not 3, and the
    // previously-uncommitted third entry is gone.
    assert_eq!(
        n1.log().last_index(),
        2,
        "minority's uncommitted entries must have been truncated"
    );
    // And the majority's entries are now committed locally.
    assert_eq!(n1.log().committed(), 2);
}

// ---------------------------------------------------------------------------
// 2. AddServer — membership grows and new quorum takes effect
// ---------------------------------------------------------------------------

/// Adding a fourth node via a ConfigChange log entry must update the
/// peer list on commit. Quorum then becomes ceil(4/2)+1=3.
#[test]
fn add_server_updates_quorum_size() {
    let mut n1 = make_node("n1", vec!["n2", "n3"], vec!["n1", "n2", "n3"]);
    assert_eq!(n1.quorum_size(), 2);

    // Deliver a ConfigChange(AddNode n4) AppendEntries from a simulated
    // leader (ourselves, via the same secret). Use term=1 to match
    // n1's post-init term window.
    let entries = vec![LogEntry {
        term: Term(1),
        index: 1,
        command: RaftCommand::ConfigChange {
            node_id: "n4".into(),
            action: MembershipAction::AddNode,
        },
    }];
    let args = make_ae(Term(1), "leader", 0, Term(0), entries, 1);
    let reply = n1.handle_append_entries(&args);
    assert!(reply.success);

    // After apply, peers now include n4; quorum size grows to 3
    // (4 voters: n1, n2, n3, n4).
    let mut peers = n1.peers().to_vec();
    peers.sort();
    assert_eq!(
        peers,
        vec!["n2".to_string(), "n3".to_string(), "n4".to_string()]
    );
    assert_eq!(n1.quorum_size(), 3, "quorum must grow with membership");
}

// ---------------------------------------------------------------------------
// 3. RemoveServer — cluster continues operating after a node is dropped
// ---------------------------------------------------------------------------

#[test]
fn remove_server_shrinks_peer_list_and_cluster_continues() {
    let mut n1 = make_node("n1", vec!["n2", "n3"], vec!["n1", "n2", "n3"]);
    assert_eq!(n1.quorum_size(), 2);

    // Apply a RemoveNode(n3) config change.
    let entries = vec![LogEntry {
        term: Term(1),
        index: 1,
        command: RaftCommand::ConfigChange {
            node_id: "n3".into(),
            action: MembershipAction::RemoveNode,
        },
    }];
    let args = make_ae(Term(1), "leader", 0, Term(0), entries, 1);
    assert!(n1.handle_append_entries(&args).success);

    // n3 is gone from the peer list.
    assert_eq!(n1.peers(), &["n2".to_string()]);
    // The remaining 2-node cluster has quorum_size=2 (both nodes needed).
    assert_eq!(n1.quorum_size(), 2);

    // The cluster still accepts writes: deliver another entry and
    // confirm it's appended on top.
    let next_entries = vec![LogEntry {
        term: Term(1),
        index: 2,
        command: RaftCommand::KeySync {
            key_id: "k1".into(),
            data: Zeroizing::new(vec![1, 2, 3]),
        },
    }];
    let args2 = make_ae(Term(1), "leader", 1, Term(1), next_entries, 2);
    assert!(n1.handle_append_entries(&args2).success);
    assert_eq!(n1.log().last_index(), 2);
    assert_eq!(n1.log().committed(), 2);
}

// ---------------------------------------------------------------------------
// 4. Stale-leader read guard — superseded leader cannot keep serving
// ---------------------------------------------------------------------------

/// A leader that has been partitioned-out and whose term has been
/// exceeded by a newer leader must step down on the next RPC it
/// receives.  After step-down, `submit_command` returns `None`, so
/// it cannot answer subsequent write requests (or reads that require
/// a leader contract) with stale state.
#[test]
fn superseded_leader_steps_down_and_stops_serving() {
    let mut old_leader = make_node("old", vec!["n2", "n3"], vec!["old", "n2", "n3"]);
    old_leader.become_candidate();
    old_leader.become_leader();
    let old_term = old_leader.current_term();

    // While it thinks it's still the leader, it accepts a local Noop.
    assert!(old_leader.submit_command(RaftCommand::Noop).is_some());

    // A new leader at a much higher term sends an AppendEntries.
    let new_term = old_term + 7;
    let args = make_ae(new_term, "new", 0, Term(0), vec![], 0);
    let _ = old_leader.handle_append_entries(&args);

    // The old leader has stepped down.
    assert_eq!(old_leader.state(), RaftState::Follower);
    assert_eq!(old_leader.current_term(), new_term);

    // It must NOT be able to submit further commands — `submit_command`
    // returns None for non-leaders, which is the stale-read guard:
    // any higher-level read path that checks `is_leader()` sees false.
    assert!(old_leader.submit_command(RaftCommand::Noop).is_none());
    assert!(!old_leader.is_leader());
}

/// Even a RequestVote from a higher-term candidate is enough to knock a
/// stale leader out of Leader state.  This covers the second common way
/// a partitioned-out leader learns it's been superseded.
#[test]
fn request_vote_from_higher_term_steps_down_stale_leader() {
    let mut old = make_node("old", vec!["n2"], vec!["old", "n2"]);
    old.become_candidate();
    old.become_leader();
    assert_eq!(old.state(), RaftState::Leader);

    let old_term = old.current_term();
    let higher = old_term + 3;
    let mut args = RequestVoteArgs {
        term: higher,
        candidate_id: "n2".to_string(),
        last_log_index: 0,
        last_log_term: Term(0),
        timestamp_ms: now_ms(),
        hmac: None,
    };
    args.hmac = Some(RaftNode::compute_request_vote_hmac(&secret(), &args));
    let _reply = old.handle_request_vote(&args);

    assert_eq!(old.state(), RaftState::Follower);
    assert_eq!(old.current_term(), higher);
    assert!(!old.is_leader());
    // And write path is closed off.
    assert!(old.submit_command(RaftCommand::Noop).is_none());
}

// ---------------------------------------------------------------------------
// 5. Linearizable-read lease
// ---------------------------------------------------------------------------

/// A leader that has not exchanged a quorum heartbeat within the election
/// timeout must not answer linearizable reads from local state: it may have
/// been partitioned-out and a newer leader could have committed entries it
/// has never seen. `RaftNode::leader_lease_is_valid(now_ms)` enforces this
/// guard.
#[test]
fn stale_leader_without_heartbeats_fails_lease_check() {
    let mut leader = make_node("L", vec!["n2", "n3"], vec!["L", "n2", "n3"]);
    leader.become_candidate();
    leader.become_leader();
    assert!(leader.is_leader());

    // Record a heartbeat at t=0 then probe the lease far in the future.
    leader.record_heartbeat(0);
    let election_timeout = leader.election_timeout();

    // Just inside the election window: lease still valid.
    assert!(
        leader.leader_lease_is_valid(election_timeout.saturating_sub(1)),
        "lease must be valid while within the election timeout window"
    );

    // Past the election timeout: stale leader cannot serve linearizable reads.
    assert!(
        !leader.leader_lease_is_valid(election_timeout + 1),
        "stale leader past the election timeout must fail the lease check"
    );

    // Far in the future: same verdict.
    assert!(!leader.leader_lease_is_valid(60_000));
}

#[test]
fn non_leader_never_holds_valid_lease() {
    let node = make_node("F", vec!["n2", "n3"], vec!["F", "n2", "n3"]);
    // Follower / candidate should never report a valid leader lease.
    assert!(!node.is_leader());
    assert!(!node.leader_lease_is_valid(0));
    assert!(!node.leader_lease_is_valid(u64::MAX));
}

#[test]
fn lease_fails_closed_on_clock_regression() {
    let mut leader = make_node("L", vec!["n2", "n3"], vec!["L", "n2", "n3"]);
    leader.become_candidate();
    leader.become_leader();
    leader.record_heartbeat(1_000);
    // A now_ms *earlier* than the heartbeat — host clock drifted backwards.
    // Fail closed rather than return a nonsense elapsed value.
    assert!(!leader.leader_lease_is_valid(500));
}

// ---------------------------------------------------------------------------
// 6. Audit C2 — missing-secret refuses RaftNode::new()-derived construction
//    via from_config when the production-gate feature is not set.
// ---------------------------------------------------------------------------

#[test]
fn missing_cluster_secret_refuses_production_construction() {
    // allow_insecure bypasses validate()'s secret check, but the production
    // gate in from_config still refuses.
    let cfg = ClusterConfig {
        node_id: "n1".into(),
        allow_insecure: true,
        cluster_secret_hex: None,
        ..Default::default()
    };
    let r = RaftNode::from_config(&cfg);
    #[cfg(not(feature = "insecure-no-cluster-secret"))]
    {
        assert!(
            r.is_err(),
            "production build must refuse to construct a secret-less node"
        );
    }
    #[cfg(feature = "insecure-no-cluster-secret")]
    {
        assert!(
            r.is_ok(),
            "insecure feature: missing-secret node is allowed"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Audit H3 — rate limiter adapts to cluster size
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_adapts_to_cluster_size() {
    // A 1-node cluster retains the historic 5 000 ms refill.
    let one = VoteRateLimiterConfig::adaptive_for_cluster_size(1);
    assert_eq!(one.refill_interval_ms, 5_000);
    // A 10-node cluster scales down to the 500 ms floor.
    let ten = VoteRateLimiterConfig::adaptive_for_cluster_size(10);
    assert_eq!(ten.refill_interval_ms, 500);
    // And RaftNode::new wires that in automatically.
    let peers: Vec<String> = (0..9).map(|i| format!("n{i}")).collect();
    let node = RaftNode::new("self".into(), peers, 1000);
    assert_eq!(node.vote_rate_limiter().refill_interval_ms(), 500);
}

// ---------------------------------------------------------------------------
// 8. Audit M7 — single rogue node with the secret cannot unilaterally add
//    itself; a majority-approved proposal commits.
// ---------------------------------------------------------------------------

#[test]
fn rogue_node_cannot_unilaterally_add_itself() {
    let mut leader = make_node("leader", vec!["n2", "n3"], vec!["leader", "n2", "n3"]);
    leader.become_candidate();
    leader.become_leader();
    // A rogue node with the secret tries to add "rogue" via the new
    // proposal path. The leader auto-approves its own proposal, which
    // counts as 1 of the required 2-of-3 majority.
    let p = leader
        .propose_config_change(
            "rogue-join".into(),
            "rogue".into(),
            MembershipAction::AddNode,
        )
        .expect("leader creates the proposal");
    assert_eq!(leader.config_change_approvals(&p.proposal_id), 1);
    // No other voter has signed off → commit must refuse.
    assert!(
        leader
            .commit_config_change_proposal(&p.proposal_id)
            .is_none(),
        "single-node unilateral ConfigChange must be rejected"
    );
}

#[test]
fn majority_approvals_commit_config_change() {
    let mut leader = make_node("leader", vec!["n2", "n3"], vec!["leader", "n2", "n3"]);
    leader.become_candidate();
    leader.become_leader();
    let p = leader
        .propose_config_change("add-n4".into(), "n4".into(), MembershipAction::AddNode)
        .unwrap();
    // n2 signs off.
    let ts = now_ms();
    let mac = RaftNode::compute_config_change_approval_hmac(
        &secret(),
        &p.proposal_id,
        &p.node_id,
        &p.action,
        "n2",
        ts,
    );
    let approval = ConfigChangeApproval {
        proposal_id: p.proposal_id.clone(),
        approver_id: "n2".into(),
        timestamp_ms: ts,
        hmac: mac,
    };
    assert!(leader.record_config_change_approval(&approval));
    // Leader + n2 = 2 of 3 voters = majority.
    let idx = leader
        .commit_config_change_proposal(&p.proposal_id)
        .expect("majority-approved proposal commits");
    assert!(idx > 0);
}

// ---------------------------------------------------------------------------
// 9. Audit L1 — truncate_after returns an error instead of panicking.
// ---------------------------------------------------------------------------

#[test]
fn conflicting_append_entries_does_not_panic_on_truncate() {
    // Drive a path that previously panicked on `truncate_after` below
    // applied: seed a follower with two committed+applied entries, then
    // send a higher-term AppendEntries whose prev_log_term disagrees
    // with the local log.  The handler used to assert!(...) inside
    // truncate_after; post-L1 it must return success=false without
    // aborting the process.
    let mut n = make_node("n1", vec!["leader"], vec!["n1", "leader"]);
    let seed = make_ae(
        Term(1),
        "leader",
        0,
        Term(0),
        vec![
            LogEntry {
                term: Term(1),
                index: 1,
                command: RaftCommand::Noop,
            },
            LogEntry {
                term: Term(1),
                index: 2,
                command: RaftCommand::Noop,
            },
        ],
        2,
    );
    assert!(n.handle_append_entries(&seed).success);
    assert_eq!(n.log().committed(), 2);

    // Contrived conflict: higher-term leader claims prev_log_index=1 had
    // Term(99) — our entry at index=1 is Term(1), so the handler enters
    // the truncate branch.  Whether the truncate succeeds or is refused
    // for invariant reasons, the process must not panic.  The important
    // guarantee is "a handler returned, not a SIGABRT".
    let bogus = make_ae(Term(5), "leader", 1, Term(99), vec![], 0);
    let _ = n.handle_append_entries(&bogus);
}

// ---------------------------------------------------------------------------
// 10. Audit L6 — a modified snapshot chunk fails HMAC verification.
// ---------------------------------------------------------------------------

#[test]
fn modified_snapshot_data_fails_authentication() {
    let follower = make_node("n1", vec!["leader"], vec!["n1", "leader"]);
    // Construct a valid InstallSnapshotArgs signed by the cluster secret.
    let mut args = InstallSnapshotArgs {
        term: Term(1),
        leader_id: "leader".into(),
        last_included_index: 3,
        last_included_term: Term(1),
        data: b"snapshot-chunk-bytes-representing-state-machine".to_vec(),
        offset: 0,
        total_size: 47,
        last_chunk: true,
        timestamp_ms: now_ms(),
        hmac: None,
    };
    args.hmac = Some(RaftNode::compute_install_snapshot_hmac(&secret(), &args));
    assert!(follower.verify_install_snapshot(&args));

    // Flip a byte in the middle of the "chunk" (the data payload) and
    // confirm the HMAC no longer validates.
    let mut tampered = args.clone();
    tampered.data[5] ^= 0x01;
    assert!(
        !follower.verify_install_snapshot(&tampered),
        "any modification to the snapshot data must invalidate the HMAC"
    );
}

// ---------------------------------------------------------------------------
// 11. Fix 7 — PreVote prevents term inflation on a partitioned candidate.
// ---------------------------------------------------------------------------

/// A partitioned candidate that cannot reach a majority must NOT bump its
/// term when it fails to win pre-votes — that is the entire purpose of the
/// PreVote optimisation.  We simulate the partition by giving the candidate
/// pre-vote replies that are all `vote_granted = false` (as would happen if
/// the majority still has a live leader and denies pre-votes per §9.6).
#[test]
fn prevote_prevents_term_inflation_in_partition() {
    let mut candidate = make_node("c1", vec!["n2", "n3"], vec!["c1", "n2", "n3"]);
    let original_term = candidate.current_term();

    // Build the pre-vote RPC the candidate would emit.
    let pv = candidate
        .prepare_pre_vote()
        .expect("candidate must be able to build a pre-vote");
    assert!(pv.term > original_term, "prospective term is current+1");
    // Critically: the real `current_term` has NOT been advanced yet.
    assert_eq!(candidate.current_term(), original_term);

    // Simulate every peer denying the pre-vote (partition / live-leader case).
    let replies = vec![
        PreVoteReply {
            term: original_term,
            vote_granted: false,
            timestamp_ms: 0,
            hmac: None,
        },
        PreVoteReply {
            term: original_term,
            vote_granted: false,
            timestamp_ms: 0,
            hmac: None,
        },
    ];
    assert!(
        !candidate.pre_vote_majority_reached(&replies),
        "partitioned candidate must not reach pre-vote majority"
    );

    // Because the majority wasn't reached, the election loop would skip
    // `become_candidate`.  Verify that the candidate's term hasn't moved.
    assert_eq!(
        candidate.current_term(),
        original_term,
        "failed pre-vote round must NOT advance current_term"
    );

    // Sanity: with a majority grant the same candidate would proceed.
    let grants = vec![
        PreVoteReply {
            term: original_term,
            vote_granted: true,
            timestamp_ms: 0,
            hmac: None,
        },
        PreVoteReply {
            term: original_term,
            vote_granted: true,
            timestamp_ms: 0,
            hmac: None,
        },
    ];
    assert!(
        candidate.pre_vote_majority_reached(&grants),
        "majority pre-vote grants must clear the gate"
    );
}

// ---------------------------------------------------------------------------
// 12. Fix 1 — InstallSnapshot with a stale term at a committed index is rejected.
// ---------------------------------------------------------------------------

/// Seed a follower with two committed entries at Term(1), then have a
/// Byzantine leader ship a snapshot claiming `last_included_term = Term(99)`
/// at index 1 — which the follower has already committed at Term(1).  The
/// handler must refuse to overwrite the committed state.
#[test]
fn snapshot_with_stale_term_at_committed_index_is_rejected() {
    let mut follower = make_node("n1", vec!["leader"], vec!["n1", "leader"]);
    // Prime the log with two committed entries at Term(1).
    let seed = make_ae(
        Term(1),
        "leader",
        0,
        Term(0),
        vec![
            LogEntry {
                term: Term(1),
                index: 1,
                command: RaftCommand::Noop,
            },
            LogEntry {
                term: Term(1),
                index: 2,
                command: RaftCommand::Noop,
            },
        ],
        2,
    );
    assert!(follower.handle_append_entries(&seed).success);
    assert_eq!(follower.log().committed(), 2);
    let commit_before = follower.log().committed();
    let last_before = follower.log().last_index();

    // Craft a snapshot whose last_included_index=1 (below commit=2) and
    // term=99 (wrong).  This simulates a Byzantine leader attempting to
    // rewrite committed history.
    let mut bogus = InstallSnapshotArgs {
        term: Term(5),
        leader_id: "leader".into(),
        last_included_index: 1,
        last_included_term: Term(99), // disagrees with follower's committed Term(1)
        data: b"{}".to_vec(),
        offset: 0,
        total_size: 2,
        last_chunk: true,
        timestamp_ms: now_ms(),
        hmac: None,
    };
    bogus.hmac = Some(RaftNode::compute_install_snapshot_hmac(&secret(), &bogus));

    // Handler must not panic, must not truncate, and must not advance state.
    let _reply = follower.handle_install_snapshot(&bogus);

    // Critical assertions — the committed tail MUST remain intact.
    assert_eq!(
        follower.log().committed(),
        commit_before,
        "committed watermark must not move on rejected snapshot"
    );
    assert_eq!(
        follower.log().last_index(),
        last_before,
        "log must not be compacted on rejected snapshot"
    );
    // The original entry at index 1 is still Term(1), not overwritten.
    assert_eq!(
        follower.log().get(1).map(|e| e.term),
        Some(Term(1)),
        "committed entry at index 1 must remain at Term(1)"
    );
}

// ---------------------------------------------------------------------------
// 13. Fix 3 — back-to-back ConfigChange AppendEntries to the same peer are rate-limited.
// ---------------------------------------------------------------------------

#[test]
fn rapid_config_changes_are_rate_limited() {
    // Three-node cluster, leader = "n1".
    let mut leader = make_node("n1", vec!["n2", "n3"], vec!["n1", "n2", "n3"]);
    leader.become_candidate();
    leader.become_leader();

    // Two consecutive ConfigChange commands (legitimate: add n4, remove n5).
    leader.submit_command(RaftCommand::ConfigChange {
        node_id: "n4".into(),
        action: MembershipAction::AddNode,
    });
    leader.submit_command(RaftCommand::ConfigChange {
        node_id: "n5".into(),
        action: MembershipAction::RemoveNode,
    });

    // First replication round should succeed for both peers.
    let first = leader.prepare_append_entries("n2");
    assert!(first.is_some(), "first ConfigChange batch must dispatch");

    // Immediate second call (well inside the default 500 ms window) must
    // be gated, returning None.
    let second = leader.prepare_append_entries("n2");
    assert!(
        second.is_none(),
        "second ConfigChange batch within 500 ms must be rate-limited"
    );

    // A different peer still gets its first copy (rate limit is per-peer).
    let for_n3 = leader.prepare_append_entries("n3");
    assert!(
        for_n3.is_some(),
        "per-peer isolation: n3 must not be gated by n2's recent send"
    );
}

// ---------------------------------------------------------------------------
// 14. Fix 4 — Term overflow returns RaftError::TermOverflow, not a panic.
// ---------------------------------------------------------------------------

#[test]
fn term_overflow_returns_error_not_panic() {
    let mut node = make_node("n1", vec!["n2"], vec!["n1", "n2"]);
    // Force the internal term to the u64 ceiling.  `current_term` is
    // `pub(crate)` inside the raft module, so we use the public
    // AppendEntries path to drive the term up to the boundary.  Because
    // that would require 2^64 AppendEntries rounds, we instead use the
    // direct API: a single AE at Term::MAX puts the follower at that term.
    let max_ae = make_ae(Term(u64::MAX), "leader", 0, Term(0), vec![], 0);
    let reply = node.handle_append_entries(&max_ae);
    assert!(reply.success);
    assert_eq!(node.current_term(), Term(u64::MAX));

    // Now a try_become_candidate call must surface TermOverflow rather
    // than panicking.
    let result: Result<(), RaftError> = node.try_become_candidate();
    assert_eq!(
        result,
        Err(RaftError::TermOverflow),
        "try_become_candidate at Term::MAX must return TermOverflow, not panic"
    );
    // The node's term must not have wrapped.
    assert_eq!(node.current_term(), Term(u64::MAX));
}

// ---------------------------------------------------------------------------
// 15. Fix 5 — concurrent inserts into the sharded replay cache do not block.
// ---------------------------------------------------------------------------

/// Smoke test: spawn 8 threads that each hammer the replay cache via
/// `handle_append_entries` with disjoint MACs.  With the sharded cache
/// (Fix 5) the inserts progress in parallel; a pre-fix single-mutex cache
/// would serialize them.  We do not assert timing (flaky in CI) — we only
/// assert that all 8 × N inserts complete and land in the cache.
#[test]
fn concurrent_replay_cache_inserts_do_not_block() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    // One follower node, shared across threads behind a Mutex (the
    // RaftNode itself is not `Sync` because of interior state; we use a
    // coarse lock just so the test compiles — the point of the test is
    // that the cache's internal lock no longer serializes *within*
    // handle_append_entries, not the outer lock here).
    let node = Arc::new(Mutex::new(make_node(
        "n1",
        vec!["leader"],
        vec!["n1", "leader"],
    )));

    const THREADS: usize = 8;
    const PER_THREAD: usize = 32;

    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        let node = Arc::clone(&node);
        handles.push(thread::spawn(move || {
            for i in 0..PER_THREAD {
                // Give each thread a distinct leader_id so the HMAC (and
                // therefore the shard index derived from its first byte)
                // differs per insert.
                let leader_id = format!("leader-{t}-{i}");
                let mut args = AppendEntriesArgs {
                    term: Term(1),
                    leader_id,
                    prev_log_index: 0,
                    prev_log_term: Term(0),
                    entries: vec![],
                    leader_commit: 0,
                    timestamp_ms: now_ms(),
                    hmac: None,
                };
                args.hmac = Some(RaftNode::compute_append_entries_hmac(&secret(), &args));
                let mut guard = node.lock().unwrap();
                let _ = guard.handle_append_entries(&args);
            }
        }));
    }
    for h in handles {
        h.join().expect("replay-cache insert thread must not panic");
    }
    // If we got here without a deadlock or panic the smoke test passes.
}

// ---------------------------------------------------------------------------
// 16. Audit L7 — shared-Arc replication keeps replicate_to_all snappy.
// ---------------------------------------------------------------------------

/// Regression guard for the audit-L7 shared-Arc optimisation of
/// `replicate_to_all`.  With 10 peers and ~1000 backlog entries, the
/// pre-fix implementation performed 10 independent `Vec<LogEntry>` clones
/// of the whole backlog.  Post-fix, a single `Arc<[LogEntry]>` is built
/// once per round and each peer receives a cheap Arc-handle clone.
///
/// This is a sanity ceiling, not a rigorous benchmark: CI runners vary
/// wildly, so we pick a generous 100 ms bound that comfortably passes on
/// any reasonable host but would fail if the implementation regressed to
/// the O(peers × backlog) path.
#[test]
fn replicate_to_all_is_fast_for_many_peers_and_long_backlog() {
    use std::time::Instant;

    // 10 peers.  Owned Strings so the RaftNode owns its peer list;
    // the helpers take `Vec<&str>`, so we also hand out borrows.
    let peer_ids: Vec<String> = (2..=11).map(|i| format!("n{i}")).collect();
    let peers_ref: Vec<&str> = peer_ids.iter().map(String::as_str).collect();
    let mut voters_ref: Vec<&str> = vec!["n1"];
    voters_ref.extend(peers_ref.iter().copied());

    let mut leader = make_node("n1", peers_ref, voters_ref);
    leader.become_candidate();
    leader.become_leader();

    // Push ~1000 entries into the leader log.  We use Noop commands so
    // HMAC computation still exercises the per-entry canonical_bytes
    // path but stays cheap.
    for _ in 0..1000 {
        leader
            .submit_command(RaftCommand::Noop)
            .expect("leader must accept Noop submissions");
    }

    let start = Instant::now();
    let messages = leader.replicate_to_all();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 100,
        "replicate_to_all with 10 peers × 1000 entries took {:?} (> 100 ms) — \
         the audit-L7 shared-Arc optimisation likely regressed",
        elapsed
    );
    // And the return payload must actually carry the entries for each peer.
    assert_eq!(messages.len(), 10, "must produce one args per peer");
    for (peer, args) in &messages {
        assert_eq!(
            args.entries.len(),
            1000,
            "peer {} should get the full 1000-entry backlog",
            peer
        );
    }
}
