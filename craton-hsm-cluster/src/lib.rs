// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! HSM clustering with Raft consensus for high availability.
//!
//! Provides cluster configuration, Raft-based leader election,
//! key replication, persistent storage, snapshots, state-machine
//! application, and health monitoring for multi-node deployments.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod health;
pub mod raft;
pub mod replication;
pub mod state_machine;
pub mod storage;
