// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! W1 -- `peer_san_or_cn` round-trips a SAN dnsName through a real
//! self-signed certificate produced by `rcgen`.
//!
//! Mints a self-signed cert with a single SAN
//! (`test-peer.cluster.local`), encodes it as DER, then asserts
//! `peer_san_or_cn` returns exactly that SAN. The point is to lock
//! the helper against accidental refactor regressions -- the
//! production accept loop relies on this exact identity-extraction
//! contract before it dispatches into the Raft layer.

use craton_hsm_cluster::replication::peer_san_or_cn;

#[test]
fn peer_san_or_cn_round_trips_san_dns() {
    // rcgen 0.13 -- `generate_simple_self_signed` returns a
    // `CertifiedKey { cert, key_pair }`; `cert.der()` is a
    // `&CertificateDer<'static>`.
    let san = "test-peer.cluster.local";
    let issued =
        rcgen::generate_simple_self_signed(vec![san.to_string()]).expect("rcgen self-signed");
    let der = issued.cert.der();

    let identity = peer_san_or_cn(der.as_ref()).expect("SAN extraction should yield a dnsName");
    assert_eq!(identity, san);
}
