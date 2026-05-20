// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! W1 -- `craton_hsm_kmip::server::peer_san_or_cn` round-trips a SAN
//! dnsName through a real self-signed certificate produced by `rcgen`.
//!
//! Locked against refactor regression: the KMIP accept loop relies on
//! this exact identity-extraction contract before it dispatches into
//! `process_message_with_identity`.

use craton_hsm_kmip::server::peer_san_or_cn;

#[test]
fn peer_san_or_cn_round_trips_san_dns() {
    let san = "test-peer.cluster.local";
    let issued =
        rcgen::generate_simple_self_signed(vec![san.to_string()]).expect("rcgen self-signed");
    let der = issued.cert.der();

    let identity = peer_san_or_cn(der.as_ref()).expect("SAN extraction should yield a dnsName");
    assert_eq!(identity, san);
}
