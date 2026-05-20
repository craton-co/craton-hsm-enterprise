// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//
// Fuzz harness for the TTLV parser.
//
// The KMIP wire format is the only attacker-facing parser this crate
// exposes. The harness feeds arbitrary bytes into `decode_ttlv` and
// asserts only that the call does not panic; legitimate errors are
// expected on virtually all inputs.
//
// Run with:
//   cargo +nightly fuzz run ttlv_decode

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Entry point promised at src/ttlv.rs:995.
    let _ = craton_hsm_kmip::ttlv::decode_ttlv(data);
});
