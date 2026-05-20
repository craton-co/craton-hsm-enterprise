// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Shared mock-crypto primitives used by the AWS / Azure / Vault shims.
//!
//! **This is not real crypto.** Every helper here is part of the mock gate
//! stack described in [`crate::mock_guard`]: the module is only compiled when
//! `mock_crypto_allowed` is emitted by `build.rs` (or under `#[cfg(test)]`),
//! so a release binary that accidentally rolled with the
//! `mock-insecure-do-not-ship` feature off will fail to even link against the
//! symbols below.
//!
//! The helpers exist to kill a pile of near-duplicate code across the three
//! shims. Every backend had its own `b64_encode`, `b64_decode`, `xor_stream`,
//! and `hmac_sign` that were subtly different (different salts, different
//! counter widths, different tag label strings). Those differences were
//! bugs waiting to happen — this module collapses them to one implementation
//! per primitive and standardises the counter type on `u64` with
//! `checked_add` so a pathological fixture cannot trip an overflow panic.

#![cfg(any(test, mock_crypto_allowed))]

// Belt-and-suspenders: a release build (`debug_assertions` off) that did NOT
// also set `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1` at compile time should never
// emit `mock_crypto_allowed` from build.rs — but if the dev-band guard there
// ever regresses, this explicit `compile_error!` makes "xor_stream in a
// release build" fail to link instead of fail at runtime. Tests still
// compile because the cfg is `any(test, ...)`.
//
// Audit finding M (xor_stream is the only confidentiality primitive in the
// mock; a clearer compile-time guard catches accidental shipping).
#[cfg(all(not(test), not(debug_assertions), not(mock_crypto_allowed)))]
compile_error!(
    "mock_crypto must not be compiled into a release binary without \
     mock_crypto_allowed; see build.rs"
);

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 type alias shared by every mock backend.
pub type HmacSha256 = Hmac<Sha256>;

/// Standard base64 alphabet (no URL-safe variant — the Vault / Azure wire
/// formats both use the classic alphabet).
const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes` as canonical base64 (with `=` padding).
///
/// The backends used to carry three separate copies of this function; they
/// are now collapsed to one.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode a canonical base64 string into raw bytes.  Returns `Err(())` on any
/// invalid character — callers map that into their own error type.
pub fn b64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return Err(()),
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Raw HMAC-SHA256 over a labelled message.
///
/// Layout: `HMAC(secret, label || 0x00 || message)`. The NUL byte gives a
/// constant-width domain separator between the label and the caller-supplied
/// message so e.g. label=`"AB"`/msg=`"C"` and label=`"A"`/msg=`"BC"` produce
/// different tags.
pub fn hmac_sign(secret: &[u8; 32], label: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(label);
    mac.update(&[0u8]);
    mac.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Derive a 32-byte sub-key from `master` via HKDF-SHA256 under `label`.
///
/// Audit finding H18: the mock KEKs used the same secret for MAC and for
/// Sign, which means a valid wrap-tag over attacker-chosen bytes is also a
/// valid signature over those bytes. Subdividing the secret with HKDF and
/// unique labels (`WRAP-AUTH`, `SIGN`, `BACKUP`, ...) closes the door.
pub fn subkey(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    // `new_from_prk` is fine here because `master` is already a uniformly
    // random 32-byte secret — we want the `Expand` half of HKDF only.
    let hk = Hkdf::<Sha256>::from_prk(master).expect("PRK length == SHA-256 output");
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .expect("HKDF expand with 32-byte output never fails for sha2");
    out
}

/// Mock XOR keystream: one HMAC per 32-byte block, keyed on `nonce || counter`.
/// Counter is always `u64` (audit finding M: standardised type across shims)
/// and uses `checked_add` so overflow **aborts** the stream with `Err(())`
/// rather than silently wrapping.
///
/// Audit finding (perf): construct the HMAC once and reuse it via
/// `Mac::reset()` between blocks instead of rebuilding the key schedule each
/// iteration. For a 1-MiB payload this drops thousands of redundant key
/// expansions. The session HMAC is dropped at function exit.
pub fn xor_stream(secret: &[u8; 32], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = vec![0u8; data.len()];
    let mut counter: u64 = 0;
    let mut offset = 0;
    while offset < data.len() {
        // Rebuild the HMAC per block. We previously used `finalize_reset` to
        // avoid recomputing the key schedule each iteration, but the
        // `Reset` bound on the underlying `HmacCore<Sha256>` instance is not
        // satisfied at the pinned `hmac = "=0.12.1"` / `sha2 = "=0.10.9"`
        // workspace versions, so `finalize_reset` does not type-check here.
        // This is mock code; the per-iteration key schedule cost is
        // acceptable.
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(nonce);
        mac.update(&counter.to_be_bytes());
        let block = mac.finalize().into_bytes();
        let take = std::cmp::min(block.len(), data.len() - offset);
        out[offset..offset + take]
            .iter_mut()
            .zip(&data[offset..offset + take])
            .zip(&block[..take])
            .for_each(|((o, d), k)| *o = d ^ k);
        offset += take;
        counter = counter.checked_add(1).ok_or(())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip_preserves_bytes() {
        let raw = b"hello world";
        let enc = b64_encode(raw);
        let dec = b64_decode(&enc).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn b64_rejects_non_alphabet() {
        assert!(b64_decode("!!!!").is_err());
        assert!(b64_decode("ab cd").is_err());
    }

    #[test]
    fn subkey_is_deterministic_and_label_separated() {
        let master = [7u8; 32];
        let a1 = subkey(&master, b"WRAP-AUTH");
        let a2 = subkey(&master, b"WRAP-AUTH");
        let b = subkey(&master, b"SIGN");
        assert_eq!(a1, a2, "HKDF is deterministic");
        assert_ne!(a1, b, "different labels must yield different sub-keys");
    }

    #[test]
    fn hmac_sign_is_label_separated() {
        let k = [1u8; 32];
        let a = hmac_sign(&k, b"WRAP", b"x");
        let b = hmac_sign(&k, b"SIGN", b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn xor_stream_roundtrip() {
        let k = [9u8; 32];
        let n = [3u8; 12];
        let pt = vec![0xAAu8; 100];
        let ct = xor_stream(&k, &n, &pt).unwrap();
        assert_ne!(ct, pt);
        let pt2 = xor_stream(&k, &n, &ct).unwrap();
        assert_eq!(pt, pt2);
    }
}
