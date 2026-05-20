// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Binary signing and integrity metadata embedding.
//!
//! Signs certified binaries with HMAC-SHA256 and embeds structured metadata
//! as a fixed-layout footer, enabling downstream verification of binary
//! integrity and provenance.
//!
//! ## Envelope format
//!
//! ```text
//! [original binary bytes]                                <-- N bytes
//! [FOOTER_MAGIC = "RHSMSIGN"]                            <-- 8 bytes
//! [FOOTER_VERSION = u8]                                  <-- 1 byte
//! [original_len   = u64 LE]                              <-- 8 bytes  (length of original binary)
//! [metadata_json  = bytes]                               <-- M bytes  (canonical JSON of metadata stub)
//! [metadata_len   = u32 LE]                              <-- 4 bytes
//! [integrity_tag  = 32 bytes]                            <-- HMAC-SHA256 over the *entire* preceding envelope
//! ```
//!
//! The HMAC tag covers **everything** before it (`original || magic ||
//! version || original_len || metadata_json || metadata_len`), so any
//! tampering — including inserting or removing bytes between the original
//! binary and the magic, or nesting an old footer inside a new one — is
//! detected at verification time.
//!
//! `metadata_json` is the *canonical* serialization of [`BinaryMetadata`]
//! with `integrity_tag` set to the empty string. Verification re-derives
//! the canonical JSON the same way, so any divergence in the byte
//! representation (field order, whitespace, escape choices) breaks
//! loudly rather than silently. The canonical encoder
//! ([`canonical_meta_json`]) uses a hand-written serializer with a
//! compile-time-pinned, lexicographically sorted key list rather than
//! relying on `serde`'s field-declaration order, which `serde_json` does
//! not guarantee as a stable wire-format property.

use crate::error::{CertError, CertResult};
use crate::integrity::{compute_hmac_sha256_parts, verify_hmac_sha256_parts};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes prepended to the metadata footer to aid detection.
pub const FOOTER_MAGIC: &[u8; 8] = b"RHSMSIGN";

/// On-disk envelope version. Bump on any layout change.
pub const FOOTER_VERSION: u8 = 1;

/// HMAC-SHA256 tag length in bytes.
const TAG_LEN: usize = 32;

/// Fixed footer overhead = magic + version + original_len + metadata_len + tag.
const FIXED_FOOTER_OVERHEAD: usize = FOOTER_MAGIC.len() + 1 + 8 + 4 + TAG_LEN;

/// Hard upper bound on `metadata_json` length accepted by the parser,
/// independent of total envelope size.  Even a multi-GB binary should
/// carry only a few hundred bytes of metadata; capping here turns an
/// adversarial `meta_len` field into a structural rejection rather than
/// an attempt at giant slice indexing or allocation.
const MAX_META_LEN: usize = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Metadata embedded in a signed binary.
///
/// The on-disk JSON encoding is produced by [`canonical_meta_json`] which
/// emits keys in fixed lexicographic order (independent of struct
/// declaration order), so reordering or renaming fields is still a
/// breaking change but the *struct* layout is no longer the source of
/// truth — the `CANONICAL_KEYS` list in `canonical_meta_json` is.
/// Adding or removing a field requires both updating that list and
/// bumping [`FOOTER_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryMetadata {
    /// Module version string.
    pub module_version: String,
    /// Build timestamp (ISO 8601).
    pub build_timestamp: String,
    /// Git commit hash (short or full).
    pub git_commit: String,
    /// Identifier of the HMAC key used for signing.
    pub hmac_key_id: String,
    /// Hex-encoded HMAC-SHA256 integrity tag (empty during signing; populated
    /// in the returned struct after [`sign_binary`]).
    pub integrity_tag: String,
}

// ---------------------------------------------------------------------------
// Canonical metadata serialization
// ---------------------------------------------------------------------------

/// Produce the canonical JSON encoding of a [`BinaryMetadata`] used by both
/// signing and verification, with `integrity_tag` forced to the empty string.
///
/// This intentionally avoids `serde_json::to_vec(&self)` because Serde
/// derives serialize fields in struct-declaration order, which is a fragile
/// guarantee for a wire format.  Instead, we emit a manually-constructed
/// JSON object with the field set fixed at compile time (any addition or
/// removal is a build error) and the keys sorted lexicographically.
fn canonical_meta_json(meta: &BinaryMetadata) -> CertResult<Vec<u8>> {
    // Compile-time pinned canonical key list. Adding or removing a field
    // forces the developer to bump `FOOTER_VERSION` and update this list.
    const CANONICAL_KEYS: [&str; 5] = [
        "build_timestamp",
        "git_commit",
        "hmac_key_id",
        "integrity_tag",
        "module_version",
    ];
    debug_assert!(
        CANONICAL_KEYS.windows(2).all(|w| w[0] < w[1]),
        "canonical metadata key list must remain lexicographically sorted",
    );

    let mut out = Vec::with_capacity(256);
    out.push(b'{');
    for (i, key) in CANONICAL_KEYS.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        // Field names are pure ASCII identifiers; no JSON-escaping needed.
        out.push(b'"');
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(b"\":");
        let value: &str = match *key {
            "build_timestamp" => meta.build_timestamp.as_str(),
            "git_commit" => meta.git_commit.as_str(),
            "hmac_key_id" => meta.hmac_key_id.as_str(),
            // `integrity_tag` is *always* the empty string in the canonical
            // form regardless of what the caller passed in, so signing and
            // verification produce byte-identical envelopes.
            "integrity_tag" => "",
            "module_version" => meta.module_version.as_str(),
            _ => unreachable!("canonical key list out of sync with match arms"),
        };
        json_encode_string(&mut out, value);
    }
    out.push(b'}');
    Ok(out)
}

/// Minimal RFC 8259-compliant JSON string encoder for ASCII / UTF-8 input.
///
/// Escapes the standard JSON escape set (`"`, `\`, control characters,
/// `\b`, `\f`, `\n`, `\r`, `\t`). Other Unicode code points are emitted
/// as-is via their UTF-8 bytes, which is permitted by RFC 8259 §7.
fn json_encode_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0c' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                // Other C0 controls — emit as a \u00XX escape.
                use std::io::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                // Encode the char as UTF-8 directly.
                let mut buf = [0u8; 4];
                let s_utf8 = c.encode_utf8(&mut buf);
                out.extend_from_slice(s_utf8.as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign a binary (as bytes) and produce metadata.
///
/// Computes HMAC-SHA256 over the full envelope-prefix (original binary,
/// magic, version, length fields, and canonical metadata JSON) so any
/// tampering with binary content **or** metadata is detected.
pub fn sign_binary(
    binary_data: &[u8],
    hmac_key: &[u8],
    module_version: &str,
    build_timestamp: &str,
    git_commit: &str,
    hmac_key_id: &str,
) -> CertResult<BinaryMetadata> {
    let stub = BinaryMetadata {
        module_version: module_version.to_string(),
        build_timestamp: build_timestamp.to_string(),
        git_commit: git_commit.to_string(),
        hmac_key_id: hmac_key_id.to_string(),
        integrity_tag: String::new(),
    };
    let meta_json = canonical_meta_json(&stub)?;

    let original_len = (binary_data.len() as u64).to_le_bytes();
    let meta_len = (meta_json.len() as u32).to_le_bytes();

    let parts: &[&[u8]] = &[
        binary_data,
        FOOTER_MAGIC,
        &[FOOTER_VERSION],
        &original_len,
        &meta_json,
        &meta_len,
    ];
    let tag = compute_hmac_sha256_parts(hmac_key, parts)?;
    Ok(BinaryMetadata {
        integrity_tag: crate::hex_util::hex_encode(&tag),
        ..stub
    })
}

/// Sign a binary file on disk and produce metadata.
///
/// Reads the file at `binary_path`, computes the envelope HMAC, and returns
/// [`BinaryMetadata`].
pub fn sign_binary_file(
    binary_path: &Path,
    hmac_key: &[u8],
    module_version: &str,
    build_timestamp: &str,
    git_commit: &str,
    hmac_key_id: &str,
) -> CertResult<BinaryMetadata> {
    let data = std::fs::read(binary_path)?;
    sign_binary(
        &data,
        hmac_key,
        module_version,
        build_timestamp,
        git_commit,
        hmac_key_id,
    )
}

// ---------------------------------------------------------------------------
// Embedding
// ---------------------------------------------------------------------------

/// Embed metadata into a binary, producing a new signed binary.
///
/// The returned `Vec<u8>` is the full envelope; see the module-level docs
/// for the exact byte layout.
pub fn embed_metadata(binary_data: &[u8], metadata: &BinaryMetadata) -> CertResult<Vec<u8>> {
    let meta_json = canonical_meta_json(metadata)?;
    let original_len = (binary_data.len() as u64).to_le_bytes();
    let meta_len = (meta_json.len() as u32).to_le_bytes();

    // Decode the integrity tag directly into a stack-allocated `[u8; 32]`
    // to avoid the per-call `Vec` allocation that `hex_decode` would
    // otherwise produce.
    let tag = hex_decode_tag(&metadata.integrity_tag)?;

    let total_len = binary_data.len() + FIXED_FOOTER_OVERHEAD + meta_json.len();
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(binary_data);
    output.extend_from_slice(FOOTER_MAGIC);
    output.push(FOOTER_VERSION);
    output.extend_from_slice(&original_len);
    output.extend_from_slice(&meta_json);
    output.extend_from_slice(&meta_len);
    output.extend_from_slice(&tag);
    Ok(output)
}

/// Decode a 64-hex-character integrity tag into a fixed-size 32-byte
/// array without allocating a `Vec<u8>` per call.
fn hex_decode_tag(hex: &str) -> CertResult<[u8; TAG_LEN]> {
    let bytes = hex.as_bytes();
    if bytes.len() != TAG_LEN * 2 {
        return Err(CertError::BadEnvelope("integrity_tag must be 32 bytes"));
    }
    let mut out = [0u8; TAG_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = nibble_from_ascii(bytes[2 * i]).ok_or(CertError::BadEnvelope(
            "integrity_tag contains non-hex byte",
        ))?;
        let lo = nibble_from_ascii(bytes[2 * i + 1]).ok_or(CertError::BadEnvelope(
            "integrity_tag contains non-hex byte",
        ))?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

#[inline]
fn nibble_from_ascii(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Parsing / extraction
// ---------------------------------------------------------------------------

/// Parsed envelope view (zero-copy slices into the input bytes).
struct ParsedEnvelope<'a> {
    original: &'a [u8],
    magic: &'a [u8],
    version: u8,
    original_len_bytes: &'a [u8; 8],
    meta_json: &'a [u8],
    meta_len_bytes: &'a [u8; 4],
    tag: &'a [u8],
    metadata: BinaryMetadata,
}

fn parse_envelope(signed: &[u8]) -> CertResult<ParsedEnvelope<'_>> {
    if signed.len() < FIXED_FOOTER_OVERHEAD {
        return Err(CertError::BadEnvelope(
            "binary too short to contain envelope",
        ));
    }

    // Trailing tag
    let tag_start = signed.len() - TAG_LEN;
    let tag = &signed[tag_start..];

    // metadata_len just before the tag
    let meta_len_off = tag_start - 4;
    let meta_len_bytes: &[u8; 4] = signed[meta_len_off..meta_len_off + 4]
        .try_into()
        .map_err(|_| CertError::BadEnvelope("failed to read metadata length"))?;
    let meta_len = u32::from_le_bytes(*meta_len_bytes) as usize;

    // Hard cap on metadata length, independent of total envelope length.
    // This rejects an adversarial `meta_len` claim before we attempt to
    // slice into the buffer or run JSON parsing on a giant blob.
    if meta_len > MAX_META_LEN {
        return Err(CertError::BadEnvelope("metadata length exceeds 1 MiB cap"));
    }

    // metadata_json
    if meta_len > meta_len_off {
        return Err(CertError::BadEnvelope("metadata length exceeds envelope"));
    }
    let meta_json_off = meta_len_off - meta_len;
    let meta_json = &signed[meta_json_off..meta_len_off];

    // original_len just before metadata_json
    if meta_json_off < 8 {
        return Err(CertError::BadEnvelope(
            "envelope truncated before original_len",
        ));
    }
    let orig_len_off = meta_json_off - 8;
    let orig_len_bytes: &[u8; 8] = signed[orig_len_off..orig_len_off + 8]
        .try_into()
        .map_err(|_| CertError::BadEnvelope("failed to read original length"))?;
    // Guard the `u64 -> usize` cast: on a 32-bit target, an envelope from
    // a 64-bit producer could legitimately claim an original length larger
    // than the local address space. Without this check, the cast would
    // silently truncate.
    let original_len_u64 = u64::from_le_bytes(*orig_len_bytes);
    if original_len_u64 > usize::MAX as u64 {
        return Err(CertError::BadEnvelope(
            "declared original length exceeds platform usize range",
        ));
    }
    let original_len = original_len_u64 as usize;

    // version byte just before original_len
    if orig_len_off < 1 {
        return Err(CertError::BadEnvelope("envelope truncated before version"));
    }
    let version_off = orig_len_off - 1;
    let version = signed[version_off];
    // Reject any envelope version we don't understand at parse time, so
    // every consumer (extract_metadata, extract_original_binary,
    // verify_signed_binary) is protected — not just verification.
    if version != FOOTER_VERSION {
        return Err(CertError::BadEnvelope("unsupported envelope version"));
    }

    // magic just before version
    if version_off < FOOTER_MAGIC.len() {
        return Err(CertError::BadEnvelope("envelope truncated before magic"));
    }
    let magic_off = version_off - FOOTER_MAGIC.len();
    let magic = &signed[magic_off..version_off];
    if magic != FOOTER_MAGIC.as_slice() {
        return Err(CertError::BadEnvelope("footer magic bytes not found"));
    }

    // original binary
    if original_len != magic_off {
        // The declared original length must exactly equal the bytes before
        // the magic — this is what blocks insertion of stray bytes between
        // the original binary and the footer.
        return Err(CertError::BadEnvelope(
            "declared original length does not match envelope offset",
        ));
    }
    let original = &signed[..magic_off];

    // Parse the JSON itself. The on-disk JSON has `integrity_tag = ""` by
    // construction (see `canonical_meta_json`); reconstruct it from the
    // trailing tag bytes so callers of `extract_metadata` see the same
    // struct that was originally signed.
    let mut metadata: BinaryMetadata = serde_json::from_slice(meta_json)?;
    metadata.integrity_tag = crate::hex_util::hex_encode(tag);

    Ok(ParsedEnvelope {
        original,
        magic,
        version,
        original_len_bytes: orig_len_bytes,
        meta_json,
        meta_len_bytes,
        tag,
        metadata,
    })
}

/// Extract metadata from a signed binary **without authenticating** it.
///
/// # Security
///
/// This function is **unauthenticated**: it reads metadata fields directly
/// from the envelope footer with no HMAC verification. The returned values
/// (including `module_version`, `git_commit`, etc.) must be treated as
/// attacker-controlled until [`verify_signed_binary`] (or
/// [`verify_and_extract`]) has succeeded against the same byte slice using
/// the correct HMAC key.
///
/// Use [`verify_and_extract`] instead whenever the metadata will drive any
/// trust decision — version compares, deployment gating, audit logging
/// based on the embedded `git_commit`, etc.
pub fn extract_metadata(signed_binary: &[u8]) -> CertResult<BinaryMetadata> {
    let env = parse_envelope(signed_binary)?;
    Ok(env.metadata)
}

/// Extract the original binary portion (without the envelope footer).
pub fn extract_original_binary(signed_binary: &[u8]) -> CertResult<Vec<u8>> {
    let env = parse_envelope(signed_binary)?;
    Ok(env.original.to_vec())
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify the integrity of a signed binary **and** return the embedded
/// metadata. Call sites that want to act on metadata should prefer this
/// over [`extract_metadata`] (which does not verify the tag).
pub fn verify_and_extract(signed_binary: &[u8], hmac_key: &[u8]) -> CertResult<BinaryMetadata> {
    verify_signed_binary(signed_binary, hmac_key)?;
    extract_metadata(signed_binary)
}

/// Verify the integrity of a signed binary.
///
/// Re-parses the envelope, recomputes the canonical metadata JSON from the
/// parsed [`BinaryMetadata`], and constant-time compares the resulting HMAC
/// tag against the embedded one.
///
/// Returns `Ok(())` on success, [`CertError::HmacMismatch`] on tag mismatch,
/// and [`CertError::BadEnvelope`] on any structural problem.
pub fn verify_signed_binary(signed_binary: &[u8], hmac_key: &[u8]) -> CertResult<()> {
    let env = parse_envelope(signed_binary)?;
    // `parse_envelope` already rejects unknown envelope versions, so by the
    // time we reach here `env.version == FOOTER_VERSION`.

    // Rebuild the canonical metadata JSON from the parsed struct and compare
    // it byte-for-byte with what we found on disk. This guards against
    // alternative serializations of the same JSON content.
    let recanonical = canonical_meta_json(&env.metadata)?;
    if recanonical != env.meta_json {
        return Err(CertError::BadEnvelope("metadata JSON is not canonical"));
    }

    // Recompute the HMAC over the full prefix.
    let parts: &[&[u8]] = &[
        env.original,
        env.magic,
        &[env.version],
        env.original_len_bytes,
        env.meta_json,
        env.meta_len_bytes,
    ];
    verify_hmac_sha256_parts(hmac_key, parts, env.tag)
}

/// A parsed `MAJOR.MINOR.PATCH` version triple used for rollback policy
/// comparisons. Each component is a `u32`; trailing components default
/// to zero so that `"2"` parses as `(2, 0, 0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SemVerTriple(u32, u32, u32);

impl SemVerTriple {
    /// Parse `s` as `MAJOR[.MINOR[.PATCH]]`. Each present component must
    /// be a decimal `u32`. Any extra `.`-separated components are
    /// rejected. Pre-release / build metadata (`-`, `+` suffixes) are
    /// **not** supported and are rejected — the firmware metadata format
    /// is intentionally numeric-only for policy comparisons.
    fn parse(s: &str) -> Result<Self, &'static str> {
        // Reject pre-release / build-metadata extensions outright. We
        // want versions like "1.2.3-rc1" to fail loudly when a rollback
        // policy is set, rather than silently mis-comparing.
        if s.contains('-') || s.contains('+') {
            return Err(
                "module_version pre-release/build metadata is not supported by the rollback policy",
            );
        }
        let mut parts = s.split('.');
        let major_str = parts.next().ok_or("module_version is empty")?;
        let major: u32 = major_str
            .parse()
            .map_err(|_| "module_version major is not a non-negative integer")?;
        let minor: u32 = match parts.next() {
            Some(m) => m
                .parse()
                .map_err(|_| "module_version minor is not a non-negative integer")?,
            None => 0,
        };
        let patch: u32 = match parts.next() {
            Some(p) => p
                .parse()
                .map_err(|_| "module_version patch is not a non-negative integer")?,
            None => 0,
        };
        if parts.next().is_some() {
            return Err("module_version has more than three components");
        }
        Ok(SemVerTriple(major, minor, patch))
    }
}

/// Explicit firmware rollback policy.
///
/// Callers pass this enum to [`verify_signed_binary_with_rollback_policy`]
/// to make their intent unambiguous at the call site. The previous API
/// (`Option<u32>`) made it too easy to accidentally pass `None` and
/// silently disable rollback protection altogether; this enum forces the
/// caller to choose [`RollbackPolicy::AnyVersion`] explicitly when that
/// is the desired behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackPolicy {
    /// Accept any module version — no rollback floor is enforced.
    /// Equivalent to the legacy `verify_signed_binary_with_policy(_, _, None)`
    /// call but spelt explicitly so reviewers can spot it.
    AnyVersion,
    /// Reject any module version whose `MAJOR` is below the given
    /// integer. The version's `MINOR.PATCH` components are not
    /// constrained — i.e. `AtLeast(2)` accepts `2.0.0`, `2.7.3`, and
    /// `3.x.y`, and rejects anything `1.x.y` or lower.
    AtLeast(u32),
}

/// Variant of [`verify_signed_binary`] that additionally rejects
/// firmware whose `module_version` is below the rollback floor encoded
/// in `policy` (audit V5).
///
/// `module_version` is parsed as `MAJOR.MINOR.PATCH` (with absent
/// trailing components defaulting to `0`) and compared component-wise
/// against the policy minimum. The comparison is the standard semver
/// ordering. Non-numeric components are rejected as
/// [`CertError::BadEnvelope`] when a non-`AnyVersion` policy is set.
///
/// This is the preferred entry point for new code. The deprecated
/// [`verify_signed_binary_with_policy`] forwards here.
pub fn verify_signed_binary_with_rollback_policy(
    signed_binary: &[u8],
    hmac_key: &[u8],
    policy: RollbackPolicy,
) -> CertResult<()> {
    let min_triple = match policy {
        RollbackPolicy::AnyVersion => None,
        RollbackPolicy::AtLeast(major) => Some((major, 0u32, 0u32)),
    };
    verify_signed_binary_with_min_version(signed_binary, hmac_key, min_triple)
}

/// Legacy `Option<u32>` rollback-policy entry point.
///
/// Use [`verify_signed_binary_with_rollback_policy`] in new code. This
/// function is preserved as a thin shim so existing callers continue
/// to compile, but the explicit [`RollbackPolicy`] enum is required to
/// review-proof the call site: `Some(n)` maps to
/// [`RollbackPolicy::AtLeast(n)`] and `None` maps to
/// [`RollbackPolicy::AnyVersion`].
#[deprecated(
    since = "0.1.2",
    note = "use `verify_signed_binary_with_rollback_policy` with `RollbackPolicy::{AnyVersion, AtLeast}` to make rollback intent explicit"
)]
pub fn verify_signed_binary_with_policy(
    signed_binary: &[u8],
    hmac_key: &[u8],
    min_version: Option<u32>,
) -> CertResult<()> {
    let policy = match min_version {
        Some(n) => RollbackPolicy::AtLeast(n),
        None => RollbackPolicy::AnyVersion,
    };
    verify_signed_binary_with_rollback_policy(signed_binary, hmac_key, policy)
}

/// Variant of [`verify_signed_binary_with_policy`] that accepts a full
/// `(major, minor, patch)` minimum-version triple. Semantics are
/// otherwise identical.
pub fn verify_signed_binary_with_min_version(
    signed_binary: &[u8],
    hmac_key: &[u8],
    min_version: Option<(u32, u32, u32)>,
) -> CertResult<()> {
    // Parse the envelope once and reuse the result for both HMAC
    // verification and the policy comparison. The previous implementation
    // called `verify_signed_binary` (which itself parses) and then
    // `parse_envelope` a second time.
    let env = parse_envelope(signed_binary)?;

    // Rebuild canonical JSON and constant-time-compare the HMAC, exactly
    // as `verify_signed_binary` does — but using the already-parsed
    // envelope.
    let recanonical = canonical_meta_json(&env.metadata)?;
    if recanonical != env.meta_json {
        return Err(CertError::BadEnvelope("metadata JSON is not canonical"));
    }
    let parts: &[&[u8]] = &[
        env.original,
        env.magic,
        &[env.version],
        env.original_len_bytes,
        env.meta_json,
        env.meta_len_bytes,
    ];
    verify_hmac_sha256_parts(hmac_key, parts, env.tag)?;

    // HMAC has passed — the metadata is now authenticated. Apply the
    // rollback policy.
    let Some((min_major, min_minor, min_patch)) = min_version else {
        return Ok(());
    };
    let min_triple = SemVerTriple(min_major, min_minor, min_patch);

    let parsed = SemVerTriple::parse(&env.metadata.module_version).map_err(|_| {
        CertError::BadEnvelope("module_version major is not a non-negative integer")
    })?;
    if parsed < min_triple {
        return Err(CertError::BadEnvelope(
            "module_version below min_version (rollback rejected)",
        ));
    }
    Ok(())
}

/// Convenience: sign, embed, and return the resulting envelope bytes.
pub fn sign_and_embed(
    binary_data: &[u8],
    hmac_key: &[u8],
    module_version: &str,
    build_timestamp: &str,
    git_commit: &str,
    hmac_key_id: &str,
) -> CertResult<Vec<u8>> {
    let meta = sign_binary(
        binary_data,
        hmac_key,
        module_version,
        build_timestamp,
        git_commit,
        hmac_key_id,
    )?;
    embed_metadata(binary_data, &meta)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // 32-byte test key — meets the minimum key length for HMAC-SHA256.
    const TEST_KEY: &[u8] = b"test-hmac-key-for-binary-signing";
    const TEST_BINARY: &[u8] = b"ELF fake binary content for testing purposes 0123456789";

    fn test_metadata() -> BinaryMetadata {
        sign_binary(
            TEST_BINARY,
            TEST_KEY,
            "0.1.0",
            "2026-03-26T00:00:00Z",
            "abc1234",
            "key-001",
        )
        .unwrap()
    }

    #[test]
    fn sign_produces_valid_metadata() {
        let meta = test_metadata();
        assert_eq!(meta.module_version, "0.1.0");
        assert_eq!(meta.git_commit, "abc1234");
        assert_eq!(meta.hmac_key_id, "key-001");
        // HMAC-SHA256 tag is 32 bytes = 64 hex chars
        assert_eq!(meta.integrity_tag.len(), 64);
        assert!(meta.integrity_tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn embed_extract_roundtrip() {
        let meta = test_metadata();
        let signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        let extracted = extract_metadata(&signed).unwrap();
        assert_eq!(extracted, meta);
    }

    #[test]
    fn verify_valid_signed_binary() {
        let meta = test_metadata();
        let signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        verify_signed_binary(&signed, TEST_KEY).unwrap();
    }

    #[test]
    fn tampered_binary_byte_detected() {
        let meta = test_metadata();
        let mut signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        signed[0] ^= 0xFF;
        assert!(matches!(
            verify_signed_binary(&signed, TEST_KEY),
            Err(CertError::HmacMismatch | CertError::BadEnvelope(_))
        ));
    }

    #[test]
    fn tampered_metadata_field_detected() {
        // Re-embed with a doctored metadata struct (changing a field that the
        // original tag was not computed over). Verification must reject.
        let meta = test_metadata();
        let mut tampered_meta = meta.clone();
        tampered_meta.git_commit = "malicious-commit".to_string();
        // Re-use the original (valid for the unmodified meta) tag — but
        // embed it with the tampered metadata.
        let signed = embed_metadata(TEST_BINARY, &tampered_meta).unwrap();
        // The embedded tag in `tampered_meta` was sourced from `meta` (same
        // hex string), but the canonical JSON differs, so verification must
        // fail.
        assert!(verify_signed_binary(&signed, TEST_KEY).is_err());
    }

    #[test]
    fn inserted_bytes_between_binary_and_footer_detected() {
        // The classic splice attack from the security review: insert junk
        // bytes between the original binary and the footer magic. The
        // declared original_len in the footer points at the *original* end,
        // so parse_envelope's length-equality check rejects it.
        let meta = test_metadata();
        let signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&signed[..TEST_BINARY.len()]);
        tampered.extend_from_slice(b"INJECTED");
        tampered.extend_from_slice(&signed[TEST_BINARY.len()..]);
        let err = verify_signed_binary(&tampered, TEST_KEY).unwrap_err();
        assert!(matches!(err, CertError::BadEnvelope(_)));
    }

    #[test]
    fn double_signing_treats_inner_envelope_as_opaque_payload() {
        // Sign once, then re-sign the signed output. The outer envelope
        // treats the inner signed bytes as opaque payload — they verify
        // because they were faithfully preserved, not because the outer
        // verifier "saw through" the inner footer.
        let meta = test_metadata();
        let inner = embed_metadata(TEST_BINARY, &meta).unwrap();
        let outer_meta = sign_binary(&inner, TEST_KEY, "0.1.0", "ts", "g", "k2").unwrap();
        let outer = embed_metadata(&inner, &outer_meta).unwrap();
        // Outer verifies as a single layer.
        verify_signed_binary(&outer, TEST_KEY).unwrap();
        // The extracted "original" of the outer is the inner signed
        // envelope, which itself verifies independently with the same key.
        let extracted_inner = extract_original_binary(&outer).unwrap();
        assert_eq!(extracted_inner, inner);
        verify_signed_binary(&inner, TEST_KEY).unwrap();
    }

    #[test]
    fn unknown_envelope_version_rejected_at_parse_time() {
        let meta = test_metadata();
        let mut signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        // The version byte sits at:
        //   len - TAG_LEN - 4 (meta_len) - meta_json.len() - 8 (orig_len) - 1 (version)
        // Recompute via extract_metadata reading the parsed structure: the
        // simplest robust approach is to scan for the magic bytes and bump
        // the byte that follows them.
        let pos = signed
            .windows(FOOTER_MAGIC.len())
            .position(|w| w == FOOTER_MAGIC.as_slice())
            .expect("magic must be present");
        signed[pos + FOOTER_MAGIC.len()] = 0xFE; // bogus version
        let err = extract_metadata(&signed).unwrap_err();
        assert!(matches!(err, CertError::BadEnvelope(_)));
        // The same payload must also be rejected by verify_signed_binary —
        // not just by extract_metadata — so version skew can't be smuggled
        // past the verifier either.
        let err = verify_signed_binary(&signed, TEST_KEY).unwrap_err();
        assert!(matches!(err, CertError::BadEnvelope(_)));
    }

    #[test]
    fn wrong_key_rejected() {
        let meta = test_metadata();
        let signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        assert!(matches!(
            verify_signed_binary(&signed, b"wrong-key-value-that-is-32bytes!"),
            Err(CertError::HmacMismatch)
        ));
    }

    #[test]
    fn short_key_rejected() {
        assert!(matches!(
            sign_binary(TEST_BINARY, b"short", "v", "t", "g", "k"),
            Err(CertError::KeyTooShort { .. })
        ));
    }

    #[test]
    fn missing_metadata_error() {
        let result = extract_metadata(TEST_BINARY);
        assert!(result.is_err());
    }

    #[test]
    fn empty_binary_sign_and_verify() {
        let meta =
            sign_binary(b"", TEST_KEY, "0.0.1", "2026-01-01T00:00:00Z", "000", "k0").unwrap();
        let signed = embed_metadata(b"", &meta).unwrap();
        let extracted = extract_metadata(&signed).unwrap();
        assert_eq!(extracted, meta);
        verify_signed_binary(&signed, TEST_KEY).unwrap();
    }

    #[test]
    fn metadata_serialization_roundtrip() {
        let meta = test_metadata();
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: BinaryMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn too_short_binary_error() {
        assert!(extract_metadata(b"").is_err());
        assert!(extract_metadata(b"abc").is_err());
        assert!(verify_signed_binary(b"short", TEST_KEY).is_err());
    }

    #[test]
    fn corrupted_footer_length_error() {
        let meta = test_metadata();
        let mut signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        // Corrupt the metadata length (4 bytes immediately before the 32-byte tag).
        let len = signed.len();
        let off = len - TAG_LEN - 4;
        signed[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(extract_metadata(&signed).is_err());
    }

    #[test]
    fn sign_binary_file_with_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, TEST_BINARY).unwrap();

        let meta = sign_binary_file(
            &path,
            TEST_KEY,
            "0.1.0",
            "2026-03-26T00:00:00Z",
            "abc1234",
            "k1",
        )
        .unwrap();
        assert_eq!(meta.module_version, "0.1.0");
        assert_eq!(meta.integrity_tag.len(), 64);

        let signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        verify_signed_binary(&signed, TEST_KEY).unwrap();
    }

    #[test]
    fn original_binary_preserved_in_signed() {
        let meta = test_metadata();
        let signed = embed_metadata(TEST_BINARY, &meta).unwrap();
        let original = extract_original_binary(&signed).unwrap();
        assert_eq!(original, TEST_BINARY);
    }

    #[test]
    fn sign_and_embed_helper_roundtrip() {
        let envelope = sign_and_embed(
            TEST_BINARY,
            TEST_KEY,
            "0.1.0",
            "2026-03-26T00:00:00Z",
            "abc1234",
            "k1",
        )
        .unwrap();
        verify_signed_binary(&envelope, TEST_KEY).unwrap();
    }

    #[test]
    fn truncated_tail_detected() {
        let envelope = sign_and_embed(TEST_BINARY, TEST_KEY, "0.1.0", "ts", "g", "k").unwrap();
        let truncated = &envelope[..envelope.len() - 1];
        assert!(verify_signed_binary(truncated, TEST_KEY).is_err());
    }

    #[test]
    fn tag_byte_flip_detected() {
        let mut envelope = sign_and_embed(TEST_BINARY, TEST_KEY, "0.1.0", "ts", "g", "k").unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        assert!(matches!(
            verify_signed_binary(&envelope, TEST_KEY),
            Err(CertError::HmacMismatch)
        ));
    }

    #[test]
    fn rollback_policy_any_version_accepts_anything() {
        let env = sign_and_embed(TEST_BINARY, TEST_KEY, "0.0.1", "ts", "g", "k").unwrap();
        verify_signed_binary_with_rollback_policy(&env, TEST_KEY, RollbackPolicy::AnyVersion)
            .unwrap();
    }

    #[test]
    fn rollback_policy_at_least_rejects_older() {
        let env = sign_and_embed(TEST_BINARY, TEST_KEY, "1.2.3", "ts", "g", "k").unwrap();
        let err =
            verify_signed_binary_with_rollback_policy(&env, TEST_KEY, RollbackPolicy::AtLeast(2))
                .unwrap_err();
        assert!(
            matches!(err, CertError::BadEnvelope(msg) if msg.contains("rollback")),
            "expected rollback rejection, got {err:?}"
        );
    }

    #[test]
    fn rollback_policy_at_least_accepts_equal_or_newer() {
        let env = sign_and_embed(TEST_BINARY, TEST_KEY, "3.0.0", "ts", "g", "k").unwrap();
        verify_signed_binary_with_rollback_policy(&env, TEST_KEY, RollbackPolicy::AtLeast(2))
            .unwrap();
        verify_signed_binary_with_rollback_policy(&env, TEST_KEY, RollbackPolicy::AtLeast(3))
            .unwrap();
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_option_u32_shim_maps_correctly() {
        // The deprecated `Option<u32>` shim must produce the same
        // verdicts as the explicit-enum entry point.
        let env = sign_and_embed(TEST_BINARY, TEST_KEY, "2.5.0", "ts", "g", "k").unwrap();
        verify_signed_binary_with_policy(&env, TEST_KEY, None).unwrap();
        verify_signed_binary_with_policy(&env, TEST_KEY, Some(2)).unwrap();
        assert!(verify_signed_binary_with_policy(&env, TEST_KEY, Some(3)).is_err());
    }
}
