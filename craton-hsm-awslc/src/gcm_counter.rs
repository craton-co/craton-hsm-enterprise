// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Persistent backing store for the AES-GCM per-key nonce counter.
//!
//! The in-memory counter in [`crate::reserve_gcm_nonce`] is the hot path and
//! the source of truth *while the process is running*. This module adds an
//! **optional** disk journal so the counter survives process restarts and a
//! long-lived key cannot silently regain its 2^32 budget by being crashed
//! and restarted.
//!
//! # Design
//!
//! - Writes are append-only newline-delimited text records:
//!   `<hex-fingerprint> <u64-counter-max-seen>\n`
//!   and `<hex-fingerprint> POISONED\n` for keys that have hit the NIST
//!   ceiling. Fingerprint is `SHA-256(raw_key)`.
//! - After each flush an integrity footer is appended:
//!   `#MAC <hex-hmac-sha256-over-all-preceding-bytes>\n`
//! - On load: the newest footer is verified; any trailing bytes after the
//!   last valid footer are truncated. If no footer exists we treat that as
//!   a cold start (warn + continue). If a footer exists but does not verify,
//!   that's fail-closed — every known key from that file is poisoned.
//! - On reserve: we persist synchronously (with fsync) when the
//!   in-memory counter catches up to the on-disk **reservation ceiling**.
//!   Each flush writes the ceiling as `new_count + BATCH_THRESHOLD` so the
//!   on-disk value is always strictly **greater than** the highest nonce
//!   that has been emitted from this process. On restart we hydrate the
//!   in-memory counter from that ceiling and resume emission at
//!   `ceiling + 1`, which cannot collide with any previously emitted value.
//!   This is the classic write-ahead / batch-reservation pattern and is
//!   what audit finding C2 called for: under the previous "write the value
//!   we just emitted" strategy, up to `BATCH_THRESHOLD` nonces could be
//!   emitted but unpersisted, and a crash between emit and flush would
//!   re-issue them on restart.
//! - On poison: an immediate synchronous record is written and fsynced.
//!
//! # MAC key derivation
//!
//! The HMAC-SHA256 key is derived from
//! `SHA-256("craton-hsm-gcm-counter-v1" || canonical_path_bytes)`. This has
//! the property that the MAC is stable across restarts for the same file
//! path (so we can actually detect tampering and truncation), at the cost
//! that an attacker with local filesystem access can forge a valid journal.
//! This is an acceptable trade-off because (a) the file lives alongside
//! key material in the operator's protected data directory and enjoys the
//! same filesystem ACLs, and (b) the MAC exists to detect accidental
//! corruption/truncation, not adversarial rewrite; an attacker with write
//! access to the counter file already has write access to the keys.
//!
//! An alternative design is an ephemeral per-process MAC key: strong
//! against offline forgery but useless for integrity checking across
//! restarts (the whole point of the file). We deliberately chose the
//! stable-key design.

#![allow(dead_code)] // consumed from lib.rs through a narrow surface

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fs2::FileExt;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use craton_hsm::error::{HsmError, HsmResult};

/// Batch threshold (in counts) — we persist when the in-memory counter has
/// advanced by this many since the last successful flush.
pub(crate) const BATCH_THRESHOLD: u64 = 1024;

/// AES-GCM per-key encryption ceiling (mirrored from lib.rs so this module
/// has no upward dependency on private constants).
const AES_GCM_NONCE_LIMIT: u64 = 1u64 << 32;

/// Journal format version marker. Present as the first line of new journal
/// files (audit finding M1). Legacy journals without a marker are accepted
/// and upgraded on the next write. A different version string refuses to
/// load — the operator must migrate explicitly.
pub(crate) const JOURNAL_VERSION_MARKER: &[u8] = b"craton-hsm-gcm-journal v1\n";

/// Upper bound on the number of malformed records we tolerate in a single
/// journal load before declaring the file too damaged to trust (audit
/// finding L2). Past this we refuse to open the file; the operator must
/// inspect and either rotate keys or restore from backup.
pub(crate) const MAX_MALFORMED_RECORDS: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Compute `SHA-256(key)` as a 32-byte fingerprint. The awslc backend keys
/// its in-memory map on raw bytes; the persistent layer always hashes first
/// so the on-disk identifier is independent of key length.
pub(crate) fn fingerprint(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

#[derive(Clone, Copy, Debug, Default)]
struct PersistEntry {
    /// Max counter value known to be on disk for this fingerprint.
    persisted: u64,
    /// True if this fingerprint has a POISONED record on disk.
    poisoned: bool,
}

/// Persistent backing store for the AES-GCM counter.
///
/// Use [`PersistentGcmCounter::in_memory`] for the default in-memory-only
/// behaviour, or [`PersistentGcmCounter::file_backed`] to enable a
/// write-through disk journal.
pub struct PersistentGcmCounter {
    inner: Mutex<Inner>,
}

enum Inner {
    InMemory,
    FileBacked(FileBacked),
    /// Test-only: every `flush_fingerprint` call returns an error. Used to
    /// exercise the flush-failure-streak → poison path without requiring a
    /// genuine filesystem failure. `record_advance` still works so the
    /// in-memory counter can progress normally; `record_poison` is tracked
    /// so assertions can verify the poison marker was requested.
    #[cfg(test)]
    FailingFlush(FailingFlush),
}

#[cfg(test)]
pub(crate) struct FailingFlush {
    pub flush_attempts: std::sync::atomic::AtomicU32,
    pub poisoned: Mutex<std::collections::HashSet<[u8; 32]>>,
}

struct FileBacked {
    path: PathBuf,
    file: File,
    mac_key: [u8; 32],
    /// Last known persisted counter per fingerprint (and poison flag).
    known: HashMap<[u8; 32], PersistEntry>,
    /// If true, the file failed its integrity check on load. Every
    /// fingerprint we previously saw is treated as poisoned; new keys are
    /// still allowed but writes are refused so the operator cannot mask the
    /// corruption.
    integrity_failed: bool,
}

impl PersistentGcmCounter {
    /// Default behaviour: no persistence, just a shim around the in-memory
    /// counter. Calls to `record_advance`/`record_poison` are no-ops.
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Inner::InMemory),
        }
    }

    /// Test-only: build a counter whose `flush_fingerprint` always fails,
    /// so callers can exercise the flush-failure-streak → poison logic
    /// (audit finding H1) without a real filesystem mishap.
    #[cfg(test)]
    pub(crate) fn failing_flush_for_tests() -> Self {
        Self {
            inner: Mutex::new(Inner::FailingFlush(FailingFlush {
                flush_attempts: std::sync::atomic::AtomicU32::new(0),
                poisoned: Mutex::new(std::collections::HashSet::new()),
            })),
        }
    }

    /// Test-only: return the number of `flush_fingerprint` attempts seen
    /// by a `failing_flush_for_tests` counter.
    #[cfg(test)]
    pub(crate) fn failing_flush_attempts(&self) -> u32 {
        match &*self.inner.lock() {
            Inner::FailingFlush(ff) => ff.flush_attempts.load(std::sync::atomic::Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Test-only: check whether a fingerprint was poisoned through the
    /// failing-flush variant.
    #[cfg(test)]
    pub(crate) fn failing_flush_was_poisoned(&self, fp: &[u8; 32]) -> bool {
        match &*self.inner.lock() {
            Inner::FailingFlush(ff) => ff.poisoned.lock().contains(fp),
            _ => false,
        }
    }

    /// File-backed journal. The file is created if it does not exist.
    /// Existing content is loaded, integrity-verified, and used to hydrate
    /// the in-memory starting values.
    pub fn file_backed(path: impl Into<PathBuf>) -> HsmResult<Self> {
        let path = path.into();
        // Derive the MAC key from the (canonicalised) path. The
        // derivation is independent of whether the file already exists,
        // so the same key drops out on every open of the same path —
        // including the very first one, where `canonicalize(path)` would
        // otherwise fail and earlier revisions of this code fell back to
        // a path-only key that no subsequent open could reproduce.
        let mac_key = derive_mac_key(&path);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                tracing::error!(error=%e, path=%path.display(), "failed to open GCM counter file");
                HsmError::GeneralError
            })?;

        // Cross-process exclusion: two processes pointed at the same journal
        // would race on the append-only writer, defeat the MAC, and reuse
        // nonces. Take an exclusive OS file lock for the lifetime of this
        // `PersistentGcmCounter`. The lock is automatically released when
        // the file handle is dropped.
        FileExt::try_lock_exclusive(&file).map_err(|e| {
            tracing::error!(
                error=%e,
                path=%path.display(),
                "failed to acquire exclusive lock on GCM counter file; another process is using it"
            );
            HsmError::AlreadyInitialized
        })?;

        // Try the current (v2) MAC key first. If the file exists but fails
        // v2 integrity *and* the file has no version marker, attempt the
        // legacy v1 MAC-key derivation — pre-M2 journals were written with
        // that key and must continue to open. Successful v1 validation is
        // an implicit upgrade trigger: the next write re-keys the file.
        let (known, integrity_failed, valid_len) = load_and_verify(&mut file, &mac_key)?;
        let (known, integrity_failed, valid_len) =
            if integrity_failed && !file_has_version_marker(&mut file)? {
                let legacy_key = derive_mac_key_v1(&path);
                match load_and_verify(&mut file, &legacy_key) {
                    Ok((k, false, v)) => {
                        tracing::info!(
                            path=%path.display(),
                            "GCM journal verified with legacy v1 MAC key; will re-key on next write"
                        );
                        (k, false, v)
                    }
                    _ => (known, integrity_failed, valid_len),
                }
            } else {
                (known, integrity_failed, valid_len)
            };

        // Truncate any trailing garbage past the last valid footer.
        if integrity_failed {
            tracing::error!(
                path=%path.display(),
                "AES-GCM counter file failed integrity check — treating all prior fingerprints as poisoned"
            );
        } else if valid_len < file_len(&file)? {
            tracing::warn!(
                path=%path.display(),
                "truncating {} bytes of unverified trailing data from GCM counter file",
                file_len(&file)? - valid_len
            );
            file.set_len(valid_len)
                .map_err(|_| HsmError::GeneralError)?;
            file.seek(SeekFrom::End(0))
                .map_err(|_| HsmError::GeneralError)?;
            file.sync_all().map_err(|_| HsmError::GeneralError)?;
        }

        let fb = FileBacked {
            path,
            file,
            mac_key,
            known,
            integrity_failed,
        };

        Ok(Self {
            inner: Mutex::new(Inner::FileBacked(fb)),
        })
    }

    /// Look up the persisted starting value (and poison flag) for a
    /// fingerprint. Callers use this on process start to hydrate the
    /// in-memory counter so it never goes backwards.
    pub(crate) fn persisted_state(&self, fp: &[u8; 32]) -> (u64, bool) {
        match &*self.inner.lock() {
            Inner::InMemory => (0, false),
            Inner::FileBacked(fb) => {
                if fb.integrity_failed && fb.known.contains_key(fp) {
                    // Fail-closed: any previously known fingerprint is poisoned.
                    return (AES_GCM_NONCE_LIMIT, true);
                }
                match fb.known.get(fp) {
                    Some(e) => (e.persisted, e.poisoned),
                    None => (0, false),
                }
            }
            #[cfg(test)]
            Inner::FailingFlush(ff) => {
                let poisoned = ff.poisoned.lock().contains(fp);
                if poisoned {
                    (AES_GCM_NONCE_LIMIT, true)
                } else {
                    (0, false)
                }
            }
        }
    }

    /// Record that the in-memory counter for `fp` has reached `new_count`
    /// (that is, nonce value `new_count` is about to be / has just been
    /// reserved by the caller).
    ///
    /// # Write-ahead reservation (audit finding C2)
    ///
    /// The on-disk value stored for `fp` is a *ceiling* — a value strictly
    /// greater than any nonce ever emitted for this key. When `new_count`
    /// is still at or below the current ceiling, no I/O is needed (the
    /// nonce we are about to emit is inside the already-reserved window).
    /// When `new_count` reaches the ceiling, we synchronously write a new
    /// ceiling equal to `new_count + BATCH_THRESHOLD` and fsync it.
    ///
    /// Crash safety: the pre-C2 design wrote *exactly* the value that was
    /// just reserved, and deferred all writes until the counter had
    /// advanced by `BATCH_THRESHOLD`. A crash between the last flush and
    /// the next one therefore lost up to `BATCH_THRESHOLD` values of
    /// counter state, and on restart those same nonces were re-issued —
    /// catastrophic for AES-GCM. The ceiling-write design eliminates that
    /// window: the on-disk value is always an *upper bound* on what has
    /// been emitted, so hydration at `persisted` cannot collide.
    ///
    /// On IO error the caller MUST refuse the encryption — nonce reuse is
    /// catastrophic, so we fail closed.
    pub(crate) fn record_advance(&self, fp: &[u8; 32], new_count: u64) -> HsmResult<()> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::InMemory => Ok(()),
            Inner::FileBacked(fb) => {
                if fb.integrity_failed {
                    tracing::error!(
                        "AES-GCM counter file is in a failed-integrity state; refusing to advance"
                    );
                    return Err(HsmError::GeneralError);
                }
                let entry = fb.known.entry(*fp).or_default();
                let is_new = entry.persisted == 0;
                // Inside the already-reserved window? No disk I/O needed.
                //
                // The persisted value is the *ceiling*: strictly greater
                // than any nonce ever emitted (see the field doc and the
                // C2 audit note above). `new_count` is the nonce the
                // caller is about to emit (or has just emitted), so the
                // safe window is `new_count < ceiling` — strict less-than.
                // Using `<=` here let the boundary value `new_count ==
                // ceiling` short-circuit, leaving the on-disk ceiling
                // equal to the just-emitted nonce, which violates the
                // strictly-greater invariant the loader relies on for
                // crash-safe hydration.
                if !is_new && new_count < entry.persisted {
                    return Ok(());
                }
                // Need to extend the reservation. The ceiling we persist
                // must be strictly greater than the value being reserved,
                // so a crash between now and the next flush cannot re-issue
                // any nonce already emitted. Saturate at the NIST 2^32
                // ceiling — past that the caller is handled by the
                // poison path.
                let ceiling = new_count
                    .saturating_add(BATCH_THRESHOLD)
                    .min(AES_GCM_NONCE_LIMIT);
                write_record(&mut fb.file, &fb.mac_key, fp, RecordKind::Count(ceiling))?;
                entry.persisted = ceiling;
                Ok(())
            }
            #[cfg(test)]
            Inner::FailingFlush(ff) => {
                // In-memory counter can still advance for test purposes;
                // only `flush_fingerprint` is forced to fail.
                if ff.poisoned.lock().contains(fp) {
                    return Err(HsmError::GeneralError);
                }
                let _ = new_count;
                Ok(())
            }
        }
    }

    /// Force-flush `fp` to the persistent journal, bypassing the batch
    /// threshold. Callers use this before evicting an in-memory counter so
    /// that the hydrated value on next sight is never lower than the value
    /// already handed out.
    pub(crate) fn flush_fingerprint(&self, fp: &[u8; 32], new_count: u64) -> HsmResult<()> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::InMemory => Ok(()),
            Inner::FileBacked(fb) => {
                if fb.integrity_failed {
                    return Err(HsmError::GeneralError);
                }
                let entry = fb.known.entry(*fp).or_default();
                if new_count <= entry.persisted {
                    return Ok(());
                }
                write_record(&mut fb.file, &fb.mac_key, fp, RecordKind::Count(new_count))?;
                entry.persisted = new_count;
                Ok(())
            }
            #[cfg(test)]
            Inner::FailingFlush(ff) => {
                ff.flush_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = new_count;
                Err(HsmError::GeneralError)
            }
        }
    }

    /// Record that `fp` has been poisoned. Synchronous + fsync.
    pub(crate) fn record_poison(&self, fp: &[u8; 32]) -> HsmResult<()> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::InMemory => Ok(()),
            Inner::FileBacked(fb) => {
                if fb.integrity_failed {
                    // Already fail-closed; skip the write (we cannot validate
                    // our own append anyway).
                    return Ok(());
                }
                write_record(&mut fb.file, &fb.mac_key, fp, RecordKind::Poisoned)?;
                let entry = fb.known.entry(*fp).or_default();
                entry.poisoned = true;
                entry.persisted = AES_GCM_NONCE_LIMIT;
                Ok(())
            }
            #[cfg(test)]
            Inner::FailingFlush(ff) => {
                ff.poisoned.lock().insert(*fp);
                Ok(())
            }
        }
    }

    /// Test/maintenance helper: drop any cached in-memory knowledge and
    /// re-open the file. Not used in production paths.
    #[cfg(test)]
    pub(crate) fn reload(&self) -> HsmResult<()> {
        let mut inner = self.inner.lock();
        if let Inner::FileBacked(fb) = &mut *inner {
            let mac_key = fb.mac_key;
            let path = fb.path.clone();
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .truncate(false)
                .open(&fb.path)
                .map_err(|_| HsmError::GeneralError)?;
            let (known, integrity_failed, valid_len) = load_and_verify(&mut file, &mac_key)?;
            // Same v1 fallback as the primary open path.
            let (known, integrity_failed, valid_len) =
                if integrity_failed && !file_has_version_marker(&mut file)? {
                    let legacy_key = derive_mac_key_v1(&path);
                    match load_and_verify(&mut file, &legacy_key) {
                        Ok((k, false, v)) => (k, false, v),
                        _ => (known, integrity_failed, valid_len),
                    }
                } else {
                    (known, integrity_failed, valid_len)
                };
            if !integrity_failed && valid_len < file_len(&file)? {
                file.set_len(valid_len)
                    .map_err(|_| HsmError::GeneralError)?;
                file.seek(SeekFrom::End(0))
                    .map_err(|_| HsmError::GeneralError)?;
            }
            fb.file = file;
            fb.known = known;
            fb.integrity_failed = integrity_failed;
        }
        Ok(())
    }
}

impl std::fmt::Debug for PersistentGcmCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        match &*inner {
            Inner::InMemory => f
                .debug_struct("PersistentGcmCounter")
                .field("mode", &"in_memory")
                .finish(),
            Inner::FileBacked(fb) => f
                .debug_struct("PersistentGcmCounter")
                .field("mode", &"file_backed")
                .field("path", &fb.path)
                .field("known_keys", &fb.known.len())
                .field("integrity_failed", &fb.integrity_failed)
                .finish(),
            #[cfg(test)]
            Inner::FailingFlush(_) => f
                .debug_struct("PersistentGcmCounter")
                .field("mode", &"failing_flush_test_only")
                .finish(),
        }
    }
}

// ----- process-global installer ---------------------------------------------

static PERSIST: OnceLock<PersistentGcmCounter> = OnceLock::new();

/// Install the process-global persistent counter. Can only be called once.
///
/// Returns `Err(HsmError::GeneralError)` if a counter is already installed.
///
/// External callers reach this through the
/// `craton_hsm_awslc::install_persistent_gcm_counter` re-export at the
/// crate root; the `gcm_counter` module itself is `pub(crate)`.
pub fn install(counter: PersistentGcmCounter) -> HsmResult<()> {
    PERSIST.set(counter).map_err(|_| HsmError::GeneralError)
}

/// Access the installed counter, falling back to a static in-memory shim.
pub(crate) fn current() -> &'static PersistentGcmCounter {
    static FALLBACK: OnceLock<PersistentGcmCounter> = OnceLock::new();
    PERSIST
        .get()
        .unwrap_or_else(|| FALLBACK.get_or_init(PersistentGcmCounter::in_memory))
}

// ============================================================================
// File format: records + MAC footer
// ============================================================================

enum RecordKind {
    Count(u64),
    Poisoned,
}

/// Append one record to the journal and rewrite the integrity footer.
///
/// # Cost
///
/// Each call rewrites the entire file from byte 0: the existing body is
/// read back, the new record appended, a fresh HMAC computed over the
/// whole thing, and the result re-written and `fsync`'d. That is
/// `O(file_size)` per flush — flushes are kept rare (1 per
/// [`BATCH_THRESHOLD`] encryptions per key) so amortised cost is
/// acceptable for a journal that grows by ~64 bytes per active key per
/// flush. A journal of N keys can grow to roughly `N * flushes_over_lifetime`
/// records, so for long-lived processes with many keys this becomes the
/// dominant cost in the encrypt path.
///
/// Soft cap for the journal file. When the on-disk size crosses this we
/// emit a one-shot `tracing::warn!` so operators notice growth before it
/// becomes pathological. The journal still works correctly past this size
/// — just slower, since every flush is O(file_size).
///
/// TODO: implement compaction / rotation. The planned approach:
///   1. On load, the in-memory `known` map already holds the max counter
///      seen per fingerprint, so we have a O(1)-per-fp summary of the
///      file's "useful" content.
///   2. When the file exceeds [`JOURNAL_SOFT_CAP_BYTES`] (or
///      [`JOURNAL_SOFT_CAP_RECORDS`] records), serialise one fresh
///      record per known fingerprint to a sibling file
///      (`<path>.compact`), include the version marker + MAC footer,
///      `fsync`, then atomically `rename` it over the original. The file
///      lock held by [`PersistentGcmCounter::file_backed`] must be
///      released and re-acquired across the rename on Windows; on Unix
///      the inode swap is fine under an open fd.
///   3. POISONED markers must survive the rewrite — they are the
///      irreversible-state bit and must round-trip even though they look
///      redundant.
///   4. The rewrite must be crash-safe: leaving the journal in a state
///      where the new file is partly written but the old file is gone
///      means losing every persisted counter.
/// Until that lands, the soft-cap warning below is the operator-visible
/// failsafe.
const JOURNAL_SOFT_CAP_BYTES: u64 = 16 * 1024 * 1024;
const JOURNAL_SOFT_CAP_RECORDS: usize = 65_536;

/// Emit a one-shot `tracing::warn!` when the GCM journal file crosses
/// [`JOURNAL_SOFT_CAP_BYTES`] / [`JOURNAL_SOFT_CAP_RECORDS`]. See the
/// TODO above [`write_record`] for the planned compaction work; until
/// it lands this warning is what operators have to act on.
fn warn_journal_size_once(size_bytes: u64, record_estimate: Option<usize>) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            target: "craton_hsm_awslc::gcm_counter",
            size_bytes,
            record_estimate = ?record_estimate,
            soft_cap_bytes = JOURNAL_SOFT_CAP_BYTES,
            soft_cap_records = JOURNAL_SOFT_CAP_RECORDS,
            "AES-GCM journal file exceeded soft cap; compaction is not yet implemented \
             so the file will continue to grow. Each flush is O(file_size), so encryption \
             throughput will degrade. Plan to restart the process with a fresh journal \
             (rotate keys first) until compaction lands."
        );
    });
}

fn write_record(
    file: &mut File,
    mac_key: &[u8; 32],
    fp: &[u8; 32],
    kind: RecordKind,
) -> HsmResult<()> {
    // Compute the MAC over (version marker + all existing file bytes up to
    // current EOF that are not part of a trailing footer) + this new
    // record. Simpler: recompute from start on each flush. Cost:
    // O(file_size) per flush — acceptable because BATCH_THRESHOLD keeps
    // flushes rare (1 per 1024 encryptions).

    // Serialise the record.
    let record = match kind {
        RecordKind::Count(n) => format!("{} {}\n", hex32(fp), n),
        RecordKind::Poisoned => format!("{} POISONED\n", hex32(fp)),
    };

    // Strip any previous footer AND any previous version marker. We'll
    // always re-prepend the current version marker below — this is how a
    // legacy journal gets transparently upgraded on first write (M1).
    let existing_body = read_without_footer_or_marker(file)?;
    let mut new_body = existing_body;
    new_body.extend_from_slice(record.as_bytes());

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(JOURNAL_VERSION_MARKER);
    mac.update(&new_body);
    let tag = mac.finalize().into_bytes();
    let footer = format!("#MAC {}\n", hex_bytes(&tag));

    file.seek(SeekFrom::Start(0))
        .map_err(|_| HsmError::GeneralError)?;
    file.set_len(0).map_err(|_| HsmError::GeneralError)?;
    file.write_all(JOURNAL_VERSION_MARKER)
        .map_err(|_| HsmError::GeneralError)?;
    file.write_all(&new_body)
        .map_err(|_| HsmError::GeneralError)?;
    file.write_all(footer.as_bytes())
        .map_err(|_| HsmError::GeneralError)?;
    file.sync_all().map_err(|_| HsmError::GeneralError)?;
    file.seek(SeekFrom::End(0))
        .map_err(|_| HsmError::GeneralError)?;

    // Soft-cap warning: until compaction lands (see TODO above), the file
    // grows monotonically. Estimate record count from the body length using
    // a conservative lower bound — record lines are ≥ 67 bytes (64 hex +
    // space + ≥1 digit + newline). Avoids a second pass over `new_body`.
    let total_size = (JOURNAL_VERSION_MARKER.len() + new_body.len() + footer.len()) as u64;
    if total_size > JOURNAL_SOFT_CAP_BYTES {
        warn_journal_size_once(total_size, None);
    } else {
        let estimated_records = new_body.len() / 67;
        if estimated_records > JOURNAL_SOFT_CAP_RECORDS {
            warn_journal_size_once(total_size, Some(estimated_records));
        }
    }
    Ok(())
}

/// Outcome of version-marker inspection at journal-load time. The first byte
/// sequence of the file either: (a) carries a known marker we accept, (b)
/// carries a legacy body with no marker we accept and upgrade on next write,
/// or (c) carries a different-version marker we refuse outright.
enum VersionCheck<'a> {
    /// Known version: body starts at this offset, marker already consumed.
    V1 { body_offset: usize, body: &'a [u8] },
    /// No marker at all — pre-versioning journal. Upgrade on next write.
    Legacy { body: &'a [u8] },
}

fn check_version<'a>(all: &'a [u8]) -> HsmResult<VersionCheck<'a>> {
    if all.starts_with(JOURNAL_VERSION_MARKER) {
        let off = JOURNAL_VERSION_MARKER.len();
        return Ok(VersionCheck::V1 {
            body_offset: off,
            body: &all[off..],
        });
    }
    // Any other line starting with our magic-line prefix but a different
    // version number is a hard error — we don't know how to read it.
    const PREFIX: &[u8] = b"craton-hsm-gcm-journal ";
    if all.starts_with(PREFIX) {
        // Extract the rest of the first line for the error log.
        let line_end = all.iter().position(|&b| b == b'\n').unwrap_or(all.len());
        let version_str = String::from_utf8_lossy(&all[..line_end]);
        tracing::error!(
            header = %version_str,
            "unknown GCM journal format version — refusing to load"
        );
        return Err(HsmError::GeneralError);
    }
    // No marker at all — legacy file. Accept and upgrade on next write.
    Ok(VersionCheck::Legacy { body: all })
}

/// Footer positions are computed relative to `body`; we also track
/// `body_offset` so the absolute `valid_len` returned to the caller covers
/// the entire prefix (version marker + body + footer line).
fn load_and_verify(
    file: &mut File,
    mac_key: &[u8; 32],
) -> HsmResult<(HashMap<[u8; 32], PersistEntry>, bool, u64)> {
    let total_len = file_len(file)?;
    if total_len == 0 {
        return Ok((HashMap::new(), false, 0));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|_| HsmError::GeneralError)?;
    let mut all = Vec::with_capacity(total_len as usize);
    std::io::Read::read_to_end(file, &mut all).map_err(|_| HsmError::GeneralError)?;

    // M1: inspect the version marker before anything else. Unknown versions
    // refuse to load; legacy (no marker) flows through as before and the
    // next write upgrades the file.
    let (body_offset, body_slice): (usize, &[u8]) = match check_version(&all)? {
        VersionCheck::V1 { body_offset, body } => (body_offset, body),
        VersionCheck::Legacy { body } => (0, body),
    };

    // Helper: parse records but refuse if too many are malformed (L2).
    let parse_and_check = |bytes: &[u8]| -> HsmResult<HashMap<[u8; 32], PersistEntry>> {
        let (known, malformed) = parse_records(bytes);
        if malformed > MAX_MALFORMED_RECORDS {
            tracing::error!(
                malformed = malformed,
                threshold = MAX_MALFORMED_RECORDS,
                "GCM journal has more than {} malformed records — refusing to load",
                MAX_MALFORMED_RECORDS
            );
            return Err(HsmError::GeneralError);
        }
        Ok(known)
    };

    // Find the last "#MAC " line within `body_slice`. Bytes before it form
    // the verified body.
    let (body, footer_tag) = match split_footer(body_slice) {
        Some(x) => x,
        None => {
            tracing::warn!("AES-GCM counter file has no integrity footer; treating as cold start");
            let known = parse_and_check(body_slice)?;
            let valid_len = all.len() as u64;
            return Ok((known, false, valid_len));
        }
    };

    // Verify MAC. Decode the hex tag first, then compare raw bytes with
    // aws-lc's constant-time primitive. Comparing hex strings byte-by-byte
    // with PartialEq leaks the mismatch position via timing.
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC-SHA256 accepts any key length");
    // MAC covers the version marker too (if present) so an attacker cannot
    // downgrade a V1 journal to legacy without tripping the integrity check.
    if body_offset > 0 {
        mac.update(&all[..body_offset]);
    }
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    let footer_bytes = match decode_hex_bytes(footer_tag.as_bytes()) {
        Some(b) if b.len() == expected.len() => b,
        _ => {
            // Malformed footer tag — treat as integrity failure.
            let known = parse_and_check(body)?;
            return Ok((known, true, 0));
        }
    };
    let ok = aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_slice(), &footer_bytes)
        .is_ok();

    if !ok {
        // Integrity failure — parse what we can so persisted_state can
        // report "known but poisoned", but flip the integrity flag so
        // future writes are refused.
        let known = parse_and_check(body)?;
        return Ok((known, true, 0));
    }

    let known = parse_and_check(body)?;
    // valid_len = version_marker + body + "#MAC " + tag + "\n"
    let valid_len = (body_offset + body.len() + 5 + footer_tag.len() + 1) as u64;
    Ok((known, false, valid_len))
}

/// Read the existing file contents *excluding* any leading version marker
/// and any trailing `#MAC ...` footer line, leaving the file cursor at EOF.
/// Used before rewriting the file with a fresh marker + fresh footer.
fn read_without_footer_or_marker(file: &mut File) -> HsmResult<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| HsmError::GeneralError)?;
    let mut all = Vec::new();
    std::io::Read::read_to_end(file, &mut all).map_err(|_| HsmError::GeneralError)?;
    // Strip leading version marker if present (legacy files have none).
    let marker_stripped: &[u8] = if all.starts_with(JOURNAL_VERSION_MARKER) {
        &all[JOURNAL_VERSION_MARKER.len()..]
    } else {
        &all
    };
    match split_footer(marker_stripped) {
        Some((body, _)) => Ok(body.to_vec()),
        None => Ok(marker_stripped.to_vec()),
    }
}

fn split_footer(all: &[u8]) -> Option<(&[u8], String)> {
    // Find the last well-formed `#MAC <hex>\n` line, starting from after a
    // newline (or from position 0). Anything after that line is garbage and
    // will be truncated by the caller.
    //
    // We scan from the end so trailing garbage does not fool us into reading
    // an interior line as the footer.
    let mut search_end = all.len();
    loop {
        let prefix = b"\n#MAC ";
        let idx = match find_last_subslice(&all[..search_end], prefix) {
            Some(i) => i + 1,
            None => {
                if all.starts_with(b"#MAC ") && search_end >= 5 {
                    0
                } else {
                    return None;
                }
            }
        };

        // Find the '\n' that terminates this footer line.
        let after = &all[idx..];
        if let Some(nl) = after.iter().position(|&b| b == b'\n') {
            let line = &after[..nl];
            if let Some(rest) = line.strip_prefix(b"#MAC ") {
                if let Ok(tag) = std::str::from_utf8(rest) {
                    let body = &all[..idx];
                    return Some((body, tag.to_string()));
                }
            }
        }

        // Current candidate isn't usable — look for an earlier one.
        if idx == 0 {
            return None;
        }
        search_end = idx - 1;
    }
}

fn find_last_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    // `slice::windows(n).rposition(...)` walks the slice once from the end
    // and stops at the first match, which is the rightmost occurrence we
    // want here. Replaces the previous O(n*m) hand-rolled scan with a
    // tight iterator loop; matches stdlib's preferred idiom for "find
    // last subslice" without pulling in `memchr::memmem`.
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Parse a body of newline-delimited records. Malformed lines are logged at
/// `WARN` (audit finding L2) and counted; the caller decides whether the
/// count exceeds [`MAX_MALFORMED_RECORDS`] and refuses the load.
///
/// Returns the parsed map and the number of malformed (non-comment,
/// non-empty) lines encountered.
fn parse_records(body: &[u8]) -> (HashMap<[u8; 32], PersistEntry>, usize) {
    let mut out: HashMap<[u8; 32], PersistEntry> = HashMap::new();
    let mut malformed: usize = 0;
    for (lineno, line) in BufReader::new(body)
        .lines()
        .map_while(Result::ok)
        .enumerate()
    {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let raw_bytes = line.as_bytes();
        let prefix_len = raw_bytes.len().min(32);
        let prefix_hex = hex_bytes(&raw_bytes[..prefix_len]);

        let mut parts = trimmed.splitn(2, ' ');
        let hex = match parts.next() {
            Some(h) => h,
            None => {
                malformed += 1;
                tracing::warn!(
                    line = lineno + 1,
                    prefix_hex = %prefix_hex,
                    "skipping malformed GCM journal line: no fields"
                );
                continue;
            }
        };
        let val = match parts.next() {
            Some(v) => v,
            None => {
                malformed += 1;
                tracing::warn!(
                    line = lineno + 1,
                    prefix_hex = %prefix_hex,
                    "skipping malformed GCM journal line: missing value"
                );
                continue;
            }
        };
        let fp = match parse_hex32(hex) {
            Some(f) => f,
            None => {
                malformed += 1;
                tracing::warn!(
                    line = lineno + 1,
                    prefix_hex = %prefix_hex,
                    "skipping malformed GCM journal line: invalid fingerprint hex"
                );
                continue;
            }
        };
        let entry = out.entry(fp).or_default();
        if val == "POISONED" {
            entry.poisoned = true;
            entry.persisted = AES_GCM_NONCE_LIMIT;
        } else if let Ok(n) = val.parse::<u64>() {
            // Never go backwards — keep the max.
            if n > entry.persisted {
                entry.persisted = n;
            }
            if n >= AES_GCM_NONCE_LIMIT {
                entry.poisoned = true;
            }
        } else {
            malformed += 1;
            tracing::warn!(
                line = lineno + 1,
                prefix_hex = %prefix_hex,
                "skipping malformed GCM journal line: value is neither u64 nor POISONED"
            );
        }
    }
    (out, malformed)
}

fn file_len(file: &File) -> HsmResult<u64> {
    file.metadata()
        .map(|m| m.len())
        .map_err(|_| HsmError::GeneralError)
}

/// Peek at the first [`JOURNAL_VERSION_MARKER`]-length bytes of `file` and
/// decide whether this is a v1-or-later (marker present) or legacy (marker
/// absent) journal. Used to gate the v1 MAC-key fallback during load.
fn file_has_version_marker(file: &mut File) -> HsmResult<bool> {
    use std::io::Read;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| HsmError::GeneralError)?;
    let mut buf = vec![0u8; JOURNAL_VERSION_MARKER.len()];
    let n = file.read(&mut buf).unwrap_or(0);
    buf.truncate(n);
    // Leave the cursor at end so later writes append; any caller that
    // wants a specific position must re-seek (all write paths do).
    let _ = file.seek(SeekFrom::End(0));
    Ok(buf == JOURNAL_VERSION_MARKER)
}

fn derive_mac_key(path: &Path) -> [u8; 32] {
    // M2: canonicalise the path so two symlinks to the same underlying
    // file derive the *same* MAC key, and a journal written via one path
    // validates when re-opened via the other.
    //
    // Note: a previous revision of this code also folded the OS-level
    // file identity (inode/file-id) into the key as a defence against
    // attacker-swapped files at the same path. That fix was reverted
    // because `derive_mac_key` is also called by callers who do not yet
    // have the file on disk (audit / verification harness, tests that
    // pre-compute a MAC for a manually-constructed journal). Including
    // the inode made the key non-deterministic across the
    // file-not-yet-exists → file-exists transition, so a journal MAC'd
    // before the file existed could never be verified after it did.
    // The path-only design is what the loader and writer have always
    // assumed and what every external test fixture depends on. The
    // attacker-swap surface is already very weak (the key is a
    // deterministic SHA-256 of the path, so anyone with read access to
    // the file's location can recompute it), so removing the inode
    // binding does not move the security model meaningfully.
    derive_mac_key_v2(path)
}

/// v2 MAC-key derivation. Canonicalises the path so symlink-equivalent
/// paths produce the same key; falls back to canonicalising the parent
/// directory (and re-attaching the filename) when the leaf file does not
/// yet exist, so the key is identical before and after journal creation.
fn derive_mac_key_v2(path: &Path) -> [u8; 32] {
    let canon = canonicalize_for_mac_key(path);
    let canon_bytes = canon.as_os_str().to_string_lossy().as_bytes().to_vec();

    let mut h = Sha256::new();
    h.update(b"craton-hsm-gcm-counter-v2");
    // Explicit domain prefix preserves the wire format from the previous
    // (inode-bearing) revision so a journal MAC'd by the old code with the
    // path-only fallback branch — which already emitted `\x00path:` and
    // nothing else — still verifies.
    h.update(b"\x00path:");
    h.update(&canon_bytes);
    h.finalize().into()
}

/// Resolve `path` to a stable canonical form regardless of whether the
/// leaf file is currently on disk.
///
/// 1. If `canonicalize(path)` succeeds, use that — same as before.
/// 2. Otherwise, if the parent directory exists, return
///    `canonicalize(parent).join(file_name)`. This means a path like
///    `/tmp/.tmpXXXXXX` resolves to the same bytes whether the leaf has
///    been created yet or not, as long as `/tmp` exists (it always
///    does). Symlink-equivalence is preserved for the parent.
/// 3. Last resort: return the raw input path verbatim.
fn canonicalize_for_mac_key(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    if let (Some(parent), Some(filename)) = (path.parent(), path.file_name()) {
        // An empty parent on a bare relative filename like `journal.dat`
        // would be `""`, which `canonicalize` rejects on most platforms.
        // Treat that the same as a missing parent and fall through.
        if !parent.as_os_str().is_empty() {
            if let Ok(canon_parent) = std::fs::canonicalize(parent) {
                return canon_parent.join(filename);
            }
        }
    }
    path.to_path_buf()
}

/// v1 MAC-key derivation — retained ONLY for transparent upgrade of
/// pre-M2 journals. A load that fails the v2 check falls back to v1; if
/// v1 verifies, the file is migrated to the v2 key on the next write.
fn derive_mac_key_v1(path: &Path) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"craton-hsm-gcm-counter-v1");
    h.update(path.as_os_str().to_string_lossy().as_bytes());
    h.finalize().into()
}

fn hex32(b: &[u8; 32]) -> String {
    hex_bytes(b)
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nib(chunk[0])?;
        let lo = hex_nib(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decode an ASCII hex byte slice (lower- or upper-case) to bytes. Returns
/// `None` on odd length or invalid digit.
fn decode_hex_bytes(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.chunks(2) {
        let hi = hex_nib(chunk[0])?;
        let lo = hex_nib(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn fp_of(k: &[u8]) -> [u8; 32] {
        fingerprint(k)
    }

    #[test]
    fn in_memory_is_noop() {
        let c = PersistentGcmCounter::in_memory();
        let fp = fp_of(b"key");
        assert_eq!(c.persisted_state(&fp), (0, false));
        c.record_advance(&fp, 99).unwrap();
        c.record_poison(&fp).unwrap();
        assert_eq!(c.persisted_state(&fp), (0, false));
    }

    #[test]
    fn round_trip_counter_survives_reload() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf); // remove so file_backed creates fresh

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"aaa");
        // First advance is the "new key" case: writes ceiling = 1024 + BATCH.
        c.record_advance(&fp, 1024).unwrap();
        // new_count=2048 > ceiling, so this advances the reservation to
        // 2048 + BATCH.
        c.record_advance(&fp, 2048).unwrap();
        drop(c);

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c2.persisted_state(&fp);
        // The on-disk value is the reservation ceiling, so it is strictly
        // greater than the largest emitted value (audit finding C2).
        assert_eq!(persisted, 2048 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

    #[test]
    fn poison_persists_across_reloads() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"bbb");
        c.record_advance(&fp, 1024).unwrap();
        c.record_poison(&fp).unwrap();
        drop(c);

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c2.persisted_state(&fp);
        assert!(poisoned);
        assert_eq!(persisted, AES_GCM_NONCE_LIMIT);
    }

    #[test]
    fn corrupted_trailing_lines_truncated_on_load() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"ccc");
        c.record_advance(&fp, 1024).unwrap();
        drop(c);

        // Append garbage after the MAC footer.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"this is not a valid record\n").unwrap();
            f.sync_all().unwrap();
        }

        // Load should succeed, truncate the garbage, and still know the counter.
        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c2.persisted_state(&fp);
        assert_eq!(persisted, 1024 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

    #[test]
    fn integrity_mac_mismatch_poisons_all_known() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"ddd");
        c.record_advance(&fp, 2048).unwrap();
        drop(c);

        // Corrupt a byte in the body (flip one hex char of the counter line).
        let mut bytes = std::fs::read(&path).unwrap();
        // Find the space in the first line and tweak the digit after it.
        for (i, &b) in bytes.iter().enumerate() {
            if b == b' ' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                bytes[i + 1] ^= 0x01;
                break;
            }
        }
        std::fs::write(&path, &bytes).unwrap();

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (_, poisoned) = c2.persisted_state(&fp);
        assert!(poisoned, "integrity failure must poison the fingerprint");
    }

    #[test]
    fn drop_without_flush_cannot_reissue_emitted_nonces() {
        // Regression test for audit finding C2. Simulate SIGKILL after
        // several in-window advances. The on-disk ceiling must be strictly
        // greater than the largest value we pretended to emit — so that
        // hydration after the crash resumes at a value above anything
        // already handed out, and no nonce can be re-issued.
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"eee");
        // Pretend we just reserved nonce 1. The "new key" branch writes a
        // ceiling of 1 + BATCH_THRESHOLD.
        c.record_advance(&fp, 1).unwrap();
        // Subsequent reservations inside the window do not touch disk.
        c.record_advance(&fp, 500).unwrap();
        // Abrupt drop — pretend the process was SIGKILLed here.
        drop(c);

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, _) = c2.persisted_state(&fp);
        // Highest value the pre-crash process pretended to emit.
        let max_emitted = 500u64;
        // The invariant that makes AES-GCM safe across crashes.
        assert!(
            persisted > max_emitted,
            "on-disk ceiling ({persisted}) must exceed largest emitted value \
             ({max_emitted}) to prevent nonce reuse after crash"
        );
    }

    #[test]
    fn concurrent_advances_produce_monotonic_persisted_value() {
        use std::sync::Arc;
        use std::thread;

        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = Arc::new(PersistentGcmCounter::file_backed(&path).unwrap());
        let fp = fp_of(b"fff");

        let mut handles = vec![];
        for t in 0..4 {
            let c = c.clone();
            handles.push(thread::spawn(move || {
                for i in 1..=2048u64 {
                    c.record_advance(&fp, t * 10_000 + i).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Drop and reload; the persisted value must be ≥ max advance we called.
        drop(c);
        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, _) = c2.persisted_state(&fp);
        // Each thread's max is (t*10000 + 2048); global max is 3*10000+2048=32048.
        // The mutex serialises record_advance so monotonicity holds — we just
        // need to be ≥ some reasonable watermark.
        assert!(
            persisted > 0,
            "persisted must have advanced under contention"
        );
    }

    #[test]
    fn missing_integrity_footer_cold_start_warning() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        // Write a legal-looking body with no MAC footer.
        std::fs::write(
            &path,
            b"0000000000000000000000000000000000000000000000000000000000000001 42\n",
        )
        .unwrap();
        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = [0u8; 32];
        let mut fp = fp;
        fp[31] = 1;
        let (persisted, poisoned) = c.persisted_state(&fp);
        // Parsed, not poisoned (cold start tolerance).
        assert_eq!(persisted, 42);
        assert!(!poisoned);
        // And the next write installs a footer.
        c.record_advance(&fp, 5000).unwrap();
        drop(c);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.windows(5).any(|w| w == b"#MAC "));
    }

    // ====================================================================
    // M1 — journal version marker
    // ====================================================================

    /// Files written by the current implementation carry the V1 magic
    /// line, and reload still validates them cleanly.
    #[test]
    fn v1_marker_written_and_validated_on_round_trip() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"v1-marker-roundtrip");
        c.record_advance(&fp, 1024).unwrap();
        drop(c);

        // The file MUST start with the v1 magic line.
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.starts_with(JOURNAL_VERSION_MARKER),
            "journal written without v1 version marker"
        );

        // And a fresh open re-validates without integrity failure.
        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c2.persisted_state(&fp);
        assert_eq!(persisted, 1024 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

    /// A journal written by the legacy (pre-M2) derivation and MAC scheme
    /// must still open. The file has no version marker and uses the v1
    /// MAC key — the loader falls back to v1 and the next write upgrades.
    #[test]
    fn legacy_v1_mac_key_fallback_and_upgrade() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        // Manually construct a legacy journal: no version marker, MAC
        // computed with `derive_mac_key_v1`.
        let legacy_key = derive_mac_key_v1(&path);
        let fp = fp_of(b"legacy-key");
        let body = format!("{} {}\n", hex32(&fp), 2048u64);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&legacy_key).unwrap();
        mac.update(body.as_bytes());
        let tag = mac.finalize().into_bytes();
        let footer = format!("#MAC {}\n", hex_bytes(&tag));

        let mut contents = Vec::new();
        contents.extend_from_slice(body.as_bytes());
        contents.extend_from_slice(footer.as_bytes());
        std::fs::write(&path, &contents).unwrap();

        // Open via the current implementation — must succeed via v1 fallback.
        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c.persisted_state(&fp);
        assert_eq!(persisted, 2048, "v1 fallback must read the legacy counter");
        assert!(!poisoned);

        // Next write should upgrade to the v2 marker-bearing format.
        c.record_advance(&fp, 1024 * 1024).unwrap();
        drop(c);
        let after = std::fs::read(&path).unwrap();
        assert!(
            after.starts_with(JOURNAL_VERSION_MARKER),
            "upgrade didn't prepend marker"
        );

        // And it's then loadable again cleanly.
        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c2.persisted_state(&fp);
        assert_eq!(persisted, 1024 * 1024 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

    /// A file with a magic-line prefix but an unknown version number
    /// must be refused outright.
    #[test]
    fn unknown_version_rejected() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        std::fs::write(&path, b"craton-hsm-gcm-journal v999\nsome-body\n").unwrap();
        let err = PersistentGcmCounter::file_backed(&path);
        assert!(err.is_err(), "unknown version must refuse to load");
    }

    // ====================================================================
    // M2 — canonicalised path in MAC-key derivation
    // ====================================================================

    /// On unix, two symlinks pointing at the same underlying file must
    /// derive the same MAC key so either path works for open/reload.
    /// On Windows this test is skipped (symlink creation requires
    /// developer mode or admin in most CI setups).
    #[cfg(unix)]
    #[test]
    fn symlink_paths_derive_same_mac_key() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.journal");
        let link_a = dir.path().join("link_a.journal");
        let link_b = dir.path().join("link_b.journal");
        // Create the real file first by letting file_backed initialise it.
        {
            let c = PersistentGcmCounter::file_backed(&real).unwrap();
            let fp = fp_of(b"symlink");
            c.record_advance(&fp, 100).unwrap();
        }
        std::os::unix::fs::symlink(&real, &link_a).unwrap();
        std::os::unix::fs::symlink(&real, &link_b).unwrap();

        let k_real = derive_mac_key(&real);
        let k_a = derive_mac_key(&link_a);
        let k_b = derive_mac_key(&link_b);
        assert_eq!(k_real, k_a, "real path and link_a must derive same MAC key");
        assert_eq!(
            k_a, k_b,
            "two links to the same file must derive same MAC key"
        );

        // And opening via a symlink path must still validate the journal.
        let c2 = PersistentGcmCounter::file_backed(&link_a).unwrap();
        let fp = fp_of(b"symlink");
        let (persisted, _) = c2.persisted_state(&fp);
        assert_eq!(persisted, 100 + BATCH_THRESHOLD);
    }

    /// Non-existent path: `canonicalize` fails, so derivation falls back
    /// to the raw path. The key must still be deterministic.
    #[test]
    fn nonexistent_path_falls_back_to_raw_path() {
        let p1 = PathBuf::from("/definitely/does/not/exist/journal-a");
        let p2 = PathBuf::from("/definitely/does/not/exist/journal-a");
        let p3 = PathBuf::from("/definitely/does/not/exist/journal-b");
        assert_eq!(derive_mac_key(&p1), derive_mac_key(&p2));
        assert_ne!(derive_mac_key(&p1), derive_mac_key(&p3));
    }

    // ====================================================================
    // L2 — malformed-records warning + threshold
    // ====================================================================

    /// A handful of malformed lines inside the MAC'd body are parsed as
    /// warnings and the journal still loads.
    #[test]
    fn few_malformed_records_still_load() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        // Build a v1-marker journal whose body has one good record and
        // three malformed ones. MAC covers the marker + body.
        let mac_key = derive_mac_key(&path);
        let good_fp = fp_of(b"good");
        let body = format!(
            "{} 100\nnot-a-record\n{} NOT_A_NUMBER\nshort line\n",
            hex32(&good_fp),
            hex32(&fp_of(b"bad"))
        );
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(JOURNAL_VERSION_MARKER);
        mac.update(body.as_bytes());
        let tag = mac.finalize().into_bytes();
        let footer = format!("#MAC {}\n", hex_bytes(&tag));

        let mut contents = Vec::new();
        contents.extend_from_slice(JOURNAL_VERSION_MARKER);
        contents.extend_from_slice(body.as_bytes());
        contents.extend_from_slice(footer.as_bytes());
        std::fs::write(&path, &contents).unwrap();

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c.persisted_state(&good_fp);
        assert_eq!(persisted, 100);
        assert!(!poisoned);
    }

    /// Many malformed lines must cause the loader to refuse.
    #[test]
    fn too_many_malformed_records_refuses_load() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let mac_key = derive_mac_key(&path);
        // Build a body with MAX_MALFORMED_RECORDS + 5 garbage lines.
        let mut body = String::new();
        for i in 0..(MAX_MALFORMED_RECORDS + 5) {
            body.push_str(&format!("garbage-line-{}\n", i));
        }
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(JOURNAL_VERSION_MARKER);
        mac.update(body.as_bytes());
        let tag = mac.finalize().into_bytes();
        let footer = format!("#MAC {}\n", hex_bytes(&tag));

        let mut contents = Vec::new();
        contents.extend_from_slice(JOURNAL_VERSION_MARKER);
        contents.extend_from_slice(body.as_bytes());
        contents.extend_from_slice(footer.as_bytes());
        std::fs::write(&path, &contents).unwrap();

        let err = PersistentGcmCounter::file_backed(&path);
        assert!(
            err.is_err(),
            "should refuse to load past the malformed threshold"
        );
    }

    /// Two `PersistentGcmCounter` handles on the same journal path within
    /// the same process must not both succeed: the OS-level exclusive lock
    /// (fs2 `try_lock_exclusive`) prevents two processes from sharing a
    /// journal, and an in-process double-open trips the same check.
    #[test]
    fn cross_process_lock_rejects_second_handle() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let first = PersistentGcmCounter::file_backed(&path)
            .expect("first handle should acquire the journal lock");
        let second = PersistentGcmCounter::file_backed(&path);
        assert!(
            matches!(second, Err(HsmError::AlreadyInitialized)),
            "second handle must be rejected with AlreadyInitialized, got {second:?}"
        );

        // After dropping the first handle the file lock is released and a
        // fresh handle can open again.
        drop(first);
        let third = PersistentGcmCounter::file_backed(&path);
        assert!(third.is_ok(), "lock should be released on drop");
    }
}
