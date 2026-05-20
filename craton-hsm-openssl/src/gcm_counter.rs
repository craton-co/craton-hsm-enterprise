// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Persistent backing store for the AES-GCM per-key nonce counter.
//!
//! Mirror of `craton-hsm-awslc::gcm_counter` kept deliberately separate
//! (per-crate, not shared) so each backend can evolve its counter format
//! independently if needed. The two modules expose nearly identical public
//! APIs and on-disk formats; any change here that affects the file layout
//! should be mirrored into the awslc crate and vice versa.
//!
//! # File format
//!
//! Journal files begin with a version magic line and contain newline-delimited
//! records followed by an integrity footer:
//!
//! - `craton-hsm-gcm-journal v1\n`  (M1: mandatory on all newly-written files)
//! - `<hex-fingerprint> <u64-counter-ceiling>\n`
//! - `<hex-fingerprint> POISONED\n`
//! - `#MAC <hex-hmac-sha256-over-version-marker-and-all-preceding-bytes>\n`
//!
//! Legacy (pre-M1) files are accepted on load when the v1 MAC key verifies;
//! the next write upgrades them to a v1 marker-bearing file.
//!
//! # Flush policy (write-ahead reservation)
//!
//! To amortise fsync cost without risking nonce reuse on crash, the on-disk
//! value for each fingerprint is a **reservation ceiling** — a value strictly
//! greater than any nonce ever emitted for the key in this process. When the
//! caller asks us to record that nonce `N` has been reserved, one of two
//! things happens:
//!
//! - `N` is still at or below the current ceiling: no I/O (the emitted value
//!   is inside the already-reserved window).
//! - `N` has reached the ceiling: we fsync a new ceiling of
//!   `N + BATCH_THRESHOLD` and fail the caller if the write fails.
//!
//! Because the on-disk value is always > the largest emitted value, a
//! SIGKILL between flushes cannot re-issue a previously emitted nonce on
//! restart: hydration resumes at `ceiling + 1` (see audit finding C2).
//!
//! # Crash atomicity (audit C-1)
//!
//! Every journal rewrite goes through the write-temp-then-rename dance:
//!
//!   1. Build the new full body + footer in memory.
//!   2. Write it to a sibling `NamedTempFile` in the journal's parent dir.
//!   3. `fsync` the temp file.
//!   4. `rename(2)` the temp over the target journal path (atomic on POSIX
//!      and on Win32 via `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`).
//!   5. `fsync` the parent directory on Unix so the rename is durable.
//!
//! A crash anywhere **before** the rename leaves the original journal
//! byte-for-byte untouched — the temp file just becomes garbage that the
//! operator (or a janitor) can reap. A crash **during** the rename is
//! atomic at the filesystem level: either the rename took effect or it
//! did not. We never call `set_len(0)` followed by a re-write on the
//! target path, which would expose a zero-byte journal on SIGKILL and
//! reset every fingerprint's nonce ceiling to 0 — exactly the failure
//! mode this counter was designed to prevent.
//!
//! # MAC key derivation
//!
//! HMAC-SHA256 key = `SHA-256("craton-hsm-gcm-counter-v2" || domain-separated
//! (canonicalised path, inode/file-index))`. Stable across restarts for a
//! given file identity (so we can integrity-check after a crash) but
//! forgeable by anyone with local filesystem access. This is the right
//! trade-off for a counter file that lives in the same protected data
//! directory as the keys: the MAC guards against accidental corruption /
//! truncation, not adversarial rewrite (which would already be game over).
//!
//! Legacy (pre-M2) files were keyed on raw-path only with a `v1` domain
//! tag; if the v2 key fails to validate and no version marker is present,
//! the loader falls back to the v1 key and then upgrades on the next write.

// Targeted allow(dead_code) (audit): blanket allow removed.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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

/// Compute `SHA-256(key)` as a 32-byte fingerprint. The openssl backend keys
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

/// Threshold (in bytes) past which the append-only journal is compacted: we
/// rewrite the file with one record per known fingerprint instead of the
/// running history. Picked at 8 MiB so steady-state operators never see a
/// rewrite and only pathological flush-storms do.
const COMPACTION_BYTES_THRESHOLD: u64 = 8 * 1024 * 1024;

/// Threshold (in records) past which the append-only journal is compacted.
/// Caps the worst-case load-time MAC scan at a known size even when records
/// are tiny.
const COMPACTION_RECORDS_THRESHOLD: usize = 4096;

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
    /// In-memory cache of the journal body (everything between the version
    /// marker and the trailing `#MAC` footer). Used to avoid re-reading the
    /// whole file on every flush; updated in lock-step with the on-disk
    /// state. The body is never separated from the file by more than one
    /// record write.
    body_cache: Vec<u8>,
    /// Number of records currently appended to the body cache. Used to
    /// trigger compaction.
    appended_records: usize,
}

impl PersistentGcmCounter {
    /// No-op persistence layer — preserves the legacy in-memory-only behaviour.
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Inner::InMemory),
        }
    }

    /// Test-only: build a counter whose `flush_fingerprint` always fails,
    /// so callers can exercise the flush-failure-streak → poison logic
    /// without a real filesystem mishap.
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

    /// File-backed journal. Creates the file if absent, otherwise loads and
    /// verifies integrity.
    pub fn file_backed(path: impl Into<PathBuf>) -> HsmResult<Self> {
        let path = path.into();
        let mac_key = derive_mac_key(&path);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                tracing::error!(
                    target: "craton_hsm_openssl::gcm",
                    error=%e, path=%path.display(),
                    "failed to open GCM counter file"
                );
                HsmError::GeneralError
            })?;

        // Try the current (v2) MAC key first. If the file exists but fails
        // v2 integrity *and* the file has no version marker, attempt the
        // legacy v1 MAC-key derivation — pre-M2 journals were written with
        // that key and must continue to open. Successful v1 validation is
        // an implicit upgrade trigger: the next write re-keys the file.
        let (known, integrity_failed, valid_len) = load_and_verify(&mut file, &mac_key)?;
        let (known, integrity_failed, valid_len) = if integrity_failed
            && !file_has_version_marker(&mut file)?
        {
            if v2_sentinel_path(&path).exists() {
                tracing::error!(
                    target: "craton_hsm_openssl::gcm",
                    path=%path.display(),
                    "v1 fallback refused: v2 sentinel sidecar present"
                );
                (known, integrity_failed, valid_len)
            } else {
                let legacy_key = derive_mac_key_v1(&path);
                match load_and_verify(&mut file, &legacy_key) {
                    Ok((k, false, v)) => {
                        tracing::info!(
                            target: "craton_hsm_openssl::gcm",
                            path=%path.display(),
                            "GCM journal verified with legacy v1 MAC key; will re-key on next write"
                        );
                        (k, false, v)
                    }
                    _ => (known, integrity_failed, valid_len),
                }
            }
        } else {
            (known, integrity_failed, valid_len)
        };

        if integrity_failed {
            tracing::error!(
                target: "craton_hsm_openssl::gcm",
                path=%path.display(),
                "AES-GCM counter file failed integrity check — treating all prior fingerprints as poisoned"
            );
        } else if valid_len < file_len(&file)? {
            tracing::warn!(
                target: "craton_hsm_openssl::gcm",
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

        // Hydrate the in-memory body cache from the on-disk body (if any).
        // We need the body bytes minus the version marker and trailing
        // `#MAC` footer; the easiest correct path is to call the same
        // helper used by `write_record` before it appends.
        let body_cache = match read_journal_body(&mut file) {
            Ok(b) => b,
            Err(_) => Vec::new(),
        };
        let appended_records = body_cache.iter().filter(|&&b| b == b'\n').count();
        let fb = FileBacked {
            path,
            file,
            mac_key,
            known,
            integrity_failed,
            body_cache,
            appended_records,
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

    /// Extend the on-disk reservation for `fp` if `new_count` has reached
    /// the existing ceiling. See the crate-level docs for the C2 rationale.
    pub(crate) fn record_advance(&self, fp: &[u8; 32], new_count: u64) -> HsmResult<()> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::InMemory => Ok(()),
            Inner::FileBacked(fb) => {
                if fb.integrity_failed {
                    tracing::error!(
                        target: "craton_hsm_openssl::gcm",
                        "AES-GCM counter file is in a failed-integrity state; refusing to advance"
                    );
                    return Err(HsmError::GeneralError);
                }
                let (is_new, current_persisted) = match fb.known.get(fp) {
                    Some(e) => (e.persisted == 0, e.persisted),
                    None => (true, 0),
                };
                // Inside the already-reserved window? No disk I/O needed.
                if !is_new && new_count <= current_persisted {
                    return Ok(());
                }
                // Extend the reservation. Ceiling is strictly greater than
                // any value emittable for this key in this process, so a
                // crash between now and the next flush cannot re-issue
                // any emitted nonce. Saturate at the NIST 2^32 ceiling.
                let ceiling = new_count
                    .saturating_add(BATCH_THRESHOLD)
                    .min(AES_GCM_NONCE_LIMIT);
                append_record(fb, fp, RecordKind::Count(ceiling))?;
                let entry = fb.known.entry(*fp).or_default();
                entry.persisted = ceiling;
                Ok(())
            }
            #[cfg(test)]
            Inner::FailingFlush(ff) => {
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
                let current_persisted = fb.known.get(fp).map(|e| e.persisted).unwrap_or(0);
                if new_count <= current_persisted {
                    return Ok(());
                }
                append_record(fb, fp, RecordKind::Count(new_count))?;
                let entry = fb.known.entry(*fp).or_default();
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

    pub(crate) fn record_poison(&self, fp: &[u8; 32]) -> HsmResult<()> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::InMemory => Ok(()),
            Inner::FileBacked(fb) => {
                if fb.integrity_failed {
                    return Ok(());
                }
                append_record(fb, fp, RecordKind::Poisoned)?;
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
                    if v2_sentinel_path(&path).exists() {
                        (known, integrity_failed, valid_len)
                    } else {
                        let legacy_key = derive_mac_key_v1(&path);
                        match load_and_verify(&mut file, &legacy_key) {
                            Ok((k, false, v)) => (k, false, v),
                            _ => (known, integrity_failed, valid_len),
                        }
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
            let body_cache = read_journal_body(&mut file).unwrap_or_default();
            let appended_records = body_cache.iter().filter(|&&b| b == b'\n').count();
            fb.file = file;
            fb.known = known;
            fb.integrity_failed = integrity_failed;
            fb.body_cache = body_cache;
            fb.appended_records = appended_records;
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

/// Install the process-global persistent GCM counter.
///
/// May be called at most once per process; subsequent calls return an error.
/// If never called, a fallback in-memory counter is used.
pub fn install(counter: PersistentGcmCounter) -> HsmResult<()> {
    PERSIST.set(counter).map_err(|_| HsmError::GeneralError)
}

pub(crate) fn current() -> &'static PersistentGcmCounter {
    static FALLBACK: OnceLock<PersistentGcmCounter> = OnceLock::new();
    PERSIST
        .get()
        .unwrap_or_else(|| FALLBACK.get_or_init(PersistentGcmCounter::in_memory))
}

// ============================================================================
// Record I/O
// ============================================================================

enum RecordKind {
    Count(u64),
    Poisoned,
}

/// Read the on-disk body (excluding the version marker and the trailing
/// `#MAC` footer). Used to hydrate `FileBacked::body_cache` after a load or
/// reload. Wraps [`read_without_footer_or_marker`] which leaves the file
/// cursor at EOF.
fn read_journal_body(file: &mut File) -> HsmResult<Vec<u8>> {
    read_without_footer_or_marker(file)
}

/// Append a record to the journal in-place using the cached body, then
/// rewrite only the trailing `#MAC` footer. Avoids the per-flush re-read of
/// the full file in the previous implementation. Triggers compaction when
/// the cumulative body size or record count exceeds the configured limits.
fn append_record(fb: &mut FileBacked, fp: &[u8; 32], kind: RecordKind) -> HsmResult<()> {
    // Format the new record line directly into the body cache to avoid the
    // per-record `format!` allocation (audit perf): one `String`/`Vec`
    // allocation per flush is enough; the hot path doesn't need a fresh
    // intermediate string for the fingerprint encoding.
    let mut line: Vec<u8> = Vec::with_capacity(64 + 1 + 22 + 1);
    push_hex_bytes(&mut line, fp);
    line.push(b' ');
    match kind {
        RecordKind::Count(n) => {
            // u64 max is 20 decimal digits; the std `write!` formatter
            // (via `io::Write`, already in scope) does not allocate for
            // the integer itself.
            let _ = write!(&mut line, "{}", n);
        }
        RecordKind::Poisoned => {
            line.extend_from_slice(b"POISONED");
        }
    }
    line.push(b'\n');
    fb.body_cache.extend_from_slice(&line);
    fb.appended_records += 1;

    // Compaction trigger: when the body has grown past the byte or record
    // threshold, rewrite the journal as one record per fingerprint. The
    // semantics are unchanged — the most recent value for each fingerprint
    // is what matters; intermediate counts can be safely collapsed.
    let needs_compaction = fb.body_cache.len() as u64 > COMPACTION_BYTES_THRESHOLD
        || fb.appended_records > COMPACTION_RECORDS_THRESHOLD;
    if needs_compaction {
        compact_journal(fb)?;
    } else {
        // Hot path: rewrite the file contents atomically via the
        // write-temp-then-rename dance in `flush_body_to_disk`. We can't
        // append: the trailing `#MAC` footer must always sit at EOF, and
        // incrementally appending a new footer without erasing the old
        // one would leave two footers behind. The temp+rename approach
        // also gives crash atomicity (audit finding C-1) — no partial
        // state ever lands on the target path.
        flush_body_to_disk(fb)?;
    }
    ensure_v2_sentinel(&fb.path);
    Ok(())
}

/// Rewrite the journal atomically: build the new contents in a sibling temp
/// file, `fsync` it, then `rename(2)` it over the target path. The original
/// journal is never observed in a partial state — see the module-level
/// "Crash atomicity" section (audit C-1).
///
/// The previous implementation called `set_len(0)` on the live file before
/// re-writing. A SIGKILL between the truncate and the new write produced a
/// zero-byte journal on disk, which on next open reset every fingerprint's
/// ceiling to 0 and allowed re-emission of previously-issued GCM nonces.
/// That is exactly the failure mode this counter exists to prevent.
///
/// On error before the rename, the on-disk file is unchanged and the temp
/// file is dropped (and unlinked by `NamedTempFile`'s Drop). On error during
/// the rename itself we surface a `HsmError::GeneralError` — POSIX guarantees
/// the rename is atomic, so the target is either entirely the old contents
/// or entirely the new.
fn flush_body_to_disk(fb: &mut FileBacked) -> HsmResult<()> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&fb.mac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(JOURNAL_VERSION_MARKER);
    mac.update(&fb.body_cache);
    let tag = mac.finalize().into_bytes();
    let footer = format!("#MAC {}\n", hex_bytes(&tag));

    // Pre-compose the entire new file payload in memory so we make exactly
    // one `write_all` syscall to the temp file. This bounds the worst-case
    // write fragmentation and avoids leaving the temp in a half-flushed
    // state if the process is interrupted mid-write (the temp is dropped
    // and the original journal is untouched).
    let mut payload =
        Vec::with_capacity(JOURNAL_VERSION_MARKER.len() + fb.body_cache.len() + footer.len());
    payload.extend_from_slice(JOURNAL_VERSION_MARKER);
    payload.extend_from_slice(&fb.body_cache);
    payload.extend_from_slice(footer.as_bytes());

    // Sibling-directory temp file: `persist` requires the temp to live on
    // the same filesystem as the destination so `rename(2)` is in fact
    // atomic. `NamedTempFile::new_in(parent)` enforces that placement.
    let parent_dir = fb
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let mut tmp = tempfile::NamedTempFile::new_in(&parent_dir).map_err(|e| {
        tracing::error!(
            target: "craton_hsm_openssl::gcm",
            error=%e, parent=%parent_dir.display(),
            "failed to create temp journal for atomic flush"
        );
        HsmError::GeneralError
    })?;
    tmp.write_all(&payload).map_err(|e| {
        tracing::error!(
            target: "craton_hsm_openssl::gcm",
            error=%e,
            "failed to write temp journal payload"
        );
        HsmError::GeneralError
    })?;
    // Durably commit the temp body before the rename. Without this fsync the
    // rename could land before the data, leaving a renamed but empty journal
    // visible after a power loss.
    tmp.as_file().sync_all().map_err(|e| {
        tracing::error!(
            target: "craton_hsm_openssl::gcm",
            error=%e,
            "fsync on temp journal failed"
        );
        HsmError::GeneralError
    })?;

    // `persist` returns the underlying File on success. On Windows the
    // target must not exist for `rename`-style atomicity by default, but
    // `NamedTempFile::persist` on stable uses `MoveFileExW` with
    // `MOVEFILE_REPLACE_EXISTING` via the same code path Unix uses for
    // `rename`. If the platform refuses overwrite, the error bubbles up
    // and the original journal is unchanged.
    let new_file = tmp.persist(&fb.path).map_err(|e| {
        tracing::error!(
            target: "craton_hsm_openssl::gcm",
            error=%e.error, path=%fb.path.display(),
            "atomic rename of GCM journal temp file failed"
        );
        HsmError::GeneralError
    })?;

    // Replace the held File handle with the just-renamed file's handle so
    // subsequent reload / mac-recompute paths see the new contents.
    fb.file = new_file;
    fb.file
        .seek(SeekFrom::End(0))
        .map_err(|_| HsmError::GeneralError)?;

    // On Unix the rename itself is atomic, but the directory entry change
    // is not durable until the parent directory is fsynced. Skip on Windows
    // — there is no public stable way to open a directory handle for
    // fsync, and `MoveFileExW` already does the equivalent metadata sync
    // when the target volume is NTFS.
    sync_parent_dir(&fb.path);

    Ok(())
}

/// fsync the parent directory of `path` on Unix so a preceding `rename(2)`
/// is durable across a power loss. No-op on platforms that do not expose
/// directory fsync semantics.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {
    // Windows: `MoveFileExW(REPLACE_EXISTING)` already commits the
    // directory entry change for the target volume; there is no stable,
    // safe API to open a directory handle for fsync. Other targets:
    // best-effort no-op.
}

/// Replace the journal body with a canonical compacted representation: one
/// record per known fingerprint, with the latest counter / poison state.
fn compact_journal(fb: &mut FileBacked) -> HsmResult<()> {
    let mut lines = String::new();
    // Iterate `known` deterministically by sorting fingerprints so the
    // post-compaction file is reproducible across runs.
    let mut keys: Vec<[u8; 32]> = fb.known.keys().copied().collect();
    keys.sort_unstable();
    for fp in &keys {
        let entry = fb.known.get(fp).expect("present");
        if entry.poisoned {
            // Inline encoding — avoid the per-record `format!` allocation
            // hit. Body cache eventually becomes the temp-file payload, so
            // any saved alloc here directly reduces flush latency.
            // SAFETY-equivalent: only ASCII hex + literal text is appended,
            // so the resulting `String` is well-formed UTF-8.
            push_hex_into_string(&mut lines, fp);
            lines.push_str(" POISONED\n");
        } else if entry.persisted > 0 {
            push_hex_into_string(&mut lines, fp);
            lines.push(' ');
            use std::fmt::Write as _;
            let _ = write!(lines, "{}", entry.persisted);
            lines.push('\n');
        }
    }
    fb.body_cache = lines.into_bytes();
    fb.appended_records = keys.len();
    flush_body_to_disk(fb)?;
    tracing::debug!(
        target: "craton_hsm_openssl::gcm",
        records = fb.appended_records,
        "compacted AES-GCM journal"
    );
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
    const PREFIX: &[u8] = b"craton-hsm-gcm-journal ";
    if all.starts_with(PREFIX) {
        let line_end = all.iter().position(|&b| b == b'\n').unwrap_or(all.len());
        let version_str = String::from_utf8_lossy(&all[..line_end]);
        tracing::error!(
            target: "craton_hsm_openssl::gcm",
            header = %version_str,
            "unknown GCM journal format version — refusing to load"
        );
        return Err(HsmError::GeneralError);
    }
    Ok(VersionCheck::Legacy { body: all })
}

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
                target: "craton_hsm_openssl::gcm",
                malformed = malformed,
                threshold = MAX_MALFORMED_RECORDS,
                "GCM journal has more than {} malformed records — refusing to load",
                MAX_MALFORMED_RECORDS
            );
            return Err(HsmError::GeneralError);
        }
        Ok(known)
    };

    let (body, footer_tag) = match split_footer(body_slice) {
        Some(x) => x,
        None => {
            tracing::warn!(
                target: "craton_hsm_openssl::gcm",
                "AES-GCM counter file has no integrity footer; treating as cold start"
            );
            let known = parse_and_check(body_slice)?;
            let valid_len = all.len() as u64;
            return Ok((known, false, valid_len));
        }
    };

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
            let known = parse_and_check(body)?;
            return Ok((known, true, 0));
        }
    };
    // Constant-time compare of raw bytes (not hex strings) to avoid leaking
    // the mismatch position via timing.
    let ok = subtle::ConstantTimeEq::ct_eq(expected.as_slice(), footer_bytes.as_slice())
        .unwrap_u8()
        == 1;

    if !ok {
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
    // Find the last well-formed `#MAC <hex>\n` line. Anything after it is
    // garbage and the caller will truncate it. Scan from the end so trailing
    // garbage does not fool us into reading an interior line as the footer.
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

        let after = &all[idx..];
        if let Some(nl) = after.iter().position(|&b| b == b'\n') {
            let line = &after[..nl];
            if let Some(rest) = line.strip_prefix(b"#MAC ") {
                if let Ok(tag) = std::str::from_utf8(rest) {
                    return Some((&all[..idx], tag.to_string()));
                }
            }
        }

        if idx == 0 {
            return None;
        }
        search_end = idx - 1;
    }
}

fn find_last_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::rfind(haystack, needle)
}

/// Parse a body of newline-delimited records. Malformed lines are logged at
/// `WARN` (audit finding L2) and counted; the caller decides whether the
/// count exceeds [`MAX_MALFORMED_RECORDS`] and refuses the load.
fn parse_records(body: &[u8]) -> (HashMap<[u8; 32], PersistEntry>, usize) {
    let mut out: HashMap<[u8; 32], PersistEntry> = HashMap::new();
    let mut malformed: usize = 0;
    for (lineno, line_bytes) in body.split(|&b| b == b'\n').enumerate() {
        let line = match std::str::from_utf8(line_bytes) {
            Ok(s) => s,
            Err(_) => {
                malformed += 1;
                tracing::warn!(
                    target: "craton_hsm_openssl::gcm",
                    line = lineno + 1,
                    "skipping malformed GCM journal line: invalid utf-8"
                );
                continue;
            }
        };
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
                    target: "craton_hsm_openssl::gcm",
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
                    target: "craton_hsm_openssl::gcm",
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
                    target: "craton_hsm_openssl::gcm",
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
            if n > entry.persisted {
                entry.persisted = n;
            }
            if n >= AES_GCM_NONCE_LIMIT {
                entry.poisoned = true;
            }
        } else {
            malformed += 1;
            tracing::warn!(
                target: "craton_hsm_openssl::gcm",
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
    let _ = file.seek(SeekFrom::End(0));
    Ok(buf == JOURNAL_VERSION_MARKER)
}

/// Sidecar path marking a journal as v2-MAC-key (audit M1 rollback guard).
fn v2_sentinel_path(journal: &Path) -> PathBuf {
    let mut p = journal.as_os_str().to_owned();
    p.push(".v2");
    PathBuf::from(p)
}

/// Atomically create the v2 sidecar (no-op if already exists).
fn ensure_v2_sentinel(journal: &Path) {
    let p = v2_sentinel_path(journal);
    if p.exists() {
        return;
    }
    match OpenOptions::new().write(true).create_new(true).open(&p) {
        Ok(mut f) => {
            let _ = f.write_all(
                b"craton-hsm-gcm-journal-v2-sentinel
",
            );
            let _ = f.sync_all();
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            tracing::warn!(
                target: "craton_hsm_openssl::gcm",
                error=%e, path=%p.display(),
                "failed to create v2 sentinel sidecar (continuing)"
            );
        }
    }
}

fn derive_mac_key(path: &Path) -> [u8; 32] {
    // H5: if the operator provides a bootstrap secret via the
    // CRATON_HSM_GCM_JOURNAL_KEY env var (hex-encoded 32 bytes) we
    // prefer it over the path-derived key. The path-derived fallback
    // is forgeable by anyone with local FS access; the env-supplied
    // secret raises the bar to whoever can read the daemon env.
    // The env value is a long-lived secret — wrap the local copy in
    // `Zeroizing` so the heap allocation backing the string is scrubbed
    // before being released, and scrub the intermediate 32-byte buffer
    // before returning. Without this the secret would linger in the
    // freed-heap pool after this function returns, exactly contrary to
    // the threat model the env-supplied key was added to address.
    if let Ok(hex_raw) = std::env::var("CRATON_HSM_GCM_JOURNAL_KEY") {
        let hex: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(hex_raw);
        if hex.len() == 64 {
            let mut out: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
            let mut ok = true;
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                let hi = match hex_nib(chunk[0]) {
                    Some(v) => v,
                    None => {
                        ok = false;
                        break;
                    }
                };
                let lo = match hex_nib(chunk[1]) {
                    Some(v) => v,
                    None => {
                        ok = false;
                        break;
                    }
                };
                out[i] = (hi << 4) | lo;
            }
            if ok {
                tracing::info!(
                    target: "craton_hsm_openssl::gcm",
                    "GCM journal MAC key sourced from CRATON_HSM_GCM_JOURNAL_KEY"
                );
                // Mix in path so two distinct journals don't share a key.
                let mut h = Sha256::new();
                h.update(b"craton-hsm-gcm-counter-env-v1");
                h.update(&*out);
                h.update(b" path:");
                h.update(path.as_os_str().to_string_lossy().as_bytes());
                return h.finalize().into();
            }
            tracing::warn!(
                target: "craton_hsm_openssl::gcm",
                "CRATON_HSM_GCM_JOURNAL_KEY had non-hex characters; ignoring"
            );
        } else {
            tracing::warn!(
                target: "craton_hsm_openssl::gcm",
                len = hex.len(),
                "CRATON_HSM_GCM_JOURNAL_KEY must be 64 hex chars; ignoring"
            );
        }
    }
    // M2: canonicalise the path and, if the file already exists, incorporate
    // the OS-level file identity (inode on unix, file-index on windows).
    // This means two symlinks to the same underlying file derive the *same*
    // MAC key, so a journal written via one path validates when re-opened
    // via the other — and spoofing via a different file (even with the
    // same user-visible name) is caught by the integrity check.
    //
    // Errors from `canonicalize` (file does not yet exist on first run,
    // permission denied, etc.) fall back to the supplied path. In that mode
    // we get no cross-symlink equivalence — historical behaviour.
    derive_mac_key_v2(path)
}

/// v2 MAC-key derivation (canonicalised path + inode/file-id). See
/// [`derive_mac_key`] for the tradeoff discussion.
fn derive_mac_key_v2(path: &Path) -> [u8; 32] {
    let (canon_bytes, id_bytes): (Vec<u8>, Option<Vec<u8>>) = match std::fs::canonicalize(path) {
        Ok(canon) => {
            let id = fs_file_identity(&canon);
            (canon.as_os_str().to_string_lossy().as_bytes().to_vec(), id)
        }
        Err(_) => (path.as_os_str().to_string_lossy().as_bytes().to_vec(), None),
    };

    let mut h = Sha256::new();
    h.update(b"craton-hsm-gcm-counter-v2");
    h.update(b"\x00path:");
    h.update(&canon_bytes);
    if let Some(id) = id_bytes {
        h.update(b"\x00id:");
        h.update(&id);
    }
    h.finalize().into()
}

/// v1 MAC-key derivation — retained ONLY for transparent upgrade of
/// pre-M2 journals.
fn derive_mac_key_v1(path: &Path) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"craton-hsm-gcm-counter-v1");
    h.update(path.as_os_str().to_string_lossy().as_bytes());
    h.finalize().into()
}

#[cfg(unix)]
fn fs_file_identity(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&md.dev().to_le_bytes());
    out.extend_from_slice(&md.ino().to_le_bytes());
    Some(out)
}

#[cfg(windows)]
fn fs_file_identity(path: &Path) -> Option<Vec<u8>> {
    // We want a stable identity tuple for the file (volume + file index)
    // that survives renames/moves on the same volume, mirroring the
    // (dev, ino) pair on Unix.
    //
    // `std::os::windows::fs::MetadataExt::file_index()` would give us the
    // 64-bit NTFS index, but it lives behind the unstable
    // `windows_by_handle` feature and therefore only compiles on nightly.
    // To stay on stable Rust we open the file and call the Win32
    // `GetFileInformationByHandle` directly, which is the API
    // `MetadataExt::file_index` itself wraps.
    //
    // Returned byte layout (little-endian, 16 bytes total):
    //   [0..4]   dwVolumeSerialNumber  (u32 LE)
    //   [4..8]   nFileIndexHigh        (u32 LE)
    //   [8..12]  nFileIndexLow         (u32 LE)
    //   [12..16] reserved zero padding (keeps the blob a round 16 bytes
    //            and gives us room for future extension without breaking
    //            v2 MAC-key derivation).
    //
    // **Integrity-binding caveat:** when the underlying filesystem does
    // not expose a unique file index (ReFS, some network mounts, or
    // handle types that reject GetFileInformationByHandle), the fallback
    // produces a constant all-zero blob. Two distinct journal files on
    // such a filesystem with the same canonical path representation
    // would then derive the same MAC key, weakening the integrity
    // binding to path-only. A one-shot warning at construction alerts
    // the operator (see `warn_windows_file_identity_degraded`).
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    // Read-only open is sufficient for GetFileInformationByHandle and
    // does not require write or delete access on the target path.
    let file = std::fs::File::open(path).ok()?;
    // SAFETY: `info` is fully written by `GetFileInformationByHandle` on
    // success; on failure we discard it and emit the degraded warning.
    // The handle comes from `File::open` above and remains live for the
    // duration of the call because `file` is not dropped until after the
    // unsafe block.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        // Win32 returns 0 on failure. Warn once so the operator knows
        // integrity-binding has degraded to path-only, then emit the
        // 16-byte all-zero blob so downstream length expectations are
        // still met.
        warn_windows_file_identity_degraded(path);
        return Some(vec![0u8; 16]);
    }

    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&info.dwVolumeSerialNumber.to_le_bytes());
    out.extend_from_slice(&info.nFileIndexHigh.to_le_bytes());
    out.extend_from_slice(&info.nFileIndexLow.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // reserved
    Some(out)
}

/// One-shot warning emitted when `file_index()` returns no NTFS file index —
/// typically on ReFS or some network mounts. Integrity-binding falls back
/// to a path-only key derivation in that case (see `fs_file_identity`).
#[cfg(windows)]
fn warn_windows_file_identity_degraded(path: &Path) {
    static WARNED: OnceLock<()> = OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            target: "craton_hsm_openssl::gcm",
            path = %path.display(),
            "Windows file_index() unavailable for GCM journal — integrity-binding falls \
             back to path-only key derivation; rotate the journal if the underlying \
             file system identity changes"
        );
    });
}

#[cfg(not(any(unix, windows)))]
fn fs_file_identity(_path: &Path) -> Option<Vec<u8>> {
    None
}

/// 256-entry lookup table for byte-to-two-hex-chars encoding (audit L1).
static HEX_TABLE: [[u8; 2]; 256] = {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut t = [[0u8; 2]; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i][0] = HEX[i >> 4];
        t[i][1] = HEX[i & 0xf];
        i += 1;
    }
    t
};

fn hex_bytes(b: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(b.len() * 2);
    for &byte in b {
        let pair = HEX_TABLE[byte as usize];
        bytes.push(pair[0]);
        bytes.push(pair[1]);
    }
    // SAFETY: every byte pushed into `bytes` came from `HEX_TABLE`, whose
    // entries are exclusively the ASCII characters `0-9` and `a-f`
    // (see the `HEX = b"0123456789abcdef"` constant used to build the
    // table). All such bytes are valid single-byte UTF-8 code units, so
    // the produced byte vector is by construction a well-formed UTF-8
    // string — exactly the invariant `String::from_utf8_unchecked`
    // requires.
    unsafe { String::from_utf8_unchecked(bytes) }
}

fn hex32(b: &[u8; 32]) -> String {
    hex_bytes(b)
}

/// Append the lower-case hex encoding of `b` to `out` without producing an
/// intermediate `String`. Used by `append_record` (per-flush hot path) to
/// avoid the `format!("{}", hex_bytes(fp))` allocation pair.
#[inline]
fn push_hex_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.reserve(b.len() * 2);
    for &byte in b {
        let pair = HEX_TABLE[byte as usize];
        out.push(pair[0]);
        out.push(pair[1]);
    }
}

/// String-flavoured counterpart to [`push_hex_bytes`], used by the
/// compaction path which builds a `String` directly.
#[inline]
fn push_hex_into_string(out: &mut String, b: &[u8]) {
    out.reserve(b.len() * 2);
    for &byte in b {
        let pair = HEX_TABLE[byte as usize];
        // SAFETY: `HEX_TABLE` only ever contains ASCII bytes `0-9` and
        // `a-f`, so each push extends `out` with a valid single-byte UTF-8
        // code unit. The invariant on `String` (valid UTF-8) is preserved.
        unsafe {
            let v = out.as_mut_vec();
            v.push(pair[0]);
            v.push(pair[1]);
        }
    }
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
        let fp = fp_of(b"k");
        assert_eq!(c.persisted_state(&fp), (0, false));
        c.record_advance(&fp, 500).unwrap();
        c.record_poison(&fp).unwrap();
        assert_eq!(c.persisted_state(&fp), (0, false));
    }

    #[test]
    fn round_trip_counter_survives_reload() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"aaa");
        c.record_advance(&fp, 1024).unwrap();
        c.record_advance(&fp, 4096).unwrap();
        drop(c);

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (p, poisoned) = c2.persisted_state(&fp);
        // The on-disk value is the reservation ceiling: strictly greater
        // than the largest emitted value (audit finding C2).
        assert_eq!(p, 4096 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

    #[test]
    fn poison_persists_across_reloads() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"bbb");
        c.record_advance(&fp, 1).unwrap();
        c.record_poison(&fp).unwrap();
        drop(c);

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (p, poisoned) = c2.persisted_state(&fp);
        assert!(poisoned);
        assert_eq!(p, AES_GCM_NONCE_LIMIT);
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

        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"garbage trailing line\n").unwrap();
            f.sync_all().unwrap();
        }

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (p, poisoned) = c2.persisted_state(&fp);
        assert_eq!(p, 1024 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

    #[test]
    fn integrity_mac_mismatch_fails_closed() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"ddd");
        c.record_advance(&fp, 4096).unwrap();
        drop(c);

        // Flip a byte in the numeric counter.
        let mut bytes = std::fs::read(&path).unwrap();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b' ' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                bytes[i + 1] ^= 0x01;
                break;
            }
        }
        std::fs::write(&path, &bytes).unwrap();

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (_, poisoned) = c2.persisted_state(&fp);
        assert!(
            poisoned,
            "integrity mismatch must fail closed for known fingerprints"
        );

        let err = c2.record_advance(&fp, 5000).unwrap_err();
        assert!(matches!(err, HsmError::GeneralError));
    }

    #[test]
    fn drop_without_flush_cannot_reissue_emitted_nonces() {
        // Regression test for audit finding C2 — see the awslc mirror test
        // of the same name for the full rationale.
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"eee");
        c.record_advance(&fp, 1).unwrap();
        c.record_advance(&fp, 400).unwrap();
        drop(c);

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (p, _) = c2.persisted_state(&fp);
        let max_emitted = 400u64;
        assert!(
            p > max_emitted,
            "on-disk ceiling ({p}) must exceed largest emitted value \
             ({max_emitted}) to prevent nonce reuse after crash"
        );
    }

    #[test]
    fn concurrent_record_advance_is_safe() {
        use std::sync::Arc;
        use std::thread;

        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = Arc::new(PersistentGcmCounter::file_backed(&path).unwrap());
        let fp = fp_of(b"fff");

        let mut handles = vec![];
        for t in 0..4u64 {
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

        drop(c);
        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (p, _) = c2.persisted_state(&fp);
        assert!(p > 0);
    }

    #[test]
    fn missing_footer_cold_start() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        std::fs::write(
            &path,
            b"0000000000000000000000000000000000000000000000000000000000000002 99\n",
        )
        .unwrap();
        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let mut fp = [0u8; 32];
        fp[31] = 2;
        let (p, poisoned) = c.persisted_state(&fp);
        assert_eq!(p, 99);
        assert!(!poisoned);
        // And the next write installs a footer AND a v1 marker.
        c.record_advance(&fp, 5000).unwrap();
        drop(c);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(JOURNAL_VERSION_MARKER));
        assert!(bytes.windows(5).any(|w| w == b"#MAC "));
    }

    // ====================================================================
    // M1 — journal version marker
    // ====================================================================

    #[test]
    fn v1_marker_written_and_validated_on_round_trip() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp = fp_of(b"v1-marker-roundtrip");
        c.record_advance(&fp, 1024).unwrap();
        drop(c);

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.starts_with(JOURNAL_VERSION_MARKER),
            "journal written without v1 version marker"
        );

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

        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (persisted, poisoned) = c2.persisted_state(&fp);
        assert_eq!(persisted, 1024 * 1024 + BATCH_THRESHOLD);
        assert!(!poisoned);
    }

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

    #[cfg(unix)]
    #[test]
    fn symlink_paths_derive_same_mac_key() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.journal");
        let link_a = dir.path().join("link_a.journal");
        let link_b = dir.path().join("link_b.journal");
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
        assert_eq!(k_real, k_a);
        assert_eq!(k_a, k_b);

        let c2 = PersistentGcmCounter::file_backed(&link_a).unwrap();
        let fp = fp_of(b"symlink");
        let (persisted, _) = c2.persisted_state(&fp);
        assert_eq!(persisted, 100 + BATCH_THRESHOLD);
    }

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

    #[test]
    fn few_malformed_records_still_load() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

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

    #[test]
    fn too_many_malformed_records_refuses_load() {
        let tf = NamedTempFile::new().unwrap();
        let path = tf.path().to_path_buf();
        drop(tf);

        let mac_key = derive_mac_key(&path);
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

    // ====================================================================
    // failing-flush helper for future eviction-poison tests
    // ====================================================================

    #[test]
    fn failing_flush_counts_attempts_and_tracks_poison() {
        let c = PersistentGcmCounter::failing_flush_for_tests();
        let fp = fp_of(b"streak");
        // record_advance succeeds (in-memory advance allowed).
        c.record_advance(&fp, 10).unwrap();
        // flush_fingerprint always errs and increments the counter.
        assert!(c.flush_fingerprint(&fp, 10).is_err());
        assert!(c.flush_fingerprint(&fp, 20).is_err());
        assert_eq!(c.failing_flush_attempts(), 2);
        // Poison is tracked.
        c.record_poison(&fp).unwrap();
        assert!(c.failing_flush_was_poisoned(&fp));
        // And subsequent advances on poisoned fp are refused.
        assert!(c.record_advance(&fp, 30).is_err());
    }

    // ====================================================================
    // C-1 — flush atomicity (write-temp-then-rename)
    // ====================================================================

    /// Regression test for audit finding C-1: a flush that fails after the
    /// in-memory body has been advanced must leave the on-disk journal in
    /// its prior, fully-MAC'd state. Before the fix, `flush_body_to_disk`
    /// did `set_len(0)` on the live file before re-writing — a crash in
    /// the middle left a zero-byte journal that on next open reset every
    /// fingerprint's ceiling to 0 and allowed re-emission of nonces.
    ///
    /// We exercise the failure path on Unix by removing write permission
    /// from the parent directory so `NamedTempFile::new_in` fails, then
    /// re-open the journal and assert the previously persisted counter is
    /// intact (no zeroing, no half-record).
    #[cfg(unix)]
    #[test]
    fn crash_during_flush_preserves_prior_state() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c1.journal");

        let c = PersistentGcmCounter::file_backed(&path).unwrap();
        let fp_a = fp_of(b"c1-key-a");
        let fp_b = fp_of(b"c1-key-b");
        c.record_advance(&fp_a, 4096).unwrap();
        c.record_advance(&fp_b, 8192).unwrap();
        drop(c);

        // Snapshot the post-good-flush bytes. After the failed flush
        // attempt the on-disk bytes must equal this snapshot.
        let before = std::fs::read(&path).unwrap();
        assert!(
            before.starts_with(JOURNAL_VERSION_MARKER),
            "pre-condition: journal must have a v1 marker"
        );

        // Re-open and trigger a flush that will fail because the parent dir
        // is no longer writable. `NamedTempFile::new_in` returns an
        // ENOENT/EACCES, `flush_body_to_disk` bubbles `HsmError::GeneralError`,
        // and the existing on-disk journal must remain byte-identical.
        let c2 = PersistentGcmCounter::file_backed(&path).unwrap();
        let orig_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        std::fs::set_permissions(
            dir.path(),
            std::fs::Permissions::from_mode(0o500), // r-x, no write
        )
        .unwrap();

        // `record_advance` for a new fingerprint forces a flush; with the
        // parent dir read-only the flush must fail.
        let fp_new = fp_of(b"c1-key-new");
        let res = c2.record_advance(&fp_new, 999);
        // Restore perms BEFORE asserting so the tempdir can be cleaned up
        // even on test failure.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(orig_mode)).unwrap();
        assert!(
            res.is_err(),
            "flush against a read-only parent dir must fail; got {:?}",
            res
        );
        drop(c2);

        // The on-disk bytes must be byte-identical to the pre-failure
        // snapshot — no zero-byte file, no half-written record.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            before, after,
            "failed flush must leave the journal byte-identical to its prior state"
        );

        // And a fresh open must recover the original counters, not zero.
        let c3 = PersistentGcmCounter::file_backed(&path).unwrap();
        let (pa, poisoned_a) = c3.persisted_state(&fp_a);
        let (pb, poisoned_b) = c3.persisted_state(&fp_b);
        assert_eq!(pa, 4096 + BATCH_THRESHOLD);
        assert_eq!(pb, 8192 + BATCH_THRESHOLD);
        assert!(!poisoned_a);
        assert!(!poisoned_b);
    }
}
