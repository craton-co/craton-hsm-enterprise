// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Configuration for the PKCS#11 passthrough backend.
//!
//! Kept in its own module so that the top-level `lib.rs` stays a thin
//! wiring file. All fields are plain data -- no live handles or locks --
//! so the config can be constructed from a CLI, a TOML file, or an
//! environment-variable loader without pulling in the rest of the crate.

use std::fmt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::cache::KEY_CACHE_DEFAULT_CAPACITY;

/// Default session-pool size. One mutex-guarded session per slot.
///
/// Sized for moderate server workloads: small enough to avoid hammering the
/// token on single-user hosts, large enough that a handful of concurrent
/// crypto requests do not serialise on a single mutex. Operators serving many
/// clients should raise this via `Pkcs11PassthroughConfig { pool_size: N, .. }`.
pub const DEFAULT_POOL_SIZE: usize = 8;

/// NIST SP 800-38D 8.3 bounds the number of distinct messages under
/// a single AES-GCM key with random 96-bit nonces at `2^32`. We use
/// that as the hard ceiling; operators can lower it via config.
pub const DEFAULT_GCM_MAX_MESSAGES_PER_KEY: u64 = 1 << 32;

/// Configuration for [`crate::Pkcs11PassthroughBackend`].
///
/// Construct via struct-literal or `Pkcs11PassthroughConfig::new(...)`.
/// The `Debug` impl deliberately redacts `pin`.
#[derive(Clone)]
pub struct Pkcs11PassthroughConfig {
    /// Filesystem path to the vendor PKCS#11 shared library
    /// (`.so` / `.dll` / `.dylib`).
    pub library_path: PathBuf,

    /// Slot ID on the external token to open sessions against.
    pub slot_id: u64,

    /// CKU_USER PIN. Wrapped in [`Zeroizing`] so the plaintext is
    /// wiped on drop.
    pub pin: Zeroizing<String>,

    /// When true, enforce the FIPS 140-3 subset (reject AES-128 keygen,
    /// reject non-approved mechanisms, etc.).
    pub fips_mode: bool,

    /// Vendor identifiers (substrings matched case-insensitively against
    /// the token info / library path) that are allow-listed for use of
    /// software-fallback FIPS-sensitive mechanisms such as
    /// `CKM_AES_KEY_WRAP_PAD` when the token itself does not implement
    /// them.
    ///
    /// In FIPS mode, [`crate::Pkcs11PassthroughBackend`] refuses to fall
    /// back to a software implementation unless the configured token
    /// vendor matches one of these strings. Outside FIPS mode the list is
    /// purely advisory and the fallback proceeds with a warning.
    ///
    /// Empty by default (no allow-listed vendors -- FIPS callers that hit
    /// a fallback path will be refused). Mark with `#[serde(default)]`
    /// if/when this struct gains a serde derive, so existing TOML configs
    /// keep parsing.
    pub fips_vendors: Vec<String>,

    /// Number of PKCS#11 sessions to pre-open and pool. Each session has
    /// its own imported-key cache and serves one concurrent operation at
    /// a time. `0` is invalid; the builder panics.
    pub pool_size: usize,

    /// Per-session imported-key cache capacity. `0` means "use the
    /// default" ([`KEY_CACHE_DEFAULT_CAPACITY`]).
    pub cache_capacity: usize,

    /// If true, the backend is allowed to fall back to a software
    /// implementation when the token cannot perform a key-generation
    /// operation (e.g., token lacks CKM_EC_KEY_PAIR_GEN for P-384).
    ///
    /// Defaults to `false` -- fail-closed. Operators who know their
    /// deployment can opt in.
    pub allow_software_keygen_fallback: bool,

    /// Maximum number of AES-GCM encryption operations permitted under
    /// a single cached key before the backend refuses further encryptions
    /// and forces rotation. See [`DEFAULT_GCM_MAX_MESSAGES_PER_KEY`].
    pub gcm_max_messages_per_key: u64,
}

impl Pkcs11PassthroughConfig {
    /// Construct a config with the given library + slot + PIN and
    /// sensible defaults for the rest. Additional fields can be set
    /// via struct-update syntax.
    pub fn new(library_path: PathBuf, slot_id: u64, pin: Zeroizing<String>) -> Self {
        Self {
            library_path,
            slot_id,
            pin,
            fips_mode: false,
            fips_vendors: Vec::new(),
            pool_size: DEFAULT_POOL_SIZE,
            cache_capacity: KEY_CACHE_DEFAULT_CAPACITY,
            allow_software_keygen_fallback: false,
            gcm_max_messages_per_key: DEFAULT_GCM_MAX_MESSAGES_PER_KEY,
        }
    }
}

impl fmt::Debug for Pkcs11PassthroughConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11PassthroughConfig")
            .field("library_path", &self.library_path)
            .field("slot_id", &self.slot_id)
            .field("pin", &"***")
            .field("fips_mode", &self.fips_mode)
            .field("fips_vendors", &self.fips_vendors)
            .field("pool_size", &self.pool_size)
            .field("cache_capacity", &self.cache_capacity)
            .field(
                "allow_software_keygen_fallback",
                &self.allow_software_keygen_fallback,
            )
            .field("gcm_max_messages_per_key", &self.gcm_max_messages_per_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Pkcs11PassthroughConfig {
        Pkcs11PassthroughConfig::new(
            PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
            0,
            Zeroizing::new("supersecret-pin-123".to_string()),
        )
    }

    #[test]
    fn default_pool_size_is_production_tuned() {
        assert!(
            DEFAULT_POOL_SIZE >= 8,
            "DEFAULT_POOL_SIZE should be at least 8 to absorb moderate concurrency without serialising on one mutex",
        );
    }

    #[test]
    fn defaults_are_safe() {
        let c = sample();
        assert_eq!(c.pool_size, DEFAULT_POOL_SIZE);
        assert_eq!(c.cache_capacity, KEY_CACHE_DEFAULT_CAPACITY);
        assert!(!c.fips_mode);
        assert!(c.fips_vendors.is_empty(), "fips_vendors defaults to empty");
        assert!(
            !c.allow_software_keygen_fallback,
            "software keygen fallback must default to disabled (fail-closed)"
        );
        assert_eq!(c.gcm_max_messages_per_key, 1u64 << 32);
    }

    #[test]
    fn debug_redacts_pin() {
        let c = sample();
        let repr = format!("{:?}", c);
        assert!(
            !repr.contains("supersecret-pin-123"),
            "Debug impl must redact PIN, got: {}",
            repr
        );
        assert!(repr.contains("***"), "expected PIN placeholder: {}", repr);
    }

    #[test]
    fn debug_includes_non_secret_fields() {
        let c = sample();
        let repr = format!("{:?}", c);
        assert!(repr.contains("slot_id"));
        assert!(repr.contains("pool_size"));
        assert!(repr.contains("gcm_max_messages_per_key"));
        assert!(repr.contains("fips_vendors"));
    }

    #[test]
    fn clone_preserves_fields() {
        let c = sample();
        let d = c.clone();
        assert_eq!(c.slot_id, d.slot_id);
        assert_eq!(c.library_path, d.library_path);
        assert_eq!(c.pool_size, d.pool_size);
        assert_eq!(c.pin.as_str(), d.pin.as_str());
        assert_eq!(c.fips_vendors, d.fips_vendors);
    }

    #[test]
    fn struct_update_syntax_works() {
        let base = sample();
        let tweaked = Pkcs11PassthroughConfig {
            fips_mode: true,
            pool_size: 16,
            allow_software_keygen_fallback: true,
            fips_vendors: vec!["SoftHSM".to_string(), "Luna".to_string()],
            ..base
        };
        assert!(tweaked.fips_mode);
        assert_eq!(tweaked.pool_size, 16);
        assert!(tweaked.allow_software_keygen_fallback);
        assert_eq!(tweaked.fips_vendors.len(), 2);
    }
}
