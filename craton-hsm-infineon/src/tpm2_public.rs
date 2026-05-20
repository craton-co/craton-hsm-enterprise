// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Minimal unmarshaler for the TPM 2.0 `TPMT_PUBLIC` wire format.
//!
//! This module closes audit finding **C-4**: `generate_*_key_pair` previously
//! returned hardcoded placeholder bytes for the public key. The TPM itself
//! produces a correct answer — the missing piece was parsing the
//! `TPM2B_PUBLIC` that `Esys_CreatePrimary` hands back.
//!
//! The parser is scoped to exactly the fields this crate needs:
//! - RSA modulus + exponent
//! - ECC P-256 / P-384 uncompressed public point (`0x04 || x || y`)
//!
//! Layout reference: *Trusted Platform Module Library — Part 2: Structures*
//! (TCG TPM 2.0), revision 1.59, §12.2.4 *TPMT_PUBLIC*.
//!
//! All integers on the wire are **big-endian**. Sizes prefixing variable
//! structures are `UINT16`. Unknown algorithms and out-of-bounds sizes are
//! mapped to `Error::Malformed` — callers should never produce a partial
//! result from a malformed buffer.

use craton_hsm::error::{HsmError, HsmResult};

// -------------------------------------------------------------------
// Algorithm identifiers (TPM 2.0 Part 2, §6.3 "TPM_ALG_ID Constants")
// -------------------------------------------------------------------

/// `TPM_ALG_RSA`
pub const TPM_ALG_RSA: u16 = 0x0001;
/// `TPM_ALG_ECC`
pub const TPM_ALG_ECC: u16 = 0x0023;
/// `TPM_ALG_NULL`
pub const TPM_ALG_NULL: u16 = 0x0010;

// -------------------------------------------------------------------
// ECC curve identifiers (Part 2, §6.4 "TPM_ECC_CURVE")
// -------------------------------------------------------------------

/// NIST P-256.
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
/// NIST P-384.
pub const TPM_ECC_NIST_P384: u16 = 0x0004;

/// Extracted key material from a parsed `TPMT_PUBLIC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA: `(modulus_be_bytes, exponent_be_bytes)`. Empty exponent means
    /// the TPM returned 0 on the wire, which per TPM 2.0 Part 2 §12.2.3.5
    /// indicates "use the default 65537".
    Rsa {
        /// RSA modulus in big-endian bytes.
        modulus: Vec<u8>,
        /// RSA public exponent in big-endian bytes. Empty means the TPM
        /// returned 0; callers should default to 65537.
        exponent: Vec<u8>,
    },
    /// ECC: uncompressed `0x04 || X || Y`, with X/Y padded to the curve's
    /// field-size in bytes (32 for P-256, 48 for P-384).
    Ecc {
        /// TPM_ECC_CURVE identifier (e.g. `TPM_ECC_NIST_P256`).
        curve_id: u16,
        /// SEC1 uncompressed point: `0x04 || X || Y`.
        uncompressed_point: Vec<u8>,
    },
}

/// Minimal reader over a `&[u8]` that charges every read against the buffer
/// length. Returning `None` means "short read"; callers upconvert to an
/// `HsmError::MalformedData`.
struct Cur<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cur<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.off], self.buf[self.off + 1]]);
        self.off += 2;
        Some(v)
    }

    fn u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let v = u32::from_be_bytes([
            self.buf[self.off],
            self.buf[self.off + 1],
            self.buf[self.off + 2],
            self.buf[self.off + 3],
        ]);
        self.off += 4;
        Some(v)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Some(s)
    }

    /// Read a `TPM2B_*` (UINT16 size + size bytes).
    fn size_bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
}

fn malformed() -> HsmError {
    HsmError::GeneralError
}

/// Skip a `TPMT_SYM_DEF_OBJECT` from the cursor.
///
/// Layout: `TPM_ALG_ID algorithm; TPMU_SYM_KEY_BITS keyBits; TPMU_SYM_MODE mode;`
/// When algorithm == `TPM_ALG_NULL` there are no further bytes. Otherwise the
/// two `TPMU_*` fields are each a `UINT16` (`keyBits` is always `TPM_KEY_BITS`
/// here; `mode` is a `TPM_ALG_ID`).
fn skip_tpmt_sym_def_object(c: &mut Cur<'_>) -> HsmResult<()> {
    let alg = c.u16().ok_or_else(malformed)?;
    if alg == TPM_ALG_NULL {
        return Ok(());
    }
    // keyBits (UINT16) + mode (TPM_ALG_ID UINT16)
    c.u16().ok_or_else(malformed)?;
    c.u16().ok_or_else(malformed)?;
    Ok(())
}

/// Skip a `TPMT_RSA_SCHEME` — `TPM_ALG_ID scheme; TPMU_ASYM_SCHEME details;`
/// where `details` for the only non-NULL cases we accept is a `TPM_ALG_ID`
/// (hash). CreatePrimary on a primary key almost always uses `TPM_ALG_NULL`.
fn skip_tpmt_rsa_scheme(c: &mut Cur<'_>) -> HsmResult<()> {
    let s = c.u16().ok_or_else(malformed)?;
    if s == TPM_ALG_NULL {
        return Ok(());
    }
    // All non-NULL schemes we recognise carry a single TPMI_ALG_HASH.
    c.u16().ok_or_else(malformed)?;
    Ok(())
}

/// Skip a `TPMT_ECC_SCHEME` — same layout as the RSA scheme for our purposes.
fn skip_tpmt_ecc_scheme(c: &mut Cur<'_>) -> HsmResult<()> {
    skip_tpmt_rsa_scheme(c)
}

/// Skip a `TPMT_KDF_SCHEME` — `TPM_ALG_ID scheme; TPMU_KDF_SCHEME details;`
/// where `details` is a single `TPMI_ALG_HASH` when scheme is not NULL.
fn skip_tpmt_kdf_scheme(c: &mut Cur<'_>) -> HsmResult<()> {
    skip_tpmt_rsa_scheme(c)
}

/// Parse a marshaled `TPMT_PUBLIC` buffer and extract the public key.
///
/// The buffer is the value of `TPM2B_PUBLIC.buffer[..size]` returned by
/// `Esys_CreatePrimary` / `Esys_Create`. The layout is:
///
/// ```text
/// TPMI_ALG_PUBLIC     type          (UINT16)
/// TPMI_ALG_HASH       nameAlg       (UINT16)
/// TPMA_OBJECT         objectAttrs   (UINT32)
/// TPM2B_DIGEST        authPolicy    (UINT16 size + bytes)
/// TPMU_PUBLIC_PARMS   parameters    (depends on `type`)
/// TPMU_PUBLIC_ID      unique        (depends on `type`)
/// ```
pub fn parse_tpmt_public(buf: &[u8]) -> HsmResult<PublicKey> {
    let mut c = Cur::new(buf);
    let alg_type = c.u16().ok_or_else(malformed)?;
    let _name_alg = c.u16().ok_or_else(malformed)?;
    let _object_attrs = c.u32().ok_or_else(malformed)?;
    // authPolicy is TPM2B_DIGEST — always present (may be zero-length).
    let _auth_policy = c.size_bytes().ok_or_else(malformed)?;

    match alg_type {
        TPM_ALG_RSA => parse_rsa_parms_and_id(&mut c),
        TPM_ALG_ECC => parse_ecc_parms_and_id(&mut c),
        _ => Err(HsmError::MechanismInvalid),
    }
}

fn parse_rsa_parms_and_id(c: &mut Cur<'_>) -> HsmResult<PublicKey> {
    // TPMS_RSA_PARMS
    skip_tpmt_sym_def_object(c)?;
    skip_tpmt_rsa_scheme(c)?;
    let _key_bits = c.u16().ok_or_else(malformed)?;
    let exponent = c.u32().ok_or_else(malformed)?;

    // TPM2B_PUBLIC_KEY_RSA: UINT16 size + modulus.
    let modulus = c.size_bytes().ok_or_else(malformed)?.to_vec();
    if modulus.is_empty() {
        return Err(malformed());
    }

    // TPM 2.0 Part 2 §12.2.3.5: exponent == 0 means "TPM default 65537".
    let exponent_be = if exponent == 0 {
        vec![0x01, 0x00, 0x01]
    } else {
        // Strip leading zeros to produce a canonical big-endian minimal form.
        let raw = exponent.to_be_bytes();
        let first_nonzero = raw.iter().position(|&b| b != 0).unwrap_or(raw.len() - 1);
        raw[first_nonzero..].to_vec()
    };

    Ok(PublicKey::Rsa {
        modulus,
        exponent: exponent_be,
    })
}

fn parse_ecc_parms_and_id(c: &mut Cur<'_>) -> HsmResult<PublicKey> {
    // TPMS_ECC_PARMS
    skip_tpmt_sym_def_object(c)?;
    skip_tpmt_ecc_scheme(c)?;
    let curve_id = c.u16().ok_or_else(malformed)?;
    skip_tpmt_kdf_scheme(c)?;

    // TPMS_ECC_POINT: TPM2B_ECC_PARAMETER x; TPM2B_ECC_PARAMETER y;
    let x = c.size_bytes().ok_or_else(malformed)?.to_vec();
    let y = c.size_bytes().ok_or_else(malformed)?.to_vec();

    let field_bytes = match curve_id {
        TPM_ECC_NIST_P256 => 32,
        TPM_ECC_NIST_P384 => 48,
        _ => return Err(HsmError::MechanismInvalid),
    };
    if x.len() > field_bytes || y.len() > field_bytes {
        return Err(malformed());
    }

    // SEC1 uncompressed point: 0x04 || pad(X) || pad(Y)
    let mut uncompressed = Vec::with_capacity(1 + field_bytes * 2);
    uncompressed.push(0x04);
    uncompressed.resize(1 + field_bytes - x.len(), 0);
    uncompressed.extend_from_slice(&x);
    let tail_start = uncompressed.len();
    uncompressed.resize(tail_start + field_bytes - y.len(), 0);
    uncompressed.extend_from_slice(&y);

    Ok(PublicKey::Ecc {
        curve_id,
        uncompressed_point: uncompressed,
    })
}

/// Safely extract the marshaled bytes from a `TPM2B_PUBLIC` returned by
/// ESAPI. Returns `None` if the size field overruns the buffer or the
/// pointer is null.
///
/// # Safety
///
/// Audit finding C3 hardening: the returned `&'a [u8]` is tied to a
/// caller-chosen lifetime `'a`, which is **unsound** if the caller picks
/// `'static`. The following invariants are the caller's responsibility:
///
/// 1. `ptr` must either be null **or** point to a valid `TPM2B_PUBLIC`
///    owned by the ESAPI stack (typically the output pointer of
///    `Esys_CreatePrimary` / `Esys_Create`).
/// 2. The pointed-to `TPM2B_PUBLIC` must remain live for the entire
///    lifetime `'a` chosen at the call site. In practice this means the
///    surrounding `EsapiContext` (which owns the ESAPI-allocated buffer)
///    must not be dropped, and `Esys_Free` must not be called on the
///    pointer, while the returned slice is in scope. **Choosing `'a =
///    'static` is undefined behaviour.**
/// 3. Callers MUST consume (e.g. copy / parse into an owned `Vec`) the
///    returned slice before the owning `EsapiContext` is dropped. All
///    in-tree callers (`lib.rs::generate_{rsa,ec_p256,ec_p384}_key_pair`)
///    parse the slice via `parse_tpmt_public` and then `drop(ctx)` —
///    audited 2026-05-16. New callers that diverge from this pattern
///    must be reviewed manually.
///
/// A future refactor will replace this signature with one that ties `'a`
/// to a borrowed `&'a EsapiContext` so the compiler enforces invariant
/// (2). Until then this doc-comment is the contract.
#[allow(unsafe_code)]
pub unsafe fn slice_from_raw<'a>(ptr: *const crate::ffi::TPM2B_PUBLIC) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: delegated to caller's contract above (invariant 1).
    let r = unsafe { &*ptr };
    let n = r.size as usize;
    if n > r.buffer.len() {
        return None;
    }
    // SAFETY: invariants 1+2 imply the pointed-to buffer outlives `'a`.
    // We only read within `[0, n)` which we just bounds-checked.
    let slice = unsafe { core::slice::from_raw_parts(r.buffer.as_ptr(), n) };
    Some(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal marshaled TPMT_PUBLIC for RSA with the given
    /// modulus and a NULL-scheme / NULL-symmetric (primary-key shape).
    fn build_rsa(modulus: &[u8], exponent_u32: u32, key_bits: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_ALG_RSA.to_be_bytes()); // type
        v.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg = SHA256
        v.extend_from_slice(&0u32.to_be_bytes()); // objectAttributes
        v.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size = 0
                                                  // parameters: TPMS_RSA_PARMS
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric.alg = NULL
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme.scheme = NULL
        v.extend_from_slice(&key_bits.to_be_bytes());
        v.extend_from_slice(&exponent_u32.to_be_bytes());
        // unique: TPM2B_PUBLIC_KEY_RSA
        v.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        v.extend_from_slice(modulus);
        v
    }

    fn build_ecc(curve: u16, x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        v.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg = SHA256
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        // parameters: TPMS_ECC_PARMS
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
        v.extend_from_slice(&curve.to_be_bytes());
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
        v.extend_from_slice(&(x.len() as u16).to_be_bytes());
        v.extend_from_slice(x);
        v.extend_from_slice(&(y.len() as u16).to_be_bytes());
        v.extend_from_slice(y);
        v
    }

    #[test]
    fn parse_rsa_default_exponent() {
        let modulus = vec![0xAAu8; 256];
        let buf = build_rsa(&modulus, 0, 2048);
        let pk = parse_tpmt_public(&buf).unwrap();
        match pk {
            PublicKey::Rsa {
                modulus: m,
                exponent,
            } => {
                assert_eq!(m, modulus);
                assert_eq!(exponent, vec![0x01, 0x00, 0x01]);
            }
            _ => panic!("expected RSA"),
        }
    }

    #[test]
    fn parse_rsa_explicit_exponent() {
        let modulus = vec![0x5Au8; 256];
        let buf = build_rsa(&modulus, 3, 2048);
        let pk = parse_tpmt_public(&buf).unwrap();
        match pk {
            PublicKey::Rsa { exponent, .. } => assert_eq!(exponent, vec![3]),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_rsa_empty_modulus_is_malformed() {
        let buf = build_rsa(&[], 0, 2048);
        assert!(parse_tpmt_public(&buf).is_err());
    }

    #[test]
    fn parse_ecc_p256_pads_point() {
        // Build with short X to prove leading-zero padding.
        let x = vec![0x11u8; 31];
        let y = vec![0x22u8; 32];
        let buf = build_ecc(TPM_ECC_NIST_P256, &x, &y);
        let pk = parse_tpmt_public(&buf).unwrap();
        match pk {
            PublicKey::Ecc {
                curve_id,
                uncompressed_point,
            } => {
                assert_eq!(curve_id, TPM_ECC_NIST_P256);
                assert_eq!(uncompressed_point.len(), 1 + 32 + 32);
                assert_eq!(uncompressed_point[0], 0x04);
                assert_eq!(uncompressed_point[1], 0x00); // padding byte
                assert_eq!(uncompressed_point[2], 0x11);
                assert_eq!(uncompressed_point[33], 0x22);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ecc_p384() {
        let x = vec![0x33u8; 48];
        let y = vec![0x44u8; 48];
        let buf = build_ecc(TPM_ECC_NIST_P384, &x, &y);
        let pk = parse_tpmt_public(&buf).unwrap();
        match pk {
            PublicKey::Ecc {
                curve_id,
                uncompressed_point,
            } => {
                assert_eq!(curve_id, TPM_ECC_NIST_P384);
                assert_eq!(uncompressed_point.len(), 1 + 48 + 48);
                assert_eq!(uncompressed_point[0], 0x04);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ecc_unknown_curve_rejected() {
        let buf = build_ecc(0x00FF, &[0u8; 32], &[0u8; 32]);
        assert!(parse_tpmt_public(&buf).is_err());
    }

    #[test]
    fn parse_truncated_rejected() {
        let buf = build_rsa(&vec![0u8; 256], 0, 2048);
        for n in 0..buf.len() {
            let truncated = &buf[..n];
            assert!(
                parse_tpmt_public(truncated).is_err(),
                "truncation at {n} was not rejected"
            );
        }
    }

    #[test]
    fn parse_unknown_alg_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x9999u16.to_be_bytes()); // bogus type
        buf.extend_from_slice(&0x000Bu16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert!(parse_tpmt_public(&buf).is_err());
    }
}
