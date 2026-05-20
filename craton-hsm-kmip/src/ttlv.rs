// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! KMIP Tag-Type-Length-Value (TTLV) binary codec.
//!
//! KMIP messages are encoded as a tree of TTLV items. Each item has a 3-byte
//! tag, 1-byte type indicator, 4-byte big-endian length, and a value padded
//! to an 8-byte boundary.

use std::fmt;

// ---------------------------------------------------------------------------
// TTLV type indicator
// ---------------------------------------------------------------------------

/// Type indicator byte in the TTLV header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlvType {
    /// Nested structure containing child TTLV items.
    Structure,
    /// 32-bit signed integer.
    Integer,
    /// 64-bit signed integer.
    LongInteger,
    /// Arbitrary-precision big integer (byte string, big-endian).
    BigInteger,
    /// 32-bit enumeration value.
    Enumeration,
    /// Boolean (8 bytes on the wire, LSB holds the value).
    Boolean,
    /// UTF-8 text string.
    TextString,
    /// Opaque byte string.
    ByteString,
    /// Date/time as signed Unix seconds.
    DateTime,
}

impl TtlvType {
    /// Return the 1-byte type indicator used on the wire.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Structure => 1,
            Self::Integer => 2,
            Self::LongInteger => 3,
            Self::BigInteger => 4,
            Self::Enumeration => 5,
            Self::Boolean => 6,
            Self::TextString => 7,
            Self::ByteString => 8,
            Self::DateTime => 9,
        }
    }

    /// Map a wire type byte back to a `TtlvType`, or `None` if unknown.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Structure),
            2 => Some(Self::Integer),
            3 => Some(Self::LongInteger),
            4 => Some(Self::BigInteger),
            5 => Some(Self::Enumeration),
            6 => Some(Self::Boolean),
            7 => Some(Self::TextString),
            8 => Some(Self::ByteString),
            9 => Some(Self::DateTime),
            _ => None,
        }
    }
}

impl fmt::Display for TtlvType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// TTLV value
// ---------------------------------------------------------------------------

/// The value part of a TTLV item.
#[derive(Debug, Clone, PartialEq)]
pub enum TtlvValue {
    /// Nested structure body.
    Structure(Vec<TtlvItem>),
    /// 32-bit signed integer value.
    Integer(i32),
    /// 64-bit signed integer value.
    LongInteger(i64),
    /// Arbitrary-precision integer encoded as big-endian bytes.
    BigInteger(Vec<u8>),
    /// 32-bit enumeration value.
    Enumeration(u32),
    /// Boolean value.
    Boolean(bool),
    /// UTF-8 text.
    TextString(String),
    /// Opaque byte string.
    ByteString(Vec<u8>),
    /// Unix-seconds timestamp.
    DateTime(i64),
}

impl TtlvValue {
    /// Return the TTLV type indicator for this value.
    pub fn ttlv_type(&self) -> TtlvType {
        match self {
            Self::Structure(_) => TtlvType::Structure,
            Self::Integer(_) => TtlvType::Integer,
            Self::LongInteger(_) => TtlvType::LongInteger,
            Self::BigInteger(_) => TtlvType::BigInteger,
            Self::Enumeration(_) => TtlvType::Enumeration,
            Self::Boolean(_) => TtlvType::Boolean,
            Self::TextString(_) => TtlvType::TextString,
            Self::ByteString(_) => TtlvType::ByteString,
            Self::DateTime(_) => TtlvType::DateTime,
        }
    }
}

// ---------------------------------------------------------------------------
// TTLV item
// ---------------------------------------------------------------------------

/// A single TTLV-encoded item (tag + value).
#[derive(Debug, Clone, PartialEq)]
pub struct TtlvItem {
    /// 3-byte tag identifier (upper byte of the `u32` is ignored on the wire).
    pub tag: u32,
    /// Typed value body.
    pub value: TtlvValue,
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Round `len` up to the next 8-byte boundary.
fn padded_len(len: usize) -> usize {
    (len + 7) & !7
}

/// Write the 8-byte TTLV header: 3-byte tag, 1-byte type, 4-byte length.
fn write_header(out: &mut Vec<u8>, tag: u32, typ: TtlvType, value_len: u32) {
    // Tag occupies 3 bytes (big-endian, upper byte of the u32 is dropped).
    out.push(((tag >> 16) & 0xFF) as u8);
    out.push(((tag >> 8) & 0xFF) as u8);
    out.push((tag & 0xFF) as u8);
    // Type indicator.
    out.push(typ.to_u8());
    // Length as 4-byte big-endian.
    out.extend_from_slice(&value_len.to_be_bytes());
}

/// Pad `out` with zero bytes so its total length is on an 8-byte boundary
/// relative to `start`.
fn pad_to_boundary(out: &mut Vec<u8>, value_len: usize) {
    let pad = padded_len(value_len) - value_len;
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// Maximum size (in bytes) of a single encoded TTLV value or structure.
///
/// Mirrors the decode-side limit so encoded messages are always decodable
/// by the same stack.  Attempting to encode a structure whose children
/// accumulate more than this many bytes returns `TtlvError::ValueTooLarge`.
const MAX_TTLV_ENCODE_SIZE: usize = MAX_TTLV_VALUE_SIZE;

/// Encode a complete [`TtlvItem`] to KMIP wire format.
///
/// Returns `Err` if any individual value or structure body exceeds
/// [`MAX_TTLV_ENCODE_SIZE`] (1 MiB), preventing unbounded allocation.
pub fn encode_ttlv(item: &TtlvItem) -> Result<Vec<u8>, TtlvError> {
    let mut out = Vec::with_capacity(256);
    encode_ttlv_into(item, &mut out)?;
    Ok(out)
}

/// Encode a [`TtlvItem`] into `out` using a single-pass, in-place approach.
///
/// For `Structure` values the 8-byte header is written first with a zero
/// length placeholder; children are encoded in-place; then the real length
/// is backpatched into the placeholder.  This avoids allocating a temporary
/// `Vec` for every nesting level.
fn encode_ttlv_into(item: &TtlvItem, out: &mut Vec<u8>) -> Result<(), TtlvError> {
    match &item.value {
        TtlvValue::Structure(children) => {
            // Write the 8-byte header with a zero-length placeholder.
            // We will backpatch bytes [header_pos+4 .. header_pos+8] once we
            // know how many bytes the children produced.
            let header_pos = out.len();
            write_header(out, item.tag, TtlvType::Structure, 0);
            let children_start = out.len(); // == header_pos + 8

            for child in children {
                encode_ttlv_into(child, out)?;
            }

            let inner_len = out.len() - children_start;
            // Guard against exceeding the TTLV length field (u32) and our
            // policy limit in a single check.
            if inner_len > MAX_TTLV_ENCODE_SIZE {
                return Err(TtlvError::ValueTooLarge(inner_len));
            }
            // Backpatch the real length into bytes [header_pos+4 .. header_pos+8].
            let len_bytes = (inner_len as u32).to_be_bytes();
            out[header_pos + 4..header_pos + 8].copy_from_slice(&len_bytes);
        }
        TtlvValue::Integer(v) => {
            write_header(out, item.tag, TtlvType::Integer, 4);
            out.extend_from_slice(&v.to_be_bytes());
            // Pad 4 bytes to reach an 8-byte boundary.
            out.extend_from_slice(&[0u8; 4]);
        }
        TtlvValue::LongInteger(v) => {
            write_header(out, item.tag, TtlvType::LongInteger, 8);
            out.extend_from_slice(&v.to_be_bytes());
        }
        TtlvValue::BigInteger(bytes) => {
            let vlen = bytes.len();
            if vlen > MAX_TTLV_ENCODE_SIZE {
                return Err(TtlvError::ValueTooLarge(vlen));
            }
            write_header(out, item.tag, TtlvType::BigInteger, vlen as u32);
            out.extend_from_slice(bytes);
            pad_to_boundary(out, vlen);
        }
        TtlvValue::Enumeration(v) => {
            write_header(out, item.tag, TtlvType::Enumeration, 4);
            out.extend_from_slice(&v.to_be_bytes());
            out.extend_from_slice(&[0u8; 4]);
        }
        TtlvValue::Boolean(v) => {
            write_header(out, item.tag, TtlvType::Boolean, 8);
            out.extend_from_slice(&[0u8; 7]);
            out.push(if *v { 1 } else { 0 });
        }
        TtlvValue::TextString(s) => {
            let bytes = s.as_bytes();
            let vlen = bytes.len();
            if vlen > MAX_TTLV_ENCODE_SIZE {
                return Err(TtlvError::ValueTooLarge(vlen));
            }
            write_header(out, item.tag, TtlvType::TextString, vlen as u32);
            out.extend_from_slice(bytes);
            pad_to_boundary(out, vlen);
        }
        TtlvValue::ByteString(bytes) => {
            let vlen = bytes.len();
            if vlen > MAX_TTLV_ENCODE_SIZE {
                return Err(TtlvError::ValueTooLarge(vlen));
            }
            write_header(out, item.tag, TtlvType::ByteString, vlen as u32);
            out.extend_from_slice(bytes);
            pad_to_boundary(out, vlen);
        }
        TtlvValue::DateTime(v) => {
            write_header(out, item.tag, TtlvType::DateTime, 8);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Error type for TTLV decoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlvError {
    /// Not enough bytes available.
    Truncated,
    /// Unknown type indicator.
    UnknownType(u8),
    /// A value field was shorter than expected.
    InvalidLength,
    /// UTF-8 decode failure in a TextString.
    InvalidUtf8,
    /// Recursion depth exceeded during decoding.
    DepthExceeded,
    /// Value length exceeds the maximum allowed size.
    ValueTooLarge(usize),
    /// A Structure declared more children than the caller permitted.
    TooManyItems(usize),
    /// Running total of bytes decoded exceeded the caller-specified budget.
    MessageTooLarge(usize),
}

impl fmt::Display for TtlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated TTLV data"),
            Self::UnknownType(t) => write!(f, "unknown TTLV type: {t}"),
            Self::InvalidLength => write!(f, "invalid TTLV value length"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in TextString"),
            Self::DepthExceeded => write!(f, "TTLV recursion depth exceeded"),
            Self::ValueTooLarge(n) => {
                write!(f, "TTLV value length {n} exceeds maximum allowed size")
            }
            Self::TooManyItems(n) => {
                write!(
                    f,
                    "TTLV structure declared {n} items, exceeding the configured maximum"
                )
            }
            Self::MessageTooLarge(n) => {
                write!(
                    f,
                    "TTLV message decoded {n} bytes, exceeding the configured budget"
                )
            }
        }
    }
}

impl std::error::Error for TtlvError {}

/// Default maximum nesting depth for decoded TTLV structures.
///
/// 32 is well above anything KMIP 2.1 actually produces (depth-6 is typical
/// for batched requests with template attributes) and gives an attacker no
/// meaningful budget to drive the parser into recursive memory allocation
/// (audit finding H4).
pub const MAX_TTLV_DEPTH: usize = 32;

/// Default maximum number of children decoded from a single Structure or
/// array before the parser refuses to continue (audit finding H4).
///
/// Without this cap, a forged Structure whose inner length covers megabytes
/// of tiny `Integer` items could drive `Vec::push` allocation to `O(N)`
/// before any single oversize value trips the per-item size check.
pub const MAX_TTLV_ITEMS: usize = 10_000;

const MAX_TTLV_VALUE_SIZE: usize = 1_048_576;

/// Decoder resource bounds plumbed through [`decode_ttlv_with_limits`].
///
/// The `max_bytes` field lets the server cap the running byte total across
/// nested structures: a message whose top-level length fits inside the
/// 1 MiB per-value limit but whose *children* collectively allocate gigabytes
/// must still be refused. Callers typically derive it from
/// `KmipServerConfig::max_message_size`.
#[derive(Debug, Clone, Copy)]
pub struct TtlvLimits {
    /// Maximum recursive structure nesting depth.
    pub max_depth: usize,
    /// Maximum number of children decoded from a single structure.
    pub max_items: usize,
    /// Cumulative byte budget for the whole decode operation.
    pub max_bytes: usize,
}

impl Default for TtlvLimits {
    fn default() -> Self {
        // The default cumulative budget is deliberately generous so the
        // pre-existing `decode_ttlv(...)` API keeps accepting any message
        // that fits inside the per-value 1 MiB limit at every nesting
        // level. Callers with a tighter policy should use
        // `decode_ttlv_with_limits` with `max_bytes = config.max_message_size`.
        Self {
            max_depth: MAX_TTLV_DEPTH,
            max_items: MAX_TTLV_ITEMS,
            max_bytes: usize::MAX,
        }
    }
}

/// Running counters for a single decode invocation.
struct DecodeCx {
    limits: TtlvLimits,
    bytes_consumed: usize,
}

impl DecodeCx {
    fn charge(&mut self, n: usize) -> Result<(), TtlvError> {
        self.bytes_consumed = self.bytes_consumed.saturating_add(n);
        if self.bytes_consumed > self.limits.max_bytes {
            return Err(TtlvError::MessageTooLarge(self.bytes_consumed));
        }
        Ok(())
    }
}

/// Decode one [`TtlvItem`] from the start of `data`.
///
/// Returns the decoded item and the number of bytes consumed.
pub fn decode_ttlv(data: &[u8]) -> Result<(TtlvItem, usize), TtlvError> {
    decode_ttlv_with_limits(data, TtlvLimits::default())
}

/// Decode a TTLV item with caller-provided resource bounds.
///
/// This is the entry point the KMIP server uses so that the configured
/// `max_message_size` flows all the way down into the decoder (audit
/// finding H4).
pub fn decode_ttlv_with_limits(
    data: &[u8],
    limits: TtlvLimits,
) -> Result<(TtlvItem, usize), TtlvError> {
    let mut cx = DecodeCx {
        limits,
        bytes_consumed: 0,
    };
    decode_ttlv_inner(data, limits.max_depth, &mut cx)
}

#[doc(hidden)]
pub(crate) fn decode_ttlv_bounded(
    data: &[u8],
    max_depth: usize,
) -> Result<(TtlvItem, usize), TtlvError> {
    let limits = TtlvLimits {
        max_depth,
        ..TtlvLimits::default()
    };
    let mut cx = DecodeCx {
        limits,
        bytes_consumed: 0,
    };
    decode_ttlv_inner(data, max_depth, &mut cx)
}

fn decode_ttlv_inner(
    data: &[u8],
    max_depth: usize,
    cx: &mut DecodeCx,
) -> Result<(TtlvItem, usize), TtlvError> {
    if max_depth == 0 {
        return Err(TtlvError::DepthExceeded);
    }

    // Need at least 8 bytes for the header.
    if data.len() < 8 {
        return Err(TtlvError::Truncated);
    }

    let tag = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    let type_byte = data[3];
    let value_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

    // Guard against attacker-controlled allocations: reject values larger than 1 MB.
    if value_len > MAX_TTLV_VALUE_SIZE {
        return Err(TtlvError::ValueTooLarge(value_len));
    }

    let typ = TtlvType::from_u8(type_byte).ok_or(TtlvError::UnknownType(type_byte))?;

    let header_len = 8;

    // Charge the 8-byte header against the message-byte budget. Structure
    // bodies and fixed-size value bodies are charged in their respective
    // arms below so the running total reflects cumulative allocation work.
    cx.charge(header_len)?;

    match typ {
        TtlvType::Structure => {
            // Children are packed inside `value_len` bytes.
            if data.len() < header_len + value_len {
                return Err(TtlvError::Truncated);
            }
            // Structure children each charge their own header+body as the
            // recursion descends. We deliberately do NOT charge value_len
            // here to avoid double-counting against the cumulative budget.
            let mut children: Vec<TtlvItem> = Vec::new();
            let mut offset = 0;
            let inner = &data[header_len..header_len + value_len];
            while offset < value_len {
                // Cap the number of children we are willing to allocate for
                // this structure up front (audit finding H4). This fires
                // before we recurse, so an attacker-crafted structure with
                // thousands of 8-byte empty integers cannot linearly blow
                // up the `Vec<TtlvItem>` allocator.
                if children.len() >= cx.limits.max_items {
                    return Err(TtlvError::TooManyItems(children.len() + 1));
                }
                let (child, consumed) = decode_ttlv_inner(&inner[offset..], max_depth - 1, cx)?;
                children.push(child);
                offset += consumed;
            }
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::Structure(children),
                },
                header_len + value_len,
            ))
        }
        TtlvType::Integer => {
            let padded = padded_len(4);
            if data.len() < header_len + padded {
                return Err(TtlvError::Truncated);
            }
            cx.charge(padded)?;
            let v = i32::from_be_bytes([
                data[header_len],
                data[header_len + 1],
                data[header_len + 2],
                data[header_len + 3],
            ]);
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::Integer(v),
                },
                header_len + padded,
            ))
        }
        TtlvType::LongInteger => {
            if data.len() < header_len + 8 {
                return Err(TtlvError::Truncated);
            }
            cx.charge(8)?;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[header_len..header_len + 8]);
            let v = i64::from_be_bytes(buf);
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::LongInteger(v),
                },
                header_len + 8,
            ))
        }
        TtlvType::BigInteger => {
            let padded = padded_len(value_len);
            if data.len() < header_len + padded {
                return Err(TtlvError::Truncated);
            }
            // Audit C: charge the byte budget **before** the `.to_vec()`
            // allocation. A message shaped to exactly hit `max_bytes` will
            // either pass at the inclusive boundary or fail before the
            // allocator is touched — the body buffer is never materialised
            // first and then rejected.
            cx.charge(padded)?;
            let bytes = data[header_len..header_len + value_len].to_vec();
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::BigInteger(bytes),
                },
                header_len + padded,
            ))
        }
        TtlvType::Enumeration => {
            let padded = padded_len(4);
            if data.len() < header_len + padded {
                return Err(TtlvError::Truncated);
            }
            cx.charge(padded)?;
            let v = u32::from_be_bytes([
                data[header_len],
                data[header_len + 1],
                data[header_len + 2],
                data[header_len + 3],
            ]);
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::Enumeration(v),
                },
                header_len + padded,
            ))
        }
        TtlvType::Boolean => {
            if data.len() < header_len + 8 {
                return Err(TtlvError::Truncated);
            }
            cx.charge(8)?;
            let v = data[header_len + 7] != 0;
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::Boolean(v),
                },
                header_len + 8,
            ))
        }
        TtlvType::TextString => {
            let padded = padded_len(value_len);
            if data.len() < header_len + padded {
                return Err(TtlvError::Truncated);
            }
            cx.charge(padded)?;
            let s = std::str::from_utf8(&data[header_len..header_len + value_len])
                .map_err(|_| TtlvError::InvalidUtf8)?
                .to_string();
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::TextString(s),
                },
                header_len + padded,
            ))
        }
        TtlvType::ByteString => {
            let padded = padded_len(value_len);
            if data.len() < header_len + padded {
                return Err(TtlvError::Truncated);
            }
            // Audit C: see `BigInteger` arm — charge first, then allocate.
            cx.charge(padded)?;
            let bytes = data[header_len..header_len + value_len].to_vec();
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::ByteString(bytes),
                },
                header_len + padded,
            ))
        }
        TtlvType::DateTime => {
            if data.len() < header_len + 8 {
                return Err(TtlvError::Truncated);
            }
            cx.charge(8)?;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[header_len..header_len + 8]);
            let v = i64::from_be_bytes(buf);
            Ok((
                TtlvItem {
                    tag,
                    value: TtlvValue::DateTime(v),
                },
                header_len + 8,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Encode an integer TTLV item.
pub fn encode_integer(tag: u32, val: i32) -> Result<Vec<u8>, TtlvError> {
    encode_ttlv(&TtlvItem {
        tag,
        value: TtlvValue::Integer(val),
    })
}

/// Encode a text string TTLV item.
pub fn encode_text_string(tag: u32, val: &str) -> Result<Vec<u8>, TtlvError> {
    encode_ttlv(&TtlvItem {
        tag,
        value: TtlvValue::TextString(val.to_string()),
    })
}

/// Encode a byte string TTLV item.
pub fn encode_byte_string(tag: u32, val: &[u8]) -> Result<Vec<u8>, TtlvError> {
    encode_ttlv(&TtlvItem {
        tag,
        value: TtlvValue::ByteString(val.to_vec()),
    })
}

/// Encode an enumeration TTLV item.
pub fn encode_enumeration(tag: u32, val: u32) -> Result<Vec<u8>, TtlvError> {
    encode_ttlv(&TtlvItem {
        tag,
        value: TtlvValue::Enumeration(val),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_integer() {
        let item = TtlvItem {
            tag: 0x42_0001,
            value: TtlvValue::Integer(42),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, consumed) = decode_ttlv(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_long_integer() {
        let item = TtlvItem {
            tag: 0x42_0002,
            value: TtlvValue::LongInteger(123_456_789_012),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, consumed) = decode_ttlv(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_enumeration() {
        let item = TtlvItem {
            tag: 0x42_005C,
            value: TtlvValue::Enumeration(1),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, consumed) = decode_ttlv(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_boolean_true() {
        let item = TtlvItem {
            tag: 0x42_0003,
            value: TtlvValue::Boolean(true),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_boolean_false() {
        let item = TtlvItem {
            tag: 0x42_0003,
            value: TtlvValue::Boolean(false),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_text_string() {
        let item = TtlvItem {
            tag: 0x42_000A,
            value: TtlvValue::TextString("hello".to_string()),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, consumed) = decode_ttlv(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_text_string_exact_boundary() {
        // 8 characters => exactly on boundary, no padding needed.
        let item = TtlvItem {
            tag: 0x42_000A,
            value: TtlvValue::TextString("abcdefgh".to_string()),
        };
        let encoded = encode_ttlv(&item).unwrap();
        assert_eq!(encoded.len(), 8 + 8); // header + 8 bytes value (no pad)
        let (decoded, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_byte_string() {
        let item = TtlvItem {
            tag: 0x42_0043,
            value: TtlvValue::ByteString(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, consumed) = decode_ttlv(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_big_integer() {
        let item = TtlvItem {
            tag: 0x42_0004,
            value: TtlvValue::BigInteger(vec![0x01, 0x02, 0x03]),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_datetime() {
        let item = TtlvItem {
            tag: 0x42_0005,
            value: TtlvValue::DateTime(1_700_000_000),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn roundtrip_structure() {
        let item = TtlvItem {
            tag: 0x42_0078,
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: 0x42_005C,
                    value: TtlvValue::Enumeration(1),
                },
                TtlvItem {
                    tag: 0x42_000A,
                    value: TtlvValue::TextString("test".to_string()),
                },
            ]),
        };
        let encoded = encode_ttlv(&item).unwrap();
        let (decoded, consumed) = decode_ttlv(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, item);
    }

    #[test]
    fn nested_structures() {
        let inner = TtlvItem {
            tag: 0x42_0008,
            value: TtlvValue::Structure(vec![TtlvItem {
                tag: 0x42_000A,
                value: TtlvValue::TextString("nested".to_string()),
            }]),
        };
        let outer = TtlvItem {
            tag: 0x42_0078,
            value: TtlvValue::Structure(vec![inner]),
        };
        let encoded = encode_ttlv(&outer).unwrap();
        let (decoded, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(decoded, outer);
    }

    #[test]
    fn padding_verification() {
        // "hi" is 2 bytes, should be padded to 8.
        let encoded = encode_text_string(0x42_0001, "hi").unwrap();
        // header (8) + value (2) + pad (6) = 16
        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn error_on_truncated_header() {
        let result = decode_ttlv(&[0x42, 0x00]);
        assert_eq!(result, Err(TtlvError::Truncated));
    }

    #[test]
    fn error_on_truncated_value() {
        // Valid header claiming 100 bytes of value but only 8 bytes total.
        let mut data = vec![0x42, 0x00, 0x01, 0x02]; // tag + type(Integer)
        data.extend_from_slice(&100u32.to_be_bytes()); // length = 100
        let result = decode_ttlv(&data);
        assert_eq!(result, Err(TtlvError::Truncated));
    }

    #[test]
    fn error_on_unknown_type() {
        let mut data = vec![0x42, 0x00, 0x01, 0xFF]; // type = 0xFF (unknown)
        data.extend_from_slice(&0u32.to_be_bytes());
        let result = decode_ttlv(&data);
        assert_eq!(result, Err(TtlvError::UnknownType(0xFF)));
    }

    #[test]
    fn convenience_encode_integer() {
        let encoded = encode_integer(0x42_0001, 99).unwrap();
        let (item, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(item.tag, 0x42_0001);
        assert_eq!(item.value, TtlvValue::Integer(99));
    }

    #[test]
    fn convenience_encode_enumeration() {
        let encoded = encode_enumeration(0x42_005C, 10).unwrap();
        let (item, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(item.value, TtlvValue::Enumeration(10));
    }

    #[test]
    fn convenience_encode_byte_string() {
        let data = vec![1, 2, 3, 4, 5];
        let encoded = encode_byte_string(0x42_0043, &data).unwrap();
        let (item, _) = decode_ttlv(&encoded).unwrap();
        assert_eq!(item.value, TtlvValue::ByteString(data));
    }

    #[test]
    fn encode_returns_error_on_oversized_value() {
        // Constructing a ByteString value larger than MAX_TTLV_ENCODE_SIZE must
        // return Err rather than panic.
        let huge = vec![0u8; MAX_TTLV_ENCODE_SIZE + 1];
        let item = TtlvItem {
            tag: 0x42_0043,
            value: TtlvValue::ByteString(huge),
        };
        assert!(matches!(
            encode_ttlv(&item),
            Err(TtlvError::ValueTooLarge(_))
        ));
    }

    #[test]
    fn error_on_oversized_value() {
        // Craft a header claiming a value larger than MAX_TTLV_VALUE_SIZE.
        let mut data = vec![0x42, 0x00, 0x43, 0x08]; // tag + type(ByteString)
        let huge_len: u32 = 2_000_000; // 2 MB > 1 MB limit
        data.extend_from_slice(&huge_len.to_be_bytes());
        // Pad with enough bytes so the truncation check doesn't fire first.
        data.extend(std::iter::repeat(0u8).take(huge_len as usize + 8));
        let result = decode_ttlv(&data);
        assert!(matches!(result, Err(TtlvError::ValueTooLarge(2_000_000))));
    }

    #[test]
    fn test_ttlv_depth_limit() {
        // Build a minimal structure that exceeds the limit
        // A Structure tag is 0x42, type 0x01 (Structure), length encoding...
        // For simplicity, just test that decode_ttlv_bounded with depth=0 returns error
        let data = vec![0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x00]; // minimal structure
        let result = decode_ttlv_bounded(&data, 0);
        assert!(matches!(result, Err(TtlvError::DepthExceeded)));
    }

    // -----------------------------------------------------------------------
    // Fuzz-style negative tests (S4)
    // -----------------------------------------------------------------------

    /// Deeply-nested structures must not blow the stack: the recursion limit
    /// fires before we run out of call frames, regardless of how many
    /// nesting levels the attacker crafts.
    #[test]
    fn nested_structure_beyond_depth_limit_rejected() {
        // Build: Structure(Structure(Structure( ... 40 levels ...))) encoded
        // bottom-up so the length field at each level is known.
        let mut current_bytes = encode_ttlv(&TtlvItem {
            tag: 0x42_0001,
            value: TtlvValue::Integer(0),
        })
        .unwrap();
        for _ in 0..40 {
            // Wrap current_bytes inside a new Structure.
            let mut next = Vec::with_capacity(current_bytes.len() + 8);
            // Tag
            next.extend_from_slice(&[0x42, 0x00, 0x78]);
            next.push(TtlvType::Structure.to_u8());
            let inner_len = current_bytes.len() as u32;
            next.extend_from_slice(&inner_len.to_be_bytes());
            next.extend_from_slice(&current_bytes);
            current_bytes = next;
        }
        let result = decode_ttlv(&current_bytes);
        assert!(matches!(result, Err(TtlvError::DepthExceeded)));
    }

    /// A structure whose declared inner-length goes past the end of the
    /// buffer must error, not panic — and must not attempt to allocate
    /// anything based on the forged length.
    #[test]
    fn structure_declared_length_overflows_buffer() {
        let mut data = vec![0x42, 0x00, 0x78, TtlvType::Structure.to_u8()];
        data.extend_from_slice(&(1_000_000u32).to_be_bytes());
        // Only give a tiny body — truncated.
        data.extend_from_slice(&[0u8; 16]);
        let result = decode_ttlv(&data);
        assert!(matches!(result, Err(TtlvError::Truncated)));
    }

    /// A Structure containing a child whose declared length exceeds the
    /// parent's inner length must be rejected as truncated.
    #[test]
    fn structure_child_length_exceeds_parent() {
        // Parent: Structure, inner_len = 16 (claims two Integer items).
        // Body: first Integer header claims 1_000_000 bytes but only 8 total remain.
        let mut data = Vec::new();
        data.extend_from_slice(&[0x42, 0x00, 0x78, TtlvType::Structure.to_u8()]);
        data.extend_from_slice(&(16u32).to_be_bytes());
        // Child 1: Integer header claiming 1M bytes.
        data.extend_from_slice(&[0x42, 0x00, 0x01, TtlvType::Integer.to_u8()]);
        data.extend_from_slice(&(1_000_000u32).to_be_bytes());
        // No actual body bytes for the lie.
        let result = decode_ttlv(&data);
        assert!(result.is_err(), "lying child length must not be accepted");
    }

    /// A TextString with invalid UTF-8 must be rejected, not crash.
    #[test]
    fn text_string_invalid_utf8_rejected() {
        // Header: tag, TextString type, length = 4.
        let mut data = vec![0x42, 0x00, 0x0A, TtlvType::TextString.to_u8()];
        data.extend_from_slice(&4u32.to_be_bytes());
        // Invalid UTF-8: lone continuation byte.
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
        data.extend_from_slice(&[0u8; 4]); // pad to boundary
        let result = decode_ttlv(&data);
        assert!(matches!(result, Err(TtlvError::InvalidUtf8)));
    }

    /// Unknown type byte must return `UnknownType`, not panic.
    #[test]
    fn all_unknown_type_bytes_rejected() {
        for bad_type in [0, 10, 100, 255u8] {
            let mut data = vec![0x42, 0x00, 0x01, bad_type];
            data.extend_from_slice(&0u32.to_be_bytes());
            data.extend_from_slice(&[0u8; 8]); // some body
            let result = decode_ttlv(&data);
            assert!(
                matches!(result, Err(TtlvError::UnknownType(_))),
                "type byte {bad_type} should be rejected"
            );
        }
    }

    /// Fuzz: random-ish byte sequences must never panic, only return errors.
    ///
    /// This is a cheap smoke-test for panic-safety; a real fuzzing harness
    /// (libfuzzer / cargo-fuzz) lives under `fuzz/`.
    #[test]
    fn random_inputs_never_panic() {
        for seed in 0u64..200 {
            // Simple LCG — deterministic so failures are reproducible.
            let mut rng = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = (rng % 256) as usize;
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                data.push((rng >> 33) as u8);
            }
            let _ = decode_ttlv(&data); // must not panic
        }
    }

    /// A value length at exactly the boundary must succeed.
    #[test]
    fn value_at_exact_size_limit_decodes() {
        // A TextString whose length is exactly MAX_TTLV_VALUE_SIZE should succeed.
        // We build the header + value programmatically.
        let n = MAX_TTLV_VALUE_SIZE;
        let mut data = Vec::with_capacity(8 + n);
        data.extend_from_slice(&[0x42, 0x00, 0x0A, TtlvType::ByteString.to_u8()]);
        data.extend_from_slice(&(n as u32).to_be_bytes());
        data.extend(std::iter::repeat(0u8).take(n));
        let (item, _) = decode_ttlv(&data).expect("boundary size must decode");
        if let TtlvValue::ByteString(bytes) = item.value {
            assert_eq!(bytes.len(), n);
        } else {
            panic!("wrong variant");
        }
    }

    /// A length of `MAX_TTLV_VALUE_SIZE + 1` must be rejected.
    #[test]
    fn value_one_byte_over_limit_rejected() {
        let n = MAX_TTLV_VALUE_SIZE + 1;
        let mut data = Vec::new();
        data.extend_from_slice(&[0x42, 0x00, 0x0A, TtlvType::ByteString.to_u8()]);
        data.extend_from_slice(&(n as u32).to_be_bytes());
        // No body needed — the length check fires before allocation.
        let result = decode_ttlv(&data);
        assert!(matches!(result, Err(TtlvError::ValueTooLarge(_))));
    }

    /// A TTLV header declaring `u32::MAX` length is rejected without
    /// attempting to allocate ~4 GiB.
    #[test]
    fn u32_max_length_rejected_without_allocation() {
        let mut data = vec![0x42, 0x00, 0x43, TtlvType::ByteString.to_u8()];
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        let result = decode_ttlv(&data);
        assert!(matches!(result, Err(TtlvError::ValueTooLarge(_))));
    }

    // -----------------------------------------------------------------------
    // Decoder bounds (audit finding H4)
    // -----------------------------------------------------------------------

    /// A deeply-nested Structure message is refused by the default depth
    /// limit. This is the DoS regression test called out in H4.
    #[test]
    fn deeply_nested_structure_rejected_by_depth_limit() {
        // Build N+1 nested empty structures where N > MAX_TTLV_DEPTH.
        let mut current = encode_ttlv(&TtlvItem {
            tag: 0x42_0001,
            value: TtlvValue::Integer(0),
        })
        .unwrap();
        for _ in 0..MAX_TTLV_DEPTH + 5 {
            let mut next = Vec::with_capacity(current.len() + 8);
            next.extend_from_slice(&[0x42, 0x00, 0x78, TtlvType::Structure.to_u8()]);
            next.extend_from_slice(&(current.len() as u32).to_be_bytes());
            next.extend_from_slice(&current);
            current = next;
        }
        let res = decode_ttlv(&current);
        assert!(matches!(res, Err(TtlvError::DepthExceeded)));
    }

    /// A Structure that declares more items than the caller-configured
    /// `max_items` is refused before the allocator runs away.
    #[test]
    fn structure_with_too_many_items_rejected() {
        // Build an outer Structure whose body is 100 copies of a minimal
        // Integer TTLV. Each integer item takes 16 bytes (8 header + 8 padded).
        let item_bytes = encode_ttlv(&TtlvItem {
            tag: 0x42_0001,
            value: TtlvValue::Integer(0),
        })
        .unwrap();
        let n = 100usize;
        let body_len = item_bytes.len() * n;

        let mut data = Vec::with_capacity(8 + body_len);
        data.extend_from_slice(&[0x42, 0x00, 0x78, TtlvType::Structure.to_u8()]);
        data.extend_from_slice(&(body_len as u32).to_be_bytes());
        for _ in 0..n {
            data.extend_from_slice(&item_bytes);
        }

        // Plenty of items permitted -> decodes OK.
        let ok = decode_ttlv_with_limits(
            &data,
            TtlvLimits {
                max_depth: MAX_TTLV_DEPTH,
                max_items: 1_000,
                max_bytes: 10 * 1024 * 1024,
            },
        );
        assert!(ok.is_ok(), "generous limits must decode cleanly");

        // Tight item cap -> rejected.
        let bad = decode_ttlv_with_limits(
            &data,
            TtlvLimits {
                max_depth: MAX_TTLV_DEPTH,
                max_items: 10,
                max_bytes: 10 * 1024 * 1024,
            },
        );
        assert!(matches!(bad, Err(TtlvError::TooManyItems(_))));
    }

    /// The cumulative byte budget catches a message that is well-formed but
    /// exceeds what the server is willing to spend on one decode.
    #[test]
    fn cumulative_byte_budget_enforced() {
        // Build a message that just barely exceeds 200 bytes of decoded
        // content (a small structure with a handful of integers).
        let mut kids = Vec::new();
        for _ in 0..20 {
            kids.push(TtlvItem {
                tag: 0x42_0001,
                value: TtlvValue::Integer(0),
            });
        }
        let outer = TtlvItem {
            tag: 0x42_0078,
            value: TtlvValue::Structure(kids),
        };
        let encoded = encode_ttlv(&outer).unwrap();
        assert!(encoded.len() > 100);

        let tight = decode_ttlv_with_limits(
            &encoded,
            TtlvLimits {
                max_depth: MAX_TTLV_DEPTH,
                max_items: MAX_TTLV_ITEMS,
                max_bytes: 64, // deliberately undersized
            },
        );
        assert!(matches!(tight, Err(TtlvError::MessageTooLarge(_))));
    }

    /// Default decoder (via `decode_ttlv`) still accepts normal messages.
    #[test]
    fn default_limits_accept_normal_messages() {
        let item = TtlvItem {
            tag: 0x42_0078,
            value: TtlvValue::Structure(vec![
                TtlvItem {
                    tag: 0x42_0001,
                    value: TtlvValue::Integer(1),
                },
                TtlvItem {
                    tag: 0x42_0002,
                    value: TtlvValue::TextString("ok".into()),
                },
            ]),
        };
        let encoded = encode_ttlv(&item).unwrap();
        assert!(decode_ttlv(&encoded).is_ok());
    }
}
