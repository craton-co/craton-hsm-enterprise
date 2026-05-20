// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Targeted negative-parsing and lifecycle tests for the KMIP crate.
//!
//! These complement the existing tests in `tests/integration.rs` and the
//! inline `mod tests` blocks in `src/ttlv.rs`, `src/operations.rs`, and
//! `src/server.rs` by covering the specific edge cases flagged by the
//! coverage audit:
//!
//! 1. TTLV decoder depth / size / truncation safety.
//! 2. Server rejection of an unknown operation enum inside a BatchItem.
//! 3. Full PreActive → Active → Deactivated → Destroyed lifecycle, plus
//!    KMIP 1.4 § 4.21 enforcement that `Destroy` on an Active key is
//!    rejected unless the key has been revoked first.
//! 4. GetAttributes on a non-existent UniqueIdentifier returns
//!    `ItemNotFound` (mapped here to `ObjectNotFound`).
//! 5. `Locate` with a non-matching filter returns an empty list, not an
//!    error.

use craton_hsm_kmip::operations::{
    process_activate, process_destroy, process_get_attributes, process_locate, process_revoke,
    InMemoryKeyStore, KmipAttribute, KmipAttributeValue, KmipKeyStore, KmipObjectState,
    KmipRequest,
};
use craton_hsm_kmip::server::{KmipServer, KmipServerConfig};
use craton_hsm_kmip::ttlv::{decode_ttlv, encode_ttlv, TtlvError, TtlvItem, TtlvType, TtlvValue};
use craton_hsm_kmip::types::{KmipOperation, KmipResultReason, KmipResultStatus, KmipTag};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_request(op: KmipOperation, unique_id: Option<&str>) -> KmipRequest {
    KmipRequest {
        operation: op,
        unique_id: unique_id.map(|s| s.to_string()),
        attributes: vec![],
        caller_identity: None,
        strict_owner_acl: false,
    }
}

// ---------------------------------------------------------------------------
// 1. TTLV decoder safety
// ---------------------------------------------------------------------------

/// Build a Structure-of-Structure-of-... chain of exactly `depth` nested
/// levels and verify the decoder rejects anything past `MAX_TTLV_DEPTH`.
///
/// `MAX_TTLV_DEPTH` is 32 in the implementation; we exceed it comfortably.
#[test]
fn ttlv_depth_beyond_32_is_rejected() {
    // Start with a leaf integer.
    let mut bytes = encode_ttlv(&TtlvItem {
        tag: 0x42_0001,
        value: TtlvValue::Integer(0),
    })
    .unwrap();

    // Wrap it 40 times — well above the 32-level limit. We build bytes
    // directly so we can exceed the limit on the wire even though the
    // encoder enforces a recursion-free streaming encode.
    for _ in 0..40 {
        let mut next = Vec::with_capacity(bytes.len() + 8);
        next.extend_from_slice(&[0x42, 0x00, 0x78]); // RequestMessage tag
        next.push(TtlvType::Structure.to_u8());
        let inner_len = bytes.len() as u32;
        next.extend_from_slice(&inner_len.to_be_bytes());
        next.extend_from_slice(&bytes);
        bytes = next;
    }

    let result = decode_ttlv(&bytes);
    assert!(
        matches!(result, Err(TtlvError::DepthExceeded)),
        "40-level nesting must be rejected as DepthExceeded, got {result:?}"
    );
}

/// A single TTLV value claiming more than 1 MiB must be rejected up-front,
/// without attempting the multi-megabyte allocation.
#[test]
fn ttlv_single_value_over_1mib_rejected() {
    const ONE_MIB: u32 = 1_048_576;

    // Header claims 1 MiB + 1 bytes; we do not even supply a body, because
    // the size check must fire before any allocation / copy.
    let mut data = vec![0x42, 0x00, 0x43, TtlvType::ByteString.to_u8()];
    data.extend_from_slice(&(ONE_MIB + 1).to_be_bytes());

    let result = decode_ttlv(&data);
    assert!(
        matches!(result, Err(TtlvError::ValueTooLarge(_))),
        "value > 1 MiB must be rejected as ValueTooLarge, got {result:?}"
    );
}

/// A truncated length field — fewer than 8 header bytes — must not panic.
#[test]
fn ttlv_truncated_header_rejected() {
    // Only 5 bytes: not enough for the 8-byte header.
    let short = [0x42, 0x00, 0x01, 0x02, 0x00];
    let result = decode_ttlv(&short);
    assert!(
        matches!(result, Err(TtlvError::Truncated)),
        "5-byte input must be Truncated, got {result:?}"
    );

    // Zero bytes.
    let empty: [u8; 0] = [];
    let result = decode_ttlv(&empty);
    assert!(matches!(result, Err(TtlvError::Truncated)));

    // 7 bytes — one short of a full header.
    let almost = [0x42, 0x00, 0x43, TtlvType::ByteString.to_u8(), 0, 0, 0];
    let result = decode_ttlv(&almost);
    assert!(matches!(result, Err(TtlvError::Truncated)));
}

/// A header with a valid type byte but a length that overflows the buffer
/// is reported as `Truncated`, not as an allocation.
#[test]
fn ttlv_length_overflows_buffer_rejected() {
    let mut data = vec![0x42, 0x00, 0x43, TtlvType::ByteString.to_u8()];
    // Claim 100 bytes of body but only provide 2.
    data.extend_from_slice(&(100u32).to_be_bytes());
    data.extend_from_slice(&[0u8; 2]);
    let result = decode_ttlv(&data);
    assert!(matches!(result, Err(TtlvError::Truncated)));
}

// ---------------------------------------------------------------------------
// 2. BatchItem with unknown operation enum value is rejected
// ---------------------------------------------------------------------------

/// A RequestMessage whose BatchItem carries an Operation enum value that
/// does not correspond to any known `KmipOperation` must yield an error
/// response — specifically an `InvalidMessage` status — not a panic and
/// not silent success.
#[test]
fn server_rejects_unknown_operation_enum_in_batch_item() {
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: false,
            ..KmipServerConfig::default()
        },
    );

    // Build a minimal RequestMessage with a BatchItem carrying an Operation
    // enum value of 0x7FFF_FFFF, which `KmipOperation::from_u32` does not
    // recognise.
    let bogus_op: u32 = 0x7FFF_FFFF;
    let request = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::RequestHeader.to_u32(),
                value: TtlvValue::Structure(vec![
                    TtlvItem {
                        tag: KmipTag::ProtocolVersion.to_u32(),
                        value: TtlvValue::Structure(vec![
                            TtlvItem {
                                tag: KmipTag::ProtocolVersionMajor.to_u32(),
                                value: TtlvValue::Integer(2),
                            },
                            TtlvItem {
                                tag: KmipTag::ProtocolVersionMinor.to_u32(),
                                value: TtlvValue::Integer(1),
                            },
                        ]),
                    },
                    TtlvItem {
                        tag: KmipTag::BatchCount.to_u32(),
                        value: TtlvValue::Integer(1),
                    },
                ]),
            },
            TtlvItem {
                tag: KmipTag::BatchItem.to_u32(),
                value: TtlvValue::Structure(vec![TtlvItem {
                    tag: KmipTag::Operation.to_u32(),
                    value: TtlvValue::Enumeration(bogus_op),
                }]),
            },
        ]),
    };
    let bytes = encode_ttlv(&request).expect("encode must succeed");
    let response_bytes = server.process_message(&bytes);

    // Decode the response and look for a ResultStatus = OperationFailed
    // (any non-empty response signalling error is acceptable; we assert
    // the minimum: the server must have produced *some* response, not
    // panicked, and must not return success).
    assert!(
        !response_bytes.is_empty(),
        "server must produce an error response rather than returning empty bytes"
    );
    let (decoded, _) = decode_ttlv(&response_bytes)
        .expect("the server's error response must itself be valid TTLV");
    // Find a ResultStatus anywhere in the tree; it must NOT be Success (0).
    fn find_result_status(item: &TtlvItem) -> Option<i32> {
        if item.tag == KmipTag::ResultStatus.to_u32() {
            if let TtlvValue::Enumeration(v) = &item.value {
                return Some(*v as i32);
            }
            if let TtlvValue::Integer(v) = &item.value {
                return Some(*v);
            }
        }
        if let TtlvValue::Structure(children) = &item.value {
            for c in children {
                if let Some(s) = find_result_status(c) {
                    return Some(s);
                }
            }
        }
        None
    }
    let status = find_result_status(&decoded).expect("response must carry a ResultStatus");
    assert_ne!(
        status,
        KmipResultStatus::Success.to_u32() as i32,
        "bogus operation must NOT produce Success"
    );
}

// ---------------------------------------------------------------------------
// 3. Full object lifecycle + KMIP 1.4 Destroy-on-Active rejection
// ---------------------------------------------------------------------------

/// Happy path: PreActive → Active → Deactivated → Destroyed.
#[test]
fn object_lifecycle_full_path() {
    let store = InMemoryKeyStore::new();

    // Create produces a PreActive object.
    let id = store.create(
        craton_hsm_kmip::types::KmipObjectType::SymmetricKey,
        vec![0u8; 32],
        Default::default(),
    );
    assert_eq!(store.get(&id).unwrap().state, KmipObjectState::PreActive);

    // Activate → Active.
    let resp = process_activate(&make_request(KmipOperation::Activate, Some(&id)), &store);
    assert_eq!(resp.status, KmipResultStatus::Success);
    assert_eq!(store.get(&id).unwrap().state, KmipObjectState::Active);

    // Revoke → Deactivated.
    let resp = process_revoke(&make_request(KmipOperation::Revoke, Some(&id)), &store);
    assert_eq!(resp.status, KmipResultStatus::Success);
    assert_eq!(store.get(&id).unwrap().state, KmipObjectState::Deactivated);

    // Destroy from Deactivated → Destroyed.
    let resp = process_destroy(&make_request(KmipOperation::Destroy, Some(&id)), &store);
    assert_eq!(resp.status, KmipResultStatus::Success);
    let obj = store.get(&id).unwrap();
    assert_eq!(obj.state, KmipObjectState::Destroyed);
    // Key material must be wiped.
    assert!(obj.key_material.is_none());
}

/// KMIP 1.4 § 4.21 / KMIP 2.1 § 4.8: `Destroy` on an Active object without
/// prior `Revoke` must fail.  An unrevoked Active key cannot be destroyed.
#[test]
fn destroy_on_active_without_revoke_rejected() {
    let store = InMemoryKeyStore::new();

    let id = store.create(
        craton_hsm_kmip::types::KmipObjectType::SymmetricKey,
        vec![0u8; 32],
        Default::default(),
    );
    process_activate(&make_request(KmipOperation::Activate, Some(&id)), &store);
    assert_eq!(store.get(&id).unwrap().state, KmipObjectState::Active);

    // Destroy without Revoke must NOT succeed.
    let resp = process_destroy(&make_request(KmipOperation::Destroy, Some(&id)), &store);
    assert_eq!(
        resp.status,
        KmipResultStatus::OperationFailed,
        "destroying an Active object without prior Revoke must fail"
    );
    assert_eq!(resp.reason, Some(KmipResultReason::PermissionDenied));
    // State must not have changed.
    assert_eq!(store.get(&id).unwrap().state, KmipObjectState::Active);
}

// ---------------------------------------------------------------------------
// 4. GetAttributes on a non-existent UniqueIdentifier
// ---------------------------------------------------------------------------

#[test]
fn get_attributes_nonexistent_returns_not_found() {
    let store = InMemoryKeyStore::new();
    let req = make_request(KmipOperation::GetAttributes, Some("kmip-does-not-exist"));
    let resp = process_get_attributes(&req, &store);
    assert_eq!(resp.status, KmipResultStatus::OperationFailed);
    // KMIP "Item Not Found" maps to our ObjectNotFound variant.
    assert_eq!(resp.reason, Some(KmipResultReason::ObjectNotFound));
}

// ---------------------------------------------------------------------------
// 5. Locate with non-matching filter
// ---------------------------------------------------------------------------

#[test]
fn locate_with_non_matching_filter_returns_empty_success() {
    let store = InMemoryKeyStore::new();
    // Create an object with one attribute.
    let mut attrs = std::collections::HashMap::new();
    attrs.insert(
        "Name".to_string(),
        KmipAttributeValue::Text("real-key".to_string()),
    );
    store.create(
        craton_hsm_kmip::types::KmipObjectType::SymmetricKey,
        vec![0u8; 32],
        attrs,
    );

    // Build a Locate request whose filter does not match anything.
    let req = KmipRequest {
        operation: KmipOperation::Locate,
        unique_id: None,
        attributes: vec![KmipAttribute {
            name: "Name".into(),
            value: KmipAttributeValue::Text("nonexistent-needle".into()),
        }],
        caller_identity: None,
        strict_owner_acl: false,
    };
    let resp = process_locate(&req, &store);

    // A non-match is NOT an error: Locate returns an empty list with
    // status Success. This matches KMIP semantics (ItemNotFound is for
    // operations that require the object to exist, like Get).
    assert_eq!(resp.status, KmipResultStatus::Success);
    assert!(
        resp.located_ids.is_empty(),
        "non-matching filter must return an empty list, got {:?}",
        resp.located_ids
    );
}
