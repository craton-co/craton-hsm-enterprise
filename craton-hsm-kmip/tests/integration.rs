// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Integration tests for the KMIP server.
//!
//! Tests the full request/response cycle through the TTLV codec and server
//! dispatcher, verifying key lifecycle operations end-to-end.

use craton_hsm_kmip::acl::{KmipAcl, KmipAclDecision};
use craton_hsm_kmip::operations::InMemoryKeyStore;
use craton_hsm_kmip::server::{KmipServer, KmipServerConfig};
use craton_hsm_kmip::ttlv::{decode_ttlv, encode_ttlv, TtlvItem, TtlvValue};
use craton_hsm_kmip::types::{
    KmipObjectType, KmipOperation, KmipResultReason, KmipResultStatus, KmipTag,
};
use zeroize::Zeroizing;

/// Helper: build a KMIP Create request for a symmetric key.
fn build_create_request(algorithm: u32, length: i32) -> Vec<u8> {
    let request = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(vec![
            // Request header
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
            // Batch item
            TtlvItem {
                tag: KmipTag::BatchItem.to_u32(),
                value: TtlvValue::Structure(vec![
                    TtlvItem {
                        tag: KmipTag::Operation.to_u32(),
                        value: TtlvValue::Enumeration(KmipOperation::Create.to_u32()),
                    },
                    TtlvItem {
                        tag: KmipTag::ObjectType.to_u32(),
                        value: TtlvValue::Enumeration(KmipObjectType::SymmetricKey.to_u32()),
                    },
                    TtlvItem {
                        tag: KmipTag::TemplateAttribute.to_u32(),
                        value: TtlvValue::Structure(vec![
                            TtlvItem {
                                tag: KmipTag::Attribute.to_u32(),
                                value: TtlvValue::Structure(vec![
                                    TtlvItem {
                                        tag: KmipTag::AttributeName.to_u32(),
                                        value: TtlvValue::TextString(
                                            "Cryptographic Algorithm".to_string(),
                                        ),
                                    },
                                    TtlvItem {
                                        tag: KmipTag::AttributeValue.to_u32(),
                                        value: TtlvValue::Enumeration(algorithm),
                                    },
                                ]),
                            },
                            TtlvItem {
                                tag: KmipTag::Attribute.to_u32(),
                                value: TtlvValue::Structure(vec![
                                    TtlvItem {
                                        tag: KmipTag::AttributeName.to_u32(),
                                        value: TtlvValue::TextString(
                                            "Cryptographic Length".to_string(),
                                        ),
                                    },
                                    TtlvItem {
                                        tag: KmipTag::AttributeValue.to_u32(),
                                        value: TtlvValue::Integer(length),
                                    },
                                ]),
                            },
                        ]),
                    },
                ]),
            },
        ]),
    };
    encode_ttlv(&request).expect("encode_ttlv succeeds on well-formed input")
}

/// Helper: build a KMIP Get request.
fn build_get_request(unique_id: &str) -> Vec<u8> {
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
                value: TtlvValue::Structure(vec![
                    TtlvItem {
                        tag: KmipTag::Operation.to_u32(),
                        value: TtlvValue::Enumeration(KmipOperation::Get.to_u32()),
                    },
                    TtlvItem {
                        tag: KmipTag::UniqueIdentifier.to_u32(),
                        value: TtlvValue::TextString(unique_id.to_string()),
                    },
                ]),
            },
        ]),
    };
    encode_ttlv(&request).expect("encode_ttlv succeeds on well-formed input")
}

/// Helper: build a simple operation request (Activate, Revoke, Destroy).
fn build_simple_request(operation: KmipOperation, unique_id: &str) -> Vec<u8> {
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
                value: TtlvValue::Structure(vec![
                    TtlvItem {
                        tag: KmipTag::Operation.to_u32(),
                        value: TtlvValue::Enumeration(operation.to_u32()),
                    },
                    TtlvItem {
                        tag: KmipTag::UniqueIdentifier.to_u32(),
                        value: TtlvValue::TextString(unique_id.to_string()),
                    },
                ]),
            },
        ]),
    };
    encode_ttlv(&request).expect("encode_ttlv succeeds on well-formed input")
}

/// Extract the result status from a raw TTLV response.
fn extract_result_status(raw: &[u8]) -> KmipResultStatus {
    let (item, _) = decode_ttlv(raw).expect("response decode failed");
    if let TtlvValue::Structure(top) = &item.value {
        for child in top {
            if child.tag == KmipTag::BatchItem.to_u32() {
                if let TtlvValue::Structure(batch) = &child.value {
                    for field in batch {
                        if field.tag == KmipTag::ResultStatus.to_u32() {
                            if let TtlvValue::Enumeration(v) = field.value {
                                return KmipResultStatus::from_u32(v)
                                    .unwrap_or(KmipResultStatus::OperationFailed);
                            }
                        }
                    }
                }
            }
        }
    }
    panic!("ResultStatus not found in response");
}

/// Extract the unique ID from a raw TTLV response.
fn extract_unique_id(raw: &[u8]) -> Option<String> {
    let (item, _) = decode_ttlv(raw).expect("response decode failed");
    if let TtlvValue::Structure(top) = &item.value {
        for child in top {
            if child.tag == KmipTag::BatchItem.to_u32() {
                if let TtlvValue::Structure(batch) = &child.value {
                    for field in batch {
                        if field.tag == KmipTag::UniqueIdentifier.to_u32() {
                            if let TtlvValue::TextString(id) = &field.value {
                                return Some(id.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn make_test_server() -> KmipServer {
    KmipServer::with_defaults()
}

// ---- Integration tests ----

#[test]
fn test_full_key_lifecycle() {
    let server = make_test_server();

    // 1. Create a 256-bit AES key
    let create_req = build_create_request(0x03, 256); // AES = 0x03
    let create_resp = server.process_message(&create_req);
    assert_eq!(
        extract_result_status(&create_resp),
        KmipResultStatus::Success
    );
    let key_id = extract_unique_id(&create_resp).expect("should return unique ID");

    // 2. Get the key (should be PreActive)
    let get_req = build_get_request(&key_id);
    let get_resp = server.process_message(&get_req);
    assert_eq!(extract_result_status(&get_resp), KmipResultStatus::Success);

    // 3. Activate the key
    let activate_req = build_simple_request(KmipOperation::Activate, &key_id);
    let activate_resp = server.process_message(&activate_req);
    assert_eq!(
        extract_result_status(&activate_resp),
        KmipResultStatus::Success
    );

    // 4. Revoke the key
    let revoke_req = build_simple_request(KmipOperation::Revoke, &key_id);
    let revoke_resp = server.process_message(&revoke_req);
    assert_eq!(
        extract_result_status(&revoke_resp),
        KmipResultStatus::Success
    );

    // 5. Destroy the key
    let destroy_req = build_simple_request(KmipOperation::Destroy, &key_id);
    let destroy_resp = server.process_message(&destroy_req);
    assert_eq!(
        extract_result_status(&destroy_resp),
        KmipResultStatus::Success
    );

    // 6. Get should fail (destroyed)
    let get_req2 = build_get_request(&key_id);
    let get_resp2 = server.process_message(&get_req2);
    assert_eq!(
        extract_result_status(&get_resp2),
        KmipResultStatus::OperationFailed
    );
}

#[test]
fn test_create_multiple_keys() {
    let server = make_test_server();

    let mut ids = Vec::new();
    for _ in 0..5 {
        let req = build_create_request(0x03, 256);
        let resp = server.process_message(&req);
        assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
        ids.push(extract_unique_id(&resp).unwrap());
    }

    // All IDs should be unique
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 5, "all key IDs should be unique");
}

#[test]
fn test_get_nonexistent_key() {
    let server = make_test_server();
    let req = build_get_request("nonexistent-key-id");
    let resp = server.process_message(&req);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

#[test]
fn test_destroy_nonexistent_key() {
    let server = make_test_server();
    let req = build_simple_request(KmipOperation::Destroy, "nonexistent");
    let resp = server.process_message(&req);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

#[test]
fn test_malformed_ttlv_rejected() {
    let server = make_test_server();
    let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
    let resp = server.process_message(&garbage);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

#[test]
fn test_empty_request_rejected() {
    let server = make_test_server();
    let resp = server.process_message(&[]);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

#[test]
fn test_oversized_message_rejected() {
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            max_message_size: 16,
            require_auth: false,
            ..KmipServerConfig::default()
        },
    );
    let req = build_create_request(0x03, 256);
    assert!(req.len() > 16);
    let resp = server.process_message(&req);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

// 32+ byte strong test token — below this, validate_for_production rejects.
#[cfg(feature = "insecure-static-token")]
const STRONG_TEST_TOKEN: &str = "integration-token-0123456789abcdef0123456789abcdef";

#[cfg(feature = "insecure-static-token")]
#[test]
fn test_auth_required_rejects_without_token() {
    std::env::set_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            ..KmipServerConfig::default()
        },
    );

    let req = build_create_request(0x03, 256);
    // No token provided
    let resp = server.process_message(&req);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

#[cfg(feature = "insecure-static-token")]
#[test]
fn test_auth_required_accepts_valid_token() {
    std::env::set_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            ..KmipServerConfig::default()
        },
    );

    let req = build_create_request(0x03, 256);
    let resp = server.process_message_with_auth(&req, Some(STRONG_TEST_TOKEN));
    assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
}

#[cfg(feature = "insecure-static-token")]
#[test]
fn test_auth_required_rejects_wrong_token() {
    std::env::set_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            ..KmipServerConfig::default()
        },
    );

    let req = build_create_request(0x03, 256);
    let resp = server.process_message_with_auth(&req, Some("wrong-secret"));
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

#[test]
fn test_query_operation() {
    let server = make_test_server();

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
                    value: TtlvValue::Enumeration(KmipOperation::Query.to_u32()),
                }]),
            },
        ]),
    };
    let req = encode_ttlv(&request).expect("encode_ttlv");
    let resp = server.process_message(&req);
    assert_eq!(extract_result_status(&resp), KmipResultStatus::Success);
}

#[test]
fn test_activate_preactive_key_then_get() {
    let server = make_test_server();

    // Create
    let create_req = build_create_request(0x03, 128);
    let create_resp = server.process_message(&create_req);
    let key_id = extract_unique_id(&create_resp).unwrap();

    // Activate
    let activate_req = build_simple_request(KmipOperation::Activate, &key_id);
    let activate_resp = server.process_message(&activate_req);
    assert_eq!(
        extract_result_status(&activate_resp),
        KmipResultStatus::Success
    );

    // Get (should succeed with active key)
    let get_req = build_get_request(&key_id);
    let get_resp = server.process_message(&get_req);
    assert_eq!(extract_result_status(&get_resp), KmipResultStatus::Success);
}

// ---------------------------------------------------------------------------
// Audit H4 / M8 integration regressions
// ---------------------------------------------------------------------------

/// Audit H4: an attacker-crafted TTLV message with thousands of nested
/// structures must be rejected by the server dispatcher before it drives
/// the decoder into deep recursion.
#[test]
fn test_deeply_nested_ttlv_rejected_by_server() {
    let server = make_test_server();

    // Build N+1 levels of empty Structure wrapping, well above MAX_TTLV_DEPTH (32).
    let mut current = encode_ttlv(&TtlvItem {
        tag: 0x42_0001,
        value: TtlvValue::Integer(0),
    })
    .expect("leaf encode");
    for _ in 0..60 {
        let mut next = Vec::with_capacity(current.len() + 8);
        next.extend_from_slice(&[0x42, 0x00, 0x78, 0x01 /* Structure */]);
        next.extend_from_slice(&(current.len() as u32).to_be_bytes());
        next.extend_from_slice(&current);
        current = next;
    }

    // The server must refuse to decode this message, returning a KMIP
    // error response rather than recursing into many stack frames.
    let resp = server.process_message(&current);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

/// Audit H4: a TTLV Structure that declares far more children than the
/// server's item cap must be rejected before the allocator runs wild.
#[test]
fn test_huge_item_count_ttlv_rejected_by_server() {
    // Build a Structure containing 20_000 padding-free Integer items.
    // Each integer encodes to 16 bytes, so the body is 320_000 bytes — well
    // under the 1 MiB per-value limit but above the 10_000 item cap.
    let item = encode_ttlv(&TtlvItem {
        tag: 0x42_0001,
        value: TtlvValue::Integer(0),
    })
    .unwrap();

    let n = 20_000usize;
    let body_len = item.len() * n;

    let mut raw = Vec::with_capacity(body_len + 8);
    raw.extend_from_slice(&[0x42, 0x00, 0x78, 0x01 /* Structure */]);
    raw.extend_from_slice(&(body_len as u32).to_be_bytes());
    for _ in 0..n {
        raw.extend_from_slice(&item);
    }

    // Default config caps max_message_size at 1 MiB, and the decoder caps
    // max_items at 10_000. Either limit must fire before the server
    // allocates a 20_000-entry child vector.
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: false,
            max_message_size: 5_000_000, // raise so the size check doesn't mask the item-count check
            ..KmipServerConfig::default()
        },
    );
    let resp = server.process_message(&raw);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
}

// ---------------------------------------------------------------------------
// Audit follow-up (2026-04-19): negative / malformed TTLV coverage
// ---------------------------------------------------------------------------

/// Extract the optional result reason from a raw TTLV response.
fn extract_result_reason(raw: &[u8]) -> Option<KmipResultReason> {
    let (item, _) = decode_ttlv(raw).ok()?;
    if let TtlvValue::Structure(top) = &item.value {
        for child in top {
            if child.tag == KmipTag::BatchItem.to_u32() {
                if let TtlvValue::Structure(batch) = &child.value {
                    for field in batch {
                        if field.tag == KmipTag::ResultReason.to_u32() {
                            if let TtlvValue::Enumeration(v) = &field.value {
                                return KmipResultReason::from_u32(*v);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Build a Register request: unique_id plus optional attributes in a
/// TemplateAttribute structure.
fn build_register_request(unique_id: &str, attrs: Vec<TtlvItem>) -> Vec<u8> {
    let mut batch_children = vec![
        TtlvItem {
            tag: KmipTag::Operation.to_u32(),
            value: TtlvValue::Enumeration(KmipOperation::Register.to_u32()),
        },
        TtlvItem {
            tag: KmipTag::UniqueIdentifier.to_u32(),
            value: TtlvValue::TextString(unique_id.to_string()),
        },
    ];
    if !attrs.is_empty() {
        batch_children.push(TtlvItem {
            tag: KmipTag::TemplateAttribute.to_u32(),
            value: TtlvValue::Structure(attrs),
        });
    }
    let request = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::RequestHeader.to_u32(),
                value: TtlvValue::Structure(vec![]),
            },
            TtlvItem {
                tag: KmipTag::BatchItem.to_u32(),
                value: TtlvValue::Structure(batch_children),
            },
        ]),
    };
    encode_ttlv(&request).expect("encode_ttlv succeeds on well-formed input")
}

/// Owner-only ACL used to exercise the pluggable authorization layer.
struct OwnerOnlyAcl {
    owner: String,
}

impl KmipAcl for OwnerOnlyAcl {
    fn authorize(
        &self,
        identity: Option<&str>,
        _operation: KmipOperation,
        _object_id: Option<&str>,
    ) -> KmipAclDecision {
        match identity {
            Some(id) if id == self.owner => KmipAclDecision::Allow,
            _ => KmipAclDecision::Deny(KmipResultReason::PermissionDenied),
        }
    }
}

/// Fix 1 coverage: a non-owner caller attempting to Register a UniqueIdentifier
/// that already belongs to another tenant must be rejected with
/// `ObjectNotFound` — not `PermissionDenied` — so Register cannot be abused
/// as a cross-tenant existence oracle.
#[test]
fn register_without_acl_permission_returns_object_not_found() {
    // Auth disabled so caller_identity flows from the token field verbatim,
    // and the pluggable ACL is AllowAll — the test isolates the per-object
    // owner ACL that `process_register` now enforces against pre-existing IDs.
    let server = KmipServer::with_defaults();

    // Alice registers an object with a fixed ID. The handler auto-attaches
    // alice as owner because the request doesn't carry one.
    let alice_reg = build_register_request("shared-id", vec![]);
    let alice_resp = server.process_message_with_auth(&alice_reg, Some("alice"));
    assert_eq!(
        extract_result_status(&alice_resp),
        KmipResultStatus::Success
    );

    // Mallory tries to register the same ID. The owner ACL masks the
    // existence check and returns ObjectNotFound rather than a
    // distinguishable PermissionDenied.
    let mallory_reg = build_register_request("shared-id", vec![]);
    let mallory_resp = server.process_message_with_auth(&mallory_reg, Some("mallory"));
    assert_eq!(
        extract_result_status(&mallory_resp),
        KmipResultStatus::OperationFailed
    );
    assert_eq!(
        extract_result_reason(&mallory_resp),
        Some(KmipResultReason::ObjectNotFound),
        "mallory must not learn that 'shared-id' exists in another tenant"
    );
}

/// Fix 1 coverage: with a pluggable ACL installed that denies unknown
/// callers globally, Register (now in `operation_requires_acl`) is gated
/// before the handler runs and returns PermissionDenied.
#[test]
fn register_denied_by_pluggable_acl_returns_permission_denied() {
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: false,
            ..KmipServerConfig::default()
        },
    )
    .with_acl(OwnerOnlyAcl {
        owner: "alice".to_string(),
    });

    // Mallory is blocked by the pluggable ACL before the handler runs.
    let reg = build_register_request("k1", vec![]);
    let resp = server.process_message_with_auth(&reg, Some("mallory"));
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
    assert_eq!(
        extract_result_reason(&resp),
        Some(KmipResultReason::PermissionDenied),
    );

    // Alice — the owner the ACL accepts — registers a *different* ID
    // successfully, proving the gate is per-caller and not a blanket deny.
    let reg_alice = build_register_request("k2", vec![]);
    let ok = server.process_message_with_auth(&reg_alice, Some("alice"));
    assert_eq!(extract_result_status(&ok), KmipResultStatus::Success);
}

/// Fix 2 coverage: a BatchItem whose Operation enumeration value does not map
/// to any known KMIP operation (parse_request returns None) must produce a
/// protocol-error response rather than dispatching to some default handler.
#[test]
fn malformed_batchitem_unknown_operation_enum_returns_protocol_error() {
    let server = KmipServer::with_defaults();

    // 0xDEAD_BEEF is deliberately outside the KMIP 2.1 Operation enumeration
    // range handled by `KmipOperation::from_u32`.
    let request = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::RequestHeader.to_u32(),
                value: TtlvValue::Structure(vec![]),
            },
            TtlvItem {
                tag: KmipTag::BatchItem.to_u32(),
                value: TtlvValue::Structure(vec![TtlvItem {
                    tag: KmipTag::Operation.to_u32(),
                    value: TtlvValue::Enumeration(0xDEAD_BEEF),
                }]),
            },
        ]),
    };
    let raw = encode_ttlv(&request).expect("encode_ttlv");
    let resp = server.process_message(&raw);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
    assert_eq!(
        extract_result_reason(&resp),
        Some(KmipResultReason::InvalidMessage),
    );
}

/// Fix 2 coverage: a BatchItem that carries the UniqueIdentifier tag but with
/// an Integer value (rather than a TextString) must be rejected. The parser
/// must not accidentally coerce or ignore the wrong type and fall through
/// to a handler with `unique_id = None`.
#[test]
fn batch_item_with_wrong_type_for_unique_identifier_is_rejected() {
    let server = KmipServer::with_defaults();

    // Get requires a UniqueIdentifier, but we deliberately encode it as an
    // Integer. `parse_request` ignores the wrongly-typed field so the
    // handler sees `unique_id = None` and returns InvalidMessage.
    let request = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::RequestHeader.to_u32(),
                value: TtlvValue::Structure(vec![]),
            },
            TtlvItem {
                tag: KmipTag::BatchItem.to_u32(),
                value: TtlvValue::Structure(vec![
                    TtlvItem {
                        tag: KmipTag::Operation.to_u32(),
                        value: TtlvValue::Enumeration(KmipOperation::Get.to_u32()),
                    },
                    TtlvItem {
                        tag: KmipTag::UniqueIdentifier.to_u32(),
                        value: TtlvValue::Integer(12345), // wrong type
                    },
                ]),
            },
        ]),
    };
    let raw = encode_ttlv(&request).expect("encode_ttlv");
    let resp = server.process_message(&raw);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
    assert_eq!(
        extract_result_reason(&resp),
        Some(KmipResultReason::InvalidMessage),
    );
}

/// Fix 2 / Fix 5 coverage: a request whose encoded length exceeds
/// `max_message_size` must be rejected with `InvalidMessage` *before* the
/// TTLV decoder runs, so a pathological length field cannot drive unbounded
/// allocation even when the wrapper bytes are otherwise well-formed.
#[test]
fn oversized_request_exceeding_max_message_size_is_rejected() {
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            max_message_size: 64,
            require_auth: false,
            ..KmipServerConfig::default()
        },
    );
    // A Create request with a full template payload is always larger than
    // 64 bytes — we verified via the `assert!` below.
    let req = build_create_request(0x03, 256);
    assert!(req.len() > 64, "test fixture must actually exceed the cap");
    let resp = server.process_message(&req);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
    assert_eq!(
        extract_result_reason(&resp),
        Some(KmipResultReason::InvalidMessage),
    );
}

/// Fix 2 coverage: Register without the mandatory `UniqueIdentifier`
/// field must return `InvalidMessage`. This covers the bare minimum
/// structural-validation contract of the Register handler.
#[test]
fn missing_required_attribute_on_register_returns_protocol_error() {
    let server = KmipServer::with_defaults();

    // Register with no UniqueIdentifier at all.
    let request = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::RequestHeader.to_u32(),
                value: TtlvValue::Structure(vec![]),
            },
            TtlvItem {
                tag: KmipTag::BatchItem.to_u32(),
                value: TtlvValue::Structure(vec![TtlvItem {
                    tag: KmipTag::Operation.to_u32(),
                    value: TtlvValue::Enumeration(KmipOperation::Register.to_u32()),
                }]),
            },
        ]),
    };
    let raw = encode_ttlv(&request).expect("encode_ttlv");
    let resp = server.process_message(&raw);
    assert_eq!(
        extract_result_status(&resp),
        KmipResultStatus::OperationFailed
    );
    assert_eq!(
        extract_result_reason(&resp),
        Some(KmipResultReason::InvalidMessage),
    );
}

// ---------------------------------------------------------------------------
// Fix 4: rate-limiter eviction under a pathological failure flood.
// ---------------------------------------------------------------------------
//
// The rate limiter's `failures` map is private to `server.rs`, so the public
// integration-test surface cannot assert on its size directly. Instead, this
// test exercises the public contract: driving 10k failed authentications from
// distinct clients must not OOM the process, and the surviving cap on
// memory is empirically observed through the lack of excessive wall-clock
// blow-up and the continued availability of the authentication path after
// the flood.

#[cfg(feature = "insecure-static-token")]
#[test]
fn rate_limit_cache_eviction_under_pathological_failure_flood() {
    std::env::set_var("CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN", "1");
    let server = KmipServer::new(
        Box::new(InMemoryKeyStore::new()),
        KmipServerConfig {
            require_auth: true,
            auth_token: Some(Zeroizing::new(STRONG_TEST_TOKEN.to_string())),
            ..KmipServerConfig::default()
        },
    );

    let req = build_create_request(0x03, 256);

    // Drive 10_000 distinct peers through a failed-auth path. The server
    // hashes the client token into a 32-byte key; by using distinct token
    // strings we guarantee distinct map slots, which is the pathological
    // shape the eviction cadence (every 100 requests) is meant to bound.
    //
    // This test intentionally does NOT assert on internal map size — that
    // surface is private. It asserts that the server remains responsive
    // throughout the flood (no OOM, no pathological slowdown) and that a
    // legitimate request with the configured token still succeeds at the
    // end, demonstrating the rate-limit and eviction logic have not
    // cascaded into a state where the server rejects all callers.
    let flood_start = std::time::Instant::now();
    for i in 0..10_000u32 {
        let token = format!("bad-token-from-peer-{:08x}", i);
        let _ = server.process_message_with_auth(&req, Some(&token));
    }
    let flood_elapsed = flood_start.elapsed();
    // Sanity upper bound: 10k in-process ops should comfortably finish in
    // under 30 seconds even on a slow CI. The exact threshold matters less
    // than catching an accidental O(n^2) regression.
    assert!(
        flood_elapsed < std::time::Duration::from_secs(30),
        "rate-limit flood took {flood_elapsed:?}, suggesting unbounded map growth"
    );

    // The legitimate operator's token is NOT any of the flooder hashes, so
    // it should still authenticate successfully unless the limiter globally
    // blackholes traffic — which would itself be a bug.
    let ok = server.process_message_with_auth(&req, Some(STRONG_TEST_TOKEN));
    assert_eq!(
        extract_result_status(&ok),
        KmipResultStatus::Success,
        "legitimate caller rejected after flood — rate-limit eviction is broken"
    );
}
