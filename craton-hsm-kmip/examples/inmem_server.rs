// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//
//! Minimal runnable demo: an in-memory KMIP server that handles one
//! Create + Get + Destroy lifecycle over a plain TCP loopback socket.
//!
//! This deliberately avoids TLS so the example is self-contained — the
//! production [`KmipServer::serve`] entry point requires mTLS, and a real
//! deployment should wire that one in. The TTLV wire format (and the
//! dispatcher) are identical either way.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example inmem_server -p craton-hsm-kmip
//! ```

use std::sync::Arc;

use craton_hsm_kmip::operations::InMemoryKeyStore;
use craton_hsm_kmip::server::{KmipServer, KmipServerConfig};
use craton_hsm_kmip::ttlv::{decode_ttlv, encode_ttlv, TtlvItem, TtlvValue};
use craton_hsm_kmip::types::{KmipOperation, KmipTag};
use craton_hsm_kmip::AllowAll;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Build a generic `BatchItem` carrying just an `Operation` + `UniqueIdentifier`.
fn op_with_id(op: KmipOperation, id: &str) -> Vec<u8> {
    wrap_request(vec![TtlvItem {
        tag: KmipTag::BatchItem.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::Operation.to_u32(),
                value: TtlvValue::Enumeration(op.to_u32()),
            },
            TtlvItem {
                tag: KmipTag::UniqueIdentifier.to_u32(),
                value: TtlvValue::TextString(id.to_string()),
            },
        ]),
    }])
}

/// Build a `Create` request for a 256-bit AES key.
fn create_aes256_request() -> Vec<u8> {
    let attrs = vec![
        attr("Cryptographic Algorithm", TtlvValue::Enumeration(3)), // AES
        attr("Cryptographic Length", TtlvValue::Integer(256)),
    ];
    wrap_request(vec![TtlvItem {
        tag: KmipTag::BatchItem.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::Operation.to_u32(),
                value: TtlvValue::Enumeration(KmipOperation::Create.to_u32()),
            },
            TtlvItem {
                tag: KmipTag::TemplateAttribute.to_u32(),
                value: TtlvValue::Structure(attrs),
            },
        ]),
    }])
}

fn attr(name: &str, value: TtlvValue) -> TtlvItem {
    TtlvItem {
        tag: KmipTag::Attribute.to_u32(),
        value: TtlvValue::Structure(vec![
            TtlvItem {
                tag: KmipTag::AttributeName.to_u32(),
                value: TtlvValue::TextString(name.to_string()),
            },
            TtlvItem {
                tag: KmipTag::AttributeValue.to_u32(),
                value,
            },
        ]),
    }
}

fn wrap_request(batch: Vec<TtlvItem>) -> Vec<u8> {
    let mut children = vec![TtlvItem {
        tag: KmipTag::RequestHeader.to_u32(),
        value: TtlvValue::Structure(vec![]),
    }];
    children.extend(batch);
    let msg = TtlvItem {
        tag: KmipTag::RequestMessage.to_u32(),
        value: TtlvValue::Structure(children),
    };
    encode_ttlv(&msg).expect("encode")
}

/// Pull `UniqueIdentifier` out of a response BatchItem.
fn unique_id(raw: &[u8]) -> Option<String> {
    let (item, _) = decode_ttlv(raw).ok()?;
    let TtlvValue::Structure(children) = item.value else {
        return None;
    };
    let batch = children
        .iter()
        .find(|c| c.tag == KmipTag::BatchItem.to_u32())?;
    let TtlvValue::Structure(batch_children) = &batch.value else {
        return None;
    };
    batch_children.iter().find_map(|c| {
        if c.tag == KmipTag::UniqueIdentifier.to_u32() {
            if let TtlvValue::TextString(s) = &c.value {
                return Some(s.clone());
            }
        }
        None
    })
}

/// Frame format: read the full 8-byte TTLV header, then `length` bytes
/// rounded up to the next multiple of 8 — the same framing the production
/// server uses on the wire.
async fn read_one(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let padded = length.next_multiple_of(8);
    let mut body = vec![0u8; padded];
    stream.read_exact(&mut body).await?;
    let mut full = Vec::with_capacity(8 + padded);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    Ok(full)
}

async fn round_trip(client: &mut TcpStream, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    client.write_all(payload).await?;
    client.flush().await?;
    read_one(client).await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    // Build a dispatcher with the in-memory store and the permissive ACL.
    // Production deployments swap `AllowAll` for an ACL backed by
    // `craton-hsm-auth` and add a real TLS config — see crate README.
    let server = Arc::new(
        KmipServer::new(
            Box::new(InMemoryKeyStore::new()),
            KmipServerConfig {
                require_auth: false,
                ..KmipServerConfig::default()
            },
        )
        .with_acl(AllowAll),
    );

    // 127.0.0.1:0 → OS-assigned ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    println!("listening on {addr}");

    // Accept one connection in the background, run the dispatcher loop,
    // and exit after the client disconnects.
    let server_clone = server.clone();
    let server_task = tokio::spawn(async move {
        let (mut sock, _peer) = listener.accept().await?;
        while let Ok(req) = read_one(&mut sock).await {
            let resp = server_clone.process_message(&req);
            sock.write_all(&resp).await?;
            sock.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });

    // Drive one Create + Get + Destroy lifecycle.
    let mut client = TcpStream::connect(addr).await?;
    let create_resp = round_trip(&mut client, &create_aes256_request()).await?;
    let id = unique_id(&create_resp).expect("Create must return a UniqueIdentifier");
    println!("created key id = {id}");

    let get_resp = round_trip(&mut client, &op_with_id(KmipOperation::Get, &id)).await?;
    println!("got key bytes back (response = {} bytes)", get_resp.len());

    let _destroy_resp = round_trip(&mut client, &op_with_id(KmipOperation::Destroy, &id)).await?;
    println!("destroyed key id = {id}");

    // Drop the client to close the connection so the server task exits.
    drop(client);
    let _ = server_task.await;
    Ok(())
}
