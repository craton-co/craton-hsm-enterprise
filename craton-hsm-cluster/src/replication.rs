// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Key replication protocol — event log with checksums and transport trait.

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Replication events
// ---------------------------------------------------------------------------

/// A discrete state-change event that must be replicated to peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationEvent {
    /// A new cryptographic key was created.
    KeyCreated,
    /// An existing key was updated (e.g., attributes changed).
    KeyUpdated,
    /// A key was deleted / destroyed.
    KeyDeleted,
    /// A key was rotated to a new version.
    KeyRotated,
    /// A cluster-level configuration value changed.
    ConfigChanged,
}

impl ReplicationEvent {
    /// Single-byte canonical tag for this event variant — used in checksum
    /// computation so the wire format never depends on serde JSON ordering.
    pub fn tag(&self) -> u8 {
        match self {
            Self::KeyCreated => 0x01,
            Self::KeyUpdated => 0x02,
            Self::KeyDeleted => 0x03,
            Self::KeyRotated => 0x04,
            Self::ConfigChanged => 0x05,
        }
    }
}

// ---------------------------------------------------------------------------
// Replication entry
// ---------------------------------------------------------------------------

/// A single entry in the replication log, carrying a SHA-256 integrity checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Timestamp (epoch milliseconds) when the event was recorded.
    pub timestamp: u64,
    /// The type of replication event.
    pub event: ReplicationEvent,
    /// Opaque payload (serialized key data, config delta, etc.).
    pub payload: Vec<u8>,
    /// SHA-256 (or HMAC-SHA256, when a secret is configured) over `event` + `payload`.
    pub checksum: [u8; 32],
}

impl ReplicationEntry {
    /// Verify the integrity of this entry by recomputing the checksum.
    pub fn verify_checksum(&self) -> bool {
        let computed = compute_checksum(&self.event, &self.payload, None);
        ct_eq(&computed, &self.checksum)
    }

    /// Verify the integrity of this entry using an HMAC secret.
    pub fn verify_checksum_with_secret(&self, secret: &[u8]) -> bool {
        let computed = compute_checksum(&self.event, &self.payload, Some(secret));
        ct_eq(&computed, &self.checksum)
    }
}

/// Constant-time 32-byte equality.
///
/// Uses `subtle::ConstantTimeEq` to keep a single audited comparison
/// implementation across the crate (mirrors `storage::ct_tag_eq` and
/// `raft::RaftNode::verify_hmac`).
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

/// Compute a checksum over the canonical encoding of the event and payload.
///
/// When `secret` is provided, uses HMAC-SHA256 for authenticated integrity.
/// Otherwise falls back to plain SHA-256.  The canonical encoding consists
/// of the 1-byte event tag followed by the payload — independent of any
/// serde representation.
fn compute_checksum(event: &ReplicationEvent, payload: &[u8], secret: Option<&[u8]>) -> [u8; 32] {
    let tag = event.tag();
    match secret {
        Some(key) => {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(&[tag]);
            mac.update(&(payload.len() as u32).to_be_bytes());
            mac.update(payload);
            mac.finalize().into_bytes().into()
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update([tag]);
            hasher.update((payload.len() as u32).to_be_bytes());
            hasher.update(payload);
            hasher.finalize().into()
        }
    }
}

// ---------------------------------------------------------------------------
// Replication log (concurrent)
// ---------------------------------------------------------------------------

/// Default maximum payload size in bytes (1 MiB).
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1_048_576;

/// Default maximum number of log entries retained before evicting the oldest.
pub const DEFAULT_MAX_LOG_ENTRIES: usize = 100_000;

/// Process-global flag so the "no cluster secret" warning fires at most once.
static SECRET_WARNED: OnceLock<()> = OnceLock::new();

/// Thread-safe, append-only replication log backed by a deque.
///
/// Enforces two bounds:
/// - `max_payload_bytes`: individual payloads larger than this limit are rejected.
/// - `max_log_entries`: when the log reaches this size the oldest entry is
///   evicted before the new entry is inserted.
#[derive(Debug)]
pub struct ReplicationLog {
    /// FIFO of entries.  Insertion order matches sequence order, so eviction
    /// is O(1) and `entries_since` is a single binary search + slice copy.
    entries: RwLock<VecDeque<ReplicationEntry>>,
    next_sequence: AtomicU64,
    /// Maximum allowed payload size in bytes.
    pub max_payload_bytes: usize,
    /// Maximum number of entries to retain.
    pub max_log_entries: usize,
    /// Optional shared secret for HMAC-based integrity checksums.  Stored
    /// in a [`Zeroizing`] buffer so the key is wiped from memory on drop.
    cluster_secret: Option<Zeroizing<Vec<u8>>>,
    /// When `true`, [`ReplicationLog::append`] will reject entries if no
    /// cluster secret has been configured, preventing unauthenticated
    /// checksums from ever being persisted.
    pub require_cluster_secret: bool,

    /// When `false` (the default), the replication log refuses to operate
    /// without a cluster secret — matching the fail-closed posture of
    /// [`ClusterConfig`].  Set to `true` only in development / test
    /// environments to fall back to unauthenticated SHA-256 checksums.
    pub allow_insecure: bool,
}

impl Default for ReplicationLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationLog {
    /// Create a new, empty replication log with default limits.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_MAX_LOG_ENTRIES)
    }

    /// Create a new, empty replication log with explicit limits.
    pub fn with_limits(max_payload_bytes: usize, max_log_entries: usize) -> Self {
        assert!(max_log_entries > 0, "max_log_entries must be > 0");
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_log_entries)),
            next_sequence: AtomicU64::new(1),
            max_payload_bytes,
            max_log_entries,
            cluster_secret: None,
            require_cluster_secret: false,
            allow_insecure: false,
        }
    }

    /// Configure the cluster secret used for authenticated checksums.
    pub fn set_cluster_secret(&mut self, secret: Vec<u8>) {
        self.cluster_secret = Some(Zeroizing::new(secret));
    }

    /// Returns `true` if a cluster secret is configured.
    pub fn has_cluster_secret(&self) -> bool {
        self.cluster_secret.is_some()
    }

    /// Returns `true` if HMAC authentication is active (i.e. a cluster
    /// secret has been configured and checksums are authenticated).
    pub fn is_authenticated(&self) -> bool {
        self.cluster_secret.is_some()
    }

    /// Append an event with its payload, computing the checksum
    /// and assigning the next monotonic sequence number.
    pub fn append(
        &self,
        event: ReplicationEvent,
        payload: Vec<u8>,
        timestamp: u64,
    ) -> Result<u64, String> {
        if payload.len() > self.max_payload_bytes {
            return Err(format!(
                "payload size {} exceeds maximum {} bytes",
                payload.len(),
                self.max_payload_bytes
            ));
        }

        if self.cluster_secret.is_none() {
            if self.require_cluster_secret || !self.allow_insecure {
                return Err(
                    "no cluster_secret configured and insecure mode is not allowed — \
                     refusing to create unauthenticated log entries. Set a cluster_secret \
                     for production use or set allow_insecure to true for development."
                        .to_string(),
                );
            }
            if SECRET_WARNED.set(()).is_ok() {
                tracing::warn!(
                    "ReplicationLog: no cluster_secret configured — log entries use unauthenticated \
                     SHA-256 checksums only.  Set cluster_secret to enable HMAC-SHA256 integrity."
                );
            }
        }

        // Hold the write lock for the entire allocate-checksum-insert sequence
        // so the sequence numbers and storage stay in lockstep without a
        // separate append mutex.
        let mut entries = self.entries.write();

        let seq = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        let checksum = compute_checksum(
            &event,
            &payload,
            self.cluster_secret.as_deref().map(|v| v.as_slice()),
        );
        let entry = ReplicationEntry {
            sequence: seq,
            timestamp,
            event,
            payload,
            checksum,
        };

        if entries.len() >= self.max_log_entries {
            entries.pop_front(); // O(1)
        }
        entries.push_back(entry);

        Ok(seq)
    }

    /// Get a clone of the entry with the given sequence number.
    pub fn get(&self, sequence: u64) -> Option<ReplicationEntry> {
        let entries = self.entries.read();
        // Sequence numbers are monotonically inserted; binary search by `sequence`.
        let idx = entries
            .binary_search_by_key(&sequence, |e| e.sequence)
            .ok()?;
        entries.get(idx).cloned()
    }

    /// Return cloned entries with sequence numbers >= `since` (inclusive).
    pub fn entries_since(&self, since: u64) -> Vec<ReplicationEntry> {
        let entries = self.entries.read();
        let start = entries.partition_point(|e| e.sequence < since);
        entries.iter().skip(start).cloned().collect()
    }

    /// Number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// The latest assigned sequence number, or 0 if nothing has been
    /// appended yet.
    pub fn latest_sequence(&self) -> u64 {
        self.next_sequence.load(Ordering::SeqCst).saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// H11 (audit): mTLS-authenticated bidirectional channel between Raft
/// nodes.
///
/// Production deployments wrap their underlying transport (TCP, QUIC,
/// gRPC, in-process pipe) in a `SecureChannel` whose `peer_id` returns
/// the verified mTLS subject of the remote end. The Raft layer then
/// uses `peer_id` to attribute incoming messages and reject ones whose
/// transport-layer identity does not match the application-layer
/// `leader_id` / `candidate_id`.
///
/// **Deployment note**: this trait deliberately does not specify how
/// the channel is established (handshake, certificate provisioning,
/// keepalive). Operators wire it at deploy time using the cluster's
/// existing TLS PKI; see [`MTlsChannel`] for a tokio-rustls skeleton.
///
/// `send` and `recv` return boxed futures rather than `async fn` so that
/// the trait is `dyn`-compatible — `ReplicationTransport` consumers want
/// to swap the channel at runtime without leaking a generic type
/// parameter through the entire `RaftNode` graph.
pub trait SecureChannel: Send + Sync {
    /// Stable identifier of the remote peer, derived from the verified
    /// TLS subject (typically the SAN matching the configured node ID).
    /// Must be safe to log: do not include private-key material or
    /// session-resumption tokens.
    fn peer_id(&self) -> &str;

    /// Send a length-prefixed frame to the peer. Implementations must
    /// reject frames larger than the configured maximum (typically
    /// `crate::raft::MAX_WIRE_FRAME_BYTES`) before any I/O so a
    /// pathological caller cannot blow the kernel buffer.
    fn send<'a>(
        &'a self,
        frame: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), SecureChannelError>> + Send + 'a>,
    >;

    /// Receive a single length-prefixed frame from the peer. Returns
    /// `Ok(None)` on a clean stream close.
    fn recv<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, SecureChannelError>>
                + Send
                + 'a,
        >,
    >;
}

/// Errors returned by a [`SecureChannel`].
#[derive(Debug)]
#[non_exhaustive]
pub enum SecureChannelError {
    /// Underlying I/O failure (socket closed, OS error).
    Io(String),
    /// TLS handshake or session-level failure (cert chain, alert).
    Tls(String),
    /// The peer presented an identity that did not match what was
    /// expected (e.g. the cert SAN does not match the configured
    /// `peer_id`). This is a hard failure — never reconnect through
    /// the same TLS context, since the remote may have been
    /// substituted for a man-in-the-middle.
    PeerIdentityMismatch {
        /// What this side expected.
        expected: String,
        /// What the cert presented.
        actual: String,
    },
    /// Frame exceeded the configured maximum size.
    FrameTooLarge {
        /// Size of the offending frame in bytes.
        size: usize,
        /// Configured maximum in bytes.
        max: usize,
    },
}

impl std::fmt::Display for SecureChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "secure-channel I/O: {m}"),
            Self::Tls(m) => write!(f, "secure-channel TLS: {m}"),
            Self::PeerIdentityMismatch { expected, actual } => write!(
                f,
                "secure-channel peer identity mismatch: expected {expected}, got {actual}"
            ),
            Self::FrameTooLarge { size, max } => {
                write!(f, "secure-channel frame too large: {size} > {max}")
            }
        }
    }
}

impl std::error::Error for SecureChannelError {}

/// H11 (audit) / W1: tokio-rustls-backed [`SecureChannel`] over
/// length-prefixed frames.
///
/// `MTlsChannel` wraps an already-handshaked TLS stream
/// (either `tokio_rustls::server::TlsStream` from `accept` or
/// `tokio_rustls::client::TlsStream` from `connect`) as a boxed
/// `AsyncRead + AsyncWrite` trait object so callers do not have to thread
/// a generic stream-direction type parameter through the Raft graph.
///
/// **Wire format**: `[4-byte BE length][payload]`. Frames whose length
/// header exceeds [`crate::raft::MAX_WIRE_FRAME_BYTES`] are rejected
/// before any allocation, matching the audit-defined cap.
///
/// **Deployment-supplied**: the rustls [`rustls::ClientConfig`] /
/// [`rustls::ServerConfig`] (cert + key paths, trust roots, ALPN string)
/// is the operator's responsibility -- see [`MTlsChannel::connect`] for
/// the client side and [`MTlsTransport::serve`] for the server side.
pub struct MTlsChannel {
    /// Verified peer identity (the cert SAN/CN matched at handshake time).
    peer_id: String,
    /// The TLS stream, wrapped behind a `tokio::sync::Mutex` so that
    /// concurrent `send` / `recv` calls remain serialised at the framing
    /// layer (TLS records are inherently sequential per direction).
    inner: tokio::sync::Mutex<std::pin::Pin<Box<dyn AsyncReadWrite>>>,
}

/// Marker trait combining `AsyncRead + AsyncWrite + Send` so
/// `MTlsChannel` can erase the direction (server vs client) of the
/// underlying TLS stream behind a single `Box<dyn ...>`.
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + ?Sized> AsyncReadWrite for T {}

impl MTlsChannel {
    /// Wrap an already-handshaked TLS stream as an [`MTlsChannel`].
    ///
    /// Used on the server side after `tokio_rustls::TlsAcceptor::accept`
    /// has completed and the caller has extracted the peer identity from
    /// the verified cert chain (see [`peer_san_or_cn`]).
    pub fn from_accepted<S>(stream: S, peer_id: String) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        Self {
            peer_id,
            inner: tokio::sync::Mutex::new(Box::pin(stream)),
        }
    }

    /// Construct a channel from an already-completed handshake without
    /// pinning a real stream. Retained for backward compatibility with
    /// the H11 skeleton; both `send` and `recv` will return cleanly on
    /// the dropped half. Prefer [`MTlsChannel::from_accepted`] or
    /// [`MTlsChannel::connect`] for production use.
    ///
    /// MED (audit): this constructor produces a no-op channel and was
    /// never appropriate for production use. It is being kept around
    /// only so existing test scaffolds compile while they migrate to
    /// `from_accepted`. Marked `#[doc(hidden)]` so it does not appear
    /// in rustdoc, and `#[deprecated]` so any new caller gets a
    /// compiler warning.
    #[doc(hidden)]
    #[deprecated(
        note = "Constructs a no-op channel; use `MTlsChannel::from_accepted` or \
                `MTlsChannel::connect` in production."
    )]
    pub fn from_verified_peer(peer_id: String) -> Self {
        let (a, _b) = tokio::io::duplex(0);
        Self {
            peer_id,
            inner: tokio::sync::Mutex::new(Box::pin(a)),
        }
    }

    /// Establish a new mTLS connection to `addr` using the supplied
    /// rustls [`rustls::ClientConfig`] and pin the verified peer
    /// identity to `peer_id`.
    ///
    /// The caller is responsible for ensuring the `ClientConfig`
    /// already carries the trust roots and client cert + key
    /// (operator-supplied PKI). After a successful handshake the
    /// returned channel can be used for length-prefixed framing.
    pub async fn connect(
        addr: &str,
        server_name: rustls::pki_types::ServerName<'static>,
        config: std::sync::Arc<rustls::ClientConfig>,
        peer_id: String,
    ) -> Result<Self, SecureChannelError> {
        let sock = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| SecureChannelError::Io(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let stream = connector
            .connect(server_name, sock)
            .await
            .map_err(|e| SecureChannelError::Tls(e.to_string()))?;
        Ok(Self::from_accepted(stream, peer_id))
    }
}

impl SecureChannel for MTlsChannel {
    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    fn send<'a>(
        &'a self,
        frame: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), SecureChannelError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let max = crate::raft::MAX_WIRE_FRAME_BYTES;
            if frame.len() > max {
                return Err(SecureChannelError::FrameTooLarge {
                    size: frame.len(),
                    max,
                });
            }
            let len_be = (frame.len() as u32).to_be_bytes();
            let mut guard = self.inner.lock().await;
            use tokio::io::AsyncWriteExt;
            guard
                .as_mut()
                .write_all(&len_be)
                .await
                .map_err(|e| SecureChannelError::Io(e.to_string()))?;
            guard
                .as_mut()
                .write_all(frame)
                .await
                .map_err(|e| SecureChannelError::Io(e.to_string()))?;
            guard
                .as_mut()
                .flush()
                .await
                .map_err(|e| SecureChannelError::Io(e.to_string()))?;
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, SecureChannelError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let max = crate::raft::MAX_WIRE_FRAME_BYTES;
            let mut header = [0u8; 4];
            let mut guard = self.inner.lock().await;
            use tokio::io::AsyncReadExt;
            // Treat `UnexpectedEof` on the header as a clean close.
            match guard.as_mut().read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(SecureChannelError::Io(e.to_string())),
            }
            let len = u32::from_be_bytes(header) as usize;
            if len > max {
                return Err(SecureChannelError::FrameTooLarge { size: len, max });
            }
            let mut payload = vec![0u8; len];
            guard
                .as_mut()
                .read_exact(&mut payload)
                .await
                .map_err(|e| SecureChannelError::Io(e.to_string()))?;
            Ok(Some(payload))
        })
    }
}

/// W1: extract the peer's stable identity from a leaf certificate's
/// DER bytes.
///
/// Walks the leaf cert's `subjectAltName` extension and returns the
/// **first** dnsName entry. If no SAN is present (or contains no
/// dnsNames) falls back to the subject's `commonName`. Returns `None`
/// on any parse failure -- callers must treat this as an
/// authentication failure rather than silently accepting an empty
/// identity.
///
/// **Note**: this function is duplicated verbatim in
/// `craton_hsm_kmip::server::peer_san_or_cn`. Keep them in lockstep --
/// any time one is updated, audit the other.
pub fn peer_san_or_cn(cert_der: &[u8]) -> Option<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    // SAN: first dnsName wins.
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(dns) = gn {
                    return Some((*dns).to_string());
                }
            }
        }
    }
    // Fallback: subject CN.
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            return Some(s.to_string());
        }
    }
    None
}

/// W1: a tokio-rustls-backed [`ReplicationTransport`] front end.
///
/// `MTlsTransport` is a thin orchestrator: it owns a per-peer table of
/// [`MTlsChannel`] handles and a connection-accept loop. Production
/// deployments wire it up at startup with their
/// `Arc<rustls::ServerConfig>` (operator-supplied PKI).
///
/// The frame handler is invoked once per accepted frame with
/// `(peer_identity, frame_bytes)` -- typically the Raft dispatch loop.
pub struct MTlsTransport {
    /// Per-peer `MTlsChannel` handles that have already finished a
    /// handshake. Populated either by [`MTlsTransport::serve`] (server
    /// side) or by an explicit [`MTlsChannel::connect`] (client side).
    channels: dashmap::DashMap<String, std::sync::Arc<MTlsChannel>>,
    /// Frame dispatcher invoked per accepted frame.
    #[allow(clippy::type_complexity)]
    frame_handler: std::sync::Arc<
        dyn Fn(&str, Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync,
    >,
}

impl MTlsTransport {
    /// Build an empty transport with the given frame dispatcher.
    ///
    /// The handler must be `Send + Sync` because it is shared across
    /// every accepted connection task.
    pub fn new<F, Fut>(handler: F) -> Self
    where
        F: Fn(&str, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        Self {
            channels: dashmap::DashMap::new(),
            frame_handler: std::sync::Arc::new(move |id, bytes| Box::pin(handler(id, bytes))),
        }
    }

    /// Register a [`MTlsChannel`] under its `peer_id` so subsequent
    /// outbound frames can be routed through it.
    pub fn register_channel(&self, channel: std::sync::Arc<MTlsChannel>) {
        let id = channel.peer_id().to_string();
        self.channels.insert(id, channel);
    }

    /// Bind a TCP listener on `addr`, wrap each accepted socket in a
    /// `tokio_rustls::TlsAcceptor`, derive the peer identity via
    /// [`peer_san_or_cn`], and dispatch every received frame to the
    /// installed handler.
    ///
    /// Runs until the future is dropped; per-connection failures are
    /// logged via `tracing::warn!` and do not tear down the listener.
    /// If `server_config` is `None`, returns
    /// `io::Error(InvalidInput, "TLS config not provided")` immediately
    /// so misconfiguration cannot silently downgrade to plaintext.
    pub async fn serve(
        self,
        addr: &str,
        server_config: Option<std::sync::Arc<rustls::ServerConfig>>,
    ) -> std::io::Result<()> {
        let server_config = server_config.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "TLS config not provided")
        })?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let handler = self.frame_handler.clone();
        loop {
            let (sock, _peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let stream = match acceptor.accept(sock).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            target: "craton_hsm_cluster::replication",
                            error = %e,
                            "TLS accept failed"
                        );
                        return;
                    }
                };
                let identity: Option<String> = {
                    let (_, conn) = stream.get_ref();
                    conn.peer_certificates()
                        .and_then(|c| c.first().and_then(|leaf| peer_san_or_cn(leaf.as_ref())))
                };
                let identity = match identity {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            target: "craton_hsm_cluster::replication",
                            "rejecting connection: peer cert had no usable SAN/CN"
                        );
                        return;
                    }
                };
                let channel = MTlsChannel::from_accepted(stream, identity.clone());
                loop {
                    match channel.recv().await {
                        Ok(Some(frame)) => {
                            // Item 2 (audit): mTLS peer-id ↔ application-id
                            // cross-check. If the frame is a JSON object
                            // carrying a `leader_id` or `candidate_id`
                            // field, that field MUST match the TLS-verified
                            // `peer_id`. A mismatch is a hard authentication
                            // failure — drop the frame and log.
                            //
                            // MED (audit, perf): the previous version parsed
                            // every frame as a full `serde_json::Value` just
                            // to peek at two string fields, then the dispatch
                            // handler immediately re-parsed it as the typed
                            // RPC struct. We now use a tiny
                            // `#[derive(Deserialize)]` projection that only
                            // looks at `leader_id` / `candidate_id` and
                            // ignores everything else — no intermediate
                            // `Value` tree, but still a single round of
                            // serde_json work before dispatch.
                            #[derive(serde::Deserialize)]
                            struct PeerIdFields<'a> {
                                #[serde(borrow, default)]
                                leader_id: Option<&'a str>,
                                #[serde(borrow, default)]
                                candidate_id: Option<&'a str>,
                            }
                            if let Ok(p) = serde_json::from_slice::<PeerIdFields>(&frame) {
                                let claimed = p.leader_id.or(p.candidate_id);
                                if let Some(c) = claimed {
                                    if c != identity {
                                        tracing::warn!(
                                            target: "craton_hsm_cluster::replication",
                                            tls_peer = %identity,
                                            claimed = %c,
                                            "rejecting frame: app-layer id does not match TLS peer"
                                        );
                                        continue;
                                    }
                                }
                            }
                            handler(&identity, frame).await;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::debug!(
                                target: "craton_hsm_cluster::replication",
                                peer = %identity,
                                error = %e,
                                "secure channel ended"
                            );
                            break;
                        }
                    }
                }
            });
        }
    }
}

/// Async transport layer for shipping replication entries between nodes.
///
/// H11 (audit): the trait additively exposes [`Self::secure_channel_for`]
/// which lets a transport hand back the [`SecureChannel`] for a given
/// peer if it is using mTLS. Implementations that do not (e.g.
/// [`InMemoryTransport`]) return `None` and the Raft layer treats the
/// peer as authenticated by HMAC alone.
#[allow(async_fn_in_trait)]
pub trait ReplicationTransport {
    /// Error type for transport operations.
    type Error: std::fmt::Debug;

    /// Send a batch of replication entries to a peer.
    async fn send_entries(
        &self,
        peer_addr: &str,
        entries: &[ReplicationEntry],
    ) -> Result<(), Self::Error>;

    /// Request a full state snapshot from a peer.
    async fn request_snapshot(&self, peer_addr: &str)
        -> Result<Vec<ReplicationEntry>, Self::Error>;

    /// Acknowledge receipt of entries up to the given sequence number.
    async fn acknowledge(&self, peer_addr: &str, up_to_sequence: u64) -> Result<(), Self::Error>;

    /// H11: optionally return the [`SecureChannel`] this transport uses
    /// for the given peer. Default returns `None` so transports that
    /// do not yet implement mTLS continue to work — the Raft layer
    /// treats the peer as authenticated by HMAC alone in that case.
    /// Production transports SHOULD override and return their
    /// [`MTlsChannel`] handle so the Raft layer can cross-check the
    /// transport-layer peer identity against the application-layer
    /// `leader_id` / `candidate_id`.
    fn secure_channel_for(&self, _peer_addr: &str) -> Option<&dyn SecureChannel> {
        None
    }
}

// ---------------------------------------------------------------------------
// In-memory transport (for testing)
// ---------------------------------------------------------------------------

/// An in-memory implementation of [`ReplicationTransport`] for use in tests.
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    /// Batches sent to each peer.
    pub sent_batches: DashMap<String, Vec<Vec<ReplicationEntry>>>,
    /// Snapshots returned to each requester.
    pub snapshots: DashMap<String, Vec<ReplicationEntry>>,
    /// Acknowledgements received.
    pub acks: DashMap<String, u64>,
}

impl InMemoryTransport {
    /// Create a new empty in-memory transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate a snapshot for the given peer.
    pub fn set_snapshot(&self, peer_addr: &str, entries: Vec<ReplicationEntry>) {
        self.snapshots.insert(peer_addr.to_string(), entries);
    }
}

impl ReplicationTransport for InMemoryTransport {
    type Error = String;

    async fn send_entries(
        &self,
        peer_addr: &str,
        entries: &[ReplicationEntry],
    ) -> Result<(), Self::Error> {
        self.sent_batches
            .entry(peer_addr.to_string())
            .or_default()
            .push(entries.to_vec());
        Ok(())
    }

    async fn request_snapshot(
        &self,
        peer_addr: &str,
    ) -> Result<Vec<ReplicationEntry>, Self::Error> {
        Ok(self
            .snapshots
            .get(peer_addr)
            .map(|s| s.value().clone())
            .unwrap_or_default())
    }

    async fn acknowledge(&self, peer_addr: &str, up_to_sequence: u64) -> Result<(), Self::Error> {
        self.acks.insert(peer_addr.to_string(), up_to_sequence);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a replication log that permits insecure (no-secret) operation for tests.
    fn insecure_log() -> ReplicationLog {
        let mut log = ReplicationLog::new();
        log.allow_insecure = true;
        log
    }

    /// Helper: create a replication log with explicit limits that permits insecure operation.
    fn insecure_log_with_limits(max_payload: usize, max_entries: usize) -> ReplicationLog {
        let mut log = ReplicationLog::with_limits(max_payload, max_entries);
        log.allow_insecure = true;
        log
    }

    #[test]
    fn test_append_and_get() {
        let log = insecure_log();
        let seq = log
            .append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 1000)
            .unwrap();
        assert_eq!(seq, 1);
        let entry = log.get(seq).unwrap();
        assert_eq!(entry.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_get_missing() {
        let log = insecure_log();
        assert!(log.get(42).is_none());
    }

    #[test]
    fn test_sequence_monotonicity() {
        let log = insecure_log();
        let s1 = log
            .append(ReplicationEvent::KeyCreated, vec![], 100)
            .unwrap();
        let s2 = log
            .append(ReplicationEvent::KeyUpdated, vec![], 200)
            .unwrap();
        let s3 = log
            .append(ReplicationEvent::KeyDeleted, vec![], 300)
            .unwrap();
        assert_eq!((s1, s2, s3), (1, 2, 3));
    }

    #[test]
    fn test_checksum_verification() {
        let log = insecure_log();
        let seq = log
            .append(ReplicationEvent::KeyRotated, vec![0xCA, 0xFE], 5000)
            .unwrap();
        let entry = log.get(seq).unwrap();
        assert!(entry.verify_checksum());
    }

    #[test]
    fn test_checksum_detects_tampering() {
        let log = insecure_log();
        let seq = log
            .append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 1000)
            .unwrap();
        let mut entry = log.get(seq).unwrap();
        entry.payload = vec![9, 9, 9];
        assert!(!entry.verify_checksum());
    }

    #[test]
    fn test_hmac_checksum_with_secret() {
        let mut log = insecure_log();
        log.set_cluster_secret(b"super-secret-key".to_vec());
        let seq = log
            .append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 1000)
            .unwrap();
        let entry = log.get(seq).unwrap();
        // Plain SHA-256 verification must fail because we used HMAC.
        assert!(!entry.verify_checksum());
        assert!(entry.verify_checksum_with_secret(b"super-secret-key"));
        assert!(!entry.verify_checksum_with_secret(b"wrong-key"));
    }

    #[test]
    fn test_canonical_event_tags_distinct() {
        let tags: Vec<u8> = [
            ReplicationEvent::KeyCreated,
            ReplicationEvent::KeyUpdated,
            ReplicationEvent::KeyDeleted,
            ReplicationEvent::KeyRotated,
            ReplicationEvent::ConfigChanged,
        ]
        .iter()
        .map(|e| e.tag())
        .collect();
        let mut sorted = tags.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len());
    }

    #[test]
    fn test_entries_since() {
        let log = insecure_log();
        log.append(ReplicationEvent::KeyCreated, vec![], 100)
            .unwrap();
        log.append(ReplicationEvent::KeyUpdated, vec![], 200)
            .unwrap();
        log.append(ReplicationEvent::KeyDeleted, vec![], 300)
            .unwrap();
        log.append(ReplicationEvent::ConfigChanged, vec![], 400)
            .unwrap();
        let entries = log.entries_since(3);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 3);
    }

    #[test]
    fn test_payload_limit_refused() {
        let log = insecure_log_with_limits(4, DEFAULT_MAX_LOG_ENTRIES);
        assert!(log
            .append(ReplicationEvent::KeyCreated, vec![1, 2, 3, 4, 5], 1000)
            .is_err());
        assert!(log.is_empty());
    }

    #[test]
    fn test_payload_limit_does_not_increment_sequence() {
        let log = insecure_log_with_limits(2, DEFAULT_MAX_LOG_ENTRIES);
        let _ = log.append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 100);
        let accepted = log
            .append(ReplicationEvent::KeyCreated, vec![1], 200)
            .unwrap();
        assert_eq!(accepted, 1);
    }

    #[test]
    fn test_log_entry_limit_evicts_oldest() {
        let log = insecure_log_with_limits(DEFAULT_MAX_PAYLOAD_BYTES, 3);
        let s1 = log
            .append(ReplicationEvent::KeyCreated, vec![], 100)
            .unwrap();
        let s2 = log
            .append(ReplicationEvent::KeyUpdated, vec![], 200)
            .unwrap();
        let s3 = log
            .append(ReplicationEvent::KeyDeleted, vec![], 300)
            .unwrap();
        let s4 = log
            .append(ReplicationEvent::KeyRotated, vec![], 400)
            .unwrap();
        assert_eq!(log.len(), 3);
        assert!(log.get(s1).is_none());
        assert!(log.get(s2).is_some());
        assert!(log.get(s3).is_some());
        assert!(log.get(s4).is_some());
    }

    #[test]
    fn test_concurrent_append_respects_bounds() {
        use std::sync::Arc;
        use std::thread;
        let log = Arc::new(insecure_log_with_limits(DEFAULT_MAX_PAYLOAD_BYTES, 50));
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let log = Arc::clone(&log);
                thread::spawn(move || {
                    for j in 0..20u64 {
                        let _ = log.append(
                            ReplicationEvent::KeyCreated,
                            format!("t-{i}-{j}").into_bytes(),
                            1000 + j,
                        );
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(log.len() <= 50);
    }

    #[tokio::test]
    async fn in_memory_transport_roundtrip() {
        let t = InMemoryTransport::new();
        let entry = ReplicationEntry {
            sequence: 1,
            timestamp: 0,
            event: ReplicationEvent::KeyCreated,
            payload: vec![],
            checksum: [0u8; 32],
        };
        t.send_entries("p1", std::slice::from_ref(&entry))
            .await
            .unwrap();
        t.acknowledge("p1", 1).await.unwrap();
        t.set_snapshot("p1", vec![entry.clone()]);
        let snap = t.request_snapshot("p1").await.unwrap();
        assert_eq!(snap.len(), 1);
        assert_eq!(*t.acks.get("p1").unwrap(), 1);
        assert_eq!(t.sent_batches.get("p1").unwrap().len(), 1);
    }

    // -- allow_insecure / fail-closed tests --

    #[test]
    fn test_default_log_rejects_append_without_secret() {
        let log = ReplicationLog::new(); // allow_insecure defaults to false
        let result = log.append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 1000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("insecure mode is not allowed"));
    }

    #[test]
    fn test_allow_insecure_permits_append_without_secret() {
        let mut log = ReplicationLog::new();
        log.allow_insecure = true;
        let result = log.append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_log_with_secret_succeeds_regardless_of_allow_insecure() {
        let mut log = ReplicationLog::new();
        // allow_insecure is false, but a secret is configured — should succeed
        log.set_cluster_secret(b"super-secret-key-for-testing!!!!".to_vec());
        let result = log.append(ReplicationEvent::KeyCreated, vec![1, 2, 3], 1000);
        assert!(result.is_ok());
    }
}
