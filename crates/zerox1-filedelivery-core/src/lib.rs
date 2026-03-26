//! `zerox1-filedelivery-core` — adapter trait for out-of-band file delivery.
//!
//! When a DELIVER payload is too large to embed in a protocol envelope,
//! the provider uploads to a storage backend and includes a [`DeliveryRef`]
//! in the envelope instead. The requester resolves the ref to fetch the data.
//!
//! # Adding a new adapter
//!
//! Implement [`FileDelivery`] and add a crate under the workspace:
//!
//! ```text
//! filedelivery/
//!   core/   ← this crate (trait + types)
//!   0g/     ← 0G Storage adapter
//!   walrus/ ← Walrus (Sui) adapter (future)
//! ```

use async_trait::async_trait;

/// A content reference returned by [`FileDelivery::upload`].
///
/// The URI scheme identifies which adapter produced it:
/// - `zerog://`  — 0G Storage (Merkle root hash)
/// - `walrus://` — Walrus (blob ID)
///
/// This ref is included in the DELIVER envelope's `payload_uri` field.
/// The receiving node passes it to the matching adapter to fetch the bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveryRef {
    /// Fully-qualified URI, e.g. `zerog://0x<merkle_root>`.
    pub uri: String,
    /// Uncompressed byte length of the content.
    pub size_bytes: u64,
    /// Optional content-type hint (e.g. `application/octet-stream`, `text/plain`).
    pub content_type: Option<String>,
}

/// Adapter trait for storing and retrieving large delivery payloads.
#[async_trait]
pub trait FileDelivery: Send + Sync {
    /// Upload `data` to the storage backend.
    ///
    /// Returns a [`DeliveryRef`] that can be serialised into the DELIVER envelope.
    async fn upload(&self, data: Vec<u8>, content_type: Option<&str>) -> anyhow::Result<DeliveryRef>;

    /// Fetch the content identified by `uri`.
    ///
    /// `uri` will always be a URI produced by this adapter's `upload`.
    async fn download(&self, uri: &str) -> anyhow::Result<Vec<u8>>;

    /// Check whether the adapter can handle the given URI scheme.
    ///
    /// Used by the node to route a `DeliveryRef` to the correct adapter.
    fn handles(&self, uri: &str) -> bool;
}

/// Maximum payload size that may be embedded directly in a DELIVER envelope.
///
/// The protocol transport ceiling is 64 KB (`MAX_MESSAGE_SIZE`). Subtracting
/// envelope header + Ed25519 signature + CBOR framing overhead leaves ~48 KB
/// for the payload. Payloads larger than this must be uploaded via a
/// [`FileDelivery`] adapter and referenced by URI.
pub const INLINE_PAYLOAD_LIMIT: usize = 48 * 1024;
