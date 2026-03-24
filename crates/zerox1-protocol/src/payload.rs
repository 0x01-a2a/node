use crate::error::ProtocolError;
use ciborium::value::Value;

// ============================================================================
// NOTARIZE_BID payload (doc 5, §5.4)
// ============================================================================

/// Protocol-defined payload for NOTARIZE_BID (0x08) messages.
///
/// The protocol reads only `bid_type` and `conversation_id`.
/// All remaining bytes are agent-defined and opaque.
#[derive(Debug, Clone)]
pub struct NotarizeBidPayload {
    /// 0x00 = participant requesting notarization
    /// 0x01 = notary offering to notarize
    pub bid_type: u8,
    /// Task being offered for notarization.
    pub conversation_id: [u8; 16],
    /// Agent-defined remainder (fee, deadline, terms — opaque to protocol).
    pub opaque: Vec<u8>,
}

impl NotarizeBidPayload {
    pub const BID_TYPE_REQUEST: u8 = 0x00;
    pub const BID_TYPE_OFFER: u8 = 0x01;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 16 + self.opaque.len());
        buf.push(self.bid_type);
        buf.extend_from_slice(&self.conversation_id);
        buf.extend_from_slice(&self.opaque);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 17 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x08,
                reason: format!("too short: {} bytes (min 17)", bytes.len()),
            });
        }
        let bid_type = bytes[0];
        if bid_type > 0x01 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x08,
                reason: format!("unknown bid_type: {bid_type:#04x}"),
            });
        }
        let conversation_id: [u8; 16] = bytes[1..17].try_into().unwrap();
        let opaque = bytes[17..].to_vec();
        Ok(Self {
            bid_type,
            conversation_id,
            opaque,
        })
    }
}

// ============================================================================
// FEEDBACK payload (doc 5, §7.2)
// ============================================================================

/// Protocol-defined payload for FEEDBACK (0x0B) messages.
///
/// This payload is parsed by all nodes to update reputation state.
/// This payload is recorded by the aggregator for reputation scoring.
#[derive(Debug, Clone)]
pub struct FeedbackPayload {
    /// Which task (= conversation_id used throughout).
    pub conversation_id: [u8; 16],
    /// Agent being rated (32-byte Ed25519 agent_id).
    pub target_agent: [u8; 32],
    /// Score: -100 to +100.
    pub score: i8,
    /// Outcome: 0 = Negative, 1 = Neutral, 2 = Positive.
    pub outcome: u8,
    /// True if this feedback flags a contested outcome.
    pub is_dispute: bool,
    /// Role of the rated agent: 0 = participant, 1 = notary.
    pub role: u8,
}

impl FeedbackPayload {
    pub const OUTCOME_NEGATIVE: u8 = 0;
    pub const OUTCOME_NEUTRAL: u8 = 1;
    pub const OUTCOME_POSITIVE: u8 = 2;

    pub const ROLE_PARTICIPANT: u8 = 0;
    pub const ROLE_NOTARY: u8 = 1;

    pub fn encode(&self) -> Vec<u8> {
        // CBOR array encoding for canonical serialization.
        let value = Value::Array(vec![
            Value::Bytes(self.conversation_id.to_vec()),
            Value::Bytes(self.target_agent.to_vec()),
            Value::Integer((self.score as i64).into()),
            Value::Integer(self.outcome.into()),
            Value::Bool(self.is_dispute),
            Value::Integer(self.role.into()),
        ]);
        let mut buf = Vec::new();
        // Writing to Vec<u8> is infallible; ciborium encoding of integer/bytes/bool is infallible.
        ciborium::into_writer(&value, &mut buf)
            .unwrap_or_else(|_| unreachable!("CBOR encode to Vec<u8> is infallible"));
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: e.to_string(),
            })?;

        let arr = match value {
            Value::Array(a) if a.len() == 6 => a,
            Value::Array(a) => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x0B,
                    reason: format!("expected 6 fields, got {}", a.len()),
                })
            }
            _ => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x0B,
                    reason: "expected CBOR array".into(),
                })
            }
        };

        let conversation_id = bytes16_from_value(&arr[0], 0x0B)?;
        let target_agent = bytes32_from_value(&arr[1], 0x0B)?;
        let score = i8_from_value(&arr[2], 0x0B)?;
        let outcome = u8_from_value(&arr[3], 0x0B)?;
        let is_dispute = bool_from_value(&arr[4], 0x0B)?;
        let role = u8_from_value(&arr[5], 0x0B)?;

        if outcome > 2 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: format!("invalid outcome value: {outcome}"),
            });
        }
        if role > 1 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: format!("invalid role value: {role}"),
            });
        }
        if !(-100..=100).contains(&score) {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: format!("score out of range: {score}"),
            });
        }

        Ok(Self {
            conversation_id,
            target_agent,
            score,
            outcome,
            is_dispute,
            role,
        })
    }
}

// ============================================================================
// BROADCAST payload (doc 5, §5.5 — named-topic pubsub, v0.4.5)
// ============================================================================

/// Protocol-defined payload for BROADCAST (0x0E) messages.
///
/// Published to the named gossipsub topic `/0x01/v1/t/{topic}`.
/// `content` is optional — senders may omit it for metadata-only frames.
#[derive(Debug, Clone)]
pub struct BroadcastPayload {
    /// User-defined topic name (e.g. "radio:defi-daily", "data:sol-price").
    pub topic: String,
    /// Human-readable title for the content.
    pub title: String,
    /// Searchable tags.
    pub tags: Vec<String>,
    /// Content format: "audio" | "text" | "data".
    pub format: String,
    /// Raw content bytes (optional — omit for metadata-only frames).
    pub content: Option<Vec<u8>>,
    /// MIME type of `content` (e.g. "audio/mpeg", "application/json").
    pub content_type: Option<String>,
    /// Zero-based index of this chunk within the stream.
    pub chunk_index: Option<u32>,
    /// Total number of chunks (if known at publish time).
    pub total_chunks: Option<u32>,
    /// Duration of audio/video content in milliseconds.
    pub duration_ms: Option<u32>,
    /// Subscription price in micro-USDC per epoch (0 = free).
    pub price_per_epoch_micro: Option<u64>,
    /// Epoch counter for the stream (increments per publish cycle).
    pub epoch: Option<u64>,
}

impl BroadcastPayload {
    pub fn encode(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Text(self.topic.clone()),
            Value::Text(self.title.clone()),
            Value::Array(self.tags.iter().map(|t| Value::Text(t.clone())).collect()),
            Value::Text(self.format.clone()),
            match &self.content {
                Some(b) => Value::Bytes(b.clone()),
                None => Value::Null,
            },
            match &self.content_type {
                Some(s) => Value::Text(s.clone()),
                None => Value::Null,
            },
            match self.chunk_index {
                Some(n) => Value::Integer((n as i64).into()),
                None => Value::Null,
            },
            match self.total_chunks {
                Some(n) => Value::Integer((n as i64).into()),
                None => Value::Null,
            },
            match self.duration_ms {
                Some(n) => Value::Integer((n as i64).into()),
                None => Value::Null,
            },
            match self.price_per_epoch_micro {
                Some(n) => Value::Integer(n.into()),
                None => Value::Null,
            },
            match self.epoch {
                Some(n) => Value::Integer(n.into()),
                None => Value::Null,
            },
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .unwrap_or_else(|_| unreachable!("CBOR encode to Vec<u8> is infallible"));
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| ProtocolError::PayloadParseError {
                msg_type: 0x0E,
                reason: e.to_string(),
            })?;

        let arr = match value {
            Value::Array(a) if a.len() == 11 => a,
            Value::Array(a) => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x0E,
                    reason: format!("expected 11 fields, got {}", a.len()),
                })
            }
            _ => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x0E,
                    reason: "expected CBOR array".into(),
                })
            }
        };

        let topic = text_from_value(&arr[0], 0x0E)?;
        let title = text_from_value(&arr[1], 0x0E)?;
        let tags = text_array_from_value(&arr[2], 0x0E)?;
        let format = text_from_value(&arr[3], 0x0E)?;

        // Enforce field length limits to prevent memory exhaustion.
        if topic.len() > 128 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0E,
                reason: format!("topic too long: {} bytes (max 128)", topic.len()),
            });
        }
        if title.len() > 256 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0E,
                reason: format!("title too long: {} bytes (max 256)", title.len()),
            });
        }
        if tags.len() > 32 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0E,
                reason: format!("too many tags: {} (max 32)", tags.len()),
            });
        }
        let content = optional_bytes_from_value(&arr[4], 0x0E)?;
        let content_type = optional_text_from_value(&arr[5], 0x0E)?;
        let chunk_index = optional_u32_from_value(&arr[6], 0x0E)?;
        let total_chunks = optional_u32_from_value(&arr[7], 0x0E)?;
        let duration_ms = optional_u32_from_value(&arr[8], 0x0E)?;
        let price_per_epoch_micro = optional_u64_from_value(&arr[9], 0x0E)?;
        let epoch = optional_u64_from_value(&arr[10], 0x0E)?;

        Ok(Self {
            topic,
            title,
            tags,
            format,
            content,
            content_type,
            chunk_index,
            total_chunks,
            duration_ms,
            price_per_epoch_micro,
            epoch,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn u8_from_value(v: &Value, msg_type: u16) -> Result<u8, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into().map_err(|_| ProtocolError::PayloadParseError {
                msg_type,
                reason: "u8 overflow".into(),
            })
        }
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected integer".into(),
        }),
    }
}

fn i8_from_value(v: &Value, msg_type: u16) -> Result<i8, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into().map_err(|_| ProtocolError::PayloadParseError {
                msg_type,
                reason: "i8 overflow".into(),
            })
        }
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected integer".into(),
        }),
    }
}

fn bool_from_value(v: &Value, msg_type: u16) -> Result<bool, ProtocolError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected bool".into(),
        }),
    }
}

fn bytes_from_value(v: &Value, msg_type: u16) -> Result<Vec<u8>, ProtocolError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected bytes".into(),
        }),
    }
}

fn bytes16_from_value(v: &Value, msg_type: u16) -> Result<[u8; 16], ProtocolError> {
    let b = bytes_from_value(v, msg_type)?;
    b.try_into().map_err(|_| ProtocolError::PayloadParseError {
        msg_type,
        reason: "expected 16-byte field".into(),
    })
}

fn bytes32_from_value(v: &Value, msg_type: u16) -> Result<[u8; 32], ProtocolError> {
    let b = bytes_from_value(v, msg_type)?;
    b.try_into().map_err(|_| ProtocolError::PayloadParseError {
        msg_type,
        reason: "expected 32-byte field".into(),
    })
}

fn text_from_value(v: &Value, msg_type: u16) -> Result<String, ProtocolError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected text".into(),
        }),
    }
}

fn text_array_from_value(v: &Value, msg_type: u16) -> Result<Vec<String>, ProtocolError> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .map(|item| text_from_value(item, msg_type))
            .collect(),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected array of text".into(),
        }),
    }
}

fn optional_bytes_from_value(v: &Value, msg_type: u16) -> Result<Option<Vec<u8>>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        Value::Bytes(b) => Ok(Some(b.clone())),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected bytes or null".into(),
        }),
    }
}

fn optional_text_from_value(v: &Value, msg_type: u16) -> Result<Option<String>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s.clone())),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected text or null".into(),
        }),
    }
}

fn optional_u32_from_value(v: &Value, msg_type: u16) -> Result<Option<u32>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            let val = n.try_into().map_err(|_| ProtocolError::PayloadParseError {
                msg_type,
                reason: "u32 overflow".into(),
            })?;
            Ok(Some(val))
        }
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected integer or null".into(),
        }),
    }
}

fn optional_u64_from_value(v: &Value, msg_type: u16) -> Result<Option<u64>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            let val = n.try_into().map_err(|_| ProtocolError::PayloadParseError {
                msg_type,
                reason: "u64 overflow".into(),
            })?;
            Ok(Some(val))
        }
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected integer or null".into(),
        }),
    }
}

// ============================================================================
// DELIVER payload (0x07)
// ============================================================================

/// Protocol-defined payload for DELIVER (0x07) messages.
///
/// Small payloads embed content inline. Large payloads reference an external
/// storage URI (e.g. `zerog://0x<merkle_root>`) so the envelope stays within
/// the 64 KB transport limit. A node with a configured file-delivery adapter
/// will upload automatically on send and can resolve the URI on receive.
#[derive(Debug, Clone)]
pub struct DeliverPayload {
    /// Task this delivery belongs to.
    pub conversation_id: [u8; 16],
    /// MIME type of the content (e.g. `text/plain`, `application/json`).
    pub content_type: Option<String>,
    /// Inline bytes — present when the payload fits within the envelope limit.
    pub inline: Option<Vec<u8>>,
    /// External storage URI — present when content was offloaded to a storage backend.
    pub payload_uri: Option<String>,
    /// Byte length of the external content (informational; aids pre-allocation).
    pub payload_size: Option<u64>,
}

impl DeliverPayload {
    pub fn encode(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Bytes(self.conversation_id.to_vec()),
            match &self.content_type {
                Some(s) => Value::Text(s.clone()),
                None => Value::Null,
            },
            match &self.inline {
                Some(b) => Value::Bytes(b.clone()),
                None => Value::Null,
            },
            match &self.payload_uri {
                Some(s) => Value::Text(s.clone()),
                None => Value::Null,
            },
            match self.payload_size {
                Some(n) => Value::Integer(n.into()),
                None => Value::Null,
            },
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .unwrap_or_else(|_| unreachable!("CBOR encode to Vec<u8> is infallible"));
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| ProtocolError::PayloadParseError {
                msg_type: 0x07,
                reason: e.to_string(),
            })?;

        let arr = match value {
            Value::Array(a) if a.len() == 5 => a,
            Value::Array(a) => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x07,
                    reason: format!("expected 5 fields, got {}", a.len()),
                })
            }
            _ => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x07,
                    reason: "expected CBOR array".into(),
                })
            }
        };

        let conversation_id = bytes16_from_value(&arr[0], 0x07)?;
        let content_type = optional_text_from_value(&arr[1], 0x07)?;
        let inline = optional_bytes_from_value(&arr[2], 0x07)?;
        let payload_uri = optional_text_from_value(&arr[3], 0x07)?;
        let payload_size = optional_u64_from_value(&arr[4], 0x07)?;

        if inline.is_none() && payload_uri.is_none() {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x07,
                reason: "DeliverPayload must have either inline or payload_uri".into(),
            });
        }

        Ok(Self {
            conversation_id,
            content_type,
            inline,
            payload_uri,
            payload_size,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_payload_round_trip() {
        let p = FeedbackPayload {
            conversation_id: [1u8; 16],
            target_agent: [2u8; 32],
            score: -42,
            outcome: FeedbackPayload::OUTCOME_NEGATIVE,
            is_dispute: true,
            role: FeedbackPayload::ROLE_PARTICIPANT,
        };
        let encoded = p.encode();
        let decoded = FeedbackPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.conversation_id, p.conversation_id);
        assert_eq!(decoded.target_agent, p.target_agent);
        assert_eq!(decoded.score, p.score);
        assert_eq!(decoded.outcome, p.outcome);
        assert_eq!(decoded.is_dispute, p.is_dispute);
        assert_eq!(decoded.role, p.role);
    }

    #[test]
    fn feedback_payload_rejects_invalid_score() {
        let p = FeedbackPayload {
            conversation_id: [0u8; 16],
            target_agent: [0u8; 32],
            score: 100, // valid boundary
            outcome: 2,
            is_dispute: false,
            role: 1,
        };
        let encoded = p.encode();
        assert!(FeedbackPayload::decode(&encoded).is_ok());

        // Manually craft a payload with score = 101 (out of range)
        let bad = FeedbackPayload {
            score: 101_u8 as i8, // wraps; testing range check
            ..p
        };
        // score=101 is out of i8::MAX=127 but > 100 check:
        // Actually 101i8 is valid i8 but out of protocol range.
        let encoded_bad = bad.encode();
        assert!(FeedbackPayload::decode(&encoded_bad).is_err());
    }

    #[test]
    fn notarize_bid_round_trip() {
        let p = NotarizeBidPayload {
            bid_type: NotarizeBidPayload::BID_TYPE_OFFER,
            conversation_id: [7u8; 16],
            opaque: b"fee:5000000,deadline:100".to_vec(),
        };
        let encoded = p.encode();
        let decoded = NotarizeBidPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.bid_type, p.bid_type);
        assert_eq!(decoded.conversation_id, p.conversation_id);
        assert_eq!(decoded.opaque, p.opaque);
    }

    #[test]
    fn notarize_bid_too_short() {
        assert!(NotarizeBidPayload::decode(&[0x00u8; 16]).is_err());
    }

    #[test]
    fn broadcast_payload_round_trip() {
        let p = BroadcastPayload {
            topic: "radio:defi-daily".into(),
            title: "Solana DeFi Digest — Ep 42".into(),
            tags: vec!["defi".into(), "solana".into(), "en".into()],
            format: "audio".into(),
            content: Some(b"mp3-bytes-here".to_vec()),
            content_type: Some("audio/mpeg".into()),
            chunk_index: Some(0),
            total_chunks: Some(10),
            duration_ms: Some(5000),
            price_per_epoch_micro: Some(10_000),
            epoch: Some(1),
        };
        let encoded = p.encode();
        let decoded = BroadcastPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.topic, p.topic);
        assert_eq!(decoded.title, p.title);
        assert_eq!(decoded.tags, p.tags);
        assert_eq!(decoded.format, p.format);
        assert_eq!(decoded.content, p.content);
        assert_eq!(decoded.content_type, p.content_type);
        assert_eq!(decoded.chunk_index, p.chunk_index);
        assert_eq!(decoded.total_chunks, p.total_chunks);
        assert_eq!(decoded.duration_ms, p.duration_ms);
        assert_eq!(decoded.price_per_epoch_micro, p.price_per_epoch_micro);
        assert_eq!(decoded.epoch, p.epoch);
    }

    #[test]
    fn broadcast_payload_rejects_oversized_fields() {
        // topic > 128 chars should fail
        let p = BroadcastPayload {
            topic: "a".repeat(129),
            title: "t".into(),
            tags: vec![],
            format: "data".into(),
            content: None,
            content_type: None,
            chunk_index: None,
            total_chunks: None,
            duration_ms: None,
            price_per_epoch_micro: None,
            epoch: None,
        };
        let encoded = p.encode();
        assert!(BroadcastPayload::decode(&encoded).is_err());

        // tags > 32 items should fail
        let p2 = BroadcastPayload {
            topic: "ok".into(),
            title: "t".into(),
            tags: (0..33).map(|i| format!("tag{i}")).collect(),
            format: "data".into(),
            content: None,
            content_type: None,
            chunk_index: None,
            total_chunks: None,
            duration_ms: None,
            price_per_epoch_micro: None,
            epoch: None,
        };
        let encoded2 = p2.encode();
        assert!(BroadcastPayload::decode(&encoded2).is_err());
    }

    #[test]
    fn broadcast_payload_nullable_fields() {
        let p = BroadcastPayload {
            topic: "data:sol-price".into(),
            title: "SOL/USD".into(),
            tags: vec![],
            format: "data".into(),
            content: None,
            content_type: None,
            chunk_index: None,
            total_chunks: None,
            duration_ms: None,
            price_per_epoch_micro: None,
            epoch: None,
        };
        let encoded = p.encode();
        let decoded = BroadcastPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.topic, p.topic);
        assert!(decoded.content.is_none());
        assert!(decoded.epoch.is_none());
    }
}
