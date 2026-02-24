use ciborium::value::Value;
use crate::error::ProtocolError;

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
    pub const BID_TYPE_OFFER: u8   = 0x01;

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
        Ok(Self { bid_type, conversation_id, opaque })
    }
}

// ============================================================================
// FEEDBACK payload (doc 5, §7.2)
// ============================================================================

/// Protocol-defined payload for FEEDBACK (0x0B) messages.
///
/// This payload is parsed by all nodes to update reputation state.
/// It must also be submitted as a SATI FeedbackV1 attestation (blind model).
#[derive(Debug, Clone)]
pub struct FeedbackPayload {
    /// Which task (= SATI task_ref, same as conversation_id used throughout).
    pub conversation_id: [u8; 16],
    /// Agent being rated (= SATI agent mint address, 32 bytes).
    pub target_agent: [u8; 32],
    /// Score: -100 to +100.
    pub score: i8,
    /// Outcome compatible with SATI FeedbackV1:
    /// 0 = Negative, 1 = Neutral, 2 = Positive.
    pub outcome: u8,
    /// True if this feedback flags a contested outcome.
    pub is_dispute: bool,
    /// Role of the rated agent: 0 = participant, 1 = notary.
    pub role: u8,
}

impl FeedbackPayload {
    pub const OUTCOME_NEGATIVE: u8 = 0;
    pub const OUTCOME_NEUTRAL:  u8 = 1;
    pub const OUTCOME_POSITIVE: u8 = 2;

    pub const ROLE_PARTICIPANT: u8 = 0;
    pub const ROLE_NOTARY:      u8 = 1;

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
        let value: Value = ciborium::from_reader(bytes).map_err(|e| {
            ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: e.to_string(),
            }
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
        let target_agent    = bytes32_from_value(&arr[1], 0x0B)?;
        let score           = i8_from_value(&arr[2], 0x0B)?;
        let outcome         = u8_from_value(&arr[3], 0x0B)?;
        let is_dispute      = bool_from_value(&arr[4], 0x0B)?;
        let role            = u8_from_value(&arr[5], 0x0B)?;

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

        Ok(Self { conversation_id, target_agent, score, outcome, is_dispute, role })
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
        _ => Err(ProtocolError::PayloadParseError { msg_type, reason: "expected integer".into() }),
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
        _ => Err(ProtocolError::PayloadParseError { msg_type, reason: "expected integer".into() }),
    }
}

fn bool_from_value(v: &Value, msg_type: u16) -> Result<bool, ProtocolError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(ProtocolError::PayloadParseError { msg_type, reason: "expected bool".into() }),
    }
}

fn bytes_from_value(v: &Value, msg_type: u16) -> Result<Vec<u8>, ProtocolError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ProtocolError::PayloadParseError { msg_type, reason: "expected bytes".into() }),
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
}
