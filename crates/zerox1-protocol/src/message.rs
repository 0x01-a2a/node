use crate::error::ProtocolError;

/// All 0x01 message types (doc 5, §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MsgType {
    /// Broadcast: "I exist, here's what I offer"
    Advertise = 0x01,
    /// Broadcast: "Who can do X?"
    Discover = 0x02,
    /// Bilateral: "Here's a deal"
    Propose = 0x03,
    /// Bilateral: "Here's a modified deal"
    Counter = 0x04,
    /// Bilateral: "Deal confirmed"
    Accept = 0x05,
    /// Bilateral: "No deal"
    Reject = 0x06,
    /// Bilateral: "Here's the work product"
    Deliver = 0x07,
    /// Pubsub (notary topic): "I want to notarize this task"
    NotarizeBid = 0x08,
    /// Bilateral: "You're the notary"
    NotarizeAssign = 0x09,
    /// Bilateral: "Notary judgment on completion"
    Verdict = 0x0A,
    /// Pubsub (reputation topic): "Rating of counterparty or notary"
    Feedback = 0x0B,
    /// Bilateral: "I challenge this verdict"
    Dispute = 0x0C,
    /// Broadcast: "I'm alive" (heartbeat)
    Beacon = 0x0D,
}

impl MsgType {
    pub fn from_u16(v: u16) -> Result<Self, ProtocolError> {
        match v {
            0x01 => Ok(Self::Advertise),
            0x02 => Ok(Self::Discover),
            0x03 => Ok(Self::Propose),
            0x04 => Ok(Self::Counter),
            0x05 => Ok(Self::Accept),
            0x06 => Ok(Self::Reject),
            0x07 => Ok(Self::Deliver),
            0x08 => Ok(Self::NotarizeBid),
            0x09 => Ok(Self::NotarizeAssign),
            0x0A => Ok(Self::Verdict),
            0x0B => Ok(Self::Feedback),
            0x0C => Ok(Self::Dispute),
            0x0D => Ok(Self::Beacon),
            other => Err(ProtocolError::UnknownMsgType(other)),
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns true if this message type is sent via pubsub broadcast.
    pub fn is_broadcast(self) -> bool {
        matches!(self, Self::Advertise | Self::Discover | Self::Beacon)
    }

    /// Returns true if this message type goes to the notary pubsub topic.
    pub fn is_notary_pubsub(self) -> bool {
        matches!(self, Self::NotarizeBid)
    }

    /// Returns true if this message type goes to the reputation pubsub topic.
    pub fn is_reputation_pubsub(self) -> bool {
        matches!(self, Self::Feedback)
    }

    /// Returns true if this message type uses direct bilateral streams.
    pub fn is_bilateral(self) -> bool {
        !self.is_broadcast() && !self.is_notary_pubsub() && !self.is_reputation_pubsub()
    }

    /// Returns true if this message type has a protocol-defined (parseable) payload.
    pub fn has_protocol_payload(self) -> bool {
        matches!(self, Self::Feedback | Self::NotarizeBid)
    }
}

impl std::fmt::Display for MsgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Advertise => "ADVERTISE",
            Self::Discover => "DISCOVER",
            Self::Propose => "PROPOSE",
            Self::Counter => "COUNTER",
            Self::Accept => "ACCEPT",
            Self::Reject => "REJECT",
            Self::Deliver => "DELIVER",
            Self::NotarizeBid => "NOTARIZE_BID",
            Self::NotarizeAssign => "NOTARIZE_ASSIGN",
            Self::Verdict => "VERDICT",
            Self::Feedback => "FEEDBACK",
            Self::Dispute => "DISPUTE",
            Self::Beacon => "BEACON",
        };
        write!(f, "{}", name)
    }
}
