// ============================================================================
// Protocol constants (doc 5, §11)
// ============================================================================

/// Protocol version byte included in every envelope.
pub const PROTOCOL_VERSION: u8 = 0x01;

// --- Identity ---------------------------------------------------------------

/// SATI program ID on Solana mainnet (and devnet — same address).
pub const SATI_PROGRAM_ID: &str = "satiRkxEiwZ51cv8PRu8UMzuaqeaNU9jABo6oAFMsLe";

/// SATI address lookup table (mainnet).
pub const SATI_LOOKUP_TABLE: &str = "fDinDQsTpN7Momkv7AxKT9oSyQam8xG2UD7v6vHu8LJ";

// --- Epoch ------------------------------------------------------------------

/// 0x01 epoch length in seconds (1 day).
/// Distinct from Solana validator epoch (~2 days). All epoch references in
/// the protocol refer to this value unless explicitly stated otherwise.
pub const EPOCH_LENGTH_SECS: u64 = 86_400;

// --- Stake & Lease ----------------------------------------------------------
// All protocol fees are denominated in USDC (6 decimal places on Solana).
// 1 USDC = 1_000_000 micro-USDC.

/// Minimum stake required to participate in the mesh (micro-USDC).
pub const MIN_STAKE_USDC: u64 = 10_000_000; // 10 USDC

/// Daily lease cost to remain active on the mesh (micro-USDC).
pub const LEASE_COST_PER_EPOCH_USDC: u64 = 1_000_000; // 1 USDC/day

/// Number of epochs an agent can miss lease payments before deactivation.
pub const GRACE_PERIOD_EPOCHS: u64 = 3;

/// Slots to wait after unlock queue before stake can be claimed.
/// ~2 days at 400ms/slot.
pub const UNLOCK_DELAY_SLOTS: u64 = 432_000;

// --- Transport --------------------------------------------------------------

/// Maximum envelope size in bytes (envelope + payload).
pub const MAX_MESSAGE_SIZE: usize = 65_536; // 64 KB

/// Maximum simultaneous libp2p connections per peer.
pub const MAX_CONNECTIONS: usize = 50;

/// Maximum inbound messages per second per peer before rate-limiting kicks in.
pub const MESSAGE_RATE_LIMIT: u32 = 100;

/// Acceptable clock skew between local and envelope timestamp (seconds).
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

// --- Reputation -------------------------------------------------------------

/// Decay factor applied per idle epoch as a fixed-precision ratio (numerator/denominator).
/// Equivalent to 0.95 decay per epoch.
pub const REPUTATION_DECAY_NUMERATOR: u64 = 95;
pub const REPUTATION_DECAY_DENOMINATOR: u64 = 100;

/// Number of consecutive idle epochs before decay begins.
pub const DECAY_WINDOW_EPOCHS: u64 = 6;

// --- Batch ------------------------------------------------------------------

/// Maximum entries per economic array in a BehaviorBatch before overflow.
pub const MAX_BATCH_ENTRIES: usize = 1_000;

// --- Challenge --------------------------------------------------------------

/// Challenge window in seconds (2 days). After this, no new challenges accepted.
pub const CHALLENGE_WINDOW_SECS: u64 = 172_800;

/// Stake required to submit a challenge (micro-USDC).
pub const CHALLENGE_STAKE_USDC: u64 = 10_000_000; // 10 USDC

/// Fraction of slashed stake paid to successful challenger (numerator/denominator).
/// Remainder goes to protocol treasury.
pub const CHALLENGE_REWARD_NUMERATOR: u64 = 1;
pub const CHALLENGE_REWARD_DENOMINATOR: u64 = 2; // 50%

// --- Pubsub topics ----------------------------------------------------------

pub const TOPIC_BROADCAST: &str = "/0x01/v1/broadcast";
pub const TOPIC_NOTARY: &str = "/0x01/v1/notary";
pub const TOPIC_REPUTATION: &str = "/0x01/v1/reputation";
