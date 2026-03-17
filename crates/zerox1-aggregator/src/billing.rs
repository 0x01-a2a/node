//! Billing module: internal credit ledger + Circle Gateway/CCTP integration.
//!
//! # Architecture
//!
//! ```text
//! Money in (any chain):
//!   Agent on Base ──┐
//!   Agent on Sol  ──┼──► Circle Gateway ──► verify_deposit() ──► credit_account()
//!   Agent on Arb  ──┘
//!   Stripe/fiat   ──────────────────────────────────────────► credit_account()
//!
//! Money out (settlement):
//!   VERDICT event ──► debit payer ──► enqueue_settlement()
//!                                          │
//!                     ┌────────────────────┘
//!                     ▼
//!   Settlement worker: CCTP burn → Iris attestation → mint on provider's chain
//! ```

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum length of account_id (hex agent_id = 64 chars, base58 = ~44).
pub const MAX_ACCOUNT_ID_LEN: usize = 100;
/// Maximum length of reference (tx hash / stripe charge id).
pub const MAX_REFERENCE_LEN: usize = 256;
/// Maximum length of payout address.
pub const MAX_ADDRESS_LEN: usize = 128;
/// Maximum single deposit (100M USDC in minor units — sanity cap).
pub const MAX_DEPOSIT_USDC: u64 = 100_000_000_000_000;

// ============================================================================
// Types
// ============================================================================

/// Payment method for billing deposits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethod {
    Gateway,
    Stripe,
    Direct,
}

impl std::fmt::Display for PaymentMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gateway => write!(f, "gateway"),
            Self::Stripe => write!(f, "stripe"),
            Self::Direct => write!(f, "direct"),
        }
    }
}

impl std::str::FromStr for PaymentMethod {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gateway" => Ok(Self::Gateway),
            "stripe" => Ok(Self::Stripe),
            "direct" => Ok(Self::Direct),
            other => Err(format!("unknown payment method: {other}")),
        }
    }
}

/// A billing account (maps to `billing_accounts` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingAccount {
    pub account_id: String,
    /// Balance in USDC minor units (1 USDC = 1,000,000).
    pub balance_usdc: u64,
    /// Tier: free | builder | scale | enterprise.
    pub tier: String,
    pub payment_method: Option<String>,
    /// CCTP domain ID for payouts.
    pub preferred_chain: Option<u32>,
    /// Wallet address on preferred_chain for settlement payouts.
    pub payout_address: Option<String>,
    /// When true, VERDICT debits are settled internally (direct credit to payee)
    /// without going through Circle CCTP. Use for enterprise/admin accounts that
    /// settle off-band or via direct Solana transfer.
    pub skip_settlement: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

/// A billing transaction entry (maps to `billing_transactions` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingTransaction {
    pub id: i64,
    pub account_id: String,
    /// deposit | withdraw | charge | refund | settlement_out | settlement_in
    pub tx_type: String,
    /// USDC minor units, always positive.
    pub amount_usdc: u64,
    pub payment_method: String,
    /// tx hash, stripe charge id, conversation_id, etc.
    pub reference: Option<String>,
    pub chain_domain: Option<u32>,
    /// pending | completed | failed
    pub status: String,
    pub created_at: u64,
}

/// An entry in the settlement queue (maps to `settlement_queue` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementQueueEntry {
    pub id: i64,
    pub conversation_id: String,
    pub payer_account: String,
    pub payee_account: String,
    /// USDC minor units.
    pub amount_usdc: u64,
    /// Aggregator escrow fee in USDC minor units.
    pub fee_usdc: u64,
    /// CCTP destination domain.
    pub dest_chain: Option<u32>,
    /// Payee wallet address on dest_chain.
    pub dest_address: Option<String>,
    /// pending | processing | completed | failed
    pub status: String,
    pub cctp_tx_hash: Option<String>,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}

/// Aggregate revenue stats for admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevenueStats {
    /// Total deposits in USDC minor units.
    pub total_deposits_usdc: u64,
    /// Total withdrawals in USDC minor units.
    pub total_withdrawals_usdc: u64,
    /// Total fees collected in USDC minor units.
    pub total_fees_usdc: u64,
    /// Total settled amount in USDC minor units.
    pub total_settled_usdc: u64,
    /// Number of billing accounts.
    pub account_count: u64,
    /// Number of pending settlements.
    pub pending_settlements: u64,
    /// Account counts by tier.
    pub tier_counts: std::collections::HashMap<String, u64>,
}

// ============================================================================
// API request/response types
// ============================================================================

/// POST /billing/deposit — Ed25519-signed by the depositor.
#[derive(Debug, Deserialize)]
pub struct DepositRequest {
    pub account_id: String,
    /// USDC minor units.
    pub amount_usdc: u64,
    pub payment_method: String,
    /// Transaction hash or payment reference.
    pub reference: String,
    /// Chain domain (for Gateway deposits).
    pub chain_domain: Option<u32>,
    /// Ed25519 signature of the canonical request body (hex).
    pub signature: String,
    /// Timestamp of the request (unix seconds).
    pub timestamp: u64,
}

/// POST /billing/withdraw — Ed25519-signed.
#[derive(Debug, Deserialize)]
pub struct WithdrawRequest {
    pub account_id: String,
    /// USDC minor units.
    pub amount_usdc: u64,
    /// CCTP destination chain domain.
    pub dest_chain: u32,
    /// Wallet address on destination chain.
    pub dest_address: String,
    /// Ed25519 signature of the request body (hex).
    pub signature: String,
    /// Timestamp of the request (unix seconds).
    pub timestamp: u64,
}

/// POST /billing/set-payout — Ed25519-signed.
#[derive(Debug, Deserialize)]
pub struct SetPayoutRequest {
    pub account_id: String,
    pub preferred_chain: u32,
    pub payout_address: String,
    /// Ed25519 signature (hex).
    pub signature: String,
    pub timestamp: u64,
}

/// Internal request to enqueue a settlement — groups the 7 params to avoid clippy::too_many_arguments.
#[derive(Debug)]
pub struct SettlementRequest<'a> {
    pub conversation_id: &'a str,
    pub payer: &'a str,
    pub payee: &'a str,
    pub amount_usdc: u64,
    pub fee_usdc: u64,
    pub dest_chain: Option<u32>,
    pub dest_address: Option<&'a str>,
}

/// GET /billing/estimate-settlement?amount_usdc=&source_chain=&dest_chain=
#[derive(Debug, Deserialize)]
pub struct EstimateParams {
    pub amount_usdc: f64,
    pub source_chain: u32,
    pub dest_chain: u32,
}

/// Billing balance response.
#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub account_id: String,
    pub balance_usdc: u64,
    pub balance_usdc_human: String,
    pub tier: String,
    pub preferred_chain: Option<u32>,
    pub payout_address: Option<String>,
}

impl From<BillingAccount> for BalanceResponse {
    fn from(a: BillingAccount) -> Self {
        let human = format!("{:.6}", a.balance_usdc as f64 / 1_000_000.0);
        Self {
            account_id: a.account_id,
            balance_usdc: a.balance_usdc,
            balance_usdc_human: human,
            tier: a.tier,
            preferred_chain: a.preferred_chain,
            payout_address: a.payout_address,
        }
    }
}

// ============================================================================
// Tier thresholds (monthly envelope credits)
// ============================================================================

/// Determine billing tier based on balance.
pub fn tier_for_balance(balance_usdc: u64) -> &'static str {
    let usdc = balance_usdc / 1_000_000;
    match usdc {
        0..=48 => "free",
        49..=198 => "builder",
        199..=999 => "scale",
        _ => "enterprise",
    }
}

// ============================================================================
// Validation helpers
// ============================================================================

/// Known CCTP V2 domain IDs.
const KNOWN_DOMAINS: &[u32] = &[
    0,     // Ethereum
    1,     // Avalanche
    2,     // Optimism
    3,     // Arbitrum
    5,     // Solana
    6,     // Base
    7,     // Polygon
    11,    // Linea
    12,    // Sei
    16,    // Unichain
    25,    // World Chain
    1420,  // HyperEVM
    64165, // Sonic
    65536, // Ink
];

pub fn is_valid_chain_domain(domain: u32) -> bool {
    KNOWN_DOMAINS.contains(&domain)
}

pub fn validate_account_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        return Err("account_id is empty");
    }
    if id.len() > MAX_ACCOUNT_ID_LEN {
        return Err("account_id too long");
    }
    // Must be hex or base58 (no control chars, spaces, etc.)
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("account_id contains invalid characters");
    }
    Ok(())
}

pub fn validate_reference(r: &str) -> Result<(), &'static str> {
    if r.is_empty() {
        return Err("reference is empty");
    }
    if r.len() > MAX_REFERENCE_LEN {
        return Err("reference too long");
    }
    if r.contains(|c: char| c.is_control()) {
        return Err("reference contains control characters");
    }
    Ok(())
}

pub fn validate_address(addr: &str, chain_domain: u32) -> Result<(), &'static str> {
    if addr.is_empty() {
        return Err("address is empty");
    }
    if addr.len() > MAX_ADDRESS_LEN {
        return Err("address too long");
    }
    match chain_domain {
        // Solana: base58, 32-44 chars
        5 => {
            if addr.len() < 32 || addr.len() > 44 {
                return Err("invalid Solana address length");
            }
            if !addr.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err("invalid Solana address characters");
            }
            // Reject base58 chars that aren't valid: 0, O, I, l
            if addr.contains('0') || addr.contains('O') || addr.contains('I') || addr.contains('l')
            {
                return Err("invalid base58 characters in Solana address");
            }
        }
        // EVM chains: 0x-prefixed hex, 42 chars
        0 | 1 | 2 | 3 | 6 | 7 | 11 | 12 | 16 | 25 | 1420 | 64165 | 65536 => {
            if !addr.starts_with("0x") && !addr.starts_with("0X") {
                return Err("EVM address must start with 0x");
            }
            if addr.len() != 42 {
                return Err("EVM address must be 42 characters");
            }
            if !addr[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("EVM address contains invalid hex characters");
            }
        }
        _ => {
            return Err("unknown chain domain");
        }
    }
    Ok(())
}

/// Validate that a timestamp is within `window_secs` of now.
pub fn validate_timestamp(ts: u64, window_secs: u64) -> Result<(), &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(ts) > window_secs {
        return Err("request expired or clock skew too large");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_for_balance() {
        assert_eq!(tier_for_balance(0), "free");
        assert_eq!(tier_for_balance(48_999_999), "free");
        assert_eq!(tier_for_balance(49_000_000), "builder");
        assert_eq!(tier_for_balance(199_000_000), "scale");
        assert_eq!(tier_for_balance(1_000_000_000), "enterprise");
    }

    #[test]
    fn test_validate_account_id() {
        assert!(validate_account_id("abc123").is_ok());
        assert!(validate_account_id("").is_err());
        assert!(validate_account_id(&"a".repeat(101)).is_err());
        assert!(validate_account_id("ab cd").is_err());
    }

    #[test]
    fn test_validate_address_solana() {
        assert!(validate_address("11111111111111111111111111111111", 5).is_ok());
        assert!(validate_address("short", 5).is_err());
        assert!(validate_address("0x1234567890abcdef1234567890abcdef12345678", 5).is_err());
    }

    #[test]
    fn test_validate_address_evm() {
        assert!(validate_address("0x1234567890abcdef1234567890abcdef12345678", 6).is_ok());
        assert!(validate_address("1234567890abcdef1234567890abcdef12345678", 6).is_err());
        assert!(validate_address("0x123", 6).is_err());
    }

    #[test]
    fn test_payment_method_parse() {
        assert_eq!("gateway".parse::<PaymentMethod>().unwrap(), PaymentMethod::Gateway);
        assert_eq!("stripe".parse::<PaymentMethod>().unwrap(), PaymentMethod::Stripe);
        assert_eq!("direct".parse::<PaymentMethod>().unwrap(), PaymentMethod::Direct);
        assert!("unknown".parse::<PaymentMethod>().is_err());
    }
}
