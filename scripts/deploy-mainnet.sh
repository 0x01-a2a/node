#!/usr/bin/env bash
# deploy-mainnet.sh — One-shot mainnet deploy for 0x01 programs.
#
# Run this script exactly once when you are ready to go live.
# It stamps the current time as GENESIS_TIMESTAMP, builds all programs,
# and deploys them to mainnet-beta.
#
# Prerequisites:
#   - Solana CLI configured to mainnet-beta: solana config set --url mainnet-beta
#   - Keypair with ≥10 SOL: solana balance
#   - cargo-build-sbf installed: cargo build-sbf --version
#
# Usage:
#   chmod +x scripts/deploy-mainnet.sh
#   ./scripts/deploy-mainnet.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Sanity checks ─────────────────────────────────────────────────────────────

CLUSTER=$(solana config get | grep "RPC URL" | awk '{print $3}')
if [[ "$CLUSTER" != *"mainnet"* ]]; then
    echo "ERROR: Solana CLI is not pointed at mainnet-beta."
    echo "       Run: solana config set --url mainnet-beta"
    echo "       Current: $CLUSTER"
    exit 1
fi

BALANCE=$(solana balance --lamports | awk '{print $1}')
MIN_LAMPORTS=9000000000  # 9 SOL minimum (10 recommended, keep 1 for fees)
if [[ "$BALANCE" -lt "$MIN_LAMPORTS" ]]; then
    echo "ERROR: Insufficient SOL balance."
    echo "       Have: $(solana balance)"
    echo "       Need: at least 9 SOL"
    exit 1
fi

# ── Stamp GENESIS_TIMESTAMP ───────────────────────────────────────────────────

GENESIS_TS=$(date -u +%s)
GENESIS_DATE=$(date -u -r "$GENESIS_TS" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -u '+%Y-%m-%d %H:%M:%S UTC')

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  0x01 Mainnet Deploy                                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  GENESIS_TIMESTAMP : $GENESIS_TS ($GENESIS_DATE)"
echo "║  Cluster           : $CLUSTER"
echo "║  Balance           : $(solana balance)"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
read -p "Proceed? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

# Patch stake-lock program
STAKELOCK="$REPO_ROOT/programs/workspace/programs/stake-lock/src/lib.rs"
sed -i.bak "s/pub const GENESIS_TIMESTAMP: i64 = [0-9_]*;/pub const GENESIS_TIMESTAMP: i64 = ${GENESIS_TS};/" "$STAKELOCK"
echo "✓ Patched $STAKELOCK"

# Patch node inactive.rs (must mirror program)
INACTIVE="$REPO_ROOT/crates/zerox1-node/src/inactive.rs"
sed -i.bak "s/const GENESIS_TIMESTAMP: *i64 = [0-9_]*;/const GENESIS_TIMESTAMP:       i64 = ${GENESIS_TS};/" "$INACTIVE"
echo "✓ Patched $INACTIVE"

# ── Build ─────────────────────────────────────────────────────────────────────

echo ""
echo "Building SBF programs..."
cd "$REPO_ROOT/programs/workspace"
cargo build-sbf 2>&1 | tail -5
echo "✓ Build complete"

# ── Deploy ────────────────────────────────────────────────────────────────────

DEPLOY_DIR="$REPO_ROOT/programs/workspace/target/deploy"
KEYPAIR_DIR="$REPO_ROOT/programs/workspace/target/deploy"

deploy_program() {
    local name="$1"
    local so="$DEPLOY_DIR/${name}.so"
    local kp="$KEYPAIR_DIR/${name}-keypair.json"

    echo ""
    echo "Deploying $name..."
    if [[ -f "$kp" ]]; then
        solana program deploy "$so" --program-id "$kp" --url mainnet-beta
    else
        solana program deploy "$so" --url mainnet-beta
    fi
    echo "✓ $name deployed"
}

deploy_program "behavior_log"
deploy_program "lease"
deploy_program "challenge"
deploy_program "stake_lock"
deploy_program "escrow"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Deploy complete!                                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  GENESIS_TIMESTAMP = $GENESIS_TS"
echo "║"
echo "║  Next steps:"
echo "║  1. Update program IDs in zerox1-node config"
echo "║  2. Rebuild zerox1-node binary (GENESIS_TIMESTAMP is now stamped)"
echo "║  3. Restart bootstrap nodes"
echo "║  4. Publish new @zerox1/sdk with mainnet program IDs"
echo "╚══════════════════════════════════════════════════════════════╝"
