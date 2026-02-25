#!/usr/bin/env bash
# Generate and write secrets to the genesis node.
# Run once after provisioning, before deploy-binaries.sh.
#
# Usage:
#   ./deploy/gcp/configure-secrets.sh

set -euo pipefail

INSTANCE="zerox1-genesis"
ZONE="us-central1-a"

# Shared secret between node and aggregator.
INGEST_SECRET=$(openssl rand -hex 32)

echo "Configuring secrets on $INSTANCE..."
echo ""

gcloud compute ssh "$INSTANCE" --zone="$ZONE" -- sudo bash -s <<REMOTE
  set -euo pipefail

  mkdir -p /etc/zerox1
  chmod 700 /etc/zerox1

  # Write environment file (sourced by all systemd services).
  cat > /etc/zerox1/env <<ENV
ZX01_AGGREGATOR_SECRET=${INGEST_SECRET}
AGGREGATOR_INGEST_SECRET=${INGEST_SECRET}
ENV
  chmod 600 /etc/zerox1/env

  # Generate Solana keypair for Kora using solana-keygen
  KORA_KEY="/var/lib/zerox1/kora-wallet.json"
  if [ ! -f "\$KORA_KEY" ]; then
    # Install solana CLI if not present
    if ! command -v solana-keygen &>/dev/null; then
      sh -c "\$(curl -sSfL https://release.anza.xyz/stable/install)"
      export PATH="\$HOME/.local/share/solana/install/active_release/bin:\$PATH"
    fi
    solana-keygen new --no-bip39-passphrase --outfile "\$KORA_KEY" --force
    chmod 600 "\$KORA_KEY"
    chown zerox1:zerox1 "\$KORA_KEY" 2>/dev/null || true
  fi

  PUBKEY=\$(solana-keygen pubkey "\$KORA_KEY" 2>/dev/null || echo "install solana CLI to get pubkey")
  echo "Kora wallet: \$PUBKEY"
  echo "Fund this address with devnet SOL at https://faucet.solana.com"

  echo "Secrets written to /etc/zerox1/env"
REMOTE

echo ""
echo "Ingest secret: $INGEST_SECRET"
echo "(Save this — needed if you add more nodes later)"
echo ""
echo "Next: fund the Kora wallet with SOL, then run:"
echo "  ./deploy/gcp/deploy-binaries.sh"
