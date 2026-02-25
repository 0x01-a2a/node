#!/usr/bin/env bash
# Deploy zerox1-node, zerox1-aggregator, and Kora to the genesis node.
# Downloads node + aggregator binaries from GitHub releases.
# Builds Kora from source on the VM.
#
# Usage:
#   RELEASE=v0.1.3 ./deploy/gcp/deploy-binaries.sh
#   (defaults to latest release if RELEASE is unset)

set -euo pipefail

INSTANCE="zerox1-genesis"
ZONE="us-central1-a"
GITHUB_REPO="0x01-a2a/node"
RELEASE="${RELEASE:-latest}"

if [ "$RELEASE" = "latest" ]; then
  RELEASE=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
    | grep '"tag_name"' | cut -d'"' -f4)
fi

echo "Deploying $RELEASE to $INSTANCE..."
echo ""

# ── Upload systemd units ─────────────────────────────────────────────────────
echo "Uploading systemd units..."
gcloud compute scp deploy/systemd/zerox1-node.service \
  "${INSTANCE}:/tmp/zerox1-node.service" --zone="$ZONE"
gcloud compute scp deploy/systemd/zerox1-aggregator.service \
  "${INSTANCE}:/tmp/zerox1-aggregator.service" --zone="$ZONE"
gcloud compute scp deploy/systemd/kora.service \
  "${INSTANCE}:/tmp/kora.service" --zone="$ZONE"

# ── Download + install binaries, build Kora, start services ─────────────────
gcloud compute ssh "$INSTANCE" --zone="$ZONE" -- sudo bash -s <<REMOTE
  set -euo pipefail

  echo "==> Stopping services to allow binary replacement..."
  systemctl stop kora zerox1-aggregator zerox1-node || true

  RELEASE="${RELEASE}"
  REPO="${GITHUB_REPO}"

  echo "==> Downloading zerox1-node \$RELEASE..."
  curl -fsSL "https://github.com/\${REPO}/releases/download/\${RELEASE}/zerox1-node-linux-x64" \
    -o /opt/zerox1/bin/zerox1-node
  chmod +x /opt/zerox1/bin/zerox1-node

  echo "==> Downloading zerox1-aggregator \$RELEASE..."
  curl -fsSL "https://github.com/\${REPO}/releases/download/\${RELEASE}/zerox1-aggregator-linux-x64" \
    -o /opt/zerox1/bin/zerox1-aggregator
  chmod +x /opt/zerox1/bin/zerox1-aggregator

  # ── Build Kora from source ─────────────────────────────────────────────────
  if [ ! -f /opt/zerox1/bin/kora ]; then
    echo "==> Building Kora from source (this takes a few minutes)..."
    export PATH="\$HOME/.cargo/bin:\$PATH"
    git clone --depth=1 https://github.com/solana-foundation/kora.git /tmp/kora-src
    cd /tmp/kora-src
    cargo build --release
    cp target/release/kora /opt/zerox1/bin/kora
    chmod +x /opt/zerox1/bin/kora
    rm -rf /tmp/kora-src
    echo "==> Kora built and installed."
  else
    echo "==> Kora already installed, skipping build."
  fi

  # ── Write Kora config ──────────────────────────────────────────────────────
  cat > /etc/zerox1/kora.toml <<KORACFG
[server]
port = 8080

[kora]
rate_limit = 100

[kora.auth]

[kora.cache]
enabled = false
default_ttl = 300
account_ttl = 60

[kora.enabled_methods]
liveness = true
estimate_transaction_fee = true
get_supported_tokens = true
sign_transaction = true
sign_and_send_transaction = true
transfer_transaction = true
get_blockhash = true
get_config = true
get_payer_signer = true

[solana]
rpc_url = "https://api.devnet.solana.com"
fee_payer_keypair = "/var/lib/zerox1/kora-wallet.json"

[validation]
max_allowed_lamports = 1000000
max_signatures = 10
price_source = "Mock"
allow_durable_transactions = false

# Program IDs allowed to be sponsored by Kora
allowed_programs = [
  "11111111111111111111111111111111",              # System Program
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",   # Token Program
  "3gXhgBLsVYVQkntuVcPdiDe2gRxbSt2CGFJKriA8q9bA",  # behavior-log
  "9g4RMQvBBVCppUc9C3Vjk2Yn3vhHzDFb8RkVm8a1WmUk",  # lease
  "KncUkaiDtvaLJRDfXDmPXKmBYnVe6m3MKBawZsf6xsj",   # challenge
  "CmtDveNpCXNJePa7pCLi7vCPeuNmWnfqq2L2YGiG7YD4",  # stake-lock
]

# Token mints allowed (USDC only)
allowed_tokens = [
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
]
allowed_spl_paid_tokens = [
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
]
disallowed_accounts = []
KORACFG
  chown zerox1:zerox1 /etc/zerox1/kora.toml
  chmod 600 /etc/zerox1/kora.toml

  cat > /etc/zerox1/signers.toml <<SIGNERSCFG
[[signers]]
name = "default"
type = "memory"
private_key_env = "KORA_PRIVATE_KEY"
SIGNERSCFG
  chown zerox1:zerox1 /etc/zerox1/signers.toml
  chmod 600 /etc/zerox1/signers.toml

  cat > /tmp/b58.py <<'EOF'
import sys, json
b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58encode(v):
    n, p = 0, 0
    for x in v: n = (n << 8) + x
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58[r])
    for x in v:
        if x == 0: p += 1
        else: break
    return '1' * p + ''.join(reversed(res))
if __name__ == '__main__':
    with open('/var/lib/zerox1/kora-wallet.json') as f:
        key_bytes = json.load(f)
    print(b58encode(key_bytes))
EOF
  KPA_BASE58=\$(python3 /tmp/b58.py)
  # Remove old KORA_PRIVATE_KEY if it exists
  sed -i '/^KORA_PRIVATE_KEY=/d' /etc/zerox1/env || true
  # Append new KORA_PRIVATE_KEY map
  echo "KORA_PRIVATE_KEY=\$KPA_BASE58" >> /etc/zerox1/env


  # ── Install systemd units ──────────────────────────────────────────────────
  cp /tmp/zerox1-node.service        /etc/systemd/system/
  cp /tmp/zerox1-aggregator.service  /etc/systemd/system/
  cp /tmp/kora.service               /etc/systemd/system/

  systemctl daemon-reload

  # ── Start/restart services (order: kora first, then node) ─────────────────
  echo "==> Starting services..."
  systemctl enable kora zerox1-aggregator zerox1-node
  systemctl restart kora
  sleep 2
  systemctl restart zerox1-aggregator
  sleep 1
  systemctl restart zerox1-node

  echo ""
  echo "Service status:"
  systemctl is-active kora              && echo "  kora:               active" || echo "  kora:               FAILED"
  systemctl is-active zerox1-aggregator && echo "  zerox1-aggregator:  active" || echo "  zerox1-aggregator:  FAILED"
  systemctl is-active zerox1-node       && echo "  zerox1-node:        active" || echo "  zerox1-node:        FAILED"
REMOTE

echo ""
echo "Deployed $RELEASE to $INSTANCE."
echo ""
echo "Wait ~10s for the node to start, then get the bootstrap multiaddr:"
echo "  ./deploy/gcp/get-bootstrap-addrs.sh"
