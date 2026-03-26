#!/usr/bin/env bash
# Deploy zerox1-node, zerox1-aggregator, and Kora to the genesis node.
# Downloads node + aggregator binaries from GitHub releases.
# Builds Kora from source on the VM.
#
# Usage:
#   RELEASE=v0.4.2 ./deploy/gcp/deploy-binaries.sh
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
gcloud compute scp deploy/systemd/zerox1-mailbox.service \
  "${INSTANCE}:/tmp/zerox1-mailbox.service" --zone="$ZONE"

# ── Download + install binaries, start services ──────────────────────────────
gcloud compute ssh "$INSTANCE" --zone="$ZONE" -- sudo bash -s <<REMOTE
  set -euo pipefail

  echo "==> Stopping services to allow binary replacement..."
  systemctl stop zerox1-aggregator zerox1-mailbox zerox1-node || true

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

  echo "==> Downloading zerox1-mailbox \$RELEASE..."
  curl -fsSL "https://github.com/\${REPO}/releases/download/\${RELEASE}/zerox1-mailbox-linux-x64" \
    -o /opt/zerox1/bin/zerox1-mailbox
  chmod +x /opt/zerox1/bin/zerox1-mailbox
  mkdir -p /var/lib/zerox1/mailbox
  chown zerox1:zerox1 /var/lib/zerox1/mailbox

  # ── Install systemd units ──────────────────────────────────────────────────
  cp /tmp/zerox1-node.service        /etc/systemd/system/
  cp /tmp/zerox1-aggregator.service  /etc/systemd/system/
  cp /tmp/zerox1-mailbox.service     /etc/systemd/system/

  systemctl daemon-reload

  # ── Start/restart services ─────────────────────────────────────────────────
  echo "==> Starting services..."
  systemctl enable zerox1-aggregator zerox1-node zerox1-mailbox
  systemctl restart zerox1-aggregator
  sleep 1
  systemctl restart zerox1-node
  sleep 3
  systemctl restart zerox1-mailbox

  echo ""
  echo "Service status:"
  systemctl is-active zerox1-aggregator   && echo "  zerox1-aggregator:    active" || echo "  zerox1-aggregator:    FAILED"
  systemctl is-active zerox1-node         && echo "  zerox1-node:          active" || echo "  zerox1-node:          FAILED"
  systemctl is-active zerox1-mailbox      && echo "  zerox1-mailbox:       active" || echo "  zerox1-mailbox:       FAILED"
REMOTE

echo ""
echo "Deployed $RELEASE to $INSTANCE."
echo ""
echo "Wait ~10s for the node to start, then get the bootstrap multiaddr:"
echo "  ./deploy/gcp/get-bootstrap-addrs.sh"
