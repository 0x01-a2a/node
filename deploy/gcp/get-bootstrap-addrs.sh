#!/usr/bin/env bash
# Extract the libp2p peer ID from the genesis node and print the multiaddr
# to paste into crates/zerox1-node/src/config.rs DEFAULT_BOOTSTRAP_PEERS.
#
# Usage:
#   ./deploy/gcp/get-bootstrap-addrs.sh

set -euo pipefail

INSTANCE="zerox1-genesis"
ZONE="us-central1-a"
DNS="bootstrap-1.0x01.world"

echo "Fetching peer ID from $INSTANCE..."

PEER_ID=$(gcloud compute ssh "$INSTANCE" --zone="$ZONE" -- \
  "journalctl -u zerox1-node --no-pager -n 500 2>/dev/null \
  | grep -oP 'peer_id=\K[A-Za-z0-9]+' \
  | tail -1")

if [ -z "$PEER_ID" ]; then
  echo "ERROR: peer ID not found. Check if zerox1-node is running:"
  echo "  gcloud compute ssh $INSTANCE --zone=$ZONE -- journalctl -u zerox1-node -n 50"
  exit 1
fi

MULTIADDR="/dns4/${DNS}/tcp/9000/p2p/${PEER_ID}"

echo ""
echo "Paste this into crates/zerox1-node/src/config.rs → DEFAULT_BOOTSTRAP_PEERS:"
echo ""
echo "  \"$MULTIADDR\","
echo ""
echo "Then commit, tag a new release, and redeploy."
