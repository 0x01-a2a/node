#!/usr/bin/env bash
# Extract the libp2p peer IDs from running bootstrap nodes and print the
# multiaddrs to put into node/crates/zerox1-node/src/config.rs.
#
# Usage:
#   ./deploy/gcp/get-bootstrap-addrs.sh

set -euo pipefail

declare -A INSTANCES=(
  ["zerox1-bootstrap-1"]="us-east1-b"
  ["zerox1-bootstrap-2"]="europe-west3-a"
  ["zerox1-bootstrap-3"]="asia-southeast1-b"
)

declare -A DNS=(
  ["zerox1-bootstrap-1"]="bootstrap-1.0x01.world"
  ["zerox1-bootstrap-2"]="bootstrap-2.0x01.world"
  ["zerox1-bootstrap-3"]="bootstrap-3.0x01.world"
)

echo "Fetching peer IDs from running nodes..."
echo ""

for NAME in "${!INSTANCES[@]}"; do
  ZONE="${INSTANCES[$NAME]}"
  HOST="${DNS[$NAME]}"

  # Grep the systemd journal for the startup multiaddr log line.
  PEER_ID=$(gcloud compute ssh "$NAME" --zone="$ZONE" -- \
    journalctl -u zerox1-node --no-pager -n 200 2>/dev/null \
    | grep "0x01 bootstrap multiaddr" \
    | grep -oP 'p2p/\K[A-Za-z0-9]+' \
    | tail -1)

  if [ -z "$PEER_ID" ]; then
    echo "  $NAME: peer ID not found yet (node may still be starting)"
    continue
  fi

  MULTIADDR="/dns4/${HOST}/tcp/9000/p2p/${PEER_ID}"
  echo "  // $NAME"
  echo "  \"$MULTIADDR\","
done

echo ""
echo "Paste the lines above into:"
echo "  node/crates/zerox1-node/src/config.rs  →  DEFAULT_BOOTSTRAP_PEERS"
echo ""
echo "Then rebuild and redeploy."
