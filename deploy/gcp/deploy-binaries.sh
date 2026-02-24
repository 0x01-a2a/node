#!/usr/bin/env bash
# Copy compiled binaries to all GCP instances and start/restart services.
#
# Run from the repo root after building:
#   cargo build --release -p zerox1-node -p zerox1-aggregator
#
# Usage:
#   ./deploy/gcp/deploy-binaries.sh

set -euo pipefail

NODE_BIN="target/release/zerox1-node"
AGG_BIN="target/release/zerox1-aggregator"

if [ ! -f "$NODE_BIN" ]; then
  echo "ERROR: $NODE_BIN not found. Run: cd node && cargo build --release -p zerox1-node"
  exit 1
fi

declare -A INSTANCES=(
  ["zerox1-bootstrap-1"]="us-east1-b"
  ["zerox1-bootstrap-2"]="europe-west3-a"
  ["zerox1-bootstrap-3"]="asia-southeast1-b"
)

# ── Deploy zerox1-node to all bootstrap instances ──────────────────────────────
for NAME in "${!INSTANCES[@]}"; do
  ZONE="${INSTANCES[$NAME]}"
  echo "Deploying zerox1-node to $NAME ($ZONE)..."

  gcloud compute scp "$NODE_BIN" "${NAME}:/opt/zerox1/bin/zerox1-node" \
    --zone="$ZONE"

  gcloud compute scp "deploy/systemd/zerox1-node.service" \
    "${NAME}:/etc/systemd/system/zerox1-node.service" \
    --zone="$ZONE"

  gcloud compute ssh "$NAME" --zone="$ZONE" -- bash -s <<'REMOTE'
    chmod +x /opt/zerox1/bin/zerox1-node
    systemctl daemon-reload
    systemctl enable zerox1-node
    systemctl restart zerox1-node
    echo "zerox1-node status:"
    systemctl is-active zerox1-node
REMOTE

  echo "  Done: $NAME"
done

# ── Deploy zerox1-aggregator to bootstrap-1 ───────────────────────────────────
if [ -f "$AGG_BIN" ]; then
  echo "Deploying zerox1-aggregator to zerox1-bootstrap-1..."

  gcloud compute scp "$AGG_BIN" \
    "zerox1-bootstrap-1:/opt/zerox1/bin/zerox1-aggregator" \
    --zone="us-east1-b"

  gcloud compute scp "deploy/systemd/zerox1-aggregator.service" \
    "zerox1-bootstrap-1:/etc/systemd/system/zerox1-aggregator.service" \
    --zone="us-east1-b"

  gcloud compute ssh "zerox1-bootstrap-1" --zone="us-east1-b" -- bash -s <<'REMOTE'
    chmod +x /opt/zerox1/bin/zerox1-aggregator
    mkdir -p /var/lib/zerox1
    systemctl daemon-reload
    systemctl enable zerox1-aggregator
    systemctl restart zerox1-aggregator
    echo "zerox1-aggregator status:"
    systemctl is-active zerox1-aggregator
REMOTE

  echo "  Done: zerox1-aggregator"
fi

echo ""
echo "All done. Get bootstrap multiaddrs with:"
echo "  ./deploy/gcp/get-bootstrap-addrs.sh"
