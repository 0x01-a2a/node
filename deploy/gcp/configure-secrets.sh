#!/usr/bin/env bash
# Generate and deploy secrets to all GCP instances.
# Run once after provisioning, before deploying binaries.
#
# Usage:
#   ./deploy/gcp/configure-secrets.sh

set -euo pipefail

# Generate a shared ingest secret (same value on all nodes + aggregator).
INGEST_SECRET=$(openssl rand -hex 32)

echo "Generated ingest secret: $INGEST_SECRET"
echo "(Save this — you'll need it if you add more nodes later)"
echo ""

declare -A INSTANCES=(
  ["zerox1-bootstrap-1"]="us-east1-b"
  ["zerox1-bootstrap-2"]="europe-west3-a"
  ["zerox1-bootstrap-3"]="asia-southeast1-b"
)

for NAME in "${!INSTANCES[@]}"; do
  ZONE="${INSTANCES[$NAME]}"
  echo "Configuring secrets on $NAME..."

  gcloud compute ssh "$NAME" --zone="$ZONE" -- bash -s <<REMOTE
    mkdir -p /etc/zerox1
    chmod 700 /etc/zerox1
    cat > /etc/zerox1/env <<ENV
ZX01_AGGREGATOR_SECRET=${INGEST_SECRET}
AGGREGATOR_INGEST_SECRET=${INGEST_SECRET}
ENV
    chmod 600 /etc/zerox1/env
    echo "  Secrets written to /etc/zerox1/env"
REMOTE

done

echo ""
echo "Done. All nodes share ingest secret: $INGEST_SECRET"
echo "Store this secret securely — it authenticates reputation data pushes."
