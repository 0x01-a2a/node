#!/usr/bin/env bash
# 0x01 GCP provisioning — creates 3 bootstrap nodes + 1 aggregator node.
# Run once from your local machine with gcloud CLI authenticated.
#
# Prerequisites:
#   gcloud auth login
#   gcloud config set project <your-project-id>
#
# Usage:
#   chmod +x deploy/gcp/provision.sh
#   ./deploy/gcp/provision.sh

set -euo pipefail

PROJECT=$(gcloud config get-value project)
echo "Provisioning 0x01 backend in project: $PROJECT"

# ── Machine config ──────────────────────────────────────────────────────────
MACHINE="e2-small"       # 1 vCPU, 2 GB RAM — ~$13/month
DISK="20GB"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"

# ── Instances ───────────────────────────────────────────────────────────────
# 3 bootstrap peers spread across regions + aggregator co-located with node 1.
declare -A INSTANCES=(
  ["zerox1-bootstrap-1"]="us-east1-b"
  ["zerox1-bootstrap-2"]="europe-west3-a"
  ["zerox1-bootstrap-3"]="asia-southeast1-b"
)

# ── Firewall rules ──────────────────────────────────────────────────────────
echo "Creating firewall rules..."

gcloud compute firewall-rules create zerox1-libp2p \
  --allow=tcp:9000 \
  --target-tags=zerox1-node \
  --description="0x01 libp2p TCP port" \
  --quiet 2>/dev/null || echo "  firewall rule zerox1-libp2p already exists"

gcloud compute firewall-rules create zerox1-aggregator \
  --allow=tcp:8081 \
  --target-tags=zerox1-aggregator \
  --description="0x01 reputation aggregator HTTP" \
  --quiet 2>/dev/null || echo "  firewall rule zerox1-aggregator already exists"

# ── Create instances ─────────────────────────────────────────────────────────
for NAME in "${!INSTANCES[@]}"; do
  ZONE="${INSTANCES[$NAME]}"
  REGION="${ZONE%-*}"

  echo "Creating instance $NAME in $ZONE..."

  # Reserve a static external IP.
  gcloud compute addresses create "${NAME}-ip" \
    --region="$REGION" \
    --quiet 2>/dev/null || echo "  static IP ${NAME}-ip already exists"

  STATIC_IP=$(gcloud compute addresses describe "${NAME}-ip" \
    --region="$REGION" \
    --format="get(address)")

  TAGS="zerox1-node"
  # First node also runs the aggregator.
  [ "$NAME" = "zerox1-bootstrap-1" ] && TAGS="zerox1-node,zerox1-aggregator"

  gcloud compute instances create "$NAME" \
    --zone="$ZONE" \
    --machine-type="$MACHINE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$DISK" \
    --boot-disk-type="pd-ssd" \
    --tags="$TAGS" \
    --address="$STATIC_IP" \
    --metadata-from-file="startup-script=deploy/gcp/startup.sh" \
    --quiet 2>/dev/null || echo "  instance $NAME already exists"

  echo "  $NAME: $STATIC_IP"
done

echo ""
echo "Instances created. Wait ~60s for startup scripts to finish, then run:"
echo "  ./deploy/gcp/deploy-binaries.sh"
