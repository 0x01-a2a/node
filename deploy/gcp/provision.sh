#!/usr/bin/env bash
# 0x01 GCP provisioning — single genesis node running zerox1-node, aggregator, and Kora.
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
INSTANCE="zerox1-genesis"
ZONE="us-central1-a"
REGION="us-central1"
MACHINE="e2-small"   # 1 vCPU, 2 GB RAM — ~$13/month
DISK="20GB"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"

echo "Provisioning 0x01 genesis node in project: $PROJECT"

# ── Firewall rules ───────────────────────────────────────────────────────────

echo "Creating firewall rules..."

# libp2p TCP — open to internet so other nodes can connect
gcloud compute firewall-rules create zerox1-libp2p \
  --allow=tcp:9000 \
  --target-tags=zerox1-node \
  --description="0x01 libp2p TCP" \
  --quiet 2>/dev/null || echo "  firewall rule zerox1-libp2p already exists"

# Aggregator HTTP — internal only (nodes push to it, not public)
gcloud compute firewall-rules create zerox1-aggregator \
  --allow=tcp:8081 \
  --target-tags=zerox1-aggregator \
  --source-ranges=10.0.0.0/8 \
  --description="0x01 aggregator HTTP (internal)" \
  --quiet 2>/dev/null || echo "  firewall rule zerox1-aggregator already exists"

# Kora runs on localhost only — no firewall rule needed

# ── Static IP ────────────────────────────────────────────────────────────────

echo "Reserving static IP..."
gcloud compute addresses create "${INSTANCE}-ip" \
  --region="$REGION" \
  --quiet 2>/dev/null || echo "  static IP ${INSTANCE}-ip already exists"

STATIC_IP=$(gcloud compute addresses describe "${INSTANCE}-ip" \
  --region="$REGION" \
  --format="get(address)")

echo "  Static IP: $STATIC_IP"

# ── Create instance ──────────────────────────────────────────────────────────

echo "Creating instance $INSTANCE in $ZONE..."

gcloud compute instances create "$INSTANCE" \
  --zone="$ZONE" \
  --machine-type="$MACHINE" \
  --image-family="$IMAGE_FAMILY" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size="$DISK" \
  --boot-disk-type="pd-ssd" \
  --tags="zerox1-node,zerox1-aggregator" \
  --address="$STATIC_IP" \
  --metadata-from-file="startup-script=deploy/gcp/startup.sh" \
  --quiet 2>/dev/null || echo "  instance $INSTANCE already exists"

echo ""
echo "Instance created: $INSTANCE ($STATIC_IP)"
echo ""
echo "Point DNS: bootstrap-1.0x01.world → $STATIC_IP"
echo ""
echo "Wait ~3 min for startup script to finish, then run:"
echo "  ./deploy/gcp/configure-secrets.sh"
echo "  ./deploy/gcp/deploy-binaries.sh"
