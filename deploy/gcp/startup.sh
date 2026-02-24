#!/usr/bin/env bash
# Runs once on first boot via GCP instance metadata startup-script.
# Prepares the OS: creates the zerox1 user, directories, and installs systemd units.
# Binaries are deployed separately via deploy-binaries.sh.

set -euo pipefail

# ── System setup ─────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y --no-install-recommends curl ca-certificates

# Create a dedicated non-root user for the zerox1 services.
useradd -r -s /bin/false zerox1 2>/dev/null || true

# Directories.
mkdir -p /opt/zerox1/bin
mkdir -p /var/lib/zerox1          # keypairs + SQLite DB
mkdir -p /var/log/zerox1
chown -R zerox1:zerox1 /opt/zerox1 /var/lib/zerox1 /var/log/zerox1

# Generate a node keypair on first boot (32 raw bytes, Ed25519 seed).
KEYFILE="/var/lib/zerox1/identity.key"
if [ ! -f "$KEYFILE" ]; then
  dd if=/dev/urandom bs=32 count=1 of="$KEYFILE" 2>/dev/null
  chmod 600 "$KEYFILE"
  chown zerox1:zerox1 "$KEYFILE"
  echo "Generated new keypair at $KEYFILE"
fi

echo "Startup complete. Deploy binaries with deploy-binaries.sh."
