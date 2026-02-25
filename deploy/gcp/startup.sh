#!/usr/bin/env bash
# Runs once on first boot via GCP instance metadata startup-script.
# Prepares OS: users, directories, Rust toolchain (needed to build Kora).
# Binaries are deployed separately via deploy-binaries.sh.

set -euo pipefail

# ── System packages ──────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y --no-install-recommends \
  curl ca-certificates build-essential pkg-config libssl-dev git

# ── zerox1 system user ───────────────────────────────────────────────────────
useradd -r -s /bin/false zerox1 2>/dev/null || true

# ── Directories ──────────────────────────────────────────────────────────────
mkdir -p /opt/zerox1/bin
mkdir -p /var/lib/zerox1      # keypairs, SQLite DB
mkdir -p /var/log/zerox1
mkdir -p /etc/zerox1
chmod 755 /etc/zerox1
chown -R zerox1:zerox1 /opt/zerox1 /var/lib/zerox1 /var/log/zerox1

# ── Node identity keypair (generated once, never changes) ────────────────────
KEYFILE="/var/lib/zerox1/identity.key"
if [ ! -f "$KEYFILE" ]; then
  dd if=/dev/urandom bs=32 count=1 of="$KEYFILE" 2>/dev/null
  chmod 600 "$KEYFILE"
  chown zerox1:zerox1 "$KEYFILE"
  echo "Generated node identity keypair at $KEYFILE"
fi

# ── Rust (needed to build Kora) ──────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal
fi

echo "Startup complete. Run deploy-binaries.sh to install services."
