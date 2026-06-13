#!/bin/bash
# suricata/setup.sh
# ─────────────────
# Run this ONCE on the target Linux machine to install and configure Suricata.
# The Rust engine writes /etc/suricata/linuxshield.yaml at runtime,
# but the binary and rule files need to be in place first.

set -euo pipefail

echo "[1/4] Installing Suricata..."
apt-get update -q
apt-get install -y suricata suricata-update

echo "[2/4] Downloading Emerging Threats Open ruleset..."
suricata-update update-sources
suricata-update enable-source et/open
suricata-update

echo "[3/4] Disabling the default systemd service (engine manages it)..."
# The Rust engine spawns Suricata itself in NFQUEUE mode.
# If you prefer to run Suricata as a system service, set
# LINUXSHIELD_SURICATA_SYSTEM=1 in the engine's environment.
systemctl stop suricata  2>/dev/null || true
systemctl disable suricata 2>/dev/null || true

echo "[4/4] Creating log directory..."
mkdir -p /var/log/suricata
chmod 750 /var/log/suricata

echo ""
echo "✓ Suricata installed.  The Rust engine will start it automatically."
echo "  To check logs: tail -f /var/log/suricata/eve.json"
