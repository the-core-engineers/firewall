#!/bin/bash
# run.sh  —  Build and start LinuxShield
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./run.sh              — build everything and start
#   ./run.sh build-only   — compile Rust without starting
#   ./run.sh api-only     — start FastAPI only (no Rust engine)
#
# Prerequisites:
#   - Rust (nightly for eBPF target): rustup install nightly
#   - bpf target: rustup target add bpfel-unknown-none --toolchain nightly
#   - cargo-bpf / aya tooling: cargo install bpf-linker
#   - nftables: apt-get install nftables
#   - Suricata: ./suricata/setup.sh
#   - Python 3.11+: pip install -r core/requirements.txt
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

IFACE="${LINUXSHIELD_IFACE:-eth0}"
DB_PATH="${LINUXSHIELD_DB:-$(pwd)/core/firewall.db}"

echo "═══════════════════════════════════════════"
echo "  LinuxShield — starting on interface $IFACE"
echo "═══════════════════════════════════════════"

# ── Step 1: Compile the XDP eBPF program (BPF target) ─────────────────────────
echo ""
echo "[1/3] Compiling XDP eBPF program..."
cargo +nightly build \
    -p xdp-firewall \
    --target bpfel-unknown-none \
    --release \
    -Z build-std=core

echo "      ✓ xdp-firewall compiled"

# ── Step 2: Compile the Rust engine (host target) ─────────────────────────────
echo ""
echo "[2/3] Compiling Rust engine..."
cargo build -p linuxshield-engine --release
echo "      ✓ linuxshield-engine compiled"

if [ "${1:-}" = "build-only" ]; then
    echo "Build complete (build-only mode)."
    exit 0
fi

if [ "${1:-}" = "api-only" ]; then
    echo "[3/3] Starting FastAPI only (no Rust engine)..."
    cd core && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    exit 0
fi

# ── Step 3: Start both the engine and FastAPI ─────────────────────────────────
echo ""
echo "[3/3] Starting services..."

# Start the Rust engine in the background (needs root for BPF + nftables)
LINUXSHIELD_IFACE="$IFACE" \
LINUXSHIELD_DB="$DB_PATH" \
RUST_LOG="linuxshield_engine=info,warn" \
    sudo -E ./target/release/linuxshield-engine &

ENGINE_PID=$!
echo "      Rust engine PID: $ENGINE_PID"

# Give the engine a moment to attach XDP and apply nftables
sleep 2

# Start FastAPI (no root needed)
echo "      Starting FastAPI..."
cd core && uvicorn main:app --host 0.0.0.0 --port 8000 &
API_PID=$!
echo "      FastAPI PID: $API_PID"

echo ""
echo "═══════════════════════════════════════════"
echo "  LinuxShield running:"
echo "    API:    http://0.0.0.0:8000"
echo "    Engine: http://127.0.0.1:7070  (internal)"
echo "    XDP:    attached to $IFACE"
echo ""
echo "  Press Ctrl+C to stop."
echo "═══════════════════════════════════════════"

# Wait for either process to exit
wait $ENGINE_PID $API_PID
