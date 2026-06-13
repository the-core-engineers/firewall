# Comprehensive Testing Guide: Enterprise Hybrid Firewall

This manual will guide you through setting up, running, and completely testing the hybrid architecture (Python FastAPI Control Plane + Rust XDP/nftables Data Plane) on your target Linux machine.

## Prerequisites

1. **Linux Virtual Machine / Bare Metal:** This system relies on native Linux kernel features (eBPF, XDP, and nftables). It **cannot** be run natively on macOS. 
2. **Root Access:** eBPF map manipulation and `nftables` require `sudo` privileges.
3. **Suricata:** Must be installed to provide Deep Packet Inspection (IPS) and to drive the Live Capture UI.

---

## Part 1: Compilation & Setup

### 1. Install Rust & eBPF Toolchain
On your Linux machine, install the Nightly Rust compiler and the eBPF linker:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

### 2. Compile the Rust Data Plane
Navigate to the Rust engine directory and compile both the kernel and userspace programs:
```bash
cd core/rust-engine

# Compile the XDP kernel program first
cd rust-engine-ebpf
cargo +nightly build --target ebpfel-unknown-none -Z build-std=core --release

# Compile the userspace daemon
cd ../rust-engine
cargo build --release
```

---

## Part 2: Running the System

You must run both the Python Control Plane (for the React UI) and the Rust Data Plane (for the actual firewalling) simultaneously.

### 1. Start the Python Control Plane
In a terminal, navigate to the `core/` directory and start FastAPI:
```bash
cd core/
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```
*Your React WebUI will now be accessible, allowing you to log in and configure rules.*

### 2. Start the Rust Data Plane
In a second terminal, navigate to the compiled Rust daemon and run it as `root`:
```bash
cd core/rust-engine/rust-engine
sudo RUST_LOG=info ./target/release/rust-engine
```
*You will see logs confirming the daemon has attached the XDP program to the Network Interface (default `eth0`), and is listening for UDP IPC signals on `127.0.0.1:9999`.*

---

## Part 3: Testing the Architecture

### Test 1: Live Capture (Suricata)
**Goal:** Verify the React UI still receives real-time packet data.
1. Open the React WebUI Dashboard.
2. Click **Start Capture**.
3. *Expected Result:* The Python backend begins tailing `/var/log/suricata/eve.json`. You will see the Live Traffic graph populate, and the real-time packet list fill with network flows. **Yes, the Live Capture frontend continues to work perfectly!**

### Test 2: Instant XDP Hardware Drop (Blocklist)
**Goal:** Verify the WebUI instantly pushes IP blocklist entries to the Rust eBPF map.
1. Ping your Linux VM from a secondary device (e.g., your laptop): `ping <linux_vm_ip>` -> *Pings should succeed.*
2. In the React WebUI, navigate to the **Blocklist** tab.
3. Add the IP address of your secondary device.
4. *Expected Result:* 
   - The Python API instantly fires a UDP `SYNC` packet.
   - The Rust console logs: `Received IPC SYNC signal from Python! Executing instant hardware sync.`
   - Your `ping` from the secondary device instantly stops receiving replies.
   - The packet is dropped at the NIC driver layer (XDP), consuming 0 CPU.

### Test 3: Complex NFTables Routing (Rules)
**Goal:** Verify the WebUI pushes complex stateful routing rules to `nftables`.
1. In the React WebUI, navigate to the **Rules** tab.
2. Add a new rule: `Action: DROP`, `Protocol: TCP`, `Dest Port: 8000`.
3. *Expected Result:*
   - The Python API fires the UDP `SYNC` packet.
   - The Rust daemon queries the SQLite database, generates an optimized `nftables` script, and executes it.
   - Run `sudo nft list ruleset` in your Linux terminal. You will see the `custom_rules` chain dynamically populated with `tcp dport 8000 drop`.
   - Any HTTP traffic attempting to reach port 8000 is now dropped by the kernel Netfilter stack.

### Test 4: Suricata Auto-IPS Mitigation
**Goal:** Verify Suricata alerts automatically trigger XDP drops via Rust.
1. Ensure the React UI Settings have **"IPS Mode"** enabled.
2. Use an attacker machine to send a known malicious payload to the Linux VM (e.g., an Nmap aggressive scan, or an exploit payload).
3. *Expected Result:*
   - Suricata detects the signature and writes a Severity 1 or 2 alert to `eve.json`.
   - The Rust daemon (which is tailing `eve.json`) detects the alert.
   - The Rust daemon instantly injects the attacker's IP directly into the XDP eBPF map.
   - The Rust console logs: `Suricata Alert! Fast-path hardware drop for IP: <attacker_ip>`.
   - The attacker is instantly locked out at the hardware layer.
