# Comprehensive Testing Guide: Enterprise Hybrid Firewall

This manual provides a complete, step-by-step guide to deploy, run, and test the entire hybrid firewall system on a **Fedora Linux** machine. Follow every section in order.

> **Important:** This system relies on native Linux kernel features (eBPF, XDP, nftables) and **cannot** run on macOS or Windows.

---

## Part 1: System Prerequisites

### 1.1 Install System Packages
```bash
# Development tools (needed for Rust compilation)
sudo dnf groupinstall "Development Tools"
sudo dnf install clang llvm elfutils-libelf-devel zlib-devel

# Suricata IPS
sudo dnf install suricata jq

# Python
sudo dnf install python3 python3-pip

# Node.js (for the React WebUI)
sudo dnf install nodejs npm

# nftables (usually pre-installed on Fedora)
sudo dnf install nftables
```

### 1.2 Install the Rust Toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install the nightly compiler and eBPF linker
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

### 1.3 Verify All Prerequisites
```bash
rustc --version          # Should show nightly
python3 --version        # Should show 3.10+
node --version           # Should show 18+
suricata --build-info | head -3
sudo nft --version
```

---

## Part 2: Suricata Setup

### 2.1 Configure Suricata Output
Edit the Suricata configuration file:
```bash
sudo nano /etc/suricata/suricata.yaml
```

Find the `outputs` section and configure `eve-log` to write to the firewall's `core/` directory:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /absolute/path/to/FirewallRepo/core/eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
        - flow
        - drop
```
> **Replace** `/absolute/path/to/FirewallRepo` with the actual path where you cloned the repository.

### 2.2 Configure the Network Interface
In the same `suricata.yaml`, find the `af-packet` section and set your active network interface:
```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```
> Run `ip link show` to find your interface name (e.g., `eth0`, `ens33`, `enp0s3`).

### 2.3 Download Threat Signatures
```bash
sudo suricata-update
```
Verify the rules are installed:
```bash
ls /var/lib/suricata/rules/suricata.rules
```

### 2.4 Validate the Configuration
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```
This performs a dry-run. If it prints `Configuration provided was successfully loaded`, Suricata is ready.

---

## Part 3: Compile the Rust Data Plane

### 3.1 Compile the eBPF Kernel Program
```bash
cd core/rust-engine/rust-engine-ebpf
cargo +nightly build --target ebpfel-unknown-none -Z build-std=core --release
```
This compiles the XDP program that will be injected into your NIC driver.

### 3.2 Compile the Userspace Daemon
```bash
cd ../rust-engine
cargo build --release
```
This compiles the Rust daemon that manages the eBPF maps, nftables rules, and Suricata tailing.

---

## Part 4: Install the Python Control Plane

```bash
cd core/
pip3 install -r requirements.txt
```

---

## Part 5: Install the React WebUI

```bash
cd webui/
npm install
```

---

## Part 6: Running the System

You need **4 terminals** (or use `tmux`/`screen`) to run all components simultaneously.

### Terminal 1: Start Suricata
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```
> Replace `eth0` with your actual interface name from Part 2.

### Terminal 2: Start the Rust Data Plane
```bash
cd core/rust-engine/rust-engine
sudo RUST_LOG=info ./target/release/rust-engine
```
You should see:
```
INFO  rust_engine > Rust Data Plane orchestrator started. Watching DB and Suricata...
INFO  rust_engine > Listening for IPC SYNC signals on UDP 127.0.0.1:9999...
```

### Terminal 3: Start the Python Control Plane (FastAPI)
```bash
cd core/
uvicorn main:app --host 0.0.0.0 --port 8000
```
You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Terminal 4: Start the React WebUI
```bash
cd webui/
npm run dev -- --host 0.0.0.0
```
You should see:
```
  VITE v5.x.x  ready in Xms
  ➜  Local:   http://localhost:5173/
  ➜  Network: http://<your-ip>:5173/
```

### Access the WebUI
Open a browser and navigate to:
- **From the same machine:** `http://localhost:5173`
- **From another machine on the network:** `http://<linux-machine-ip>:5173`

**Default login credentials:**
- Username: `admin`
- Password: `admin`

---

## Part 7: Testing the Architecture

### Test 1: Live Capture (Suricata)
**Goal:** Verify the React UI receives real-time packet data from Suricata.

1. Log into the WebUI.
2. Navigate to **Live Capture**.
3. Click **Start Capture**.
4. From another terminal, generate some network traffic:
   ```bash
   curl https://google.com
   ping 8.8.8.8 -c 5
   ```
5. **Expected Result:** The Live Traffic table populates with flow entries showing protocol, source/destination IPs, and ports.

---

### Test 2: Instant XDP Hardware Drop (Blocklist)
**Goal:** Verify the WebUI instantly pushes IP blocklist entries to the XDP eBPF map.

1. From a second machine on the same network, ping the Linux firewall:
   ```bash
   ping <linux-firewall-ip>
   ```
   → Pings should succeed.
2. In the WebUI, navigate to **Blocklist**.
3. Add the IP address of the second machine. Set Reason to `Test block`.
4. **Expected Result:**
   - In **Terminal 2** (Rust), you see:
     ```
     INFO  rust_engine > Received IPC SYNC signal from Python! Executing instant hardware sync.
     ```
   - The `ping` from the second machine **instantly stops receiving replies**.
   - The packet is dropped at the NIC driver layer (XDP), consuming 0 CPU.
5. **Cleanup:** Remove the IP from the Blocklist in the WebUI.

---

### Test 3: Complex NFTables Routing (Rules)
**Goal:** Verify the WebUI pushes complex stateful routing rules to nftables.

1. In the WebUI, navigate to **Firewall Rules**.
2. Add a new rule:
   - Action: `DROP`
   - Protocol: `TCP`
   - Dest Port: `8080`
   - Description: `Test TCP drop`
3. **Expected Result:**
   - In **Terminal 2** (Rust), you see the IPC sync log.
   - Verify in a new terminal:
     ```bash
     sudo nft list ruleset
     ```
     You should see the `custom_rules` chain containing `tcp dport 8080 drop`.
4. **Cleanup:** Delete the test rule from the WebUI.

---

### Test 4: Suricata Auto-IPS Mitigation
**Goal:** Verify Suricata alerts automatically trigger XDP drops via the Rust daemon.

1. Ensure Suricata is running (Terminal 1).
2. From an attacker machine, run a known malicious signature scan:
   ```bash
   # Nmap aggressive scan (triggers multiple Suricata signatures)
   sudo nmap -A -T4 <linux-firewall-ip>
   ```
3. **Expected Result:**
   - Suricata detects the signature and writes a Severity 1 or 2 alert to `eve.json`.
   - In **Terminal 2** (Rust), you see:
     ```
     INFO  rust_engine > Suricata Alert! Fast-path hardware drop for IP: <attacker-ip>
     ```
   - The attacker is instantly locked out at the hardware layer.

---

### Test 5: Packet Tester (Simulated)
**Goal:** Verify the Packet Tester evaluates rules correctly without touching the network.

1. In the WebUI, navigate to **Packet Tester**.
2. Fill in the form:
   - Protocol: `TCP`
   - Source IP: `192.168.1.100`
   - Dest IP: `8.8.8.8`
   - Dest Port: `443`
3. Click **Test Packet**.
4. **Expected Result:** The result tile shows `ALLOWED` with the reason matching an `Allow HTTPS` rule (or your default policy).

---

### Test 6: Dashboard Statistics
**Goal:** Verify that the Dashboard displays real-time packet counters.

1. Navigate to **Dashboard**.
2. Start a Live Capture from the **Live Capture** page.
3. Generate traffic from another terminal:
   ```bash
   for i in $(seq 1 50); do curl -s http://google.com > /dev/null; done
   ```
4. **Expected Result:** The Dashboard tiles update in real time showing increasing counters for Total Analyzed, Packets Allowed, Packets Dropped, and Packets Blocked.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `eBPF binary not found` in Rust logs | You forgot to compile the eBPF kernel program first (Part 3, Step 1) |
| `failed to attach the XDP program to interface eth0` | Your interface name is different. Check with `ip link show` and update the `iface` variable in `main.rs` |
| `Failed to bind UDP IPC port` | Another instance of the Rust daemon is already running. Kill it with `sudo pkill rust-engine` |
| Suricata won't start | Run `sudo suricata -T -c /etc/suricata/suricata.yaml` to validate the config |
| WebUI can't connect to API | Ensure FastAPI is running on port 8000 and that no firewall is blocking it. Check `webui/src/context/AuthContext.jsx` for the API URL |
| `nftables update failed` in Rust logs | Ensure `nftables` service is running: `sudo systemctl start nftables` |
| WebUI shows blank page | Run `npm install` in the `webui/` directory first |
