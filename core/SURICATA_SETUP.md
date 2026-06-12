# Suricata & pf Configuration Guide (macOS)

This document provides the instructions necessary to deploy the Intrusion Detection System (Suricata) and kernel-level packet filtering (`pf`) on your target macOS environment. 

> **WARNING**: Do not execute these steps on your development machine unless you explicitly intend to start intercepting traffic locally.

## 1. Prerequisites (macOS & Linux)

### macOS (Host Machine)
Ensure you have Homebrew installed on the target machine.
```bash
brew update
brew install suricata
```

### Linux (Ubuntu Server 22.04 / 24.04)
Suricata is maintained in an official PPA by the OISF.
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```

## 2. Suricata Configuration (`suricata.yaml`)

- **macOS:** `/opt/homebrew/etc/suricata/suricata.yaml` (Apple Silicon) or `/usr/local/etc/suricata/suricata.yaml` (Intel).
- **Linux:** `/etc/suricata/suricata.yaml`

You must modify `suricata.yaml` to ensure it outputs its JSON logs directly to the firewall's `core` directory so the Python orchestrator can read them in real-time.

Find the `outputs` section and configure `eve-log`:

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

## 3. Managing Suricata Rules
Suricata uses the Emerging Threats (ET) ruleset by default. To download and update the rules to the latest signatures, run:

```bash
sudo suricata-update
```
This will place the consolidated rules file in `/opt/homebrew/var/lib/suricata/rules/suricata.rules`. Ensure your `suricata.yaml` points to this file in the `rule-files:` section.

## 4. Running the Engine

The Python orchestrator (`core/engine.py`) has been rewritten to manage macOS `pf` and tail the `eve.json` file. 

To start the packet capture and DPI on the target machine, you will need to start Suricata explicitly targeting the active network interface (e.g., `en0` for Wi-Fi).

```bash
sudo suricata -c /opt/homebrew/etc/suricata/suricata.yaml -i en0
```

Once Suricata is running and writing to `eve.json`, start your FastAPI backend:

```bash
sudo python3 -m uvicorn main:app --reload
```

## 5. OS-Agnostic Kernel Integration (`pf` & `iptables`)
The Python backend (`core/engine.py`) has been fully abstracted to operate natively on both macOS and Linux.

- **On macOS:** It automatically generates a `pf_custom.conf` file and injects it into Apple's kernel using `pfctl`.
- **On Linux:** It automatically generates an `iptables_custom.rules` file and injects it into the Netfilter stack using `iptables-restore` (linked to a custom `SURICATA_BLOCKS` chain).

**Note:** Both `pf` and `iptables` require root privileges to manipulate kernel routing tables. The Python backend **must** be run with `sudo` for any rule enforcement or IPS auto-blocking to function.

## 6. Enterprise Performance Optimization (Linux Only)
Deep Packet Inspection is inherently CPU-intensive. To deploy this firewall in a high-throughput enterprise environment without bottlenecking the CPU, you must apply the following optimizations in `suricata.yaml` and your Linux OS:

### A. eBPF / XDP (eXpress Data Path)
XDP allows Linux to drop packets directly at the Network Interface Card (NIC) driver level, bypassing the Linux kernel networking stack entirely.
- In `suricata.yaml`, enable `ebpf:` and `xdp-mode: hw` (hardware offload).
- When a threat is detected, Suricata compiles the block rule into eBPF bytecode and pushes it to the NIC, saving massive CPU cycles.

### B. Fast Packet Acquisition (`AF_PACKET`)
Do not use standard `pcap` on Linux for high speeds. 
- In `suricata.yaml`, configure the `af-packet:` section. Set `cluster-type: cluster_flow` and enable `tpacket-v3`. This allows the Linux kernel to load-balance packets across multiple Suricata worker threads efficiently.

### C. BPF Pre-Filtering
Not all traffic needs Deep Packet Inspection. Encrypted video streaming (e.g., Netflix, YouTube) uses massive bandwidth but cannot be deeply inspected anyway. 
- Create a `bpf-filter` to bypass DPI for heavy, trusted streaming domains or specific subnets. This immediately reduces Suricata's CPU load by 40-60%.

### D. CPU Pinning (Worker Threads)
Configure `threading:` in `suricata.yaml`. Pin the management/capture threads to CPU Core 0, and pin the worker threads exclusively to Cores 1-N. This prevents the Linux scheduler from moving threads around, significantly reducing L3 cache misses and context-switching latency.
