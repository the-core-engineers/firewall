# Firewall Implementation Overview

This document outlines the architecture, data models, and features of the Enterprise Hybrid Firewall project.

## Architecture
The system is divided into three primary components:
1. **Control Plane (`/core`)**: A Python/FastAPI backend that serves the REST API and WebUI. It manages rules, blocklists, logs, and settings in a SQLite database (`firewall.db`). It communicates enforcement changes to the Rust Data Plane via instant UDP IPC signals.
2. **Data Plane (`/core/rust-engine`)**: A Rust daemon built with the `aya` eBPF framework. It attaches an XDP program to the NIC for hardware-level IP blocking, generates `nftables` rulesets for complex stateful rules, and tails Suricata's `eve.json` for automatic IPS threat mitigation.
3. **Web UI (`/webui`)**: A React/Vite frontend built using the IBM Carbon Design System (`@carbon/react`) for a professional, responsive user experience.

## Data Models & Storage
All state is persisted in a local SQLite database (`firewall.db`) within the `/core` directory.
- `rules`: Stores firewall rules (ALLOW, BLOCK, DROP) with associated filters (Protocol, Source/Dest IP, Source/Dest Port). These are enforced via `nftables` by the Rust Data Plane.
- `blocklist`: A dedicated table of IPs that are blocked at the XDP hardware level. The Flood Detector and Suricata IPS auto-mitigation populate this automatically.
- `settings`: A key-value store for engine configurations, such as `rate_limit` (max packets/min) and `flood_threshold` (max packets/sec).
- `logs`: Historical packet logs detailing the action taken on processed packets.

## Packet Filtering Pipeline
Packets are filtered across two enforcement layers:

### Layer 1: XDP (eBPF Hardware Level)
When a packet arrives at the NIC, the XDP program checks its source IP against the `BLOCKLIST` eBPF HashMap. If found, the packet is dropped instantly at the driver level (`XDP_DROP`) — before the Linux kernel even allocates memory for it. This is used for:
- All IPs in the blocklist table
- Suricata IPS auto-blocked IPs (Severity 1-2 alerts)

### Layer 2: nftables (Linux Netfilter)
Packets that pass XDP enter the Linux kernel networking stack and are evaluated by `nftables` rules in the `inet firewall custom_rules` chain. These rules handle complex 5-tuple matching:
- Protocol (TCP, UDP, ICMP)
- Source/Destination IP
- Source/Destination Port
- Action (ACCEPT, DROP, REJECT)

### IPC Flow (WebUI → Enforcement)
1. User adds a rule or blocks an IP via the React WebUI.
2. FastAPI writes the change to SQLite and sends a UDP `SYNC` packet to `127.0.0.1:9999`.
3. The Rust daemon receives the signal and instantly syncs the XDP map and regenerates the nftables ruleset.

## Web UI
The Web UI connects to the Control Plane and provides several views:
- **Dashboard**: Real-time packet statistics and traffic graphs.
- **Live Capture**: Suricata-backed real-time view of the last 50 packets processed.
- **Firewall Rules**: Manage protocol, IP, and port rules (enforced via nftables).
- **Blocklist**: View and manage the XDP hardware blocklist.
- **Settings**: Adjust Rate Limiter and Flood Detector thresholds dynamically.
- **Logs**: View and clear historical database logs.
- **Packet Tester**: Simulate an incoming packet and see exactly how the engine would evaluate it.

## Deployment
This firewall runs exclusively on **Fedora Linux** due to its reliance on eBPF/XDP and nftables. See `core/rust-engine/README.md` for compilation instructions and `manual/TESTING_GUIDE.md` for the comprehensive testing guide.
