# Packet Filtering Firewall - Architecture and Implementation

## Overview
This project implements an enterprise-grade network firewall with a hybrid architecture:
- A **Python/FastAPI Control Plane** with a **React/Carbon Design WebUI** for configuration and monitoring.
- A **Rust Data Plane** using eBPF/XDP (via the `aya` framework) and `nftables` for high-performance packet filtering at the Linux kernel and NIC hardware level.
- **Suricata IPS** for deep packet inspection, with automatic threat mitigation fed back into the XDP layer.

## Components

### Control Plane (Python FastAPI + React WebUI)
The Control Plane serves the web interface and REST API. It does **not** perform any packet filtering itself. Instead, it writes rules and blocklists to a shared SQLite database (`firewall.db`) and sends instant UDP IPC sync signals to the Rust Data Plane daemon.

- **API Endpoints**:
  - `GET /rules`, `POST /rules`, `DELETE /rules/{id}`: Manage firewall rules (synced to nftables via Rust).
  - `GET /blocklist`, `POST /blocklist`, `DELETE /blocklist/{id}`: Manage IP blocklist (synced to XDP eBPF map via Rust).
  - `POST /capture/start`, `POST /capture/stop`: Control the Suricata-backed live capture view.
  - `POST /test`: Evaluate a simulated packet against current rules.

### Data Plane (Rust Daemon + eBPF/XDP + nftables)
The Rust daemon is the enforcement engine. It runs as a privileged `root` process and:
1. **Listens for UDP IPC signals** on `127.0.0.1:9999` from the Python FastAPI backend.
2. **Syncs the blocklist** from SQLite into the XDP eBPF `BLOCKLIST` HashMap for instant NIC-level hardware drops.
3. **Generates nftables rulesets** from the SQLite `rules` table for complex stateful filtering (TCP/UDP port rules, ICMP, etc.).
4. **Tails Suricata's `eve.json`** and auto-injects high-severity threat IPs into the XDP map.

### Frontend (React / Vite)
The frontend is a Single Page Application (SPA) built with React and Vite. It uses the IBM Carbon Design System for a clean, professional UI.
- **Dashboard**: Real-time statistics (packets analyzed, allowed, dropped, blocked).
- **Live Capture**: Displays real-time Suricata-backed packet data with Start/Stop/Clear controls.
- **Firewall Rules**: Interface to view, add, and remove firewall rules (enforced via nftables).
- **Blocklist**: Manage IPs blocked at the XDP hardware level.
- **Packet Tester**: Simulate a network packet and see the engine's verdict.
- **Settings**: Configure rate limits, flood thresholds, and UI theme.

## Design Decisions
1. **Hybrid Architecture**: The Control Plane (Python) is decoupled from the Data Plane (Rust). Python handles UI and API concerns; Rust handles all kernel-level enforcement.
2. **XDP for Blocklists**: IP blocklists are enforced at the NIC driver layer via eBPF XDP, achieving zero-CPU-cost packet drops for DDoS mitigation.
3. **nftables for Complex Rules**: Multi-field rules (protocol + IP + port combinations) are enforced via the Linux Netfilter `nftables` subsystem, which handles stateful inspection that XDP cannot.
4. **Instant IPC**: The Python backend sends a UDP `SYNC` signal to the Rust daemon on every rule or blocklist mutation, ensuring sub-millisecond enforcement latency.
5. **Suricata Integration**: Suricata provides deep packet inspection (IPS). High-severity alerts are automatically fed into the XDP blocklist by the Rust daemon.
6. **Linux Only**: Due to the reliance on eBPF/XDP and nftables, this firewall runs exclusively on Linux (Fedora).
