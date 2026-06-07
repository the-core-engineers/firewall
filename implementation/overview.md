# Firewall Implementation Overview

This document outlines the architecture, data models, and features of the Packet Filtering Firewall project.

## Architecture
The system is divided into two primary components:
1. **Core Engine (`/core`)**: A Python/FastAPI backend that uses `scapy` for live packet capture (sniffing) and evaluation. It exposes a REST API for the Web UI.
2. **Web UI (`/webui`)**: A React/Vite frontend built using the IBM Carbon Design System (`@carbon/react`) for a professional, responsive user experience.

## Data Models & Storage
All state is persisted in a local SQLite database (`firewall.db`) within the `/core` directory.
- `rules`: Stores firewall rules (ALLOW, BLOCK, DROP) with associated filters (Protocol, Source/Dest IP, Source/Dest Port).
- `blocklist`: A dedicated table of IPs that are permanently blocked. IPs here bypass all rules and are immediately dropped. The Flood Detector populates this automatically.
- `settings`: A key-value store for Core configurations, such as `rate_limit` (max packets/min) and `flood_threshold` (max packets/sec).
- `logs`: Historical packet logs detailing the action taken on processed packets.

## Packet Filtering Features
When the Core Engine captures a packet, it is evaluated in the following order:

1. **Blocklist Evaluation (Highest Priority):**
   - The packet's source IP is checked against the permanent Blocklist. If found, it is immediately dropped.
2. **Flood Detection:**
   - The engine tracks the number of packets from each IP per second.
   - If an IP exceeds the configured `flood_threshold`, it is considered a flood attack (e.g., SYN flood or DoS). The IP is permanently added to the Blocklist and future packets are dropped.
3. **Rate Limiting:**
   - The engine tracks the number of packets from each IP per minute.
   - If an IP exceeds the configured `rate_limit`, its packets are dropped for the remainder of the minute.
4. **Rule Evaluation:**
   - The packet is tested against user-defined rules.
   - Filters include Protocol (TCP, UDP, ICMP), Source/Dest IP, and Source/Dest Port.
   - The first matching rule dictates the action (ALLOW, BLOCK, DROP).
5. **Default Policy:**
   - If no blocklist, rate limits, or rules apply, the packet is ALLOWED by default.

## Web UI
The Web UI connects to the Core Engine and provides several views:
- **Live Network Filter**: A real-time view of the last 50 packets processed.
- **Firewall Rules**: Manage protocol, IP, and port rules.
- **Blocklist**: View and manage the permanent blocklist.
- **Settings**: Adjust Rate Limiter and Flood Detector thresholds dynamically.
- **Logs**: View and clear historical database logs.
- **Packet Tester**: A tool to simulate an incoming packet and see exactly how the engine would evaluate it.
