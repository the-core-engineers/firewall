# Technical Documentation: Comprehensive Firewall Architecture

This document provides a comprehensive technical overview of the current working state of the Advanced Next-Generation Network Firewall. It details both the Python FastAPI backend engine and the React Carbon frontend, outlining how they communicate securely and reliably.

---

## 1. System Architecture Overview

The firewall operates on a decoupled architecture:
1. **Backend Packet Inspection Engine**: A Python application built with `FastAPI` and `Scapy`. It handles real-time network sniffing, rule evaluation, database storage, and API endpoints.
2. **Frontend UI**: A React application utilizing the IBM Carbon Design System. It polls the backend for analytics and provides an interface for dynamic rule management and live traffic monitoring.

---

## 2. Backend Inspection Engine (`core/`)

The backend is structurally decoupled into logical domains: models, routing, database, and the packet processing engine.

### 2.1 Database & Schemas (`database.py` & `models.py`)
The firewall uses asynchronous SQLite (`aiosqlite`) to persist state across sessions. The primary tables and schemas enforce specific data formatting constraints:
- **`rules`**: Stores firewall policies. The Pydantic model (`Rule`) rigorously enforces **camelCase** for properties like `srcIp`, `dstIp`, `srcPort`, and `dstPort`.
- **`blocklist`**: Dynamically isolates hostile IPs. Entries require an internally generated UUID (`id`) and the target `ip`.
- **`logs`**: Records the verdict (ALLOW, DROP, BLOCK) of network packets matching rules. It returns rows containing camelCase properties (`srcIp`, `dstPort`) to the frontend.
- **`settings`**: A simple Key-Value store managing global config like `rate_limit` and `theme`.

### 2.2 Packet Processing Logic (`engine.py`)
The `Scapy` sniffing loop operates in a daemonized background thread to prevent blocking the REST API.
- **Rate Limiting**: An in-memory sliding window algorithm tracks packet counts per IP. Any IP exceeding the `flood_threshold` (per second) is immediately appended to the blocklist. Any IP exceeding the `rate_limit` (per minute) is dropped.
- **Rule Evaluation**: Packets are evaluated against the ordered `rules` table. If properties match, the assigned `action` (ALLOW/DROP) is executed.
- **Telemetry Buffering**: Packets analyzed per second are aggregated into asynchronous "delta" batches. This ensures the frontend UI receives clean packets/second statistics rather than raw individual throughput lines.

### 2.3 REST API Design (`api/`)
The FastAPI router exposes modularized endpoints:
- **`POST /login`**: Uses JWT for session security. Requires standard `application/json` payload matching `LoginRequest`.
- **`GET /capture/status`**: Returns `{"status": "working"}` or `{"status": "stopped"}`.
- **`POST /capture/clear`**: Safely flushes the live packet buffer (`captured_packets.clear()`) without interrupting the active sniffer.
- **`POST /settings`**: Strictly requires individual Key-Value payloads (e.g., updating the rate limit requires a discrete POST, rather than a monolithic PUT of the whole settings array).
- **`POST /test`**: Simulates packets passing through the engine. Requires a `PacketTest` model (camelCase).

---

## 3. Frontend WebUI Architecture (`webui/src/`)

The monolithic React frontend was successfully debundled into a scalable, Context API-driven architecture.

### 3.1 Global State Management (`context/`)
1. **`AuthContext.jsx`**: Manages the local storage `fw_token`, user login, and automatically injects the `Bearer` token into all outgoing requests via the `authFetch` wrapper.
2. **`AppContext.jsx`**: The single source of truth for all global data. It establishes background intervals (e.g., polling `fetchStats` every 1 second) and strictly parses JSON responses to conform to backend expectations (e.g., mapping `data.status === 'working'` to the `isCapturing` boolean).

### 3.2 Dynamic Pages (`pages/`)
Each interactive page handles isolated functionality:
- **`Rules.jsx` & `Blocklist.jsx`**: When users input new entries, the React components explicitly parse snake_case local state (e.g., `src_ip`) into the camelCase JSON payload (`srcIp`) required by the FastAPI backend models. Deletions strictly pass the backend UUID (`id`).
- **`Settings.jsx`**: Interates over modified local settings and pipelines individual `POST` events to update the backend gracefully.
- **`Logs.jsx` & `LiveCapture.jsx`**: Implements a unified color-coding design system across the application (ALLOW = Green, BLOCK = Red, DROP = Magenta).

### 3.3 Application Shell (`components/AppShell.jsx`)
Dictates the master layout. It relies on Carbon's `isRail={true}` property. When the user collapses the navigation drawer, it condenses into a narrow rail keeping icons permanently visible, thus preserving core navigation flows without restricting dashboard screen real estate. The `AppShell` preserves native Carbon margin mappings to ensure the `<Content>` element dynamically clears the master header without CSS clipping.
