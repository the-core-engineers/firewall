# Core Backend — Developer Documentation

**Branch:** `beta-testing`  
**Location:** `core/`  
**Stack:** Python 3 · FastAPI · SQLite (aiosqlite) · JWT · Suricata · Rust/eBPF/XDP (Data Plane)  
**Last updated:** 2026-06-13

---

## Table of Contents

1. [Overview](#1-overview)
2. [Directory Structure](#2-directory-structure)
3. [Setup & Running](#3-setup--running)
4. [Database Layer — `database.py`](#4-database-layer--databasepy)
   - 4.1 [Schema](#41-schema)
   - 4.2 [Functions](#42-functions)
   - 4.3 [Default Seed Rules](#43-default-seed-rules)
5. [Data Models — `models.py`](#5-data-models--modelspy)
6. [Authentication — `login.py`](#6-authentication--loginpy)
7. [Control Plane Engine — `engine.py`](#7-control-plane-engine--enginepy)
   - 7.1 [Port Matching](#71-port-matching)
   - 7.2 [IPC Sync Trigger](#72-ipc-sync-trigger)
   - 7.3 [Live Capture (Suricata)](#73-live-capture-suricata)
   - 7.4 [Statistics & Traffic History](#74-statistics--traffic-history)
8. [Rust Data Plane — `rust-engine/`](#8-rust-data-plane--rust-engine)
9. [REST API Routes](#9-rest-api-routes)
   - 9.1 [Authentication](#91-authentication)
   - 9.2 [Rules — `/rules`](#92-rules----rules)
   - 9.3 [Blocklist — `/blocklist`](#93-blocklist----blocklist)
   - 9.4 [Logs — `/logs`](#94-logs----logs)
   - 9.5 [Capture — `/capture`](#95-capture----capture)
   - 9.6 [Packet Tester — `/test`](#96-packet-tester----test)
   - 9.7 [Settings — `/settings`](#97-settings----settings)
10. [Application Entry Point — `main.py`](#10-application-entry-point--mainpy)
11. [Known Limitations & TODOs](#11-known-limitations--todos)

---

## 1. Overview

The `core/` package implements the **Control Plane** of the firewall. It operates as a hybrid system:

- **REST API** — exposes all management functions (rules, blocklist, logs, settings, capture control, and a packet simulator) to the Web UI via a FastAPI application.
- **IPC Bridge** — when rules or blocklist entries are mutated via the API, the Control Plane sends an instant UDP `SYNC` signal to the Rust Data Plane daemon on `127.0.0.1:9999`, triggering hardware-level enforcement.
- **Live Capture** — tails Suricata's `eve.json` to provide real-time packet visibility in the WebUI.

**Actual packet filtering is NOT performed by Python.** All enforcement is handled by the Rust Data Plane (`core/rust-engine/`), which manages eBPF/XDP maps (for blocklist drops at the NIC) and `nftables` rulesets (for complex stateful rules).

All persistent state lives in a single SQLite file (`core/firewall.db`), which is created automatically on first run.

---

## 2. Directory Structure

```
core/
├── main.py               # FastAPI app factory; mounts all routers
├── database.py           # SQLite schema, CRUD helpers, async seeder
├── engine.py             # IPC trigger, Suricata live capture, statistics
├── login.py              # JWT auth, user table, route /login
├── models.py             # Pydantic request/response models
├── requirements.txt      # Python dependencies
├── SURICATA_SETUP.md     # Suricata deployment guide (Fedora Linux)
├── api/
│   ├── __init__.py
│   ├── rules.py          # GET/POST/DELETE /rules (triggers Rust IPC sync)
│   ├── blocklist.py      # GET/POST/DELETE /blocklist (triggers Rust IPC sync)
│   ├── logs.py           # GET/DELETE /logs
│   ├── capture.py        # POST /capture/start|stop|clear, GET /capture/status|packets|stats
│   ├── settings.py       # GET/POST /settings
│   └── tester.py         # POST /test
└── rust-engine/          # Rust Data Plane (eBPF/XDP + nftables)
    ├── Cargo.toml        # Workspace definition
    ├── README.md         # Compilation & deployment guide
    ├── rust-engine/      # Userspace daemon (Tokio async, UDP IPC, SQLite sync)
    ├── rust-engine-ebpf/ # eBPF kernel program (XDP BLOCKLIST map)
    └── rust-engine-common/ # Shared types between kernel and userspace
```

---

## 3. Setup & Running

### Prerequisites

- **Fedora Linux** (required for eBPF/XDP and nftables)
- Python 3.10+
- Rust Nightly + `bpf-linker` (for compiling the Data Plane)
- Suricata (for deep packet inspection and live capture)
- Node.js 18+ (for the Web UI only; not needed for the core alone)

### Install Python dependencies

```bash
cd core
pip install -r requirements.txt
```

**`requirements.txt` contents:**

| Package | Purpose |
|---|---|
| `fastapi` | REST framework |
| `uvicorn` | ASGI server |
| `pydantic` | Request/response validation |
| `aiosqlite` | Async SQLite driver |
| `bcrypt` | Password hashing |
| `python-jose` | JWT encoding/decoding |
| `python-multipart` | Form data parsing (FastAPI dependency) |

### Start the Control Plane (Python API)

```bash
cd core
uvicorn main:app --host 0.0.0.0 --port 8000
```

The API listens on `http://localhost:8000` by default. The interactive API explorer is available at `http://localhost:8000/docs`.

### Start the Data Plane (Rust Daemon)

See `core/rust-engine/README.md` for full compilation instructions. Once compiled:

```bash
cd core/rust-engine/rust-engine
sudo RUST_LOG=info ./target/release/rust-engine
```

> **Note:** Both the Control Plane and Data Plane must be running simultaneously. The Control Plane handles the WebUI and API; the Data Plane handles all kernel-level packet enforcement.

---

## 4. Database Layer — `database.py`

### 4.1 Schema

All tables are created by `init_db()` using synchronous SQLite on application start.

#### `rules`

Stores firewall policies. Evaluated in insertion order (first match wins).

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | TEXT PK | No | 8-char UUID prefix |
| `action` | TEXT | No | `ALLOW`, `BLOCK`, or `DROP` |
| `protocol` | TEXT | No | `TCP`, `UDP`, `ICMP`, `ALL` |
| `srcIp` | TEXT | Yes | Source IP filter (`NULL` = any) |
| `dstIp` | TEXT | Yes | Destination IP filter (`NULL` = any) |
| `srcPort` | TEXT | Yes | Source port specification (see §7.1) |
| `dstPort` | TEXT | Yes | Destination port specification (see §7.1) |
| `description` | TEXT | Yes | Human-readable label |

#### `logs`

Immutable audit trail. Written by `log_packet()` after every evaluated packet.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | Packet UUID |
| `timestamp` | TEXT | `YYYY-MM-DD HH:MM:SS` |
| `protocol` | TEXT | `TCP`, `UDP`, `ICMP`, `OTHER` |
| `srcIp` | TEXT | Source IP |
| `dstIp` | TEXT | Destination IP |
| `srcPort` | TEXT | Source port |
| `dstPort` | TEXT | Destination port |
| `action` | TEXT | `ALLOW`, `DROP`, or `BLOCK` |
| `reason` | TEXT | Human-readable verdict reason |

#### `settings`

Key-value store for engine configuration.

| Key | Default | Description |
|---|---|---|
| `rate_limit` | `1000` | Max packets per IP per **minute** before drop |
| `flood_threshold` | `100` | Max packets per IP per **second** before auto-block |
| `theme` | `white` | WebUI theme token |

#### `blocklist`

IPs in this table bypass all rules and are immediately blocked.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | 8-char UUID prefix |
| `ip` | TEXT | Blocked IP address |
| `reason` | TEXT | Why it was blocked |
| `timestamp` | TEXT | When it was added |

#### `users`

Managed by `login.py`, not `database.py`. Stores bcrypt-hashed credentials.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | 8-char UUID prefix |
| `username` | TEXT UNIQUE | Login username |
| `password_hash` | TEXT | bcrypt hash |

---

### 4.2 Functions

#### `init_db() → None`
Synchronous. Creates all four tables if they do not exist. Called once at application startup before the ASGI loop begins.

#### `get_db_data() → (rules, settings, blocklist)`
Synchronous. Returns a snapshot of all three runtime tables in a single connection. Called from `engine.py` inside the packet callback, which runs in a background thread (not the async event loop).

```python
rules, settings, blocklist = get_db_data()
# rules    : List[dict]  — full rows from `rules`
# settings : dict        — {key: value} from `settings`
# blocklist: List[str]   — just the IP strings from `blocklist`
```

#### `add_to_blocklist_sync(ip, reason) → None`
Synchronous. Adds an IP to the blocklist if not already present. Used by `engine.py` when flood detection fires, because that code runs outside the async event loop.

#### `log_packet(packet_info, action, reason) → None`
Synchronous. Inserts one row into `logs`. Called by `packet_callback()` after every evaluated packet.

#### `seed_db_async() → None` (async)
Called once on FastAPI startup via `@app.on_event("startup")`. Seeds default rules and settings **only if the tables are empty** — safe to call on every restart without creating duplicates.

---

### 4.3 Default Seed Rules

The seeder populates 33 rules covering web, DNS, SSH, mail, infrastructure, LDAP/AD, RPC, IPsec, and a comprehensive set of BLOCK rules for legacy/high-risk protocols. Port specifications use the formats described in §7.1.

Key seeded rules:

| Port(s) | Protocol | Action | Service |
|---|---|---|---|
| `80`, `443` | TCP | ALLOW | HTTP / HTTPS |
| `22` | TCP | ALLOW | SSH |
| `53` | UDP + TCP | ALLOW | DNS |
| `389`, `636` | TCP/UDP | ALLOW | LDAP / LDAP SSL |
| `135` | TCP | ALLOW | RPC Endpoint Mapper |
| `49152-65535` | TCP | ALLOW | RPC dynamic ports (range) |
| `500`, `4500` | UDP | ALLOW | IPsec IKE / NAT-T |
| `137` | UDP + TCP | BLOCK | NetBIOS Name Service (NBNS) |
| `445` | TCP | BLOCK | SMB (external) |
| `3389` | TCP | BLOCK | RDP (external) |
| `23` | TCP | BLOCK | Telnet |

---

## 5. Data Models — `models.py`

All models use **camelCase** field names to match the SQLite column names and the JSON expected by the Web UI.

### `Rule` (request body for `POST /rules`)

```python
class Rule(BaseModel):
    action: str               # "ALLOW" | "BLOCK" | "DROP"
    protocol: str             # "TCP" | "UDP" | "ICMP" | "ALL"
    srcIp: Optional[str]      # exact IP or None
    dstIp: Optional[str]
    srcPort: Optional[str]    # single / range / comma-list (see §7.1)
    dstPort: Optional[str]
    description: Optional[str]
```

### `RuleResponse` (returned by `GET /rules` and `POST /rules`)

Extends `Rule` with `id: str`.

### `PacketTest` (request body for `POST /test`)

```python
class PacketTest(BaseModel):
    protocol: str
    srcIp: str
    dstIp: str
    srcPort: Optional[str]
    dstPort: Optional[str]
    payload: Optional[str]    # not currently used by engine
```

### `SettingModel` (request body for `POST /settings`)

```python
class SettingModel(BaseModel):
    key: str
    value: str
```

### `BlocklistEntry` / `BlocklistResponse`

```python
class BlocklistEntry(BaseModel):
    ip: str
    reason: str

class BlocklistResponse(BlocklistEntry):
    id: str
    timestamp: str
```

---

## 6. Authentication — `login.py`

The module initialises the `users` table on import and seeds a default `admin` / `admin` account if no users exist.

> ⚠ **Change the default password** before any non-local deployment.

### JWT Configuration

| Parameter | Value |
|---|---|
| Algorithm | `HS256` |
| Token expiry | 24 hours (1440 minutes) |
| Secret key | `super-secret-firewall-key` (hardcoded — use an env var in production) |

### `POST /login`

**Request:**
```json
{ "username": "admin", "password": "admin" }
```

**Response (200):**
```json
{ "access_token": "<jwt>", "token_type": "bearer" }
```

**Response (401):**
```json
{ "detail": "Incorrect username or password" }
```

### `get_current_user(token)` dependency

All protected routes use `Depends(get_current_user)`. It decodes the JWT and returns the username string, or raises HTTP 401 if the token is missing, expired, or invalid.

---

## 7. Control Plane Engine — `engine.py`

### 7.1 Port Matching

The `port_matches(rule_port, packet_port)` helper supports three formats stored as plain TEXT in the database, with no schema changes needed:

| Format | Example | Behaviour |
|---|---|---|
| Single port | `'80'` | Exact integer comparison |
| Range (inclusive) | `'49152-65535'` | `low <= packet_port <= high` |
| Comma list | `'80,443,8080'` | Membership in set |

`packet_port` may be an `int` or a `str`. An empty/`None` rule port means "any" and always matches. A `None` or unparseable packet port always returns `False`.

```python
port_matches('49152-65535', 50000)  # True
port_matches('80,443',      443)    # True
port_matches('80',          8080)   # False
port_matches(None,          9999)   # True  (no restriction)
port_matches('80',          None)   # False (packet has no port)
```

### 7.2 IPC Sync Trigger

When any rule or blocklist mutation occurs via the REST API, the `trigger_rust_sync()` function sends a UDP `SYNC` packet to `127.0.0.1:9999`. The Rust Data Plane daemon receives this signal and instantly:
1. Reads the `blocklist` table from SQLite and syncs all IPs into the XDP eBPF `BLOCKLIST` HashMap.
2. Reads the `rules` table from SQLite, generates an optimized `nftables` configuration script, and executes `sudo nft -f` to apply the rules.

```python
def trigger_rust_sync():
    """Send instant UDP signal to Rust Data Plane daemon."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"SYNC", ("127.0.0.1", 9999))
        sock.close()
    except Exception as e:
        print(f"Warning: Could not signal Rust daemon: {e}")
```

This replaces the old Scapy-based packet sniffing and Python-level rule evaluation. **Python no longer performs any packet filtering.**

### 7.3 Live Capture (Suricata)

Live capture is now powered by **Suricata** deep packet inspection. The Python engine tails Suricata's `eve.json` log file to populate the real-time packet view in the WebUI. When the user clicks "Start Capture":
1. The engine begins reading new entries from `eve.json`.
2. Flow and alert events are parsed and converted into the packet format expected by the frontend.
3. Packets are appended to the `captured_packets` buffer (capped at 50 entries).

### 7.4 Statistics & Traffic History

`traffic_history` holds at most **120 entries** (60 seconds × 2 groups: Inbound / Outbound). Each entry is:

```json
{ "group": "Inbound", "date": "2026-06-09T10:00:01Z", "value": 1024 }
```

The WebUI's `AppContext` further derives a **packets/second delta** by computing `newStats.analyzed - prev.analyzed` on each polling cycle and pushing that into a separate 60-point rolling array for the sparkline.

---

## 8. Rust Data Plane — `rust-engine/`

The Rust Data Plane is the actual enforcement engine. It is a separate binary that runs as a privileged `root` process alongside the Python Control Plane.

### Architecture
- **eBPF Kernel Program** (`rust-engine-ebpf/`): An XDP program compiled for `ebpfel-unknown-none` using the `aya-ebpf` framework. It maintains a `BLOCKLIST` HashMap. For every packet arriving at the NIC, it checks the source IP against this map. Matches trigger `XDP_DROP` at the driver level.
- **Userspace Daemon** (`rust-engine/`): An async Tokio daemon that:
  1. Loads the eBPF program and attaches it to the network interface.
  2. Listens on `127.0.0.1:9999` (UDP) for `SYNC` signals from Python.
  3. On each signal, reads `firewall.db` and syncs blocklist IPs into the XDP map and generates/executes `nftables` rulesets.
  4. Tails Suricata's `eve.json` and auto-injects Severity 1-2 threat IPs into the XDP map.

For compilation and deployment instructions, see `core/rust-engine/README.md`.

---

## 9. REST API Routes

All routes except `POST /login` require a valid `Authorization: Bearer <token>` header.

When a mutation route (POST/DELETE on rules or blocklist) completes, the API calls `trigger_rust_sync()` to signal the Rust Data Plane for instant enforcement.

### 9.1 Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/login` | No | Returns a JWT token |

---

### 9.2 Rules — `/rules`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/rules` | Yes | List all rules |
| POST | `/rules` | Yes | Add a new rule (triggers Rust IPC sync → nftables update) |
| DELETE | `/rules/{rule_id}` | Yes | Delete a rule by ID (triggers Rust IPC sync → nftables update) |

**`POST /rules` — request body:**
```json
{
  "action": "ALLOW",
  "protocol": "TCP",
  "srcIp": null,
  "dstIp": null,
  "srcPort": null,
  "dstPort": "443",
  "description": "Allow HTTPS"
}
```

**`POST /rules` — response:**
```json
{
  "id": "a1b2c3d4",
  "action": "ALLOW",
  "protocol": "TCP",
  "srcIp": null,
  "dstIp": null,
  "srcPort": null,
  "dstPort": "443",
  "description": "Allow HTTPS"
}
```

Port fields accept single ports (`"80"`), ranges (`"49152-65535"`), or comma-separated values (`"80,443"`).

---

### 9.3 Blocklist — `/blocklist`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/blocklist` | Yes | List all blocked IPs |
| POST | `/blocklist` | Yes | Manually block an IP (triggers Rust IPC sync → XDP map update) |
| DELETE | `/blocklist/{entry_id}` | Yes | Remove a block by entry ID (triggers Rust IPC sync → XDP map update) |

**`POST /blocklist` — request body:**
```json
{ "ip": "192.168.1.100", "reason": "Manual block" }
```

Returns HTTP 400 if the IP is already in the blocklist.

---

### 9.4 Logs — `/logs`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/logs` | Yes | Last 100 log entries (newest first) |
| DELETE | `/logs` | Yes | Permanently delete all logs |

---

### 9.5 Capture — `/capture`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/capture/start` | Yes | Start tailing Suricata's eve.json for live capture |
| POST | `/capture/stop` | Yes | Stop the live capture |
| POST | `/capture/clear` | Yes | Flush `captured_packets` in memory |
| GET | `/capture/status` | Yes | `{"status": "working"}` or `{"status": "stopped"}` |
| GET | `/capture/packets` | Yes | Last 50 captured packets |
| GET | `/capture/stats` | Yes | Cumulative counters + traffic history |

**`GET /capture/stats` — response:**
```json
{
  "analyzed": 1500,
  "allowed": 1200,
  "dropped": 250,
  "blocked": 50,
  "traffic": [
    { "group": "Inbound",  "date": "2026-06-09T10:00:00Z", "value": 2048 },
    { "group": "Outbound", "date": "2026-06-09T10:00:00Z", "value": 512 }
  ]
}
```

---

### 8.6 Packet Tester — `/test`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/test` | Yes | Simulate a packet through the engine |

**Request body:**
```json
{
  "protocol": "TCP",
  "srcIp": "192.168.1.5",
  "dstIp": "8.8.8.8",
  "srcPort": "54321",
  "dstPort": "443"
}
```

**Response:**
```json
{
  "allowed": true,
  "action": "ALLOW",
  "reason": "Allow HTTPS",
  "matchedRule": { ...full rule object or null... }
}
```

The tester runs the packet through the full `evaluate_packet()` pipeline including blocklist and rate-limit checks, but **does not log the result** and **does not affect counters**.

---

### 8.7 Settings — `/settings`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/settings` | Yes | Returns `{key: value}` dict of all settings |
| POST | `/settings` | Yes | Upsert one setting key-value pair |

The backend uses `INSERT OR REPLACE` — sending the same key twice overwrites the previous value. Each setting must be sent in a separate `POST` request.

**Request body:**
```json
{ "key": "rate_limit", "value": "500" }
```

---

## 10. Application Entry Point — `main.py`

```python
app = FastAPI()

# CORS — open to all origins (suitable for local dev; restrict in production)
app.add_middleware(CORSMiddleware, allow_origins=["*"], ...)

# Synchronous DB table creation (runs before event loop starts)
init_db()

# Async seed (runs inside the event loop after startup)
@app.on_event("startup")
async def startup_event():
    await seed_db_async()

# Routers
app.include_router(login_router)        # /login
app.include_router(rules_router)        # /rules (triggers Rust IPC sync)
app.include_router(blocklist_router)    # /blocklist (triggers Rust IPC sync)
app.include_router(settings_router)    # /settings
app.include_router(logs_router)         # /logs
app.include_router(capture_router)      # /capture/*
app.include_router(tester_router)       # /test
```

---

## 11. Known Limitations & TODOs

| # | Area | Issue | Suggested Fix |
|---|---|---|---|
| 1 | Security | `SECRET_KEY` is hardcoded in `login.py` | Load from environment variable (`os.getenv`) |
| 2 | Security | Default credentials are `admin` / `admin` | Force password change on first login |
| 3 | Security | CORS allows all origins (`"*"`) | Restrict to the WebUI origin in production |
| 4 | Port matching | No CIDR support for IP fields | Add `ipaddress.ip_network` range matching alongside exact IP |
| 5 | Persistence | Stats counters reset to zero on every restart | Persist counters in `settings` table or a dedicated `stats` table |
| 6 | Protocol | `payload` field in `PacketTest` is accepted but never used | Wire it into the engine or remove it |
| 7 | Audit | No password change endpoint exists | Add `PUT /users/me/password` |
| 8 | Rust DP | XDP map does not support IPv6 addresses yet | Extend eBPF map to `u128` keys for IPv6 |
| 9 | Rust DP | nftables sync flushes all rules on every update | Implement incremental rule diffing |
