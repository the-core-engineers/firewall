"""
core/engine_client.py
─────────────────────
Replaces engine.py.

Previously engine.py used Scapy to sniff packets and evaluate rules in Python.
Now all of that is done in kernel space:

  - XDP/eBPF:   blocks IPs before the kernel allocates any memory  ← NEW
  - nftables:   applies protocol/port/IP rules                     ← NEW
  - Suricata:   deep packet inspection + intrusion prevention       ← NEW

This file is purely a thin HTTP client that tells the Rust engine
(127.0.0.1:7070) what to do whenever FastAPI's routes change state.

WHY HTTP?
  The Rust engine manages shared kernel state (BPF maps, nftables).
  Calling it over HTTP keeps FastAPI stateless and avoids concurrency
  bugs that would arise from directly calling C libraries from asyncio.

WHAT HAPPENED TO:
  - toggle_capture()  → removed; packet capture is now done by the kernel
  - evaluate_packet() → removed; rules live in nftables, not Python dicts
  - get_recent_packets() → not implemented here; the React UI can subscribe
                            to Suricata alerts via GET /alerts instead.
  - get_stats() → proxied from the Rust engine's /stats endpoint
"""

import httpx
import asyncio
from typing import Optional

ENGINE_BASE = "http://127.0.0.1:7070"

# We use a single shared async client for connection pooling.
# httpx.AsyncClient is safe to reuse across requests.
_client: Optional[httpx.AsyncClient] = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=ENGINE_BASE,
            timeout=httpx.Timeout(5.0),   # 5 s — engine should respond quickly
        )
    return _client


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKLIST OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

async def blocklist_add(ip: str) -> dict:
    """Tell the Rust engine to add `ip` to the XDP BLOCKLIST map immediately.
    Call this right after inserting the IP into SQLite."""
    resp = await get_client().post("/blocklist/add", json={"ip": ip})
    resp.raise_for_status()
    return resp.json()


async def blocklist_remove(ip: str) -> dict:
    """Remove `ip` from the XDP BLOCKLIST map."""
    resp = await get_client().post("/blocklist/remove", json={"ip": ip})
    resp.raise_for_status()
    return resp.json()


async def blocklist_sync() -> dict:
    """Full re-sync: Rust engine reads the entire blocklist table from DB
    and repopulates the BPF map.  Use after bulk changes."""
    resp = await get_client().post("/blocklist/sync")
    resp.raise_for_status()
    return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
# RULES OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

async def rules_apply() -> dict:
    """Tell the Rust engine to re-read all rules from DB and atomically
    replace the nftables ruleset.  Call this after any rule add/delete."""
    resp = await get_client().post("/rules/apply")
    resp.raise_for_status()
    return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
# STATS & ALERTS (read-only)
# ─────────────────────────────────────────────────────────────────────────────

async def get_stats() -> dict:
    """XDP drop/pass counters from the BPF STATS map, summed across CPUs."""
    try:
        resp = await get_client().get("/stats")
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return {
            "xdp_dropped_packets": 0,
            "xdp_dropped_bytes":   0,
            "xdp_passed_packets":  0,
            "xdp_passed_bytes":    0,
        }


async def get_alerts(limit: int = 100) -> list:
    """Recent Suricata IPS alerts (newest first)."""
    try:
        resp = await get_client().get("/alerts")
        resp.raise_for_status()
        data = resp.json()
        return data[:limit]
    except httpx.HTTPError:
        return []


async def clear_alerts() -> dict:
    """Clear the Rust engine's in-memory alert buffer."""
    resp = await get_client().delete("/alerts")
    resp.raise_for_status()
    return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────

async def engine_healthy() -> bool:
    """Return True if the Rust engine is reachable and healthy."""
    try:
        resp = await get_client().get("/health", timeout=2.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# BACKWARD-COMPATIBLE STUBS
# (So existing code that imported these names doesn't break immediately)
# ─────────────────────────────────────────────────────────────────────────────

def get_status() -> str:
    """Engine is always 'working' — XDP runs continuously in the kernel."""
    return "working"


def get_recent_packets() -> list:
    """Packet capture is now done at kernel level.
    Return empty list; route the UI to /alerts for Suricata events."""
    return []
