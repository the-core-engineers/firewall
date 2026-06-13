"""
core/api/capture.py  (updated)
────────────────────────────────
What changed:
  • /capture/start and /capture/stop are REMOVED.
    XDP runs continuously in the kernel — there's nothing to start/stop
    from userspace.  The BPF program is attached when the engine boots
    and detached when it exits.

  • /capture/packets now returns recent Suricata alerts instead of
    the Scapy-sniffed packet ring buffer.  The Web UI can still render
    a live event table — it just shows IPS alerts now, not raw packets.

  • /capture/stats now proxies XDP BPF counters from the Rust engine.

  • /capture/status returns a health check of the Rust engine.
"""

from fastapi import APIRouter, Depends
from login import get_current_user
import engine_client

router = APIRouter(prefix="/capture", tags=["capture"])


@router.get("/status")
async def status(user: str = Depends(get_current_user)):
    """Return whether the Rust engine (and therefore XDP) is running."""
    healthy = await engine_client.engine_healthy()
    return {
        "status":  "working" if healthy else "engine_unreachable",
        "xdp":     "active" if healthy else "unknown",
        "message": "XDP filter runs continuously in kernel space",
    }


@router.get("/packets")
async def get_packets(user: str = Depends(get_current_user)):
    """Return recent Suricata IPS alert events (replaces Scapy packet buffer).

    Each alert has the structure Suricata writes to eve.json:
      {
        "timestamp": "...",
        "event_type": "alert",
        "src_ip": "...", "dest_ip": "...",
        "src_port": ..., "dest_port": ...,
        "proto": "TCP",
        "alert": {
          "action": "blocked",
          "signature": "ET SCAN Nmap ...",
          "severity": 2
        }
      }
    """
    return await engine_client.get_alerts(limit=50)


@router.get("/stats")
async def stats(user: str = Depends(get_current_user)):
    """XDP drop/pass counters from the BPF STATS map.

    These are kernel-space counters — no Python code counts packets anymore.
    The numbers represent packets processed since the XDP program was attached.
    """
    return await engine_client.get_stats()


@router.post("/clear")
async def clear_capture(user: str = Depends(get_current_user)):
    """Clear the Suricata alert buffer in the Rust engine."""
    return await engine_client.clear_alerts()


# ─── Kept for backward compatibility ─────────────────────────────────────────
# If your frontend still calls these, they return a no-op response.

@router.post("/start")
async def start_capture(user: str = Depends(get_current_user)):
    """No-op: XDP runs continuously, no explicit start needed."""
    return {"status": "xdp_always_active", "message": "XDP filter runs in kernel space"}


@router.post("/stop")
async def stop_capture(user: str = Depends(get_current_user)):
    """No-op: detaching XDP requires restarting the engine, not an API call."""
    return {"status": "xdp_always_active", "message": "Stop the engine process to detach XDP"}
