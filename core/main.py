"""
core/main.py  (updated)
────────────────────────
Changes vs original:
  • Removed `from engine import ...` — the Scapy engine is gone.
  • Added startup health check for the Rust engine.
  • Added GET /alerts route (proxies Suricata alerts from the engine).
  • Added GET /engine/health route (exposes engine health to the UI).
  • httpx is added to requirements.txt for engine_client.
"""

import logging
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, seed_db_async
from login import login_router, get_current_user

from api.rules     import router as rules_router
from api.blocklist import router as blocklist_router
from api.settings  import router as settings_router
from api.logs      import router as logs_router
from api.capture   import router as capture_router
from api.tester    import router as tester_router
import engine_client

log = logging.getLogger(__name__)

app = FastAPI(title="LinuxShield API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database init ─────────────────────────────────────────────────────────────
init_db()


@app.on_event("startup")
async def startup_event():
    await seed_db_async()

    # Check that the Rust engine is up; log a warning if not.
    # The API will still start — routes that need the engine will return
    # graceful errors instead of crashing the whole server.
    if await engine_client.engine_healthy():
        log.info("Rust engine is healthy at 127.0.0.1:7070")
    else:
        log.warning(
            "Rust engine is NOT reachable at 127.0.0.1:7070. "
            "XDP blocklist and nftables rules will not be updated until it starts."
        )


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(login_router)
app.include_router(rules_router)
app.include_router(blocklist_router)
app.include_router(settings_router)
app.include_router(logs_router)
app.include_router(capture_router)
app.include_router(tester_router)


# ── Extra top-level routes ────────────────────────────────────────────────────

@app.get("/alerts", tags=["alerts"])
async def get_alerts(limit: int = 100, user: str = Depends(get_current_user)):
    """Recent Suricata IPS alerts (newest first).
    These are deep-packet-inspection events — distinct from the simple
    blocklist/rule logs already in the /logs endpoint.
    """
    return await engine_client.get_alerts(limit=limit)


@app.get("/engine/health", tags=["engine"])
async def engine_health():
    """Proxy the Rust engine's health endpoint (no auth required)."""
    healthy = await engine_client.engine_healthy()
    return {
        "engine": "ok" if healthy else "unreachable",
        "xdp":    "active" if healthy else "unknown",
    }
