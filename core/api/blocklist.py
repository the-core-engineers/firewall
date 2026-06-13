"""
core/api/blocklist.py  (updated)
─────────────────────────────────
What changed vs the original:
  • After INSERT → calls engine_client.blocklist_add(ip)
    This updates the XDP BPF map immediately so the kernel starts
    dropping packets from that IP before the HTTP response even returns.

  • After DELETE → calls engine_client.blocklist_remove(ip)
    The XDP map entry is removed so the IP is unblocked instantly.

Everything else (JWT auth, SQLite persistence, Pydantic models) is unchanged.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List
import uuid
from datetime import datetime
import aiosqlite
from models import BlocklistEntry, BlocklistResponse
from database import DB_PATH
from login import get_current_user
import engine_client  # ← replaces the old `from engine import ...`

router = APIRouter(prefix="/blocklist", tags=["blocklist"])


@router.get("", response_model=List[BlocklistResponse])
async def get_blocklist(user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM blocklist") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


@router.post("", response_model=BlocklistResponse)
async def add_blocklist(entry: BlocklistEntry, user: str = Depends(get_current_user)):
    entry_id  = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM blocklist WHERE ip = ?", (entry.ip,)
        )
        if (await cursor.fetchone())[0] != 0:
            raise HTTPException(status_code=400, detail="IP already in blocklist")

        await db.execute(
            "INSERT INTO blocklist (id, ip, reason, timestamp) VALUES (?, ?, ?, ?)",
            (entry_id, entry.ip, entry.reason, timestamp),
        )
        await db.commit()

    # ── Tell the Rust engine to add this IP to the XDP BPF map NOW ──────────
    # This is a fire-and-forget style call: if the engine is down, we log a
    # warning but still return 200 because the DB write succeeded.
    # On next engine restart it will re-sync from the DB automatically.
    try:
        await engine_client.blocklist_add(entry.ip)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "Engine blocklist_add failed (XDP map may be stale): %s", exc
        )

    return BlocklistResponse(id=entry_id, timestamp=timestamp, **entry.dict())


@router.delete("/{entry_id}")
async def delete_blocklist(entry_id: str, user: str = Depends(get_current_user)):
    # First get the IP so we can tell the engine which IP to remove from the map.
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT ip FROM blocklist WHERE id = ?", (entry_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Blocklist entry not found")
        ip = row[0]

        await db.execute("DELETE FROM blocklist WHERE id = ?", (entry_id,))
        await db.commit()

    # ── Remove from XDP BPF map ──────────────────────────────────────────────
    try:
        await engine_client.blocklist_remove(ip)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "Engine blocklist_remove failed (XDP map may be stale): %s", exc
        )

    return {"message": "Blocklist entry deleted"}
