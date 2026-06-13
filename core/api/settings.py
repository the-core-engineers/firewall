"""
core/api/settings.py  (updated)
─────────────────────────────────
Change vs original:
  When `default_policy` is updated, we call engine_client.rules_apply()
  so nftables immediately picks up the new chain default (accept vs drop).
  All other settings (theme, rate_limit, flood_threshold) don't affect nftables.
"""

from fastapi import APIRouter, Depends
import aiosqlite
from models import SettingModel
from database import DB_PATH
from login import get_current_user
import engine_client
import logging

log = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["settings"])

# Settings that require an nftables re-apply when they change
NFTABLES_SETTINGS = {"default_policy"}


@router.get("")
async def get_settings(user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM settings") as cursor:
            rows = await cursor.fetchall()
            return {row['key']: row['value'] for row in rows}


@router.post("")
async def update_setting(setting: SettingModel, user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (setting.key, setting.value)
        )
        await db.commit()

    # Re-apply nftables if this setting affects the kernel ruleset
    if setting.key in NFTABLES_SETTINGS:
        try:
            await engine_client.rules_apply()
        except Exception as exc:
            log.warning("Engine rules_apply failed after settings change: %s", exc)

    return setting
