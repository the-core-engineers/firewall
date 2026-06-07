from fastapi import APIRouter, Depends
import aiosqlite
from models import SettingModel
from database import DB_PATH
from login import get_current_user

router = APIRouter(prefix="/settings", tags=["settings"])

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
        await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (setting.key, setting.value))
        await db.commit()
    return setting
