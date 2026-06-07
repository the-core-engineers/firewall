from fastapi import APIRouter, Depends
import aiosqlite
from database import DB_PATH
from login import get_current_user

router = APIRouter(prefix="/logs", tags=["logs"])

@router.get("")
async def get_logs(user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

@router.delete("")
async def delete_logs(user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM logs")
        await db.commit()
    return {"message": "Logs deleted"}
