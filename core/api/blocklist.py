from fastapi import APIRouter, Depends, HTTPException
from typing import List
import uuid
from datetime import datetime
import aiosqlite
from models import BlocklistEntry, BlocklistResponse
from database import DB_PATH
from login import get_current_user
from engine import trigger_rust_sync

router = APIRouter(prefix="/blocklist", tags=["blocklist"])

@router.get("", response_model=List[BlocklistResponse])
async def get_blocklist(user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM blocklist ORDER BY timestamp DESC") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

@router.post("", response_model=BlocklistResponse)
async def add_blocklist(entry: BlocklistEntry, user: str = Depends(get_current_user)):
    entry_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute('''
                INSERT INTO blocklist (id, ip, reason, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (entry_id, entry.ip, entry.reason, timestamp))
            await db.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(status_code=400, detail="IP already in blocklist")
    
    trigger_rust_sync()
    return BlocklistResponse(id=entry_id, timestamp=timestamp, **entry.dict())

@router.delete("/{entry_id}")
async def delete_blocklist(entry_id: str, user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM blocklist WHERE id = ?", (entry_id,))
        await db.commit()
    
    trigger_rust_sync()
    return {"message": "Blocklist entry deleted"}
