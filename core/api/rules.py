from fastapi import APIRouter, Depends
from typing import List
import uuid
import aiosqlite
from models import Rule, RuleResponse
from database import DB_PATH
from login import get_current_user
from engine import trigger_rust_sync

router = APIRouter(prefix="/rules", tags=["rules"])

@router.get("", response_model=List[RuleResponse])
async def get_rules(user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM rules") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

@router.post("", response_model=RuleResponse)
async def add_rule(rule: Rule, user: str = Depends(get_current_user)):
    rule_id = str(uuid.uuid4())[:8]
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
            INSERT INTO rules (id, action, protocol, srcIp, dstIp, srcPort, dstPort, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_id, rule.action, rule.protocol, rule.srcIp, rule.dstIp,
            rule.srcPort, rule.dstPort, rule.description
        ))
        await db.commit()
    
    # Notify Rust Daemon for instant hardware execution
    trigger_rust_sync()
    return RuleResponse(id=rule_id, **rule.dict())

@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        await db.commit()
        
    # Notify Rust Daemon for instant hardware execution
    trigger_rust_sync()
    return {"message": "Rule deleted"}
