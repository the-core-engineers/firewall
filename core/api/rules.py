"""
core/api/rules.py  (updated)
──────────────────────────────
What changed:
  • After any write (POST / DELETE) → calls engine_client.rules_apply()
    This tells the Rust engine to re-read rules from DB and atomically
    replace the nftables ruleset.  The old Python evaluate_packet() loop
    is completely gone; nftables does the filtering in kernel space now.
"""

from fastapi import APIRouter, Depends
from typing import List
import uuid
import aiosqlite
from models import Rule, RuleResponse
from database import DB_PATH
from login import get_current_user
import engine_client
import logging

log = logging.getLogger(__name__)
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
        await db.execute(
            """INSERT INTO rules (id, action, protocol, srcIp, dstIp, srcPort, dstPort, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (rule_id, rule.action, rule.protocol, rule.srcIp, rule.dstIp,
             rule.srcPort, rule.dstPort, rule.description),
        )
        await db.commit()

    # ── Re-apply nftables ruleset ────────────────────────────────────────────
    try:
        await engine_client.rules_apply()
    except Exception as exc:
        log.warning("Engine rules_apply failed (nftables may be stale): %s", exc)

    return RuleResponse(id=rule_id, **rule.dict())


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        await db.commit()

    # ── Re-apply nftables ruleset ────────────────────────────────────────────
    try:
        await engine_client.rules_apply()
    except Exception as exc:
        log.warning("Engine rules_apply failed (nftables may be stale): %s", exc)

    return {"message": "Rule deleted"}
