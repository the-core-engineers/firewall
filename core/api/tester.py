from fastapi import APIRouter, Depends
from models import PacketTest
from database import get_db_data
from engine import evaluate_packet
from login import get_current_user

router = APIRouter(prefix="/test", tags=["tester"])

@router.post("")
async def test_packet(packet: PacketTest, user: str = Depends(get_current_user)):
    packet_info = packet.dict()
    rules, settings, blocklist = get_db_data()
    action, reason, rule = evaluate_packet(packet_info, rules, settings, blocklist)
    return {
        "allowed": action == 'ALLOW',
        "action": action,
        "reason": reason,
        "matchedRule": rule
    }
