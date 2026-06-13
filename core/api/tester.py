"""
core/api/tester.py  (updated)
───────────────────────────────
The packet tester never used Scapy — it just ran evaluate_packet() which was
pure Python rule matching.  Now that engine.py is deleted, we inline that
logic here.  Zero dependencies on the Rust engine; this is simulation only.

The actual enforcement in production is done by nftables.  This endpoint
lets you preview what nftables WOULD do given the current DB rules,
without sending real packets.
"""

from fastapi import APIRouter, Depends
from models import PacketTest
from database import get_db_data
from login import get_current_user

router = APIRouter(prefix="/test", tags=["tester"])


# ── Inlined from the old engine.py (no Scapy, pure Python) ──────────────────

def _port_matches(rule_port: str, packet_port) -> bool:
    if not rule_port:
        return True
    if packet_port is None or packet_port == '':
        return False
    try:
        pkt = int(packet_port)
    except (ValueError, TypeError):
        return False

    rule_port = rule_port.strip()
    if '-' in rule_port:
        parts = rule_port.split('-', 1)
        try:
            return int(parts[0]) <= pkt <= int(parts[1])
        except ValueError:
            return False
    if ',' in rule_port:
        try:
            return pkt in {int(p.strip()) for p in rule_port.split(',')}
        except ValueError:
            return False
    try:
        return pkt == int(rule_port)
    except ValueError:
        return False


def _evaluate(packet_info: dict, rules: list, settings: dict, blocklist: list):
    src_ip = packet_info.get('srcIp')

    if src_ip in blocklist:
        return 'BLOCK', f"IP {src_ip} is in the blocklist (XDP would drop this)", None

    for rule in rules:
        match = True
        if rule['protocol'] != 'ALL' and rule['protocol'] != packet_info.get('protocol'):
            match = False
        if rule['srcIp'] and rule['srcIp'] != src_ip:
            match = False
        if rule['dstIp'] and rule['dstIp'] != packet_info.get('dstIp'):
            match = False
        if rule['srcPort'] and not _port_matches(rule['srcPort'], packet_info.get('srcPort')):
            match = False
        if rule['dstPort'] and not _port_matches(rule['dstPort'], packet_info.get('dstPort')):
            match = False
        if match:
            reason = rule['description'] or f"Matched rule {rule['id']}"
            return rule['action'], reason, rule

    default_policy = settings.get('default_policy', 'ALLOW').upper()
    if default_policy == 'DROP':
        return 'DROP', "Default drop policy (nftables chain default)", None
    return 'ALLOW', "Default allow policy (nftables chain default)", None


# ── Route ─────────────────────────────────────────────────────────────────────

@router.post("")
async def test_packet(packet: PacketTest, user: str = Depends(get_current_user)):
    """Simulate how the current ruleset would treat this packet.

    This is a preview tool only — it reads rules from the DB and runs the same
    matching logic that nftables uses.  The Suricata IPS layer (deep packet
    inspection) is not simulated here because it requires real packet content.
    """
    packet_info = packet.dict()
    rules, settings, blocklist = get_db_data()
    action, reason, rule = _evaluate(packet_info, rules, settings, blocklist)
    return {
        "allowed":     action == 'ALLOW',
        "action":      action,
        "reason":      reason,
        "matchedRule": rule,
        "note": (
            "This simulates nftables rule matching. "
            "XDP blocklist and Suricata IPS also enforce traffic in production."
        ),
    }
