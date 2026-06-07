from pydantic import BaseModel
from typing import Optional

class Rule(BaseModel):
    action: str
    protocol: str
    srcIp: Optional[str] = None
    dstIp: Optional[str] = None
    srcPort: Optional[str] = None
    dstPort: Optional[str] = None
    description: Optional[str] = None

class RuleResponse(Rule):
    id: str

class PacketTest(BaseModel):
    protocol: str
    srcIp: str
    dstIp: str
    srcPort: Optional[str] = None
    dstPort: Optional[str] = None
    payload: Optional[str] = None

class SettingModel(BaseModel):
    key: str
    value: str

class BlocklistEntry(BaseModel):
    ip: str
    reason: str

class BlocklistResponse(BlocklistEntry):
    id: str
    timestamp: str
