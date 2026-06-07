from fastapi import APIRouter, Depends
from engine import toggle_capture, get_status, get_recent_packets, get_stats, clear_packets
from login import get_current_user

router = APIRouter(prefix="/capture", tags=["capture"])

@router.post("/start")
def start_capture(user: str = Depends(get_current_user)):
    toggle_capture(True)
    return {"status": "started"}

@router.post("/stop")
def stop_capture(user: str = Depends(get_current_user)):
    toggle_capture(False)
    return {"status": "stopped"}

@router.post("/clear")
def clear_capture(user: str = Depends(get_current_user)):
    clear_packets()
    return {"status": "cleared"}

@router.get("/status")
def status(user: str = Depends(get_current_user)):
    return {"status": get_status()}

@router.get("/packets")
def get_packets(user: str = Depends(get_current_user)):
    return get_recent_packets()

@router.get("/stats")
def stats(user: str = Depends(get_current_user)):
    return get_stats()
