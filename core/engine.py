import time
from database import get_db_data

# These variables will prevent the UI from crashing
captured_packets = []
is_capturing = False

# Stats counters (Currently 0, the Rust engine will update them later)
total_analyzed = 0
total_allowed = 0
total_dropped = 0
total_blocked = 0
traffic_history = []

def toggle_capture(should_capture: bool):
    global is_capturing
    is_capturing = should_capture
    if is_capturing:
        print("[Python Engine] Capture Start signal received. (Actual sniffing will be done by Rust now)")
    else:
        print("[Python Engine] Capture Stop signal received.")

def get_status():
    global is_capturing
    return "working" if is_capturing else "stopped"

def get_recent_packets():
    global captured_packets
    return captured_packets

def get_stats():
    global total_analyzed, total_allowed, total_dropped, total_blocked, traffic_history
    return {
        "analyzed": total_analyzed,
        "allowed": total_allowed,
        "dropped": total_dropped,
        "blocked": total_blocked,
        "traffic": traffic_history
    }

def clear_packets():
    global captured_packets
    captured_packets.clear()

# NEW FUNCTION: To prevent tester.py from crashing
def evaluate_packet(packet_info, rules, settings, blocklist):
    return "ALLOW", "Dummy engine is running", None
