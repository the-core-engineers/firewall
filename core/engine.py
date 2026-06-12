import time
import uuid
import threading
import subprocess
import os
import json
import socket
from datetime import datetime
from database import get_db_data, add_to_blocklist_sync, log_packet

RUST_IPC_PORT = 9999

def trigger_rust_sync():
    """Sends a UDP packet to the Rust Daemon to trigger an instant XDP/nftables update."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"SYNC", ("127.0.0.1", RUST_IPC_PORT))
        sock.close()
    except Exception as e:
        print(f"Failed to trigger Rust IPC: {e}")

captured_packets = []
is_capturing = False
suricata_thread = None
pf_thread = None

total_analyzed = 0
total_allowed = 0
total_dropped = 0
total_blocked = 0

traffic_history = []
current_second = int(time.time())
current_inbound = 0
current_outbound = 0

last_pf_hash = ""

# Paths for Suricata integration
EVE_JSON_PATH = os.path.join(os.path.dirname(__file__), "eve.json")
PF_CONF_PATH = os.path.join(os.path.dirname(__file__), "pf_custom.conf")

import sys

# Ensure iptables chains exist on Linux
if sys.platform == "linux":
    subprocess.run(["sudo", "iptables", "-N", "SURICATA_BLOCKS"], capture_output=True)
    subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-j", "SURICATA_BLOCKS"], capture_output=True)
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-j", "SURICATA_BLOCKS"], capture_output=True)

def tail_eve_json():
    """Reads Suricata's eve.json to populate the React UI dashboard. 
    NOTE: Actual hardware blocking is now handled by the high-speed Rust XDP daemon!"""
    global captured_packets, total_analyzed, total_blocked, total_allowed
    global current_second, current_inbound, current_outbound, traffic_history
    
    while not os.path.exists(EVE_JSON_PATH):
        time.sleep(1)
        
    with open(EVE_JSON_PATH, "r") as f:
        f.seek(0, 2)
        while is_capturing:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                event = json.loads(line)
                now_sec = int(time.time())
                
                if now_sec != current_second:
                    traffic_history.append({'group': 'Inbound', 'date': datetime.fromtimestamp(current_second).isoformat() + "Z", 'value': current_inbound})
                    traffic_history.append({'group': 'Outbound', 'date': datetime.fromtimestamp(current_second).isoformat() + "Z", 'value': current_outbound})
                    if len(traffic_history) > 120: traffic_history = traffic_history[-120:]
                    current_second = now_sec
                    current_inbound = 0
                    current_outbound = 0

                event_type = event.get("event_type")
                
                if event_type == "flow":
                    flow = event.get("flow", {})
                    bytes_in = flow.get("bytes_toserver", 0)
                    bytes_out = flow.get("bytes_toclient", 0)
                    current_inbound += bytes_in
                    current_outbound += bytes_out
                    
                    pkt = {
                        'id': str(uuid.uuid4())[:8],
                        'time': event.get("timestamp", "").replace("T", " ")[:19],
                        'protocol': event.get("proto", "TCP"),
                        'src': f"{event.get('src_ip')}:{event.get('src_port')}",
                        'dst': f"{event.get('dest_ip')}:{event.get('dest_port')}",
                        'status': 'ALLOW',
                        'reason': 'Suricata Flow',
                        'dpi': 'Yes'
                    }
                    captured_packets.insert(0, pkt)
                    if len(captured_packets) > 100: captured_packets.pop()
                    total_analyzed += 1
                    total_allowed += 1

                elif event_type == "alert":
                    # The actual hardware packet dropping is handled instantly by the Rust XDP Daemon.
                    # We only log it here for the UI stats if IPS mode is on.
                    rules, settings, blocklist = get_db_data()
                    ips_mode = settings.get("ai_action_mode", "IDS") == "IPS"
                    severity = event.get("alert", {}).get("severity", 3)
                    
                    if ips_mode and severity <= 2:
                        total_blocked += 1
                        
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"Error parsing eve.json line: {e}")

def toggle_capture(should_capture: bool):
    global is_capturing, suricata_thread
    if should_capture and not is_capturing:
        is_capturing = True
        suricata_thread = threading.Thread(target=tail_eve_json, daemon=True)
        suricata_thread.start()
    elif not should_capture and is_capturing:
        is_capturing = False

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

def _kill_flow_aggregator():
    """Mock cleanup for FastAPI shutdown to prevent crashes, since Go aggregator is gone."""
    pass

# Keep evaluate_packet intact for the "Packet Tester" UI feature
def evaluate_packet(packet_info, rules, settings, blocklist):
    src_ip = packet_info.get('srcIp')
    if src_ip in blocklist:
        return 'BLOCK', f"IP {src_ip} is in the Blocklist", None

    for rule in rules:
        match = True
        if rule['protocol'] != 'ALL' and rule['protocol'] != packet_info.get('protocol'):
            match = False
        if rule['srcIp'] and rule['srcIp'] != src_ip:
            match = False
        if rule['dstIp'] and rule['dstIp'] != packet_info.get('dstIp'):
            match = False
        if rule['srcPort'] and packet_info.get('srcPort') != rule['srcPort']: # Simplified port matching
            match = False
        if rule['dstPort'] and packet_info.get('dstPort') != rule['dstPort']:
            match = False
            
        if match:
            reason = rule['description'] if rule['description'] else f"Matched rule {rule['id']}"
            return rule['action'], reason, rule
            
    default_policy = settings.get('default_policy', 'ALLOW').upper()
    if default_policy == 'DROP':
        return 'DROP', "Default drop policy ", None
    else:
        return 'ALLOW', "Default allow policy ", None
