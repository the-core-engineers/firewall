import time
import uuid
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from database import get_db_data, add_to_blocklist_sync, log_packet

captured_packets = []
is_capturing = False
capture_thread = None

# In-memory rate limiting and flood detection
packet_counts_per_ip = {} # IP -> count per minute
flood_counts_per_ip = {}  # IP -> count per second
last_minute_reset = time.time()
last_second_reset = time.time()

# Statistics Counters
total_analyzed = 0
total_allowed = 0
total_dropped = 0
total_blocked = 0

traffic_history = []
current_second = int(time.time())
current_inbound = 0
current_outbound = 0

# A simple heuristic for local network (can be expanded)
def is_local_ip(ip):
    return ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('127.')

def port_matches(rule_port: str, packet_port) -> bool:
    """
    Check whether a packet port satisfies a rule port specification.

    Supported rule_port formats (all stored as plain TEXT in the DB):
      - Single port  : '80'
      - Range        : '49152-65535'   (low-high, inclusive)
      - Comma list   : '80,443,8080'   (exact values)

    packet_port can be an int or a string; None/empty always returns False.
    A None/empty rule_port means "any port" — callers skip this check entirely.
    """
    if not rule_port:
        return True                          # no restriction → always matches
    if packet_port is None or packet_port == '':
        return False                         # rule wants a port, packet has none

    try:
        pkt = int(packet_port)
    except (ValueError, TypeError):
        return False                         # unparseable packet port → no match

    rule_port = rule_port.strip()

    # Range: "49152-65535"
    if '-' in rule_port:
        parts = rule_port.split('-', 1)
        try:
            low, high = int(parts[0]), int(parts[1])
            return low <= pkt <= high
        except ValueError:
            return False

    # Comma list: "80,443,8080"
    if ',' in rule_port:
        try:
            return pkt in {int(p.strip()) for p in rule_port.split(',')}
        except ValueError:
            return False

    # Single port: "80"
    try:
        return pkt == int(rule_port)
    except ValueError:
        return False

def evaluate_packet(packet_info, rules, settings, blocklist):
    global packet_counts_per_ip, flood_counts_per_ip, last_minute_reset, last_second_reset
    src_ip = packet_info.get('srcIp')
    
    if src_ip in blocklist:
        return 'BLOCK', f"IP {src_ip} is in the Blocklist", None

    current_time = time.time()
    
    if current_time - last_minute_reset >= 60:
        packet_counts_per_ip = {}
        last_minute_reset = current_time
    
    if current_time - last_second_reset >= 1:
        flood_counts_per_ip = {}
        last_second_reset = current_time

    flood_threshold = int(settings.get('flood_threshold', '100'))
    flood_counts_per_ip[src_ip] = flood_counts_per_ip.get(src_ip, 0) + 1
    if flood_counts_per_ip[src_ip] > flood_threshold:
        add_to_blocklist_sync(src_ip, f"Auto-blocked: Exceeded flood threshold ({flood_threshold} pkts/sec)")
        return 'DROP', f"Flood detected from {src_ip}", None

    rate_limit = int(settings.get('rate_limit', '1000'))
    packet_counts_per_ip[src_ip] = packet_counts_per_ip.get(src_ip, 0) + 1
    if packet_counts_per_ip[src_ip] > rate_limit:
        return 'DROP', f"Rate limit exceeded for {src_ip}", None

    for rule in rules:
        match = True
        if rule['protocol'] != 'ALL' and rule['protocol'] != packet_info.get('protocol'):
            match = False
        if rule['srcIp'] and rule['srcIp'] != src_ip:
            match = False
        if rule['dstIp'] and rule['dstIp'] != packet_info.get('dstIp'):
            match = False
        if rule['srcPort'] and not port_matches(rule['srcPort'], packet_info.get('srcPort')):
            match = False
        if rule['dstPort'] and not port_matches(rule['dstPort'], packet_info.get('dstPort')):
            match = False
            
        if match:
            reason = rule['description'] if rule['description'] else f"Matched rule {rule['id']}"
            return rule['action'], reason, rule
            
    return 'ALLOW', "Default allow policy", None

def packet_callback(packet):
    global captured_packets
    global total_analyzed, total_allowed, total_dropped, total_blocked
    global traffic_history, current_second, current_inbound, current_outbound
    
    now_sec = int(time.time())
    if now_sec != current_second:
        traffic_history.append({
            'group': 'Inbound',
            'date': datetime.fromtimestamp(current_second).isoformat() + "Z",
            'value': current_inbound
        })
        traffic_history.append({
            'group': 'Outbound',
            'date': datetime.fromtimestamp(current_second).isoformat() + "Z",
            'value': current_outbound
        })
        # Keep last 60 seconds (2 entries per second -> 120 items max)
        if len(traffic_history) > 120:
            traffic_history = traffic_history[-120:]
        
        current_second = now_sec
        current_inbound = 0
        current_outbound = 0

    if IP in packet:
        packet_len = len(packet)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if is_local_ip(dst_ip) and not is_local_ip(src_ip):
            current_inbound += packet_len
        elif is_local_ip(src_ip) and not is_local_ip(dst_ip):
            current_outbound += packet_len
        else:
            # Fallback if both local or both public
            current_inbound += packet_len
            
        packet_info = {
            'id': str(uuid.uuid4())[:8],
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'srcIp': src_ip,
            'dstIp': dst_ip,
            'protocol': 'OTHER',
            'srcPort': '',
            'dstPort': ''
        }
        
        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_info['srcPort'] = packet[TCP].sport
            packet_info['dstPort'] = packet[TCP].dport
        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_info['srcPort'] = packet[UDP].sport
            packet_info['dstPort'] = packet[UDP].dport
        elif ICMP in packet:
            packet_info['protocol'] = 'ICMP'

        rules, settings, blocklist = get_db_data()
        action, reason, rule = evaluate_packet(packet_info, rules, settings, blocklist)

        # Update Counters
        total_analyzed += 1
        if action == 'ALLOW':
            total_allowed += 1
        elif action == 'DROP':
            total_dropped += 1
        elif action == 'BLOCK':
            total_blocked += 1

        log_packet(packet_info, action, reason)
        
        captured_packets.insert(0, {
            'id': packet_info['id'],
            'time': packet_info['time'],
            'protocol': packet_info['protocol'],
            'src': f"{packet_info['srcIp']}:{packet_info['srcPort']}" if packet_info['srcPort'] else packet_info['srcIp'],
            'dst': f"{packet_info['dstIp']}:{packet_info['dstPort']}" if packet_info['dstPort'] else packet_info['dstIp'],
            'status': action,
            'reason': reason
        })
        
        if len(captured_packets) > 50:
            captured_packets.pop()

def start_sniffing():
    global is_capturing
    while is_capturing:
        sniff(prn=packet_callback, store=False, count=10, timeout=1)

def toggle_capture(should_capture: bool):
    global is_capturing, capture_thread
    if should_capture and not is_capturing:
        is_capturing = True
        capture_thread = threading.Thread(target=start_sniffing, daemon=True)
        capture_thread.start()
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
