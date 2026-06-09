import sqlite3
import aiosqlite
import uuid
from datetime import datetime

DB_PATH = "firewall.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        protocol TEXT NOT NULL,
        srcIp TEXT,
        dstIp TEXT,
        srcPort TEXT,
        dstPort TEXT,
        description TEXT
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        protocol TEXT NOT NULL,
        srcIp TEXT,
        dstIp TEXT,
        srcPort TEXT,
        dstPort TEXT,
        action TEXT NOT NULL,
        reason TEXT
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocklist (
        id TEXT PRIMARY KEY,
        ip TEXT NOT NULL,
        reason TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def get_db_data():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rules")
    rules = [dict(row) for row in cursor.fetchall()]
    cursor.execute("SELECT * FROM settings")
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    cursor.execute("SELECT * FROM blocklist")
    blocklist = [row['ip'] for row in cursor.fetchall()]
    conn.close()
    return rules, settings, blocklist

def add_to_blocklist_sync(ip, reason):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM blocklist WHERE ip = ?", (ip,))
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO blocklist (id, ip, reason, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (str(uuid.uuid4())[:8], ip, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    conn.close()

def log_packet(packet_info, action, reason):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (id, timestamp, protocol, srcIp, dstIp, srcPort, dstPort, action, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        packet_info['id'],
        packet_info['time'],
        packet_info['protocol'],
        packet_info['srcIp'],
        packet_info['dstIp'],
        packet_info['srcPort'],
        packet_info['dstPort'],
        action,
        reason
    ))
    conn.commit()
    conn.close()

async def seed_db_async():
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM rules")
        if (await cursor.fetchone())[0] == 0:
            default_rules = [
                # ── Web ──────────────────────────────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '80',          'Allow HTTP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '443',         'Allow HTTPS'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '8080',        'Allow HTTP Alternate / dev proxy'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '8443',        'Allow HTTPS Alternate'),
                # ── DNS ──────────────────────────────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '53',          'Allow DNS (UDP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '53',          'Allow DNS (TCP — zone transfers / DNSSEC)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '853',         'Allow DNS-over-TLS (DoT)'),
                # ── Secure remote access ─────────────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '22',          'Allow SSH'),
                # ── Mail ─────────────────────────────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '25',          'Allow SMTP relay'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '465',         'Allow SMTPS (implicit TLS)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '587',         'Allow SMTP Submission (STARTTLS)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '993',         'Allow IMAPS'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '995',         'Allow POP3S'),
                # ── Infrastructure ───────────────────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '123',         'Allow NTP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '67',          'Allow DHCP Server'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '68',          'Allow DHCP Client'),
                # ── LDAP / Active Directory────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '389',         'Allow LDAP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '389',         'Allow LDAP (UDP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '636',         'Allow LDAP SSL'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3268',        'Allow Global Catalog'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3269',        'Allow Global Catalog SSL'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '9389',        'Allow Active Directory Web Services (ADWS)'),
                # ── RPC / Windows services ─────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '135',         'Allow RPC Endpoint Mapper'),
                # PORT RANGE — RPC dynamic ports
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '49152-65535', 'Allow RPC dynamic / ephemeral ports'),
                # ── IPsec / VPN ────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '500',         'Allow IPsec ISAKMP (IKE)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '4500',        'Allow IPsec NAT-T'),
                # ── Apple Services ───────────────────────────────────────────
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '88',          'Allow Kerberos'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '110',         'Allow Post Office Protocol (POP3)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '137',         'Allow Windows Internet Naming Service (WINS)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '138',         'Allow NetBIOS Datagram Service'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '139',         'Allow Server Message Block (SMB)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '143',         'Allow Internet Message Access Protocol (IMAP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '192',         'Allow OSU Network Monitoring System'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '443',         'Allow QUIC'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '445',         'Allow Microsoft SMB Domain Server'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '515',         'Allow Line Printer (LPR), Line Printer Daemon (LPD)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '548',         'Allow Apple Filing Protocol (AFP) over TCP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '554',         'Allow Real Time Streaming Protocol (RTSP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '554',         'Allow Real Time Streaming Protocol (RTSP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '631',         'Allow Internet Printing Protocol (IPP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '749',         'Allow Kerberos 5 admin/changepw'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '749',         'Allow Kerberos 5 admin/changepw'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '995',         'Allow Mail POP SSL'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '1900',        'Allow SSDP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '2197',        'Allow Apple Push Notification Service (APNS)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3031',        'Allow Remote AppleEvents'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '3031',        'Allow Remote AppleEvents'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3283',        'Allow Apple Remote Desktop'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '3283',        'Allow Apple Remote Desktop'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3284',        'Allow Classroom File Transfer'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3285',        'Allow Classroom'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '3478-3497',   'Allow FaceTime, Game Center'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3689',        'Allow Digital Audio Access Protocol (DAAP)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '3690',        'Allow Subversion'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '3690',        'Allow Subversion'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '4398',        'Allow Game Centere'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '5000',        'Allow AirPlay'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '5100',        'Allow macOS camera and scanner sharing'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '5223',        'Allow Apple Push Notification Service (APNS)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '5228',        'Allow Spotlight Suggestions, Siri'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '5297',        'Allow Messages (local traffic)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '5350',        'Allow NAT Port Mapping Protocol Announcements'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '5351',        'Allow NAT Port Mapping Protocol'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '5353',        'Allow Multicast DNS (MDNS)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '5900',        'Allow Remote Framebuffer'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '5900',        'Allow Remote Framebuffer, RTP, RTCP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '5901-5902',   'Allow RTP, RTCP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '6000',        'Allow AirPlay'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '7000',        'Allow AirPlay'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '8000-8999',   'Allow Web service, iTunes Radio streams'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '9100',        'Allow Printing'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '9418',        'Allow git pack transfer'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '9418',        'Allow git pack transfer'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '16384-16472', 'Allow RTP, RTCP (Messages, FaceTime, Game Center)'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP',  None, None, None, '42000-42999', 'Allow iTunes Radio streams'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'UDP',  None, None, None, '49152-65535', 'Allow Xsan'),
              
            ]
            await db.executemany('''
                INSERT INTO rules (id, action, protocol, srcIp, dstIp, srcPort, dstPort, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', default_rules)
            
        cursor = await db.execute("SELECT COUNT(*) FROM settings")
        if (await cursor.fetchone())[0] == 0:
            default_settings = [
                ('rate_limit', '1000'),
                ('flood_threshold', '100'),
                ('theme', 'white'),
                ('default_policy', 'ALLOW')
            ]
            await db.executemany('''
                INSERT INTO settings (key, value) VALUES (?, ?)
            ''', default_settings)
            
        await db.commit()
