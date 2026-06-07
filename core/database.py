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
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP', None, None, None, '80', 'Allow HTTP'),
                (str(uuid.uuid4())[:8], 'ALLOW', 'TCP', None, None, None, '443', 'Allow HTTPS'),
                (str(uuid.uuid4())[:8], 'BLOCK', 'ICMP', None, None, None, None, 'Block ICMP (Ping)'),
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
                ('theme', 'white')
            ]
            await db.executemany('''
                INSERT INTO settings (key, value) VALUES (?, ?)
            ''', default_settings)
            
        await db.commit()
