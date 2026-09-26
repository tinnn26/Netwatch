import sqlite3
from datetime import datetime


def create_database():
    connection = sqlite3.connect("netwatch.db")

    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        mac TEXT UNIQUE,
        hostname TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS port_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        port INTEGER,
        service TEXT,
        scanned_at TEXT
    )
    """)

    connection.commit()
    connection.close()




def save_device(ip, mac, hostname):
    connection = sqlite3.connect("netwatch.db")

    cursor = connection.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "SELECT id FROM devices WHERE mac = ?",
        (mac,)
    )

    device = cursor.fetchone()

    if device:
        cursor.execute("""
            UPDATE devices
            SET ip = ?, hostname = ?, last_seen = ?
            WHERE mac = ?
        """, (ip, hostname, now, mac))

        is_new = False

    else:
        cursor.execute("""
            INSERT INTO devices
            (ip, mac, hostname, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, mac, hostname, now, now))

        is_new = True

    connection.commit()
    connection.close()


    return is_new

def get_devices():
    connection = sqlite3.connect("netwatch.db")

    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip, mac, hostname, first_seen, last_seen
        FROM devices
        ORDER BY last_seen DESC
    """)

    devices = cursor.fetchall()

    connection.close()

    return devices

def save_port_scan(ip, port, service):
    connection = sqlite3.connect("netwatch.db")

    cursor = connection.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO port_scans
        (ip, port, service, scanned_at)
        VALUES (?, ?, ?, ?)
    """, (ip, port, service, now))

    connection.commit()
    connection.close()