import sqlite3


def create_database():
    connection = sqlite3.connect("netwatch.db")

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac TEXT,
            hostname TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_device(ip, mac, hostname):
    connection = sqlite3.connect("netwatch.db")

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO devices (ip, mac, hostname)
        VALUES (?, ?, ?)
    """, (ip, mac, hostname))

    connection.commit()
    connection.close()