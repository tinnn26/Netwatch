"""SQLite persistence for inventory, scan history, alerts and risk findings."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).with_name("netwatch.db")


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _connect():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    """Create the schema; safe to call at each application start."""
    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                mac TEXT UNIQUE,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                service TEXT,
                scanned_at TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                network TEXT NOT NULL,
                device_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'completed'
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                device_ip TEXT,
                device_mac TEXT,
                evidence TEXT NOT NULL DEFAULT '{}',
                acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(run_id) REFERENCES scan_runs(id)
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ports_ip_time ON port_scans(ip, scanned_at DESC)")


def start_scan_run(network: str) -> int:
    with _connect() as connection:
        cursor = connection.execute(
            "INSERT INTO scan_runs (started_at, network) VALUES (?, ?)", (_now(), network)
        )
        return int(cursor.lastrowid)


def finish_scan_run(run_id: int, device_count: int, status: str = "completed"):
    with _connect() as connection:
        connection.execute(
            "UPDATE scan_runs SET device_count = ?, status = ? WHERE id = ?",
            (device_count, status, run_id),
        )


def save_device(ip: str, mac: str, hostname: str):
    """Upsert a device and return whether it was new and its previous IP."""
    now = _now()
    with _connect() as connection:
        previous = connection.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
        if previous:
            old_ip = previous["ip"]
            connection.execute(
                "UPDATE devices SET ip = ?, hostname = ?, last_seen = ? WHERE mac = ?",
                (ip, hostname, now, mac),
            )
            return {"is_new": False, "previous_ip": old_ip if old_ip != ip else None}
        connection.execute(
            "INSERT INTO devices (ip, mac, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (ip, mac, hostname, now, now),
        )
        return {"is_new": True, "previous_ip": None}


def get_devices():
    with _connect() as connection:
        return connection.execute(
            "SELECT ip, mac, hostname, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
        ).fetchall()


def save_port_scan(ip: str, port: int, service: str, run_id: int | None = None):
    with _connect() as connection:
        connection.execute(
            "INSERT INTO port_scans (ip, port, service, scanned_at) VALUES (?, ?, ?, ?)",
            (ip, port, service, _now()),
        )


def get_latest_open_ports(ip: str) -> set[int]:
    """Return ports from the most recent scan batch for an IP."""
    with _connect() as connection:
        latest = connection.execute(
            "SELECT MAX(scanned_at) AS scanned_at FROM port_scans WHERE ip = ?", (ip,)
        ).fetchone()["scanned_at"]
        if not latest:
            return set()
        rows = connection.execute(
            "SELECT DISTINCT port FROM port_scans WHERE ip = ? AND scanned_at = ?", (ip, latest)
        ).fetchall()
        return {row["port"] for row in rows}


def save_alert(run_id: int, alert: dict):
    with _connect() as connection:
        cursor = connection.execute("""
            INSERT INTO alerts
                (run_id, created_at, severity, category, title, description,
                 device_ip, device_mac, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, alert.get("created_at", _now()), alert["severity"], alert["category"],
            alert["title"], alert["description"], alert.get("device_ip"), alert.get("device_mac"),
            json.dumps(alert.get("evidence", {}), ensure_ascii=False),
        ))
        return int(cursor.lastrowid)


def get_alerts(limit: int = 100, unacknowledged_only: bool = False):
    where = "WHERE acknowledged = 0" if unacknowledged_only else ""
    with _connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item["evidence"] or "{}")
            results.append(item)
        return results


def get_alert_summary():
    with _connect() as connection:
        totals = connection.execute("""
            SELECT severity, COUNT(*) AS count FROM alerts
            WHERE acknowledged = 0 GROUP BY severity
        """).fetchall()
        return {row["severity"]: row["count"] for row in totals}


def acknowledge_alert(alert_id: int) -> bool:
    with _connect() as connection:
        cursor = connection.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        return cursor.rowcount > 0
