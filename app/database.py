import json
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "scanner_history.sqlite3"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                resolved_ip TEXT NOT NULL,
                ports_scanned INTEGER NOT NULL,
                open_count INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                results_json TEXT NOT NULL
            )
            """
        )


def save_scan(target: str, resolved_ip: str, ports_scanned: int, open_results: list[dict[str, Any]], duration_ms: float) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (target, resolved_ip, ports_scanned, open_count, duration_ms, results_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (target, resolved_ip, ports_scanned, len(open_results), round(duration_ms, 1), json.dumps(open_results)),
        )
        return int(cursor.lastrowid)


def list_scans(limit: int = 10) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, target, resolved_ip, ports_scanned, open_count, duration_ms, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["results"] = json.loads(data.pop("results_json"))
    return data
