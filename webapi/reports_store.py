"""
Persistent storage for scan reports.

A scan result (findings, counts) plus the context needed to
re-run per-finding exploit generation (target, auth, schema) is saved as a
named *report* in a small SQLite database. Reports are listed, viewed, edited
and deleted from the Reports tab in the UI — they are never shown on the Scan
tab, which only kicks off a scan.

The database is a single file whose location is configurable with the
``GRAPEQL_REPORTS_DB`` environment variable (default: ``reports.db`` in the
current working directory).
"""

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

REPORTS_DB = Path(os.environ.get("GRAPEQL_REPORTS_DB", "reports.db")).resolve()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(REPORTS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the reports table if it does not exist."""
    REPORTS_DB.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                target     TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                data       TEXT NOT NULL
            )
            """
        )


def _summary(row: sqlite3.Row) -> Dict[str, Any]:
    """Lightweight listing entry — no full findings payload."""
    data = json.loads(row["data"])
    result = data.get("result", {}) if isinstance(data, dict) else {}
    return {
        "id": row["id"],
        "name": row["name"],
        "target": row["target"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "counts": result.get("counts", {}),
        "total": result.get("total", 0),
    }


def _full(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "target": row["target"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "data": json.loads(row["data"]),
    }


def create_report(name: str, target: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a new report and return its full record."""
    report_id = uuid.uuid4().hex
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO reports (id, name, target, created_at, updated_at, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (report_id, name, target, now, now, json.dumps(data)),
        )
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return _full(row)


def list_reports() -> List[Dict[str, Any]]:
    """Return report summaries, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC"
        ).fetchall()
    return [_summary(r) for r in rows]


def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
    return _full(row) if row else None


def update_report(
    report_id: str,
    name: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Update a report's name and/or data. Returns the updated record."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        if row is None:
            return None
        new_name = name if name is not None else row["name"]
        if data is not None:
            new_data = data
            new_target = data.get("target") if isinstance(data, dict) else row["target"]
        else:
            new_data = json.loads(row["data"])
            new_target = row["target"]
        conn.execute(
            "UPDATE reports SET name = ?, target = ?, updated_at = ?, data = ? "
            "WHERE id = ?",
            (new_name, new_target, time.time(), json.dumps(new_data), report_id),
        )
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
    return _full(row)


def delete_report(report_id: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    return cur.rowcount > 0
