"""SQLite-backed incident ticket tracking - a single analyst's personal
case log, not a shared/multi-tenant store. Three tables: incidents (the
tickets themselves), incident_updates (the note/audit trail per ticket),
and sops (per-alert-type runbook steps, editable without a code change).
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from datetime import datetime, timedelta, timezone

DEFAULT_DB_PATH = os.environ.get("TRACKER_DB_PATH", "tracker.db")

VALID_STATUSES = ("open", "escalated", "resolved", "false_positive")


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            disposition_reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT
        )
        """
    )
    existing_incident_columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
    if "external_ticket_ref" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN external_ticket_ref TEXT")
    if "awaiting_stakeholder_reply" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN awaiting_stakeholder_reply INTEGER NOT NULL DEFAULT 0")
    if "affected_user" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN affected_user TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_affected_user ON incidents(affected_user)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL UNIQUE,
            steps TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    existing_sop_columns = {row[1] for row in conn.execute("PRAGMA table_info(sops)").fetchall()}
    if "category" not in existing_sop_columns:
        conn.execute("ALTER TABLE sops ADD COLUMN category TEXT")
    if "structured_json" not in existing_sop_columns:
        conn.execute("ALTER TABLE sops ADD COLUMN structured_json TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_incident(row: sqlite3.Row) -> dict:
    return dict(row)


def _create_incident_sync(db_path: str, alert_type: str, title: str, description: str | None,
                           external_ticket_ref: str | None, affected_user: str | None) -> dict:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "INSERT INTO incidents (alert_type, title, description, status, created_at, updated_at, "
            "external_ticket_ref, affected_user) VALUES (?, ?, ?, 'open', ?, ?, ?, ?)",
            (alert_type, title, description, now, now, external_ticket_ref, affected_user),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _row_to_incident(row)
    finally:
        conn.close()


def _set_awaiting_stakeholder_sync(db_path: str, incident_id: int, awaiting: bool) -> bool:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "UPDATE incidents SET awaiting_stakeholder_reply = ?, updated_at = ? WHERE id = ?",
            (1 if awaiting else 0, now, incident_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def _get_shift_summary_sync(db_path: str, hours: int) -> dict:
    conn = _connect(db_path)
    try:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        rows = conn.execute("SELECT * FROM incidents WHERE created_at >= ?", (since,)).fetchall()
        incidents = [_row_to_incident(r) for r in rows]

        by_status: dict[str, int] = {}
        for incident in incidents:
            by_status[incident["status"]] = by_status.get(incident["status"], 0) + 1

        return {
            "window_hours": hours,
            "total_incidents": len(incidents),
            "by_status": by_status,
            "with_external_ticket": sum(1 for i in incidents if i["external_ticket_ref"]),
            "awaiting_stakeholder_reply": sum(1 for i in incidents if i["awaiting_stakeholder_reply"]),
        }
    finally:
        conn.close()


def _get_incident_sync(db_path: str, incident_id: int) -> dict | None:
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return _row_to_incident(row) if row else None
    finally:
        conn.close()


def _list_incidents_sync(db_path: str, status: str | None) -> list[dict]:
    conn = _connect(db_path)
    try:
        if status:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC", (status,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        return [_row_to_incident(r) for r in rows]
    finally:
        conn.close()


def _update_status_sync(db_path: str, incident_id: int, status: str, disposition_reason: str | None) -> bool:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        resolved_at = now if status in ("resolved", "false_positive") else None
        cursor = conn.execute(
            "UPDATE incidents SET status = ?, disposition_reason = COALESCE(?, disposition_reason), "
            "updated_at = ?, resolved_at = ? WHERE id = ?",
            (status, disposition_reason, now, resolved_at, incident_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def _add_update_note_sync(db_path: str, incident_id: int, note: str) -> bool:
    conn = _connect(db_path)
    try:
        exists = conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not exists:
            return False
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO incident_updates (incident_id, note, created_at) VALUES (?, ?, ?)",
            (incident_id, note, now),
        )
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        conn.commit()
        return True
    finally:
        conn.close()


def _get_updates_sync(db_path: str, incident_id: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC", (incident_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _get_stale_incidents_sync(db_path: str, hours_threshold: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_threshold)).isoformat()
        rows = conn.execute(
            "SELECT * FROM incidents WHERE status IN ('open', 'escalated') AND updated_at < ? ORDER BY updated_at ASC",
            (cutoff,),
        ).fetchall()
        return [_row_to_incident(r) for r in rows]
    finally:
        conn.close()


def _get_user_history_sync(db_path: str, affected_user: str) -> list[dict]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE affected_user = ? ORDER BY created_at DESC", (affected_user,)
        ).fetchall()
        return [_row_to_incident(r) for r in rows]
    finally:
        conn.close()


def _export_incidents_csv_sync(db_path: str) -> str:
    import csv
    import io

    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        buffer = io.StringIO()
        if rows:
            writer = csv.DictWriter(buffer, fieldnames=rows[0].keys())
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))
        else:
            buffer.write(
                "id,alert_type,title,description,status,disposition_reason,created_at,updated_at,"
                "resolved_at,external_ticket_ref,awaiting_stakeholder_reply,affected_user\n"
            )
        return buffer.getvalue()
    finally:
        conn.close()


def _get_setting_sync(db_path: str, key: str) -> str | None:
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
    finally:
        conn.close()


def _set_setting_sync(db_path: str, key: str, value: str) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()


def _row_to_sop(row: sqlite3.Row) -> dict:
    import json
    sop = dict(row)
    raw = sop.pop("structured_json", None)
    sop["structured"] = json.loads(raw) if raw else None
    return sop


def _upsert_sop_sync(db_path: str, alert_type: str, steps: str, category: str | None = None,
                      structured: dict | None = None) -> None:
    import json
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        structured_json = json.dumps(structured) if structured else None
        conn.execute(
            "INSERT INTO sops (alert_type, steps, category, structured_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(alert_type) DO UPDATE SET steps = excluded.steps, category = excluded.category, "
            "structured_json = excluded.structured_json, updated_at = excluded.updated_at",
            (alert_type, steps, category, structured_json, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _get_sop_sync(db_path: str, alert_type: str) -> dict | None:
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM sops WHERE alert_type = ?", (alert_type,)).fetchone()
        return _row_to_sop(row) if row else None
    finally:
        conn.close()


def _list_sops_sync(db_path: str) -> list[dict]:
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM sops ORDER BY alert_type ASC").fetchall()
        return [_row_to_sop(r) for r in rows]
    finally:
        conn.close()


class TrackerDB:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH

    async def create_incident(self, alert_type: str, title: str, description: str | None = None,
                               external_ticket_ref: str | None = None, affected_user: str | None = None) -> dict:
        return await asyncio.to_thread(
            _create_incident_sync, self.db_path, alert_type, title, description, external_ticket_ref, affected_user
        )

    async def set_awaiting_stakeholder(self, incident_id: int, awaiting: bool) -> bool:
        return await asyncio.to_thread(_set_awaiting_stakeholder_sync, self.db_path, incident_id, awaiting)

    async def get_shift_summary(self, hours: int = 8) -> dict:
        return await asyncio.to_thread(_get_shift_summary_sync, self.db_path, hours)

    async def get_user_history(self, affected_user: str) -> list[dict]:
        return await asyncio.to_thread(_get_user_history_sync, self.db_path, affected_user)

    async def export_incidents_csv(self) -> str:
        return await asyncio.to_thread(_export_incidents_csv_sync, self.db_path)

    async def get_setting(self, key: str) -> str | None:
        return await asyncio.to_thread(_get_setting_sync, self.db_path, key)

    async def set_setting(self, key: str, value: str) -> None:
        await asyncio.to_thread(_set_setting_sync, self.db_path, key, value)

    async def get_incident(self, incident_id: int) -> dict | None:
        return await asyncio.to_thread(_get_incident_sync, self.db_path, incident_id)

    async def list_incidents(self, status: str | None = None) -> list[dict]:
        return await asyncio.to_thread(_list_incidents_sync, self.db_path, status)

    async def update_status(self, incident_id: int, status: str, disposition_reason: str | None = None) -> bool:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status {status!r} - must be one of {VALID_STATUSES}")
        if status in ("resolved", "false_positive"):
            incident = await self.get_incident(incident_id)
            if incident:
                if incident["awaiting_stakeholder_reply"]:
                    raise ValueError("Cannot close while still awaiting a stakeholder reply.")
                if not disposition_reason and not incident["disposition_reason"]:
                    raise ValueError("Closure requires a disposition reason explaining the resolution.")
        return await asyncio.to_thread(_update_status_sync, self.db_path, incident_id, status, disposition_reason)

    async def add_update_note(self, incident_id: int, note: str) -> bool:
        return await asyncio.to_thread(_add_update_note_sync, self.db_path, incident_id, note)

    async def get_updates(self, incident_id: int) -> list[dict]:
        return await asyncio.to_thread(_get_updates_sync, self.db_path, incident_id)

    async def get_stale_incidents(self, hours_threshold: int = 24) -> list[dict]:
        return await asyncio.to_thread(_get_stale_incidents_sync, self.db_path, hours_threshold)

    async def upsert_sop(self, alert_type: str, steps: str, category: str | None = None,
                          structured: dict | None = None) -> None:
        await asyncio.to_thread(_upsert_sop_sync, self.db_path, alert_type, steps, category, structured)

    async def get_sop(self, alert_type: str) -> dict | None:
        return await asyncio.to_thread(_get_sop_sync, self.db_path, alert_type)

    async def list_sops(self) -> list[dict]:
        return await asyncio.to_thread(_list_sops_sync, self.db_path)
