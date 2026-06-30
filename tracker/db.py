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
VALID_PRIORITIES = ("low", "medium", "high")

# The core disposition/verdict enum - the single most customer-visible
# field on a closed ticket (per GAP Cyber Defense's alert schema). Kept
# separate from the free-text disposition_reason: verdict is the fixed
# classification, disposition_reason remains the analyst's prose
# explanation of *why*.
VALID_DISPOSITION_VERDICTS = (
    "Malicious", "Unresolved-suspicious", "Policy violation", "Authorized", "Benign-other",
)
VALID_DETECTION_QUALITY = ("Working", "Logic gap", "Context gap", "Data gap", "Duplicate")

# The analyst's own self-reported checklist - explicitly ticked per
# incident, distinct from investigation_score.py's heuristic estimate
# (which infers status from existing data rather than asking).
CHECKLIST_ITEMS = (
    "User verified", "Logs reviewed", "Related alerts checked",
    "Evidence collected", "SOP followed", "Recommendations provided",
)


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
    if "priority" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN priority TEXT NOT NULL DEFAULT 'medium'")
    if "checklist_json" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN checklist_json TEXT")
    if "confidence_percent" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN confidence_percent INTEGER")
    if "disposition_verdict" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN disposition_verdict TEXT")
    if "evidence_reference" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN evidence_reference TEXT")
    if "activity_occurred" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN activity_occurred INTEGER")
    if "detection_quality" not in existing_incident_columns:
        conn.execute("ALTER TABLE incidents ADD COLUMN detection_quality TEXT")
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
    import json
    incident = dict(row)
    raw = incident.pop("checklist_json", None)
    saved = json.loads(raw) if raw else {}
    incident["checklist"] = {item: saved.get(item, False) for item in CHECKLIST_ITEMS}
    if incident.get("activity_occurred") is not None:
        incident["activity_occurred"] = bool(incident["activity_occurred"])
    return incident


def _create_incident_sync(db_path: str, alert_type: str, title: str, description: str | None,
                           external_ticket_ref: str | None, affected_user: str | None, priority: str) -> dict:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "INSERT INTO incidents (alert_type, title, description, status, created_at, updated_at, "
            "external_ticket_ref, affected_user, priority) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)",
            (alert_type, title, description, now, now, external_ticket_ref, affected_user, priority),
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


def _set_priority_sync(db_path: str, incident_id: int, priority: str) -> bool:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "UPDATE incidents SET priority = ?, updated_at = ? WHERE id = ?",
            (priority, now, incident_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def _set_checklist_item_sync(db_path: str, incident_id: int, item: str, checked: bool) -> bool:
    import json
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT checklist_json FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            return False
        current = json.loads(row["checklist_json"]) if row["checklist_json"] else {}
        current[item] = checked
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE incidents SET checklist_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(current), now, incident_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def _set_confidence_sync(db_path: str, incident_id: int, confidence_percent: int) -> bool:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "UPDATE incidents SET confidence_percent = ?, updated_at = ? WHERE id = ?",
            (confidence_percent, now, incident_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def _set_disposition_sync(db_path: str, incident_id: int, verdict: str, evidence_reference: str | None,
                           activity_occurred: bool, detection_quality: str) -> bool:
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "UPDATE incidents SET disposition_verdict = ?, evidence_reference = ?, "
            "activity_occurred = ?, detection_quality = ?, updated_at = ? WHERE id = ?",
            (verdict, evidence_reference, int(activity_occurred), detection_quality, now, incident_id),
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


def _list_incidents_sync(db_path: str, status: str | None, priority: str | None) -> list[dict]:
    conn = _connect(db_path)
    try:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if priority:
            clauses.append("priority = ?")
            params.append(priority)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(f"SELECT * FROM incidents {where} ORDER BY created_at DESC", params).fetchall()
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


def _get_disposition_history_sync(db_path: str, alert_type: str) -> dict:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM incidents WHERE alert_type = ? COLLATE NOCASE GROUP BY status",
            (alert_type,),
        ).fetchall()
        by_status = {row["status"]: row["count"] for row in rows}
        return {"by_status": by_status, "total": sum(by_status.values())}
    finally:
        conn.close()


def _get_similar_incidents_sync(db_path: str, alert_type: str, exclude_id: int, limit: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE alert_type = ? COLLATE NOCASE AND id != ? "
            "ORDER BY created_at DESC LIMIT ?",
            (alert_type, exclude_id, limit),
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


def _search_incidents_sync(db_path: str, query: str, limit: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        pattern = f"%{query}%"
        rows = conn.execute(
            "SELECT * FROM incidents WHERE alert_type LIKE ? COLLATE NOCASE OR title LIKE ? COLLATE NOCASE "
            "OR description LIKE ? COLLATE NOCASE OR affected_user LIKE ? COLLATE NOCASE "
            "OR external_ticket_ref LIKE ? COLLATE NOCASE ORDER BY created_at DESC LIMIT ?",
            (pattern, pattern, pattern, pattern, pattern, limit),
        ).fetchall()
        return [_row_to_incident(r) for r in rows]
    finally:
        conn.close()


def _search_sops_sync(db_path: str, query: str, limit: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        pattern = f"%{query}%"
        rows = conn.execute(
            "SELECT * FROM sops WHERE alert_type LIKE ? COLLATE NOCASE OR category LIKE ? COLLATE NOCASE "
            "ORDER BY alert_type ASC LIMIT ?",
            (pattern, pattern, limit),
        ).fetchall()
        return [_row_to_sop(r) for r in rows]
    finally:
        conn.close()


class TrackerDB:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH

    async def create_incident(self, alert_type: str, title: str, description: str | None = None,
                               external_ticket_ref: str | None = None, affected_user: str | None = None,
                               priority: str = "medium") -> dict:
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority {priority!r} - must be one of {VALID_PRIORITIES}")
        return await asyncio.to_thread(
            _create_incident_sync, self.db_path, alert_type, title, description, external_ticket_ref,
            affected_user, priority,
        )

    async def set_priority(self, incident_id: int, priority: str) -> bool:
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority {priority!r} - must be one of {VALID_PRIORITIES}")
        return await asyncio.to_thread(_set_priority_sync, self.db_path, incident_id, priority)

    async def set_checklist_item(self, incident_id: int, item: str, checked: bool) -> bool:
        if item not in CHECKLIST_ITEMS:
            raise ValueError(f"Invalid checklist item {item!r} - must be one of {CHECKLIST_ITEMS}")
        return await asyncio.to_thread(_set_checklist_item_sync, self.db_path, incident_id, item, checked)

    async def set_confidence(self, incident_id: int, confidence_percent: int) -> bool:
        if not 0 <= confidence_percent <= 100:
            raise ValueError("confidence_percent must be between 0 and 100")
        return await asyncio.to_thread(_set_confidence_sync, self.db_path, incident_id, confidence_percent)

    async def set_disposition(self, incident_id: int, verdict: str, evidence_reference: str | None,
                               activity_occurred: bool, detection_quality: str) -> bool:
        if verdict not in VALID_DISPOSITION_VERDICTS:
            raise ValueError(f"Invalid disposition verdict {verdict!r} - must be one of {VALID_DISPOSITION_VERDICTS}")
        if detection_quality not in VALID_DETECTION_QUALITY:
            raise ValueError(f"Invalid detection quality {detection_quality!r} - must be one of {VALID_DETECTION_QUALITY}")
        if verdict == "Authorized" and not (evidence_reference and evidence_reference.strip()):
            raise ValueError("Disposition 'Authorized' requires an evidence reference (e.g. a ServiceNow/Jira ticket).")
        return await asyncio.to_thread(
            _set_disposition_sync, self.db_path, incident_id, verdict, evidence_reference,
            activity_occurred, detection_quality,
        )

    async def set_awaiting_stakeholder(self, incident_id: int, awaiting: bool) -> bool:
        return await asyncio.to_thread(_set_awaiting_stakeholder_sync, self.db_path, incident_id, awaiting)

    async def get_shift_summary(self, hours: int = 8) -> dict:
        return await asyncio.to_thread(_get_shift_summary_sync, self.db_path, hours)

    async def get_user_history(self, affected_user: str) -> list[dict]:
        return await asyncio.to_thread(_get_user_history_sync, self.db_path, affected_user)

    async def get_disposition_history(self, alert_type: str) -> dict:
        return await asyncio.to_thread(_get_disposition_history_sync, self.db_path, alert_type)

    async def get_similar_incidents(self, alert_type: str, exclude_id: int, limit: int = 3) -> list[dict]:
        return await asyncio.to_thread(_get_similar_incidents_sync, self.db_path, alert_type, exclude_id, limit)

    async def export_incidents_csv(self) -> str:
        return await asyncio.to_thread(_export_incidents_csv_sync, self.db_path)

    async def get_setting(self, key: str) -> str | None:
        return await asyncio.to_thread(_get_setting_sync, self.db_path, key)

    async def set_setting(self, key: str, value: str) -> None:
        await asyncio.to_thread(_set_setting_sync, self.db_path, key, value)

    async def get_incident(self, incident_id: int) -> dict | None:
        return await asyncio.to_thread(_get_incident_sync, self.db_path, incident_id)

    async def list_incidents(self, status: str | None = None, priority: str | None = None) -> list[dict]:
        return await asyncio.to_thread(_list_incidents_sync, self.db_path, status, priority)

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

    async def search_incidents(self, query: str, limit: int = 20) -> list[dict]:
        return await asyncio.to_thread(_search_incidents_sync, self.db_path, query, limit)

    async def search_sops(self, query: str, limit: int = 20) -> list[dict]:
        return await asyncio.to_thread(_search_sops_sync, self.db_path, query, limit)
