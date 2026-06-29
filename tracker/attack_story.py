"""Builds a chronological narrative across all of one user's incidents -
"08:45 phishing email received... 08:52 risky sign-in detected... 09:00
host isolated" - instead of separate, disconnected ticket rows. Built
entirely from data already tracked (incident creation, update notes,
closure), not inferred/generated.
"""

from __future__ import annotations

from .db import TrackerDB


async def build_attack_story(db: TrackerDB, affected_user: str) -> list[dict]:
    incidents = await db.get_user_history(affected_user)
    if not incidents:
        return []

    events = []
    for incident in incidents:
        events.append({
            "timestamp": incident["created_at"],
            "description": f"Incident #{incident['id']} created: [{incident['alert_type']}] {incident['title']}",
            "incident_id": incident["id"],
        })

        updates = await db.get_updates(incident["id"])
        for update in updates:
            events.append({
                "timestamp": update["created_at"],
                "description": f"Note on #{incident['id']}: {update['note']}",
                "incident_id": incident["id"],
            })

        if incident["resolved_at"]:
            reason = f" - {incident['disposition_reason']}" if incident["disposition_reason"] else ""
            events.append({
                "timestamp": incident["resolved_at"],
                "description": f"Incident #{incident['id']} marked {incident['status']}{reason}",
                "incident_id": incident["id"],
            })

    events.sort(key=lambda e: e["timestamp"])
    return events
