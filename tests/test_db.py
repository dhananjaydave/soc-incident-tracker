import tempfile
from pathlib import Path

import pytest

from tracker.db import TrackerDB


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test_tracker.db"))


async def test_create_and_get_incident(db):
    created = await db.create_incident("System Compromise", "Host X showing C2 traffic")
    assert created["status"] == "open"
    fetched = await db.get_incident(created["id"])
    assert fetched["title"] == "Host X showing C2 traffic"


async def test_get_nonexistent_incident_returns_none(db):
    assert await db.get_incident(99999) is None


async def test_list_incidents_filters_by_status(db):
    await db.create_incident("Phishing", "Email reported")
    escalated = await db.create_incident("System Compromise", "Active C2")
    await db.update_status(escalated["id"], "escalated")

    open_only = await db.list_incidents(status="open")
    escalated_only = await db.list_incidents(status="escalated")
    assert len(open_only) == 1
    assert len(escalated_only) == 1
    assert escalated_only[0]["id"] == escalated["id"]


async def test_update_status_sets_resolved_at_for_terminal_states(db):
    incident = await db.create_incident("Brute Force", "Many failed logins")
    assert incident["resolved_at"] is None
    await db.update_status(incident["id"], "resolved", "Confirmed benign - known admin retry")
    fetched = await db.get_incident(incident["id"])
    assert fetched["resolved_at"] is not None
    assert fetched["disposition_reason"] == "Confirmed benign - known admin retry"


async def test_update_status_does_not_set_resolved_at_for_open_or_escalated(db):
    incident = await db.create_incident("Phishing", "test")
    await db.update_status(incident["id"], "escalated", "Needs IR review")
    fetched = await db.get_incident(incident["id"])
    assert fetched["resolved_at"] is None


async def test_invalid_status_rejected(db):
    incident = await db.create_incident("Phishing", "test")
    with pytest.raises(ValueError):
        await db.update_status(incident["id"], "not_a_real_status")


async def test_update_status_on_missing_incident_returns_false(db):
    result = await db.update_status(99999, "resolved")
    assert result is False


async def test_add_and_retrieve_update_notes(db):
    incident = await db.create_incident("System Compromise", "test")
    await db.add_update_note(incident["id"], "Isolated the host")
    await db.add_update_note(incident["id"], "Confirmed with IT - safe to close")
    notes = await db.get_updates(incident["id"])
    assert len(notes) == 2
    assert notes[0]["note"] == "Isolated the host"


async def test_add_note_on_missing_incident_returns_false(db):
    result = await db.add_update_note(99999, "note")
    assert result is False


async def test_stale_incidents_detected():
    import sqlite3
    from datetime import datetime, timedelta, timezone
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        db = TrackerDB(db_path=db_path)
        incident = await db.create_incident("System Compromise", "old ticket")

        # Manually backdate updated_at, since the public API always
        # stamps "now" - simulating a ticket that's genuinely gone stale.
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (old_time, incident["id"]))
        conn.commit()
        conn.close()

        stale = await db.get_stale_incidents(hours_threshold=24)
        assert len(stale) == 1
        assert stale[0]["id"] == incident["id"]


async def test_recently_updated_incident_not_stale(db):
    await db.create_incident("System Compromise", "fresh ticket")
    stale = await db.get_stale_incidents(hours_threshold=24)
    assert stale == []


async def test_resolved_incident_never_counted_as_stale(db):
    incident = await db.create_incident("Phishing", "test")
    await db.update_status(incident["id"], "resolved")
    stale = await db.get_stale_incidents(hours_threshold=0)
    assert stale == []


async def test_sop_upsert_and_get(db):
    await db.upsert_sop("System Compromise", "1. Isolate host\n2. Preserve evidence\n3. Escalate to IR")
    sop = await db.get_sop("System Compromise")
    assert "Isolate host" in sop["steps"]


async def test_sop_upsert_overwrites_existing(db):
    await db.upsert_sop("Phishing", "Old steps")
    await db.upsert_sop("Phishing", "New steps")
    sop = await db.get_sop("Phishing")
    assert sop["steps"] == "New steps"


async def test_sop_missing_returns_none(db):
    assert await db.get_sop("Nonexistent Type") is None


async def test_list_sops(db):
    await db.upsert_sop("Phishing", "steps a")
    await db.upsert_sop("System Compromise", "steps b")
    sops = await db.list_sops()
    assert len(sops) == 2
