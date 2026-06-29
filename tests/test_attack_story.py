import tempfile
from pathlib import Path

import pytest

from tracker.attack_story import build_attack_story
from tracker.db import TrackerDB


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


async def test_empty_for_unknown_user(db):
    story = await build_attack_story(db, "nosuchuser")
    assert story == []


async def test_includes_incident_creation_event(db):
    await db.create_incident("Phishing", "Suspicious email", affected_user="jdoe")
    story = await build_attack_story(db, "jdoe")
    assert len(story) == 1
    assert "created" in story[0]["description"]
    assert "Phishing" in story[0]["description"]


async def test_includes_update_notes(db):
    incident = await db.create_incident("Phishing", "test", affected_user="jdoe")
    await db.add_update_note(incident["id"], "Checked headers")
    story = await build_attack_story(db, "jdoe")
    assert any("Checked headers" in e["description"] for e in story)


async def test_includes_closure_event(db):
    incident = await db.create_incident("Phishing", "test", affected_user="jdoe")
    await db.update_status(incident["id"], "resolved", "Confirmed benign")
    story = await build_attack_story(db, "jdoe")
    closure_events = [e for e in story if "resolved" in e["description"]]
    assert len(closure_events) == 1
    assert "Confirmed benign" in closure_events[0]["description"]


async def test_merges_multiple_incidents_chronologically(db):
    first = await db.create_incident("Phishing", "first", affected_user="jdoe")
    second = await db.create_incident("Azure Risky Sign-in", "second", affected_user="jdoe")
    story = await build_attack_story(db, "jdoe")
    incident_ids_in_order = [e["incident_id"] for e in story]
    assert incident_ids_in_order == sorted(incident_ids_in_order) or incident_ids_in_order == [first["id"], second["id"]]
    assert len(story) == 2


async def test_events_sorted_by_timestamp(db):
    incident = await db.create_incident("Phishing", "test", affected_user="jdoe")
    await db.add_update_note(incident["id"], "first note")
    await db.add_update_note(incident["id"], "second note")
    await db.update_status(incident["id"], "resolved", "done")
    story = await build_attack_story(db, "jdoe")
    timestamps = [e["timestamp"] for e in story]
    assert timestamps == sorted(timestamps)


async def test_excludes_other_users(db):
    await db.create_incident("Phishing", "test", affected_user="jdoe")
    await db.create_incident("Phishing", "other", affected_user="asmith")
    story = await build_attack_story(db, "jdoe")
    assert len(story) == 1
