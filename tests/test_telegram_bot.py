import tempfile
from pathlib import Path

import pytest

from tracker.db import TrackerDB
from tracker import telegram_bot


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


async def test_help_command(db):
    reply = await telegram_bot.handle_command(db, "/help")
    assert "Commands:" in reply


async def test_unrecognized_message(db):
    reply = await telegram_bot.handle_command(db, "just some text")
    assert "Unrecognized" in reply


async def test_unknown_command(db):
    reply = await telegram_bot.handle_command(db, "/notarealcommand")
    assert "Unknown command" in reply


async def test_tickets_empty(db):
    reply = await telegram_bot.handle_command(db, "/tickets")
    assert "No open or escalated" in reply


async def test_tickets_lists_open_and_escalated_not_resolved(db):
    open_t = await db.create_incident("Phishing", "Open one")
    escalated_t = await db.create_incident("System Compromise", "Escalated one")
    await db.update_status(escalated_t["id"], "escalated")
    resolved_t = await db.create_incident("Brute Force", "Resolved one")
    await db.update_status(resolved_t["id"], "resolved")

    reply = await telegram_bot.handle_command(db, "/tickets")
    assert f"#{open_t['id']}" in reply
    assert f"#{escalated_t['id']}" in reply
    assert f"#{resolved_t['id']}" not in reply


async def test_close_command(db):
    incident = await db.create_incident("Phishing", "test")
    reply = await telegram_bot.handle_command(db, f"/close {incident['id']} confirmed benign")
    assert "marked resolved" in reply
    fetched = await db.get_incident(incident["id"])
    assert fetched["status"] == "resolved"
    assert fetched["disposition_reason"] == "confirmed benign"


async def test_close_nonexistent_ticket(db):
    reply = await telegram_bot.handle_command(db, "/close 99999 some reason")
    assert "No ticket #99999" in reply


async def test_close_with_non_numeric_id_does_not_crash(db):
    reply = await telegram_bot.handle_command(db, "/close abc some text here")
    assert "Usage" in reply


async def test_close_missing_args(db):
    reply = await telegram_bot.handle_command(db, "/close")
    assert "Usage" in reply


async def test_falsepositive_command(db):
    incident = await db.create_incident("Brute Force", "test")
    reply = await telegram_bot.handle_command(db, f"/falsepositive {incident['id']} known retry pattern")
    assert "marked false_positive" in reply
    fetched = await db.get_incident(incident["id"])
    assert fetched["status"] == "false_positive"


async def test_escalate_command(db):
    incident = await db.create_incident("System Compromise", "test")
    reply = await telegram_bot.handle_command(db, f"/escalate {incident['id']} needs IR")
    fetched = await db.get_incident(incident["id"])
    assert fetched["status"] == "escalated"


async def test_note_command(db):
    incident = await db.create_incident("Phishing", "test")
    reply = await telegram_bot.handle_command(db, f"/note {incident['id']} checked with user, legit")
    assert "Note added" in reply
    notes = await db.get_updates(incident["id"])
    assert notes[0]["note"] == "checked with user, legit"


async def test_note_missing_args(db):
    reply = await telegram_bot.handle_command(db, "/note")
    assert "Usage" in reply


async def test_sop_command_found(db):
    await db.upsert_sop("Phishing", "1. Do this\n2. Do that")
    reply = await telegram_bot.handle_command(db, "/sop Phishing")
    assert "Do this" in reply


async def test_sop_command_not_found_lists_available(db):
    await db.upsert_sop("Phishing", "steps")
    reply = await telegram_bot.handle_command(db, "/sop Nonexistent")
    assert "No SOP found" in reply
    assert "Phishing" in reply


async def test_sop_missing_args(db):
    reply = await telegram_bot.handle_command(db, "/sop")
    assert "Usage" in reply


async def test_summary_empty(db):
    reply = await telegram_bot.handle_command(db, "/summary")
    assert "No incidents in the last 8h" in reply


async def test_summary_default_window(db):
    await db.create_incident("Phishing", "test", external_ticket_ref="INC001")
    reply = await telegram_bot.handle_command(db, "/summary")
    assert "Total incidents: 1" in reply
    assert "open: 1" in reply
    assert "With an external ticket: 1" in reply


async def test_summary_custom_window(db):
    await db.create_incident("Phishing", "test")
    reply = await telegram_bot.handle_command(db, "/summary 24")
    assert "last 24h" in reply


async def test_summary_invalid_window(db):
    reply = await telegram_bot.handle_command(db, "/summary notanumber")
    assert "Usage" in reply


def test_is_authorized(monkeypatch):
    monkeypatch.setattr(telegram_bot, "ALLOWED_CHAT_IDS", {"944650675"})
    assert telegram_bot.is_authorized("944650675") is True
    assert telegram_bot.is_authorized("111111111") is False
