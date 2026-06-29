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


async def test_closing_without_reason_rejected(db):
    incident = await db.create_incident("Phishing", "test")
    with pytest.raises(ValueError, match="disposition reason"):
        await db.update_status(incident["id"], "resolved")


async def test_false_positive_without_reason_rejected(db):
    incident = await db.create_incident("Phishing", "test")
    with pytest.raises(ValueError, match="disposition reason"):
        await db.update_status(incident["id"], "false_positive")


async def test_closing_while_awaiting_stakeholder_rejected(db):
    incident = await db.create_incident("Phishing", "test")
    await db.set_awaiting_stakeholder(incident["id"], True)
    with pytest.raises(ValueError, match="stakeholder"):
        await db.update_status(incident["id"], "resolved", "Confirmed benign")


async def test_closing_after_stakeholder_replied_succeeds(db):
    incident = await db.create_incident("Phishing", "test")
    await db.set_awaiting_stakeholder(incident["id"], True)
    await db.set_awaiting_stakeholder(incident["id"], False)
    await db.update_status(incident["id"], "resolved", "Confirmed benign")
    fetched = await db.get_incident(incident["id"])
    assert fetched["status"] == "resolved"


async def test_closing_with_existing_disposition_reason_does_not_require_new_one(db):
    incident = await db.create_incident("Phishing", "test")
    await db.update_status(incident["id"], "escalated", "Needs IR review")
    await db.update_status(incident["id"], "resolved")
    fetched = await db.get_incident(incident["id"])
    assert fetched["status"] == "resolved"
    assert fetched["disposition_reason"] == "Needs IR review"


async def test_escalating_without_reason_does_not_require_closure_checks(db):
    incident = await db.create_incident("Phishing", "test")
    await db.update_status(incident["id"], "escalated")
    fetched = await db.get_incident(incident["id"])
    assert fetched["status"] == "escalated"


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
    await db.update_status(incident["id"], "resolved", "Confirmed benign")
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


async def test_search_incidents_matches_title(db):
    await db.create_incident("Phishing", "Suspicious email about invoice")
    await db.create_incident("Brute Force", "Many failed VPN logins")
    results = await db.search_incidents("invoice")
    assert len(results) == 1
    assert "invoice" in results[0]["title"]


async def test_search_incidents_matches_alert_type(db):
    await db.create_incident("Azure Risky Sign-in", "test")
    results = await db.search_incidents("risky sign-in")
    assert len(results) == 1


async def test_search_incidents_matches_affected_user(db):
    await db.create_incident("Phishing", "test", affected_user="jdoe")
    results = await db.search_incidents("jdoe")
    assert len(results) == 1


async def test_search_incidents_case_insensitive(db):
    await db.create_incident("Phishing", "URGENT Email From CEO")
    results = await db.search_incidents("urgent")
    assert len(results) == 1


async def test_search_incidents_no_match_returns_empty(db):
    await db.create_incident("Phishing", "test")
    results = await db.search_incidents("nonexistent-query-xyz")
    assert results == []


async def test_search_incidents_respects_limit(db):
    for i in range(10):
        await db.create_incident("Phishing", f"matching ticket {i}")
    results = await db.search_incidents("matching", limit=3)
    assert len(results) == 3


async def test_search_sops_matches_alert_type(db):
    await db.upsert_sop("Azure Risky Sign-in", "steps", category="SOP-03: Risky Sign-in")
    results = await db.search_sops("risky")
    assert len(results) == 1


async def test_search_sops_matches_category(db):
    await db.upsert_sop("Custom Rule", "steps", category="SOP-02: MFA Abuse")
    results = await db.search_sops("MFA")
    assert len(results) == 1


async def test_sop_with_structured_rule_book_fields(db):
    structured = {
        "investigation_steps": ["Check source IP", "Review auth logs"],
        "required_fields": ["Source IP", "Username"],
        "escalation_criteria": "More than 50 attempts in 10 minutes",
        "splunk_query_hint": "index=vpn action=failure",
        "containment_actions": ["Block source IP at firewall"],
        "closure_checklist": ["Evidence attached", "Stakeholder notified"],
        "false_positive_indicators": ["Known scheduled job IP"],
    }
    await db.upsert_sop("GP-VPN Brute Force Attempts", "1. Check source\n2. Block if malicious",
                         category="SOP-01: VPN / Authentication / Password Spraying", structured=structured)
    sop = await db.get_sop("GP-VPN Brute Force Attempts")
    assert sop["category"] == "SOP-01: VPN / Authentication / Password Spraying"
    assert sop["structured"]["escalation_criteria"] == "More than 50 attempts in 10 minutes"
    assert "Check source IP" in sop["structured"]["investigation_steps"]


async def test_sop_without_structured_fields_has_none(db):
    await db.upsert_sop("Phishing", "basic steps")
    sop = await db.get_sop("Phishing")
    assert sop["structured"] is None
    assert sop["category"] is None


async def test_get_setting_missing_returns_none(db):
    assert await db.get_setting("nonexistent_key") is None


async def test_set_and_get_setting(db):
    await db.set_setting("admin_password_hash", "some-hash-value")
    assert await db.get_setting("admin_password_hash") == "some-hash-value"


async def test_set_setting_overwrites_existing(db):
    await db.set_setting("admin_password_hash", "old-hash")
    await db.set_setting("admin_password_hash", "new-hash")
    assert await db.get_setting("admin_password_hash") == "new-hash"


async def test_create_incident_with_external_ticket_ref(db):
    incident = await db.create_incident("Phishing", "test", external_ticket_ref="INC0012345")
    assert incident["external_ticket_ref"] == "INC0012345"


async def test_create_incident_without_external_ticket_ref_is_none(db):
    incident = await db.create_incident("Phishing", "test")
    assert incident["external_ticket_ref"] is None


async def test_awaiting_stakeholder_defaults_false(db):
    incident = await db.create_incident("Phishing", "test")
    assert incident["awaiting_stakeholder_reply"] == 0


async def test_set_awaiting_stakeholder(db):
    incident = await db.create_incident("Phishing", "test")
    await db.set_awaiting_stakeholder(incident["id"], True)
    fetched = await db.get_incident(incident["id"])
    assert fetched["awaiting_stakeholder_reply"] == 1
    await db.set_awaiting_stakeholder(incident["id"], False)
    fetched = await db.get_incident(incident["id"])
    assert fetched["awaiting_stakeholder_reply"] == 0


async def test_set_awaiting_stakeholder_missing_incident_returns_false(db):
    result = await db.set_awaiting_stakeholder(99999, True)
    assert result is False


async def test_shift_summary_empty(db):
    summary = await db.get_shift_summary(hours=8)
    assert summary["total_incidents"] == 0
    assert summary["by_status"] == {}
    assert summary["with_external_ticket"] == 0
    assert summary["awaiting_stakeholder_reply"] == 0


async def test_shift_summary_counts_correctly(db):
    a = await db.create_incident("Phishing", "a", external_ticket_ref="INC001")
    b = await db.create_incident("System Compromise", "b")
    await db.update_status(b["id"], "escalated")
    await db.set_awaiting_stakeholder(a["id"], True)

    summary = await db.get_shift_summary(hours=8)
    assert summary["total_incidents"] == 2
    assert summary["by_status"]["open"] == 1
    assert summary["by_status"]["escalated"] == 1
    assert summary["with_external_ticket"] == 1
    assert summary["awaiting_stakeholder_reply"] == 1


async def test_create_incident_with_affected_user(db):
    incident = await db.create_incident("Phishing", "test", affected_user="jdoe")
    assert incident["affected_user"] == "jdoe"


async def test_get_user_history_returns_only_that_users_incidents(db):
    await db.create_incident("Phishing", "a", affected_user="jdoe")
    await db.create_incident("Brute Force", "b", affected_user="jdoe")
    await db.create_incident("System Compromise", "c", affected_user="asmith")

    history = await db.get_user_history("jdoe")
    assert len(history) == 2
    assert all(i["affected_user"] == "jdoe" for i in history)


async def test_get_user_history_empty_for_unknown_user(db):
    await db.create_incident("Phishing", "a", affected_user="jdoe")
    history = await db.get_user_history("nosuchuser")
    assert history == []


async def test_disposition_history_counts_by_status(db):
    a = await db.create_incident("Phishing", "a")
    b = await db.create_incident("Phishing", "b")
    c = await db.create_incident("Phishing", "c")
    await db.update_status(a["id"], "false_positive", "benign")
    await db.update_status(b["id"], "false_positive", "benign")
    await db.update_status(c["id"], "resolved", "confirmed")

    history = await db.get_disposition_history("Phishing")
    assert history["total"] == 3
    assert history["by_status"]["false_positive"] == 2
    assert history["by_status"]["resolved"] == 1


async def test_disposition_history_empty_for_unknown_alert_type(db):
    history = await db.get_disposition_history("Nonexistent Alert Type")
    assert history == {"by_status": {}, "total": 0}


async def test_disposition_history_case_insensitive(db):
    await db.create_incident("phishing", "a")
    history = await db.get_disposition_history("Phishing")
    assert history["total"] == 1


async def test_export_csv_empty_db_has_header_only(db):
    csv_text = await db.export_incidents_csv()
    lines = csv_text.strip().splitlines()
    assert len(lines) == 1
    assert "alert_type" in lines[0]


async def test_export_csv_includes_incident_data(db):
    await db.create_incident("Phishing", "Suspicious email", affected_user="jdoe")
    csv_text = await db.export_incidents_csv()
    assert "Phishing" in csv_text
    assert "Suspicious email" in csv_text
    assert "jdoe" in csv_text


async def test_export_csv_is_parseable(db):
    import csv as csv_module
    import io
    await db.create_incident("Phishing", "test, with a comma", affected_user="jdoe")
    csv_text = await db.export_incidents_csv()
    reader = csv_module.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["title"] == "test, with a comma"


async def test_shift_summary_excludes_incidents_outside_window():
    import sqlite3
    from datetime import datetime, timedelta, timezone
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        db = TrackerDB(db_path=db_path)
        await db.create_incident("Phishing", "old one")

        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE incidents SET created_at = ?", (old_time,))
        conn.commit()
        conn.close()

        summary = await db.get_shift_summary(hours=8)
        assert summary["total_incidents"] == 0
