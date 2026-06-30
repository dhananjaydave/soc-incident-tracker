import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

os.environ.setdefault("TRACKER_SECRET_KEY", "test-secret-key-not-for-production")

import pytest
from fastapi.testclient import TestClient

from tracker import api, auth
from tracker.db import TrackerDB

TEST_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setattr(api, "db", TrackerDB(db_path=str(Path(tmp) / "test.db")))
        yield


@pytest.fixture(autouse=True)
def _configured_admin(monkeypatch):
    monkeypatch.setattr(api, "ADMIN_USERNAME", "admin")
    monkeypatch.setattr(api, "ADMIN_PASSWORD_HASH", auth.hash_password(TEST_PASSWORD))


@pytest.fixture(autouse=True)
def _clear_login_rate_limit():
    auth._login_attempt_log.clear()
    yield
    auth._login_attempt_log.clear()


@pytest.fixture(autouse=True)
def _no_real_telegram_calls():
    with patch("tracker.telegram_bot.notify_all", new_callable=AsyncMock), \
         patch("tracker.telegram_bot.send_message", new_callable=AsyncMock):
        yield


@pytest.fixture
def client():
    # base_url must be https:// - the session cookie is Secure, and a
    # plain http:// TestClient base URL would silently never send it back,
    # masking real auth bugs behind what looks like a cookie problem.
    with TestClient(api.app, base_url="https://testserver") as c:
        yield c


def _login(client) -> None:
    resp = client.post("/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert resp.status_code == 200


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_index_serves_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_login_with_correct_credentials(client):
    resp = client.post("/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert resp.status_code == 200
    assert auth.SESSION_COOKIE_NAME in resp.cookies


def test_login_with_wrong_password(client):
    resp = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_with_wrong_username(client):
    resp = client.post("/login", json={"username": "notadmin", "password": TEST_PASSWORD})
    assert resp.status_code == 401


def test_login_wrong_username_and_wrong_password_take_similar_time(client):
    """A wrong username shouldn't short-circuit before the bcrypt check -
    that timing difference would let an attacker learn whether 'admin' is
    correct just from response latency, without any password attempt."""
    import time
    start = time.perf_counter()
    client.post("/login", json={"username": "notadmin", "password": "wrong"})
    wrong_username_time = time.perf_counter() - start

    start = time.perf_counter()
    client.post("/login", json={"username": "admin", "password": "wrong"})
    wrong_password_time = time.perf_counter() - start

    assert wrong_username_time > 0.05  # actually ran the slow bcrypt check, didn't short-circuit
    assert abs(wrong_username_time - wrong_password_time) < 0.1


def test_login_rate_limited_after_threshold(client):
    for _ in range(auth.LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        client.post("/login", json={"username": "admin", "password": "wrong"})
    blocked = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert blocked.status_code == 429


def test_protected_route_requires_auth(client):
    resp = client.get("/api/incidents")
    assert resp.status_code == 401


def test_protected_route_works_after_login(client):
    _login(client)
    resp = client.get("/api/incidents")
    assert resp.status_code == 200


def test_list_incidents_filters_by_priority(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "a", "priority": "low"})
    high = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "b", "priority": "high"}).json()["incident"]
    resp = client.get("/api/incidents", params={"priority": "high"})
    results = resp.json()
    assert len(results) == 1
    assert results[0]["id"] == high["id"]


def test_logout_clears_session(client):
    _login(client)
    client.post("/logout")
    resp = client.get("/api/incidents")
    assert resp.status_code == 401


def test_change_password_success(client):
    _login(client)
    resp = client.post("/api/change-password", json={
        "current_password": TEST_PASSWORD, "new_password": "a-brand-new-strong-password",
    })
    assert resp.status_code == 200


def test_change_password_then_login_with_new_password(client):
    _login(client)
    client.post("/api/change-password", json={
        "current_password": TEST_PASSWORD, "new_password": "a-brand-new-strong-password",
    })
    client.post("/logout")
    resp = client.post("/login", json={"username": "admin", "password": "a-brand-new-strong-password"})
    assert resp.status_code == 200


def test_change_password_old_password_no_longer_works(client):
    _login(client)
    client.post("/api/change-password", json={
        "current_password": TEST_PASSWORD, "new_password": "a-brand-new-strong-password",
    })
    client.post("/logout")
    resp = client.post("/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert resp.status_code == 401


def test_change_password_wrong_current_password_rejected(client):
    _login(client)
    resp = client.post("/api/change-password", json={
        "current_password": "totally-wrong", "new_password": "a-brand-new-strong-password",
    })
    assert resp.status_code == 401


def test_change_password_requires_auth(client):
    resp = client.post("/api/change-password", json={
        "current_password": TEST_PASSWORD, "new_password": "a-brand-new-strong-password",
    })
    assert resp.status_code == 401


def test_change_password_rejects_too_short_new_password(client):
    _login(client)
    resp = client.post("/api/change-password", json={"current_password": TEST_PASSWORD, "new_password": "short"})
    assert resp.status_code == 422


def test_me_endpoint(client):
    _login(client)
    resp = client.get("/api/me")
    assert resp.json()["username"] == "admin"


def test_create_incident(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "Suspicious email reported"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident"]["status"] == "open"
    assert body["sop"] is not None  # Phishing has a seeded default SOP


def test_create_incident_defaults_to_medium_priority(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"})
    assert resp.json()["incident"]["priority"] == "medium"


def test_create_incident_with_explicit_priority(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test", "priority": "high"})
    assert resp.json()["incident"]["priority"] == "high"


def test_create_incident_rejects_invalid_priority(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test", "priority": "urgent"})
    assert resp.status_code == 400


def test_set_priority_requires_auth(client):
    resp = client.post("/api/incidents/1/priority", json={"priority": "high"})
    assert resp.status_code == 401


def test_set_priority_updates_incident(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/priority", json={"priority": "high"})
    assert resp.status_code == 200
    fetched = client.get(f"/api/incidents/{created['id']}").json()["incident"]
    assert fetched["priority"] == "high"


def test_set_priority_invalid_value_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/priority", json={"priority": "urgent"})
    assert resp.status_code == 400


def test_set_priority_nonexistent_incident_404(client):
    _login(client)
    resp = client.post("/api/incidents/99999/priority", json={"priority": "high"})
    assert resp.status_code == 404


def test_checklist_items_requires_auth(client):
    resp = client.get("/api/checklist-items")
    assert resp.status_code == 401


def test_checklist_items_returns_six(client):
    _login(client)
    resp = client.get("/api/checklist-items")
    assert len(resp.json()) == 6


def test_set_checklist_item_requires_auth(client):
    resp = client.post("/api/incidents/1/checklist", json={"item": "Logs reviewed", "checked": True})
    assert resp.status_code == 401


def test_set_checklist_item_updates_incident(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/checklist", json={"item": "Logs reviewed", "checked": True})
    assert resp.status_code == 200
    fetched = client.get(f"/api/incidents/{created['id']}").json()["incident"]
    assert fetched["checklist"]["Logs reviewed"] is True


def test_set_checklist_item_invalid_item_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/checklist", json={"item": "Not real", "checked": True})
    assert resp.status_code == 400


def test_set_checklist_item_nonexistent_incident_404(client):
    _login(client)
    resp = client.post("/api/incidents/99999/checklist", json={"item": "Logs reviewed", "checked": True})
    assert resp.status_code == 404


def test_set_confidence_requires_auth(client):
    resp = client.post("/api/incidents/1/confidence", json={"confidence_percent": 85})
    assert resp.status_code == 401


def test_set_confidence_updates_incident(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/confidence", json={"confidence_percent": 85})
    assert resp.status_code == 200
    fetched = client.get(f"/api/incidents/{created['id']}").json()["incident"]
    assert fetched["confidence_percent"] == 85


def test_set_confidence_out_of_range_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/confidence", json={"confidence_percent": 150})
    assert resp.status_code == 422


def test_set_confidence_nonexistent_incident_404(client):
    _login(client)
    resp = client.post("/api/incidents/99999/confidence", json={"confidence_percent": 50})
    assert resp.status_code == 404


def test_disposition_options_requires_auth(client):
    resp = client.get("/api/disposition-options")
    assert resp.status_code == 401


def test_disposition_options_returns_five_verdicts(client):
    _login(client)
    resp = client.get("/api/disposition-options")
    assert len(resp.json()["verdicts"]) == 5
    assert "Malicious" in resp.json()["verdicts"]


def test_disposition_options_includes_verdict_definitions(client):
    _login(client)
    resp = client.get("/api/disposition-options")
    definitions = resp.json()["verdict_definitions"]
    assert set(definitions.keys()) == set(resp.json()["verdicts"])
    assert "Adversarial intent" in definitions["Malicious"]


def test_set_disposition_requires_auth(client):
    resp = client.post("/api/incidents/1/disposition", json={
        "verdict": "Malicious", "activity_occurred": True, "detection_quality": "Working",
    })
    assert resp.status_code == 401


def test_set_disposition_updates_incident(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/disposition", json={
        "verdict": "Malicious", "activity_occurred": True, "detection_quality": "Working",
    })
    assert resp.status_code == 200
    fetched = client.get(f"/api/incidents/{created['id']}").json()["incident"]
    assert fetched["disposition_verdict"] == "Malicious"


def test_set_disposition_invalid_verdict_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/disposition", json={
        "verdict": "Definitely Bad", "activity_occurred": True, "detection_quality": "Working",
    })
    assert resp.status_code == 400


def test_set_disposition_authorized_without_evidence_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/disposition", json={
        "verdict": "Authorized", "activity_occurred": True, "detection_quality": "Working",
    })
    assert resp.status_code == 400


def test_set_disposition_nonexistent_incident_404(client):
    _login(client)
    resp = client.post("/api/incidents/99999/disposition", json={
        "verdict": "Malicious", "activity_occurred": True, "detection_quality": "Working",
    })
    assert resp.status_code == 404


def test_rule_catalog_requires_auth(client):
    resp = client.get("/api/rule-catalog")
    assert resp.status_code == 401


def test_rule_catalog_returns_entries_with_expected_shape(client):
    _login(client)
    resp = client.get("/api/rule-catalog")
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) > 50
    sample = entries[0]
    assert set(sample.keys()) == {"sop", "title", "category", "category_prefix", "default_severity"}


def test_rule_catalog_lookup_exact_match(client):
    _login(client)
    resp = client.get("/api/rule-catalog/lookup", params={"title": "Access - Gap-GP-VPN Password Spraying Attempts - Rule"})
    assert resp.status_code == 200
    assert resp.json()["sop"] == "SOP-01"
    assert resp.json()["default_severity"] == "High"


def test_rule_catalog_lookup_fallback_keyword_match(client):
    _login(client)
    resp = client.get("/api/rule-catalog/lookup", params={"title": "Some New VPN Detection Rule"})
    assert resp.status_code == 200
    assert resp.json()["sop"] == "SOP-01"
    assert resp.json()["matched"] == "fallback"


def test_rule_catalog_lookup_no_match(client):
    _login(client)
    resp = client.get("/api/rule-catalog/lookup", params={"title": "Completely Unrelated Gibberish Title"})
    assert resp.status_code == 200
    assert resp.json()["sop"] is None
    assert resp.json()["matched"] == "none"


def test_sop_reference_lookup_requires_auth(client):
    resp = client.get("/api/sop-reference/lookup", params={"alert_title": "Access - Gap-GP-VPN Password Spraying Attempts - Rule"})
    assert resp.status_code == 401


def test_sop_reference_lookup_exact_match_returns_full_reference(client):
    _login(client)
    resp = client.get("/api/sop-reference/lookup", params={"alert_title": "Access - Gap-GP-VPN Password Spraying Attempts - Rule"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["sop"] == "SOP-01"
    assert data["catalog_entry"]["default_severity"] == "High"
    assert "Successful authentication is observed." in data["reference"]["l1_escalation_triggers"]


def test_sop_reference_lookup_sop_without_reference_yet(client):
    _login(client)
    resp = client.get("/api/sop-reference/lookup", params={"alert_title": "Threat - Gap-MSFT-High - Rule"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["sop"] == "SOP-04"
    assert data["reference"] is None


def test_sop_reference_lookup_no_match(client):
    _login(client)
    resp = client.get("/api/sop-reference/lookup", params={"alert_title": "Completely Unrelated Gibberish Title"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["sop"] is None
    assert data["reference"] is None


def test_detection_quality_history_requires_auth(client):
    resp = client.get("/api/detection-quality-history", params={"alert_type": "Phishing"})
    assert resp.status_code == 401


def test_detection_quality_history_reflects_past_dispositions(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    client.post(f"/api/incidents/{created['id']}/disposition", json={
        "verdict": "Malicious", "activity_occurred": True, "detection_quality": "Logic gap",
    })
    resp = client.get("/api/detection-quality-history", params={"alert_type": "Phishing"})
    assert resp.status_code == 200
    assert resp.json()["by_quality"]["Logic gap"] == 1


def test_similar_incidents_preview_requires_auth(client):
    resp = client.get("/api/similar-incidents", params={"alert_type": "Phishing"})
    assert resp.status_code == 401


def test_similar_incidents_preview_includes_all_without_exclusion(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.get("/api/similar-incidents", params={"alert_type": "Phishing"})
    assert resp.status_code == 200
    ids = {i["id"] for i in resp.json()}
    assert created["id"] in ids


def test_create_incident_unknown_alert_type_has_no_sop(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Totally Custom Type", "title": "test"})
    assert resp.json()["sop"] is None


def test_docs_disabled_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_create_incident_rejects_non_json_body(client):
    """FastAPI's own Pydantic body parsing already requires valid JSON
    matching the schema - a plain cross-site <form> POST can't produce
    that, which is exactly the CSRF protection this needs on top of the
    SameSite=Strict session cookie. No separate check required."""
    _login(client)
    resp = client.post(
        "/api/incidents",
        data="alert_type=Phishing&title=test",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 422


def test_emergency_incident_requires_auth(client):
    resp = client.post("/api/incidents/emergency", json={"title": "Active ransomware spreading"})
    assert resp.status_code == 401


def test_emergency_incident_created_already_escalated(client):
    _login(client)
    resp = client.post("/api/incidents/emergency", json={"title": "Active ransomware spreading"})
    assert resp.status_code == 200
    incident = resp.json()["incident"]
    assert incident["status"] == "escalated"
    assert incident["alert_type"] == "Major Incident"
    assert incident["disposition_reason"]


def test_emergency_incident_defaults_to_high_priority(client):
    _login(client)
    resp = client.post("/api/incidents/emergency", json={"title": "Active ransomware spreading"})
    assert resp.json()["incident"]["priority"] == "high"


def test_emergency_incident_has_rule_book_guidance(client):
    _login(client)
    created = client.post("/api/incidents/emergency", json={"title": "Active ransomware spreading"}).json()["incident"]
    resp = client.get(f"/api/incidents/{created['id']}")
    assert resp.json()["sop"] is not None


def test_emergency_incident_sends_notification(client):
    _login(client)
    with patch("tracker.api.notify", new_callable=AsyncMock) as mock_notify:
        client.post("/api/incidents/emergency", json={"title": "Active ransomware spreading"})
    mock_notify.assert_called_once()
    assert "MAJOR INCIDENT" in mock_notify.call_args[0][0]


def test_emergency_incident_appears_in_ticket_list(client):
    _login(client)
    client.post("/api/incidents/emergency", json={"title": "Active ransomware spreading"})
    resp = client.get("/api/incidents")
    assert any(t["alert_type"] == "Major Incident" for t in resp.json())


def test_get_incident_with_updates_and_sop(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    client.post(f"/api/incidents/{created['id']}/notes", json={"note": "checked headers"})
    resp = client.get(f"/api/incidents/{created['id']}")
    body = resp.json()
    assert len(body["updates"]) == 1
    assert body["sop"] is not None


def test_get_incident_includes_investigation_score(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Azure Risky Sign-in", "title": "test"}).json()["incident"]
    resp = client.get(f"/api/incidents/{created['id']}")
    score = resp.json()["investigation_score"]
    assert "percent_done" in score
    assert "items" in score


def test_get_incident_includes_disposition_history(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    client.post(f"/api/incidents/{created['id']}/status", json={"status": "false_positive", "reason": "benign"})
    resp = client.get(f"/api/incidents/{created['id']}")
    history = resp.json()["disposition_history"]
    assert history["by_status"]["false_positive"] == 1
    assert history["total"] == 1


def test_get_incident_includes_similar_incidents(client):
    _login(client)
    first = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "first"}).json()["incident"]
    second = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "second"}).json()["incident"]
    resp = client.get(f"/api/incidents/{first['id']}")
    similar_ids = [s["id"] for s in resp.json()["similar_incidents"]]
    assert second["id"] in similar_ids
    assert first["id"] not in similar_ids


def test_get_incident_includes_mitre_techniques_from_rule_book(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Azure Risky Sign-in", "title": "test"}).json()["incident"]
    resp = client.get(f"/api/incidents/{created['id']}")
    techniques = resp.json()["mitre_techniques"]
    assert any(t["id"] == "T1078" for t in techniques)


def test_get_incident_mitre_techniques_empty_for_unmapped_alert_type(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Totally Custom Type", "title": "test"}).json()["incident"]
    resp = client.get(f"/api/incidents/{created['id']}")
    assert resp.json()["mitre_techniques"] == []


def test_get_nonexistent_incident_404(client):
    _login(client)
    resp = client.get("/api/incidents/99999")
    assert resp.status_code == 404


def test_create_incident_with_affected_user(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test", "affected_user": "jdoe"})
    assert resp.json()["incident"]["affected_user"] == "jdoe"


def test_user_history(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "a", "affected_user": "jdoe"})
    client.post("/api/incidents", json={"alert_type": "Brute Force", "title": "b", "affected_user": "other"})
    resp = client.get("/api/users/jdoe/history")
    history = resp.json()
    assert len(history) == 1
    assert history[0]["affected_user"] == "jdoe"


def test_attack_story_requires_auth(client):
    resp = client.get("/api/users/jdoe/attack-story")
    assert resp.status_code == 401


def test_attack_story_returns_chronological_events(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test", "affected_user": "jdoe"})
    resp = client.get("/api/users/jdoe/attack-story")
    story = resp.json()
    assert len(story) == 1
    assert "created" in story[0]["description"]


def test_attack_story_empty_for_unknown_user(client):
    _login(client)
    resp = client.get("/api/users/nosuchuser/attack-story")
    assert resp.json() == []


def test_user_history_requires_auth(client):
    resp = client.get("/api/users/jdoe/history")
    assert resp.status_code == 401


def test_export_csv_route_not_shadowed_by_incident_id_route(client):
    """/api/incidents/export must resolve to the export route, not get
    captured by /api/incidents/{incident_id} trying (and failing) to
    parse 'export' as an int."""
    _login(client)
    resp = client.get("/api/incidents/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


def test_export_csv_contains_created_incident(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "Exported ticket"})
    resp = client.get("/api/incidents/export")
    assert "Exported ticket" in resp.text


def test_export_csv_requires_auth(client):
    resp = client.get("/api/incidents/export")
    assert resp.status_code == 401


def test_export_pdf_requires_auth(client):
    resp = client.get("/api/incidents/export/pdf")
    assert resp.status_code == 401


def test_export_pdf_returns_valid_pdf(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "Exported ticket"})
    resp = client.get("/api/incidents/export/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")


def test_summary_endpoint(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"})
    resp = client.get("/api/summary")
    assert resp.json()["total_incidents"] == 1


def test_summary_clamps_extreme_hours_values(client):
    _login(client)
    resp = client.get("/api/summary", params={"hours": 999999})
    assert resp.status_code == 200  # clamped server-side, not rejected


def test_set_awaiting_stakeholder(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/awaiting-stakeholder", json={"awaiting": True})
    assert resp.status_code == 200
    fetched = client.get(f"/api/incidents/{created['id']}").json()["incident"]
    assert fetched["awaiting_stakeholder_reply"] == 1


def test_set_awaiting_stakeholder_nonexistent_incident(client):
    _login(client)
    resp = client.post("/api/incidents/99999/awaiting-stakeholder", json={"awaiting": True})
    assert resp.status_code == 404


def test_update_status(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Brute Force", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/status", json={"status": "resolved", "reason": "benign"})
    assert resp.status_code == 200
    fetched = client.get(f"/api/incidents/{created['id']}").json()["incident"]
    assert fetched["status"] == "resolved"


def test_update_status_invalid_value(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Brute Force", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/status", json={"status": "not_a_real_status"})
    assert resp.status_code == 400


def test_update_status_nonexistent_incident(client):
    _login(client)
    resp = client.post("/api/incidents/99999/status", json={"status": "resolved"})
    assert resp.status_code == 404


def test_update_status_resolve_without_reason_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Brute Force", "title": "test"}).json()["incident"]
    resp = client.post(f"/api/incidents/{created['id']}/status", json={"status": "resolved"})
    assert resp.status_code == 400


def test_update_status_resolve_while_awaiting_stakeholder_rejected(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Brute Force", "title": "test"}).json()["incident"]
    client.post(f"/api/incidents/{created['id']}/awaiting-stakeholder", json={"awaiting": True})
    resp = client.post(f"/api/incidents/{created['id']}/status", json={"status": "resolved", "reason": "benign"})
    assert resp.status_code == 400


def test_list_incidents_filtered_by_status(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "a"})
    second = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "b"}).json()["incident"]
    client.post(f"/api/incidents/{second['id']}/status", json={"status": "escalated"})
    resp = client.get("/api/incidents", params={"status": "open"})
    assert len(resp.json()) == 1


def test_sops_list_includes_seeded_defaults(client):
    _login(client)
    resp = client.get("/api/sops")
    alert_types = {s["alert_type"] for s in resp.json()}
    assert "Phishing" in alert_types
    assert "System Compromise" in alert_types


def test_upsert_sop_adds_new_alert_type(client):
    _login(client)
    client.post("/api/sops", json={"alert_type": "My Custom Rule", "steps": "1. Do the thing"})
    resp = client.get("/api/sops/My Custom Rule")
    assert resp.json()["steps"] == "1. Do the thing"


def test_get_sop_for_unregistered_type_404(client):
    _login(client)
    resp = client.get("/api/sops/Nonexistent")
    assert resp.status_code == 404


def test_upsert_sop_with_category(client):
    _login(client)
    client.post("/api/sops", json={
        "alert_type": "My Custom Rule", "steps": "1. Do the thing", "category": "SOP-01: Custom",
    })
    resp = client.get("/api/sops/My Custom Rule")
    assert resp.json()["category"] == "SOP-01: Custom"


def test_rule_book_categories_requires_auth(client):
    resp = client.get("/api/rule-book/categories")
    assert resp.status_code == 401


def test_rule_book_categories_returns_eight(client):
    _login(client)
    resp = client.get("/api/rule-book/categories")
    assert resp.status_code == 200
    assert len(resp.json()) == 8


def test_confidence_scale_requires_auth(client):
    resp = client.get("/api/rule-book/confidence-scale")
    assert resp.status_code == 401


def test_confidence_scale_returns_bands(client):
    _login(client)
    resp = client.get("/api/rule-book/confidence-scale")
    assert len(resp.json()) == 4


def test_suspicious_ip_guide_requires_auth(client):
    resp = client.get("/api/rule-book/suspicious-ip-guide")
    assert resp.status_code == 401


def test_suspicious_ip_guide_returns_steps(client):
    _login(client)
    resp = client.get("/api/rule-book/suspicious-ip-guide")
    assert resp.json()["steps"]


def test_disposition_history_route_requires_auth(client):
    resp = client.get("/api/disposition-history", params={"alert_type": "Phishing"})
    assert resp.status_code == 401


def test_disposition_history_route_returns_counts(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    client.post(f"/api/incidents/{created['id']}/status", json={"status": "false_positive", "reason": "benign"})
    resp = client.get("/api/disposition-history", params={"alert_type": "Phishing"})
    body = resp.json()
    assert body["total"] == 1
    assert body["by_status"]["false_positive"] == 1


def test_real_rule_book_entries_present_in_sops_list(client):
    _login(client)
    resp = client.get("/api/sops")
    alert_types = {sop["alert_type"] for sop in resp.json()}
    assert "Azure Risky Sign-in" in alert_types
    assert "O365 Phishing Alert" in alert_types


def test_mitre_list(client):
    _login(client)
    resp = client.get("/api/mitre")
    assert resp.status_code == 200
    assert len(resp.json()) > 0


def test_mitre_list_requires_auth(client):
    resp = client.get("/api/mitre")
    assert resp.status_code == 401


def test_mitre_detail_found(client):
    _login(client)
    resp = client.get("/api/mitre/T1055")
    assert resp.json()["name"] == "Process Injection"


def test_mitre_detail_not_found(client):
    _login(client)
    resp = client.get("/api/mitre/T9999")
    assert resp.status_code == 404


def test_detection_gap_requires_auth(client):
    resp = client.get("/api/detection-gap")
    assert resp.status_code == 401


def test_detection_gap_returns_coverage_stats(client):
    _login(client)
    resp = client.get("/api/detection-gap")
    body = resp.json()
    assert "percent_covered" in body
    assert "uncovered" in body
    assert body["total_count"] > 0


def test_feed_requires_auth(client):
    resp = client.get("/api/feed")
    assert resp.status_code == 401


def test_feed_returns_results(client):
    _login(client)
    fake_result = [{"source": "Test Source", "status": "ok", "entries": [{"title": "x", "link": "y", "published": "z"}]}]
    with patch("tracker.api.fetch_all_feeds", new_callable=AsyncMock, return_value=fake_result):
        resp = client.get("/api/feed")
    assert resp.status_code == 200
    assert resp.json() == fake_result


def test_feed_latest_requires_auth(client):
    resp = client.get("/api/feed/latest")
    assert resp.status_code == 401


def test_feed_latest_returns_merged_results(client):
    _login(client)
    fake_result = [{"source": "Test Source", "status": "ok", "entries": [
        {"title": "x", "link": "y", "published_iso": "2026-01-01T00:00:00+00:00"},
    ]}]
    with patch("tracker.api.fetch_all_feeds", new_callable=AsyncMock, return_value=fake_result):
        resp = client.get("/api/feed/latest")
    assert resp.status_code == 200
    assert resp.json()[0]["title"] == "x"
    assert resp.json()[0]["source"] == "Test Source"


def test_feed_latest_respects_limit_param(client):
    _login(client)
    fake_result = [{"source": "S", "status": "ok", "entries": [
        {"title": f"item {i}", "published_iso": "2026-01-01T00:00:00+00:00"} for i in range(20)
    ]}]
    with patch("tracker.api.fetch_all_feeds", new_callable=AsyncMock, return_value=fake_result):
        resp = client.get("/api/feed/latest", params={"limit": 3})
    assert len(resp.json()) == 3


def test_global_search_requires_auth(client):
    resp = client.get("/api/search", params={"q": "phishing"})
    assert resp.status_code == 401


def test_global_search_empty_query_returns_empty_results(client):
    _login(client)
    resp = client.get("/api/search", params={"q": "  "})
    assert resp.json() == {"incidents": [], "sops": [], "mitre": []}


def test_global_search_finds_incident_and_mitre_and_sop(client):
    _login(client)
    client.post("/api/incidents", json={"alert_type": "Phishing", "title": "Suspicious phishing email"})
    resp = client.get("/api/search", params={"q": "phishing"})
    body = resp.json()
    assert len(body["incidents"]) >= 1
    assert len(body["sops"]) >= 1
    assert any(t["name"] == "Phishing" for t in body["mitre"])


def test_global_search_no_match_returns_empty_lists(client):
    _login(client)
    resp = client.get("/api/search", params={"q": "totally-nonexistent-xyz123"})
    body = resp.json()
    assert body == {"incidents": [], "sops": [], "mitre": []}


def test_investigate_ioc_requires_auth(client):
    resp = client.get("/api/investigate/ioc", params={"indicator": "1.2.3.4"})
    assert resp.status_code == 401


def test_investigate_ioc_returns_enrichment_result(client):
    _login(client)
    fake_result = {"indicator": "1.2.3.4", "type": "ip", "verdict": "malicious"}
    with patch("tracker.integrations.lookup_ioc", new_callable=AsyncMock, return_value=fake_result) as mock_lookup:
        resp = client.get("/api/investigate/ioc", params={"indicator": "1.2.3.4"})
    assert resp.status_code == 200
    assert resp.json() == fake_result
    mock_lookup.assert_called_once_with("1.2.3.4", "all")


def test_investigate_ioc_service_unavailable_returns_502(client):
    _login(client)
    with patch("tracker.integrations.lookup_ioc", new_callable=AsyncMock, side_effect=ConnectionError("down")):
        resp = client.get("/api/investigate/ioc", params={"indicator": "1.2.3.4"})
    assert resp.status_code == 502


def test_investigate_phishing_requires_auth(client):
    resp = client.post("/api/investigate/phishing", data={"raw_text": "test"})
    assert resp.status_code == 401


def test_investigate_phishing_with_raw_text(client):
    _login(client)
    fake_result = {"verdict": "phishing", "subject": "Urgent"}
    with patch("tracker.integrations.analyze_phishing", new_callable=AsyncMock, return_value=fake_result):
        resp = client.post("/api/investigate/phishing", data={"raw_text": "click here now"})
    assert resp.status_code == 200
    assert resp.json() == fake_result


def test_investigate_phishing_requires_input(client):
    _login(client)
    resp = client.post("/api/investigate/phishing", data={})
    assert resp.status_code == 400


def test_investigate_file_requires_auth(client):
    resp = client.post("/api/investigate/file", files={"file": ("test.exe", b"fake bytes")})
    assert resp.status_code == 401


def test_investigate_file_returns_analysis(client):
    _login(client)
    fake_result = {"verdict": "clean", "filename": "test.txt", "hashes": {"sha256": "abc"}}
    with patch("tracker.integrations.analyze_file", new_callable=AsyncMock, return_value=fake_result):
        resp = client.post("/api/investigate/file", files={"file": ("test.txt", b"hello world")})
    assert resp.status_code == 200
    assert resp.json() == fake_result


def test_investigate_file_empty_file_rejected(client):
    _login(client)
    resp = client.post("/api/investigate/file", files={"file": ("empty.txt", b"")})
    assert resp.status_code == 400


def test_telegram_webhook_wrong_secret_rejected(client, monkeypatch):
    monkeypatch.setattr("tracker.telegram_bot.WEBHOOK_SECRET", "real-secret")
    resp = client.post(
        "/telegram/webhook",
        json={"message": {"chat": {"id": 944650675}, "text": "/help"}},
        headers={"X-Telegram-Bot-Api-Secret-Token": "wrong-secret"},
    )
    assert resp.status_code == 403


def test_telegram_webhook_unauthorized_chat_silently_ignored(client, monkeypatch):
    monkeypatch.setattr("tracker.telegram_bot.WEBHOOK_SECRET", None)
    monkeypatch.setattr("tracker.telegram_bot.ALLOWED_CHAT_IDS", {"944650675"})
    with patch("tracker.telegram_bot.send_message", new_callable=AsyncMock) as mock_send:
        resp = client.post(
            "/telegram/webhook",
            json={"message": {"chat": {"id": 111111111}, "text": "/tickets"}},
        )
        assert resp.status_code == 200
        mock_send.assert_not_called()


def test_telegram_webhook_authorized_chat_gets_reply(client, monkeypatch):
    monkeypatch.setattr("tracker.telegram_bot.WEBHOOK_SECRET", None)
    monkeypatch.setattr("tracker.telegram_bot.ALLOWED_CHAT_IDS", {"944650675"})
    with patch("tracker.telegram_bot.send_message", new_callable=AsyncMock) as mock_send:
        resp = client.post(
            "/telegram/webhook",
            json={"message": {"chat": {"id": 944650675}, "text": "/tickets"}},
        )
        assert resp.status_code == 200
        mock_send.assert_called_once()


def test_oversized_body_rejected(client):
    _login(client)
    huge = "a" * (api.MAX_BODY_BYTES + 1000)
    resp = client.post(
        "/api/incidents", content=('{"alert_type": "' + huge + '"}').encode(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
