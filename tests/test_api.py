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


def test_create_incident_unknown_alert_type_has_no_sop(client):
    _login(client)
    resp = client.post("/api/incidents", json={"alert_type": "Totally Custom Type", "title": "test"})
    assert resp.json()["sop"] is None


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


def test_get_incident_with_updates_and_sop(client):
    _login(client)
    created = client.post("/api/incidents", json={"alert_type": "Phishing", "title": "test"}).json()["incident"]
    client.post(f"/api/incidents/{created['id']}/notes", json={"note": "checked headers"})
    resp = client.get(f"/api/incidents/{created['id']}")
    body = resp.json()
    assert len(body["updates"]) == 1
    assert body["sop"] is not None


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


def test_rule_book_categories_returns_six(client):
    _login(client)
    resp = client.get("/api/rule-book/categories")
    assert resp.status_code == 200
    assert len(resp.json()) == 6


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
