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
