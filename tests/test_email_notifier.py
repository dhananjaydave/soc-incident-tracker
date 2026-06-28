from unittest.mock import patch

from tracker import email_notifier


def test_not_configured_when_env_vars_missing(monkeypatch):
    monkeypatch.setattr(email_notifier, "SMTP_USER", None)
    monkeypatch.setattr(email_notifier, "SMTP_PASSWORD", None)
    monkeypatch.setattr(email_notifier, "NOTIFY_EMAIL_TO", None)
    assert email_notifier.is_configured() is False


def test_configured_when_all_vars_present(monkeypatch):
    monkeypatch.setattr(email_notifier, "SMTP_USER", "me@gmail.com")
    monkeypatch.setattr(email_notifier, "SMTP_PASSWORD", "app-password")
    monkeypatch.setattr(email_notifier, "NOTIFY_EMAIL_TO", "me@gmail.com")
    assert email_notifier.is_configured() is True


async def test_send_email_noop_when_not_configured(monkeypatch):
    monkeypatch.setattr(email_notifier, "SMTP_USER", None)
    with patch("tracker.email_notifier._send_sync") as mock_send:
        await email_notifier.send_email("subject", "body")
    mock_send.assert_not_called()


async def test_send_email_calls_smtp_when_configured(monkeypatch):
    monkeypatch.setattr(email_notifier, "SMTP_USER", "me@gmail.com")
    monkeypatch.setattr(email_notifier, "SMTP_PASSWORD", "app-password")
    monkeypatch.setattr(email_notifier, "NOTIFY_EMAIL_TO", "me@gmail.com")
    with patch("tracker.email_notifier._send_sync") as mock_send:
        await email_notifier.send_email("Test Subject", "Test Body")
    mock_send.assert_called_once_with("Test Subject", "Test Body")


async def test_send_email_degrades_gracefully_on_smtp_failure(monkeypatch):
    monkeypatch.setattr(email_notifier, "SMTP_USER", "me@gmail.com")
    monkeypatch.setattr(email_notifier, "SMTP_PASSWORD", "app-password")
    monkeypatch.setattr(email_notifier, "NOTIFY_EMAIL_TO", "me@gmail.com")
    with patch("tracker.email_notifier._send_sync", side_effect=ConnectionError("SMTP server unreachable")):
        await email_notifier.send_email("subject", "body")  # should not raise
