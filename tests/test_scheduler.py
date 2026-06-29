import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from tracker import scheduler
from tracker.db import TrackerDB


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


async def test_check_stale_tickets_notifies_for_each_stale_ticket(db):
    import sqlite3
    incident = await db.create_incident("System Compromise", "Old ticket")
    old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    conn = sqlite3.connect(db.db_path)
    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (old_time, incident["id"]))
    conn.commit()
    conn.close()

    with patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        stale = await scheduler.check_stale_tickets(db)
        assert len(stale) == 1
        mock_notify.assert_called_once()
        assert str(incident["id"]) in mock_notify.call_args[0][0]


async def test_check_stale_tickets_no_notification_when_nothing_stale(db):
    await db.create_incident("Phishing", "Fresh ticket")
    with patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        stale = await scheduler.check_stale_tickets(db)
        assert stale == []
        mock_notify.assert_not_called()


async def test_check_cve_and_kev_notifies_for_each_finding(db):
    fake_cve = {"id": "CVE-2026-0001", "cvss": 9.8, "description": "desc", "link": "https://example.com"}
    fake_kev = {"id": "CVE-2026-0002", "name": "Exploited thing", "date_added": "2026-06-29", "link": "https://example.com"}
    with patch("tracker.scheduler.cve_monitor.check_for_new_cves", new_callable=AsyncMock, return_value=[fake_cve]), \
         patch("tracker.scheduler.cve_monitor.check_for_new_kev_entries", new_callable=AsyncMock, return_value=[fake_kev]), \
         patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        await scheduler.check_cve_and_kev(db)

    assert mock_notify.call_count == 2


async def test_check_cve_and_kev_no_notification_when_nothing_new(db):
    with patch("tracker.scheduler.cve_monitor.check_for_new_cves", new_callable=AsyncMock, return_value=[]), \
         patch("tracker.scheduler.cve_monitor.check_for_new_kev_entries", new_callable=AsyncMock, return_value=[]), \
         patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        await scheduler.check_cve_and_kev(db)

    mock_notify.assert_not_called()


async def test_check_internal_tools_notifies_on_newly_down(monkeypatch):
    monkeypatch.setattr(scheduler, "_previously_down", set())
    with patch("tracker.scheduler.health_check.check_internal_tools", new_callable=AsyncMock, return_value=["IOC Enrichment"]), \
         patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        await scheduler.check_internal_tools()

    mock_notify.assert_called_once()
    assert "unreachable" in mock_notify.call_args[0][0].lower()
    assert scheduler._previously_down == {"IOC Enrichment"}


async def test_check_internal_tools_no_renotify_while_still_down(monkeypatch):
    monkeypatch.setattr(scheduler, "_previously_down", {"IOC Enrichment"})
    with patch("tracker.scheduler.health_check.check_internal_tools", new_callable=AsyncMock, return_value=["IOC Enrichment"]), \
         patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        await scheduler.check_internal_tools()

    mock_notify.assert_not_called()


async def test_check_internal_tools_notifies_on_recovery(monkeypatch):
    monkeypatch.setattr(scheduler, "_previously_down", {"IOC Enrichment"})
    with patch("tracker.scheduler.health_check.check_internal_tools", new_callable=AsyncMock, return_value=[]), \
         patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        await scheduler.check_internal_tools()

    mock_notify.assert_called_once()
    assert "recovered" in mock_notify.call_args[0][0].lower()
    assert scheduler._previously_down == set()


async def test_send_daily_digest_calls_notify(db):
    with patch("tracker.scheduler.build_daily_digest", new_callable=AsyncMock, return_value="digest text"), \
         patch("tracker.scheduler.notify", new_callable=AsyncMock) as mock_notify:
        await scheduler.send_daily_digest(db)

    mock_notify.assert_called_once_with("SOC Tracker: daily digest", "digest text")


async def test_start_scheduler_is_idempotent(db):
    scheduler.start_scheduler(db)
    try:
        first_instance = scheduler._scheduler
        scheduler.start_scheduler(db)
        assert scheduler._scheduler is first_instance  # second call was a no-op, not a new scheduler
    finally:
        scheduler.stop_scheduler()  # stopped within the same event loop it started on


async def test_stop_scheduler_clears_instance(db):
    scheduler.start_scheduler(db)
    scheduler.stop_scheduler()
    assert scheduler._scheduler is None
