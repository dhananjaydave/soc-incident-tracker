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

    with patch("tracker.scheduler.notify_all", new_callable=AsyncMock) as mock_notify:
        stale = await scheduler.check_stale_tickets(db)
        assert len(stale) == 1
        mock_notify.assert_called_once()
        assert str(incident["id"]) in mock_notify.call_args[0][0]


async def test_check_stale_tickets_no_notification_when_nothing_stale(db):
    await db.create_incident("Phishing", "Fresh ticket")
    with patch("tracker.scheduler.notify_all", new_callable=AsyncMock) as mock_notify:
        stale = await scheduler.check_stale_tickets(db)
        assert stale == []
        mock_notify.assert_not_called()


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
