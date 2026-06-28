"""Periodically checks for stale (open/escalated, no update in N hours)
tickets and pings Telegram - so a forgotten ticket doesn't just sit
silently until the next time the dashboard happens to be opened.
"""

from __future__ import annotations

import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .db import TrackerDB
from .notifications import notify

STALE_HOURS_THRESHOLD = int(os.environ.get("TRACKER_STALE_HOURS", "24"))
CHECK_INTERVAL_MINUTES = int(os.environ.get("TRACKER_CHECK_INTERVAL_MINUTES", "60"))

_scheduler: AsyncIOScheduler | None = None


async def check_stale_tickets(db: TrackerDB) -> list[dict]:
    stale = await db.get_stale_incidents(hours_threshold=STALE_HOURS_THRESHOLD)
    for incident in stale:
        await notify(
            f"SOC Tracker: ticket #{incident['id']} is stale",
            f"Ticket #{incident['id']} ({incident['alert_type']}: {incident['title']}) "
            f"is still {incident['status']} with no update in over {STALE_HOURS_THRESHOLD}h.",
        )
    return stale


def start_scheduler(db: TrackerDB) -> None:
    """Idempotent - calling this more than once (e.g. from a duplicate
    module import path) must not register the job twice.

    Deliberately doesn't pass next_run_time - that argument defaulting to
    None silently pauses an APScheduler job forever, a real bug hit
    earlier in this same portfolio (the Amul stock checker). Leaving it
    unset gives the normal "first run after one interval" behavior.
    """
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(check_stale_tickets, "interval", minutes=CHECK_INTERVAL_MINUTES, args=[db])
    _scheduler.start()


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        if _scheduler.running:
            _scheduler.shutdown(wait=False)
        _scheduler = None
