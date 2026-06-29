"""Background jobs, all on the same APScheduler instance:

- stale ticket reminders (open/escalated, no update in N hours)
- new high-severity CVE / CISA KEV checks
- internal-tool (IOC/Phishing/File-Analyser) reachability checks
- a daily shift-handoff digest at a fixed hour

All push a Telegram (+ email, if configured) notification via
.notifications.notify so a forgotten ticket, a newly exploited CVE, or a
dead internal service doesn't just sit unnoticed until someone happens to
open the dashboard.
"""

from __future__ import annotations

import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from . import cve_monitor, health_check
from .daily_digest import build_daily_digest
from .db import TrackerDB
from .notifications import notify

STALE_HOURS_THRESHOLD = int(os.environ.get("TRACKER_STALE_HOURS", "24"))
CHECK_INTERVAL_MINUTES = int(os.environ.get("TRACKER_CHECK_INTERVAL_MINUTES", "60"))
CVE_CHECK_INTERVAL_MINUTES = int(os.environ.get("TRACKER_CVE_CHECK_INTERVAL_MINUTES", "240"))
HEALTH_CHECK_INTERVAL_MINUTES = int(os.environ.get("TRACKER_HEALTH_CHECK_INTERVAL_MINUTES", "15"))
# UTC hour - default 02:00 UTC = 07:30 IST, a reasonable "before a typical
# morning shift" time. Adjust to your own timezone/shift start.
DAILY_DIGEST_HOUR_UTC = int(os.environ.get("TRACKER_DAILY_DIGEST_HOUR_UTC", "2"))

_scheduler: AsyncIOScheduler | None = None

# Tracks which internal tools were down as of the last check, purely
# in-memory - only notify on a state CHANGE (newly down, or recovered),
# not on every single check while something stays down.
_previously_down: set[str] = set()


async def check_stale_tickets(db: TrackerDB) -> list[dict]:
    stale = await db.get_stale_incidents(hours_threshold=STALE_HOURS_THRESHOLD)
    for incident in stale:
        await notify(
            f"SOC Tracker: ticket #{incident['id']} is stale",
            f"Ticket #{incident['id']} ({incident['alert_type']}: {incident['title']}) "
            f"is still {incident['status']} with no update in over {STALE_HOURS_THRESHOLD}h.",
        )
    return stale


async def check_cve_and_kev(db: TrackerDB) -> None:
    new_cves = await cve_monitor.check_for_new_cves(db)
    for cve in new_cves:
        await notify(
            f"SOC Tracker: new high-severity CVE {cve['id']}",
            f"{cve['id']} (CVSS {cve['cvss']}): {cve['description']}\n{cve['link']}",
        )

    new_kev = await cve_monitor.check_for_new_kev_entries(db)
    for entry in new_kev:
        await notify(
            f"SOC Tracker: {entry['id']} added to CISA KEV (actively exploited)",
            f"{entry['id']} - {entry['name']}\nAdded to CISA's Known Exploited Vulnerabilities catalog "
            f"on {entry['date_added']} - this is confirmed active exploitation, not just a score.\n{entry['link']}",
        )


async def check_internal_tools() -> None:
    global _previously_down
    currently_down = set(await health_check.check_internal_tools())

    newly_down = currently_down - _previously_down
    recovered = _previously_down - currently_down

    if newly_down:
        await notify(
            "SOC Tracker: internal tool unreachable",
            f"Unreachable: {', '.join(sorted(newly_down))}. The Investigate tab "
            f"will fail for these until the underlying service is back.",
        )
    if recovered:
        await notify("SOC Tracker: internal tool recovered", f"Reachable again: {', '.join(sorted(recovered))}.")

    _previously_down = currently_down


async def send_daily_digest(db: TrackerDB) -> None:
    digest = await build_daily_digest(db)
    await notify("SOC Tracker: daily digest", digest)


def start_scheduler(db: TrackerDB) -> None:
    """Idempotent - calling this more than once (e.g. from a duplicate
    module import path) must not register the jobs twice.

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
    _scheduler.add_job(check_cve_and_kev, "interval", minutes=CVE_CHECK_INTERVAL_MINUTES, args=[db])
    _scheduler.add_job(check_internal_tools, "interval", minutes=HEALTH_CHECK_INTERVAL_MINUTES)
    _scheduler.add_job(send_daily_digest, "cron", hour=DAILY_DIGEST_HOUR_UTC, minute=0, args=[db])
    _scheduler.start()


def stop_scheduler() -> None:
    global _scheduler, _previously_down
    if _scheduler is not None:
        if _scheduler.running:
            _scheduler.shutdown(wait=False)
        _scheduler = None
    _previously_down = set()
