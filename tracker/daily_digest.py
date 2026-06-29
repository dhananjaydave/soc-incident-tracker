"""Builds the morning shift-handoff digest - one message that answers
"what do I need to know before this shift" instead of making the analyst
piece it together from three different tabs. All data already tracked
elsewhere in the app; this just bundles it.
"""

from __future__ import annotations

import logging

from . import cve_monitor
from .db import TrackerDB

logger = logging.getLogger(__name__)

DIGEST_WINDOW_HOURS = 24


async def build_daily_digest(db: TrackerDB) -> str:
    summary = await db.get_shift_summary(hours=DIGEST_WINDOW_HOURS)
    stale = await db.get_stale_incidents(hours_threshold=DIGEST_WINDOW_HOURS)

    try:
        recent_cves = await cve_monitor._fetch_recent_high_severity_cves()
    except Exception as exc:
        logger.warning("Daily digest CVE lookup failed: %s", exc)
        recent_cves = []

    lines = [f"Daily SOC digest - last {DIGEST_WINDOW_HOURS}h", ""]
    lines.append(f"Incidents: {summary['total_incidents']} total")
    for status, count in sorted(summary["by_status"].items()):
        lines.append(f"  {status}: {count}")
    lines.append(f"Awaiting stakeholder reply: {summary['awaiting_stakeholder_reply']}")
    lines.append(f"Stale (no update in {DIGEST_WINDOW_HOURS}h+): {len(stale)}")
    lines.append("")
    lines.append(f"New high-severity CVEs (CVSS>=7): {len(recent_cves)}")
    for cve in recent_cves[:5]:
        lines.append(f"  {cve['id']} (CVSS {cve['cvss']})")

    return "\n".join(lines)
