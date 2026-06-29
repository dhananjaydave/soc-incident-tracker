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

# NVD's global CVSS>=7 volume is ~30-100+ CVEs/day across every vendor -
# accurate but useless as a daily read for one org. The digest uses a
# much higher bar (critical only); the regular CVE/KEV scheduler job
# (cve_monitor.py) still alerts individually on CVSS>=7 as they appear,
# deduped so that doesn't repeat the same noise problem.
DIGEST_MIN_CVSS = 9.0
DIGEST_MAX_CVES_SHOWN = 5


async def build_daily_digest(db: TrackerDB) -> str:
    summary = await db.get_shift_summary(hours=DIGEST_WINDOW_HOURS)
    stale = await db.get_stale_incidents(hours_threshold=DIGEST_WINDOW_HOURS)

    try:
        recent_cves = await cve_monitor._fetch_recent_high_severity_cves(min_cvss=DIGEST_MIN_CVSS)
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
    lines.append(f"New critical CVEs (CVSS>={DIGEST_MIN_CVSS}): {len(recent_cves)}")
    for cve in sorted(recent_cves, key=lambda c: -c["cvss"])[:DIGEST_MAX_CVES_SHOWN]:
        lines.append(f"  {cve['id']} (CVSS {cve['cvss']})")
    if len(recent_cves) > DIGEST_MAX_CVES_SHOWN:
        lines.append(f"  ...and {len(recent_cves) - DIGEST_MAX_CVES_SHOWN} more - full list in the dashboard's CVE check")
    lines.append("(High/medium-severity CVEs CVSS 7-8.9 are still alerted individually as they're found, just not repeated in this daily rollup.)")

    return "\n".join(lines)
