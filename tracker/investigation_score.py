"""Estimates how much of a ticket's Rule Book closure checklist is
actually done, from data the tracker already has - not a strict
verification (most checklist items can't be proven from data alone), a
"have you actually done this" reminder so nothing gets forgotten before
closing. Items it can't map to anything concrete are flagged for manual
review rather than guessed at either way.
"""

from __future__ import annotations


def _item_status(item: str, incident: dict, has_notes: bool) -> str:
    lowered = item.lower()
    if "reason" in lowered or "disposition" in lowered:
        return "done" if incident.get("disposition_reason") else "needs_review"
    if "stakeholder" in lowered:
        return "done" if not incident.get("awaiting_stakeholder_reply") else "needs_review"
    if "note" in lowered or "document" in lowered or "investigat" in lowered:
        return "done" if has_notes else "needs_review"
    return "needs_review"


def compute_investigation_score(incident: dict, sop: dict | None, updates: list[dict]) -> dict:
    checklist = []
    if sop and sop.get("structured"):
        checklist = sop["structured"].get("closure_checklist") or []

    has_notes = len(updates) > 0
    items = [{"item": item, "status": _item_status(item, incident, has_notes)} for item in checklist]

    done_count = sum(1 for i in items if i["status"] == "done")
    percent_done = round((done_count / len(items)) * 100) if items else 0

    return {"items": items, "percent_done": percent_done, "done_count": done_count, "total_count": len(items)}
