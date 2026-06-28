"""Bidirectional Telegram bot for the incident tracker - private, locked
to an allowlisted chat id (same pattern as the Amul and Phishing bots in
this same portfolio). Sends notifications (new ticket, stale-ticket
reminders) and accepts commands so routine acknowledgments don't require
opening the dashboard.
"""

from __future__ import annotations

import logging
import os
import re

import httpx

from .db import TrackerDB

logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("TRACKER_TELEGRAM_BOT_TOKEN")
WEBHOOK_SECRET = os.environ.get("TRACKER_TELEGRAM_WEBHOOK_SECRET")
ALLOWED_CHAT_IDS = {c.strip() for c in os.environ.get("TRACKER_ALLOWED_CHAT_IDS", "").split(",") if c.strip()}

API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}" if BOT_TOKEN else None
REQUEST_TIMEOUT = 15

HELP_TEXT = (
    "Commands:\n"
    "/tickets - list open/escalated tickets\n"
    "/close <id> <note> - mark resolved\n"
    "/falsepositive <id> <reason> - mark false positive\n"
    "/escalate <id> <reason> - mark escalated\n"
    "/note <id> <text> - add an update note\n"
    "/sop <alert type> - show the SOP for that alert type\n"
    "/summary [hours] - shift summary (defaults to 8h)\n"
    "/help - show this message"
)


async def send_message(chat_id: str, text: str) -> None:
    if not API_BASE:
        logger.warning("TRACKER_TELEGRAM_BOT_TOKEN not configured - skipping Telegram send")
        return
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            await client.post(f"{API_BASE}/sendMessage", data={"chat_id": chat_id, "text": text})
    except httpx.HTTPError as exc:
        logger.warning("Telegram send failed: %s", exc)


async def notify_all(text: str) -> None:
    for chat_id in ALLOWED_CHAT_IDS:
        await send_message(chat_id, text)


def _format_ticket_line(incident: dict) -> str:
    return f"#{incident['id']} [{incident['status']}] {incident['alert_type']}: {incident['title']}"


async def _handle_tickets(db: TrackerDB) -> str:
    open_tickets = await db.list_incidents(status="open")
    escalated = await db.list_incidents(status="escalated")
    tickets = open_tickets + escalated
    if not tickets:
        return "No open or escalated tickets."
    return "\n".join(_format_ticket_line(t) for t in tickets)


_ID_AND_TEXT_RE = re.compile(r"^(\d+)\s+(.+)$", re.DOTALL)


async def _handle_status_change(db: TrackerDB, args: str, status: str) -> str:
    match = _ID_AND_TEXT_RE.match(args.strip())
    if not match:
        return f"Usage: /{status.replace('_', '')} <id> <reason>"
    incident_id, reason = int(match.group(1)), match.group(2).strip()
    incident = await db.get_incident(incident_id)
    if not incident:
        return f"No ticket #{incident_id} found."
    try:
        await db.update_status(incident_id, status, reason)
    except ValueError as exc:
        return str(exc)
    return f"Ticket #{incident_id} marked {status}."


async def _handle_note(db: TrackerDB, args: str) -> str:
    match = _ID_AND_TEXT_RE.match(args.strip())
    if not match:
        return "Usage: /note <id> <text>"
    incident_id, note = int(match.group(1)), match.group(2).strip()
    added = await db.add_update_note(incident_id, note)
    return f"Note added to #{incident_id}." if added else f"No ticket #{incident_id} found."


async def _handle_sop(db: TrackerDB, args: str) -> str:
    alert_type = args.strip()
    if not alert_type:
        return "Usage: /sop <alert type>"
    sop = await db.get_sop(alert_type)
    if not sop:
        all_sops = await db.list_sops()
        available = ", ".join(s["alert_type"] for s in all_sops) or "(none configured)"
        return f"No SOP found for '{alert_type}'. Available: {available}"
    return f"SOP for {alert_type}:\n{sop['steps']}"


DEFAULT_SHIFT_HOURS = 8


async def _handle_summary(db: TrackerDB, args: str) -> str:
    hours = DEFAULT_SHIFT_HOURS
    if args.strip():
        try:
            hours = int(args.strip())
        except ValueError:
            return "Usage: /summary [hours] (defaults to 8 if omitted)"

    summary = await db.get_shift_summary(hours=hours)
    if summary["total_incidents"] == 0:
        return f"No incidents in the last {hours}h."

    status_lines = "\n".join(f"  {status}: {count}" for status, count in summary["by_status"].items())
    return (
        f"Shift summary (last {hours}h):\n"
        f"Total incidents: {summary['total_incidents']}\n"
        f"{status_lines}\n"
        f"With an external ticket: {summary['with_external_ticket']}\n"
        f"Awaiting stakeholder reply: {summary['awaiting_stakeholder_reply']}"
    )


async def handle_command(db: TrackerDB, text: str) -> str:
    text = text.strip()
    if not text.startswith("/"):
        return "Unrecognized message. Send /help for commands."

    parts = text[1:].split(maxsplit=1)
    command = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    if command == "help":
        return HELP_TEXT
    if command == "tickets":
        return await _handle_tickets(db)
    if command == "close":
        return await _handle_status_change(db, args, "resolved")
    if command == "falsepositive":
        return await _handle_status_change(db, args, "false_positive")
    if command == "escalate":
        return await _handle_status_change(db, args, "escalated")
    if command == "note":
        return await _handle_note(db, args)
    if command == "sop":
        return await _handle_sop(db, args)
    if command == "summary":
        return await _handle_summary(db, args)
    return f"Unknown command '{command}'. Send /help for commands."


def is_authorized(chat_id: str) -> bool:
    return str(chat_id) in ALLOWED_CHAT_IDS
