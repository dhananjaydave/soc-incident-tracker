"""Combines Telegram (primary) and email (backup) notification channels
into one call - every notification site in the app calls this instead of
the individual channels directly, so a new channel only needs to be
added in one place.
"""

from __future__ import annotations

from . import email_notifier, telegram_bot


async def notify(subject: str, body: str) -> None:
    await telegram_bot.notify_all(body)
    await email_notifier.send_email(subject, body)
