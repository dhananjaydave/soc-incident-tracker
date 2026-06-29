"""Formats a (subject, body) pair into one Telegram message - every
notification site in the app calls this instead of telegram_bot
directly, so the message format only needs to change in one place.
"""

from __future__ import annotations

from . import telegram_bot


async def notify(subject: str, body: str) -> None:
    await telegram_bot.notify_all(f"{subject}\n{body}")
