"""Email notifications as a backup to Telegram - same free Gmail SMTP
approach already used by the Amul stock checker elsewhere in this
portfolio (an app password, not the real account password). Optional -
degrades to a no-op if not configured, since Telegram is the primary
channel and this is just a backup.
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SMTP_HOST = os.environ.get("TRACKER_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("TRACKER_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("TRACKER_SMTP_USER")
SMTP_PASSWORD = os.environ.get("TRACKER_SMTP_PASSWORD")
NOTIFY_EMAIL_TO = os.environ.get("TRACKER_NOTIFY_EMAIL_TO")


def is_configured() -> bool:
    return bool(SMTP_USER and SMTP_PASSWORD and NOTIFY_EMAIL_TO)


def _send_sync(subject: str, body: str) -> None:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = NOTIFY_EMAIL_TO

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, [NOTIFY_EMAIL_TO], msg.as_string())


async def send_email(subject: str, body: str) -> None:
    if not is_configured():
        return
    try:
        await asyncio.to_thread(_send_sync, subject, body)
    except Exception as exc:
        logger.warning("Email notification failed: %s", exc)
