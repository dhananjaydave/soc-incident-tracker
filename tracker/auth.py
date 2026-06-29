"""Single-user authentication - bcrypt-hashed password, signed session
cookies (no server-side session store needed), and per-IP rate limiting
on login attempts. There's exactly one account here by design (this is a
personal tool, not a multi-tenant system) - simpler surface, smaller
attack area than a full user-management system would need.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SESSION_COOKIE_NAME = "tracker_session"
# A 12h session covers a full shift without forcing a re-login mid-shift,
# while still expiring daily rather than staying valid indefinitely on a
# device that's lost, shared, or left unlocked.
SESSION_MAX_AGE_SECONDS = int(os.environ.get("TRACKER_SESSION_MAX_AGE_SECONDS", str(12 * 3600)))

LOGIN_RATE_LIMIT_WINDOW_SECONDS = 900  # 15 minutes
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5
_login_attempt_log: dict[str, list[float]] = defaultdict(list)


def _secret_key() -> str:
    key = os.environ.get("TRACKER_SECRET_KEY")
    if not key:
        raise RuntimeError("TRACKER_SECRET_KEY must be set - used to sign session cookies.")
    return key


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret_key(), salt="tracker-session")


# A precomputed bcrypt hash with no corresponding real password - used to
# keep a wrong-username login attempt taking the same ~100ms as a
# wrong-password one, instead of returning near-instantly. Generated
# once, hardcoded (it's not a secret - nothing maps to it).
DUMMY_HASH = "$2b$12$iMKkhrdjZehIwkZKht488./AQ1VzxmtlQV4hjnJ6vMzAdAiXkzwKC"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def create_session_token(username: str) -> str:
    return _serializer().dumps({"user": username})


def verify_session_token(token: str | None) -> str | None:
    """Returns the username if the token is valid and unexpired, else None."""
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("user")


def login_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = _login_attempt_log[ip]
    attempts[:] = [t for t in attempts if now - t < LOGIN_RATE_LIMIT_WINDOW_SECONDS]
    if len(attempts) >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        return True
    attempts.append(now)
    return False


def reset_rate_limit(ip: str) -> None:
    """Called on a successful login - a real user shouldn't stay throttled
    by their own earlier typos."""
    _login_attempt_log.pop(ip, None)
