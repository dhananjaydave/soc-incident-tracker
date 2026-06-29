"""FastAPI app for the personal SOC incident tracker - login-gated
(single account, by design), backs onto the dashboard UI and the
bidirectional Telegram bot.

Run locally:   uvicorn tracker.api:app --reload
"""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import auth, integrations, telegram_bot
from .db import TrackerDB
from .investigation_score import compute_investigation_score
from .mitre_knowledge import get_technique, list_techniques, search_techniques
from .notifications import notify
from .pdf_export import build_incidents_pdf
from .rule_book import SOP_CATEGORIES, seed_rule_book
from .scheduler import start_scheduler, stop_scheduler
from .security_feed import fetch_all_feeds, merge_latest
from .seed_sops import seed_default_sops

db = TrackerDB()

# Most JSON API routes are tiny - this stays small. File-upload routes
# (phishing .eml / file analysis) have their own separate, larger cap
# below since they pass raw file bytes through to the other internal tools.
MAX_BODY_BYTES = 200 * 1024
MAX_UPLOAD_BYTES = 12 * 1024 * 1024
MAX_TEXT_LENGTH = 4096

# Notify at most once per rate-limit window per IP, not once per blocked
# attempt - a real brute-force run would otherwise spam dozens of nearly
# identical Telegram messages.
_rate_limit_notified_at: dict[str, float] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await seed_default_sops(db)
    await seed_rule_book(db)
    start_scheduler(db)
    yield
    stop_scheduler()


app = FastAPI(title="SOC Incident Tracker", version="1.0.0", lifespan=lifespan)

_STATIC_DIR = Path(__file__).resolve().parent / "static"

ADMIN_USERNAME = os.environ.get("TRACKER_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("TRACKER_ADMIN_PASSWORD_HASH")


_UPLOAD_PATHS = {"/api/investigate/phishing", "/api/investigate/file"}


@app.middleware("http")
async def reject_oversized_bodies(request: Request, call_next):
    limit = MAX_UPLOAD_BYTES if request.url.path in _UPLOAD_PATHS else MAX_BODY_BYTES
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > limit:
        return JSONResponse(status_code=413, content={"detail": "Request body too large."})
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def _client_ip(request: Request) -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    return request.client.host if request.client else "unknown"


async def _current_password_hash() -> str | None:
    # A changed password is stored in the database (so it persists and is
    # actually changeable at runtime) and takes priority over the env var,
    # which only serves as the initial bootstrap value before any change.
    db_hash = await db.get_setting("admin_password_hash")
    return db_hash or ADMIN_PASSWORD_HASH


def require_auth(tracker_session: str | None = Cookie(default=None)) -> str:
    username = auth.verify_session_token(tracker_session)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return username


class LoginRequest(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=256)


class CreateIncidentRequest(BaseModel):
    alert_type: str = Field(max_length=256)
    title: str = Field(max_length=512)
    description: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)
    external_ticket_ref: str | None = Field(default=None, max_length=128)
    affected_user: str | None = Field(default=None, max_length=256)


class EmergencyIncidentRequest(BaseModel):
    title: str = Field(max_length=512)
    description: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)
    affected_user: str | None = Field(default=None, max_length=256)


class StatusUpdateRequest(BaseModel):
    status: str = Field(max_length=32)
    reason: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)


class NoteRequest(BaseModel):
    note: str = Field(max_length=MAX_TEXT_LENGTH)


class AwaitingStakeholderRequest(BaseModel):
    awaiting: bool


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class SopRequest(BaseModel):
    alert_type: str = Field(max_length=256)
    steps: str = Field(max_length=MAX_TEXT_LENGTH)
    category: str | None = Field(default=None, max_length=256)


@app.get("/", response_class=HTMLResponse)
def index():
    return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    ip = _client_ip(request)
    if auth.login_rate_limited(ip):
        # Someone is actively hammering the login - worth knowing about
        # immediately on a single-user system, not just throttling silently.
        # Deduplicated to once per window so a real brute-force run doesn't
        # spam dozens of near-identical notifications.
        last_notified = _rate_limit_notified_at.get(ip, 0)
        if time.time() - last_notified > auth.LOGIN_RATE_LIMIT_WINDOW_SECONDS:
            _rate_limit_notified_at[ip] = time.time()
            await notify("SOC Tracker: possible brute-force login attempt", f"Login rate limit hit from {ip}.")
        raise HTTPException(status_code=429, detail="Too many login attempts - try again later.")

    current_hash = await _current_password_hash()
    if not current_hash:
        raise HTTPException(status_code=500, detail="Server not configured - no admin password set.")

    # Always run the (deliberately slow) bcrypt check, even on a wrong
    # username, against a dummy hash - otherwise a wrong username returns
    # near-instantly while a wrong password takes ~100ms, a timing
    # side-channel that reveals whether "admin" is the right username.
    username_correct = body.username == ADMIN_USERNAME
    password_correct = auth.verify_password(body.password, current_hash if username_correct else auth.DUMMY_HASH)
    if not username_correct or not password_correct:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    auth.reset_rate_limit(ip)
    token = auth.create_session_token(body.username)
    response.set_cookie(
        auth.SESSION_COOKIE_NAME, token, max_age=auth.SESSION_MAX_AGE_SECONDS,
        httponly=True, secure=True, samesite="strict",
    )
    await notify("SOC Tracker: login", f"Login successful from {ip}.")
    return {"status": "ok"}


@app.post("/logout")
async def logout(response: Response, _user: str = Depends(require_auth)):
    response.delete_cookie(auth.SESSION_COOKIE_NAME)
    return {"status": "ok"}


@app.post("/api/change-password")
async def change_password(body: ChangePasswordRequest, request: Request, _user: str = Depends(require_auth)):
    current_hash = await _current_password_hash()
    if not current_hash or not auth.verify_password(body.current_password, current_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")

    new_hash = auth.hash_password(body.new_password)
    await db.set_setting("admin_password_hash", new_hash)
    await notify("SOC Tracker: password changed", f"Dashboard password was changed from {_client_ip(request)}.")
    return {"status": "ok"}


@app.get("/api/me")
async def me(user: str = Depends(require_auth)):
    return {"username": user}


@app.get("/api/incidents")
async def list_incidents(status: str | None = None, _user: str = Depends(require_auth)):
    return await db.list_incidents(status=status)


@app.post("/api/incidents")
async def create_incident(body: CreateIncidentRequest, _user: str = Depends(require_auth)):
    incident = await db.create_incident(
        body.alert_type, body.title, body.description, body.external_ticket_ref, body.affected_user
    )
    sop = await db.get_sop(body.alert_type)
    await notify(f"SOC Tracker: new ticket #{incident['id']}", f"[{body.alert_type}] {body.title}")
    return {"incident": incident, "sop": sop}


EMERGENCY_ALERT_TYPE = "Major Incident"


@app.post("/api/incidents/emergency")
async def create_emergency_incident(body: EmergencyIncidentRequest, _user: str = Depends(require_auth)):
    incident = await db.create_incident(EMERGENCY_ALERT_TYPE, body.title, body.description, affected_user=body.affected_user)
    await db.update_status(incident["id"], "escalated", "Emergency button activated - immediate escalation.")
    updated = await db.get_incident(incident["id"])
    await notify(
        f"\U0001F6A8 MAJOR INCIDENT #{incident['id']}",
        f"{body.title}\n{body.description or ''}\nCreated and escalated immediately via the Emergency button.",
    )
    return {"incident": updated}


@app.get("/api/summary")
async def shift_summary(hours: int = 8, _user: str = Depends(require_auth)):
    return await db.get_shift_summary(hours=max(1, min(hours, 24 * 30)))


@app.get("/api/users/{username}/history")
async def user_history(username: str, _user: str = Depends(require_auth)):
    return await db.get_user_history(username)


@app.get("/api/incidents/export")
async def export_incidents(_user: str = Depends(require_auth)):
    csv_text = await db.export_incidents_csv()
    return Response(
        content=csv_text, media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents.csv"},
    )


@app.get("/api/incidents/export/pdf")
async def export_incidents_pdf(_user: str = Depends(require_auth)):
    incidents = await db.list_incidents()
    pdf_bytes = build_incidents_pdf(incidents)
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=incidents.pdf"},
    )


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int, _user: str = Depends(require_auth)):
    incident = await db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    updates = await db.get_updates(incident_id)
    sop = await db.get_sop(incident["alert_type"])
    score = compute_investigation_score(incident, sop, updates)
    disposition_history = await db.get_disposition_history(incident["alert_type"])
    return {"incident": incident, "updates": updates, "sop": sop, "investigation_score": score,
            "disposition_history": disposition_history}


@app.post("/api/incidents/{incident_id}/status")
async def update_status(incident_id: int, body: StatusUpdateRequest, _user: str = Depends(require_auth)):
    try:
        updated = await db.update_status(incident_id, body.status, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found.")
    await notify(f"SOC Tracker: ticket #{incident_id} {body.status}", f"Ticket #{incident_id} marked {body.status}.")
    return {"status": "ok"}


@app.post("/api/incidents/{incident_id}/notes")
async def add_note(incident_id: int, body: NoteRequest, _user: str = Depends(require_auth)):
    added = await db.add_update_note(incident_id, body.note)
    if not added:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"status": "ok"}


@app.post("/api/incidents/{incident_id}/awaiting-stakeholder")
async def set_awaiting_stakeholder(incident_id: int, body: AwaitingStakeholderRequest, _user: str = Depends(require_auth)):
    updated = await db.set_awaiting_stakeholder(incident_id, body.awaiting)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"status": "ok"}


@app.get("/api/rule-book/categories")
async def rule_book_categories(_user: str = Depends(require_auth)):
    return SOP_CATEGORIES


@app.get("/api/disposition-history")
async def disposition_history(alert_type: str, _user: str = Depends(require_auth)):
    return await db.get_disposition_history(alert_type)


@app.get("/api/sops")
async def list_sops(_user: str = Depends(require_auth)):
    return await db.list_sops()


@app.post("/api/sops")
async def upsert_sop(body: SopRequest, _user: str = Depends(require_auth)):
    await db.upsert_sop(body.alert_type, body.steps, category=body.category)
    return {"status": "ok"}


@app.get("/api/sops/{alert_type}")
async def get_sop(alert_type: str, _user: str = Depends(require_auth)):
    sop = await db.get_sop(alert_type)
    if not sop:
        raise HTTPException(status_code=404, detail="No SOP for this alert type.")
    return sop


@app.get("/api/mitre")
async def mitre_list(_user: str = Depends(require_auth)):
    return list_techniques()


@app.get("/api/mitre/{technique_id}")
async def mitre_detail(technique_id: str, _user: str = Depends(require_auth)):
    technique = get_technique(technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail="Unknown technique ID.")
    return technique


@app.get("/api/feed")
async def security_feed(_user: str = Depends(require_auth)):
    return await fetch_all_feeds()


@app.get("/api/feed/latest")
async def security_feed_latest(limit: int = 12, _user: str = Depends(require_auth)):
    results = await fetch_all_feeds()
    return merge_latest(results, limit=max(1, min(limit, 50)))


@app.get("/api/search")
async def global_search(q: str, _user: str = Depends(require_auth)):
    q = q.strip()
    if not q:
        return {"incidents": [], "sops": [], "mitre": []}
    incidents, sops = await asyncio.gather(db.search_incidents(q), db.search_sops(q))
    return {"incidents": incidents, "sops": sops, "mitre": search_techniques(q)}


@app.get("/api/investigate/ioc")
async def investigate_ioc(indicator: str, checks: str = "all", _user: str = Depends(require_auth)):
    try:
        return await integrations.lookup_ioc(indicator, checks)
    except Exception:
        raise HTTPException(status_code=502, detail="IOC enrichment service unavailable.")


@app.post("/api/investigate/phishing")
async def investigate_phishing(raw_text: str | None = Form(default=None),
                                file: UploadFile | None = File(default=None),
                                _user: str = Depends(require_auth)):
    if not raw_text and not file:
        raise HTTPException(status_code=400, detail="Provide raw_text or an .eml file.")
    file_bytes = await file.read() if file else None
    try:
        return await integrations.analyze_phishing(raw_text=raw_text, file_bytes=file_bytes,
                                                     filename=file.filename if file else None)
    except Exception:
        raise HTTPException(status_code=502, detail="Phishing triage service unavailable.")


@app.post("/api/investigate/file")
async def investigate_file(file: UploadFile = File(...), _user: str = Depends(require_auth)):
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Empty file.")
    try:
        return await integrations.analyze_file(file_bytes, file.filename or "upload")
    except Exception:
        raise HTTPException(status_code=502, detail="File analyser service unavailable.")


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    secret_header = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if telegram_bot.WEBHOOK_SECRET and secret_header != telegram_bot.WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="forbidden")

    payload = await request.json()
    message = payload.get("message", {})
    chat_id = str(message.get("chat", {}).get("id", ""))
    text = message.get("text", "")

    if not telegram_bot.is_authorized(chat_id):
        return {"ok": True}  # silently ignore - don't confirm bot existence to strangers

    reply = await telegram_bot.handle_command(db, text)
    await telegram_bot.send_message(chat_id, reply)
    return {"ok": True}
