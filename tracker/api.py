"""FastAPI app for the personal SOC incident tracker - login-gated
(single account, by design), backs onto the dashboard UI and the
bidirectional Telegram bot.

Run locally:   uvicorn tracker.api:app --reload
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import auth, telegram_bot
from .db import TrackerDB
from .scheduler import start_scheduler, stop_scheduler
from .seed_sops import seed_default_sops

db = TrackerDB()

MAX_BODY_BYTES = 200 * 1024
MAX_TEXT_LENGTH = 4096


@asynccontextmanager
async def lifespan(app: FastAPI):
    await seed_default_sops(db)
    start_scheduler(db)
    yield
    stop_scheduler()


app = FastAPI(title="SOC Incident Tracker", version="1.0.0", lifespan=lifespan)

_STATIC_DIR = Path(__file__).resolve().parent / "static"

ADMIN_USERNAME = os.environ.get("TRACKER_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("TRACKER_ADMIN_PASSWORD_HASH")


@app.middleware("http")
async def reject_oversized_bodies(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
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


class StatusUpdateRequest(BaseModel):
    status: str = Field(max_length=32)
    reason: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)


class NoteRequest(BaseModel):
    note: str = Field(max_length=MAX_TEXT_LENGTH)


class SopRequest(BaseModel):
    alert_type: str = Field(max_length=256)
    steps: str = Field(max_length=MAX_TEXT_LENGTH)


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
        raise HTTPException(status_code=429, detail="Too many login attempts - try again later.")

    if not ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=500, detail="Server not configured - no admin password set.")

    if body.username != ADMIN_USERNAME or not auth.verify_password(body.password, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    auth.reset_rate_limit(ip)
    token = auth.create_session_token(body.username)
    response.set_cookie(
        auth.SESSION_COOKIE_NAME, token, max_age=auth.SESSION_MAX_AGE_SECONDS,
        httponly=True, secure=True, samesite="strict",
    )
    return {"status": "ok"}


@app.post("/logout")
async def logout(response: Response, _user: str = Depends(require_auth)):
    response.delete_cookie(auth.SESSION_COOKIE_NAME)
    return {"status": "ok"}


@app.get("/api/me")
async def me(user: str = Depends(require_auth)):
    return {"username": user}


@app.get("/api/incidents")
async def list_incidents(status: str | None = None, _user: str = Depends(require_auth)):
    return await db.list_incidents(status=status)


@app.post("/api/incidents")
async def create_incident(body: CreateIncidentRequest, _user: str = Depends(require_auth)):
    incident = await db.create_incident(body.alert_type, body.title, body.description)
    sop = await db.get_sop(body.alert_type)
    await telegram_bot.notify_all(f"New ticket #{incident['id']}: [{body.alert_type}] {body.title}")
    return {"incident": incident, "sop": sop}


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int, _user: str = Depends(require_auth)):
    incident = await db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    updates = await db.get_updates(incident_id)
    sop = await db.get_sop(incident["alert_type"])
    return {"incident": incident, "updates": updates, "sop": sop}


@app.post("/api/incidents/{incident_id}/status")
async def update_status(incident_id: int, body: StatusUpdateRequest, _user: str = Depends(require_auth)):
    try:
        updated = await db.update_status(incident_id, body.status, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found.")
    await telegram_bot.notify_all(f"Ticket #{incident_id} marked {body.status}.")
    return {"status": "ok"}


@app.post("/api/incidents/{incident_id}/notes")
async def add_note(incident_id: int, body: NoteRequest, _user: str = Depends(require_auth)):
    added = await db.add_update_note(incident_id, body.note)
    if not added:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"status": "ok"}


@app.get("/api/sops")
async def list_sops(_user: str = Depends(require_auth)):
    return await db.list_sops()


@app.post("/api/sops")
async def upsert_sop(body: SopRequest, _user: str = Depends(require_auth)):
    await db.upsert_sop(body.alert_type, body.steps)
    return {"status": "ok"}


@app.get("/api/sops/{alert_type}")
async def get_sop(alert_type: str, _user: str = Depends(require_auth)):
    sop = await db.get_sop(alert_type)
    if not sop:
        raise HTTPException(status_code=404, detail="No SOP for this alert type.")
    return sop


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
