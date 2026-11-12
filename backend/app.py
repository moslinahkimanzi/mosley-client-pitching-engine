"""MCAS API: authenticated workspace, secure drafts, prospect research and integrations."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Optional, Literal

from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

BASE = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("MCAS_DATABASE_PATH", str(BASE / "data" / "mcas.db")))
SECRET = os.getenv("MCAS_SECRET_KEY", "development-only-change-this-secret")
COOKIE = "mcas_session"
CSRF_COOKIE = "mcas_csrf"
SESSION_SECONDS = 60 * 60 * 24 * 14
IS_PROD = os.getenv("MCAS_ENV", "development").lower() == "production"
MAX_BODY_BYTES = 1_000_000

if IS_PROD and (len(SECRET) < 40 or SECRET.startswith("development-only")):
    raise RuntimeError("Set a unique MCAS_SECRET_KEY of at least 40 characters for production.")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="MCAS API", version="1.0.0", description="Mosley Client Acquisition System")
(BASE / "assets").mkdir(parents=True, exist_ok=True)
app.mount("/assets", StaticFiles(directory=BASE / "assets"), name="assets")
origins = [x.strip() for x in os.getenv("MCAS_ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if x.strip()]
hosts = [x.strip() for x in os.getenv("MCAS_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if x.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts or ["localhost"])
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"],
                   allow_headers=["Content-Type", "X-CSRF-Token"])

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=15000")
    try:
        yield con
        con.commit()
    finally:
        con.close()

def now():
    return datetime.now(timezone.utc).isoformat()

def add_column(con, table, name, definition):
    cols = {r["name"] for r in con.execute("PRAGMA table_info(" + table + ")").fetchall()}
    if name not in cols:
        con.execute("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS leads(
            id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,website TEXT,market TEXT,evidence TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Unverified',score INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS drafts(
            id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            lead_id TEXT,kind TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending_approval',created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,action TEXT NOT NULL,
            created_at TEXT NOT NULL,metadata TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS followups(
            id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            lead_id TEXT NOT NULL,title TEXT NOT NULL,due_at TEXT,state TEXT NOT NULL DEFAULT 'open',
            notes TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,
            FOREIGN KEY(lead_id) REFERENCES leads(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS proposals(
            id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            lead_id TEXT,title TEXT NOT NULL,content TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'draft',
            created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
            FOREIGN KEY(lead_id) REFERENCES leads(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS oauth_states(
            state_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS integrations(
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider TEXT NOT NULL,encrypted_refresh_token TEXT NOT NULL,connected_at TEXT NOT NULL,
            PRIMARY KEY(user_id,provider)
        );
        CREATE INDEX IF NOT EXISTS idx_leads_user_updated ON leads(user_id,updated_at);
        CREATE INDEX IF NOT EXISTS idx_drafts_user_created ON drafts(user_id,created_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_followups_user_due ON followups(user_id,due_at,state);
        CREATE INDEX IF NOT EXISTS idx_proposals_user ON proposals(user_id,updated_at);
        """)
        add_column(c, "leads", "contact_email", "TEXT")
        add_column(c, "leads", "contact_phone", "TEXT")
        add_column(c, "leads", "source_url", "TEXT")
        add_column(c, "leads", "do_not_contact", "INTEGER NOT NULL DEFAULT 0")
        add_column(c, "drafts", "to_email", "TEXT")

init_db()

def audit(c, uid, action, metadata=None):
    c.execute("INSERT INTO audit_log(user_id,action,created_at,metadata) VALUES(?,?,?,?)",
              (uid, action, now(), json.dumps(metadata or {})[:4000]))

def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + salt.hex() + "$" + digest.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt, digest = encoded.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, digest)
    except Exception:
        return False

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def csrf_signature(nonce: str) -> str:
    return hmac.new(SECRET.encode(), ("csrf:" + nonce).encode(), hashlib.sha256).hexdigest()

def new_csrf():
    nonce = secrets.token_urlsafe(24)
    return nonce + "." + csrf_signature(nonce)

def valid_csrf(value: str) -> bool:
    try:
        nonce, signature = value.split(".", 1)
        return hmac.compare_digest(signature, csrf_signature(nonce))
    except Exception:
        return False

def set_csrf(response: Response):
    token = new_csrf()
    response.set_cookie(CSRF_COOKIE, token, max_age=SESSION_SECONDS, httponly=False,
                        secure=IS_PROD, samesite="strict", path="/")
    return token

def current_user(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Sign in required")
    with db() as c:
        row = c.execute("""SELECT users.id,users.email FROM sessions
            JOIN users ON users.id=sessions.user_id
            WHERE token_hash=? AND expires_at>?""",
            (token_hash(token), int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, "Session expired; sign in again")
    return dict(row)

def owned_lead(c, lead_id, uid):
    row = c.execute("SELECT * FROM leads WHERE id=? AND user_id=?", (lead_id, uid)).fetchone()
    if not row:
        raise HTTPException(404, "Prospect not found")
    return row

# Lightweight per-process throttling. Configure a shared limiter before running multiple workers.
_rate_windows: dict[str, list[float]] = {}
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) > MAX_BODY_BYTES:
                return Response("Request body too large", status_code=413)
        except ValueError:
            return Response("Invalid content length", status_code=400)
    origin = request.headers.get("origin")
    unsafe = request.method in {"POST", "PATCH", "DELETE", "PUT"}
    if unsafe and origin and origin not in origins:
        return Response("Origin not allowed", status_code=403)
    if unsafe and request.url.path not in {"/api/integrations/gmail/callback"}:
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        header_token = request.headers.get("x-csrf-token", "")
        if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token) or not valid_csrf(header_token):
            return Response("CSRF validation failed. Refresh and try again.", status_code=403)

    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    token = request.cookies.get(COOKIE, "")
    if path in {"/api/auth/login", "/api/auth/register"}:
        category, cap = "auth", 8
    elif path == "/api/assistant/draft":
        category, cap = "ai", 6
    elif path in {"/api/research/search", "/api/research/run"}:
        category, cap = "search", 5
    elif path == "/api/audit-website":
        category, cap = "website", 10
    elif path.endswith("/gmail") and request.method == "POST":
        category, cap = "gmail", 8
    else:
        category, cap = "general", 120

    keys = [ip + ":" + category]
    if token and category not in {"auth", "general"}:
        keys.append("session:" + token_hash(token)[:24] + ":" + category)
    current = time.time()
    for key in keys:
        recent = [stamp for stamp in _rate_windows.get(key, []) if current - stamp < 60]
        if len(recent) >= cap:
            return Response("Too many requests for this operation. Try again shortly.", status_code=429,
                            headers={"Retry-After": "60"})
    for key in keys:
        recent = [stamp for stamp in _rate_windows.get(key, []) if current - stamp < 60]
        recent.append(current)
        _rate_windows[key] = recent
    if len(_rate_windows) > 10000:
        for key, stamps in list(_rate_windows.items()):
            kept = [stamp for stamp in stamps if current - stamp < 60]
            if kept:
                _rate_windows[key] = kept
            else:
                del _rate_windows[key]

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
    if IS_PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

class RegisterIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=200)

class LoginIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=200)

class LeadIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    website: Optional[str] = Field(default=None, max_length=2048)
    market: str = Field(default="Kenya", max_length=100)
    evidence: str = Field(default="", max_length=5000)
    status: Literal["Unverified", "Verified", "Contacted", "Replied", "Interested", "Negotiating", "Won", "Lost"] = "Unverified"
    contact_email: Optional[str] = Field(default=None, max_length=254)
    contact_phone: Optional[str] = Field(default=None, max_length=50)
    source_url: Optional[str] = Field(default=None, max_length=2048)
    do_not_contact: bool = False

class DraftIn(BaseModel):
    lead_id: Optional[str] = None
    kind: str = Field(default="Cold email", max_length=40)
    to_email: Optional[str] = Field(default=None, max_length=254)
    subject: str = Field(max_length=200)
    body: str = Field(min_length=1, max_length=12000)

class FollowupIn(BaseModel):
    lead_id: str
    title: str = Field(min_length=1, max_length=160)
    due_at: Optional[str] = Field(default=None, max_length=60)
    notes: str = Field(default="", max_length=3000)
    state: Literal["open", "done", "cancelled"] = "open"

class ProposalIn(BaseModel):
    lead_id: Optional[str] = None
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=20000)
    state: Literal["draft", "reviewed", "approved", "archived"] = "draft"

class ResearchIn(BaseModel):
    query: str = Field(min_length=2, max_length=160)

class ResearchRunIn(BaseModel):
    location: str = Field(min_length=2, max_length=100)
    industry: Literal["any", "restaurant", "salon", "retail", "professional", "hotel", "healthcare", "education"] = "any"
    keywords: str = Field(default="", max_length=120)
    max_results: int = Field(default=6, ge=1, le=12)

class AIIn(BaseModel):
    lead_id: Optional[str] = None
    task: str = Field(default="email", max_length=30)
    prospect_name: str = Field(max_length=120)
    market: str = Field(default="", max_length=100)
    service: str = Field(default="website development", max_length=160)
    evidence: str = Field(default="", max_length=3000)
    incoming: str = Field(default="", max_length=5000)

@app.get("/")
def home():
    return FileResponse(BASE / "index.html")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "MCAS API", "version": "1.0.0", "time": now()}

@app.get("/api/auth/csrf")
def get_csrf(response: Response):
    token = set_csrf(response)
    return {"csrf_token": token}

def validate_email(email: Optional[str]):
    if email is None or email == "":
        return
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(422, "Enter a valid email address")

@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterIn, response: Response):
    email = payload.email.strip().lower()
    validate_email(email)
    if len(set(payload.password)) < 5:
        raise HTTPException(422, "Choose a stronger password with more varied characters")
    uid = secrets.token_urlsafe(18)
    session = secrets.token_urlsafe(36)
    try:
        with db() as c:
            c.execute("INSERT INTO users VALUES(?,?,?,?)", (uid, email, password_hash(payload.password), now()))
            c.execute("INSERT INTO sessions VALUES(?,?,?)", (token_hash(session), uid, int(time.time()) + SESSION_SECONDS))
            audit(c, uid, "account.created")
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with this email already exists")
    response.set_cookie(COOKIE, session, max_age=SESSION_SECONDS, httponly=True,
                        secure=IS_PROD, samesite="lax", path="/")
    set_csrf(response)
    return {"id": uid, "email": email}

@app.post("/api/auth/login")
def login(payload: LoginIn, response: Response):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (payload.email.strip().lower(),)).fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(401, "Email or password is incorrect")
        # Rotate active sessions on successful login to reduce stale-session risk.
        c.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
        session = secrets.token_urlsafe(36)
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (token_hash(session), row["id"], int(time.time()) + SESSION_SECONDS))
        audit(c, row["id"], "account.login")
    response.set_cookie(COOKIE, session, max_age=SESSION_SECONDS, httponly=True,
                        secure=IS_PROD, samesite="lax", path="/")
    set_csrf(response)
    return {"id": row["id"], "email": row["email"]}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))
    response.delete_cookie(COOKIE, path="/", httponly=True, secure=IS_PROD, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=IS_PROD, samesite="strict")
    return {"ok": True}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return user

@app.get("/api/leads")
def list_leads(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM leads WHERE user_id=? ORDER BY updated_at DESC", (user["id"],)).fetchall()
    return [dict(x) for x in rows]

@app.post("/api/leads", status_code=201)
def add_lead(payload: LeadIn, user=Depends(current_user)):
    lid = secrets.token_urlsafe(15)
    stamp = now()
    validate_email(payload.contact_email)
    with db() as c:
        c.execute("""INSERT INTO leads(id,user_id,name,website,market,evidence,status,score,created_at,updated_at,
            contact_email,contact_phone,source_url,do_not_contact) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (lid, user["id"], payload.name.strip(), payload.website, payload.market, payload.evidence,
             payload.status, 0, stamp, stamp, payload.contact_email, payload.contact_phone, payload.source_url,
             int(payload.do_not_contact)))
        audit(c, user["id"], "lead.created", {"lead_id": lid})
    return {"id": lid, "name": payload.name, "status": payload.status}

@app.patch("/api/leads/{lead_id}")
def update_lead(lead_id: str, payload: LeadIn, user=Depends(current_user)):
    validate_email(payload.contact_email)
    with db() as c:
        cur = c.execute("""UPDATE leads SET name=?,website=?,market=?,evidence=?,status=?,contact_email=?,
            contact_phone=?,source_url=?,do_not_contact=?,updated_at=? WHERE id=? AND user_id=?""",
            (payload.name.strip(), payload.website, payload.market, payload.evidence, payload.status,
             payload.contact_email, payload.contact_phone, payload.source_url, int(payload.do_not_contact),
             now(), lead_id, user["id"]))
        if not cur.rowcount:
            raise HTTPException(404, "Prospect not found")
        audit(c, user["id"], "lead.updated", {"lead_id": lead_id})
    return {"ok": True}

@app.delete("/api/leads/{lead_id}")
def delete_lead(lead_id: str, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("DELETE FROM leads WHERE id=? AND user_id=?", (lead_id, user["id"]))
        if not cur.rowcount:
            raise HTTPException(404, "Prospect not found")
        audit(c, user["id"], "lead.deleted", {"lead_id": lead_id})
    return {"ok": True}

@app.get("/api/drafts")
def list_drafts(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM drafts WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    return [dict(x) for x in rows]

@app.post("/api/drafts", status_code=201)
def save_draft(payload: DraftIn, user=Depends(current_user)):
    validate_email(payload.to_email)
    did = secrets.token_urlsafe(15)
    with db() as c:
        if payload.lead_id:
            lead = owned_lead(c, payload.lead_id, user["id"])
            if int(lead["do_not_contact"] or 0) and payload.kind.lower() in {"cold email", "follow-up", "outreach"}:
                raise HTTPException(403, "This prospect is marked do-not-contact; outreach drafts are blocked.")
        c.execute("""INSERT INTO drafts(id,user_id,lead_id,kind,subject,body,state,created_at,to_email)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (did, user["id"], payload.lead_id, payload.kind, payload.subject, payload.body,
             "pending_approval", now(), payload.to_email))
        audit(c, user["id"], "draft.saved", {"draft_id": did, "kind": payload.kind})
    return {"id": did, "state": "pending_approval"}

@app.delete("/api/drafts/{draft_id}")
def delete_draft(draft_id: str, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("DELETE FROM drafts WHERE id=? AND user_id=?", (draft_id, user["id"]))
        if not cur.rowcount:
            raise HTTPException(404, "Draft not found")
        audit(c, user["id"], "draft.deleted", {"draft_id": draft_id})
    return {"ok": True}

@app.get("/api/followups")
def list_followups(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("""SELECT f.*,l.name AS lead_name FROM followups f
            JOIN leads l ON l.id=f.lead_id WHERE f.user_id=? ORDER BY
            CASE WHEN f.due_at IS NULL THEN 1 ELSE 0 END, f.due_at""", (user["id"],)).fetchall()
    return [dict(x) for x in rows]

@app.post("/api/followups", status_code=201)
def create_followup(payload: FollowupIn, user=Depends(current_user)):
    fid = secrets.token_urlsafe(15)
    with db() as c:
        owned_lead(c, payload.lead_id, user["id"])
        c.execute("INSERT INTO followups(id,user_id,lead_id,title,due_at,state,notes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                  (fid, user["id"], payload.lead_id, payload.title, payload.due_at, payload.state, payload.notes, now()))
        audit(c, user["id"], "followup.created", {"followup_id": fid})
    return {"id": fid, "state": payload.state}

@app.patch("/api/followups/{followup_id}")
def update_followup(followup_id: str, payload: dict, user=Depends(current_user)):
    state = str(payload.get("state", "open"))
    if state not in {"open", "done", "cancelled"}:
        raise HTTPException(422, "Invalid follow-up state")
    with db() as c:
        cur = c.execute("UPDATE followups SET state=? WHERE id=? AND user_id=?", (state, followup_id, user["id"]))
        if not cur.rowcount:
            raise HTTPException(404, "Follow-up not found")
        audit(c, user["id"], "followup.updated", {"followup_id": followup_id, "state": state})
    return {"ok": True}

@app.get("/api/proposals")
def list_proposals(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM proposals WHERE user_id=? ORDER BY updated_at DESC", (user["id"],)).fetchall()
    return [dict(x) for x in rows]

@app.post("/api/proposals", status_code=201)
def save_proposal(payload: ProposalIn, user=Depends(current_user)):
    pid = secrets.token_urlsafe(15)
    with db() as c:
        if payload.lead_id:
            owned_lead(c, payload.lead_id, user["id"])
        stamp = now()
        c.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?)",
                  (pid, user["id"], payload.lead_id, payload.title, payload.content, payload.state, stamp, stamp))
        audit(c, user["id"], "proposal.saved", {"proposal_id": pid})
    return {"id": pid, "state": payload.state}

@app.get("/api/research/search")
def research_search(q: str = Query(min_length=2, max_length=160), user=Depends(current_user)):
    key = os.getenv("BRAVE_SEARCH_API_KEY")
    if not key:
        raise HTTPException(503, "Live search is not configured. Add BRAVE_SEARCH_API_KEY on the server.")
    params = urllib.parse.urlencode({"q": q, "count": 10})
    req = urllib.request.Request("https://api.search.brave.com/res/v1/web/search?" + params,
        headers={"Accept": "application/json", "X-Subscription-Token": key, "User-Agent": "MCAS/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read(1_500_000))
    except Exception:
        raise HTTPException(502, "Search provider request failed")
    results = data.get("web", {}).get("results", [])
    with db() as c:
        audit(c, user["id"], "research.search", {"query": q[:100], "count": len(results)})
    return {"query": q, "results": [{"title": x.get("title"), "url": x.get("url"),
            "description": x.get("description")} for x in results[:10]],
            "provider": "Brave Search",
            "warning": "Search results are discovery leads, not verified facts. Open and verify each source before contacting a business."}

# Outbound website checks pin a validated public IP for each connection and never follow redirects blindly.
class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self.pinned_ip = ip
    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.pinned_ip = ip
    def connect(self):
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

def resolve_public(host):
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(422, "Website host could not be resolved")
    ips = sorted({r[4][0].split("%")[0] for r in records})
    if not ips:
        raise HTTPException(422, "Website host has no address")
    parsed = [ipaddress.ip_address(value) for value in ips]
    if any(not value.is_global for value in parsed):
        raise HTTPException(400, "Private, local, reserved and non-public network targets are blocked")
    return ips[0]

def safe_site_fetch(initial_url):
    url = initial_url
    original_scheme = urllib.parse.urlparse(url).scheme.lower()
    for hop in range(4):
        p = urllib.parse.urlparse(url)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
            raise HTTPException(422, "Provide a public http or https URL")
        try:
            port = p.port or (443 if p.scheme == "https" else 80)
        except ValueError:
            raise HTTPException(422, "Invalid website port")
        if port not in {80, 443}:
            raise HTTPException(400, "Only standard HTTP and HTTPS ports are allowed")
        if p.scheme == "https" and port != 443 or p.scheme == "http" and port != 80:
            raise HTTPException(400, "Non-standard ports are blocked")
        if original_scheme == "https" and p.scheme != "https":
            raise HTTPException(400, "HTTPS-to-HTTP redirects are blocked")
        ip = resolve_public(p.hostname)
        conn_cls = PinnedHTTPS if p.scheme == "https" else PinnedHTTP
        conn = conn_cls(p.hostname, ip, port, 8)
        path = urllib.parse.urlunparse(("", "", p.path or "/", p.params, p.query, ""))
        try:
            conn.request("GET", path, headers={"Host": p.hostname, "User-Agent": "MCAS-SiteAudit/1.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1", "Connection": "close"})
            res = conn.getresponse()
            status = res.status
            headers = dict(res.getheaders())
            if status in {301, 302, 303, 307, 308}:
                location = headers.get("Location") or headers.get("location")
                res.read(2048)
                conn.close()
                if not location or hop == 3:
                    raise HTTPException(502, "Website redirect could not be safely followed")
                url = urllib.parse.urljoin(url, location)
                continue
            ctype = headers.get("Content-Type", headers.get("content-type", ""))
            if "text/html" not in ctype.lower() and "application/xhtml" not in ctype.lower():
                res.read(2048)
                conn.close()
                return {"url": url, "http_status": status, "content_type": ctype,
                        "title": None, "has_viewport_meta": None, "has_meta_description": None,
                        "has_h1": None, "has_form": None,
                        "note": "Response is not HTML; page metadata was not analysed."}
            body = res.read(512001)
            conn.close()
            if len(body) > 512000:
                body = body[:512000]
            html = body.decode("utf-8", "replace")
            match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            viewport = bool(re.search(r"""<meta[^>]+name=["']viewport""", html, re.I))
            description = bool(re.search(r"""<meta[^>]+name=["']description""", html, re.I))
            has_h1 = bool(re.search(r"<h1\b", html, re.I))
            has_form = bool(re.search(r"<form\b", html, re.I))
            title = re.sub(r"\s+", " ", match.group(1)).strip()[:180] if match else None
            return {"url": url, "http_status": status, "content_type": ctype, "title": title,
                    "has_viewport_meta": viewport, "has_meta_description": description,
                    "has_h1": has_h1, "has_form": has_form,
                    "note": "Lightweight public-page check only; not a full SEO, accessibility, security or conversion audit."}
        except HTTPException:
            conn.close()
            raise
        except Exception:
            conn.close()
            raise HTTPException(502, "Website could not be checked safely")
    raise HTTPException(502, "Too many redirects")


# Local, low-volume business discovery. Results are incomplete OSM records, not proof that
# a business does or does not have a website. Cache searches and keep result counts bounded.
_OVERPASS_CACHE: dict[str, tuple[float, list[dict]]] = {}
OVERPASS_DEFAULT = "https://overpass.private.coffee/api/interpreter"


_GEOCODE_CACHE: dict[str, tuple[float, dict]] = {}

def geocode_location(location: str) -> dict:
    """Resolve a named place once and cache its bounding box for 24 hours."""
    key = location.strip().casefold()
    cached = _GEOCODE_CACHE.get(key)
    if cached and time.time() - cached[0] < 86400:
        return cached[1]
    params = urllib.parse.urlencode({"q": location, "format": "jsonv2", "limit": 1, "addressdetails": 1})
    req = urllib.request.Request("https://nominatim.openstreetmap.org/search?" + params,
        headers={"User-Agent": "MCAS/1.2 (user-triggered business research)",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            rows = json.loads(response.read(300_000))
        if not rows:
            raise HTTPException(404, "That place could not be found. Try a more specific town, suburb or city.")
        row = rows[0]
        raw_box = row.get("boundingbox") or []
        if len(raw_box) != 4:
            raise ValueError("Missing place bounding box")
        south, north, west, east = (float(v) for v in raw_box)
        if north - south > 3.0 or east - west > 3.0:
            raise HTTPException(422, "That location is too broad. Enter a town, city or neighbourhood instead.")
        result = {"display_name": row.get("display_name", location),
                  "bbox": (south, west, north, east),
                  "place_type": row.get("type") or row.get("addresstype") or "place"}
        _GEOCODE_CACHE[key] = (time.time(), result)
        return result
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Place lookup is temporarily unavailable. Please wait and try again.")

def overpass_query_for(location: str, industry: str, bbox: Optional[tuple] = None) -> str:
    safe_name = re.sub(r"[^\w\s,'-]", "", location.strip(), flags=re.UNICODE).strip()
    if not safe_name:
        raise HTTPException(422, "Use a town, city or area name containing letters or numbers.")
    if industry == "restaurant":
        filters = ['nwr["name"]["amenity"~"^(restaurant|cafe|fast_food|bar|pub)$"](area.searchArea);']
    elif industry == "salon":
        filters = ['nwr["name"]["shop"~"^(hairdresser|beauty)$"](area.searchArea);']
    elif industry == "retail":
        filters = ['nwr["name"]["shop"](area.searchArea);']
    elif industry == "professional":
        filters = ['nwr["name"]["office"](area.searchArea);']
    elif industry == "hotel":
        filters = ['nwr["name"]["tourism"~"^(hotel|guest_house|hostel)$"](area.searchArea);']
    elif industry == "healthcare":
        filters = ['nwr["name"]["amenity"~"^(clinic|doctors|dentist|hospital)$"](area.searchArea);']
    elif industry == "education":
        filters = ['nwr["name"]["amenity"~"^(school|college|university|kindergarten)$"](area.searchArea);']
    else:
        filters = [
            'nwr["name"]["amenity"~"^(restaurant|cafe|fast_food|bar|pub|clinic|doctors|dentist|school|college)$"](area.searchArea);',
            'nwr["name"]["shop"](area.searchArea);',
            'nwr["name"]["office"](area.searchArea);',
            'nwr["name"]["tourism"~"^(hotel|guest_house|hostel)$"](area.searchArea);',
            'nwr["name"]["craft"](area.searchArea);'
        ]
    if bbox:
        south, west, north, east = bbox
        bounds = "({:.6f},{:.6f},{:.6f},{:.6f})".format(south, west, north, east)
        return '[out:json][timeout:35];(' + ''.join(
            item.replace('(area.searchArea)', bounds) for item in filters
        ) + ');out center tags 100;'
    return ('[out:json][timeout:25];'
            'area["name"~"^' + safe_name + '$",i]["boundary"="administrative"]->.searchArea;'
            '(' + ''.join(filters) + ');out center tags 100;')

def opportunity_score(tags: dict, website_state: str, website_audit: dict,
                      email: Optional[str], phone: Optional[str]) -> tuple[int, list[str]]:
    """Transparent heuristic priority; not a claim that a business wants a website."""
    score = 0
    reasons = []
    if website_state == "broken":
        score += 35; reasons.append("listed website returned an error")
    elif website_state == "needs_improvement":
        score += 28; reasons.append("limited page checks found missing technical basics")
    elif website_state == "not_listed":
        score += 12; reasons.append("website URL is not listed; existence remains unverified")
    elif website_state == "access_restricted":
        score += 8; reasons.append("website check was restricted")
    elif website_state == "needs_review":
        score += 5; reasons.append("website could not be verified")
    else:
        score += 3; reasons.append("listed website responded to a lightweight check")
    if email:
        score += 15; reasons.append("public contact email listed")
    if phone:
        score += 10; reasons.append("public phone number listed")
    if any(tags.get(k) for k in ("addr:street", "addr:city", "addr:postcode")):
        score += 5; reasons.append("public address details listed")
    if website_audit.get("has_viewport_meta") is False:
        score += 8; reasons.append("mobile viewport metadata not detected")
    if website_audit.get("has_h1") is False:
        score += 4; reasons.append("main heading not detected")
    if website_audit.get("has_form") is False and website_state in {"working", "needs_improvement"}:
        score += 3; reasons.append("no HTML form detected on the fetched page")
    return min(100, score), reasons

def business_strategy(tags: dict) -> dict:
    amenity = str(tags.get("amenity", "")).lower()
    shop = str(tags.get("shop", "")).lower()
    tourism = str(tags.get("tourism", "")).lower()
    if amenity in {"restaurant", "cafe", "fast_food", "bar", "pub"}:
        return {
            "type": "Mobile-first restaurant website",
            "pages": ["Home and restaurant introduction", "Menu with categories, prices and dietary notes",
                      "About the restaurant", "Gallery", "Location, opening hours and contact"],
            "features": ["Tap-to-call and WhatsApp enquiry", "Map directions", "Easy-to-update menu",
                         "Reservation enquiry flow if the restaurant accepts bookings"],
            "roadmap": ["Confirm menu, prices, opening hours and brand assets",
                        "Build and test the mobile menu and contact journey",
                        "Add local search metadata and optimise food photography"]
        }
    if shop in {"hairdresser", "beauty"}:
        return {
            "type": "Salon and beauty-service website",
            "pages": ["Home", "Treatments and services", "Price guide", "Gallery", "Location and bookings"],
            "features": ["WhatsApp or booking enquiry", "Service descriptions and price ranges",
                         "Gallery using approved images", "Opening hours and map directions"],
            "roadmap": ["Confirm services, prices and booking process",
                        "Create service pages and mobile booking calls to action",
                        "Optimise images and local business details"]
        }
    if shop:
        return {
            "type": "Retail catalogue website",
            "pages": ["Home and featured products", "Product categories", "Product details",
                      "Delivery and returns information", "Contact"],
            "features": ["Product catalogue", "WhatsApp product enquiries", "Stock and price update workflow",
                         "Online checkout only if requested and scoped"],
            "roadmap": ["Collect approved product data and photography",
                        "Build searchable categories and enquiry flow",
                        "Add checkout only after payment and delivery requirements are agreed"]
        }
    if tourism:
        return {
            "type": "Hospitality website",
            "pages": ["Home", "Rooms and facilities", "Gallery", "Rates and policies",
                      "Location and booking enquiries"],
            "features": ["Room / service information", "Booking enquiry", "Map and contact details"],
            "roadmap": ["Confirm facilities, rates and availability process",
                        "Build mobile-first pages and enquiry flow",
                        "Optimise photography and local search metadata"]
        }
    if amenity in {"clinic", "doctors", "dentist", "hospital"}:
        return {
            "type": "Healthcare practice website",
            "pages": ["Home", "Treatments and services", "Practitioner information",
                      "Appointment enquiry", "Location and patient FAQs"],
            "features": ["Appointment request", "Verified practitioner credentials",
                         "Privacy-conscious forms and clear contact information"],
            "roadmap": ["Validate qualifications and service information",
                        "Build accessible, privacy-conscious pages",
                        "Test appointment and contact workflows"]
        }
    return {
        "type": "Professional or local-business website",
        "pages": ["Home and value proposition", "Services", "About and credentials",
                  "Work examples or case studies with permission", "Contact / enquiry"],
        "features": ["Mobile enquiry form", "Click-to-call / WhatsApp", "Clear service-area information",
                     "Search-friendly page titles and metadata"],
        "roadmap": ["Confirm target customers and service offering",
                    "Build the essential pages and enquiry journey",
                    "Test mobile usability, accessibility and performance"]
    }

def make_outreach_copy(name: str, location: str, website_state: str, audit: dict,
                       strategy: dict, contact_email: Optional[str]) -> tuple[str, str]:
    subject = "A website idea for " + name
    if website_state == "not_listed":
        evidence_line = ("I found your public business listing, but it did not include an official website link. "
                         "That does not necessarily mean you do not have a website, so I wanted to check first.")
    elif website_state == "broken":
        evidence_line = ("I checked the website listed for your business and it returned HTTP "
                         + str(audit.get("http_status")) + " during my check. This may be temporary, "
                         "but it seemed worth flagging.")
        subject = "A website issue I noticed for " + name
    elif website_state == "needs_improvement":
        observations = []
        if audit.get("has_viewport_meta") is False:
            observations.append("I could not find a mobile viewport setting in the page HTML")
        if audit.get("has_meta_description") is False:
            observations.append("I could not find a meta description")
        if audit.get("title") is None:
            observations.append("I could not detect a page title")
        evidence_line = ("I ran a limited technical check on the public website. " +
                         ("; ".join(observations) + "." if observations else "There may be room to improve the customer journey.") +
                         " This was not a full audit.")
    else:
        evidence_line = ("I found your public business listing while researching " + location +
                         ". I have not confirmed a specific website problem, so I do not want to make assumptions.")
    body = ("Hello " + name + " team,\n\n"
            "I came across your business while researching " + location + ". " + evidence_line + "\n\n"
            "I build practical, mobile-friendly websites that help customers understand what a business offers "
            "and take the next step. For your business, I would suggest starting with a "
            + strategy["type"].lower() + ", including " + ", ".join(strategy["pages"][:3]).lower()
            + ", and a clear contact or enquiry path.\n\n"
            "Would you be open to a short conversation? I can share a tailored outline and a clear scope "
            "before you decide whether it is useful.\n\n"
            "Best regards,\nMosley | Web Developer\n\n"
            "If this is not relevant, let me know and I will not follow up.")
    return subject, body

@app.post("/api/research/run")
def run_business_research(payload: ResearchRunIn, user=Depends(current_user)):
    location = payload.location.strip()
    if not location or not re.search(r"[A-Za-z0-9]", location):
        raise HTTPException(422, "Enter a specific town, city or administrative area.")
    cache_key = location.casefold() + "|" + payload.industry
    cached = _OVERPASS_CACHE.get(cache_key)
    elements = cached[1] if cached and time.time() - cached[0] < 900 else None
    if elements is None:
        endpoint = os.getenv("MCAS_OVERPASS_ENDPOINT", OVERPASS_DEFAULT)
        parsed_endpoint = urllib.parse.urlparse(endpoint)
        if parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname:
            raise HTTPException(503, "The configured OpenStreetMap discovery endpoint must use HTTPS.")
        place = geocode_location(location)
        query = overpass_query_for(location, payload.industry, place["bbox"])
        req = urllib.request.Request(endpoint, data=urllib.parse.urlencode({"data": query}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "MCAS/1.1 (user-triggered local-business discovery)",
                     "Accept": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=35) as response:
                data = json.loads(response.read(2_000_000))
            elements = data.get("elements", [])
            _OVERPASS_CACHE[cache_key] = (time.time(), elements)
        except Exception:
            raise HTTPException(502, "OpenStreetMap discovery is temporarily unavailable. Try again later or use manual web search.")
    discovered = []
    saved_count = 0
    for element in elements:
        if len(discovered) >= payload.max_results:
            break
        tags = element.get("tags") or {}
        name = str(tags.get("name", "")).strip()
        if not name:
            continue
        keyword = payload.keywords.strip().casefold()
        searchable = " ".join(str(tags.get(k, "")) for k in ("name", "brand", "amenity", "shop", "office", "tourism", "cuisine", "craft")).casefold()
        if keyword and keyword not in searchable:
            continue
        raw_website = tags.get("website") or tags.get("contact:website") or tags.get("url")
        website = None
        website_audit = {}
        website_state = "not_listed"
        if raw_website:
            website = str(raw_website).strip()
            if not re.match(r"^https?://", website, re.I):
                website = "https://" + website
            try:
                website_audit = safe_site_fetch(website)
                status = int(website_audit.get("http_status") or 0)
                if status in {404, 410, 500, 502, 503, 504}:
                    website_state = "broken"
                elif status in {401, 403, 429}:
                    website_state = "access_restricted"
                elif 200 <= status < 400:
                    website_state = "needs_improvement" if (
                        website_audit.get("has_viewport_meta") is False or
                        website_audit.get("has_meta_description") is False or
                        website_audit.get("title") is None
                    ) else "working"
                else:
                    website_state = "needs_review"
            except HTTPException:
                website_state = "needs_review"
        osm_type = str(element.get("type", "node"))
        osm_id = str(element.get("id", ""))
        source_url = "https://www.openstreetmap.org/" + osm_type + "/" + osm_id
        email = tags.get("contact:email") or tags.get("email")
        if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", str(email)):
            email = None
        phone = tags.get("contact:phone") or tags.get("phone")
        strategy = business_strategy(tags)
        score, score_reasons = opportunity_score(tags, website_state, website_audit, str(email) if email else None, str(phone) if phone else None)
        facts = ["Discovered in OpenStreetMap public data; verify the business is still operating.",
                 "Heuristic opportunity priority: " + str(score) + "/100; this is a research signal, not buying intent."]
        for category_key in ("amenity", "shop", "office", "tourism", "craft"):
            if tags.get(category_key):
                facts.append("OpenStreetMap category " + category_key + ": " + str(tags[category_key]) + ".")
        if website_state == "not_listed":
            facts.append("No website URL was listed in this OpenStreetMap record. This is not proof that the business has no website.")
        elif website_state == "broken":
            facts.append("The listed website returned HTTP " + str(website_audit.get("http_status")) + " during this check.")
        elif website_state == "needs_improvement":
            findings = []
            if website_audit.get("has_viewport_meta") is False: findings.append("mobile viewport metadata not detected")
            if website_audit.get("has_meta_description") is False: findings.append("meta description not detected")
            if website_audit.get("title") is None: findings.append("page title not detected")
            facts.append("Limited page check: " + ", ".join(findings) + ".")
        elif website_state == "access_restricted":
            facts.append("The website restricted this automated check; no broken-site conclusion was made.")
        elif website_state == "needs_review":
            facts.append("The website could not be reliably checked; do not describe it as broken.")
        elif website_audit:
            facts.append("Website responded with HTTP " + str(website_audit.get("http_status")) + ".")
        if tags.get("addr:street") or tags.get("addr:city"):
            facts.append("Public address tags are present in the source listing.")
        evidence = " ".join(facts) + " Source: " + source_url
        if website_audit.get("url"):
            evidence += " Website checked: " + website_audit["url"] + " (limited technical observations only)."
        with db() as c:
            existing = c.execute("SELECT id FROM leads WHERE user_id=? AND lower(name)=lower(?) AND lower(market)=lower(?)",
                                  (user["id"], name, location)).fetchone()
            if existing:
                discovered.append({"name": name, "lead_id": existing["id"], "duplicate": True,
                    "website": website, "website_state": website_state, "evidence": evidence,
                    "source_url": source_url, "recommendation": strategy["type"],
                    "pages": strategy["pages"], "opportunity_score": score, "score_reasons": score_reasons, "draft_created": False, "proposal_created": False})
                continue
            lead_id = secrets.token_urlsafe(15)
            stamp = now()
            c.execute("""INSERT INTO leads(id,user_id,name,website,market,evidence,status,score,created_at,updated_at,
                contact_email,contact_phone,source_url,do_not_contact) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (lead_id, user["id"], name, website, location, evidence, "Unverified", score, stamp, stamp,
                 str(email) if email else None, str(phone) if phone else None, source_url))
            title = "Website opportunity plan — " + name
            proposal = ("WEBSITE OPPORTUNITY PLAN\n\nBusiness: " + name + "\nLocation: " + location +
                "\nDiscovery source: OpenStreetMap public listing (" + source_url + ")\n\n"
                "1. DISCOVERY OBSERVATIONS (VERIFY WITH BUSINESS)\n" + evidence + "\n\n"
                "2. RECOMMENDED DIRECTION\n" + strategy["type"] + "\n\n"
                "3. SUGGESTED PAGES\n- " + "\n- ".join(strategy["pages"]) + "\n\n"
                "4. SUGGESTED FEATURES\n- " + "\n- ".join(strategy["features"]) + "\n\n"
                "5. IMPLEMENTATION ROADMAP\n- " + "\n- ".join(strategy["roadmap"]) + "\n\n"
                "6. SCOPE TO CONFIRM WITH THE CLIENT\nContent, brand assets, domain, hosting, budget, delivery timeline, "
                "maintenance, integrations and who will update the site.\n\n"
                "7. COMMERCIALS\nPrice and dates to be agreed after discovery. Do not invent a quote or promise results.\n\n"
                "IMPORTANT: OpenStreetMap records are incomplete. 'Website not listed' does not prove there is no website. "
                "Confirm the business identity and all observations before sharing this proposal.")
            proposal_id = secrets.token_urlsafe(15)
            c.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?)",
                (proposal_id, user["id"], lead_id, title, proposal, "draft", stamp, stamp))
            subject, body = make_outreach_copy(name, location, website_state, website_audit, strategy, str(email) if email else None)
            draft_id = secrets.token_urlsafe(15)
            c.execute("""INSERT INTO drafts(id,user_id,lead_id,kind,subject,body,state,created_at,to_email)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (draft_id, user["id"], lead_id, "Cold email", subject, body, "pending_approval", stamp,
                 str(email) if email else None))
            audit(c, user["id"], "research.prospect_prepared", {"lead_id": lead_id,
                "website_state": website_state, "draft_id": draft_id, "proposal_id": proposal_id})
            saved_count += 1
        gmail_draft_created = False
        if email:
            with db() as c:
                gmail_connected = bool(c.execute(
                    "SELECT 1 FROM integrations WHERE user_id=? AND provider='gmail'", (user["id"],)
                ).fetchone())
            if gmail_connected:
                try:
                    create_gmail_draft_for_user(draft_id, user["id"])
                    gmail_draft_created = True
                except HTTPException:
                    # Preserve the MCAS draft if Gmail is temporarily unavailable.
                    gmail_draft_created = False
        discovered.append({"name": name, "lead_id": lead_id, "duplicate": False,
            "website": website, "website_state": website_state, "evidence": evidence,
            "source_url": source_url, "contact_email": str(email) if email else None,
            "recommendation": strategy["type"], "pages": strategy["pages"], "opportunity_score": score, "score_reasons": score_reasons,
            "website_audit": website_audit,
            "draft_created": True, "proposal_created": True,
            "gmail_draft_created": gmail_draft_created})
    with db() as c:
        audit(c, user["id"], "research.run", {"location": location, "industry": payload.industry,
                                               "results": len(discovered), "saved": saved_count})
    state_counts = {}
    for item in discovered:
        state_counts[item["website_state"]] = state_counts.get(item["website_state"], 0) + 1
    ranked = sorted((x.get("opportunity_score", 0) for x in discovered), reverse=True)
    return {"location": location, "resolved_location": place["display_name"],
        "industry": payload.industry, "results": discovered,
        "summary": {"reviewed": len(discovered), "new_prospects_saved": saved_count,
                    "website_states": state_counts,
                    "highest_opportunity_score": ranked[0] if ranked else 0},
        "saved": saved_count, "source": "OpenStreetMap contributors",
        "attribution": "© OpenStreetMap contributors — Open Database License (ODbL)",
        "warning": "Discovery is incomplete and based on OpenStreetMap tags. A missing website tag is not proof that no website exists. Review every business, website finding, contact detail, proposal and email before outreach."}

@app.post("/api/leads/{lead_id}/builder-prompt")
def create_builder_prompt(lead_id: str, user=Depends(current_user)):
    with db() as c:
        lead = owned_lead(c, lead_id, user["id"])
        if lead["status"] != "Won":
            raise HTTPException(409, "Mark the prospect as accepted before generating a website-builder prompt.")
    tags = {}
    notes = (lead["evidence"] or "").lower()
    market = lead["market"] or "the target location"
    if any(word in notes for word in ["restaurant", "cafe", "food", "menu"]):
        tags["amenity"] = "restaurant"
    elif any(word in notes for word in ["salon", "hairdresser", "beauty"]):
        tags["shop"] = "hairdresser"
    elif any(word in notes for word in ["retail", "shop", "products"]):
        tags["shop"] = "retail"
    strategy = business_strategy(tags)
    prompt = ("Act as a senior website strategist, UX designer and full-stack web developer. "
        "Create a complete, responsive, production-minded website for " + lead["name"] + " in " + market + ".\n\n"
        "BUSINESS CONTEXT\nUse only the following recorded discovery observations: " + (lead["evidence"] or "No discovery notes supplied.") + "\n"
        "Treat map-listing details as provisional until the business confirms them. A missing website link in a directory does not prove no website exists.\n"
        "Do not invent menu items, prices, opening hours, staff biographies, awards, reviews, testimonials, addresses or business claims. "
        "Use clearly labelled placeholders for missing content and ask for confirmation.\n\n"
        "RECOMMENDED DIRECTION\n" + strategy["type"] + "\n\n"
        "PAGES\n- " + "\n- ".join(strategy["pages"]) + "\n\n"
        "FEATURES\n- " + "\n- ".join(strategy["features"]) + "\n\n"
        "QUALITY AND ENGINEERING REQUIREMENTS\n- Mobile-first responsive layouts and accessible keyboard navigation.\n"
        "- Fast loading, optimised images, semantic HTML, clear page titles and metadata.\n"
        "- Strong visual hierarchy, consistent typography, spacing and brand system.\n"
        "- Secure forms with validation, spam protection and privacy-conscious data handling.\n"
        "- Functional navigation, working links, clear calls to action and helpful empty/error states.\n"
        "- No fabricated reviews, fake metrics or unapproved copyrighted images.\n"
        "- Include a simple content update/handover approach so the business can maintain its information.\n"
        "- Explain any required paid services before using them; prefer free/local development and avoid secret keys in client code.\n\n"
        "DELIVERY\nProvide the complete source code, project structure, setup instructions, environment-variable example, "
        "testing steps and deployment guidance. Explain assumptions and list the business information still needed before launch.")
    with db() as c:
        audit(c, user["id"], "builder_prompt.generated", {"lead_id": lead_id})
    return {"lead_id": lead_id, "business": lead["name"], "prompt": prompt,
            "note": "Client acceptance is recorded, but confirm the final scope, content, budget and delivery terms before starting build work."}

@app.post("/api/audit-website")
def audit_website(payload: dict, user=Depends(current_user)):
    raw = str(payload.get("url", ""))[:2048].strip()
    result = safe_site_fetch(raw)
    result["checked_at"] = now()
    with db() as c:
        audit(c, user["id"], "website.audit", {"url": result.get("url"), "status": result.get("http_status")})
    return result

@app.post("/api/assistant/draft")
def ai_assistant(payload: AIIn, user=Depends(current_user)):
    base = os.getenv("AI_API_BASE_URL", "").rstrip("/")
    key = os.getenv("AI_API_KEY", "")
    model = os.getenv("AI_MODEL", "")
    if not (base and key and model):
        raise HTTPException(503, "AI is not configured. Set AI_API_BASE_URL, AI_API_KEY and AI_MODEL on the server.")
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise HTTPException(503, "AI endpoint must use HTTPS")
    if payload.task not in {"email", "reply", "proposal"}:
        raise HTTPException(422, "Unsupported assistant task")
    if not payload.lead_id:
        raise HTTPException(422, "Select a saved prospect so its evidence and do-not-contact status can be checked.")
    with db() as c:
        lead = owned_lead(c, payload.lead_id, user["id"])
        if payload.task == "email" and int(lead["do_not_contact"] or 0):
            raise HTTPException(403, "This prospect is marked do-not-contact; outreach drafting is blocked.")
    system = ("You are an ethical B2B website-development sales assistant. Never invent observations, "
              "customer facts, metrics, urgency or testimonials. Use only the supplied evidence. If evidence "
              "is insufficient, explicitly say that research is incomplete. Respect do-not-contact requests. "
              "Write concise, respectful, personalised business communication.")
    input_data = payload.model_dump()
    input_data.update({"prospect_name": lead["name"], "market": lead["market"], "evidence": lead["evidence"]})
    user_prompt = json.dumps(input_data, ensure_ascii=False)
    req = urllib.request.Request(base + "/chat/completions",
        data=json.dumps({"model": model, "temperature": 0.35, "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": user_prompt}
        ]}).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=35) as r:
            data = json.loads(r.read(500000))
        text = data["choices"][0]["message"]["content"]
    except Exception:
        raise HTTPException(502, "AI provider request failed; no draft was saved")
    with db() as c:
        audit(c, user["id"], "assistant.generated", {"task": payload.task})
    return {"draft": str(text)[:16000], "provider": "configured AI provider",
            "warning": "Review every statement against your evidence before saving or sending."}

def gmail_ready():
    required = ["GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REDIRECT_URI", "MCAS_ENCRYPTION_KEY"]
    if not all(os.getenv(v) for v in required) or Fernet is None:
        return False
    if IS_PROD and not os.getenv("GMAIL_REDIRECT_URI", "").startswith("https://"):
        return False
    try:
        Fernet(os.getenv("MCAS_ENCRYPTION_KEY").encode())
        return True
    except Exception:
        return False

def fernet():
    if Fernet is None or not gmail_ready():
        raise HTTPException(503, "Gmail integration is not configured. Add Google OAuth credentials and MCAS_ENCRYPTION_KEY on the server.")
    try:
        return Fernet(os.getenv("MCAS_ENCRYPTION_KEY").encode())
    except Exception:
        raise HTTPException(500, "MCAS_ENCRYPTION_KEY must be a valid Fernet key")

@app.get("/api/integrations/status")
def integration_status(user=Depends(current_user)):
    return {"web_search_configured": bool(os.getenv("BRAVE_SEARCH_API_KEY")),
            "ai_configured": bool(os.getenv("AI_API_BASE_URL") and os.getenv("AI_API_KEY") and os.getenv("AI_MODEL")),
            "gmail_configured": gmail_ready()}

@app.get("/api/integrations/gmail/status")
def gmail_status(user=Depends(current_user)):
    with db() as c:
        ok = c.execute("SELECT 1 FROM integrations WHERE user_id=? AND provider='gmail'", (user["id"],)).fetchone()
    return {"configured": gmail_ready(), "connected": bool(ok), "capability": "MCAS creates Gmail drafts only. It does not read, search, list or monitor incoming emails, and exposes no send endpoint. Google’s gmail.compose scope technically permits sending at API level, but MCAS does not implement or invoke any send operation."}

@app.get("/api/integrations/gmail/start")
def gmail_start(user=Depends(current_user)):
    if not gmail_ready():
        raise HTTPException(503, "Gmail OAuth is not configured on this server")
    state = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("DELETE FROM oauth_states WHERE expires_at<?", (int(time.time()),))
        c.execute("INSERT INTO oauth_states VALUES(?,?,?)", (token_hash(state), user["id"], int(time.time()) + 600))
    params = urllib.parse.urlencode({
        "client_id": os.getenv("GMAIL_CLIENT_ID"), "redirect_uri": os.getenv("GMAIL_REDIRECT_URI"),
        "response_type": "code", "scope": "https://www.googleapis.com/auth/gmail.compose",
        "access_type": "offline", "prompt": "consent", "state": state
    })
    return RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?" + params, status_code=302)

@app.get("/api/integrations/gmail/callback")
def gmail_callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse("/?gmail=cancelled", status_code=303)
    if not code or not state:
        raise HTTPException(400, "OAuth response is incomplete")
    with db() as c:
        row = c.execute("SELECT * FROM oauth_states WHERE state_hash=? AND expires_at>?",
                        (token_hash(state), int(time.time()))).fetchone()
        c.execute("DELETE FROM oauth_states WHERE state_hash=?", (token_hash(state),))
    if not row:
        raise HTTPException(400, "OAuth state is invalid or expired")
    form = urllib.parse.urlencode({
        "code": code, "client_id": os.getenv("GMAIL_CLIENT_ID"),
        "client_secret": os.getenv("GMAIL_CLIENT_SECRET"), "redirect_uri": os.getenv("GMAIL_REDIRECT_URI"),
        "grant_type": "authorization_code"
    }).encode()
    req = urllib.request.Request("https://oauth2.googleapis.com/token", data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            token_data = json.loads(r.read(100000))
        refresh = token_data.get("refresh_token")
        if not refresh:
            raise ValueError("Google did not return a refresh token; reconnect with consent.")
        encrypted = fernet().encrypt(refresh.encode()).decode()
    except Exception:
        raise HTTPException(502, "Could not complete Google OAuth. Check the OAuth client and redirect URI.")
    with db() as c:
        c.execute("""INSERT INTO integrations(user_id,provider,encrypted_refresh_token,connected_at)
            VALUES(?,'gmail',?,?) ON CONFLICT(user_id,provider) DO UPDATE SET
            encrypted_refresh_token=excluded.encrypted_refresh_token,connected_at=excluded.connected_at""",
            (row["user_id"], encrypted, now()))
        audit(c, row["user_id"], "gmail.connected")
    return RedirectResponse("/?gmail=connected", status_code=303)

@app.delete("/api/integrations/gmail")
def gmail_disconnect(user=Depends(current_user)):
    with db() as c:
        c.execute("DELETE FROM integrations WHERE user_id=? AND provider='gmail'", (user["id"],))
        audit(c, user["id"], "gmail.disconnected")
    return {"ok": True}

def gmail_access_token(uid):
    with db() as c:
        row = c.execute("SELECT encrypted_refresh_token FROM integrations WHERE user_id=? AND provider='gmail'", (uid,)).fetchone()
    if not row:
        raise HTTPException(409, "Connect Gmail first")
    try:
        refresh = fernet().decrypt(row["encrypted_refresh_token"].encode()).decode()
    except Exception:
        raise HTTPException(500, "Stored Gmail credential could not be decrypted; reconnect Gmail")
    data = urllib.parse.urlencode({
        "client_id": os.getenv("GMAIL_CLIENT_ID"), "client_secret": os.getenv("GMAIL_CLIENT_SECRET"),
        "refresh_token": refresh, "grant_type": "refresh_token"
    }).encode()
    req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read(100000))["access_token"]
    except Exception:
        raise HTTPException(502, "Could not refresh Gmail access")

def create_gmail_draft_for_user(draft_id: str, uid: str):
    with db() as c:
        draft = c.execute("SELECT * FROM drafts WHERE id=? AND user_id=?", (draft_id, uid)).fetchone()
        if not draft:
            raise HTTPException(404, "Draft not found")
        if not draft["to_email"]:
            raise HTTPException(422, "Add a recipient email before creating the Gmail draft")
        if draft["lead_id"]:
            lead = c.execute("SELECT do_not_contact FROM leads WHERE id=? AND user_id=?",
                             (draft["lead_id"], uid)).fetchone()
            if lead and lead["do_not_contact"]:
                raise HTTPException(403, "This prospect is marked do-not-contact")
    validate_email(draft["to_email"])
    if "\r" in draft["subject"] or "\n" in draft["subject"]:
        raise HTTPException(422, "Email subject must be a single line")
    message = EmailMessage()
    message["To"] = draft["to_email"]
    message["Subject"] = draft["subject"]
    message.set_content(draft["body"])
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode().rstrip("=")
    token = gmail_access_token(uid)
    req = urllib.request.Request("https://gmail.googleapis.com/gmail/v1/users/me/drafts",
        data=json.dumps({"message": {"raw": raw}}).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            response = json.loads(r.read(100000))
    except Exception:
        raise HTTPException(502, "Gmail could not create the draft; no message was sent")
    with db() as c:
        audit(c, uid, "gmail.draft_created", {"draft_id": draft_id})
    return {"ok": True, "gmail_draft_id": response.get("id"),
            "message": "Created a draft in Gmail. It has not been sent."}

@app.post("/api/drafts/{draft_id}/gmail")
def create_gmail_draft(draft_id: str, user=Depends(current_user)):
    return create_gmail_draft_for_user(draft_id, user["id"])

@app.get("/api/metrics")
def metrics(user=Depends(current_user)):
    with db() as c:
        total = c.execute("SELECT COUNT(*) n FROM leads WHERE user_id=?", (user["id"],)).fetchone()["n"]
        verified = c.execute("SELECT COUNT(*) n FROM leads WHERE user_id=? AND status='Verified'", (user["id"],)).fetchone()["n"]
        drafts = c.execute("SELECT COUNT(*) n FROM drafts WHERE user_id=?", (user["id"],)).fetchone()["n"]
        pending = c.execute("SELECT COUNT(*) n FROM drafts WHERE user_id=? AND state='pending_approval'", (user["id"],)).fetchone()["n"]
        followups = c.execute("SELECT COUNT(*) n FROM followups WHERE user_id=? AND state='open'", (user["id"],)).fetchone()["n"]
        dnc = c.execute("SELECT COUNT(*) n FROM leads WHERE user_id=? AND do_not_contact=1", (user["id"],)).fetchone()["n"]
    return {"leads": total, "verified": verified, "drafts": drafts,
            "pending_approval": pending, "open_followups": followups, "do_not_contact": dnc, "sent": 0}

@app.get("/api/billing/status")
def billing_status(user=Depends(current_user)):
    return {"plan": "beta", "billing_enabled": False,
            "message": "Subscription checkout is not enabled in this build. Do not accept customer payments until a payment provider and webhook verification are configured."}
