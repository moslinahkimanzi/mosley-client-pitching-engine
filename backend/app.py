"""MCAS API foundation: account isolation, leads, drafts, safe website checks and optional search."""
from __future__ import annotations
import hashlib, hmac, json, os, re, secrets, socket, sqlite3, time, urllib.error, urllib.parse, urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl

BASE = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("MCAS_DATABASE_PATH", str(BASE / "data" / "mcas.db")))
SECRET = os.getenv("MCAS_SECRET_KEY", "development-only-change-this-secret")
COOKIE = "mcas_session"
SESSION_SECONDS = 60 * 60 * 24 * 14
if len(SECRET) < 32 and os.getenv("MCAS_ENV") == "production":
    raise RuntimeError("MCAS_SECRET_KEY must be at least 32 characters in production")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="MCAS API", version="0.2.0", description="Mosley Client Acquisition System API")
origins = [x.strip() for x in os.getenv("MCAS_ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET","POST","PATCH","DELETE"], allow_headers=["Content-Type"])

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS leads(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,website TEXT,market TEXT,evidence TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'Unverified',score INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS drafts(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,lead_id TEXT,kind TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending_approval',created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,action TEXT NOT NULL,created_at TEXT NOT NULL,metadata TEXT NOT NULL DEFAULT '{}');
        CREATE INDEX IF NOT EXISTS idx_leads_user ON leads(user_id,updated_at);
        CREATE INDEX IF NOT EXISTS idx_drafts_user ON drafts(user_id,created_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        """)

init_db()

def now(): return datetime.now(timezone.utc).isoformat()
def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + salt.hex() + "$" + digest.hex()
def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt, digest = encoded.split("$")
        if scheme != "pbkdf2_sha256": return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, digest)
    except Exception: return False
def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()
def audit(c, uid, action, metadata=None):
    c.execute("INSERT INTO audit_log(user_id,action,created_at,metadata) VALUES(?,?,?,?)",(uid,action,now(),json.dumps(metadata or {})))

class RegisterIn(BaseModel):
    email: str = Field(min_length=5,max_length=254)
    password: str = Field(min_length=12,max_length=200)
class LoginIn(BaseModel):
    email: str
    password: str
class LeadIn(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    website: str | None = Field(default=None,max_length=2048)
    market: str = Field(default="Kenya",max_length=100)
    evidence: str = Field(default="",max_length=5000)
    status: str = Field(default="Unverified",max_length=40)
class DraftIn(BaseModel):
    lead_id: str | None = None
    kind: str = Field(default="Cold email",max_length=40)
    subject: str = Field(max_length=200)
    body: str = Field(min_length=1,max_length=12000)

def current_user(request: Request):
    token = request.cookies.get(COOKIE)
    if not token: raise HTTPException(401,"Sign in required")
    with db() as c:
        row = c.execute("SELECT users.id,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?",(token_hash(token),int(time.time()))).fetchone()
    if not row: raise HTTPException(401,"Session expired")
    return dict(row)

@app.get("/api/health")
def health():
    return {"status":"ok","service":"MCAS API","version":"0.2.0","time":now()}

@app.post("/api/auth/register",status_code=201)
def register(payload:RegisterIn,response:Response):
    email=payload.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email): raise HTTPException(422,"Enter a valid email address")
    if len(set(payload.password)) < 5: raise HTTPException(422,"Choose a stronger password")
    uid=secrets.token_urlsafe(18); token=secrets.token_urlsafe(36)
    try:
        with db() as c:
            c.execute("INSERT INTO users VALUES(?,?,?,?)",(uid,email,password_hash(payload.password),now()))
            c.execute("INSERT INTO sessions VALUES(?,?,?)",(token_hash(token),uid,int(time.time())+SESSION_SECONDS))
            audit(c,uid,"account.created")
    except sqlite3.IntegrityError: raise HTTPException(409,"An account with this email already exists")
    response.set_cookie(COOKIE,token,max_age=SESSION_SECONDS,httponly=True,secure=os.getenv("MCAS_COOKIE_SECURE","false").lower()=="true",samesite="lax",path="/")
    return {"id":uid,"email":email}
@app.post("/api/auth/login")
def login(payload:LoginIn,response:Response):
    with db() as c:
        row=c.execute("SELECT * FROM users WHERE email=?",(payload.email.strip().lower(),)).fetchone()
        if not row or not verify_password(payload.password,row["password_hash"]): raise HTTPException(401,"Email or password is incorrect")
        token=secrets.token_urlsafe(36)
        c.execute("INSERT INTO sessions VALUES(?,?,?)",(token_hash(token),row["id"],int(time.time())+SESSION_SECONDS))
        audit(c,row["id"],"account.login")
    response.set_cookie(COOKIE,token,max_age=SESSION_SECONDS,httponly=True,secure=os.getenv("MCAS_COOKIE_SECURE","false").lower()=="true",samesite="lax",path="/")
    return {"id":row["id"],"email":row["email"]}
@app.post("/api/auth/logout")
def logout(request:Request,response:Response):
    token=request.cookies.get(COOKIE)
    if token:
        with db() as c: c.execute("DELETE FROM sessions WHERE token_hash=?",(token_hash(token),))
    response.delete_cookie(COOKIE,path="/")
    return {"ok":True}
@app.get("/api/auth/me")
def me(user=Depends(current_user)): return user

@app.get("/api/leads")
def list_leads(user=Depends(current_user)):
    with db() as c: rows=c.execute("SELECT * FROM leads WHERE user_id=? ORDER BY updated_at DESC",(user["id"],)).fetchall()
    return [dict(x) for x in rows]
@app.post("/api/leads",status_code=201)
def add_lead(payload:LeadIn,user=Depends(current_user)):
    lid=secrets.token_urlsafe(15); stamp=now()
    with db() as c:
        c.execute("INSERT INTO leads(id,user_id,name,website,market,evidence,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(lid,user["id"],payload.name.strip(),payload.website,payload.market,payload.evidence,payload.status,stamp,stamp))
        audit(c,user["id"],"lead.created",{"lead_id":lid})
    return {"id":lid,"name":payload.name,"status":payload.status}
@app.patch("/api/leads/{lead_id}")
def update_lead(lead_id:str,payload:LeadIn,user=Depends(current_user)):
    with db() as c:
        cur=c.execute("UPDATE leads SET name=?,website=?,market=?,evidence=?,status=?,updated_at=? WHERE id=? AND user_id=?",(payload.name,payload.website,payload.market,payload.evidence,payload.status,now(),lead_id,user["id"]))
        if not cur.rowcount: raise HTTPException(404,"Lead not found")
        audit(c,user["id"],"lead.updated",{"lead_id":lead_id})
    return {"ok":True}
@app.delete("/api/leads/{lead_id}")
def delete_lead(lead_id:str,user=Depends(current_user)):
    with db() as c:
        cur=c.execute("DELETE FROM leads WHERE id=? AND user_id=?",(lead_id,user["id"]))
        if not cur.rowcount: raise HTTPException(404,"Lead not found")
        audit(c,user["id"],"lead.deleted",{"lead_id":lead_id})
    return {"ok":True}

@app.get("/api/drafts")
def list_drafts(user=Depends(current_user)):
    with db() as c: rows=c.execute("SELECT * FROM drafts WHERE user_id=? ORDER BY created_at DESC",(user["id"],)).fetchall()
    return [dict(x) for x in rows]
@app.post("/api/drafts",status_code=201)
def save_draft(payload:DraftIn,user=Depends(current_user)):
    did=secrets.token_urlsafe(15)
    with db() as c:
        if payload.lead_id and not c.execute("SELECT 1 FROM leads WHERE id=? AND user_id=?",(payload.lead_id,user["id"])).fetchone(): raise HTTPException(404,"Lead not found")
        c.execute("INSERT INTO drafts VALUES(?,?,?,?,?,?,?,?)",(did,user["id"],payload.lead_id,payload.kind,payload.subject,payload.body,"pending_approval",now()))
        audit(c,user["id"],"draft.saved",{"draft_id":did,"kind":payload.kind})
    return {"id":did,"state":"pending_approval"}

def public_ip(host: str):
    try: addresses=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    except socket.gaierror: raise HTTPException(422,"Website host could not be resolved")
    ips={x[4][0].split("%")[0] for x in addresses}
    for ip in ips:
        import ipaddress
        parsed=ipaddress.ip_address(ip)
        if not parsed.is_global: raise HTTPException(400,"Private or non-public network targets are blocked")
    return ips

@app.post("/api/audit-website")
def audit_website(payload:dict,user=Depends(current_user)):
    raw=str(payload.get("url",""))[:2048]
    parsed=urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http","https") or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(422,"Provide a valid public http or https URL")
    public_ip(parsed.hostname)
    req=urllib.request.Request(raw,headers={"User-Agent":"MCAS-SiteCheck/0.2 (+manual prospect research)"},method="GET")
    opener=urllib.request.build_opener(urllib.request.HTTPHandler(),urllib.request.HTTPSHandler())
    try:
        with opener.open(req,timeout=8) as res:
            body=res.read(512000).decode("utf-8","replace")
            headers=dict(res.headers)
            status=res.status
    except urllib.error.HTTPError as e:
        status=e.code; body=""
        headers=dict(e.headers)
    except Exception as e: raise HTTPException(502,"Website could not be checked safely")
    title=re.search(r"<title[^>]*>(.*?)</title>",body,re.I|re.S)
    viewport=bool(re.search(r'<meta[^>]+name=["\']viewport',body,re.I))
    return {"url":raw,"checked_at":now(),"http_status":status,"title":re.sub(r"\s+"," ",title.group(1)).strip()[:180] if title else None,"has_viewport_meta":viewport,"content_type":headers.get("Content-Type"),"note":"A lightweight technical check only; not a full accessibility, SEO, security or conversion audit."}

@app.get("/api/research/search")
def research_search(q:str=Field(min_length=2,max_length=160),user=Depends(current_user)):
    key=os.getenv("BRAVE_SEARCH_API_KEY")
    if not key: raise HTTPException(503,"Live search is not configured. Add BRAVE_SEARCH_API_KEY on the server.")
    query=urllib.parse.urlencode({"q":q,"count":10})
    req=urllib.request.Request("https://api.search.brave.com/res/v1/web/search?"+query,headers={"Accept":"application/json","X-Subscription-Token":key,"User-Agent":"MCAS/0.2"})
    try:
        with urllib.request.urlopen(req,timeout=12) as r: data=json.loads(r.read(1_500_000))
    except Exception: raise HTTPException(502,"Search provider request failed")
    results=data.get("web",{}).get("results",[])
    return {"query":q,"results":[{"title":x.get("title"),"url":x.get("url"),"description":x.get("description")} for x in results[:10]],"provider":"Brave Search","warning":"Search results are discovery leads, not verified facts. Check each source before outreach."}

@app.get("/api/metrics")
def metrics(user=Depends(current_user)):
    with db() as c:
        leads=c.execute("SELECT COUNT(*) n FROM leads WHERE user_id=?",(user["id"],)).fetchone()["n"]
        drafts=c.execute("SELECT COUNT(*) n FROM drafts WHERE user_id=?",(user["id"],)).fetchone()["n"]
        pending=c.execute("SELECT COUNT(*) n FROM drafts WHERE user_id=? AND state='pending_approval'",(user["id"],)).fetchone()["n"]
    return {"leads":leads,"drafts":drafts,"pending_approval":pending,"sent":0}
