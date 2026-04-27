from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import psycopg2
import os
import secrets
import uuid
import re
from datetime import datetime, timezone, timedelta

load_dotenv()

app = FastAPI(
    title="AION Cloud",
    version="1.0.0",
    description="Managed Authorization for AI Agents"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")
TTL_SECONDS = 300
SCOPE_REGEX = re.compile(r'^[a-zA-Z0-9._\-]+$')

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cloud_users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            plan TEXT DEFAULT 'free',
            calls_used INTEGER DEFAULT 0,
            calls_limit INTEGER DEFAULT 1000,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cloud_tokens (
            jti TEXT PRIMARY KEY,
            user_id INTEGER REFERENCES cloud_users(id),
            scope TEXT NOT NULL,
            issuer TEXT,
            issued_at TIMESTAMPTZ DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            consumed BOOLEAN DEFAULT FALSE,
            revoked BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("AION Cloud DB initialized")

init_db()

def get_user(api_key: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, email, plan, calls_used, calls_limit FROM cloud_users WHERE api_key=%s", (api_key,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

def increment_calls(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE cloud_users SET calls_used = calls_used + 1 WHERE id=%s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

class RegisterRequest(BaseModel):
    email: str

class IssueRequest(BaseModel):
    scope: str
    issuer: str = "aion-cloud-agent"

class EnforceRequest(BaseModel):
    jti: str
    scope: str

@app.post("/register")
def register(req: RegisterRequest):
    api_key = "aion-" + secrets.token_urlsafe(32)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO cloud_users (email, api_key) VALUES (%s, %s) RETURNING id, email, api_key, plan, calls_limit",
            (req.email, api_key)
        )
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return {
            "message": "Registration successful",
            "email": user[1],
            "api_key": user[2],
            "plan": user[3],
            "calls_limit": user[4]
        }
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=400, detail="Email already registered")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/issue")
def issue_token(req: IssueRequest, x_aion_api_key: str = Header(None)):
    if not x_aion_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = get_user(x_aion_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    user_id, email, plan, calls_used, calls_limit = user
    if calls_used >= calls_limit:
        raise HTTPException(status_code=429, detail="Monthly limit reached. Upgrade to Pro.")

    if not req.scope or len(req.scope) > 100:
        raise HTTPException(status_code=400, detail="Invalid scope")
    if not SCOPE_REGEX.match(req.scope):
        raise HTTPException(status_code=400, detail="Scope contains invalid characters")

    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    expires_at = now + timedelta(seconds=TTL_SECONDS)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cloud_tokens (jti, user_id, scope, issuer, issued_at, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (jti, user_id, req.scope, req.issuer, now, expires_at))
    conn.commit()
    cur.close()
    conn.close()

    increment_calls(user_id)

    return {
        "jti": jti,
        "scope": req.scope,
        "issuer": req.issuer,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "consumed": False,
        "revoked": False,
        "plan": plan,
        "calls_remaining": calls_limit - calls_used - 1
    }

@app.post("/enforce")
def enforce_token(req: EnforceRequest, x_aion_api_key: str = Header(None)):
    if not x_aion_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = get_user(x_aion_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cloud_tokens WHERE jti=%s", (req.jti,))
    token = cur.fetchone()

    if not token:
        cur.close()
        conn.close()
        return {"error": "NOT_FOUND"}

    jti, user_id, scope, issuer, issued_at, expires_at, consumed, revoked = token

    if revoked:
        cur.close()
        conn.close()
        return {"error": "ENFORCEMENT_DENIED", "reason": "REVOKED"}

    if consumed:
        cur.close()
        conn.close()
        return {"error": "ENFORCEMENT_DENIED", "reason": "CONSUMED"}

    if scope != req.scope:
        cur.close()
        conn.close()
        return {"error": "ENFORCEMENT_DENIED", "reason": "SCOPE_MISMATCH"}

    if expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        cur.close()
        conn.close()
        return {"error": "ENFORCEMENT_DENIED", "reason": "EXPIRED"}

    cur.execute("UPDATE cloud_tokens SET consumed=TRUE WHERE jti=%s", (req.jti,))
    conn.commit()
    cur.close()
    conn.close()

    return {"status": "ENFORCED", "jti": req.jti, "scope": req.scope}

@app.post("/revoke/{jti}")
def revoke_token(jti: str, x_aion_api_key: str = Header(None)):
    if not x_aion_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = get_user(x_aion_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE cloud_tokens SET revoked=TRUE WHERE jti=%s", (jti,))
    conn.commit()
    cur.close()
    conn.close()

    return {"status": "REVOKED", "jti": jti}

@app.get("/me")
def get_me(x_aion_api_key: str = Header(None)):
    if not x_aion_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = get_user(x_aion_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    user_id, email, plan, calls_used, calls_limit = user
    return {
        "email": email,
        "plan": plan,
        "calls_used": calls_used,
        "calls_remaining": calls_limit - calls_used,
        "calls_limit": calls_limit
    }

@app.get("/health")
def health():
    return {"status": "AION Cloud is running", "version": "1.0.0"}