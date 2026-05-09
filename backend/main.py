from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import psycopg2
import psycopg2.errors
import psycopg2.extras
import os
import secrets
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import Any

load_dotenv()

app = FastAPI(
    title="AION Cloud",
    version="1.1.0",
    description="Cloud receipt vault and managed authorization for AI agents",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_KEY = os.environ.get("ADMIN_KEY")
TTL_SECONDS = 300
SCOPE_REGEX = re.compile(r"^[a-zA-Z0-9._\-]+$")


def get_conn():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")
    return psycopg2.connect(DATABASE_URL, sslmode="require")



def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            plan TEXT DEFAULT 'free',
            calls_used INTEGER DEFAULT 0,
            calls_limit INTEGER DEFAULT 10000,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )

    cur.execute(
        """
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
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_receipts (
            id SERIAL PRIMARY KEY,
            receipt_id TEXT UNIQUE NOT NULL,
            user_id INTEGER REFERENCES cloud_users(id),
            agent TEXT,
            scope TEXT,
            decision TEXT,
            risk TEXT,
            reason TEXT,
            status TEXT,
            receipt_hash TEXT,
            metadata JSONB,
            received_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )

    conn.commit()
    cur.close()
    conn.close()
    print("AION Cloud DB initialized")


@app.on_event("startup")
def startup():
    init_db()



def get_user(api_key: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, email, plan, calls_used, calls_limit FROM cloud_users WHERE api_key=%s",
        (api_key,),
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def require_user(api_key: str):
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = get_user(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

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


class ReceiptRequest(BaseModel):
    receipt_id: str = Field(..., max_length=120)
    agent: str = "unknown-agent"
    scope: str
    decision: str
    risk: str
    reason: str = ""
    status: str
    receipt_hash: str = ""
    metadata: dict[str, Any] = {}


@app.post("/register")
def register(req: RegisterRequest):
    api_key = "aion-" + secrets.token_urlsafe(32)

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cloud_users (email, api_key)
            VALUES (%s, %s)
            RETURNING id, email, api_key, plan, calls_limit
            """,
            (req.email, api_key),
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
            "calls_limit": user[4],
        }

    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=400, detail="Email already registered")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue")
def issue_token(req: IssueRequest, x_aion_api_key: str = Header(None)):
    user = require_user(x_aion_api_key)
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
    cur.execute(
        """
        INSERT INTO cloud_tokens (jti, user_id, scope, issuer, issued_at, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (jti, user_id, req.scope, req.issuer, now, expires_at),
    )
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
        "calls_remaining": calls_limit - calls_used - 1,
    }


@app.post("/enforce")
def enforce_token(req: EnforceRequest, x_aion_api_key: str = Header(None)):
    user = require_user(x_aion_api_key)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cloud_tokens WHERE jti=%s", (req.jti,))
    token = cur.fetchone()

    if not token:
        cur.close()
        conn.close()
        return {"error": "NOT_FOUND"}

    jti, user_id, scope, issuer, issued_at, expires_at, consumed, revoked = token

    if user_id != user[0]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Token does not belong to this API key")

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
    user = require_user(x_aion_api_key)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE cloud_tokens SET revoked=TRUE WHERE jti=%s AND user_id=%s",
        (jti, user[0]),
    )
    conn.commit()
    cur.close()
    conn.close()

    return {"status": "REVOKED", "jti": jti}


@app.post("/receipts")
def create_receipt(req: ReceiptRequest, x_aion_api_key: str = Header(None)):
    user = require_user(x_aion_api_key)
    user_id = user[0]

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cloud_receipts (
                receipt_id, user_id, agent, scope, decision, risk,
                reason, status, receipt_hash, metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, received_at
            """,
            (
                req.receipt_id,
                user_id,
                req.agent,
                req.scope,
                req.decision,
                req.risk,
                req.reason,
                req.status,
                req.receipt_hash,
                psycopg2.extras.Json(req.metadata),
            ),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        return {
            "status": "RECEIPT_STORED",
            "id": row[0],
            "receipt_id": req.receipt_id,
            "received_at": row[1].isoformat(),
        }

    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Receipt already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/receipts")
def list_receipts(x_aion_api_key: str = Header(None), limit: int = 50):
    user = require_user(x_aion_api_key)
    limit = max(1, min(limit, 100))

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT receipt_id, agent, scope, decision, risk, status,
               reason, receipt_hash, metadata, received_at
        FROM cloud_receipts
        WHERE user_id=%s
        ORDER BY received_at DESC
        LIMIT %s
        """,
        (user[0], limit),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return {
        "count": len(rows),
        "receipts": [
            {
                "receipt_id": r[0],
                "agent": r[1],
                "scope": r[2],
                "decision": r[3],
                "risk": r[4],
                "status": r[5],
                "reason": r[6],
                "receipt_hash": r[7],
                "metadata": r[8],
                "received_at": r[9].isoformat(),
            }
            for r in rows
        ],
    }


@app.get("/me")
def get_me(x_aion_api_key: str = Header(None)):
    user = require_user(x_aion_api_key)
    user_id, email, plan, calls_used, calls_limit = user

    return {
        "email": email,
        "plan": plan,
        "calls_used": calls_used,
        "calls_remaining": calls_limit - calls_used,
        "calls_limit": calls_limit,
    }


@app.get("/admin/users")
def admin_users(admin_key: str):
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT email, plan, calls_used, calls_limit,
               calls_limit - calls_used as calls_remaining,
               created_at
        FROM cloud_users
        ORDER BY created_at DESC
        """
    )
    users = cur.fetchall()
    cur.close()
    conn.close()

    return {
        "total_users": len(users),
        "users": [
            {
                "email": u[0],
                "plan": u[1],
                "calls_used": u[2],
                "calls_limit": u[3],
                "calls_remaining": u[4],
                "joined": str(u[5]),
            }
            for u in users
        ],
    }


@app.get("/health")
def health():
    return {"status": "AION Cloud is running", "version": "1.1.0"}
