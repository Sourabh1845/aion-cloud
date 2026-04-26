from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import psycopg2
import os
import secrets
from datetime import datetime, timezone

load_dotenv()

app = FastAPI(
    title="AION Cloud",
    version="1.0.0",
    description="Managed AION Protocol"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")

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
    conn.commit()
    cur.close()
    conn.close()
    print("DB initialized")

init_db()

class RegisterRequest(BaseModel):
    email: str

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

@app.get("/me")
def get_me(api_key: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT email, plan, calls_used, calls_limit, created_at FROM cloud_users WHERE api_key=%s",
        (api_key,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return {
        "email": user[0],
        "plan": user[1],
        "calls_used": user[2],
        "calls_limit": user[3],
        "created_at": str(user[4])
    }

@app.get("/health")
def health():
    return {"status": "AION Cloud is running", "version": "1.0.0"}