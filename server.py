"""
server.py  —  FastAPI backend for the Incident Reporting App
============================================================
A "zero-knowledge" server. It stores ONLY:
  - each user's PUBLIC key and an Argon2 PASSWORD HASH (never the password),
  - group keys already SEALED to each member (it cannot open them),
  - chat messages and incident reports as CIPHERTEXT.
It never sees a private key, a group key, or any plaintext.

Run it locally:
    pip install -r requirements.txt
    uvicorn server:app --reload
Then open http://127.0.0.1:8000/docs to try the endpoints.

Storage: a single SQLite file (incident.db) — free to host 24/7.
"""

import os
import secrets
import sqlite3
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

DB_PATH = os.environ.get("DB_PATH", "incident.db")
MAX_MEMBERS = 50
ph = PasswordHasher()  # Argon2id — winner of the Password Hashing Competition


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token    TEXT PRIMARY KEY,
            username TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS groups (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            key_version INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS group_members (
            group_id          TEXT NOT NULL,
            username          TEXT NOT NULL,
            wrapped_group_key TEXT NOT NULL,
            key_version       INTEGER NOT NULL,
            PRIMARY KEY (group_id, username, key_version)
        );
        CREATE TABLE IF NOT EXISTS items (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id         TEXT NOT NULL,
            kind             TEXT NOT NULL,     -- 'chat' or 'incident'
            sender           TEXT NOT NULL,
            key_version      INTEGER NOT NULL,
            nonce            TEXT NOT NULL,
            ciphertext       TEXT NOT NULL,     -- encrypted text or incident JSON
            media_nonce      TEXT,
            media_ciphertext TEXT,
            media_name       TEXT,
            created_at       TEXT NOT NULL,
            updated_at       TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


app = FastAPI(title="Incident Reporting API (end-to-end encrypted)")


@app.on_event("startup")
def _startup():
    init_db()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user(authorization):
    """Turn an 'Authorization: Bearer <token>' header into a username."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1]
    conn = get_conn()
    row = conn.execute("SELECT username FROM sessions WHERE token=?", (token,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "invalid or expired token")
    return row["username"]


def require_member(group_id, username):
    conn = get_conn()
    row = conn.execute(
        "SELECT 1 FROM group_members WHERE group_id=? AND username=?",
        (group_id, username),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(403, "you are not a member of this group")


# ---------------------------------------------------------------------------
# Request bodies (never any plaintext or secret)
# ---------------------------------------------------------------------------
class RegisterIn(BaseModel):
    username: str
    password: str
    public_key: str


class LoginIn(BaseModel):
    username: str
    password: str


class GroupIn(BaseModel):
    id: str
    name: str


class MemberIn(BaseModel):
    username: str
    wrapped_group_key: str
    key_version: int = 1


class ItemIn(BaseModel):
    kind: str                       # 'chat' or 'incident'
    key_version: int
    nonce: str
    ciphertext: str
    media_nonce: str | None = None
    media_ciphertext: str | None = None
    media_name: str | None = None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post("/register")
def register(body: RegisterIn):
    """Create an account. Stores an Argon2 hash + public key — never the password."""
    conn = get_conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
        conn.close()
        raise HTTPException(400, "username already taken")
    conn.execute(
        "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
        (body.username, ph.hash(body.password), body.public_key),
    )
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions (token, username) VALUES (?, ?)",
                 (token, body.username))
    conn.commit()
    conn.close()
    return {"token": token, "username": body.username}


@app.post("/login")
def login(body: LoginIn):
    conn = get_conn()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username=?", (body.username,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(401, "wrong username or password")
    try:
        ph.verify(row["password_hash"], body.password)
    except VerifyMismatchError:
        conn.close()
        raise HTTPException(401, "wrong username or password")
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions (token, username) VALUES (?, ?)",
                 (token, body.username))
    conn.commit()
    conn.close()
    return {"token": token, "username": body.username}


@app.get("/users/{username}/public_key")
def get_public_key(username: str, authorization: str | None = Header(default=None)):
    current_user(authorization)
    conn = get_conn()
    row = conn.execute(
        "SELECT public_key FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "user not found")
    return {"username": username, "public_key": row["public_key"]}


# ---------------------------------------------------------------------------
# Groups & members
# ---------------------------------------------------------------------------
@app.post("/groups")
def create_group(group: GroupIn, authorization: str | None = Header(default=None)):
    current_user(authorization)
    conn = get_conn()
    conn.execute("INSERT OR IGNORE INTO groups (id, name) VALUES (?, ?)",
                 (group.id, group.name))
    conn.commit()
    conn.close()
    return {"ok": True, "group_id": group.id}


@app.get("/groups")
def my_groups(authorization: str | None = Header(default=None)):
    """List the groups the logged-in user belongs to."""
    user = current_user(authorization)
    conn = get_conn()
    rows = conn.execute(
        "SELECT g.id, g.name, "
        "(SELECT COUNT(DISTINCT username) FROM group_members WHERE group_id=g.id) AS members "
        "FROM groups g JOIN group_members m ON m.group_id=g.id "
        "WHERE m.username=? ORDER BY g.name",
        (user,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/groups/{group_id}/members")
def add_member(group_id: str, member: MemberIn,
               authorization: str | None = Header(default=None)):
    current_user(authorization)
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "group not found")
    count = conn.execute(
        "SELECT COUNT(DISTINCT username) AS n FROM group_members WHERE group_id=?",
        (group_id,),
    ).fetchone()["n"]
    already = conn.execute(
        "SELECT 1 FROM group_members WHERE group_id=? AND username=?",
        (group_id, member.username),
    ).fetchone()
    if not already and count >= MAX_MEMBERS:
        conn.close()
        raise HTTPException(400, f"group is full (max {MAX_MEMBERS} members)")
    conn.execute(
        "INSERT OR REPLACE INTO group_members "
        "(group_id, username, wrapped_group_key, key_version) VALUES (?, ?, ?, ?)",
        (group_id, member.username, member.wrapped_group_key, member.key_version),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/groups/{group_id}/my-key")
def get_my_wrapped_key(group_id: str, authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    conn = get_conn()
    row = conn.execute(
        "SELECT wrapped_group_key, key_version FROM group_members "
        "WHERE group_id=? AND username=? ORDER BY key_version DESC LIMIT 1",
        (group_id, user),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "no key for you in this group")
    return {"wrapped_group_key": row["wrapped_group_key"],
            "key_version": row["key_version"]}


# ---------------------------------------------------------------------------
# Items: chat messages AND incident reports (ciphertext only)
# ---------------------------------------------------------------------------
@app.post("/groups/{group_id}/items")
def post_item(group_id: str, item: ItemIn,
              authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    require_member(group_id, user)
    if item.kind not in ("chat", "incident"):
        raise HTTPException(400, "kind must be 'chat' or 'incident'")
    ts = now_iso()
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO items (group_id, kind, sender, key_version, nonce, ciphertext, "
        "media_nonce, media_ciphertext, media_name, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (group_id, item.kind, user, item.key_version, item.nonce, item.ciphertext,
         item.media_nonce, item.media_ciphertext, item.media_name, ts, ts),
    )
    conn.commit()
    item_id = cur.lastrowid
    conn.close()
    return {"ok": True, "id": item_id}


@app.get("/groups/{group_id}/items")
def list_items(group_id: str, kind: str | None = None,
               authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    require_member(group_id, user)
    conn = get_conn()
    if kind:
        rows = conn.execute(
            "SELECT * FROM items WHERE group_id=? AND kind=? ORDER BY id",
            (group_id, kind),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM items WHERE group_id=? ORDER BY id", (group_id,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.put("/groups/{group_id}/items/{item_id}")
def update_item(group_id: str, item_id: int, item: ItemIn,
                authorization: str | None = Header(default=None)):
    """Replace an incident's ciphertext (e.g. after adding a timestamped update)."""
    user = current_user(authorization)
    require_member(group_id, user)
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM items WHERE id=? AND group_id=?",
                        (item_id, group_id)).fetchone():
        conn.close()
        raise HTTPException(404, "item not found")
    conn.execute(
        "UPDATE items SET nonce=?, ciphertext=?, media_nonce=?, media_ciphertext=?, "
        "media_name=?, updated_at=? WHERE id=? AND group_id=?",
        (item.nonce, item.ciphertext, item.media_nonce, item.media_ciphertext,
         item.media_name, now_iso(), item_id, group_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/")
def root():
    return {"service": "Incident Reporting API", "encrypted": True, "docs": "/docs"}
