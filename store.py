"""Pesticide Shop Calculator — license store (V3).

Storage backends (chosen at runtime):
  * PostgreSQL when DATABASE_URL is set (Render free Postgres in production).
  * SQLite file otherwise (local dev / last-resort fallback; back it up via
    GET /v1/export — Render's free disk is ephemeral).

Schema is deliberately extensible for the NEXT phase (shopkeeper accounts +
cloud sync — NOT built in V3):
  * license_keys has a nullable user_id column (a key can later belong to a
    shopkeeper account instead of only an install_id).
  * a users table already exists — with the exact signup fields the next
    phase needs (full_name, phone, post_office/address, email/Gmail) — unused
    by V3 endpoints, reserved for the accounts phase.
  * the next phase will add per-account data tables (bills, stock, ledger
    rows keyed by user_id) so a shopkeeper who logs back in after a device
    crash restores everything — data must never be lost. Those tables are
    NOT created here; the pattern to follow is the same as license_keys
    (user_id column + created_at).
  * API routes are versioned under /v1/ so /v2/ can add users/sync later
    without breaking V3 clients.
"""
import os
import re
import sqlite3
import threading


def _norm_key(raw):
    """Canonical key form: uppercase alphanumerics only (no dashes/spaces).
    Keys are DISPLAYED dashed (XXXXX-XXXXX-...) but STORED and LOOKED UP
    normalized — so activate() (which strips dashes) matches what
    register-key stored."""
    return re.sub(r"[^A-Z0-9]", "", str(raw or "").upper())

SCHEMA_KEYS = """
CREATE TABLE IF NOT EXISTS license_keys (
    key_id      TEXT PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    install_id  TEXT,
    user_id     TEXT,
    created_at  TEXT NOT NULL,
    activated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_license_key ON license_keys(license_key);
"""

SCHEMA_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    full_name   TEXT,
    phone       TEXT,
    post_office TEXT,
    email       TEXT,
    created_at  TEXT NOT NULL
);
"""


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


class SQLiteStore:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA_KEYS + SCHEMA_USERS)
            self._conn.commit()
        self.backend = "sqlite"

    def create_key(self, key_id, license_key, install_id):
        with self._lock:
            self._conn.execute(
                "INSERT INTO license_keys (key_id, license_key, install_id, user_id, created_at, activated_at)"
                " VALUES (?, ?, ?, NULL, ?, NULL)",
                (key_id, _norm_key(license_key), install_id, _now_iso()))
            self._conn.commit()

    def get_key(self, license_key):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM license_keys WHERE license_key = ?",
                (_norm_key(license_key),)).fetchone()
        return dict(row) if row else None

    def bind_key(self, key_id, install_id):
        with self._lock:
            self._conn.execute(
                "UPDATE license_keys SET install_id = ?, activated_at = ? WHERE key_id = ?",
                (install_id, _now_iso(), key_id))
            self._conn.commit()

    def list_keys(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM license_keys ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def export_all(self):
        with self._lock:
            keys = [dict(r) for r in self._conn.execute(
                "SELECT * FROM license_keys ORDER BY created_at").fetchall()]
            users = [dict(r) for r in self._conn.execute(
                "SELECT * FROM users ORDER BY created_at").fetchall()]
        return {"keys": keys, "users": users}


class PostgresStore:
    def __init__(self, dsn):
        import psycopg2
        import psycopg2.extras
        self._psycopg2 = psycopg2
        self._extras = psycopg2.extras
        self._dsn = dsn
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_KEYS)
                cur.execute(SCHEMA_USERS)
            conn.commit()
        finally:
            conn.close()
        self.backend = "postgres"

    def _connect(self):
        conn = self._psycopg2.connect(self._dsn)
        conn.autocommit = False
        return conn

    def create_key(self, key_id, license_key, install_id):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO license_keys (key_id, license_key, install_id, user_id, created_at, activated_at)"
                    " VALUES (%s, %s, %s, NULL, %s, NULL)",
                    (key_id, _norm_key(license_key), install_id, _now_iso()))
            conn.commit()
        finally:
            conn.close()

    def get_key(self, license_key):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM license_keys WHERE license_key = %s",
                            (_norm_key(license_key),))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def bind_key(self, key_id, install_id):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE license_keys SET install_id = %s, activated_at = %s WHERE key_id = %s",
                    (install_id, _now_iso(), key_id))
            conn.commit()
        finally:
            conn.close()

    def list_keys(self):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM license_keys ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def export_all(self):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM license_keys ORDER BY created_at")
                keys = [dict(r) for r in cur.fetchall()]
                cur.execute("SELECT * FROM users ORDER BY created_at")
                users = [dict(r) for r in cur.fetchall()]
            return {"keys": keys, "users": users}
        finally:
            conn.close()


def get_store():
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        return PostgresStore(dsn)
    path = os.environ.get("LICENSE_DB_PATH", "data/license.db")
    return SQLiteStore(path)
