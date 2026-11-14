"""Pesticide Shop Calculator — license store (V3).

Storage backends (chosen at runtime):
  * PostgreSQL when DATABASE_URL is set (Render free Postgres in production).
  * SQLite file otherwise (local dev / last-resort fallback; back it up via
    GET /v1/export — Render's free disk is ephemeral).

Schema is deliberately extensible for the NEXT phase (shopkeeper accounts +
cloud sync — NOT built in V3):
  * psc_license_keys has a nullable user_id column (a key can later belong to a
    shopkeeper account instead of only an install_id).
  * a psc_users table already exists — with the exact signup fields the next
    phase needs (full_name, phone, post_office/address, email/Gmail) — unused
    by V3 endpoints, reserved for the accounts phase.
  * the next phase will add per-account data tables (bills, stock, ledger
    rows keyed by user_id) so a shopkeeper who logs back in after a device
    crash restores everything — data must never be lost. Those tables are
    NOT created here; the pattern to follow is the same as psc_license_keys
    (user_id column + created_at).
  * API routes are versioned under /v1/ so /v2/ can add psc_users/sync later
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


def canon_email(raw):
    """Canonical mailbox form: lowercase + trimmed. For Gmail addresses
    (gmail.com / googlemail.com) dots in the local part are ignored and
    anything after '+' is ignored — a.tikur+shop@gmail.com IS
    atikur@gmail.com. Without this, one Gmail can open many accounts
    (dots / +tags), which is exactly what happened live (Nov 2026)."""
    email = str(raw or "").strip().lower()
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    if domain in ("gmail.com", "googlemail.com"):
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    return local + "@" + domain


def _dedupe_emails(rows):
    """rows: [(id, email)] ordered oldest-first. Returns {id: new_email}
    for rows whose stored email must change: the earliest account per
    mailbox gets the canonical address; later duplicates get a +dup<N>
    variant (never log-in-able — login canonicalizes first — but always
    visible in the admin list, and bannable). Nothing is deleted."""
    used = set()
    claimed = set()
    updates = {}
    for _id, raw in rows:
        canon = canon_email(raw)
        if canon not in claimed:
            claimed.add(canon)
            used.add(canon)
            if raw != canon:
                updates[_id] = canon
        else:
            local, sep, domain = canon.partition("@")
            n = 1
            while True:
                cand = "%s+dup%d%s%s" % (local, n, "@" if sep else "", domain)
                if cand not in used:
                    break
                n += 1
            used.add(cand)
            if raw != cand:
                updates[_id] = cand
    return updates

SCHEMA_KEYS = """
CREATE TABLE IF NOT EXISTS psc_license_keys (
    key_id      TEXT PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    install_id  TEXT,
    user_id     TEXT,
    created_at  TEXT NOT NULL,
    activated_at TEXT,
    plan        TEXT NOT NULL DEFAULT 'lifetime',
    expires_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_psc_license_key ON psc_license_keys(license_key);
"""
# Subscription plans (v3.4.0 server): a key carries a plan + an expiry.
# plan: 'monthly' (30 days) | 'yearly' (365 days) | 'lifetime' (no expiry).
# expires_at is unix seconds, NULL = lifetime. Legacy rows (created before
# these columns existed) get plan 'lifetime' + NULL expiry via migration,
# so they behave exactly as before. Expiry is set at FIRST bind (activate),
# never at key creation — a key bought today but activated next month
# still gets its full term.

SCHEMA_USERS = """
CREATE TABLE IF NOT EXISTS psc_users (
    id          TEXT PRIMARY KEY,
    full_name   TEXT,
    phone       TEXT,
    post_office TEXT,
    email       TEXT,
    password_hash TEXT,
    banned      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
"""

# Email verification codes (v3.3.0): one row per issued code. The code
# itself is NEVER stored — only its SHA-256 hash. `payload` holds the
# pending signup fields (JSON) so the account is created only AFTER the
# code is verified; login/reset rows carry no payload. Rows are deleted
# on use and pruned when expired.
SCHEMA_VERIFICATIONS = """
CREATE TABLE IF NOT EXISTS psc_verifications (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    payload     TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_psc_verif_email ON psc_verifications(email);
"""

# 3-day free trial (v3.1.0): ONE trial per ACCOUNT — user_id is the PRIMARY
# KEY. install_id records which device started it. Starting again never
# extends: the same account always gets its ORIGINAL expiry. A new account
# on a new device is the only way to a fresh trial — that is the known
# limit of a trial without hardware fingerprinting; the paid key (one key
# = one device, server-bound) is what protects revenue.
# NOTE: the first v3.1.0 deploy created this table keyed by install_id;
# both stores migrate it to user_id on startup (see __init__).
SCHEMA_TRIALS = """
CREATE TABLE IF NOT EXISTS psc_trials (
    user_id    TEXT PRIMARY KEY,
    install_id TEXT,
    started_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


# Auto-payment purchases (Atikur Pay gateway): one row per checkout the
# app starts. The row is keyed by `purchase_ref`, generated HERE (the
# license server never calls the gateway — PythonAnywhere free cannot
# reach it). The gateway's public checkout endpoint creates the payment
# and, when it is paid, webhooks /v1/payment-callback with the ref; the
# license key is then issued server-side and the row records its key_id
# + the gateway's payment id, so a repeated callback or status check
# can NEVER issue a second key. `issuing` is a transient claim state:
# the callback flips a pending row to `issuing` (one atomic UPDATE)
# before creating the key, so two concurrent callbacks cannot both
# issue. `failed` is terminal.
SCHEMA_PAYMENTS = """
CREATE TABLE IF NOT EXISTS psc_payments (
    purchase_ref TEXT PRIMARY KEY,
    gateway_payment_id TEXT,
    install_id TEXT NOT NULL,
    plan       TEXT NOT NULL,
    amount     INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    key_id     TEXT,
    created_at TEXT NOT NULL,
    paid_at    TEXT
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
            self._conn.executescript(SCHEMA_KEYS + SCHEMA_USERS + SCHEMA_TRIALS + SCHEMA_VERIFICATIONS + SCHEMA_PAYMENTS)
            self._conn.commit()
            # Migrate pre-fix trials table (PK was install_id) to PK user_id.
            row = self._conn.execute(
                "SELECT name FROM pragma_table_info('psc_trials') WHERE pk = 1").fetchone()
            if row and row[0] == 'install_id':
                self._conn.executescript("""
                    DELETE FROM psc_trials WHERE user_id IS NULL;
                    CREATE TABLE psc_trials_new (
                        user_id TEXT PRIMARY KEY, install_id TEXT,
                        started_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                        created_at TEXT NOT NULL);
                    INSERT INTO psc_trials_new (user_id, install_id, started_at, expires_at, created_at)
                        SELECT user_id, install_id, started_at, expires_at, created_at FROM psc_trials;
                    DROP TABLE psc_trials;
                    ALTER TABLE psc_trials_new RENAME TO psc_trials;
                """)
                self._conn.commit()
            # Migrate psc_license_keys (v3.4.0): plan + expires_at columns.
            # Legacy rows get plan 'lifetime' + NULL expiry = lifetime,
            # exactly their old behavior.
            key_cols = [r[1] for r in self._conn.execute(
                "PRAGMA table_info('psc_license_keys')").fetchall()]
            if 'plan' not in key_cols:
                self._conn.execute(
                    "ALTER TABLE psc_license_keys ADD COLUMN plan TEXT NOT NULL DEFAULT 'lifetime'")
            if 'expires_at' not in key_cols:
                self._conn.execute(
                    "ALTER TABLE psc_license_keys ADD COLUMN expires_at INTEGER")
            self._conn.commit()
            # Migrate psc_payments (webhook redesign): rows are keyed by
            # purchase_ref (generated here) + the gateway's payment id
            # arrives later via the callback. Fresh DBs get both columns
            # from CREATE TABLE; this covers a DB created by the
            # never-deployed direct-call build (payment_id PK schema).
            pay_cols = [r[1] for r in self._conn.execute(
                "PRAGMA table_info('psc_payments')").fetchall()]
            if 'purchase_ref' not in pay_cols:
                self._conn.execute(
                    "ALTER TABLE psc_payments ADD COLUMN purchase_ref TEXT")
            if 'gateway_payment_id' not in pay_cols:
                self._conn.execute(
                    "ALTER TABLE psc_payments ADD COLUMN gateway_payment_id TEXT")
            self._conn.commit()
            # Migrate psc_users: banned column + canonical emails + unique index.
            cols = [r[1] for r in self._conn.execute(
                "PRAGMA table_info('psc_users')").fetchall()]
            if 'banned' not in cols:
                self._conn.execute(
                    "ALTER TABLE psc_users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0")
            if 'password_hash' not in cols:
                self._conn.execute(
                    "ALTER TABLE psc_users ADD COLUMN password_hash TEXT")
            rows = self._conn.execute(
                "SELECT id, email FROM psc_users ORDER BY created_at ASC, id ASC").fetchall()
            for _id, new_email in _dedupe_emails([(r[0], r[1]) for r in rows]).items():
                self._conn.execute(
                    "UPDATE psc_users SET email = ? WHERE id = ?", (new_email, _id))
            self._conn.commit()
            try:
                self._conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_psc_users_email ON psc_users(email)")
                self._conn.commit()
            except Exception as e:
                print("WARNING: could not create unique email index: %s" % e, flush=True)
        self.backend = "sqlite"

    def get_key_by_install_id(self, install_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_license_keys WHERE install_id = ?",
                (install_id,)).fetchone()
        return dict(row) if row else None

    def get_trial_by_user(self, user_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_trials WHERE user_id = ?",
                (user_id,)).fetchone()
        return dict(row) if row else None

    def create_trial(self, install_id, user_id, started_at, expires_at):
        with self._lock:
            self._conn.execute(
                "INSERT INTO psc_trials (install_id, user_id, started_at, expires_at, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (install_id, user_id, started_at, expires_at, _now_iso()))
            self._conn.commit()

    def list_trials(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM psc_trials ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def create_user(self, user_id, full_name, phone, post_office, email, password_hash=None):
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO psc_users (id, full_name, phone, post_office, email, password_hash, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, full_name, phone, post_office, email, password_hash, _now_iso()))
                self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Unique-email race: another signup for this mailbox just landed.
            return False

    def set_password_hash(self, user_id, password_hash):
        with self._lock:
            cur = self._conn.execute(
                "UPDATE psc_users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id))
            self._conn.commit()
            return cur.rowcount > 0

    def create_verification(self, ver_id, email, purpose, code_hash, payload, expires_at):
        with self._lock:
            self._conn.execute(
                "DELETE FROM psc_verifications WHERE expires_at < strftime('%s', 'now')")
            self._conn.execute(
                "INSERT INTO psc_verifications (id, email, purpose, code_hash, payload, attempts, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                (ver_id, email, purpose, code_hash, payload, _now_iso(), expires_at))
            self._conn.commit()

    def get_verification(self, email, purpose):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_verifications WHERE email = ? AND purpose = ?"
                " ORDER BY created_at DESC, id DESC LIMIT 1",
                (email, purpose)).fetchone()
        return dict(row) if row else None

    def delete_verifications(self, email, purpose):
        with self._lock:
            self._conn.execute(
                "DELETE FROM psc_verifications WHERE email = ? AND purpose = ?",
                (email, purpose))
            self._conn.commit()

    def bump_attempts(self, ver_id):
        with self._lock:
            self._conn.execute(
                "UPDATE psc_verifications SET attempts = attempts + 1 WHERE id = ?",
                (ver_id,))
            row = self._conn.execute(
                "SELECT attempts FROM psc_verifications WHERE id = ?", (ver_id,)).fetchone()
            self._conn.commit()
        return int(row[0]) if row else 0

    def count_recent_codes(self, email, since_iso):
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM psc_verifications WHERE email = ? AND created_at >= ?",
                (email, since_iso)).fetchone()
        return int(row[0]) if row else 0

    def get_user_by_email(self, email):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_users WHERE email = ?"
                " ORDER BY created_at ASC, id ASC LIMIT 1",
                (email,)).fetchone()
        return dict(row) if row else None

    def list_users(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM psc_users ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def set_banned(self, user_id, banned):
        with self._lock:
            cur = self._conn.execute(
                "UPDATE psc_users SET banned = ? WHERE id = ?",
                (1 if banned else 0, user_id))
            self._conn.commit()
            return cur.rowcount > 0

    def get_user_by_id(self, user_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_users WHERE id = ?",
                (user_id,)).fetchone()
        return dict(row) if row else None

    def create_key(self, key_id, license_key, install_id, plan='lifetime'):
        with self._lock:
            self._conn.execute(
                "INSERT INTO psc_license_keys (key_id, license_key, install_id, user_id, created_at, activated_at, plan, expires_at)"
                " VALUES (?, ?, ?, NULL, ?, NULL, ?, NULL)",
                (key_id, _norm_key(license_key), install_id, _now_iso(), plan))
            self._conn.commit()

    def get_key(self, license_key):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_license_keys WHERE license_key = ?",
                (_norm_key(license_key),)).fetchone()
        return dict(row) if row else None

    def bind_key(self, key_id, install_id):
        with self._lock:
            self._conn.execute(
                "UPDATE psc_license_keys SET install_id = ?, activated_at = ? WHERE key_id = ?",
                (install_id, _now_iso(), key_id))
            self._conn.commit()

    def set_key_expiry(self, key_id, expires_at):
        """Set the expiry (unix seconds, or None = lifetime) of a key.
        Called once at first bind; re-activating the same key never
        touches it again, so time can never be extended by re-entry."""
        with self._lock:
            self._conn.execute(
                "UPDATE psc_license_keys SET expires_at = ? WHERE key_id = ?",
                (expires_at, key_id))
            self._conn.commit()

    def list_keys_by_install_id(self, install_id):
        """All keys bound to one device (oldest first) — used to stack a
        renewal onto the device's latest expiry and to detect a lifetime
        key, which blocks any further key on that device."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM psc_license_keys WHERE install_id = ?"
                " ORDER BY created_at ASC, key_id ASC",
                (install_id,)).fetchall()
        return [dict(r) for r in rows]

    def list_keys(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM psc_license_keys ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def create_payment(self, purchase_ref, install_id, plan, amount):
        """A checkout the app started: pending until the gateway's
        webhook reports it paid. purchase_ref is generated HERE and is
        the row's key; the gateway's payment id is unknown until the
        callback arrives."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO psc_payments (purchase_ref, gateway_payment_id, install_id, plan, amount, status, key_id, created_at, paid_at)"
                " VALUES (?, NULL, ?, ?, ?, 'pending', NULL, ?, NULL)",
                (purchase_ref, install_id, plan, amount, _now_iso()))
            self._conn.commit()

    def get_payment_by_ref(self, purchase_ref):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_payments WHERE purchase_ref = ?",
                (purchase_ref,)).fetchone()
        return dict(row) if row else None

    def claim_payment(self, purchase_ref):
        """Atomically flip a pending row to `issuing`. Returns True only
        for the ONE caller that won the claim — concurrent callbacks
        for the same purchase can never both issue a key."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE psc_payments SET status = 'issuing'"
                " WHERE purchase_ref = ? AND status = 'pending'",
                (purchase_ref,))
            self._conn.commit()
            return cur.rowcount > 0

    def set_payment_paid(self, purchase_ref, key_id, gateway_payment_id):
        """Mark the purchase paid + record the issued key and the
        gateway's payment id. Called once, right after the key is
        created and bound."""
        with self._lock:
            self._conn.execute(
                "UPDATE psc_payments SET status = 'paid', key_id = ?, gateway_payment_id = ?, paid_at = ?"
                " WHERE purchase_ref = ?",
                (key_id, gateway_payment_id, _now_iso(), purchase_ref))
            self._conn.commit()

    def set_payment_failed(self, purchase_ref):
        """Terminal failure. The shopkeeper must start a fresh purchase."""
        with self._lock:
            self._conn.execute(
                "UPDATE psc_payments SET status = 'failed' WHERE purchase_ref = ?",
                (purchase_ref,))
            self._conn.commit()

    def reset_payment_pending(self, purchase_ref):
        """Release an `issuing` claim (issuance crashed mid-way) so the
        next callback retries instead of stalling forever."""
        with self._lock:
            self._conn.execute(
                "UPDATE psc_payments SET status = 'pending'"
                " WHERE purchase_ref = ? AND status = 'issuing'",
                (purchase_ref,))
            self._conn.commit()

    def get_key_by_id(self, key_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM psc_license_keys WHERE key_id = ?",
                (key_id,)).fetchone()
        return dict(row) if row else None

    def export_all(self):
        with self._lock:
            keys = [dict(r) for r in self._conn.execute(
                "SELECT * FROM psc_license_keys ORDER BY created_at").fetchall()]
            psc_users = [dict(r) for r in self._conn.execute(
                "SELECT * FROM psc_users ORDER BY created_at").fetchall()]
            trials = [dict(r) for r in self._conn.execute(
                "SELECT * FROM psc_trials ORDER BY created_at").fetchall()]
        for u in psc_users:
            u.pop("password_hash", None)  # password hashes never leave the DB
        return {"keys": keys, "psc_users": psc_users, "trials": trials}


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
                cur.execute(SCHEMA_TRIALS)
                cur.execute(SCHEMA_VERIFICATIONS)
                cur.execute(SCHEMA_PAYMENTS)
            conn.commit()
            # Migrate pre-fix trials table (PK was install_id) to PK user_id.
            from psycopg2 import sql as _sql
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT tc.constraint_name FROM information_schema.table_constraints tc "
                    "WHERE tc.table_name = 'psc_trials' AND tc.constraint_type = 'PRIMARY KEY'")
                pkrow = cur.fetchone()
                if pkrow:
                    cur.execute(
                        "SELECT column_name FROM information_schema.key_column_usage "
                        "WHERE table_name = 'psc_trials' AND constraint_name = %s",
                        (pkrow[0],))
                    pk_cols = [r[0] for r in cur.fetchall()]
                    if pk_cols == ['install_id']:
                        cur.execute("DELETE FROM psc_trials WHERE user_id IS NULL")
                        cur.execute(_sql.SQL("ALTER TABLE psc_trials DROP CONSTRAINT {}").format(
                            _sql.Identifier(pkrow[0])))
                        cur.execute("ALTER TABLE psc_trials ADD PRIMARY KEY (user_id)")
            conn.commit()
            # Migrate psc_license_keys (v3.4.0): plan + expires_at columns.
            # Legacy rows get plan 'lifetime' + NULL expiry = lifetime,
            # exactly their old behavior.
            with conn.cursor() as cur:
                cur.execute(
                    "ALTER TABLE psc_license_keys ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'lifetime'")
                cur.execute(
                    "ALTER TABLE psc_license_keys ADD COLUMN IF NOT EXISTS expires_at INTEGER")
            conn.commit()
            # Migrate psc_payments (webhook redesign): rows are keyed by
            # purchase_ref (generated here) + the gateway's payment id
            # arrives later via the callback. Fresh DBs get both columns
            # from CREATE TABLE; this covers a DB created by the
            # never-deployed direct-call build (payment_id PK schema).
            with conn.cursor() as cur:
                cur.execute(
                    "ALTER TABLE psc_payments ADD COLUMN IF NOT EXISTS purchase_ref TEXT")
                cur.execute(
                    "ALTER TABLE psc_payments ADD COLUMN IF NOT EXISTS gateway_payment_id TEXT")
            conn.commit()
            # Migrate psc_users: banned column + canonical emails.
            with conn.cursor() as cur:
                cur.execute(
                    "ALTER TABLE psc_users ADD COLUMN IF NOT EXISTS banned INTEGER NOT NULL DEFAULT 0")
                cur.execute(
                    "ALTER TABLE psc_users ADD COLUMN IF NOT EXISTS password_hash TEXT")
                cur.execute(
                    "SELECT id, email FROM psc_users ORDER BY created_at ASC, id ASC")
                rows = cur.fetchall()
                for _id, new_email in _dedupe_emails(
                        [(r[0], r[1]) for r in rows]).items():
                    cur.execute(
                        "UPDATE psc_users SET email = %s WHERE id = %s",
                        (new_email, _id))
            conn.commit()
            # Unique email index in its own transaction: a failure here must
            # never take the server down (the app-level check still applies).
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS idx_psc_users_email ON psc_users(email)")
                conn.commit()
            except Exception as e:
                conn.rollback()
                print("WARNING: could not create unique email index: %s" % e, flush=True)
        finally:
            conn.close()
        self.backend = "postgres"

    def get_key_by_install_id(self, install_id):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_license_keys WHERE install_id = %s",
                            (install_id,))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_trial_by_user(self, user_id):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_trials WHERE user_id = %s",
                            (user_id,))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def create_trial(self, install_id, user_id, started_at, expires_at):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO psc_trials (install_id, user_id, started_at, expires_at, created_at)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (install_id, user_id, started_at, expires_at, _now_iso()))
            conn.commit()
        finally:
            conn.close()

    def list_trials(self):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_trials ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def create_user(self, user_id, full_name, phone, post_office, email, password_hash=None):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO psc_users (id, full_name, phone, post_office, email, password_hash, created_at)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (user_id, full_name, phone, post_office, email, password_hash, _now_iso()))
            conn.commit()
            return True
        except self._psycopg2.IntegrityError:
            # Unique-email race: another signup for this mailbox just landed.
            conn.rollback()
            return False
        finally:
            conn.close()

    def set_password_hash(self, user_id, password_hash):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_users SET password_hash = %s WHERE id = %s",
                    (password_hash, user_id))
                changed = cur.rowcount > 0
            conn.commit()
            return changed
        finally:
            conn.close()

    def create_verification(self, ver_id, email, purpose, code_hash, payload, expires_at):
        conn = self._connect()
        try:
            import time as _time
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM psc_verifications WHERE expires_at < %s",
                    (int(_time.time()),))
                cur.execute(
                    "INSERT INTO psc_verifications (id, email, purpose, code_hash, payload, attempts, created_at, expires_at)"
                    " VALUES (%s, %s, %s, %s, %s, 0, %s, %s)",
                    (ver_id, email, purpose, code_hash, payload, _now_iso(), expires_at))
            conn.commit()
        finally:
            conn.close()

    def get_verification(self, email, purpose):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM psc_verifications WHERE email = %s AND purpose = %s"
                    " ORDER BY created_at DESC, id DESC LIMIT 1",
                    (email, purpose))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def delete_verifications(self, email, purpose):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM psc_verifications WHERE email = %s AND purpose = %s",
                    (email, purpose))
            conn.commit()
        finally:
            conn.close()

    def bump_attempts(self, ver_id):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_verifications SET attempts = attempts + 1 WHERE id = %s",
                    (ver_id,))
                cur.execute(
                    "SELECT attempts FROM psc_verifications WHERE id = %s", (ver_id,))
                row = cur.fetchone()
            conn.commit()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def count_recent_codes(self, email, since_iso):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM psc_verifications WHERE email = %s AND created_at >= %s",
                    (email, since_iso))
                row = cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def get_user_by_email(self, email):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_users WHERE email = %s"
                            " ORDER BY created_at ASC, id ASC LIMIT 1",
                            (email,))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_users(self):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_users ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def set_banned(self, user_id, banned):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_users SET banned = %s WHERE id = %s",
                    (1 if banned else 0, user_id))
                changed = cur.rowcount > 0
            conn.commit()
            return changed
        finally:
            conn.close()

    def get_user_by_id(self, user_id):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_users WHERE id = %s",
                            (user_id,))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _connect(self):
        conn = self._psycopg2.connect(self._dsn)
        conn.autocommit = False
        return conn

    def create_key(self, key_id, license_key, install_id, plan='lifetime'):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO psc_license_keys (key_id, license_key, install_id, user_id, created_at, activated_at, plan, expires_at)"
                    " VALUES (%s, %s, %s, NULL, %s, NULL, %s, NULL)",
                    (key_id, _norm_key(license_key), install_id, _now_iso(), plan))
            conn.commit()
        finally:
            conn.close()

    def get_key(self, license_key):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_license_keys WHERE license_key = %s",
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
                    "UPDATE psc_license_keys SET install_id = %s, activated_at = %s WHERE key_id = %s",
                    (install_id, _now_iso(), key_id))
            conn.commit()
        finally:
            conn.close()

    def set_key_expiry(self, key_id, expires_at):
        """Set the expiry (unix seconds, or None = lifetime) of a key.
        Called once at first bind; re-activating the same key never
        touches it again, so time can never be extended by re-entry."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_license_keys SET expires_at = %s WHERE key_id = %s",
                    (expires_at, key_id))
            conn.commit()
        finally:
            conn.close()

    def list_keys_by_install_id(self, install_id):
        """All keys bound to one device (oldest first) — used to stack a
        renewal onto the device's latest expiry and to detect a lifetime
        key, which blocks any further key on that device."""
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_license_keys WHERE install_id = %s"
                            " ORDER BY created_at ASC, key_id ASC",
                            (install_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def list_keys(self):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_license_keys ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def create_payment(self, purchase_ref, install_id, plan, amount):
        """A checkout the app started: pending until the gateway's
        webhook reports it paid. purchase_ref is generated HERE and is
        the row's key; the gateway's payment id is unknown until the
        callback arrives."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO psc_payments (purchase_ref, gateway_payment_id, install_id, plan, amount, status, key_id, created_at, paid_at)"
                    " VALUES (%s, NULL, %s, %s, %s, 'pending', NULL, %s, NULL)",
                    (purchase_ref, install_id, plan, amount, _now_iso()))
            conn.commit()
        finally:
            conn.close()

    def get_payment_by_ref(self, purchase_ref):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_payments WHERE purchase_ref = %s",
                            (purchase_ref,))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def claim_payment(self, purchase_ref):
        """Atomically flip a pending row to `issuing`. Returns True only
        for the ONE caller that won the claim — concurrent callbacks
        for the same purchase can never both issue a key."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_payments SET status = 'issuing'"
                    " WHERE purchase_ref = %s AND status = 'pending'",
                    (purchase_ref,))
                claimed = cur.rowcount > 0
            conn.commit()
            return claimed
        finally:
            conn.close()

    def set_payment_paid(self, purchase_ref, key_id, gateway_payment_id):
        """Mark the purchase paid + record the issued key and the
        gateway's payment id. Called once, right after the key is
        created and bound."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_payments SET status = 'paid', key_id = %s, gateway_payment_id = %s, paid_at = %s"
                    " WHERE purchase_ref = %s",
                    (key_id, gateway_payment_id, _now_iso(), purchase_ref))
            conn.commit()
        finally:
            conn.close()

    def set_payment_failed(self, purchase_ref):
        """Terminal failure. The shopkeeper must start a fresh purchase."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_payments SET status = 'failed' WHERE purchase_ref = %s",
                    (purchase_ref,))
            conn.commit()
        finally:
            conn.close()

    def reset_payment_pending(self, purchase_ref):
        """Release an `issuing` claim (issuance crashed mid-way) so the
        next callback retries instead of stalling forever."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE psc_payments SET status = 'pending'"
                    " WHERE purchase_ref = %s AND status = 'issuing'",
                    (purchase_ref,))
            conn.commit()
        finally:
            conn.close()

    def get_key_by_id(self, key_id):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_license_keys WHERE key_id = %s",
                            (key_id,))
                row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def export_all(self):
        conn = self._connect()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM psc_license_keys ORDER BY created_at")
                keys = [dict(r) for r in cur.fetchall()]
                cur.execute("SELECT * FROM psc_users ORDER BY created_at")
                psc_users = [dict(r) for r in cur.fetchall()]
                cur.execute("SELECT * FROM psc_trials ORDER BY created_at")
                trials = [dict(r) for r in cur.fetchall()]
            for u in psc_users:
                u.pop("password_hash", None)  # password hashes never leave the DB
            return {"keys": keys, "psc_users": psc_users, "trials": trials}
        finally:
            conn.close()


def get_store():
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        return PostgresStore(dsn)
    path = os.environ.get("LICENSE_DB_PATH", "data/license.db")
    return SQLiteStore(path)
