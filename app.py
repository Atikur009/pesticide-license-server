"""Pesticide Shop Calculator — license server (V3).

Online activation: a key is useless until this server confirms it.
The app holds NO secret — it only carries the RSA *public* key and verifies
the server's signed activation token offline afterwards.

Endpoints (all JSON):
  GET  /health                  -> {status, version, store}
  POST /v1/register-key         -> admin only (X-Admin-Secret). {install_id?,
                                   plan?} creates a random key, returns
                                   {key, key_id, plan}. plan is monthly |
                                   yearly | lifetime (default lifetime).
                                   Expiry is NOT set here — it starts at
                                   first activation (see /v1/activate).
  POST /v1/activate             -> {install_id, key}. Binds the key to that
                                   install_id on first use; rejects a key
                                   already bound to a different install_id.
                                   Subscription plans (v3.4.0): monthly =
                                   30 days, yearly = 365 days, lifetime =
                                   no expiry. A renewal key on the same
                                   device EXTENDS from the device's latest
                                   expiry (never from "now" when time is
                                   left); re-entering the SAME key returns
                                   its STORED expiry and never extends it.
                                   A device with a lifetime key rejects any
                                   further key (409 already_licensed).
                                   Returns {token, key_id, install_id,
                                   plan, expires_at, days_left}.
  POST /v1/purchase             -> {install_id, plan}. AUTO-BUY (Atikur Pay
                                   gateway): creates a gateway checkout for
                                   the plan's BDT price and returns
                                   {payment_id, payment_url, amount,
                                   currency: "BDT", plan, status}. The
                                   shopkeeper pays on the gateway page
                                   (bKash + TrxID, SMS-verified by the
                                   gateway) — no key typing. A lifetime
                                   device gets 409 already_licensed.
  POST /v1/purchase/status      -> {payment_id}. Asks the gateway whether
                                   the payment is paid. pending -> {status:
                                   "pending"}; paid -> the key is issued
                                   server-side (same stacking rules as
                                   /v1/activate) and the EXACT activate
                                   response is returned; repeat calls return
                                   the SAME stored activation (never a second
                                   key). failed/expired/cancelled -> {status:
                                   "failed"} (terminal). No session needed —
                                   the payment is the authorization.
  POST /v1/signup               -> {full_name, phone, post_office, email,
                                   password}. Validates and EMAILS a 6-digit
                                   code; the account is created only when the
                                   code is verified (verify-signup). One
                                   account per Gmail (canonical mailbox form).
  POST /v1/verify-signup        -> {email, code}. Creates the account and
                                   returns a 30-day session token.
  POST /v1/login                -> {email, password?, phone?}. Accounts WITH
                                   a password need the password; legacy
                                   accounts WITHOUT one need the phone given
                                   at signup. On success EMAILS a code; the
                                   session comes from verify-login.
  POST /v1/verify-login         -> {email, code}. Returns the account + a
                                   fresh 30-day session token.
  POST /v1/request-code         -> {email, purpose=signup|login|reset}.
                                   (Re)sends a code. 60s cooldown, 5/hour
                                   per mailbox. For signup it reuses the
                                   pending signup details from the first call.
  POST /v1/reset-password       -> {email, code, new_password}. Sets a new
                                   password after an emailed code (forgot /
                                   change-password flow).
  POST /v1/start-trial           -> {install_id} + session. Starts a 3-day FREE trial
                                   (v3.1.0): one trial per install_id, recorded
                                   in psc_trials. Returns a signed TRIAL token
                                   {token, install_id, expires_at, days_left}.
                                   Re-starting never extends the original
                                   expiry; a device with a paid key gets 409
                                   already_licensed. Trial token payload has
                                   "type": "trial" and "exp" (unix seconds);
                                   the app verifies the signature offline and
                                   locks again after expiry. Reinstalling the
                                   app creates a new install_id and therefore
                                   a new trial — known limit, see store.py.
  GET  /v1/keys                 -> admin only. Lists issued keys + bindings.
  GET  /v1/users                -> admin only. Lists shopkeeper accounts
                                   (Gmail, name, phone, trial state, banned).
  POST /v1/users/<id>/ban       -> admin only. {banned: true/false}.
                                   A banned account cannot log in or start
                                   a trial (already-issued 30-day sessions
                                   keep working offline until they expire —
                                   the app verifies them without a network).
  GET  /v1/export               -> admin only. Full JSON backup dump.

Token: base64url(payload) + "." + base64url(RSA-PKCS1v1.5-SHA256 signature)
payload = {"install_id": ..., "key_id": ..., "iat": <unix seconds>,
           "type": "license", "plan": "monthly"|"yearly"|"lifetime",
           "exp": <unix seconds>}. "exp" is present only for term plans
(monthly/yearly); lifetime tokens carry NO exp and never expire. Tokens
issued before v3.4.0 have no "plan"/"exp" and are treated as lifetime.
The client verifies the signature with the embedded RSA public key and
checks payload.install_id == its own Install ID. No network needed after
activation.

Secrets (Render env vars, NEVER in the repo):
  LICENSE_ADMIN_SECRET  — required for /v1/register-key, /v1/keys, /v1/export.
  LICENSE_SIGNING_KEY   — RSA private key PEM (or base64 of it in
                          LICENSE_SIGNING_KEY_B64). Generated once; the public
                          half lives in server/public_key.pem and in the app.
  DATABASE_URL          — set MANUALLY in the Render dashboard to the internal
                          connection string of atikur-smm-panel-db (Render
                          allows only one free Postgres DB; this service
                          shares the panel's). Without it the server uses a
                          local SQLite file (data/license.db).
  SMTP_USER / SMTP_APP_PASSWORD — Gmail address + app password that sends
                          the verification codes (see mailer.py). Without
                          them the auth endpoints report email_unconfigured.
  ATIKUR_PAY_API_KEY        — merchant API key for the Atikur Pay gateway
                          (created in the gateway dashboard for the
                          pesticide app). Without it /v1/purchase* report
                          gateway_not_configured (503).
  ATIKUR_PAY_BASE_URL       — gateway base URL (default
                          https://atikur-pay.onrender.com).
  PLAN_PRICES_BDT           — optional JSON override of the plan prices in
                          BDT, e.g. {"monthly":250,"yearly":2500,
                          "lifetime":12500} (the defaults). The server is
                          the ONLY place that knows BDT prices.

Next phase (NOT built here): shopkeeper accounts + cloud sync. The schema
already has psc_users + psc_license_keys.user_id, and routes are /v1/ versioned, so
/v2/ can add them without a rewrite.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

from flask import Flask, jsonify, request

import mailer
from store import canon_email, get_store

VERSION = "3.4.0"
KEY_ALPHABET = string.ascii_uppercase + string.digits
# Subscription plans (v3.4.0): term in seconds, None = lifetime (no expiry).
# Prices live in the app/keygen UI only ($2 monthly, $20 yearly, $100
# lifetime) — the server only knows terms, never money.
PLANS = {"monthly": 30 * 86400, "yearly": 365 * 86400, "lifetime": None}
# Auto-buy (Atikur Pay): BDT prices charged on the gateway checkout page.
# The server is the ONLY place that knows BDT prices — the app displays
# whatever /v1/purchase returns. Override via PLAN_PRICES_BDT (JSON).
DEFAULT_PLAN_PRICES_BDT = {"monthly": 250, "yearly": 2500, "lifetime": 12500}
ATIKUR_PAY_BASE_URL = os.environ.get(
    "ATIKUR_PAY_BASE_URL", "https://atikur-pay.onrender.com").rstrip("/")
ATIKUR_PAY_API_KEY = os.environ.get("ATIKUR_PAY_API_KEY") or None


def _plan_prices_bdt():
    """BDT price per plan: defaults, overridden per-plan by the
    PLAN_PRICES_BDT env JSON. A bad override never breaks the server —
    invalid entries fall back to the defaults."""
    prices = dict(DEFAULT_PLAN_PRICES_BDT)
    raw = os.environ.get("PLAN_PRICES_BDT")
    if raw:
        try:
            override = json.loads(raw)
        except ValueError:
            override = None
        if isinstance(override, dict):
            for plan, amount in override.items():
                if plan in prices and isinstance(amount, (int, float)) and amount >= 1:
                    prices[plan] = int(amount)
    return prices
TRIAL_DAYS = 3
TRIAL_SECONDS = TRIAL_DAYS * 86400
SESSION_DAYS = 30
SESSION_SECONDS = SESSION_DAYS * 86400
# Email verification codes (v3.3.0)
CODE_TTL_SECONDS = 600
CODE_COOLDOWN_SECONDS = 60
CODE_HOURLY_MAX = 5
CODE_MAX_ATTEMPTS = 5
PASSWORD_MIN_LENGTH = 6
PASSWORD_ITERATIONS = 200000

app = Flask(__name__)
store = get_store()

# ---------------------------------------------------------------- signing --
def _load_signing_key():
    """Load the RSA private key from env. Dev fallback: ephemeral keypair
    (tokens from this run verify only against this run — never for prod)."""
    from cryptography.hazmat.primitives import serialization
    pem_b64 = os.environ.get("LICENSE_SIGNING_KEY_B64")
    pem = os.environ.get("LICENSE_SIGNING_KEY")
    if pem_b64:
        pem = base64.b64decode(pem_b64).decode("utf-8")
    if pem:
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    from cryptography.hazmat.primitives.asymmetric import rsa
    print("WARNING: LICENSE_SIGNING_KEY not set — using an EPHEMERAL keypair "
          "(dev only; tokens will not verify after a restart).", flush=True)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_SIGNING_KEY = _load_signing_key()
_ADMIN_SECRET = os.environ.get("LICENSE_ADMIN_SECRET")
if not _ADMIN_SECRET:
    _ADMIN_SECRET = secrets.token_urlsafe(32)
    print("WARNING: LICENSE_ADMIN_SECRET not set — using a random one for "
          "this run only: %s" % _ADMIN_SECRET, flush=True)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign_payload(payload: dict) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _SIGNING_KEY.sign(
        payload_b64.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256())
    return payload_b64 + "." + _b64url(sig)


def _verify_token(token):
    """Verify one of our own signed tokens (license / trial / session).
    Returns the payload dict, or None if the signature or shape is bad."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        parts = str(token or "").split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if not isinstance(payload, dict) or "iat" not in payload:
            return None
        _SIGNING_KEY.public_key().verify(
            _b64url_decode(sig_b64),
            payload_b64.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256())
        return payload
    except Exception:
        return None


def sign_token(install_id: str, key_id: str, token_type: str = "license", exp=None, extra=None) -> str:
    payload = {"install_id": install_id, "key_id": key_id,
               "iat": int(time.time()), "type": token_type}
    if exp is not None:
        payload["exp"] = int(exp)
    if extra:
        payload.update(extra)
    return _sign_payload(payload)


def public_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    return _SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")


# ---------------------------------------------------------------- helpers --
def _admin_ok() -> bool:
    return request.headers.get("X-Admin-Secret") == _ADMIN_SECRET


def _norm_key(raw) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(raw or "").upper())


def _new_key() -> str:
    raw = "".join(secrets.choice(KEY_ALPHABET) for _ in range(20))
    return "-".join(raw[i:i + 5] for i in range(0, 20, 5))


def _new_key_id() -> str:
    return "K-" + "".join(secrets.choice(KEY_ALPHABET) for _ in range(8))


def _new_user_id() -> str:
    return "U-" + "".join(secrets.choice(KEY_ALPHABET) for _ in range(8))


def _norm_email(raw) -> str:
    # Canonical mailbox form (Gmail dots / +tags collapse to one mailbox).
    return canon_email(raw)


def _norm_phone(raw) -> str:
    return re.sub(r"[^0-9+]", "", str(raw or "").strip())


def _session_user():
    """The logged-in shopkeeper from the Authorization: Bearer session
    token, or None. A session lasts 30 days, then the user logs in again."""
    auth = request.headers.get("Authorization") or ""
    if not auth.startswith("Bearer "):
        return None
    payload = _verify_token(auth[7:].strip())
    if not payload or payload.get("type") != "session":
        return None
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or exp <= time.time():
        return None
    if not payload.get("user_id"):
        return None
    return payload


def _new_session(user_id, email):
    now = int(time.time())
    return _sign_payload({"user_id": user_id, "email": email,
                          "type": "session", "iat": now,
                          "exp": now + SESSION_SECONDS})


# ------------------------------------------------------- Atikur Pay client --
class _GatewayError(Exception):
    """The gateway could not be reached or answered garbage. Never carries
    the API key — nothing about a gateway call is ever logged."""


def _gateway_request(method, path, body=None):
    """One merchant-API call to Atikur Pay (server-to-server, stdlib
    urllib only). Returns (http_status, parsed_json). Raises
    _GatewayError on network failure or a non-JSON answer."""
    url = ATIKUR_PAY_BASE_URL + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-API-Key", ATIKUR_PAY_API_KEY)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # The gateway answered with an error status — its JSON body (if
        # any) is still useful to the caller.
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except Exception:
            return exc.code, {}
    except Exception:
        raise _GatewayError()


# ------------------------------------------------------- passwords + OTP --
def _hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt, PASSWORD_ITERATIONS)
    return "pbkdf2$%d$%s$%s" % (PASSWORD_ITERATIONS, _b64url(salt), _b64url(dk))


def _check_password(password, stored):
    try:
        scheme, iters, salt_b64, hash_b64 = str(stored or "").split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 _b64url_decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, _b64url_decode(hash_b64))
    except Exception:
        return False


def _issue_code(email, purpose, payload=None):
    """Rate-limited code issue: cooldown + hourly cap, store only the hash,
    email the code. Returns a Flask response. For a signup RESEND (payload
    None) the pending signup details from the first call are preserved."""
    from datetime import datetime, timedelta, timezone
    now = int(time.time())
    existing = store.get_verification(email, purpose)
    if existing:
        # created_at is not arithmetic-friendly; creation = expiry - TTL.
        created_ts = int(existing["expires_at"]) - CODE_TTL_SECONDS
        wait = CODE_COOLDOWN_SECONDS - (now - created_ts)
        if wait > 0:
            return jsonify({"error": "too_many_codes",
                            "message": "একটু অপেক্ষা করুন — %d সেকেন্ড পরে আবার কোড পাঠাতে পারবেন।" % wait,
                            "retry_after": wait}), 429
        if payload is None and existing.get("payload"):
            payload = existing["payload"]
    if purpose == "signup" and not payload:
        return jsonify({"error": "signup_first",
                        "message": "আগে সাইন আপের তথ্য (নাম, মোবাইল, পাসওয়ার্ড) দিন।"}), 400
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    if store.count_recent_codes(email, since) >= CODE_HOURLY_MAX:
        return jsonify({"error": "too_many_codes",
                        "message": "এক ঘণ্টায় অনেকগুলো কোড পাঠানো হয়েছে — পরে আবার চেষ্টা করুন।",
                        "retry_after": 3600}), 429
    code = "%06d" % secrets.randbelow(1000000)
    code_hash = hashlib.sha256(code.encode("ascii")).hexdigest()
    ver_id = "V-" + "".join(secrets.choice(KEY_ALPHABET) for _ in range(8))
    store.delete_verifications(email, purpose)
    store.create_verification(ver_id, email, purpose, code_hash, payload,
                              now + CODE_TTL_SECONDS)
    ok, reason = mailer.send_code_email(email, code, purpose)
    if not ok:
        store.delete_verifications(email, purpose)
        if reason == "not_configured":
            return jsonify({"error": "email_unconfigured",
                            "message": "ইমেইল পাঠানোর সেটআপ হয়নি — আতিকুরের সাথে যোগাযোগ করুন।"}), 503
        return jsonify({"error": "email_send_failed",
                        "message": "কোড পাঠানো যায়নি — আবার চেষ্টা করুন।"}), 502
    return jsonify({"otp_required": True, "email": email, "sent": True})


def _check_code(email, purpose, code):
    """Returns (row, None) when the code matches, else (None, response)."""
    row = store.get_verification(email, purpose)
    if not row:
        return None, (jsonify({"error": "invalid_code",
                               "message": "কোডটি ভুল বা মেয়াদ শেষ — নতুন কোড পাঠান।"}), 400)
    if int(time.time()) > int(row["expires_at"]):
        store.delete_verifications(email, purpose)
        return None, (jsonify({"error": "code_expired",
                               "message": "কোডের মেয়াদ শেষ — নতুন কোড পাঠান।"}), 400)
    if int(row.get("attempts") or 0) >= CODE_MAX_ATTEMPTS:
        store.delete_verifications(email, purpose)
        return None, (jsonify({"error": "invalid_code",
                               "message": "অনেকবার ভুল কোড দেওয়া হয়েছে — নতুন কোড পাঠান।"}), 400)
    digest = hashlib.sha256(str(code or "").strip().encode("ascii", "ignore")).hexdigest()
    if not hmac.compare_digest(digest, row["code_hash"]):
        attempts = store.bump_attempts(row["id"])
        if attempts >= CODE_MAX_ATTEMPTS:
            store.delete_verifications(email, purpose)
        return None, (jsonify({"error": "invalid_code",
                               "message": "কোডটি ভুল — আবার চেষ্টা করুন।"}), 400)
    return row, None


# Light brute-force guard on activation: 30 attempts per IP per 10 minutes.
_ATTEMPTS = defaultdict(list)


def _rate_limited() -> bool:
    ip = request.remote_addr or "unknown"
    now = time.time()
    window = [t for t in _ATTEMPTS[ip] if now - t < 600]
    _ATTEMPTS[ip] = window
    if len(window) >= 30:
        return True
    window.append(now)
    return False


@app.after_request
def _cors(resp):
    # The desktop app (file://) and Android WebView fetch this API — CORS
    # must allow them. The API is key-checked; origin is not a secret.
    # Authorization MUST be listed: /v1/start-trial sends a Bearer session
    # token, and without it the browser's preflight fails — the app then
    # reports "no internet" even though the network is fine (seen live
    # 2026-11-07: login worked, trial failed, same phone, same server).
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Secret, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/v1/<path:_any>", methods=["OPTIONS"])
@app.route("/health", methods=["OPTIONS"])
def _options(_any=None):
    return ("", 204)


# ---------------------------------------------------------------- routes --
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": VERSION, "store": store.backend})


def _days_left(expires_at, now):
    """Whole days left until expiry, rounded UP (any part of a day counts
    as a day, like the trial display). None = lifetime, 0 = expired."""
    if expires_at is None:
        return None
    return max(0, (int(expires_at) - int(now) + 86399) // 86400)


def _key_plan(rec):
    """A key row's plan; legacy rows (no plan stored) are lifetime."""
    plan = (rec or {}).get("plan") or "lifetime"
    return plan if plan in PLANS else "lifetime"


def _device_has_lifetime(install_id):
    """True when any key bound to this device is lifetime — such a device
    needs no further key, ever (same rule for manual keys and auto-buy)."""
    for other in store.list_keys_by_install_id(install_id):
        if _key_plan(other) == "lifetime":
            return True
    return False


def _compute_expiry(store, install_id, plan, now):
    """Expiry (unix seconds, None = lifetime) for a FRESH key bind on a
    device: a renewal stacks onto the device's latest expiry when time is
    left (a key bought early loses nothing); an expired device starts
    fresh from now. Shared by /v1/activate and /v1/purchase/status so the
    two paths can never diverge."""
    term = PLANS[plan]
    if term is None:
        return None
    base = now
    for other in store.list_keys_by_install_id(install_id):
        other_exp = other.get("expires_at")
        if other_exp is not None and int(other_exp) > base:
            base = int(other_exp)
    return base + term


def _issue_activation(install_id, key_id, plan, expires_at, now):
    """The activation response shape — identical for a manual key and an
    auto-buy purchase. The token carries plan + exp (term plans only)."""
    token = sign_token(install_id, key_id,
                       exp=expires_at, extra={"plan": plan})
    return {"token": token, "key_id": key_id, "install_id": install_id,
            "plan": plan, "expires_at": expires_at,
            "days_left": _days_left(expires_at, now)}


@app.route("/v1/register-key", methods=["POST"])
def register_key():
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    install_id = (body.get("install_id") or "").strip().upper() or None
    plan = str(body.get("plan") or "lifetime").strip().lower()
    if plan not in PLANS:
        return jsonify({"error": "invalid_plan",
                        "message": "প্ল্যান সঠিক নয় — monthly, yearly বা lifetime হতে হবে।"}), 400
    key_id = _new_key_id()
    key = _new_key()
    # Extremely unlikely collision — retry once if the key already exists.
    if store.get_key(key):
        key = _new_key()
    store.create_key(key_id, key, install_id, plan)
    return jsonify({"key": key, "key_id": key_id, "plan": plan,
                    "install_id": install_id, "bound": bool(install_id)}), 201


@app.route("/v1/activate", methods=["POST"])
def activate():
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    install_id = (body.get("install_id") or "").strip().upper()
    key = _norm_key(body.get("key"))
    if not install_id or not key:
        return jsonify({"error": "missing_fields",
                        "message": "Install ID এবং কী — দুটোই লাগবে।"}), 400
    rec = store.get_key(key)
    if not rec:
        return jsonify({"error": "invalid_key",
                        "message": "ভুল কী! সঠিক কী আতিকুরের কাছ থেকে নিন।"}), 403
    bound = rec.get("install_id")
    if bound and bound != install_id:
        return jsonify({"error": "bound_other_device",
                        "message": "এই কী অন্য একটি ডিভাইসে ব্যবহৃত হয়েছে।"}), 403
    plan = _key_plan(rec)
    term = PLANS[plan]
    now = int(time.time())
    if bound:
        # Same key, same device: return the STORED expiry — re-entering a
        # key must NEVER extend time (even after expiry; the client then
        # shows "expired" and the shopkeeper buys a renewal key).
        expires_at = rec.get("expires_at")
        if term is not None and expires_at is None:
            # Anomalous row (term plan, no expiry stored — cannot happen
            # through this code, only by manual DB edits): repair once
            # from now, then the stored value rules forever after.
            expires_at = now + term
            store.set_key_expiry(rec["key_id"], expires_at)
    else:
        # Fresh bind. A lifetime device needs no further key, ever.
        if _device_has_lifetime(install_id):
            return jsonify({"error": "already_licensed",
                            "message": "এই ডিভাইসে লাইফটাইম লাইসেন্স আছে — নতুন কী লাগবে না।"}), 409
        expires_at = _compute_expiry(store, install_id, plan, now)
        store.bind_key(rec["key_id"], install_id)
        if term is not None:
            store.set_key_expiry(rec["key_id"], expires_at)
    return jsonify(_issue_activation(install_id, rec["key_id"], plan,
                                     expires_at, now))


@app.route("/v1/purchase", methods=["POST"])
def purchase():
    """Auto-buy step 1: create an Atikur Pay checkout for the plan's BDT
    price. The app opens payment_url; the shopkeeper pays there (bKash
    Send Money + TrxID, SMS-verified by the gateway). No session needed
    — creating a checkout moves no money. Deliberately NOT rate-limited:
    the companion status endpoint is polled every 10s and must never hit
    the 30/10min activation guard."""
    if not ATIKUR_PAY_API_KEY:
        return jsonify({"error": "gateway_not_configured",
                        "message": "অটোমেটিক পেমেন্ট চালু হয়নি — অ্যাডমিনের সাথে যোগাযোগ করুন।"}), 503
    body = request.get_json(silent=True) or {}
    install_id = (body.get("install_id") or "").strip().upper()
    plan = str(body.get("plan") or "").strip().lower()
    if not install_id:
        return jsonify({"error": "missing_fields",
                        "message": "Install ID লাগবে।"}), 400
    if plan not in PLANS:
        return jsonify({"error": "invalid_plan",
                        "message": "প্ল্যান সঠিক নয় — monthly, yearly বা lifetime হতে হবে।"}), 400
    if _device_has_lifetime(install_id):
        return jsonify({"error": "already_licensed",
                        "message": "এই ডিভাইসে লাইফটাইম লাইসেন্স আছে — নতুন কী লাগবে না।"}), 409
    amount = _plan_prices_bdt()[plan]
    invoice = "PSC-%s-%s-%d-%s" % (
        plan, install_id, int(time.time()),
        "".join(secrets.choice(KEY_ALPHABET) for _ in range(6)))
    try:
        status_code, data = _gateway_request(
            "POST", "/api/v1/create-payment",
            {"amount": amount, "currency": "BDT",
             "merchantInvoiceNumber": invoice, "customerRef": install_id})
    except _GatewayError:
        return jsonify({"error": "gateway_error",
                        "message": "পেমেন্ট সার্ভারে যোগাযোগ হয়নি — আবার চেষ্টা করুন।"}), 502
    if status_code not in (200, 201) or not data.get("payment_id") or not data.get("payment_url"):
        return jsonify({"error": "gateway_error",
                        "message": "পেমেন্ট তৈরি হয়নি — আবার চেষ্টা করুন।"}), 502
    store.create_payment(data["payment_id"], install_id, plan, amount)
    return jsonify({"payment_id": data["payment_id"],
                    "payment_url": data["payment_url"],
                    "amount": amount, "currency": "BDT", "plan": plan,
                    "status": "pending"}), 201


@app.route("/v1/purchase/status", methods=["POST"])
def purchase_status():
    """Auto-buy step 2: ask the gateway whether the payment is paid. A
    paid payment issues the license key server-side (same stacking rules
    as /v1/activate) and returns the EXACT activate response; repeat
    calls return the SAME stored activation — one payment, one key,
    forever. No session needed — the payment is the authorization."""
    if not ATIKUR_PAY_API_KEY:
        return jsonify({"error": "gateway_not_configured",
                        "message": "অটোমেটিক পেমেন্ট চালু হয়নি — অ্যাডমিনের সাথে যোগাযোগ করুন।"}), 503
    body = request.get_json(silent=True) or {}
    payment_id = str(body.get("payment_id") or "").strip()
    if not payment_id:
        return jsonify({"error": "missing_fields",
                        "message": "payment_id লাগবে।"}), 400
    row = store.get_payment(payment_id)
    if not row:
        return jsonify({"error": "payment_not_found",
                        "message": "পেমেন্টটি পাওয়া যায়নি — আবার কিনুন।"}), 404
    if row.get("status") == "failed":
        return jsonify({"status": "failed", "payment_id": payment_id,
                        "plan": row.get("plan")})
    if row.get("status") == "paid" and row.get("key_id"):
        # Already issued: return the STORED activation — same key, same
        # expiry, never a second key.
        key_rec = store.get_key_by_id(row["key_id"])
        if key_rec:
            plan = _key_plan(key_rec)
            return jsonify(_issue_activation(
                row["install_id"], row["key_id"], plan,
                key_rec.get("expires_at"), int(time.time())))
        return jsonify({"error": "server_error",
                        "message": "লাইসেন্স পাওয়া যায়নি — অ্যাডমিনের সাথে যোগাযোগ করুন।"}), 500
    try:
        status_code, data = _gateway_request(
            "GET", "/api/v1/payment/status?payment_id=" + urllib.parse.quote(payment_id))
    except _GatewayError:
        return jsonify({"error": "gateway_error",
                        "message": "পেমেন্ট সার্ভারে যোগাযোগ হয়নি — আবার চেষ্টা করুন।"}), 502
    if status_code != 200:
        return jsonify({"error": "gateway_error",
                        "message": "পেমেন্ট যাচাই হয়নি — আবার চেষ্টা করুন।"}), 502
    gw_status = str(data.get("status") or "").strip().lower()
    if gw_status == "pending":
        return jsonify({"status": "pending", "payment_id": payment_id,
                        "plan": row.get("plan")})
    if gw_status != "paid":
        # failed / expired / cancelled / anything unknown: terminal. The
        # gateway only ever sets pending/paid today, so this is purely
        # defensive — a stuck checkout must never poll forever.
        store.set_payment_failed(payment_id)
        return jsonify({"status": "failed", "payment_id": payment_id,
                        "plan": row.get("plan")})
    # Paid: claim the row (exactly one issuer wins), then issue the key.
    if not store.claim_payment(payment_id):
        # Another check is issuing (or just issued) — re-read and answer
        # from the stored row; the client polls again if still issuing.
        fresh = store.get_payment(payment_id)
        if fresh and fresh.get("status") == "paid" and fresh.get("key_id"):
            key_rec = store.get_key_by_id(fresh["key_id"])
            if key_rec:
                plan = _key_plan(key_rec)
                return jsonify(_issue_activation(
                    fresh["install_id"], fresh["key_id"], plan,
                    key_rec.get("expires_at"), int(time.time())))
        return jsonify({"status": "pending", "payment_id": payment_id,
                        "plan": row.get("plan")})
    try:
        now = int(time.time())
        install_id = row["install_id"]
        plan = row["plan"]
        if _device_has_lifetime(install_id):
            store.reset_payment_pending(payment_id)
            return jsonify({"error": "already_licensed",
                            "message": "এই ডিভাইসে লাইফটাইম লাইসেন্স আছে — নতুন কী লাগবে না।"}), 409
        key_id = _new_key_id()
        key = _new_key()
        if store.get_key(key):
            key = _new_key()
        store.create_key(key_id, key, install_id, plan)
        expires_at = _compute_expiry(store, install_id, plan, now)
        store.bind_key(key_id, install_id)
        if PLANS[plan] is not None:
            store.set_key_expiry(key_id, expires_at)
        store.set_payment_paid(payment_id, key_id)
    except Exception:
        # Never leave the row stuck in `issuing` — the next check retries.
        store.reset_payment_pending(payment_id)
        return jsonify({"error": "server_error",
                        "message": "লাইসেন্স তৈরি হয়নি — আবার চেষ্টা করুন।"}), 500
    return jsonify(_issue_activation(install_id, key_id, plan,
                                     expires_at, now))


@app.route("/v1/signup", methods=["POST"])
def signup():
    """Step 1 of signup: validate the fields + password and email a
    verification code. The account is created only by verify-signup."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    full_name = (body.get("full_name") or "").strip()
    phone = _norm_phone(body.get("phone"))
    post_office = (body.get("post_office") or "").strip()
    email = _norm_email(body.get("email"))
    password = str(body.get("password") or "")
    if not full_name or not phone or not post_office or not email or not password:
        return jsonify({"error": "missing_fields",
                        "message": "নাম, মোবাইল নম্বর, পোস্ট অফিস, Gmail ও পাসওয়ার্ড — সবগুলো লাগবে।"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "invalid_email",
                        "message": "সঠিক Gmail ঠিকানা দিন।"}), 400
    if len(password) < PASSWORD_MIN_LENGTH:
        return jsonify({"error": "weak_password",
                        "message": "পাসওয়ার্ড কমপক্ষে %d অক্ষরের হতে হবে।" % PASSWORD_MIN_LENGTH}), 400
    if store.get_user_by_email(email):
        return jsonify({"error": "account_exists",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট আছে — লগইন করুন।"}), 409
    payload = json.dumps({"full_name": full_name, "phone": phone,
                          "post_office": post_office,
                          "password_hash": _hash_password(password)})
    return _issue_code(email, "signup", payload)


@app.route("/v1/verify-signup", methods=["POST"])
def verify_signup():
    """Step 2 of signup: a correct code creates the account + session."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    email = _norm_email(body.get("email"))
    code = str(body.get("code") or "").strip()
    if not email or not code:
        return jsonify({"error": "missing_fields",
                        "message": "Gmail ও কোড — দুটোই লাগবে।"}), 400
    row, err = _check_code(email, "signup", code)
    if err:
        return err
    try:
        payload = json.loads(row.get("payload") or "{}")
    except ValueError:
        payload = {}
    if store.get_user_by_email(email):
        store.delete_verifications(email, "signup")
        return jsonify({"error": "account_exists",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট আছে — লগইন করুন।"}), 409
    user_id = _new_user_id()
    if not store.create_user(user_id, payload.get("full_name", ""),
                             payload.get("phone", ""), payload.get("post_office", ""),
                             email, payload.get("password_hash")):
        return jsonify({"error": "account_exists",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট আছে — লগইন করুন।"}), 409
    store.delete_verifications(email, "signup")
    return jsonify({"user_id": user_id, "full_name": payload.get("full_name", ""),
                    "phone": payload.get("phone", ""),
                    "post_office": payload.get("post_office", ""),
                    "email": email,
                    "session_token": _new_session(user_id, email)}), 201


@app.route("/v1/login", methods=["POST"])
def login():
    """Step 1 of login: check the password (or the phone for legacy
    accounts without a password), then email a verification code."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    email = _norm_email(body.get("email"))
    password = str(body.get("password") or "")
    phone = _norm_phone(body.get("phone"))
    if not email:
        return jsonify({"error": "missing_fields",
                        "message": "Gmail লাগবে।"}), 400
    user = store.get_user_by_email(email)
    if not user:
        return jsonify({"error": "account_not_found",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট পাওয়া যায়নি — সাইন আপ করুন।"}), 404
    if user.get("banned"):
        return jsonify({"error": "account_banned",
                        "message": "এই অ্যাকাউন্টটি বন্ধ করা হয়েছে — আতিকুরের সাথে যোগাযোগ করুন।"}), 403
    if user.get("password_hash"):
        if not password or not _check_password(password, user["password_hash"]):
            return jsonify({"error": "wrong_password",
                            "message": "পাসওয়ার্ড ভুল হয়েছে।"}), 403
    else:
        # Legacy account (created before passwords): phone identifies it.
        if not phone or _norm_phone(user.get("phone")) != phone:
            return jsonify({"error": "wrong_phone",
                            "message": "মোবাইল নম্বর মেলেনি — সাইন আপের সময় দেওয়া নম্বরটি দিন।"}), 403
    return _issue_code(email, "login")


@app.route("/v1/verify-login", methods=["POST"])
def verify_login():
    """Step 2 of login: a correct code returns a fresh session token."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    email = _norm_email(body.get("email"))
    code = str(body.get("code") or "").strip()
    if not email or not code:
        return jsonify({"error": "missing_fields",
                        "message": "Gmail ও কোড — দুটোই লাগবে।"}), 400
    _row, err = _check_code(email, "login", code)
    if err:
        return err
    user = store.get_user_by_email(email)
    if not user:
        return jsonify({"error": "account_not_found",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট পাওয়া যায়নি — সাইন আপ করুন।"}), 404
    if user.get("banned"):
        return jsonify({"error": "account_banned",
                        "message": "এই অ্যাকাউন্টটি বন্ধ করা হয়েছে — আতিকুরের সাথে যোগাযোগ করুন।"}), 403
    store.delete_verifications(email, "login")
    return jsonify({"user_id": user["id"], "full_name": user.get("full_name"),
                    "phone": user.get("phone"),
                    "post_office": user.get("post_office"),
                    "email": email,
                    "session_token": _new_session(user["id"], email)})


@app.route("/v1/request-code", methods=["POST"])
def request_code():
    """(Re)send a verification code. purpose: signup | login | reset."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    email = _norm_email(body.get("email"))
    purpose = str(body.get("purpose") or "").strip()
    if not email or purpose not in ("signup", "login", "reset"):
        return jsonify({"error": "missing_fields",
                        "message": "Gmail ও সঠিক ধরন লাগবে।"}), 400
    user = store.get_user_by_email(email)
    if purpose == "signup":
        if user:
            return jsonify({"error": "account_exists",
                            "message": "এই Gmail দিয়ে অ্যাকাউন্ট আছে — লগইন করুন।"}), 409
    else:
        if not user:
            return jsonify({"error": "account_not_found",
                            "message": "এই Gmail দিয়ে অ্যাকাউন্ট পাওয়া যায়নি — সাইন আপ করুন।"}), 404
        if user.get("banned"):
            return jsonify({"error": "account_banned",
                            "message": "এই অ্যাকাউন্টটি বন্ধ করা হয়েছে — আতিকুরের সাথে যোগাযোগ করুন।"}), 403
    return _issue_code(email, purpose)


@app.route("/v1/reset-password", methods=["POST"])
def reset_password():
    """Set a new password after an emailed code (forgot/change flow)."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    email = _norm_email(body.get("email"))
    code = str(body.get("code") or "").strip()
    new_password = str(body.get("new_password") or "")
    if not email or not code or not new_password:
        return jsonify({"error": "missing_fields",
                        "message": "Gmail, কোড ও নতুন পাসওয়ার্ড — সবগুলো লাগবে।"}), 400
    if len(new_password) < PASSWORD_MIN_LENGTH:
        return jsonify({"error": "weak_password",
                        "message": "পাসওয়ার্ড কমপক্ষে %d অক্ষরের হতে হবে।" % PASSWORD_MIN_LENGTH}), 400
    user = store.get_user_by_email(email)
    if not user:
        return jsonify({"error": "account_not_found",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট পাওয়া যায়নি — সাইন আপ করুন।"}), 404
    if user.get("banned"):
        return jsonify({"error": "account_banned",
                        "message": "এই অ্যাকাউন্টটি বন্ধ করা হয়েছে — আতিকুরের সাথে যোগাযোগ করুন।"}), 403
    _row, err = _check_code(email, "reset", code)
    if err:
        return err
    store.set_password_hash(user["id"], _hash_password(new_password))
    store.delete_verifications(email, "reset")
    return jsonify({"ok": True, "email": email})


@app.route("/v1/start-trial", methods=["POST"])
def start_trial():
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    sess = _session_user()
    if not sess:
        return jsonify({"error": "unauthorized",
                        "message": "প্রথমে লগইন করুন — ট্রায়াল শুরু করতে অ্যাকাউন্ট লাগবে।"}), 401
    user_id = sess["user_id"]
    user = store.get_user_by_id(user_id)
    if user and user.get("banned"):
        return jsonify({"error": "account_banned",
                        "message": "এই অ্যাকাউন্টটি বন্ধ করা হয়েছে — আতিকুরের সাথে যোগাযোগ করুন।"}), 403
    body = request.get_json(silent=True) or {}
    install_id = (body.get("install_id") or "").strip().upper()
    if not install_id:
        return jsonify({"error": "missing_fields",
                        "message": "Install ID লাগবে।"}), 400
    # A device that already owns a paid key needs no trial.
    if store.get_key_by_install_id(install_id):
        return jsonify({"error": "already_licensed",
                        "message": "এই ডিভাইসে লাইসেন্স আছে — ট্রায়াল লাগবে না।"}), 409
    now = int(time.time())
    trial = store.get_trial_by_user(user_id)
    if trial:
        # One trial per account — never extend the original expiry.
        expires_at = int(trial["expires_at"])
    else:
        expires_at = now + TRIAL_SECONDS
        store.create_trial(install_id, user_id, now, expires_at)
    token = sign_token(install_id, None, token_type="trial", exp=expires_at,
                       extra={"user_id": user_id})
    # Clamp: a 3-day trial must never report more than 3 days left.
    days_left = min(TRIAL_DAYS, max(0, (expires_at - now + 86399) // 86400))
    return jsonify({"token": token, "install_id": install_id,
                    "user_id": user_id,
                    "expires_at": expires_at, "days_left": days_left})


@app.route("/v1/keys", methods=["GET"])
def list_keys():
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"keys": store.list_keys()})


@app.route("/v1/users", methods=["GET"])
def list_users():
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    now = int(time.time())
    trials = {t["user_id"]: t for t in store.list_trials()}
    users = []
    for u in store.list_users():
        trial = trials.get(u["id"])
        days_left = None
        if trial:
            days_left = min(TRIAL_DAYS,
                            max(0, (int(trial["expires_at"]) - now + 86399) // 86400))
        users.append({"user_id": u["id"],
                      "full_name": u.get("full_name"),
                      "phone": u.get("phone"),
                      "post_office": u.get("post_office"),
                      "email": u.get("email"),
                      "banned": bool(u.get("banned")),
                      "created_at": u.get("created_at"),
                      "trial_expires_at": int(trial["expires_at"]) if trial else None,
                      "trial_days_left": days_left})
    return jsonify({"count": len(users), "users": users})


@app.route("/v1/users/<user_id>/ban", methods=["POST"])
def ban_user(user_id):
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    banned = body.get("banned", True)
    user = store.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    store.set_banned(user_id, bool(banned))
    return jsonify({"user_id": user_id, "email": user.get("email"),
                    "banned": bool(banned)})


@app.route("/v1/export", methods=["GET"])
def export_all():
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(store.export_all())


@app.route("/v1/public-key", methods=["GET"])
def pubkey():
    """The RSA public key (safe to publish) — clients embed this."""
    return jsonify({"public_key_pem": public_key_pem()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
