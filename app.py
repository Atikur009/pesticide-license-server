"""Pesticide Shop Calculator — license server (V3).

Online activation: a key is useless until this server confirms it.
The app holds NO secret — it only carries the RSA *public* key and verifies
the server's signed activation token offline afterwards.

Endpoints (all JSON):
  GET  /health                  -> {status, version, store}
  POST /v1/register-key         -> admin only (X-Admin-Secret). {install_id?}
                                   creates a random key, returns {key, key_id}.
  POST /v1/activate             -> {install_id, key}. Binds the key to that
                                   install_id on first use; rejects a key
                                   already bound to a different install_id.
                                   Returns {token, key_id, install_id}.
  POST /v1/signup               -> {full_name, phone, post_office, email}.
                                   Creates a shopkeeper account (one per
                                   Gmail) and returns a 30-day session token.
  POST /v1/login                -> {email, phone}. Returns the account + a
                                   fresh 30-day session token. The session
                                   token (type "session") goes in the
                                   Authorization: Bearer header for trial.
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
payload = {"install_id": ..., "key_id": ..., "iat": <unix seconds>}.
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

Next phase (NOT built here): shopkeeper accounts + cloud sync. The schema
already has psc_users + psc_license_keys.user_id, and routes are /v1/ versioned, so
/v2/ can add them without a rewrite.
"""
import base64
import json
import os
import re
import secrets
import string
import time
from collections import defaultdict

from flask import Flask, jsonify, request

from store import canon_email, get_store

VERSION = "3.2.0"
KEY_ALPHABET = string.ascii_uppercase + string.digits
TRIAL_DAYS = 3
TRIAL_SECONDS = TRIAL_DAYS * 86400
SESSION_DAYS = 30
SESSION_SECONDS = SESSION_DAYS * 86400

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


@app.route("/v1/register-key", methods=["POST"])
def register_key():
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    install_id = (body.get("install_id") or "").strip().upper() or None
    key_id = _new_key_id()
    key = _new_key()
    # Extremely unlikely collision — retry once if the key already exists.
    if store.get_key(key):
        key = _new_key()
    store.create_key(key_id, key, install_id)
    return jsonify({"key": key, "key_id": key_id,
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
    if not bound:
        store.bind_key(rec["key_id"], install_id)
    token = sign_token(install_id, rec["key_id"])
    return jsonify({"token": token, "key_id": rec["key_id"],
                    "install_id": install_id})


@app.route("/v1/signup", methods=["POST"])
def signup():
    """Create a shopkeeper account: full name + phone + post office + Gmail.
    One account per Gmail. Returns the account + a 30-day session token."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    full_name = (body.get("full_name") or "").strip()
    phone = _norm_phone(body.get("phone"))
    post_office = (body.get("post_office") or "").strip()
    email = _norm_email(body.get("email"))
    if not full_name or not phone or not post_office or not email:
        return jsonify({"error": "missing_fields",
                        "message": "নাম, মোবাইল নম্বর, পোস্ট অফিস ও Gmail — সবগুলো লাগবে।"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "invalid_email",
                        "message": "সঠিক Gmail ঠিকানা দিন।"}), 400
    if store.get_user_by_email(email):
        return jsonify({"error": "account_exists",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট আছে — লগইন করুন।"}), 409
    user_id = _new_user_id()
    if not store.create_user(user_id, full_name, phone, post_office, email):
        # Unique-email race: another signup for this mailbox just landed.
        return jsonify({"error": "account_exists",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট আছে — লগইন করুন।"}), 409
    return jsonify({"user_id": user_id, "full_name": full_name,
                    "phone": phone, "post_office": post_office,
                    "email": email,
                    "session_token": _new_session(user_id, email)}), 201


@app.route("/v1/login", methods=["POST"])
def login():
    """Log in with Gmail + phone (the two the shopkeeper gave at signup).
    Returns the account + a fresh 30-day session token."""
    if _rate_limited():
        return jsonify({"error": "too_many_attempts",
                        "message": "অনেকবার চেষ্টা করা হয়েছে — কিছুক্ষণ পরে আবার চেষ্টা করুন।"}), 429
    body = request.get_json(silent=True) or {}
    email = _norm_email(body.get("email"))
    phone = _norm_phone(body.get("phone"))
    if not email or not phone:
        return jsonify({"error": "missing_fields",
                        "message": "Gmail ও মোবাইল নম্বর — দুটোই লাগবে।"}), 400
    user = store.get_user_by_email(email)
    if not user:
        return jsonify({"error": "account_not_found",
                        "message": "এই Gmail দিয়ে অ্যাকাউন্ট পাওয়া যায়নি — সাইন আপ করুন।"}), 404
    if user.get("banned"):
        return jsonify({"error": "account_banned",
                        "message": "এই অ্যাকাউন্টটি বন্ধ করা হয়েছে — আতিকুরের সাথে যোগাযোগ করুন।"}), 403
    if _norm_phone(user.get("phone")) != phone:
        return jsonify({"error": "wrong_phone",
                        "message": "মোবাইল নম্বর মেলেনি — সাইন আপের সময় দেওয়া নম্বরটি দিন।"}), 403
    return jsonify({"user_id": user["id"], "full_name": user.get("full_name"),
                    "phone": user.get("phone"),
                    "post_office": user.get("post_office"),
                    "email": email,
                    "session_token": _new_session(user["id"], email)})


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
