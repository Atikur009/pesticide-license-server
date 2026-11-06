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
  GET  /v1/keys                 -> admin only. Lists issued keys + bindings.
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

from store import get_store

VERSION = "3.0.0"
KEY_ALPHABET = string.ascii_uppercase + string.digits

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


def sign_token(install_id: str, key_id: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    payload = {"install_id": install_id, "key_id": key_id, "iat": int(time.time())}
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _SIGNING_KEY.sign(
        payload_b64.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256())
    return payload_b64 + "." + _b64url(sig)


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
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Secret"
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


@app.route("/v1/keys", methods=["GET"])
def list_keys():
    if not _admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"keys": store.list_keys()})


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
