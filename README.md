# Pesticide Shop Calculator — License Server

Online license activation for the Pesticide Shop Calculator (V3). A key is
only usable after the server checks it — no key can be forged offline,
because the signing secret lives only on the server. After one activation
the app works fully offline: the app verifies the signed activation token
locally with the embedded public key.

## Endpoints (all JSON)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | — | `{"status":"ok"}` |
| POST | `/v1/register-key` | `X-Admin-Secret` | Body `{"install_id"?, "plan"?}` → creates a key, returns `{"key_id","key","plan","install_id"}`. `plan`: `monthly` (30 days) \| `yearly` (365 days) \| `lifetime` (default, no expiry). Used by keygen.html. |
| POST | `/v1/activate` | — | Body `{"install_id","key"}` → validates, binds key to install_id on first use, rejects if bound elsewhere. Returns `{"token","install_id","key_id","plan","expires_at","days_left"}`. Renewal keys stack onto the device's latest expiry; re-entering the same key returns its stored expiry; a lifetime device rejects new keys (409). |
| POST | `/v1/signup` | — | Body `{"full_name","phone","post_office","email","password"}` → emails a 6-digit code; account created by verify-signup. One account per Gmail (canonical mailbox form). |
| POST | `/v1/verify-signup` | — | Body `{"email","code"}` → creates the account, returns a 30-day session token. |
| POST | `/v1/login` | — | Body `{"email","password?","phone?"}` → password accounts need the password, legacy accounts need the phone; then emails a code. |
| POST | `/v1/verify-login` | — | Body `{"email","code"}` → returns a fresh 30-day session token. |
| POST | `/v1/request-code` | — | Body `{"email","purpose":"signup"\|"login"\|"reset"}` → (re)sends a code. 60s cooldown, 5/hour per mailbox. |
| POST | `/v1/reset-password` | — | Body `{"email","code","new_password"}` → sets a new password. |
| POST | `/v1/start-trial` | `Bearer` session | Body `{"install_id"}` → 3-day trial token, one per account. |
| GET | `/v1/keys` | `X-Admin-Secret` | Lists issued keys + bindings. |
| GET | `/v1/users` | `X-Admin-Secret` | Lists shopkeeper accounts (Gmail, name, phone, trial state, banned). |
| POST | `/v1/users/<id>/ban` | `X-Admin-Secret` | Body `{"banned":true/false}`. |
| GET | `/v1/export` | `X-Admin-Secret` | Full backup dump (keys, users, trials; password hashes stripped). |
| GET | `/v1/public-key` | — | The RSA public key (same as `public_key.pem` in this repo). |

Passwords are stored as PBKDF2-HMAC-SHA256 hashes (200k iterations), never
plaintext. Verification codes live only as SHA-256 hashes, expire after 10
minutes, and allow 5 attempts. Code emails go out via SMTP — see `mailer.py`.

Key format: `XXXXX-XXXXX-XXXXX-XXXXX` (uppercase letters + digits, no confusing
characters). One key = one device (install_id). A key bound to a different
install_id is rejected with `409`.

## Activation token

`base64url(payload).base64url(signature)` — payload is
`{"install_id","key_id","iat"}`; signature is RSA-2048 PKCS1v15 with SHA-256.
The app verifies it locally with the public key in `public_key.pem` (also
embedded in the app's `license.js`). The private key is NEVER in this repo
— it lives only as the Render env var `LICENSE_SIGNING_KEY`.

## Storage (durable)

Render free Postgres (`DATABASE_URL` from render.yaml) when set; otherwise a
local SQLite file (`data/license.db` — local dev only). Render's free disk is
ephemeral, so the app never relies on it in production. `/v1/export` is the
backup route.

## Deploy (Render free tier)

1. Push this repo to GitHub, then in Render: **New → Blueprint** and point
   it at this repo (render.yaml creates the web service +
   `pesticide-license-db` Postgres).
2. In the Render dashboard set the env vars (never commit them):
   - `LICENSE_SIGNING_KEY` — RSA-2048 private key PEM (whole file)
   - `LICENSE_ADMIN_SECRET` — admin secret used by keygen.html
   - `SMTP_USER` + `SMTP_APP_PASSWORD` — Gmail address + app password that
     sends the verification codes (optional `SMTP_HOST`/`SMTP_PORT`/
     `SMTP_FROM`; defaults are Gmail's). Without them the auth endpoints
     report `email_unconfigured`.
3. Note the service URL (`https://pesticide-license-server.onrender.com`).
   Optional custom domain: `license.atikur.cyou` — Cloudflare CNAME to the
   Render service, then verify in Render. The app uses ONE base URL; if the
   custom domain is attached, update `API_BASE` in the app's `license.js`
   and in `keygen.html` to match.

## Local dev

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
LICENSE_SIGNING_KEY="$(cat /path/to/private.pem)" \
LICENSE_ADMIN_SECRET="..." python app.py
# server on http://127.0.0.1:5000
```

## Shopkeeper accounts (live since v3.1, passwords + email codes since v3.3)

Accounts live in `psc_users` (full_name, phone, post_office, email, password
hash, banned flag). Trials are one per account (`psc_trials`, keyed by
user_id). Cloud sync of shop data (bills/stock/ledger keyed by `user_id`)
is still a future phase — data stays on the device, with file + Google
Drive backup in the app.
