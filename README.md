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
| POST | `/v1/register-key` | `X-Admin-Secret` | Body `{"install_id"?}` → creates a key, returns `{"key_id","key","install_id"}`. Used by keygen.html. |
| POST | `/v1/activate` | — | Body `{"install_id","key"}` → validates, binds key to install_id on first use, rejects if bound elsewhere. Returns `{"token","install_id","key_id"}`. |
| GET | `/v1/keys` | `X-Admin-Secret` | Lists issued keys + bindings. |
| GET | `/v1/export` | `X-Admin-Secret` | Full backup dump (keys). |
| GET | `/v1/public-key` | — | The RSA public key (same as `public_key.pem` in this repo). |

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

## Future: shopkeeper accounts + cloud sync (NOT in V3)

The storage layer is already designed for it: `psc_license_keys.user_id`
(nullable) and a `psc_users` table with the signup fields — full_name, phone,
post_office (address), email (Gmail). The next phase will add per-account
data tables (bills, stock, ledger rows keyed by `user_id`) so a shopkeeper
who logs back in after a device crash restores everything, plus `/v2/`
account + sync endpoints. Nothing about accounts or sync is implemented
here.
