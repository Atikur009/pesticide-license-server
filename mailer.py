"""OTP emails for the Pesticide Shop Calculator license server.

Sends the 6-digit verification code via SMTP. Configuration lives ONLY in
Render env vars (never in the repo):
  SMTP_HOST          — default smtp.gmail.com
  SMTP_PORT          — default 587 (STARTTLS)
  SMTP_USER          — the Gmail address that sends the codes
  SMTP_APP_PASSWORD  — a Gmail app password (NOT the account password)
  SMTP_FROM          — optional From address; defaults to SMTP_USER

Without SMTP_USER + SMTP_APP_PASSWORD the server reports email_unconfigured
and no code is issued — accounts are never created half-verified.
Codes are never logged.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage


def smtp_configured():
    return bool(os.environ.get("SMTP_USER") and os.environ.get("SMTP_APP_PASSWORD"))


_SUBJECTS = {
    "signup": "Pesticide Shop Calculator — যাচাইকরণ কোড",
    "login": "Pesticide Shop Calculator — লগইন কোড",
    "reset": "Pesticide Shop Calculator — পাসওয়ার্ড বদলের কোড",
}

_INTROS = {
    "signup": "অ্যাকাউন্ট খুলতে নিচের কোডটি লিখুন।",
    "login": "লগইন করতে নিচের কোডটি লিখুন।",
    "reset": "পাসওয়ার্ড বদলাতে নিচের কোডটি লিখুন।",
}


def send_code_email(to_email, code, purpose):
    """Send the verification code. Returns (True, None) or (False, reason)
    where reason is 'not_configured' or 'send_failed'."""
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_APP_PASSWORD")
    if not user or not password:
        return False, "not_configured"
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        port = 587
    sender = os.environ.get("SMTP_FROM") or user
    intro = _INTROS.get(purpose, _INTROS["login"])
    body = (
        "আসসালামু আলাইকুম,\n\n"
        "%s\n\n"
        "আপনার কোড: %s\n\n"
        "এই কোডটি ১০ মিনিট পর্যন্ত চলবে। কোডটি কাউকে দেবেন না — "
        "আতিকুরও কখনো আপনার কোড চাইবেন না।\n\n"
        "— Pesticide Shop Calculator\n"
        % (intro, code)
    )
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = _SUBJECTS.get(purpose, _SUBJECTS["login"])
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            smtp.login(user, password)
            smtp.send_message(msg)
        return True, None
    except Exception as exc:  # never log the code or the recipient's secret
        print("SMTP send failed: %s" % exc, flush=True)
        return False, "send_failed"
