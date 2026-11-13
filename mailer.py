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

Connection attempts, in order (first success wins):
  1. The host's IPv4 addresses on SMTP_PORT with STARTTLS. Some hosts
     have no IPv6 route and the default resolution order can fail the
     whole connection with "Network is unreachable" — connecting to an
     IPv4 address directly avoids that. TLS still validates the
     hostname's certificate (see _send_starttls).
  2. The hostname itself on SMTP_PORT with STARTTLS (default behavior).
  3. The hostname on port 465 with implicit TLS, in case the STARTTLS
     port is filtered. Skipped when SMTP_PORT is already 465.
Each attempt has a short timeout so a blackholed route fails fast.
"""
import os
import smtplib
import socket
import ssl
from email.message import EmailMessage

_ATTEMPT_TIMEOUT = 8
_MAX_IPV4_ATTEMPTS = 2


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


def _ipv4_addresses(host, port):
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    seen, out = set(), []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _send_starttls(connect_host, port, host, user, password, msg):
    ctx = ssl.create_default_context()
    with smtplib.SMTP(connect_host, port, timeout=_ATTEMPT_TIMEOUT) as smtp:
        if connect_host != host:
            # Connecting by IP: smtplib uses _host for TLS SNI + cert
            # validation, so point it at the hostname, not the IP.
            smtp._host = host
        smtp.starttls(context=ctx)
        smtp.login(user, password)
        smtp.send_message(msg)


def _send_ssl(host, port, user, password, msg):
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, timeout=_ATTEMPT_TIMEOUT, context=ctx) as smtp:
        smtp.login(user, password)
        smtp.send_message(msg)


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

    attempts = []
    for ip in _ipv4_addresses(host, port)[:_MAX_IPV4_ATTEMPTS]:
        attempts.append(("ipv4:%s:%d" % (ip, port),
                         lambda ip=ip: _send_starttls(ip, port, host, user, password, msg)))
    attempts.append(("host:%s:%d" % (host, port),
                     lambda: _send_starttls(host, port, host, user, password, msg)))
    if port != 465:
        attempts.append(("ssl:%s:465" % host,
                         lambda: _send_ssl(host, 465, user, password, msg)))
    errors = []
    for label, fn in attempts:
        try:
            fn()
            return True, None
        except Exception as exc:  # never log the code or the credentials
            errors.append("%s: %s" % (label, exc))
    print("SMTP send failed: %s" % " | ".join(errors), flush=True)
    return False, "send_failed"
