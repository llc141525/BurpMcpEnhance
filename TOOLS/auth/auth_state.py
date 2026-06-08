"""共享认证态捕获与导出工具。"""

from __future__ import annotations

import argparse
import base64
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import find_db  # noqa: E402

TOKEN_NAME_RE = ("token", "auth", "jwt", "bearer", "csrf", "xsrf", "api_key", "apikey", "secret")


def _from_unix_ts(ts: Any) -> str | None:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, TypeError, ValueError):
        return None


def _is_jwt_like(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return all(parts[:2])


def _jwt_expiry(value: str) -> str | None:
    if not _is_jwt_like(value):
        return None
    try:
        payload = value.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        return _from_unix_ts(decoded.get("exp"))
    except Exception:  # noqa: BLE001
        return None


def classify_token_kind(name: str, value: str) -> str:
    """Conservatively classify a storage/cookie value."""
    lname = name.lower()
    stripped = value.strip()
    if stripped.lower().startswith("bearer "):
        return "bearer"
    if _is_jwt_like(stripped):
        return "jwt"
    if "csrf" in lname or "xsrf" in lname:
        return "csrf"
    if "api_key" in lname or "apikey" in lname or lname.endswith("key"):
        return "api_key"
    return "storage"


def _is_security_relevant_storage(name: str, value: str) -> bool:
    if not value or len(value) > 8192:
        return False
    lname = name.lower()
    return any(part in lname for part in TOKEN_NAME_RE) or classify_token_kind(name, value) != "storage"


def storage_items_to_tokens(
    origin: str,
    storage_type: str,
    items: dict[str, str],
    role: str = "primary",
) -> list[dict[str, Any]]:
    """Convert localStorage/sessionStorage key-values into DB token rows."""
    tokens = []
    for name, value in items.items():
        if not _is_security_relevant_storage(name, value):
            continue
        kind = classify_token_kind(name, value)
        raw_value = value.strip()
        if raw_value.lower().startswith("bearer "):
            expires_at = _jwt_expiry(raw_value.split(None, 1)[1])
        else:
            expires_at = _jwt_expiry(raw_value)
        tokens.append(
            {
                "role": role,
                "storage_type": storage_type,
                "origin": origin,
                "token_name": name,
                "token_value": value,
                "token_kind": kind,
                "expires_at": expires_at,
            }
        )
    return tokens


def cookies_to_auth_session_rows(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize Playwright cookies into auth_sessions-compatible rows."""
    rows = []
    for cookie in cookies:
        rows.append(
            {
                "token_name": cookie.get("name", ""),
                "token_value": cookie.get("value", ""),
                "domain": cookie.get("domain", ""),
                "path": cookie.get("path", "/"),
                "expires_at": _from_unix_ts(cookie.get("expires")),
                "cookie_source": "cdp_capture",
            }
        )
    return rows


def upsert_storage_tokens(conn: sqlite3.Connection, tokens: list[dict[str, Any]]) -> int:
    """Upsert storage-backed tokens into auth_storage_tokens."""
    count = 0
    for token in tokens:
        cur = conn.execute(
            """INSERT INTO auth_storage_tokens
               (role, storage_type, origin, token_name, token_value, token_kind, expires_at, source, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'cdp_capture', 1)
               ON CONFLICT(role, storage_type, origin, token_name) DO UPDATE SET
                 token_value=excluded.token_value,
                 token_kind=excluded.token_kind,
                 expires_at=excluded.expires_at,
                 is_active=1,
                 last_seen_at=datetime('now','localtime')""",
            (
                token.get("role", "primary"),
                token["storage_type"],
                token["origin"],
                token["token_name"],
                token["token_value"],
                token.get("token_kind", "storage"),
                token.get("expires_at"),
            ),
        )
        count += cur.rowcount
    conn.commit()
    return count


def upsert_auth_session_rows(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    count = 0
    for row in rows:
        cur = conn.execute(
            """INSERT INTO auth_sessions
               (token_type, token_name, token_value, domain, path, expires_at, is_active, cookie_source)
               VALUES ('cookie', ?, ?, ?, ?, ?, 1, ?)
               ON CONFLICT(token_name, domain) DO UPDATE SET
                 token_value=excluded.token_value,
                 path=excluded.path,
                 expires_at=excluded.expires_at,
                 is_active=1,
                 cookie_source=excluded.cookie_source,
                 last_checked_at=datetime('now','localtime')""",
            (
                row["token_name"],
                row["token_value"],
                row["domain"],
                row.get("path", "/"),
                row.get("expires_at"),
                row.get("cookie_source", "cdp_capture"),
            ),
        )
        count += cur.rowcount
    conn.commit()
    return count


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _origin_from_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


async def _capture_browser_state(cdp_url: str, seed_url: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from patchright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(cdp_url)
        context = browser.contexts[0] if browser.contexts else await browser.new_context()
        pages = context.pages
        parsed_seed = urlparse(seed_url)
        page = next((pg for pg in pages if urlparse(pg.url).netloc == parsed_seed.netloc), None)
        if page is None:
            page = await context.new_page()
            await page.goto(seed_url, wait_until="domcontentloaded", timeout=30000)

        cookies = await context.cookies()
        storage_tokens: list[dict[str, Any]] = []
        for pg in context.pages:
            if not pg.url.startswith("http"):
                continue
            origin = _origin_from_url(pg.url)
            try:
                local_items = await pg.evaluate(
                    "() => Object.fromEntries(Array.from({length: localStorage.length}, (_, i) => "
                    "[localStorage.key(i), localStorage.getItem(localStorage.key(i))]))"
                )
                session_items = await pg.evaluate(
                    "() => Object.fromEntries(Array.from({length: sessionStorage.length}, (_, i) => "
                    "[sessionStorage.key(i), sessionStorage.getItem(sessionStorage.key(i))]))"
                )
            except Exception:  # noqa: BLE001,S112
                continue
            storage_tokens.extend(storage_items_to_tokens(origin, "localStorage", local_items or {}))
            storage_tokens.extend(storage_items_to_tokens(origin, "sessionStorage", session_items or {}))

    return cookies, storage_tokens


def capture_to_db(target: str, db_path: str | Path, cdp_url: str | None = None, seed_url: str | None = None) -> dict:
    """Capture cookies and storage tokens from CDP and persist them."""
    import asyncio

    conn = _connect(db_path)
    try:
        state = conn.execute("SELECT seed_url, cdp_url FROM scan_state WHERE id=1").fetchone()
        seed = seed_url or (state["seed_url"] if state else None)
        cdp = cdp_url or (state["cdp_url"] if state else None) or "http://localhost:9222"
        if not seed:
            target_row = conn.execute("SELECT domain FROM targets LIMIT 1").fetchone()
            if target_row and target_row["domain"]:
                domain = target_row["domain"]
                seed = domain if domain.startswith("http") else "https://" + domain
        if not seed:
            raise ValueError(f"missing seed_url for {target}")

        cookies, storage_tokens = asyncio.run(_capture_browser_state(cdp, seed))
        cookie_rows = cookies_to_auth_session_rows(cookies)
        cookie_count = upsert_auth_session_rows(conn, cookie_rows)
        token_count = upsert_storage_tokens(conn, storage_tokens)
        return {"cookies": cookie_count, "storage_tokens": token_count}
    finally:
        conn.close()


def export_header(target: str, url: str) -> dict[str, str]:
    db_path = find_db(target)
    if not db_path:
        raise FileNotFoundError(target)
    host = urlparse(url).netloc
    conn = _connect(db_path)
    try:
        cookies = conn.execute(
            "SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1 AND token_type='cookie'"
        ).fetchall()
        parts = [
            f"{row['token_name']}={row['token_value']}"
            for row in cookies
            if host == row["domain"].lstrip(".") or host.endswith(row["domain"].lstrip("."))
        ]
        headers = {"Cookie": "; ".join(parts)} if parts else {}
        bearer = conn.execute(
            """SELECT token_value FROM auth_storage_tokens
               WHERE is_active=1 AND token_kind IN ('bearer','jwt')
               ORDER BY last_seen_at DESC LIMIT 1"""
        ).fetchone()
        if bearer:
            value = bearer["token_value"]
            headers["Authorization"] = value if value.lower().startswith("bearer ") else f"Bearer {value}"
        return headers
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CDP auth state capture/export")
    sub = parser.add_subparsers(dest="cmd", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--target", required=True)
    capture.add_argument("--cdp-url", default=None)
    capture.add_argument("--seed-url", default=None)
    export = sub.add_parser("export-header")
    export.add_argument("--target", required=True)
    export.add_argument("--url", required=True)
    args = parser.parse_args()

    if args.cmd == "capture":
        db_path = find_db(args.target)
        if not db_path:
            sys.exit(f"[auth_state] 未找到目标 DB: {args.target}")
        counts = capture_to_db(args.target, db_path, args.cdp_url, args.seed_url)
        print(json.dumps(counts, ensure_ascii=False))
    elif args.cmd == "export-header":
        print(json.dumps(export_header(args.target, args.url), ensure_ascii=False))


if __name__ == "__main__":
    main()
