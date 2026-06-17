# TOOLS/db/cookie_helper.py
"""从 auth_sessions 表读取活跃 cookies，用于 pipeline 工具的 Cookie 头注入。"""

import sqlite3
import sys
from datetime import datetime
from urllib.parse import urlparse


def _domain_matches(cookie_domain: str, request_host: str) -> bool:
    """检查 cookie domain 是否匹配请求 host。支持 .example.com 泛匹配。"""
    cd = cookie_domain.lstrip(".").lower()
    rh = request_host.lower()
    return rh == cd or rh.endswith("." + cd)


def _path_matches(cookie_path: str, request_path: str) -> bool:
    """检查 cookie path 是否是请求 path 的前缀。"""
    cp = cookie_path or "/"
    rp = request_path or "/"
    if cp == "/":
        return True
    return rp == cp or rp.startswith(cp if cp.endswith("/") else cp + "/")


def _is_expired(expires_at: str | None) -> bool:
    """True if the cookie has a known expiry that is in the past.

    Accepts ISO-format strings (what write_cookies_to_db stores) and unix
    timestamp strings (legacy / Playwright raw format).
    """
    if not expires_at:
        return False
    # Try ISO format first (primary format written by write_cookies_to_db)
    try:
        exp = datetime.fromisoformat(expires_at)
        # Strip timezone so comparison with naive datetime.now() works
        if exp.tzinfo is not None:
            exp = exp.replace(tzinfo=None)
        return exp < datetime.now()
    except (ValueError, TypeError):
        pass
    # Fallback: unix timestamp as float string
    try:
        ts = float(expires_at)
        if ts < 0:
            return False  # session cookie (no expiry)
        return datetime.fromtimestamp(ts) < datetime.now()
    except (ValueError, OSError, OverflowError):
        return False


def get_auth_cookies_dict(
    db_path: str,
    domain: str,
    request_path: str = "/",
    role: str = "primary",
) -> dict[str, str]:
    """返回匹配 domain + path 且未过期的活跃 cookies {name: value}，无匹配返回空 dict。"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT token_name, token_value, domain, path, expires_at
               FROM auth_sessions
               WHERE is_active=1 AND COALESCE(role, 'primary')=?""",
            (role,),
        ).fetchall()
        conn.close()
    except Exception as e:  # noqa: BLE001
        print(f"[cookie_helper] DB error ({db_path}): {e}", file=sys.stderr)
        return {}

    # 提取 host（去掉端口）
    host = urlparse(domain if "://" in domain else f"http://{domain}").hostname or domain.split(":")[0]

    result = {}
    for row in rows:
        if not row["domain"] or not _domain_matches(row["domain"], host):
            continue
        if not _path_matches(row["path"] or "/", request_path):
            continue
        if _is_expired(row["expires_at"]):
            continue
        result[row["token_name"]] = row["token_value"]
    return result


def get_auth_cookie_header(
    db_path: str,
    domain: str,
    request_path: str = "/",
    role: str = "primary",
) -> str | None:
    """返回 'name1=val1; name2=val2' 格式字符串，无匹配返回 None。"""
    d = get_auth_cookies_dict(db_path, domain, request_path, role=role)
    if not d:
        return None
    return "; ".join(f"{k}={v}" for k, v in d.items())
