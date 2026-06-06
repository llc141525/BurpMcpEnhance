# TOOLS/db/cookie_helper.py
"""从 auth_sessions 表读取活跃 cookies，用于 pipeline 工具的 Cookie 头注入。"""

import sqlite3
import sys
from urllib.parse import urlparse


def _domain_matches(cookie_domain: str, request_host: str) -> bool:
    """检查 cookie domain 是否匹配请求 host。支持 .example.com 泛匹配。"""
    cd = cookie_domain.lstrip(".").lower()
    rh = request_host.lower()
    return rh == cd or rh.endswith("." + cd)


def get_auth_cookies_dict(db_path: str, domain: str) -> dict[str, str]:
    """返回匹配 domain 的所有活跃 cookies {name: value}，无匹配返回空 dict。"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1").fetchall()
        conn.close()
    except Exception as e:  # noqa: BLE001
        print(f"[cookie_helper] DB error ({db_path}): {e}", file=sys.stderr)
        return {}

    # 提取 host（去掉端口）
    host = urlparse(domain if "://" in domain else f"http://{domain}").hostname or domain.split(":")[0]

    result = {}
    for row in rows:
        if row["domain"] and _domain_matches(row["domain"], host):
            result[row["token_name"]] = row["token_value"]
    return result


def get_auth_cookie_header(db_path: str, domain: str) -> str | None:
    """返回 'name1=val1; name2=val2' 格式字符串，无匹配返回 None。"""
    d = get_auth_cookies_dict(db_path, domain)
    if not d:
        return None
    return "; ".join(f"{k}={v}" for k, v in d.items())
