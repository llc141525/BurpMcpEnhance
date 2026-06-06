"""Session 健康检查 + 过期监控。

用法:
  python3 TOOLS/auth_check.py --target "台州学院"                    # 检查所有活跃 session
  python3 TOOLS/auth_check.py --target "台州学院" --url https://t.com/api/me  # 自定义测试端点
  python3 TOOLS/auth_check.py --target "台州学院" --update           # 检查并更新 is_active
  python3 TOOLS/auth_check.py --target "台州学院" --list             # 仅列出 session 状态
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"

CLASH_PROXY = "http://127.0.0.1:9870"

LOGIN_PAGE_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "logon",
    "请输入密码",
    "请输入用户名",
    "登录",
    "登入",
    "authentication required",
    "unauthorized",
    "会话过期",
    "session expired",
    "请先登录",
    "重新登录",
    "re-login",
]


def find_target_db(target: str) -> str | None:
    matches = sorted(
        DBS_DIR.glob(f"{target}_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return str(matches[0]) if matches else None


def get_sessions(db_path: str, active_only: bool = True) -> list[dict]:
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        sql = "SELECT id, token_type, token_name, token_value, domain, path, is_active, expires_at FROM auth_sessions"
        if active_only:
            sql += " WHERE is_active = 1"
        return [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def update_session(db_path: str, session_id: int, is_active: int, expires_at: str | None = None) -> None:
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE auth_sessions SET is_active = ?, last_checked_at = ?,"
            " expires_at = COALESCE(?, expires_at) WHERE id = ?",
            (is_active, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), expires_at, session_id),
        )
        conn.commit()
    finally:
        conn.close()


def check_session(
    session: dict,
    test_url: str,
    proxy: str,
    timeout: int,
) -> dict:
    """返回 {valid, status_code, reason, response_preview}"""
    sess = requests.Session()
    sess.proxies = {"http": proxy, "https": proxy}
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    token_type = (session.get("token_type") or "cookie").lower()
    token_name = session["token_name"] or ""
    token_value = session["token_value"] or ""

    if not token_value:
        return {"valid": False, "status_code": 0, "reason": "token_value 为空", "response_preview": ""}

    if token_type == "bearer":  # noqa: S105
        sess.headers["Authorization"] = f"Bearer {token_value}"
    else:
        sess.cookies.set(token_name, token_value, domain=session.get("domain") or "", path=session.get("path") or "/")

    try:
        resp = sess.get(test_url, timeout=timeout, allow_redirects=True)
    except Exception as e:
        return {"valid": False, "status_code": 0, "reason": f"请求失败: {e}", "response_preview": ""}

    body_lower = resp.text[:2000].lower()
    redirected_to_login = False

    # 302 重定向到登录页
    for r in resp.history:
        rloc = (r.headers.get("Location") or "").lower()
        if any(kw in rloc for kw in ("login", "signin", "auth", "sso")):
            redirected_to_login = True
            break

    # 401/403
    if resp.status_code in (401, 403):
        return {
            "valid": False,
            "status_code": resp.status_code,
            "reason": f"HTTP {resp.status_code}",
            "response_preview": resp.text[:200],
        }

    # 重定向到登录
    if redirected_to_login:
        return {
            "valid": False,
            "status_code": resp.status_code,
            "reason": "重定向到登录页",
            "response_preview": str(resp.history[0].headers.get("Location", "")),
        }

    # 响应体含登录关键词
    if any(kw in body_lower for kw in LOGIN_PAGE_KEYWORDS):
        return {
            "valid": False,
            "status_code": resp.status_code,
            "reason": "响应体含登录关键词",
            "response_preview": resp.text[:200],
        }

    return {
        "valid": True,
        "status_code": resp.status_code,
        "reason": "OK",
        "response_preview": resp.text[:200],
    }


def main():
    parser = argparse.ArgumentParser(description="Session 健康检查 + 过期监控")
    parser.add_argument("--target", required=True, help="目标名称")
    parser.add_argument("--url", help="测试端点 URL（默认用 session 的 domain 根路径）")
    parser.add_argument("--update", action="store_true", help="检查后将结果写入 DB (is_active, last_checked_at)")
    parser.add_argument("--list", action="store_true", help="仅列出 session 状态，不发请求")
    parser.add_argument("--proxy", default=CLASH_PROXY, help="代理地址")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时 (默认 10s)")
    args = parser.parse_args()

    db_path = find_target_db(args.target)
    if db_path is None:
        print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False))
        sys.exit(1)

    sessions = get_sessions(db_path)

    if not sessions:
        print(json.dumps({"msg": "无活跃 session", "target": args.target}, ensure_ascii=False))
        return

    if args.list:
        now = datetime.now()
        for s in sessions:
            exp = s.get("expires_at")
            expired = False
            if exp:
                try:
                    expired = datetime.strptime(exp, "%Y-%m-%d %H:%M:%S") < now
                except ValueError:
                    pass
            s["_expired"] = expired
        print(json.dumps({"sessions": sessions}, ensure_ascii=False, indent=2))
        return

    results = []
    for s in sessions:
        test_url = args.url or f"https://{s['domain']}{s.get('path', '/')}" if s.get("domain") else None
        if not test_url:
            results.append({"session_id": s["id"], "error": "无测试 URL，请用 --url 指定"})
            continue

        print(f"[{s['id']}] 检查 {test_url} ...", file=sys.stderr)
        check = check_session(s, test_url, args.proxy, args.timeout)
        entry = {
            "session_id": s["id"],
            "token_name": s["token_name"],
            "token_type": s.get("token_type", "cookie"),
            "domain": s.get("domain"),
            "valid": check["valid"],
            "status_code": check["status_code"],
            "reason": check["reason"],
        }
        results.append(entry)

        if args.update:
            update_session(db_path, s["id"], 1 if check["valid"] else 0)
            entry["db_updated"] = True

    print(json.dumps({"target": args.target, "results": results}, ensure_ascii=False, indent=2))

    valid = sum(1 for r in results if r.get("valid"))
    invalid = len(results) - valid
    print(f"\n有效: {valid}, 过期/无效: {invalid}", file=sys.stderr)


if __name__ == "__main__":
    main()
