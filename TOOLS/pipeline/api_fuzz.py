# TOOLS/pipeline/api_fuzz.py
"""API 命名空间爆破：词列+模式推断探测隐藏 admin/teacher API，写入 hunt_queue。

用法:
  uv run python TOOLS/pipeline/api_fuzz.py --target "台州学院"
  uv run python TOOLS/pipeline/api_fuzz.py --target "台州学院" --delay 2.0 --max-rotations 5

输出:
  [API_FUZZ] probed={n} found={m} waf_rotations={k}
"""

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.waf_rotate import RotatingFetcher, is_clash_alive  # noqa: E402

BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

ADMIN_NAMESPACE_PATHS = [
    "/api/admin",
    "/api/admin/users",
    "/api/admin/list",
    "/api/admin/info",
    "/api/manage",
    "/api/management",
    "/api/manager",
    "/api/staff",
    "/api/internal",
    "/api/system",
    "/api/backstage",
    "/api/console",
    "/api/superadmin",
    "/api/privileged",
    "/api/teacher",
    "/api/teacher/list",
    "/api/teacher/course",
    "/api/instructor",
    "/api/tutor",
    "/api/faculty",
    "/api/v1/admin",
    "/api/v1/teacher",
    "/api/v1/manage",
    "/api/v1/staff",
    "/api/v2/admin",
    "/api/v2/teacher",
    "/api/v2/manage",
    "/admin/api",
    "/admin/api/users",
    "/admin/api/list",
    "/manage/api",
    "/teacher/api",
    "/system/api",
    "/console/api",
    "/api/jiaoshi",
    "/api/guanli",
    "/api/xitong",
    "/api/jiaowu",
]

ADMIN_STEMS = ["admin", "teacher", "manage", "staff", "system", "internal", "instructor"]

_ROLE_SRC_WORDS = ("student", "user", "member", "xuesheng", "xsgl", "tongxue")


def extract_known_api_paths(conn: sqlite3.Connection) -> list[str]:
    """从 DB 聚合所有已知 API 路径（pages + js_files + suspicious_points）。"""
    paths: list[str] = []

    rows = conn.execute("SELECT api_calls_json FROM pages WHERE api_calls_json IS NOT NULL").fetchall()
    for row in rows:
        raw = row[0] if isinstance(row, tuple) else row["api_calls_json"]
        try:
            calls = json.loads(raw)
            if isinstance(calls, list):
                paths.extend(c.get("url", "") for c in calls if isinstance(c, dict) and c.get("url"))
            elif isinstance(calls, dict):
                paths.extend(str(v) for v in calls.values() if v)
        except (json.JSONDecodeError, AttributeError):
            pass

    try:
        rows2 = conn.execute(
            "SELECT discovered_apis_json FROM js_files WHERE analyzed=1 AND discovered_apis_json IS NOT NULL"
        ).fetchall()
        for row in rows2:
            raw = row[0] if isinstance(row, tuple) else row["discovered_apis_json"]
            try:
                apis = json.loads(raw)
                if isinstance(apis, list):
                    paths.extend(str(a) for a in apis if a)
            except (json.JSONDecodeError, AttributeError):
                pass
    except sqlite3.OperationalError:
        pass

    try:
        rows3 = conn.execute("SELECT DISTINCT url FROM suspicious_points WHERE url IS NOT NULL").fetchall()
        paths.extend(row[0] if isinstance(row, tuple) else row["url"] for row in rows3)
    except sqlite3.OperationalError:
        pass

    return [p for p in paths if p and isinstance(p, str)]


def derive_prefixes(paths: list[str]) -> list[str]:
    """从已知路径推导 API base prefix（如 /api/v1/）。"""
    if not paths:
        return ["/api/"]

    candidates: list[str] = []
    for p in paths:
        path_part = urlparse(p).path if ("://" in p) else p
        parts = [x for x in path_part.split("/") if x]
        for depth in (2, 3):
            if len(parts) >= depth:
                candidates.append("/" + "/".join(parts[:depth]) + "/")

    if not candidates:
        return ["/api/"]

    counts = Counter(candidates)
    top = [prefix for prefix, cnt in counts.most_common(5) if cnt >= 2]
    return top if top else ["/api/"]


def build_probe_list(conn: sqlite3.Connection, base_url: str) -> list[str]:
    """Tier1 内嵌词列 + Tier2 动态推导，去重后返回完整 URL 列表。"""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    known_paths: set[str] = set()
    for table, col in (("pages", "url"), ("hunt_queue", "url")):
        try:
            for row in conn.execute(f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL").fetchall():  # noqa: S608
                u = row[0] if isinstance(row, tuple) else row[col]
                if u:
                    known_paths.add(urlparse(u).path)
        except sqlite3.OperationalError:
            pass

    candidate_paths: set[str] = set(ADMIN_NAMESPACE_PATHS)

    known_api_paths = extract_known_api_paths(conn)
    prefixes = derive_prefixes(known_api_paths)

    for prefix in prefixes:
        for stem in ADMIN_STEMS:
            candidate_paths.add(f"{prefix.rstrip('/')}/{stem}")

    for p in known_api_paths:
        path_part = urlparse(p).path if ("://" in p) else p
        for src in _ROLE_SRC_WORDS:
            if f"/{src}/" in path_part or path_part.endswith(f"/{src}"):
                for stem in ADMIN_STEMS:
                    replaced = path_part.replace(f"/{src}/", f"/{stem}/").replace(f"/{src}", f"/{stem}")
                    if replaced != path_part:
                        candidate_paths.add(replaced)

    result = [f"{origin}{path}" for path in sorted(candidate_paths) if path not in known_paths]
    return result


def classify_response(auth_code: int, unauth_code: int) -> tuple[str, str] | None:
    """(auth_code, unauth_code) → (business_intent, risk_hint) 或 None（跳过）。"""
    SUCCESS = {200, 201, 204}
    FORBIDDEN = {401, 403}
    ERROR = {500, 502}

    if unauth_code in SUCCESS:
        return "unauth_admin_access", "Critical"
    if unauth_code in FORBIDDEN and auth_code in SUCCESS:
        return "vertical_priv_esc", "High"
    if auth_code in FORBIDDEN:
        return "admin_403_probe", "Medium"
    if auth_code in ERROR or unauth_code in ERROR:
        return "server_error_probe", "Medium"
    return None


def probe_url(
    url: str,
    primary_cookie: str | None,
    fetcher: RotatingFetcher,
    delay: float,
) -> tuple[int, int]:
    """发两次请求（带 auth + 不带 auth），返回 (auth_code, unauth_code)。"""

    def _get(cookie: str | None) -> requests.Response:
        headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
        if cookie:
            headers["Cookie"] = cookie
        return requests.get(url, headers=headers, proxies=BURP_PROXY, timeout=10, verify=False)  # noqa: S501

    auth_code = 0
    unauth_code = 0

    try:
        resp, _, _ = fetcher.fetch_with_rotation(lambda: _get(primary_cookie))
        if isinstance(resp, requests.Response):
            auth_code = resp.status_code
    except Exception:  # noqa: S110
        pass
    time.sleep(delay)

    try:
        resp, _, _ = fetcher.fetch_with_rotation(lambda: _get(None))
        if isinstance(resp, requests.Response):
            unauth_code = resp.status_code
    except Exception:  # noqa: S110
        pass
    time.sleep(delay)

    return auth_code, unauth_code


def write_to_hunt_queue(
    conn: sqlite3.Connection,
    target_id: int,
    url: str,
    business_intent: str,
    risk_hint: str,
    auth_code: int,
    unauth_code: int,
) -> bool:
    """写入 hunt_queue，返回 True 表示新插入。"""
    notes = f"api_fuzz | auth={auth_code} unauth={unauth_code}"
    try:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO hunt_queue
               (target_id, method, url, query_string, endpoint_type, business_intent,
                risk_hint, status, source, notes)
               VALUES (?, 'GET', ?, '', 'admin_api', ?, ?, 'queued', 'auto', ?)""",
            (target_id, url, business_intent, risk_hint, notes),
        )
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"  [warn] hunt_queue 写入失败 {url}: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="API 命名空间爆破：探测隐藏 admin/teacher API")
    parser.add_argument("--target", required=True)
    parser.add_argument("--delay", type=float, default=1.5, help="请求间隔秒数（默认 1.5）")
    parser.add_argument(
        "--max-rotations", type=int, default=3, dest="max_rotations", help="WAF 触发最大换 IP 次数（默认 3）"
    )
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

    if not is_clash_alive():
        print("[warn] Clash 不可达，将在无 IP 轮换的情况下继续探测")

    row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_url = row["seed_url"] if row else None
    if not seed_url:
        print("[error] DB 中无 seed_url，请先运行 init_scan.py", file=sys.stderr)
        conn.close()
        sys.exit(1)

    target_row = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()
    target_id: int = target_row["id"] if target_row else 1

    primary_cookie = get_auth_cookie_header(str(db_path), seed_url, role="primary")
    if not primary_cookie:
        print("[warn] 无 primary session，仅发 unauth 请求")

    probe_list = build_probe_list(conn, seed_url)
    print(f"[api_fuzz] 探测列表: {len(probe_list)} 个 URL  delay={args.delay}s  max_rotations={args.max_rotations}")

    fetcher = RotatingFetcher(max_rotations=args.max_rotations, rotate_delay=30.0)
    found = 0
    total_rotations = 0

    for url in probe_list:
        auth_code, unauth_code = probe_url(url, primary_cookie, fetcher, args.delay)
        total_rotations += len(fetcher.rotation_log)
        fetcher.rotation_log.clear()

        result = classify_response(auth_code, unauth_code)
        if result is None:
            continue

        business_intent, risk_hint = result
        inserted = write_to_hunt_queue(conn, target_id, url, business_intent, risk_hint, auth_code, unauth_code)
        if inserted:
            found += 1
            marker = {"Critical": "[!!!]", "High": "[!! ]", "Medium": "[ ! ]"}.get(risk_hint, "[   ]")
            print(f"  {marker} {risk_hint:8s} {url}  auth={auth_code} unauth={unauth_code}")

    conn.close()
    print(f"\n[API_FUZZ] probed={len(probe_list)} found={found} waf_rotations={total_rotations}")


if __name__ == "__main__":
    main()
