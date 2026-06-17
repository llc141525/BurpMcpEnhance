# TOOLS/pipeline/xss_scan.py
"""存储型 XSS 检测：表单 text/textarea 注入唯一 beacon，重新 fetch 验证未转义反射。

用法:
  uv run python TOOLS/pipeline/xss_scan.py --target "台州学院"

输出:
  [XSS_SCAN] targets={n} tested={m} found_stored={k} found_reflected={j}
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.waf_rotate import RotatingFetcher  # noqa: E402

BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

XSS_SKIP_TYPES: frozenset[str] = frozenset(
    {
        "hidden",
        "submit",
        "button",
        "checkbox",
        "radio",
        "file",
        "password",
        "image",
        "reset",
        "color",
        "range",
    }
)

XSS_SKIP_NAMES: frozenset[str] = frozenset(
    {
        "_token",
        "csrf",
        "__requestverificationtoken",
        "authenticity_token",
    }
)


def build_beacon(uid: str) -> str:
    """返回含唯一标识符的 XSS payload。"""
    return f"<img src=x id=xssbeacon_{uid} onerror=this.src>"


def beacon_in_response(beacon_uid: str, html: str) -> bool:
    """True if the beacon tag appears unescaped in html."""
    marker = f"id=xssbeacon_{beacon_uid}"
    if marker not in html:
        return False
    idx = html.find(marker)
    # Look back far enough to find the opening tag character (e.g. "<img src=x ...")
    # The marker is preceded by something like "<img src=x " (12+ chars) or its escaped form.
    prefix = html[max(0, idx - 50) : idx]
    return "&lt;" not in prefix


def find_xss_targets(conn: sqlite3.Connection) -> list[dict]:
    """从 pages.forms_json 找 text/textarea 类型的 input，返回探测目标列表。"""
    targets: list[dict] = []
    seen: set[tuple[str, str]] = set()

    rows = conn.execute(
        "SELECT url, forms_json FROM pages WHERE forms_json IS NOT NULL AND status='visited'"
    ).fetchall()

    for row in rows:
        page_url = row[0] if isinstance(row, tuple) else row["url"]
        forms_raw = row[1] if isinstance(row, tuple) else row["forms_json"]
        if not forms_raw:
            continue
        try:
            forms = json.loads(forms_raw)
        except (json.JSONDecodeError, TypeError):
            continue

        for form in forms:
            action = form.get("action", page_url) or page_url
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            for inp in inputs:
                itype = inp.get("type", "text").lower()
                iname = inp.get("name", "")
                itag = inp.get("tag", "input").lower()
                hidden = inp.get("hidden", False)

                if hidden or itype in XSS_SKIP_TYPES:
                    continue
                if iname.lower() in XSS_SKIP_NAMES:
                    continue
                if not iname:
                    continue
                if itag not in ("input", "textarea"):
                    continue

                key = (action, iname)
                if key not in seen:
                    seen.add(key)
                    targets.append(
                        {
                            "page_url": page_url,
                            "form_action": action,
                            "form_method": method,
                            "param": iname,
                            "all_inputs": inputs,
                        }
                    )

    return targets


def _build_form_data(inputs: list[dict], target_param: str, payload: str) -> dict[str, str]:
    """Build form submission dict, injecting payload only into target_param."""
    data: dict[str, str] = {}
    for inp in inputs:
        iname = inp.get("name", "")
        itype = inp.get("type", "text").lower()
        ival = inp.get("value", "")
        if not iname or itype in ("submit", "button", "image", "reset"):
            continue
        data[iname] = payload if iname == target_param else (ival or "test")
    return data


def submit_form(
    form_action: str,
    method: str,
    form_data: dict[str, str],
    cookie: str | None,
    fetcher: RotatingFetcher,
    delay: float,
) -> tuple[int, str]:
    """Submit form; returns (status_code, response_body[:8192])."""
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        headers["Cookie"] = cookie

    def _submit() -> requests.Response:
        if method == "POST":
            return requests.post(  # noqa: S113
                form_action,
                data=form_data,
                headers=headers,
                proxies=BURP_PROXY,
                timeout=10,
                verify=False,  # noqa: S501
            )
        return requests.get(  # noqa: S113
            form_action,
            params=form_data,
            headers=headers,
            proxies=BURP_PROXY,
            timeout=10,
            verify=False,  # noqa: S501
        )

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_submit)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.status_code, resp.text[:8192]
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] form submit failed: {exc}", file=sys.stderr)
    time.sleep(delay)
    return 0, ""


def fetch_page(url: str, cookie: str | None, fetcher: RotatingFetcher, delay: float) -> str:
    """Fetch a page and return body[:16384]."""
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        headers["Cookie"] = cookie

    def _get() -> requests.Response:
        return requests.get(  # noqa: S113
            url,
            headers=headers,
            proxies=BURP_PROXY,
            timeout=10,
            verify=False,  # noqa: S501
        )

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_get)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.text[:16384]
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] fetch failed: {exc}", file=sys.stderr)
    time.sleep(delay)
    return ""


def write_xss_sp(
    conn: sqlite3.Connection,
    url: str,
    param: str,
    beacon_uid: str,
    page_url: str,
    is_stored: bool,
) -> bool:
    """写 suspicious_points；URL+param+test_type 组合去重；返回是否新插入。"""
    sp_id = f"SP-XSS-{uuid.uuid4().hex[:8]}"
    risk = "High" if is_stored else "Low"
    xss_type = "stored_xss" if is_stored else "reflected_xss"
    evidence = f"beacon_uid={beacon_uid} found_in={'page_url' if is_stored else 'same_response'}"
    reasoning = (
        f"存储型 XSS：提交表单 {url} param={param}，在 {page_url} 发现未转义反射"
        if is_stored
        else f"反射型 XSS（低置信度）：param={param}"
    )
    try:
        existing = conn.execute(
            "SELECT id FROM suspicious_points WHERE url=? AND param=? AND test_type=?",
            (url, param, xss_type),
        ).fetchone()
        if existing:
            return False
        conn.execute(
            """INSERT INTO suspicious_points
               (id, url, param, method, test_type, evidence, source, reasoning,
                risk, test_status, created_at)
               VALUES (?, ?, ?, 'POST', ?, ?, 'xss_scan', ?, ?, 'untested', ?)""",
            (
                sp_id,
                url,
                param,
                xss_type,
                evidence,
                reasoning,
                risk,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"  [warn] SP 写入失败: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="存储型 XSS 检测")
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

    cookie = get_auth_cookie_header(str(db_path), seed_url, role="primary")
    xss_targets = find_xss_targets(conn)
    print(f"[xss_scan] 目标: {len(xss_targets)} 个表单字段  delay={args.delay}s")

    fetcher = RotatingFetcher(max_rotations=args.max_rotations, rotate_delay=30.0)
    found_stored = 0
    found_reflected = 0
    tested = 0

    for target in xss_targets:
        uid = uuid.uuid4().hex[:8]
        beacon = build_beacon(uid)
        form_data = _build_form_data(target["all_inputs"], target["param"], beacon)

        status, body = submit_form(
            target["form_action"],
            target["form_method"],
            form_data,
            cookie,
            fetcher,
            args.delay,
        )
        tested += 1

        if status == 0:
            continue

        if beacon_in_response(uid, body):
            write_xss_sp(conn, target["form_action"], target["param"], uid, target["form_action"], is_stored=False)
            found_reflected += 1
            print(f"  [ ! ] Reflected XSS (low conf): {target['form_action']} param={target['param']}")
            continue

        stored_body = fetch_page(target["page_url"], cookie, fetcher, args.delay)
        if beacon_in_response(uid, stored_body):
            write_xss_sp(conn, target["form_action"], target["param"], uid, target["page_url"], is_stored=True)
            found_stored += 1
            action = target["form_action"]
            param = target["param"]
            found_at = target["page_url"]
            print(f"  [!!!] Stored XSS: submit={action} param={param} found_at={found_at}")

    conn.close()
    n = len(xss_targets)
    print(f"\n[XSS_SCAN] targets={n} tested={tested} found_stored={found_stored} found_reflected={found_reflected}")


if __name__ == "__main__":
    main()
