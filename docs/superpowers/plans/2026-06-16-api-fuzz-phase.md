# API Fuzz Phase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 stealth-scanner 的 `probe` 阶段之后插入新的 `api_fuzz` 阶段，用内嵌词列 + 模式推断主动探测隐藏 admin/teacher API，结果写入 `hunt_queue`，由 business-logic-hunt 自然消费。

**Architecture:** `run_scan.py` 在 probe 结束后切换到 `api_fuzz` phase，调用 `pipeline/api_fuzz.py`；脚本从 DB 提取已知 API 路径推导 prefix，拼接 Tier1 内嵌词列 + Tier2 动态替换，用 `RotatingFetcher`（1.5s/req，WAF 命中自动换 IP + 30s 冷却）逐一探测，分类响应后写入 `hunt_queue`；`api_fuzz` 完成后自动切换到 `exploit`。

**Tech Stack:** Python 3.12+, requests, sqlite3, `TOOLS/utils/waf_rotate.RotatingFetcher`, `TOOLS/db/cookie_helper.get_auth_cookie_header`, `TOOLS/db/db_utils.{connect,find_db}`

---

## File Map

| 路径 | 操作 | 职责 |
|------|------|------|
| `TOOLS/pipeline/api_fuzz.py` | 新建 | 主逻辑：提取路径 → 构建探测列表 → RotatingFetcher 探测 → 写 hunt_queue |
| `TOOLS/tests/test_api_fuzz.py` | 新建 | 单元测试：derive_prefixes / classify_response / write_to_hunt_queue / build_probe_list |
| `TOOLS/run_scan.py` | 修改 | probe_next_phase() 返回 'api_fuzz'；新增 handle_api_fuzz()；更新 HANDLERS |
| `TOOLS/tests/test_run_scan.py` | 修改 | 第 158 行断言从 "exploit" 改为 "api_fuzz" |
| `.claude/skills/stealth-scanner/SKILL.md` | 修改 | 状态机表格 + 输出标签表加 api_fuzz 行 |

---

## Task 1: 编写 test_api_fuzz.py（TDD RED 阶段）

**Files:**
- Create: `TOOLS/tests/test_api_fuzz.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_api_fuzz.py
"""api_fuzz.py 单元测试。"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.api_fuzz import (
    build_probe_list,
    classify_response,
    derive_prefixes,
    extract_known_api_paths,
    write_to_hunt_queue,
)


# ── Fixture ───────────────────────────────────────────────────────────────────


@pytest.fixture
def conn():
    """内存 DB，含 hunt_queue / pages / js_files / suspicious_points / targets / scan_state。"""
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT
        );
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            seed_url TEXT,
            phase TEXT DEFAULT 'api_fuzz'
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            depth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued',
            api_calls_json TEXT,
            source TEXT
        );
        CREATE TABLE js_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            analyzed INTEGER DEFAULT 0,
            discovered_apis_json TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT,
            test_type TEXT,
            source TEXT,
            risk TEXT,
            test_status TEXT
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
            created_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(method, url, query_string)
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute(
        "INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'api_fuzz')"
    )
    c.commit()
    yield c
    c.close()


# ── derive_prefixes ────────────────────────────────────────────────────────────


def test_derive_prefixes_basic():
    paths = ["/api/v1/courses", "/api/v1/users", "/api/v1/login"]
    result = derive_prefixes(paths)
    assert "/api/v1/" in result


def test_derive_prefixes_empty_returns_fallback():
    result = derive_prefixes([])
    assert result == ["/api/"]


def test_derive_prefixes_with_full_urls():
    paths = ["https://example.com/api/v1/courses", "https://example.com/api/v1/users"]
    result = derive_prefixes(paths)
    assert "/api/v1/" in result


def test_derive_prefixes_mixed_paths():
    paths = ["/api/v1/a", "/api/v1/b", "/api/v2/c"]
    result = derive_prefixes(paths)
    assert any("/api/" in p for p in result)


# ── classify_response ──────────────────────────────────────────────────────────


def test_classify_unauth_200_is_critical():
    intent, risk = classify_response(200, 200)
    assert intent == "unauth_admin_access"
    assert risk == "Critical"


def test_classify_unauth_200_auth_403():
    intent, risk = classify_response(403, 200)
    assert intent == "unauth_admin_access"
    assert risk == "Critical"


def test_classify_vertical_priv_esc_auth_200_unauth_401():
    intent, risk = classify_response(200, 401)
    assert intent == "vertical_priv_esc"
    assert risk == "High"


def test_classify_vertical_priv_esc_auth_200_unauth_403():
    intent, risk = classify_response(200, 403)
    assert intent == "vertical_priv_esc"
    assert risk == "High"


def test_classify_both_403_is_medium():
    intent, risk = classify_response(403, 403)
    assert intent == "admin_403_probe"
    assert risk == "Medium"


def test_classify_auth_403_unauth_404():
    intent, risk = classify_response(403, 404)
    assert intent == "admin_403_probe"
    assert risk == "Medium"


def test_classify_server_error():
    result = classify_response(500, 500)
    assert result is not None
    assert result[0] == "server_error_probe"
    assert result[1] == "Medium"


def test_classify_404_both_returns_none():
    result = classify_response(404, 404)
    assert result is None


def test_classify_0_both_returns_none():
    result = classify_response(0, 0)
    assert result is None


# ── extract_known_api_paths ────────────────────────────────────────────────────


def test_extract_from_pages_api_calls_json(conn):
    conn.execute(
        "INSERT INTO pages (url, api_calls_json, status) VALUES (?, ?, 'visited')",
        ("/index", json.dumps([{"url": "/api/v1/courses"}, {"url": "/api/v1/users"}])),
    )
    conn.commit()
    paths = extract_known_api_paths(conn)
    assert "/api/v1/courses" in paths
    assert "/api/v1/users" in paths


def test_extract_from_js_files(conn):
    conn.execute(
        "INSERT INTO js_files (url, analyzed, discovered_apis_json) VALUES (?, 1, ?)",
        ("/static/app.js", json.dumps(["/api/v1/teacher", "/api/v1/admin"])),
    )
    conn.commit()
    paths = extract_known_api_paths(conn)
    assert "/api/v1/teacher" in paths


def test_extract_from_suspicious_points(conn):
    conn.execute(
        "INSERT INTO suspicious_points (id, url) VALUES ('SP-001', '/api/v1/grades')"
    )
    conn.commit()
    paths = extract_known_api_paths(conn)
    assert "/api/v1/grades" in paths


def test_extract_empty_db_returns_list(conn):
    paths = extract_known_api_paths(conn)
    assert isinstance(paths, list)


# ── write_to_hunt_queue ────────────────────────────────────────────────────────


def test_write_inserts_correct_fields(conn):
    inserted = write_to_hunt_queue(
        conn,
        target_id=1,
        url="https://example.com/api/admin/users",
        business_intent="vertical_priv_esc",
        risk_hint="High",
        auth_code=200,
        unauth_code=403,
    )
    assert inserted is True
    row = conn.execute(
        "SELECT * FROM hunt_queue WHERE url='https://example.com/api/admin/users'"
    ).fetchone()
    assert row["endpoint_type"] == "admin_api"
    assert row["source"] == "auto"
    assert "api_fuzz" in row["notes"]
    assert "auth=200" in row["notes"]
    assert "unauth=403" in row["notes"]
    assert row["risk_hint"] == "High"
    assert row["status"] == "queued"


def test_write_ignores_duplicate(conn):
    url = "https://example.com/api/admin"
    write_to_hunt_queue(conn, 1, url, "admin_403_probe", "Medium", 403, 403)
    inserted_again = write_to_hunt_queue(conn, 1, url, "admin_403_probe", "Medium", 403, 403)
    assert inserted_again is False
    count = conn.execute("SELECT count(*) FROM hunt_queue WHERE url=?", (url,)).fetchone()[0]
    assert count == 1


def test_write_critical_risk_hint(conn):
    write_to_hunt_queue(
        conn, 1, "https://example.com/api/superadmin", "unauth_admin_access", "Critical", 200, 200
    )
    row = conn.execute("SELECT risk_hint FROM hunt_queue").fetchone()
    assert row["risk_hint"] == "Critical"


# ── build_probe_list ──────────────────────────────────────────────────────────


def test_build_probe_list_returns_full_urls(conn):
    probe_list = build_probe_list(conn, "https://example.com")
    assert len(probe_list) > 0
    assert all(p.startswith("https://example.com") for p in probe_list)


def test_build_probe_list_excludes_known_pages(conn):
    conn.execute(
        "INSERT INTO pages (url, status) VALUES ('https://example.com/api/admin', 'visited')"
    )
    conn.commit()
    probe_list = build_probe_list(conn, "https://example.com")
    paths = [p.replace("https://example.com", "") for p in probe_list]
    assert "/api/admin" not in paths


def test_build_probe_list_excludes_hunt_queue_entries(conn):
    conn.execute(
        """INSERT INTO hunt_queue (target_id, method, url, source)
           VALUES (1, 'GET', 'https://example.com/api/teacher', 'auto')"""
    )
    conn.commit()
    probe_list = build_probe_list(conn, "https://example.com")
    assert "https://example.com/api/teacher" not in probe_list
```

- [ ] **Step 2: 确认测试失败（模块不存在）**

```bash
cd "e:/SRC挖掘/SRC" && uv run pytest TOOLS/tests/test_api_fuzz.py -v 2>&1 | head -20
```

期望输出：`ModuleNotFoundError` 或 `ImportError: cannot import name ...`

---

## Task 2: 实现 TOOLS/pipeline/api_fuzz.py（TDD GREEN 阶段）

**Files:**
- Create: `TOOLS/pipeline/api_fuzz.py`

- [ ] **Step 1: 创建脚本**

```python
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
    "/api/admin", "/api/admin/users", "/api/admin/list", "/api/admin/info",
    "/api/manage", "/api/management", "/api/manager",
    "/api/staff", "/api/internal", "/api/system", "/api/backstage",
    "/api/console", "/api/superadmin", "/api/privileged",
    "/api/teacher", "/api/teacher/list", "/api/teacher/course",
    "/api/instructor", "/api/tutor", "/api/faculty",
    "/api/v1/admin", "/api/v1/teacher", "/api/v1/manage", "/api/v1/staff",
    "/api/v2/admin", "/api/v2/teacher", "/api/v2/manage",
    "/admin/api", "/admin/api/users", "/admin/api/list",
    "/manage/api", "/teacher/api", "/system/api", "/console/api",
    "/api/jiaoshi", "/api/guanli", "/api/xitong", "/api/jiaowu",
]

ADMIN_STEMS = ["admin", "teacher", "manage", "staff", "system", "internal", "instructor"]

# 路径中若出现这些角色词，生成对应 admin 变种
_ROLE_SRC_WORDS = ("student", "user", "member", "xuesheng", "xsgl", "tongxue")


def extract_known_api_paths(conn: sqlite3.Connection) -> list[str]:
    """从 DB 聚合所有已知 API 路径（pages + js_files + suspicious_points）。"""
    paths: list[str] = []

    rows = conn.execute(
        "SELECT api_calls_json FROM pages WHERE api_calls_json IS NOT NULL"
    ).fetchall()
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
        rows3 = conn.execute(
            "SELECT DISTINCT url FROM suspicious_points WHERE url IS NOT NULL"
        ).fetchall()
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
            for row in conn.execute(f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL").fetchall():
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
                    replaced = path_part.replace(f"/{src}/", f"/{stem}/").replace(
                        f"/{src}", f"/{stem}"
                    )
                    if replaced != path_part:
                        candidate_paths.add(replaced)

    result = [
        f"{origin}{path}"
        for path in sorted(candidate_paths)
        if path not in known_paths
    ]
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
        return requests.get(url, headers=headers, proxies=BURP_PROXY, timeout=10, verify=False)

    auth_code = 0
    unauth_code = 0

    try:
        resp, _, _ = fetcher.fetch_with_rotation(lambda: _get(primary_cookie))
        if isinstance(resp, requests.Response):
            auth_code = resp.status_code
    except Exception:
        pass
    time.sleep(delay)

    try:
        resp, _, _ = fetcher.fetch_with_rotation(lambda: _get(None))
        if isinstance(resp, requests.Response):
            unauth_code = resp.status_code
    except Exception:
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
               (target_id, method, url, endpoint_type, business_intent,
                risk_hint, status, source, notes)
               VALUES (?, 'GET', ?, 'admin_api', ?, ?, 'queued', 'auto', ?)""",
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
    parser.add_argument("--max-rotations", type=int, default=3, dest="max_rotations",
                        help="WAF 触发最大换 IP 次数（默认 3）")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

    if not is_clash_alive():
        print("[warn] Clash 不可达，将在无 IP 轮换的情况下继续探测")

    row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_url = (row["seed_url"] if row else None)
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
        inserted = write_to_hunt_queue(
            conn, target_id, url, business_intent, risk_hint, auth_code, unauth_code
        )
        if inserted:
            found += 1
            marker = {"Critical": "[!!!]", "High": "[!! ]", "Medium": "[ ! ]"}.get(risk_hint, "[   ]")
            print(f"  {marker} {risk_hint:8s} {url}  auth={auth_code} unauth={unauth_code}")

    conn.close()
    print(f"\n[API_FUZZ] probed={len(probe_list)} found={found} waf_rotations={total_rotations}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 运行测试，确认通过**

```bash
cd "e:/SRC挖掘/SRC" && uv run pytest TOOLS/tests/test_api_fuzz.py -v
```

期望：所有测试通过，无 FAILED。

- [ ] **Step 3: 提交**

```bash
cd "e:/SRC挖掘/SRC" && git add TOOLS/pipeline/api_fuzz.py TOOLS/tests/test_api_fuzz.py && git commit -m "feat: add api_fuzz pipeline script with WAF-aware probing"
```

---

## Task 3: 更新 run_scan.py（插入 api_fuzz phase）

**Files:**
- Modify: `TOOLS/run_scan.py`
- Modify: `TOOLS/tests/test_run_scan.py`

- [ ] **Step 1: 修改 probe_next_phase 函数**

在 `TOOLS/run_scan.py` 第 115-117 行，把：

```python
def probe_next_phase(new_sp: int) -> str | None:
    """无新 SP → 'exploit'，否则 None（继续展示 SP）。"""
    return "exploit" if new_sp == 0 else None
```

改为：

```python
def probe_next_phase(new_sp: int) -> str | None:
    """无新 SP → 'api_fuzz'，否则 None（继续展示 SP）。"""
    return "api_fuzz" if new_sp == 0 else None
```

- [ ] **Step 2: 新增 handle_api_fuzz 函数**

在 `handle_exploit` 函数（约第 263 行）之前插入：

```python
def handle_api_fuzz(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=api_fuzz → 运行 api_fuzz.py ...")
    before_hq = conn.execute(
        "SELECT count(*) FROM hunt_queue WHERE source='auto' AND notes LIKE 'api_fuzz%'"
    ).fetchone()[0]

    subprocess.run(  # noqa: S603
        [PYTHON, str(PIPELINE_DIR / "api_fuzz.py"), "--target", target],
        timeout=600,
        check=False,
    )

    after_hq = conn.execute(
        "SELECT count(*) FROM hunt_queue WHERE source='auto' AND notes LIKE 'api_fuzz%'"
    ).fetchone()[0]
    new_entries = after_hq - before_hq

    set_phase(conn, "exploit")
    print_tag(
        "PHASE_TRANSITION",
        [
            f"api_fuzz → exploit    新增 hunt_queue 条目: {new_entries}",
            f"如需立即测试: Skill(skill='business-logic-hunt', args='目标: {target}')",
        ],
    )
```

- [ ] **Step 3: 把 api_fuzz 加入 HANDLERS dict**

找到 `HANDLERS = {` 字典（约第 436 行），在 `"probe": handle_probe,` 行之后加一行：

```python
    "api_fuzz": handle_api_fuzz,
```

完整 HANDLERS 应为：

```python
HANDLERS = {
    "init": handle_init,
    "spider": handle_spider,
    "probe": handle_probe,
    "api_fuzz": handle_api_fuzz,
    "exploit": handle_exploit,
    "brute": handle_brute,
    "reflect": handle_reflect,
    "auth_ready": handle_auth_ready,
    "auth_explore": handle_auth_explore,
}
```

- [ ] **Step 4: 更新 test_run_scan.py 的 probe_next_phase 断言**

在 `TOOLS/tests/test_run_scan.py` 第 158 行，把：

```python
        assert probe_next_phase(new_sp=0) == "exploit"
```

改为：

```python
        assert probe_next_phase(new_sp=0) == "api_fuzz"
```

同时更新第 7 行注释从 `probe_next_phase (无新 SP → brute 决策)` 为：

```python
  - probe_next_phase      (无新 SP → api_fuzz 决策)
```

- [ ] **Step 5: 运行全部 run_scan 测试，确认通过**

```bash
cd "e:/SRC挖掘/SRC" && uv run pytest TOOLS/tests/test_run_scan.py -v
```

期望：所有测试通过。特别确认 `test_probe_transitions_to_api_fuzz_when_no_new_sp` 或现有 probe 测试通过。

- [ ] **Step 6: 运行全量测试，确认无回归**

```bash
cd "e:/SRC挖掘/SRC" && uv run pytest TOOLS/tests/ -v --tb=short 2>&1 | tail -20
```

期望：所有测试通过。

- [ ] **Step 7: 提交**

```bash
cd "e:/SRC挖掘/SRC" && git add TOOLS/run_scan.py TOOLS/tests/test_run_scan.py && git commit -m "feat: insert api_fuzz phase between probe and exploit in stealth-scanner"
```

---

## Task 4: 更新 stealth-scanner SKILL.md

**Files:**
- Modify: `.claude/skills/stealth-scanner/SKILL.md`

- [ ] **Step 1: 在状态机表格中加 api_fuzz 行**

找到 `.claude/skills/stealth-scanner/SKILL.md` 中的状态机表格，在 `probe` 行之后、`exploit` 行之前插入：

```markdown
| `api_fuzz`     | 词列+模式推断探测隐藏 API     | `pipeline/api_fuzz.py`                       |
```

- [ ] **Step 2: 在输出标签表中加 [API_FUZZ] 行**

在输出标签处理表（`## 输出标签处理`）中，在 `[NEW_SUSPICIOUS_POINTS]` 行之后插入：

```markdown
| `[API_FUZZ]`              | api_fuzz 阶段完成，新增 hunt_queue 条目          | 记录条数后再次调用 `run_scan.py`            |
```

- [ ] **Step 3: 更新状态机 phases 行**

找到：
```
phases: `init` → `auth_pending` → `auth_ready` → `auth_explore` → `spider` ↔ `probe` → `exploit` → `brute` → `spider`
```

改为：
```
phases: `init` → `auth_pending` → `auth_ready` → `auth_explore` → `spider` ↔ `probe` → `api_fuzz` → `exploit` → `brute` → `spider`
```

- [ ] **Step 4: 提交**

```bash
cd "e:/SRC挖掘/SRC" && git add .claude/skills/stealth-scanner/SKILL.md && git commit -m "docs: document api_fuzz phase in stealth-scanner skill"
```

---

## 自检清单

完成所有任务后确认：

- [ ] `uv run pytest TOOLS/tests/test_api_fuzz.py -v` → 全部通过
- [ ] `uv run pytest TOOLS/tests/test_run_scan.py -v` → 全部通过（probe_next_phase 返回 'api_fuzz'）
- [ ] `uv run pytest TOOLS/tests/ -v --tb=short` → 无回归
- [ ] `TOOLS/pipeline/api_fuzz.py` 中 `classify_response(200, 200)` 返回 `("unauth_admin_access", "Critical")`
- [ ] `TOOLS/run_scan.py` 的 `HANDLERS` dict 包含 `"api_fuzz": handle_api_fuzz`
- [ ] hunt_queue 写入时 `source='auto'`，`notes` 包含 `api_fuzz |`
