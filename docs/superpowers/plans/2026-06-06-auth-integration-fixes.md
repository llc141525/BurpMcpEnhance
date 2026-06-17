# Auth Integration Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复认证后业务覆盖的三个断链（auth_ready 无 handler、pipeline 无 cookie、auth_explore 缺失），并接通 Caido MCP 让 Claude 能直接查询 Caido 录制的认证流量。

**Architecture:** 新增共享 cookie helper 模块供三个 pipeline 脚本读取 auth_sessions；新增 auth_explore.py 用 patchright 深度导航并拦截 XHR 写 suspicious_points；run_scan.py 加 auth_ready/auth_explore handler 让 phase 状态机闭环；Caido MCP server 用 mcp SDK 包装 GraphQL API 写入 .mcp.json。

**Tech Stack:** Python 3.11, patchright 1.59.1, mcp 1.26.0, SQLite WAL, Caido v0.56.2 GraphQL API (localhost:8181/graphql)

---

## File Map

| 操作 | 文件 | 职责 |
|------|------|------|
| 新建 | `TOOLS/db/cookie_helper.py` | 从 auth_sessions 读 cookies → Cookie header 字符串 |
| 修改 | `TOOLS/pipeline/bfs_crawl.py` | run_katana() 加 `-H "Cookie: ..."` |
| 修改 | `TOOLS/pipeline/scrapling_fetch.py` | fetch() 加 `cookies=` 参数 |
| 修改 | `TOOLS/pipeline/probe_runner.py` | arjun/nuclei/mode_methods 加 Cookie 头 |
| 新建 | `TOOLS/auth/auth_explore.py` | Playwright 深度导航 + 网络拦截 → suspicious_points |
| 修改 | `TOOLS/run_scan.py` | 加 handle_auth_ready + handle_auth_explore + HANDLERS |
| 新建 | `TOOLS/caido_mcp.py` | MCP stdio server 包装 Caido GraphQL |
| 修改 | `.mcp.json` | 加 caido MCP server 条目 |
| 新建 | `tests/test_cookie_helper.py` | cookie_helper 单元测试 |
| 新建 | `tests/test_auth_explore.py` | auth_explore 纯函数测试 |
| 新建 | `tests/test_caido_mcp.py` | Caido MCP GraphQL 查询测试 |

---

## Task 1: Cookie Helper 模块

**Files:**
- Create: `TOOLS/db/cookie_helper.py`
- Test: `tests/test_cookie_helper.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_cookie_helper.py
import sqlite3
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))
from db.cookie_helper import get_auth_cookie_header, get_auth_cookies_dict


def _make_db(cookies: list[dict]) -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(f.name)
    conn.execute("""CREATE TABLE auth_sessions (
        id INTEGER PRIMARY KEY,
        token_type TEXT, token_name TEXT, token_value TEXT,
        domain TEXT, path TEXT DEFAULT '/', is_active INTEGER DEFAULT 1
    )""")
    for c in cookies:
        conn.execute(
            "INSERT INTO auth_sessions (token_type,token_name,token_value,domain,is_active) VALUES (?,?,?,?,?)",
            (c["type"], c["name"], c["value"], c["domain"], c.get("active", 1)),
        )
    conn.commit()
    conn.close()
    return f.name


def test_get_auth_cookie_header_matches_domain():
    db = _make_db([
        {"type": "cookie", "name": "JSESSIONID", "value": "abc123", "domain": "example.com"},
        {"type": "cookie", "name": "token", "value": "xyz", "domain": "other.com"},
    ])
    header = get_auth_cookie_header(db, "example.com")
    assert header == "JSESSIONID=abc123"


def test_get_auth_cookie_header_subdomain_match():
    db = _make_db([
        {"type": "cookie", "name": "SID", "value": "s1", "domain": ".example.com"},
    ])
    assert get_auth_cookie_header(db, "app.example.com") == "SID=s1"


def test_get_auth_cookie_header_inactive_excluded():
    db = _make_db([
        {"type": "cookie", "name": "OLD", "value": "v", "domain": "example.com", "active": 0},
    ])
    assert get_auth_cookie_header(db, "example.com") is None


def test_get_auth_cookies_dict():
    db = _make_db([
        {"type": "cookie", "name": "A", "value": "1", "domain": "x.com"},
        {"type": "cookie", "name": "B", "value": "2", "domain": "x.com"},
    ])
    d = get_auth_cookies_dict(db, "x.com")
    assert d == {"A": "1", "B": "2"}


def test_no_matching_cookies_returns_none():
    db = _make_db([])
    assert get_auth_cookie_header(db, "example.com") is None
```

- [ ] **Step 2: 运行确认失败**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_cookie_helper.py -v 2>&1 | tail -10
```

Expected: `ModuleNotFoundError: No module named 'db.cookie_helper'`

- [ ] **Step 3: 实现 cookie_helper.py**

```python
# TOOLS/db/cookie_helper.py
"""从 auth_sessions 表读取活跃 cookies，用于 pipeline 工具的 Cookie 头注入。"""
import sqlite3
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
        rows = conn.execute(
            "SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1"
        ).fetchall()
        conn.close()
    except Exception:
        return {}

    # 提取 host（去掉端口）
    host = domain.split(":")[0] if ":" in domain and not domain.startswith("http") else urlparse(domain).hostname or domain

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
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_cookie_helper.py -v 2>&1 | tail -15
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add TOOLS/db/cookie_helper.py tests/test_cookie_helper.py
git commit -m "feat: add cookie_helper — read auth_sessions for pipeline cookie injection"
```

---

## Task 2: bfs_crawl.py — katana 加 Cookie 头

**Files:**
- Modify: `TOOLS/pipeline/bfs_crawl.py`（`run_katana` 函数，约第 80-110 行）

- [ ] **Step 1: 在 run_katana 中加 cookie 注入**

读取 `TOOLS/db/cookie_helper.py`，在 `bfs_crawl.py` 顶部加 sys.path 和 import，在 `run_katana()` 接收 `cookie_header` 参数：

```python
# 在文件顶部 import 区域后加（PROJECT_ROOT 已定义）：
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookie_header  # noqa: E402
```

修改 `run_katana` 签名和 cmd 构建（在 `cmd = [...]` 之后、`subprocess.run` 之前）：

```python
def run_katana(seed_urls: list[str], depth: int, max_pages: int, cookie_header: str | None = None) -> list[str]:
    # ... existing code unchanged until cmd construction ...
    cmd = [
        "katana",
        "-list", input_file,
        "-d", str(depth),
        "-c", "10",
        "-p", "10",
        "-ef", "woff,css,png,svg,jpg,jpeg,gif,ico,ttf,eot",
        "-kf", "all",
        "-jc",
        "-jsl",
        "-timeout", "10",
        "-o", out_file,
        "-silent",
    ]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    # ... rest unchanged ...
```

在 `main()` 里，`connect(db_path)` 之后、`run_katana(...)` 之前加：

```python
    cookie_header = get_auth_cookie_header(str(db_path), seed_urls[0] if seed_urls else "")
    if cookie_header:
        print(f"[bfs_crawl] 带认证 Cookie 爬取 ({len(cookie_header.split(';'))} 条)", file=sys.stderr)
```

然后调用改为：

```python
    discovered = run_katana(seed_urls, args.depth, args.max_pages, cookie_header=cookie_header)
```

- [ ] **Step 2: 运行现有测试确认无回归**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_run_scan.py -v 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 3: Commit**

```bash
git add TOOLS/pipeline/bfs_crawl.py
git commit -m "feat: bfs_crawl — inject auth_sessions cookies into katana"
```

---

## Task 3: scrapling_fetch.py — Fetcher 加 cookies

**Files:**
- Modify: `TOOLS/pipeline/scrapling_fetch.py`（`fetch` 函数，约第 58 行）

- [ ] **Step 1: 修改 fetch() 加 cookies 参数**

在 `fetch()` 定义处加 `cookies` 参数，并传入 Fetcher：

```python
def fetch(url, proxy=None, timeout=15, force_stealth=False, solve_captcha=False, cookies: dict | None = None):
    """返回 (Response 对象, used_stealth_bool, captcha_result)"""
    from waf_rotate import is_waf_blocked, rotate_ip

    proxy = proxy or os.environ.get("HTTP_PROXY", "http://127.0.0.1:9870")
    captcha_result = None
    last_err = None
    max_rotations = 3

    # ── 路径 A: 普通 Fetcher ──
    if not force_stealth:
        for attempt in range(max_rotations + 1):
            try:
                Fetcher = _get_fetcher()
                fetch_kwargs = dict(proxy=proxy, timeout=timeout)
                if cookies:
                    fetch_kwargs["cookies"] = cookies
                page = Fetcher.get(url, **fetch_kwargs)
                # ... rest of path A unchanged ...
```

在路径 B（StealthyFetcher）同样加 cookies：

```python
            kwargs = dict(
                proxy=proxy,
                timeout=timeout * 1000,
                headless=True,
                disable_resources=True,
                block_ads=True,
            )
            if cookies:
                kwargs["cookies"] = cookies
            if solve_captcha:
                kwargs["page_action"] = auto_solve_captcha
```

在 `main()` 里，加 `--cookies` CLI 参数并传入 fetch：

```python
    parser.add_argument("--cookies", default=None, help='JSON 字符串: {"name":"value"}')
    # ...
    cookies = json.loads(args.cookies) if args.cookies else None
    page, used_stealth, captcha_result = fetch(
        url,
        proxy=proxy,
        timeout=timeout,
        force_stealth=force_stealth,
        solve_captcha=solve_captcha,
        cookies=cookies,
    )
```

在文件顶部已有 `import json`，如无则补加。

- [ ] **Step 2: 运行现有测试**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/ -v -k "not browser_auth and not chrome" 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 3: Commit**

```bash
git add TOOLS/pipeline/scrapling_fetch.py
git commit -m "feat: scrapling_fetch — add cookies param to Fetcher/StealthyFetcher"
```

---

## Task 4: probe_runner.py — arjun/nuclei/methods 加 Cookie 头

**Files:**
- Modify: `TOOLS/pipeline/probe_runner.py`（三个 mode 函数）

- [ ] **Step 1: 加 cookie_helper import 和 cookie 读取**

在文件顶部 import 区域后（`PROJECT_ROOT` 已定义）加：

```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookie_header  # noqa: E402
```

- [ ] **Step 2: 修改 mode_methods 加 Cookie 头**

`mode_methods` 函数签名不变，内部 `req.add_header` 后加：

```python
        req.add_header("User-Agent", "Mozilla/5.0")
        if cookie_header:
            req.add_header("Cookie", cookie_header)
```

在函数签名加参数：`def mode_methods(url: str, conn: sqlite3.Connection, proxy: str | None, cookie_header: str | None = None) -> int:`

- [ ] **Step 3: 修改 mode_params（arjun）加 Cookie 头**

`mode_params` 签名加 `cookie_header: str | None = None`，在 cmd 构建后加：

```python
    cmd = [python_exe, "-m", "arjun", "-u", url, "-oJ", out_file, "-q"]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
```

- [ ] **Step 4: 修改 mode_nuclei 加 Cookie 头**

`mode_nuclei` 签名加 `cookie_header: str | None = None`，在 cmd 构建中加：

```python
    cmd = [
        "nuclei", "-u", url,
        "-tags", tag_arg,
        "-severity", "medium,high,critical",
        "-json-export", out_file,
        "-silent", "-timeout", "10", "-c", "5",
    ]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
```

- [ ] **Step 5: 修改 main() 传 cookie_header**

在 `main()` 里，`find_db` 和 `connect` 之后加：

```python
    seed_url = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_domain = seed_url[0] if seed_url and seed_url[0] else ""
    cookie_header = get_auth_cookie_header(str(db_path), seed_domain)
    if cookie_header:
        print(f"[probe_runner] 带认证 Cookie ({len(cookie_header.split(';'))} 条)")
```

各模式调用时传入 `cookie_header=cookie_header`。

- [ ] **Step 6: 运行测试**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/ -v -k "not browser_auth and not chrome" 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add TOOLS/pipeline/probe_runner.py
git commit -m "feat: probe_runner — inject auth cookies into arjun, nuclei, method probe"
```

---

## Task 5: auth_explore.py — Playwright 深度导航 + 网络拦截

**Files:**
- Create: `TOOLS/auth/auth_explore.py`
- Test: `tests/test_auth_explore.py`

- [ ] **Step 1: 写纯函数测试（不依赖浏览器）**

```python
# tests/test_auth_explore.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))
from auth.auth_explore import filter_api_requests, parse_request_params, write_explore_results_to_db
import sqlite3, tempfile


def test_filter_api_requests_excludes_static():
    requests = [
        {"url": "https://x.com/api/users", "method": "GET", "resource_type": "xhr"},
        {"url": "https://x.com/style.css", "method": "GET", "resource_type": "stylesheet"},
        {"url": "https://x.com/api/orders", "method": "POST", "resource_type": "fetch"},
    ]
    result = filter_api_requests(requests, "x.com")
    assert len(result) == 2
    assert all(r["url"].startswith("https://x.com/api/") for r in result)


def test_filter_api_requests_excludes_cross_domain():
    requests = [
        {"url": "https://cdn.other.com/lib.js", "method": "GET", "resource_type": "xhr"},
        {"url": "https://x.com/api/me", "method": "GET", "resource_type": "xhr"},
    ]
    result = filter_api_requests(requests, "x.com")
    assert len(result) == 1


def test_parse_request_params_query_string():
    params = parse_request_params("https://x.com/api?id=1&type=admin", None)
    assert "id" in params
    assert "type" in params


def test_parse_request_params_post_json():
    params = parse_request_params("https://x.com/api", '{"userId":1,"action":"delete"}')
    assert "userId" in params
    assert "action" in params


def test_write_explore_results_to_db():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(f.name)
    conn.execute("""CREATE TABLE suspicious_points (
        id TEXT PRIMARY KEY, url TEXT, param TEXT, method TEXT,
        test_type TEXT, evidence TEXT, source TEXT, reasoning TEXT,
        risk TEXT DEFAULT 'Medium', test_status TEXT DEFAULT 'untested',
        created_at TEXT
    )""")
    conn.execute("CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT UNIQUE, depth INTEGER, status TEXT)")
    conn.commit()

    api_requests = [
        {"url": "https://x.com/api/users", "method": "GET", "params": ["page", "limit"], "nav_context": "用户管理"},
        {"url": "https://x.com/api/orders", "method": "POST", "params": ["orderId"], "nav_context": "订单"},
    ]
    page_urls = ["https://x.com/users", "https://x.com/orders"]

    counts = write_explore_results_to_db(conn, api_requests, page_urls, sp_prefix="SP-AE")
    assert counts["sp"] == 2
    assert counts["pages"] == 2
    conn.close()
```

- [ ] **Step 2: 运行确认失败**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_auth_explore.py -v 2>&1 | tail -10
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: 实现 auth_explore.py（纯函数部分）**

```python
# TOOLS/auth/auth_explore.py
"""认证后深度导航 + 网络请求拦截，发现 API endpoint 写入 suspicious_points。

用法:
  python TOOLS/auth/auth_explore.py --target "台州学院"

输出:
  - suspicious_points 写入认证后发现的 API endpoint（source='auth_explore'）
  - pages 写入新发现的页面 URL
  - phase → spider
"""
import argparse
import asyncio
import json
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # auth/→TOOLS/→SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookies_dict  # noqa: E402

STATIC_TYPES = {"stylesheet", "image", "font", "media", "websocket", "manifest", "ping"}
STATIC_EXT_RE = re.compile(r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip)(\?.*)?$", re.I)

NAV_SELECTORS = [
    "nav a[href]", "aside a[href]", ".sidebar a[href]",
    "[role='menuitem']", "[role='tab']", ".menu-item a[href]",
    ".nav-item a[href]", "ul.nav a[href]", ".ant-menu-item a[href]",
    ".el-menu-item", ".layui-nav-item a[href]",
]


# ── 纯函数（可测试）────────────────────────────────────────────────────────────


def filter_api_requests(requests: list[dict], base_domain: str) -> list[dict]:
    """过滤：只保留同域 XHR/fetch，排除静态资源。"""
    result = []
    base = base_domain.split(":")[0].lstrip("www.")
    for r in requests:
        if r.get("resource_type") not in ("xhr", "fetch", "document"):
            continue
        url = r.get("url", "")
        try:
            host = urlparse(url).netloc.lstrip("www.")
        except Exception:
            continue
        if not (host == base or host.endswith("." + base)):
            continue
        if STATIC_EXT_RE.search(url.split("?")[0]):
            continue
        result.append(r)
    return result


def parse_request_params(url: str, post_data: str | None) -> list[str]:
    """从 URL query string 和 POST body 提取参数名列表。"""
    params = set()
    parsed = urlparse(url)
    if parsed.query:
        params.update(parse_qs(parsed.query).keys())
    if post_data:
        try:
            body = json.loads(post_data)
            if isinstance(body, dict):
                params.update(body.keys())
        except (json.JSONDecodeError, ValueError):
            for part in post_data.split("&"):
                if "=" in part:
                    params.add(part.split("=")[0])
    return sorted(params)


def write_explore_results_to_db(
    conn: sqlite3.Connection,
    api_requests: list[dict],
    page_urls: list[str],
    sp_prefix: str = "SP-AE",
) -> dict:
    """写 suspicious_points + pages，返回 {'sp': N, 'pages': N}。"""
    # 计算下一个 SP id
    rows = conn.execute(
        f"SELECT id FROM suspicious_points WHERE id LIKE '{sp_prefix}-%' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    try:
        next_num = int(rows[0].split("-")[-1]) + 1 if rows else 1
    except (ValueError, IndexError):
        next_num = 1

    sp_count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for req in api_requests:
        sp_id = f"{sp_prefix}-{next_num:03d}"
        next_num += 1
        params = req.get("params", [])
        context = req.get("nav_context", "")
        cur = conn.execute(
            """INSERT INTO suspicious_points
               (id, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
               VALUES (?, ?, ?, ?, 'auth_surface', ?, 'auth_explore', ?, 'Medium', 'untested', ?)
               ON CONFLICT(id) DO NOTHING""",
            (
                sp_id,
                req["url"],
                ", ".join(params) if params else "",
                req.get("method", "GET"),
                f"认证后页面 [{context}] 发出的请求，params={params}",
                f"认证用户操作触发的 API，存在 IDOR/越权/敏感数据暴露风险。来源: {context}",
                now,
            ),
        )
        sp_count += cur.rowcount

    page_count = 0
    for url in page_urls:
        cur = conn.execute(
            "INSERT INTO pages (url, depth, status) VALUES (?, 2, 'queued') ON CONFLICT(url) DO NOTHING",
            (url,),
        )
        page_count += cur.rowcount

    conn.commit()
    return {"sp": sp_count, "pages": page_count}


# ── Playwright 浏览器导航（需要 patchright）────────────────────────────────────


async def explore_authenticated(
    cdp_url: str,
    seed_url: str,
    cookies: dict[str, str],
    base_domain: str,
    nav_depth: int = 2,
) -> tuple[list[dict], list[str]]:
    """连接已有 Chrome，注入 cookies，BFS 点击导航项，拦截网络请求。
    返回 (api_requests, page_urls)。
    """
    from patchright.async_api import async_playwright

    all_api_requests: list[dict] = []
    all_page_urls: set[str] = set()

    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(cdp_url)
        context = browser.contexts[0] if browser.contexts else await browser.new_context()

        # 注入 cookies
        if cookies:
            cookie_list = [
                {"name": k, "value": v, "domain": base_domain, "path": "/"}
                for k, v in cookies.items()
            ]
            await context.add_cookies(cookie_list)

        page = await context.new_page()
        current_nav_context = "首页"

        # 拦截请求
        def on_request(request):
            if request.resource_type in ("xhr", "fetch"):
                params = parse_request_params(request.url, request.post_data)
                all_api_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "params": params,
                    "nav_context": current_nav_context,
                    "post_data": request.post_data,
                })

        page.on("request", on_request)

        # 导航到 seed URL
        try:
            await page.goto(seed_url, wait_until="networkidle", timeout=30000)
            all_page_urls.add(page.url)
        except Exception as e:
            print(f"[auth_explore] 首页导航失败: {e}", file=sys.stderr)
            return [], []

        # 收集顶层导航项 href
        nav_hrefs: list[tuple[str, str]] = []  # (href, label)
        for selector in NAV_SELECTORS:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[:30]:
                    href = await el.get_attribute("href") or ""
                    label = (await el.inner_text()).strip()[:30]
                    if href and href not in ("#", "javascript:void(0)", "javascript:;"):
                        nav_hrefs.append((href, label or href))
            except Exception:
                continue

        print(f"[auth_explore] 发现 {len(nav_hrefs)} 个导航项", file=sys.stderr)

        # BFS 点击（深度 nav_depth）
        visited_hrefs: set[str] = set()
        for href, label in nav_hrefs[:40]:  # 最多处理 40 个顶层
            if href in visited_hrefs:
                continue
            visited_hrefs.add(href)
            current_nav_context = label  # 更新拦截上下文

            try:
                # 构造绝对 URL
                if href.startswith("http"):
                    nav_url = href
                elif href.startswith("/"):
                    nav_url = f"{urlparse(seed_url).scheme}://{base_domain}{href}"
                else:
                    continue

                await page.goto(nav_url, wait_until="networkidle", timeout=15000)
                all_page_urls.add(page.url)

                if nav_depth >= 2:
                    # 收集子菜单项
                    sub_hrefs = []
                    for sel in NAV_SELECTORS:
                        try:
                            els = await page.query_selector_all(sel)
                            for el in els[:20]:
                                sh = await el.get_attribute("href") or ""
                                sl = (await el.inner_text()).strip()[:30]
                                if sh and sh not in ("#", "javascript:void(0)") and sh not in visited_hrefs:
                                    sub_hrefs.append((sh, f"{label}>{sl}"))
                        except Exception:
                            continue

                    for sub_href, sub_label in sub_hrefs[:15]:
                        visited_hrefs.add(sub_href)
                        current_nav_context = sub_label
                        try:
                            if sub_href.startswith("http"):
                                sub_url = sub_href
                            elif sub_href.startswith("/"):
                                sub_url = f"{urlparse(seed_url).scheme}://{base_domain}{sub_href}"
                            else:
                                continue
                            await page.goto(sub_url, wait_until="networkidle", timeout=10000)
                            all_page_urls.add(page.url)
                        except Exception:
                            continue

            except Exception as e:
                print(f"[auth_explore] 导航 {href} 失败: {e}", file=sys.stderr)
                continue

        await page.close()

    filtered = filter_api_requests(all_api_requests, base_domain)
    # 去重（同 URL+method 只保留一条）
    seen = set()
    deduped = []
    for r in filtered:
        key = (r["url"].split("?")[0], r["method"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped, list(all_page_urls)


# ── CLI ──────────────────────────────────────────────────────────────────────


def find_db(target: str) -> Path:
    dbs = sorted(DBS_DIR.glob(f"{target}*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dbs:
        sys.exit(f"[error] 找不到目标 DB: {target}")
    return dbs[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row

    row = conn.execute("SELECT seed_url, cdp_url FROM scan_state WHERE id=1").fetchone()
    seed_url = row["seed_url"] if row and row["seed_url"] else None
    cdp_url = row["cdp_url"] if row and row["cdp_url"] else "http://localhost:9222"

    if not seed_url:
        row2 = conn.execute("SELECT domain FROM targets LIMIT 1").fetchone()
        if row2:
            d = row2["domain"].strip()
            seed_url = d if d.startswith("http") else "https://" + d

    if not seed_url:
        sys.exit("[error] 无 seed_url，请先运行 init_scan.py")

    base_domain = urlparse(seed_url).netloc
    cookies = get_auth_cookies_dict(str(db_path), base_domain)

    print(f"[auth_explore] 目标: {args.target}  seed: {seed_url}  cookies: {len(cookies)} 条")

    api_requests, page_urls = asyncio.run(
        explore_authenticated(cdp_url, seed_url, cookies, base_domain)
    )

    counts = write_explore_results_to_db(conn, api_requests, page_urls)
    conn.execute("UPDATE scan_state SET phase='spider' WHERE id=1")
    conn.commit()
    conn.close()

    print(f"[auth_explore] 完成: SP={counts['sp']}  pages={counts['pages']}  phase→spider")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 运行单元测试**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_auth_explore.py -v 2>&1 | tail -15
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add TOOLS/auth/auth_explore.py tests/test_auth_explore.py
git commit -m "feat: add auth_explore — Playwright deep nav + XHR interception for authenticated surface"
```

---

## Task 6: run_scan.py — auth_ready + auth_explore handlers

**Files:**
- Modify: `TOOLS/run_scan.py`（末尾 HANDLERS dict 和 main 函数，约第 219-260 行）

- [ ] **Step 1: 加 handle_auth_ready 函数**

在 `handle_auth_pending` 函数之后（约第 228 行）插入：

```python
def handle_auth_ready(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    """auth_ready → auth_explore：确认 cookies 存在后转 explore phase。"""
    count = conn.execute("SELECT count(*) FROM auth_sessions WHERE is_active=1").fetchone()[0]
    if count == 0:
        print_tag(
            "AUTH_BARRIER",
            [
                "auth_sessions 为空，cookies 尚未写入",
                "请先通过 browser_auth.py 或手动方式完成登录后重试",
            ],
        )
        return
    set_phase(conn, "auth_explore")
    print_tag("PHASE_TRANSITION", [f"auth_ready → auth_explore  ({count} 条 cookies 已就绪)"])


def handle_auth_explore(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    """auth_explore → spider：运行 auth_explore.py 深度导航。"""
    print("[run_scan] phase=auth_explore → 运行 auth_explore.py ...")
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(TOOLS_DIR / "auth" / "auth_explore.py"), "--target", target],
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        print("[warn] auth_explore 失败，直接转 spider")
    # auth_explore.py 内部已设置 phase=spider；若脚本异常则手动设置
    current = get_phase(conn)
    if current == "auth_explore":
        set_phase(conn, "spider")
    sp_count = conn.execute(
        "SELECT count(*) FROM suspicious_points WHERE source='auth_explore' AND test_status='untested'"
    ).fetchone()[0]
    print_tag(
        "PHASE_TRANSITION",
        [
            f"auth_explore → spider  (新增 SP: {sp_count} 条)",
        ],
    )
```

- [ ] **Step 2: 更新 HANDLERS dict 和 main()**

将现有 HANDLERS dict（约第 234 行）改为：

```python
HANDLERS = {
    "init": handle_init,
    "spider": handle_spider,
    "probe": handle_probe,
    "brute": handle_brute,
    "auth_ready": handle_auth_ready,
    "auth_explore": handle_auth_explore,
}
```

将 `main()` 里的 `if phase == "auth_pending":` 块改为：

```python
    if phase in ("auth_pending", "auth_timeout", "chrome_error"):
        handle_auth_pending(conn)
    elif phase in HANDLERS:
        HANDLERS[phase](args.target, db_path, conn)
    else:
        print(f"[warn] 未知 phase: {phase!r}，重置为 init")
        set_phase(conn, "init")
```

- [ ] **Step 3: 运行 run_scan 测试**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_run_scan.py -v 2>&1 | tail -15
```

Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add TOOLS/run_scan.py
git commit -m "feat: run_scan — add auth_ready/auth_explore handlers, close phase state machine"
```

---

## Task 7: Caido MCP Server

**Files:**
- Create: `TOOLS/caido_mcp.py`
- Modify: `.mcp.json`
- Test: `tests/test_caido_mcp.py`

### 7.0 前置：获取 Caido API Token

在继续之前，需要先从 Caido UI 生成 API Key：

1. 启动 Caido：`C:\Users\llc\caido\caido-cli.exe --listen 127.0.0.1:8181 --no-open`
2. 浏览器打开 `http://127.0.0.1:8181`
3. 进入 **Settings → API Keys → Generate new key**
4. 复制生成的 token，设置环境变量：
   ```bash
   # PowerShell（持久化）
   [System.Environment]::SetEnvironmentVariable("CAIDO_API_KEY", "你的token", "User")
   # 或写入 .env / Windows 系统环境变量
   ```
5. 验证：
   ```bash
   curl -s http://127.0.0.1:8181/graphql \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $CAIDO_API_KEY" \
     -d '{"query":"{ requests(first:1) { edges { node { id host method path } } } }"}' 
   ```
   Expected: `{"data":{"requests":{"edges":[...]}}}`

- [ ] **Step 1: 写 GraphQL 查询测试（需要 Caido 在线 + CAIDO_API_KEY）**

```python
# tests/test_caido_mcp.py
"""集成测试：需要 Caido 在线且 CAIDO_API_KEY 已设置，否则 skip。"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))
from caido_mcp import caido_query, list_requests_query, get_request_detail_query

CAIDO_URL = "http://127.0.0.1:8181"


@pytest.fixture(autouse=True)
def require_caido():
    if not os.environ.get("CAIDO_API_KEY"):
        pytest.skip("CAIDO_API_KEY 未设置")
    try:
        import requests
        requests.get(CAIDO_URL, timeout=2)
    except Exception:
        pytest.skip("Caido 未运行")


def test_caido_query_returns_data():
    result = caido_query('{ runtime { version } }')
    assert "data" in result
    assert "runtime" in result["data"]


def test_list_requests_query_structure():
    gql = list_requests_query(limit=5)
    result = caido_query(gql)
    assert "data" in result
    edges = result["data"].get("requests", {}).get("edges", [])
    assert isinstance(edges, list)


def test_get_request_detail_query_invalid_id():
    gql = get_request_detail_query("nonexistent_id")
    result = caido_query(gql)
    # 无效 ID 应返回 null 而不是 error
    assert "data" in result
```

- [ ] **Step 2: 运行测试确认 skip（未设置 token）**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/test_caido_mcp.py -v 2>&1 | tail -10
```

Expected: `SKIPPED` (CAIDO_API_KEY 未设置)

- [ ] **Step 3: 实现 caido_mcp.py**

```python
# TOOLS/caido_mcp.py
"""Caido MCP Server — 包装 Caido GraphQL API，通过 stdio 提供给 Claude Code。

环境变量:
  CAIDO_API_KEY   Caido API token（Settings → API Keys → Generate）
  CAIDO_URL       Caido 地址（默认 http://127.0.0.1:8181）

.mcp.json 配置:
  {
    "caido": {
      "command": "E:\\SRC挖掘\\SRC\\.venv\\Scripts\\python.exe",
      "args": ["E:\\SRC挖掘\\SRC\\TOOLS\\caido_mcp.py"],
      "env": {"CAIDO_API_KEY": "your_token_here"}
    }
  }
"""
import json
import os
import sys

import requests as _requests
import urllib3

urllib3.disable_warnings()

CAIDO_URL = os.environ.get("CAIDO_URL", "http://127.0.0.1:8181")
CAIDO_API_KEY = os.environ.get("CAIDO_API_KEY", "")


# ── GraphQL helpers（纯函数，可测试）────────────────────────────────────────────


def caido_query(gql: str, variables: dict | None = None) -> dict:
    """发送 GraphQL 查询到 Caido，返回响应 dict。"""
    headers = {"Content-Type": "application/json"}
    if CAIDO_API_KEY:
        headers["Authorization"] = f"Bearer {CAIDO_API_KEY}"
    payload: dict = {"query": gql}
    if variables:
        payload["variables"] = variables
    try:
        resp = _requests.post(
            f"{CAIDO_URL}/graphql",
            headers=headers,
            json=payload,
            timeout=15,
            verify=False,  # noqa: S501
        )
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def list_requests_query(limit: int = 50, after: str | None = None, host_filter: str | None = None) -> str:
    after_clause = f', after: "{after}"' if after else ""
    filter_clause = ""
    if host_filter:
        # Caido filter syntax: PRESET with query string
        filter_clause = f', filter: {{ query: "host:{host_filter}" }}'
    return f"""{{
  requests(first: {limit}{after_clause}{filter_clause}) {{
    edges {{
      node {{
        id host method path query isTls port createdAt
        response {{ statusCode length }}
      }}
    }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}"""


def get_request_detail_query(request_id: str) -> str:
    return f"""{{
  request(id: "{request_id}") {{
    id host method path query raw
    response {{ statusCode length raw }}
  }}
}}"""


def get_sitemap_query() -> str:
    return """{
  sitemapRootEntries {
    host port isTls
    descendantEntries {
      path requestCount
    }
  }
}"""


def search_requests_query(host: str, limit: int = 100) -> str:
    return list_requests_query(limit=limit, host_filter=host)


# ── MCP Server ────────────────────────────────────────────────────────────────


def run_mcp_server() -> None:
    """MCP stdio server 主循环。"""
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    import asyncio

    app = Server("caido-mcp")

    @app.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="caido_list_requests",
                description="列出 Caido 代理历史中的 HTTP 请求（认证后流量）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 50, "description": "返回条数"},
                        "after": {"type": "string", "description": "分页游标（endCursor）"},
                        "host_filter": {"type": "string", "description": "按 host 过滤，如 example.com"},
                    },
                },
            ),
            Tool(
                name="caido_get_request",
                description="获取 Caido 中单个 HTTP 请求的完整内容（含 raw 请求和响应）",
                inputSchema={
                    "type": "object",
                    "required": ["request_id"],
                    "properties": {
                        "request_id": {"type": "string", "description": "Caido 请求 ID"},
                    },
                },
            ),
            Tool(
                name="caido_get_sitemap",
                description="获取 Caido 站点地图（按 host 聚合的所有路径）",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="caido_search_requests",
                description="按 host 搜索 Caido 代理历史",
                inputSchema={
                    "type": "object",
                    "required": ["host"],
                    "properties": {
                        "host": {"type": "string", "description": "目标 host，如 app.example.com"},
                        "limit": {"type": "integer", "default": 100},
                    },
                },
            ),
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name == "caido_list_requests":
            gql = list_requests_query(
                limit=arguments.get("limit", 50),
                after=arguments.get("after"),
                host_filter=arguments.get("host_filter"),
            )
        elif name == "caido_get_request":
            gql = get_request_detail_query(arguments["request_id"])
        elif name == "caido_get_sitemap":
            gql = get_sitemap_query()
        elif name == "caido_search_requests":
            gql = search_requests_query(arguments["host"], arguments.get("limit", 100))
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        result = caido_query(gql)
        return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(main())


if __name__ == "__main__":
    if not CAIDO_API_KEY:
        print("[error] 请设置 CAIDO_API_KEY 环境变量", file=sys.stderr)
        sys.exit(1)
    run_mcp_server()
```

- [ ] **Step 4: 更新 .mcp.json**

读取当前 `.mcp.json`，在 `mcpServers` 中加入 caido 条目：

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp",
      "env": {
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost"
      }
    },
    "caido": {
      "command": "E:\\SRC挖掘\\SRC\\.venv\\Scripts\\python.exe",
      "args": ["E:\\SRC挖掘\\SRC\\TOOLS\\caido_mcp.py"],
      "env": {
        "CAIDO_API_KEY": "",
        "CAIDO_URL": "http://127.0.0.1:8181",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost"
      }
    },
    "MiniMax": {
      "command": "uvx",
      "args": ["minimax-coding-plan-mcp", "-y"],
      "env": {
        "MINIMAX_API_KEY": "sk-cp-ECfFbjNgBCOjnL2I4IQuiLGbx5Ix6FJwp0KQgEdXQjsvVG1WqVyCnuP0pVez5SEf-J2QTWUxxYnXO518zo0hbIyXgmWn57VMWeZOXyzIeT9_I0kO-x5rsDQ",
        "MINIMAX_API_HOST": "https://api.minimaxi.com"
      }
    },
    "scrapling": {
      "command": "E:\\SRC挖掘\\SRC\\.venv\\Scripts\\scrapling.exe",
      "args": ["mcp"]
    }
  }
}
```

> **注意：** `CAIDO_API_KEY` 的值需要在 Step 7.0 生成 token 后填入。

- [ ] **Step 5: 设置 CAIDO_API_KEY 后运行集成测试**

```bash
# 先启动 Caido
"C:/Users/llc/caido/caido-cli.exe" --listen 127.0.0.1:8181 --no-open &
sleep 3
# 运行测试（需已设置 CAIDO_API_KEY）
cd "e:/SRC挖掘/SRC" && CAIDO_API_KEY=$CAIDO_API_KEY .venv/Scripts/python -m pytest tests/test_caido_mcp.py -v 2>&1 | tail -15
```

Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add TOOLS/caido_mcp.py tests/test_caido_mcp.py .mcp.json
git commit -m "feat: add Caido MCP server wrapping GraphQL API, wire into .mcp.json"
```

---

## Task 8: 全量测试 + 收尾

- [ ] **Step 1: 运行全量测试**

```bash
cd "e:/SRC挖掘/SRC" && .venv/Scripts/python -m pytest tests/ -v --tb=short 2>&1 | tail -30
```

Expected: 全部通过（Caido 集成测试 skip 或 pass）

- [ ] **Step 2: 验证新 phase 流转（smoke test）**

```bash
# 检查 run_scan.py 能识别所有新 phase
cd "e:/SRC挖掘/SRC" && python3 -c "
from TOOLS.run_scan import HANDLERS
assert 'auth_ready' in HANDLERS, 'auth_ready missing'
assert 'auth_explore' in HANDLERS, 'auth_explore missing'
print('Phase handlers OK:', list(HANDLERS.keys()))
"
```

- [ ] **Step 3: 更新 stealth-scanner SKILL.md 状态机描述**

在 `SKILL.md` 的状态机表格加入两行：

```
| `auth_ready`   | cookies 已写入，准备深度探索 | handle_auth_ready → auth_explore |
| `auth_explore` | Playwright 深度导航 + 网络拦截 | auth_explore.py → spider |
```

- [ ] **Step 4: Final commit**

```bash
git add .claude/skills/stealth-scanner/SKILL.md
git commit -m "docs: update stealth-scanner state machine with auth_ready/auth_explore phases"
```

---

## Self-Review

**Spec 覆盖检查：**
- Fix 1 (auth_ready handler) → Task 6 ✓
- Fix 2 (cookie injection: bfs/scrapling/probe) → Task 2/3/4，共享 cookie_helper → Task 1 ✓
- Fix 3 (auth_explore) → Task 5 ✓
- Fix 4 (Caido MCP) → Task 7 ✓

**Placeholder 检查：**
- 无 TBD/TODO（Caido token 获取步骤已在 Task 7.0 明确说明）
- 所有代码块完整

**类型一致性：**
- `get_auth_cookie_header(db_path: str, domain: str) -> str | None` — 在 Task 1 定义，Task 2/3/4 使用 ✓
- `get_auth_cookies_dict(db_path: str, domain: str) -> dict[str, str]` — Task 1 定义，Task 5 使用 ✓
- `write_explore_results_to_db(conn, api_requests, page_urls, sp_prefix)` — Task 5 定义和测试一致 ✓
- `caido_query / list_requests_query / get_request_detail_query` — Task 7 定义和测试一致 ✓
