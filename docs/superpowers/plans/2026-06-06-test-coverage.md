# 测试覆盖计划 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 TOOLS/ 中的核心纯函数补充 pytest 单元测试，覆盖 8 个模块的纯逻辑（不触及外部工具/真实数据库/网络）。

**Architecture:** 测试文件放在 `TOOLS/tests/`，用 pytest + in-memory SQLite。所有被测函数已提取为纯函数（无 subprocess、无网络、无文件 IO），可直接 import 测试。本计划依赖 Bug修复计划（2026-06-06-bug-fixes.md）已执行完毕。

**Tech Stack:** pytest, sqlite3 in-memory, unittest.mock（仅 mock requests/subprocess）

**前置条件：** 已执行 Bug修复计划的全部 12 个 Task。

---

## 文件改动一览

| 文件 | 操作 |
|------|------|
| `TOOLS/tests/__init__.py` | 创建（空文件） |
| `TOOLS/tests/conftest.py` | 创建（共享 fixture） |
| `TOOLS/tests/test_cookie_helper.py` | 创建 |
| `TOOLS/tests/test_auth_explore.py` | 创建 |
| `TOOLS/tests/test_browser_auth.py` | 创建 |
| `TOOLS/tests/test_js_analyzer.py` | 创建 |
| `TOOLS/tests/test_waf_rotate.py` | 创建 |
| `TOOLS/tests/test_migrate.py` | 创建 |

---

## Task 1: 测试目录 + conftest.py

**Files:**
- Create: `TOOLS/tests/__init__.py`
- Create: `TOOLS/tests/conftest.py`

- [ ] **Step 1: 创建 __init__.py**

```bash
touch TOOLS/tests/__init__.py
```

- [ ] **Step 2: 创建 conftest.py**

```python
# TOOLS/tests/conftest.py
"""共享 pytest fixtures。"""

import sqlite3
import sys
from pathlib import Path

import pytest

# 把 TOOLS/ 加入 sys.path，使所有 from db.xxx / from utils.xxx 可用
_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))


@pytest.fixture
def mem_db():
    """返回 in-memory SQLite 连接，建好 auth_sessions 表。"""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_type TEXT,
            token_name TEXT,
            token_value TEXT,
            domain TEXT,
            path TEXT DEFAULT '/',
            is_active INTEGER DEFAULT 1,
            cookie_source TEXT,
            expires_at TEXT
        );
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            depth INTEGER,
            status TEXT,
            source TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT,
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            reasoning TEXT,
            risk TEXT,
            test_status TEXT,
            created_at TEXT
        );
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT DEFAULT (datetime('now', 'localtime')),
            description TEXT
        );
    """)
    yield conn
    conn.close()
```

- [ ] **Step 3: 验证 conftest 可被 pytest 加载**

```bash
cd e:/SRC挖掘/SRC
python -m pytest TOOLS/tests/conftest.py --collect-only 2>&1 | head -10
```

Expected: 无报错（0 个测试被收集，这是正常的）

- [ ] **Step 4: Commit**

```bash
git add TOOLS/tests/__init__.py TOOLS/tests/conftest.py
git commit -m "test: add TOOLS/tests/ with conftest and shared in-memory DB fixture"
```

---

## Task 2: test_cookie_helper.py

**Files:**
- Create: `TOOLS/tests/test_cookie_helper.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_cookie_helper.py
import time

import pytest

from db.cookie_helper import (
    _domain_matches,
    _is_expired,
    _path_matches,
    get_auth_cookies_dict,
    get_auth_cookie_header,
)


class TestDomainMatches:
    def test_exact_match(self):
        assert _domain_matches("example.com", "example.com")

    def test_subdomain_match(self):
        assert _domain_matches("example.com", "api.example.com")

    def test_dot_prefix_match(self):
        assert _domain_matches(".example.com", "api.example.com")

    def test_no_match_different_domain(self):
        assert not _domain_matches("other.com", "api.example.com")

    def test_no_partial_match(self):
        # "example.com" should not match "notexample.com"
        assert not _domain_matches("example.com", "notexample.com")

    def test_empty_cookie_domain(self):
        # empty domain matches nothing
        assert not _domain_matches("", "example.com")


class TestPathMatches:
    def test_root_matches_all(self):
        assert _path_matches("/", "/api/v1/users")

    def test_empty_matches_all(self):
        assert _path_matches("", "/anything")

    def test_exact_match(self):
        assert _path_matches("/api", "/api")

    def test_prefix_with_slash(self):
        assert _path_matches("/api", "/api/v1/users")

    def test_no_partial_segment_match(self):
        # /api must NOT match /api2
        assert not _path_matches("/api", "/api2/endpoint")

    def test_no_unrelated_path(self):
        assert not _path_matches("/admin", "/api/v1")


class TestIsExpired:
    def test_none_not_expired(self):
        assert not _is_expired(None)

    def test_empty_not_expired(self):
        assert not _is_expired("")

    def test_negative_one_not_expired(self):
        assert not _is_expired("-1")

    def test_past_timestamp_expired(self):
        past = str(time.time() - 3600)  # 1 hour ago
        assert _is_expired(past)

    def test_future_timestamp_not_expired(self):
        future = str(time.time() + 3600)  # 1 hour from now
        assert not _is_expired(future)

    def test_iso_past_expired(self):
        assert _is_expired("2020-01-01T00:00:00+00:00")

    def test_iso_future_not_expired(self):
        assert not _is_expired("2099-12-31T23:59:59+00:00")

    def test_unparseable_not_expired(self):
        # conservative: don't filter cookies with unrecognized format
        assert not _is_expired("garbage")


class TestGetAuthCookiesDict:
    def test_returns_matching_cookie(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('session', 'abc123', 'example.com', '/', 1)"
        )
        mem_db.commit()

        db_file = str(tmp_path / "test.db")
        # 把 mem_db 的数据写到临时文件
        import sqlite3 as _s
        dst = _s.connect(db_file)
        mem_db.backup(dst)
        dst.close()

        result = get_auth_cookies_dict(db_file, "example.com")
        assert result == {"session": "abc123"}

    def test_ignores_inactive(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('session', 'abc123', 'example.com', '/', 0)"
        )
        mem_db.commit()

        db_file = str(tmp_path / "test.db")
        import sqlite3 as _s
        dst = _s.connect(db_file)
        mem_db.backup(dst)
        dst.close()

        result = get_auth_cookies_dict(db_file, "example.com")
        assert result == {}

    def test_ignores_expired(self, mem_db, tmp_path):
        past = str(time.time() - 3600)
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active, expires_at) "
            "VALUES ('session', 'abc123', 'example.com', '/', 1, ?)",
            (past,),
        )
        mem_db.commit()

        db_file = str(tmp_path / "test.db")
        import sqlite3 as _s
        dst = _s.connect(db_file)
        mem_db.backup(dst)
        dst.close()

        result = get_auth_cookies_dict(db_file, "example.com")
        assert result == {}

    def test_path_mismatch_excluded(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('admin_token', 'xyz', 'example.com', '/admin', 1)"
        )
        mem_db.commit()

        db_file = str(tmp_path / "test.db")
        import sqlite3 as _s
        dst = _s.connect(db_file)
        mem_db.backup(dst)
        dst.close()

        result = get_auth_cookies_dict(db_file, "example.com", request_path="/api/v1")
        assert result == {}
```

- [ ] **Step 2: 运行并确认通过**

```bash
cd e:/SRC挖掘/SRC
python -m pytest TOOLS/tests/test_cookie_helper.py -v
```

Expected: 全部 PASS（约 16 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/tests/test_cookie_helper.py
git commit -m "test: add test_cookie_helper.py — domain/path/expiry matching + DB integration"
```

---

## Task 3: test_auth_explore.py

**Files:**
- Create: `TOOLS/tests/test_auth_explore.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_auth_explore.py
from auth.auth_explore import filter_api_requests, parse_request_params


class TestFilterApiRequests:
    def _make_req(self, url, resource_type="xhr"):
        return {"url": url, "resource_type": resource_type, "method": "GET"}

    def test_keeps_xhr_same_domain(self):
        reqs = [self._make_req("https://example.com/api/v1")]
        result = filter_api_requests(reqs, "example.com")
        assert len(result) == 1

    def test_keeps_fetch_same_domain(self):
        reqs = [{"url": "https://example.com/api", "resource_type": "fetch", "method": "POST"}]
        result = filter_api_requests(reqs, "example.com")
        assert len(result) == 1

    def test_excludes_stylesheet(self):
        reqs = [self._make_req("https://example.com/style.css", "stylesheet")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_excludes_image(self):
        reqs = [self._make_req("https://example.com/logo.png", "image")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_excludes_different_domain(self):
        reqs = [self._make_req("https://cdn.other.com/api")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_keeps_subdomain(self):
        reqs = [self._make_req("https://api.example.com/v1")]
        result = filter_api_requests(reqs, "example.com")
        assert len(result) == 1

    def test_excludes_static_extension(self):
        reqs = [self._make_req("https://example.com/fonts/icon.woff2")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_empty_list(self):
        assert filter_api_requests([], "example.com") == []


class TestParseRequestParams:
    def test_query_string_params(self):
        params = parse_request_params("https://example.com/api?id=1&type=user", None)
        assert set(params) == {"id", "type"}

    def test_json_post_body(self):
        params = parse_request_params("https://example.com/api", '{"userId": 1, "action": "read"}')
        assert set(params) == {"userId", "action"}

    def test_form_post_body(self):
        params = parse_request_params("https://example.com/api", "username=foo&password=bar")
        assert set(params) == {"username", "password"}

    def test_no_params(self):
        params = parse_request_params("https://example.com/api", None)
        assert params == []

    def test_combined_query_and_body(self):
        params = parse_request_params(
            "https://example.com/api?page=1",
            '{"filter": "active"}'
        )
        assert set(params) == {"page", "filter"}
```

- [ ] **Step 2: 运行**

```bash
python -m pytest TOOLS/tests/test_auth_explore.py -v
```

Expected: 全部 PASS（约 13 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/tests/test_auth_explore.py
git commit -m "test: add test_auth_explore.py — filter_api_requests and parse_request_params"
```

---

## Task 4: test_browser_auth.py

**Files:**
- Create: `TOOLS/tests/test_browser_auth.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_browser_auth.py
from auth.browser_auth import parse_surface_urls


class TestParseSurfaceUrls:
    def _item(self, url):
        return {"url": url, "title": "test"}

    def test_keeps_same_domain(self):
        result = parse_surface_urls([self._item("https://example.com/page")], "example.com")
        assert len(result) == 1

    def test_keeps_subdomain(self):
        result = parse_surface_urls([self._item("https://api.example.com/v1")], "example.com")
        assert len(result) == 1

    def test_excludes_different_domain(self):
        result = parse_surface_urls([self._item("https://evil.com/page")], "example.com")
        assert result == []

    def test_excludes_css(self):
        result = parse_surface_urls([self._item("https://example.com/style.css")], "example.com")
        assert result == []

    def test_excludes_image_png(self):
        result = parse_surface_urls([self._item("https://example.com/img.png")], "example.com")
        assert result == []

    def test_excludes_image_jpg(self):
        result = parse_surface_urls([self._item("https://example.com/photo.jpg")], "example.com")
        assert result == []

    def test_keeps_js(self):
        # JS files should be kept for analysis
        result = parse_surface_urls([self._item("https://example.com/app.js")], "example.com")
        assert len(result) == 1

    def test_excludes_non_http(self):
        result = parse_surface_urls([self._item("ftp://example.com/file")], "example.com")
        assert result == []

    def test_empty_url(self):
        result = parse_surface_urls([{"url": "", "title": ""}], "example.com")
        assert result == []

    def test_www_subdomain_treated_as_same(self):
        result = parse_surface_urls([self._item("https://www.example.com/page")], "example.com")
        assert len(result) == 1

    def test_multiple_mixed(self):
        items = [
            self._item("https://example.com/api"),
            self._item("https://example.com/icon.svg"),
            self._item("https://other.com/page"),
            self._item("https://sub.example.com/data"),
        ]
        result = parse_surface_urls(items, "example.com")
        assert len(result) == 2  # /api and sub.example.com/data
```

- [ ] **Step 2: 运行**

```bash
python -m pytest TOOLS/tests/test_browser_auth.py -v
```

Expected: 全部 PASS（约 11 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/tests/test_browser_auth.py
git commit -m "test: add test_browser_auth.py — parse_surface_urls domain/extension filtering"
```

---

## Task 5: test_js_analyzer.py

**Files:**
- Create: `TOOLS/tests/test_js_analyzer.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_js_analyzer.py
from js_analyzer import parse_mmx_output, score_js_url


class TestScoreJsUrl:
    def test_cdn_skipped(self):
        assert score_js_url("https://cdnjs.cloudflare.com/jquery.min.js") == 0

    def test_vendor_skipped(self):
        assert score_js_url("https://example.com/vendor.bundle.js") == 0

    def test_jquery_skipped(self):
        assert score_js_url("https://example.com/jquery.min.js") == 0

    def test_high_priority_api(self):
        assert score_js_url("https://example.com/api.js") == 2

    def test_high_priority_auth(self):
        assert score_js_url("https://example.com/auth-service.js") == 2

    def test_high_priority_config(self):
        assert score_js_url("https://example.com/config.js") == 2

    def test_chunk_medium_priority(self):
        # webpack/vite hash chunk
        assert score_js_url("https://example.com/main.abc123ef.js") == 1

    def test_generic_medium_priority(self):
        # unknown name, not CDN, not vendor
        assert score_js_url("https://example.com/dashboard.js") == 1


class TestParseMmxOutput:
    def test_valid_json(self):
        raw = '{"api_endpoints": [{"path": "/api/v1", "method": "GET", "params": ["id"]}], "hardcoded_secrets": [], "internal_routes": [], "auth_patterns": []}'
        result = parse_mmx_output(raw)
        assert result is not None
        assert len(result["api_endpoints"]) == 1

    def test_json_in_markdown_fence(self):
        raw = '```json\n{"api_endpoints": [], "hardcoded_secrets": [], "internal_routes": [], "auth_patterns": []}\n```'
        result = parse_mmx_output(raw)
        assert result is not None
        assert result["api_endpoints"] == []

    def test_json_with_preamble(self):
        raw = 'Here is the analysis:\n{"api_endpoints": [], "hardcoded_secrets": [{"type": "apikey", "name": "API_KEY", "value": "secret123"}], "internal_routes": [], "auth_patterns": []}'
        result = parse_mmx_output(raw)
        assert result is not None
        assert len(result["hardcoded_secrets"]) == 1

    def test_invalid_returns_none(self):
        assert parse_mmx_output("not json at all") is None

    def test_empty_returns_none(self):
        assert parse_mmx_output("") is None

    def test_list_returns_none(self):
        # top-level list is not a valid response
        assert parse_mmx_output("[1, 2, 3]") is None
```

- [ ] **Step 2: 运行**

```bash
python -m pytest TOOLS/tests/test_js_analyzer.py -v
```

Expected: 全部 PASS（约 13 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/tests/test_js_analyzer.py
git commit -m "test: add test_js_analyzer.py — score_js_url priority logic and parse_mmx_output"
```

---

## Task 6: test_waf_rotate.py

**Files:**
- Create: `TOOLS/tests/test_waf_rotate.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_waf_rotate.py
from utils.waf_rotate import is_waf_blocked


class TestIsWafBlocked:
    # ── 状态码触发 ───────────────────────────────────────
    def test_403_blocked(self):
        assert is_waf_blocked(403, "")

    def test_429_blocked(self):
        assert is_waf_blocked(429, "rate limit exceeded")

    def test_503_blocked(self):
        assert is_waf_blocked(503, "")

    def test_200_no_keywords_not_blocked(self):
        assert not is_waf_blocked(200, "welcome to the portal")

    # ── 关键词触发 ───────────────────────────────────────
    def test_waf_keyword(self):
        assert is_waf_blocked(200, "waf protection activated")

    def test_modsecurity_keyword(self):
        assert is_waf_blocked(403, "modsecurity blocked your request")

    def test_security_intercept_zh(self):
        assert is_waf_blocked(200, "安全拦截，您的访问已被限制")

    def test_cloudflare_ray_id(self):
        assert is_waf_blocked(403, "Cloudflare Ray ID: 7abc123def")

    def test_too_many_requests(self):
        assert is_waf_blocked(200, "too many requests from your IP")

    # ── 修复后：不再误判 ─────────────────────────────────
    def test_verify_email_not_blocked(self):
        # "verify" 已从关键词移除
        assert not is_waf_blocked(200, "Please verify your email address to continue")

    def test_normal_404_not_blocked(self):
        # "您访问的页面不存在" 已从关键词移除
        assert not is_waf_blocked(404, "您访问的页面不存在，请检查您输入的网址")

    def test_ddos_article_not_blocked(self):
        # "ddos" 已替换为更精确的 "ddos protection"
        assert not is_waf_blocked(200, "本文介绍DDoS攻击的原理与防御方法")

    def test_ddos_protection_page_blocked(self):
        assert is_waf_blocked(200, "ddos protection is active for your IP")

    def test_2fa_page_not_blocked(self):
        assert not is_waf_blocked(200, "Enter your verification code for two-factor authentication")

    def test_empty_body(self):
        assert not is_waf_blocked(200, "")

    def test_none_body(self):
        assert not is_waf_blocked(200, None)
```

- [ ] **Step 2: 运行**

```bash
python -m pytest TOOLS/tests/test_waf_rotate.py -v
```

Expected: 全部 PASS（约 15 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/tests/test_waf_rotate.py
git commit -m "test: add test_waf_rotate.py — is_waf_blocked including regression tests for removed keywords"
```

---

## Task 7: test_migrate.py

**Files:**
- Create: `TOOLS/tests/test_migrate.py`

- [ ] **Step 1: 创建测试文件**

```python
# TOOLS/tests/test_migrate.py
import sqlite3

from db.migrate import apply_migration, detect_legacy_db, ensure_schema_version, get_current_version


def _mem_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


class TestDetectLegacyDb:
    def test_empty_db_not_legacy(self):
        conn = _mem_conn()
        assert not detect_legacy_db(conn)

    def test_has_targets_table_is_legacy(self):
        conn = _mem_conn()
        conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY)")
        assert detect_legacy_db(conn)

    def test_has_pages_table_is_legacy(self):
        conn = _mem_conn()
        conn.execute("CREATE TABLE pages (id INTEGER PRIMARY KEY)")
        assert detect_legacy_db(conn)

    def test_unrelated_table_not_legacy(self):
        conn = _mem_conn()
        conn.execute("CREATE TABLE random_stuff (id INTEGER PRIMARY KEY)")
        assert not detect_legacy_db(conn)


class TestEnsureSchemaVersion:
    def test_creates_table(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "schema_version" in tables

    def test_idempotent(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        ensure_schema_version(conn)  # should not raise


class TestGetCurrentVersion:
    def test_empty_version_table_returns_zero(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        assert get_current_version(conn) == 0

    def test_returns_max_version(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        conn.execute("INSERT INTO schema_version (version) VALUES (3)")
        conn.execute("INSERT INTO schema_version (version) VALUES (1)")
        conn.commit()
        assert get_current_version(conn) == 3


class TestApplyMigration:
    def test_applies_valid_sql(self, tmp_path):
        sql_file = tmp_path / "002_test.sql"
        sql_file.write_text("CREATE TABLE test_table (id INTEGER PRIMARY KEY);")
        conn = _mem_conn()
        ensure_schema_version(conn)
        result = apply_migration(conn, 2, str(sql_file))
        assert result is True
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "test_table" in tables

    def test_ignores_duplicate_column(self, tmp_path):
        sql_file = tmp_path / "003_dup.sql"
        conn = _mem_conn()
        ensure_schema_version(conn)
        conn.execute("CREATE TABLE t (id INTEGER, existing TEXT)")
        sql_file.write_text("ALTER TABLE t ADD COLUMN existing TEXT;")
        result = apply_migration(conn, 3, str(sql_file))
        assert result is True  # should ignore, not fail

    def test_ignores_table_already_exists(self, tmp_path):
        sql_file = tmp_path / "004_exists.sql"
        conn = _mem_conn()
        ensure_schema_version(conn)
        conn.execute("CREATE TABLE already_there (id INTEGER)")
        sql_file.write_text("CREATE TABLE already_there (id INTEGER);")
        result = apply_migration(conn, 4, str(sql_file))
        assert result is True

    def test_fails_on_real_error(self, tmp_path):
        sql_file = tmp_path / "005_bad.sql"
        sql_file.write_text("SELECT * FROM nonexistent_table_xyz;")
        conn = _mem_conn()
        ensure_schema_version(conn)
        result = apply_migration(conn, 5, str(sql_file))
        assert result is False
```

- [ ] **Step 2: 运行**

```bash
python -m pytest TOOLS/tests/test_migrate.py -v
```

Expected: 全部 PASS（约 12 个测试）

- [ ] **Step 3: Commit**

```bash
git add TOOLS/tests/test_migrate.py
git commit -m "test: add test_migrate.py — detect_legacy_db, schema_version, apply_migration edge cases"
```

---

## 最终验证

- [ ] **运行全套测试**

```bash
cd e:/SRC挖掘/SRC
python -m pytest TOOLS/tests/ -v --tb=short 2>&1 | tail -30
```

Expected: 所有测试 PASS，总计约 80 个测试。

- [ ] **统计覆盖率（可选）**

```bash
python -m pytest TOOLS/tests/ --cov=TOOLS --cov-report=term-missing 2>&1 | grep -E "TOTAL|cookie_helper|auth_explore|browser_auth|js_analyzer|waf_rotate|migrate"
```

- [ ] **确认 git log**

```bash
git log --oneline -10
```

Expected: 看到 7 个 test commit。

---

## 自检清单

- [x] conftest 提供 in-memory DB fixture，避免真实 DB 依赖
- [x] 所有测试仅测纯函数，无网络/subprocess
- [x] waf_rotate 测试包含修复前误报场景的回归测试
- [x] migrate 测试覆盖"应忽略"和"不应忽略"两类错误
- [x] cookie_helper 测试覆盖 domain/path/expiry 三个维度
