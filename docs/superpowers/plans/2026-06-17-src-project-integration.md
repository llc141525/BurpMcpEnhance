# SRC Project Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dead code (`caido_mcp.py` and its test), enhance `ssrf_scan.py` with Burp Collaborator OOB detection support, and update `CLAUDE.md` to reflect the new Burp MCP capabilities from Plan 1 (plugin awareness, new tools, Collaborator SSRF workflow, GraphQL hunting).

**Architecture:** No new files created. Three targeted edits: delete dead code, add CLI args to `ssrf_scan.py`, rewrite the MCP tools section in `CLAUDE.md`. Depends on Plan 1 being deployed — run Plan 1 first.

**Tech Stack:** Python 3.11 (uv), pytest, argparse for `ssrf_scan.py`.

**Prerequisite:** Plan 1 (`2026-06-17-burp-mcp-simplify-and-extend.md`) must be completed and the new `burp-mcp-all.jar` loaded in Burp Suite.

---

## File Map

| Action | File | Change |
|--------|------|--------|
| Delete | `E:\SRC挖掘\SRC\TOOLS\caido_mcp.py` | Dead code — Caido not in `.mcp.json` |
| Delete | `E:\SRC挖掘\SRC\tests\test_caido_mcp.py` | Test for dead code |
| Modify | `E:\SRC挖掘\SRC\TOOLS\pipeline\ssrf_scan.py` | Add `--collaborator-url` and `--collaborator-payload-id` args |
| Modify | `E:\SRC挖掘\SRC\TOOLS\tests\test_ssrf_scan.py` | Add tests for new Collaborator args |
| Modify | `E:\SRC挖掘\SRC\CLAUDE.md` | Update MCP tools table, add plugin awareness, Collaborator SSRF workflow, GraphQL section |

---

## Task 1: Remove dead Caido code

**Files:**
- Delete: `E:\SRC挖掘\SRC\TOOLS\caido_mcp.py`
- Delete: `E:\SRC挖掘\SRC\tests\test_caido_mcp.py`

Context: `caido_mcp.py` is not referenced in `.mcp.json` (verified — `.mcp.json` only has `burp` and `scrapling`). It is dead code. Its test suite also tests a non-running server.

- [ ] **Step 1: Verify caido is not in .mcp.json**

```bash
cat "E:/SRC挖掘/SRC/.mcp.json"
```

Expected output contains only `burp` and `scrapling` keys. Confirm no `caido` entry before deleting.

- [ ] **Step 2: Delete the files**

```bash
rm "E:/SRC挖掘/SRC/TOOLS/caido_mcp.py"
rm "E:/SRC挖掘/SRC/tests/test_caido_mcp.py"
```

- [ ] **Step 3: Verify no remaining imports**

```bash
grep -r "caido_mcp\|caido_list_requests\|caido_get_request\|caido_get_sitemap\|caido_search_requests" "E:/SRC挖掘/SRC/TOOLS/" "E:/SRC挖掘/SRC/tests/" 2>/dev/null
```

Expected: no output (no other files import caido_mcp).

- [ ] **Step 4: Run tests to confirm nothing broke**

```bash
cd "E:/SRC挖掘/SRC"
uv run pytest TOOLS/tests/ -x -q 2>&1 | tail -20
```

Expected: same pass/fail count as before (test_caido_mcp.py was testing a dead server, so removing it may actually fix a failure).

- [ ] **Step 5: Commit**

```bash
cd "E:/SRC挖掘/SRC"
git add -u TOOLS/caido_mcp.py tests/test_caido_mcp.py
git commit -m "chore: remove dead caido_mcp.py and its test (not in .mcp.json)"
```

---

## Task 2: Enhance ssrf_scan.py with Collaborator OOB support

**Files:**
- Modify: `E:\SRC挖掘\SRC\TOOLS\pipeline\ssrf_scan.py`
- Modify: `E:\SRC挖掘\SRC\TOOLS\tests\test_ssrf_scan.py`

**Background:** The current `ssrf_scan.py` only detects *reflected* SSRF (server returns internal content in the response body). Blind/OOB SSRF (server makes a request but response body is unchanged) is invisible to it. Adding a Collaborator URL as an injectable payload lets the AI orchestrate OOB detection via `get_collaborator_interactions`.

**Correct workflow the AI will use:**
```
1. AI calls generate_collaborator_payload → gets payload="abc123.burpcollaborator.net", payloadId="abc123"
2. AI calls: uv run python TOOLS/pipeline/ssrf_scan.py --target "xxx" --collaborator-url "http://abc123.burpcollaborator.net/" --collaborator-payload-id "abc123"
3. Script injects the Collaborator URL alongside internal targets
4. After script finishes, AI calls get_collaborator_interactions(payloadId="abc123")
5. Any DNS/HTTP callback = blind SSRF confirmed
```

- [ ] **Step 1: Write failing tests**

Open `TOOLS/tests/test_ssrf_scan.py` and add these tests (append to existing file):

```python
import pytest
from unittest.mock import patch, MagicMock
from TOOLS.pipeline.ssrf_scan import main, probe_ssrf, is_ssrf_response


class TestCollaboratorArgs:
    """Tests for Burp Collaborator OOB SSRF support."""

    def test_collaborator_url_added_to_probe_targets(self, tmp_path):
        """When --collaborator-url is given, it should be probed alongside internal targets."""
        import sqlite3
        import sys

        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        conn.execute("""CREATE TABLE pages (
            id INTEGER PRIMARY KEY, url TEXT, status TEXT,
            suspicious_params_json TEXT
        )""")
        conn.execute("""CREATE TABLE scan_state (id INTEGER, seed_url TEXT)""")
        conn.execute("INSERT INTO scan_state VALUES (1, 'https://example.com')")
        conn.execute("""INSERT INTO pages VALUES (1, 'https://example.com/api?url=http://x.com', 'visited', NULL)""")
        conn.execute("""CREATE TABLE targets (id INTEGER PRIMARY KEY, name TEXT)""")
        conn.execute("INSERT INTO targets VALUES (1, 'test')")
        conn.execute("""CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, method TEXT, url TEXT, query_string TEXT,
            endpoint_type TEXT, business_intent TEXT, risk_hint TEXT,
            status TEXT, source TEXT, notes TEXT
        )""")
        conn.execute("""CREATE TABLE auth_sessions (
            id INTEGER PRIMARY KEY, target_id INTEGER, seed_url TEXT,
            role TEXT, cookie_header TEXT, created_at INTEGER
        )""")
        conn.commit()
        conn.close()

        probed_urls = []

        def fake_probe(url, param, payload, cookie, fetcher, delay):
            probed_urls.append(payload)
            return 0, ""  # no SSRF triggered

        with patch("TOOLS.pipeline.ssrf_scan.find_db", return_value=db), \
             patch("TOOLS.pipeline.ssrf_scan.probe_ssrf", side_effect=fake_probe), \
             patch("TOOLS.pipeline.ssrf_scan.get_auth_cookie_header", return_value=None), \
             patch("sys.argv", ["ssrf_scan.py", "--target", "test",
                                "--collaborator-url", "http://abc123.burpcollaborator.net/"]):
            main()

        assert "http://abc123.burpcollaborator.net/" in probed_urls, \
            f"Collaborator URL should be in probed payloads. Got: {probed_urls}"

    def test_collaborator_payload_id_printed(self, tmp_path, capsys):
        """When --collaborator-payload-id is given, it should be printed so AI can use it."""
        import sqlite3

        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT, status TEXT, suspicious_params_json TEXT)")
        conn.execute("CREATE TABLE scan_state (id INTEGER, seed_url TEXT)")
        conn.execute("INSERT INTO scan_state VALUES (1, 'https://example.com')")
        conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO targets VALUES (1, 'test')")
        conn.execute("CREATE TABLE hunt_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER, method TEXT, url TEXT, query_string TEXT, endpoint_type TEXT, business_intent TEXT, risk_hint TEXT, status TEXT, source TEXT, notes TEXT)")
        conn.execute("CREATE TABLE auth_sessions (id INTEGER PRIMARY KEY, target_id INTEGER, seed_url TEXT, role TEXT, cookie_header TEXT, created_at INTEGER)")
        conn.commit()
        conn.close()

        with patch("TOOLS.pipeline.ssrf_scan.find_db", return_value=db), \
             patch("TOOLS.pipeline.ssrf_scan.get_auth_cookie_header", return_value=None), \
             patch("sys.argv", ["ssrf_scan.py", "--target", "test",
                                "--collaborator-url", "http://abc123.burpcollaborator.net/",
                                "--collaborator-payload-id", "abc123"]):
            main()

        out = capsys.readouterr().out
        assert "abc123" in out, f"Payload ID should appear in output. Got: {out}"
        assert "get_collaborator_interactions" in out, \
            f"Output should remind AI to call get_collaborator_interactions. Got: {out}"

    def test_no_collaborator_url_means_internal_targets_only(self, tmp_path):
        """Without --collaborator-url, only INTERNAL_TARGETS are probed (no regression)."""
        import sqlite3
        from TOOLS.pipeline.ssrf_scan import INTERNAL_TARGETS

        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT, status TEXT, suspicious_params_json TEXT)")
        conn.execute("CREATE TABLE scan_state (id INTEGER, seed_url TEXT)")
        conn.execute("INSERT INTO scan_state VALUES (1, 'https://example.com')")
        conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO targets VALUES (1, 'test')")
        conn.execute("CREATE TABLE hunt_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER, method TEXT, url TEXT, query_string TEXT, endpoint_type TEXT, business_intent TEXT, risk_hint TEXT, status TEXT, source TEXT, notes TEXT)")
        conn.execute("CREATE TABLE auth_sessions (id INTEGER PRIMARY KEY, target_id INTEGER, seed_url TEXT, role TEXT, cookie_header TEXT, created_at INTEGER)")
        conn.commit()
        conn.close()

        probed_payloads = []

        def fake_probe(url, param, payload, cookie, fetcher, delay):
            probed_payloads.append(payload)
            return 0, ""

        with patch("TOOLS.pipeline.ssrf_scan.find_db", return_value=db), \
             patch("TOOLS.pipeline.ssrf_scan.probe_ssrf", side_effect=fake_probe), \
             patch("TOOLS.pipeline.ssrf_scan.get_auth_cookie_header", return_value=None), \
             patch("sys.argv", ["ssrf_scan.py", "--target", "test"]):
            main()

        for p in probed_payloads:
            assert "burpcollaborator" not in p, \
                f"Without --collaborator-url, no Collaborator URL should be probed. Got: {p}"
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
cd "E:/SRC挖掘/SRC"
uv run pytest TOOLS/tests/test_ssrf_scan.py::TestCollaboratorArgs -v
```

Expected: FAIL — `--collaborator-url` argument doesn't exist yet.

- [ ] **Step 3: Add the CLI args and probe logic to ssrf_scan.py**

In `ssrf_scan.py`, find the `main()` function and apply these changes:

**3a — Add two new parser arguments** after `parser.add_argument("--max-rotations", ...)`:

```python
parser.add_argument(
    "--collaborator-url",
    default=None,
    dest="collaborator_url",
    help="Burp Collaborator payload URL for OOB/blind SSRF detection "
         "(e.g. http://abc123.burpcollaborator.net/). "
         "Generate via generate_collaborator_payload MCP tool before calling this script.",
)
parser.add_argument(
    "--collaborator-payload-id",
    default=None,
    dest="collaborator_payload_id",
    help="Collaborator payload ID (returned by generate_collaborator_payload). "
         "Printed in output so the AI knows which ID to poll with get_collaborator_interactions.",
)
```

**3b — Build the payload list** after `candidates = find_ssrf_candidates(conn)`:

```python
probe_targets = list(INTERNAL_TARGETS)
if args.collaborator_url:
    probe_targets.append(args.collaborator_url)
    print(f"[ssrf_scan] OOB mode: Collaborator URL added to probe targets")
    if args.collaborator_payload_id:
        print(f"[ssrf_scan] Collaborator payload ID: {args.collaborator_payload_id}")
        print(
            f"[ssrf_scan] After scan, AI must call: "
            f"get_collaborator_interactions(payloadId='{args.collaborator_payload_id}')"
        )
```

**3c — Replace `INTERNAL_TARGETS` with `probe_targets` in the loop** (currently line `for payload in INTERNAL_TARGETS:`):

```python
    for payload in probe_targets:   # was: for payload in INTERNAL_TARGETS:
```

The full updated `main()` function block after the parse + db setup section:

```python
    probe_targets = list(INTERNAL_TARGETS)
    if args.collaborator_url:
        probe_targets.append(args.collaborator_url)
        print(f"[ssrf_scan] OOB mode: Collaborator URL added to probe targets")
        if args.collaborator_payload_id:
            print(f"[ssrf_scan] Collaborator payload ID: {args.collaborator_payload_id}")
            print(
                f"[ssrf_scan] After scan, AI must call: "
                f"get_collaborator_interactions(payloadId='{args.collaborator_payload_id}')"
            )

    cookie = get_auth_cookie_header(str(db_path), seed_url, role="primary")
    candidates = find_ssrf_candidates(conn)
    print(f"[ssrf_scan] 候选: {len(candidates)} 个  delay={args.delay}s")

    fetcher = RotatingFetcher(max_rotations=args.max_rotations, rotate_delay=30.0)
    found = 0
    probed = 0

    for cand in candidates:
        for payload in probe_targets:          # ← changed from INTERNAL_TARGETS
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
```

- [ ] **Step 4: Run new tests**

```bash
cd "E:/SRC挖掘/SRC"
uv run pytest TOOLS/tests/test_ssrf_scan.py::TestCollaboratorArgs -v
```

Expected: PASS.

- [ ] **Step 5: Run full test suite**

```bash
uv run pytest TOOLS/tests/ -x -q 2>&1 | tail -20
```

Expected: No regressions.

- [ ] **Step 6: Commit**

```bash
cd "E:/SRC挖掘/SRC"
git add TOOLS/pipeline/ssrf_scan.py TOOLS/tests/test_ssrf_scan.py
git commit -m "feat: add Collaborator OOB SSRF detection to ssrf_scan.py"
```

---

## Task 3: Update CLAUDE.md

**Files:**
- Modify: `E:\SRC挖掘\SRC\CLAUDE.md`

This task rewrites two sections and adds two new ones. The changes reflect the capabilities added by Plan 1 and the correct AI workflow for using them.

- [ ] **Step 1: Update the MCP services table**

Find the `### MCP 服务` section. Replace the Burp Suite row and its note:

**OLD:**
```markdown
| Burp Suite              | `list_proxy_http_history` + `get_proxy_http_detail`            | 流量分析+参数篡改+漏洞验证。**结果不直接读，喂 etl_analyzer.py 过滤**                    |
```

**NEW:**
```markdown
| Burp Suite              | 见下方"Burp MCP 工具速查"                                     | 流量分析+参数篡改+漏洞验证+主动扫描+Collaborator OOB+GraphQL探测 |
```

- [ ] **Step 2: Add a "Burp MCP 工具速查" section**

Add this block immediately after the MCP 服务 table (before `### 工具脚本`):

```markdown
### Burp MCP 工具速查

#### 插件感知（重要）

**A 类插件（HTTP Handler）— 对所有 `send_http1_request` 调用自动生效**（无需任何操作）：
- Bypass WAF · Knife · 403 Bypasser · autoDecoder · captcha-killer · Content Type Converter

**B 类插件（Scanner Extension）— 调用 `start_active_scan` 时自动运行**：
- Active Scan++ · Param Miner · HTTP Request Smuggler · FastjsonScan · ShiroScan · Struts RCE · Retirejs

> 调用 `get_burp_info` 可查看当前 Burp 版本、版本类型及能力总结。

#### 工具分类

| 工具 | 用途 | 注意 |
|------|------|------|
| `get_burp_info` | Burp 版本/能力总览 | 会话开始时调用一次 |
| `list_proxy_http_history` | DB 缓存历史（轻量，推荐）| 结果喂 etl_analyzer |
| `get_proxy_http_detail` | 按 ID 取完整请求/响应 | 用 list 先拿 ID |
| `get_proxy_http_history` | 实时 Burp 历史，可选 regex 过滤 | 返回 JSON，量大 |
| `diff_proxy_responses` | 对比两条响应的差异行 | 省 Token，漏洞确认首选 |
| `manage_scope` | 添加/删除/检查目标 Scope | 测试前必须确认 in-scope |
| `get_site_map` | 读取 Burp 已发现的 URL | 可按 URL 前缀过滤 |
| `start_active_scan` | 触发主动扫描（Pro 专属）| auditType: lightweight/extensions_only/deep |
| `get_scanner_issues` | 读取 Burp 扫描结果（实时）| Pro 专属 |
| `list_scanner_issues` | 读取 DB 缓存的扫描结果 | 更轻量，推荐 |
| `generate_collaborator_payload` | 生成 Collaborator OOB payload | Pro 专属 |
| `get_collaborator_interactions` | 查询 OOB 回调（DNS/HTTP/SMTP）| Pro 专属 |
| `graphql_introspect` | 获取并缓存 GraphQL schema | 每个目标调一次即可 |
| `graphql_list_types` | 列出缓存 schema 中的所有类型 | 需先调 introspect |
| `graphql_describe_type` | 查看某类型的所有字段和参数 | 需先调 introspect |
| `graphql_query` | 执行任意 GraphQL 查询 | 用于测试发现的操作 |
| `send_http1_request` | 发送 HTTP/1.1 请求 | A 类插件自动处理 |
| `manage_auto_approve_targets` | 管理请求自动审批列表 | action: add/remove/list/clear |
```

- [ ] **Step 3: Add Collaborator SSRF workflow**

Find `### ETL 分析策略 (etl_analyzer.py)` and add before it:

```markdown
### Collaborator OOB SSRF 工作流

Python 子进程没有 MCP 访问权限，所以 ssrf_scan.py 无法自己调用 generate_collaborator_payload。正确分工：

**AI 负责 orchestrate，ssrf_scan.py 只接收参数：**

```
1. AI 调用: generate_collaborator_payload
   → 得到 payload="abc123.burpcollaborator.net", payloadId="abc123"

2. AI 传参运行扫描:
   uv run python TOOLS/pipeline/ssrf_scan.py --target "目标名" \
     --collaborator-url "http://abc123.burpcollaborator.net/" \
     --collaborator-payload-id "abc123"

3. 等待脚本完成（OOB 回调需时间传播，建议等 10-30 秒后再查）

4. AI 调用: get_collaborator_interactions(payloadId="abc123")
   → 有 DNS/HTTP 回调 = 盲 SSRF 确认
```

**无 Collaborator 时（仅检测反射型 SSRF）：**

```bash
uv run python TOOLS/pipeline/ssrf_scan.py --target "目标名"
```
```

- [ ] **Step 4: Add GraphQL hunting section**

Find `### Burp 查询规则` and add after it:

```markdown
### GraphQL 目标探测工作流

GraphQL 接口（常见于 `/graphql`, `/api/graphql`, `/v1/graphql`）：

```
1. AI 调用: graphql_introspect(targetHostname=..., targetPort=443, usesHttps=True, path="/graphql")
   → 返回 schema 摘要（queries/mutations/types），schema 自动缓存

2. AI 调用: graphql_list_types(cacheKey="host:443/graphql")
   → 查看所有类型，识别敏感实体（User, Admin, Order, File...）

3. AI 调用: graphql_describe_type(cacheKey="...", typeName="User")
   → 查看字段定义，发现隐藏字段（password, role, token...）

4. AI 调用: graphql_query(query="{ user(id:1) { id name email role } }", ...)
   → 验证 IDOR / 越权 / 信息泄露
```

**注意事项：**
- schema 缓存在 Burp 进程内存中，重启 Burp 后需重新 introspect
- 遇到需要 Authorization 的 GraphQL，先用 `manage_scope` + `send_http1_request` 发带 token 的请求
- 发现 mutation 中有 `createAdmin` / `resetPassword` / `assignRole` 等立即升级给操作员
```

- [ ] **Step 5: Update the Burp 查询规则 to reflect merged tool name**

Find this line in CLAUDE.md under `### Burp 查询规则`:

```
- **优先用 `list_proxy_http_history`**（返回精简字段），不用 `get_proxy_http_history_regex`（返回全量字段）
```

Replace with:

```
- **优先用 `list_proxy_http_history`**（返回精简字段）
- 需要实时过滤时用 `get_proxy_http_history`，可选传 `regex` 参数（原 `get_proxy_http_history_regex` 已合并入此工具）
- 响应对比确认漏洞时用 `diff_proxy_responses`，只返回差异行，省 Token
```

- [ ] **Step 6: Commit**

```bash
cd "E:/SRC挖掘/SRC"
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with new Burp MCP tools, plugin awareness, Collaborator workflow, GraphQL hunting"
```

---

## Self-Review

**Spec coverage:**
- ✅ Delete `caido_mcp.py` dead code (Task 1)
- ✅ Delete `test_caido_mcp.py` (Task 1)
- ✅ `ssrf_scan.py` `--collaborator-url` arg (Task 2)
- ✅ `ssrf_scan.py` `--collaborator-payload-id` arg (Task 2)
- ✅ Tests for new args with mock DB (Task 2)
- ✅ CLAUDE.md: Burp MCP tool quick reference table (Task 3)
- ✅ CLAUDE.md: Plugin awareness (A class / B class) (Task 3)
- ✅ CLAUDE.md: Collaborator SSRF orchestration workflow (Task 3)
- ✅ CLAUDE.md: GraphQL hunting workflow (Task 3)
- ✅ CLAUDE.md: merged tool name update (`get_proxy_http_history_regex` note) (Task 3)

**Placeholder scan:** No TBDs. All code, bash commands, and markdown blocks are complete.

**Type consistency:** `probe_targets` variable introduced in `main()` only. `args.collaborator_url` and `args.collaborator_payload_id` added consistently in parser and used in same function.

**Dependency check:** Plan 2 Task 3 references tool names from Plan 1 (`diff_proxy_responses`, `graphql_introspect`, `manage_auto_approve_targets`, `get_burp_info`, `start_active_scan`). These must exist before `CLAUDE.md` is updated — run Plan 1 first.
