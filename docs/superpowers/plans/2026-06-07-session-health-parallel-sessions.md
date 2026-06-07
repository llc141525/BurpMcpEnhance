# Session Health Check + Parallel Session Guidance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect and recover from mid-scan session expiry, store credentials for auto-relogin, and prompt the operator to start parallel sessions after authentication.

**Architecture:** Migration adds `username`/`password` columns to `auth_sessions`; `browser_auth.py` writes credentials on success; `run_scan.py` gains a pure `needs_relogin()` function and a `ensure_session_valid()` side-effectful function that auto-renews sessions at spider/auth_explore entry; `stealth-scanner/SKILL.md` gains a non-blocking post-auth guidance block.

**Tech Stack:** Python 3.11, SQLite (via sqlite3), pytest, browser-use, existing `auth_check.py --update`

---

## File Map

| Action | File |
|--------|------|
| Create | `migrations/010_add_auth_credentials.sql` |
| Modify | `TOOLS/auth/browser_auth.py` — add `write_credentials_to_db()`, call in `main()` |
| Modify | `TOOLS/run_scan.py` — add `needs_relogin()`, `ensure_session_valid()`, wire into handlers |
| Modify | `TOOLS/tests/test_run_scan.py` — add 6 `TestNeedsRelogin` tests |
| Modify | `TOOLS/tests/test_browser_auth.py` — add `TestWriteCredentials` test |
| Modify | `.claude/skills/stealth-scanner/SKILL.md` — add post-auth parallel session block |

---

## Task 1: Migration 010 — add credential columns

**Files:**
- Create: `migrations/010_add_auth_credentials.sql`

- [ ] **Step 1: Create the migration file**

```sql
-- 010: store login credentials for session re-login
ALTER TABLE auth_sessions ADD COLUMN username TEXT DEFAULT NULL;
ALTER TABLE auth_sessions ADD COLUMN password TEXT DEFAULT NULL;
```

Save to `migrations/010_add_auth_credentials.sql`.

- [ ] **Step 2: Verify the migration applies to an existing DB**

```bash
cd "e:/SRC挖掘/SRC"
python TOOLS/db/migrate.py --target "台州学院" --status
python TOOLS/db/migrate.py --target "台州学院"
python TOOLS/db/migrate.py --target "台州学院" --status
```

Expected: status shows version 10 after running. If no target DB exists, create one first:
```bash
python TOOLS/db/db_query.py --target "台州学院" --init
python TOOLS/db/migrate.py --target "台州学院"
```

- [ ] **Step 3: Verify columns exist**

```bash
python TOOLS/db/db_query.py --target "台州学院" "PRAGMA table_info(auth_sessions)"
```

Expected: rows for `username` and `password` appear in the output.

- [ ] **Step 4: Commit**

```bash
git add migrations/010_add_auth_credentials.sql
git commit -m "feat: migration 010 — add username/password to auth_sessions"
```

---

## Task 2: browser_auth.py — write credentials after login

**Files:**
- Modify: `TOOLS/auth/browser_auth.py`
- Modify: `TOOLS/tests/test_browser_auth.py`

- [ ] **Step 1: Write the failing test**

Add to `TOOLS/tests/test_browser_auth.py`:

```python
import sqlite3
import sys
from pathlib import Path

# (already imported in existing test file; add only the new class below)

class TestWriteCredentialsToDb:
    def _make_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.executescript("""
            CREATE TABLE auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT, token_name TEXT, token_value TEXT,
                domain TEXT, path TEXT DEFAULT '/',
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                role TEXT DEFAULT 'primary', expires_at TEXT,
                last_checked_at TEXT, cookie_source TEXT DEFAULT 'manual',
                username TEXT DEFAULT NULL,
                password TEXT DEFAULT NULL
            );
            INSERT INTO auth_sessions (token_type, token_name, token_value, domain, cookie_source)
            VALUES ('cookie', 'session', 'abc123', 'example.com', 'browser_use');
        """)
        return conn

    def test_writes_username_and_password(self, tmp_path):
        db_file = tmp_path / "test.db"
        conn = self._make_db()
        # persist to tmp file
        import os
        dest = sqlite3.connect(str(db_file))
        for line in conn.iterdump():
            dest.execute(line)
        dest.commit()
        dest.close()
        conn.close()

        from auth.browser_auth import write_credentials_to_db
        write_credentials_to_db(str(db_file), "user123", "pass456")

        check = sqlite3.connect(str(db_file))
        row = check.execute("SELECT username, password FROM auth_sessions WHERE cookie_source='browser_use'").fetchone()
        check.close()
        assert row[0] == "user123"
        assert row[1] == "pass456"

    def test_does_not_write_when_no_browser_use_row(self, tmp_path):
        db_file = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_file))
        conn.executescript("""
            CREATE TABLE auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT, token_name TEXT, token_value TEXT,
                domain TEXT, cookie_source TEXT DEFAULT 'manual',
                username TEXT DEFAULT NULL, password TEXT DEFAULT NULL
            );
            INSERT INTO auth_sessions (token_type, cookie_source) VALUES ('cookie', 'manual');
        """)
        conn.commit()
        conn.close()

        from auth.browser_auth import write_credentials_to_db
        # Should not raise, just updates nothing
        write_credentials_to_db(str(db_file), "user123", "pass456")

        check = sqlite3.connect(str(db_file))
        row = check.execute("SELECT username FROM auth_sessions").fetchone()
        check.close()
        assert row[0] is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python.exe -m pytest TOOLS/tests/test_browser_auth.py::TestWriteCredentialsToDb -v
```

Expected: `ImportError` or `AttributeError: module 'auth.browser_auth' has no attribute 'write_credentials_to_db'`

- [ ] **Step 3: Implement write_credentials_to_db in browser_auth.py**

Add this function after the existing `write_cookies_to_db` function (around line 90):

```python
def write_credentials_to_db(db_path: str, username: str, password: str) -> None:
    """写 username/password 到最近一条 browser_use cookie 记录。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        "UPDATE auth_sessions SET username=?, password=? "
        "WHERE id=(SELECT MAX(id) FROM auth_sessions WHERE cookie_source='browser_use')",
        (username, password),
    )
    conn.commit()
    conn.close()
```

Then in `main()`, inside the `if success:` block, add the credential write after `set_phase`:

```python
    if success:
        set_phase(db_path, "auth_ready")
        if args.username:
            write_credentials_to_db(db_path, args.username, args.password)
        print("[browser_auth] 登录成功，phase → auth_ready", file=sys.stderr)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/Scripts/python.exe -m pytest TOOLS/tests/test_browser_auth.py -v
```

Expected: all tests PASS (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add TOOLS/auth/browser_auth.py TOOLS/tests/test_browser_auth.py
git commit -m "feat: browser_auth writes credentials to auth_sessions after login"
```

---

## Task 3: needs_relogin() — TDD

**Files:**
- Modify: `TOOLS/tests/test_run_scan.py` (add `TestNeedsRelogin` class)
- Modify: `TOOLS/run_scan.py` (add `needs_relogin` function)

- [ ] **Step 1: Write the failing tests**

Add to `TOOLS/tests/test_run_scan.py` (after existing imports, add `needs_relogin` to the import line):

```python
from run_scan import (
    build_auth_barrier_lines,
    build_spider_summary,
    get_phase,
    get_queue_count,
    get_sp_count,
    needs_relogin,           # ← add this
    probe_next_phase,
    set_phase,
    spider_next_phase,
)
```

Add this class at the bottom of the file:

```python
# ── needs_relogin ─────────────────────────────────────────────────────────────


class TestNeedsRelogin:
    def test_empty_sessions_returns_true(self):
        assert needs_relogin([]) is True

    def test_no_active_sessions_returns_true(self):
        sessions = [{"is_active": 0, "expires_at": "2099-01-01 00:00:00"}]
        assert needs_relogin(sessions) is True

    def test_active_no_expiry_returns_false(self):
        sessions = [{"is_active": 1, "expires_at": None}]
        assert needs_relogin(sessions) is False

    def test_active_future_expiry_returns_false(self):
        sessions = [{"is_active": 1, "expires_at": "2099-01-01 00:00:00"}]
        assert needs_relogin(sessions) is False

    def test_active_expired_returns_true(self):
        sessions = [{"is_active": 1, "expires_at": "2020-01-01 00:00:00"}]
        assert needs_relogin(sessions) is True

    def test_mixed_expired_and_future_returns_false(self):
        sessions = [
            {"is_active": 1, "expires_at": "2020-01-01 00:00:00"},
            {"is_active": 1, "expires_at": "2099-01-01 00:00:00"},
        ]
        assert needs_relogin(sessions) is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/Scripts/python.exe -m pytest TOOLS/tests/test_run_scan.py::TestNeedsRelogin -v
```

Expected: `ImportError: cannot import name 'needs_relogin' from 'run_scan'`

- [ ] **Step 3: Implement needs_relogin in run_scan.py**

Add this function after `get_sp_count` (around line 52), before the `# ── Output ──` section:

```python
def needs_relogin(sessions: list[dict]) -> bool:
    """True 表示所有活跃 session 均已过期或无 session，需要重新登录。"""
    from datetime import datetime

    active = [s for s in sessions if s.get("is_active")]
    if not active:
        return True
    now = datetime.now()
    for s in active:
        exp = s.get("expires_at")
        if not exp:
            return False  # 无过期时间视为永久有效
        try:
            if datetime.strptime(exp, "%Y-%m-%d %H:%M:%S") > now:
                return False
        except ValueError:
            return False  # 格式异常视为有效
    return True
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/Scripts/python.exe -m pytest TOOLS/tests/test_run_scan.py::TestNeedsRelogin -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Run full test suite to check for regressions**

```bash
.venv/Scripts/python.exe -m pytest TOOLS/tests/test_run_scan.py -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add TOOLS/tests/test_run_scan.py TOOLS/run_scan.py
git commit -m "feat: add needs_relogin() pure function with 6 unit tests"
```

---

## Task 4: ensure_session_valid() + wire into handlers

**Files:**
- Modify: `TOOLS/run_scan.py`

- [ ] **Step 1: Add ensure_session_valid() to run_scan.py**

Add this function after `needs_relogin()`, before the `# ── Output ──` section:

```python
def ensure_session_valid(target: str, db_path: Path, conn: sqlite3.Connection) -> bool:
    """检查 session 健康状态；已过期则尝试自动续期。返回 True 表示 session 有效。"""
    has_auth = conn.execute(
        "SELECT count(*) FROM auth_sessions WHERE cookie_source='browser_use'"
    ).fetchone()[0]
    if not has_auth:
        return True  # 无需认证的目标直接通过

    subprocess.run(
        [PYTHON, str(TOOLS_DIR / "db" / "auth_check.py"), "--target", target, "--update"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    rows = conn.execute(
        "SELECT is_active, expires_at, username, password FROM auth_sessions "
        "WHERE cookie_source='browser_use' ORDER BY id DESC LIMIT 5"
    ).fetchall()
    sessions = [
        {"is_active": r[0], "expires_at": r[1], "username": r[2], "password": r[3]}
        for r in rows
    ]

    if not needs_relogin(sessions):
        return True

    active_cred = next((s for s in sessions if s.get("username")), None)
    if active_cred:
        url_row = conn.execute("SELECT url FROM pages WHERE depth=0 LIMIT 1").fetchone()
        login_url = url_row[0] if url_row else None
        if login_url:
            re_result = subprocess.run(  # noqa: S603
                [
                    PYTHON,
                    str(TOOLS_DIR / "auth" / "browser_auth.py"),
                    "--target", target,
                    "--url", login_url,
                    "--username", active_cred["username"],
                    "--password", active_cred["password"],
                ],
                timeout=360,
                check=False,
            )
            if re_result.returncode == 0:
                print("[run_scan] Session 已续期")
                return True

    url_row = conn.execute("SELECT url FROM pages WHERE depth=0 LIMIT 1").fetchone()
    login_url = url_row[0] if url_row else None
    print_tag(
        "AUTH_BARRIER",
        ["会话已过期，无法自动续期", *build_auth_barrier_lines(target, login_url)],
    )
    return False
```

- [ ] **Step 2: Wire ensure_session_valid into handle_spider**

In `handle_spider`, add the guard as the very first line of the function body:

```python
def handle_spider(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    if not ensure_session_valid(target, db_path, conn):
        return
    print("[run_scan] phase=spider → 运行 bfs_crawl.py ...")
    # ... rest unchanged
```

- [ ] **Step 3: Wire ensure_session_valid into handle_auth_explore**

In `handle_auth_explore`, add the guard as the very first line:

```python
def handle_auth_explore(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    if not ensure_session_valid(target, db_path, conn):
        return
    print("[run_scan] phase=auth_explore → 运行 auth_explore.py ...")
    # ... rest unchanged
```

- [ ] **Step 4: Run the full test suite to verify no regressions**

```bash
.venv/Scripts/python.exe -m pytest TOOLS/tests/ -v
```

Expected: all existing tests PASS. (ensure_session_valid itself calls subprocesses so it is not unit tested — its logic is covered by needs_relogin tests.)

- [ ] **Step 5: Smoke-test on a target without auth (ensure_session_valid returns True silently)**

```bash
python TOOLS/db/db_query.py --target "台州学院" "SELECT count(*) FROM auth_sessions WHERE cookie_source='browser_use'"
```

If result is 0, run_scan.py will pass through `ensure_session_valid` without touching auth_check.py. Verify:

```bash
python TOOLS/run_scan.py --target "台州学院"
```

Expected: normal output, no `[AUTH_BARRIER]` tag, spider or probe phase runs normally.

- [ ] **Step 6: Commit**

```bash
git add TOOLS/run_scan.py
git commit -m "feat: ensure_session_valid() — auto-renew expired sessions at spider/auth_explore entry"
```

---

## Task 5: SKILL.md — parallel session guidance

**Files:**
- Modify: `.claude/skills/stealth-scanner/SKILL.md`

- [ ] **Step 1: Add post-auth guidance section to SKILL.md**

In `.claude/skills/stealth-scanner/SKILL.md`, find the section:

```markdown
### 降级：手动登录（browser_auth 失败时）
```

Add the following new section immediately after that section ends (after the third `run_scan.py` step block):

```markdown
### 认证完成后（并行 session 引导）

收到 `[PHASE_TRANSITION] auth_pending → auth_ready` 或 `[PHASE_TRANSITION] auth_explore → spider` 后，输出以下提示块，然后立即继续调用 `run_scan.py`（不等待操作员响应）：

```
=== 认证完成，建议同时启动 ===

Session B — vuln-review（随时消化现有 SP）:
  Skill(skill="vuln-review", args="模式: 复核; 目标: {目标}")

Session C — business-logic-hunt（需 Burp 历史有流量后启动）:
  Skill(skill="business-logic-hunt", args="目标: {目标}")

secondary 账号（IDOR 测试必需，有则注册）:
  python TOOLS/auth/browser_auth.py --target "{目标}" \
    --url "{登录URL}" --username <B账号> --password <B密码>
  然后执行:
  python TOOLS/db/db_query.py --target "{目标}" \
    "UPDATE auth_sessions SET role='secondary' WHERE id=(SELECT MAX(id) FROM auth_sessions)" --write
```
```

- [ ] **Step 2: Verify skill-editor consistency check**

```
Skill(skill="skill-editor", args="validate stealth-scanner")
```

Expected: all checks pass — allowed-tools covers all tools referenced, name matches directory.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/stealth-scanner/SKILL.md
git commit -m "feat: stealth-scanner — post-auth parallel session guidance block"
```

---

## Self-Review

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| migration 010 `username`/`password` columns | Task 1 |
| browser_auth.py writes credentials after login | Task 2 |
| `needs_relogin()` pure function | Task 3 |
| 6 unit tests for `needs_relogin` | Task 3 |
| `ensure_session_valid()` in run_scan.py | Task 4 |
| Wire into `handle_spider` + `handle_auth_explore` | Task 4 |
| SKILL.md parallel session guidance block | Task 5 |

**No gaps found.**

**Type consistency:** `needs_relogin(sessions: list[dict])` — consistent across Task 3 tests and Task 3 implementation. `ensure_session_valid(target: str, db_path: Path, conn: sqlite3.Connection) -> bool` — consistent between Task 4 implementation and Task 4 wire steps. `write_credentials_to_db(db_path: str, username: str, password: str)` — consistent between Task 2 test and implementation.

**No placeholders found.**
