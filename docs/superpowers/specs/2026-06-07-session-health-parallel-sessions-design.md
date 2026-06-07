# Session Health Check + Parallel Session Guidance — Design Spec

**Date:** 2026-06-07  
**Status:** Approved  
**Scope:** run_scan.py session expiry recovery + SKILL.md parallel session launch guidance

---

## Problem Statement

Two scanner failures identified in post-mortem:

1. **Session expiry mid-scan** — `auth_sessions` has no credential storage. When cookies expire during spider/auth_explore phase, there is no mechanism to detect or recover. The scan proceeds silently with unauthenticated requests.

2. **No parallel session coordination** — After authentication succeeds, vuln-review / business-logic-hunt / manual-replay are never started. The secondary account (required for IDOR testing) is never registered. The operator has no prompt to do either.

---

## Section 1: Data Layer — Credential Storage

### auth_sessions schema change

New columns via migration `010_add_auth_credentials.sql`:

```sql
ALTER TABLE auth_sessions ADD COLUMN username TEXT DEFAULT NULL;
ALTER TABLE auth_sessions ADD COLUMN password TEXT DEFAULT NULL;
```

**Constraint:** Both columns are nullable. Credentials are optional — targets that require only cookie-based auth (SSO, OAuth) will leave these NULL.

### browser_auth.py write path

After successful login, `browser_auth.py` writes credentials to the most recently inserted auth_sessions row:

```python
# After write_cookies_to_db(db_path, cookies):
if args.username:
    conn.execute(
        "UPDATE auth_sessions SET username=?, password=? "
        "WHERE id=(SELECT MAX(id) FROM auth_sessions WHERE cookie_source='browser_use')",
        (args.username, args.password)
    )
    conn.commit()
```

Credentials are only written when `--username` / `--password` were passed to browser_auth.py. No credentials → NULL columns remain NULL.

---

## Section 2: Session Health Check

### New function: `needs_relogin`

Pure function in run_scan.py, unit-testable without subprocess:

```python
def needs_relogin(sessions: list[dict]) -> bool:
    """True if all active sessions are expired or missing."""
    from datetime import datetime
    now = datetime.now()
    active = [s for s in sessions if s.get("is_active")]
    if not active:
        return True
    for s in active:
        exp = s.get("expires_at")
        if not exp:
            return False  # no expiry = treated as valid
        try:
            if datetime.strptime(exp, "%Y-%m-%d %H:%M:%S") > now:
                return False  # at least one valid session
        except ValueError:
            return False
    return True  # all expired
```

### New function: `ensure_session_valid`

Called at the top of `handle_spider` and `handle_auth_explore`:

```python
def ensure_session_valid(target: str, db_path: Path, conn: sqlite3.Connection) -> bool:
    """Check session health; re-login if expired. Returns True if session is valid."""
    # 0. Skip entirely for targets with no browser_use auth sessions
    has_auth = conn.execute(
        "SELECT count(*) FROM auth_sessions WHERE cookie_source='browser_use'"
    ).fetchone()[0]
    if not has_auth:
        return True

    # 1. Run auth_check.py --update
    subprocess.run(
        [PYTHON, str(TOOLS_DIR / "db" / "auth_check.py"), "--target", target, "--update"],
        capture_output=True, text=True, timeout=30, check=False
    )

    # 2. Re-read sessions from DB after update
    rows = conn.execute(
        "SELECT is_active, expires_at, username, password FROM auth_sessions "
        "WHERE cookie_source='browser_use' ORDER BY id DESC LIMIT 5"
    ).fetchall()
    sessions = [{"is_active": r[0], "expires_at": r[1], "username": r[2], "password": r[3]} for r in rows]

    if not needs_relogin(sessions):
        return True

    # 3. Session expired — attempt re-login with stored credentials
    active_cred = next((s for s in sessions if s.get("username")), None)
    if active_cred:
        url_row = conn.execute("SELECT url FROM pages WHERE depth=0 LIMIT 1").fetchone()
        login_url = url_row[0] if url_row else None
        if login_url:
            re_result = subprocess.run(
                [PYTHON, str(TOOLS_DIR / "auth" / "browser_auth.py"),
                 "--target", target, "--url", login_url,
                 "--username", active_cred["username"],
                 "--password", active_cred["password"]],
                timeout=360, check=False
            )
            if re_result.returncode == 0:
                print("[run_scan] Session renewed via browser_auth")
                return True

    # 4. No credentials or re-login failed → AUTH_BARRIER
    url_row = conn.execute("SELECT url FROM pages WHERE depth=0 LIMIT 1").fetchone()
    login_url = url_row[0] if url_row else None
    print_tag("AUTH_BARRIER", [
        "会话已过期，无法自动续期",
        *build_auth_barrier_lines(target, login_url)
    ])
    return False
```

### Call sites

```python
def handle_spider(target, db_path, conn):
    if not ensure_session_valid(target, db_path, conn):
        return  # AUTH_BARRIER already printed
    # ... existing spider logic

def handle_auth_explore(target, db_path, conn):
    if not ensure_session_valid(target, db_path, conn):
        return  # AUTH_BARRIER already printed
    # ... existing auth_explore logic
```

---

## Section 3: Parallel Session Guidance (SKILL.md)

### Trigger

After `[PHASE_TRANSITION] auth_pending → auth_ready` or `[PHASE_TRANSITION] auth_explore → spider` is received, SKILL.md instructs AI to output the following block **before** calling run_scan.py again:

### Output block (non-blocking — AI outputs then continues)

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

提示后继续运行 stealth-scanner，不等待操作员确认。
```

### SKILL.md placement

Inserted as a subsection under **登录流程**:

```markdown
### 认证完成后（并行 session 引导）

收到 `[PHASE_TRANSITION] auth_pending → auth_ready` 或 `auth_explore → spider` 后，输出以下提示块，然后立即继续调用 `run_scan.py`（不等待操作员响应）：

[上方 output block]
```

---

## Migration

File: `migrations/010_add_auth_credentials.sql`

```sql
-- 2026-06-07: add credential columns for session re-login
ALTER TABLE auth_sessions ADD COLUMN username TEXT DEFAULT NULL;
ALTER TABLE auth_sessions ADD COLUMN password TEXT DEFAULT NULL;
```

Applied via:

```bash
python TOOLS/db/migrate.py --target "{目标}"
```

`migrate.py` applies all pending migrations in order, so this runs automatically on next `migrate.py` call.

---

## Unit Tests

New tests in `TOOLS/tests/test_run_scan.py`:

| Test | Input | Expected |
|------|-------|----------|
| `test_needs_relogin_empty` | `[]` | `True` |
| `test_needs_relogin_no_active` | `[{is_active: 0, ...}]` | `True` |
| `test_needs_relogin_no_expiry` | `[{is_active: 1, expires_at: None}]` | `False` |
| `test_needs_relogin_future` | `[{is_active: 1, expires_at: "2099-01-01 00:00:00"}]` | `False` |
| `test_needs_relogin_expired` | `[{is_active: 1, expires_at: "2020-01-01 00:00:00"}]` | `True` |
| `test_needs_relogin_mixed` | one expired + one future | `False` |

---

## File Change Summary

| File | Change |
|------|--------|
| `migrations/010_add_auth_credentials.sql` | New migration: `username`, `password` columns |
| `TOOLS/auth/browser_auth.py` | Write credentials after successful login |
| `TOOLS/run_scan.py` | Add `needs_relogin()`, `ensure_session_valid()`, call at spider/auth_explore entry |
| `TOOLS/tests/test_run_scan.py` | 6 new unit tests for `needs_relogin` |
| `.claude/skills/stealth-scanner/SKILL.md` | Add parallel session guidance block under 登录流程 |

---

## Out of Scope

- Credential encryption at rest (plaintext in SQLite, acceptable for local tool)
- Multi-target credential reuse
- Automatic secondary account creation
