# Orchestrator + JS Analysis Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the natural-language SKILL.md orchestration with a real Python state machine (`run_scan.py`) and add an automated JS analysis pipeline (`js_analyzer.py`), with all TOOLS scripts reorganized into logical subdirectories.

**Architecture:** `run_scan.py` at TOOLS root reads `scan_state.phase` from SQLite, dispatches to the correct pipeline script via subprocess, and prints structured `[TAG]` output for Claude to read. `js_analyzer.py` is called during spider phase to pull unanalyzed JS from `js_files` table, extract endpoints/secrets via `mmx text chat`, and write findings to `suspicious_points`. All 20+ scripts are reorganized into `pipeline/`, `auth/`, `recon/`, `db/`, `utils/` subdirectories.

**Tech Stack:** Python 3.12, SQLite (WAL mode), subprocess, pytest; external tools: katana, httpx, nuclei, arjun, mmx CLI

---

## File Map

**Created:**
- `TOOLS/run_scan.py` — phase state machine orchestrator
- `TOOLS/js_analyzer.py` — JS batch analysis via mmx
- `TOOLS/pipeline/__init__.py`
- `TOOLS/auth/__init__.py`
- `TOOLS/recon/__init__.py`
- `TOOLS/db/__init__.py`
- `TOOLS/utils/__init__.py`
- `tests/test_run_scan.py`
- `tests/test_js_analyzer.py`

**Moved (git mv):**
- `TOOLS/{init_scan,bfs_crawl,probe_runner,brutescan,scrapling_fetch}.py` → `TOOLS/pipeline/`
- `TOOLS/{browser_auth,chrome_manager,captcha_bypass,feishu_notify}.py` → `TOOLS/auth/`
- `TOOLS/{fofa_relay,zoomeye_query,burp-surface}.py` → `TOOLS/recon/`
- `TOOLS/{db_query,db_backup,migrate,auth_check,session_dash,log_utils,log_view}.py` → `TOOLS/db/`
- `TOOLS/{variant_search,waf_rotate,clash-helper.ps1}` → `TOOLS/utils/`

**Deleted:**
- `TOOLS/migrate_old_db.py`
- `TOOLS/start-stealth-browser.ps1`
- `TOOLS/ad-hoc/` → `tmp/ad-hoc/`

**Modified:**
- `TOOLS/pipeline/init_scan.py` — fix hardcoded `DBS_DIR`
- `TOOLS/pipeline/bfs_crawl.py` — fix hardcoded `DBS_DIR`
- `TOOLS/pipeline/probe_runner.py` — fix hardcoded `DBS_DIR`
- `TOOLS/auth/browser_auth.py` — fix `PROJECT_ROOT` depth
- `TOOLS/auth/chrome_manager.py` — fix `PROJECT_ROOT` depth
- `TOOLS/db/db_query.py` — fix hardcoded `DBS_DIR`
- `TOOLS/db/{db_backup,auth_check,session_dash,log_view}.py` — fix `PROJECT_ROOT` depth
- `TOOLS/utils/variant_search.py` — fix `PROJECT_ROOT` depth
- `tests/test_browser_auth.py` — update import path
- `tests/test_chrome_manager.py` — update import path
- `tests/test_feishu_notify.py` — update import path
- `pyproject.toml` — update ruff ignore paths
- `CLAUDE.md` — update tool table paths
- `.claude/skills/stealth-scanner/SKILL.md` — simplify to 5-line usage

---

## Task 1: TOOLS Directory Reorganization

**Files:** Create subdirs + `__init__.py` files, `git mv` all scripts, delete dead files, move `ad-hoc/`

- [ ] **Step 1: Create subdirectories and empty `__init__.py` files**

```bash
mkdir -p TOOLS/pipeline TOOLS/auth TOOLS/recon TOOLS/db TOOLS/utils
touch TOOLS/pipeline/__init__.py TOOLS/auth/__init__.py TOOLS/recon/__init__.py TOOLS/db/__init__.py TOOLS/utils/__init__.py
```

- [ ] **Step 2: Move pipeline scripts**

```bash
git mv TOOLS/init_scan.py TOOLS/pipeline/init_scan.py
git mv TOOLS/bfs_crawl.py TOOLS/pipeline/bfs_crawl.py
git mv TOOLS/probe_runner.py TOOLS/pipeline/probe_runner.py
git mv TOOLS/brutescan.py TOOLS/pipeline/brutescan.py
git mv TOOLS/scrapling_fetch.py TOOLS/pipeline/scrapling_fetch.py
```

- [ ] **Step 3: Move auth scripts**

```bash
git mv TOOLS/browser_auth.py TOOLS/auth/browser_auth.py
git mv TOOLS/chrome_manager.py TOOLS/auth/chrome_manager.py
git mv TOOLS/captcha_bypass.py TOOLS/auth/captcha_bypass.py
git mv TOOLS/feishu_notify.py TOOLS/auth/feishu_notify.py
```

- [ ] **Step 4: Move recon scripts**

```bash
git mv TOOLS/fofa_relay.py TOOLS/recon/fofa_relay.py
git mv TOOLS/zoomeye_query.py TOOLS/recon/zoomeye_query.py
git mv "TOOLS/burp-surface.py" "TOOLS/recon/burp-surface.py"
```

- [ ] **Step 5: Move db scripts**

```bash
git mv TOOLS/db_query.py TOOLS/db/db_query.py
git mv TOOLS/db_backup.py TOOLS/db/db_backup.py
git mv TOOLS/migrate.py TOOLS/db/migrate.py
git mv TOOLS/auth_check.py TOOLS/db/auth_check.py
git mv TOOLS/session_dash.py TOOLS/db/session_dash.py
git mv TOOLS/log_utils.py TOOLS/db/log_utils.py
git mv TOOLS/log_view.py TOOLS/db/log_view.py
```

- [ ] **Step 6: Move utils scripts**

```bash
git mv TOOLS/variant_search.py TOOLS/utils/variant_search.py
git mv TOOLS/waf_rotate.py TOOLS/utils/waf_rotate.py
git mv "TOOLS/clash-helper.ps1" "TOOLS/utils/clash-helper.ps1"
```

- [ ] **Step 7: Delete dead files and move ad-hoc**

```bash
git rm TOOLS/migrate_old_db.py
git rm "TOOLS/start-stealth-browser.ps1"
mkdir -p tmp/ad-hoc
git mv TOOLS/ad-hoc/* tmp/ad-hoc/ 2>/dev/null || true
git rm -rf TOOLS/ad-hoc
```

- [ ] **Step 8: Stage `__init__.py` files**

```bash
git add TOOLS/pipeline/__init__.py TOOLS/auth/__init__.py TOOLS/recon/__init__.py TOOLS/db/__init__.py TOOLS/utils/__init__.py
```

- [ ] **Step 9: Verify structure**

```bash
ls TOOLS/pipeline/ TOOLS/auth/ TOOLS/recon/ TOOLS/db/ TOOLS/utils/
```

Expected output: each subdir lists its scripts. No `.py` files left at `TOOLS/` root except `run_scan.py` (not yet created), `js_analyzer.py` (not yet created), `schema.sql`, `requirements.txt`, `__init__.py`.

- [ ] **Step 10: Commit**

```bash
git commit -m "refactor: reorganize TOOLS into pipeline/auth/recon/db/utils subdirs"
```

---

## Task 2: Fix Hardcoded DBS_DIR in Pipeline Scripts

**Files:** `TOOLS/pipeline/init_scan.py`, `TOOLS/pipeline/bfs_crawl.py`, `TOOLS/pipeline/probe_runner.py`

All three have `DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))` on line 27/27/35 respectively. After moving to `pipeline/`, the correct relative path is `parent.parent.parent / "dbs"`.

- [ ] **Step 1: Fix `TOOLS/pipeline/init_scan.py`**

Find and replace line 27:
```python
# OLD
DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))
```
```python
# NEW (insert before it)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
```

Remove the `import os` only if it's no longer needed after this change — check the rest of the file first. (`os` is still used for `os.unlink`, so keep the import.)

- [ ] **Step 2: Fix `TOOLS/pipeline/bfs_crawl.py`**

Same change on line 27:
```python
# OLD
DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DBS_DIR = PROJECT_ROOT / "dbs"
```

- [ ] **Step 3: Fix `TOOLS/pipeline/probe_runner.py`**

Same change on line 35:
```python
# OLD
DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DBS_DIR = PROJECT_ROOT / "dbs"
```

- [ ] **Step 4: Verify paths resolve correctly**

```bash
python3 -c "
from pathlib import Path
p = Path('TOOLS/pipeline/init_scan.py').resolve()
root = p.parent.parent.parent
print('PROJECT_ROOT:', root)
print('dbs exists:', (root / 'dbs').exists())
"
```

Expected: `dbs exists: True`

- [ ] **Step 5: Commit**

```bash
git add TOOLS/pipeline/init_scan.py TOOLS/pipeline/bfs_crawl.py TOOLS/pipeline/probe_runner.py
git commit -m "fix: update DBS_DIR to relative path in pipeline scripts"
```

---

## Task 3: Fix PROJECT_ROOT Depth in Auth, DB, and Utils Scripts

**Files:** `TOOLS/auth/browser_auth.py`, `TOOLS/auth/chrome_manager.py`, `TOOLS/db/db_backup.py`, `TOOLS/db/auth_check.py`, `TOOLS/db/session_dash.py`, `TOOLS/db/log_view.py`, `TOOLS/utils/variant_search.py`, `TOOLS/db/db_query.py`

Scripts using `Path(__file__).resolve().parent.parent` had depth 2 (TOOLS/ → SRC/). After moving one level deeper (auth/, db/, utils/), they need depth 3.

- [ ] **Step 1: Fix `TOOLS/auth/browser_auth.py` lines 31–32**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # auth/ → TOOLS/ → SRC/
```

- [ ] **Step 2: Fix `TOOLS/auth/chrome_manager.py` lines 23–24**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # auth/ → TOOLS/ → SRC/
```

- [ ] **Step 3: Fix `TOOLS/db/db_backup.py` line 19**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
```

- [ ] **Step 4: Fix `TOOLS/db/auth_check.py` line 21**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
```

- [ ] **Step 5: Fix `TOOLS/db/session_dash.py` line 15**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
```

- [ ] **Step 6: Fix `TOOLS/db/log_view.py` line 18**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
```

- [ ] **Step 7: Fix `TOOLS/utils/variant_search.py` line 18**

```python
# OLD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
```
```python
# NEW
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # utils/ → TOOLS/ → SRC/
```

- [ ] **Step 8: Fix `TOOLS/db/db_query.py` hardcoded paths (lines 36, 38)**

```python
# OLD
DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))
DEFAULT_DB = os.path.expandvars(r"E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db")
```
```python
# NEW
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
DBS_DIR = _PROJECT_ROOT / "dbs"
DEFAULT_DB = str(_PROJECT_ROOT / ".claude" / "skills" / "stealth-scanner" / "scanner.db")
```

- [ ] **Step 9: Verify db_query still works**

```bash
python3 TOOLS/db/db_query.py --check 2>&1 | head -5
```

Expected: health check output (or "找不到默认 DB" if no default DB exists — that's fine).

- [ ] **Step 10: Commit**

```bash
git add TOOLS/auth/ TOOLS/db/ TOOLS/utils/
git commit -m "fix: update PROJECT_ROOT depth for scripts in auth/db/utils subdirs"
```

---

## Task 4: Update Test Imports and pyproject.toml

**Files:** `tests/test_browser_auth.py`, `tests/test_chrome_manager.py`, `tests/test_feishu_notify.py`, `pyproject.toml`

- [ ] **Step 1: Update `tests/test_browser_auth.py` imports**

Replace all occurrences of:
```python
from TOOLS.browser_auth import
```
with:
```python
from TOOLS.auth.browser_auth import
```

Run: `grep -n "from TOOLS" tests/test_browser_auth.py` to find all occurrences first.

- [ ] **Step 2: Update `tests/test_chrome_manager.py` imports**

Replace:
```python
from TOOLS.chrome_manager import
```
with:
```python
from TOOLS.auth.chrome_manager import
```

- [ ] **Step 3: Update `tests/test_feishu_notify.py` imports**

Replace:
```python
from TOOLS.feishu_notify import
```
with:
```python
from TOOLS.auth.feishu_notify import
```

- [ ] **Step 4: Run existing tests to verify they still pass**

```bash
python3 -m pytest tests/ -v 2>&1 | tail -20
```

Expected: all previously passing tests still pass.

- [ ] **Step 5: Update `pyproject.toml` ruff ignore paths**

Replace the `[tool.ruff.lint.per-file-ignores]` section:

```toml
[tool.ruff.lint.per-file-ignores]
"TOOLS/auth/captcha_bypass.py" = ["S311", "S110", "S112"]
"TOOLS/pipeline/scrapling_fetch.py" = ["S110", "S112"]
"TOOLS/db/db_query.py" = ["S608"]
"TOOLS/recon/fofa_relay.py" = ["S501"]
"TOOLS/utils/waf_rotate.py" = ["S105", "S311", "S501"]
"TOOLS/db/db_backup.py" = ["S603", "S607"]
"TOOLS/db/session_dash.py" = ["S608"]
"TOOLS/pipeline/init_scan.py" = ["S603", "S607"]
"TOOLS/pipeline/bfs_crawl.py" = ["S603", "S607"]
"TOOLS/pipeline/probe_runner.py" = ["S603", "S607", "S608", "S310"]
```

Also update the `exclude` list:
```toml
exclude = ["tmp/ad-hoc/**", "TOOLS/android/**"]
```

- [ ] **Step 6: Verify ruff passes**

```bash
python3 -m ruff check TOOLS/ 2>&1 | head -20
```

Expected: no errors (or only pre-existing issues unrelated to this change).

- [ ] **Step 7: Commit**

```bash
git add tests/ pyproject.toml
git commit -m "fix: update test imports and ruff paths after TOOLS reorganization"
```

---

## Task 5: Implement `TOOLS/run_scan.py`

**Files:** Create `TOOLS/run_scan.py`, create `tests/test_run_scan.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_run_scan.py`:

```python
"""Tests for run_scan.py — pure functions only (no subprocess calls)."""
import io
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def _make_db(phase: str = "init") -> tuple[str, sqlite3.Connection]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(tmp.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            phase TEXT DEFAULT 'init',
            total_pages INTEGER DEFAULT 0,
            total_js INTEGER DEFAULT 0,
            total_suspicious INTEGER DEFAULT 0,
            call_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("INSERT INTO scan_state (id, phase) VALUES (1, ?)", (phase,))
    conn.commit()
    return tmp.name, conn


def test_get_phase_returns_current_phase():
    from TOOLS.run_scan import get_phase
    _, conn = _make_db("spider")
    assert get_phase(conn) == "spider"
    conn.close()


def test_set_phase_updates_db():
    from TOOLS.run_scan import get_phase, set_phase
    _, conn = _make_db("spider")
    set_phase(conn, "probe")
    assert get_phase(conn) == "probe"
    conn.close()


def test_print_tag_outputs_bracket_tag(capsys):
    from TOOLS.run_scan import print_tag
    print_tag("SPIDER_BATCH", ["新增页面: +10", "队列剩余: 50"])
    out = capsys.readouterr().out
    assert "[SPIDER_BATCH]" in out
    assert "新增页面: +10" in out
    assert "队列剩余: 50" in out


def test_print_tag_each_line_indented(capsys):
    from TOOLS.run_scan import print_tag
    print_tag("TEST", ["line one", "line two"])
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert lines[0] == "[TEST]"
    assert lines[1].startswith("  ")
    assert lines[2].startswith("  ")


def test_handle_auth_pending_prints_barrier_and_returns(capsys):
    from TOOLS.run_scan import handle_auth_pending
    _, conn = _make_db("auth_pending")
    # should print AUTH_BARRIER and return without error
    handle_auth_pending(conn)
    out = capsys.readouterr().out
    assert "AUTH_BARRIER" in out
    conn.close()


def test_get_queue_count_returns_int():
    from TOOLS.run_scan import get_queue_count
    _, conn = _make_db()
    conn.execute("""
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued'
        )
    """)
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://a.com', 'queued')")
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://b.com', 'visited')")
    conn.commit()
    assert get_queue_count(conn) == 1
    conn.close()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_run_scan.py -v 2>&1 | tail -15
```

Expected: all 6 tests fail with `ModuleNotFoundError` or `ImportError` since `run_scan.py` doesn't exist yet.

- [ ] **Step 3: Implement `TOOLS/run_scan.py`**

Create `TOOLS/run_scan.py`:

```python
"""编排层：读 scan_state.phase → 调用对应工具脚本 → 打印结构化摘要 → 退出。

用法:
  python TOOLS/run_scan.py --target "台州学院"
  python TOOLS/run_scan.py --target "台州学院" --once   # 只跑一个批次后退出

输出标签:
  [INIT_DONE]           初始化完成，列出存活资产
  [AUTH_BARRIER]        发现认证壁垒，等待操作员
  [SPIDER_BATCH]        BFS 批次完成 + JS 分析摘要
  [PHASE_TRANSITION]    phase 发生切换
  [NEW_SUSPICIOUS_POINTS]  probe 发现新可疑点，停下等 Claude 判断
"""

import argparse
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
TOOLS_DIR = Path(__file__).resolve().parent
PIPELINE_DIR = TOOLS_DIR / "pipeline"


# ── DB helpers ────────────────────────────────────────────────────────────────


def find_db(target: str) -> Path:
    dbs = sorted(DBS_DIR.glob(f"{target}*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dbs:
        sys.exit(f"[error] 找不到目标 DB: dbs/{target}*.db")
    return dbs[0]


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def get_phase(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT phase FROM scan_state WHERE id=1").fetchone()
    return row[0] if row else "init"


def set_phase(conn: sqlite3.Connection, phase: str) -> None:
    conn.execute("UPDATE scan_state SET phase=? WHERE id=1", (phase,))
    conn.commit()


def get_queue_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT count(*) FROM pages WHERE status='queued'").fetchone()
    return row[0] if row else 0


def get_sp_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT count(*) FROM suspicious_points WHERE test_status='untested'").fetchone()
    return row[0] if row else 0


# ── Output ────────────────────────────────────────────────────────────────────


def print_tag(tag: str, lines: list[str]) -> None:
    print(f"[{tag}]")
    for line in lines:
        print(f"  {line}")
    print()


# ── Phase handlers ────────────────────────────────────────────────────────────


def handle_init(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=init → 运行 init_scan.py ...")
    result = subprocess.run(
        [sys.executable, str(PIPELINE_DIR / "init_scan.py"), "--target", target],
        capture_output=False,
        timeout=180,
    )
    if result.returncode != 0:
        print("[warn] init_scan.py 异常退出")

    # Check if auth is needed
    row = conn.execute("SELECT phase FROM scan_state WHERE id=1").fetchone()
    new_phase = row[0] if row else "init"

    if new_phase == "auth_pending":
        # init_scan already set this phase — surface it
        url_row = conn.execute(
            "SELECT url FROM pages WHERE status='queued' AND depth=0 LIMIT 1"
        ).fetchone()
        login_url = url_row[0] if url_row else "（未知）"
        print_tag("AUTH_BARRIER", [
            f"登录页: {login_url}",
            "操作: 通过 Burp 手动登录，成功后写入 auth_sessions 表，然后运行:",
            f'  python TOOLS/db/db_query.py --target "{target}" '
            '"UPDATE scan_state SET phase=\'spider\' WHERE id=1" --write',
        ])
        return

    # Normal path: transition to spider
    set_phase(conn, "spider")
    live_count = conn.execute(
        "SELECT count(*) FROM targets WHERE ip IS NOT NULL AND ip != ''"
    ).fetchone()[0]
    print_tag("INIT_DONE", [
        f"存活资产: {live_count}",
        "下一步: 再次调用 run_scan.py 开始爬取",
    ])


def handle_spider(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=spider → 运行 bfs_crawl.py ...")
    before_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    before_js = conn.execute("SELECT count(*) FROM js_files").fetchone()[0]

    subprocess.run(
        [sys.executable, str(PIPELINE_DIR / "bfs_crawl.py"), "--target", target, "--depth", "3"],
        capture_output=False,
        timeout=300,
    )

    after_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    after_js = conn.execute("SELECT count(*) FROM js_files").fetchone()[0]
    queue = get_queue_count(conn)

    # Run JS analysis batch
    print("[run_scan] → 运行 js_analyzer.py (batch=5) ...")
    js_result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "js_analyzer.py"), "--target", target, "--batch", "5"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    js_summary_lines = [l for l in js_result.stdout.splitlines() if l.strip()]

    new_sp = conn.execute(
        "SELECT count(*) FROM suspicious_points WHERE source='js_analysis' AND test_status='untested'"
    ).fetchone()[0]

    summary = [
        f"新增页面: +{after_pages - before_pages}    JS 文件: +{after_js - before_js}    队列剩余: {queue}",
    ]
    if js_summary_lines:
        summary.append("JS 分析:")
        summary.extend(f"  {l}" for l in js_summary_lines[:10])
    if new_sp:
        summary.append(f"新增 SP (js_analysis): {new_sp} 条")

    if queue == 0:
        set_phase(conn, "probe")
        summary.append("→ 队列耗尽，切换至 probe phase")
        print_tag("PHASE_TRANSITION", summary)
    else:
        print_tag("SPIDER_BATCH", summary)


def handle_probe(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=probe → 运行 probe_runner.py (batch=20) ...")
    before_sp = get_sp_count(conn)

    subprocess.run(
        [sys.executable, str(PIPELINE_DIR / "probe_runner.py"),
         "--target", target, "--mode", "params", "--batch", "20"],
        capture_output=False,
        timeout=300,
    )

    after_sp = get_sp_count(conn)
    new_sp = after_sp - before_sp

    if new_sp > 0:
        # Fetch the new SPs for display
        rows = conn.execute(
            "SELECT id, method, url, param, test_type, risk FROM suspicious_points "
            "WHERE test_status='untested' ORDER BY id DESC LIMIT 10"
        ).fetchall()
        sp_lines = [f"{r[0]}  {r[1]} {r[2]}  param={r[3]}  {r[4]}  {r[5]}" for r in rows]
        print_tag("NEW_SUSPICIOUS_POINTS", sp_lines + ["→ 发送高风险 SP 给 vuln-review skill 验证"])
        return

    # No new SPs and probe queue empty → brute
    set_phase(conn, "brute")
    print_tag("PHASE_TRANSITION", ["probe → brute    无新可疑点，进入目录爆破"])


def handle_brute(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    # Get seed URL for brute
    row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_url = row[0] if row and row[0] else None
    if not seed_url:
        row2 = conn.execute("SELECT domain FROM targets LIMIT 1").fetchone()
        seed_url = ("https://" + row2[0]) if row2 else None

    if not seed_url:
        print("[warn] 无法确定爆破目标 URL，跳过 brute phase")
        set_phase(conn, "spider")
        return

    print(f"[run_scan] phase=brute → 运行 brutescan.py on {seed_url} ...")
    subprocess.run(
        [sys.executable, str(PIPELINE_DIR / "brutescan.py"), "-u", seed_url, "-n", "200"],
        capture_output=False,
        timeout=600,
    )
    set_phase(conn, "spider")
    print_tag("PHASE_TRANSITION", ["brute → spider    目录爆破完成"])


def handle_auth_pending(conn: sqlite3.Connection) -> None:
    print_tag("AUTH_BARRIER", [
        "当前 phase=auth_pending，等待操作员完成登录",
        "完成后执行:",
        '  python TOOLS/db/db_query.py --target "目标名" '
        '"UPDATE scan_state SET phase=\'spider\' WHERE id=1" --write',
    ])


# ── Main ──────────────────────────────────────────────────────────────────────


HANDLERS = {
    "init": handle_init,
    "spider": handle_spider,
    "probe": handle_probe,
    "brute": handle_brute,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="SRC 扫描编排器")
    parser.add_argument("--target", required=True, help="目标名（匹配 dbs/{target}*.db）")
    parser.add_argument("--once", action="store_true", help="只跑一个批次后退出（默认行为）")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

    phase = get_phase(conn)
    print(f"[run_scan] 目标: {args.target}  DB: {db_path.name}  phase: {phase}")

    if phase == "auth_pending":
        handle_auth_pending(conn)
    elif phase in HANDLERS:
        HANDLERS[phase](args.target, db_path, conn)
    else:
        print(f"[warn] 未知 phase: {phase!r}，重置为 init")
        set_phase(conn, "init")

    conn.close()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_run_scan.py -v 2>&1 | tail -15
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add TOOLS/run_scan.py tests/test_run_scan.py
git commit -m "feat: add run_scan.py phase state machine orchestrator"
```

---

## Task 6: Implement `TOOLS/js_analyzer.py`

**Files:** Create `TOOLS/js_analyzer.py`, create `tests/test_js_analyzer.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_js_analyzer.py`:

```python
"""Tests for js_analyzer.py — pure functions only."""
import json
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock

import pytest


def _make_db() -> tuple[str, sqlite3.Connection]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(tmp.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE js_files (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            page_url TEXT,
            analyzed INTEGER DEFAULT 0,
            discovered_apis_json TEXT,
            hardcoded_secrets_json TEXT,
            analyzed_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT DEFAULT 'GET',
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            risk TEXT DEFAULT 'Medium',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT
        )
    """)
    conn.commit()
    return tmp.name, conn


def test_score_js_url_skips_cdn():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://cdnjs.cloudflare.com/jquery.min.js") == 0
    assert score_js_url("https://unpkg.com/react@18/umd/react.js") == 0
    assert score_js_url("https://jsdelivr.net/npm/lodash.js") == 0


def test_score_js_url_skips_vendor_filenames():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://example.com/static/vendor.js") == 0
    assert score_js_url("https://example.com/js/jquery.min.js") == 0
    assert score_js_url("https://example.com/dist/chunk-vendors.js") == 0


def test_score_js_url_high_priority_keywords():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://example.com/js/api-config.js") == 2
    assert score_js_url("https://example.com/static/auth.js") == 2
    assert score_js_url("https://example.com/assets/router.js") == 2
    assert score_js_url("https://example.com/js/user-service.js") == 2


def test_score_js_url_medium_priority_business_domain():
    from TOOLS.js_analyzer import score_js_url
    # Business domain, no specific keyword → medium priority
    assert score_js_url("https://example.com/js/app.chunk.abc123.js") == 1


def test_parse_mmx_output_valid_json():
    from TOOLS.js_analyzer import parse_mmx_output
    raw = json.dumps({
        "api_endpoints": [{"path": "/api/user", "method": "POST", "params": ["uid"]}],
        "hardcoded_secrets": [{"type": "apikey", "name": "ACCESS_KEY", "value": "sk-abc"}],
        "internal_routes": ["/admin/debug"],
        "auth_patterns": []
    })
    result = parse_mmx_output(raw)
    assert result is not None
    assert len(result["api_endpoints"]) == 1
    assert result["hardcoded_secrets"][0]["name"] == "ACCESS_KEY"


def test_parse_mmx_output_invalid_json_returns_none():
    from TOOLS.js_analyzer import parse_mmx_output
    assert parse_mmx_output("not json at all") is None
    assert parse_mmx_output("```json\n{broken}```") is None


def test_write_findings_to_db_inserts_rows():
    from TOOLS.js_analyzer import write_findings_to_db
    db_path, conn = _make_db()
    findings = {
        "api_endpoints": [{"path": "/api/info", "method": "GET", "params": ["id"]}],
        "hardcoded_secrets": [{"type": "apikey", "name": "KEY", "value": "abc123"}],
        "internal_routes": ["/internal/debug"],
        "auth_patterns": [],
    }
    count = write_findings_to_db(conn, "https://example.com/main.js", findings, "SP-JA")
    assert count >= 2  # at least 1 endpoint + 1 secret
    rows = conn.execute("SELECT * FROM suspicious_points").fetchall()
    assert len(rows) >= 2
    types = {r[4] for r in rows}  # test_type column
    assert "hardcoded_secret" in types
    conn.close()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_js_analyzer.py -v 2>&1 | tail -15
```

Expected: all 7 tests fail with `ImportError`.

- [ ] **Step 3: Implement `TOOLS/js_analyzer.py`**

Create `TOOLS/js_analyzer.py`:

```python
"""JS 批量分析：从 js_files 表取未分析 JS → mmx 提取 → 写 suspicious_points。

用法:
  python TOOLS/js_analyzer.py --target "台州学院" --batch 5
  python TOOLS/js_analyzer.py --target "台州学院" --url "https://example.com/main.js"

依赖: mmx CLI (mmx text chat), requests
"""

import argparse
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
TMP_DIR = PROJECT_ROOT / "tmp"

# CDN hostnames to skip entirely
CDN_HOSTS = {"cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net", "staticfiles.com",
              "ajax.googleapis.com", "cdn.jsdelivr.net", "static.cloudflareinsights.com"}

# Filename patterns to skip
LOW_PRIORITY_RE = re.compile(
    r"(vendor|jquery|bootstrap|chunk-vendor|lodash|react\.min|vue\.min|angular\.min"
    r"|moment|popper|d3\.min|echarts\.min|three\.min)",
    re.IGNORECASE,
)

# High-priority filename keywords
HIGH_PRIORITY_RE = re.compile(
    r"(config|api|auth|router|service|main|app|user|order|login|token|secret|key)",
    re.IGNORECASE,
)

MMX_PROMPT_TEMPLATE = """\
分析以下 JavaScript 代码，以 JSON 格式返回安全相关信息（只返回 JSON，无其他内容）：
{{
  "api_endpoints": [{{"path": "...", "method": "GET或POST", "params": ["param1"]}}],
  "hardcoded_secrets": [{{"type": "apikey/token/password/key", "name": "变量名", "value": "值"}}],
  "internal_routes": ["路由路径"],
  "auth_patterns": ["认证头/Cookie名称描述"]
}}

JavaScript 内容：
{content}
"""


# ── Priority scoring ───────────────────────────────────────────────────────────


def score_js_url(url: str) -> int:
    """Return 0 (skip), 1 (medium), or 2 (high priority)."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        filename = Path(parsed.path).name.lower()
    except Exception:
        return 0

    if host in CDN_HOSTS:
        return 0
    if LOW_PRIORITY_RE.search(filename):
        return 0
    if HIGH_PRIORITY_RE.search(filename):
        return 2
    return 1


# ── mmx integration ───────────────────────────────────────────────────────────


def fetch_js_content(url: str, timeout: int = 15) -> str | None:
    try:
        import requests
        resp = requests.get(url, timeout=timeout, verify=False)  # noqa: S501
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        print(f"  [warn] fetch 失败 {url}: {e}", file=sys.stderr)
    return None


def call_mmx(js_content: str) -> str:
    """Send JS content to mmx text chat, return raw stdout."""
    prompt = MMX_PROMPT_TEMPLATE.format(content=js_content[:30000])  # cap at 30KB
    try:
        result = subprocess.run(
            ["mmx", "text", "chat"],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print("[warn] mmx 未安装或不在 PATH，跳过 JS 分析", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print("[warn] mmx 超时（60s），跳过该 JS 文件", file=sys.stderr)
        return ""


def parse_mmx_output(raw: str) -> dict | None:
    """Extract JSON from mmx response. Returns None if parsing fails."""
    # mmx sometimes wraps in ```json ... ```
    match = re.search(r"```json\s*(.*?)```", raw, re.DOTALL)
    if match:
        raw = match.group(1)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    # Try finding first { ... } block
    brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass
    return None


# ── DB writes ─────────────────────────────────────────────────────────────────


def next_sp_id(conn: sqlite3.Connection, prefix: str = "SP-JA") -> str:
    row = conn.execute(
        "SELECT id FROM suspicious_points WHERE id LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{prefix}-%",),
    ).fetchone()
    num = 1
    if row:
        try:
            num = int(row[0].split("-")[-1]) + 1
        except ValueError:
            pass
    return f"{prefix}-{num:03d}"


def write_findings_to_db(
    conn: sqlite3.Connection, js_url: str, findings: dict, id_prefix: str = "SP-JA"
) -> int:
    """Write extracted findings to suspicious_points. Returns count of rows inserted."""
    count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ep in findings.get("api_endpoints", []):
        sp_id = next_sp_id(conn, id_prefix)
        conn.execute(
            "INSERT OR IGNORE INTO suspicious_points "
            "(id, url, param, method, test_type, evidence, source, risk, test_status, created_at) "
            "VALUES (?, ?, ?, ?, 'js_endpoint', ?, 'js_analysis', 'Medium', 'untested', ?)",
            (
                sp_id,
                ep.get("path", ""),
                ",".join(ep.get("params", [])),
                ep.get("method", "GET"),
                f"发现于 JS: {js_url}",
                now,
            ),
        )
        count += conn.execute("SELECT changes()").fetchone()[0]

    for secret in findings.get("hardcoded_secrets", []):
        sp_id = next_sp_id(conn, id_prefix)
        evidence = f"{secret.get('name', '?')}={secret.get('value', '?')} (type={secret.get('type', '?')}) in {js_url}"
        conn.execute(
            "INSERT OR IGNORE INTO suspicious_points "
            "(id, url, test_type, evidence, source, risk, test_status, created_at) "
            "VALUES (?, ?, 'hardcoded_secret', ?, 'js_analysis', 'High', 'untested', ?)",
            (sp_id, js_url, evidence, now),
        )
        count += conn.execute("SELECT changes()").fetchone()[0]

    for route in findings.get("internal_routes", []):
        sp_id = next_sp_id(conn, id_prefix)
        conn.execute(
            "INSERT OR IGNORE INTO suspicious_points "
            "(id, url, test_type, evidence, source, risk, test_status, created_at) "
            "VALUES (?, ?, 'internal_route', ?, 'js_analysis', 'Low', 'untested', ?)",
            (sp_id, route, f"内部路由发现于 JS: {js_url}", now),
        )
        count += conn.execute("SELECT changes()").fetchone()[0]

    conn.commit()

    # Update js_files record
    conn.execute(
        "UPDATE js_files SET analyzed=1, discovered_apis_json=?, hardcoded_secrets_json=?, analyzed_at=? WHERE url=?",
        (
            json.dumps(findings.get("api_endpoints", []), ensure_ascii=False),
            json.dumps(findings.get("hardcoded_secrets", []), ensure_ascii=False),
            now,
            js_url,
        ),
    )
    conn.commit()
    return count


# ── Main analysis logic ───────────────────────────────────────────────────────


def find_db(target: str) -> Path:
    dbs = sorted(DBS_DIR.glob(f"{target}*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dbs:
        sys.exit(f"[error] 找不到目标 DB: dbs/{target}*.db")
    return dbs[0]


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def analyze_batch(target: str, batch: int = 5) -> dict:
    db_path = find_db(target)
    conn = connect(db_path)

    rows = conn.execute(
        "SELECT url FROM js_files WHERE analyzed=0 ORDER BY id DESC"
    ).fetchall()
    candidates = [r[0] for r in rows]

    # Score and sort
    scored = [(score_js_url(u), u) for u in candidates]
    scored = [(s, u) for s, u in scored if s > 0]
    scored.sort(key=lambda x: -x[0])

    to_process = [u for _, u in scored[:batch]]
    skipped = len(candidates) - len(to_process)

    results = {"analyzed": 0, "skipped_low_priority": skipped, "total_sp_written": 0, "details": []}

    for js_url in to_process:
        print(f"  [js] 分析: {js_url}")
        content = fetch_js_content(js_url)
        if not content:
            conn.execute("UPDATE js_files SET analyzed=1 WHERE url=?", (js_url,))
            conn.commit()
            results["details"].append(f"✗ {Path(js_url).name}  → fetch 失败")
            continue

        raw = call_mmx(content)
        if not raw:
            TMP_DIR.mkdir(exist_ok=True)
            (TMP_DIR / f"js_mmx_fail_{hash(js_url) % 9999}.txt").write_text(
                js_url + "\n" + content[:2000], encoding="utf-8"
            )
            conn.execute("UPDATE js_files SET analyzed=1 WHERE url=?", (js_url,))
            conn.commit()
            results["details"].append(f"✗ {Path(js_url).name}  → mmx 无响应")
            continue

        findings = parse_mmx_output(raw)
        if not findings:
            results["details"].append(f"✗ {Path(js_url).name}  → mmx 返回非 JSON")
            conn.execute("UPDATE js_files SET analyzed=1 WHERE url=?", (js_url,))
            conn.commit()
            continue

        sp_count = write_findings_to_db(conn, js_url, findings)
        results["analyzed"] += 1
        results["total_sp_written"] += sp_count

        ep_count = len(findings.get("api_endpoints", []))
        sec_count = len(findings.get("hardcoded_secrets", []))
        detail = f"✓ {Path(js_url).name}  → {ep_count} 端点, {sec_count} 密钥"
        print(f"    {detail}")
        results["details"].append(detail)

    conn.close()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="JS 批量分析器")
    parser.add_argument("--target", help="目标名")
    parser.add_argument("--url", help="单个 JS URL（用于测试）")
    parser.add_argument("--batch", type=int, default=5, help="批次大小（默认 5）")
    args = parser.parse_args()

    if args.url and args.target:
        db_path = find_db(args.target)
        conn = connect(db_path)
        content = fetch_js_content(args.url)
        if content:
            raw = call_mmx(content)
            findings = parse_mmx_output(raw) or {}
            count = write_findings_to_db(conn, args.url, findings)
            print(f"[js_analyzer] 写入 {count} 条 SP")
        conn.close()
    elif args.target:
        results = analyze_batch(args.target, args.batch)
        print(f"[js_analyzer] 分析: {results['analyzed']}  跳过: {results['skipped_low_priority']}  新增SP: {results['total_sp_written']}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_js_analyzer.py -v 2>&1 | tail -15
```

Expected: all 7 tests PASS.

- [ ] **Step 5: Run all tests**

```bash
python3 -m pytest tests/ -v 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add TOOLS/js_analyzer.py tests/test_js_analyzer.py
git commit -m "feat: add js_analyzer.py — JS batch analysis via mmx"
```

---

## Task 7: Update CLAUDE.md and SKILL.md

**Files:** `CLAUDE.md`, `.claude/skills/stealth-scanner/SKILL.md`

- [ ] **Step 1: Update CLAUDE.md tool table**

Find the `### 工具脚本` section in `CLAUDE.md` and replace the entire table with:

```markdown
### 工具脚本

`TOOLS/` 目录:

| 脚本 | 用途 |
|------|------|
| `run_scan.py` | **唯一主入口**: 读 phase 自动调度下一步 |
| `js_analyzer.py` | **JS 批量分析**: mmx 提取端点/密钥 → suspicious_points |
| `pipeline/init_scan.py` | httpx 批量验活 + 技术指纹 |
| `pipeline/bfs_crawl.py` | katana BFS 爬取，写 pages/js_files |
| `pipeline/probe_runner.py` | arjun 参数 fuzz + nuclei + HTTP 方法探测 |
| `pipeline/brutescan.py` | 轻量目录爆破 |
| `pipeline/scrapling_fetch.py` | Scrapling 驱动页面抓取 + 结构化提取 |
| `auth/browser_auth.py` | browser-use 登录 agent |
| `auth/chrome_manager.py` | Chrome 单实例 CDP 管理 |
| `auth/captcha_bypass.py` | OCR 验证码 + 滑块绕过 |
| `auth/feishu_notify.py` | 飞书通知 + 操作员回复轮询 |
| `recon/fofa_relay.py` | FOFA 被动侦察 |
| `recon/zoomeye_query.py` | ZoomEye 被动侦察 |
| `recon/burp-surface.py` | Burp 历史参数词频分析 |
| `db/db_query.py` | 统一 DB 查询工具 |
| `db/db_backup.py` | DB 备份 |
| `db/migrate.py` | DB schema 迁移 |
| `db/auth_check.py` | Session 健康检查 |
| `db/session_dash.py` | 扫描进度总览 |
| `db/log_utils.py` | 结构化 JSON 日志 helper |
| `db/log_view.py` | 日志查询 |
| `utils/variant_search.py` | 变种搜索 |
| `utils/waf_rotate.py` | WAF 绕过/IP 轮换 |
| `utils/clash-helper.ps1` | Clash 代理切换 |
```

- [ ] **Step 2: Update stealth-scanner SKILL.md — usage section**

Open `.claude/skills/stealth-scanner/SKILL.md`. Find the `## 工具速查` table and replace with:

```markdown
## 工具速查

| 场景 | 命令 |
|------|------|
| **启动/继续扫描** | `python TOOLS/run_scan.py --target "{目标}"` |
| 单独 JS 分析 | `python TOOLS/js_analyzer.py --target "{目标}" --batch 5` |
| DB 查询 | `python TOOLS/db/db_query.py --target "{目标}" "SELECT ..."` |
| 资产侦察 | `python TOOLS/recon/fofa_relay.py` |
| 手动登录后恢复 | `python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='spider' WHERE id=1" --write` |
```

Also replace the `## 使用方式` (or equivalent top-level instructions) with:

```markdown
## 使用方式

1. 运行: `python TOOLS/run_scan.py --target "{目标}"`
2. 读输出标签并响应:
   - `[AUTH_BARRIER]` → 告知操作员等待登录
   - `[NEW_SUSPICIOUS_POINTS]` → 判断哪些 SP 值得发给 vuln-review
   - `[SPIDER_BATCH]` / `[INIT_DONE]` / `[PHASE_TRANSITION]` → 再次调用 run_scan.py
3. 无其他调度步骤
```

- [ ] **Step 3: Verify CLAUDE.md still renders correctly**

```bash
python3 -c "
with open('CLAUDE.md', encoding='utf-8') as f:
    content = f.read()
assert 'run_scan.py' in content
assert 'pipeline/init_scan.py' in content
assert 'db/db_query.py' in content
print('CLAUDE.md OK')
"
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md ".claude/skills/stealth-scanner/SKILL.md"
git commit -m "docs: update CLAUDE.md and SKILL.md for new TOOLS structure and run_scan.py"
```

---

## Task 8: Smoke Test on 台州学院 DB

**Goal:** Verify run_scan.py and js_analyzer.py work end-to-end against the real 台州学院 database.

- [ ] **Step 1: Check current DB state**

```bash
python3 TOOLS/db/db_query.py --target "台州学院" "SELECT phase, total_pages, total_js FROM scan_state WHERE id=1"
python3 TOOLS/db/db_query.py --target "台州学院" "SELECT count(*) as unanalyzed FROM js_files WHERE analyzed=0"
```

Note the current phase and unanalyzed JS count.

- [ ] **Step 2: Test js_analyzer standalone (dry run)**

```bash
python3 TOOLS/js_analyzer.py --target "台州学院" --batch 3 2>&1
```

Expected: prints `✓` or `✗` lines for 3 JS files, no Python traceback.

- [ ] **Step 3: Verify SP rows were written**

```bash
python3 TOOLS/db/db_query.py --target "台州学院" "SELECT id, test_type, risk, evidence FROM suspicious_points WHERE source='js_analysis' ORDER BY id DESC LIMIT 5"
```

Expected: at least 1 row with `source='js_analysis'`.

- [ ] **Step 4: Test run_scan.py without running actual network tools**

Check that it reads phase correctly and prints the right tag without crashing:

```bash
python3 TOOLS/run_scan.py --target "台州学院" --once 2>&1 | head -20
```

Expected: prints `[run_scan] 目标: 台州学院  DB: ...  phase: <current_phase>` then the appropriate tag output. No Python traceback.

- [ ] **Step 5: Final test suite**

```bash
python3 -m pytest tests/ -v 2>&1 | tail -25
```

Expected: all tests PASS.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "test: smoke test run_scan and js_analyzer against 台州学院 DB"
```

---

## Self-Review

**Spec coverage check:**
- ✅ 单命令启动 (`run_scan.py`) — Task 5
- ✅ 结构化输出标签 — Task 5 (`print_tag`)
- ✅ DB 单一真相 (`scan_state` only) — Task 5
- ✅ JS 自动分析管道 — Task 6 (`js_analyzer.py`)
- ✅ TOOLS 目录清晰 — Tasks 1–4
- ✅ 删除死代码 — Task 1
- ✅ 接口标准化 (PROJECT_ROOT pattern) — Tasks 2–3
- ✅ SKILL.md 简化 — Task 7
- ✅ CLAUDE.md 更新 — Task 7
- ✅ 端到端测试 — Task 8

**Type consistency check:**
- `get_phase(conn)` → `str` — used in `main()` ✅
- `set_phase(conn, phase)` → `None` — called in handlers ✅
- `get_queue_count(conn)` → `int` — used in `handle_spider` ✅
- `score_js_url(url)` → `int` — used in `analyze_batch` ✅
- `parse_mmx_output(raw)` → `dict | None` — used in `analyze_batch` ✅
- `write_findings_to_db(conn, js_url, findings, prefix)` → `int` — used in `analyze_batch` ✅
