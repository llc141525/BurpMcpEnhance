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
import re
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
            for part in raw.split(","):
                p = part.strip()
                if p:
                    stacks.add(p)
    return sorted(stacks)


def get_missing_mapped_plugins(conn: sqlite3.Connection, stacks: list[str]) -> list[dict]:
    """返回映射表中尚未安装（plugins 表无记录）的插件。"""
    installed = {row[0] for row in conn.execute("SELECT name FROM plugins WHERE source='mapping'").fetchall()}
    return [p for p in get_plugins_for_stacks(stacks) if p["name"] not in installed]


def build_analysis_context(
    conn: sqlite3.Connection,
    stacks: list[str],
    installed_plugin_names: list[str],
) -> dict:
    """构建喂给 mmx 的分析上下文。"""
    rows = conn.execute("SELECT test_type, COUNT(*) as cnt FROM suspicious_points GROUP BY test_type").fetchall()
    sp_coverage = {r[0]: r[1] for r in rows}

    rows2 = conn.execute("SELECT DISTINCT type FROM findings").fetchall()
    confirmed_types = [r[0] for r in rows2]

    return {
        "tech_stacks": stacks,
        "sp_coverage": sp_coverage,
        "confirmed_types": confirmed_types,
        "installed_plugins": installed_plugin_names,
    }


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


def call_mmx_gap_analysis(ctx: dict) -> list[dict]:
    """用 mmx 分析覆盖缺口，返回 gap 列表。失败返回 []。

    每个 gap: {"gap": str, "vuln_types": list[str], "suggest": str, "priority": "High|Medium|Low"}
    """
    prompt = (
        "你是 SRC 渗透测试助手，分析以下扫描数据，找出尚未覆盖的漏洞类型。\n"
        "只输出 JSON 数组，无 markdown 围栏。每项字段:\n"
        '{"gap":"描述","vuln_types":["rce"],"suggest":"nuclei_template|python_script","priority":"High|Medium|Low"}\n'
        "规则: 仅输出 High/Medium 缺口（Low 不输出）; 已安装插件覆盖的类型不重复; 最多 5 条;\n"
        "扫描数据:\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
    )
    tmp_dir = PROJECT_ROOT / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    tmp_path = tmp_dir / f"reflect_gap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    tmp_path.write_text(prompt, encoding="utf-8")
    prompt_content = tmp_path.read_text(encoding="utf-8")
    tmp_path.unlink(missing_ok=True)

    result = subprocess.run(  # noqa: S603
        ["mmx", "text", "chat", "--message", prompt_content, "--output", "text", "--non-interactive"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    raw = result.stdout.strip()
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

        plugins.append(
            {
                "name": name,
                "type": suggest,
                "trigger_stack": "",
                "covers_vuln_types": json.dumps(vuln_types),
                "file_path": rel_path,
                "install_cmd": None,
                "source": "ai_generated",
                "gap_desc": gap["gap"],
                "priority": gap.get("priority", "Medium"),
            }
        )
    return plugins


def _gap_to_name(gap: str) -> str:
    """将缺口描述转为 slug（小写字母数字-）。"""
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
            (p["name"], p["type"], p["trigger_stack"], p["covers_vuln_types"], p["file_path"], now),
        )
        if cur.rowcount:
            staged.append(p)
    conn.commit()
    return staged


def parse_feishu_reply(reply: str, plugin_ids: list[int]) -> list[int]:
    """解析飞书回复，返回需要激活的 plugin id 列表。"""
    r = reply.strip().lower()
    if r == "no":
        return []
    if r.startswith("skip"):
        skip_nums = {int(x) for x in re.findall(r"\d+", r)}
        return [pid for i, pid in enumerate(plugin_ids, 1) if i not in skip_nums]
    return list(plugin_ids)


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
    lines.append('\n回复 "ok" 全部激活 | "skip 2" 跳过第2条 | "no" 全部丢弃')
    lines.append(f"（{timeout_minutes}分钟无回复 → Claude Code 审批）")

    from auth.feishu_notify import send_text_wait_reply  # noqa: PLC0415

    reply = send_text_wait_reply(chat_id, "\n".join(lines), timeout=timeout_minutes * 60)
    if reply is None:
        return None
    return parse_feishu_reply(reply, plugin_ids)


def activate_plugins(conn: sqlite3.Connection, ids_to_activate: list[int]) -> None:
    """将指定 id 的插件置为 active=1。"""
    if not ids_to_activate:
        return
    placeholders = ",".join("?" * len(ids_to_activate))
    conn.execute(f"UPDATE plugins SET active=1 WHERE id IN ({placeholders})", ids_to_activate)  # noqa: S608
    conn.commit()


def _finish(conn: sqlite3.Connection, target: str, added_names: list[str]) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE scan_state SET reflect_ran_at=?, plugins_added_json=? WHERE id=1",
        (now, json.dumps(added_names)),
    )
    conn.commit()
    print(f"[reflect] 完成: 新增插件={added_names}  ran_at={now}")


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
    installed_names = [r[0] for r in conn.execute("SELECT name FROM plugins WHERE source='mapping'").fetchall()]
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

    staged_ids = [conn.execute("SELECT id FROM plugins WHERE name=?", (p["name"],)).fetchone()[0] for p in staged]

    # ── 审批 ─────────────────────────────────────────────────────────────────
    approved_ids = request_approval_feishu(staged, staged_ids, args.target, args.feishu_timeout)

    if approved_ids is None:
        # 超时 → Claude Code 接管
        pending_payload = json.dumps(
            [
                {"id": pid, "name": p["name"], "priority": p["priority"], "gap": p["gap_desc"]}
                for pid, p in zip(staged_ids, staged, strict=False)
            ],
            ensure_ascii=False,
        )
        print(f"[APPROVAL_PENDING] {pending_payload}")
        conn.close()
        sys.exit(2)

    activate_plugins(conn, approved_ids)
    _finish(conn, args.target, [p["name"] for p in staged])
    conn.close()
    sys.exit(0)


if __name__ == "__main__":
    main()
