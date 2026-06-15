"""编排层：读 scan_state.phase → 调用对应工具脚本 → 打印结构化摘要 → 退出。

用法:
  python TOOLS/run_scan.py --target "台州学院"
  python TOOLS/run_scan.py --target "台州学院" --once

输出标签:
  [INIT_DONE]                初始化完成
  [AUTH_BARRIER]             发现认证壁垒，等待操作员
  [SPIDER_BATCH]             BFS 批次完成 + JS 分析摘要
  [PHASE_TRANSITION]         phase 切换
  [NEW_SUSPICIOUS_POINTS]    probe 发现新可疑点
"""

import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # TOOLS/ → SRC/
TOOLS_DIR = Path(__file__).resolve().parent
PIPELINE_DIR = TOOLS_DIR / "pipeline"

# 优先用 uv venv Python（含 browser-use 等依赖），fallback 到当前解释器
_venv_python = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
PYTHON = str(_venv_python) if _venv_python.exists() else sys.executable

sys.path.insert(0, str(TOOLS_DIR))
from db.db_utils import connect, find_db  # noqa: E402


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


def ensure_session_valid(target: str, db_path: Path, conn: sqlite3.Connection) -> bool:
    """检查 session 健康状态；已过期则调 session_manager 自动续期。返回 True 表示 session 有效。"""
    has_auth = conn.execute("SELECT count(*) FROM auth_sessions WHERE is_active=1").fetchone()[0]
    if not has_auth:
        return True  # 无需认证的目标直接通过

    result = subprocess.run(  # noqa: S603
        [PYTHON, str(TOOLS_DIR / "auth" / "session_manager.py"), "--target", target, "--role", "primary"],
        timeout=400,
        check=False,
    )
    if result.returncode == 0:
        return True

    url_row = conn.execute("SELECT url FROM pages WHERE depth=0 LIMIT 1").fetchone()
    login_url = url_row[0] if url_row else None
    print_tag(
        "AUTH_BARRIER",
        ["会话已过期，无法自动续期", *build_auth_barrier_lines(target, login_url)],
    )
    return False


# ── Output ────────────────────────────────────────────────────────────────────


def print_tag(tag: str, lines: list[str]) -> None:
    print(f"[{tag}]")
    for line in lines:
        print(f"  {line}")
    print()


# ── Pure decision / formatting functions (testable without subprocess) ────────


def spider_next_phase(queue_count: int) -> str | None:
    """队列耗尽 → 'probe'，否则 None（继续 spider）。"""
    return "probe" if queue_count == 0 else None


def probe_next_phase(new_sp: int) -> str | None:
    """无新 SP → 'exploit'，否则 None（继续展示 SP）。"""
    return "exploit" if new_sp == 0 else None


def exploit_next_phase() -> str:
    return "brute"


def build_spider_summary(
    new_pages: int,
    new_js: int,
    queue: int,
    js_lines: list[str],
    new_sp: int,
) -> list[str]:
    """构建 SPIDER_BATCH / PHASE_TRANSITION 的摘要行列表。"""
    summary = [
        f"新增页面: +{new_pages}    JS 文件: +{new_js}    队列剩余: {queue}",
    ]
    if js_lines:
        summary.append("JS 分析:")
        summary.extend(f"  {line}" for line in js_lines[:8])
    if new_sp:
        summary.append(f"新增 SP (js_analysis): {new_sp} 条")
    return summary


def build_auth_barrier_lines(target: str, login_url: str | None) -> list[str]:
    """构建 AUTH_BARRIER 标签的正文行列表。"""
    url_display = login_url if login_url else "（未知）"
    return [
        f"登录页: {url_display}",
        "操作: 通过 Burp 手动登录，成功后写入 auth_sessions 表，然后运行:",
        f'  python TOOLS/db/db_query.py --target "{target}" '
        "\"UPDATE scan_state SET phase='auth_ready' WHERE id=1\" --write",
    ]


# ── Phase handlers ────────────────────────────────────────────────────────────


def handle_init(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=init → 运行 init_scan.py ...")
    subprocess.run(  # noqa: S603
        [PYTHON, str(PIPELINE_DIR / "init_scan.py"), "--target", target],
        timeout=180,
        check=False,
    )

    row = conn.execute("SELECT phase FROM scan_state WHERE id=1").fetchone()
    new_phase = row[0] if row else "init"

    if new_phase == "auth_pending":
        url_row = conn.execute("SELECT url FROM pages WHERE status='queued' AND depth=0 LIMIT 1").fetchone()
        login_url = url_row[0] if url_row else None
        print_tag("AUTH_BARRIER", build_auth_barrier_lines(target, login_url))
        return

    set_phase(conn, "spider")
    live_count = conn.execute("SELECT count(*) FROM targets WHERE ip IS NOT NULL AND ip != ''").fetchone()[0]
    print_tag(
        "INIT_DONE",
        [
            f"存活资产: {live_count}",
            "下一步: 再次调用 run_scan.py 开始爬取",
        ],
    )


def handle_spider(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    if not ensure_session_valid(target, db_path, conn):
        return
    print("[run_scan] phase=spider → 运行 bfs_crawl.py ...")
    before_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    before_js = conn.execute("SELECT count(*) FROM js_files").fetchone()[0]

    subprocess.run(  # noqa: S603
        [PYTHON, str(PIPELINE_DIR / "bfs_crawl.py"), "--target", target, "--depth", "3"],
        timeout=600,
        check=False,
    )

    after_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    after_js = conn.execute("SELECT count(*) FROM js_files").fetchone()[0]
    queue = get_queue_count(conn)

    print("[run_scan] → 运行 js_analyzer.py (batch=5) ...")
    js_result = subprocess.run(  # noqa: S603
        [PYTHON, str(TOOLS_DIR / "js_analyzer.py"), "--target", target, "--batch", "5"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    js_lines = [line for line in js_result.stdout.splitlines() if line.strip() and not line.startswith("[js_analyzer]")]

    new_sp = conn.execute(
        "SELECT count(*) FROM suspicious_points WHERE source='js_analysis' AND test_status='untested'"
    ).fetchone()[0]

    summary = build_spider_summary(after_pages - before_pages, after_js - before_js, queue, js_lines, new_sp)

    next_phase = spider_next_phase(queue)
    if next_phase:
        set_phase(conn, next_phase)
        summary.append(f"→ 队列耗尽，切换至 {next_phase} phase")
        print_tag("PHASE_TRANSITION", summary)
    else:
        print_tag("SPIDER_BATCH", summary)


def handle_probe(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=probe → 运行 probe_runner.py (batch=20) ...")
    before_sp = get_sp_count(conn)

    subprocess.run(  # noqa: S603
        [
            PYTHON,
            str(PIPELINE_DIR / "probe_runner.py"),
            "--target",
            target,
            "--mode",
            "params",
            "--batch",
            "20",
        ],
        timeout=300,
        check=False,
    )

    after_sp = get_sp_count(conn)
    new_sp = after_sp - before_sp

    next_phase = probe_next_phase(new_sp)
    if next_phase is None:
        rows = conn.execute(
            "SELECT id, method, url, param, test_type, risk FROM suspicious_points "
            "WHERE test_status='untested' ORDER BY id DESC LIMIT 10"
        ).fetchall()
        sp_lines = [f"{r[0]}  {r[1]} {r[2]}  param={r[3]}  {r[4]}  {r[5]}" for r in rows]
        print_tag("NEW_SUSPICIOUS_POINTS", sp_lines + ["→ 发送高风险 SP 给 vuln-review skill 验证"])
        return

    set_phase(conn, next_phase)
    print_tag("PHASE_TRANSITION", [f"probe → {next_phase}    无新可疑点，进入框架专项 exploit 阶段"])


def handle_exploit(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=exploit → 运行 framework_exploit.py ...")
    fe_result = subprocess.run(  # noqa: S603
        [PYTHON, str(PIPELINE_DIR / "framework_exploit.py"), "--target", target],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if fe_result.stdout:
        for line in fe_result.stdout.splitlines():
            if line.startswith("[UNKNOWN_FRAMEWORK]"):
                names = line.split("] ", 1)[-1]
                print_tag(
                    "UNKNOWN_FRAMEWORK",
                    [
                        f"以下框架不在知识库中: {names}",
                        "用 Claude WebSearch 查 CVE 后手动补写 SP:",
                        "  WebSearch('框架名 CVE RCE 漏洞 2024 2025')",
                    ],
                )
            else:
                print(line)

    # SQLi 扫描（仅当有含参 URL 时）
    param_count = conn.execute("SELECT count(*) FROM pages WHERE url LIKE '%?%'").fetchone()[0]
    if param_count > 0:
        print(f"[run_scan] phase=exploit → 运行 sqli_scan.py (含参URL={param_count}) ...")
        subprocess.run(  # noqa: S603
            [PYTHON, str(PIPELINE_DIR / "sqli_scan.py"), "--target", target, "--batch", "5"],
            timeout=1800,
            check=False,
        )

    set_phase(conn, exploit_next_phase())
    print_tag("PHASE_TRANSITION", ["exploit → brute    框架专项 + SQLi 扫描完成"])


def handle_brute(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_url = row[0] if row and row[0] else None
    if not seed_url:
        row2 = conn.execute("SELECT domain FROM targets LIMIT 1").fetchone()
        if row2:
            d = row2[0].strip()
            seed_url = d if d.startswith("http") else "https://" + d

    if not seed_url:
        print("[warn] 无法确定爆破目标 URL，跳过 brute phase")
        set_phase(conn, "spider")
        return

    print(f"[run_scan] phase=brute → 运行 brutescan.py on {seed_url} ...")
    subprocess.run(  # noqa: S603
        [PYTHON, str(PIPELINE_DIR / "brutescan.py"), "-u", seed_url, "-n", "200"],
        timeout=600,
        check=False,
    )
    set_phase(conn, "reflect")
    print_tag("PHASE_TRANSITION", ["brute → reflect    目录爆破完成，进入自进化分析"])


def handle_reflect(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=reflect → 运行 reflect.py ...")
    result = subprocess.run(  # noqa: S603
        [PYTHON, str(PIPELINE_DIR / "reflect.py"), "--target", target],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="")

    if result.returncode == 2:
        pending_line = next(
            (line for line in result.stdout.splitlines() if line.startswith("[APPROVAL_PENDING]")),
            None,
        )
        if pending_line:
            import json  # noqa: PLC0415

            pending_json = pending_line[len("[APPROVAL_PENDING]") :].strip()
            try:
                pending = json.loads(pending_json)
            except json.JSONDecodeError:
                pending = []
            _handle_reflect_approval_cli(conn, pending)
    elif result.returncode not in (0, 2):
        print(f"[warn] reflect.py 退出码 {result.returncode}，非致命，继续")

    set_phase(conn, "done")
    print_tag("PHASE_TRANSITION", ["reflect → done    自进化分析完成"])


def _handle_reflect_approval_cli(conn: sqlite3.Connection, pending: list[dict]) -> None:
    """飞书审批超时后，在 Claude Code 界面展示待审批列表并读取输入。"""
    if not pending:
        return
    print("\n[reflect] 飞书审批超时，等待审批:")
    for i, p in enumerate(pending, 1):
        print(f"  [{i}] {p.get('name', '?')} ({p.get('priority', '?')}) — {p.get('gap', '?')}")
    print("\n回复 'ok' 全部激活 | 'skip N' 跳过第N条 | 'no' 全部丢弃 (默认: ok)")
    try:
        reply = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        reply = "ok"
    if not reply:
        reply = "ok"

    from pipeline.reflect import activate_plugins, parse_feishu_reply  # noqa: PLC0415

    plugin_ids = [p["id"] for p in pending if isinstance(p.get("id"), int)]
    approved_ids = parse_feishu_reply(reply, plugin_ids)
    activate_plugins(conn, approved_ids)
    print(f"[reflect] 激活 {len(approved_ids)} 个插件")


def handle_auth_pending(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    """先尝试 browser_auth.py AI 自动登录；失败或环境不足时降级为 [AUTH_BARRIER]。"""
    url_row = conn.execute("SELECT url FROM pages WHERE status='queued' AND depth=0 LIMIT 1").fetchone()
    login_url = url_row[0] if url_row else None

    has_deepseek = bool(os.environ.get("DEEPSEEK_API"))
    has_feishu = bool(os.environ.get("FEISHU_CHAT_ID"))

    if has_deepseek and has_feishu and login_url:
        print(f"[run_scan] phase=auth_pending → browser_auth.py on {login_url}")
        result = subprocess.run(  # noqa: S603
            [PYTHON, str(TOOLS_DIR / "auth" / "browser_auth.py"), "--target", target, "--url", login_url],
            timeout=360,
            check=False,
        )
        if result.returncode == 0:
            # browser_auth.py 已将 phase 设为 auth_ready，下次调用 run_scan 继续
            print_tag("PHASE_TRANSITION", ["auth_pending → auth_ready    AI 登录成功"])
            return

    # browser_auth 失败或环境不足 → 降级为手动登录指南
    print_tag("AUTH_BARRIER", build_auth_barrier_lines(target, login_url))


def handle_auth_ready(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=auth_ready → 切换至 auth_explore")
    set_phase(conn, "auth_explore")
    print_tag("PHASE_TRANSITION", ["auth_ready → auth_explore    开始认证后深度导航"])


def handle_auth_explore(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    if not ensure_session_valid(target, db_path, conn):
        return
    print("[run_scan] phase=auth_explore → 运行 auth_explore.py ...")
    result = subprocess.run(  # noqa: S603
        [PYTHON, str(TOOLS_DIR / "auth" / "auth_explore.py"), "--target", target],
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        print(f"[warn] auth_explore.py 退出码 {result.returncode}，手动切换 phase→spider")
        set_phase(conn, "spider")

    sp_count = get_sp_count(conn)
    print_tag(
        "PHASE_TRANSITION",
        [
            f"auth_explore → spider    认证面 SP: {sp_count} 条",
        ],
    )


# ── Main ──────────────────────────────────────────────────────────────────────


HANDLERS = {
    "init": handle_init,
    "spider": handle_spider,
    "probe": handle_probe,
    "exploit": handle_exploit,
    "brute": handle_brute,
    "reflect": handle_reflect,
    "auth_ready": handle_auth_ready,
    "auth_explore": handle_auth_explore,
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
        handle_auth_pending(args.target, db_path, conn)
    elif phase == "auth_timeout":
        # 重置为 auth_pending 并重试 AI 登录
        set_phase(conn, "auth_pending")
        handle_auth_pending(args.target, db_path, conn)
    elif phase == "chrome_error":
        print_tag(
            "AUTH_BARRIER",
            [
                "Chrome 启动失败，请检查 chrome_manager.py",
                "修复后执行: UPDATE scan_state SET phase='init' WHERE id=1",
            ],
        )
    elif phase in HANDLERS:
        HANDLERS[phase](args.target, db_path, conn)
    else:
        print(f"[warn] 未知 phase: {phase!r}，重置为 init")
        set_phase(conn, "init")

    conn.close()


if __name__ == "__main__":
    main()
