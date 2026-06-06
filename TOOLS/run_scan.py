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
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # TOOLS/ → SRC/
TOOLS_DIR = Path(__file__).resolve().parent
PIPELINE_DIR = TOOLS_DIR / "pipeline"

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


# ── Output ────────────────────────────────────────────────────────────────────


def print_tag(tag: str, lines: list[str]) -> None:
    print(f"[{tag}]")
    for line in lines:
        print(f"  {line}")
    print()


# ── Phase handlers ────────────────────────────────────────────────────────────


def handle_init(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=init → 运行 init_scan.py ...")
    subprocess.run(  # noqa: S603
        [sys.executable, str(PIPELINE_DIR / "init_scan.py"), "--target", target],
        timeout=180,
        check=False,
    )

    row = conn.execute("SELECT phase FROM scan_state WHERE id=1").fetchone()
    new_phase = row[0] if row else "init"

    if new_phase == "auth_pending":
        url_row = conn.execute("SELECT url FROM pages WHERE status='queued' AND depth=0 LIMIT 1").fetchone()
        login_url = url_row[0] if url_row else "（未知）"
        print_tag(
            "AUTH_BARRIER",
            [
                f"登录页: {login_url}",
                "操作: 通过 Burp 手动登录，成功后写入 auth_sessions 表，然后运行:",
                f'  python TOOLS/db/db_query.py --target "{target}" '
                "\"UPDATE scan_state SET phase='spider' WHERE id=1\" --write",
            ],
        )
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
    print("[run_scan] phase=spider → 运行 bfs_crawl.py ...")
    before_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    before_js = conn.execute("SELECT count(*) FROM js_files").fetchone()[0]

    subprocess.run(  # noqa: S603
        [sys.executable, str(PIPELINE_DIR / "bfs_crawl.py"), "--target", target, "--depth", "3"],
        timeout=300,
        check=False,
    )

    after_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    after_js = conn.execute("SELECT count(*) FROM js_files").fetchone()[0]
    queue = get_queue_count(conn)

    print("[run_scan] → 运行 js_analyzer.py (batch=5) ...")
    js_result = subprocess.run(  # noqa: S603
        [sys.executable, str(TOOLS_DIR / "js_analyzer.py"), "--target", target, "--batch", "5"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    js_lines = [line for line in js_result.stdout.splitlines() if line.strip() and not line.startswith("[js_analyzer]")]

    new_sp = conn.execute(
        "SELECT count(*) FROM suspicious_points WHERE source='js_analysis' AND test_status='untested'"
    ).fetchone()[0]

    summary = [
        f"新增页面: +{after_pages - before_pages}    JS 文件: +{after_js - before_js}    队列剩余: {queue}",
    ]
    if js_lines:
        summary.append("JS 分析:")
        summary.extend(f"  {line}" for line in js_lines[:8])
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

    subprocess.run(  # noqa: S603
        [
            sys.executable,
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

    if new_sp > 0:
        rows = conn.execute(
            "SELECT id, method, url, param, test_type, risk FROM suspicious_points "
            "WHERE test_status='untested' ORDER BY id DESC LIMIT 10"
        ).fetchall()
        sp_lines = [f"{r[0]}  {r[1]} {r[2]}  param={r[3]}  {r[4]}  {r[5]}" for r in rows]
        print_tag("NEW_SUSPICIOUS_POINTS", sp_lines + ["→ 发送高风险 SP 给 vuln-review skill 验证"])
        return

    set_phase(conn, "brute")
    print_tag("PHASE_TRANSITION", ["probe → brute    无新可疑点，进入目录爆破"])


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
        [sys.executable, str(PIPELINE_DIR / "brutescan.py"), "-u", seed_url, "-n", "200"],
        timeout=600,
        check=False,
    )
    set_phase(conn, "spider")
    print_tag("PHASE_TRANSITION", ["brute → spider    目录爆破完成"])


def handle_auth_pending(conn: sqlite3.Connection) -> None:
    print_tag(
        "AUTH_BARRIER",
        [
            "当前 phase=auth_pending，等待操作员完成登录",
            "完成后执行:",
            '  python TOOLS/db/db_query.py --target "目标名" '
            "\"UPDATE scan_state SET phase='spider' WHERE id=1\" --write",
        ],
    )


def handle_auth_ready(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=auth_ready → 切换至 auth_explore")
    set_phase(conn, "auth_explore")
    print_tag("PHASE_TRANSITION", ["auth_ready → auth_explore    开始认证后深度导航"])


def handle_auth_explore(target: str, db_path: Path, conn: sqlite3.Connection) -> None:
    print("[run_scan] phase=auth_explore → 运行 auth_explore.py ...")
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(TOOLS_DIR / "auth" / "auth_explore.py"), "--target", target],
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
    "brute": handle_brute,
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
        handle_auth_pending(conn)
    elif phase == "auth_timeout":
        print_tag(
            "AUTH_BARRIER",
            [
                "登录超时，请重新尝试手动登录",
                "完成后执行: UPDATE scan_state SET phase='auth_ready' WHERE id=1",
            ],
        )
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
