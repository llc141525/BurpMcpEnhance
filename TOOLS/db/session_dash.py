"""三 Session 进度总览。读 scan_state + 各表行数，检测停滞。

用法:
  python3 TOOLS/session_dash.py --all                          # 所有目标概览
  python3 TOOLS/session_dash.py --target "货讯通科技"           # 单目标详情
  python3 TOOLS/session_dash.py --all --stuck-hours 6           # 标记超过 6h 无进展的目标
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DBS_DIR = PROJECT_ROOT / "dbs"


def find_all_dbs() -> list[Path]:
    return sorted(DBS_DIR.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)


def find_target_db(target: str) -> Path | None:
    matches = sorted(DBS_DIR.glob(f"{target}_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def query_one(conn) -> dict | None:
    row = conn.execute("SELECT * FROM scan_state WHERE id = 1").fetchone()
    return dict(row) if row else None


def count_table(conn, table: str, where: str = "1=1") -> int:
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}").fetchone()
        return row[0] if row else 0
    except Exception:
        return -1


def dash_target(db_path: Path) -> dict:
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        state = query_one(conn)
        if state is None:
            return {"db": db_path.name, "error": "no scan_state"}

        target_name = db_path.stem.rsplit("_", 1)[0]

        pages_total = count_table(conn, "pages")
        pages_queued = count_table(conn, "pages", "status='queued'")
        pages_scanned = count_table(conn, "pages", "status='scanned'")

        sp_total = count_table(conn, "suspicious_points")
        sp_untested = count_table(conn, "suspicious_points", "test_status='untested'")
        sp_confirmed = count_table(conn, "suspicious_points", "test_status='confirmed'")
        sp_fp = count_table(conn, "suspicious_points", "test_status='false_positive'")

        findings_total = count_table(conn, "findings")
        findings_high = count_table(conn, "findings", "risk='High'")
        findings_critical = count_table(conn, "findings", "risk='Critical'")

        js_count = count_table(conn, "js_files")

        phase = state.get("phase", "unknown")
        started = state.get("started_at", "")
        call_count = state.get("call_count", 0)

        # 活跃度判断
        hours_since_start = None
        if started:
            try:
                st = datetime.strptime(started, "%Y-%m-%d %H:%M:%S")
                hours_since_start = round((datetime.now() - st).total_seconds() / 3600, 1)
            except ValueError:
                pass

        stuck = False
        if phase in ("spider", "probe", "brute") and hours_since_start is not None and hours_since_start > 24:
            stuck = True

        return {
            "target": target_name,
            "db": db_path.name,
            "phase": phase,
            "rounds": call_count,
            "started": started,
            "hours_ago": hours_since_start,
            "stuck": stuck,
            "pages": {"total": pages_total, "queued": pages_queued, "scanned": pages_scanned},
            "js_files": js_count,
            "suspicious_points": {
                "total": sp_total,
                "untested": sp_untested,
                "confirmed": sp_confirmed,
                "false_positive": sp_fp,
            },
            "findings": {"total": findings_total, "critical": findings_critical, "high": findings_high},
        }
    finally:
        conn.close()


def print_detail(d: dict) -> None:
    if "error" in d:
        print(f"=== {d['db']} === [SKIP: {d['error']}]\n")
        return
    print(f"=== {d['target']} ===")
    stuck_tag = " [STUCK]" if d.get("stuck") else ""
    print(f"Phase: {d['phase']}{stuck_tag} | Rounds: {d['rounds']} | Started: {d['started']} ({d['hours_ago']}h ago)")

    p = d["pages"]
    if p["total"] > 0:
        print(f"  pages:        {p['total']:>5} total | {p['scanned']:>5} scanned | {p['queued']:>5} queued")
    if d["js_files"] > 0:
        print(f"  js_files:     {d['js_files']:>5}")

    sp = d["suspicious_points"]
    if sp["total"] > 0:
        print(
            f"  suspicious:   {sp['total']:>5} total | {sp['untested']:>5} untested"
            f" | {sp['confirmed']:>5} confirmed | {sp['false_positive']:>5} fp"
        )

    f = d["findings"]
    if f["total"] > 0:
        print(f"  findings:     {f['total']:>5} total | CRIT:{f['critical']} HIGH:{f['high']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Session 进度总览")
    parser.add_argument("--target", help="目标名称")
    parser.add_argument("--all", action="store_true", help="所有目标概览")
    parser.add_argument("--stuck-hours", type=int, default=24, help="停滞阈值小时数 (默认 24)")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    if args.target:
        db_path = find_target_db(args.target)
        if db_path is None:
            print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False))
            sys.exit(1)
        dbs = [db_path]
    elif args.all:
        dbs = find_all_dbs()
        if not dbs:
            print(json.dumps({"msg": "dbs/ 目录无 DB 文件"}, ensure_ascii=False))
            return
    else:
        parser.print_help()
        sys.exit(1)

    results = []
    for db_path in dbs:
        d = dash_target(db_path)
        # 重新评估 stuck 阈值
        if d.get("hours_ago") and d["hours_ago"] > args.stuck_hours and d["phase"] not in ("done", "init"):
            d["stuck"] = True
        results.append(d)
        if not args.json:
            print_detail(d)

    if args.json:
        print(json.dumps({"dashboards": results}, ensure_ascii=False, indent=2))

    stuck_count = sum(1 for r in results if r.get("stuck"))
    if stuck_count:
        names = ", ".join(r.get("target", r.get("db", "?")) for r in results if r.get("stuck"))
        print(f"[!] {stuck_count} 目标疑似停滞 (> {args.stuck_hours}h): {names}")


if __name__ == "__main__":
    main()
