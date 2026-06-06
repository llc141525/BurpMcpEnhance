"""结构化活动日志查询。

用法:
  python3 TOOLS/log_view.py                        # 最近 20 条
  python3 TOOLS/log_view.py --today                # 今天所有
  python3 TOOLS/log_view.py --errors               # 只看错误
  python3 TOOLS/log_view.py --waf                  # 只看 WAF 事件
  python3 TOOLS/log_view.py --target "货讯通科技"   # 按目标过滤
  python3 TOOLS/log_view.py --tool brutescan       # 按工具过滤
  python3 TOOLS/log_view.py --last 50 --json       # 最近 50 条，JSON 输出
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
LOG_FILE = PROJECT_ROOT / ".session-log.jsonl"


def load_log() -> list[dict]:
    if not LOG_FILE.exists():
        return []
    entries = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def filter_entries(entries: list[dict], args) -> list[dict]:
    if args.today:
        today = datetime.now().strftime("%Y-%m-%d")
        entries = [e for e in entries if (e.get("ts") or "").startswith(today)]

    if args.errors:
        entries = [e for e in entries if e.get("event") == "error"]

    if args.waf:
        entries = [e for e in entries if e.get("event") in ("waf_blocked", "waf_detect")]

    if args.target:
        t = args.target.lower()
        entries = [e for e in entries if t in (e.get("target") or "").lower()]

    if args.tool:
        t = args.tool.lower()
        entries = [e for e in entries if t in (e.get("tool") or "").lower()]

    return entries


def fmt_entry(e: dict) -> str:
    ts = e.get("ts", "?")[:19]
    tool = e.get("tool", "?")
    event = e.get("event", "?")
    target = e.get("target", "") or ""
    detail = e.get("detail", "") or e.get("error", "") or ""
    url = e.get("url", "") or ""
    elapsed = e.get("elapsed", "")

    parts = [f"[{ts}]", f"{tool}/{event}"]
    if target:
        parts.append(f"| {target}")
    if url:
        parts.append(f"| {url}")
    if elapsed:
        parts.append(f"| {elapsed}s")
    if detail:
        parts.append(f"| {detail}")
    return " ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="结构化活动日志查询")
    parser.add_argument("--today", action="store_true", help="今天所有")
    parser.add_argument("--errors", action="store_true", help="只看错误")
    parser.add_argument("--waf", action="store_true", help="只看 WAF 事件")
    parser.add_argument("--target", help="按目标过滤")
    parser.add_argument("--tool", help="按工具过滤")
    parser.add_argument("--last", type=int, default=20, help="最近 N 条 (默认 20)")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    entries = load_log()
    entries = filter_entries(entries, args)

    total = len(entries)
    if args.last and not args.today and not args.errors and not args.waf:
        entries = entries[-args.last :]

    if args.json:
        print(json.dumps({"total": total, "shown": len(entries), "entries": entries}, ensure_ascii=False, indent=2))
    else:
        for e in entries:
            print(fmt_entry(e))
        if total != len(entries):
            print(f"--- 共 {total} 条，显示 {len(entries)} 条 ---")


if __name__ == "__main__":
    main()
