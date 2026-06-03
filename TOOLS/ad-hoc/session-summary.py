"""Session summary hook for Claude Code SRC sessions.

Creates a timestamped session summary entry, lists recently modified files,
and reminds the operator to save findings before the session context is lost.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path("E:/SRC挖掘/SRC")
REPORTS_DIR = PROJECT_ROOT / "reports"
SESSION_LOG = PROJECT_ROOT / ".session-log.jsonl"


def main():
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    date_tag = now.strftime("%Y%m%d_%H%M%S")

    # Collect recently modified files in the project (last 24h)
    recent_files = []
    cutoff = now.timestamp() - 86400
    for f in PROJECT_ROOT.rglob("*"):
        if f.is_file() and f.suffix not in {".pyc", ".pyo", ".class"}:
            try:
                mtime = f.stat().st_mtime
                if mtime > cutoff:
                    recent_files.append({
                        "path": str(f.relative_to(PROJECT_ROOT)),
                        "mtime": datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
                    })
            except OSError:
                pass

    recent_files.sort(key=lambda x: x["mtime"], reverse=True)
    recent_files = recent_files[:30]  # top 30

    # Ensure reports dir exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Append to session log
    entry = {
        "timestamp": timestamp,
        "date_tag": date_tag,
        "recent_files": [f["path"] for f in recent_files[:15]],
        "findings_saved": None  # operator fills this in
    }
    try:
        with open(SESSION_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass

    print(f"\n{'='*60}")
    print(f" SRC Session Ended — {timestamp}")
    print(f"{'='*60}")
    print(f"\n  Reports: {REPORTS_DIR}")
    print(f"  Session log: {SESSION_LOG}")
    print(f"\n  Recently modified files:")
    if recent_files:
        for rf in recent_files[:15]:
            safe_path = rf['path'].encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding)
            print(f"    [{rf['mtime']}] {safe_path}")
    else:
        print("    (none in last 24h)")
    print(f"\n  REMINDER: Save any pending findings to reports/ before closing!")
    print(f"{'='*60}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
