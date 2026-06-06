"""共享 DB helper — 所有 TOOLS pipeline 脚本统一导入，消除复制粘贴。"""

import sqlite3
import sys
from pathlib import Path

# db/ → TOOLS/ → SRC/
_TOOLS_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _TOOLS_DIR.parent
DBS_DIR = _PROJECT_ROOT / "dbs"


def find_db(target: str) -> Path:
    """返回最新修改的匹配 DB 路径，找不到则 sys.exit。"""
    dbs = sorted(DBS_DIR.glob(f"{target}*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dbs:
        sys.exit(f"[error] 找不到目标 DB: dbs/{target}*.db")
    return dbs[0]


def connect(db_path: "Path | str") -> sqlite3.Connection:
    """打开 SQLite 连接，启用 WAL + busy_timeout + row_factory。"""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn
