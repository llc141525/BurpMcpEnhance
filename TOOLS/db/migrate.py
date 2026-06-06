"""DB 迁移工具 — 按编号顺序执行 migrations/ 目录下的 .sql 文件。

用法:
  python3 TOOLS/migrate.py --target "台州学院"           # 升级到最新
  python3 TOOLS/migrate.py --target "台州学院" --status   # 查看当前版本
  python3 TOOLS/migrate.py --file path/to/db.db           # 直接指定 DB 文件
"""

import argparse
import os
import re
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
MIGRATIONS_DIR = PROJECT_ROOT / "migrations"
DBS_DIR = PROJECT_ROOT / "dbs"

_TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS_DIR))
from db.db_utils import connect  # noqa: E402


def find_target_db(target_name: str) -> str | None:
    matches = sorted(
        DBS_DIR.glob(f"{target_name}_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return str(matches[0]) if matches else None


def ensure_schema_version(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT DEFAULT (datetime('now', 'localtime')),
            description TEXT
        )"""
    )
    conn.commit()


def get_current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return row[0] if row and row[0] else 0


def detect_legacy_db(conn: sqlite3.Connection) -> bool:
    """若 DB 已有业务表但 schema_version 为空，判定为旧 DB。"""
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    return "targets" in tables or "pages" in tables


def list_migrations() -> list[tuple[int, str, str]]:
    """返回 [(version, filename, filepath), ...] 按 version 排序。"""
    results = []
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = re.match(r"^(\d+)_", f.name)
        if m:
            version = int(m.group(1))
            results.append((version, f.name, str(f)))
    results.sort(key=lambda x: x[0])
    return results


def apply_migration(conn: sqlite3.Connection, version: int, filepath: str) -> bool:
    sql = Path(filepath).read_text(encoding="utf-8").strip()
    if not sql or sql.startswith("--") and "\n" not in sql:
        # comment-only file = marker migration, still record as applied
        conn.execute(
            "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
            (version, Path(filepath).stem),
        )
        conn.commit()
        return True

    try:
        conn.executescript(sql)
        conn.execute(
            "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
            (version, Path(filepath).stem),
        )
        conn.commit()
        return True
    except sqlite3.OperationalError as e:
        # column already exists etc. → record and continue
        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
                (version, Path(filepath).stem),
            )
            conn.commit()
            return True
        print(f"  [ERROR] v{version}: {e}", file=sys.stderr)
        return False


def do_migrate(db_path: str) -> dict:
    conn = connect(db_path)
    try:
        ensure_schema_version(conn)
        current = get_current_version(conn)

        # 旧 DB 标记：表已存在但 schema_version 为空
        if current == 0 and detect_legacy_db(conn):
            conn.execute("INSERT OR IGNORE INTO schema_version (version, description) VALUES (1, '001_initial_schema')")
            conn.commit()
            current = 1

        migrations = list_migrations()
        pending = [(v, fn, fp) for v, fn, fp in migrations if v > current]

        if not pending:
            return {
                "db": db_path,
                "current_version": current,
                "applied": [],
                "message": "已是最新版本",
            }

        applied = []
        for ver, fname, fpath in pending:
            ok = apply_migration(conn, ver, fpath)
            if ok:
                applied.append({"version": ver, "file": fname})
            else:
                return {
                    "db": db_path,
                    "current_version": current,
                    "applied": applied,
                    "error": f"迁移 v{ver} ({fname}) 失败",
                }

        return {
            "db": db_path,
            "current_version": get_current_version(conn),
            "applied": applied,
            "message": "迁移完成",
        }
    finally:
        conn.close()


def do_status(db_path: str) -> dict:
    conn = connect(db_path)
    try:
        ensure_schema_version(conn)
        current = get_current_version(conn)

        if current == 0 and detect_legacy_db(conn):
            conn.execute("INSERT OR IGNORE INTO schema_version (version, description) VALUES (1, '001_initial_schema')")
            conn.commit()
            current = 1

        migrations = list_migrations()
        history = conn.execute(
            "SELECT version, applied_at, description FROM schema_version ORDER BY version"
        ).fetchall()

        return {
            "db": db_path,
            "current_version": current,
            "total_migrations": len(migrations),
            "pending": [fn for v, fn, _ in migrations if v > current],
            "history": [{"version": r[0], "applied_at": r[1], "description": r[2]} for r in history],
        }
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="DB 迁移工具")
    parser.add_argument("--target", help="目标名（自动匹配 dbs/{target}_*.db）")
    parser.add_argument("--file", help="直接指定 DB 文件路径")
    parser.add_argument("--status", action="store_true", help="仅查看迁移状态，不执行")
    args = parser.parse_args()

    if args.file:
        db_path = os.path.expandvars(args.file)
    elif args.target:
        db_path = find_target_db(args.target)
        if db_path is None:
            print(f'{{"error": "未找到目标 DB: {args.target}"}}')
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(db_path):
        print(f'{{"error": "DB 文件不存在: {db_path}"}}')
        sys.exit(1)

    if args.status:
        result = do_status(db_path)
    else:
        result = do_migrate(db_path)

    import json

    print(json.dumps(result, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
