"""scanner.db 统一查询工具。替代内联 python3 -c sqlite3 模板。

用法:
  python3 db_query.py <sql>                     SELECT → JSON 数组
  python3 db_query.py <sql> --params '["val1"]' 带参数查询
  python3 db_query.py <sql> --write              INSERT/UPDATE/DELETE → {changes: N}
  python3 db_query.py <sql> --write --params '...'
  python3 db_query.py -t <表名>                  描述表结构
  python3 db_query.py --check                    DB 健康检查
  python3 db_query.py --file 路径.db <sql>       指定其他数据库文件
  python3 db_query.py --target "目标名" <sql>    从 dbs/ 目录找最新目标 DB 并查询
  python3 db_query.py --target "目标名" --init    初始化新目标 DB

DB 路径优先级: --file > --target > 默认 dbs/{target}_{date}.db
输出格式: JSON 到 stdout, 错误到 stderr

示例:
  python3 db_query.py "SELECT url, depth FROM pages WHERE status='queued'"
  python3 db_query.py \
    "INSERT INTO pages (url, depth, status) VALUES (?, ?, 'queued')" \
    --write --params '["https://t.com/x", 1]'
  python3 db_query.py "UPDATE scan_state SET phase='spider' WHERE id=1" --write
  python3 db_query.py -t pages
  python3 db_query.py --check
  python3 db_query.py --target "台州学院" "SELECT * FROM targets"
  python3 db_query.py --target "台州学院" --init
"""

import json
import os
import re
import sqlite3
import sys
from pathlib import Path

DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))

DEFAULT_DB = os.path.expandvars(r"E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db")


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def do_select(conn, sql, params):
    cur = conn.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    return rows


def do_write(conn, sql, params):
    cur = conn.execute(sql, params)
    conn.commit()
    return {"changes": cur.rowcount, "lastrowid": cur.lastrowid}


def describe_table(conn, table_name):
    cur = conn.execute('PRAGMA table_info("{}")'.format(table_name.replace('"', '""')))
    cols = [dict(r) for r in cur.fetchall()]
    if not cols:
        raise ValueError(f"表 '{table_name}' 不存在")
    return cols


def health_check(conn):
    info = {}

    # scan_state
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_state'")
    if cur.fetchone():
        cur = conn.execute("SELECT phase, seed_url, total_pages, total_js, total_suspicious FROM scan_state WHERE id=1")
        row = cur.fetchone()
        info["scan_state"] = dict(row) if row else None
    else:
        info["scan_state"] = None

    # counts
    for table in ("pages", "js_files", "suspicious_points", "findings"):
        try:
            cur = conn.execute(f'SELECT count(*) as cnt FROM "{table}"')
            info[table] = cur.fetchone()["cnt"]
        except sqlite3.OperationalError:
            info[table] = None

    # queue
    try:
        cur = conn.execute("SELECT status, count(*) as cnt FROM pages GROUP BY status")
        info["queue"] = {r["status"]: r["cnt"] for r in cur.fetchall()}
    except sqlite3.OperationalError:
        info["queue"] = None

    # auth
    try:
        cur = conn.execute("SELECT count(*) as cnt FROM auth_sessions WHERE is_active=1")
        info["active_sessions"] = cur.fetchone()["cnt"]
    except sqlite3.OperationalError:
        info["active_sessions"] = 0

    # DB file size
    db_path = Path(conn.execute("PRAGMA database_list").fetchone()["file"])
    if db_path.exists():
        info["db_size_kb"] = db_path.stat().st_size // 1024

    return info


def find_target_db(target_name):
    """从 dbs/ 目录找最新的目标 DB，按文件名排序取最新"""
    DBS_DIR.mkdir(parents=True, exist_ok=True)
    pattern = f"{target_name}_*.db"
    matches = sorted(DBS_DIR.glob(pattern), reverse=True)
    if not matches:
        return None
    return str(matches[0])


def make_target_db_path(target_name):
    """为目标生成今天的 DB 文件路径"""
    from datetime import date

    DBS_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today().strftime("%Y-%m-%d")
    filename = f"{target_name}_{today}.db"
    return str(DBS_DIR / filename)


def init_db(db_path, target_name):
    """读取 schema.sql 并执行，创建所有表，写入初始 targets 记录，标记所有 migrations 为已应用。"""
    schema_path = Path(__file__).parent / "schema.sql"
    conn = connect(db_path)
    try:
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO targets (target_name, domain) VALUES (?, ?)", [target_name, ""])
        # 标记所有已存在的 migration 为已应用
        migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
        if migrations_dir.is_dir():
            for f in sorted(migrations_dir.glob("*.sql")):
                m = re.match(r"^(\d+)_", f.name)
                if m:
                    ver = int(m.group(1))
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
                        (ver, f.stem),
                    )
        conn.commit()
    finally:
        conn.close()
    return db_path


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    # Parse flags
    sql = None
    db_path = None  # None means will be determined by --target or DEFAULT_DB
    is_write = False
    params_json = None
    describe = None
    do_check = False
    target_name = None
    do_init = False

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--file" and i + 1 < len(args):
            db_path = os.path.expandvars(args[i + 1])
            i += 2
        elif a == "--target" and i + 1 < len(args):
            target_name = args[i + 1]
            i += 2
        elif a == "--init":
            do_init = True
            i += 1
        elif a == "--write":
            is_write = True
            i += 1
        elif a == "--params" and i + 1 < len(args):
            params_json = args[i + 1]
            i += 2
        elif a == "-t" and i + 1 < len(args):
            describe = args[i + 1]
            i += 2
        elif a == "--check":
            do_check = True
            i += 1
        elif a.startswith("-"):
            print(f"未知选项: {a}", file=sys.stderr)
            sys.exit(1)
        else:
            sql = a
            i += 1

    params = json.loads(params_json) if params_json else []

    # Determine DB path
    if db_path is None:
        if target_name:
            if do_init:
                db_path = make_target_db_path(target_name)
            else:
                db_path = find_target_db(target_name)
                if db_path is None:
                    err_msg = f"未找到目标 DB: {target_name}_*.db，请先使用 --init 初始化"
                    print(json.dumps({"error": err_msg}, ensure_ascii=False))
                    sys.exit(1)
        else:
            db_path = DEFAULT_DB

    # Handle --init
    if do_init:
        if not target_name:
            print(json.dumps({"error": "--init 需要配合 --target 使用"}, ensure_ascii=False))
            sys.exit(1)
        init_db(db_path, target_name)
        print(json.dumps({"init": "ok", "db_path": db_path}, ensure_ascii=False))
        return

    if not os.path.exists(db_path):
        print(json.dumps({"error": f"数据库不存在: {db_path}"}, ensure_ascii=False))
        sys.exit(1)

    conn = connect(db_path)

    try:
        if do_check:
            result = health_check(conn)
        elif describe:
            result = describe_table(conn, describe)
        elif sql and is_write:
            result = do_write(conn, sql, params)
        elif sql:
            result = do_select(conn, sql, params)
        else:
            result = {"error": "未指定 SQL 或操作"}
    except Exception as e:
        result = {"error": str(e), "sql": sql}

    conn.close()
    print(json.dumps(result, ensure_ascii=False, default=str))

    if isinstance(result, dict) and "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
