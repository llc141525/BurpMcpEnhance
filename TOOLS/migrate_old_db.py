"""旧 scanner.db 迁移到新按目标分库格式。

用法:
  python3 TOOLS/migrate_old_db.py
  python3 TOOLS/migrate_old_db.py --source "E:\old\path\scanner.db"
  python3 TOOLS/migrate_old_db.py --source "..." --force   # 覆盖已存在的目标 DB
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

# 默认路径
OLD_DB_DEFAULT = os.path.expandvars(r"E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db")
DBS_DIR = Path(os.path.expandvars(r"E:\SRC挖掘\SRC\dbs"))
TOOLS_DIR = Path(__file__).parent.resolve()


def infer_target_name(seed_url):
    """从 seed_url 推断目标名，直接使用域名."""
    if not seed_url:
        return "unknown"
    domain = urlparse(seed_url).netloc
    return domain if domain else "unknown"


def connect_old(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_all(conn, table):
    """返回表的所有行作为 dict 列表."""
    cur = conn.execute(f'SELECT * FROM "{table}"')
    return [dict(row) for row in cur.fetchall()]


def get_old_tables(conn):
    """返回旧 DB 中存在的业务表列表."""
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ("
        "'targets','scan_state','pages','js_files','suspicious_points',"
        "'findings','auth_credentials','auth_flow_steps','auth_sessions')"
    )
    return [r["name"] for r in cur.fetchall()]


def call_db_query(args, capture=True):
    """调用 db_query.py，返回 stdout JSON（或返回空 dict 当出错时）."""
    cmd = [sys.executable, str(TOOLS_DIR / "db_query.py")] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if capture:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"error": result.stdout + result.stderr}
        return result
    except Exception as e:
        return {"error": str(e)}


def migrate(source_db, target_name, force=False):
    """执行迁移：读取旧 DB，迁移到新按目标分库。"""
    # 1. 确认旧 DB 存在
    if not os.path.exists(source_db):
        print(f"错误: 源数据库不存在: {source_db}")
        return False

    # 2. 读取旧 DB
    old_conn = connect_old(source_db)
    old_tables = get_old_tables(old_conn)

    # 3. 确定新 DB 路径
    today = date.today().strftime("%Y-%m-%d")
    new_db_name = f"{target_name}_{today}.db"
    new_db_path = DBS_DIR / new_db_name

    # 4. 目标 DB 已存在检查
    if new_db_path.exists():
        if not force:
            print(f"错误: 目标数据库已存在: {new_db_path}")
            print("使用 --force 覆盖（或重命名现有 DB 后再运行）")
            old_conn.close()
            return False

    # 5. 创建新目标 DB（调用 db_query.py --init）
    init_result = call_db_query(["--target", target_name, "--init"])
    if isinstance(init_result, dict) and "error" in init_result:
        print(f"错误: 初始化目标 DB 失败: {init_result['error']}")
        old_conn.close()
        return False

    # 6. 从旧 DB 读取所有数据
    data = {}
    for table in old_tables:
        data[table] = fetch_all(old_conn, table)
    old_conn.close()

    # 7. 获取新 DB 中 targets 表的 id（刚插入的那条）
    new_conn = sqlite3.connect(str(new_db_path))
    new_conn.execute("PRAGMA journal_mode=WAL")
    new_conn.execute("PRAGMA busy_timeout=5000")
    new_conn.row_factory = sqlite3.Row

    target_row = new_conn.execute("SELECT id FROM targets WHERE target_name=?", (target_name,)).fetchone()
    new_target_id = target_row["id"] if target_row else None

    if new_target_id is None:
        # 如果 db_query.py --init 没有写入 targets（比如被修改了），手动写入
        cur = new_conn.execute("INSERT INTO targets (target_name, domain) VALUES (?, ?)", (target_name, ""))
        new_target_id = cur.lastrowid
        new_conn.commit()

    migrated = {}

    # 8. 迁移各表

    # 8a. scan_state
    if "scan_state" in data and data["scan_state"]:
        row = data["scan_state"][0]
        new_conn.execute(
            """INSERT INTO scan_state
               (id, target_id, seed_url, phase, started_at, spider_ended_at,
                reviewed_at, max_depth, max_pages, total_pages, total_js,
                total_apis, total_forms, total_suspicious, total_findings, call_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"],
                new_target_id,
                row.get("seed_url"),
                row.get("phase"),
                row.get("started_at"),
                row.get("spider_ended_at"),
                row.get("reviewed_at"),
                row.get("max_depth", 3),
                row.get("max_pages", 200),
                row.get("total_pages", 0),
                row.get("total_js", 0),
                row.get("total_apis", 0),
                row.get("total_forms", 0),
                row.get("total_suspicious", 0),
                row.get("total_findings", 0),
                row.get("call_count", 0),
            ),
        )
        new_conn.commit()
        migrated["scan_state"] = 1

    # 8b. pages
    if "pages" in data:
        for row in data["pages"]:
            new_conn.execute(
                """INSERT INTO pages
                   (id, url, depth, status, title, links_found,
                    forms_json, js_files_json, api_calls_json,
                    suspicious_params_json, crawled_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row["url"],
                    row.get("depth", 0),
                    row.get("status", "queued"),
                    row.get("title"),
                    row.get("links_found", 0),
                    row.get("forms_json"),
                    row.get("js_files_json"),
                    row.get("api_calls_json"),
                    row.get("suspicious_params_json"),
                    row.get("crawled_at"),
                ),
            )
        new_conn.commit()
        migrated["pages"] = len(data["pages"])

    # 8c. js_files
    if "js_files" in data:
        for row in data["js_files"]:
            new_conn.execute(
                """INSERT INTO js_files
                   (id, url, page_url, analyzed, discovered_apis_json,
                    hardcoded_secrets_json, internal_routes_json,
                    debug_switches_json, analyzed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row["url"],
                    row.get("page_url"),
                    row.get("analyzed", 0),
                    row.get("discovered_apis_json"),
                    row.get("hardcoded_secrets_json"),
                    row.get("internal_routes_json"),
                    row.get("debug_switches_json"),
                    row.get("analyzed_at"),
                ),
            )
        new_conn.commit()
        migrated["js_files"] = len(data["js_files"])

    # 8d. suspicious_points
    if "suspicious_points" in data:
        for row in data["suspicious_points"]:
            new_conn.execute(
                """INSERT INTO suspicious_points
                   (id, page_url, url, param, method, test_type, evidence,
                    source, reasoning, risk, test_status, burp_request_id,
                    created_at, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row.get("page_url"),
                    row.get("url"),
                    row.get("param"),
                    row.get("method", "GET"),
                    row.get("test_type"),
                    row.get("evidence"),
                    row.get("source"),
                    row.get("reasoning"),
                    row.get("risk", "Medium"),
                    row.get("test_status", "untested"),
                    row.get("burp_request_id"),
                    row.get("created_at"),
                    row.get("notes"),
                ),
            )
        new_conn.commit()
        migrated["suspicious_points"] = len(data["suspicious_points"])

    # 8e. findings（旧 DB 没有 target_id，INSERT 时填 NULL）
    if "findings" in data:
        for row in data["findings"]:
            new_conn.execute(
                """INSERT INTO findings
                   (id, sp_id, target_id, type, url, param, method,
                    payload, evidence, risk, cvss, remediation,
                    confirmed_at, burp_request_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row.get("sp_id"),
                    None,  # target_id = NULL（operator 后续修正）
                    row.get("type"),
                    row.get("url"),
                    row.get("param"),
                    row.get("method"),
                    row.get("payload"),
                    row.get("evidence"),
                    row.get("risk"),
                    row.get("cvss"),
                    row.get("remediation"),
                    row.get("confirmed_at"),
                    row.get("burp_request_id"),
                ),
            )
        new_conn.commit()
        migrated["findings"] = len(data["findings"])

    # 8f. auth_credentials
    if "auth_credentials" in data:
        for row in data["auth_credentials"]:
            new_conn.execute(
                """INSERT INTO auth_credentials
                   (id, account_label, username, password, login_url, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    row["id"],
                    row.get("account_label"),
                    row.get("username"),
                    row.get("password"),
                    row.get("login_url"),
                    row.get("created_at"),
                ),
            )
        new_conn.commit()
        migrated["auth_credentials"] = len(data["auth_credentials"])

    # 8g. auth_flow_steps
    if "auth_flow_steps" in data:
        for row in data["auth_flow_steps"]:
            new_conn.execute(
                """INSERT INTO auth_flow_steps
                   (id, step_index, action_type, url, selector_uid,
                    value, wait_ms, description)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row.get("step_index"),
                    row.get("action_type"),
                    row.get("url"),
                    row.get("selector_uid"),
                    row.get("value"),
                    row.get("wait_ms"),
                    row.get("description"),
                ),
            )
        new_conn.commit()
        migrated["auth_flow_steps"] = len(data["auth_flow_steps"])

    # 8h. auth_sessions
    if "auth_sessions" in data:
        for row in data["auth_sessions"]:
            new_conn.execute(
                """INSERT INTO auth_sessions
                   (id, token_type, token_name, token_value, domain,
                    path, is_active, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    row["id"],
                    row.get("token_type"),
                    row.get("token_name"),
                    row.get("token_value"),
                    row.get("domain"),
                    row.get("path", "/"),
                    row.get("is_active", 1),
                    row.get("created_at"),
                ),
            )
        new_conn.commit()
        migrated["auth_sessions"] = len(data["auth_sessions"])

    new_conn.close()

    # 9. 打印迁移摘要
    print("=== 数据库迁移完成 ===")
    print(f"源: {source_db}")
    print(f"目标: {new_db_path}")
    print("迁移记录:")
    for table, count in migrated.items():
        print(f"  - {table}: {count}")
    for table in data:
        if table not in migrated:
            print(f"  - {table}: 0 (表存在但无数据)")
    print(f"\n新 DB 路径: {new_db_path}")
    print("注意: findings 表的 target_id 已设为 NULL，请确认后手动更新。")

    return True


def main():
    parser = argparse.ArgumentParser(description="旧 scanner.db 迁移到新按目标分库格式。")
    parser.add_argument("--source", default=OLD_DB_DEFAULT, help=f"源数据库路径（默认: {OLD_DB_DEFAULT}）")
    parser.add_argument("--force", action="store_true", help="覆盖已存在的目标 DB（默认会拒绝覆盖）")
    args = parser.parse_args()

    # 展开路径中的环境变量
    source = os.path.expandvars(args.source)

    # 尝试从旧 DB 读取 seed_url 以推断目标名
    if os.path.exists(source):
        try:
            conn = connect_old(source)
            row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
            conn.close()
            seed_url = dict(row)["seed_url"] if row else None
        except Exception:
            seed_url = None
    else:
        seed_url = None

    target_name = infer_target_name(seed_url)
    print(f"检测到源 DB: {source}")
    print(f"目标名: {target_name}")
    print(f"目标 DB: dbs/{target_name}_{date.today().strftime('%Y-%m-%d')}.db")
    print()

    ok = migrate(source, target_name, force=args.force)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
