import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.reflect_map import get_plugins_for_stacks


def test_spring_boot_returns_actuator():
    plugins = get_plugins_for_stacks(["Spring Boot"])
    names = [p["name"] for p in plugins]
    assert "spring-actuator" in names


def test_unknown_stack_returns_empty():
    plugins = get_plugins_for_stacks(["UnknownFramework"])
    assert plugins == []


def test_multi_stack_deduplicates():
    plugins = get_plugins_for_stacks(["Spring Boot", "Spring Boot"])
    names = [p["name"] for p in plugins]
    assert names.count("spring-actuator") == 1


def test_plugin_has_required_fields():
    plugins = get_plugins_for_stacks(["Shiro"])
    for p in plugins:
        assert "name" in p
        assert "type" in p
        assert "vuln_types" in p
        assert p["type"] in ("nuclei_template", "python_script", "tool_binary", "config")


def _make_test_db() -> tuple[str, sqlite3.Connection]:
    """创建最小测试 DB（含 targets + plugins + scan_state 表）。"""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY, target_name TEXT, tech_stack TEXT);
        CREATE TABLE plugins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            trigger_stack TEXT,
            covers_vuln_types TEXT,
            file_path TEXT,
            install_cmd TEXT,
            source TEXT DEFAULT 'mapping',
            active INTEGER DEFAULT 1,
            created_at TEXT,
            last_used_at TEXT
        );
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            reflect_ran_at TEXT,
            plugins_added_json TEXT
        );
        INSERT INTO targets VALUES (1, 'test', '["Spring Boot","JWT"]');
        INSERT INTO scan_state VALUES (1, NULL, NULL);
    """)
    conn.commit()
    return path, conn


def test_read_tech_stacks():
    from pipeline.reflect import read_tech_stacks

    path, conn = _make_test_db()
    stacks = read_tech_stacks(conn)
    assert "Spring Boot" in stacks
    assert "JWT" in stacks
    conn.close()
    os.unlink(path)


def test_get_missing_mapped_plugins():
    from pipeline.reflect import get_missing_mapped_plugins

    path, conn = _make_test_db()
    # spring-actuator 已安装
    conn.execute("INSERT INTO plugins (name, type, source) VALUES ('spring-actuator','nuclei_template','mapping')")
    conn.commit()
    missing = get_missing_mapped_plugins(conn, ["Spring Boot"])
    names = [p["name"] for p in missing]
    assert "spring-actuator" not in names  # 已安装
    assert "spring4shell" in names  # 未安装
    conn.close()
    os.unlink(path)


def test_build_analysis_context():
    from pipeline.reflect import build_analysis_context

    path, conn = _make_test_db()
    conn.executescript("""
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY, test_type TEXT, test_status TEXT
        );
        CREATE TABLE findings (id TEXT PRIMARY KEY, type TEXT);
        INSERT INTO suspicious_points VALUES ('SP-1','auth_surface','untested');
        INSERT INTO suspicious_points VALUES ('SP-2','sqli','untested');
        INSERT INTO findings VALUES ('F-1','info_leak');
    """)
    conn.commit()
    ctx = build_analysis_context(conn, ["Spring Boot", "JWT"], ["spring-actuator"])
    assert "Spring Boot" in ctx["tech_stacks"]
    assert "auth_surface" in ctx["sp_coverage"]
    assert "info_leak" in ctx["confirmed_types"]
    assert "spring-actuator" in ctx["installed_plugins"]
    conn.close()
    os.unlink(path)


def test_parse_feishu_reply_ok():
    from pipeline.reflect import parse_feishu_reply

    ids = [1, 2, 3]
    assert parse_feishu_reply("ok", ids) == [1, 2, 3]


def test_parse_feishu_reply_skip():
    from pipeline.reflect import parse_feishu_reply

    ids = [1, 2, 3]
    assert parse_feishu_reply("skip 2", ids) == [1, 3]


def test_parse_feishu_reply_no():
    from pipeline.reflect import parse_feishu_reply

    ids = [1, 2, 3]
    assert parse_feishu_reply("no", ids) == []


def test_parse_feishu_reply_unknown_defaults_to_ok():
    from pipeline.reflect import parse_feishu_reply

    ids = [1, 2]
    assert parse_feishu_reply("随便什么", ids) == [1, 2]
