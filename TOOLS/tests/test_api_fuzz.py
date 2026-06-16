# TOOLS/tests/test_api_fuzz.py
"""api_fuzz.py 单元测试。"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.api_fuzz import (
    build_probe_list,
    classify_response,
    derive_prefixes,
    extract_known_api_paths,
    write_to_hunt_queue,
)

# ── Fixture ───────────────────────────────────────────────────────────────────


@pytest.fixture
def conn():
    """内存 DB，含 hunt_queue / pages / js_files / suspicious_points / targets / scan_state。"""
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT
        );
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            seed_url TEXT,
            phase TEXT DEFAULT 'api_fuzz'
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            depth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued',
            api_calls_json TEXT,
            source TEXT
        );
        CREATE TABLE js_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            analyzed INTEGER DEFAULT 0,
            discovered_apis_json TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT,
            test_type TEXT,
            source TEXT,
            risk TEXT,
            test_status TEXT
        );
        CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            query_string TEXT,
            endpoint_type TEXT,
            business_intent TEXT,
            risk_hint TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'queued',
            source TEXT DEFAULT 'auto',
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(method, url, query_string)
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'api_fuzz')")
    c.commit()
    yield c
    c.close()


# ── derive_prefixes ────────────────────────────────────────────────────────────


def test_derive_prefixes_basic():
    paths = ["/api/v1/courses", "/api/v1/users", "/api/v1/login"]
    result = derive_prefixes(paths)
    assert "/api/v1/" in result


def test_derive_prefixes_empty_returns_fallback():
    result = derive_prefixes([])
    assert result == ["/api/"]


def test_derive_prefixes_with_full_urls():
    paths = ["https://example.com/api/v1/courses", "https://example.com/api/v1/users"]
    result = derive_prefixes(paths)
    assert "/api/v1/" in result


def test_derive_prefixes_mixed_paths():
    paths = ["/api/v1/a", "/api/v1/b", "/api/v2/c"]
    result = derive_prefixes(paths)
    assert any("/api/" in p for p in result)


# ── classify_response ──────────────────────────────────────────────────────────


def test_classify_unauth_200_is_critical():
    intent, risk = classify_response(200, 200)
    assert intent == "unauth_admin_access"
    assert risk == "Critical"


def test_classify_unauth_200_auth_403():
    intent, risk = classify_response(403, 200)
    assert intent == "unauth_admin_access"
    assert risk == "Critical"


def test_classify_vertical_priv_esc_auth_200_unauth_401():
    intent, risk = classify_response(200, 401)
    assert intent == "vertical_priv_esc"
    assert risk == "High"


def test_classify_vertical_priv_esc_auth_200_unauth_403():
    intent, risk = classify_response(200, 403)
    assert intent == "vertical_priv_esc"
    assert risk == "High"


def test_classify_both_403_is_medium():
    intent, risk = classify_response(403, 403)
    assert intent == "admin_403_probe"
    assert risk == "Medium"


def test_classify_auth_403_unauth_404():
    intent, risk = classify_response(403, 404)
    assert intent == "admin_403_probe"
    assert risk == "Medium"


def test_classify_server_error():
    result = classify_response(500, 500)
    assert result is not None
    assert result[0] == "server_error_probe"
    assert result[1] == "Medium"


def test_classify_404_both_returns_none():
    result = classify_response(404, 404)
    assert result is None


def test_classify_0_both_returns_none():
    result = classify_response(0, 0)
    assert result is None


# ── extract_known_api_paths ────────────────────────────────────────────────────


def test_extract_from_pages_api_calls_json(conn):
    conn.execute(
        "INSERT INTO pages (url, api_calls_json, status) VALUES (?, ?, 'visited')",
        ("/index", json.dumps([{"url": "/api/v1/courses"}, {"url": "/api/v1/users"}])),
    )
    conn.commit()
    paths = extract_known_api_paths(conn)
    assert "/api/v1/courses" in paths
    assert "/api/v1/users" in paths


def test_extract_from_js_files(conn):
    conn.execute(
        "INSERT INTO js_files (url, analyzed, discovered_apis_json) VALUES (?, 1, ?)",
        ("/static/app.js", json.dumps(["/api/v1/teacher", "/api/v1/admin"])),
    )
    conn.commit()
    paths = extract_known_api_paths(conn)
    assert "/api/v1/teacher" in paths


def test_extract_from_suspicious_points(conn):
    conn.execute("INSERT INTO suspicious_points (id, url) VALUES ('SP-001', '/api/v1/grades')")
    conn.commit()
    paths = extract_known_api_paths(conn)
    assert "/api/v1/grades" in paths


def test_extract_empty_db_returns_list(conn):
    paths = extract_known_api_paths(conn)
    assert isinstance(paths, list)


# ── write_to_hunt_queue ────────────────────────────────────────────────────────


def test_write_inserts_correct_fields(conn):
    inserted = write_to_hunt_queue(
        conn,
        target_id=1,
        url="https://example.com/api/admin/users",
        business_intent="vertical_priv_esc",
        risk_hint="High",
        auth_code=200,
        unauth_code=403,
    )
    assert inserted is True
    row = conn.execute("SELECT * FROM hunt_queue WHERE url='https://example.com/api/admin/users'").fetchone()
    assert row["endpoint_type"] == "admin_api"
    assert row["source"] == "auto"
    assert "api_fuzz" in row["notes"]
    assert "auth=200" in row["notes"]
    assert "unauth=403" in row["notes"]
    assert row["risk_hint"] == "High"
    assert row["status"] == "queued"


def test_write_ignores_duplicate(conn):
    url = "https://example.com/api/admin"
    write_to_hunt_queue(conn, 1, url, "admin_403_probe", "Medium", 403, 403)
    inserted_again = write_to_hunt_queue(conn, 1, url, "admin_403_probe", "Medium", 403, 403)
    assert inserted_again is False
    count = conn.execute("SELECT count(*) FROM hunt_queue WHERE url=?", (url,)).fetchone()[0]
    assert count == 1


def test_write_critical_risk_hint(conn):
    write_to_hunt_queue(conn, 1, "https://example.com/api/superadmin", "unauth_admin_access", "Critical", 200, 200)
    row = conn.execute("SELECT risk_hint FROM hunt_queue").fetchone()
    assert row["risk_hint"] == "Critical"


# ── build_probe_list ──────────────────────────────────────────────────────────


def test_build_probe_list_returns_full_urls(conn):
    probe_list = build_probe_list(conn, "https://example.com")
    assert len(probe_list) > 0
    assert all(p.startswith("https://example.com") for p in probe_list)


def test_build_probe_list_excludes_known_pages(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/api/admin', 'visited')")
    conn.commit()
    probe_list = build_probe_list(conn, "https://example.com")
    paths = [p.replace("https://example.com", "") for p in probe_list]
    assert "/api/admin" not in paths


def test_build_probe_list_excludes_hunt_queue_entries(conn):
    conn.execute(
        """INSERT INTO hunt_queue (target_id, method, url, source)
           VALUES (1, 'GET', 'https://example.com/api/teacher', 'auto')"""
    )
    conn.commit()
    probe_list = build_probe_list(conn, "https://example.com")
    assert "https://example.com/api/teacher" not in probe_list
