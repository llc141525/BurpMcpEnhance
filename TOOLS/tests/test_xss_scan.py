# TOOLS/tests/test_xss_scan.py
"""xss_scan.py 单元测试。"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.xss_scan import (
    beacon_in_response,
    build_beacon,
    find_xss_targets,
    write_xss_sp,
)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT);
        CREATE TABLE scan_state (id INTEGER PRIMARY KEY, seed_url TEXT, phase TEXT);
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued',
            forms_json TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT DEFAULT 'GET',
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            reasoning TEXT,
            risk TEXT DEFAULT 'High',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'vuln_scan')")
    c.commit()
    yield c
    c.close()


def test_find_xss_targets_text_input(conn):
    forms = json.dumps(
        [
            {
                "action": "https://example.com/search",
                "method": "GET",
                "inputs": [{"tag": "input", "name": "q", "type": "text", "value": "", "hidden": False}],
            }
        ]
    )
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_xss_targets(conn)
    assert len(targets) == 1
    assert targets[0]["param"] == "q"
    assert targets[0]["form_action"] == "https://example.com/search"


def test_find_xss_targets_textarea(conn):
    forms = json.dumps(
        [
            {
                "action": "https://example.com/comment",
                "method": "POST",
                "inputs": [{"tag": "textarea", "name": "content", "type": "text", "value": "", "hidden": False}],
            }
        ]
    )
    conn.execute(
        "INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/post', 'visited', ?)", (forms,)
    )
    conn.commit()
    targets = find_xss_targets(conn)
    assert any(t["param"] == "content" for t in targets)


def test_find_xss_targets_skips_hidden_and_submit(conn):
    forms = json.dumps(
        [
            {
                "action": "https://example.com/form",
                "method": "POST",
                "inputs": [
                    {"tag": "input", "name": "_token", "type": "hidden", "value": "abc", "hidden": True},
                    {"tag": "input", "name": "submit_btn", "type": "submit", "value": "Submit", "hidden": False},
                    {"tag": "input", "name": "comment", "type": "text", "value": "", "hidden": False},
                ],
            }
        ]
    )
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_xss_targets(conn)
    params = [t["param"] for t in targets]
    assert "comment" in params
    assert "_token" not in params
    assert "submit_btn" not in params


def test_build_beacon_unique():
    b1 = build_beacon("aabb1122")
    b2 = build_beacon("ccdd3344")
    assert b1 != b2
    assert "xssbeacon_aabb1122" in b1
    assert "<img" in b1


def test_beacon_in_response_detects_unescaped():
    uid = "aabb1122"
    beacon = build_beacon(uid)
    html = f"<html><body>{beacon}</body></html>"
    assert beacon_in_response(uid, html) is True


def test_beacon_in_response_not_triggered_when_escaped():
    uid = "aabb1122"
    beacon = build_beacon(uid)
    escaped = beacon.replace("<", "&lt;").replace(">", "&gt;")
    html = f"<html><body>{escaped}</body></html>"
    assert beacon_in_response(uid, html) is False


def test_beacon_in_response_not_triggered_when_absent():
    assert beacon_in_response("aabb1122", "<html><body>nothing here</body></html>") is False


def test_write_xss_sp_stored(conn):
    inserted = write_xss_sp(
        conn,
        url="https://example.com/comment",
        param="content",
        beacon_uid="aabb1122",
        page_url="https://example.com/comments",
        is_stored=True,
    )
    assert inserted is True
    row = conn.execute("SELECT * FROM suspicious_points").fetchone()
    assert row["test_type"] == "stored_xss"
    assert row["risk"] == "High"


def test_write_xss_sp_reflected_is_low(conn):
    write_xss_sp(
        conn,
        url="https://example.com/search",
        param="q",
        beacon_uid="ccdd3344",
        page_url="https://example.com/search",
        is_stored=False,
    )
    row = conn.execute("SELECT * FROM suspicious_points").fetchone()
    assert row["risk"] == "Low"


def test_write_xss_sp_deduplicates(conn):
    write_xss_sp(conn, "https://example.com/x", "q", "uid1", "https://example.com/x", True)
    inserted2 = write_xss_sp(conn, "https://example.com/x", "q", "uid2", "https://example.com/x", True)
    count = conn.execute("SELECT count(*) FROM suspicious_points").fetchone()[0]
    assert count == 1
    assert inserted2 is False
