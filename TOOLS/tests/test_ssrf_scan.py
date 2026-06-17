# TOOLS/tests/test_ssrf_scan.py
"""ssrf_scan.py 单元测试。"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.ssrf_scan import (
    find_ssrf_candidates,
    is_ssrf_response,
    write_ssrf_candidate,
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
            suspicious_params_json TEXT,
            forms_json TEXT
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
            UNIQUE(method, url, query_string)
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'vuln_scan')")
    c.commit()
    yield c
    c.close()


def test_find_ssrf_candidates_from_url_query_param(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/api?url=http://x.com', 'visited')")
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert len(results) == 1
    assert results[0]["param"] == "url"
    assert "example.com/api" in results[0]["url"]


def test_find_ssrf_candidates_from_redirect_param(conn):
    conn.execute(
        "INSERT INTO pages (url, status) VALUES ('https://example.com/login?redirect=http://a.com', 'visited')"
    )
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert any(r["param"] == "redirect" for r in results)


def test_find_ssrf_candidates_from_suspicious_params_json(conn):
    sp = json.dumps([{"name": "callback", "type": "text"}, {"name": "q", "type": "text"}])
    conn.execute(
        "INSERT INTO pages (url, status, suspicious_params_json) VALUES ('https://example.com/api', 'visited', ?)",
        (sp,),
    )
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert any(r["param"] == "callback" for r in results)
    assert not any(r["param"] == "q" for r in results)


def test_find_ssrf_candidates_skips_non_ssrf_params(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/search?q=hello&page=2', 'visited')")
    conn.commit()
    results = find_ssrf_candidates(conn)
    assert len(results) == 0


def test_is_ssrf_response_detects_passwd():
    assert is_ssrf_response(200, "root:x:0:0:root:/root:/bin/bash") is True


def test_is_ssrf_response_detects_aws_metadata():
    assert is_ssrf_response(200, '{"instanceId":"i-0abcd1234","privateIp":"10.0.0.1"}') is True


def test_is_ssrf_response_detects_ssh_banner():
    assert is_ssrf_response(200, "SSH-2.0-OpenSSH_8.0") is True


def test_is_ssrf_response_normal_404():
    assert is_ssrf_response(404, "Not Found") is False


def test_is_ssrf_response_normal_200_html():
    assert is_ssrf_response(200, "<html><body>Welcome</body></html>") is False


def test_write_ssrf_candidate_inserts_new_row(conn):
    target_id = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()[0]
    inserted = write_ssrf_candidate(
        conn, target_id, "https://example.com/api?url=x", "url", "127.0.0.1 responded with SSH", "High"
    )
    assert inserted is True
    row = conn.execute("SELECT * FROM hunt_queue").fetchone()
    assert row is not None
    assert row["endpoint_type"] == "ssrf_candidate"
    assert "ssrf" in (row["notes"] or "")


def test_write_ssrf_candidate_deduplicates(conn):
    target_id = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()[0]
    write_ssrf_candidate(conn, target_id, "https://example.com/api?url=x", "url", "evidence", "High")
    inserted2 = write_ssrf_candidate(conn, target_id, "https://example.com/api?url=x", "url", "evidence2", "High")
    assert inserted2 is False
    assert conn.execute("SELECT count(*) FROM hunt_queue").fetchone()[0] == 1
