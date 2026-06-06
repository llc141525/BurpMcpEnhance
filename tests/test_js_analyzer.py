"""Tests for js_analyzer.py — pure functions only."""
import json
import sqlite3
import tempfile

import pytest


def _make_db() -> tuple[str, sqlite3.Connection]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(tmp.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE js_files (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            page_url TEXT,
            analyzed INTEGER DEFAULT 0,
            discovered_apis_json TEXT,
            hardcoded_secrets_json TEXT,
            analyzed_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT DEFAULT 'GET',
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            risk TEXT DEFAULT 'Medium',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT
        )
    """)
    conn.commit()
    return tmp.name, conn


def test_score_js_url_skips_cdn():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js") == 0
    assert score_js_url("https://unpkg.com/react@18/umd/react.js") == 0
    assert score_js_url("https://cdn.jsdelivr.net/npm/lodash.js") == 0


def test_score_js_url_skips_vendor_filenames():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://example.com/static/vendor.js") == 0
    assert score_js_url("https://example.com/js/jquery.min.js") == 0
    assert score_js_url("https://example.com/dist/chunk-vendors.js") == 0


def test_score_js_url_high_priority_keywords():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://example.com/js/api-config.js") == 2
    assert score_js_url("https://example.com/static/auth.js") == 2
    assert score_js_url("https://example.com/assets/router.js") == 2
    assert score_js_url("https://example.com/js/user-service.js") == 2


def test_score_js_url_medium_priority_business_domain():
    from TOOLS.js_analyzer import score_js_url
    assert score_js_url("https://example.com/js/app.chunk.abc123.js") == 1


def test_parse_mmx_output_valid_json():
    from TOOLS.js_analyzer import parse_mmx_output
    raw = json.dumps({
        "api_endpoints": [{"path": "/api/user", "method": "POST", "params": ["uid"]}],
        "hardcoded_secrets": [{"type": "apikey", "name": "ACCESS_KEY", "value": "sk-abc"}],
        "internal_routes": ["/admin/debug"],
        "auth_patterns": []
    })
    result = parse_mmx_output(raw)
    assert result is not None
    assert len(result["api_endpoints"]) == 1
    assert result["hardcoded_secrets"][0]["name"] == "ACCESS_KEY"


def test_parse_mmx_output_invalid_json_returns_none():
    from TOOLS.js_analyzer import parse_mmx_output
    assert parse_mmx_output("not json at all") is None
    assert parse_mmx_output("some text without braces") is None


def test_write_findings_to_db_inserts_rows():
    from TOOLS.js_analyzer import write_findings_to_db
    _, conn = _make_db()
    findings = {
        "api_endpoints": [{"path": "/api/info", "method": "GET", "params": ["id"]}],
        "hardcoded_secrets": [{"type": "apikey", "name": "KEY", "value": "abc123"}],
        "internal_routes": ["/internal/debug"],
        "auth_patterns": [],
    }
    count = write_findings_to_db(conn, "https://example.com/main.js", findings, "SP-JA")
    assert count >= 2
    rows = conn.execute("SELECT * FROM suspicious_points").fetchall()
    assert len(rows) >= 2
    types = {r[4] for r in rows}
    assert "hardcoded_secret" in types
    conn.close()
