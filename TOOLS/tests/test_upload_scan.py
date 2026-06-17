# TOOLS/tests/test_upload_scan.py
"""upload_scan.py 单元测试。"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.upload_scan import (
    build_payloads,
    extract_uploaded_url,
    find_upload_targets,
    is_webshell_output,
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
            method TEXT DEFAULT 'POST',
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            reasoning TEXT,
            risk TEXT DEFAULT 'High',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT
        );
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            target_id INTEGER,
            type TEXT,
            url TEXT,
            param TEXT,
            method TEXT,
            payload TEXT,
            evidence TEXT,
            risk TEXT,
            cvss TEXT,
            remediation TEXT,
            confirmed_at TEXT
        );
    """)
    c.execute("INSERT INTO targets (domain) VALUES ('example.com')")
    c.execute("INSERT INTO scan_state (id, seed_url, phase) VALUES (1, 'https://example.com', 'vuln_scan')")
    c.commit()
    yield c
    c.close()


def test_find_upload_targets_from_forms_json(conn):
    forms = json.dumps(
        [
            {
                "action": "https://example.com/upload",
                "method": "POST",
                "inputs": [
                    {"tag": "input", "name": "file", "type": "file", "value": "", "hidden": False},
                    {"tag": "input", "name": "submit", "type": "submit", "value": "Upload", "hidden": False},
                ],
            }
        ]
    )
    conn.execute("INSERT INTO pages (url, status, forms_json) VALUES ('https://example.com/', 'visited', ?)", (forms,))
    conn.commit()
    targets = find_upload_targets(conn)
    assert len(targets) == 1
    assert targets[0]["upload_url"] == "https://example.com/upload"
    assert targets[0]["field_name"] == "file"


def test_find_upload_targets_from_url_pattern(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/file/upload', 'visited')")
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/api/avatar/update', 'visited')")
    conn.commit()
    targets = find_upload_targets(conn)
    urls = [t["upload_url"] for t in targets]
    assert "https://example.com/file/upload" in urls
    assert "https://example.com/api/avatar/update" in urls


def test_find_upload_targets_skips_non_upload(conn):
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://example.com/search', 'visited')")
    conn.commit()
    targets = find_upload_targets(conn)
    assert len(targets) == 0


def test_build_payloads_contains_svg():
    payloads = build_payloads()
    assert "svg_xss" in payloads
    svg = payloads["svg_xss"]
    assert b"onload" in svg["data"]
    assert svg["filename"].endswith(".svg")
    assert "svg" in svg["content_type"]


def test_build_payloads_contains_php_webshell():
    payloads = build_payloads()
    assert "php_webshell" in payloads
    php = payloads["php_webshell"]
    assert b"shell_exec" in php["data"]
    assert b"GIF89a" in php["data"]


def test_build_payloads_contains_jsp_webshell():
    payloads = build_payloads()
    assert "jsp_webshell" in payloads
    jsp = payloads["jsp_webshell"]
    assert b"Runtime" in jsp["data"]


def test_is_webshell_output_linux_root_ls():
    assert is_webshell_output("bin\nboot\ndev\netc\nhome\nlib\nopt\nroot\nsrv\ntmp\nusr\nvar\n") is True


def test_is_webshell_output_normal_html():
    assert is_webshell_output("<html><body>Not Found</body></html>") is False


def test_is_webshell_output_partial_match():
    assert is_webshell_output("bin\nboot\netc") is True


def test_extract_uploaded_url_from_json_url_field():
    body = '{"code":0,"data":{"url":"/uploads/shell.php"}}'
    result = extract_uploaded_url(body, "https://example.com")
    assert result == "https://example.com/uploads/shell.php"


def test_extract_uploaded_url_from_json_path_field():
    body = '{"success":true,"path":"/files/test.jpg"}'
    result = extract_uploaded_url(body, "https://example.com")
    assert result == "https://example.com/files/test.jpg"


def test_extract_uploaded_url_returns_none_when_not_found():
    body = '{"error":"file too large"}'
    result = extract_uploaded_url(body, "https://example.com")
    assert result is None
