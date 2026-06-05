"""Tests for browser_auth.py"""
import json
import sqlite3
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_parse_surface_urls_filters_same_domain():
    from TOOLS.browser_auth import parse_surface_urls
    raw = [
        {"url": "https://example.com/dashboard", "title": "Dashboard"},
        {"url": "https://example.com/settings", "title": "Settings"},
        {"url": "https://other.com/evil", "title": "External"},
        {"url": "https://sub.example.com/api", "title": "API"},
    ]
    result = parse_surface_urls(raw, base_domain="example.com")
    urls = [r["url"] for r in result]
    assert "https://example.com/dashboard" in urls
    assert "https://example.com/settings" in urls
    assert "https://sub.example.com/api" in urls
    assert "https://other.com/evil" not in urls


def test_parse_surface_urls_filters_static_assets():
    from TOOLS.browser_auth import parse_surface_urls
    raw = [
        {"url": "https://example.com/page", "title": "Page"},
        {"url": "https://example.com/style.css", "title": ""},
        {"url": "https://example.com/logo.png", "title": ""},
        {"url": "https://example.com/app.js", "title": ""},
    ]
    result = parse_surface_urls(raw, base_domain="example.com")
    urls = [r["url"] for r in result]
    assert "https://example.com/page" in urls
    assert "https://example.com/style.css" not in urls
    assert "https://example.com/logo.png" not in urls
    # JS files are NOT filtered — they may contain API endpoints worth crawling
    assert "https://example.com/app.js" in urls


def test_write_surface_urls_to_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        depth INTEGER,
        status TEXT,
        source TEXT
    )""")
    conn.commit()
    conn.close()

    from TOOLS.browser_auth import write_surface_urls_to_db
    urls = [
        {"url": "https://example.com/dashboard", "title": "Dashboard"},
        {"url": "https://example.com/admin", "title": "Admin"},
    ]
    count = write_surface_urls_to_db(db_path, urls)
    assert count == 2

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT url, source FROM pages").fetchall()
    conn.close()
    assert len(rows) == 2
    assert all(r[1] == "browser_use" for r in rows)


def test_write_cookies_to_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE auth_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_type TEXT,
        token_name TEXT,
        token_value TEXT,
        domain TEXT,
        path TEXT,
        is_active INTEGER DEFAULT 1,
        cookie_source TEXT DEFAULT 'manual'
    )""")
    conn.commit()
    conn.close()

    from TOOLS.browser_auth import write_cookies_to_db
    cookies = [
        {"name": "session", "value": "abc123", "domain": "example.com", "path": "/"},
        {"name": "csrf", "value": "xyz", "domain": "example.com", "path": "/"},
    ]
    write_cookies_to_db(db_path, cookies)

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT token_name, cookie_source FROM auth_sessions").fetchall()
    conn.close()
    assert len(rows) == 2
    assert all(r[1] == "browser_use" for r in rows)
