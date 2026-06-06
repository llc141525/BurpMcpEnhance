# tests/test_cookie_helper.py
import sqlite3
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))
from db.cookie_helper import get_auth_cookie_header, get_auth_cookies_dict


def _make_db(cookies: list[dict]) -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(f.name)
    conn.execute("""CREATE TABLE auth_sessions (
        id INTEGER PRIMARY KEY,
        token_type TEXT, token_name TEXT, token_value TEXT,
        domain TEXT, path TEXT DEFAULT '/', is_active INTEGER DEFAULT 1
    )""")
    for c in cookies:
        conn.execute(
            "INSERT INTO auth_sessions (token_type,token_name,token_value,domain,is_active) VALUES (?,?,?,?,?)",
            (c["type"], c["name"], c["value"], c["domain"], c.get("active", 1)),
        )
    conn.commit()
    conn.close()
    return f.name


def test_get_auth_cookie_header_matches_domain():
    db = _make_db([
        {"type": "cookie", "name": "JSESSIONID", "value": "abc123", "domain": "example.com"},
        {"type": "cookie", "name": "token", "value": "xyz", "domain": "other.com"},
    ])
    header = get_auth_cookie_header(db, "example.com")
    assert header == "JSESSIONID=abc123"


def test_get_auth_cookie_header_subdomain_match():
    db = _make_db([
        {"type": "cookie", "name": "SID", "value": "s1", "domain": ".example.com"},
    ])
    assert get_auth_cookie_header(db, "app.example.com") == "SID=s1"


def test_get_auth_cookie_header_inactive_excluded():
    db = _make_db([
        {"type": "cookie", "name": "OLD", "value": "v", "domain": "example.com", "active": 0},
    ])
    assert get_auth_cookie_header(db, "example.com") is None


def test_get_auth_cookies_dict():
    db = _make_db([
        {"type": "cookie", "name": "A", "value": "1", "domain": "x.com"},
        {"type": "cookie", "name": "B", "value": "2", "domain": "x.com"},
    ])
    d = get_auth_cookies_dict(db, "x.com")
    assert d == {"A": "1", "B": "2"}


def test_no_matching_cookies_returns_none():
    db = _make_db([])
    assert get_auth_cookie_header(db, "example.com") is None
