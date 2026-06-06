# tests/test_auth_explore.py
import sys
import sqlite3
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))
from auth.auth_explore import filter_api_requests, parse_request_params, write_explore_results_to_db


def test_filter_api_requests_excludes_static():
    reqs = [
        {"url": "https://x.com/api/users", "method": "GET", "resource_type": "xhr"},
        {"url": "https://x.com/style.css", "method": "GET", "resource_type": "stylesheet"},
        {"url": "https://x.com/api/orders", "method": "POST", "resource_type": "fetch"},
    ]
    result = filter_api_requests(reqs, "x.com")
    assert len(result) == 2
    assert all(r["url"].startswith("https://x.com/api/") for r in result)


def test_filter_api_requests_excludes_cross_domain():
    reqs = [
        {"url": "https://cdn.other.com/lib.js", "method": "GET", "resource_type": "xhr"},
        {"url": "https://x.com/api/me", "method": "GET", "resource_type": "xhr"},
    ]
    result = filter_api_requests(reqs, "x.com")
    assert len(result) == 1


def test_parse_request_params_query_string():
    params = parse_request_params("https://x.com/api?id=1&type=admin", None)
    assert "id" in params
    assert "type" in params


def test_parse_request_params_post_json():
    params = parse_request_params("https://x.com/api", '{"userId":1,"action":"delete"}')
    assert "userId" in params
    assert "action" in params


def test_write_explore_results_to_db():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(f.name)
    conn.execute("""CREATE TABLE suspicious_points (
        id TEXT PRIMARY KEY, url TEXT, param TEXT, method TEXT,
        test_type TEXT, evidence TEXT, source TEXT, reasoning TEXT,
        risk TEXT DEFAULT 'Medium', test_status TEXT DEFAULT 'untested',
        created_at TEXT
    )""")
    conn.execute("CREATE TABLE pages (id INTEGER PRIMARY KEY, url TEXT UNIQUE, depth INTEGER, status TEXT)")
    conn.commit()

    api_requests = [
        {"url": "https://x.com/api/users", "method": "GET", "params": ["page", "limit"], "nav_context": "用户管理"},
        {"url": "https://x.com/api/orders", "method": "POST", "params": ["orderId"], "nav_context": "订单"},
    ]
    page_urls = ["https://x.com/users", "https://x.com/orders"]

    counts = write_explore_results_to_db(conn, api_requests, page_urls, sp_prefix="SP-AE")
    assert counts["sp"] == 2
    assert counts["pages"] == 2
    conn.close()
