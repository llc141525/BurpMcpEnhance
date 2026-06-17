# TOOLS/tests/test_race_scan.py
"""race_scan.py 单元测试（RED 阶段 — race_scan.py 尚未实现）。"""

import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from pipeline.race_scan import (
    find_race_candidates,
    is_race_detected,
    write_race_finding,
    write_race_sp,
)


class MockResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            domain TEXT
        );
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            target_id INTEGER,
            seed_url TEXT,
            phase TEXT DEFAULT 'init'
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            depth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued',
            source TEXT DEFAULT NULL
        );
        CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            query_string TEXT,
            body TEXT,
            content_type TEXT,
            endpoint_type TEXT,
            business_intent TEXT,
            risk_hint TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'queued',
            notes TEXT,
            source TEXT DEFAULT 'auto',
            UNIQUE(method, url, query_string)
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
            risk TEXT DEFAULT 'Medium',
            test_status TEXT DEFAULT 'untested',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            notes TEXT
        );
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            sp_id TEXT,
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
            confirmed_at TEXT,
            burp_request_id INTEGER
        );
        INSERT INTO targets (target_name, domain) VALUES ('测试目标', 'example.com');
        INSERT INTO scan_state (id, target_id, seed_url, phase)
            VALUES (1, 1, 'https://example.com', 'vuln_scan');
    """)
    yield c
    c.close()


# ---------------------------------------------------------------------------
# find_race_candidates
# ---------------------------------------------------------------------------


def test_find_race_candidates_from_business_intent(conn):
    conn.execute("""
        INSERT INTO hunt_queue (target_id, method, url, query_string, business_intent, status)
        VALUES (1, 'POST', 'https://example.com/api/coupon/use', '', '优惠券核销', 'queued')
    """)
    conn.commit()
    results = find_race_candidates(conn)
    assert len(results) == 1
    assert "coupon" in results[0]["url"]


def test_find_race_candidates_from_url_keyword(conn):
    conn.execute("""
        INSERT INTO hunt_queue (target_id, method, url, query_string, business_intent, status)
        VALUES (1, 'POST', 'https://example.com/api/pay/order', '', '提交订单', 'queued')
    """)
    conn.commit()
    results = find_race_candidates(conn)
    assert len(results) >= 1
    assert any("pay" in r["url"] for r in results)


def test_find_race_candidates_empty(conn):
    results = find_race_candidates(conn)
    assert results == []


def test_find_race_candidates_skips_non_race(conn):
    conn.execute("""
        INSERT INTO hunt_queue (target_id, method, url, query_string, business_intent, status)
        VALUES (1, 'GET', 'https://example.com/api/user/info', '', '获取用户信息', 'queued')
    """)
    conn.commit()
    results = find_race_candidates(conn)
    assert results == []


def test_find_race_candidates_skips_tested(conn):
    conn.execute("""
        INSERT INTO hunt_queue (target_id, method, url, query_string, business_intent, status)
        VALUES (1, 'POST', 'https://example.com/api/redeem', '', '兑换积分', 'tested')
    """)
    conn.commit()
    results = find_race_candidates(conn)
    assert results == []


# ---------------------------------------------------------------------------
# is_race_detected
# ---------------------------------------------------------------------------


def test_is_race_detected_multiple_success():
    responses = [MockResponse(200, '{"code":0,"msg":"success","data":{"points":100}}') for _ in range(8)]
    responses += [MockResponse(200, '{"code":1,"msg":"already used"}') for _ in range(7)]
    detected, evidence = is_race_detected(responses)
    assert detected is True
    assert "8" in evidence  # 8 successes mentioned in evidence


def test_is_race_not_detected_single_success():
    responses = [MockResponse(200, '{"code":0,"msg":"success"}')]
    responses += [MockResponse(200, '{"code":1,"msg":"already used"}') for _ in range(14)]
    detected, evidence = is_race_detected(responses)
    assert detected is False


def test_is_race_not_detected_all_fail():
    responses = [MockResponse(400, '{"error":"invalid"}') for _ in range(15)]
    detected, evidence = is_race_detected(responses)
    assert detected is False


def test_is_race_handles_exceptions():
    responses = [Exception("connection refused")] * 5
    responses += [MockResponse(200, '{"code":0,"msg":"success"}') for _ in range(2)]
    detected, evidence = is_race_detected(responses)
    assert detected is True  # 2 successes still trigger detection


# ---------------------------------------------------------------------------
# write_race_finding
# ---------------------------------------------------------------------------


def test_write_race_finding(conn):
    result = write_race_finding(conn, 1, "https://example.com/api/coupon/use", "POST", "8/15 并发成功", 8)
    assert result is True
    row = conn.execute("SELECT * FROM findings WHERE type='race_condition'").fetchone()
    assert row is not None
    assert row["risk"] == "High"
    assert row["url"] == "https://example.com/api/coupon/use"


def test_write_race_finding_dedup(conn):
    write_race_finding(conn, 1, "https://example.com/api/coupon/use", "POST", "8/15", 8)
    result2 = write_race_finding(conn, 1, "https://example.com/api/coupon/use", "POST", "9/15", 9)
    assert result2 is False
    count = conn.execute("SELECT COUNT(*) FROM findings WHERE type='race_condition'").fetchone()[0]
    assert count == 1


# ---------------------------------------------------------------------------
# write_race_sp
# ---------------------------------------------------------------------------


def test_write_race_sp(conn):
    result = write_race_sp(conn, 1, "https://example.com/api/pay", "POST", "响应时间差异 > 500ms")
    assert result is True
    row = conn.execute("SELECT * FROM suspicious_points WHERE test_type='race_condition'").fetchone()
    assert row is not None
    assert row["risk"] == "Medium"
    assert row["source"] == "race_scan"


def test_write_race_sp_dedup(conn):
    write_race_sp(conn, 1, "https://example.com/api/pay", "POST", "first")
    result2 = write_race_sp(conn, 1, "https://example.com/api/pay", "POST", "second")
    assert result2 is False
    count = conn.execute("SELECT COUNT(*) FROM suspicious_points WHERE test_type='race_condition'").fetchone()[0]
    assert count == 1
