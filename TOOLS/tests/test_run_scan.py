"""run_scan.py 编排逻辑单元测试。

覆盖:
  - get_phase / set_phase / get_queue_count / get_sp_count (纯 DB 读写)
  - build_spider_summary  (spider 阶段输出构建)
  - spider_next_phase     (队列空 → probe 决策)
  - probe_next_phase      (无新 SP → brute 决策)
  - build_auth_barrier_lines (AUTH_BARRIER 消息格式)
"""

import sqlite3
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from run_scan import (
    build_auth_barrier_lines,
    build_spider_summary,
    exploit_next_phase,
    get_phase,
    get_queue_count,
    get_sp_count,
    needs_relogin,
    probe_next_phase,
    set_phase,
    spider_next_phase,
)

# ── Fixture ───────────────────────────────────────────────────────────────────


@pytest.fixture
def conn():
    """内存 DB，含 scan_state / pages / suspicious_points。"""
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            phase TEXT DEFAULT 'init'
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            depth INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued'
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            test_status TEXT DEFAULT 'untested'
        );
    """)
    yield c
    c.close()


# ── get_phase ─────────────────────────────────────────────────────────────────


class TestGetPhase:
    def test_returns_init_when_no_row(self, conn):
        assert get_phase(conn) == "init"

    def test_returns_stored_phase(self, conn):
        conn.execute("INSERT INTO scan_state (id, phase) VALUES (1, 'spider')")
        conn.commit()
        assert get_phase(conn) == "spider"

    def test_returns_auth_pending(self, conn):
        conn.execute("INSERT INTO scan_state (id, phase) VALUES (1, 'auth_pending')")
        conn.commit()
        assert get_phase(conn) == "auth_pending"


# ── set_phase ─────────────────────────────────────────────────────────────────


class TestSetPhase:
    def test_updates_phase(self, conn):
        conn.execute("INSERT INTO scan_state (id, phase) VALUES (1, 'init')")
        conn.commit()
        set_phase(conn, "spider")
        row = conn.execute("SELECT phase FROM scan_state WHERE id=1").fetchone()
        assert row[0] == "spider"

    def test_transitions_through_all_phases(self, conn):
        conn.execute("INSERT INTO scan_state (id, phase) VALUES (1, 'init')")
        conn.commit()
        for phase in ("spider", "probe", "brute", "auth_pending", "auth_ready", "auth_explore"):
            set_phase(conn, phase)
            assert get_phase(conn) == phase


# ── get_queue_count ───────────────────────────────────────────────────────────


class TestGetQueueCount:
    def test_empty_table_returns_zero(self, conn):
        assert get_queue_count(conn) == 0

    def test_counts_only_queued(self, conn):
        conn.execute("INSERT INTO pages (url, status) VALUES ('http://a.com', 'queued')")
        conn.execute("INSERT INTO pages (url, status) VALUES ('http://b.com', 'visited')")
        conn.execute("INSERT INTO pages (url, status) VALUES ('http://c.com', 'queued')")
        conn.commit()
        assert get_queue_count(conn) == 2

    def test_all_visited_returns_zero(self, conn):
        conn.execute("INSERT INTO pages (url, status) VALUES ('http://a.com', 'visited')")
        conn.commit()
        assert get_queue_count(conn) == 0


# ── get_sp_count ──────────────────────────────────────────────────────────────


class TestGetSpCount:
    def test_empty_returns_zero(self, conn):
        assert get_sp_count(conn) == 0

    def test_counts_only_untested(self, conn):
        conn.execute("INSERT INTO suspicious_points (id, test_status) VALUES ('SP-001', 'untested')")
        conn.execute("INSERT INTO suspicious_points (id, test_status) VALUES ('SP-002', 'confirmed')")
        conn.execute("INSERT INTO suspicious_points (id, test_status) VALUES ('SP-003', 'untested')")
        conn.commit()
        assert get_sp_count(conn) == 2

    def test_all_confirmed_returns_zero(self, conn):
        conn.execute("INSERT INTO suspicious_points (id, test_status) VALUES ('SP-001', 'confirmed')")
        conn.commit()
        assert get_sp_count(conn) == 0


# ── spider_next_phase ─────────────────────────────────────────────────────────


class TestSpiderNextPhase:
    def test_empty_queue_returns_probe(self):
        assert spider_next_phase(queue_count=0) == "probe"

    def test_non_empty_queue_returns_none(self):
        assert spider_next_phase(queue_count=5) is None

    def test_single_item_queue_returns_none(self):
        assert spider_next_phase(queue_count=1) is None


# ── probe_next_phase ──────────────────────────────────────────────────────────


class TestProbeNextPhase:
    def test_no_new_sp_transitions_to_exploit(self):
        assert probe_next_phase(new_sp=0) == "exploit"

    def test_new_sp_found_returns_none(self):
        assert probe_next_phase(new_sp=3) is None

    def test_single_new_sp_returns_none(self):
        assert probe_next_phase(new_sp=1) is None


# ── build_spider_summary ──────────────────────────────────────────────────────


class TestBuildSpiderSummary:
    def test_basic_summary_line(self):
        lines = build_spider_summary(new_pages=10, new_js=2, queue=5, js_lines=[], new_sp=0)
        assert any("10" in line and "2" in line and "5" in line for line in lines)

    def test_includes_js_lines_when_present(self):
        lines = build_spider_summary(new_pages=0, new_js=1, queue=0, js_lines=["api=/v1/users"], new_sp=0)
        assert any("api=/v1/users" in line for line in lines)

    def test_includes_sp_count_when_nonzero(self):
        lines = build_spider_summary(new_pages=0, new_js=0, queue=0, js_lines=[], new_sp=4)
        assert any("4" in line for line in lines)

    def test_no_sp_line_when_zero(self):
        lines = build_spider_summary(new_pages=0, new_js=0, queue=0, js_lines=[], new_sp=0)
        # should not add an extra SP line when count is 0
        sp_lines = [line for line in lines if "SP" in line and "0" in line and "js_analysis" in line]
        assert len(sp_lines) == 0

    def test_js_lines_capped_at_eight(self):
        many = [f"line{i}" for i in range(20)]
        lines = build_spider_summary(new_pages=0, new_js=0, queue=0, js_lines=many, new_sp=0)
        js_content = [line for line in lines if "line" in line]
        assert len(js_content) <= 8


# ── build_auth_barrier_lines ──────────────────────────────────────────────────


class TestBuildAuthBarrierLines:
    def test_contains_login_url(self):
        lines = build_auth_barrier_lines("台州学院", "https://sso.tzc.edu.cn/login")
        assert any("https://sso.tzc.edu.cn/login" in line for line in lines)

    def test_contains_target_in_db_query_command(self):
        lines = build_auth_barrier_lines("台州学院", "https://example.com/login")
        full = "\n".join(lines)
        assert "台州学院" in full

    def test_sets_phase_to_auth_ready(self):
        lines = build_auth_barrier_lines("台州学院", "https://example.com/login")
        full = "\n".join(lines)
        assert "auth_ready" in full

    def test_unknown_url_when_none(self):
        lines = build_auth_barrier_lines("台州学院", None)
        assert any("未知" in line for line in lines)


# ── needs_relogin ─────────────────────────────────────────────────────────────


class TestNeedsRelogin:
    def test_empty_sessions_returns_true(self):
        assert needs_relogin([]) is True

    def test_no_active_sessions_returns_true(self):
        sessions = [{"is_active": 0, "expires_at": "2099-01-01 00:00:00"}]
        assert needs_relogin(sessions) is True

    def test_active_no_expiry_returns_false(self):
        sessions = [{"is_active": 1, "expires_at": None}]
        assert needs_relogin(sessions) is False

    def test_active_future_expiry_returns_false(self):
        sessions = [{"is_active": 1, "expires_at": "2099-01-01 00:00:00"}]
        assert needs_relogin(sessions) is False

    def test_active_expired_returns_true(self):
        sessions = [{"is_active": 1, "expires_at": "2020-01-01 00:00:00"}]
        assert needs_relogin(sessions) is True

    def test_mixed_expired_and_future_returns_false(self):
        sessions = [
            {"is_active": 1, "expires_at": "2020-01-01 00:00:00"},
            {"is_active": 1, "expires_at": "2099-01-01 00:00:00"},
        ]
        assert needs_relogin(sessions) is False


# ── exploit_next_phase ────────────────────────────────────────────────────────


class TestExploitNextPhase:
    def test_always_returns_brute(self):
        assert exploit_next_phase() == "brute"
