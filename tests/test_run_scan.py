"""Tests for run_scan.py — pure functions only (no subprocess calls)."""
import sqlite3
import tempfile

import pytest


def _make_db(phase: str = "init") -> tuple[str, sqlite3.Connection]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    conn = sqlite3.connect(tmp.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE scan_state (
            id INTEGER PRIMARY KEY,
            phase TEXT DEFAULT 'init',
            total_pages INTEGER DEFAULT 0,
            total_js INTEGER DEFAULT 0,
            total_suspicious INTEGER DEFAULT 0,
            call_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("INSERT INTO scan_state (id, phase) VALUES (1, ?)", (phase,))
    conn.commit()
    return tmp.name, conn


def test_get_phase_returns_current_phase():
    from TOOLS.run_scan import get_phase
    _, conn = _make_db("spider")
    assert get_phase(conn) == "spider"
    conn.close()


def test_set_phase_updates_db():
    from TOOLS.run_scan import get_phase, set_phase
    _, conn = _make_db("spider")
    set_phase(conn, "probe")
    assert get_phase(conn) == "probe"
    conn.close()


def test_print_tag_outputs_bracket_tag(capsys):
    from TOOLS.run_scan import print_tag
    print_tag("SPIDER_BATCH", ["新增页面: +10", "队列剩余: 50"])
    out = capsys.readouterr().out
    assert "[SPIDER_BATCH]" in out
    assert "新增页面: +10" in out
    assert "队列剩余: 50" in out


def test_print_tag_each_line_indented(capsys):
    from TOOLS.run_scan import print_tag
    print_tag("TEST", ["line one", "line two"])
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert lines[0] == "[TEST]"
    assert lines[1].startswith("  ")
    assert lines[2].startswith("  ")


def test_handle_auth_pending_prints_barrier_and_returns(capsys):
    from TOOLS.run_scan import handle_auth_pending
    _, conn = _make_db("auth_pending")
    handle_auth_pending(conn)
    out = capsys.readouterr().out
    assert "AUTH_BARRIER" in out
    conn.close()


def test_get_queue_count_returns_int():
    from TOOLS.run_scan import get_queue_count
    _, conn = _make_db()
    conn.execute("""
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            status TEXT DEFAULT 'queued'
        )
    """)
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://a.com', 'queued')")
    conn.execute("INSERT INTO pages (url, status) VALUES ('https://b.com', 'visited')")
    conn.commit()
    assert get_queue_count(conn) == 1
    conn.close()
