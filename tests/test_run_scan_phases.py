# tests/test_run_scan_phases.py
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "TOOLS"))

from run_scan import handle_auth_ready, handle_auth_explore, set_phase, get_phase


def _make_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE scan_state (id INTEGER PRIMARY KEY, phase TEXT, seed_url TEXT, cdp_url TEXT)"
    )
    conn.execute(
        "CREATE TABLE suspicious_points (id TEXT PRIMARY KEY, test_status TEXT)"
    )
    conn.execute("INSERT INTO scan_state VALUES (1, 'auth_ready', 'https://x.com', NULL)")
    conn.commit()
    return conn


def test_handle_auth_ready_transitions_to_auth_explore():
    conn = _make_db()
    handle_auth_ready("testTarget", Path("/tmp/test.db"), conn)
    assert get_phase(conn) == "auth_explore"
    conn.close()


def test_handle_auth_explore_calls_subprocess_and_reads_sp(tmp_path):
    conn = _make_db()
    conn.execute("UPDATE scan_state SET phase='auth_explore' WHERE id=1")
    conn.commit()

    with patch("run_scan.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        handle_auth_explore("testTarget", tmp_path / "test.db", conn)
        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "auth_explore.py" in " ".join(str(c) for c in cmd)

    conn.close()


def test_handle_auth_explore_fallback_on_nonzero_exit(tmp_path):
    conn = _make_db()
    conn.execute("UPDATE scan_state SET phase='auth_explore' WHERE id=1")
    conn.commit()

    with patch("run_scan.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        handle_auth_explore("testTarget", tmp_path / "test.db", conn)
        assert get_phase(conn) == "spider"

    conn.close()
