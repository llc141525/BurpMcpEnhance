"""Tests for chrome_manager.py"""
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_is_chrome_running_returns_true_when_port_responds():
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        from TOOLS.chrome_manager import is_chrome_running
        assert is_chrome_running(9222) is True


def test_is_chrome_running_returns_false_when_port_closed():
    import requests
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        from TOOLS.chrome_manager import is_chrome_running
        assert is_chrome_running(9222) is False


def test_wait_for_chrome_returns_cdp_url_when_ready():
    with patch("TOOLS.chrome_manager.is_chrome_running", side_effect=[False, False, True]):
        with patch("time.sleep"):
            from TOOLS.chrome_manager import wait_for_chrome
            result = wait_for_chrome(port=9222, timeout=5)
            assert result == "http://localhost:9222"


def test_wait_for_chrome_raises_on_timeout():
    with patch("TOOLS.chrome_manager.is_chrome_running", return_value=False):
        with patch("time.sleep"):
            with patch("time.time", side_effect=[0, 1, 2, 3, 4, 5, 6]):
                from TOOLS.chrome_manager import wait_for_chrome
                with pytest.raises(TimeoutError):
                    wait_for_chrome(port=9222, timeout=5)


def test_write_cdp_url_to_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE scan_state (id INTEGER PRIMARY KEY, cdp_url TEXT)")
    conn.execute("INSERT INTO scan_state (id) VALUES (1)")
    conn.commit()
    conn.close()

    from TOOLS.chrome_manager import write_cdp_url_to_db
    write_cdp_url_to_db(db_path, "http://localhost:9222")

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT cdp_url FROM scan_state WHERE id=1").fetchone()
    conn.close()
    assert row[0] == "http://localhost:9222"
