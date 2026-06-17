# TOOLS/tests/conftest.py
"""共享 pytest fixtures。"""

import sqlite3
import sys
from pathlib import Path

import pytest

# 把 TOOLS/ 加入 sys.path，使所有 from db.xxx / from utils.xxx 可用
_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))


@pytest.fixture
def mem_db():
    """返回 in-memory SQLite 连接，建好 auth_sessions 表。"""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_type TEXT,
            token_name TEXT,
            token_value TEXT,
            domain TEXT,
            path TEXT DEFAULT '/',
            is_active INTEGER DEFAULT 1,
            role TEXT DEFAULT 'primary',
            cookie_source TEXT,
            expires_at TEXT
        );
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT
        );
        CREATE TABLE pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            depth INTEGER,
            status TEXT,
            source TEXT
        );
        CREATE TABLE suspicious_points (
            id TEXT PRIMARY KEY,
            url TEXT,
            param TEXT,
            method TEXT,
            test_type TEXT,
            evidence TEXT,
            source TEXT,
            reasoning TEXT,
            risk TEXT,
            test_status TEXT,
            created_at TEXT
        );
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT DEFAULT (datetime('now', 'localtime')),
            description TEXT
        );
    """)
    yield conn
    conn.close()
