import sqlite3

from auth.auth_state import (
    classify_token_kind,
    cookies_to_auth_session_rows,
    export_header,
    storage_items_to_tokens,
    upsert_storage_tokens,
)

_AUTH_STORAGE_DDL = """
CREATE TABLE auth_storage_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT DEFAULT 'primary',
    storage_type TEXT NOT NULL,
    origin TEXT NOT NULL,
    token_name TEXT NOT NULL,
    token_value TEXT NOT NULL,
    token_kind TEXT DEFAULT 'storage',
    is_active INTEGER DEFAULT 1,
    first_seen_at TEXT DEFAULT (datetime('now','localtime')),
    last_seen_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT,
    source TEXT DEFAULT 'cdp_capture',
    UNIQUE(role, storage_type, origin, token_name)
);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(_AUTH_STORAGE_DDL)
    return conn


class TestTokenClassification:
    def test_classifies_jwt_like_value(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.signature"  # noqa: S105
        assert classify_token_kind("access_token", token) == "jwt"

    def test_classifies_bearer_value(self):
        assert classify_token_kind("authorization", "Bearer abc.def") == "bearer"

    def test_classifies_csrf_name(self):
        assert classify_token_kind("csrfToken", "abc123") == "csrf"

    def test_classifies_api_key_name(self):
        assert classify_token_kind("apiKey", "abc123") == "api_key"


class TestStorageTokens:
    def test_storage_items_to_tokens_keeps_security_relevant_values(self):
        tokens = storage_items_to_tokens(
            origin="https://portal.example.edu",
            storage_type="localStorage",
            items={
                "accessToken": "Bearer abc.def",
                "theme": "dark",
                "csrf": "csrf-value",
            },
        )

        names = {t["token_name"] for t in tokens}
        assert names == {"accessToken", "csrf"}
        assert {t["token_kind"] for t in tokens} == {"bearer", "csrf"}

    def test_upsert_storage_tokens_updates_existing_row(self):
        conn = _conn()

        upsert_storage_tokens(
            conn,
            [
                {
                    "role": "primary",
                    "storage_type": "localStorage",
                    "origin": "https://portal.example.edu",
                    "token_name": "accessToken",
                    "token_value": "old",
                    "token_kind": "storage",
                    "expires_at": None,
                }
            ],
        )
        upsert_storage_tokens(
            conn,
            [
                {
                    "role": "primary",
                    "storage_type": "localStorage",
                    "origin": "https://portal.example.edu",
                    "token_name": "accessToken",
                    "token_value": "new",
                    "token_kind": "bearer",
                    "expires_at": "2099-01-01 00:00:00",
                }
            ],
        )

        rows = conn.execute("SELECT token_value, token_kind, expires_at FROM auth_storage_tokens").fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0]["token_value"] == "new"  # noqa: S105
        assert rows[0]["token_kind"] == "bearer"  # noqa: S105
        assert rows[0]["expires_at"] == "2099-01-01 00:00:00"

    def test_upsert_storage_tokens_creates_missing_table(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row

        upsert_storage_tokens(
            conn,
            [
                {
                    "role": "primary",
                    "storage_type": "localStorage",
                    "origin": "https://portal.example.edu",
                    "token_name": "accessToken",
                    "token_value": "abc.def.ghi",
                    "token_kind": "jwt",
                    "expires_at": None,
                }
            ],
        )

        row = conn.execute("SELECT token_name FROM auth_storage_tokens").fetchone()
        conn.close()
        assert row["token_name"] == "accessToken"


class TestCookieRows:
    def test_cookies_to_auth_session_rows_normalizes_playwright_cookies(self):
        rows = cookies_to_auth_session_rows(
            [
                {
                    "name": "SESSION",
                    "value": "abc",
                    "domain": ".example.edu",
                    "path": "/",
                    "expires": 4102444800,
                }
            ]
        )

        assert rows == [
            {
                "token_name": "SESSION",
                "token_value": "abc",
                "domain": ".example.edu",
                "path": "/",
                "expires_at": "2100-01-01 00:00:00",
                "cookie_source": "cdp_capture",
                "role": "primary",
            }
        ]

    def test_cookies_to_auth_session_rows_preserves_role(self):
        rows = cookies_to_auth_session_rows(
            [{"name": "SESSION", "value": "abc", "domain": ".example.edu", "path": "/", "expires": -1}],
            role="secondary",
        )

        assert rows[0]["role"] == "secondary"


class TestExportHeader:
    def test_export_header_matches_cookie_domain_when_url_has_port(self, tmp_path, monkeypatch):
        from auth import auth_state

        db_file = str(tmp_path / "target.db")
        conn = sqlite3.connect(db_file)
        conn.executescript(
            _AUTH_STORAGE_DDL
            + """
            CREATE TABLE auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT,
                token_name TEXT,
                token_value TEXT,
                domain TEXT,
                path TEXT DEFAULT '/',
                is_active INTEGER DEFAULT 1,
                role TEXT DEFAULT 'primary'
            );
            INSERT INTO auth_sessions (token_type, token_name, token_value, domain)
            VALUES ('cookie', 'SESSION', 'abc', '.example.edu');
            """
        )
        conn.close()

        monkeypatch.setattr(auth_state, "find_db", lambda target: db_file)

        headers = export_header("目标", "https://portal.example.edu:8443/home")

        assert headers["Cookie"] == "SESSION=abc"


class TestSchemaCompatibility:
    def test_full_schema_auth_sessions_supports_stored_credentials(self):
        from pathlib import Path

        conn = sqlite3.connect(":memory:")
        conn.executescript(Path("TOOLS/db/schema.sql").read_text(encoding="utf-8"))

        columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_sessions)")}
        conn.close()

        assert {"username", "password"} <= columns


class TestSessionManagerPriority:
    def test_ensure_session_tries_cdp_capture_before_browser_relogin(self, tmp_path, monkeypatch):
        from auth import session_manager

        db_file = str(tmp_path / "target.db")
        conn = sqlite3.connect(db_file)
        conn.executescript(
            """
            CREATE TABLE auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT,
                token_name TEXT,
                token_value TEXT,
                domain TEXT,
                path TEXT DEFAULT '/',
                is_active INTEGER DEFAULT 0,
                role TEXT DEFAULT 'primary',
                expires_at TEXT,
                username TEXT,
                password TEXT
            );
            CREATE TABLE auth_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_label TEXT,
                username TEXT,
                password TEXT,
                login_url TEXT
            );
            CREATE TABLE scan_state (
                id INTEGER PRIMARY KEY,
                seed_url TEXT,
                cdp_url TEXT
            );
            INSERT INTO auth_credentials (account_label, username, password, login_url)
            VALUES ('primary', 'u', 'p', 'https://login.example.edu');
            INSERT INTO scan_state (id, seed_url, cdp_url)
            VALUES (1, 'https://portal.example.edu', 'http://localhost:9222');
            """
        )
        conn.close()

        valid_calls = {"count": 0}
        capture_calls = []
        relogin_calls = []

        def fake_sessions_valid(_conn, role="primary"):
            valid_calls["count"] += 1
            return valid_calls["count"] >= 2

        def fake_capture_to_db(target, path, role="primary"):
            capture_calls.append((target, path, role))
            return {"cookies": 1, "storage_tokens": 0}

        monkeypatch.setattr(session_manager, "find_db", lambda target: db_file)
        monkeypatch.setattr(session_manager.subprocess, "run", lambda *args, **kwargs: None)
        monkeypatch.setattr(session_manager, "sessions_valid", fake_sessions_valid)
        monkeypatch.setattr(session_manager, "capture_to_db", fake_capture_to_db, raising=False)
        monkeypatch.setattr(
            session_manager,
            "run_relogin",
            lambda *args, **kwargs: relogin_calls.append(args) or True,
        )

        assert session_manager.ensure_session("目标")
        assert capture_calls == [("目标", db_file, "primary")]
        assert relogin_calls == []

    def test_secondary_session_skips_cdp_capture_and_relogs_with_secondary(self, tmp_path, monkeypatch):
        from auth import session_manager

        db_file = str(tmp_path / "target.db")
        conn = sqlite3.connect(db_file)
        conn.executescript(
            """
            CREATE TABLE auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT,
                token_name TEXT,
                token_value TEXT,
                domain TEXT,
                path TEXT DEFAULT '/',
                is_active INTEGER DEFAULT 0,
                role TEXT DEFAULT 'primary',
                expires_at TEXT,
                username TEXT,
                password TEXT
            );
            CREATE TABLE auth_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_label TEXT,
                username TEXT,
                password TEXT,
                login_url TEXT
            );
            CREATE TABLE scan_state (
                id INTEGER PRIMARY KEY,
                seed_url TEXT,
                cdp_url TEXT
            );
            INSERT INTO auth_credentials (account_label, username, password, login_url)
            VALUES ('secondary', 'u2', 'p2', 'https://login.example.edu');
            INSERT INTO scan_state (id, seed_url, cdp_url)
            VALUES (1, 'https://portal.example.edu', 'http://localhost:9222');
            """
        )
        conn.close()

        capture_calls = []
        relogin_calls = []

        monkeypatch.setattr(session_manager, "find_db", lambda target: db_file)
        monkeypatch.setattr(session_manager.subprocess, "run", lambda *args, **kwargs: None)
        monkeypatch.setattr(session_manager, "sessions_valid", lambda _conn, role="primary": False)
        monkeypatch.setattr(
            session_manager,
            "try_cdp_capture",
            lambda *args, **kwargs: capture_calls.append((args, kwargs)) or True,
        )
        monkeypatch.setattr(
            session_manager,
            "run_relogin",
            lambda *args, **kwargs: relogin_calls.append((args, kwargs)) or True,
        )

        assert session_manager.ensure_session("目标", role="secondary")
        assert capture_calls == []
        assert relogin_calls == [(("目标", "https://login.example.edu", "u2", "p2"), {"role": "secondary"})]
