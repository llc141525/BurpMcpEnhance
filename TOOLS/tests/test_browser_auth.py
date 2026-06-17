# TOOLS/tests/test_browser_auth.py
import sqlite3

from auth.browser_auth import parse_surface_urls


class TestParseSurfaceUrls:
    def _item(self, url):
        return {"url": url, "title": "test"}

    def test_keeps_same_domain(self):
        result = parse_surface_urls([self._item("https://example.com/page")], "example.com")
        assert len(result) == 1

    def test_keeps_subdomain(self):
        result = parse_surface_urls([self._item("https://api.example.com/v1")], "example.com")
        assert len(result) == 1

    def test_excludes_different_domain(self):
        result = parse_surface_urls([self._item("https://evil.com/page")], "example.com")
        assert result == []

    def test_excludes_css(self):
        result = parse_surface_urls([self._item("https://example.com/style.css")], "example.com")
        assert result == []

    def test_excludes_image_png(self):
        result = parse_surface_urls([self._item("https://example.com/img.png")], "example.com")
        assert result == []

    def test_excludes_image_jpg(self):
        result = parse_surface_urls([self._item("https://example.com/photo.jpg")], "example.com")
        assert result == []

    def test_keeps_js(self):
        result = parse_surface_urls([self._item("https://example.com/app.js")], "example.com")
        assert len(result) == 1

    def test_excludes_non_http(self):
        result = parse_surface_urls([self._item("ftp://example.com/file")], "example.com")
        assert result == []

    def test_empty_url(self):
        result = parse_surface_urls([{"url": "", "title": ""}], "example.com")
        assert result == []

    def test_www_subdomain_treated_as_same(self):
        result = parse_surface_urls([self._item("https://www.example.com/page")], "example.com")
        assert len(result) == 1

    def test_multiple_mixed(self):
        items = [
            self._item("https://example.com/api"),
            self._item("https://example.com/icon.svg"),
            self._item("https://other.com/page"),
            self._item("https://sub.example.com/data"),
        ]
        result = parse_surface_urls(items, "example.com")
        assert len(result) == 2  # /api and sub.example.com/data


_AUTH_SESSIONS_DDL = """
CREATE TABLE auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_type TEXT, token_name TEXT, token_value TEXT,
    domain TEXT, path TEXT DEFAULT '/',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    role TEXT DEFAULT 'primary', expires_at TEXT,
    last_checked_at TEXT, cookie_source TEXT DEFAULT 'manual',
    username TEXT DEFAULT NULL,
    password TEXT DEFAULT NULL
);
CREATE UNIQUE INDEX idx_auth_sessions_role_name_domain
    ON auth_sessions(role, token_name, domain);
CREATE TABLE auth_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_label TEXT,
    username TEXT,
    password TEXT,
    login_url TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);
"""


class TestWriteCredentialsToDb:
    def _db_with_browser_use_row(self, tmp_path) -> str:
        db_file = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_file)
        _insert = (
            "INSERT INTO auth_sessions "
            "(token_type, token_name, token_value, domain, cookie_source) "
            "VALUES ('cookie', 'session', 'abc123', 'example.com', 'browser_use');"
        )
        conn.executescript(_AUTH_SESSIONS_DDL + _insert)  # noqa: S608
        conn.close()
        return db_file

    def test_writes_username_and_password(self, tmp_path):
        db_file = self._db_with_browser_use_row(tmp_path)

        from auth.browser_auth import write_credentials_to_db

        write_credentials_to_db(db_file, "user123", "pass456")

        conn = sqlite3.connect(db_file)
        # auth_credentials row always written
        cred = conn.execute("SELECT username, password FROM auth_credentials WHERE account_label='primary'").fetchone()
        # auth_sessions updated for is_active=1 row
        sess = conn.execute("SELECT username, password FROM auth_sessions WHERE is_active=1").fetchone()
        conn.close()
        assert cred[0] == "user123"
        assert cred[1] == "pass456"
        assert sess[0] == "user123"
        assert sess[1] == "pass456"

    def test_writes_secondary_credentials_and_updates_secondary_session(self, tmp_path):
        db_file = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_file)
        conn.executescript(
            _AUTH_SESSIONS_DDL
            + """
            INSERT INTO auth_sessions
              (token_type, token_name, token_value, domain, cookie_source, role)
            VALUES
              ('cookie', 'session', 'primary-value', 'example.com', 'browser_use', 'primary'),
              ('cookie', 'session', 'secondary-value', 'example.com', 'browser_use', 'secondary');
            """
        )
        conn.close()

        from auth.browser_auth import write_credentials_to_db

        write_credentials_to_db(db_file, "userB", "passB", account_label="secondary")

        conn = sqlite3.connect(db_file)
        cred = conn.execute(
            "SELECT username, password FROM auth_credentials WHERE account_label='secondary'"
        ).fetchone()
        primary = conn.execute("SELECT username FROM auth_sessions WHERE role='primary'").fetchone()
        secondary = conn.execute("SELECT username, password FROM auth_sessions WHERE role='secondary'").fetchone()
        conn.close()
        assert cred == ("userB", "passB")
        assert primary[0] is None
        assert secondary == ("userB", "passB")

    def test_writes_credentials_when_no_browser_use_row(self, tmp_path):
        """auth_credentials is always written; no is_active row means auth_sessions unchanged."""
        db_file = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_file)
        _insert = "INSERT INTO auth_sessions (token_type, cookie_source, is_active) VALUES ('cookie', 'manual', 0);"
        conn.executescript(_AUTH_SESSIONS_DDL + _insert)  # noqa: S608
        conn.close()

        from auth.browser_auth import write_credentials_to_db

        write_credentials_to_db(db_file, "user123", "pass456")

        conn = sqlite3.connect(db_file)
        # auth_credentials still written
        cred = conn.execute("SELECT username FROM auth_credentials WHERE account_label='primary'").fetchone()
        # no active session, so auth_sessions username stays NULL
        sess = conn.execute("SELECT username FROM auth_sessions").fetchone()
        conn.close()
        assert cred[0] == "user123"
        assert sess[0] is None


class TestPersistCdpAuthState:
    def test_persist_cdp_auth_state_delegates_to_auth_state_capture(self, monkeypatch):
        from auth import browser_auth

        calls = []

        def fake_capture(target, db_path, cdp_url, role="primary"):
            calls.append((target, db_path, cdp_url, role))
            return {"cookies": 2, "storage_tokens": 1}

        monkeypatch.setattr(browser_auth, "capture_to_db", fake_capture, raising=False)

        assert browser_auth.persist_cdp_auth_state("目标", "db.sqlite", "http://localhost:9222")
        assert calls == [("目标", "db.sqlite", "http://localhost:9222", "primary")]

    def test_persist_cdp_auth_state_passes_role(self, monkeypatch):
        from auth import browser_auth

        calls = []

        def fake_capture(target, db_path, cdp_url, role="primary"):
            calls.append((target, db_path, cdp_url, role))
            return {"cookies": 2, "storage_tokens": 1}

        monkeypatch.setattr(browser_auth, "capture_to_db", fake_capture, raising=False)

        assert browser_auth.persist_cdp_auth_state("目标", "db.sqlite", "http://localhost:9222", role="secondary")
        assert calls == [("目标", "db.sqlite", "http://localhost:9222", "secondary")]
