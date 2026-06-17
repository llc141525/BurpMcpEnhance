# TOOLS/tests/test_cookie_helper.py
import sqlite3
import time

from db.cookie_helper import (
    _domain_matches,
    _is_expired,
    _path_matches,
    get_auth_cookie_header,
    get_auth_cookies_dict,
)


class TestDomainMatches:
    def test_exact_match(self):
        assert _domain_matches("example.com", "example.com")

    def test_subdomain_match(self):
        assert _domain_matches("example.com", "api.example.com")

    def test_dot_prefix_match(self):
        assert _domain_matches(".example.com", "api.example.com")

    def test_no_match_different_domain(self):
        assert not _domain_matches("other.com", "api.example.com")

    def test_no_partial_match(self):
        # "example.com" should not match "notexample.com"
        assert not _domain_matches("example.com", "notexample.com")

    def test_empty_cookie_domain(self):
        assert not _domain_matches("", "example.com")


class TestPathMatches:
    def test_root_matches_all(self):
        assert _path_matches("/", "/api/v1/users")

    def test_empty_matches_all(self):
        assert _path_matches("", "/anything")

    def test_exact_match(self):
        assert _path_matches("/api", "/api")

    def test_prefix_with_slash(self):
        assert _path_matches("/api", "/api/v1/users")

    def test_no_partial_segment_match(self):
        # /api must NOT match /api2
        assert not _path_matches("/api", "/api2/endpoint")

    def test_no_unrelated_path(self):
        assert not _path_matches("/admin", "/api/v1")


class TestIsExpired:
    def test_none_not_expired(self):
        assert not _is_expired(None)

    def test_empty_not_expired(self):
        assert not _is_expired("")

    def test_negative_one_not_expired(self):
        assert not _is_expired("-1")

    def test_past_timestamp_expired(self):
        past = str(time.time() - 3600)  # 1 hour ago
        assert _is_expired(past)

    def test_future_timestamp_not_expired(self):
        future = str(time.time() + 3600)  # 1 hour from now
        assert not _is_expired(future)

    def test_iso_past_expired(self):
        assert _is_expired("2020-01-01T00:00:00+00:00")

    def test_iso_future_not_expired(self):
        assert not _is_expired("2099-12-31T23:59:59+00:00")

    def test_unparseable_not_expired(self):
        # conservative: don't filter cookies with unrecognized format
        assert not _is_expired("garbage")


def _dump_db(mem_db, tmp_path) -> str:
    """Write mem_db contents to a temp file, return path string."""
    db_file = str(tmp_path / "test.db")
    dst = sqlite3.connect(db_file)
    mem_db.backup(dst)
    dst.close()
    return db_file


class TestGetAuthCookiesDict:
    def test_returns_matching_cookie(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('session', 'abc123', 'example.com', '/', 1)"
        )
        mem_db.commit()

        result = get_auth_cookies_dict(_dump_db(mem_db, tmp_path), "example.com")
        assert result == {"session": "abc123"}

    def test_ignores_inactive(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('session', 'abc123', 'example.com', '/', 0)"
        )
        mem_db.commit()

        result = get_auth_cookies_dict(_dump_db(mem_db, tmp_path), "example.com")
        assert result == {}

    def test_ignores_expired(self, mem_db, tmp_path):
        past = str(time.time() - 3600)
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active, expires_at) "
            "VALUES ('session', 'abc123', 'example.com', '/', 1, ?)",
            (past,),
        )
        mem_db.commit()

        result = get_auth_cookies_dict(_dump_db(mem_db, tmp_path), "example.com")
        assert result == {}

    def test_path_mismatch_excluded(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('admin_token', 'xyz', 'example.com', '/admin', 1)"
        )
        mem_db.commit()

        result = get_auth_cookies_dict(_dump_db(mem_db, tmp_path), "example.com", request_path="/api/v1")
        assert result == {}


class TestGetAuthCookieHeader:
    def test_formats_as_header(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active) "
            "VALUES ('tok', 'val', 'example.com', '/', 1)"
        )
        mem_db.commit()

        header = get_auth_cookie_header(_dump_db(mem_db, tmp_path), "example.com")
        assert header == "tok=val"

    def test_returns_none_when_empty(self, tmp_path):
        # empty DB — no cookies
        db_file = str(tmp_path / "empty.db")
        conn = sqlite3.connect(db_file)
        conn.execute(
            "CREATE TABLE auth_sessions "
            "(id INTEGER PRIMARY KEY, token_name TEXT, token_value TEXT, domain TEXT, "
            "path TEXT, is_active INTEGER, role TEXT DEFAULT 'primary', expires_at TEXT)"
        )
        conn.commit()
        conn.close()

        result = get_auth_cookie_header(db_file, "example.com")
        assert result is None

    def test_filters_by_role(self, mem_db, tmp_path):
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active, role) "
            "VALUES ('tok', 'primary', 'example.com', '/', 1, 'primary')"
        )
        mem_db.execute(
            "INSERT INTO auth_sessions (token_name, token_value, domain, path, is_active, role) "
            "VALUES ('tok', 'secondary', 'example.com', '/', 1, 'secondary')"
        )
        mem_db.commit()

        header = get_auth_cookie_header(_dump_db(mem_db, tmp_path), "example.com", role="secondary")
        assert header == "tok=secondary"
