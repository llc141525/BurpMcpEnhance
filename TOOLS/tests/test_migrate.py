# TOOLS/tests/test_migrate.py
import sqlite3

from db.migrate import apply_migration, detect_legacy_db, ensure_schema_version, get_current_version


def _mem_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


class TestDetectLegacyDb:
    def test_empty_db_not_legacy(self):
        conn = _mem_conn()
        assert not detect_legacy_db(conn)

    def test_has_targets_table_is_legacy(self):
        conn = _mem_conn()
        conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY)")
        assert detect_legacy_db(conn)

    def test_has_pages_table_is_legacy(self):
        conn = _mem_conn()
        conn.execute("CREATE TABLE pages (id INTEGER PRIMARY KEY)")
        assert detect_legacy_db(conn)

    def test_unrelated_table_not_legacy(self):
        conn = _mem_conn()
        conn.execute("CREATE TABLE random_stuff (id INTEGER PRIMARY KEY)")
        assert not detect_legacy_db(conn)


class TestEnsureSchemaVersion:
    def test_creates_table(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "schema_version" in tables

    def test_idempotent(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        ensure_schema_version(conn)  # should not raise


class TestGetCurrentVersion:
    def test_empty_version_table_returns_zero(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        assert get_current_version(conn) == 0

    def test_returns_max_version(self):
        conn = _mem_conn()
        ensure_schema_version(conn)
        conn.execute("INSERT INTO schema_version (version) VALUES (3)")
        conn.execute("INSERT INTO schema_version (version) VALUES (1)")
        conn.commit()
        assert get_current_version(conn) == 3


class TestApplyMigration:
    def test_applies_valid_sql(self, tmp_path):
        sql_file = tmp_path / "002_test.sql"
        sql_file.write_text("CREATE TABLE test_table (id INTEGER PRIMARY KEY);")
        conn = _mem_conn()
        ensure_schema_version(conn)
        result = apply_migration(conn, 2, str(sql_file))
        assert result is True
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "test_table" in tables

    def test_ignores_duplicate_column(self, tmp_path):
        sql_file = tmp_path / "003_dup.sql"
        conn = _mem_conn()
        ensure_schema_version(conn)
        conn.execute("CREATE TABLE t (id INTEGER, existing TEXT)")
        sql_file.write_text("ALTER TABLE t ADD COLUMN existing TEXT;")
        result = apply_migration(conn, 3, str(sql_file))
        assert result is True

    def test_ignores_table_already_exists(self, tmp_path):
        sql_file = tmp_path / "004_exists.sql"
        conn = _mem_conn()
        ensure_schema_version(conn)
        conn.execute("CREATE TABLE already_there (id INTEGER)")
        sql_file.write_text("CREATE TABLE already_there (id INTEGER);")
        result = apply_migration(conn, 4, str(sql_file))
        assert result is True

    def test_fails_on_real_error(self, tmp_path):
        sql_file = tmp_path / "005_bad.sql"
        sql_file.write_text("SELECT * FROM nonexistent_table_xyz;")
        conn = _mem_conn()
        ensure_schema_version(conn)
        result = apply_migration(conn, 5, str(sql_file))
        assert result is False
