import sqlite3

from utils.queue_hygiene import analyze_queue, apply_low_value


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE hunt_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            query_string TEXT,
            status TEXT DEFAULT 'queued',
            notes TEXT,
            tested_at TEXT
        );
        INSERT INTO hunt_queue (method, url, query_string, status)
        VALUES
          ('GET', 'https://portal.example.edu/portal-api/v2/theme/themeInfo', 'random_number=1', 'queued'),
          ('GET', 'https://portal.example.edu/portal-api/v2/theme/themeInfo', 'random_number=2', 'queued'),
          ('GET', 'https://portal.example.edu/api/user/profile', 'uid=42&random_number=1', 'queued');
        """
    )
    return conn


class TestQueueHygiene:
    def test_analyze_is_dry_run(self):
        conn = _conn()

        summary = analyze_queue(conn)
        queued = conn.execute("SELECT count(*) AS c FROM hunt_queue WHERE status='queued'").fetchone()["c"]
        conn.close()

        assert summary["queued"] == 3
        assert summary["duplicate_groups"] == 1
        assert summary["random_param_duplicates"] == 1
        assert summary["low_value_queued"] == 2
        assert queued == 3

    def test_apply_marks_only_low_value_queued_tested(self):
        conn = _conn()
        summary = analyze_queue(conn)

        changed = apply_low_value(conn, summary["low_value_ids"])
        statuses = conn.execute("SELECT url, status FROM hunt_queue ORDER BY id").fetchall()
        conn.close()

        assert changed == 2
        assert [row["status"] for row in statuses] == ["tested", "tested", "queued"]
