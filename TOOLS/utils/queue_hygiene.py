"""Dry-run/apply cleanup for noisy hunt_queue entries."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

from db.db_utils import connect, find_db  # noqa: E402
from utils.signal_filter import canonicalize_url, classify_endpoint  # noqa: E402


def _full_url(row: sqlite3.Row) -> str:
    url = row["url"] or ""
    query = row["query_string"] or ""
    if query and "?" not in url:
        return f"{url}?{query}"
    return url


def analyze_queue(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        """
        SELECT id, method, url, query_string, status
        FROM hunt_queue
        WHERE status='queued'
        ORDER BY id
        """
    ).fetchall()
    duplicate_groups: dict[str, list[int]] = defaultdict(list)
    low_value = []
    random_duplicates = 0

    for row in rows:
        full_url = _full_url(row)
        canonical = canonicalize_url(full_url)
        key = f"{row['method']} {canonical}"
        duplicate_groups[key].append(row["id"])
        signal = classify_endpoint(full_url, row["method"])
        if signal.value in ("low_value", "ignore"):
            low_value.append({"id": row["id"], "url": full_url, "value": signal.value, "reason": signal.reason})

    duplicates = {key: ids for key, ids in duplicate_groups.items() if len(ids) > 1}
    random_duplicates = sum(len(ids) - 1 for ids in duplicates.values())
    return {
        "queued": len(rows),
        "duplicate_groups": len(duplicates),
        "random_param_duplicates": random_duplicates,
        "low_value_queued": len(low_value),
        "low_value_ids": [item["id"] for item in low_value],
        "low_value_sample": low_value[:20],
    }


def apply_low_value(conn: sqlite3.Connection, ids: list[int]) -> int:
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    cur = conn.execute(
        f"""
        UPDATE hunt_queue
        SET status='tested',
            notes=COALESCE(notes || ' | ', '') || 'queue_hygiene: low_value endpoint',
            tested_at=datetime('now','localtime')
        WHERE id IN ({placeholders}) AND status='queued'
        """,
        ids,
    )
    conn.commit()
    return cur.rowcount


def main() -> None:
    parser = argparse.ArgumentParser(description="hunt_queue signal/noise hygiene")
    parser.add_argument("--target", required=True)
    parser.add_argument("--dry-run", action="store_true", help="analyze only; this is the default")
    parser.add_argument("--apply", action="store_true", help="mark low-value queued entries as tested")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)
    try:
        summary = analyze_queue(conn)
        summary["applied"] = apply_low_value(conn, summary["low_value_ids"]) if args.apply else 0
        summary["mode"] = "apply" if args.apply else "dry-run"
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
