#!/usr/bin/env python3
"""
ZoomEye 被动侦察工具 — SRC 攻击面发现（免费 10000 条/月）
查询 ZoomEye API，结果写入 scanner.db recon_assets 表，可一键种入 BFS 队列。

环境变量:
  ZOOMEYE_KEY   ZoomEye API Key（账号页 → API，或 zoomeye.org/profile）

用法:
  python3 TOOLS/zoomeye_query.py --preset domain tourzj.edu.cn
  python3 TOOLS/zoomeye_query.py --preset domain tourzj.edu.cn --seed
  python3 TOOLS/zoomeye_query.py -q 'site:tourzj.edu.cn' --size 200
  python3 TOOLS/zoomeye_query.py -q 'hostname:tourzj.edu.cn' --json
  python3 TOOLS/zoomeye_query.py --preset ip 1.2.3.4
  python3 TOOLS/zoomeye_query.py --preset cidr 1.2.3.0/24

查询示例（-q 参数，ZoomEye 语法）:
  site:target.com
  hostname:target.com
  ip:1.2.3.4
  cidr:1.2.3.0/24
  service:http AND site:target.com
  ssl:target.com
"""

import argparse
import json
import os
import sqlite3
import sys
import time

try:
    import requests
except ImportError:
    print('{"error": "缺少 requests: pip install requests"}', file=sys.stderr)
    sys.exit(1)

ZOOMEYE_HOST_API = "https://api.zoomeye.org/host/search"
CLASH_PROXY = "http://127.0.0.1:9870"
DEFAULT_DB = r"E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db"
PAGE_SIZE = 20  # ZoomEye 每页固定 20 条

PRESETS = {
    "domain": 'site:"{value}"',
    "host": 'hostname:"{value}"',
    "ip": 'ip:"{value}"',
    "cidr": 'cidr:"{value}"',
    "ssl": 'ssl:"{value}"',
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT    DEFAULT 'zoomeye',
    query        TEXT,
    host         TEXT,
    ip           TEXT,
    port         INTEGER,
    protocol     TEXT,
    domain       TEXT,
    title        TEXT,
    server       TEXT,
    country      TEXT,
    city         TEXT,
    os           TEXT,
    icp          TEXT,
    cert         TEXT,
    url          TEXT    UNIQUE,
    seeded       INTEGER DEFAULT 0,
    created_at   TEXT    DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_recon_url    ON recon_assets(url);
CREATE INDEX IF NOT EXISTS idx_recon_domain ON recon_assets(domain);
CREATE INDEX IF NOT EXISTS idx_recon_ip     ON recon_assets(ip);
"""


def db_connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def build_url(hit: dict) -> str:
    portinfo = hit.get("portinfo", {})
    proto = (portinfo.get("service") or "http").lower()
    if proto not in ("http", "https"):
        proto = "http"
    ip = hit.get("ip", "")
    port = portinfo.get("port", 80)
    hostname = ""
    rdns = hit.get("rdns", [])
    if rdns:
        hostname = rdns[0]
    host = hostname or ip
    if port in (80, 443):
        return f"{proto}://{host}"
    return f"{proto}://{host}:{port}"


def save_assets(conn, hits: list[dict], query: str, source: str) -> tuple[int, int]:
    inserted = skipped = 0
    for h in hits:
        url = build_url(h)
        portinfo = h.get("portinfo", {})
        rdns = h.get("rdns", [])
        geo = h.get("geoinfo", {})
        try:
            conn.execute(
                """INSERT OR IGNORE INTO recon_assets
                   (source, query, host, ip, port, protocol, domain, title,
                    server, country, city, os, url)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    source,
                    query,
                    rdns[0] if rdns else h.get("ip"),
                    h.get("ip"),
                    portinfo.get("port"),
                    portinfo.get("service"),
                    rdns[0] if rdns else None,
                    portinfo.get("title"),
                    portinfo.get("server"),
                    geo.get("country", {}).get("names", {}).get("en"),
                    geo.get("city", {}).get("names", {}).get("zh-CN"),
                    portinfo.get("os"),
                    url,
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0]:
                inserted += 1
            else:
                skipped += 1
        except sqlite3.Error:
            skipped += 1
    conn.commit()
    return inserted, skipped


def seed_bfs_queue(conn, query: str) -> int:
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                url       TEXT UNIQUE,
                depth     INTEGER DEFAULT 0,
                status    TEXT DEFAULT 'queued',
                source    TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )""")
        cur = conn.execute("SELECT url FROM recon_assets WHERE seeded=0 AND query=?", (query,))
        urls = [r[0] for r in cur.fetchall()]
        seeded = 0
        for url in urls:
            conn.execute(
                "INSERT OR IGNORE INTO pages (url, depth, status, source) VALUES (?,0,'queued','zoomeye')",
                (url,),
            )
            if conn.execute("SELECT changes()").fetchone()[0]:
                seeded += 1
        conn.execute("UPDATE recon_assets SET seeded=1 WHERE seeded=0 AND query=?", (query,))
        conn.commit()
        return seeded
    except sqlite3.Error as e:
        print(f"[WARN] seed BFS 失败: {e}", file=sys.stderr)
        return 0


def zoomeye_search(api_key: str, query: str, size: int, use_proxy: bool) -> list[dict]:
    headers = {"API-KEY": api_key}
    proxies = {"http": CLASH_PROXY, "https": CLASH_PROXY} if use_proxy else None
    results = []
    page = 1
    fetched = 0

    while fetched < size:
        params = {"query": query, "page": page}
        try:
            resp = requests.get(ZOOMEYE_HOST_API, headers=headers, params=params, proxies=proxies, timeout=30)
        except requests.RequestException as e:
            print(f"[ERROR] 请求失败 (page={page}): {e}", file=sys.stderr)
            break

        if resp.status_code == 401:
            print("[ERROR] API Key 无效，请检查 ZOOMEYE_KEY 环境变量", file=sys.stderr)
            break
        if resp.status_code == 403:
            print("[ERROR] 配额已用完（免费账号 10000 条/月）", file=sys.stderr)
            break
        if not resp.ok:
            print(f"[ERROR] HTTP {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
            break

        data = resp.json()
        hits = data.get("matches", [])
        total = data.get("total", 0)
        results.extend(hits)
        fetched += len(hits)

        print(
            f"[ZoomEye] page={page} got={len(hits)} total={total} fetched={fetched}/{min(size, total)}",
            file=sys.stderr,
        )

        if len(hits) < PAGE_SIZE or fetched >= total or fetched >= size:
            break
        page += 1
        time.sleep(0.3)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="ZoomEye 被动侦察 → scanner.db recon_assets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-q", "--query", help="ZoomEye 查询，如 site:example.com")
    g.add_argument("--preset", nargs=2, metavar=("TYPE", "VALUE"), help=f"内置模板: {', '.join(PRESETS)}")

    parser.add_argument("--size", type=int, default=100, help="最多返回条数 (默认 100)")
    parser.add_argument("--seed", action="store_true", help="种入 BFS pages 队列")
    parser.add_argument("--json", action="store_true", help="只输出 JSON，不写 DB")
    parser.add_argument("--no-proxy", action="store_true", help="不走 Clash 代理")
    parser.add_argument("--db", default=DEFAULT_DB, help="scanner.db 路径")
    parser.add_argument("--key", help="ZoomEye API Key（优先于 ZOOMEYE_KEY 环境变量）")

    args = parser.parse_args()

    api_key = args.key or os.environ.get("ZOOMEYE_KEY", "")
    if not api_key:
        print(
            "[ERROR] 需要 ZoomEye API Key。\n"
            "  方式1: 设置环境变量  ZOOMEYE_KEY=xxx\n"
            "  方式2: 用参数         --key xxx\n"
            "  获取:  zoomeye.org → 个人中心 → API",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.preset:
        ptype, pval = args.preset
        if ptype not in PRESETS:
            print(f"[ERROR] 未知 preset: {ptype}，可选: {', '.join(PRESETS)}", file=sys.stderr)
            sys.exit(1)
        query = PRESETS[ptype].format(value=pval)
    else:
        query = args.query

    print(f"[ZoomEye] 查询: {query}", file=sys.stderr)

    hits = zoomeye_search(api_key, query, args.size, use_proxy=not args.no_proxy)
    if not hits:
        print(json.dumps({"query": query, "count": 0, "results": []}, ensure_ascii=False))
        return

    for h in hits:
        h["_url"] = build_url(h)

    if args.json:
        simplified = [
            {
                "url": h["_url"],
                "ip": h.get("ip"),
                "port": h.get("portinfo", {}).get("port"),
                "title": h.get("portinfo", {}).get("title"),
                "server": h.get("portinfo", {}).get("server"),
                "rdns": h.get("rdns", []),
                "country": h.get("geoinfo", {}).get("country", {}).get("names", {}).get("en"),
            }
            for h in hits
        ]
        print(
            json.dumps(
                {"query": query, "count": len(simplified), "results": simplified}, ensure_ascii=False, default=str
            )
        )
        return

    conn = db_connect(args.db)
    inserted, skipped = save_assets(conn, hits, query, source="zoomeye")
    print(f"[DB] inserted={inserted} skipped={skipped}", file=sys.stderr)

    seeded = 0
    if args.seed:
        seeded = seed_bfs_queue(conn, query)
        print(f"[BFS] seeded={seeded} URLs into pages queue", file=sys.stderr)

    conn.close()

    summary = {
        "query": query,
        "total_fetched": len(hits),
        "inserted": inserted,
        "skipped": skipped,
        "bfs_seeded": seeded,
        "sample": [
            {
                "url": h["_url"],
                "ip": h.get("ip"),
                "title": h.get("portinfo", {}).get("title"),
                "server": h.get("portinfo", {}).get("server"),
                "rdns": h.get("rdns", []),
            }
            for h in hits[:20]
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
