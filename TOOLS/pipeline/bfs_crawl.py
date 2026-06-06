"""BFS 批量爬取：katana 驱动，结果写入 pages + js_files 表。

用法:
  python3 TOOLS/bfs_crawl.py --target "目标名"
  python3 TOOLS/bfs_crawl.py --target "目标名" --depth 3 --max-pages 500
  python3 TOOLS/bfs_crawl.py --url "https://example.com" --target "目标名" --depth 2

输出:
  - 新发现的页面 URL 写入 pages 表 (status='queued')
  - JS 文件 URL 写入 js_files 表 (analyzed=0)
  - 打印爬取摘要

依赖: katana (projectdiscovery) 安装在 PATH 中
"""

import argparse
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookie_header  # noqa: E402

JS_EXT_RE = re.compile(r"\.js(\?.*)?$", re.IGNORECASE)
SKIP_EXT_RE = re.compile(
    r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|tar|gz)(\?.*)?$",
    re.IGNORECASE,
)


def find_db(target: str) -> Path:
    dbs = sorted(DBS_DIR.glob(f"{target}*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dbs:
        sys.exit(f"[error] 找不到目标 DB: dbs/{target}*.db")
    return dbs[0]


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def get_seed_urls(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT url FROM pages WHERE depth=0 AND status='queued' ORDER BY id LIMIT 20").fetchall()
    if not rows:
        rows = conn.execute("SELECT domain FROM targets WHERE domain IS NOT NULL AND domain != ''").fetchall()
        seeds = []
        for r in rows:
            d = r["domain"].strip()
            if not d.startswith("http"):
                d = "https://" + d
            seeds.append(d)
        return seeds
    return [r["url"] for r in rows]


def same_domain(base: str, url: str) -> bool:
    try:
        base_host = urlparse(base).netloc
        url_host = urlparse(url).netloc
        if not base_host or not url_host:
            return False
        # strip www. prefix for comparison
        b = base_host[4:] if base_host.startswith("www.") else base_host
        u = url_host[4:] if url_host.startswith("www.") else url_host
        return bool(u == b or u.endswith("." + b))
    except Exception:
        return False


def run_katana(seed_urls: list[str], depth: int, max_pages: int, cookie_header: str | None = None) -> list[str]:
    if not shutil.which("katana"):
        sys.exit("[error] katana 未安装，请先安装: https://github.com/projectdiscovery/katana")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(seed_urls))
        input_file = f.name

    out_file = input_file + ".out"
    cmd = [
        "katana",
        "-list",
        input_file,
        "-d",
        str(depth),
        "-c",
        "10",  # concurrency
        "-p",
        "10",  # parallelism
        "-ef",
        "woff,css,png,svg,jpg,jpeg,gif,ico,ttf,eot",  # exclude extensions
        "-kf",
        "all",  # known files (all = robotstxt+sitemapxml)
        "-jc",  # JS crawling
        "-jsl",  # JS parsing
        "-timeout",
        "10",
        "-o",
        out_file,
        "-silent",
    ]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    print(f"[katana] 从 {len(seed_urls)} 个种子爬取（depth={depth}, max={max_pages}）...")
    try:
        subprocess.run(cmd, check=False, timeout=300)
    except subprocess.TimeoutExpired:
        print("[warn] katana 超时（300s）")
    finally:
        os.unlink(input_file)

    urls: list[str] = []
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u and (u.startswith("http://") or u.startswith("https://")):
                    urls.append(u)
        os.unlink(out_file)

    return urls[:max_pages]


def import_to_db(conn: sqlite3.Connection, discovered: list[str], seed_urls: list[str]) -> tuple[int, int]:
    base = seed_urls[0] if seed_urls else ""
    pages_added = 0
    js_added = 0

    for url in discovered:
        if SKIP_EXT_RE.search(url):
            continue
        if base and not same_domain(base, url):
            continue

        if JS_EXT_RE.search(url):
            cur = conn.execute(
                "INSERT INTO js_files (url, page_url) VALUES (?, ?) ON CONFLICT(url) DO NOTHING",
                (url, base),
            )
            if cur.rowcount:
                js_added += 1
        else:
            cur = conn.execute(
                "INSERT INTO pages (url, depth, status) VALUES (?, 1, 'queued') ON CONFLICT(url) DO NOTHING",
                (url,),
            )
            if cur.rowcount:
                pages_added += 1

    conn.commit()
    return pages_added, js_added


def main() -> None:
    parser = argparse.ArgumentParser(description="katana BFS 批量爬取")
    parser.add_argument("--target", required=True, help="目标名 (从 dbs/ 查找 DB)")
    parser.add_argument("--url", help="覆盖种子 URL（默认从 DB 读取）")
    parser.add_argument("--depth", type=int, default=3, help="爬取深度 (默认 3)")
    parser.add_argument("--max-pages", type=int, default=500, help="最大页面数 (默认 500)")
    parser.add_argument("--no-chrome", action="store_true", help="跳过 Chrome 单实例启动")
    args = parser.parse_args()

    # ── 启动/确认 Chrome 单实例 ────────────────────────────────────────
    if not args.no_chrome:
        try:
            result = subprocess.run(  # noqa: S603
                [sys.executable, str(Path(__file__).parent / "chrome_manager.py"), "--target", args.target],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0:
                print(f"[warn] chrome_manager 失败，继续不带 CDP: {result.stderr.strip()}")
            else:
                print(f"[chrome] {result.stdout.strip()}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] chrome_manager 异常: {e}")
    # ─────────────────────────────────────────────────────────────────

    db_path = find_db(args.target)
    conn = connect(db_path)

    seed_urls = [args.url] if args.url else get_seed_urls(conn)
    if not seed_urls:
        sys.exit("[error] 无种子 URL，请先运行 init_scan.py")

    print(f"[db] {db_path.name}")
    print(f"[seeds] {seed_urls[:5]}")

    cookie_header = get_auth_cookie_header(str(db_path), seed_urls[0] if seed_urls else "")
    if cookie_header:
        print(f"[bfs_crawl] 带认证 Cookie 爬取 ({len(cookie_header.split(';'))} 条)", file=sys.stderr)

    discovered = run_katana(seed_urls, args.depth, args.max_pages, cookie_header=cookie_header)
    pages_added, js_added = import_to_db(conn, discovered, seed_urls)
    conn.close()

    print("\n=== bfs_crawl 完成 ===")
    print(f"发现: {len(discovered)} 个 URL")
    print(f"写入 pages: {pages_added} 条")
    print(f"写入 js_files: {js_added} 条")
    print(f"DB: {db_path.name}")


if __name__ == "__main__":
    main()
