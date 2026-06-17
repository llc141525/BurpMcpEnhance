"""初始化扫描：httpx 批量验活 + 技术指纹 + 写 DB。

用法:
  python3 TOOLS/init_scan.py --target "目标名"
  python3 TOOLS/init_scan.py --target "目标名" --urls "https://a.com,https://b.com"
  python3 TOOLS/init_scan.py --urls-file /tmp/urls.txt

输出:
  - 更新 targets.tech_stack / title / ip / server
  - 新发现的 URL 写入 pages 表 (status='queued', depth=0)
  - 打印 httpx 扫描摘要

依赖: httpx (projectdiscovery) 安装在 PATH 中
"""

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/

_TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS_DIR))
from db.db_utils import connect, find_db  # noqa: E402

LOGIN_KEYWORDS = re.compile(r"(login|signin|sign-in|auth|passport|sso|oauth|账号|登录|验证|portal)", re.IGNORECASE)
AUTH_STATUS_CODES = {302, 401, 403}
AUTH_KEYWORDS = re.compile(
    r"(login|signin|sign-in|auth|passport|sso|oauth|账号|登录|验证|portal|请先登录|会话过期)",
    re.IGNORECASE,
)


def get_target_urls(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT domain FROM targets WHERE domain IS NOT NULL AND domain != ''").fetchall()
    urls = []
    for row in rows:
        d = row["domain"].strip()
        if not d.startswith("http"):
            d = "https://" + d
        urls.append(d)
    return urls


def run_httpx(urls: list[str]) -> list[dict]:
    if not shutil.which("httpx"):
        sys.exit("[error] httpx 未安装，请先安装: https://github.com/projectdiscovery/httpx")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        input_file = f.name

    out_file = input_file + ".json"
    cmd = [
        "httpx",
        "-l",
        input_file,
        "-sc",  # status code
        "-title",  # page title
        "-tech-detect",  # tech detection (Wappalyzer-based)
        "-server",  # Server header
        "-ip",  # resolved IP
        "-fr",  # follow redirects
        "-timeout",
        "10",
        "-threads",
        "10",
        "-json",
        "-o",
        out_file,
        "-silent",
    ]
    print(f"[httpx] 扫描 {len(urls)} 个 URL...")
    try:
        subprocess.run(cmd, check=False, timeout=120)
    except subprocess.TimeoutExpired:
        print("[warn] httpx 超时")
    finally:
        os.unlink(input_file)

    results = []
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        os.unlink(out_file)
    return results


def _strip_scheme(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").rstrip("/")


def update_target(conn: sqlite3.Connection, result: dict) -> dict:
    url = result.get("url", result.get("input", ""))
    status_code = result.get("status_code", 0)
    title = result.get("title", "")
    ip = result.get("host", "")
    tech_list: list = result.get("tech", []) or []
    tech_stack = ", ".join(tech_list) if tech_list else ""

    # targets schema: id, target_name, domain, ip, tech_stack, requires_auth, auth_status, discovered_at, notes
    # match on full URL OR bare hostname (domain may be stored either way)
    hostname = _strip_scheme(url)
    rows_updated = conn.execute(
        "UPDATE targets SET tech_stack=?, ip=? WHERE domain=? OR domain=?",
        (tech_stack, ip, url, hostname),
    ).rowcount
    conn.commit()

    if rows_updated == 0:
        print(f"  [warn] targets 中未找到匹配域名: {hostname}（跳过更新）")

    needs_login = bool(LOGIN_KEYWORDS.search(title or "") or LOGIN_KEYWORDS.search(url or ""))
    if needs_login:
        print(f"  [!] 疑似登录页: {url} — {title}")

    needs_auth = (
        status_code in AUTH_STATUS_CODES
        or bool(AUTH_KEYWORDS.search(title or ""))
        or bool(AUTH_KEYWORDS.search(url or ""))
    )
    if needs_auth:
        print(f"  [!] 疑似需要认证: {url} (HTTP {status_code}) — {title}")

    if status_code in (200, 301, 302):
        conn.execute(
            "INSERT INTO pages (url, depth, status) VALUES (?, 0, 'queued') ON CONFLICT(url) DO NOTHING",
            (url,),
        )
        conn.commit()

    return {"url": url, "needs_auth": needs_auth, "status_code": status_code}


def print_summary(results: list[dict]) -> None:
    print("\n=== init_scan 完成 ===")
    print(f"扫描: {len(results)} 个")
    live = [r for r in results if r.get("status_code", 0) in (200, 301, 302)]
    print(f"存活: {len(live)} 个")
    for r in live:
        tech = ", ".join(r.get("tech", []) or [])
        print(f"  {r.get('status_code')} {r.get('url')} [{tech or r.get('webserver', '')}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="httpx 批量验活 + 技术指纹")
    parser.add_argument("--target", help="目标名 (从 dbs/ 查找 DB)")
    parser.add_argument("--urls", help="逗号分隔的 URL 列表")
    parser.add_argument("--urls-file", help="URL 列表文件路径")
    args = parser.parse_args()

    urls: list[str] = []

    if args.urls:
        urls = [u.strip() for u in args.urls.split(",") if u.strip()]
    elif args.urls_file:
        with open(args.urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.target:
        db_path = find_db(args.target)
        conn = connect(db_path)
        urls = get_target_urls(conn)
        conn.close()
    else:
        parser.print_help()
        sys.exit(1)

    if not urls:
        sys.exit("[error] 无可扫描的 URL")

    results = run_httpx(urls)

    auth_targets: list[dict] = []
    if args.target:
        db_path = find_db(args.target)
        conn = connect(db_path)
        for r in results:
            info = update_target(conn, r)
            if info["needs_auth"]:
                auth_targets.append(info)
        conn.close()
        print(f"[db] 已更新 targets 表，DB: {db_path.name}")

    print_summary(results)

    # ── auth 检测：设置 auth_pending，由 run_scan.py 展示 AUTH_BARRIER ──
    if auth_targets and args.target:
        db_path_str = str(find_db(args.target))
        conn2 = sqlite3.connect(db_path_str)
        conn2.execute("UPDATE scan_state SET phase='auth_pending' WHERE id=1")
        conn2.commit()
        conn2.close()
        login_url = auth_targets[0]["url"]
        print(f"\n[auth] 检测到认证壁垒: {login_url}，phase → auth_pending，等待操作员手动登录")
    # ─────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    main()
