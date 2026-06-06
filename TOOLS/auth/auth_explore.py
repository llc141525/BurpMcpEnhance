# TOOLS/auth/auth_explore.py
"""认证后深度导航 + 网络请求拦截，发现 API endpoint 写入 suspicious_points。

用法:
  python TOOLS/auth/auth_explore.py --target "台州学院"

输出:
  - suspicious_points 写入认证后发现的 API endpoint（source='auth_explore'）
  - pages 写入新发现的页面 URL
  - phase → spider
"""

import argparse
import asyncio
import json
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # auth/→TOOLS/→SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookies_dict  # noqa: E402

STATIC_TYPES = {"stylesheet", "image", "font", "media", "websocket", "manifest", "ping"}
STATIC_EXT_RE = re.compile(r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip)(\?.*)?$", re.I)

NAV_SELECTORS = [
    "nav a[href]",
    "aside a[href]",
    ".sidebar a[href]",
    "[role='menuitem']",
    "[role='tab']",
    ".menu-item a[href]",
    ".nav-item a[href]",
    "ul.nav a[href]",
    ".ant-menu-item a[href]",
    ".el-menu-item",
    ".layui-nav-item a[href]",
]


# ── Pure functions (testable without browser) ─────────────────────────────────


def _strip_www(host: str) -> str:
    """去掉 host 前缀的 www. (精确匹配，不用 lstrip 避免 B005)。"""
    return host[4:] if host.startswith("www.") else host


def filter_api_requests(requests: list[dict], base_domain: str) -> list[dict]:
    """过滤：只保留同域 XHR/fetch，排除静态资源。"""
    result = []
    base = _strip_www(base_domain.split(":")[0])
    for r in requests:
        if r.get("resource_type") not in ("xhr", "fetch", "document"):
            continue
        url = r.get("url", "")
        try:
            host = _strip_www(urlparse(url).netloc)
        except Exception:  # noqa: S112,BLE001 — urlparse may raise on malformed URLs
            continue
        if not (host == base or host.endswith("." + base)):
            continue
        if STATIC_EXT_RE.search(url.split("?")[0]):
            continue
        result.append(r)
    return result


def parse_request_params(url: str, post_data: str | None) -> list[str]:
    """从 URL query string 和 POST body 提取参数名列表。"""
    params: set[str] = set()
    parsed = urlparse(url)
    if parsed.query:
        params.update(parse_qs(parsed.query).keys())
    if post_data:
        try:
            body = json.loads(post_data)
            if isinstance(body, dict):
                params.update(body.keys())
        except (json.JSONDecodeError, ValueError):
            for part in post_data.split("&"):
                if "=" in part:
                    params.add(part.split("=")[0])
    return sorted(params)


def write_explore_results_to_db(
    conn: sqlite3.Connection,
    api_requests: list[dict],
    page_urls: list[str],
    sp_prefix: str = "SP-AE",
) -> dict:
    """写 suspicious_points + pages，返回 {'sp': N, 'pages': N}。"""
    rows = conn.execute(
        "SELECT id FROM suspicious_points WHERE id LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{sp_prefix}-%",),
    ).fetchone()
    try:
        next_num = int(rows[0].split("-")[-1]) + 1 if rows else 1
    except (ValueError, IndexError):
        next_num = 1

    sp_count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for req in api_requests:
        sp_id = f"{sp_prefix}-{next_num:03d}"
        next_num += 1
        params = req.get("params", [])
        context = req.get("nav_context", "")
        cur = conn.execute(
            """INSERT INTO suspicious_points
               (id, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
               VALUES (?, ?, ?, ?, 'auth_surface', ?, 'auth_explore', ?, 'Medium', 'untested', ?)
               ON CONFLICT(id) DO NOTHING""",
            (
                sp_id,
                req["url"],
                ", ".join(params) if params else "",
                req.get("method", "GET"),
                f"认证后页面 [{context}] 发出的请求，params={params}",
                f"认证用户操作触发的 API，存在 IDOR/越权/敏感数据暴露风险。来源: {context}",
                now,
            ),
        )
        sp_count += cur.rowcount

    page_count = 0
    for url in page_urls:
        cur = conn.execute(
            "INSERT INTO pages (url, depth, status) VALUES (?, 2, 'queued') ON CONFLICT(url) DO NOTHING",
            (url,),
        )
        page_count += cur.rowcount

    conn.commit()
    return {"sp": sp_count, "pages": page_count}


# ── Playwright browser navigation ─────────────────────────────────────────────


async def explore_authenticated(
    cdp_url: str,
    seed_url: str,
    cookies: dict[str, str],
    base_domain: str,
    nav_depth: int = 2,
) -> tuple[list[dict], list[str]]:
    """连接已有 Chrome，注入 cookies，BFS 点击导航项，拦截网络请求。"""
    from patchright.async_api import async_playwright

    all_api_requests: list[dict] = []
    all_page_urls: set[str] = set()
    current_nav_context = "首页"

    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(cdp_url)
        context = browser.contexts[0] if browser.contexts else await browser.new_context()

        if cookies:
            cookie_list = [{"name": k, "value": v, "domain": base_domain, "path": "/"} for k, v in cookies.items()]
            await context.add_cookies(cookie_list)

        page = await context.new_page()

        def on_request(request):
            if request.resource_type in ("xhr", "fetch"):
                params = parse_request_params(request.url, request.post_data)
                all_api_requests.append(
                    {
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "params": params,
                        "nav_context": current_nav_context,
                        "post_data": request.post_data,
                    }
                )

        page.on("request", on_request)

        try:
            await page.goto(seed_url, wait_until="networkidle", timeout=30000)
            all_page_urls.add(page.url)
        except Exception as e:
            print(f"[auth_explore] 首页导航失败: {e}", file=sys.stderr)
            return [], []

        nav_hrefs: list[tuple[str, str]] = []
        for selector in NAV_SELECTORS:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[:30]:
                    href = await el.get_attribute("href") or ""
                    label = (await el.inner_text()).strip()[:30]
                    if href and href not in ("#", "javascript:void(0)", "javascript:;"):
                        nav_hrefs.append((href, label or href))
            except Exception:  # noqa: S112,BLE001 — DOM query may fail for dynamic selectors
                continue

        print(f"[auth_explore] 发现 {len(nav_hrefs)} 个导航项", file=sys.stderr)

        visited_hrefs: set[str] = set()
        scheme = urlparse(seed_url).scheme

        for href, label in nav_hrefs[:40]:
            if href in visited_hrefs:
                continue
            visited_hrefs.add(href)
            current_nav_context = label  # captured by closure — intentional

            try:
                if href.startswith("http"):
                    nav_url = href
                elif href.startswith("/"):
                    nav_url = f"{scheme}://{base_domain}{href}"
                else:
                    continue

                await page.goto(nav_url, wait_until="networkidle", timeout=15000)
                all_page_urls.add(page.url)

                if nav_depth >= 2:
                    sub_hrefs: list[tuple[str, str]] = []
                    for sel in NAV_SELECTORS:
                        try:
                            els = await page.query_selector_all(sel)
                            for el in els[:20]:
                                sh = await el.get_attribute("href") or ""
                                sl = (await el.inner_text()).strip()[:30]
                                if sh and sh not in ("#", "javascript:void(0)") and sh not in visited_hrefs:
                                    sub_hrefs.append((sh, f"{label}>{sl}"))
                        except Exception:  # noqa: S112,BLE001 — sub-selector may fail
                            continue

                    for sub_href, sub_label in sub_hrefs[:15]:
                        visited_hrefs.add(sub_href)
                        current_nav_context = sub_label  # captured by closure — intentional
                        try:
                            if sub_href.startswith("http"):
                                sub_url = sub_href
                            elif sub_href.startswith("/"):
                                sub_url = f"{scheme}://{base_domain}{sub_href}"
                            else:
                                continue
                            await page.goto(sub_url, wait_until="networkidle", timeout=10000)
                            all_page_urls.add(page.url)
                        except Exception:  # noqa: S112,BLE001 — sub-nav may fail
                            continue

            except Exception as e:
                print(f"[auth_explore] 导航 {href} 失败: {e}", file=sys.stderr)
                continue

        await page.close()

    filtered = filter_api_requests(all_api_requests, base_domain)
    seen: set[tuple[str, str]] = set()
    deduped = []
    for r in filtered:
        key = (r["url"].split("?")[0], r["method"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped, list(all_page_urls)


# ── CLI ───────────────────────────────────────────────────────────────────────


def find_db(target: str) -> Path:
    dbs = sorted(DBS_DIR.glob(f"{target}*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dbs:
        sys.exit(f"[error] 找不到目标 DB: {target}")
    return dbs[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row

    row = conn.execute("SELECT seed_url, cdp_url FROM scan_state WHERE id=1").fetchone()
    seed_url = row["seed_url"] if row and row["seed_url"] else None
    cdp_url = row["cdp_url"] if row and row["cdp_url"] else "http://localhost:9222"

    if not seed_url:
        row2 = conn.execute("SELECT domain FROM targets LIMIT 1").fetchone()
        if row2:
            d = row2["domain"].strip()
            seed_url = d if d.startswith("http") else "https://" + d

    if not seed_url:
        sys.exit("[error] 无 seed_url，请先运行 init_scan.py")

    base_domain = urlparse(seed_url).netloc
    cookies = get_auth_cookies_dict(str(db_path), base_domain)

    print(f"[auth_explore] 目标: {args.target}  seed: {seed_url}  cookies: {len(cookies)} 条")

    api_requests, page_urls = asyncio.run(explore_authenticated(cdp_url, seed_url, cookies, base_domain))

    counts = write_explore_results_to_db(conn, api_requests, page_urls)
    conn.execute("UPDATE scan_state SET phase='spider' WHERE id=1")
    conn.commit()
    conn.close()

    print(f"[auth_explore] 完成: SP={counts['sp']}  pages={counts['pages']}  phase→spider")


if __name__ == "__main__":
    main()
