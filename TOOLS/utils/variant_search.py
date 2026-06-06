"""变种分析工具 — 从已确认漏洞提取签名，搜索同目标内的同类端点/参数，写入 suspicous_points。

用法:
  python3 TOOLS/variant_search.py --target "台州学院" --finding F-001
  python3 TOOLS/variant_search.py --target "台州学院" --sp SP-001
  python3 TOOLS/variant_search.py --target "台州学院" --param userId --type idor --url "https://t.com/api/user/info"
"""

import argparse
import json
import re
import sqlite3
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DBS_DIR = PROJECT_ROOT / "dbs"

# 漏洞类型 → 搜索策略
TYPE_STRATEGIES: dict[str, dict] = {
    "idor": {
        "url_prefix": True,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["id", "uid", "userId", "user_id", "uid", "account_id", "order_id", "group_id", "role_id"],
    },
    "unauth_access": {
        "url_prefix": True,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["token", "auth", "session", "access_token", "jwt"],
    },
    "sqli": {
        "url_prefix": False,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["id", "q", "keyword", "search", "query", "type", "cat", "category", "sort", "order", "page"],
    },
    "xss": {
        "url_prefix": False,
        "param_match": True,
        "js_api_search": False,
        "related_params": [
            "q",
            "search",
            "keyword",
            "name",
            "title",
            "content",
            "msg",
            "message",
            "redirect",
            "url",
            "return",
        ],
    },
    "command_injection": {
        "url_prefix": False,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["cmd", "command", "exec", "ping", "host", "ip", "domain", "url", "path", "file"],
    },
    "path_traversal": {
        "url_prefix": False,
        "param_match": True,
        "js_api_search": False,
        "related_params": [
            "file",
            "filename",
            "path",
            "dir",
            "folder",
            "template",
            "page",
            "include",
            "src",
            "download",
        ],
    },
    "ssti": {
        "url_prefix": False,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["name", "template", "page", "content", "msg", "message", "subject", "body", "title"],
    },
    "ssrf": {
        "url_prefix": False,
        "param_match": True,
        "js_api_search": False,
        "related_params": [
            "url",
            "redirect",
            "callback",
            "webhook",
            "endpoint",
            "target",
            "uri",
            "link",
            "host",
            "domain",
            "path",
        ],
    },
    "info_leak": {
        "url_prefix": True,
        "param_match": False,
        "js_api_search": True,
        "related_params": [],
    },
    "hardcoded_secret": {
        "url_prefix": False,
        "param_match": False,
        "js_api_search": True,
        "related_params": ["key", "secret", "token", "password", "apikey", "accessKey", "secretKey", "appSecret"],
    },
    "js_debug": {
        "url_prefix": False,
        "param_match": False,
        "js_api_search": True,
        "related_params": ["debug", "test", "verbose", "swagger", "docs", "openapi", "graphql"],
    },
    "file_upload": {
        "url_prefix": True,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["file", "upload", "image", "img", "attachment", "avatar", "photo"],
    },
    "csrf": {
        "url_prefix": True,
        "param_match": True,
        "js_api_search": False,
        "related_params": ["token", "csrf", "_token", "xsrf", "authenticity_token"],
    },
}


def find_target_db(target_name: str) -> str | None:
    matches = sorted(
        DBS_DIR.glob(f"{target_name}_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return str(matches[0]) if matches else None


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def _is_id_like(segment: str) -> bool:
    """判断路径段是否像 ID / 资源标识符 / 具体端点。"""
    if re.match(r"^\d+$", segment):
        return True
    if re.match(r"^[0-9a-f]{8,}$", segment):
        return True
    # 驼峰端点名: uploadToOss, getUserInfo, addSignInTask
    if re.match(r"^[a-z]+[A-Z]", segment):
        return True
    # 含扩展名: index.html, config.php, user.do
    if re.match(r".+\.\w{2,5}$", segment):
        return True
    return False


def extract_url_prefix(url: str) -> str:
    """从 URL 提取路径前缀，用于搜索同类端点。
    /api/user/info?id=5             → /api/user/
    /admin/user/123                 → /admin/user/
    /api/base/oss/uploadToOss       → /api/base/oss/
    """
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return "/"
    parts = path.split("/")
    while parts and _is_id_like(parts[-1]):
        parts.pop()
    prefix = "/" + "/".join(parts) + "/" if parts else "/"
    return prefix


def search_pages(conn: sqlite3.Connection, url_prefix: str, params: list[str]) -> list[dict]:
    """搜索 pages 表中匹配 URL 前缀或包含目标参数的页面。"""
    results = []

    # URL 前缀匹配
    if url_prefix and url_prefix != "/":
        rows = conn.execute(
            "SELECT url, title, forms_json, suspicious_params_json FROM pages WHERE url LIKE ?",
            (f"%{url_prefix}%",),
        ).fetchall()
        for row in rows:
            results.append(
                {
                    "url": row["url"],
                    "title": row["title"],
                    "match_type": "url_prefix",
                    "match_detail": f"URL 匹配前缀 {url_prefix}",
                }
            )

    # 参数名匹配（搜索 pages 的 URL 查询参数）
    if params:
        all_urls = conn.execute("SELECT url, title FROM pages").fetchall()
        seen = {r["url"] for r in results}
        for row in all_urls:
            if row["url"] in seen:
                continue
            parsed = urlparse(row["url"])
            qs_params = set(re.findall(r"[?&]([^=&#]+)=", parsed.query))
            match_params = qs_params & set(params)
            if match_params:
                results.append(
                    {
                        "url": row["url"],
                        "title": row["title"],
                        "match_type": "param_match",
                        "match_detail": f"参数匹配: {', '.join(sorted(match_params))}",
                    }
                )

    return results


def search_js(
    conn: sqlite3.Connection,
    url_prefix: str,
    params: list[str],
    search_apis: bool,
) -> list[dict]:
    """搜索 js_files 表中相关条目。"""
    results = []

    if search_apis:
        rows = conn.execute(
            "SELECT url, page_url, discovered_apis_json FROM js_files WHERE discovered_apis_json IS NOT NULL"
        ).fetchall()
        for row in rows:
            try:
                apis = json.loads(row["discovered_apis_json"])
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(apis, list):
                continue
            matched = []
            for api in apis:
                api_str = str(api)
                if url_prefix and url_prefix != "/" and url_prefix in api_str:
                    matched.append(api_str)
                elif any(p in api_str for p in params):
                    matched.append(api_str)
            if matched:
                results.append(
                    {
                        "js_url": row["url"],
                        "page_url": row["page_url"],
                        "match_type": "js_api",
                        "match_detail": f"匹配 API: {matched[:5]}",
                    }
                )

    # 参数名在 JS URL 中出现
    if params:
        js_rows = conn.execute("SELECT url, page_url FROM js_files").fetchall()
        seen_js = {r["js_url"] for r in results}
        for row in js_rows:
            if row["url"] in seen_js:
                continue
            js_lower = row["url"].lower()
            if any(p.lower() in js_lower for p in params):
                results.append(
                    {
                        "js_url": row["url"],
                        "page_url": row["page_url"],
                        "match_type": "js_url_param",
                        "match_detail": "JS URL 含目标参数",
                    }
                )

    return results


def insert_suspicious_points(
    conn: sqlite3.Connection,
    page_results: list[dict],
    js_results: list[dict],
    param: str,
    vuln_type: str,
    source_finding_id: str,
) -> int:
    """写入 suspicous_points，去重。返回新增数量。"""
    now_ts = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 查已存在的 SP，避免重复入队
    existing = set(
        row[0]
        for row in conn.execute("SELECT url FROM suspicious_points WHERE source LIKE 'variant_search%'").fetchall()
    )

    count = 0
    for pr in page_results:
        url = pr["url"]
        if url in existing:
            continue
        sp_id = f"VAR-{uuid.uuid4().hex[:10]}"
        try:
            conn.execute(
                """INSERT INTO suspicious_points
                   (id, page_url, url, param, test_type, evidence, source, risk, created_at, reasoning)
                   VALUES (?, ?, ?, ?, ?, ?, 'variant_search', 'Medium', ?, ?)""",
                (
                    sp_id,
                    url,
                    url,
                    param,
                    vuln_type,
                    pr.get("match_detail", ""),
                    now_ts,
                    f"变种搜索 #{source_finding_id}: {pr.get('match_detail', '')}",
                ),
            )
            count += 1
            existing.add(url)
        except sqlite3.IntegrityError:
            pass

    for jr in js_results:
        js_url = jr.get("js_url", "")
        if js_url in existing:
            continue
        sp_id = f"VAR-{uuid.uuid4().hex[:10]}"
        try:
            conn.execute(
                """INSERT INTO suspicious_points
                   (id, page_url, url, param, test_type, evidence, source, risk, created_at, reasoning)
                   VALUES (?, ?, ?, ?, ?, ?, 'variant_search', 'Low', ?, ?)""",
                (
                    sp_id,
                    jr.get("page_url", js_url),
                    js_url,
                    param or "js_pattern",
                    f"{vuln_type}_js",
                    jr.get("match_detail", ""),
                    now_ts,
                    f"变种搜索 #{source_finding_id}: JS 文件 {jr.get('match_detail', '')}",
                ),
            )
            count += 1
            existing.add(js_url)
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    return count


def load_finding(conn: sqlite3.Connection, finding_id: str) -> dict | None:
    row = conn.execute("SELECT id, type, url, param FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return dict(row) if row else None


def load_sp(conn: sqlite3.Connection, sp_id: str) -> dict | None:
    row = conn.execute(
        "SELECT id, test_type as type, url, param FROM suspicious_points WHERE id = ?", (sp_id,)
    ).fetchone()
    return dict(row) if row else None


def do_search(
    db_path: str,
    vuln_type: str,
    param: str,
    url: str,
    source_id: str,
) -> dict:
    conn = connect(db_path)
    try:
        strategy = TYPE_STRATEGIES.get(vuln_type, {})
        if not strategy:
            # fallback: param match + url prefix
            strategy = {"url_prefix": True, "param_match": True, "js_api_search": False, "related_params": [param]}

        url_prefix = extract_url_prefix(url) if strategy.get("url_prefix") else ""
        params = strategy.get("related_params", [])
        if param and param not in params:
            params.insert(0, param)

        page_results = (
            search_pages(conn, url_prefix, params) if strategy.get("url_prefix") or strategy.get("param_match") else []
        )
        js_results = search_js(conn, url_prefix, params, strategy.get("js_api_search", False))
        inserted = insert_suspicious_points(conn, page_results, js_results, param, vuln_type, source_id)

        return {
            "source_id": source_id,
            "vuln_type": vuln_type,
            "param": param,
            "url_prefix": url_prefix,
            "strategy": {k: v for k, v in strategy.items() if k != "related_params"},
            "pages_matched": len(page_results),
            "js_matched": len(js_results),
            "sp_inserted": inserted,
        }
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="变种搜索 — 从漏洞签名搜索同类端点")
    parser.add_argument("--target", required=True, help="目标名")
    parser.add_argument("--finding", help="finding ID (F-xxx)")
    parser.add_argument("--sp", help="suspicious_point ID (SP-xxx)")
    parser.add_argument("--param", help="直接指定参数名（需同时指定 --type 和 --url）")
    parser.add_argument("--type", help="漏洞类型")
    parser.add_argument("--url", help="漏洞 URL")
    parser.add_argument("--dry-run", action="store_true", help="仅搜索不入队")
    args = parser.parse_args()

    db_path = find_target_db(args.target)
    if db_path is None:
        print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False))
        sys.exit(1)

    conn = connect(db_path)

    # 数据源：--finding 优先，其次 --sp，最后直接参数
    if args.finding:
        record = load_finding(conn, args.finding)
        if record is None:
            conn.close()
            print(json.dumps({"error": f"未找到 finding: {args.finding}"}, ensure_ascii=False))
            sys.exit(1)
        vuln_type = record["type"]
        param = record["param"] or ""
        url = record["url"] or ""
        source_id = args.finding
    elif args.sp:
        record = load_sp(conn, args.sp)
        if record is None:
            conn.close()
            print(json.dumps({"error": f"未找到 SP: {args.sp}"}, ensure_ascii=False))
            sys.exit(1)
        vuln_type = record["type"]
        param = record["param"] or ""
        url = record["url"] or ""
        source_id = args.sp
    elif args.param and args.type and args.url:
        vuln_type = args.type
        param = args.param
        url = args.url
        source_id = "DIRECT"
    else:
        conn.close()
        parser.print_help()
        sys.exit(1)

    conn.close()

    if args.dry_run:
        url_prefix = extract_url_prefix(url) if TYPE_STRATEGIES.get(vuln_type, {}).get("url_prefix") else ""
        params = TYPE_STRATEGIES.get(vuln_type, {}).get("related_params", [])
        if param and param not in params:
            params.insert(0, param)
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "vuln_type": vuln_type,
                    "param": param,
                    "url_prefix": url_prefix,
                    "params_search": params,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    result = do_search(db_path, vuln_type, param, url, source_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
