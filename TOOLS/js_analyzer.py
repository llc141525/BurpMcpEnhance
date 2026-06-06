"""JS 批量分析：从 js_files 表取未分析 JS → mmx 提取 → 写 suspicious_points。

用法:
  python TOOLS/js_analyzer.py --target "台州学院" --batch 5
  python TOOLS/js_analyzer.py --target "台州学院" --url "https://example.com/main.js"

依赖: mmx CLI (mmx text chat), requests
"""

import argparse
import json
import re
import sqlite3
import subprocess
import sys
import uuid as _uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # TOOLS/ → SRC/
TMP_DIR = PROJECT_ROOT / "tmp"

_TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_TOOLS_DIR))
from db.db_utils import connect, find_db  # noqa: E402

CDN_HOSTS = {
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "jsdelivr.net",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "static.cloudflareinsights.com",
    "staticfiles.com",
}

LOW_PRIORITY_RE = re.compile(
    r"(vendor|jquery|bootstrap|chunk-vendor|lodash|react\.min|vue\.min"
    r"|angular\.min|moment|popper|d3\.min|echarts\.min|three\.min)",
    re.IGNORECASE,
)

# Webpack/vite generic chunk pattern — medium priority (not high, not skip)
CHUNK_RE = re.compile(r"\w+\.[a-f0-9]{6,}\.(js|mjs)$", re.IGNORECASE)

HIGH_PRIORITY_RE = re.compile(
    r"(config|api|auth|router|service|main|app|user|order|login|token|secret|key)",
    re.IGNORECASE,
)

MMX_PROMPT = """\
分析以下 JavaScript 代码，以 JSON 格式返回安全相关信息（只返回 JSON，无其他内容）：
{{
  "api_endpoints": [{{"path": "...", "method": "GET或POST", "params": ["param1"]}}],
  "hardcoded_secrets": [{{"type": "apikey/token/password/key", "name": "变量名", "value": "值"}}],
  "internal_routes": ["路由路径"],
  "auth_patterns": ["认证头/Cookie名称描述"]
}}

JavaScript 内容：
{content}
"""


def score_js_url(url: str) -> int:
    """Return 0 (skip), 1 (medium), 2 (high priority)."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        filename = Path(parsed.path).name.lower()
    except Exception:
        return 0
    if host in CDN_HOSTS:
        return 0
    if LOW_PRIORITY_RE.search(filename):
        return 0
    # Webpack/vite generic content-hashed chunks — medium priority
    if CHUNK_RE.search(filename):
        return 1
    if HIGH_PRIORITY_RE.search(filename):
        return 2
    return 1


def fetch_js_content(url: str, timeout: int = 15) -> str | None:
    try:
        import requests  # noqa: PLC0415

        resp = requests.get(url, timeout=timeout, verify=False)  # noqa: S501
        if resp.status_code == 200:
            return resp.text
    except Exception as exc:
        print(f"  [warn] fetch 失败 {url}: {exc}", file=sys.stderr)
    return None


def call_mmx(js_content: str, js_url: str = "") -> str:
    MAX_CHARS = 30000
    truncated = len(js_content) > MAX_CHARS
    if truncated:
        print(
            f"  [warn] JS 截断到 {MAX_CHARS}/{len(js_content)} chars — 分析结果可能不完整: {js_url}",
            file=sys.stderr,
        )
    content = js_content[:MAX_CHARS]
    if truncated:
        content += "\n// [TRUNCATED]"
    prompt = MMX_PROMPT.format(content=content)
    try:
        result = subprocess.run(  # noqa: S603
            ["mmx", "text", "chat"],  # noqa: S607
            input=prompt,
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print("[warn] mmx 未安装或不在 PATH", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print("[warn] mmx 超时（60s）", file=sys.stderr)
        return ""


def parse_mmx_output(raw: str) -> dict | None:
    """Extract JSON dict from mmx response. Returns None on failure."""
    # Strip markdown code fences
    match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    if match:
        raw = match.group(1)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    # Try first {...} block
    brace = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace:
        try:
            data = json.loads(brace.group(0))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return None


def new_sp_id(prefix: str = "SP-JA") -> str:
    return f"{prefix}-{_uuid.uuid4().hex[:8]}"


def write_findings_to_db(conn: sqlite3.Connection, js_url: str, findings: dict, id_prefix: str = "SP-JA") -> int:
    """Write extracted findings to suspicious_points. Returns count inserted."""
    count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ep in findings.get("api_endpoints", []):
        sp_id = new_sp_id(id_prefix)
        conn.execute(
            "INSERT OR IGNORE INTO suspicious_points "
            "(id, url, param, method, test_type, evidence, source, risk, test_status, created_at) "
            "VALUES (?, ?, ?, ?, 'js_endpoint', ?, 'js_analysis', 'Medium', 'untested', ?)",
            (
                sp_id,
                ep.get("path", ""),
                ",".join(ep.get("params", [])),
                ep.get("method", "GET"),
                f"发现于 JS: {js_url}",
                now,
            ),
        )
        count += conn.execute("SELECT changes()").fetchone()[0]

    for secret in findings.get("hardcoded_secrets", []):
        sp_id = new_sp_id(id_prefix)
        evidence = f"{secret.get('name', '?')}={secret.get('value', '?')} (type={secret.get('type', '?')}) in {js_url}"
        conn.execute(
            "INSERT OR IGNORE INTO suspicious_points "
            "(id, url, test_type, evidence, source, risk, test_status, created_at) "
            "VALUES (?, ?, 'hardcoded_secret', ?, 'js_analysis', 'High', 'untested', ?)",
            (sp_id, js_url, evidence, now),
        )
        count += conn.execute("SELECT changes()").fetchone()[0]

    for route in findings.get("internal_routes", []):
        sp_id = new_sp_id(id_prefix)
        conn.execute(
            "INSERT OR IGNORE INTO suspicious_points "
            "(id, url, test_type, evidence, source, risk, test_status, created_at) "
            "VALUES (?, ?, 'internal_route', ?, 'js_analysis', 'Low', 'untested', ?)",
            (sp_id, route, f"内部路由发现于 JS: {js_url}", now),
        )
        count += conn.execute("SELECT changes()").fetchone()[0]

    conn.commit()

    conn.execute(
        "UPDATE js_files SET analyzed=1, discovered_apis_json=?, hardcoded_secrets_json=?, analyzed_at=? WHERE url=?",
        (
            json.dumps(findings.get("api_endpoints", []), ensure_ascii=False),
            json.dumps(findings.get("hardcoded_secrets", []), ensure_ascii=False),
            now,
            js_url,
        ),
    )
    conn.commit()
    return count


def analyze_batch(target: str, batch: int = 5) -> dict:
    db_path = find_db(target)
    conn = connect(db_path)

    rows = conn.execute("SELECT url FROM js_files WHERE analyzed=0 ORDER BY id DESC").fetchall()
    candidates = [r[0] for r in rows]

    scored = [(score_js_url(u), u) for u in candidates]
    scored = [(s, u) for s, u in scored if s > 0]
    scored.sort(key=lambda x: -x[0])
    to_process = [u for _, u in scored[:batch]]
    skipped = len(candidates) - len(to_process)

    results: dict = {"analyzed": 0, "skipped_low_priority": skipped, "total_sp_written": 0, "details": []}

    for js_url in to_process:
        print(f"  [js] 分析: {js_url}")
        content = fetch_js_content(js_url)
        if not content:
            conn.execute("UPDATE js_files SET analyzed=1 WHERE url=?", (js_url,))
            conn.commit()
            results["details"].append(f"✗ {Path(js_url).name}  → fetch 失败")
            continue

        raw = call_mmx(content, js_url)
        if not raw:
            TMP_DIR.mkdir(exist_ok=True)
            (TMP_DIR / f"js_mmx_fail_{abs(hash(js_url)) % 9999}.txt").write_text(
                js_url + "\n" + content[:2000], encoding="utf-8"
            )
            conn.execute("UPDATE js_files SET analyzed=1 WHERE url=?", (js_url,))
            conn.commit()
            results["details"].append(f"✗ {Path(js_url).name}  → mmx 无响应")
            continue

        findings = parse_mmx_output(raw)
        if not findings:
            conn.execute("UPDATE js_files SET analyzed=1 WHERE url=?", (js_url,))
            conn.commit()
            results["details"].append(f"✗ {Path(js_url).name}  → mmx 返回非 JSON")
            continue

        sp_count = write_findings_to_db(conn, js_url, findings)
        results["analyzed"] += 1
        results["total_sp_written"] += sp_count

        ep_count = len(findings.get("api_endpoints", []))
        sec_count = len(findings.get("hardcoded_secrets", []))
        detail = f"✓ {Path(js_url).name}  → {ep_count} 端点, {sec_count} 密钥"
        print(f"    {detail}")
        results["details"].append(detail)

    conn.close()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="JS 批量分析器")
    parser.add_argument("--target", help="目标名")
    parser.add_argument("--url", help="单个 JS URL")
    parser.add_argument("--batch", type=int, default=5, help="批次大小（默认 5）")
    args = parser.parse_args()

    if args.url and args.target:
        db_path = find_db(args.target)
        conn = connect(db_path)
        content = fetch_js_content(args.url)
        if content:
            raw = call_mmx(content, args.url)
            findings = parse_mmx_output(raw) or {}
            count = write_findings_to_db(conn, args.url, findings)
            print(f"[js_analyzer] 写入 {count} 条 SP")
        conn.close()
    elif args.target:
        results = analyze_batch(args.target, args.batch)
        analyzed = results["analyzed"]
        skipped = results["skipped_low_priority"]
        sp_written = results["total_sp_written"]
        print(f"[js_analyzer] 分析: {analyzed}  跳过: {skipped}  新增SP: {sp_written}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
