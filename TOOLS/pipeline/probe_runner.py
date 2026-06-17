"""主动探测：参数 fuzz (arjun) + 框架专项 (nuclei) + API 方法探测 + 结果写 DB。

用法:
  # 参数 fuzz (arjun)
  python3 TOOLS/probe_runner.py --target "目标名" --mode params --url "https://example.com/api"
  python3 TOOLS/probe_runner.py --target "目标名" --mode params --batch 20

  # nuclei 框架专项扫描
  python3 TOOLS/probe_runner.py --target "目标名" --mode nuclei --url "https://example.com"
  python3 TOOLS/probe_runner.py --target "目标名" --mode nuclei --tags "springboot,thinkphp"

  # HTTP 方法探测
  python3 TOOLS/probe_runner.py --target "目标名" --mode methods --url "https://example.com/api/v1"

输出:
  - 可疑发现写入 suspicious_points 表
  - 打印摘要

依赖:
  - arjun: python3.14 -m arjun
  - nuclei: nuclei (PATH)
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid as _uuid
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402

# nuclei tags 与框架指纹的映射
FRAMEWORK_TAGS = {
    "struts": "apache,struts",
    "struts2": "apache,struts",
    "thinkphp": "thinkphp",
    "spring": "springboot,spring",
    "springboot": "springboot",
    "aspnet": "asp,aspx",
    "viewstate": "asp,aspx",
    "openresty": "nginx",
    "jetty": "java",
    "shiro": "shiro",
    "fastjson": "fastjson",
    "log4j": "log4j",
}

HTTP_METHODS = ["OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"]


def load_active_plugins(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """从 plugins 表读取已激活插件，按类型分组，返回路径列表。"""
    rows = conn.execute("SELECT type, file_path FROM plugins WHERE active=1 AND file_path IS NOT NULL").fetchall()
    result: dict[str, list[str]] = {"nuclei_template": [], "python_script": []}
    for ptype, fpath in rows:
        if ptype in result and fpath:
            result[ptype].append(fpath)
    return result


def new_sp_id(prefix: str = "SP-PR") -> str:
    return f"{prefix}-{_uuid.uuid4().hex[:8]}"


def _write_sp_direct(
    conn: sqlite3.Connection,
    url: str,
    param: str,
    method: str,
    test_type: str,
    evidence: str,
    reasoning: str,
    risk: str = "Medium",
) -> str:
    sp_id = new_sp_id()
    conn.execute(
        """INSERT INTO suspicious_points
           (id, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'probe_runner', ?, ?, 'untested', ?)
           ON CONFLICT(id) DO NOTHING""",
        (sp_id, url, param, method, test_type, evidence, reasoning, risk, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    return sp_id


# Keep backward-compatible alias used by mode_params and mode_nuclei
write_sp = _write_sp_direct


def mode_methods(url: str, conn: sqlite3.Connection, proxy: str | None, cookie_header: str | None = None) -> int:
    """测试非标准 HTTP 方法。

    OPTIONS: 仅当 Allow/ACAO 头声明危险方法时写 SP。
    PUT/DELETE/PATCH/TRACE: 仅当响应 2xx 时写 SP。
    HEAD: 永不写 SP（200 是正常行为）。
    """
    import urllib.request

    added = 0

    for method in HTTP_METHODS:
        for attempt, retry_delay in enumerate((0, 1, 2)):
            if retry_delay:
                import time

                time.sleep(retry_delay)
            try:
                req = urllib.request.Request(url, method=method)
                req.add_header("User-Agent", "Mozilla/5.0")
                if cookie_header:
                    req.add_header("Cookie", cookie_header)

                if proxy:
                    import urllib.request as ur

                    handler = ur.ProxyHandler({"http": proxy, "https": proxy})
                    opener = ur.build_opener(handler)
                    resp = opener.open(req, timeout=10)
                else:
                    resp = urllib.request.urlopen(req, timeout=10)

                code = resp.getcode()
                headers = dict(resp.headers)
                body = resp.read()
                size = len(body)

                if method == "OPTIONS":
                    allow_raw = headers.get("Allow", "") + "," + headers.get("Access-Control-Allow-Methods", "")
                    exposed_dangerous = {m.strip().upper() for m in allow_raw.split(",")} & {
                        "PUT",
                        "DELETE",
                        "PATCH",
                        "TRACE",
                    }
                    if not exposed_dangerous:
                        break  # OPTIONS 200 without dangerous methods is normal
                    evidence = f"OPTIONS → HTTP {code}, Allow 暴露危险方法: {sorted(exposed_dangerous)}"
                    reasoning = f"OPTIONS 响应头声明支持 {sorted(exposed_dangerous)}，可能暴露未授权写操作面"
                elif method in ("PUT", "DELETE", "PATCH", "TRACE"):
                    if code not in (200, 201, 204):
                        break
                    evidence = f"{method} → HTTP {code}, body_len={size}"
                    reasoning = f"{method} 返回 {code}，可能暴露未授权操作面"
                else:
                    break

                sp_id = _write_sp_direct(conn, url, method, method, "method_tampering", evidence, reasoning)
                print(f"  [+] {method} {url} → {code} ({sp_id})")
                added += 1
                break

            except Exception as e:
                e_str = str(e)
                if any(x in e_str for x in ("403", "404", "405", "501")):
                    break  # 明确拒绝，不重试
                if attempt < 2:
                    continue
                print(f"  [-] {method} {url} → {e}")
                break

    return added


def mode_params(url: str, conn: sqlite3.Connection, proxy: str | None, cookie_header: str | None = None) -> int:
    """arjun 参数发现，写入发现的参数。"""
    python_exe = "python3.14"
    try:
        subprocess.run([python_exe, "-m", "arjun", "--help"], capture_output=True, check=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError):
        python_exe = sys.executable

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        out_file = f.name

    cmd = [python_exe, "-m", "arjun", "-u", url, "-oJ", out_file, "-q"]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]

    env = os.environ.copy()
    if proxy:
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy

    print(f"[arjun] {url}")
    try:
        subprocess.run(cmd, check=False, timeout=120, capture_output=True, env=env)
    except subprocess.TimeoutExpired:
        print("[warn] arjun 超时")

    added = 0
    if os.path.exists(out_file):
        try:
            with open(out_file) as f:
                data = json.load(f)
            params = data.get("params", []) if isinstance(data, dict) else data
            if params:
                sp_id = write_sp(
                    conn,
                    url,
                    ", ".join(params),
                    "GET",
                    "parameter_fuzz",
                    f"arjun 发现参数: {params}",
                    "端点存在隐藏参数，可能影响访问控制或业务逻辑",
                )
                print(f"  [+] 发现参数 {params} ({sp_id})")
                added += 1
        except Exception as e:
            print(f"  [warn] 解析 arjun 输出失败: {e}")
        os.unlink(out_file)

    return added


def mode_nuclei(url: str, conn: sqlite3.Connection, tags: str | None, cookie_header: str | None = None) -> int:
    """nuclei 扫描，发现写 SP。"""
    if not shutil.which("nuclei"):
        sys.exit("[error] nuclei 未安装")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        out_file = f.name

    # 如果没有指定 tags，用通用模板
    tag_arg = tags or "exposure,misconfiguration,default-login,tech"
    cmd = [
        "nuclei",
        "-u",
        url,
        "-tags",
        tag_arg,
        "-severity",
        "medium,high,critical",
        "-json-export",
        out_file,
        "-silent",
        "-timeout",
        "10",
        "-c",
        "5",
    ]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    try:
        active_plugins = load_active_plugins(conn)
        for tpl_path in active_plugins.get("nuclei_template", []):
            full = PROJECT_ROOT / tpl_path
            if full.exists():
                cmd += ["-t", str(full)]
    except Exception as e:
        print(f"  [warn] 加载插件模板失败: {e}")
    print(f"[nuclei] {url} (tags={tag_arg})")
    try:
        subprocess.run(cmd, check=False, timeout=180)
    except subprocess.TimeoutExpired:
        print("[warn] nuclei 超时")

    added = 0
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
        os.unlink(out_file)
        if content:
            try:
                data = json.loads(content)
                # v3.4+ outputs a JSON array; older versions output JSONL
                findings = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                # fallback: try JSONL line by line
                findings = []
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                try:
                    matched_url = finding.get("matched-at", url)
                    template_id = finding.get("template-id", "unknown")
                    severity = finding.get("info", {}).get("severity", "medium").title()
                    name = finding.get("info", {}).get("name", template_id)
                    evidence = finding.get("extracted-results", [])
                    evidence_str = f"nuclei/{template_id}: {name}" + (f" — {evidence[:3]}" if evidence else "")
                    risk_map = {"Critical": "Critical", "High": "High", "Medium": "Medium"}
                    risk = risk_map.get(severity, "Medium")
                    sp_id = write_sp(
                        conn,
                        matched_url,
                        "",
                        "GET",
                        "framework_probe",
                        evidence_str,
                        f"nuclei 模板 {template_id} 命中",
                        risk,
                    )
                    print(f"  [+] {severity} {template_id} @ {matched_url} ({sp_id})")
                    added += 1
                except Exception as e:
                    print(f"  [warn] 处理 finding 失败: {e}")

    return added


def batch_params(conn: sqlite3.Connection, limit: int, proxy: str | None, cookie_header: str | None = None) -> int:
    rows = conn.execute(
        """SELECT url FROM pages
           WHERE status='visited'
           AND url LIKE '%?%'
           AND url NOT IN (
               SELECT DISTINCT url FROM suspicious_points WHERE source='probe_runner'
           )
           ORDER BY id LIMIT ?""",
        (limit,),
    ).fetchall()
    added = 0
    for row in rows:
        added += mode_params(row["url"], conn, proxy, cookie_header)
    return added


def main() -> None:
    parser = argparse.ArgumentParser(description="主动探测: params | nuclei | methods")
    parser.add_argument("--target", required=True, help="目标名")
    parser.add_argument("--mode", required=True, choices=["params", "nuclei", "methods"], help="探测模式")
    parser.add_argument("--url", help="目标 URL（单个）")
    parser.add_argument("--batch", type=int, default=0, help="批量处理 N 个 URL（params 模式）")
    parser.add_argument("--tags", help="nuclei tags，逗号分隔")
    parser.add_argument("--proxy", default=None, help="HTTP 代理（默认不使用，例: http://127.0.0.1:8080）")
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)
    total_added = 0

    # 获取认证 Cookie
    seed_row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_domain = seed_row[0] if seed_row and seed_row[0] else ""
    cookie_header = get_auth_cookie_header(str(db_path), seed_domain, role="primary")
    if cookie_header:
        print(f"[probe_runner] 带认证 Cookie ({len(cookie_header.split(';'))} 条)")

    if args.mode == "params":
        if args.batch:
            total_added = batch_params(conn, args.batch, args.proxy, cookie_header)
        elif args.url:
            total_added = mode_params(args.url, conn, args.proxy, cookie_header)
        else:
            sys.exit("[error] params 模式需要 --url 或 --batch")

    elif args.mode == "nuclei":
        url = args.url
        if not url:
            rows = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
            if not rows:
                sys.exit("[error] nuclei 模式需要 --url 或 DB 中有 seed_url")
            url = rows["seed_url"]
        tags = args.tags
        if not tags:
            rows = conn.execute(
                """SELECT evidence FROM suspicious_points
                   WHERE test_type='framework_fingerprint' LIMIT 5"""
            ).fetchall()
            if rows:
                detected = " ".join(r["evidence"] or "" for r in rows).lower()
                tag_parts: list[str] = []
                for fw, tag in FRAMEWORK_TAGS.items():
                    if fw in detected:
                        tag_parts.append(tag)
                tags = ",".join(set(tag_parts)) if tag_parts else None
        total_added = mode_nuclei(url, conn, tags, cookie_header)

    elif args.mode == "methods":
        if not args.url:
            sys.exit("[error] methods 模式需要 --url")
        total_added = mode_methods(args.url, conn, args.proxy, cookie_header)

    try:
        active_scripts = load_active_plugins(conn).get("python_script", [])
        for script_path in active_scripts:
            full_path = PROJECT_ROOT / script_path
            if full_path.exists():
                subprocess.run(  # noqa: S603
                    [sys.executable, str(full_path), "--target", args.target, "--db", str(db_path)],
                    timeout=120,
                    check=False,
                )
    except Exception as e:
        print(f"[warn] 执行插件脚本失败: {e}")

    conn.close()
    print(f"\n=== probe_runner ({args.mode}) ===")
    print(f"新增 suspicious_points: {total_added} 条")
    print(f"DB: {db_path.name}")


if __name__ == "__main__":
    main()
