#!/usr/bin/env python3
"""
轻量可控目录爆破脚本
替代 dirsearch（CLI 因缺少 setuptools/pkg_resources 无法使用）。
走 Clash 代理，自动 IP 轮换，可控每轮条数，输出 JSON lines。

用法:
  python3 TOOLS/brutescan.py -u https://target.com -n 200 -o results.json
  python3 TOOLS/brutescan.py -u https://target.com -w custom.txt -e php,asp -n 100
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print('{"error": "requests 模块未安装，请执行: pip install requests"}')
    sys.exit(1)

# ── 常量 ────────────────────────────────────────────────────────────────
CLASH_PROXY = "http://127.0.0.1:9870"

DEFAULT_EXTENSIONS = ["php", "asp", "aspx", "jsp", "do", "action", "html", "htm"]

# 内置精简字典（高价值 200 条，当 dirsearch 字典不可用时 fallback）
FALLBACK_WORDLIST = [
    ".git/HEAD",
    ".env",
    ".htaccess",
    "admin",
    "api",
    "api/",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/swagger",
    "api-docs",
    "backup",
    "bak",
    "config",
    "console",
    "crossdomain.xml",
    "css",
    "data",
    "db",
    "debug",
    "download",
    "error",
    "export",
    "favicon.ico",
    "file",
    "graphql",
    "gql",
    "health",
    "image",
    "img",
    "index",
    "info",
    "install",
    "js",
    "json",
    "login",
    "log",
    "manage",
    "manager",
    "media",
    "oauth",
    "old",
    "openapi.json",
    "phpinfo.php",
    "ping",
    "proxy",
    "public",
    "README.md",
    "redirect",
    "report",
    "reset",
    "rest",
    "rest/api",
    "robot.txt",
    "robots.txt",
    "saml",
    "search",
    "secret",
    "service",
    "session",
    "setting",
    "settings",
    "setup",
    "signin",
    "signup",
    "soap",
    "sql",
    "sso",
    "static",
    "status",
    "swagger",
    "swagger.json",
    "swagger-ui",
    "test",
    "tmp",
    "token",
    "trace",
    "upload",
    "uploads",
    "user",
    "users",
    "v1",
    "v2",
    "v3",
    "vendor",
    "version",
    "webapi",
    "webconsole",
    "webservice",
    "ws",
    "wsdl",
    "www",
    "xml",
    "actuator",
    "actuator/health",
    "actuator/info",
    "actuator/env",
    "actuator/metrics",
    "actuator/beans",
    "actuator/mappings",
    ".well-known/",
    ".well-known/security.txt",
]


def find_default_wordlist():
    """寻找 dirsearch 内置字典"""
    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Python\pythoncore-3.11-64\Lib\site-packages\dirsearch\db\dicc.txt"),
        os.path.expandvars(r"%APPDATA%\Python\Python311\site-packages\dirsearch\db\dicc.txt"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def load_wordlist(path, limit=0):
    """加载字典，返回路径列表"""
    paths = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 跳过含变量替换的条目（%EXT% 后续展开）
            if "%EXT%" in line:
                continue
            paths.append(line)
    if limit > 0:
        paths = paths[:limit]
    return paths


def expand_extensions(path, extensions):
    """展开 %EXT% 占位符"""
    if "%EXT%" not in path:
        return [path]
    results = []
    for ext in extensions:
        results.append(path.replace("%EXT%", ext))
    return results


def _try_import_rotate():
    try:
        from waf_rotate import is_waf_blocked, rotate_ip  # noqa: F811

        return is_waf_blocked, rotate_ip
    except ImportError:
        return None, None


_is_waf_blocked, _rotate_ip = _try_import_rotate()


def switch_clash_proxy():
    """通过 Clash API 切换代理节点。使用 waf_rotate 或 fallback。"""
    if _rotate_ip:
        new_ip = _rotate_ip()
        return f"切到 {new_ip}" if new_ip else ""
    return ""


def should_record(status_code, content_length, seen_lengths):
    """判断是否值得记录此响应"""
    if status_code in (200, 301, 302, 307, 308, 401, 403, 500):
        # content-length 去重：相同 status + 相同 length 只记一次
        key = (status_code, content_length)
        if key in seen_lengths:
            return False
        seen_lengths.add(key)
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description="轻量目录爆破")
    parser.add_argument("-u", "--url", required=True, help="目标 URL（如 https://target.com）")
    parser.add_argument("-w", "--wordlist", help="字典路径（默认 dirsearch dicc.txt）")
    parser.add_argument("-n", "--limit", type=int, default=200, help="每轮最大路径数 (默认 200)")
    parser.add_argument("-e", "--extensions", help="扩展名（逗号分隔，如 php,asp）")
    parser.add_argument("-o", "--output", default="brute_results.json", help="输出文件")
    parser.add_argument("--proxy", default=CLASH_PROXY, help="代理地址")
    parser.add_argument("--ip-every", type=int, default=50, help="每 N 请求切一次 IP (默认 50)")
    parser.add_argument("--delay", type=float, default=0.5, help="请求间隔秒数 (默认 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认 10)")
    args = parser.parse_args()

    # ── 字典加载 ──
    wordlist_path = args.wordlist or find_default_wordlist()
    if wordlist_path and os.path.exists(wordlist_path):
        print(json.dumps({"msg": f"使用字典: {wordlist_path}"}))
        raw_paths = load_wordlist(wordlist_path, args.limit)
    else:
        print(json.dumps({"msg": "dirsearch 字典未找到，使用内置 fallback 字典"}))
        raw_paths = FALLBACK_WORDLIST[: args.limit]

    extensions = args.extensions.split(",") if args.extensions else DEFAULT_EXTENSIONS

    # 展开 %EXT%
    all_paths = []
    for p in raw_paths:
        all_paths.extend(expand_extensions(p, extensions))
    # 去重保持顺序
    seen = set()
    unique_paths = []
    for p in all_paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)

    total = len(unique_paths)
    print(json.dumps({"msg": f"加载 {total} 条路径（去重后）"}))

    # ── 请求准备 ──
    target_url = args.url.rstrip("/")
    session = requests.Session()
    session.proxies = {"http": args.proxy, "https": args.proxy}
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
    )
    session.verify = False  # SRC 测试中忽略证书错误
    # 禁用 SSL 警告
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── 扫描 ──
    results = []
    seen_lengths = set()
    req_count = 0
    found_count = 0
    start_time = time.time()

    # 开始时切一次 IP
    ip_msg = switch_clash_proxy()
    print(json.dumps({"ip_switch": ip_msg}))

    for idx, path in enumerate(unique_paths, 1):
        # IP 轮换
        req_count += 1
        if req_count % args.ip_every == 0:
            ip_msg = switch_clash_proxy()
            print(json.dumps({"ip_switch": ip_msg}))

        url = f"{target_url}/{path.lstrip('/')}"
        sys.stdout.write(f"\r[{idx}/{total}] {url:<70}")
        sys.stdout.flush()

        # 带 WAF 检测的重试（最多 3 次旋转）
        for retry in range(4):
            try:
                resp = session.get(url, timeout=args.timeout, allow_redirects=False)
                time.sleep(args.delay)

                # WAF 检测
                if retry < 3 and _is_waf_blocked and _is_waf_blocked(resp.status_code, resp.text):
                    new_ip = switch_clash_proxy()
                    print(f"\n[WAF] {url} blocked (status={resp.status_code}) → rotate → {new_ip}")
                    time.sleep(1)
                    continue

                if should_record(resp.status_code, len(resp.content), seen_lengths):
                    entry = {
                        "url": url,
                        "path": "/" + path.lstrip("/"),
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "title": extract_title(resp.text),
                        "location": resp.headers.get("Location", ""),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    results.append(entry)
                    found_count += 1
                    print(f"  → {resp.status_code} ({len(resp.content)}B)")
                break
            except requests.exceptions.Timeout:
                print("  → timeout")
                break
            except requests.exceptions.ConnectionError as e:
                if retry < 3:
                    new_ip = switch_clash_proxy()
                    print(f"\n[WAF] connection error → rotate → {new_ip}")
                    time.sleep(2)
                    continue
                print(f"  → connection error: {e}")
                time.sleep(2)
                break
            except Exception as e:
                print(f"  → error: {e}")
                break

    elapsed = time.time() - start_time
    print()

    # ── 输出 ──
    output = {
        "target": target_url,
        "scanned": total,
        "found": found_count,
        "elapsed_seconds": round(elapsed, 1),
        "rate": f"{total / elapsed:.1f}/s" if elapsed > 0 else "N/A",
        "results": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(
        json.dumps(
            {
                "summary": {
                    "target": target_url,
                    "scanned": total,
                    "found": found_count,
                    "elapsed": f"{elapsed:.1f}s",
                    "output": args.output,
                }
            },
            ensure_ascii=False,
        )
    )


def extract_title(html):
    """从 HTML 提取 <title>"""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


if __name__ == "__main__":
    main()
