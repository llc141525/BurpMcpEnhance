"""Scrapling 驱动的页面抓取与结构化数据提取

用法:
  python3 scrapling_fetch.py <url> [选项]

选项:
  --stealth        强制使用 StealthyFetcher (patchright 浏览器)
  --extract-all    提取所有数据类型（默认）
  --extract-links  提取链接
  --extract-forms  提取表单
  --extract-js     提取 JS 文件
  --extract-api    提取内联 API 调用
  --extract-params 提取可疑参数
  --html           输出完整 HTML（body 解码为 utf-8）
  --proxy URL      代理 URL (默认: http://127.0.0.1:9870)
  --timeout SEC    超时秒数 (默认: 15; Stealthy 用毫秒 = sec*1000)
  --solve-captcha  遇到验证码时自动尝试解决（需要 StealthyFetcher）

输出: JSON 到 stdout, 日志/错误到 stderr

示例:
  python3 scrapling_fetch.py https://target.com/page
  python3 scrapling_fetch.py https://target.com/js/app.js --html
  python3 scrapling_fetch.py https://target.com --stealth --extract-links
"""

import json
import os
import re
import sys
import time
import urllib.parse
from urllib.parse import urljoin


# ---------------------------------------------------------------------------
# 抓取
# ---------------------------------------------------------------------------
def _get_fetcher():
    from scrapling.fetchers import Fetcher

    return Fetcher


def _get_stealth():
    from scrapling.fetchers import StealthyFetcher

    return StealthyFetcher


def _get_body_text(page) -> str:
    body = getattr(page, "body", b"") or b""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def fetch(url, proxy=None, timeout=15, force_stealth=False, solve_captcha=False, cookies: dict | None = None):
    """返回 (Response 对象, used_stealth_bool, captcha_result)

    遇到 WAF 拦截自动 rotate IP 后重试（最多 3 次旋转）。
    """
    from waf_rotate import is_waf_blocked, rotate_ip

    proxy = proxy or os.environ.get("HTTP_PROXY", "http://127.0.0.1:9870")
    captcha_result = None
    last_err = None
    max_rotations = 3

    # ── 路径 A: 普通 Fetcher ──
    if not force_stealth:
        for attempt in range(max_rotations + 1):
            try:
                Fetcher = _get_fetcher()
                fetch_kwargs = dict(proxy=proxy, timeout=timeout)
                if cookies:
                    fetch_kwargs["cookies"] = cookies
                page = Fetcher.get(url, **fetch_kwargs)

                if is_waf_blocked(page.status, _get_body_text(page)):
                    if attempt < max_rotations:
                        new_ip = rotate_ip()
                        print(
                            f"[WAF] scrapling Fetcher blocked (status={page.status}) → rotate → {new_ip}",
                            file=sys.stderr,
                        )
                        time.sleep(1)
                        continue
                    print("[WAF] scrapling Fetcher blocked, max rotations reached", file=sys.stderr)

                if page.status not in (200, 201, 301, 302, 304, 401, 403, 404):
                    raise ValueError(f"HTTP {page.status}")
                return page, False, captcha_result
            except ValueError:
                last_err = "HTTP error from Fetcher"
                break
            except Exception as e:
                last_err = str(e)
                if attempt < max_rotations:
                    time.sleep(0.5)
                    continue
                break
    else:
        last_err = None

    # ── 路径 B: StealthyFetcher ──
    for attempt in range(max_rotations + 1):
        try:
            from captcha_bypass import auto_solve_captcha

            Stealthy = _get_stealth()
            kwargs = dict(
                proxy=proxy,
                timeout=timeout * 1000,
                headless=True,
                disable_resources=True,
                block_ads=True,
            )
            if cookies:
                kwargs["cookies"] = cookies
            if solve_captcha:
                kwargs["page_action"] = auto_solve_captcha

            page = Stealthy.fetch(url, **kwargs)

            if is_waf_blocked(page.status, _get_body_text(page)):
                if attempt < max_rotations:
                    new_ip = rotate_ip()
                    print(f"[WAF] Stealthy blocked (status={page.status}) → rotate → {new_ip}", file=sys.stderr)
                    time.sleep(1)
                    continue

            # 事后检测：检查返回内容是否仍是验证码页
            if solve_captcha:
                html = _get_body_text(page)
                still_captcha = any(
                    kw in html.lower()
                    for kw in ("geetest", "captcha", "验证码", "slideverify", "请完成安全验证", "verify you are human")
                )
                captcha_result = {"detected": still_captcha, "solved": not still_captcha}

            return page, True, captcha_result
        except Exception as e:
            if attempt < max_rotations:
                new_ip = rotate_ip()
                print(f"[WAF] Stealthy error → rotate → {new_ip}", file=sys.stderr)
                time.sleep(0.5)
                continue
            msg = f"{str(last_err or '') + '; ' if last_err else ''}{str(e)}"
            raise RuntimeError(f"所有 fetcher 均失败: {msg}") from e

    msg = f"{str(last_err or '') + '; ' if last_err else ''}WAF blocked after {max_rotations} rotations"
    raise RuntimeError(f"所有 fetcher 均失败: {msg}")


# ---------------------------------------------------------------------------
# 提取（直接使用 Response.css()）
# ---------------------------------------------------------------------------
def extract_links(page, base_url):
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.netloc
    links = []
    for href in page.css("a[href]::attr(href)").getall():
        try:
            abs_url = urljoin(base_url, href)
            p = urllib.parse.urlparse(abs_url)
            if p.scheme in ("http", "https") and (p.netloc == domain or not p.netloc):
                links.append(abs_url)
        except Exception:
            pass
    return list(dict.fromkeys(links))


def extract_forms(page, base_url):
    forms = []
    for form in page.css("form"):
        action = form.css("::attr(action)").get() or ""
        try:
            action = urljoin(base_url, action)
        except Exception:
            pass
        method = (form.css("::attr(method)").get() or "GET").upper()
        inputs = []
        for inp in form.css("input, select, textarea"):
            inputs.append(
                {
                    "tag": getattr(inp, "tag", "input"),
                    "name": inp.css("::attr(name)").get() or "",
                    "type": inp.css("::attr(type)").get() or "text",
                    "value": inp.css("::attr(value)").get() or "",
                    "hidden": (inp.css("::attr(type)").get() or "") == "hidden",
                }
            )
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def extract_js_files(page, base_url):
    files = []
    for src in page.css("script[src]::attr(src)").getall():
        try:
            files.append(urljoin(base_url, src))
        except Exception:
            pass
    return list(dict.fromkeys(files))


def extract_inline_apis(page, base_url):
    apis = set()
    patterns = [
        re.compile(r"""['"](https?://[^'"\s]+(?:/api/|/rest/|/v[12]/)[^'"\s]*)['"]"""),
        re.compile(r"""['"](/[a-z]+/[a-z]+/[a-zA-Z0-9_\-/]+)['"]"""),
        re.compile(r'(?:fetch|axios\.get|axios\.post|ajax|XMLHttpRequest)\s*\(\s*["\']([^"\']+)'),
        re.compile(r'url:\s*["\']([^"\']+)'),
    ]
    for script in page.css("script:not([src])"):
        try:
            text = script.css("::text").get()
            if not text:
                continue
        except Exception:
            continue
        for pat in patterns:
            for m in pat.finditer(text):
                c = m.group(1)
                if c.startswith("/") or "://" in c:
                    apis.add(c)
    return list(apis)


def extract_suspicious_params(url):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    keywords = {
        "path_traversal": ["file", "path", "doc", "template", "view", "dir", "show", "page"],
        "idor": ["uid", "user_id", "id", "role", "type", "mode", "account", "user"],
        "xss": ["q", "s", "search", "query", "keyword", "callback", "redirect", "url", "next", "dest"],
        "cmd": ["cmd", "exec", "command", "action", "debug", "shell"],
    }
    found = []
    for param, values in qs.items():
        pl = param.lower()
        for test_type, kws in keywords.items():
            if any(kw == pl or pl.endswith("_" + kw) or pl.startswith(kw + "_") for kw in kws):
                found.append({"param": param, "value": values[0] if values else "", "test_type": test_type})
                break
    return found


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scrapling_fetch.py <url> [options]", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]
    args_list = sys.argv[2:]
    args_set = set(args_list)

    proxy = None
    timeout = 15
    cookies_json = None
    for i, arg in enumerate(args_list):
        if arg == "--proxy" and i + 1 < len(args_list):
            proxy = args_list[i + 1]
        elif arg == "--timeout" and i + 1 < len(args_list):
            timeout = int(args_list[i + 1])
        elif arg == "--cookies" and i + 1 < len(args_list):
            cookies_json = args_list[i + 1]

    force_stealth = "--stealth" in args_set
    solve_captcha = "--solve-captcha" in args_set
    if solve_captcha and not force_stealth:
        force_stealth = True  # 验证码解决需要 StealthyFetcher

    extract_all = "--extract-all" in args_set or not any(a.startswith("--extract-") for a in args_set)

    cookies = json.loads(cookies_json) if cookies_json else None

    try:
        page, used_stealth, captcha_result = fetch(
            url,
            proxy=proxy,
            timeout=timeout,
            force_stealth=force_stealth,
            solve_captcha=solve_captcha,
            cookies=cookies,
        )
    except Exception as e:
        print(json.dumps({"error": str(e), "url": url, "status": 0}, ensure_ascii=False))
        sys.exit(1)

    result = {
        "url": str(getattr(page, "url", url)),
        "status": page.status,
        "used_stealth": used_stealth,
    }
    if captcha_result:
        result["captcha"] = captcha_result

    if extract_all or "--extract-links" in args_set:
        result["links"] = extract_links(page, url)
    if extract_all or "--extract-forms" in args_set:
        result["forms"] = extract_forms(page, url)
    if extract_all or "--extract-js" in args_set:
        result["js_files"] = extract_js_files(page, url)
    if extract_all or "--extract-api" in args_set:
        result["apis"] = extract_inline_apis(page, url)
    if extract_all or "--extract-params" in args_set:
        result["suspicious_params"] = extract_suspicious_params(url)
    if "--html" in args_set:
        body = page.body if hasattr(page, "body") else b""
        result["html"] = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
