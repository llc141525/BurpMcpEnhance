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
import subprocess
import sys
import uuid
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # auth/→TOOLS/→SRC/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # TOOLS/
from db.cookie_helper import get_auth_cookies_dict  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402
from utils.signal_filter import (  # noqa: E402
    canonical_query_string,
    canonicalize_url,
    classify_auth_surface,
    classify_endpoint,
    classify_mmx_fallback,
    endpoint_fingerprint,
    summarize_response,
)

STATIC_TYPES = {"stylesheet", "image", "font", "media", "websocket", "manifest", "ping"}
STATIC_EXT_RE = re.compile(r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip)(\?.*)?$", re.I)

# Hunt queue pre-filter: ID-like param names and numeric path segments
_ID_PARAM_RE = re.compile(r"^(id|uid|user_?id|order_?id|oid|pid|tid|sid|no|num|code|sn)$", re.I)
_NUMERIC_PATH_RE = re.compile(r"/\d{2,}(/|$|\?)")

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

UNSAFE_LABEL_RE = re.compile(
    r"(logout|sign\s*out|exit|delete|remove|submit|save|confirm|pay|bind|unbind|"
    r"退出|注销|删除|移除|提交|保存|确认|支付|绑定|解绑)",
    re.I,
)

RESPONSE_URL_KEYS = {
    "url",
    "href",
    "link",
    "path",
    "route",
    "targetUrl",
    "redirectUrl",
    "appUrl",
    "menuUrl",
    "moduleUrl",
    "iframeUrl",
    "openUrl",
}

LABEL_KEYS = ("name", "title", "label", "text", "menuName", "appName", "moduleName")

INLINE_ROUTE_PATTERNS = [
    re.compile(r"window\.open\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"router\.push\(\s*(?:\{\s*path\s*:\s*)?['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"navigate\(\s*['\"]([^'\"]+)['\"]", re.I),
]

DOM_CANDIDATE_SELECTOR = ",".join(
    [
        "a[href]",
        "button",
        "[role='button']",
        "[role='menuitem']",
        "[role='tab']",
        "[onclick]",
        "[data-url]",
        "[data-href]",
        "[data-route]",
        "[data-path]",
        "[data-to]",
        "[data-link]",
        "[data-src]",
        "iframe[src]",
        ".menu-item",
        ".nav-item",
        ".el-menu-item",
        ".ant-menu-item",
        ".layui-nav-item",
        ".card",
        ".el-card",
        ".ant-card",
    ]
)


# ── Pure functions (testable without browser) ─────────────────────────────────


def is_unsafe_label(label: str) -> bool:
    """Return True when a clickable label looks destructive/session-ending."""
    return bool(label and UNSAFE_LABEL_RE.search(label))


def normalize_candidate_url(value: str, seed_url: str) -> str | None:
    """Normalize absolute, relative, and hash-route candidate values."""
    raw = (value or "").strip()
    if not raw or raw.lower().startswith(("javascript:", "mailto:", "tel:")):
        return None
    if raw == "#":
        return None
    if raw.startswith("#"):
        base = seed_url.split("#", 1)[0]
        return base + raw
    normalized = urljoin(seed_url, raw)
    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, parsed.fragment))


def _same_site_url(candidate_url: str, seed_url: str) -> bool:
    candidate_host = urlparse(candidate_url).netloc
    seed_host = urlparse(seed_url).netloc
    if not candidate_host or not seed_host:
        return False
    return _site_domain(candidate_host) == _site_domain(seed_host)


def extract_inline_route_literals(script: str) -> list[str]:
    """Extract common inline/script navigation route literals."""
    routes: list[str] = []
    for pattern in INLINE_ROUTE_PATTERNS:
        routes.extend(match.group(1) for match in pattern.finditer(script or ""))
    return list(dict.fromkeys(routes))


def _label_from_obj(obj: dict, fallback: str = "") -> str:
    for key in LABEL_KEYS:
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:60]
    return fallback[:60]


def extract_response_candidates(
    payload,
    seed_url: str,
    source_url: str,
    parent_label: str = "",
) -> list[dict]:
    """Extract framework-neutral navigation candidates from nested JSON payloads."""
    candidates: list[dict] = []

    def walk(node, inherited_label: str) -> None:
        if isinstance(node, dict):
            label = _label_from_obj(node, inherited_label)
            for key, value in node.items():
                if key in RESPONSE_URL_KEYS and isinstance(value, str):
                    normalized = normalize_candidate_url(value, seed_url)
                    if normalized and _same_site_url(normalized, seed_url) and not is_unsafe_label(label):
                        candidates.append(
                            {
                                "kind": "response_url",
                                "value": normalized,
                                "label": label or normalized,
                                "source": source_url,
                                "framework_hint": "unknown",
                            }
                        )
                else:
                    walk(value, label)
        elif isinstance(node, list):
            for item in node:
                walk(item, inherited_label)

    walk(payload, parent_label)
    seen: set[str] = set()
    deduped = []
    for candidate in candidates:
        key = candidate["value"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _candidate_prefix(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.netloc:
        return value[:80]
    parts = [p for p in parsed.path.split("/") if p]
    first = parts[0] if parts else ""
    return f"{parsed.netloc}/{first}"


class CandidateQueue:
    """Bounded breadth-preserving candidate queue."""

    def __init__(self, per_prefix_cap: int = 3, per_host_cap: int = 20):
        self.per_prefix_cap = per_prefix_cap
        self.per_host_cap = per_host_cap
        self._seen: set[str] = set()
        self._prefix_counts: dict[str, int] = defaultdict(int)
        self._host_counts: dict[str, int] = defaultdict(int)
        self._items: deque[dict] = deque()

    def add(self, candidate: dict) -> bool:
        value = candidate.get("value", "")
        if not value or value in self._seen:
            return False
        parsed = urlparse(value)
        host = parsed.netloc or candidate.get("kind", "unknown")
        prefix = _candidate_prefix(value)
        if self._host_counts[host] >= self.per_host_cap:
            return False
        if self._prefix_counts[prefix] >= self.per_prefix_cap:
            return False
        self._seen.add(value)
        self._host_counts[host] += 1
        self._prefix_counts[prefix] += 1
        self._items.append(candidate)
        return True

    def extend(self, candidates: list[dict]) -> None:
        for candidate in candidates:
            self.add(candidate)

    def pop(self) -> dict | None:
        if not self._items:
            return None
        return self._items.popleft()

    def items(self) -> list[dict]:
        return list(self._items)


def _framework_hint_from_attrs(attrs: dict) -> str:
    text = " ".join(str(v) for v in attrs.values() if v).lower()
    if "el-" in text:
        return "vue"
    if "ant-" in text:
        return "react"
    if "layui" in text:
        return "layui"
    if attrs.get("tag") == "iframe":
        return "iframe"
    return "unknown"


def _candidate_from_attr_value(attr_value: str, label: str, seed_url: str, source: str, hint: str) -> dict | None:
    normalized = normalize_candidate_url(attr_value, seed_url)
    if not normalized or not _same_site_url(normalized, seed_url) or is_unsafe_label(label):
        return None
    return {"kind": "url", "value": normalized, "label": label or normalized, "source": source, "framework_hint": hint}


def dom_attrs_to_candidates(attrs: dict, seed_url: str, source: str) -> list[dict]:
    """Build URL/click candidates from a DOM attribute snapshot."""
    label = (attrs.get("text") or attrs.get("aria") or attrs.get("title") or "").strip()[:60]
    if is_unsafe_label(label):
        return []
    hint = _framework_hint_from_attrs(attrs)
    candidates: list[dict] = []
    for key in (
        "href",
        "dataUrl",
        "dataHref",
        "dataRoute",
        "dataPath",
        "dataTo",
        "dataLink",
        "dataSrc",
        "src",
        "formAction",
    ):
        value = attrs.get(key)
        if isinstance(value, str):
            candidate = _candidate_from_attr_value(value, label, seed_url, f"{source}:{key}", hint)
            if candidate:
                candidates.append(candidate)
    onclick = attrs.get("onclick") or ""
    for route in extract_inline_route_literals(onclick):
        candidate = _candidate_from_attr_value(route, label, seed_url, f"{source}:onclick", hint)
        if candidate:
            candidates.append(candidate)
    if not candidates and label:
        fingerprint = json.dumps(
            {
                "text": label,
                "role": attrs.get("role", ""),
                "tag": attrs.get("tag", ""),
                "className": attrs.get("className", ""),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        candidates.append(
            {
                "kind": "click",
                "value": fingerprint,
                "label": label,
                "source": source,
                "framework_hint": hint,
            }
        )
    return candidates


def _strip_www(host: str) -> str:
    """去掉 host 前缀的 www. (精确匹配，不用 lstrip 避免 B005)。"""
    return host[4:] if host.startswith("www.") else host


def _site_domain(host: str) -> str:
    """Best-effort same-site root for Chinese edu/gov/com second-level suffixes."""
    clean = _strip_www(host.split(":")[0].lower())
    parts = [p for p in clean.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in {"edu.cn", "gov.cn", "com.cn", "net.cn", "org.cn"}:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean


def filter_api_requests(requests: list[dict], base_domain: str) -> list[dict]:
    """过滤：只保留同域 XHR/fetch，排除静态资源。"""
    result = []
    base = _site_domain(base_domain)
    for r in requests:
        if r.get("resource_type") not in ("xhr", "fetch"):
            continue
        url = r.get("url", "")
        try:
            host = _strip_www(urlparse(url).netloc.split(":")[0])
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
    sp_count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sp_cols = {row["name"] for row in conn.execute("PRAGMA table_info(suspicious_points)").fetchall()}
    for req in api_requests:
        params = req.get("params", [])
        context = req.get("nav_context", "")
        method = req.get("method", "GET").upper()
        response_summary = req.get("response_summary") or {}
        auth_type, risk_score, reason = classify_auth_surface(
            req["url"],
            method,
            params,
            response_summary=response_summary,
            has_body=bool(req.get("post_data")),
        )
        if auth_type in ("auth_required", "public_api", "noise_counter"):
            continue
        signal = classify_endpoint(req["url"], method, params)
        url = signal.canonical_url
        fingerprint = endpoint_fingerprint(req["url"], method, params)
        test_type = auth_type
        if "endpoint_fingerprint" in sp_cols:
            existing = conn.execute(
                """SELECT id FROM suspicious_points
                   WHERE source='auth_explore' AND endpoint_fingerprint=? AND test_type=? LIMIT 1""",
                (fingerprint, test_type),
            ).fetchone()
        else:
            existing = conn.execute(
                "SELECT id FROM suspicious_points WHERE url=? AND method=? AND test_type=? LIMIT 1",
                (url, method, test_type),
            ).fetchone()
        if existing:
            continue
        sp_id = f"{sp_prefix}-{uuid.uuid4().hex[:8]}"
        evidence = {
            "nav_context": context,
            "params": params,
            "classification": auth_type,
            "classification_reason": reason,
            "response_summary": response_summary,
        }
        values = {
            "id": sp_id,
            "url": url,
            "param": ", ".join(params) if params else "",
            "method": method,
            "test_type": test_type,
            "evidence": json.dumps(evidence, ensure_ascii=False),
            "source": "auth_explore",
            "reasoning": f"认证用户操作触发的高价值 API，分类={auth_type}，原因={reason}，来源: {context}",
            "risk": "High" if risk_score >= 60 else "Medium",
            "test_status": "untested",
            "created_at": now,
        }
        optional = {
            "endpoint_fingerprint": fingerprint,
            "response_summary": json.dumps(response_summary, ensure_ascii=False),
            "risk_score": risk_score,
        }
        values.update({key: value for key, value in optional.items() if key in sp_cols})
        columns = list(values.keys())
        placeholders = ", ".join("?" for _ in columns)
        cur = conn.execute(
            f"""INSERT INTO suspicious_points
                ({", ".join(columns)})
                VALUES ({placeholders})
                ON CONFLICT(id) DO NOTHING""",
            tuple(values[col] for col in columns),
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


# ── Hunt queue: pre-filter + mmx classification + write ──────────────────────


def _is_hunt_candidate(req: dict) -> bool:
    """Heuristic pre-filter: 值得做三层重放测试的请求，不依赖 URL pattern。"""
    signal = classify_endpoint(req.get("url", ""), req.get("method", "GET"), req.get("params", []))
    if signal.is_candidate:
        req["url"] = signal.canonical_url
        return True
    if signal.value in ("low_value", "ignore"):
        return False
    method = req.get("method", "GET").upper()
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    params = req.get("params", [])
    if any(_ID_PARAM_RE.match(p) for p in params):
        return True
    path = urlparse(req.get("url", "")).path
    if _NUMERIC_PATH_RE.search(path):
        return True
    if len(params) >= 2:  # GET with multiple params likely a data query
        return True
    return False


def _classify_with_mmx(candidates: list[dict], tmp_dir: Path) -> list[dict]:
    """用 mmx 对候选请求做业务意图分类。失败时返回空列表（降级：跳过写 hunt_queue）。"""
    if not candidates:
        return []

    mmx_input = [
        {
            "idx": i,
            "method": r.get("method", "GET"),
            "url": r.get("url", ""),
            "params": r.get("params", []),
            "nav_context": r.get("nav_context", ""),
            "has_body": bool(r.get("post_data")),
        }
        for i, r in enumerate(candidates)
    ]

    ts = datetime.now().strftime("%H%M%S")
    input_file = tmp_dir / f"ae_classify_{ts}.json"
    input_file.write_text(json.dumps(mmx_input, ensure_ascii=False), encoding="utf-8")

    prompt = (
        "你是 SRC 渗透测试助手，分析以下认证后浏览器自动触发的 XHR 请求，判断其业务价值。\n"
        "nav_context 是触发该请求的导航项标签（如「学生管理>成绩查询」），是最强的业务语义信号。\n"
        '输出 JSON 数组，每条: {"idx":<int>,"endpoint_type":"business_api|auth_login|auth_register|'
        'auth_reset_password|auth_verify_code|low_value","business_intent":"一句话业务含义",'
        '"risk_hint":"High|Medium|Low"}\n'
        "low_value: 纯导航/字典/枚举/配置查询、无参GET、统计埋点\n"
        "risk_hint=High: 含 id/uid/oid 参数 或 POST/DELETE/PUT 或涉及用户/订单/权限数据\n"
        "返回纯 JSON 数组，无 markdown 围栏:\n"
        f"{input_file.read_text(encoding='utf-8')}"
    )

    try:
        result = subprocess.run(  # noqa: S603
            ["mmx", "text", "chat", "--output", "text", "--non-interactive", "--message", prompt],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        raw = result.stdout.strip()
        try:
            classified = json.loads(raw)
        except json.JSONDecodeError:
            start, end = raw.find("["), raw.rfind("]")
            if start >= 0 and end > start:
                classified = json.loads(raw[start : end + 1])
            else:
                print("[auth_explore] mmx 分类输出无法解析，使用本地启发式分类", file=sys.stderr)
                return [item for item in (classify_mmx_fallback(req) for req in candidates) if item]

        idx_map = {item["idx"]: item for item in classified if isinstance(item, dict)}
        results = []
        for i, req in enumerate(candidates):
            cls = idx_map.get(i, {})
            if cls.get("endpoint_type", "low_value") == "low_value":
                continue
            results.append(
                {
                    **req,
                    "endpoint_type": cls.get("endpoint_type", "business_api"),
                    "business_intent": cls.get("business_intent", req.get("nav_context", "")),
                    "risk_hint": cls.get("risk_hint", "Medium"),
                }
            )
        return results

    except Exception as e:  # noqa: BLE001
        print(f"[auth_explore] mmx 分类异常: {e}，使用本地启发式分类", file=sys.stderr)
        return [item for item in (classify_mmx_fallback(req) for req in candidates) if item]


def write_hunt_queue(
    conn: sqlite3.Connection,
    classified: list[dict],
    target_id: int,
) -> int:
    """将 mmx 分类后的业务接口写入 hunt_queue（source='auth_explore'）。"""
    count = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for req in classified:
        url = req.get("url", "")
        url_base = canonicalize_url(url).split("?")[0]
        query_string = canonical_query_string(url)
        body = req.get("post_data") or ""
        content_type = "application/json" if body and body.lstrip().startswith("{") else ""
        try:
            cur = conn.execute(
                """INSERT INTO hunt_queue
                   (target_id, method, url, query_string, body, content_type,
                    endpoint_type, business_intent, risk_hint, source, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'auth_explore', 'queued', ?)
                   ON CONFLICT(method, url, query_string) DO NOTHING""",
                (
                    target_id,
                    req.get("method", "GET").upper(),
                    url_base,
                    query_string,
                    body,
                    content_type,
                    req.get("endpoint_type", "business_api"),
                    req.get("business_intent", ""),
                    req.get("risk_hint", "Medium"),
                    now,
                ),
            )
            count += cur.rowcount
        except sqlite3.Error as e:
            print(f"[auth_explore] hunt_queue 写入失败 {url_base}: {e}", file=sys.stderr)
    conn.commit()
    return count


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
    response_summaries: dict[tuple[str, str], dict] = {}

    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(cdp_url)
        context = browser.contexts[0] if browser.contexts else await browser.new_context()

        if cookies:
            cookie_list = [{"name": k, "value": v, "domain": base_domain, "path": "/"} for k, v in cookies.items()]
            await context.add_cookies(cookie_list)

        page = await context.new_page()

        def on_request(request):
            captured_context = current_nav_context  # 值快照，不捕获引用
            try:
                if request.resource_type in ("xhr", "fetch"):
                    params = parse_request_params(request.url, request.post_data)
                    all_api_requests.append(
                        {
                            "url": request.url,
                            "method": request.method,
                            "resource_type": request.resource_type,
                            "params": params,
                            "nav_context": captured_context,
                            "post_data": request.post_data,
                        }
                    )
            except Exception as e:  # noqa: BLE001
                print(f"[auth_explore] on_request error: {e}", file=sys.stderr)

        page.on("request", on_request)

        response_candidates: list[dict] = []
        response_tasks: list[asyncio.Task] = []

        async def on_response(response):
            if response.request.resource_type not in ("xhr", "fetch"):
                return
            try:
                content_type = response.headers.get("content-type", "")
                body_text = await response.text()
                key = (response.url, response.request.method.upper())
                response_summaries[key] = summarize_response(response.status, content_type, body_text[:20000])
                if "json" not in content_type.lower():
                    return
                payload = json.loads(body_text)
                response_candidates.extend(
                    extract_response_candidates(payload, seed_url=seed_url, source_url=response.url)
                )
            except Exception:  # noqa: S112,BLE001 — response bodies may be unavailable
                return

        def schedule_response(response):
            response_tasks.append(asyncio.create_task(on_response(response)))

        async def drain_response_tasks() -> None:
            if not response_tasks:
                return
            pending = list(response_tasks)
            response_tasks.clear()
            await asyncio.gather(*pending, return_exceptions=True)

        async def collect_dom_candidates(source: str) -> list[dict]:
            try:
                snapshots = await page.evaluate(
                    """selector => Array.from(document.querySelectorAll(selector)).slice(0, 120).map(el => ({
                        tag: el.tagName.toLowerCase(),
                        text: (el.innerText || el.textContent || '').trim().slice(0, 80),
                        aria: el.getAttribute('aria-label') || '',
                        title: el.getAttribute('title') || '',
                        role: el.getAttribute('role') || '',
                        className: el.className || '',
                        href: el.getAttribute('href') || '',
                        src: el.getAttribute('src') || '',
                        onclick: el.getAttribute('onclick') || '',
                        dataUrl: el.getAttribute('data-url') || '',
                        dataHref: el.getAttribute('data-href') || '',
                        dataRoute: el.getAttribute('data-route') || '',
                        dataPath: el.getAttribute('data-path') || '',
                        dataTo: el.getAttribute('data-to') || '',
                        dataLink: el.getAttribute('data-link') || '',
                        dataSrc: el.getAttribute('data-src') || '',
                        formAction: el.getAttribute('formaction') || ''
                    }))""",
                    DOM_CANDIDATE_SELECTOR,
                )
            except Exception:  # noqa: S112,BLE001
                return []
            candidates: list[dict] = []
            for attrs in snapshots:
                candidates.extend(dom_attrs_to_candidates(attrs, seed_url, source))
            return candidates

        async def click_fingerprint(fingerprint: str) -> bool:
            try:
                data = json.loads(fingerprint)
            except json.JSONDecodeError:
                return False
            try:
                return await page.evaluate(
                    """({selector, fp}) => {
                        const text = fp.text || '';
                        const nodes = Array.from(document.querySelectorAll(selector));
                        const match = nodes.find(el => {
                            const label = (el.innerText || el.textContent || '').trim().slice(0, 60);
                            const role = el.getAttribute('role') || '';
                            const tag = el.tagName.toLowerCase();
                            return label === text && (!fp.role || fp.role === role) && (!fp.tag || fp.tag === tag);
                        });
                        if (!match) return false;
                        match.click();
                        return true;
                    }""",
                    {"selector": DOM_CANDIDATE_SELECTOR, "fp": data},
                )
            except Exception:  # noqa: S112,BLE001
                return False

        page.on("response", schedule_response)

        try:
            await page.goto(seed_url, wait_until="networkidle", timeout=30000)
            all_page_urls.add(page.url)
            await drain_response_tasks()
        except Exception as e:
            print(f"[auth_explore] 首页导航失败: {e}", file=sys.stderr)
            return [], []

        queue = CandidateQueue(per_prefix_cap=3, per_host_cap=20)
        queue.extend(await collect_dom_candidates("seed_dom"))
        queue.extend(response_candidates)
        response_candidates.clear()

        print(f"[auth_explore] 初始发现 {len(queue.items())} 个候选入口", file=sys.stderr)

        processed = 0
        max_candidates = 60 if nav_depth >= 2 else 30
        while processed < max_candidates:
            candidate = queue.pop()
            if not candidate:
                break
            processed += 1
            current_nav_context = candidate.get("label", candidate.get("value", ""))[:80]

            try:
                if candidate["kind"] in ("url", "hash", "response_url"):
                    await page.goto(candidate["value"], wait_until="networkidle", timeout=15000)
                    all_page_urls.add(page.url)
                elif candidate["kind"] == "click":
                    await page.goto(seed_url, wait_until="domcontentloaded", timeout=10000)
                    before_pages = set(context.pages)
                    clicked = await click_fingerprint(candidate["value"])
                    if not clicked:
                        continue
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:  # noqa: S112,BLE001
                        await page.wait_for_timeout(1000)
                    for popup in [pg for pg in context.pages if pg not in before_pages]:
                        try:
                            all_page_urls.add(popup.url)
                            await popup.wait_for_load_state("networkidle", timeout=5000)
                            await popup.close()
                        except Exception:  # noqa: S112,BLE001
                            continue
                    all_page_urls.add(page.url)
                else:
                    continue

                await drain_response_tasks()
                queue.extend(response_candidates)
                response_candidates.clear()
                if nav_depth >= 2:
                    queue.extend(await collect_dom_candidates(current_nav_context))
            except Exception as e:
                print(
                    f"[auth_explore] 候选入口 {candidate.get('label') or candidate.get('value')} 失败: {e}",
                    file=sys.stderr,
                )
                continue

        await page.close()

    filtered = filter_api_requests(all_api_requests, base_domain)
    seen: set[tuple[str, str]] = set()
    deduped = []
    for r in filtered:
        r["response_summary"] = response_summaries.get((r["url"], r["method"].upper()), {})
        key = (endpoint_fingerprint(r["url"], r["method"], r.get("params", [])), r["method"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped, list(all_page_urls)


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

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
    cookies = get_auth_cookies_dict(str(db_path), base_domain, role="primary")

    print(f"[auth_explore] 目标: {args.target}  seed: {seed_url}  cookies: {len(cookies)} 条")

    api_requests, page_urls = asyncio.run(explore_authenticated(cdp_url, seed_url, cookies, base_domain))

    counts = write_explore_results_to_db(conn, api_requests, page_urls)

    # 业务接口 → hunt_queue：heuristic 预筛 + mmx 分类
    candidates = [r for r in api_requests if _is_hunt_candidate(r)]
    hq_count = 0
    if candidates:
        tmp_dir = PROJECT_ROOT / "tmp"
        tmp_dir.mkdir(exist_ok=True)
        classified = _classify_with_mmx(candidates, tmp_dir)
        if classified:
            target_row = conn.execute("SELECT id FROM targets LIMIT 1").fetchone()
            target_id = target_row["id"] if target_row else 0
            hq_count = write_hunt_queue(conn, classified, target_id)

    conn.execute("UPDATE scan_state SET phase='spider' WHERE id=1")
    conn.commit()
    conn.close()

    print(
        f"[auth_explore] 完成: SP={counts['sp']}  pages={counts['pages']}"
        f"  hunt_queue={hq_count}({len(candidates)} candidates)  phase→spider"
    )


if __name__ == "__main__":
    main()
