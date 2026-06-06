"""WAF 检测 + Clash IP 自动轮换模块。

供 scrapling_fetch.py / brutescan.py 等 HTTP 工具使用。

用法:
  from waf_rotate import is_waf_blocked, rotate_ip, RotatingFetcher

  # 手动检查 + 轮换
  if is_waf_blocked(resp.status_code, resp.text):
      rotate_ip()
      # retry request

  # 自动轮换 wrapper
  fetcher = RotatingFetcher(max_rotations=3)
  resp = fetcher.fetch_with_rotation(lambda: requests.get(url))
"""

import random
import time
from typing import Callable

import requests
import urllib3

urllib3.disable_warnings()

CLASH_API = "http://127.0.0.1:9097"
CLASH_SECRET = "set-your-secret"
CLASH_HEADERS = {"Authorization": f"Bearer {CLASH_SECRET}"}

# WAF 拦截特征
WAF_STATUS = {403, 420, 429, 503}

WAF_BODY_KEYWORDS = [
    "waf",
    "blocked",
    "modsecurity",
    "access denied",
    "request rejected",
    "cloudflare ray id",
    "tencent cloud",
    "安全拦截",
    "访问被拒绝",
    "请求被拦截",
    "您的请求已被拦截",
    "您的IP已被",
    "IP黑名单",
    "captcha",
    "challenge",
    "ddos protection",
    "rate limit exceeded",
    "too many requests",
    "您的访问已被拦截",
]


def is_waf_blocked(status_code: int, body: str) -> bool:
    """检查响应是否被 WAF / 限速拦截。"""
    if status_code in WAF_STATUS:
        return True
    body_lower = body.lower() if body else ""
    for kw in WAF_BODY_KEYWORDS:
        if kw in body_lower:
            return True
    return False


def _clash_get(path: str) -> dict | None:
    try:
        resp = requests.get(f"{CLASH_API}{path}", headers=CLASH_HEADERS, timeout=5, verify=False)
        return resp.json() if resp.ok else None
    except Exception:
        return None


def _clash_put(path: str, body: dict) -> bool:
    try:
        resp = requests.put(
            f"{CLASH_API}{path}",
            headers=CLASH_HEADERS,
            json=body,
            timeout=5,
            verify=False,
        )
        return resp.ok
    except Exception:
        return False


def _clash_delete(path: str) -> bool:
    try:
        resp = requests.delete(f"{CLASH_API}{path}", headers=CLASH_HEADERS, timeout=5, verify=False)
        return resp.ok
    except Exception:
        return False


def get_available_nodes(group: str = "Proxy") -> list[str]:
    """返回指定代理组的可用节点列表。"""
    data = _clash_get("/proxies")
    if not data or "proxies" not in data:
        return []
    group_data = data["proxies"].get(group, {})
    all_nodes = group_data.get("all", [])
    current = group_data.get("now", "")
    return [n for n in all_nodes if n not in ("DIRECT", "REJECT", current)]


def rotate_ip(group: str = "Proxy") -> str | None:
    """切换到随机代理节点，断开旧连接。返回新节点名。"""
    nodes = get_available_nodes(group)
    if not nodes:
        # fallback: 包含当前节点
        data = _clash_get("/proxies")
        if data and "proxies" in data:
            group_data = data["proxies"].get(group, {})
            all_nodes = group_data.get("all", [])
            nodes = [n for n in all_nodes if n not in ("DIRECT", "REJECT")]
    if not nodes:
        return None

    pick = random.choice(nodes)
    ok = _clash_put(f"/proxies/{group}", {"name": pick})
    if not ok:
        return None

    _clash_delete("/connections")
    return pick


class RotatingFetcher:
    """带 WAF 检测 + IP 自动轮换的 fetch wrapper。"""

    def __init__(self, max_rotations: int = 3, rotate_delay: float = 1.0):
        self.max_rotations = max_rotations
        self.rotate_delay = rotate_delay
        self.rotation_log: list[str] = []

    def fetch_with_rotation(self, fetch_fn: Callable, is_response_fn=None) -> tuple:
        """执行 fetch_fn()，遇到 WAF 自动 rotate_ip 后重试。

        fetch_fn: 返回 requests.Response 的可调用对象
        is_response_fn: 可选的自定义 WAF 检测，参数 (status_code, body) → bool
           若不提供，用默认 is_waf_blocked

        返回: (response, rotation_count, log)
        """
        check_fn = is_response_fn or is_waf_blocked
        resp = None

        for attempt in range(max(0, self.max_rotations) + 1):
            resp = fetch_fn()
            if not isinstance(resp, requests.Response):
                # 如果不是 Response 对象，直接返回
                return resp, attempt, self.rotation_log

            if not check_fn(resp.status_code, resp.text):
                return resp, attempt, self.rotation_log

            if attempt < self.max_rotations:
                new_ip = rotate_ip()
                node_info = new_ip or "unknown"
                self.rotation_log.append(
                    f"[WAF] attempt={attempt + 1} status={resp.status_code} → rotate → {node_info}"
                )
                time.sleep(self.rotate_delay)
            else:
                self.rotation_log.append(
                    f"[WAF] attempt={attempt + 1} status={resp.status_code} → max rotations reached"
                )

        return resp, self.max_rotations, self.rotation_log


def is_clash_alive() -> bool:
    """检查 Clash API 是否可达。"""
    data = _clash_get("/proxies")
    return data is not None
