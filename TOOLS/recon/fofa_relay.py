#!/usr/bin/env python3
"""
FOFA 中转查询工具 — 走 fafaapi.ccwu.cc 代理
无需 F 币，无需 cf_clearance

环境变量:
  FOFA_RELAY_KEY  FOFA 中继 API Key（从 https://fafaapi.ccwu.cc:8443/fofa.html 配置获取）

用法:
  python3 TOOLS/fofa_relay.py -q 'domain="oocl.com"' --size 500
  python3 TOOLS/fofa_relay.py --preset domain oocl.com --size 500
  python3 TOOLS/fofa_relay.py -q 'domain="oocl.com"' --json
"""

import argparse
import base64
import json
import os
import sys
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://fafaapi.ccwu.cc:8443"
DEFAULT_SIZE = 500
DEFAULT_FIELDS = "ip,port,protocol,host,domain,title,server,link,country_name"

PRESETS = {
    "domain": 'domain="{value}"',
    "ip": 'ip="{value}"',
    "title": 'title="{value}"',
    "icp": 'icp="{value}"',
    "cert": 'cert="{value}"',
    "host": 'host="{value}"',
}


def _encode(text: str) -> str:
    """base64 编码查询（前端 JS aesEncrypt 等效）"""
    return base64.b64encode(text.encode()).decode()


def validate_key(key: str) -> dict:
    """校验 Key 有效性并返回额度信息"""
    try:
        resp = requests.get(
            f"{BASE_URL}/fofaapi/v1/validate-key",
            params={"key": key},
            verify=False,
            timeout=10,
        )
        if resp.status_code != 200:
            return {"valid": False, "errmsg": f"HTTP {resp.status_code}"}
        return resp.json()
    except Exception as e:
        return {"valid": False, "errmsg": str(e)}


def search(key: str, query: str, size: int = DEFAULT_SIZE, fields: str = DEFAULT_FIELDS, route: str = "1") -> dict:
    """查询 FOFA（手动拼 URL 避免 requests 二次编码）"""
    q_encoded = _encode(query)
    # 注意: base64 的 = 不能 URL 编码（API 返回 400），用 safe='=' 保留
    url = (
        f"{BASE_URL}/fofaapi"
        f"?key={key}"
        f"&queryStr={quote(q_encoded, safe='=')}"
        f"&fields={quote(fields, safe=',')}"
        f"&page=1"
        f"&size={size}"
        f"&route={route}"
    )
    resp = requests.get(url, verify=False, timeout=60)
    resp.raise_for_status()
    return resp.json()


def normalize(raw: dict, query: str) -> dict:
    """将中转 API 响应统一成 fofa_query.py 兼容格式"""
    # 检查错误响应
    if raw.get("error"):
        raise RuntimeError(raw.get("errmsg", "查询失败"))

    # 兼容三种响应包装
    data = raw.get("finalResults") or raw.get("data") or []
    # results 可能是 null 或包含旧格式数据
    if not data:
        data = raw.get("results") or []
    total_hits = raw.get("total", len(data))

    results = []
    for item in data:
        if isinstance(item, dict):
            # 新格式: item.fields = {ip, port, host, ...}
            fields = item.get("fields", item)
            ip = fields.get("ip", "")
            port = str(fields.get("port", ""))
            protocol = fields.get("protocol", "")
            host = fields.get("host", "") or fields.get("link", "")
            domain = fields.get("domain", "")
            title = fields.get("title", "")
            server = fields.get("server", "")

            if not protocol:
                protocol = "https" if port == "443" or host.startswith("https") else "http"
            if not host:
                host = f"{protocol}://{ip}:{port}" if port not in ("80", "443", "") else f"{protocol}://{ip}"

            results.append(
                {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "host": host,
                    "domain": domain,
                    "title": title,
                    "server": server,
                }
            )
        elif isinstance(item, list):
            # 兼容旧格式: [host, ip, port, title, domain, server]
            host = item[0] if len(item) > 0 else ""
            ip = item[1] if len(item) > 1 else ""
            port = str(item[2]) if len(item) > 2 else ""
            title = item[3] if len(item) > 3 else ""
            domain = item[4] if len(item) > 4 else ""
            protocol = "https" if port == "443" or host.startswith("https") else "http"
            server = item[5] if len(item) > 5 else ""
            if not host:
                host = f"{protocol}://{ip}:{port}" if port not in ("80", "443", "") else f"{protocol}://{ip}"
            results.append(
                {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "host": host,
                    "domain": domain,
                    "title": title,
                    "server": server,
                }
            )

    return {
        "query": query,
        "count": len(results),
        "total": total_hits,
        "results": results,
        "_remaining": raw.get("newTodayRemaining"),
    }


def main():
    parser = argparse.ArgumentParser(description="FOFA 中转查询")
    parser.add_argument("--check-key", action="store_true", help="仅校验 Key 有效性并退出")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-q", "--query", help="FOFA 查询语句")
    group.add_argument("--preset", nargs=2, metavar=("TYPE", "VALUE"), help=f"预设查询，TYPE: {', '.join(PRESETS)}")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE, help=f"返回条数（默认 {DEFAULT_SIZE}）")
    parser.add_argument("--key", help="FOFA Relay Key（优先于 FOFA_RELAY_KEY 环境变量）")
    parser.add_argument("--fields", default=DEFAULT_FIELDS, help=f"返回字段（默认: {DEFAULT_FIELDS}）")
    parser.add_argument("--route", choices=["1", "2", "3", "4"], default="1", help="中继线路（默认 1）")
    parser.add_argument("--json", action="store_true", help="仅输出 JSON 结果（不打印日志）")
    args = parser.parse_args()

    key = args.key or os.environ.get("FOFA_RELAY_KEY", "")
    if not key:
        # 兼容旧环境变量，但打印警告
        fallback = os.environ.get("FOFA_KEY", "")
        if fallback:
            print("[WARN] 检测到 FOFA_KEY 环境变量，但中继服务使用独立的 Key", file=sys.stderr)
            print("[WARN] 请设置 FOFA_RELAY_KEY 或使用 --key 参数传入中继 Key", file=sys.stderr)
        else:
            print("[ERROR] 需要 FOFA Relay Key: --key <key> 或设置 FOFA_RELAY_KEY 环境变量", file=sys.stderr)
            print("[HINT] 在 https://fafaapi.ccwu.cc:8443/fofa.html 配置获取 Key", file=sys.stderr)
            sys.exit(1)

    # 仅校验 Key（不需要 -q / --preset）
    if args.check_key:
        result = validate_key(key)
        if result.get("valid"):
            info = result
            print("[OK] Key 有效")
            print(f"     首次使用: {info.get('firstUsedAt', '-')}")
            print(f"     到期时间: {info.get('expireTime', '-')}")
            print(f"     今日剩余: {info.get('todayRemaining', '-')}")
        else:
            print(f"[ERROR] Key 无效: {result.get('errmsg', '未知错误')}", file=sys.stderr)
        sys.exit(0 if result.get("valid") else 1)

    # 构造查询
    if not args.query and not args.preset:
        parser.print_help()
        sys.exit(1)
    if args.preset:
        ptype, pval = args.preset
        if ptype not in PRESETS:
            print(f"[ERROR] 未知 preset: {ptype}，可选: {', '.join(PRESETS)}", file=sys.stderr)
            sys.exit(1)
        query = PRESETS[ptype].format(value=pval)
    else:
        query = args.query

    if not args.json:
        print(f"[RELAY] 查询: {query}", file=sys.stderr)
        print(f"[RELAY] 线路: {args.route}  字段: {args.fields}", file=sys.stderr)

    try:
        raw = search(key, query, args.size, args.fields, args.route)
    except Exception as e:
        print(f"[ERROR] 请求失败: {e}", file=sys.stderr)
        out = {"query": query, "count": 0, "results": []}
        print(json.dumps(out, ensure_ascii=False))
        sys.exit(1)

    try:
        out = normalize(raw, query)
    except RuntimeError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        out = {"query": query, "count": 0, "results": []}
        print(json.dumps(out, ensure_ascii=False))
        sys.exit(1)

    if not args.json:
        if out.get("total") and out["total"] > out["count"]:
            print(f"[RELAY] 返回 {out['count']} 条（共 {out['total']} 条匹配）", file=sys.stderr)
        else:
            print(f"[RELAY] 返回 {out['count']} 条", file=sys.stderr)
        if out.get("_remaining") is not None:
            print(f"[RELAY] 今日剩余: {out['_remaining']} 次", file=sys.stderr)

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
