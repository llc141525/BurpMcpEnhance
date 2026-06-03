"""
Burp 攻击面分析器 — 从 Burp 代理历史提取结构化攻击面信息

用途:
  操作员通过 Burp MCP 获取代理历史 → 输入到此工具 → 输出结构化攻击面分析

工作流:
  1. 操作员: get_proxy_http_history_regex(regex="...") 获取感兴趣的历史
  2. 操作员: 将历史 JSON 保存到文件或通过 stdin 管道输入
  3. AI: 运行此工具分析，生成攻击面地图

输出:
  - 参数词频表 (所有请求中出现的参数名及频率)
  - 端点结构树 (按路径前缀分组的 API 结构)
  - 可疑参数检测 (路径遍历、文件包含、SQL模式等)
  - 认证/授权模式分析
  - 测试假设生成
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

# ============================================================
# 可疑模式定义
# ============================================================

SUSPICIOUS_PARAM_NAMES = {
    # 文件操作类
    "file",
    "filename",
    "filepath",
    "path",
    "dir",
    "directory",
    "folder",
    "attachment",
    "upload",
    "download",
    "img",
    "image",
    "src",
    "source",
    "include",
    "page",
    "load",
    "template",
    # SQL 注入倾向
    "id",
    "uid",
    "user_id",
    "order_id",
    "article_id",
    "category",
    "cat",
    "type",
    "status",
    "action",
    # 命令执行
    "cmd",
    "command",
    "exec",
    "execute",
    "shell",
    "ping",
    "traceroute",
    "nslookup",
    "host",
    "url",
    "domain",
    # SSRF
    "redirect",
    "redirect_url",
    "callback",
    "webhook",
    "hook",
    "notify_url",
    "return_url",
    "goto",
    "target",
    "endpoint",
    # 越权
    "role",
    "permission",
    "group",
    "is_admin",
    "admin",
    "user",
    "username",
    "account",
    "token",
    "access_token",
    # 缓存/调试
    "cache",
    "debug",
    "trace",
    "test",
    "mock",
    "bypass",
    "limit",
    "offset",
    "page_size",
    "order",
}

SUSPICIOUS_PARAM_VALUES = [
    # 路径穿越
    (r"\.\./", "Path Traversal (../)"),
    (r"\.\.\\", "Path Traversal (..\\)"),
    (r"\.\.%2f", "Path Traversal (URL encoded ../)"),
    (r"\.\.%252f", "Path Traversal (double URL encoded)"),
    # SQL
    (r"'|\"|--|;#|/\*", "SQL Injection pattern"),
    (r"union\s+select", "SQL UNION injection"),
    (r"sleep\(\d", "SQL time-based injection"),
    (r"1=1|1=2|1'='1", "SQL tautology"),
    # XSS
    (r"<script>", "XSS pattern"),
    (r"onerror=|onload=|onclick=", "XSS event handler"),
    # SSTI
    (r"\{\{.*\}\}", "SSTI pattern (Jinja2/Twig)"),
    (r"#\{.*\}", "SSTI pattern (Ruby)"),
    (r"\$\{.*\}", "SSTI pattern (Freemarker)"),
    # Command injection
    (r";\s*(id|whoami|ls|cat|pwd|dir)", "Command injection"),
    (r"`.*`", "Backtick command injection"),
    (r"\$\(.*\)", "Subshell command injection"),
    # SSRF
    (r"https?://\d+\.\d+\.\d+\.\d+", "SSRF (IP URL)"),
    (
        r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|"
        r"10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168\.)",
        "SSRF (internal)",
    ),
    (r"file:///", "File protocol SSRF"),
]


# ============================================================
# Burp 历史解析
# ============================================================


def parse_burp_history(raw_data):
    """
    解析 Burp MCP 返回的代理历史数据。
    支持格式:
    - JSON 数组: [{url, method, request, response, status, length, ...}]
    - JSON lines: 每行一个请求对象
    """
    if isinstance(raw_data, str):
        raw_data = raw_data.strip()

    if not raw_data:
        return []

    # Try JSON array
    try:
        data = json.loads(raw_data)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "requests" in data:
            return data["requests"]
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return [data]
    except json.JSONDecodeError:
        pass

    # Try JSON lines
    items = []
    for line in raw_data.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return items


# ============================================================
# 核心分析
# ============================================================


class SurfaceAnalyzer:
    def __init__(self, requests):
        self.requests = requests
        self.url_map = defaultdict(list)  # path prefix → requests
        self.method_counts = Counter()
        self.status_counts = Counter()
        self.param_freq = Counter()  # 参数名频率
        self.param_values = defaultdict(set)  # 参数名 → 取值集合
        self.path_depth = defaultdict(int)  # 路径深度统计
        self.auth_tokens = set()  # 发现的认证 token
        self.hosts = set()

    def analyze(self):
        for req in self.requests:
            self._analyze_request(req)
        return self._build_report()

    def _analyze_request(self, req):
        url = req.get("url", "") or req.get("path", "")
        if not url:
            return

        parsed = urlparse(url)
        self.hosts.add(parsed.netloc)

        method = req.get("method", "GET").upper()
        self.method_counts[method] += 1

        status = req.get("status", req.get("response_status", 0))
        if isinstance(status, int):
            self.status_counts[status] += 1

        path = parsed.path
        self.path_depth[path] += 1

        # 按路径前缀分组
        parts = path.strip("/").split("/")
        for i in range(1, min(len(parts) + 1, 5)):
            prefix = "/" + "/".join(parts[:i])
            self.url_map[prefix].append(url)

        # 参数分析
        params = parse_qs(parsed.query)
        for name, values in params.items():
            name_lower = name.lower()
            self.param_freq[name_lower] += 1
            for v in values:
                decoded = unquote(v)
                self.param_values[name_lower].add(decoded)

            # 检测认证 token
            if name_lower in ("token", "access_token", "jwt", "session", "auth"):
                for v in values:
                    if len(v) > 20:
                        self.auth_tokens.add(name_lower)

        # 请求体参数分析
        body = req.get("body", req.get("request_body", ""))
        if isinstance(body, str) and body.strip():
            # JSON body
            if body.strip().startswith(("{", "[")):
                try:
                    body_json = json.loads(body)
                    self._extract_json_params(body_json, "")
                except json.JSONDecodeError:
                    pass
            # Form body
            elif "=" in body:
                for part in body.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        self.param_freq[k.lower()] += 1
                        decoded = unquote(v)
                        self.param_values[k.lower()].add(decoded)

    def _extract_json_params(self, obj, prefix):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                self.param_freq[full_key] += 1
                if isinstance(v, (str, int, float, bool)):
                    self.param_values[full_key].add(str(v))
                elif isinstance(v, (dict, list)):
                    self._extract_json_params(v, full_key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:5]):
                self._extract_json_params(item, f"{prefix}[{i}]")

    def _build_report(self):
        report = {
            "summary": self._build_summary(),
            "endpoint_tree": self._build_endpoint_tree(),
            "parameters": self._build_param_analysis(),
            "suspicious_findings": self._find_suspicious_params(),
            "test_hypotheses": [],
            "attack_surface": self._build_attack_surface(),
        }
        report["test_hypotheses"] = self._generate_hypotheses(report)
        return report

    def _build_summary(self):
        return {
            "total_requests": len(self.requests),
            "unique_hosts": sorted(self.hosts),
            "methods": dict(self.method_counts.most_common()),
            "status_codes": dict(self.status_counts.most_common()),
            "unique_params": len(self.param_freq),
            "unique_paths": len(self.path_depth),
        }

    def _build_endpoint_tree(self):
        """构建端点结构树"""
        tree = {}
        for path, urls in sorted(self.url_map.items()):
            parts = path.strip("/").split("/")
            current = tree
            for p in parts:
                if p not in current:
                    current[p] = {}
                current = current[p]
            current["_urls"] = len(urls)
            current["_methods"] = []
            for u in urls:
                for req in self.requests:
                    if req.get("url", "").startswith(u):
                        m = req.get("method", "GET")
                        if m not in current["_methods"]:
                            current["_methods"].append(m)
        return tree

    def _build_param_analysis(self):
        params = []
        for name, freq in self.param_freq.most_common(50):
            values = list(self.param_values.get(name, set()))[:5]
            is_suspicious = name in SUSPICIOUS_PARAM_NAMES
            params.append(
                {
                    "name": name,
                    "frequency": freq,
                    "sample_values": values[:5],
                    "suspicious": is_suspicious,
                }
            )
        return params

    def _find_suspicious_params(self):
        findings = []
        for name, values in self.param_values.items():
            for v in values:
                for pattern, label in SUSPICIOUS_PARAM_VALUES:
                    if re.search(pattern, v, re.IGNORECASE):
                        findings.append(
                            {
                                "param": name,
                                "value_preview": v[:80],
                                "pattern": label,
                            }
                        )
                        break
        return findings[:30]  # 限制输出数量

    def _generate_hypotheses(self, report):
        hypotheses = []

        # 1. 从可疑参数名生成测试假设
        suspicious_params = [p["name"] for p in report["parameters"] if p["suspicious"]]
        if suspicious_params:
            hypotheses.append(
                {
                    "type": "参数注入测试",
                    "targets": suspicious_params[:10],
                    "description": "以下参数常见于注入类漏洞，值得手工测试 payload",
                    "priority": "高",
                }
            )

        # 2. 从参数值中的模式生成假设
        if report["suspicious_findings"]:
            patterns = list(set(f["pattern"] for f in report["suspicious_findings"]))
            hypotheses.append(
                {
                    "type": "参数值异常",
                    "targets": patterns[:5],
                    "description": "请求中已包含可疑 payload 模式，需确认是否已存在漏洞或 WAF 未拦截",
                    "priority": "高",
                }
            )

        # 3. 路径遍历探测
        path_parts = set()
        for path in self.path_depth:
            parts = path.strip("/").split("/")
            for _, p in enumerate(parts):
                if len(p) > 30 and ("/" in p):
                    path_parts.add(p[:50])
        if path_parts:
            hypotheses.append(
                {
                    "type": "路径遍历/IDOR",
                    "targets": list(path_parts)[:5],
                    "description": "检测到较长/复杂路径片段，尝试遍历或替换",
                    "priority": "中",
                }
            )

        # 4. 未授权访问
        # 如果有多个不同 path 但同 host，检查是否有不需要认证就能访问的
        hypotheses.append(
            {
                "type": "越权/未授权",
                "targets": sorted(self.hosts),
                "description": "建议将同一端点的不同用户请求对比，检查响应差异",
                "priority": "中",
            }
        )

        # 5. 调试端点
        debug_paths = [
            p
            for p in self.path_depth
            if any(kw in p.lower() for kw in ["debug", "test", "mock", "dev", "staging", "internal", "admin"])
        ]
        if debug_paths:
            hypotheses.append(
                {
                    "type": "调试/管理端点",
                    "targets": debug_paths[:5],
                    "description": "检测到疑似调试或管理后台端点，值得深入测试",
                    "priority": "中",
                }
            )

        return hypotheses

    def _build_attack_surface(self):
        """构建攻击面摘要"""
        return {
            "param_count": len(self.param_freq),
            "path_count": len(self.path_depth),
            "suspicious_param_count": sum(1 for n in self.param_freq if n in SUSPICIOUS_PARAM_NAMES),
            "suspicious_value_count": len(
                [
                    1
                    for n, v in self.param_values.items()
                    for val in v
                    if any(re.search(p, val, re.IGNORECASE) for p, _ in SUSPICIOUS_PARAM_VALUES)
                ]
            ),
        }


# ============================================================
# CLI 入口
# ============================================================


def main():
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
        raw = Path(input_path).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()

    if not raw.strip():
        print(json.dumps({"error": "No input data"}, ensure_ascii=False, indent=2))
        sys.exit(1)

    requests = parse_burp_history(raw)

    if not requests:
        print(json.dumps({"error": "Could not parse any requests from input"}, ensure_ascii=False, indent=2))
        sys.exit(1)

    analyzer = SurfaceAnalyzer(requests)
    report = analyzer.analyze()

    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
