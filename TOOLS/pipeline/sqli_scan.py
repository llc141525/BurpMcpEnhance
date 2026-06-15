"""SQLmap 包装器：读 DB 含参 URL → sqlmap 扫描 → WAF 轮转 → 写 findings。

用法:
  uv run python TOOLS/pipeline/sqli_scan.py --target "台州学院" --batch 5
  uv run python TOOLS/pipeline/sqli_scan.py --target "台州学院" --url "https://example.com/api?id=1"
"""

from __future__ import annotations

import re
import sys
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
