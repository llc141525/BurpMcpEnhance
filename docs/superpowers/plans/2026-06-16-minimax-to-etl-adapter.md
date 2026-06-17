# MiniMax → ETL Adapter 迁移实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 DeepSeek adapter 替换 MiniMax 文本ETL，删除 mmx MCP，更新所有 skill 和文档引用。

**Architecture:** 新建 `TOOLS/utils/etl_analyzer.py` 暴露 `analyze(task, data) -> str` 接口，内部调 DeepSeek API（OpenAI兼容）。所有 skill 文件和 CLAUDE.md 将 `mmx text chat` 引用替换为 `etl_analyzer`，图像和搜索改为 Claude 直接执行。

**Tech Stack:** Python 3.11+, openai SDK (DeepSeek OpenAI-compat API), uv, pytest, SQLite (不变)

---

## File Map

| 操作 | 文件 |
|------|------|
| 新建 | `TOOLS/utils/etl_analyzer.py` |
| 新建 | `TOOLS/tests/test_etl_analyzer.py` |
| 修改 | `.claude/settings.local.json` |
| 修改 | `CLAUDE.md` |
| 修改 | `AGENTS.md` |
| 重写 | `.claude/skills/mmx-router/SKILL.md` |
| 修改 | `.claude/skills/business-logic-hunt/SKILL.md` |
| 修改 | `.claude/skills/manual-replay/SKILL.md` |
| 修改 | `.claude/skills/stealth-scanner/SKILL.md` |
| 修改 | `.claude/skills/vuln-review/SKILL.md` |
| 修改 | `.claude/skills/src-report/SKILL.md` |
| 修改 | `.claude/skills/asset-recon/SKILL.md` |

---

## Task 1: 安装 openai 依赖

**Files:**
- Modify: `pyproject.toml` (via uv)

- [ ] **Step 1: 安装 openai 包**

```bash
uv add openai
```

Expected: `pyproject.toml` 中出现 `openai` 依赖，`.venv` 已安装。

- [ ] **Step 2: 验证可导入**

```bash
uv run python -c "from openai import OpenAI; print('ok')"
```

Expected: 打印 `ok`。

---

## Task 2: 创建 etl_analyzer.py（TDD — 先写测试）

**Files:**
- Create: `TOOLS/tests/test_etl_analyzer.py`
- Create: `TOOLS/utils/etl_analyzer.py`

- [ ] **Step 1: 写失败测试**

新建 `TOOLS/tests/test_etl_analyzer.py`：

```python
"""Unit tests for etl_analyzer.py"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.etl_analyzer import analyze


@pytest.fixture
def mock_deepseek(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API", "test-key-xxx")
    with patch("utils.etl_analyzer.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"result": "test"}'
        mock_client.chat.completions.create.return_value = mock_response
        yield mock_client


def test_analyze_filter_burp_returns_string(mock_deepseek):
    result = analyze("filter_burp", '{"url": "/api/test"}')
    assert result == '{"result": "test"}'
    mock_deepseek.chat.completions.create.assert_called_once()


def test_analyze_uses_correct_model(mock_deepseek):
    analyze("filter_burp", "data")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    assert call_kwargs["model"] == "deepseek-chat"


def test_analyze_unknown_task_raises_value_error(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API", "test-key-xxx")
    with pytest.raises(ValueError, match="Unknown task"):
        analyze("nonexistent_task", "data")


def test_analyze_missing_api_key_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API", raising=False)
    with pytest.raises(RuntimeError, match="DEEPSEEK_API"):
        analyze("filter_burp", "data")


def test_analyze_instruction_prepended_to_data(mock_deepseek):
    analyze("filter_burp", "raw_data", instruction="extra context")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    user_msg = call_kwargs["messages"][1]["content"]
    assert "extra context" in user_msg
    assert "raw_data" in user_msg


def test_analyze_no_instruction_sends_data_only(mock_deepseek):
    analyze("filter_burp", "raw_data")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    user_msg = call_kwargs["messages"][1]["content"]
    assert user_msg == "raw_data"


@pytest.mark.parametrize("task", [
    "filter_burp",
    "analyze_js",
    "filter_db",
    "extract_endpoints",
    "classify_business",
    "analyze_flow",
    "generate_variants",
    "diff_responses",
])
def test_all_tasks_have_system_prompts(task, mock_deepseek):
    result = analyze(task, "sample data")
    assert result is not None
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    system_msg = call_kwargs["messages"][0]["content"]
    assert len(system_msg) > 10
```

- [ ] **Step 2: 运行测试确认失败**

```bash
uv run pytest TOOLS/tests/test_etl_analyzer.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'utils.etl_analyzer'`

- [ ] **Step 3: 实现 etl_analyzer.py**

新建 `TOOLS/utils/etl_analyzer.py`：

```python
"""
ETL Adapter: DeepSeek-backed text analysis for SRC vulnerability hunting.
Replaces mmx text chat as the primary data ETL engine.

Usage (Python):
    from utils.etl_analyzer import analyze
    result = analyze("filter_burp", raw_json_text)

Usage (CLI):
    uv run python TOOLS/utils/etl_analyzer.py --task filter_burp < data.json
    uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat file.js)"
"""
import argparse
import os
import sys

from openai import OpenAI

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

_SYSTEM_PROMPTS: dict[str, str] = {
    "filter_burp": (
        "从以下Burp代理历史中提取所有API端点（路径+参数名），"
        "JSON格式，字段：url(string), params(array of string)。"
        "排除第三方CDN/统计/广告。返回纯JSON数组，无markdown围栏。"
    ),
    "analyze_js": (
        "从以下JS代码提取：1.API端点 2.硬编码密钥/token 3.敏感参数名。"
        "JSON输出，字段：apis(数组), secrets(数组), sensitive_params(数组)。"
        "返回纯JSON，无markdown围栏。"
    ),
    "filter_db": (
        "以下是数据库查询结果，请标出其中测试状态异常、风险等级High、"
        "或参数名可疑（含file/path/uid/cmd/role等）的记录，"
        "只输出可疑行，保留原始格式。"
    ),
    "extract_endpoints": (
        "从以下HTML提取：1.所有表单（action, method, 字段名）"
        "2.外链API URL 3.注释中的敏感信息。"
        "JSON输出，字段：forms(数组), api_urls(数组), sensitive_comments(数组)。"
        "返回纯JSON，无markdown围栏。"
    ),
    "classify_business": (
        "你是SRC渗透测试助手，从Burp HTTP历史列表筛选业务接口。"
        "输出JSON数组，每条: {\"burp_history_id\":<int>,\"method\":\"POST\","
        "\"url\":\"...\",\"endpoint_type\":\"business_api|auth_login|auth_register"
        "|auth_reset_password|auth_verify_code\",\"business_intent\":\"一句话业务含义\","
        "\"risk_hint\":\"High|Medium|Low\",\"flow_step\":<int>,\"auth_required\":true|false}\n"
        "判定: auth_*: URL含login/register/reset/sms/captcha; "
        "business_api: /api/或.do/.action且非登录; "
        "risk=High: 含id/uid/oid参数或DELETE/PUT; Low: 字典/枚举无参数\n"
        "排除: 第三方CDN/统计/广告; 同URL去重保留risk最高; health check/version端点\n"
        "返回纯JSON，无markdown围栏。"
    ),
    "analyze_flow": (
        "分析以下HTTP请求序列，识别业务流程链，输出JSON:\n"
        "{\"flow_chains\":[{\"chain_id\":1,\"steps\":[1,2,3],\"flow_name\":\"创建订单流程\","
        "\"state_params\":{\"order_id\":\"请求2响应→请求3请求\"},\"auth_context\":\"primary\"}],"
        "\"cross_request_params\":[{\"param_name\":\"token\","
        "\"source_request_id\":1,\"target_request_id\":2}]}\n"
        "规则: flow_chains 识别 flow_step>0 的连续请求链; "
        "state_params 标注跨请求传递参数。返回纯JSON，无markdown围栏。"
    ),
    "generate_variants": (
        "给定HTTP请求及业务意图，生成安全测试变种，输出JSON数组（5-15条）:\n"
        "[{\"test_type\":\"idor|unauth|param_logic|user_enum|captcha_reuse"
        "|password_reset_takeover|info_leak\","
        "\"target_param\":\"参数名\",\"original_value\":\"原始值\","
        "\"replacement_value\":\"替换值\","
        "\"modification\":\"replace_param|remove_auth|replace_cookie|remove_param|add_param\","
        "\"description\":\"变种说明\"}]\n"
        "业务意图→变种映射: 订单创建/查询→idor+unauth+param_logic; "
        "登录→user_enum; 验证码→captcha_reuse; "
        "密码重置→password_reset_takeover; 用户信息→idor+info_leak\n"
        "返回纯JSON，无markdown围栏。"
    ),
    "diff_responses": (
        "对比以下两个HTTP响应，判断是否存在安全漏洞（如IDOR/注入/信息泄露），"
        "说明差异和判断依据。输出格式：{\"has_vuln\": true|false, "
        "\"vuln_type\": \"类型或null\", \"evidence\": \"差异说明\", "
        "\"confidence\": \"High|Medium|Low\"}"
    ),
}


def analyze(task: str, data: str, instruction: str = "") -> str:
    """Call DeepSeek to perform ETL analysis on data.

    Args:
        task: One of the keys in _SYSTEM_PROMPTS.
        data: Raw text to analyze (JSON, JS, HTML, SQL output, etc.).
        instruction: Optional extra instruction prepended to data.

    Returns:
        DeepSeek response text (typically JSON).

    Raises:
        RuntimeError: If DEEPSEEK_API env var is not set.
        ValueError: If task is not a recognized task name.
    """
    api_key = os.environ.get("DEEPSEEK_API")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API environment variable not set")

    system_prompt = _SYSTEM_PROMPTS.get(task)
    if not system_prompt:
        valid = list(_SYSTEM_PROMPTS.keys())
        raise ValueError(f"Unknown task: {task!r}. Valid tasks: {valid}")

    client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
    user_content = f"{instruction}\n{data}" if instruction else data

    response = client.chat.completions.create(
        model=DEEPSEEK_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        temperature=0.1,
        max_tokens=4096,
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL text analyzer via DeepSeek")
    parser.add_argument(
        "--task",
        required=True,
        choices=list(_SYSTEM_PROMPTS.keys()),
        help="Analysis task type",
    )
    parser.add_argument("--instruction", default="", help="Additional instruction")
    parser.add_argument("--data", default=None, help="Data to analyze (or stdin)")
    args = parser.parse_args()

    raw_data = args.data if args.data is not None else sys.stdin.read()
    print(analyze(args.task, raw_data, args.instruction))
```

- [ ] **Step 4: 运行测试确认通过**

```bash
uv run pytest TOOLS/tests/test_etl_analyzer.py -v
```

Expected: 全部 PASS（15个测试）。

- [ ] **Step 5: Commit**

```bash
git add TOOLS/utils/etl_analyzer.py TOOLS/tests/test_etl_analyzer.py
git commit -m "feat: add etl_analyzer.py DeepSeek adapter replacing mmx text chat"
```

---

## Task 3: 删除 MiniMax MCP 配置

**Files:**
- Modify: `.claude/settings.local.json`

- [ ] **Step 1: 删除 allow 列表中的 minimax 权限**

在 `.claude/settings.local.json` 中，找到并删除这一行：

```
      "mcp__minimax__*"
```

（位于 `permissions.allow` 数组中，约第74行）

- [ ] **Step 2: 删除 enabledMcpjsonServers 中的 MiniMax**

在同文件的 `enabledMcpjsonServers` 数组中，找到并删除：

```
    "MiniMax"
```

- [ ] **Step 3: 验证 JSON 格式正确**

```bash
uv run python -c "import json; json.load(open('.claude/settings.local.json')); print('valid JSON')"
```

Expected: `valid JSON`

- [ ] **Step 4: Commit**

```bash
git add .claude/settings.local.json
git commit -m "chore: remove MiniMax MCP from settings"
```

---

## Task 4: 重写 mmx-router skill 为 etl-router

**Files:**
- Modify: `.claude/skills/mmx-router/SKILL.md` (完整重写)

- [ ] **Step 1: 用新内容覆盖 SKILL.md**

将 `.claude/skills/mmx-router/SKILL.md` 全文替换为：

```markdown
---
name: mmx-router
description: SRC 项目的文本ETL路由协议。定义何时调用 etl_analyzer.py 处理数据而非 Claude 直读，以及各 task 的适用场景。供 stealth-scanner、vuln-review、business-logic-hunt、manual-replay 引用。
allowed-tools: Bash
---

# etl-router

SRC 漏洞挖掘场景的文本ETL规范。定义**何时必须用 `etl_analyzer.py` 处理数据**，以及使用哪个 task。

## 核心原则

**Claude 不读原始噪音数据。** 以下数据源必须先交给 `etl_analyzer.py` 处理，Claude 只读返回的精简结果。

## 路由规则

| 数据源 | 阈值 | etl_analyzer task |
|--------|------|-------------------|
| Burp HTTP 历史查询结果 | 任意大小 | `filter_burp` |
| DB 查询结果 | >10 行 | `filter_db` |
| JS 文件内容 | 含密钥信号¹ | `analyze_js` |
| HTML 页面内容 | >5KB | `extract_endpoints` |
| 业务接口意图分类 | 任意 | `classify_business` |
| HTTP 请求流程分析 | 任意 | `analyze_flow` |
| 安全测试变种生成 | 任意 | `generate_variants` |
| PoC 响应差异对比 | 任意 | `diff_responses` |

¹ **JS 两层处理规则**：URL 端点提取由 `js_analyzer.py` 的正则层完成，直接写入 `pages` 表，**不调 etl_analyzer**。只有含密钥信号（`api_key / secret / token / auth / Bearer / accessKey / appSecret / REACT_APP_ / VUE_APP_`）时，才将文件内容送 `analyze_js`。

## 图像理解 / 联网搜索

- **图像/截图**：直接用 Claude 的 `Read` 工具读取图片文件（Claude 是多模态的）
- **联网搜索**：直接用 Claude 内置 `WebSearch` 工具

## 调用方式

```bash
# CLI 调用（stdin 输入）
echo "{burp_json}" | uv run python TOOLS/utils/etl_analyzer.py --task filter_burp

# CLI 调用（--data 参数）
uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat /tmp/target.js)"

# 加额外指令
uv run python TOOLS/utils/etl_analyzer.py --task classify_business \
  --instruction "额外要求：每条增加 flow_step 字段" \
  --data "$(cat /tmp/burp_history.json)"
```

## Python 调用（脚本内）

```python
import sys
sys.path.insert(0, "TOOLS")
from utils.etl_analyzer import analyze

result = analyze("filter_burp", raw_burp_json)
result = analyze("classify_business", burp_json, instruction="额外要求：...")
```

## Task 一览

| task | 用途 |
|------|------|
| `filter_burp` | 过滤Burp历史，提取目标URL/参数列表 |
| `analyze_js` | 提取JS中的API端点、硬编码密钥、敏感参数 |
| `filter_db` | 筛选DB查询结果中的可疑/异常记录 |
| `extract_endpoints` | 从HTML提取表单/API URL/注释 |
| `classify_business` | 业务接口意图分类（business_api/auth_*/admin_api等）|
| `analyze_flow` | 识别HTTP请求序列中的业务流程链 |
| `generate_variants` | 生成安全测试变种（IDOR/unauth/param_logic等）|
| `diff_responses` | 对比两个HTTP响应判断安全差异 |
```

- [ ] **Step 2: Commit**

```bash
git add ".claude/skills/mmx-router/SKILL.md"
git commit -m "refactor: rewrite mmx-router skill as etl-router (DeepSeek adapter)"
```

---

## Task 5: 更新 CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: 删除工具资源表中的 MiniMax 行**

找到并删除以下两行（约第68-69行）：

```
| **MiniMax MCP**   | `web_search` / `understand_image`                              | **省 Token 主力**: 搜索 + 图片理解 + 文本处理（DB 结果分析、Burp 历史过滤、大文件摘要） |
| **mmx CLI**       | `mmx vision describe` / `mmx search query` / `mmx text chat` | **补充工具**: 图像理解、搜索、文本对话（配合 Skill 使用）                               |
```

- [ ] **Step 2: 更新 Burp Suite 行（删除 MiniMax 提及）**

找到（约第62行）：

```
| Burp Suite              | `list_proxy_http_history` + `get_proxy_http_detail`            | 流量分析+参数篡改+漏洞验证。**结果不直接读，喂 MiniMax 过滤**                           |
```

替换为：

```
| Burp Suite              | `list_proxy_http_history` + `get_proxy_http_detail`            | 流量分析+参数篡改+漏洞验证。**结果不直接读，喂 etl_analyzer.py 过滤**                    |
```

- [ ] **Step 3: 更新 js_analyzer.py 描述**

找到（约第78行）：

```
| `js_analyzer.py`              | **JS 批量分析**: mmx 提取端点/密钥 → suspicious_points                                                                                                                      |
```

替换为：

```
| `js_analyzer.py`              | **JS 批量分析**: 正则提取端点 + etl_analyzer 深度分析密钥信号 → suspicious_points                                                                                            |
```

- [ ] **Step 4: 重写"省 Token 策略"章节**

找到整个章节（约第105-130行）：

```
### 省 Token 策略 (MiniMax MCP + CLI)

高 Token 低智商的 ETL 任务全部交给 MiniMax：

```
┌──────────────────────────┬───────────────────────────────────┬─────────────┐
│ 场景                     │ 执行方                             │ 说明         │
├──────────────────────────┼───────────────────────────────────┼─────────────┤
│ Burp HTTP 历史查询结果   │ mmx text chat                     │ 喂原始 JSON，让 MiniMax 提取目标 URL/参数，Claude 只读摘要 │
│ DB 查询结果（>10 行）    │ mmx text chat                     │ 喂 SQL 结果集，让 MiniMax 筛选异常/可疑记录，Claude 只读筛选结果 │
│ 大 JS/HTML 文件（>5KB）  │ mmx text chat                     │ 喂文件内容，让 MiniMax 提取 API 端点/参数/敏感信息，Claude 只读提取结果 │
│ 联网搜索                 │ MiniMax MCP: web_search           │ 别用内置 WebSearch — DeepSeek 不支持                       │
│ 图片理解/验证码          │ MiniMax MCP: understand_image     │ 含截图分析、OCR                                            │
│ 验证码绕过               │ captcha_bypass.py (ddddocr)       │ 主力离线 OCR，不费 Token                                   │
└──────────────────────────┴───────────────────────────────────┴─────────────┘
```

**铁律**：Claude 不读原始噪音数据。Burp 历史、DB 结果集、大 JS/HTML — 先给 MiniMax 解析，Claude 只处理 MiniMax 返回的精简结果。

CLI 用法：

```
mmx text chat              → 喂任意文本，返回分析/筛选/提取结果
mmx vision describe <文件>  → 图片理解（本地文件/URL）
mmx search query <关键词>   → 联网搜索
```
```

替换为：

```
### ETL 分析策略 (etl_analyzer.py)

高 Token 低智商的 ETL 任务全部交给 `etl_analyzer.py`（DeepSeek驱动）：

| 场景 | task 参数 | 说明 |
|------|-----------|------|
| Burp HTTP 历史查询结果 | `filter_burp` | 喂原始 JSON，提取目标 URL/参数，Claude 只读摘要 |
| DB 查询结果（>10 行） | `filter_db` | 喂 SQL 结果集，筛选异常/可疑记录，Claude 只读筛选结果 |
| 大 JS/HTML 文件（含密钥信号） | `analyze_js` / `extract_endpoints` | 喂文件内容，提取端点/密钥/敏感信息，Claude 只读提取结果 |
| 业务接口分类 | `classify_business` | 分类 Burp 历史中的业务接口意图 |
| 流程分析 | `analyze_flow` | 识别请求序列中的业务流程链 |
| 变种生成 | `generate_variants` | 生成安全测试变种 |
| PoC 响应对比 | `diff_responses` | 对比两个HTTP响应判断漏洞 |

**铁律**：Claude 不读原始噪音数据。Burp 历史、DB 结果集、大 JS/HTML — 先给 etl_analyzer 解析，Claude 只处理返回的精简结果。

**联网搜索**：直接用 Claude 内置 `WebSearch` 工具。
**图像/截图理解**：直接用 Claude `Read` 工具读取图片（Claude 原生多模态）。

CLI 用法：
```bash
# 文本分析
echo "{json}" | uv run python TOOLS/utils/etl_analyzer.py --task filter_burp
uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat file.js)"
```
```

- [ ] **Step 5: 更新 manual-replay skill 描述（第147行附近）**

找到：

```
| **manual-replay**       | 操作员跑业务流程 → AI 变种攻击。时间窗口 Burp 采集 → mmx 分类 → 流分析 → 变种生成 → 三层执行 | `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5")` |
```

替换为：

```
| **manual-replay**       | 操作员跑业务流程 → AI 变种攻击。时间窗口 Burp 采集 → etl_analyzer 分类 → 流分析 → 变种生成 → 三层执行 | `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5")` |
```

- [ ] **Step 6: 更新业务逻辑猎手描述（第207行附近）**

找到：

```
- 读取 Burp 历史 → MiniMax 筛选业务接口
```

替换为：

```
- 读取 Burp 历史 → etl_analyzer 筛选业务接口
```

- [ ] **Step 7: 更新步骤描述（第220行附近）**

找到：

```
3. 时间窗口采集 Burp 历史 → MiniMax 分类业务意图
```

替换为：

```
3. 时间窗口采集 Burp 历史 → etl_analyzer 分类业务意图
```

- [ ] **Step 8: 重写"低智商高 Token 任务"章节**

找到（约第256-290行）整块：

```
### 低智商高 Token 任务 — 全部路由给 MiniMax

Claude 不读原始噪音数据。以下场景**必须**先经 `mmx text chat` 处理：

| 数据源                  | 如何喂给 MiniMax         | Claude 只读什么                     |
| ----------------------- | ------------------------ | ----------------------------------- |
| Burp HTTP 历史查询结果  | 将返回 JSON 文本直接喂入 | MiniMax 筛选后的目标 URL/参数列表   |
| DB 查询结果（>10 行）   | 将 SQL 输出文本喂入      | MiniMax 标注的可疑记录/异常行       |
| 大 JS/HTML 文件（>5KB） | 将文件内容文本喂入       | MiniMax 提取的 API 端点/参数/敏感词 |
| 页面爬取内容（HTML）    | 将 HTML 文本喂入         | MiniMax 提取的表单/链接/注释        |
```

替换为：

```
### 低智商高 Token 任务 — 全部路由给 etl_analyzer

Claude 不读原始噪音数据。以下场景**必须**先经 `etl_analyzer.py` 处理：

| 数据源 | task 参数 | Claude 只读什么 |
|--------|-----------|-----------------|
| Burp HTTP 历史查询结果 | `filter_burp` | etl_analyzer 筛选后的目标 URL/参数列表 |
| DB 查询结果（>10 行） | `filter_db` | etl_analyzer 标注的可疑记录/异常行 |
| 大 JS 文件（含密钥信号） | `analyze_js` | etl_analyzer 提取的 API 端点/参数/敏感词 |
| 页面爬取内容（HTML >5KB） | `extract_endpoints` | etl_analyzer 提取的表单/链接/注释 |
```

- [ ] **Step 9: 更新 Burp 查询规则**

找到：

```
- 结果直接喂 MiniMax 过滤，Claude 不读原始 JSON
```

替换为：

```
- 结果直接喂 etl_analyzer（task=filter_burp）过滤，Claude 不读原始 JSON
```

- [ ] **Step 10: 更新文件内容分析段落**

找到（约第284-290行）：

```
### 文件内容分析优先用 MiniMax

已抓到的 JS/HTML 文件（`js_files` 表、本地缓存），分析端点/参数/敏感信息时：

1. `Read` 读取文件文本（一次读取，不逐行交互）
2. 全文喂入 `mmx text chat`，让 MiniMax 提取：API 端点、参数名、敏感字符串、可能漏洞点
3. Claude 只处理 MiniMax 返回的提取结果，决定是否深入验证
```

替换为：

```
### 文件内容分析优先用 etl_analyzer

已抓到的 JS/HTML 文件（`js_files` 表、本地缓存），分析端点/参数/敏感信息时：

1. `Read` 读取文件文本（一次读取，不逐行交互）
2. 全文喂入 `etl_analyzer.py`（task=`analyze_js` 或 `extract_endpoints`），提取：API 端点、参数名、敏感字符串、可能漏洞点
3. Claude 只处理 etl_analyzer 返回的提取结果，决定是否深入验证
```

- [ ] **Step 11: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: replace MiniMax/mmx references with etl_analyzer in CLAUDE.md"
```

---

## Task 6: 更新 business-logic-hunt skill

**Files:**
- Modify: `.claude/skills/business-logic-hunt/SKILL.md`

- [ ] **Step 1: 删除 allowed-tools 中的 mcp__MiniMax__***

找到（第4行）：

```
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit
```

替换为：

```
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit
```

- [ ] **Step 2: 更新工具表中的 MiniMax 行**

找到：

```
| MiniMax | `mmx text chat --message` |
```

替换为：

```
| ETL分析 | `uv run python TOOLS/utils/etl_analyzer.py --task classify_business` |
```

- [ ] **Step 3: 更新意图分类步骤**

找到：

```
→ mmx 做业务意图分类（endpoint_type + business_intent）
```

替换为：

```
→ etl_analyzer（task=classify_business）做业务意图分类（endpoint_type + business_intent）
```

- [ ] **Step 4: 更新错误处理描述（两处）**

找到：

```
6. mmx JSON 解析失败 → 兜底提取 → 仍失败退出
```

替换为：

```
6. etl_analyzer JSON 解析失败 → 兜底提取 → 仍失败退出
```

找到：

```
- mmx 连续异常 → 退出
```

替换为：

```
- etl_analyzer 连续异常 → 退出
```

- [ ] **Step 5: Commit**

```bash
git add ".claude/skills/business-logic-hunt/SKILL.md"
git commit -m "refactor: replace mmx with etl_analyzer in business-logic-hunt skill"
```

---

## Task 7: 更新 manual-replay skill

**Files:**
- Modify: `.claude/skills/manual-replay/SKILL.md`

- [ ] **Step 1: 删除 allowed-tools 中的 mcp__MiniMax__***

找到（第4行）：

```
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit
```

替换为：

```
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit
```

- [ ] **Step 2: 更新工具表中的 MiniMax 行**

找到：

```
| MiniMax | `mmx text chat --message` |
```

替换为：

```
| ETL分析 | `uv run python TOOLS/utils/etl_analyzer.py --task <task>` |
```

- [ ] **Step 3: 重写 mmx 意图分类段落**

找到（约第103-112行）：

```
写入临时文件供 mmx 分析：
```bash
echo '{过滤后的JSON}' > tmp/manual_replay_raw_{target}_{ts}.json
```

### 3. mmx 意图分类

将过滤后的 JSON 写入 `tmp/manual_replay_raw_{target}_{ts}.json`，使用 `Skill(skill="mmx-router")` 的 **业务端点意图分类** 模板调用（注意：manual-replay 额外需要 `flow_step` 字段，在 prompt 末尾补充说明：`额外要求：每条增加 "flow_step":<int>，同一流程按顺序编号从1起，独立请求标0；以及 "auth_required":true|false`）。

输出容错：JSON 解析失败时从原始输出提取 `[...]` 块；仍失败则写入 `tmp/manual_replay_mmx_error_{ts}.txt` 后退出。
```

替换为：

```
写入临时文件供分析：
```bash
echo '{过滤后的JSON}' > tmp/manual_replay_raw_{target}_{ts}.json
```

### 3. etl_analyzer 意图分类

将过滤后的 JSON 写入 `tmp/manual_replay_raw_{target}_{ts}.json`，调用：

```bash
uv run python TOOLS/utils/etl_analyzer.py \
  --task classify_business \
  --instruction "额外要求：每条增加 flow_step 字段（同一流程按顺序从1起，独立请求标0）；以及 auth_required 字段（true|false）" \
  --data "$(cat tmp/manual_replay_raw_{target}_{ts}.json)"
```

输出容错：JSON 解析失败时从原始输出提取 `[...]` 块；仍失败则写入 `tmp/manual_replay_etl_error_{ts}.txt` 后退出。
```

- [ ] **Step 4: 更新流分析步骤**

找到：

```
将请求序列写入 `tmp/manual_replay_requests_{target}_{ts}.json`，使用 `Skill(skill="mmx-router")` 的 **HTTP 请求流程分析** 模板调用 mmx，输出写入 `tmp/manual_replay_flow_{target}_{ts}.json`。
```

替换为：

```
将请求序列写入 `tmp/manual_replay_requests_{target}_{ts}.json`，调用：

```bash
uv run python TOOLS/utils/etl_analyzer.py \
  --task analyze_flow \
  --data "$(cat tmp/manual_replay_requests_{target}_{ts}.json)" \
  > tmp/manual_replay_flow_{target}_{ts}.json
```
```

- [ ] **Step 5: 更新变种生成步骤**

找到：

```
对每个端点，将请求上下文（url/method/body/business_intent/risk_hint/auth_required/flow_chain/cross_request_params）写入 `tmp/manual_replay_req_{id}.json`，使用 `Skill(skill="mmx-router")` 的 **安全测试变种生成** 模板调用 mmx，对每个端点执行并汇总所有变种。
```

替换为：

```
对每个端点，将请求上下文（url/method/body/business_intent/risk_hint/auth_required/flow_chain/cross_request_params）写入 `tmp/manual_replay_req_{id}.json`，调用：

```bash
uv run python TOOLS/utils/etl_analyzer.py \
  --task generate_variants \
  --data "$(cat tmp/manual_replay_req_{id}.json)"
```

对每个端点执行并汇总所有变种。
```

- [ ] **Step 6: 更新错误处理（两处）**

找到：

```
| mmx 分类失败 | 内置兜底提取 → 仍失败则退出 |
```

替换为：

```
| etl_analyzer 分类失败 | 内置兜底提取 → 仍失败则退出 |
```

找到：

```
| mmx JSON 解析失败 | 内置兜底提取 → 仍失败则退出 |
```

替换为：

```
| etl_analyzer JSON 解析失败 | 内置兜底提取 → 仍失败则退出 |
```

找到：

```
- mmx 连续异常 → 退出
```

替换为：

```
- etl_analyzer 连续异常 → 退出
```

- [ ] **Step 7: 更新 description frontmatter**

找到（第3行）：

```
description: 操作员手工跑业务流程 → AI 变种攻击。时间窗口采集 Burp 历史 → mmx 分类 → 流分析 → 结构化变种生成 → 三层执行。覆盖 IDOR/未授权/参数逻辑/验证码复用/用户枚举/密码重置。
```

替换为：

```
description: 操作员手工跑业务流程 → AI 变种攻击。时间窗口采集 Burp 历史 → etl_analyzer 分类 → 流分析 → 结构化变种生成 → 三层执行。覆盖 IDOR/未授权/参数逻辑/验证码复用/用户枚举/密码重置。
```

- [ ] **Step 8: Commit**

```bash
git add ".claude/skills/manual-replay/SKILL.md"
git commit -m "refactor: replace mmx with etl_analyzer in manual-replay skill"
```

---

## Task 8: 更新 stealth-scanner、vuln-review、src-report、asset-recon skills

**Files:**
- Modify: `.claude/skills/stealth-scanner/SKILL.md`
- Modify: `.claude/skills/vuln-review/SKILL.md`
- Modify: `.claude/skills/src-report/SKILL.md`
- Modify: `.claude/skills/asset-recon/SKILL.md`

### stealth-scanner

- [ ] **Step 1: 删除 allowed-tools 中的 mcp__MiniMax__***

找到（第4行）：

```
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Grep, Glob, Skill
```

替换为：

```
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, Grep, Glob, Skill
```

- [ ] **Step 2: 更新 JS 分析描述**

找到：

```
| 单独 JS 分析（两层）              | `python TOOLS/js_analyzer.py --target "{目标}" --batch 5`（第1层正则提取URL写pages；第2层含密钥信号才送mmx）  |
```

替换为：

```
| 单独 JS 分析（两层）              | `python TOOLS/js_analyzer.py --target "{目标}" --batch 5`（第1层正则提取URL写pages；第2层含密钥信号才送etl_analyzer analyze_js）  |
```

- [ ] **Step 3: 替换"MiniMax 路由"章节**

找到：

```
## MiniMax 路由

遵循 `Skill(skill="mmx-router")` 的路由规则：何时必须把数据交给 mmx 处理、用哪些 prompt 模板。
```

替换为：

```
## ETL 分析路由

遵循 `Skill(skill="mmx-router")` 的路由规则：何时必须用 `etl_analyzer.py` 处理数据、用哪个 task。
```

### vuln-review

- [ ] **Step 4: 删除 vuln-review 的 mcp__MiniMax__***

找到（第4行）：

```
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Skill
```

替换为：

```
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, Skill
```

- [ ] **Step 5: 替换 vuln-review 的"MiniMax 路由"章节**

找到：

```
## MiniMax 路由

遵循 `Skill(skill="mmx-router")` 的路由规则。PoC 响应对比使用 mmx-router 的 **PoC 响应差异分析** 模板。
```

替换为：

```
## ETL 分析路由

遵循 `Skill(skill="mmx-router")` 的路由规则。PoC 响应对比使用 `etl_analyzer.py --task diff_responses`。
```

### src-report

- [ ] **Step 6: 删除 src-report 的 mcp__MiniMax__***

找到（第4行）：

```
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, AskUserQuestion, Glob, mcp__MiniMax__*
```

替换为：

```
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, AskUserQuestion, Glob
```

### asset-recon

- [ ] **Step 7: 删除 asset-recon 的 mcp__MiniMax__***

找到（第4行）：

```
allowed-tools: mcp__MiniMax__*, mcp__burp__*, Bash, PowerShell, Read, Write, Edit, Skill, Glob
```

替换为：

```
allowed-tools: mcp__burp__*, Bash, PowerShell, Read, Write, Edit, Skill, Glob
```

- [ ] **Step 8: 重写 asset-recon 的 Step 6 — MiniMax 解析结果**

找到整块（约第118-135行）：

```
### Step 6 — MiniMax 解析结果

对 FOFA 和 ZoomEye 的原始 JSON 输出，调用 MiniMax 解析：

```bash
# 合并两个结果文件，提取所有资产
mmx text chat --output text --non-interactive --message "从以下侦察结果中提取所有资产，输出纯 JSON 数组，每个元素包含：
{"domain": "子域名或IP", "ip": "IP", "port": 80/443, "tech_stack": "Apache/Vue/Spring等", "requires_auth": true/false, "notes": "备注"}
...
```
```

替换为：

```
### Step 6 — etl_analyzer 解析结果

对 FOFA 和 ZoomEye 的原始 JSON 输出，调用 etl_analyzer 解析：

```bash
# 合并两个结果文件，提取所有资产
cat tmp/fofa_{target}.json tmp/zoomeye_{target}.json > tmp/recon_combined_{target}.json
uv run python TOOLS/utils/etl_analyzer.py \
  --task filter_db \
  --instruction '从以下侦察结果中提取所有资产，输出纯 JSON 数组，每个元素包含：{"domain": "子域名或IP", "ip": "IP", "port": 80, "tech_stack": "Apache/Vue/Spring等", "requires_auth": true, "notes": "备注"}' \
  --data "$(cat tmp/recon_combined_{target}.json)"
```
```

- [ ] **Step 9: 更新 asset-recon 的 MiniMax 路由规则章节**

找到：

```
## MiniMax 路由规则

遵循 `mmx-router` skill 规范：
- FOFA/ZoomEye 结果文件 >10 行 → `mmx text chat` 解析
- Claude 不读原始 JSON，只处理 MiniMax 返回的精简 assets 数组
- 解析失败时回退到手动 JSON 解析（逐条读取 sample 字段）
```

替换为：

```
## ETL 分析路由规则

遵循 `mmx-router` skill 规范：
- FOFA/ZoomEye 结果文件 >10 行 → `etl_analyzer.py --task filter_db` 解析
- Claude 不读原始 JSON，只处理 etl_analyzer 返回的精简 assets 数组
- 解析失败时回退到手动 JSON 解析（逐条读取 sample 字段）
```

- [ ] **Step 10: Commit**

```bash
git add ".claude/skills/stealth-scanner/SKILL.md" ".claude/skills/vuln-review/SKILL.md" ".claude/skills/src-report/SKILL.md" ".claude/skills/asset-recon/SKILL.md"
git commit -m "refactor: replace mcp__MiniMax__ and mmx refs in 4 skills"
```

---

## Task 9: 同步更新 AGENTS.md

**Files:**
- Modify: `AGENTS.md`

- [ ] **Step 1: 批量替换 MiniMax/mmx 引用**

在 `AGENTS.md` 中执行与 CLAUDE.md 相同的替换。AGENTS.md 是 CLAUDE.md 的 Codex 镜像，结构完全相同。

逐一替换（对照 Task 5 的每个步骤，在 AGENTS.md 中找同样的文本并做同样的替换）：

1. 删除工具表中 MiniMax MCP 和 mmx CLI 两行
2. 更新 Burp Suite 行（`喂 MiniMax 过滤` → `喂 etl_analyzer.py 过滤`）
3. 更新 js_analyzer.py 描述
4. 重写省Token策略章节 → ETL分析策略
5. 更新 manual-replay 描述（`mmx 分类` → `etl_analyzer 分类`）
6. 更新业务逻辑猎手描述（`MiniMax 筛选` → `etl_analyzer 筛选`）
7. 更新步骤描述（`MiniMax 分类` → `etl_analyzer 分类`）
8. 重写"低智商高 Token 任务"章节
9. 更新 Burp 查询规则（`喂MiniMax` → `喂etl_analyzer`）
10. 更新文件内容分析段落

- [ ] **Step 2: Commit**

```bash
git add AGENTS.md
git commit -m "docs: sync AGENTS.md with CLAUDE.md etl_analyzer migration"
```

---

## Task 10: 验证

- [ ] **Step 1: 运行全部测试**

```bash
uv run pytest TOOLS/tests/ -v 2>&1 | tail -20
```

Expected: 所有现有测试 + 新增 etl_analyzer 测试全部 PASS，0 failures。

- [ ] **Step 2: 确认 mmx 引用清零**

```bash
grep -r "mmx text chat\|mcp__MiniMax\|mmx vision\|mmx search" CLAUDE.md AGENTS.md .claude/skills/ --include="*.md" -l
```

Expected: 无输出（0 个文件）。

- [ ] **Step 3: 确认 settings.local.json 无 MiniMax**

```bash
grep -i "minimax" .claude/settings.local.json
```

Expected: 无输出。

- [ ] **Step 4: etl_analyzer CLI 冒烟测试**

```bash
echo '{"test": "data"}' | uv run python TOOLS/utils/etl_analyzer.py --task filter_db
```

Expected: DeepSeek 返回分析结果（需要 `DEEPSEEK_API` 环境变量已设置）。

- [ ] **Step 5: 最终 Commit（如有未提交内容）**

```bash
git status
```

若有未提交文件，补充 commit。
