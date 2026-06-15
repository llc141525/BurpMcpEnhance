---
name: mmx-router
description: SRC 项目的 MiniMax CLI token 路由协议。定义何时必须把数据交给 mmx 处理而非 Claude 直读，以及安全测试专用 prompt 模板。供 stealth-scanner 和 vuln-review 引用。
allowed-tools: Bash
---

# mmx-router

SRC 漏洞挖掘场景的 mmx 使用规范。通用 mmx CLI 用法见全局 `mmx-cli` skill；本 skill 只定义**何时强制路由给 mmx** 以及**在安全场景下用哪些 prompt**。

## 核心原则

**Claude 不读原始噪音数据。** 以下数据源必须先交给 mmx 处理，Claude 只读 mmx 返回的精简结果。

¹ **JS 文件两层处理规则**：URL 端点提取由 `js_analyzer.py` 的 JSFinder 层（正则）完成，直接写入 `pages` 表，**不调 mmx**。只有文件内容含高价值密钥信号（`api_key / secret / token / auth / Bearer / accessKey / appSecret / REACT_APP_ / VUE_APP_` 等关键词）时，才将文件内容送 mmx 做深度分析。触发条件是**信号存在**，不是文件大小阈值。

## 路由规则

| 数据源 | 阈值 | mmx 任务 |
|--------|------|---------|
| Burp HTTP 历史查询结果 | 任意大小 | 提取目标 URL / 参数列表 |
| DB 查询结果（scanner.db） | >10 行 | 筛选可疑/异常记录 |
| JS 文件内容 | 含密钥信号¹ | 提取 API 端点/硬编码密钥/敏感参数（URL 提取已由 JSFinder 层完成，无需 mmx） |
| HTML 页面内容 | >5KB | 提取表单/链接/注释 |
| Burp HTTP 响应体 | >5KB | 提取关键字段/差异 |
| 图片/截图理解 | 任意 | `mmx vision describe` |

## Web Search

不使用 mmx 进行 web search。需要搜索时直接使用 Claude 内置 `WebSearch` 工具。

mmx 仅用于：
- `mmx text chat` — 大文本 ETL（Burp 历史过滤、DB 结果摘要、大 JS/HTML 提取）
- `mmx vision describe` — 图片理解、验证码识别

## Agent 标准调用格式

```bash
# 文本分析（最常用）
mmx text chat --message "任务说明：\n数据内容" --output text --non-interactive

# 大文件内容分析（先写临时文件）
mmx text chat --message "$(cat /tmp/data.txt)" --output text --non-interactive

# 图片/截图理解
mmx vision describe --image /path/to/screenshot.png --prompt "提取页面中的表单字段和API端点" --output text --non-interactive
```

> **Windows 下 stdin 管道失效**：`--messages-file -` 在 Windows 上报 `ENOENT: no such file or directory, open 'E:\\dev\\stdin'`。必须用 `--message "$(cat file)"` 或先写临时 JSON 文件再用 `--messages-file /tmp/msg.json`。

## 安全场景 Prompt 模板

以下模板均已验证可直接使用。

### Burp 历史过滤

```bash
mmx text chat --output text --non-interactive --message "从以下Burp代理历史中提取所有API端点（路径+参数名），JSON格式，字段：url, params:
{BURP_HISTORY_TEXT}"
```

### JS 文件分析

```bash
mmx text chat --output text --non-interactive --message "从以下JS代码提取：1.API端点 2.硬编码密钥/token 3.敏感参数名。JSON输出，字段：apis(数组), secrets(数组), sensitive_params(数组)：
$(cat /tmp/target.js)"
```

### DB 结果筛选

```bash
mmx text chat --output text --non-interactive --message "以下是数据库查询结果，请标出其中测试状态异常、风险等级High、或参数名可疑（含file/path/uid/cmd/role等）的记录，只输出可疑行：
{DB_QUERY_OUTPUT}"
```

### HTML 页面提取

```bash
mmx text chat --output text --non-interactive --message "从以下HTML提取：1.所有表单（action, method, 字段名）2.外链API URL 3.注释中的敏感信息。JSON输出：
$(cat /tmp/page.html)"
```

### PoC 响应差异分析

```bash
mmx text chat --output text --non-interactive --message "对比以下两个HTTP响应，判断是否存在安全漏洞（如IDOR/注入/信息泄露），说明差异和判断依据：
=== 基准请求响应 ===
{BASELINE_RESPONSE}
=== 测试请求响应 ===
{TEST_RESPONSE}"
```

### 业务端点意图分类（business-logic-hunt / manual-replay collecting 阶段）

```bash
mmx text chat --output text --non-interactive --message "你是 SRC 渗透测试助手，从 Burp HTTP 历史列表筛选业务接口。
输出 JSON 数组，每条: {\"burp_history_id\":<int>,\"method\":\"POST\",\"url\":\"...\",\"endpoint_type\":\"business_api|auth_login|auth_register|auth_reset_password|auth_verify_code\",\"business_intent\":\"一句话业务含义\",\"risk_hint\":\"High|Medium|Low\"}
判定: auth_*: URL含login/register/reset/sms/captcha; business_api: /api/或.do/.action且非登录; risk=High: 含id/uid/oid参数或DELETE/PUT; Low: 字典/枚举无参数
排除: 第三方CDN/统计/广告; 同URL去重保留risk最高; health check/version端点
返回纯JSON，无markdown围栏:
$(cat {BURP_HISTORY_FILE})"
```

### HTTP 请求流程分析（manual-replay analyze 阶段）

```bash
mmx text chat --output text --non-interactive --message "分析以下 HTTP 请求序列，识别业务流程链，输出 JSON:
{\"flow_chains\":[{\"chain_id\":1,\"steps\":[1,2,3],\"flow_name\":\"创建订单流程\",\"state_params\":{\"order_id\":\"请求2响应→请求3请求\"},\"auth_context\":\"primary\"}],\"cross_request_params\":[{\"param_name\":\"token\",\"source_request_id\":1,\"target_request_id\":2}]}
规则: flow_chains 识别 flow_step>0 的连续请求链; state_params 标注跨请求传递参数; cross_request_params 同参数名在相邻请求间的位置:
$(cat {REQUESTS_FILE})"
```

### 安全测试变种生成（manual-replay variant_gen 阶段）

```bash
mmx text chat --output text --non-interactive --message "给定 HTTP 请求及业务意图，生成安全测试变种，输出 JSON 数组（5-15条）:
[{\"test_type\":\"idor|unauth|param_logic|user_enum|captcha_reuse|password_reset_takeover|info_leak\",\"target_param\":\"参数名\",\"original_value\":\"原始值\",\"replacement_value\":\"替换值\",\"modification\":\"replace_param|remove_auth|replace_cookie|remove_param|add_param\",\"description\":\"变种说明\"}]
业务意图→变种映射: 订单创建/查询→idor+unauth+param_logic; 登录→user_enum; 验证码→captcha_reuse; 密码重置→password_reset_takeover; 用户信息→idor+info_leak
返回纯JSON，无markdown围栏:
$(cat {REQUEST_CONTEXT_FILE})"
```

## 与 MCP 的分工

| 工具 | 适用场景 |
|------|---------|
| `mmx text chat`（CLI） | 数据分析、文本提取、JSON处理 — 本 skill 的主力 |
| `mcp__MiniMax__understand_image` | 图片理解（与 `mmx vision describe` 等效，MCP 版） |
| Claude 内置 `WebSearch` | 联网搜索 — 不再使用 mmx search / mcp__MiniMax__web_search |
