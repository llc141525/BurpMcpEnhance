---
name: mmx-router
description: SRC 项目的 MiniMax CLI token 路由协议。定义何时必须把数据交给 mmx 处理而非 Claude 直读，以及安全测试专用 prompt 模板。供 stealth-scanner 和 vuln-review 引用。
allowed-tools: Bash
---

# mmx-router

SRC 漏洞挖掘场景的 mmx 使用规范。通用 mmx CLI 用法见全局 `mmx-cli` skill；本 skill 只定义**何时强制路由给 mmx** 以及**在安全场景下用哪些 prompt**。

## 核心原则

**Claude 不读原始噪音数据。** 以下数据源必须先交给 mmx 处理，Claude 只读 mmx 返回的精简结果。

## 路由规则

| 数据源 | 阈值 | mmx 任务 |
|--------|------|---------|
| Burp HTTP 历史查询结果 | 任意大小 | 提取目标 URL / 参数列表 |
| DB 查询结果（scanner.db） | >10 行 | 筛选可疑/异常记录 |
| JS 文件内容 | >5KB | 提取 API 端点/硬编码密钥/敏感参数 |
| HTML 页面内容 | >5KB | 提取表单/链接/注释 |
| Burp HTTP 响应体 | >5KB | 提取关键字段/差异 |
| 联网搜索 | 任意 | `mmx search query`（不用内置 WebSearch） |
| 图片/截图理解 | 任意 | `mmx vision describe` |

## Agent 标准调用格式

```bash
# 文本分析（最常用）
mmx text chat --message "任务说明：\n数据内容" --output text --non-interactive

# 大文件内容分析（先写临时文件）
mmx text chat --message "$(cat /tmp/data.txt)" --output text --non-interactive

# 联网搜索
mmx search query --q "CVE-2024 ThinkPHP RCE" --output text --non-interactive

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

## 与 MCP 的分工

| 工具 | 适用场景 |
|------|---------|
| `mmx text chat`（CLI） | 数据分析、文本提取、JSON处理 — 本 skill 的主力 |
| `mcp__MiniMax__web_search` | 联网搜索（与 `mmx search query` 等效，MCP 版） |
| `mcp__MiniMax__understand_image` | 图片理解（与 `mmx vision describe` 等效，MCP 版） |

两者功能等效，选其一即可，不要同一任务调两次。
