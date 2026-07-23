# Task 06 — MCP 默认工具集与高成本工具分层实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将默认 MCP 工具控制在 15 个以内，同时保留高级能力的兼容开关。

**Architecture:** `McpConfig` 增加高级工具开关；默认只注册核心工具，高成本、低频或高风险工具在高级模式注册。缓存查询优先，原始 Burp 历史查询必须有数量、字节和时间限制。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/McpTool.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

## 默认核心工具

保留：`send_http1_request`、`manage_scope`、`start_active_scan`、`list_security_candidates`、`get_proxy_http_detail`、`list_scanner_issues`、`get_scanner_issue_detail`、`diff_proxy_responses`、`get_exporter_stats`、`get_burp_info`；GraphQL 工具仅在 GraphQL 能力开关开启时注册。

高级默认关闭：直接 Proxy/WebSocket 全量历史、Collaborator 全量查询、配置写入、Repeater/Intruder/Editor、异步队列/文件、单独编码工具。

## Steps

- [ ] 写失败测试：默认注册工具数量不超过 15 个。
- [ ] 写失败测试：开启高级模式后，高级工具仍可注册并保持原名称兼容。
- [ ] 写失败测试：原始历史工具不能返回超过固定条数和固定字节数。
- [ ] 增加显式 `limit`、`maxBytes` 和可选时间范围，所有值在服务端再次限制。
- [ ] 统一 list/detail 描述为“摘要优先、按 ID 取详情”，减少模型误调用。
- [ ] 对无法在 Burp API 数据源侧分页的接口记录全量读取指标，并阻止过大的返回。
- [ ] 将高成本工具的注册条件集中在 `registerTools()`，避免散落在多个注册函数中。
- [ ] 运行：`./gradlew.bat test --tests "*.ToolsKtTest"`。

## 验收

默认 MCP 工具列表不超过 15 个；已有高级工具在开启开关后可继续使用，核心缓存查询不依赖直接读取 Burp 全量历史。
