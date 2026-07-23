# Task 07 — Scope 自动化与审批默认值实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 让 AI 能显式、可靠地确保目标 URL 在 Burp Scope 中，并将新安装配置的历史访问审批默认改为关闭。

**Architecture:** `manage_scope` 增加幂等的 `ensure` 动作；Scope list/clear 使用结构化 JSON，不使用跨层级正则替换；审批默认只改变缺省值，已有持久化值保留。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/config/McpConfigTest.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

## Steps

- [ ] 写失败测试：`ensure` 对已在 Scope 的 URL 不重复添加，并返回 unchanged。
- [ ] 写失败测试：`ensure` 对不在 Scope 的 URL 添加一次，并返回 added。
- [ ] 写失败测试：Scope list/clear 不破坏项目配置中的其他数组和字段。
- [ ] 实现 `ensure`，要求调用者提供明确 URL；不得从任意正文静默推断并修改 Scope。
- [ ] `start_active_scan` 执行前输出 Scope 检查结果；不在 Scope 时返回明确原因。
- [ ] 使用 `Json.parseToJsonElement` / `JsonObject` 修改 Scope include 节点，替换当前正则清理方式。
- [ ] 将 `requireHistoryAccessApproval` 的缺省值改为 `false`。
- [ ] 写配置测试：无持久化值读取为 false，已有持久化 true 仍读取为 true。
- [ ] 运行：`./gradlew.bat test --tests "*.McpConfigTest" --tests "*.ToolsKtTest"`。

## 验收

AI 可以通过 `manage_scope(action="ensure", url="...")` 得到明确结果；清空 DB 后配合 reimport 可以重新读取 Scope 内历史；旧用户配置不会被静默改变。
