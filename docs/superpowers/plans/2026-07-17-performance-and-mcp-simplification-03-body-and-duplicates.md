# Task 03 — 正文与 raw duplicate 数据放大控制实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 降低重复请求、响应正文和 SQLite 写入造成的磁盘、内存与 GC 压力。

**Architecture:** canonical 记录保留安全分析所需摘要；raw duplicate 默认关闭，开启时独立限制数量和正文大小；MCP 详情默认不读取正文，正文仅在显式请求时按字节上限返回。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/exporter/Exporter.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

## Interfaces

```kotlin
var McpConfig.saveRawDuplicates: Boolean
var McpConfig.maxRawDuplicatesPerCanonical: Int
var McpConfig.maxRawDuplicateBodySize: Int
```

## Steps

- [ ] 写失败测试：默认配置下 duplicate 不写入。
- [ ] 写失败测试：开启 duplicate 后每个 canonical 不超过数量上限。
- [ ] 写失败测试：duplicate request/response body 不超过独立字节上限，并标记截断。
- [ ] 默认关闭 raw duplicate；已有持久化 `true` 必须保持兼容。
- [ ] 保留 canonical 的 URL、方法、状态、参数、候选评分和摘要字段。
- [ ] 详情工具的 `include_body=false` 路径不得拼接正文；`include_body=true` 必须使用固定最大字节数。
- [ ] 对非法负数和过大配置做 `coerceIn`，不得允许无界保存。
- [ ] 运行：`./gradlew.bat test --tests "*.DatabaseTest"`。

## 验收

默认运行不会因为重复请求保存 10 份完整正文；安全候选列表不读取正文，详情查询的返回大小有硬上限。
