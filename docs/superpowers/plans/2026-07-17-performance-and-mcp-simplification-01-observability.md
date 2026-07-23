# Task 01 — Exporter 性能基线与可观察性实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为 Exporter 建立同步规模、过滤数量、耗时和错误状态的可观察基线。

**Architecture:** 在每轮同步内创建不可变快照，统计 Burp history 总量、新增量、Scope 过滤量、噪声过滤量、写入量和耗时；MCP 只返回计数与状态，不返回敏感内容。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/exporter/Exporter.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/exporter/ExporterTest.kt`

## Interfaces

新增或等价实现以下字段：

```kotlin
data class ExporterStats(
    val isRunning: Boolean,
    val totalExported: Int,
    val lastExportTime: Long,
    val historySeen: Int,
    val newEntriesSeen: Int,
    val filteredOutOfScope: Int,
    val filteredNoise: Int,
    val lastCycleDurationMs: Long,
    val lastCycleError: String?,
    val dbStats: DbStats
)
```

## Steps

- [ ] 写失败测试：一次同步报告完整历史数、新增数、Scope 过滤数、噪声过滤数和耗时。
- [ ] 写失败测试：同步异常后 `lastCycleError` 有值，Exporter 下一轮仍可继续运行。
- [ ] 实现线程安全的指标快照；不能把 request/response body 写入指标或日志。
- [ ] 在 `get_exporter_stats` 中返回所有计数和最近错误。
- [ ] 为计时使用 `System.nanoTime()`，对外统一转换为毫秒。
- [ ] 运行：`./gradlew.bat test --tests "*.ExporterTest"`。
- [ ] 运行：`./gradlew.bat shadowJar`。

## 验收

无新增记录时可以观察到 `newEntriesSeen=0`；同步耗时和全量历史数量可在不打开调试日志的情况下获取。
