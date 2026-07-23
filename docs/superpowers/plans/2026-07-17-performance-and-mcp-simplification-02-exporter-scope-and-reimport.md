# Task 02 — Exporter 增量同步、Scope-only 与重新导入实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 修复清空 DB 后 Scope-only 无法恢复的问题，并明确普通轮询、Scope 变化和全量 reimport 的语义。

**Architecture:** 普通轮询只处理同步水位之后的数据；显式 `reimport()` 重置水位并重新判断当前历史。数据库清空必须通知 Exporter 重置水位，避免两个组件状态分裂。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/exporter/Exporter.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/config/HttpHistoryPanel.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/exporter/ExporterTest.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

## Interfaces

```kotlin
fun Exporter.reimport()
internal fun Exporter.resetWatermark()
fun Exporter.notifyDatabaseCleared()
```

如果现有生命周期不适合公开 `notifyDatabaseCleared()`，由拥有 Exporter 的协调层在 `clearProxyHttpHistory()` 后调用等价方法。

## Steps

- [ ] 写失败测试：清空 DB 后，已有历史中符合 Scope 的记录能重新导入。
- [ ] 写失败测试：Scope-only 开启时，非 Scope 记录不写 DB，但过滤计数正确。
- [ ] 写失败测试：Scope-only 关闭后重新开启，显式 reimport 按当前 Scope 重算旧历史。
- [ ] 将普通轮询和显式 reimport 分成两个入口；reimport 必须重置水位。
- [ ] 清空数据库后同步重置 Exporter 水位，不能只删除 SQLite 行。
- [ ] 处理同一时间戳记录：不能只依赖时间戳，使用稳定 ID/复合游标或在边界保留重叠窗口并依赖去重。
- [ ] Scope 判断和噪声过滤计数必须发生在写入之前，并更新 Task 01 的指标。
- [ ] `manage_scope` 或 UI 的“导入”动作调用显式 reimport，而不是只触发一次普通轮询。
- [ ] 运行：`./gradlew.bat test --tests "*.ExporterTest" --tests "*.DatabaseTest"`。

## 验收

清空 DB 后不需要产生新请求，点击“导入”即可恢复当前 Scope 内已有历史；普通 30 秒轮询不会每次重建全量历史对象。
