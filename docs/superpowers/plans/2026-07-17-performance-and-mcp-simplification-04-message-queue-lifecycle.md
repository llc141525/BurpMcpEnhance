# Task 04 — MessageQueue 生命周期实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 防止异步任务结果长期滞留在内存中。

**Architecture:** MessageQueue 自己拥有一个每 60 秒运行的清理 Job；默认清理 5 分钟前完成或失败的任务，不清理 PENDING/RUNNING 任务；shutdown 先停止清理 Job，再取消工作作用域。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/queue/MessageQueue.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/ExtensionBase.kt`（仅在生命周期需要接入时）
- Test: `src/test/kotlin/net/portswigger/mcp/queue/MessageQueueTest.kt`

## Steps

- [ ] 写失败测试：完成时间超过 TTL 的结果会被清除。
- [ ] 写失败测试：PENDING/RUNNING 结果不会被清除。
- [ ] 写失败测试：shutdown 后清理 Job 不再运行，所有 active Job 被取消。
- [ ] 在构造或启动时创建单一 cleanup Job，避免每个任务创建定时器。
- [ ] 保留手动 `cleanup(maxAgeMs)` 供测试和诊断调用。
- [ ] 让 `shutdown()` 按“停止清理、取消任务、清空容器”的顺序执行。
- [ ] 运行：`./gradlew.bat test --tests "*.MessageQueueTest" --tests "*.FileQueueTest"`。

## 验收

连续提交 10,000 个任务后，已完成结果不会无限增长；运行中的任务不被 TTL 清理误删。
