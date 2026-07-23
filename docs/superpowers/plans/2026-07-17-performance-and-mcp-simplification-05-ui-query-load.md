# Task 05 — Swing 历史面板与 SQLite 查询压力实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 降低历史面板自动刷新、统计查询和表格模型更新造成的持续负载。

**Architecture:** UI 只加载轻量摘要并限制为 100 行；自动刷新默认 15 秒，搜索继续 debounce；统计信息采用低频缓存或单次聚合查询，不在每次表格刷新执行四个独立 COUNT。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/HttpHistoryPanel.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

## Steps

- [ ] 写测试：历史列表查询只返回摘要字段，不读取 request/response body 或 headers。
- [ ] 将表格加载上限从 500 调整为 100。
- [ ] 将自动刷新间隔从 5 秒调整为 15 秒，保留手动搜索 300ms debounce。
- [ ] 将四次独立统计查询合并为一次聚合查询，或缓存统计结果至少 15 秒。
- [ ] 检查 `captured_at` 排序的 SQLite 查询计划；只添加实际能改善查询的索引。
- [ ] 搜索查询继续限制结果数量；不为 `%keyword%` 添加无效普通索引。
- [ ] 防止旧的 IO 查询完成后覆盖用户最新搜索结果，可使用查询序号或取消前一 Job。
- [ ] 运行：`./gradlew.bat test --tests "*.DatabaseTest"`。
- [ ] 手动验证：历史面板连续运行 10 分钟，搜索、滚动和双击详情无明显卡顿。

## 验收

UI 自动刷新不会持续触发大批量表格更新；详情打开仍在 IO 线程读取，Swing EDT 只负责显示。
