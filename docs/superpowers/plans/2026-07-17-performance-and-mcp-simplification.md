# Burp MCP 性能与 MCP 接口收敛实施 Spec

> 本文件是实现文档索引。每个实现步骤都是独立文件，按顺序执行；每个文件都包含自己的目标、文件边界、测试与验收标准。

## 总目标

解决历史数据增长导致的 Burp 卡顿，修复 Scope-only 导入为空，减少正文/重复数据放大，避免队列内存长期增长，并将默认 MCP 暴露面收敛到高价值工具。

## 全局约束

- 阻塞 Burp API、SQLite 和文件操作使用 `Dispatchers.IO`。
- MCP 默认不返回完整 request/response body；正文必须显式按 ID、范围和字节上限请求。
- 普通轮询不能通过全量对象转换完成增量判断；全量扫描只能由显式 reimport 触发。
- HTTP 默认上限保持 100,000 行，Scanner 默认上限保持 10,000 行。
- 清空数据库后必须能重新导入当前 Burp 历史；Scope-only 不得依赖之后新产生请求才能恢复。
- 保留工作区已有未提交修改，不覆盖 `README.md`、`ScopeTools.kt`、`Tools.kt` 或既有 plans。
- 历史访问审批默认改为关闭只影响没有持久化值的新配置，不能静默覆盖已有持久化值。
- 每一步单独测试、单独提交，完成后再进入下一步。

## 现状证据

- `Exporter.exportProxyHttpHistory()` 每 30 秒调用 `api.proxy().history()`，再做水位过滤。
- Scope 判断在全量历史读取之后，数据库清空不会自动重置 Exporter 水位。
- raw duplicate 默认可保存每个 canonical 最多 10 份完整请求/响应。
- UI 每 5 秒查询最多 500 行并执行多次统计查询。
- MCP 原始历史分页是“先全量读取、后内存分页”。
- `MessageQueue.cleanup()` 存在，但当前未发现运行时调度调用。
- `McpConfig.requireHistoryAccessApproval` 当前默认值为 `true`。

## 实现文档

| 顺序 | 文档 | 交付物 |
|---:|---|---|
| 1 | [01-observability.md](2026-07-17-performance-and-mcp-simplification-01-observability.md) | Exporter 性能基线与状态指标 |
| 2 | [02-exporter-scope-and-reimport.md](2026-07-17-performance-and-mcp-simplification-02-exporter-scope-and-reimport.md) | 增量同步、清空 DB、Scope-only、reimport |
| 3 | [03-body-and-duplicates.md](2026-07-17-performance-and-mcp-simplification-03-body-and-duplicates.md) | 正文与 raw duplicate 数据放大控制 |
| 4 | [04-message-queue-lifecycle.md](2026-07-17-performance-and-mcp-simplification-04-message-queue-lifecycle.md) | 异步任务结果 TTL 清理 |
| 5 | [05-ui-query-load.md](2026-07-17-performance-and-mcp-simplification-05-ui-query-load.md) | Swing 刷新和 SQLite 查询压力降低 |
| 6 | [06-mcp-default-tools.md](2026-07-17-performance-and-mcp-simplification-06-mcp-default-tools.md) | 默认 MCP 工具集与高成本工具分层 |
| 7 | [07-scope-and-approval-defaults.md](2026-07-17-performance-and-mcp-simplification-07-scope-and-approval-defaults.md) | Scope ensure、结构化 Scope 操作、审批默认值 |
| 8 | [08-plugin-impact-diagnostics.md](2026-07-17-performance-and-mcp-simplification-08-plugin-impact-diagnostics.md) | 第三方插件影响诊断与 A/B 验证 |

## 完整验收

- `./gradlew.bat test` 全部通过。
- `./gradlew.bat shadowJar` 成功生成 `build/libs/burp-mcp-all.jar`。
- 100,000 条历史夹具连续运行 10 分钟，无新增时不反复转换全量历史。
- 清空 DB 后点击导入，Scope-only 能恢复当前 Scope 内旧记录。
- 默认 MCP 工具数量不超过 15 个，高级模式可恢复完整能力。
- 连续提交 10,000 个异步任务后，5 分钟后的已完成结果不再占用队列内存。
- UI 历史面板连续运行 10 分钟无明显 CPU 峰值或界面阻塞。
- 关闭/开启第三方插件分别记录 CPU、堆内存、历史增长速度和 Exporter 周期耗时。
