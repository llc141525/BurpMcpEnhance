# Task 08 — 第三方插件影响诊断实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 区分“插件存在”“插件会参与请求/扫描”“插件确实造成性能影响”，避免凭猜测建议用户卸载必要插件。

**Architecture:** 只读收集插件元数据、历史规模、Exporter 周期耗时和 Burp 版本信息；不改变任何第三方插件状态。实际因果通过关闭/开启插件组的 A/B 测试确认。

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/plugins/BurpPluginSupport.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/plugins/BurpPluginSupportTest.kt`

## Steps

- [ ] 写测试：插件报告能区分已检测插件、已配置插件、请求处理插件和扫描插件。
- [ ] 在 `get_burp_info` 中增加只读诊断：插件数量、HTTP history 数量、Scanner issue 数量、最近 Exporter 耗时。
- [ ] 明确报告“本 MCP 基础缓存/HTTP 工具不依赖第三方插件”。
- [ ] 对 Active Scan++、FastjsonScan、ShiroScan 等仅报告可能参与扫描，不宣称必然造成卡顿。
- [ ] 增加文档化 A/B 步骤：关闭插件组、重启 Burp、保持相同流量，比较 CPU、堆内存、历史增长速度和 Exporter 周期耗时。
- [ ] 运行：`./gradlew.bat test --tests "*.BurpPluginSupportTest"`。

## 验收

插件诊断能够提供可比较数据；报告不会把插件“已安装”直接等同于“必须保留”或“必然导致性能问题”。

## 完整回归

- [ ] `./gradlew.bat test`
- [ ] `./gradlew.bat shadowJar`
- [ ] 使用 100,000 条历史夹具完成 10 分钟压力验证。
