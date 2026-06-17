# MiniMax → ETL Adapter 迁移设计

**日期**: 2026-06-16
**背景**: MiniMax订阅即将过期，同时项目需要降低对特定AI服务商的耦合，以应对AI工具快速更迭带来的过时风险。

---

## 目标

1. 用 DeepSeek 替代 MiniMax 承担文本ETL任务（Burp历史过滤、JS分析、DB结果筛选）
2. 图像理解和联网搜索直接由 Claude 执行，不再中转
3. 删除 mmx MCP server，消除对 MiniMax 的所有依赖
4. 通过 Adapter 接口隔离，未来换模型只改一个文件

---

## 架构

### 新增：`TOOLS/utils/etl_analyzer.py`

唯一对外接口：

```python
def analyze(task: str, data: str, instruction: str = "") -> str
```

- `task`：语义标签，枚举值：`filter_burp` / `analyze_js` / `filter_db` / `extract_endpoints`
- `data`：原始文本（JSON字符串、JS内容、SQL输出等）
- `instruction`：可选的额外指令
- 返回：DeepSeek 精简后的结果字符串
- API key：读 `DEEPSEEK_API` 环境变量（项目中已存在）
- 同时支持 CLI 调用：`uv run python TOOLS/utils/etl_analyzer.py --task filter_burp`（stdin 读数据）

每个 task 有内置的 system prompt，专门针对安全测试场景优化：

| task | 用途 | 输入 | 输出 |
|---|---|---|---|
| `filter_burp` | 过滤Burp历史，提取目标URL/参数 | Burp history JSON | 目标URL列表+参数摘要 |
| `analyze_js` | 提取JS中的API端点、敏感信息 | JS文件内容 | 端点列表+敏感词 |
| `filter_db` | 筛选DB查询结果中的异常/可疑行 | SQL结果集文本 | 可疑记录列表 |
| `extract_endpoints` | 从HTML/文本提取接口和参数 | HTML内容 | 端点+参数列表 |

### 删除：mmx MCP

从 `.claude/settings.json` 删除 MiniMax MCP server 配置块。

`mcp__MiniMax__web_search` 和 `mcp__MiniMax__understand_image` 工具随之消失。

### 图像理解 / 搜索的替代

| 原调用 | 替代 |
|---|---|
| `mcp__MiniMax__understand_image` | Claude 直接 `Read` 图片文件 |
| `mcp__MiniMax__web_search` | Claude 直接使用 `WebSearch` 工具 |
| `mmx vision describe <file>` | 不再使用 |
| `mmx search query <关键词>` | 不再使用 |

---

## 指令层变更

### CLAUDE.md

删除以下内容：
- 工具资源表中的 MiniMax MCP 行和 mmx CLI 行
- 省Token策略章节中的 MiniMax/mmx 相关说明

新增/重写：
- 省Token策略改为：文本ETL → `etl_analyzer.py`；图像/搜索 → Claude 直接执行

### Skills

| Skill | 改动 |
|---|---|
| `mmx-router` | 整个重写为 `etl-router`，说明 `etl_analyzer.py` 的调用时机和方式 |
| `business-logic-hunt` | 删除所有 `mmx text chat` 调用，改为 `etl_analyzer` |
| `manual-replay` | 同上 |
| `stealth-scanner` | 同上 |
| `vuln-review` | 同上 |

### AGENTS.md

与 CLAUDE.md 同步更新（将"工具资源"和"省Token策略"章节保持一致）。

---

## 变更清单（执行顺序）

**Phase 1 — 新建 Adapter**
1. `TOOLS/utils/etl_analyzer.py` — DeepSeek 适配器实现
2. `TOOLS/tests/test_etl_analyzer.py` — 单元测试（mock DeepSeek API）

**Phase 2 — 删除 mmx MCP**
3. `.claude/settings.json` — 删除 MiniMax MCP 配置块
4. 检查 `settings.local.json` 等其他配置文件

**Phase 3 — 更新指令层**
5. `CLAUDE.md` — 删除 MiniMax/mmx 三处引用，重写省Token章节
6. `AGENTS.md` — 同步更新
7. `.claude/skills/mmx-router/SKILL.md` — 重写为 `etl-router`
8. `business-logic-hunt` / `manual-replay` / `stealth-scanner` / `vuln-review` skill — 替换所有 `mmx text chat` 引用

**Phase 4 — 验证**
9. `uv run pytest TOOLS/tests/test_etl_analyzer.py`
10. 真实ETL任务冒烟测试

---

## 不在本次范围内

- captcha_bypass.py（ddddocr）的替换——独立问题，后续处理
- browser_auth.py 的简化——独立问题，后续处理
- CLAUDE.md / AGENTS.md 双文件同步问题的根本解决——后续处理
- Auth 模块合并——后续处理
