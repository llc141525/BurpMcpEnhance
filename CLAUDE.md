# SRC 漏洞挖掘项目

## 角色分工

| 角色 | 职责 |
| ---- | ---- |
| **操作员（人）** | 浏览目标站、筛选可疑请求、授权自动化工具、提交报告 |
| **Claude（AI）** | 分析 Burp 流量、构造 PoC、验证漏洞、JS 逆向、编写报告 |

**协作原则**: 人做决策，AI 做执行。遇到无法判断的情况立即升级给操作员。

## 目录规范

| 目录 | 用途 |
| ---- | ---- |
| `dbs/` | **按目标分库** — `dbs/{目标}_{日期}.db`，每个目标独立 DB |
| `TOOLS/` | 通用工具脚本（长期维护） |
| `reports/` | 正式漏洞报告（可提交 SRC） |
| `res/` | 静态资源（截图、验证码样本等） |
| `tmp/` | **所有临时文件** — 分析中间产物、PoC 草稿、日志、调试脚本 |

**临时文件铁律**：所有临时文件必须写到 `tmp/`，**禁止**写入根目录或 `.claude/`。

### 测试边界

- 仅对授权范围内的资产进行测试
- 遵守各 SRC 平台的测试规则和时间窗口
- 禁止对未授权目标进行任何测试

## Python 环境管理（CRITICAL）

所有 Python 操作必须通过 `uv`，禁止直接调用 `python/python3/pip/pytest`：

| 场景 | 命令 |
| ---- | ---- |
| 运行脚本 | `uv run python TOOLS/xxx.py ...` |
| 运行测试 | `uv run pytest TOOLS/tests/` |
| 运行单个测试 | `uv run pytest TOOLS/tests/test_xxx.py` |
| 安装运行依赖 | `uv add <package>` |
| 安装开发依赖 | `uv add --dev <package>` |
| 临时执行工具 | `uv run <tool> ...` |

禁止 `pip install` / `uv pip install`。子进程调用 Python 时用 `sys.executable`，入口由 `uv run` 启动。

## 工具资源

### MCP 服务

| 工具 | 用途 | 适用场景 |
| ---- | ---- | -------- |
| Burp Suite | 见下方"Burp MCP 工具速查" | 流量分析+参数篡改+漏洞验证+主动扫描+Collaborator OOB+GraphQL探测 |
| Scrapling (Python lib) | 爬虫引擎: Fetcher/StealthyFetcher | **爬虫主力**: 页面抓取、链接/表单/API 提取 |
| Chrome DevTools | 浏览器调试、JS 执行、网络监控 | **仅限登录流程**: 手动登录、验证码、会话恢复 |
| SQLite (Python sqlite3) | 查询 dbs/{目标}_{日期}.db | 扫描结果分析（**不再使用 mcp\_\_sqlite\_\_\* 工具**） |
| LSP | goToDefinition / findReferences / documentSymbol / hover | **JS 逆向主力**: 大文件导航、调用链追踪、结构分析 |
| Stealth Browser | 反检测浏览器 + 验证码识别 | **仅限登录流程**: 替代 Chrome DevTools 场景的浏览器操作 |

### Burp MCP 工具速查

#### 插件感知（重要）

**A 类插件（HTTP Handler）— 对所有 `send_http1_request` 调用自动生效**（无需任何操作）：
- Bypass WAF · Knife · 403 Bypasser · autoDecoder · captcha-killer · Content Type Converter

**B 类插件（Scanner Extension）— 调用 `start_active_scan` 时自动运行**：
- Active Scan++ · Param Miner · HTTP Request Smuggler · FastjsonScan · ShiroScan · Struts RCE · Retirejs

> 调用 `get_burp_info` 可查看当前 Burp 版本、版本类型及能力总结。

#### 工具分类

| 工具 | 用途 | 注意 |
| ---- | ---- | ---- |
| `get_burp_info` | Burp 版本/能力总览 | 会话开始时调用一次 |
| `list_proxy_http_history` | DB 缓存历史（轻量，推荐）| 结果喂 etl_analyzer |
| `get_proxy_http_detail` | 按 ID 取完整请求/响应 | 用 list 先拿 ID |
| `get_proxy_http_history` | 实时 Burp 历史，可选 regex 过滤 | 返回 JSON，量大 |
| `diff_proxy_responses` | 对比两条响应的差异行 | 省 Token，漏洞确认首选 |
| `manage_scope` | 添加/删除/检查目标 Scope | 测试前必须确认 in-scope |
| `get_site_map` | 读取 Burp 已发现的 URL | 可按 URL 前缀过滤 |
| `start_active_scan` | 触发主动扫描（Pro 专属）| B 类插件自动运行 |
| `get_scanner_issues` | 读取 Burp 扫描结果（实时）| Pro 专属 |
| `list_scanner_issues` | 读取 DB 缓存的扫描结果 | 更轻量，推荐 |
| `generate_collaborator_payload` | 生成 Collaborator OOB payload | Pro 专属 |
| `get_collaborator_interactions` | 查询 OOB 回调（DNS/HTTP/SMTP）| Pro 专属 |
| `graphql_introspect` | 获取并缓存 GraphQL schema | 每个目标调一次即可 |
| `graphql_list_types` | 列出缓存 schema 中的所有类型 | 需先调 introspect |
| `graphql_describe_type` | 查看某类型的所有字段和参数 | 需先调 introspect |
| `graphql_query` | 执行任意 GraphQL 查询 | 用于测试发现的操作 |
| `send_http1_request` | 发送 HTTP/1.1 请求 | A 类插件自动处理 |
| `manage_auto_approve_targets` | 管理请求自动审批列表 | action: add/remove/list/clear |

### 工具脚本

`TOOLS/` 目录:

| 脚本 | 用途 |
| ---- | ---- |
| `run_scan.py` | **唯一主入口**: 读 phase 自动调度下一步 |
| `js_analyzer.py` | **JS 批量分析**: 正则提取端点 + etl_analyzer 深度分析密钥信号 → suspicious_points |
| `pipeline/init_scan.py` | httpx 批量验活 + 技术指纹 |
| `pipeline/bfs_crawl.py` | katana BFS 爬取，写 pages/js_files |
| `pipeline/probe_runner.py` | arjun 参数 fuzz + nuclei + HTTP 方法探测 |
| `pipeline/api_fuzz.py` | 隐藏 admin/teacher API 命名空间爆破 → hunt_queue |
| `pipeline/ssrf_scan.py` | SSRF 候选发现 → hunt_queue(endpoint_type='ssrf_candidate') |
| `pipeline/upload_scan.py` | 文件上传漏洞测试（SVG/PHP/JSP webshell）→ suspicious_points/findings |
| `pipeline/xss_scan.py` | 存储型 XSS beacon 注入检测 → suspicious_points |
| `auth/auth_explore.py` | Playwright 认证后深度导航 + XHR 拦截，写 suspicious_points（source='auth_explore'） |
| `auth/browser_auth.py` | AI 自动登录 agent；需 `DEEPSEEK_API` + `FEISHU_CHAT_ID` 环境变量 |
| `auth/chrome_manager.py` | Chrome 单实例 CDP 管理（`:9222`） |
| `recon/fofa_relay.py` | FOFA 被动侦察 |
| `recon/zoomeye_query.py` | ZoomEye 被动侦察 |
| `db/db_query.py` | 统一 DB 查询工具；`--init` 新建目标 DB（读 `db/schema.sql`） |
| `db/db_utils.py` | 共享 `find_db` / `connect` helper（被所有管线脚本使用） |
| `db/migrate.py` | DB schema 迁移：`uv run python TOOLS/db/migrate.py --target "xxx"` |
| `utils/variant_search.py` | 变种搜索 |
| `utils/waf_rotate.py` | WAF 绕过/IP 轮换 |
| `tests/` | 单元测试（`uv run pytest TOOLS/tests/`） |

### Collaborator OOB SSRF 工作流

Python 子进程没有 MCP 访问权限，ssrf_scan.py 只接收参数，AI 负责 orchestrate：

```
1. AI 调用: generate_collaborator_payload
   → 得到 payload="abc123.burpcollaborator.net", payloadId="abc123"

2. AI 传参运行:
   uv run python TOOLS/pipeline/ssrf_scan.py --target "目标名" \
     --collaborator-url "http://abc123.burpcollaborator.net/" \
     --collaborator-payload-id "abc123"

3. 等 10-30 秒后调用: get_collaborator_interactions(payloadId="abc123")
   → 有 DNS/HTTP 回调 = 盲 SSRF 确认
```

无 Collaborator 时（仅检测反射型 SSRF）：`uv run python TOOLS/pipeline/ssrf_scan.py --target "目标名"`

### ETL 分析策略 (etl_analyzer.py)

高 Token 低智商的 ETL 任务全部交给 `etl_analyzer.py`（DeepSeek驱动）：

| 场景 | task 参数 | 说明 |
| ---- | --------- | ---- |
| Burp HTTP 历史查询结果 | `filter_burp` | 喂原始 JSON，提取目标 URL/参数，Claude 只读摘要 |
| DB 查询结果（>10 行） | `filter_db` | 喂 SQL 结果集，筛选异常/可疑记录，Claude 只读筛选结果 |
| 大 JS/HTML 文件（含密钥信号） | `analyze_js` / `extract_endpoints` | 喂文件内容，提取端点/密钥/敏感信息，Claude 只读提取结果 |
| 业务接口分类 | `classify_business` | 分类 Burp 历史中的业务接口意图 |
| 流程分析 | `analyze_flow` | 识别请求序列中的业务流程链 |
| 变种生成 | `generate_variants` | 生成安全测试变种 |
| PoC 响应对比 | `diff_responses` | 对比两个HTTP响应判断漏洞 |

**铁律**：Claude 不读原始噪音数据。Burp 历史、DB 结果集、大 JS/HTML — 先给 etl_analyzer 解析，Claude 只处理返回的精简结果。

**联网搜索**：直接用 Claude 内置 `WebSearch` 工具。
**图像/截图理解**：直接用 Claude `Read` 工具读取图片（Claude 原生多模态）。

CLI 用法：
```bash
uv run python TOOLS/utils/etl_analyzer.py --task filter_burp --data "$(cat burp.json)"
uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat file.js)"
uv run python TOOLS/utils/etl_analyzer.py --task filter_db --data "$(cat query_result.txt)"
```

### 浏览器/引擎选择

```
需要爬虫抓取/端点收割? → Scrapling (TOOLS/scrapling_fetch.py)
需要自动化调试/抓包? → Chrome DevTools
需要手动登录/交互? → 操作员通过 Burp 代理浏览
遇到图形验证码/滑块? → captcha_bypass.py (基于 ddddocr, 离线免费)
```

### 可用 Skills

| Skill | 用途 | 调用方式 |
| ----- | ---- | -------- |
| **asset-recon** | FOFA/ZoomEye 被动侦察，初始化目标 DB，写入 targets 表 | `Skill(skill="asset-recon", args="目标: 台州学院")` |
| **business-logic-hunt** | Burp 历史 → 三层重放 → IDOR/未授权/信息泄露/验证码/枚举/密码重置/参数逻辑替换 | `Skill(skill="business-logic-hunt", args="目标: 台州学院")` |
| **manual-replay** | 操作员跑业务流程 → AI 变种攻击。时间窗口 Burp 采集 → etl_analyzer 分类 → 流分析 → 变种生成 → 三层执行 | `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5")` |
| **stealth-scanner** | BFS 爬虫 + 框架指纹 + API探测 + 参数fuzz + 框架专项探测 + 10轮记忆总结 | `Skill(skill="stealth-scanner", args="目标: 台州学院")` |
| **vuln-review** | PoC 验证，结果写入 findings 表 | `Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")` |
| **src-report** | 读 findings 生成 edu/补天/CNVD 三平台 docx 报告，评审结论写 DB，已报告漏洞自动去重 | `Skill(skill="src-report", args="平台: edu; 目标: 台州学院")` |
| **vuln-auditor** | 补天审核员视角复核 docx 报告，发 Burp 请求 / 运行 PoC 脚本，打回记录写 memory | `Skill(skill="vuln-auditor", args="目标: 台州学院")` |

## 并发协作

三个独立 Claude Code session 通过 SQLite WAL 协同（busy_timeout=5000）：

| Session | Skill | 写表 |
| ------- | ----- | ---- |
| A — asset-recon | asset-recon | targets, pages, scan_state |
| B — stealth-scanner | stealth-scanner | pages, js_files, suspicious_points |
| C — vuln-review | vuln-review | suspicious_points.test_status, findings |

## 工作流程

| 步骤 | 调用 | 关键前置/说明 |
| ---- | ---- | ------------- |
| 1. 资产梳理 | `asset-recon` | 初始化 DB，FOFA/ZoomEye 侦察 |
| 2. 扫描 | `stealth-scanner` | BFS → probe → api_fuzz → vuln_scan → exploit |
| 2.5 业务逻辑 | `business-logic-hunt` | 需 primary+secondary 账号；F-BLH-*/SP-BLH-* 前缀 |
| 2.6 变种攻击 | `manual-replay` | 操作员跑完业务流程后调用；F-RP-*/SP-RP-* 前缀 |
| 3. 复核 | `vuln-review` | 可与扫描并行，任何时候均可运行 |
| 4. 报告 | `src-report` | 平台参数: edu / 补天 / CNVD |

## Token 管理（CRITICAL）

### Burp 查询规则

- **优先用 `list_proxy_http_history`**（返回精简字段）
- 需要实时过滤时用 `get_proxy_http_history`，可选传 `regex` 参数
- 响应对比确认漏洞时用 `diff_proxy_responses`，只返回差异行，省 Token
- 结果直接喂 etl_analyzer（task=filter_burp）过滤，Claude 不读原始 JSON
- 精确定位需求: `list_proxy_http_history(count=5, offset=N)` — 控制在 5 条以内

### GraphQL 目标探测工作流

GraphQL 接口（常见于 `/graphql`, `/api/graphql`, `/v1/graphql`）：

```
1. graphql_introspect(targetHostname=..., targetPort=443, usesHttps=True, path="/graphql")
   → 返回 schema 摘要（queries/mutations/types），schema 自动缓存

2. graphql_list_types(cacheKey="host:443/graphql")
   → 识别敏感实体（User, Admin, Order, File...）

3. graphql_describe_type(cacheKey="...", typeName="User")
   → 发现隐藏字段（password, role, token...）

4. graphql_query(query="{ user(id:1) { id name email role } }", ...)
   → 验证 IDOR / 越权 / 信息泄露
```

注意：schema 缓存在 Burp 进程内存，重启后需重新 introspect。发现 `createAdmin` / `resetPassword` / `assignRole` 等 mutation 立即升级操作员。

### JS 逆向时的 LSP 导航

大 JS 文件（>500 行，webpack/vite 打包产物）必须用 LSP 定位：

1. `documentSymbol(filePath)` 先看结构
2. `workspaceSymbol` / `findReferences` 定位目标
3. `Read(offset, limit)` 只读 20-50 行精确片段
4. 如需分析代码片段 → 喂 etl_analyzer(task=analyze_js)

禁止 `Read` 2000+ 行打包 JS。

### Stealth Browser Token 约束

- **默认用 `browser_snapshot`** 获取页面结构（aom/hybrid 模式），仅在需要视觉证据时 `take_screenshot`
- 不要截整页截图 — 用 `uid` 参数截具体元素
- 登录完成后立即 `browser_tabs(action="close")` 关掉不用的 tab

## 升级给操作员

遇到以下情况**立即暂停并告知操作员**，不要自行决策：

- 发现疑似高危漏洞（RCE、SQL 注入可写 shell、任意文件上传）
- 会话过期且无法重新登录
- 目标返回异常大量数据
- 不确定某个测试是否合规
- 验证码/滑块绕过连续失败 3 次以上
- PoC 验证结果不确定，second-opinion 也无法判断

## 输出规范

- **正式报告**: 调用 `Skill(skill="src-report")` 生成，含利用链 + 完整 PoC + 修复建议，直接可提交 SRC 平台
- **临时发现**: 对话中简要说明漏洞类型、端点、风险等级即可，不用展开完整 PoC
