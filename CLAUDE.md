# SRC 漏洞挖掘项目

## 角色分工

| 角色                   | 职责                                                  |
| ---------------------- | ----------------------------------------------------- |
| **操作员（人）** | 浏览目标站、筛选可疑请求、授权自动化工具、提交报告    |
| **Claude（AI）** | 分析 Burp 流量、构造 PoC、验证漏洞、JS 逆向、编写报告 |

**协作原则**: 人做决策，AI 做执行。遇到无法判断的情况立即升级给操作员。

## 目录规范

| 目录         | 用途                                                                        |
| ------------ | --------------------------------------------------------------------------- |
| `dbs/`     | **按目标分库的 DB 目录** — `dbs/{目标}_{日期}.db`，每个目标独立 DB |
| `TOOLS/`   | 通用工具脚本（长期维护）                                                    |
| `reports/` | 正式漏洞报告（可提交 SRC）                                                  |
| `res/`     | 静态资源（截图、验证码样本等）                                              |
| `tmp/`     | **所有临时文件** — 分析中间产物、PoC 草稿、日志、调试脚本            |

**临时文件铁律**：所有临时文件（脚本、JSON、日志、HTML 响应、JS 反混淆产物）必须写到 `tmp/` 目录，**禁止**写入根目录或 `.claude/`。

### 测试边界

- 仅对授权范围内的资产进行测试
- 遵守各 SRC 平台的测试规则和时间窗口
- 禁止对未授权目标进行任何测试

## Python 环境管理（CRITICAL）

本项目使用 `uv` 管理 Python 环境、依赖和命令执行。所有 Python 相关操作必须通过 `uv` 完成，不直接调用系统 `python` / `python3` / `pip` / `pytest`。

### 统一命令规范

| 场景             | 命令                                      |
| ---------------- | ----------------------------------------- |
| 运行脚本         | `uv run python TOOLS/xxx.py ...`        |
| 运行测试         | `uv run pytest TOOLS/tests/`            |
| 运行单个测试文件 | `uv run pytest TOOLS/tests/test_xxx.py` |
| 安装运行依赖     | `uv add <package>`                      |
| 安装开发依赖     | `uv add --dev <package>`                |
| 临时执行工具     | `uv run <tool> ...`                     |

### 禁止事项

- 禁止直接执行 `python TOOLS/...`、`python3 TOOLS/...`、`pytest ...`
- 禁止使用 `pip install ...` 或 `uv pip install ...` 管理项目依赖
- 禁止依赖系统 PATH 中的 Python 解释器
- 如工具脚本内部需要调用 Python 子进程，优先使用当前 `sys.executable`，并确保入口由 `uv run` 启动

### 例外

只有在诊断环境本身损坏、确认 `uv` 不可用，或需要检查解释器路径时，才允许短暂执行系统级探测命令。此类命令不能用于运行项目脚本或安装依赖。

## 工具资源

### MCP 服务

| 工具                    | 用途                                                               | 适用场景                                                                                      |
| ----------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Burp Suite              | `list_proxy_http_history` + `get_proxy_http_detail`            | 流量分析+参数篡改+漏洞验证。**结果不直接读，喂 etl_analyzer.py 过滤**                    |
| Scrapling (Python lib)  | 爬虫引擎: Fetcher/StealthyFetcher                                  | **爬虫主力**: 页面抓取、链接/表单/API 提取                                              |
| Chrome DevTools         | 浏览器调试、JS 执行、网络监控                                      | **仅限登录流程**: 手动登录、验证码、会话恢复                                            |
| SQLite (Python sqlite3) | 查询 dbs/{目标}_{日期}.db                                          | 扫描结果分析（**不再使用 mcp\_\_sqlite\_\_\* 工具**）                                   |
| LSP                     | goToDefinition / findReferences / documentSymbol / hover           | **JS 逆向主力**: 大文件导航、调用链追踪、结构分析                                       |
| Stealth Browser         | 反检测浏览器 + 验证码识别                                          | **仅限登录流程**: 替代 Chrome DevTools 场景的浏览器操作                                 |

### 工具脚本

`TOOLS/` 目录:

| 脚本                            | 用途                                                                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run_scan.py`                 | **唯一主入口**: 读 phase 自动调度下一步                                                                                                                                      |
| `js_analyzer.py`              | **JS 批量分析**: 正则提取端点 + etl_analyzer 深度分析密钥信号 → suspicious_points                                                                                            |
| `pipeline/init_scan.py`       | httpx 批量验活 + 技术指纹                                                                                                                                                          |
| `pipeline/bfs_crawl.py`       | katana BFS 爬取，写 pages/js_files                                                                                                                                                 |
| `pipeline/probe_runner.py`    | arjun 参数 fuzz + nuclei + HTTP 方法探测                                                                                                                                           |
| `pipeline/brutescan.py`       | 轻量目录爆破                                                                                                                                                                       |
| `pipeline/scrapling_fetch.py` | Scrapling 驱动页面抓取 + 结构化提取                                                                                                                                                |
| `auth/auth_explore.py`        | Playwright 认证后深度导航 + XHR 拦截，写 suspicious_points（source='auth_explore'）                                                                                                |
| `auth/browser_auth.py`        | AI 自动登录 agent —`auth_pending` 时由 `run_scan.py` 自动调用；遇验证码/QR/SMS 通过飞书通知操作员；需 `uv add browser-use` + 环境变量 `DEEPSEEK_API` + `FEISHU_CHAT_ID` |
| `auth/chrome_manager.py`      | Chrome 单实例 CDP 管理（`:9222`）                                                                                                                                                |
| `auth/captcha_bypass.py`      | OCR 验证码 + 滑块绕过                                                                                                                                                              |
| `auth/feishu_notify.py`       | 飞书通知 + 操作员回复轮询                                                                                                                                                          |
| `recon/fofa_relay.py`         | FOFA 被动侦察                                                                                                                                                                      |
| `recon/zoomeye_query.py`      | ZoomEye 被动侦察                                                                                                                                                                   |
| `recon/burp-surface.py`       | Burp 历史参数词频分析                                                                                                                                                              |
| `db/db_query.py`              | 统一 DB 查询工具；`--init` 新建目标 DB（读 `db/schema.sql`）                                                                                                                   |
| `db/db_utils.py`              | 共享 `find_db` / `connect` helper（被所有管线脚本使用）                                                                                                                        |
| `db/db_backup.py`             | DB 备份                                                                                                                                                                            |
| `db/migrate.py`               | DB schema 迁移；存量 DB 补列：`uv run python TOOLS/db/migrate.py --target "xxx"`                                                                                                 |
| `db/auth_check.py`            | Session 健康检查                                                                                                                                                                   |
| `db/session_dash.py`          | 扫描进度总览                                                                                                                                                                       |
| `db/log_utils.py`             | 结构化 JSON 日志 helper                                                                                                                                                            |
| `db/log_view.py`              | 日志查询                                                                                                                                                                           |
| `utils/variant_search.py`     | 变种搜索                                                                                                                                                                           |
| `utils/waf_rotate.py`         | WAF 绕过/IP 轮换                                                                                                                                                                   |
| `utils/clash-helper.ps1`      | Clash 代理切换                                                                                                                                                                     |
| `tests/`                      | 单元测试（92 个，`uv run pytest TOOLS/tests/`）                                                                                                                                  |

### ETL 分析策略 (etl_analyzer.py)

高 Token 低智商的 ETL 任务全部交给 `etl_analyzer.py`（DeepSeek驱动）：

| 场景 | task 参数 | 说明 |
|------|-----------|------|
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

| Skill                         | 用途                                                                                              | 调用方式                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **asset-recon**         | FOFA/ZoomEye 被动侦察，初始化目标 DB，写入 targets 表                                             | `Skill(skill="asset-recon", args="目标: 台州学院")`                          |
| **business-logic-hunt** | Burp 历史 → 三层重放 → IDOR/未授权/信息泄露/验证码/枚举/密码重置/参数逻辑替换                   | `Skill(skill="business-logic-hunt", args="目标: 台州学院")`                  |
| **manual-replay**       | 操作员跑业务流程 → AI 变种攻击。时间窗口 Burp 采集 → etl_analyzer 分类 → 流分析 → 变种生成 → 三层执行 | `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5")` |
| **stealth-scanner**     | BFS 爬虫 + 框架指纹 + API探测 + 参数fuzz + 框架专项探测 + 10轮记忆总结                            | `Skill(skill="stealth-scanner", args="目标: 台州学院")`                      |
| **vuln-review**         | PoC 验证，结果写入 findings 表                                                                    | `Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")`              |
| **src-report**          | 读 findings 生成 edu/补天/CNVD 三平台 docx 报告，评审结论写 DB，已报告漏洞自动去重                | `Skill(skill="src-report", args="平台: edu; 目标: 台州学院")`                |
| **vuln-auditor**        | 补天审核员视角复核 docx 报告，发 Burp 请求 / 运行 PoC 脚本，打回记录写 memory                     | `Skill(skill="vuln-auditor", args="目标: 台州学院")`                         |

## 并发三 Session 模型

三个独立 Claude Code session 通过 SQLite 协同工作，可同时运行：

**Session A — asset-recon** (`Skill(skill="asset-recon", args="目标: 台州学院")`):

- FOFA + ZoomEye 被动侦察
- 初始化目标 DB（`dbs/{target}_{date}.db`）
- 写入 `targets` 表 + `pages` 表（所有资产入队）
- Phase 流转: `init → recon → done`

**Session B — stealth-scanner** (`Skill(skill="stealth-scanner", args="目标: 台州学院")`):

- Scrapling 驱动 BFS 遍历页面、收割 JS、识别可疑参数
- 认证流程：`auth_pending`（等操作员 Burp 手动登录）→ `auth_ready` → `auth_explore`（Playwright CDP 深度导航 + XHR 拦截）
- Phase 3 接管攻击面探测（API方法探测、参数fuzz、表单交互、框架专项）；全程注入 auth_sessions Cookie
- 内置每 10 轮向 memory 系统写入进度总结
- Phase 流转: `init → auth_pending → auth_ready → auth_explore → spider ↔ probe → brute`
- 每轮处理 1-3 页 + 1 个 JS 文件，状态持久化在 DB

**Session C — vuln-review** (`Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")`):

- 轮询 DB 中 `suspicious_points`（test_status='untested'）
- 逐条 PoC 验证 → 写入 `findings`
- 不需等 scanner 完成，任何时候都可运行

**协作**:

- asset-recon 写 `targets`、`pages`、`scan_state`
- stealth-scanner 写 `pages`、`js_files`、`suspicious_points`
- vuln-review 读上述表，写 `suspicious_points.test_status`、`findings`
- WAL 模式 + busy_timeout=5000 处理并发

## 工作流程

### 1. 资产梳理（入口）

操作员调用 `Skill(skill="asset-recon", args="目标: 台州学院")` 初始化目标 DB：

- FOFA + ZoomEye 被动侦察，主域名自动提取
- 所有资产写入 `targets` 表 + `pages` 表（depth=0, status='queued'）

### 2. 扫描（stealth-scanner）

操作员调用 `Skill(skill="stealth-scanner", args="目标: 台州学院")` 启动 BFS 爬虫：

- Scrapling 驱动页面抓取、框架指纹、JS 收割
- Phase 3 攻击面探测：API 方法探测、参数 fuzz、表单交互、框架专项
- 每 10 轮自动向 memory 系统写入进度总结

### 2.5 业务逻辑猎手（business-logic-hunt）

操作员调用 `Skill(skill="business-logic-hunt", args="目标: 台州学院")` 深度挖掘业务漏洞：

- 读取 Burp 历史 → etl_analyzer 筛选业务接口
- 三层重放测试（A 账号 / B 账号 / 未授权）
- 确认漏洞直接写 findings 表（F-BLH-* 前缀）
- 低置信度发现写 suspicious_points（SP-BLH-* 前缀）
- 增量队列模式，每次调用处理 5 个端点
- 需先在 auth_sessions 准备 primary + secondary 两个账号

### 2.6 手工流程变种攻击（manual-replay）

操作员调用 `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay")` 对刚手工操作的业务流程执行变种攻击：

1. 操作员在 Burp 中跑完业务流程（注册→登录→下单等）
2. 回到 Claude 调用 manual-replay skill
3. 时间窗口采集 Burp 历史 → etl_analyzer 分类业务意图
4. AI 识别流程步骤和跨请求参数依赖
5. 按业务意图生成变种（IDOR/未授权/参数逻辑/验证码复用等）
6. 三层执行（A 账号 / B 账号 / 未授权）
7. 确认漏洞写 findings 表（F-RP-* 前缀），低置信度写 suspicious_points（SP-RP-* 前缀）
8. 输出摘要后退出，增量模式每次重跑重新采集

前置条件：auth_sessions 表中已有 primary + secondary 两个账号的 token。

### 3. 复核（vuln-review）

操作员调用 `Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")` 验证可疑点：

- 逐条读 `suspicious_points`（test_status='untested'）
- 构造 PoC → Burp 发送 → 判定 confirmed/false_positive → 写入 `findings`
- 不需等 scanner 完成，任何时候都可运行

### 4. 报告（src-report）

- `Skill(skill="src-report", args="平台: edu; 目标: 台州学院")` 生成 edu 平台提交报告
- `Skill(skill="src-report", args="平台: 补天; 目标: 台州学院")` 生成补天平台提交报告
- `Skill(skill="src-report", args="平台: CNVD; 目标: 台州学院")` 生成 CNVD 平台提交报告
- 保存到 `reports/{平台}_提交_{目标}_{日期}.md`

### 目录爆破（可选）

BFS 队列空时可由操作员触发:

```bash
uv run python TOOLS/pipeline/brutescan.py -u https://target.com -n 200
```

结果自动导入 `pages` 表后继续 BFS 爬取。

## Token 管理（CRITICAL）

### 低智商高 Token 任务 — 全部路由给 etl_analyzer

Claude 不读原始噪音数据。以下场景**必须**先经 `etl_analyzer.py` 处理：

| 数据源 | task 参数 | Claude 只读什么 |
|--------|-----------|-----------------|
| Burp HTTP 历史查询结果 | `filter_burp` | etl_analyzer 筛选后的目标 URL/参数列表 |
| DB 查询结果（>10 行） | `filter_db` | etl_analyzer 标注的可疑记录/异常行 |
| 大 JS 文件（含密钥信号） | `analyze_js` | etl_analyzer 提取的 API 端点/参数/敏感词 |
| 页面爬取内容（HTML >5KB） | `extract_endpoints` | etl_analyzer 提取的表单/链接/注释 |

### Burp 查询规则

- **优先用 `list_proxy_http_history`**（返回精简字段），不用 `get_proxy_http_history_regex`（返回全量字段）
- 结果直接喂 etl_analyzer（task=filter_burp）过滤，Claude 不读原始 JSON
- 精确定位需求: `list_proxy_http_history(count=5, offset=N)` — 控制在 5 条以内

### JS 逆向时的 LSP 导航

大 JS 文件（>500 行，webpack/vite 打包产物）必须用 LSP 定位：

1. `documentSymbol(filePath)` 先看结构
2. `workspaceSymbol` / `findReferences` 定位目标
3. `Read(offset, limit)` 只读 20-50 行精确片段
4. 如需分析读到的代码片段内容 → 喂 MiniMax 提取关键逻辑

禁止 `Read` 2000+ 行打包 JS。

### 文件内容分析优先用 etl_analyzer

已抓到的 JS/HTML 文件（`js_files` 表、本地缓存），分析端点/参数/敏感信息时：

1. `Read` 读取文件文本（一次读取，不逐行交互）
2. 全文喂入 `etl_analyzer.py`（task=`analyze_js` 或 `extract_endpoints`），提取：API 端点、参数名、敏感字符串、可能漏洞点
3. Claude 只处理 etl_analyzer 返回的提取结果，决定是否深入验证

### Stealth Browser Token 约束

`browser_snapshot` 返回的 a11y tree 比 `take_screenshot` 省 token 得多。规则：

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
