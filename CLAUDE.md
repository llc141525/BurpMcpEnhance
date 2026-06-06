# SRC 漏洞挖掘项目

## 角色分工

| 角色             | 职责                                                  |
| ---------------- | ----------------------------------------------------- |
| **操作员（人）** | 浏览目标站、筛选可疑请求、授权自动化工具、提交报告    |
| **Claude（AI）** | 分析 Burp 流量、构造 PoC、验证漏洞、JS 逆向、编写报告 |

**协作原则**: 人做决策，AI 做执行。遇到无法判断的情况立即升级给操作员。

## 目录规范

| 目录 | 用途 |
|------|------|
| `dbs/` | **按目标分库的 DB 目录** — `dbs/{目标}_{日期}.db`，每个目标独立 DB |
| `TOOLS/` | 通用工具脚本（长期维护） |
| `reports/` | 正式漏洞报告（可提交 SRC） |
| `res/` | 静态资源（截图、验证码样本等） |
| `tmp/` | **所有临时文件** — 分析中间产物、PoC 草稿、日志、调试脚本 |

**临时文件铁律**：所有临时文件（脚本、JSON、日志、HTML 响应、JS 反混淆产物）必须写到 `tmp/` 目录，**禁止**写入根目录或 `.claude/`。

### 测试边界

- 仅对授权范围内的资产进行测试
- 遵守各 SRC 平台的测试规则和时间窗口
- 禁止对未授权目标进行任何测试

## 工具资源

### MCP 服务

| 工具                    | 用途                                               | 适用场景                                              |
| ----------------------- | -------------------------------------------------- | ----------------------------------------------------- |
| Burp Suite              | `list_proxy_http_history` + `get_proxy_http_detail` | 流量分析+参数篡改+漏洞验证。**结果不直接读，喂 MiniMax 过滤** |
| Scrapling (Python lib)  | 爬虫引擎: Fetcher/StealthyFetcher                  | **爬虫主力**: 页面抓取、链接/表单/API 提取            |
| Chrome DevTools         | 浏览器调试、JS 执行、网络监控                      | **仅限登录流程**: 手动登录、验证码、会话恢复          |
| SQLite (Python sqlite3) | 查询 dbs/{目标}_{日期}.db | 扫描结果分析（**不再使用 mcp\_\_sqlite\_\_\* 工具**） |
| LSP                    | goToDefinition / findReferences / documentSymbol / hover | **JS 逆向主力**: 大文件导航、调用链追踪、结构分析 |
| Stealth Browser        | 反检测浏览器 + 验证码识别                         | **仅限登录流程**: 替代 Chrome DevTools 场景的浏览器操作 |
| **MiniMax MCP**        | `web_search` / `understand_image`                | **省 Token 主力**: 搜索 + 图片理解 + 文本处理（DB 结果分析、Burp 历史过滤、大文件摘要） |
| **mmx CLI**            | `mmx vision describe` / `mmx search query` / `mmx text chat` | **补充工具**: 图像理解、搜索、文本对话（配合 Skill 使用） |

### 工具脚本

`TOOLS/` 目录:

| 脚本 | 用途 |
|------|------|
| `run_scan.py` | **唯一主入口**: 读 phase 自动调度下一步 |
| `js_analyzer.py` | **JS 批量分析**: mmx 提取端点/密钥 → suspicious_points |
| `pipeline/init_scan.py` | httpx 批量验活 + 技术指纹 |
| `pipeline/bfs_crawl.py` | katana BFS 爬取，写 pages/js_files |
| `pipeline/probe_runner.py` | arjun 参数 fuzz + nuclei + HTTP 方法探测 |
| `pipeline/brutescan.py` | 轻量目录爆破 |
| `pipeline/scrapling_fetch.py` | Scrapling 驱动页面抓取 + 结构化提取 |
| `auth/browser_auth.py` | browser-use 登录 agent |
| `auth/chrome_manager.py` | Chrome 单实例 CDP 管理 |
| `auth/captcha_bypass.py` | OCR 验证码 + 滑块绕过 |
| `auth/feishu_notify.py` | 飞书通知 + 操作员回复轮询 |
| `recon/fofa_relay.py` | FOFA 被动侦察 |
| `recon/zoomeye_query.py` | ZoomEye 被动侦察 |
| `recon/burp-surface.py` | Burp 历史参数词频分析 |
| `db/db_query.py` | 统一 DB 查询工具 |
| `db/db_backup.py` | DB 备份 |
| `db/migrate.py` | DB schema 迁移 |
| `db/auth_check.py` | Session 健康检查 |
| `db/session_dash.py` | 扫描进度总览 |
| `db/log_utils.py` | 结构化 JSON 日志 helper |
| `db/log_view.py` | 日志查询 |
| `utils/variant_search.py` | 变种搜索 |
| `utils/waf_rotate.py` | WAF 绕过/IP 轮换 |
| `utils/clash-helper.ps1` | Clash 代理切换 |

### 省 Token 策略 (MiniMax MCP + CLI)

高 Token 低智商的 ETL 任务全部交给 MiniMax：

```
┌──────────────────────────┬───────────────────────────────────┬─────────────┐
│ 场景                     │ 执行方                             │ 说明         │
├──────────────────────────┼───────────────────────────────────┼─────────────┤
│ Burp HTTP 历史查询结果   │ mmx text chat                     │ 喂原始 JSON，让 MiniMax 提取目标 URL/参数，Claude 只读摘要 │
│ DB 查询结果（>10 行）    │ mmx text chat                     │ 喂 SQL 结果集，让 MiniMax 筛选异常/可疑记录，Claude 只读筛选结果 │
│ 大 JS/HTML 文件（>5KB）  │ mmx text chat                     │ 喂文件内容，让 MiniMax 提取 API 端点/参数/敏感信息，Claude 只读提取结果 │
│ 联网搜索                 │ MiniMax MCP: web_search           │ 别用内置 WebSearch — DeepSeek 不支持                       │
│ 图片理解/验证码          │ MiniMax MCP: understand_image     │ 含截图分析、OCR                                            │
│ 验证码绕过               │ captcha_bypass.py (ddddocr)       │ 主力离线 OCR，不费 Token                                   │
└──────────────────────────┴───────────────────────────────────┴─────────────┘
```

**铁律**：Claude 不读原始噪音数据。Burp 历史、DB 结果集、大 JS/HTML — 先给 MiniMax 解析，Claude 只处理 MiniMax 返回的精简结果。

CLI 用法：
```
mmx text chat              → 喂任意文本，返回分析/筛选/提取结果
mmx vision describe <文件>  → 图片理解（本地文件/URL）
mmx search query <关键词>   → 联网搜索
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
|-------|------|----------|
| **asset-recon** | FOFA/ZoomEye 被动侦察，初始化目标 DB，写入 targets 表 | `Skill(skill="asset-recon", args="目标: 台州学院")` |
| **business-logic-hunt** | Burp 历史 → 三层重放 → IDOR/未授权/信息泄露/验证码/枚举/密码重置/参数逻辑替换 | `Skill(skill="business-logic-hunt", args="目标: 台州学院")` |
| **manual-replay** | 操作员跑业务流程 → AI 变种攻击。时间窗口 Burp 采集 → mmx 分类 → 流分析 → 变种生成 → 三层执行 | `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5")` |
| **stealth-scanner** | BFS 爬虫 + 框架指纹 + API探测 + 参数fuzz + 框架专项探测 + 10轮记忆总结 | `Skill(skill="stealth-scanner", args="目标: 台州学院")` |
| **vuln-review** | PoC 验证，结果写入 findings 表 | `Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")` |
| **src-report** | 读 findings 生成 edu/补天/CNVD 三平台 docx 报告，评审结论写 DB，已报告漏洞自动去重 | `Skill(skill="src-report", args="平台: edu; 目标: 台州学院")` |
| **vuln-auditor** | 补天审核员视角复核 docx 报告，发 Burp 请求 / 运行 PoC 脚本，打回记录写 memory | `Skill(skill="vuln-auditor", args="目标: 台州学院")` |

## 并发三 Session 模型

三个独立 Claude Code session 通过 SQLite 协同工作，可同时运行：

**Session A — asset-recon** (`Skill(skill="asset-recon", args="目标: 台州学院")`):
- FOFA + ZoomEye 被动侦察
- 初始化目标 DB（`dbs/{target}_{date}.db`）
- 写入 `targets` 表 + `pages` 表（所有资产入队）
- Phase 流转: `init → recon → done`

**Session B — stealth-scanner** (`Skill(skill="stealth-scanner", args="目标: 台州学院")`):
- Scrapling 驱动 BFS 遍历页面、收割 JS、识别可疑参数
- Phase 3 接管攻击面探测（API方法探测、参数fuzz、表单交互、框架专项）
- 内置每 10 轮向 memory 系统写入进度总结
- Phase 流转: `init → spider ↔ probe → brute → spider`
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
- 读取 Burp 历史 → MiniMax 筛选业务接口
- 三层重放测试（A 账号 / B 账号 / 未授权）
- 确认漏洞直接写 findings 表（F-BLH-* 前缀）
- 低置信度发现写 suspicious_points（SP-BLH-* 前缀）
- 增量队列模式，每次调用处理 5 个端点
- 需先在 auth_sessions 准备 primary + secondary 两个账号

### 2.6 手工流程变种攻击（manual-replay）

操作员调用 `Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay")` 对刚手工操作的业务流程执行变种攻击：

1. 操作员在 Burp 中跑完业务流程（注册→登录→下单等）
2. 回到 Claude 调用 manual-replay skill
3. 时间窗口采集 Burp 历史 → MiniMax 分类业务意图
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
python3 TOOLS/brutescan.py -u https://target.com -n 200 -o results.json
```

结果自动导入 `pages` 表后继续 BFS 爬取。

## Token 管理（CRITICAL）

### 低智商高 Token 任务 — 全部路由给 MiniMax

Claude 不读原始噪音数据。以下场景**必须**先经 `mmx text chat` 处理：

| 数据源 | 如何喂给 MiniMax | Claude 只读什么 |
|--------|------------------|-----------------|
| Burp HTTP 历史查询结果 | 将返回 JSON 文本直接喂入 | MiniMax 筛选后的目标 URL/参数列表 |
| DB 查询结果（>10 行） | 将 SQL 输出文本喂入 | MiniMax 标注的可疑记录/异常行 |
| 大 JS/HTML 文件（>5KB） | 将文件内容文本喂入 | MiniMax 提取的 API 端点/参数/敏感词 |
| 页面爬取内容（HTML） | 将 HTML 文本喂入 | MiniMax 提取的表单/链接/注释 |

### Burp 查询规则

- **优先用 `list_proxy_http_history`**（返回精简字段），不用 `get_proxy_http_history_regex`（返回全量字段）
- 结果直接喂 MiniMax 过滤，Claude 不读原始 JSON
- 精确定位需求: `list_proxy_http_history(count=5, offset=N)` — 控制在 5 条以内

### JS 逆向时的 LSP 导航

大 JS 文件（>500 行，webpack/vite 打包产物）必须用 LSP 定位：

1. `documentSymbol(filePath)` 先看结构
2. `workspaceSymbol` / `findReferences` 定位目标
3. `Read(offset, limit)` 只读 20-50 行精确片段
4. 如需分析读到的代码片段内容 → 喂 MiniMax 提取关键逻辑

禁止 `Read` 2000+ 行打包 JS。

### 文件内容分析优先用 MiniMax

已抓到的 JS/HTML 文件（`js_files` 表、本地缓存），分析端点/参数/敏感信息时：
1. `Read` 读取文件文本（一次读取，不逐行交互）
2. 全文喂入 `mmx text chat`，让 MiniMax 提取：API 端点、参数名、敏感字符串、可能漏洞点
3. Claude 只处理 MiniMax 返回的提取结果，决定是否深入验证

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

## 禁止事项

- 禁止对未授权资产测试
- 禁止 DoS/DDoS 测试
- 禁止获取未授权数据
- 禁止在社交平台泄露漏洞细节
