---
name: stealth-scanner
description: 网站爬虫与主动探测。BFS 发现页面/JS/端点（katana+httpx），框架指纹+参数fuzz+框架专项（nuclei+arjun）。机械动作全部由脚本完成，AI 只做分析判断。写 SQLite，不验证漏洞。每 10 轮写入 memory 进度总结。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Grep, Glob
---

# stealth-scanner

仅负责信息收集 + 主动探测。结果写 SQLite，漏洞验证由 vuln-review 在独立 session 完成。

## 使用方式

1. 运行: `python TOOLS/run_scan.py --target "{目标}"`
2. 读输出标签并响应:
   - `[AUTH_BARRIER]` → 告知操作员等待登录
   - `[NEW_SUSPICIOUS_POINTS]` → 判断哪些 SP 值得发给 vuln-review
   - `[SPIDER_BATCH]` / `[INIT_DONE]` / `[PHASE_TRANSITION]` → 再次调用 run_scan.py
3. 无其他调度步骤

## 环境常量

| 常量 | 值 |
|------|-----|
| DBS_DIR | `E:\SRC挖掘\SRC\dbs` |
| Memory 路径 | `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\{target_name}_progress.md` |

## 工具速查

| 场景 | 命令 |
|------|------|
| **启动/继续扫描** | `python TOOLS/run_scan.py --target "{目标}"` |
| 单独 JS 分析 | `python TOOLS/js_analyzer.py --target "{目标}" --batch 5` |
| DB 查询 | `python TOOLS/db/db_query.py --target "{目标}" "SELECT ..."` |
| 资产侦察 | `python TOOLS/recon/fofa_relay.py` |
| 手动登录后恢复 | `python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='spider' WHERE id=1" --write` |
| Chrome 启动 | `python TOOLS/auth/chrome_manager.py --target "{目标}"` |
| 自动登录 | `python TOOLS/auth/browser_auth.py --target "{目标}" --url "https://..."` |

## DB 操作

```bash
python3 TOOLS/db/db_query.py --target "{目标}" "SELECT phase FROM scan_state WHERE id=1"
python3 TOOLS/db/db_query.py --target "{目标}" "SELECT url, depth FROM pages WHERE status='queued' LIMIT 5"
python3 TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='spider' WHERE id=1" --write
python3 TOOLS/db/db_query.py --target "{目标}" --check
```

## 前置检查

```bash
# 1. Burp
mcp__burp__list_proxy_http_history(count=1)

# 2. 工具链
httpx --version && nuclei --version && katana --version

# 3. DB
python3 TOOLS/db/db_query.py --target "{目标}" --check
```

任一失败则提示对应组件不可用，终止执行。

## 容错

1. 工具调用失败 → 等 2 秒 → 重试 → 最多 3 次
2. scrapling_fetch.py timeout=15s → fallback StealthyFetcher → 仍失败则跳过
3. SQLite busy_timeout=5000，写失败等 1 秒重试
4. Phase 3 probe 中的 HTTP 请求走 Burp 代理（127.0.0.1:8080）

## MiniMax 路由

**铁律**: Burp 历史、DB 结果集（>10 行）、JS/HTML（>5KB）— 先给 `mmx text chat` 处理，Claude 只读精简结果。

## 状态机

phases: `init` → `auth_pending` → `auth_ready` → `auth_explore` → `spider` ↔ `probe` → `brute` → `spider`

| phase | 含义 | 主力工具 |
|-------|------|----------|
| `init` | 初始化 | init_scan.py |
| `auth_pending` | 等待凭证 | 操作员 Burp 手动登录 |
| `auth_ready` | 已获会话凭证，自动切换至 auth_explore | run_scan.py |
| `auth_explore` | 认证后深度导航，拦截 XHR/fetch 发现 API 攻击面 | auth_explore.py |
| `spider` | BFS 爬取 + 框架指纹（带认证 Cookie） | bfs_crawl.py + init_scan.py |
| `probe` | 业务主动探测（带认证 Cookie） | probe_runner.py |
| `brute` | 目录爆破 | brutescan.py |
| `auth_timeout` | 飞书等待超时（3分钟无回复），跳过该目标 | — |
| `chrome_error` | Chrome 启动失败（:9222 15秒无响应），通知操作员 | — |

## Phase 1: 初始化

### 入口检查

从 `args="目标: {name}"` 解析目标名。

```bash
python3 TOOLS/db/db_query.py --target "{目标}" "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_state'"
```

- 表存在 → 读取 phase
- 不存在 → 输出 "请先调用 asset-recon skill 初始化目标"，终止

```bash
python3 TOOLS/db/db_query.py --target "{目标}" "SELECT phase, seed_url, total_pages, total_js, total_suspicious, total_findings, call_count FROM scan_state WHERE id=1"
```

phase 分支:
- `spider` → Phase 2
- `probe` → Phase 3
- `brute` → Phase 4
- `auth_pending` → 登录流程
- `auth_ready` → run_scan.py 自动切至 auth_explore
- `auth_explore` → run_scan.py 自动运行 auth_explore.py → 完成后 phase=spider
- `init` 或无数据 → 继续 Phase 1.1

### 1.1 批量验活 + 技术指纹

```bash
python3 TOOLS/pipeline/init_scan.py --target "{目标}"
```

- httpx 批量检测所有 `targets` 域名：存活状态、页面标题、技术栈、IP
- 结果自动更新 `targets` 表，并将存活 URL 写入 `pages` 表（depth=0, status='queued'）
- 输出摘要给 AI 判断：哪些目标存活、技术栈、是否有登录页

### 1.2 登录流程（简化）

只读取 `auth_sessions` 中的有效凭证：

```sql
SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1 AND (role='primary' OR role IS NULL);
```

| auth_sessions | 动作 |
|--------------|------|
| 有有效会话 | 用 Burp 验证 cookie 是否仍然有效（请求一个已知需认证的页面） |
| 无有效会话 | 提示操作员通过 Burp 代理手动登录，登录成功后手动写入 auth_sessions |

会话验证:
```python
mcp__burp__send_http1_request(method="GET", url="http://目标/api/user/profile", ...)
```
- 返回 200 → `UPDATE scan_state SET phase='auth_ready'`
- 返回 302/401 → 提示重新登录

### 1.3 恢复检查

```
phase = 'spider':
  SELECT count(*) FROM pages WHERE status='queued'
  > 0 → Phase 2 | = 0 且 visited>0 → 转 probe

phase = 'probe':
  SELECT count(*) FROM suspicious_points WHERE test_status='untested'
  > 0 → Phase 3 | = 0 → 转 brute

phase = 'brute':
  SELECT count(*) FROM pages WHERE status='queued'
  > 0 → UPDATE phase='spider' → Phase 2 | = 0 → Phase 3
```

## Phase 2: BFS 爬虫 + 框架指纹

### 2.1 批量 BFS 爬取（katana）

```bash
python3 TOOLS/pipeline/bfs_crawl.py --target "{目标}" --depth 3 --max-pages 500
```

- katana 从 pages 表中的种子 URL 出发，深度优先爬取
- 发现的新页面 → 写入 `pages` 表（status='queued'）
- 发现的 JS 文件 → 写入 `js_files` 表（analyzed=0）
- **不读取 HTML 内容**，只收集 URL

### 2.2 框架指纹（httpx tech-detect）

init_scan.py 已经在 Phase 1 自动完成。若需补充单目标：

```bash
python3 TOOLS/pipeline/init_scan.py --urls "{url}"
```

从 `targets.tech_stack` 读取指纹结果，写入 `suspicious_points`（test_type='framework_fingerprint'）：

```bash
python3 TOOLS/db/db_query.py --target "{目标}" \
  "INSERT INTO suspicious_points (id, url, test_type, evidence, source, risk, test_status, created_at)
   SELECT 'SP-FP-'||substr(t.id,1,3), t.domain, 'framework_fingerprint', t.tech_stack, 'init_scan', 'Info', 'untested', datetime('now','localtime')
   FROM targets t WHERE t.tech_stack IS NOT NULL AND t.tech_stack != ''" --write
```

### 2.3 目标页面精细分析（AI 驱动，选择性）

对于含有以下特征的页面（从 pages 表中筛选），AI 调用 scrapling_fetch.py 做深度分析：

```bash
python3 TOOLS/db/db_query.py --target "{目标}" \
  "SELECT url FROM pages WHERE status='queued' AND (url LIKE '%login%' OR url LIKE '%api%' OR url LIKE '%admin%' OR url LIKE '%upload%') LIMIT 5"
```

对每个选中 URL 执行：

```bash
python3 TOOLS/pipeline/scrapling_fetch.py "{url}" --extract-all
```

从输出中识别：
- `$.suspicious_params` → 写 suspicious_points (test_status='untested')
- `$.forms` → 页面更新 forms_json
- `$.apis` → 含内部路径（/admin、/debug）→ 写 suspicious_points
- form 隐藏字段敏感值（role=user、uid=1）→ 写 suspicious_points (test_type='idor')
- HTML 中硬编码 secret → 写 suspicious_points (test_type='info_disclosure')

**注意**: 通过 katana 发现的普通页面（无上述特征）无需调用 scrapling_fetch.py。

更新页面状态：

```sql
UPDATE pages SET status='visited', title='{title}', forms_json='{json}', crawled_at='{datetime}' WHERE url='{url}';
```

### 2.4 JS 收割

```sql
SELECT url FROM js_files WHERE analyzed=0 LIMIT 1;
```

```bash
python3 TOOLS/pipeline/scrapling_fetch.py "{js_url}" --html
```

JS 内容喂 MiniMax：

```bash
mmx text chat --message "从这个JS提取: 1.API端点 2.硬编码密钥/token 3.内部路由 4.调试开关。JSON输出。" --message "$(cat {js_file})"
```

写入：

```sql
UPDATE js_files SET analyzed=1, discovered_apis_json='{MiniMax输出}', hardcoded_secrets_json='{MiniMax输出}', internal_routes_json='{MiniMax输出}', debug_switches_json='{MiniMax输出}', analyzed_at='{datetime}' WHERE url='{url}';
```

发现的路径级端点入 pages 队列。

### 2.5 Auth 处理

init_scan 检测到 302/401/403 或含登录关键词的页面时自动触发：

前置：`chrome_manager.py` 检测 Caido 是否在线（`:8181`）再决定是否挂代理。需先确认 Caido 已启动（`caido-cli --listen 127.0.0.1:8181 --no-open`）。

1. 写 `scan_state.phase='auth_pending'`
2. `chrome_manager.py` 确保 Chrome 在 `:9222` 在线（不重复启动）
3. `browser_auth.py` 启动 browser-use agent（Claude Haiku），导航登录页
4. 遇到 QR/CAPTCHA/OTP → `feishu_notify.py` 发飞书消息/截图给操作员手机
5. 操作员在手机飞书回复验证码/确认扫码完成
6. agent 填入答案 → 完成登录
7. 提取 cookies → 写 `auth_sessions`（`cookie_source='browser_use'`）
8. Surface discovery：展开菜单、导航页 → 发现 URL 写 `pages`（`source='browser_use'`）
9. 写 `scan_state.phase='auth_ready'`
10. run_scan.py 自动切换至 `auth_explore` → `auth_explore.py` 深度导航点击所有菜单 + 拦截 XHR/fetch → 发现的 API endpoint 写 `suspicious_points`（source='auth_explore'）→ phase 自动切回 `spider`
11. BFS spider + 后续探测全程带认证 Cookie（从 `auth_sessions` 读取）

## Phase 3: 业务主动探测

BFS 队列空后自动进入。

### 3.0 读取框架指纹

```sql
SELECT url, evidence FROM suspicious_points WHERE test_type='framework_fingerprint' AND test_status='untested';
```

### 3.1 取待测可疑点

```sql
SELECT id, url, param, method, test_type, evidence, risk FROM suspicious_points WHERE test_status='untested' LIMIT 10;
```

空 → 转 Phase 4 (brute)。

### 3.2 API 方法探测（脚本）

对业务端点（/api/、/register/、!action 等，**不含首页/登录页**）：

```bash
python3 TOOLS/pipeline/probe_runner.py --target "{目标}" --mode methods --url "{api_url}"
```

- 自动测试 OPTIONS/PUT/DELETE/PATCH/HEAD/TRACE
- 响应 200/201/204 的方法 → 写入 suspicious_points (test_type='method_tampering')

### 3.3 参数 Fuzz（脚本）

```bash
python3 TOOLS/pipeline/probe_runner.py --target "{目标}" --mode params --batch 20
```

- arjun 对 pages 表中带参数的 URL 批量发现隐藏参数
- 发现的参数 → 写入 suspicious_points (test_type='parameter_fuzz')

也可针对单个 URL：

```bash
python3 TOOLS/pipeline/probe_runner.py --target "{目标}" --mode params --url "{url}"
```

### 3.4 表单交互（AI 驱动）

```sql
SELECT url, forms_json FROM pages WHERE forms_json IS NOT NULL AND forms_json != '[]';
```

从 `forms_json` 提取 form action 和默认字段，通过 Burp POST 空数据/默认值：

```python
mcp__burp__send_http1_request(method="POST", url="http://目标/form-action", ...)
```

响应与空请求有差异 → 写 suspicious_points (test_type='form_interaction')。

### 3.5 认证/注册流探测（AI 驱动）

对含 login/register 特征的端点：

| 检查项 | 判定 |
|--------|------|
| 验证码可复用 | 同一 captcha token 请求 2 次，第二次仍 200 |
| 用户枚举 | 存在/不存在账号返回 code/size/msg 不同 |
| 注册开放 | POST 注册页返回 200+成功 |
| 默认凭证 | admin/admin123, test/test123 等 |

发现后写 suspicious_points (test_type='auth_flow')。

### 3.6 框架专项探测（nuclei）

根据 Phase 2 识别的框架，自动触发对应模板：

```bash
python3 TOOLS/pipeline/probe_runner.py --target "{目标}" --mode nuclei
```

- 自动从 `suspicious_points.evidence` 中匹配框架名 → 选 nuclei tags
- 若无框架指纹，使用默认 tags: `exposure,misconfiguration,default-login,tech`
- 发现 → 写 suspicious_points (test_type='framework_probe')

指定 tags：

```bash
python3 TOOLS/pipeline/probe_runner.py --target "{目标}" --mode nuclei --tags "springboot,thinkphp"
```

### 3.7 暂停条件

```sql
SELECT count(*) as untested FROM suspicious_points WHERE test_status='untested';
```

- `untested = 0` → 转 Phase 4 (brute)
- 处理完本轮 → 输出摘要退出（下次调用继续）

```sql
UPDATE scan_state SET phase='probe', total_suspicious=(SELECT count(*) FROM suspicious_points), call_count=call_count+1 WHERE id=1;
```

## Phase 4: 自动目录爆破

### 4.1 代理检查

```powershell
. .\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv
```

### 4.2 运行 brutescan

```bash
python3 TOOLS/pipeline/brutescan.py -u {target_url} -n 200 -o results.json
```

### 4.3 导入结果

```sql
INSERT INTO pages (url, depth, status) VALUES (?, 1, 'queued') ON CONFLICT(url) DO NOTHING;
```

### 4.4 转回 spider

```sql
UPDATE scan_state SET phase='spider' WHERE id=1;
```

有 queued → Phase 2。空 → 回 `probe`。

## 10 轮记忆总结机制

每次 skill 调用结束时执行：

```python
call_count += 1
db_query("UPDATE scan_state SET call_count=? WHERE id=1", [call_count])
if call_count % 10 == 0:
    write_memory_summary(target_name, call_count, scan_state)
```

write_memory_summary:
1. 读 scan_state（phase, total_pages, total_js, total_suspicious, total_findings）
2. 读 pages WHERE status='visited' 计数
3. 读 suspicious_points WHERE test_status='untested' top 5 by risk
4. 读 findings top 3 by risk
5. 写入 `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\{target_name}_progress.md`

Memory 文件格式：

```markdown
---
name: {target_name}-progress
description: {目标} 扫描进度记忆（自动每10轮更新）
metadata:
  type: project
  target: {target_name}
  last_updated: {datetime}
---

# {目标} 扫描进度 — {datetime}

## 当前状态
- Phase: {phase}
- 页面: {visited} visited / {total}
- JS: {n} analyzed
- 可疑点: {n} (untested: {n})
- 确认漏洞: {n}

## 关键发现
- {bullet points}

## 待处理
- {bullet points}
```

## 调用行为

每次 Skill 调用做一批工作后终止：

| phase | 工作量 |
|-------|--------|
| `spider` | bfs_crawl 一轮 + AI 分析 3-5 个关键页面 + 1 个 JS |
| `probe` | probe_runner params/nuclei 一轮 + AI 分析 3-5 条可疑点 |
| `brute` | brutescan 200 条 → 导入 → 切回 spider |
| 无可做工作 | 输出统计摘要后退出 |

```
=== stealth-scanner 执行摘要 ===
目标: {target_name}
Phase: {phase}
页面: {n} visited / {total} queued
JS: {n} analyzed
可疑点: {n} (untested: {n})
确认漏洞: {n}
call_count: {call_count}
```

## 数据库 schema

### targets

```sql
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    domain TEXT,
    ip TEXT,
    tech_stack TEXT,
    requires_auth INTEGER DEFAULT 0,
    auth_status TEXT DEFAULT 'not_logged_in',
    discovered_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);
```

### scan_state

```sql
CREATE TABLE scan_state (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    seed_url TEXT,
    phase TEXT DEFAULT 'init',
    started_at TEXT,
    max_depth INTEGER DEFAULT 3,
    max_pages INTEGER DEFAULT 200,
    total_pages INTEGER DEFAULT 0,
    total_js INTEGER DEFAULT 0,
    total_suspicious INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    call_count INTEGER DEFAULT 0,
    cdp_url TEXT DEFAULT NULL
);
```

### pages

```sql
CREATE TABLE pages (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    depth INTEGER DEFAULT 0,
    status TEXT DEFAULT 'queued',
    title TEXT,
    forms_json TEXT,
    js_files_json TEXT,
    api_calls_json TEXT,
    suspicious_params_json TEXT,
    crawled_at TEXT
);
```

### js_files

```sql
CREATE TABLE js_files (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    page_url TEXT,
    analyzed INTEGER DEFAULT 0,
    discovered_apis_json TEXT,
    hardcoded_secrets_json TEXT,
    internal_routes_json TEXT,
    debug_switches_json TEXT,
    analyzed_at TEXT
);
```

### suspicious_points

```sql
CREATE TABLE suspicious_points (
    id TEXT PRIMARY KEY,
    page_url TEXT,
    url TEXT,
    param TEXT,
    method TEXT DEFAULT 'GET',
    test_type TEXT,
    evidence TEXT,
    source TEXT,
    reasoning TEXT,
    risk TEXT DEFAULT 'Medium',
    test_status TEXT DEFAULT 'untested',
    burp_request_id INTEGER,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);
```

## 故障恢复

1. `SELECT phase FROM scan_state WHERE id=1` — 检查阶段
2. `SELECT url, depth FROM pages WHERE status='queued' ORDER BY depth` — 恢复 BFS 队列
3. `SELECT id, test_type FROM suspicious_points WHERE test_status='untested'` — 恢复 probe 队列
4. 从对应 phase 继续
