---
name: stealth-scanner
description: 网站爬虫与主动探测。BFS 发现页面/JS/端点（katana+httpx），框架指纹+参数fuzz+框架专项（nuclei+arjun）。机械动作全部由脚本完成，AI 只做分析判断。写 SQLite，不验证漏洞。每 10 轮写入 memory 进度总结。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Grep, Glob, Skill
---
# stealth-scanner

仅负责信息收集 + 主动探测。结果写 SQLite，漏洞验证由 vuln-review 在独立 session 完成。

## 使用方式

```bash
python TOOLS/run_scan.py --target "{目标}"
```

读输出标签并响应（见"输出标签处理"一节）。每次调用只运行一个批次后退出。重复调用直到扫描完成。

## 环境常量

| 常量        | 值                                                                              |
| ----------- | ------------------------------------------------------------------------------- |
| DBS_DIR     | `E:\SRC挖掘\SRC\dbs`                                                          |
| Memory 路径 | `C:\Users\llc\.Codex\projects\e--SRC---SRC\memory\{target_name}_progress.md` |

## 工具速查

| 场景                             | 命令                                                                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **启动/继续扫描**          | `python TOOLS/run_scan.py --target "{目标}"`                                                                  |
| 单独 JS 分析（两层）              | `python TOOLS/js_analyzer.py --target "{目标}" --batch 5`（第1层正则提取URL写pages；第2层含密钥信号才送mmx）  |
| DB 查询                          | `python TOOLS/db/db_query.py --target "{目标}" "SELECT ..."`                                                  |
| 资产侦察                         | `python TOOLS/recon/fofa_relay.py`                                                                            |
| 登录后恢复（写 auth_ready）      | `python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='auth_ready' WHERE id=1" --write` |
| Chrome 启动（auth_explore 需要） | `python TOOLS/auth/chrome_manager.py --target "{目标}"`                                                       |

## 前置检查

```bash
# Burp 在线
mcp__burp__list_proxy_http_history(count=1)

# 工具链
httpx --version && nuclei --version && katana --version

# DB 存在
python3 TOOLS/db/db_query.py --target "{目标}" --check
```

任一失败则提示对应组件不可用，终止执行。

## 状态机

phases: `init` → `auth_pending` → `auth_ready` → `auth_explore` → `spider` ↔ `probe` → `brute` → `spider`

| phase            | 含义                      | 由 run_scan.py 调用的脚本                      |
| ---------------- | ------------------------- | ---------------------------------------------- |
| `init`         | 初始化 + 技术指纹         | `pipeline/init_scan.py`                      |
| `auth_pending` | 等待操作员 Burp 手动登录  | —                                             |
| `auth_ready`   | 凭证已写入，自动切换      | —                                             |
| `auth_explore` | 认证后深度导航 + XHR 拦截 | `auth/auth_explore.py`                       |
| `spider`       | BFS 爬取 + JS 两层分析    | `pipeline/bfs_crawl.py` + `js_analyzer.py` |
| `probe`        | 参数 fuzz + nuclei 探测   | `pipeline/probe_runner.py`                   |
| `brute`        | 目录爆破                  | `pipeline/brutescan.py`                      |
| `auth_timeout` | 登录超时，等待操作员重试  | —                                             |
| `chrome_error` | Chrome CDP 启动失败       | —                                             |

## 输出标签处理

`run_scan.py` 输出结构化标签，AI 按如下规则响应：

| 标签                        | 含义                                 | AI 动作                                                      |
| --------------------------- | ------------------------------------ | ------------------------------------------------------------ |
| `[INIT_DONE]`             | 初始化完成，phase 已切为 spider      | 再次调用 `run_scan.py`                                     |
| `[SPIDER_BATCH]`          | 一轮 BFS + JS 分析完成，队列仍有页面 | 读摘要 → 再次调用 `run_scan.py`                           |
| `[PHASE_TRANSITION]`      | phase 已自动切换                     | 读新 phase → 再次调用 `run_scan.py`                       |
| `[NEW_SUSPICIOUS_POINTS]` | probe 发现新可疑点                   | 评估风险等级 → 高危转 vuln-review；再次调用 `run_scan.py` |
| `[AUTH_BARRIER]`          | 发现认证壁垒或登录超时               | 告知操作员（见"登录流程"一节），等待恢复                     |

### [NEW_SUSPICIOUS_POINTS] 处理细则

标签内含最多 10 条 SP 摘要（`id  method url  param  test_type  risk`）。

- `risk=High/Critical` 且 `test_type` 含 `idor/auth/sqli` → 立即通知操作员并转 vuln-review
- 其余 → 记录后再次调用 `run_scan.py` 继续

## 登录流程

init_scan 检测到认证壁垒 → `phase='auth_pending'` → `run_scan.py` 自动调用 `browser_auth.py`。

### AI 自动登录（browser_auth.py）

前置：环境变量 `DEEPSEEK_API` + `FEISHU_CHAT_ID` 已设置，Chrome 已启动（`:9222`）。

登录阻断处理：

| 阻断类型    | browser_auth.py 行为                                           |
| ----------- | -------------------------------------------------------------- |
| 图形验证码  | 截图 → 通过飞书发图给操作员 → 等待回复验证码 → 自动填写提交 |
| 二维码      | 截图 → 飞书发图 "请用手机扫码登录" → 等待页面跳转（3 分钟）  |
| 短信验证码  | 点击发送 → 飞书通知操作员 → 等待回复 → 自动填写提交         |
| 用户名/密码 | 若传入 `--username/--password` 直接填写；否则飞书询问操作员  |

登录成功 → `phase='auth_ready'`，再次调用 `run_scan.py` 继续。

### 降级：手动登录（browser_auth 失败时）

收到 `[AUTH_BARRIER]` 标签时，`browser_auth.py` 无法完成登录，操作员接管：

1. 启动 Chrome（若未启动）：
   ```bash
   python TOOLS/auth/chrome_manager.py --target "{目标}"
   ```
2. 通过 Burp 代理手动登录，成功后将 phase 设为 `auth_ready`：
   ```bash
   python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='auth_ready' WHERE id=1" --write
   ```
3. 再次调用 `run_scan.py`

### 认证完成后（并行 session 引导）

收到 `[PHASE_TRANSITION] auth_pending → auth_ready` 或 `[PHASE_TRANSITION] auth_explore → spider` 后，输出以下提示块，然后立即继续调用 `run_scan.py`（不等待操作员响应）：

```
=== 认证完成，建议同时启动 ===

Session B — vuln-review（随时消化现有 SP）:
  Skill(skill="vuln-review", args="模式: 复核; 目标: {目标}")

Session C — business-logic-hunt（需 Burp 历史有流量后启动）:
  Skill(skill="business-logic-hunt", args="目标: {目标}")

secondary 账号（IDOR 测试必需，有则注册）:
  python TOOLS/auth/browser_auth.py --target "{目标}" \
    --url "{登录URL}" --username <B账号> --password <B密码> \
    --role secondary --account-label secondary
```

## 容错

- 脚本调用失败 → run_scan.py 用 `check=False` 继续，打印 warn 行
- SQLite busy_timeout=5000，写失败等 1 秒重试
- HTTP 请求走 Burp 代理（127.0.0.1:8080）

## MiniMax 路由

遵循 `Skill(skill="mmx-router")` 的路由规则：何时必须把数据交给 mmx 处理、用哪些 prompt 模板。

## 10 轮记忆总结

每次 skill 调用结束时：

```bash
python3 TOOLS/db/db_query.py --target "{目标}" \
  "SELECT phase, total_pages, total_js, total_suspicious, total_findings, call_count FROM scan_state WHERE id=1"
```

若 `call_count % 10 == 0`，写 memory 摘要到 `{Memory 路径}/{target_name}_progress.md`：

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

每次 Skill 调用运行一次 `run_scan.py` 后终止，输出摘要：

```
=== stealth-scanner 执行摘要 ===
目标: {target_name}
Phase: {phase}  →  {new_phase}
页面: {n} visited / {total} queued
JS: {n} analyzed
可疑点: {n} (untested: {n})
确认漏洞: {n}
call_count: {call_count}
```

## 数据库 schema

```sql
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    domain TEXT, ip TEXT, tech_stack TEXT,
    requires_auth INTEGER DEFAULT 0,
    auth_status TEXT DEFAULT 'not_logged_in',
    discovered_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);

CREATE TABLE scan_state (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    seed_url TEXT, phase TEXT DEFAULT 'init',
    started_at TEXT, spider_ended_at TEXT, reviewed_at TEXT,
    max_depth INTEGER DEFAULT 3, max_pages INTEGER DEFAULT 200,
    total_pages INTEGER DEFAULT 0, total_js INTEGER DEFAULT 0,
    total_apis INTEGER DEFAULT 0, total_forms INTEGER DEFAULT 0,
    total_suspicious INTEGER DEFAULT 0, total_findings INTEGER DEFAULT 0,
    call_count INTEGER DEFAULT 0, cdp_url TEXT DEFAULT NULL
);

CREATE TABLE pages (
    id INTEGER PRIMARY KEY, url TEXT UNIQUE,
    depth INTEGER DEFAULT 0, status TEXT DEFAULT 'queued',
    title TEXT, links_found INTEGER DEFAULT 0,
    forms_json TEXT, js_files_json TEXT, api_calls_json TEXT,
    suspicious_params_json TEXT, crawled_at TEXT, source TEXT DEFAULT NULL
);

CREATE TABLE js_files (
    id INTEGER PRIMARY KEY, url TEXT UNIQUE, page_url TEXT,
    analyzed INTEGER DEFAULT 0,
    discovered_apis_json TEXT, hardcoded_secrets_json TEXT,
    internal_routes_json TEXT, debug_switches_json TEXT, analyzed_at TEXT
);

CREATE TABLE suspicious_points (
    id TEXT PRIMARY KEY, page_url TEXT, url TEXT, param TEXT,
    method TEXT DEFAULT 'GET', test_type TEXT, evidence TEXT,
    source TEXT, reasoning TEXT, risk TEXT DEFAULT 'Medium',
    test_status TEXT DEFAULT 'untested', burp_request_id INTEGER,
    created_at TEXT DEFAULT (datetime('now', 'localtime')), notes TEXT
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY, sp_id TEXT, target_id INTEGER REFERENCES targets(id),
    type TEXT, url TEXT, param TEXT, method TEXT, payload TEXT,
    evidence TEXT, risk TEXT, cvss TEXT, remediation TEXT,
    confirmed_at TEXT, burp_request_id INTEGER,
    review_status TEXT, review_notes TEXT,
    reported_platforms TEXT DEFAULT '', report_file TEXT,
    audit_status TEXT DEFAULT 'pending', audit_notes TEXT
);

CREATE TABLE auth_sessions (
    id INTEGER PRIMARY KEY, token_type TEXT, token_name TEXT,
    token_value TEXT, domain TEXT, path TEXT DEFAULT '/',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    role TEXT DEFAULT 'primary', expires_at TEXT,
    last_checked_at TEXT, cookie_source TEXT DEFAULT 'manual'
);

CREATE TABLE hunt_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    method TEXT NOT NULL, url TEXT NOT NULL,
    query_string TEXT, body TEXT, content_type TEXT,
    burp_history_id INTEGER, endpoint_type TEXT, business_intent TEXT,
    risk_hint TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'queued' CHECK(status IN ('queued','in_progress','tested','confirmed','error')),
    tested_types_json TEXT DEFAULT '[]', finding_ids TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    tested_at TEXT, notes TEXT,
    source TEXT DEFAULT 'auto' CHECK(source IN ('auto','manual_replay')),
    flow_id TEXT, UNIQUE(method, url, query_string)
);
```

## 故障恢复

```bash
# 检查当前 phase
python3 TOOLS/db/db_query.py --target "{目标}" "SELECT phase FROM scan_state WHERE id=1"

# 重置 phase（如需）
python3 TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='spider' WHERE id=1" --write

# 再次运行
python TOOLS/run_scan.py --target "{目标}"
```
