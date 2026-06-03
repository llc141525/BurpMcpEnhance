# business-logic-hunt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the business-logic-hunt skill — a Burp-driven business logic vulnerability hunter that uses A/B dual-account + unauth three-layer replay to detect IDOR, unauth access, info leaks, captcha reuse, user enum, password reset takeover, and param logic tampering.

**Architecture:** Independent skill (no dependency on stealth-scanner/vuln-review). Uses `hunt_queue` table for incremental queue processing. Writes confirmed findings directly, low-confidence results to suspicious_points for vuln-review to handle.

**Tech Stack:** Burp MCP (HTTP replay), MiniMax CLI (Burp history filtering), SQLite (state), Python db_query.py (DB ops)

---

## File Inventory

| Action | File | Purpose |
|--------|------|---------|
| Create | `migrations/004_add_hunt_queue.sql` | hunt_queue 表 + 索引 |
| Create | `migrations/005_add_auth_sessions_role.sql` | auth_sessions.role 字段 |
| Create | `.claude/skills/business-logic-hunt/SKILL.md` | 主 skill 文件 |
| Modify | `.claude/skills/stealth-scanner/SKILL.md:131` | auth_sessions 查询加 `AND role='primary'` |
| Modify | `.claude/skills/stealth-scanner/SKILL.md:179` | auth_sessions 查询加 `AND role='primary'` |
| Modify | `CLAUDE.md:104-110` | Skills 表加 business-logic-hunt 行 |
| Modify | `CLAUDE.md:140-177` | 工作流加 hunting 第 2.5 步 |

---

### Task 1: 迁移文件 — 004_add_hunt_queue.sql

**Files:**
- Create: `migrations/004_add_hunt_queue.sql`

- [ ] **Step 1: 写迁移文件**

```sql
-- 004: business-logic-hunt 队列表
CREATE TABLE IF NOT EXISTS hunt_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    query_string TEXT,
    body TEXT,
    content_type TEXT,
    burp_history_id INTEGER,
    endpoint_type TEXT,
    business_intent TEXT,
    risk_hint TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'queued' CHECK(status IN ('queued','in_progress','tested','confirmed','error')),
    tested_types_json TEXT DEFAULT '[]',
    finding_ids TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    tested_at TEXT,
    notes TEXT,
    UNIQUE(method, url, query_string)
);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_status ON hunt_queue(status);
CREATE INDEX IF NOT EXISTS idx_hunt_queue_target ON hunt_queue(target_id);
```

- [ ] **Step 2: 验证格式**

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect(':memory:')
conn.executescript(open('migrations/004_add_hunt_queue.sql', encoding='utf-8').read())
cols = [r[1] for r in conn.execute('PRAGMA table_info(hunt_queue)').fetchall()]
assert 'id' in cols and 'target_id' in cols and 'method' in cols
print('004: OK —', len(cols), 'columns')
"
```

Expected: `004: OK — 14 columns`

- [ ] **Step 3: Commit**

```bash
git add migrations/004_add_hunt_queue.sql
git commit -m "feat: add hunt_queue table (migration 004)"
```

---

### Task 2: 迁移文件 — 005_add_auth_sessions_role.sql

**Files:**
- Create: `migrations/005_add_auth_sessions_role.sql`

- [ ] **Step 1: 写迁移文件**

```sql
-- 005: auth_sessions 增加角色字段（支持双账号/三层重放）
ALTER TABLE auth_sessions ADD COLUMN role TEXT DEFAULT 'primary';
```

- [ ] **Step 2: 验证幂等性**

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect(':memory:')
conn.executescript('CREATE TABLE auth_sessions (id INTEGER PRIMARY KEY, token_name TEXT, token_value TEXT, domain TEXT, is_active INTEGER DEFAULT 1);')
conn.executescript(open('migrations/005_add_auth_sessions_role.sql').read())
# 两次执行不报错
conn.executescript(open('migrations/005_add_auth_sessions_role.sql').read())
cols = {r[1] for r in conn.execute('PRAGMA table_info(auth_sessions)').fetchall()}
assert 'role' in cols
print('005: OK — add column is idempotent')
"
```

Expected: `005: OK — add column is idempotent`

- [ ] **Step 3: Commit**

```bash
git add migrations/005_add_auth_sessions_role.sql
git commit -m "feat: add auth_sessions.role column (migration 005)"
```

---

### Task 3: stealth-scanner auth_sessions 查询修复

**Files:**
- Modify: `.claude/skills/stealth-scanner/SKILL.md:131`
- Modify: `.claude/skills/stealth-scanner/SKILL.md:179`

- [ ] **Step 1: 修复 Phase 1.2.1 的查询（line 131）**

改前:
```sql
SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1;
```

改后:
```sql
SELECT token_name, token_value, domain FROM auth_sessions WHERE is_active=1 AND (role='primary' OR role IS NULL);
```

- [ ] **Step 2: 修复 Phase 2.0 的查询（line 179）**

改前:
```sql
SELECT token_name, token_value FROM auth_sessions WHERE is_active=1 AND domain LIKE '%{domain}%';
```

改后:
```sql
SELECT token_name, token_value FROM auth_sessions WHERE is_active=1 AND (role='primary' OR role IS NULL) AND domain LIKE '%{domain}%';
```

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/stealth-scanner/SKILL.md
git commit -m "fix: add role='primary' filter to stealth-scanner auth_sessions queries"
```

---

### Task 4: business-logic-hunt SKILL.md（主 skill）

**Files:**
- Create: `.claude/skills/business-logic-hunt/SKILL.md`

这是最大的任务。SKILL.md 是 Claude 执行的主指令文件，包含完整的工作流、prompt 模板和判定逻辑。

- [ ] **Step 1: 写 SKILL.md**

```markdown
---
name: business-logic-hunt
description: 业务逻辑漏洞主动猎手。读 Burp 历史 → 筛业务接口 → 用 A/B 双账号+未授权三层重放 → 写 findings。覆盖 IDOR/未授权/信息泄露/验证码缺陷/用户枚举/密码重置/参数逻辑替换。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit
---

# business-logic-hunt

独立运行，不依赖 stealth-scanner / vuln-review。

## 环境常量

| 常量 | 值 |
|------|-----|
| DBS_DIR | `E:\SRC挖掘\SRC\dbs` |
| DB 操作 | `TOOLS/db_query.py` |
| Burp 历史 | `mcp__burp__list_proxy_http_history` / `get_proxy_http_detail` |
| MiniMax | `mmx text chat --message` |
| 代理预热 | `.\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv` |

## 入口

```
Skill(skill="business-logic-hunt", args="目标: 台州学院")
Skill(skill="business-logic-hunt", args="目标: 台州学院; 模式: refresh")
```

### 入口检查

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT count(*) FROM auth_sessions WHERE is_active=1 AND role='primary'"
python3 TOOLS/db_query.py --target "{目标}" "SELECT count(*) FROM auth_sessions WHERE is_active=1 AND role='secondary'"
```

Primary >=1 且 secondary >=1 → 继续。否则输出：
```
请准备 primary + secondary 账号。
primary: 已有 token 自动 role='primary'（默认）
secondary: INSERT INTO auth_sessions (token_name, token_value, domain, role, is_active) VALUES ('JSESSIONID', 'xxx', 'example.com', 'secondary', 1);
```

### 迁移

```bash
python3 TOOLS/migrate.py --target "{目标}"
```

### 阶段推断

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hunt_queue'"
```

- 表不存在 → init 阶段（首次运行，自动迁移）
- 表存在但空 → collecting 阶段
- `SELECT count(*) FROM hunt_queue WHERE status='queued'` > 0 → testing 阶段
- 全 tested/confirmed/error → done 阶段

### 状态恢复

```bash
# 处理上一轮中断的 in_progress
python3 TOOLS/db_query.py --target "{目标}" "UPDATE hunt_queue SET status='queued' WHERE status='in_progress'" --write
```

## 容错

1. Burp MCP 调用失败 → 等待 2 秒重试 → 最多 3 次
2. SQLite busy → 等待 1 秒重试 → 最多 3 次
3. 单个端点失败 → 标 error 跳过，继续下一条
4. A 账号 session 过期(302/401) → 标 error + notes="primary session expired"，提示重登
5. WAF 拦截(403/451) → 标 error + notes="WAF blocked"，跳过
6. mmx JSON 解析失败 → 兜底提取 → 仍失败退出

## Phase: collecting

### 1. Burp 历史分页

```bash
# 分批读取（精简字段）
mcp__burp__list_proxy_http_history(count=500, offset=0)
mcp__burp__list_proxy_http_history(count=500, offset=500)
# ... 直到空或 offset>10000
```

读取目标域名（从 targets.domain 获取）。本地预过滤：
- 移除静态资源（.css/.js/.png/.jpg/.svg/.ico/.woff/.ttf/.gif/.webp/.map）
- 移除 OPTIONS/HEAD 请求
- 只保留目标域名或其子域的 URL

### 2. mmx 筛选

**Prompt 文件**（写入 `tmp/business_hunt_filter_prompt.txt`）:

```
你是 SRC 渗透测试助手，从 Burp HTTP 历史精简列表中筛选出"业务接口"。

输出 JSON 数组，每条:
{
  "burp_history_id": <int>,
  "method": "POST",
  "url": "https://example.com/api/order/get",
  "endpoint_type": "business_api" | "auth_login" | "auth_register" | "auth_reset_password" | "auth_verify_code",
  "business_intent": "<一句话业务含义,如:查询订单详情>",
  "risk_hint": "High" | "Medium" | "Low"
}

判定规则:
- auth_login/register/reset_password/verify_code: URL 含 login/register/reset/forget/sms/captcha 等关键字
- business_api: URL 含 /api/ 或 .do/.action 且非登录类
- risk_hint=High: 操作敏感对象（含 id/uid/oid 参数 或 method=DELETE/PUT）
- risk_hint=Medium: 普通 GET 查询业务数据
- risk_hint=Low: 字典/枚举查询（/dict, /options, /list 无参数）

排除:
- 第三方 CDN/统计/广告域名
- 同一 URL 重复出现的请求保留 risk_hint 最高的一条
- 仅 health check / version 端点

返回纯 JSON 数组, 不要 markdown 围栏或解释文字。
```

**调用**：

```bash
echo '{过滤后的精简JSON}' | mmx text chat --message "$(cat tmp/business_hunt_filter_prompt.txt)" --stdin
```

**输出容错**：
```python
raw = mmx_output
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    start = raw.find('[')
    end = raw.rfind(']')
    if start >= 0 and end > start:
        data = json.loads(raw[start:end+1])
    else:
        print("[错误] mmx 输出无法解析为 JSON，已写入 tmp/business_hunt_mmx_error_{ts}.txt")
        exit()
```

### 3. 拿完整请求 + 入队

对 mmx 返回的每条：

```bash
mcp__burp__get_proxy_http_detail(id={burp_history_id})
```

解析完整请求 → 提取 method/url/query_string/body/content_type。

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO hunt_queue (target_id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint, status) \
   VALUES ((SELECT id FROM targets WHERE target_name='{目标}'), ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued')" \
  --write --params '["{method}","{url}","{query_string}","{body}","{content_type}",{burp_history_id},"{endpoint_type}","{business_intent}","{risk_hint}"]'
```

### 4. 采集完成

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT count(*) FROM hunt_queue"
```

输出 "采集完成: {n} 个业务端 -> 入队"。

## Phase: testing

### 主循环

```bash
# 1. 取 5 个 queued，优先 risk_hint=High
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint \
   FROM hunt_queue WHERE status='queued' \
   ORDER BY CASE risk_hint WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, id LIMIT 5"
```

结果空 → 输出 "队列空，全部处理完成" → clean exit。

### 端点类型 → 测试映射

```
business_api          → [idor, unauth, info_leak, param_logic]
auth_login            → [user_enum, captcha_reuse]
auth_register         → [captcha_reuse, user_enum]
auth_reset_password   → [password_reset_takeover, user_enum]
auth_verify_code      → [captcha_reuse]
```

### 三层重放核心

```python
# 重构 HTTP 请求
# 从 burp_history_id 拿原始请求
# 用对应 role 的 token 替换 Cookie/Authorization 值
# A 请求: primary token
# B 请求: secondary token
# unauth: 删除 Cookie 和 Authorization header

def inject_credentials(raw_request, token_name, token_value):
    """替换请求中的 Cookie / Authorization header"""
    # 读取原始请求的 method / url / headers / body
    # 替换或新增 Cookie header
    # 保持其他 header 不变
    return modified_request

def strip_credentials(raw_request):
    """删除 Cookie 和 Authorization header"""
    pass
```

### 测试算法

#### idor
```python
# 三层重放后比对 A_body 和 B_body
# A.status==200 and B.status==200:
#   similarity = SequenceMatcher(None, A_body, B_body).ratio()
#   >0.85 → confirmed (B 看到了 A 的数据)
#   >0.5  → low_confidence
```

#### unauth
```python
# A.status==200 and unauth.status==200:
#   similarity > 0.85 → confirmed（未授权可访问）
# unauth.status==200 and len(body)>100 and not login_keyword:
#   → low_confidence
# login_keyword: login/登录/未登录/401/unauthorized
```

#### info_leak
```python
# 正则扫描 A_body:
# PHONE=1[3-9]\d{9}, IDCARD=\d{17}[\dXx], EMAIL=[\w.-]+@[\w.-]+
# matches > 3 and is_json_array → confirmed（批量泄露）
# matches > 0 → low_confidence
```

#### param_logic
```python
# LOGIC_PARAMS = ['status','role','type','level','is_admin','admin','group','permission','state','enabled','verified']
# LOGIC_VALUES = {'status':['1','999'],'role':['admin','superuser'],'type':['admin','1'],'is_admin':['true','1'],'enabled':['true'],'verified':['true']}
# 提取参数名，命中 LOGIC_PARAMS 则替换为各新值重发
# 响应 200 + success_keyword('success'/'操作成功'/'修改成功'/'已更新'/'OK')
#   或 响应长度差异 >+100 → confirmed
```

#### user_enum
```python
# 默认试 username=admin vs username=nonexistent_xyz_{random}
# 状态码不同 → confirmed
# 响应长度差异 >20% → confirmed
# 响应消息不同 → low_confidence
```

#### captcha_reuse
```python
# 原请求含 captcha/verifyCode/code/sms_code 字段
# 同一 captcha 重放 2 次
# 两次都 200 + success_keyword → confirmed
# 第二次 200 且无 '过期'/'已使用'/'expired'/'used' → low_confidence
```

#### password_reset_takeover
```python
# TARGET_FIELDS = {'phone':'13800000000','email':'attacker@evil.com','uid':'1','account':'admin'}
# 参数命中 → 替换为 target value → 发送 unauth 请求
# 200 + success_keyword → confirmed
# 200 且无 '不存在'/'invalid'/'失败' → low_confidence
```

### 写 findings（confirmed）

```bash
# 去重检查 — 同类型+同URL+同method 已有 finding 则跳过
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id FROM findings WHERE type='business_{test_type}' AND url='{url}' AND method='{method}'"

# 生成 F-BLH-{n} ID (从现有 BLH 最大编号 +1)
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT COALESCE(MAX(CAST(SUBSTR(id,7) AS INTEGER)), 0)+1 FROM findings WHERE id LIKE 'F-BLH-%'"
```

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id, review_status, audit_status) \
   VALUES ('F-BLH-{seq}', 'BLH-{endpoint_id}', (SELECT id FROM targets WHERE target_name='{目标}'), 'business_{test_type}', '{url}', '{param}', '{method}', '{payload}', '{evidence}', '{risk}', '', '{remediation}', datetime('now','localtime'), {burp_request_id}, NULL, 'pending')" \
  --write
```

risk 映射: idor=High, unauth=High, info_leak=High, password_reset_takeover=Critical, param_logic=High, user_enum=Medium, captcha_reuse=Medium

### 写 suspicious_points（low_confidence）

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO suspicious_points (id, page_url, url, param, method, test_type, evidence, source, reasoning, risk, test_status, burp_request_id, created_at) \
   VALUES ('SP-BLH-{seq}', '{url}', '{url}', '{param}', '{method}', 'business_{test_type}', '{evidence}', 'business_logic_hunt', '{reasoning}', 'Medium', 'untested', {burp_request_id}, datetime('now','localtime'))" \
  --write
```

### 更新端点状态

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "UPDATE hunt_queue SET status='{confirmed/tested}', tested_types_json='[{tested_types_json}]', finding_ids='{finding_ids}', tested_at=datetime('now','localtime') WHERE id={id}" \
  --write
```

### 终端摘要

```
=== business-logic-hunt 执行摘要 ===
目标: {target_name}
队列: queued {n} | tested {n} | confirmed {n} | error {n}

本轮 confirmed ({n}):
  F-BLH-{id} {type} {method} {url} ({risk})

本轮 low_confidence（待 vuln-review 复核）:
  SP-BLH-{id} {type} {method} {url}

本轮 Burp 请求: ~{n} 次
如需复核 SP-BLH-* 请运行: vuln-review
如需切换 IP: Switch-ClashProxy
```

## 升级操作员

- A 账号 session 过期 → 暂停，提示重新登录
- 高危漏洞（password_reset_takeover confirmed）→ 升级操作员确认合规性
- Burp MCP 不可用 → 退出
- mmx 连续异常 → 退出
```

> 注意：以上 SKILL.md 是指导 Claude 执行的指令集。Claude 在执行时会逐句按指示走，Readd 该文件并按步骤行动。

- [ ] **Step 2: 验证文件**

```bash
python3 -c "
import yaml
with open('.claude/skills/business-logic-hunt/SKILL.md') as f:
    content = f.read()
# 检查 frontmatter
parts = content.split('---')
assert len(parts) >= 3
meta = yaml.safe_load(parts[1])
assert meta['name'] == 'business-logic-hunt'
assert 'mcp__burp__' in meta['allowed-tools'][0]
print('SKILL.md: frontmatter OK')
"
```

Expected: `SKILL.md: frontmatter OK`

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/business-logic-hunt/SKILL.md
git commit -m "feat: add business-logic-hunt skill"
```

---

### Task 5: 更新 CLAUDE.md — Skills 表

**Files:**
- Modify: `CLAUDE.md:104-110`

- [ ] **Step 1: Skills 表加一行**

在 asset-recon 和 stealth-scanner 之间插入：

```
| **business-logic-hunt** | Burp 历史 → 三层重放 → IDOR/未授权/信息泄露/验证码/枚举/逻辑替换 | `Skill(skill="business-logic-hunt", args="目标: 台州学院")` |
```

- [ ] **Step 2: 在文件底部的工作流 2 和 3 之间插入 hunting 步骤**

在 `### 2. 扫描（stealth-scanner）` 和 `### 3. 复核（vuln-review）` 之间插入：

```markdown
### 2.5 业务逻辑猎手（business-logic-hunt）

操作员调用 `Skill(skill="business-logic-hunt", args="目标: 台州学院")` 深度挖掘业务漏洞：
- 读取 Burp 历史 → MiniMax 筛选业务接口
- 三层重放测试（A 账号 / B 账号 / 未授权）
- 确认漏洞直接写 findings 表（F-BLH-* 前缀）
- 低置信度发现写 suspicious_points 表（SP-BLH-* 前缀）
- 增量队列模式，每次调用处理 5 个端点
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add business-logic-hunt to CLAUDE.md skill table and workflow"
```

---

### Task 6: DB 迁移验证 + 端到端检查

**Files:** (none new) — run validation

- [ ] **Step 1: 迁移已存在的目标 DB**

```bash
python3 TOOLS/migrate.py --target "浙江省教育厅" --status
# 确认当前版本
python3 TOOLS/migrate.py --target "浙江省教育厅"
# 确认成功升级到 v5
```

- [ ] **Step 2: 验证 auth_sessions 有 role 列**

```bash
python3 TOOLS/db_query.py --target "浙江省教育厅" "PRAGMA table_info(auth_sessions)" | python3 -c "import sys,json; cols=[c['name'] for c in json.load(sys.stdin)]; assert 'role' in cols; print('auth_sessions.role:', 'OK')"
```

- [ ] **Step 3: 验证 hunt_queue 表已创建**

```bash
python3 TOOLS/db_query.py --target "浙江省教育厅" "PRAGMA table_info(hunt_queue)" | python3 -c "import sys,json; cols=[c['name'] for c in json.load(sys.stdin)]; assert 'id' in cols; assert 'endpoint_type' in cols; print('hunt_queue:', len(cols), 'columns OK')"
```

- [ ] **Step 4: 所有文件提交状态检查**

```bash
git status
# 确认所有文件已提交
```
