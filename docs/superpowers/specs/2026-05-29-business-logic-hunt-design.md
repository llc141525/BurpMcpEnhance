# business-logic-hunt Skill 设计文档

**日期**: 2026-05-29  
**状态**: 设计稿 / 待审阅  
**范围**: 业务逻辑漏洞主动猎手 skill 的完整设计

---

## 1. 背景与痛点

当前 SRC 工作流（asset-recon → stealth-scanner → vuln-review）的漏洞发现集中在**语法层**：
- SQL 注入、XSS、命令执行、文件上传 — 通过 payload 注入即可发现
- 信息泄露、框架漏洞 — 通过路径探针发现
- 参数 fuzz — 通过字典批量注入发现

高赏金漏洞几乎都在**语义层/业务逻辑层**，需要理解"业务流程"才能发现：
- IDOR 越权（换一个用户的 ID 看到别人的数据）
- 未授权访问（不登录能访问需认证接口）
- 验证码可复用/绕过
- 用户枚举
- 任意密码重置
- 参数逻辑替换（status/role/type 篡改）
- 敏感信息批量泄露

wooyun-legacy skill（含 88,636 个真实案例）已存在于项目但未被引用于工作流。stealth-scanner 的 Phase 3 probe 虽然做了参数 fuzz 和表单交互，但不构造"多个身份重放同一个请求"的业务验证场景。

## 2. Skill 元数据

```yaml
---
name: business-logic-hunt
description: 业务逻辑漏洞主动猎手。读 Burp 历史 → 筛业务接口 → 用 A/B 双账号+未授权三层重放 → 写 findings。覆盖 IDOR/未授权/信息泄露/验证码缺陷/用户枚举/密码重置/参数逻辑替换。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit
---
```

### 触发方式

```
Skill(skill="business-logic-hunt", args="目标: 台州学院")
Skill(skill="business-logic-hunt", args="目标: 台州学院; 模式: refresh")     # 重新采集 Burp 历史
```

### 状态推断

不引入独立 phase 表。从 `hunt_queue` 表内容推断阶段：

| 条件 | 推断阶段 |
|------|----------|
| 表不存在 | init（首次） |
| 表存在但空 | collecting（首次采集 Burp） |
| status='queued' > 0 | testing（有端点待测） |
| 全 tested/confirmed/error | done（全部处理完成） |

### 输入依赖

- **必须**: auth_sessions 表存在 ≥2 个 is_active=1 凭证，分别标 role='primary' 和 role='secondary'
- **必须**: Burp MCP 可用，历史 ≥10 条
- **可选**: 模式: refresh（强制重新采集 Burp 历史入队）

### 输出

- confirmed 漏洞 → `findings` 表
- low_confidence 发现 → `suspicious_points` 表（source='business_logic_hunt'）
- 队列状态 → `hunt_queue` 表

## 3. 账号模型（三层重放）

### 3.1 角色定义

| 角色 | 含义 | 来源 |
|------|------|------|
| primary | A 账号（原始操作员账号） | auth_sessions WHERE role='primary' |
| secondary | B 账号（不同用户） | auth_sessions WHERE role='secondary' |
| unauth | 无凭证 | 从请求中清除 Cookie/Authorization header |

### 3.2 凭证注入策略

```
if 原请求含 Cookie: JSESSIONID=xxx → 替换为对应 role 的 token
if 原请求含 Authorization: Bearer xxx → 同上
unauth → 直接删除上述两个 header
```

### 3.3 操作员准备 B 账号

```sql
INSERT INTO auth_sessions (token_name, token_value, domain, role, is_active)
VALUES ('JSESSIONID', 'B的session值', 'example.com', 'secondary', 1);
```

## 4. DB Schema

### 4.1 新表 `hunt_queue`

```sql
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
    status TEXT DEFAULT 'queued',
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

### 4.2 auth_sessions 加 role 字段

```sql
ALTER TABLE auth_sessions ADD COLUMN role TEXT DEFAULT 'primary';
-- 取值: 'primary' / 'secondary' / 'admin' / 'unauth'(占位)
```

### 4.3 迁移文件

```
migrations/004_add_hunt_queue.sql
migrations/005_add_auth_sessions_role.sql
```

幂等可重跑（IF NOT EXISTS / column 已存在则忽略）。

## 5. Phase: init（首次 / 恢复）

### 5.1 迁移自动执行

skill 启动时检查 migration 状态，执行 004 和 005。

### 5.2 前置检查

```sql
SELECT count(*) FROM auth_sessions WHERE is_active=1 AND role='primary';     -- must >=1
SELECT count(*) FROM auth_sessions WHERE is_active=1 AND role='secondary';   -- must >=1
```

检查失败 → 输出提示后退出。

### 5.3 恢复检查

```sql
SELECT status, count(*) FROM hunt_queue GROUP BY status;
```

- `in_progress` > 0 → 重置为 `queued`（因为中断）
- `queued` > 0 → 跳过 collecting，直接进入 testing
- 空 → 进入 collecting

## 6. Phase: collecting（Burp 历史 → 入队）

仅在首次调用或 `模式: refresh` 时执行。

### 6.1 Burp 历史分页采集

```python
# 分批读 Burp 历史（精简字段）
all_entries = []
offset = 0
batch_size = 500

while True:
    batch = mcp__burp__list_proxy_http_history(count=batch_size, offset=offset)
    if not batch or len(batch) == 0:
        break
    all_entries.extend(batch)
    offset += batch_size
    if offset > 10000:  # 硬上限
        break

# 本地预过滤（避免不必要的 mmx token 消耗）
filtered = [
    h for h in all_entries
    if not is_static(h.url)
    and h.method not in ("OPTIONS", "HEAD")
    and is_target_domain(h.url, target_domain)
]
```

`is_static`: `.css` / `.js` / `.png` / `.jpg` / `.svg` / `.ico` / `.woff` / `.ttf` / `.gif` / `.webp` / `.map`

### 6.2 mmx 筛选 prompt

```
你是 SRC 渗透测试助手，从 Burp HTTP 历史精简列表中筛选出"业务接口"。

输出 JSON 数组，每条:
{
  "burp_history_id": <int>,
  "method": "POST",
  "url": "https://example.com/api/order/get",
  "endpoint_type": "business_api" | "auth_login" | "auth_register" | "auth_reset_password" | "auth_verify_code",
  "business_intent": "<一句业务含义,如:查询订单详情>",
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

执行：
```bash
echo "{filtered_summary_json}" | mmx text chat --message "$(cat tmp/business_hunt_filter_prompt.txt)" --stdin
```

### 6.3 mmx 输出容错

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
        raise RuntimeError("mmx 输出无法解析为 JSON")
```

### 6.4 获取完整请求上下文

mmx 返回每条 → `mcp__burp__get_proxy_http_detail(id=burp_history_id)` → 解析 method/url/query_string/body/content_type。

### 6.5 入队

```sql
INSERT INTO hunt_queue (target_id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint, status)
VALUES ((SELECT id FROM targets WHERE target_name='{目标}'), ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued')
ON CONFLICT(method, url, query_string) DO NOTHING;
```

### 6.6 collecting → testing 流转

不写 phase。下次调用时 `SELECT count(*) FROM hunt_queue WHERE status='queued'` > 0 自动进入 testing。

## 7. Phase: testing（主循环）

### 7.1 端点类型 → 测试组合映射

```
business_api          → [idor, unauth, info_leak, param_logic]
auth_login            → [user_enum, captcha_reuse]
auth_register         → [captcha_reuse, user_enum]
auth_reset_password   → [password_reset_takeover, user_enum]
auth_verify_code      → [captcha_reuse]
```

### 7.2 主循环

```python
# 1. 取本轮 5 个 queued
batch = db_query("""
    SELECT id, method, url, query_string, body, content_type,
           burp_history_id, endpoint_type, business_intent, risk_hint
    FROM hunt_queue
    WHERE status='queued'
    ORDER BY
        CASE risk_hint WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
        id
    LIMIT 5
""")

if not batch:
    print("队列空 → done")

# 2. 加载三套凭证
primary   = load_session(role='primary')
secondary = load_session(role='secondary')

# 3. 处理每个端点
for ep in batch:
    db_update(ep.id, status='in_progress')
    tested_types = []
    finding_ids = []

    for test_type in ENDPOINT_TYPE_MAP[ep.endpoint_type]:
        try:
            result = run_test(test_type, ep, primary, secondary)
            tested_types.append(test_type)
            if result.confidence == 'confirmed':
                fid = write_finding(test_type, ep, result)
                finding_ids.append(fid)
            elif result.confidence == 'low_confidence':
                write_suspicious(test_type, ep, result)
        except Exception as e:
            log_error(ep.id, test_type, e)
            continue

    new_status = 'confirmed' if finding_ids else 'tested'
    db_update(ep.id,
              status=new_status,
              tested_types_json=json.dumps(tested_types),
              finding_ids=','.join(finding_ids),
              tested_at=now())
```

### 7.3 三层重放工具函数

```python
def replay_three_layer(endpoint, primary, secondary):
    """同一请求用三种身份重放 — 返回各响应"""
    req_A      = inject_credentials(endpoint.raw_request, primary)
    req_B      = inject_credentials(endpoint.raw_request, secondary)
    req_unauth = strip_credentials(endpoint.raw_request)

    return {
        'A':      send_via_burp(req_A),
        'B':      send_via_burp(req_B),
        'unauth': send_via_burp(req_unauth),
    }
```

## 8. 七类测试算法

以下每类测试输出 `{confidence, evidence, payload, risk, affected_param, reasoning}`，其中 `confidence` ∈ `{'confirmed', 'low_confidence', 'no_vuln'}`。

### 8.1 idor — IDOR 越权

```
三层重放 → 比对 A 和 B 的响应体

if A.status == 200 and B.status == 200:
    similarity = SequenceMatcher(None, A_body, B_body).ratio()
    if similarity > 0.85:
        → confirmed（B 看到了 A 的数据）
    elif similarity > 0.5:
        → low_confidence（可能是同名资源）

evidence = "A {len(A_body)} vs B {len(B_body)}, 相似度 {similarity:.2f}"
```

### 8.2 unauth — 未授权访问

```
if A.status == 200 and unauth.status == 200:
    similarity = SequenceMatcher(None, A_body, unauth_body).ratio()
    if similarity > 0.85:
        → confirmed
elif unauth.status == 200 and len(unauth_body) > 100
     and not contains_login_keyword(unauth_body):
    → low_confidence

contains_login_keyword: 'login'/'登录'/'未登录'/'401'/'unauthorized'
```

### 8.3 info_leak — 业务信息泄露

```
正则扫描 A 响应 body:
  PHONE_RE  = r'1[3-9]\d{9}'
  IDCARD_RE = r'\d{17}[\dXx]'
  EMAIL_RE  = r'[\w.-]+@[\w.-]+'

if matches > 3 and is_json_array_response:
    → confirmed（批量泄露）
elif matches > 0:
    → low_confidence
```

### 8.4 param_logic — 参数逻辑替换

```
LOGIC_PARAMS = ['status', 'role', 'type', 'level', 'is_admin', 'admin',
                'group', 'permission', 'state', 'enabled', 'verified']
LOGIC_VALUES = {'status': ['1','999'], 'role': ['admin','superuser'],
                'type': ['admin','1'], 'is_admin': ['true','1'],
                'enabled': ['true'], 'verified': ['true']}

for param_name in extract_params(endpoint):
    if param_name in LOGIC_PARAMS:
        for new_value in LOGIC_VALUES[param_name]:
            modified_req = replace(endpoint, param_name, new_value)
            resp = send_with_A_token(modified_req)
            if resp.status == 200 and (
                contains_success_keyword(resp.body)
                or len(resp.body) > len(A_body) + 100
            ):
                → confirmed
                break

contains_success_keyword: 'success'/'操作成功'/'修改成功'/'已更新'/'OK'
```

### 8.5 user_enum — 用户枚举

```
已知用户名（默认试 'admin'）：

resp_exists    = send_with(username='admin')
resp_notexists = send_with(username='nonexistent_' + random())

if abs(resp_exists.status - resp_notexists.status) != 0:
    → confirmed（状态码不同）
elif abs(len(resp_exists.body) - len(resp_notexists.body)) > 0.2 * len(resp_exists.body):
    → confirmed（长度差异 >20%）
elif response_msg_differs(resp_exists.body, resp_notexists.body):
    → low_confidence
```

### 8.6 captcha_reuse — 验证码可复用

```
仅当原请求含 captcha/verifyCode/code/sms_code 字段

resp1 = replay(endpoint, with_A_token)
resp2 = replay(endpoint, with_A_token)     # 同一 captcha 重放

if resp1.status == 200 and resp2.status == 200
   and contains_success_keyword(resp1.body)
   and contains_success_keyword(resp2.body):
    → confirmed
elif resp2.status == 200
     and not contains_keyword(resp2.body, ['过期','已使用','expired','used']):
    → low_confidence
```

### 8.7 password_reset_takeover — 任意密码重置

```
扫 endpoint 参数:
  TARGET_FIELDS = {'phone': '13800000000', 'email': 'attacker@evil.com',
                    'uid': '1', 'account': 'admin', 'username': 'admin'}

for param_name in extract_params(endpoint):
    if param_name in TARGET_FIELDS:
        modified_req = replace(endpoint, param_name, TARGET_FIELDS[param_name])
        resp = send_unauth(modified_req)

        if resp.status == 200 and contains_success_keyword(resp.body):
            → confirmed
        elif resp.status == 200
             and not contains_keyword(resp.body, ['不存在','invalid','失败','not found']):
            → low_confidence
```

## 9. 输出处理

### 9.1 confirmed → findings（双轨去重）

```python
def write_finding(test_type, endpoint, result):
    # 去重：检查同端点同类型是否已有 finding
    existing = db_query("""
        SELECT id FROM findings
        WHERE type='business_{}'
        AND url='{}'
        AND method='{}'
    """.format(test_type, endpoint.url, endpoint.method))
    if existing:
        return None                     # 已有不重复写

    finding_id = "F-BLH-{}".format(next_seq())
    risk_map = {
        'idor': 'High', 'unauth': 'High', 'info_leak': 'High',
        'password_reset_takeover': 'Critical',
        'param_logic': 'High', 'user_enum': 'Medium', 'captcha_reuse': 'Medium'
    }

    db_insert('findings', {
        'id': finding_id,
        'sp_id': 'BLH-{}'.format(endpoint.id),
        'target_id': endpoint.target_id,
        'type': 'business_' + test_type,
        'url': endpoint.url,
        'param': result.affected_param or '',
        'method': endpoint.method,
        'payload': result.payload,
        'evidence': result.evidence,
        'risk': risk_map[test_type],
        'cvss': '',
        'remediation': REMEDIATION_TEMPLATES[test_type],
        'confirmed_at': now(),
        'burp_request_id': result.burp_resend_id,
        'review_status': None,
        'audit_status': 'pending'
    })
    return finding_id
```

### 9.2 low_confidence → suspicious_points

```python
def write_suspicious(test_type, endpoint, result):
    sp_id = "SP-BLH-{}".format(next_seq())
    db_insert('suspicious_points', {
        'id': sp_id,
        'page_url': endpoint.url,
        'url': endpoint.url,
        'param': result.affected_param or '',
        'method': endpoint.method,
        'test_type': 'business_' + test_type,
        'evidence': result.evidence,
        'source': 'business_logic_hunt',
        'reasoning': result.reasoning,
        'risk': 'Medium',
        'test_status': 'untested',
        'burp_request_id': result.burp_resend_id,
    })
```

### 9.3 终端摘要

```
=== business-logic-hunt 执行摘要 ===
目标: 台州学院
队列: queued 127 | tested 48 | confirmed 12 | error 3

本轮 confirmed (2):
  F-BLH-013 idor    POST /api/order/get         id=42     (High)
  F-BLH-014 unauth  GET  /api/user/profile                 (High)

本轮 low_confidence (写入 suspicious_points，待 vuln-review 复核):
  SP-BLH-027 info_leak  GET  /api/userList                 (Medium)

本轮 Burp 请求: ~45 次
如需复核 SP-BLH-* 请运行: vuln-review
如需切换 IP: Switch-ClashProxy
```

## 10. 故障恢复

| 失败场景 | 动作 |
|---------|------|
| skill 中途崩溃，端点 `in_progress` | 启动时重置回 `queued` |
| 单端点超时/Burp 失败 | 标 `error` + notes，跳过 |
| A 账号 session 过期（302/401） | 标 `error`，提示重登，退出 |
| Burp MCP 不可用 | 退出，输出"Burp 离线" |
| mmx JSON 解析失败 | 兜底提取 → 仍失败写 `tmp/business_hunt_mmx_error_{ts}.txt` 后退出 |
| SQLite busy | 等 1s 重试 3 次 |
| WAF 拦截（403/451） | 标 `error` + notes='WAF blocked'，跳过（不绕过） |

## 11. 调用约定

| 维度 | 约束 |
|------|------|
| 每轮端点数 | ≤5 |
| 每轮 Burp 请求 | ≤45（5 端点 × 3 测试 × 3 层） |
| 每端点 findings | ≤7（每测试类型至多 1 条，去重） |
| 运行时长目标 | ≤5 分钟（不含 mmx） |
| IP 切换 | 不自动，每轮提示操作员 |

## 12. 对外影响清单

| 受影响的 skill/文件 | 改动 |
|-------------------|------|
| stealth-scanner Phase 1.2.1 | auth_sessions 查询加 `AND role='primary'` |
| stealth-scanner Phase 2.0 | auth_sessions 查询加 `AND role='primary'` |
| vuln-review Step 2a | 说明 `likely_fixed_types` 不含 `business_*` 前缀 |
| TOOLS/migrate.py | 加 004/005 迁移检测 |
| CLAUDE.md | skill 表加 business-logic-hunt 行 |

## 13. 操作员首次使用流程

```
1. 登录 A 账号（已有，role='primary'）
2. 通过 Burp 浏览器登录 B 账号
3. 从 Burp 历史找到 B 的 cookie/token
4. INSERT INTO auth_sessions VALUES (..., 'secondary', 1)
5. 运行: Skill(skill="business-logic-hunt", args="目标: 台州学院")
   → 自动采集 Burp 历史 + 过滤 + 入队
6. 查看摘要 → 重调用即可继续
7. 确认 findings → src-report 生成报告
8. SP-BLH-* 低置信度 → vuln-review 复核
```

---

## 13.1 已知局限

| 局限 | 影响 | 原因 |
|------|------|------|
| CSRF token 不处理 | 含 CSRF token 的端点重放 B 账号可能 403 | 请求中的 token 值属于 A 账号，MV 层不替换 |
| JSON body 中的业务 ID | POST `{"userId": 42}` 语义不会替换 | MV 层只替换 header 级的凭证，不改 body 语义 |
| 字符相似度阈值 | IDOR 判定倚赖响应体对比，动态页面可能误判 | MV 层不做语义理解 |
| 单端点三种凭证串行 | 不是独立并发，时序差异可能引入噪声 | MVP 简洁优先 |

## 14. 未纳入 MVP 的功能

| 功能 | 原因 |
|------|------|
| 自动注册临时账号 | 需验证码处理，复杂度高 |
| 复杂业务链测试 | 步骤间状态依赖，增量难实现 |
| 并发请求（Race condition） | 时序问题，单次调用无法保证 | 
| WAF 绕过 | vuln-review 已有实现，不重复 |
| 响应 AI 判定 | MiniMax 介入响应分析，后续评估 |
