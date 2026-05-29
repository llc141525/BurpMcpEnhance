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
python3 TOOLS/db_query.py --target "{目标}" "UPDATE hunt_queue SET status='queued' WHERE status='in_progress'" --write
```

## 容错

1. Burp MCP 调用失败 → 等待 2 秒重试 → 最多 3 次
2. SQLite busy → 等待 1 秒重试 → 最多 3 次
3. 单个端点失败 → 标 error 跳过，继续下一条
4. A 账号 session 过期（302/401） → 标 error + notes="primary session expired"，提示重登
5. WAF 拦截（403/451） → 标 error + notes="WAF blocked"，跳过
6. mmx JSON 解析失败 → 兜底提取 → 仍失败退出

## Phase: collecting

### 1. Burp 历史分页

```bash
mcp__burp__list_proxy_http_history(count=500, offset=0)
mcp__burp__list_proxy_http_history(count=500, offset=500)
# 直到空或 offset>10000
```

读取目标域名（从 targets.domain 获取）。本地预过滤：
- 移除静态资源（.css/.js/.png/.jpg/.svg/.ico/.woff/.ttf/.gif/.webp/.map）
- 移除 OPTIONS/HEAD 请求
- 只保留目标域名或其子域的 URL

### 2. mmx 筛选

写入 `tmp/business_hunt_filter_prompt.txt`:
```
你是 SRC 渗透测试助手，从 Burp HTTP 历史精简列表中筛选出"业务接口"。

输出 JSON 数组，每条:
{
  "burp_history_id": <int>,
  "method": "POST",
  "url": "https://example.com/api/order/get",
  "endpoint_type": "business_api" | "auth_login" | "auth_register" | "auth_reset_password" | "auth_verify_code",
  "business_intent": "<一句话业务含义，如:查询订单详情>",
  "risk_hint": "High" | "Medium" | "Low"
}

判定规则:
- auth_login/register/reset_password/verify_code: URL 含 login/register/reset/forget/sms/captcha 等
- business_api: URL 含 /api/ 或 .do/.action 且非登录类
- risk_hint=High: 含 id/uid/oid 参数 或 method=DELETE/PUT
- risk_hint=Medium: 普通 GET 查询业务数据
- risk_hint=Low: 字典/枚举查询（/dict, /options, /list 无参数）

排除:
- 第三方 CDN/统计/广告域名
- 同 URL 去重保留 risk_hint 最高的一条
- 仅 health check / version 端点

返回纯 JSON 数组，不要 markdown 围栏或解释文字。
```

调用：
```bash
echo '{过滤后的精简JSON}' | mmx text chat --message "$(cat tmp/business_hunt_filter_prompt.txt)" --stdin
```

输出容错：
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
        print("[错误] mmx 输出无法解析，已写入 tmp/business_hunt_mmx_error_{ts}.txt")
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

输出 "采集完成: {n} 个业务端 -> 入队"

## Phase: testing

### 主循环

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint \
   FROM hunt_queue WHERE status='queued' \
   ORDER BY CASE risk_hint WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, id LIMIT 5"
```

### 类型映射

```
business_api          → [idor, unauth, info_leak, param_logic]
auth_login            → [user_enum, captcha_reuse]
auth_register         → [captcha_reuse, user_enum]
auth_reset_password   → [password_reset_takeover, user_enum]
auth_verify_code      → [captcha_reuse]
```

### 三层重放核心

```python
# 1. 从 burp_history_id 获取原始请求
# 2. 用 primary token 替换 Cookie/Authorization → A 请求
# 3. 用 secondary token 替换 → B 请求
# 4. 删除 Cookie 和 Authorization header → unauth 请求
# 5. 三个请求逐一通过 Burp 发送
# 6. 记录每个响应的 status/body/length
```

### 测试算法

#### idor
```python
# A.status==200 and B.status==200:
#   similarity = SequenceMatcher(None, A_body, B_body).ratio()
#   >0.85 → confirmed（B 看到了 A 的数据）
#   >0.5  → low_confidence
# evidence = "A {len(A)} vs B {len(B)}, sim {similarity:.2f}"
```

#### unauth
```python
# A.status==200 and unauth.status==200:
#   similarity > 0.85 → confirmed
# unauth.status==200 and len(body)>100 and not login_keyword:
#   → low_confidence
# login_keyword: login/登录/未登录/401/unauthorized
```

#### info_leak
```python
# 正则扫描 A_body:
#   PHONE=1[3-9]\d{9}, IDCARD=\d{17}[\dXx], EMAIL=[\w.-]+@[\w.-]+
# matches > 3 + json_array → confirmed
# matches > 0 → low_confidence
```

#### param_logic
```python
# LOGIC_PARAMS = ['status','role','type','level','is_admin','admin','group','permission','state','enabled','verified']
# LOGIC_VALUES = {'status':['1','999'],'role':['admin','superuser'],'type':['admin','1'],...}
# 参数命中 → 替换 → 重发 → 200 + success_keyword → confirmed
```

#### user_enum
```python
# 默认试 admin vs nonexistent_xyz_{random}
# 状态码不同 → confirmed
# 长度差异 >20% → confirmed
# 消息不同 → low_confidence
```

#### captcha_reuse
```python
# 原请求含 captcha/verifyCode/code/sms_code
# 同一 captcha 重发两次
# 都 200 + success → confirmed
# 第二次 200 且无 expired/used → low_confidence
```

#### password_reset_takeover
```python
# TARGET_FIELDS = {'phone':'13800000000','email':'attacker@evil.com','uid':'1','account':'admin'}
# 参数命中 → 替换 → unauth 发送
# 200 + success → confirmed
# 200 且无 '不存在'/'invalid' → low_confidence
```

### 写 findings（confirmed）

```bash
# 去重检查
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id FROM findings WHERE type='business_{test_type}' AND url='{url}' AND method='{method}'"
# 已有 → skip

# 生成 F-BLH-{n}
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT COALESCE(MAX(CAST(SUBSTR(id,7) AS INTEGER)), 0)+1 FROM findings WHERE id LIKE 'F-BLH-%'"
```

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id, review_status, audit_status) \
   VALUES ('F-BLH-{seq}', 'BLH-{endpoint_id}', (SELECT id FROM targets WHERE target_name='{目标}'), 'business_{test_type}', '{url}', '{param}', '{method}', '{payload}', '{evidence}', '{risk}', '', '{remediation}', datetime('now','localtime'), {burp_request_id}, NULL, 'pending')" \
  --write
```

risk: idor=High, unauth=High, info_leak=High, password_reset_takeover=Critical, param_logic=High, user_enum=Medium, captcha_reuse=Medium

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
  "UPDATE hunt_queue SET status='{confirmed/tested}', tested_types_json='[{tested_types}]', finding_ids='{finding_ids}', tested_at=datetime('now','localtime') WHERE id={id}" \
  --write
```

### 摘要

```
=== business-logic-hunt 执行摘要 ===
目标: {target}
队列: queued {n} | tested {n} | confirmed {n} | error {n}

本轮 confirmed ({n}):
  F-BLH-{id} {type} {method} {url} ({risk})

本轮 low_confidence（待 vuln-review 复核）:
  SP-BLH-{id} {type} {method} {url}

本轮 Burp 请求: ~{n}
如需复核 SP-BLH-*: vuln-review
如需切换 IP: Switch-ClashProxy
```

## 升级操作员

- A 账号 session 过期 → 暂停，提示重新登录
- 高危漏洞（password_reset_takeover confirmed）→ 升级操作员确认合规性
- Burp MCP 不可用 → 退出
- mmx 连续异常 → 退出
