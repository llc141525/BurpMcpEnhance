---
name: business-logic-hunt
description: 业务逻辑漏洞主动猎手。DB三路收集（auth_explore XHR + JS静态分析 + probe可疑点）+ 内置浏览器探索（不依赖stealth-scanner）→ A/B双账号+未授权三层重放 → 写 findings。覆盖 IDOR/垂直越权/批量IDOR/未授权/信息泄露/验证码缺陷/用户枚举/密码重置/参数逻辑/边界值注入。
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit
---

# business-logic-hunt

独立运行，不依赖 stealth-scanner / vuln-review。

## 环境常量

| 常量 | 值 |
|------|-----|
| DBS_DIR | `E:\SRC挖掘\SRC\dbs` |
| DB 操作 | `TOOLS/db_query.py` |
| ETL分析 | `uv run python TOOLS/utils/etl_analyzer.py --task classify_business` |
| 代理预热 | `.\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv` |

## 入口

```
Skill(skill="business-logic-hunt", args="目标: 台州学院")
Skill(skill="business-logic-hunt", args="目标: 台州学院; 模式: refresh")
```

### 入口检查

```bash
python3 TOOLS/auth/session_manager.py --target "{目标}"
```

- 退出码 0 → session 有效（或已自动续期）→ 继续
- 退出码 1 → session 无效且无法自动续期 → 输出：
  ```
  [AUTH_BARRIER] Session 已过期。
  请手动登录后执行:
    python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='auth_ready' WHERE id=1" --write
  如果 login_url 未存储，首次调用需加参数:
    python3 TOOLS/auth/session_manager.py --target "{目标}" --login-url "https://sso.example.com/login?..."
  ```
  然后退出，等待操作员恢复。

secondary 账号（IDOR 测试必需）:
```
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

1. HTTP 请求失败（连接超时/代理拒绝）→ 等待 2 秒重试 → 最多 3 次
2. SQLite busy → 等待 1 秒重试 → 最多 3 次
3. 单个端点失败 → 标 error 跳过，继续下一条
4. A 账号 session 过期（302/401） → 调 `python3 TOOLS/auth/session_manager.py --target "{目标}"` 续期；续期成功后重试当前端点；续期失败则停止并输出 `[AUTH_BARRIER]`
5. WAF 拦截（403/451） → 标 error + notes="WAF blocked"，跳过
6. etl_analyzer JSON 解析失败 → 兜底提取 → 仍失败退出

## Phase: explore（自包含浏览器探索）

触发条件：

```sql
SELECT COUNT(*) FROM pages WHERE source='auth_explore'
```

结果 < 20 → 执行本阶段；≥ 20 → 跳过，直接进 collecting（stealth-scanner 已提供足够数据）。

### 前置检查

1. Chrome CDP `localhost:9222` 可用 → 否则提示：
   ```bash
   python TOOLS/auth/chrome_manager.py --target "{目标}"
   ```
   等待操作员启动后继续，或跳过 explore 直接进 collecting。
2. `auth_sessions` 有有效 `primary` session → 否则输出 `[AUTH_BARRIER]` 停止。

### 执行步骤

```
1. 从 auth_sessions 读 primary token，注入 Cookie

2. 确定导航目标页面：
   -- 优先：业务关键词页面
   SELECT url FROM pages
   WHERE depth <= 1 AND status='visited'
     AND (url LIKE '%course%' OR url LIKE '%class%'
       OR url LIKE '%homework%' OR url LIKE '%order%'
       OR url LIKE '%user%' OR url LIKE '%profile%'
       OR url LIKE '%admin%' OR url LIKE '%setting%'
       OR url LIKE '%score%' OR url LIKE '%exam%')
   LIMIT 10
   -- 若匹配不足 10 页，补充 depth <= 2 的已访问页面，按 depth ASC 填满

3. 逐页打开，停留 3 秒等待 XHR 完成
   拦截 XHR/fetch：记录 method + url + request_body + response_status

4. 去重，写入 pages 表（source='blh_explore'，api_calls_json=拦截到的 XHR JSON）

5. 输出：
   [BLH_EXPLORE] 导航 {m} 页，发现 {n} 个业务端点
```

---

## Phase: collecting（DB 三路汇总）

不再读 Burp 历史。三路来源全部来自 DB。

### 路 1 — auth_explore / blh_explore XHR 记录

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT DISTINCT p.url, p.method, p.api_calls_json
   FROM pages p
   WHERE p.source IN ('auth_explore', 'blh_explore')
     AND p.status = 'visited'
     AND p.api_calls_json IS NOT NULL"
```

### 路 2 — JS 静态分析发现的 API 端点

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT js.url as js_url, js.discovered_apis_json
   FROM js_files js
   WHERE js.analyzed = 1
     AND js.discovered_apis_json IS NOT NULL"
```

展开 `discovered_apis_json` 数组，拼上目标 base URL，构造完整端点列表。

### 路 3 — probe 阶段写入的可疑点

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT sp.url, sp.method, sp.param, sp.test_type, sp.risk
   FROM suspicious_points sp
   WHERE sp.source IN ('probe', 'auth_explore', 'blh_explore')
     AND sp.test_status = 'untested'"
```

### 处理流程

```
三路合并 → 按 (method, url) 去重
→ 写临时文件 tmp/blh_collect_{target}_{ts}.json
→ etl_analyzer（task=classify_business）做业务意图分类（endpoint_type + business_intent）
  admin_api 识别规则：URL 含 /admin/ /manage/ /teacher/ /staff/ /system/，
  或 DELETE/PATCH 且路径模式为 /api/{resource}/{id}
→ 按 endpoint_type 写 hunt_queue（source='auto'）
→ 输出：采集完成：{n} 个业务端点入队
```

若三路全部为空，输出：

```
[BLH_EMPTY] DB 无可用业务端点。
请先运行 stealth-scanner 或确保 auth_explore/blh_explore 阶段已完成。
```

然后停止。

## Phase: testing

### 主循环

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  # burp_history_id may be NULL for DB-sourced rows; always pass as NULL to findings/SP INSERTs
  "SELECT id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint \
   FROM hunt_queue WHERE status='queued' \
   ORDER BY CASE risk_hint WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, id LIMIT 5"
```

### 类型映射

```python
TYPE_MAP = {
    # 新增
    'admin_api':           ['vertical_priv_esc', 'unauth'],
    'batch_api':           ['batch_idor', 'unauth'],
    'payment_api':         ['boundary_value', 'idor'],
    # 原有
    'business_api':        ['idor', 'unauth', 'info_leak', 'param_logic'],
    'auth_login':          ['user_enum', 'captcha_reuse'],
    'auth_register':       ['captcha_reuse', 'user_enum'],
    'auth_reset_password': ['password_reset_takeover', 'user_enum'],
    'auth_verify_code':    ['captcha_reuse'],
}

RISK_MAP = {
    'idor':                    'High',
    'vertical_priv_esc':       'High',
    'batch_idor':              'High',
    'boundary_value':          'High',
    'unauth':                  'High',
    'info_leak':               'Medium',
    'password_reset_takeover': 'Critical',
    'param_logic':             'High',
    'user_enum':               'Medium',
    'captcha_reuse':           'Medium',
}
```

#### payment_api 识别规则（mmx 分类时）
URL 含 `/pay/` `/payment/` `/order/` `/cart/` `/checkout/` `/price/` `/amount/` `/coupon/` `/discount/`，或 body/query 含 `price`/`amount`/`quantity`/`count`/`total`/`credit` 等数值参数。

### 三层重放核心

```python
# 1. 从 hunt_queue 读取 (method, url, query_string, body, content_type) 重构请求
# 2. 用 primary token 替换 Cookie/Authorization → A 请求
# 3. 用 secondary token 替换 → B 请求
# 4. 删除 Cookie 和 Authorization header → unauth 请求
# 5. 三个请求逐一发送（通过 Burp 代理 127.0.0.1:8080 或直连）
# 6. 记录每个响应的 status/body/length
```

### 响应比对

每条端点三层请求（primary / secondary / unauth）发完后，调用比对脚本判定结果：

```bash
python TOOLS/utils/compare.py \
  --test-type {idor|unauth|info_leak|param_logic|user_enum|captcha_reuse|password_reset_takeover|vertical_priv_esc|batch_idor|boundary_value} \
  --a-status {A状态码} --a-body '{A响应体}' \
  [--b-status {B状态码} --b-body '{B响应体}'] \
  [--unauth-status {unauth状态码} --unauth-body '{unauth响应体}'] \
  [--target-param {参数名}]
# 输出: {"verdict": "confirmed|low_confidence|false_positive", "evidence": "..."}
```

verdict 映射：`confirmed` → 写 findings；`low_confidence` → 写 suspicious_points；`false_positive` → 跳过。

#### vertical_priv_esc（垂直越权）特殊处理

```bash
python TOOLS/utils/compare.py --test-type vertical_priv_esc \
  --a-status {primary状态码} --a-body '{primary响应}' \
  --b-status {teacher状态码} --b-body '{teacher响应}'
# b-status=0 表示 auth_sessions 中无 teacher/admin session
```

verdict 扩展：
- `confirmed` → 写 findings（F-BLH-*）
- `needs_teacher_account` → 写 suspicious_points，notes="接口返回403，需操作员提供 teacher/admin 账号验证"
- `false_positive` → 跳过

#### batch_idor（批量越权）构造变种

批量端点识别：body 或 query 含数组参数（ids/user_ids/item_ids/order_ids 等）。

B 的 id 来源（优先顺序）：
1. secondary session 访问 `/api/users/me` 或个人主页自动获取自身 id
2. IDOR 测试阶段已通过 secondary session 发现的资源 id
3. 均无法获取 → 跳过变种 ③，仅执行 ① ②

```bash
python TOOLS/utils/compare.py --test-type batch_idor \
  --a-status {变种①状态} --a-body '{变种①响应}' \
  --b-status {变种②状态} --b-body '{变种②响应}' \
  --unauth-status {变种③状态} --unauth-body '{变种③响应}'
# ①=A+[A_id]基线  ②=B+[A_id]  ③=A+[A_id,B_id]
```

#### boundary_value（边界值注入）构造变种

目标参数（price/amount/quantity/count/credit 等数值字段）逐一替换为：`-1`、`0`、`0.01`、`99999999`。

```bash
# 正常值基线（a）
python TOOLS/utils/compare.py --test-type boundary_value \
  --a-status {正常响应状态} --a-body '{正常响应体}' \
  --b-status {边界值响应状态} --b-body '{边界值响应体}' \
  --target-param price
# confirmed → 边界值被服务端接受（价格篡改成功）→ 写 findings
# low_confidence → 200 但无明确成功/失败信号 → 写 suspicious_points
# false_positive → 边界值被拒绝（正确校验）→ 跳过
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

# burp_request_id: 若 hunt_queue 来自 DB 三路（非 Burp 历史），则为 NULL
```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id, review_status, audit_status) \
   VALUES ('F-BLH-{seq}', 'BLH-{endpoint_id}', (SELECT id FROM targets WHERE target_name='{目标}'), 'business_{test_type}', '{url}', '{param}', '{method}', '{payload}', '{evidence}', '{risk}', '', '{remediation}', datetime('now','localtime'), {burp_request_id or NULL}, NULL, 'pending')" \
  --write
```

risk: 见上方 RISK_MAP（vertical_priv_esc=High, batch_idor=High 已包含）

### 写 suspicious_points（low_confidence）

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO suspicious_points (id, page_url, url, param, method, test_type, evidence, source, reasoning, risk, test_status, burp_request_id, created_at) \
   VALUES ('SP-BLH-{seq}', '{url}', '{url}', '{param}', '{method}', 'business_{test_type}', '{evidence}', 'business_logic_hunt', '{reasoning}', 'Medium', 'untested', {burp_request_id or NULL}, datetime('now','localtime'))" \
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

本轮 HTTP 请求: ~{n}
如需复核 SP-BLH-*: vuln-review
如需切换 IP: Switch-ClashProxy
```

## 升级操作员

- A 账号 session 过期 → 暂停，提示重新登录
- 高危漏洞（password_reset_takeover confirmed）→ 升级操作员确认合规性
- HTTP 代理不可用（127.0.0.1:8080 连接拒绝）→ 退出
- etl_analyzer 连续异常 → 退出
