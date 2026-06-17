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
python3 TOOLS/auth/session_manager.py --target "{目标}" --role primary
```

- 退出码 0 → session 有效（或已通过 CDP/browser_auth 自动续期）→ 继续
- 退出码 1 → session 无效且无法自动续期 → 输出：
  ```
  [AUTH_BARRIER] Session 已过期。
  请手动登录后执行:
    python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='auth_ready' WHERE id=1" --write
  如果 login_url 未存储，首次调用需加参数:
    python3 TOOLS/auth/session_manager.py --target "{目标}" --role primary --login-url "https://sso.example.com/login?..."
  ```
  然后退出，等待操作员恢复。

`session_manager.py` 续期顺序:
1. `auth_check.py --update` 刷新 `auth_sessions.is_active`
2. 从现有 Chrome CDP 捕获 Cookie / storage token
3. 使用已存凭据调用 `TOOLS/auth/browser_auth.py` 自动重新登录
4. 仍失败才输出 `[AUTH_BARRIER]`

### 认证态 / Token 获取

入口检查后必须由 Codex 自动完成认证态获取，不要求操作员手工拿 Cookie/token。

```bash
python3 TOOLS/auth/auth_explore.py --target "{目标}"
python3 TOOLS/auth/auth_state.py capture --target "{目标}"
```

执行规则:
- `auth_explore.py` 负责连接 `scan_state.cdp_url` 的现有 Chrome，注入 DB Cookie，认证态导航并写入 `suspicious_points` / `pages`。
- `auth_state.py capture` 负责从 CDP 捕获 Cookie、localStorage、sessionStorage，写入 `auth_sessions` 和 `auth_storage_tokens`。
- 如果缺少 `patchright` 等运行依赖，Codex 在 `tmp/` 创建临时 venv 并安装依赖后重试；临时环境不得写到根目录。
- 执行后查询 `auth_storage_tokens`，确认存在 `is_active=1` 且 `token_kind IN ('bearer','jwt')` 的 primary token；只输出 token 长度和来源，不输出 token 明文。
- primary 请求必须优先携带 DB 中匹配域 Cookie、`X-Id-Token`、`Authorization: Bearer <auth_storage_tokens.token_value>`。
- 每条验证 notes 必须记录 `auth_mode=cookie+bearer|cookie_only|none`；没有 bearer token 的 primary/unauth 结果不得写 confirmed，只能写 low_confidence 或 tested。
- 若 `auth_explore.py` 因 mmx CLI 缺失跳过 hunt_queue 分类，不视为认证失败；继续使用已捕获 token 进行 testing。
- 只有 `session_manager.py`、`auth_explore.py`、`auth_state.py capture` 连续失败，且无法得到可用 Cookie/token 时，才输出 `[AUTH_BARRIER]`。

secondary 账号（IDOR 测试必需）:
```
primary: 已有 token 自动 role='primary'（默认）
secondary: 使用 `python TOOLS/auth/browser_auth.py --target "{目标}" --url "{登录URL}" --username <B账号> --password <B密码> --role secondary --account-label secondary` 登录，或写入 `auth_sessions.role='secondary'` 的可用 Cookie/token。
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
4. A/B 账号 session 过期（302/401/跳登录页） → 按过期账号调 `python3 TOOLS/auth/session_manager.py --target "{目标}" --role primary|secondary` 续期；续期成功后重试当前端点一次；续期失败则停止并输出 `[AUTH_BARRIER]`
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

将过滤后的精简 JSON 写入 `tmp/business_hunt_history_{target}_{ts}.json`，使用 `Skill(skill="mmx-router")` 的 **业务端点意图分类** 模板调用：

```bash
mmx text chat --output text --non-interactive --message "你是 SRC 渗透测试助手...（见 mmx-router skill）:
$(cat tmp/business_hunt_history_{target}_{ts}.json)"
```

输出容错（JSON 解析失败时从原始输出提取 `[...]` 块）；解析仍失败则写入 `tmp/business_hunt_mmx_error_{ts}.txt` 后退出。

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
# 2. 用 primary Cookie + X-Id-Token + Authorization Bearer → A 请求
# 3. 用 secondary token 替换 → B 请求
# 4. 删除 Cookie 和 Authorization header → unauth 请求
# 5. 三个请求逐一通过 Burp 发送
# 6. 记录每个响应的 status/body/length
```

### 响应比对

每条端点三层请求（primary / secondary / unauth）发完后，调用比对脚本判定结果：

```bash
python TOOLS/utils/compare.py \
  --test-type {idor|unauth|info_leak|param_logic|user_enum|captcha_reuse|password_reset_takeover} \
  --a-status {A状态码} --a-body '{A响应体}' \
  [--b-status {B状态码} --b-body '{B响应体}'] \
  [--unauth-status {unauth状态码} --unauth-body '{unauth响应体}'] \
  [--target-param {参数名}]
# 输出: {"verdict": "confirmed|low_confidence|false_positive", "evidence": "..."}
```

verdict 映射：`confirmed` → 写 findings；`low_confidence` → 写 suspicious_points；`false_positive` → 跳过。

`SP-BLH-*` 进入 vuln-review 前必须重新执行 token 态 baseline；若 baseline 未携带 bearer token，复核结论不得 confirmed。

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

- A/B 账号 session 过期且 `session_manager.py` 通过 CDP/browser_auth 续期失败 → 暂停，输出 `[AUTH_BARRIER]`，等待操作员手动登录
- 高危漏洞（password_reset_takeover confirmed）→ 升级操作员确认合规性
- Burp MCP 不可用 → 退出
- mmx 连续异常 → 退出
