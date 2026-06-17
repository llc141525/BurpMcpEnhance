---
name: manual-replay
description: 操作员手工跑业务流程 → AI 变种攻击。时间窗口采集 Burp 历史 → mmx 分类 → 流分析 → 结构化变种生成 → 三层执行。覆盖 IDOR/未授权/参数逻辑/验证码复用/用户枚举/密码重置。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit
---

# manual-replay

独立运行，不依赖 stealth-scanner / vuln-review / business-logic-hunt。

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
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5; 流程: 下单")
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay")
```

参数：
- `窗口` — 时间窗口（分钟），默认 5，从执行时刻往前推
- `流程` — 按 business_intent 筛选（可选），如"下单""注册"；不传则处理全部采集端点

### 入口检查

```bash
python3 TOOLS/auth/session_manager.py --target "{目标}" --role primary
```

- 退出码 0 → session 有效（或已通过 CDP/browser_auth 自动续期）→ 继续
- 退出码 1 → 输出以下提示后退出：
  ```
  [AUTH_BARRIER] Session 已过期，自动续期失败。
  请手动登录后执行:
    python TOOLS/db/db_query.py --target "{目标}" "UPDATE scan_state SET phase='auth_ready' WHERE id=1" --write
  如 login_url 未存储，加参数:
    python3 TOOLS/auth/session_manager.py --target "{目标}" --role primary --login-url "https://sso.example.com/login?..."
  ```

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
- primary 变种请求必须优先携带 DB 中匹配域 Cookie、`X-Id-Token`、`Authorization: Bearer <auth_storage_tokens.token_value>`。
- 每条执行 notes 必须记录 `auth_mode=cookie+bearer|cookie_only|none`；没有 bearer token 的 primary/unauth 结果不得写 confirmed，只能写 low_confidence 或 tested。
- 若 `auth_explore.py` 因 mmx CLI 缺失跳过 hunt_queue 分类，不视为认证失败；继续使用已捕获 token 执行 replay。
- 只有 `session_manager.py`、`auth_explore.py`、`auth_state.py capture` 连续失败，且无法得到可用 Cookie/token 时，才输出 `[AUTH_BARRIER]`。

### 迁移检查

```bash
python3 TOOLS/migrate.py --target "{目标}"
```

### 阶段推断

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT source, status, COUNT(*) as cnt FROM hunt_queue WHERE source='manual_replay' GROUP BY status"
```

- 无返回 → collect 阶段
- 存在 status='queued' → analyze/variant_gen/execute 阶段（恢复模式）
- 全部 tested/confirmed/error → 提示"上一轮已完成"并退出

### 状态恢复

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "UPDATE hunt_queue SET status='queued' WHERE source='manual_replay' AND status='in_progress'" --write
```

## Phase: collect

### 1. 获取目标域名

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT domain FROM targets WHERE target_name='{目标}'"
```

### 2. 时间窗口 Burp 分页

```bash
# 计算窗口起始时间
WINDOW_SINCE=$(python3 -c "from datetime import datetime,timedelta; print((datetime.now()-timedelta(minutes=${窗口:-5})).strftime('%Y-%m-%dT%H:%M:%S'))")

# 分页拉取（最多 2000 条）
mcp__burp__list_proxy_http_history(count=500, offset=0)
mcp__burp__list_proxy_http_history(count=500, offset=500)
mcp__burp__list_proxy_http_history(count=500, offset=1000)
mcp__burp__list_proxy_http_history(count=500, offset=1500)
```

本地过滤（JSON 处理）：
```
- 移除静态资源（.css/.js/.png/.jpg/.svg/.ico/.woff/.ttf/.gif/.webp/.map）
- 移除 OPTIONS/HEAD 请求
- 只保留目标域名或其子域的 URL
- 保留 time >= WINDOW_SINCE 的记录
- 按 time 升序排列（保留操作员浏览顺序）
- 去重：同 method+url 保留 time 最早的
```

写入临时文件供 mmx 分析：
```bash
echo '{过滤后的JSON}' > tmp/manual_replay_raw_{target}_{ts}.json
```

### 3. mmx 意图分类

将过滤后的 JSON 写入 `tmp/manual_replay_raw_{target}_{ts}.json`，使用 `Skill(skill="mmx-router")` 的 **业务端点意图分类** 模板调用（注意：manual-replay 额外需要 `flow_step` 字段，在 prompt 末尾补充说明：`额外要求：每条增加 "flow_step":<int>，同一流程按顺序编号从1起，独立请求标0；以及 "auth_required":true|false`）。

输出容错：JSON 解析失败时从原始输出提取 `[...]` 块；仍失败则写入 `tmp/manual_replay_mmx_error_{ts}.txt` 后退出。

### 4. 获取完整请求 + 入队

对 mmx 返回的每条：
```bash
mcp__burp__get_proxy_http_detail(id={burp_history_id})
```

提取 method/url/query_string/body/content_type。

```bash
FLOW_ID="replay_{目标}_$(date +%Y%m%d_%H%M)"
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO hunt_queue (target_id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint, source, flow_id, status) \
   VALUES ((SELECT id FROM targets WHERE target_name='{目标}'), ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual_replay', '$FLOW_ID', 'queued')" \
  --write --params '["{method}","{url}","{query_string}","{body}","{content_type}",{burp_history_id},"{endpoint_type}","{business_intent}","{risk_hint}"]'
```

### 5. 采集完成

```bash
python3 TOOLS/db_query.py --target "{目标}" "SELECT COUNT(*) FROM hunt_queue WHERE source='manual_replay'"
```

输出 "采集完成: {n} 个端点 -> 进入分析阶段"

## Phase: analyze

### 1. 载入采集数据

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id, method, url, query_string, body, content_type, burp_history_id, endpoint_type, business_intent, risk_hint \
   FROM hunt_queue WHERE source='manual_replay' AND status='queued' \
   ORDER BY id"
```

### 2. 流分析

将请求序列写入 `tmp/manual_replay_requests_{target}_{ts}.json`，使用 `Skill(skill="mmx-router")` 的 **HTTP 请求流程分析** 模板调用 mmx，输出写入 `tmp/manual_replay_flow_{target}_{ts}.json`。

## Phase: variant_gen

### 1. 加载流程分析结果

```bash
FLOW_DATA=$(cat tmp/manual_replay_flow_{target}_{ts}.json)
```

### 2. AI 变种生成

对每个端点，将请求上下文（url/method/body/business_intent/risk_hint/auth_required/flow_chain/cross_request_params）写入 `tmp/manual_replay_req_{id}.json`，使用 `Skill(skill="mmx-router")` 的 **安全测试变种生成** 模板调用 mmx，对每个端点执行并汇总所有变种。

### 3. 入执行队列

变种不持久化到 DB（内存中执行）。汇总后输出：
"生成完成: {n} 个端点, {m} 条变种 -> 进入执行阶段"

## Phase: execute

### 1. 主循环 — 逐变种执行

```bash
# 从 hunt_queue 读取端点列表
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id, method, url, query_string, body, content_type, burp_history_id FROM hunt_queue \
   WHERE source='manual_replay' AND status='queued' ORDER BY id"
```

对每个端点及其变种：

```python
# 1. 从 burp_history_id 获取原始请求 → 解析 method/url/headers/body
# 2. 对每条变种，构造修改后的请求

def apply_variant(original_request, variant):
    if variant.modification == 'replace_param':
        # 替换 query_string 或 body 中的参数值
        pass
    elif variant.modification == 'remove_auth':
        # 删除 Cookie、X-Id-Token 和 Authorization header
        pass
    elif variant.modification == 'replace_cookie':
        # 将 primary Cookie/X-Id-Token/Authorization 替换为 secondary 凭证
        pass
    elif variant.modification == 'remove_param':
        # 删除指定参数
        pass
    elif variant.modification == 'add_param':
        # 添加额外参数
        pass

# 3. 通过 Burp 发送
# 使用 mcp__burp__send_http1_request 发送修改后的请求
```

### 2. 快速响应判定

每条变种请求发完后，调用比对脚本：

```bash
python TOOLS/utils/compare.py \
  --test-type {test_type} \
  --a-status {A状态码} --a-body '{A响应体}' \
  [--b-status {B状态码} --b-body '{B响应体}'] \
  [--unauth-status {unauth状态码} --unauth-body '{unauth响应体}'] \
  [--target-param {参数名}]
# 输出: {"verdict": "confirmed|low_confidence|false_positive", "evidence": "..."}
```

### 3. 写 findings（confirmed）

```bash
# 去重检查
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT id FROM findings WHERE type='replay_{test_type}' AND url='{url}' AND method='{method}'"
# 已有 → skip

# 生成 F-RP-{n}
python3 TOOLS/db_query.py --target "{目标}" \
  "SELECT COALESCE(MAX(CAST(SUBSTR(id,9) AS INTEGER)), 0)+1 FROM findings WHERE id LIKE 'F-RP-%'"
```

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id, review_status, audit_status) \
   VALUES ('F-RP-{seq}', 'RP-{endpoint_id}', (SELECT id FROM targets WHERE target_name='{目标}'), 'replay_{test_type}', '{url}', '{param}', '{method}', '{payload}', '{evidence}', '{risk}', '', '{remediation}', datetime('now','localtime'), {burp_request_id}, NULL, 'pending')" \
  --write
```

risk 映射：idor=High, unauth=High, info_leak=High, password_reset_takeover=Critical, param_logic=High, user_enum=Medium, captcha_reuse=Medium

### 4. 写 suspicious_points（low_confidence）

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "INSERT INTO suspicious_points (id, page_url, url, param, method, test_type, evidence, source, reasoning, risk, test_status, burp_request_id, created_at) \
   VALUES ('SP-RP-{seq}', '{url}', '{url}', '{param}', '{method}', 'replay_{test_type}', '{evidence}', 'manual_replay', '{reasoning}', 'Medium', 'untested', {burp_request_id}, datetime('now','localtime'))" \
  --write
```

### 5. 更新端点状态

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "UPDATE hunt_queue SET status='tested', tested_at=datetime('now','localtime') WHERE id={id}" \
  --write
```

### 6. 终端摘要

```
=== manual-replay 执行摘要 ===
目标: {target}
时间窗口: 最近 {窗口} 分钟
采集端点: {n} 个（含 {m} 个流程步骤）
生成变种: {v} 条

本轮 confirmed ({n}):
  F-RP-{id} {type} {method} {url} ({risk})

本轮 low_confidence（待 vuln-review 复核）:
  SP-RP-{id} {type} {method} {url}

如需复核 SP-RP-*: vuln-review
如需切换 IP: Switch-ClashProxy
```

## 容错

| 场景 | 行为 |
|------|------|
| Burp MCP 调用失败 | 等待 2 秒重试 → 最多 3 次 |
| SQLite busy | 等待 1 秒重试 → 最多 3 次 |
| 时间窗口内无请求 | 提示"时间窗口内无目标域名请求"，退出 |
| mmx 分类失败 | 内置兜底提取 → 仍失败则退出 |
| 单变种执行失败 | 标 error，继续下一条 |
| A/B 账号 session 过期（302/401/跳登录页） | 按过期账号调 `python3 TOOLS/auth/session_manager.py --target "{目标}" --role primary|secondary` 续期；成功后重试当前请求一次；失败则停止输出 `[AUTH_BARRIER]` |
| WAF 拦截（403/451） | 标 error + notes="WAF blocked"，跳过 |
| mmx JSON 解析失败 | 内置兜底提取 → 仍失败则退出 |

## 升级操作员

- A/B 账号 session 过期且 `session_manager.py` 通过 CDP/browser_auth 续期失败 → 暂停，输出 `[AUTH_BARRIER]`，等待操作员手动登录
- 高危漏洞（password_reset_takeover confirmed）→ 暂停，升级操作员确认合规性
- Burp MCP 不可用 → 退出
- mmx 连续异常 → 退出
