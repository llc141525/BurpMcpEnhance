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
python3 TOOLS/db_query.py --target "{目标}" "SELECT count(*) FROM auth_sessions WHERE is_active=1 AND role='primary'"
python3 TOOLS/db_query.py --target "{目标}" "SELECT count(*) FROM auth_sessions WHERE is_active=1 AND role='secondary'"
```

Primary >=1 且 secondary >=1 → 继续。否则输出：
```
请准备 primary + secondary 账号。
primary: 已有 token 自动 role='primary'（默认）
secondary: INSERT INTO auth_sessions (token_name, token_value, domain, role, is_active) VALUES ('JSESSIONID', 'xxx', 'example.com', 'secondary', 1);
```

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

写入 `tmp/manual_replay_filter_prompt.txt`:
```
你是 SRC 渗透测试助手，从 Burp HTTP 历史列表中筛选出手工操作流程中的"业务接口"。

输出 JSON 数组，每条:
{
  "burp_history_id": <int>,
  "method": "POST",
  "url": "https://example.com/api/order/create",
  "endpoint_type": "business_api" | "auth_login" | "auth_register" | "auth_reset_password" | "auth_verify_code" | "flow_step",
  "business_intent": "<一句话业务含义，如:创建订单>",
  "flow_step": <int, 同一次流程的步骤序号，从1开始, 独立请求标0>,
  "risk_hint": "High" | "Medium" | "Low",
  "auth_required": true | false
}

flow_step 规则:
- 属于同一业务流程的请求按执行顺序编号（如注册流程: 1=提交手机号, 2=填写验证码, 3=设置密码）
- 独立请求（查询字典、获取列表等）标 0

判定规则:
- auth_login/register/reset_password/verify_code: URL 含 login/register/reset/forget/sms/captcha 等
- business_api: URL 含 /api/ 或 .do/.action 且非登录类
- flow_step > 0: 请求属于同一业务流程链
- risk_hint=High: 含 id/uid/oid 参数 或 method=DELETE/PUT 或涉及支付/订单
- risk_hint=Medium: 普通 GET 查询业务数据
- risk_hint=Low: 字典/枚举查询（/dict, /options, /list 无参数）

排除:
- 第三方 CDN/统计/广告域名
- 同 URL 去重保留 risk_hint 最高且 flow_step 不为空的
- 仅 health check / version 端点

返回纯 JSON 数组，不要 markdown 围栏或解释文字。
```

调用：
```bash
mmx text chat --message "$(cat tmp/manual_replay_filter_prompt.txt)" --stdin < tmp/manual_replay_raw_{target}_{ts}.json
```

输出容错（同 business-logic-hunt 模式）：
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
        print("[错误] mmx 输出无法解析，已写入 tmp/manual_replay_mmx_error_{ts}.txt")
        exit()
```

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

对全部请求执行 AI 流分析（`mmx text chat`）：

Prompt:
```
分析以下 HTTP 请求序列，输出 JSON:
{
  "flow_chains": [
    {
      "chain_id": 1,
      "steps": [1, 2, 3],
      "flow_name": "创建订单流程",
      "state_params": {"order_id": "请求2的响应→请求3的请求"},
      "auth_context": "primary"
    }
  ],
  "cross_request_params": [
    {"param_name": "token", "source_request_id": 1, "target_request_id": 2}
  ]
}

请求序列:
{请求序列JSON}

规则:
- flow_chains: 识别属于同一流程的请求链（flow_step > 0 的连续序列）
- state_params: 标注跨请求传递的参数（如 token、orderId）
- cross_request_params: 标注同一参数名在相邻请求间出现的位置
- auth_context: 根据 Cookie/Authorization 判断使用的身份
```

输出写入 `tmp/manual_replay_flow_{target}_{ts}.json`。

## Phase: variant_gen

### 1. 加载流程分析结果

```bash
FLOW_DATA=$(cat tmp/manual_replay_flow_{target}_{ts}.json)
```

### 2. AI 变种生成

对每个端点，按 `business_intent` 映射变种模板：

Prompt:
```
你是一个 Web 安全测试的变种生成器。给定一个 HTTP 请求及其业务意图，生成可能的安全测试变种。

请求:
- URL: {url}
- Method: {method}
- Query: {query_string}
- Body: {body}
- Content-Type: {content_type}
- Business Intent: {business_intent}
- Risk Hint: {risk_hint}
- Auth Required: {auth_required}
- Flow Chain: {flow_chain_id}, Step {flow_step}

跨请求参数传递:
{cross_request_params}

输出 JSON 数组，每条变种:
{
  "test_type": "idor"|"unauth"|"param_logic"|"user_enum"|"captcha_reuse"|"password_reset_takeover"|"info_leak",
  "target_param": "要修改的参数名",
  "original_value": "原始值",
  "replacement_value": "替换值",
  "modification": "replace_param"|"remove_auth"|"replace_cookie"|"remove_param"|"add_param",
  "description": "变种说明"
}

业务意图→变种映射:
- 用户注册/登录: user_enum, bruteforce_bypass
- 验证码校验: captcha_reuse, captcha_bypass
- 创建订单: idor(替换user_id), param_logic(改价格/数量), unauth
- 查询订单: idor(替换order_id), info_leak, unauth
- 修改订单: idor, param_logic(状态/金额), unauth
- 密码重置: password_reset_takeover(替换手机/邮箱)
- 用户信息: idor(替换uid), info_leak
- 文件上传: file_type_bypass, unauth
- 支付/扣款: param_logic(金额/数量/货币), idor, unauth
- 通用查询: unauth, info_leak

返回纯 JSON 数组，5-15 条变种。
```

对每个端点执行并汇总所有变种。

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
        # 删除 Cookie 和 Authorization header
        pass
    elif variant.modification == 'replace_cookie':
        # 将 primary cookie 替换为 secondary cookie
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

```python
A = primary_response
B = secondary_response  # 仅 idor 类需要
unauth = unauth_response  # 仅 unauth 类需要

from difflib import SequenceMatcher

def is_confirmed(test_type, A, B=None, unauth=None):
    if test_type == 'idor' and B:
        sim = SequenceMatcher(None, A['body'], B['body']).ratio()
        return sim > 0.85, sim
    elif test_type == 'unauth' and unauth:
        if unauth['status'] == 200 and len(unauth['body']) > 100:
            sim = SequenceMatcher(None, A['body'], unauth['body']).ratio()
            return sim > 0.85, sim
    elif test_type == 'param_logic':
        return A['status'] == 200 and 'success' in A['body'].lower(), 0
    elif test_type == 'info_leak':
        import re
        leaks = re.findall(r'1[3-9]\d{9}|\d{17}[\dXx]|[\w.-]+@[\w.-]+', A['body'])
        return len(leaks) > 3, len(leaks)
    # ... 其他类型
    return False, 0
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
| A/B 账号 session 过期（302/401） | 标 error + notes，提示重登 |
| WAF 拦截（403/451） | 标 error + notes="WAF blocked"，跳过 |
| mmx JSON 解析失败 | 内置兜底提取 → 仍失败则退出 |

## 升级操作员

- A 账号 session 过期 → 暂停，提示重新登录
- 高危漏洞（password_reset_takeover confirmed）→ 暂停，升级操作员确认合规性
- Burp MCP 不可用 → 退出
- mmx 连续异常 → 退出
