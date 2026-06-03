# manual-replay 工作流设计

> **目标：** 补齐"操作员手动跑业务流程 → AI 变种攻击"的实战环节，覆盖 business-logic-hunt 自动采集无法触及的深度业务链路（多步流程、状态依赖、业务语义）。

---

## 1. 架构总览

### 定位

独立 skill，不依赖 stealth-scanner / vuln-review。操作员手动在 Burp 中完成业务流程（注册→登录→下单等），AI 读取 Burp 历史做变种攻击。

### 四阶段模型

```
collect → analyze → variant_gen → execute
```

| 阶段 | 输入 | 输出 |
|------|------|------|
| **collect** | Burp 历史（时间窗口过滤） | 原始请求列表 + mmx 分类 |
| **analyze** | 分类后的请求链 | flow 拓扑 + intent 标注 + 状态依赖映射 |
| **variant_gen** | 带 intent 的请求链 | 每个请求的变种集（参数替换、权限降级、逻辑旁路） |
| **execute** | 变种集 | confirmed → findings / low_confidence → suspicious_points |

### 调用方式

```
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay")
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5")
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5; 流程: 下单")
```

参数：
- `窗口` — 时间窗口（分钟），默认 5，从当前时间往前推
- `流程` — 按业务意图筛选（可选），如"下单""注册"，不传则处理全部

---

## 2. 采集 & 流量分析（collect + analyze）

### 2.1 时间窗口采集

```bash
mcp__burp__list_proxy_http_history(count=500, offset=0)
# 过滤：目标域名 + 排除静态资源 + 排除 OPTIONS/HEAD
# 时间过滤：最近 N 分钟（默认 5）
# 按 time 排序升序（保留操作员浏览顺序）
```

写入 `tmp/manual_replay_raw_{target}_{ts}.json` 供 mmx 分析。

### 2.2 mmx 意图分类

Prompt 输出结构：
```json
[
  {
    "burp_history_id": 1234,
    "method": "POST",
    "url": "https://target.com/api/order/create",
    "endpoint_type": "business_api" | "auth_login" | "auth_register" | "auth_reset_password" | "auth_verify_code" | "flow_step",
    "business_intent": "创建订单",
    "flow_step": 1,
    "risk_hint": "High" | "Medium" | "Low",
    "auth_required": true | false
  }
]
```

- `flow_step` — 手工标注步骤序号，同一次流程的请求按此排序
- `auth_required` — 该请求是否需要登录态

### 2.3 AI 流分析

对 mmx 返回的请求序列执行：

1. **链式检测** — 相邻请求间是否存在相同的参数名（如 `token`、`orderId`、`ticket`）
2. **身份上下文标注** — 识别哪些请求使用了相同的 Cookie/Authorization
3. **关键参数标注** — 标记需要跨请求追踪的动态值（Session token、CSRF token、Step token）

---

## 3. 变种生成引擎（variant_gen）

### 3.1 结构化 AI 模板系统

每类 `business_intent` 绑定一组变种模板。AI 按请求的实际参数实例化：

| business_intent | 变种模板 |
|-----------------|----------|
| 用户注册 | user_enum（枚举已注册用户） |
| 用户登录 | user_enum + bruteforce_bypass（密码绕过） |
| 验证码校验 | captcha_reuse（验证码复用）+ captcha_bypass（跳过） |
| 创建订单 | idor（替换 user_id） + param_logic（改价格/数量） + unauth（未授权） |
| 查询订单 | idor（替换 order_id） + info_leak（响应信息泄露） + unauth |
| 修改订单 | idor + param_logic（状态/金额） + unauth |
| 密码重置 | password_reset_takeover（替换目标手机/邮箱） |
| 用户信息查询 | idor（替换 uid） + info_leak |
| 文件上传 | file_type_bypass（类型绕过） + unauth |
| 支付/扣款 | param_logic（改金额/数量/货币） + idor + unauth |

### 3.2 AI 变种构造规则

每条变种 = `{test_type, target_param, replacement_value, description}`：

```
IDOR 系列:
  - 目标参数: id / uid / orderId / userId / ticketId / 等
  - 替换值: 其他用户的 ID（来自 secondary 账号的已知 ID）
  - 规则: 删除 Cookie/Authorization 重放

参数逻辑系列:
  - 目标参数: status / role / type / level / is_admin / amount / price / quantity / 等
  - 替换值: admin / 1 / 0 / -1 / 999999 / true / 等
  - 规则: 保持认证态不变

越权系列:
  - 目标参数: 同 IDOR
  - 替换值: 从 secondary 账号的请求中提取的对应参数值
  - 规则: 将 A 的 Cookie 替换为 B 的 Cookie，参数不变
```

### 3.3 流感知变种

AI 识别跨请求参数传递后，对每一步分别生成变种：

```
请求1: POST /api/order/create  →  body: {product_id:1, quantity:1}
  └─ 变种: quantity → -1, 9999, 0（param_logic）

请求2: POST /api/order/confirm →  body: {order_id:"xxx", amount:100}
  └─ 变种: amount → 0, 1, -1（param_logic）
  └─ 变种: 去掉 Cookie 重放（unauth）

请求3: POST /api/order/pay     →  body: {order_id:"xxx", coupon:"xxx"}
  └─ 变种: 替换 coupon 为他人券（idor）
  └─ 变种: 去掉 Cookie 重放（unauth）
```

---

## 4. 执行 & 输出（execute）

### 4.1 变种执行

```python
for variant in variants:
    # 从 burp_history_id 获取原始请求
    # 按 variant.rule 修改参数/Cookie/Header
    # 通过 Burp 发送
    # 记录 status/body/length

    # 与原始响应快速比较
    if similarity > 0.85 and status == 200:
        confirmed
    elif status == 200 and body not in [error_patterns]:
        low_confidence
    else:
        false
```

### 4.2 双输出

**confirmed** → findings 表，前缀 `F-RP-{seq}`：

```sql
INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id, review_status, audit_status)
VALUES ('F-RP-{seq}', 'RP-{endpoint_id}', (SELECT id FROM targets WHERE target_name='{目标}'),
        'replay_{test_type}', '{url}', '{param}', '{method}', '{payload}', '{evidence}',
        '{risk}', '', '{remediation}', datetime('now','localtime'), {burp_request_id}, NULL, 'pending');
```

risk 映射：idor=High, unauth=High, info_leak=High, password_reset_takeover=Critical, param_logic=High, user_enum=Medium, captcha_reuse=Medium

**low_confidence** → suspicious_points 表，前缀 `SP-RP-{seq}`。

### 4.3 终端摘要

```
=== manual-replay 执行摘要 ===
目标: {target}
时间窗口: 最近 5 分钟
采集端点: {n} 个（含 {m} 个流程步骤）
生成变种: {n} 条

本轮 confirmed ({n}):
  F-RP-{id} {type} {method} {url} ({risk})

本轮 low_confidence（待 vuln-review 复核）:
  SP-RP-{id} {type} {method} {url}

如需复核 SP-RP-*: vuln-review
如需切换 IP: Switch-ClashProxy
```

---

## 5. DB Schema & 外部影响

### 5.1 DB 变更

migration 006：hunt_queue 增加 source/flow_id 字段

```sql
ALTER TABLE hunt_queue ADD COLUMN source TEXT DEFAULT 'auto' CHECK(source IN ('auto','manual_replay'));
ALTER TABLE hunt_queue ADD COLUMN flow_id TEXT;
```

- `source='manual_replay'` — 手工流程采集的端点
- `flow_id='replay_{target}_{yyyymmdd_HHMM'` — 同次流程的分组标识

### 5.2 外部影响

| 影响范围 | 变更 |
|----------|------|
| CLAUDE.md | 新增 manual-replay 到 Skills 表 + 工作流 2.6 |
| auth_sessions | 无变化（复用 primary/secondary） |
| findings | 新增 F-RP-* 前缀记录 |
| suspicious_points | 新增 SP-RP-* 前缀记录 |
| hunt_queue | 新增 source + flow_id 字段 |

---

## 6. 错误处理 & 升级

| 场景 | 行为 |
|------|------|
| Burp 历史为空（窗口内无请求） | 提示"时间窗口内无目标域名请求，扩大窗口或手动操作后重试"，退出 |
| mmx 分类失败 / JSON 不完整 | 内置兜底提取（`raw.find('[')…rfind(']')`），失败则标 error 退出 |
| 单端点变种执行失败 | 标 error，继续下一条 |
| A/B 账号 session 过期 | 标 error + notes，提示重登 |
| 变种生成中 Claude 中间退出 | 已写入 flow_variants_json → 恢复时读缓存，不重新生成 |
| 高危漏洞（password_reset_takeover） | 弹出升级提示，操作员确认合规性 |

**幂等恢复**：变种由 AI 即时生成（不持久化缓存）。断线恢复后扫描 `hunt_queue WHERE source='manual_replay' AND status='queued'` 重新 analyze → variant_gen → execute。Burp 原始请求已持久化在 hunt_queue，无需重新采集。

---

## 7. 与 business-logic-hunt 的边界

| 维度 | business-logic-hunt | manual-replay |
|------|---------------------|---------------|
| 采集方式 | 自动 Burp 历史全量扫描 | 时间窗口手工流程 |
| 覆盖深度 | 单端点独立测试 | 多步流程 + 状态依赖 |
| 变种策略 | 固定算法（7 种） | AI 按 intent 推荐模板 |
| 触发方式 | 独立调用，增量队列 | 操作员跑完流程后立即执行 |
| 输出前缀 | F-BLH-* / SP-BLH-* | F-RP-* / SP-RP-* |
