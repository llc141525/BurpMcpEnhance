# Skill 重设计：business-logic-hunt + src-report

**日期**: 2026-06-14  
**背景**: 头歌平台渗透测试复盘，发现三个问题：
1. business-logic-hunt 只挖 Burp 流量，与 manual-replay 职责重叠
2. stealth-scanner 在 /goal Stop hook 压力下自动触发 src-report（行为问题，已决定不再使用 /goal）
3. src-report 复核过程不可见，操作员感觉审查被跳过

---

## 一、职责边界重新定义

| Skill | 数据来源 | 职责 |
|-------|---------|------|
| **manual-replay** | Burp 历史（时间窗口） | 操作员手工跑了什么 → AI 变种攻击 |
| **business-logic-hunt** | DB 三路 + 内置浏览器探索 | AI 主动发现操作员没测的业务逻辑 |
| **stealth-scanner** | katana + nuclei + arjun | 广度 BFS + 框架探测，不测漏洞 |

**business-logic-hunt 不再读 Burp 历史**。Burp 历史分析完全归 manual-replay。

---

## 二、business-logic-hunt 重设计

### 2.1 Phase 状态机（新增 explore）

```
init → explore → collecting → testing → done
            ↑
      (< 20 条 auth_explore 数据时才运行)
```

### 2.2 Phase: explore（新增，自包含）

**目的**：在不依赖 stealth-scanner 的情况下，自己驱动浏览器发现业务端点。

**触发条件**：
```sql
SELECT COUNT(*) FROM pages WHERE source='auth_explore'
-- 结果 < 20 → 执行 explore
-- 结果 >= 20 → 跳过，直接进 collecting（stealth-scanner 已提供足够数据）
```

**前置检查**：
1. Chrome CDP `localhost:9222` 可用 → 否则提示 `python TOOLS/auth/chrome_manager.py --target {目标}` 后等待或跳过
2. `auth_sessions` 有有效 `primary` session → 否则输出 `[AUTH_BARRIER]` 停止

**执行步骤**：
```
1. 注入 Cookie（从 auth_sessions 读 primary token）

2. 确定导航目标页面（从 DB 推断）：
   -- 优先：业务关键词页面
   SELECT url FROM pages
   WHERE depth <= 1 AND status='visited'
     AND (url LIKE '%course%' OR url LIKE '%class%'
       OR url LIKE '%homework%' OR url LIKE '%order%'
       OR url LIKE '%user%' OR url LIKE '%profile%'
       OR url LIKE '%admin%' OR url LIKE '%setting%'
       OR url LIKE '%score%' OR url LIKE '%exam%')
   LIMIT 10
   -- 若匹配不足 10 页，补充 depth <= 2 的已访问页面，按 depth ASC 排序填满

3. 逐页导航，停留 3 秒等待 XHR 完成
   拦截 XHR/fetch，记录：method + url + request_body + response_status

4. 去重后写入 pages 表（source='blh_explore'）
   并预填 api_calls_json 字段供 collecting 阶段读取

5. 输出摘要：
   [BLH_EXPLORE] 导航 {m} 页，发现 {n} 个业务端点
```

**与 stealth-scanner 的关系**：

| 维度 | stealth-scanner auth_explore | business-logic-hunt explore |
|------|-----------------------------|-----------------------------|
| 广度 | BFS 全量页面 | 业务关键词筛选，最多 10 页 |
| 深度 | 所有子页面递归 | 深度 1，聚焦当前页 XHR |
| 写入 | pages + suspicious_points | pages（source='blh_explore'） |
| 依赖 | 独立 | 独立 |

两者互补，数据可共用，互不依赖。

---

### 2.3 Phase: collecting（DB 三路汇总，去掉 Burp 历史）

**路 1 — auth_explore / blh_explore XHR 记录**：
```sql
SELECT DISTINCT p.url, p.method, p.api_calls_json
FROM pages p
WHERE p.source IN ('auth_explore', 'blh_explore')
  AND p.status = 'visited'
  AND p.api_calls_json IS NOT NULL
```

**路 2 — JS 静态分析发现的 API 端点**：
```sql
SELECT js.url as js_url, js.discovered_apis_json
FROM js_files js
WHERE js.analyzed = 1
  AND js.discovered_apis_json IS NOT NULL
```
展开 `discovered_apis_json` 数组，拼上目标 base URL，构造完整端点列表。

**路 3 — probe 阶段写入的可疑点**：
```sql
SELECT sp.url, sp.method, sp.param, sp.test_type, sp.risk
FROM suspicious_points sp
WHERE sp.source IN ('probe', 'auth_explore', 'blh_explore')
  AND sp.test_status = 'untested'
```

**处理流程**：
```
三路合并 → 按 (method, url) 去重
→ 写临时文件 tmp/blh_collect_{target}_{ts}.json
→ mmx 做业务意图分类（endpoint_type + business_intent）
→ 按 endpoint_type 写 hunt_queue（source='auto'）
→ 输出：采集完成：{n} 个业务端点入队
```

---

### 2.4 Phase: testing（扩展覆盖）

#### 更新后的端点类型映射

```python
TYPE_MAP = {
    # 新增
    'admin_api':           ['vertical_priv_esc', 'unauth'],
    'batch_api':           ['batch_idor', 'unauth'],
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
    'unauth':                  'High',
    'info_leak':               'Medium',
    'password_reset_takeover': 'Critical',
    'param_logic':             'High',
    'user_enum':               'Medium',
    'captcha_reuse':           'Medium',
}
```

#### admin_api 识别规则（mmx 分类时）
URL 含 `/admin/` `/manage/` `/teacher/` `/staff/` `/system/`，或 DELETE/PATCH 且路径模式为 `/api/{resource}/{id}` 形式。

#### vertical_priv_esc 测试逻辑（新增）

```
Step 1：primary（普通用户）发请求
  → HTTP 200 + 数据    → 可能公开接口，转 info_leak 判定
  → HTTP 403/权限不足   → 高权限接口确认 → 进 Step 2
  → HTTP 500           → 缺认证前置（missing require_login）→ confirmed

Step 2：检查 auth_sessions 是否有 role='teacher'/'admin' session
  → 有 → 用高权限 session 重发
         teacher=200 / primary=403 → confirmed 垂直越权
         teacher=403 / primary=403 → 两者都拒绝，false_positive
  → 无 → 写 suspicious_point（evidence="接口返回403但无高权限账号验证"）
          notes="需操作员提供 teacher/admin 账号验证"
```

#### batch_idor 测试逻辑（新增）

```
原始请求识别：body 或 query 含数组参数（ids/user_ids/item_ids/order_ids 等）

构造变种：
  ① A 账号 + [A_own_id]           → baseline，应成功
  ② B 账号 + [A_own_id]           → B 用 A 的 id → 若成功 = 跨账号写操作
  ③ A 账号 + [A_own_id, B_own_id] → 混合 id → 若 B 的也被操作 = 批量 IDOR

B 的 id 来源（优先顺序）：
  1. secondary session 访问个人主页/profile 接口（如 `/api/users/me`）自动获取自身 id
  2. IDOR 测试阶段已通过 secondary session 访问发现的资源 id
  3. 若均无法获取 → 跳过变种 ③，仅执行 ① ②
```

#### 主流漏洞覆盖矩阵（设计完成后）

| 漏洞类别 | 覆盖 | 测试类型 |
|---------|------|---------|
| 水平越权（IDOR） | ✅ | `idor` |
| 垂直越权 | ✅ | `vertical_priv_esc` |
| 未授权访问 | ✅ | `unauth` |
| 批量操作越权 | ✅ | `batch_idor` |
| 信息泄露（有实质数据） | ✅ | `info_leak` |
| 参数逻辑篡改 | ✅ | `param_logic` |
| 密码重置缺陷 | ✅ | `password_reset_takeover` |
| 用户枚举 | ✅ | `user_enum` |
| 验证码缺陷 | ✅ | `captcha_reuse` |
| 业务流程跳跃 | ❌ | v2 迭代 |
| 条件竞争 | ❌ | v2 迭代 |

---

## 三、src-report 复核可见化

### 3.1 Step 4 改为逐条公开审查

每条 finding 处理时**即时输出**，格式：

```
─── 审查 [N/Total] {finding_id} ───
类型: {type}  原等级: {risk}
URL:  {method} {url}
证据: {evidence 前 200 字}

推理: {1-2 行判断依据}
→ {确凿|充分|不足}  复核等级: {等级}  决策: {✅ 通过 | ❌ 剔除（原因）}
──────────────────────────────────
```

每条审查完立即写 DB（`review_status='included'` 或 `'excluded'`），全部完成后输出汇总表，等待操作员确认。

### 3.2 自动剔除：无意义信息泄露

在原有自动剔除条件基础上新增规则，针对 `type='info_disclosure'` 或 `test_type='info_leak'`：

**自动剔除，当证据仅含以下内容（无实质数据）**：
- 响应头指纹：`Server:` `X-Powered-By:` `X-Generator:` `X-Runtime:` `X-Frame-Options:` 等
- 框架/语言/版本号泄露（"Rails 6.x"、"PHP/7.4"、"nginx/1.18"）
- 路径/文件存在性（robots.txt 可读、.git/HEAD 返回 200 但无内容）
- 错误页面暴露技术栈但无业务数据、无 PII

**保留，当证据包含以下任意一项**：
- 真实 PII：姓名、手机号、邮箱、身份证号、学籍号、地址
- 他人业务数据：订单、成绩、私信、支付信息
- 内部基础设施：内网 IP、内部主机名、数据库表结构、服务器绝对路径
- 凭证类：API Key、Token、密码、Session

审查时的输出示例：
```
─── 审查 [3/8] F-XXX ───
类型: info_disclosure  原等级: Low
URL:  GET /  (响应头)
证据: Server: nginx/1.18.0, X-Powered-By: Phusion Passenger 6.0.14

推理: 仅响应头版本指纹，无 PII/业务数据/内网信息，属无实质危害的信息泄露。
→ 证据不足  决策: ❌ 自动剔除（无意义信息泄露：仅框架指纹）
──────────────────────────────────
```

---

## 四、改动范围汇总

| 文件 | 改动 |
|------|------|
| `.claude/skills/business-logic-hunt/SKILL.md` | 新增 Phase: explore；collecting 改三路 DB 汇总，去掉 Burp 历史；TYPE_MAP 新增 admin_api / batch_api；新增 vertical_priv_esc 和 batch_idor 测试逻辑 |
| `.claude/skills/src-report/SKILL.md` | Step 4 改逐条公开审查；新增无意义信息泄露自动剔除规则 |
| `TOOLS/utils/compare.py` | 新增 `--test-type vertical_priv_esc`：比较 primary(403) vs teacher(200)，输出 confirmed/false_positive/needs_teacher_account；新增 `--test-type batch_idor`：比较三个变种响应，当变种 ② 或 ③ 返回 2xx 且含被操作数据时判 confirmed |

**不改动**：manual-replay（职责不变）、stealth-scanner（职责不变）、vuln-review、src-report Phase 2（写报告）。

---

## 五、v2 迭代（本次不做）

- 业务流程跳跃（flow bypass）：需要多步骤状态追踪
- 条件竞争（race condition）：需要并发请求支持
- 业务流建模（攻击矩阵自动生成）：mmx 识别业务对象 + 操作，生成跨账号攻击矩阵
