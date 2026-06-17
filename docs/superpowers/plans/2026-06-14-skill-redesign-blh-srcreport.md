# [Skill 重设计 BLH + src-report] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 更新三个文件：compare.py 新增 vertical_priv_esc / batch_idor 测试类型；business-logic-hunt/SKILL.md 替换 Burp 历史采集为 DB 三路 + 新增自包含 explore 阶段；src-report/SKILL.md 新增逐条可见复核 + 自动剔除无意义信息泄露规则。

**Architecture:** 无新建文件。compare.py 新增两个 handler 函数并注册到 `_HANDLERS` 字典；business-logic-hunt/SKILL.md 做三处精确替换（frontmatter、collecting 节、testing 节的类型映射 + 新测试逻辑）；src-report/SKILL.md 替换 Step 4 节。

**Tech Stack:** Python 3, argparse, difflib.SequenceMatcher, uv run pytest; SKILL.md 为 Markdown 指令文档（无运行时测试，靠 diff 验证）。

---

## Task 1: compare.py — 新增 vertical_priv_esc 和 batch_idor

**Files:**
- Modify: `TOOLS/utils/compare.py`
- Test: `TOOLS/tests/test_compare.py`

- [ ] **Step 1: 追加 vertical_priv_esc 失败测试**

在 `TOOLS/tests/test_compare.py` 末尾追加（保留已有内容）：

```python
from utils.compare import compare_vertical_priv_esc, compare_batch_idor


class TestCompareVerticalPrivEsc:
    def test_primary_403_teacher_200_is_confirmed(self):
        verdict, evidence = compare_vertical_priv_esc(
            403, '{"code":403,"message":"权限不足"}',
            200, '{"code":0,"data":{"users":[{"id":1,"name":"学生甲"}]}}',
        )
        assert verdict == "confirmed"
        assert "teacher=200" in evidence

    def test_primary_500_missing_auth_is_confirmed(self):
        verdict, evidence = compare_vertical_priv_esc(
            500, '{"error":"undefined method for nil:NilClass"}',
            0, '',
        )
        assert verdict == "confirmed"
        assert "500" in evidence

    def test_both_403_is_false_positive(self):
        verdict, evidence = compare_vertical_priv_esc(
            403, '{"code":403}',
            403, '{"code":403}',
        )
        assert verdict == "false_positive"
        assert "teacher=403" in evidence

    def test_no_teacher_session_is_needs_teacher_account(self):
        verdict, evidence = compare_vertical_priv_esc(
            403, '{"code":403}',
            0, '',
        )
        assert verdict == "needs_teacher_account"

    def test_primary_200_is_false_positive_public_endpoint(self):
        verdict, evidence = compare_vertical_priv_esc(
            200, '{"code":0,"data":{}}',
            0, '',
        )
        assert verdict == "false_positive"
        assert "public endpoint" in evidence
```

- [ ] **Step 2: 运行 — 验证失败**

```bash
cd "e:\SRC挖掘\SRC" && uv run pytest TOOLS/tests/test_compare.py::TestCompareVerticalPrivEsc -v 2>&1 | head -20
```

期望输出含：`ImportError: cannot import name 'compare_vertical_priv_esc'`

- [ ] **Step 3: 实现 compare_vertical_priv_esc**

在 `TOOLS/utils/compare.py` 的 `compare_password_reset` 函数之后、`_HANDLERS = {` 之前插入：

```python
def compare_vertical_priv_esc(
    a_status: int, a_body: str,
    b_status: int, b_body: str,
) -> tuple[str, str]:
    """a=primary（普通用户），b=teacher/admin（高权限，b_status=0 表示无会话）。"""
    if a_status == 500:
        return "confirmed", f"a_status=500 missing require_login; response={a_body[:120]}"
    if a_status == 200:
        return "false_positive", "primary can access, likely public endpoint"
    if a_status in (403, 401):
        if b_status == 0:
            return "needs_teacher_account", "primary returns 403 but no teacher/admin session to verify"
        if b_status == 200:
            return "confirmed", f"primary={a_status} teacher=200 body={b_body[:200]}"
        return "false_positive", f"both primary={a_status} and teacher={b_status}"
    return "false_positive", f"a_status={a_status}"
```

- [ ] **Step 4: 运行 — 验证通过**

```bash
cd "e:\SRC挖掘\SRC" && uv run pytest TOOLS/tests/test_compare.py::TestCompareVerticalPrivEsc -v
```

期望：`5 passed`

- [ ] **Step 5: 追加 batch_idor 失败测试**

在 `TOOLS/tests/test_compare.py` 末尾追加：

```python
class TestCompareBatchIdor:
    def test_variant2_b_with_a_id_succeeds_is_confirmed(self):
        baseline = '{"code":0,"data":{"items":[{"id":101,"score":95}]}}'
        b_cross  = '{"code":0,"data":{"items":[{"id":101,"score":95}]}}'
        verdict, evidence = compare_batch_idor(
            200, baseline,      # ① A + [A_id]
            200, b_cross,       # ② B + [A_id]
            0,   '',            # ③ 未执行
        )
        assert verdict == "confirmed"
        assert "variant②" in evidence

    def test_variant3_mixed_ids_is_confirmed(self):
        baseline = '{"code":0,"data":{"ids":[101]}}'
        mixed    = '{"code":0,"data":{"ids":[101,202]}}'
        verdict, evidence = compare_batch_idor(
            200, baseline,
            403, '{"code":403}',   # ② 拒绝
            200, mixed,            # ③ A + [A_id, B_id]
        )
        assert verdict == "confirmed"
        assert "variant③" in evidence

    def test_variant2_403_is_false_positive(self):
        baseline = '{"code":0,"data":{"ids":[101]}}'
        verdict, evidence = compare_batch_idor(
            200, baseline,
            403, '{"code":403}',
            403, '{"code":403}',
        )
        assert verdict == "false_positive"

    def test_baseline_fail_is_false_positive(self):
        verdict, evidence = compare_batch_idor(
            404, '',
            0, '',
            0, '',
        )
        assert verdict == "false_positive"
        assert "baseline" in evidence
```

- [ ] **Step 6: 运行 — 验证失败**

```bash
cd "e:\SRC挖掘\SRC" && uv run pytest TOOLS/tests/test_compare.py::TestCompareBatchIdor -v 2>&1 | head -20
```

期望：`ImportError: cannot import name 'compare_batch_idor'`

- [ ] **Step 7: 实现 compare_batch_idor + 注册两个新类型**

在 `compare_vertical_priv_esc` 之后、`_HANDLERS = {` 之前插入：

```python
def compare_batch_idor(
    a_status: int, a_body: str,
    b_status: int, b_body: str,
    unauth_status: int, unauth_body: str,
) -> tuple[str, str]:
    """a=variant①(A+[A_id]基线), b=variant②(B+[A_id]), unauth=variant③(A+[A_id,B_id])。"""
    if a_status != 200:
        return "false_positive", f"baseline variant① a_status={a_status}, not a batch endpoint"
    if b_status == 200 and len(b_body) > 50:
        s = _sim(a_body, b_body)
        if s > 0.7:
            return "confirmed", f"variant② B+[A_id] succeeded sim={s:.2f}, cross-account operation"
    if unauth_status == 200 and len(unauth_body) > 50:
        s = _sim(a_body, unauth_body)
        if s > 0.7:
            return "confirmed", f"variant③ A+[A_id,B_id] succeeded sim={s:.2f}, batch IDOR"
    if b_status == 200 or unauth_status == 200:
        return "low_confidence", f"variant② b_status={b_status} variant③ unauth_status={unauth_status} but body too short"
    return "false_positive", f"variant② b_status={b_status} variant③ unauth_status={unauth_status}"
```

将 `_HANDLERS` 字典中 `"password_reset_takeover"` 行之后添加：

```python
    "vertical_priv_esc": lambda a: compare_vertical_priv_esc(
        a.a_status, a.a_body, a.b_status, a.b_body
    ),
    "batch_idor": lambda a: compare_batch_idor(
        a.a_status, a.a_body, a.b_status, a.b_body, a.unauth_status, a.unauth_body
    ),
```

（`argparse choices=list(_HANDLERS)` 会自动包含新 key，无需手动改）

- [ ] **Step 8: 运行全部测试**

```bash
cd "e:\SRC挖掘\SRC" && uv run pytest TOOLS/tests/test_compare.py -v
```

期望：所有测试通过（含原有 3 个 TestCompareUnauth 测试，共 12 passed）

- [ ] **Step 9: Commit**

```bash
cd "e:\SRC挖掘\SRC"
git add TOOLS/utils/compare.py TOOLS/tests/test_compare.py
git commit -m "feat: add vertical_priv_esc and batch_idor handlers to compare.py"
```

---

## Task 2: business-logic-hunt/SKILL.md

**Files:**
- Modify: `.claude/skills/business-logic-hunt/SKILL.md`

- [ ] **Step 1: 更新 frontmatter description**

定位 `.claude/skills/business-logic-hunt/SKILL.md` 第 3 行，替换：

旧：
```
description: 业务逻辑漏洞主动猎手。读 Burp 历史 → 筛业务接口 → 用 A/B 双账号+未授权三层重放 → 写 findings。覆盖 IDOR/未授权/信息泄露/验证码缺陷/用户枚举/密码重置/参数逻辑替换。
```

新：
```
description: 业务逻辑漏洞主动猎手。DB三路收集（auth_explore XHR + JS静态分析 + probe可疑点）+ 内置浏览器探索（不依赖stealth-scanner）→ A/B双账号+未授权三层重放 → 写 findings。覆盖 IDOR/垂直越权/批量IDOR/未授权/信息泄露/验证码缺陷/用户枚举/密码重置/参数逻辑。
```

- [ ] **Step 2: 替换整个 Phase: collecting 节（去掉 Burp 历史，加 explore + DB三路）**

将从 `## Phase: collecting` 到 `## Phase: testing` 之间的全部内容（不含 `## Phase: testing` 行本身）替换为：

```markdown
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
→ mmx 做业务意图分类（endpoint_type + business_intent）
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

```

- [ ] **Step 3: 更新 Phase: testing 的类型映射**

找到 `### 类型映射` 节，将旧代码块：

```
```
business_api          → [idor, unauth, info_leak, param_logic]
auth_login            → [user_enum, captcha_reuse]
auth_register         → [captcha_reuse, user_enum]
auth_reset_password   → [password_reset_takeover, user_enum]
auth_verify_code      → [captcha_reuse]
```
```

替换为：

````markdown
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
````

- [ ] **Step 4: 更新 compare.py 调用行 + 新增两个测试逻辑块**

找到 `### 响应比对` 节的 bash 代码块，将 `--test-type` 那行：

旧：
```
  --test-type {idor|unauth|info_leak|param_logic|user_enum|captcha_reuse|password_reset_takeover} \
```

新：
```
  --test-type {idor|unauth|info_leak|param_logic|user_enum|captcha_reuse|password_reset_takeover|vertical_priv_esc|batch_idor} \
```

再找到 `verdict 映射：\`confirmed\` → 写 findings；\`low_confidence\` → 写 suspicious_points；\`false_positive\` → 跳过。` 这行，在其之后追加：

```markdown
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
```

- [ ] **Step 5: Commit**

```bash
cd "e:\SRC挖掘\SRC"
git add ".claude/skills/business-logic-hunt/SKILL.md"
git commit -m "feat: business-logic-hunt DB三路collecting + explore phase + admin_api/batch_idor types"
```

---

## Task 3: src-report/SKILL.md

**Files:**
- Modify: `.claude/skills/src-report/SKILL.md`

- [ ] **Step 1: 替换 Step 4 为逐条可见审查格式（含无意义信息泄露剔除规则）**

将 `.claude/skills/src-report/SKILL.md` 中的 `### Step 4: 逐条证据审查` 节（从标题行到 `### Step 5:` 之前的全部内容）替换为：

```markdown
### Step 4: 逐条证据审查（每条实时输出）

对每条 finding，**先输出审查过程再写 DB**，不等全部处理完再批量输出：

```
─── 审查 [N/Total] {finding_id} ───
类型: {type}  原等级: {risk}
URL:  {method} {url}
证据: {evidence 前 200 字}

推理: {1-2 行判断依据}
→ {确凿|充分|不足}  复核等级: {等级}  决策: {✅ 通过 | ❌ 剔除（原因）}
──────────────────────────────────
```

#### 4a. 证据确凿度判定

| 判定 | 标准 | 动作 |
|------|------|------|
| 确凿 | PoC 响应明确证明漏洞存在（如越权返回数据、SQL报错、命令执行回显） | 进入等级复核 |
| 充分 | 有间接证据但缺完整回显（如盲注时间差、CORS 响应头配置） | 需补充注明"间接证据" |
| 不足 | 仅框架指纹/版本号/公开端点，或 "若 WAF 被绕过" 类假设 | **剔除** |

**自动剔除的情况：**

- 明确声明 "当前状态：默认密钥解密失败，利用条件未满足"
- 仅凭响应头指纹（Server/X-Powered-By 等）推论漏洞存在
- "如果绕过 WAF..." 但未实际绕过
- 端点按设计为公开（OIDC well-known、login 页面等）
- 无任何 PoC 响应只有理论分析

**无意义信息泄露自动剔除**：当 `type='info_disclosure'` 或 `test_type='info_leak'` 时额外检查：

| 证据仅含（无实质数据）→ 自动剔除 | 证据含以下任意一项 → 保留 |
|---|---|
| 响应头指纹：Server / X-Powered-By / X-Generator / X-Runtime 等 | 真实 PII：姓名、手机号、邮箱、身份证号、学籍号 |
| 框架/语言/版本号（Rails 6.x / PHP/7.4 / nginx/1.18） | 他人业务数据：订单、成绩、私信、支付信息 |
| 路径/文件存在性（robots.txt 可读 / .git/HEAD 返回 200 但无内容） | 内网信息：内网 IP、主机名、DB 表结构、绝对路径 |
| 错误页面暴露技术栈但无业务数据、无 PII | 凭证：API Key、Token、密码、Session |

剔除输出示例：
```
─── 审查 [3/8] F-XXX ───
类型: info_disclosure  原等级: Low
URL:  GET /  (响应头)
证据: Server: nginx/1.18.0, X-Powered-By: Phusion Passenger 6.0.14

推理: 仅响应头版本指纹，无 PII/业务数据/内网信息。
→ 证据不足  决策: ❌ 自动剔除（无意义信息泄露：仅框架指纹）
──────────────────────────────────
```

**判定为剔除后立即写 DB**：

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "UPDATE findings SET review_status='excluded', review_notes='{原因}' WHERE id='{id}'" --write
```

#### 4b. 等级复核

对证据确凿/充分的漏洞，对照 Step 2 的定级规则重新评定：

- DB 中的 risk 字段仅为扫描器初步判断，不可直接采信
- 按管理员提供的规则逐条对照，给出复核等级
- 若原等级与复核等级不一致，标注调整原因

**判定为通过后立即写 DB**：

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "UPDATE findings SET review_status='included' WHERE id='{id}'" --write
```
```

- [ ] **Step 2: Commit**

```bash
cd "e:\SRC挖掘\SRC"
git add ".claude/skills/src-report/SKILL.md"
git commit -m "feat: src-report Step 4 visible per-finding review + auto-exclude meaningless info disclosure"
```

---

## Self-Review

**Spec coverage check:**

| Spec 要求 | 实现任务 |
|-----------|---------|
| business-logic-hunt 不再读 Burp 历史 | Task 2 Step 2 |
| Phase: explore 自包含浏览器探索 | Task 2 Step 2 |
| explore 页面不足时补充 depth≤2 | Task 2 Step 2 |
| DB 三路 collecting | Task 2 Step 2 |
| 三路为空时输出 BLH_EMPTY | Task 2 Step 2 |
| admin_api + batch_api 加入 TYPE_MAP | Task 2 Step 3 |
| RISK_MAP 更新 | Task 2 Step 3 |
| vertical_priv_esc compare 逻辑 | Task 1 Step 3 |
| batch_idor compare 逻辑 | Task 1 Step 7 |
| batch_idor B id 来源三优先级 | Task 2 Step 4 |
| needs_teacher_account verdict 处理 | Task 2 Step 4 |
| compare.py 调用行包含新类型 | Task 2 Step 4 |
| src-report Step 4 逐条可见输出 | Task 3 Step 1 |
| 无意义信息泄露自动剔除 | Task 3 Step 1 |
| 保留含 PII/凭证的 info_leak | Task 3 Step 1 |

**Placeholder scan:** 无 TBD/TODO。所有代码块完整，包含具体函数签名和 assert 语句。

**Type consistency:** `compare_vertical_priv_esc(a_status, a_body, b_status, b_body)` 在 Task 1 Step 3 定义，Task 1 Step 1 测试调用同签名，Task 2 Step 4 的 lambda 调用 `a.a_status, a.a_body, a.b_status, a.b_body`——一致。`compare_batch_idor(a_status, a_body, b_status, b_body, unauth_status, unauth_body)` 同理——一致。
