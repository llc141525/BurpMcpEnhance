---
name: vuln-review
description: 安全漏洞 PoC 验证引擎。门控探测已修复类型 + WAF 绕过 + PoC 验证 + 价值决策树 + 双层变种分析，结果写入 findings/suppressions 表。
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, Skill
---

# vuln-review

只做 PoC 验证，不做攻击面扩大。

## 环境常量

```
PROJECT_ROOT = E:\SRC挖掘\SRC
DBS_DIR = PROJECT_ROOT/dbs
DB查询工具 = TOOLS/db_query.py
```

所有 DB 操作通过 `python3 TOOLS/db_query.py --target "{目标名}"` 执行。

## 入口

### 参数解析

从 args 提取:
- `目标: {name}` — 必填，目标名称
- `规则文件: res/vuln_rules.json` — 可选，不提供则跳过 fix-aware 门控逻辑

### 数据库就绪检查

```python
# 用 Bash 检查 dbs/ 目录是否存在目标 DB
ls "{DBS_DIR}/{目标名}_*.db"
# 若无文件，输出：
#   未找到目标 DB，请先调用 asset-recon 初始化
```

```bash
python3 TOOLS/db_query.py --target "{目标名}" "SELECT phase FROM scan_state WHERE id=1"
```

| 结果 | 动作 |
|------|------|
| 返回 phase | 继续 |
| 空 | 输出"请先运行 stealth-scanner" 后停止 |

### Session 续期检查

```bash
python3 TOOLS/auth/session_manager.py --target "{目标名}"
```

- 退出码 0 → session 有效（或已自动续期）→ 继续
- 退出码 1 → 输出以下提示后退出：
  ```
  [AUTH_BARRIER] Session 已过期，自动续期失败。
  请手动登录后执行:
    python TOOLS/db/db_query.py --target "{目标名}" "UPDATE scan_state SET phase='auth_ready' WHERE id=1" --write
  如 login_url 未存储，加参数:
    python3 TOOLS/auth/session_manager.py --target "{目标名}" --login-url "https://sso.example.com/login?..."
  ```

## 容错规则

1. **重试** — Burp MCP 调用失败后：等待 2 秒重试，最多 3 次。失败则跳过该条。
2. **SQLite 读失败** — 等待 1 秒重试，最多 3 次。
3. **高危** — RCE/SQL 写 shell/任意文件上传，立即升级操作员，不继续。

## ETL 分析路由

遵循 `Skill(skill="mmx-router")` 的路由规则。PoC 响应对比使用 `etl_analyzer.py --task diff_responses`。

## 关键包保留规则

所有验证请求必须通过 Burp 发送。误报也保留一次 Burp 请求作为参考。

## 代理配置

```powershell
. .\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv
```

操作员说"换 IP"时才执行 Switch-ClashProxy。

## 模式 1: 漏洞复核

触发: `Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")`
带规则文件: `Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院; 规则文件: res/vuln_rules.json")`

### Step 0 — 加载规则文件

检查 args 中是否包含 `规则文件:`。若包含且文件存在:

```bash
test -f "res/vuln_rules.json" && echo "EXISTS" || echo "NOT_FOUND"
```

- 文件存在 → `Read res/vuln_rules.json` 解析 `likely_fixed_types` 列表和对应规则
- 文件不存在 / 未指定 → 设 `likely_fixed_types = []`（跳过所有门控逻辑）

确保 vuln_suppressions 表存在:

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "CREATE TABLE IF NOT EXISTS vuln_suppressions (
     vuln_type TEXT PRIMARY KEY,
     gate_payload TEXT,
     gate_response_summary TEXT,
     verdict TEXT CHECK(verdict IN ('fix_confirmed','waf_blocked','inconclusive','suppressed_value','low_priority')),
     bypass_successful INTEGER DEFAULT 0,
     checked_at TEXT DEFAULT (datetime('now','localtime'))
   )" --write
```

### Step 1 — 加载待复核

从 suspicious_points 加载 untested 条目，排除已被 suppression 跳过的类型:

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "SELECT sp.* FROM suspicious_points sp
   LEFT JOIN vuln_suppressions vs ON sp.test_type = vs.vuln_type
   WHERE sp.test_status='untested'
     AND (vs.verdict IS NULL OR vs.verdict NOT IN ('fix_confirmed','waf_blocked'))
   ORDER BY sp.risk DESC"
```

若指定 `目标: SP-001,SP-002` 则只加载指定 ID；否则加载所有 untested。

结果为空 → 输出"无可复核可疑点"后退出。

### Step 2 — 逐条验证

对每条可疑点:

#### 2a. 门控探测（仅当 test_type IN likely_fixed_types）

```
test_type 不在 likely_fixed_types → 跳过门控，直接进入 2d PoC 验证
```

**基准请求** — 同 URL 同参数，不携带 payload，通过 Burp 发送:

```python
# 重构基准请求 (无 payload)
baseline_url = sp.url.replace(sp.param + '=' + sp.payload, sp.param + '=')
# 或用原始 GET 不带参
mcp__burp__send_http1_request(content=baseline_http, targetHostname=..., ...)
```

记录: 状态码、响应体长度、响应体前 500 字符。

**门控请求** — 注入 gate payload:

```python
# 从 vuln_rules.json 中找到 test_type 对应的 gate payload
gate_payload = rules[test_type].gate.payload
gate_url = sp.url.replace(sp.param + '=', sp.param + '=' + gate_payload)
mcp__burp__send_http1_request(content=gate_http, ...)
```

**响应对比** — 判定:

| 门控响应 vs 基准 | 判定 | 下一步 |
|-------------------|------|--------|
| 状态码相同 + 响应体无明显异常内容 + 无漏洞特征 | `fix_confirmed` | 写 suppression → 跳过该条 |
| 出现漏洞特征（SQL 报错/命令回显/模板输出） | 仍存在漏洞 | 进入 2d PoC 验证 |
| 状态码 403/451 或拦截页关键字 | WAF 拦截 | 进入 2b WAF 绕过 |

**写 suppression** (fix_confirmed):

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "INSERT OR REPLACE INTO vuln_suppressions
   (vuln_type, gate_payload, gate_response_summary, verdict, bypass_successful, checked_at)
   VALUES ('{test_type}', '{gate_payload}', '基线{基线状态码}/{基线长度} vs 门控{门控状态码}/{门控长度} - 响应一致', 'fix_confirmed', 0, datetime('now','localtime'))" --write
```

#### 2b. WAF 绕过

门控请求被 WAF 拦截时执行。

**收集上下文**: 原始 gate payload、拦截响应状态码、拦截页关键字（如 "ModSecurity"、"Blocked"、"WAF"、"420" 等）。

**AI 生成绕过变体**: 基于拦截特征从以下策略选择 2-3 种组合，生成 3-5 个变体:

| 策略 | 适用场景 | 示例 |
|------|----------|------|
| URL 编码 | 通用 | `' OR '1'='1` → `%27%20OR%20%271%27%3D%271` |
| 注释混淆 | SQLi | `'/**/OR/**/'1'='1` |
| 大小写变换 | 关键字过滤 | `' oR '1'='1` |
| 双写绕过 | 关键字过滤 | `' OORR '1'='1` |
| HPP 参数污染 | GET 参数 | `?id=1&id=1' OR '1'='1` |
| 空白符替换 | CMDi | `;echo$IFS\`VULN_CHECK\`` |
| Body 填充 | WAF 前 N KB 检查 | payload 前填充 8KB 填充字符 |
| 编码嵌套 | 通用 | 双重 URL 编码 |

**逐条重放**: 对每个变体，用 Burp 发送并检查响应:

```
for variant in variants:
    resp = mcp__burp__send_http1_request(variant, ...)
    if resp.status == 200 AND 无WAF拦截特征:
        → 绕过成功，重新执行 2a 门控探测（用绕过后的请求）
        break
else:
    → 所有变体被拦，判定 waf_blocked
```

**写 suppression** (waf_blocked):

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "INSERT OR REPLACE INTO vuln_suppressions
   (vuln_type, gate_payload, gate_response_summary, verdict, bypass_successful, checked_at)
   VALUES ('{test_type}', '{gate_payload}', 'WAF拦截: {拦截特征}, 尝试{数量}个绕过变体均失败', 'waf_blocked', 0, datetime('now','localtime'))" --write
```

写完后跳过该条，继续下一条。

#### 2c. 门控恢复（绕过成功后）

WAF 绕过成功 → 重新执行一次门控探测（用绕过后的请求上下文），仍按 2a 的判定表处理:
- fix_confirmed → 写 suppression 后跳过
- 仍出现漏洞特征 → 进入 2d PoC

#### 2d. PoC 验证（原流程）

读 page 上下文:

```bash
python3 TOOLS/db_query.py --target "{目标名}" "SELECT * FROM pages WHERE url='{page_url}'"
```

构造最小 PoC → Burp 发送 → 对比基线 → 判定。

**响应对比优先用 `diff_proxy_responses`**（只返回变化行，省 token）：

```python
# 发送基线请求，记录 burp_id_baseline
# 发送 PoC 请求，记录 burp_id_poc
diff = mcp__burp__diff_proxy_responses(id1=burp_id_baseline, id2=burp_id_poc)
# 只读 diff 判断是否漏洞特征，不读全文
```

IDOR 测试：A 账号请求 id1，B 账号请求 id2，diff 有数据差异即为越权。

### Step 3 — 结果判定

| 判断 | 操作 |
|------|------|
| 确认存在漏洞 | 进入 Step 3a 决策树评估 |
| 误报 | `UPDATE suspicious_points SET test_status='false_positive', notes='{原因}' WHERE id='SP-{n}'` |
| 不确定 | `UPDATE suspicious_points SET test_status='false_positive', notes='需操作员确认: {原因}'` |
| 高危（RCE/写shell/上传） | 暂停，升级操作员 |

### Step 3a — 价值决策树

PoC 确认漏洞存在后，执行决策树决定后续扫描策略:

**Q1: 该漏洞能否在基础设施层一次修复？**

> 如 WAF 规则、API 网关过滤、全局输入清洗等，一次配置所有同类漏洞都被拦截。
>
> 是 → 判定 `suppressed_value` → 该漏洞提交 SRC，但扫描器不再深入测试同类型
> 否 → 进入 Q2

**Q2: 目标是单一技术栈还是多团队分散开发？**

> 单一（如全部 Java Spring Boot）→ 修复可以快速传播到所有服务，窗口期短 → `low_priority`
> 多团队/多语言（不同 BU 用不同框架）→ 每处修复方式不同，投入大 → 进入 Q3

**Q3: 修复是否必须逐处改代码？**

> 每处都要改 → 修复成本高，厂商修复意愿低，同类漏洞可大量挖掘 → 判定 `continue`（高价值）
> 改配置/升级依赖即可解决 → 修复相对容易，窗口期短 → 判定 `low_priority`

AI 无法判断时（如不确定技术栈），输出询问操作员:

```
[决策树] 无法判断目标技术栈。请回答：
  A) 单一技术栈
  B) 多团队分散
```

默认（操作员不回复）→ 选 B（多团队分散，保守策略）。

**写入决策结果**:

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "INSERT OR REPLACE INTO vuln_suppressions
   (vuln_type, gate_payload, gate_response_summary, verdict, bypass_successful, checked_at)
   VALUES ('{type}', '', '价值评估: {Q1结果} → {Q2结果} → {Q3结果} => {决策}', '{verdict}', 0, datetime('now','localtime'))" --write
```

| verdict | 含义 | 扫描策略 |
|---------|------|----------|
| `suppressed_value` | 低价值，基础架构已覆盖 | 跳过同类 |
| `low_priority` | 窗口期短/修复成本低 | 不优先，不深入 |
| `continue` | 高价值 | 正常验证，可深挖 |

### Step 4 — 记录确认的漏洞

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id)
   VALUES (
     'F-{n}', 'SP-{n}',
     (SELECT id FROM targets WHERE target_name='{target_name}'),
     '{type}', '{url}', '{param}', '{method}',
     '{payload}', '{evidence}', '{risk}', '{cvss}',
     '{remediation}', datetime('now','localtime'), {burp_request_id}
   )" --write
```

### Step 4b — 变种分析 Phase A: 自动端点搜索

每确认一个漏洞后，自动触发变种搜索:

```bash
python3 TOOLS/variant_search.py --target "{目标名}" --finding {F-xxx}
```

结果自动写入 `suspicious_points` (source='variant_search')，下轮 vuln-review 自然处理。

若 findings 表中同类型已确认漏洞 > 1 个，对每个都执行一次变种搜索。后续 confirmed 的漏洞也会被后续轮次的 vuln-review 自动触发。

### Step 4c — 变种分析 Phase B: 代码级模式搜索（可选，Claude 驱动）

**触发条件**: finding 类型为以下之一且对应 JS 文件在 `js_files` 表中:
- `hardcoded_secret` — 密钥/凭证硬编码
- `idor` / `unauth_access` — 不安全权限检查模式
- `js_debug` — 调试开关/API 文档暴露

**流程**:

1. 从 finding 读 JS 文件 URL，在 `js_files` 表找到对应文件
2. 若 JS 文件已本地缓存 → `Read` 读取；否则用 Scrapling 抓取
3. 调用 `Skill(skill="variant-analysis:variant-analysis")` 进行 5 步渐进式代码模式搜索:
   - Step 1: 理解原始漏洞根因
   - Step 2: 构造精确匹配（ripgrep 搜关键代码行）
   - Step 3: 识别可抽象的元素（变量名→通配符，字面值→任意值）
   - Step 4: 渐进泛化，每次改一处，审查新命中
   - Step 5: 对新命中分类（高/中/低置信度）
4. 将新命中写入 `suspicious_points` (source='variant_analysis_code')

**FP 率 > 50% 时停止泛化**，记录已确认的命中即可。

Phase B 非自动——由 Claude 判断是否值得深入。对于大部分 `sqli`/`xss`/`command_injection` 类型，Phase A 的端点搜索已足够。

### Step 5 — 输出复核摘要

```
=== 漏洞复核结果 ===
复核可疑点: {n} 个
├─ 确认: {n} 个
├─ 误报: {n} 个
├─ fix_confirmed 跳过: {n} 个 (门控探测确认已修复)
├─ waf_blocked 跳过: {n} 个 (WAF 绕不过)
├─ suppressed_value: {n} 个 (价值评估 — 基础架构已覆盖)
├─ low_priority: {n} 个 (价值评估 — 低优先级)
└─ 升级操作员: {n} 个

Suppressions 生效: {n} 个类型被跳过
```

## framework_exploit / sqli_scan 来源处理

**source = 'framework_exploit'**（由 `pipeline/framework_exploit.py` 写入）:
- 对应具体 CVE 攻击路径，误报率低，优先验证
- 验证方式：Burp 重发对应请求，确认 success_pattern 命中
- 确认后直接写 findings，无需额外变种测试

**source = 'sqli_scan'**（由 `pipeline/sqli_scan.py` 写入 findings 表）:
- sqlmap 已完成自动确认，findings 表中记录即为有效 PoC
- 直接进入 src-report 报告流程，跳过 PoC 重验步骤
- 报告中附上 sqlmap payload 作为 PoC 证据

## 协作约定

- 高危（RCE/SQL 写 shell/任意文件上传）→ 暂停，升级操作员
- 无法判断 → 标记 `需操作员确认: {原因}`，继续下一条
- 决策树无法判断 → 询问操作员，默认保守选项
- 复核完成 → 输出摘要后干净退出
