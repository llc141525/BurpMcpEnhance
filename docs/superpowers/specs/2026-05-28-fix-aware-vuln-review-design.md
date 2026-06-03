# Fix-Aware Vulnerability Review — Design

## Problem

当 SRC/补天平台厂商提交的漏洞定级规则中包含"已修复"的漏洞类型（如 SQL 注入已通过参数化查询修复），扫描器仍按规则对这些类型进行深度测试，浪费时间和请求。需要一种机制：先确认修复是否存在，已修复则跳过后续测试。

## 设计约束

- 不修改 `stealth-scanner`（只做信息收集+主动探测，不参与决策）
- 新增逻辑全部集中在 `vuln-review`
- WAF 绕过 payload 由 AI 在 vuln-review 运行时即时生成，不依赖第三方工具
- 判断结果持久化，避免重复验证

## 核心流程

```
stealth-scanner (不变)
  BFS爬取 → 发现可疑点 → 写入 suspicious_points
                            ↓
vuln-review (新增 bypass + 跳过逻辑)
                   ↓
           ┌───────────────────┐
           │ 读取规则文件       │
           │ 提取易修复类型列表  │
           └───────────────────┘
                   ↓
           ┌───────────────────┐
           │ 取一条待测可疑点   │
           └───────────────────┘
                   ↓
           ┌────────────────────────────┐
           │ 检查 vuln_suppressions     │
           │ 该类型是否已确认为已修复？  │
           └────────────────────────────┘
           yes → 跳过，标记 skipped_by_suppression
           no  → 继续
                   ↓
           ┌────────────────────────────┐
           │ 该类型在"易修复"列表中？    │
           └────────────────────────────┘
           no  → 走原始 PoC 验证流程
           yes → 进入 bypass + 门控流程
                   ↓
           ┌────────────────────────────┐
           │ 1. 基准请求 (无payload)     │
           │ 2. 门控探测 (最小检测pyl)   │
           │    ├─ 响应同基线 → fix_confirmed
           │    ├─ 异常响应 → 存在漏洞 → 正常验证
           │    └─ WAF拦截 → 进入 bypass
           └────────────────────────────┘
                   ↓
           ┌────────────────────────────┐
           │ WAF 绕过 (AI即时生成)       │
           │ 被拦请求 + 拦截特征 →       │
           │ AI生成3-5个绕过变体         │
           │ → 逐条重放                 │
           └────────────────────────────┘
                   ↓
           ┌────────────────────────────┐
           │ 绕过结果判定                │
           │ 有绕过 → 重新执行门控探测    │
           │ 全拦   → 标记 waf_blocked   │
           └────────────────────────────┘
```

## 新增表: vuln_suppressions

```sql
CREATE TABLE vuln_suppressions (
    vuln_type TEXT PRIMARY KEY,
    gate_payload TEXT,
    gate_response_summary TEXT,
    verdict TEXT CHECK(verdict IN ('fix_confirmed', 'waf_blocked', 'inconclusive')),
    bypass_successful INTEGER DEFAULT 0,
    checked_at TEXT DEFAULT (datetime('now', 'localtime'))
);
```

| 字段 | 用途 |
|------|------|
| `vuln_type` | 漏洞类型主键（如 `sql_injection`） |
| `gate_payload` | 门控探测使用的 payload |
| `gate_response_summary` | 基线 vs 门控响应的对比说明 |
| `verdict` | 判定结论 |
| `bypass_successful` | 是否成功绕过了 WAF（0/1） |
| `checked_at` | 判定时间 |

写入后，同一目标后续任何同类型的可疑点直接跳过：

```
SELECT verdict FROM vuln_suppressions WHERE vuln_type = '{type}'
  → fix_confirmed → 跳过
  → waf_blocked → 跳过（WAF绕不过，不浪费时间）
  → 空 → 正常验证
```

## 规则文件格式

在 `res/` 下新增 `res/vuln_rules.json`，与现有的 `res/rule.txt` 共存：

```json
{
  "likely_fixed_types": [
    "sql_injection",
    "command_injection",
    "path_traversal",
    "ssti",
    "xss_reflected"
  ],
  "rules": [
    {
      "type": "sql_injection",
      "label": "SQL注入",
      "gate": {
        "param": "q",
        "payload": "' OR '1'='1"
      },
      "indicators": {
        "vulnerable_patterns": ["SQL syntax", "mysql_fetch", "odbc_", "Unclosed quotation"],
        "fixed_patterns": []
      }
    },
    {
      "type": "command_injection",
      "label": "命令执行",
      "gate": {
        "param": "cmd",
        "payload": ";echo VULN_CHECK"
      },
      "indicators": {
        "vulnerable_patterns": ["VULN_CHECK"],
        "fixed_patterns": []
      }
    }
  ]
}
```

`likely_fixed_types` 为"容易修复的漏洞类型"列表，由补天规则文本人工提炼。不在列表中的类型不受影响。

## vuln-review 模式: 复核+跳过

新增 vuln-review 执行入口：

```
Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院; 规则文件: res/vuln_rules.json")
```

### 新增逻辑步骤

**Step 0 — 加载规则文件**

```
读取 res/vuln_rules.json
提取 likely_fixed_types 列表
```

**Step 0.5 — 加载 suppression 表**

```
SELECT vuln_type, verdict FROM vuln_suppressions
```

**Step 1 — 加载待复核（修改）**

```
SELECT sp.* FROM suspicious_points sp
LEFT JOIN vuln_suppressions vs ON sp.test_type = vs.vuln_type
WHERE sp.test_status = 'untested'
  AND (vs.verdict IS NULL OR vs.verdict NOT IN ('fix_confirmed', 'waf_blocked'))
ORDER BY sp.risk DESC;
```

这样 `fix_confirmed` / `waf_blocked` 类型的可疑点自动被排除。

**Step 2.5 — 门控探测（新增，插入在 PoC 之前）**

仅当 `test_type IN likely_fixed_types` 时执行：

1. **基准请求**：用同 URL 与参数但无 payload 发送一次，记录状态码 + 响应长度 + 关键内容
2. **门控请求**：注入 gate payload，发送
3. **基线对比**：
   - 门控响应与基准基本一致（状态码相同 + 内容无异常 → `fix_confirmed`
   - 门控响应出现漏洞特征（SQL 报错、命令回显等）→ 走原 PoC 验证
   - 门控响应被 WAF 拦截（403/451/拦截页）→ 进入 Step 2.6 WAF 绕过

**Step 2.6 — WAF 绕过（新增）**

1. 收集：原始 payload + 拦截响应特征（状态码、拦截关键字、页面标题）
2. AI 即时生成 3-5 个绕过变体（编码、注释混淆、大小写变换、HTTP 参数污染等）
3. 通过 Burp 逐条发送
4. 有绕过成功（返回 200 且非拦截页）→ 重新执行 Step 2.5 门控探测
5. 全部拦截 → 写入 `vuln_suppressions (waf_blocked)`，该类型后续跳过

**Step 2.7 — 写 suppression（新增）**

判定为 `fix_confirmed` 时：

```
INSERT OR REPLACE INTO vuln_suppressions
(vuln_type, gate_payload, gate_response_summary, verdict, bypass_successful, checked_at)
VALUES ('{test_type}', '{payload}', '{基线对比摘要}', 'fix_confirmed', {0/1}, datetime('now','localtime'));
```

## Step 3 — 价值评估决策树（新增）

PoC 确认漏洞存在后，在写入 findings 前执行价值评估。决策树决定后续扫描策略：

```
PoC 确认漏洞存在
        ↓
┌─ 问题1: 修复能否在基础设施层一次解决？
│
│  是 → 提交该漏洞，suppressed
│  否 → 进入问题2
│
├─ 问题2: 单一技术栈还是多团队分散？
│
│  单一 → 修复传播快，窗口期短，low_priority
│  分散 → 进入问题3
│
├─ 问题3: 修复需要改代码？
│
│  每处都改 → 高价值，继续挖掘
│  改配置/升级依赖 → 低价值，suppressed
│
└─ 决策结果:
     suppressed_value → 提交漏洞，同类跳过
     low_priority    → 不优先，继续但不深挖
     continue        → 高价值，正常验证
```

### 决策结果写入 suppression

```sql
INSERT OR REPLACE INTO vuln_suppressions
(vuln_type, gate_payload, gate_response_summary, verdict, bypass_successful, checked_at)
VALUES ('{test_type}', '{payload}', '价值评估: {决策理由}', '{verdict}', 0, datetime('now','localtime'));
```

### 人工兜底

AI 无法判断时（如不确定目标技术栈），输出询问：

```
[决策树] 无法判断目标是否为单一技术栈。
请操作员回答：
  A) 单一技术栈（如全部 Java Spring）
  B) 多团队分散（如不同 BU 用不同语言/框架）
```

操作员回复后继续。不回答则默认"多团队分散"（不跳过，保守策略）。

## WAF 绕过策略（AI 即时生成）

不使用第三方工具，由 AI 在运行时基于上下文生成绕过变体。

### 生成策略

| 技术 | 适用场景 | 示例 |
|------|----------|------|
| URL 编码变体 | SQLi, XSS, CMDi | `' OR '1'='1` → `%27%20OR%20%271%27%3D%271` |
| 注释混淆 | SQLi | `'/**/OR/**/'1'='1` |
| 大小写变换 | SQLi, XSS | `' oR '1'='1` |
| 双写绕过 | 关键字过滤 | `' OORR '1'='1` |
| 参数污染 (HPP) | SQLi, CMDi | `?id=1&id=1' OR '1'='1` |
| 空白符替换 | CMDi | `;echo$IFS`VULN_CHECK |
| 编码嵌套 | 通用 | 多重 URL 编码、Unicode 编码 |
| 请求体填充 | WAF 检查前 N KB | 在 payload 前填充填充字符 |

### 生成方式

AI 根据被拦请求的特征，从以上策略中选择 2-3 种组合，每次生成 3-5 个变体。选择依据：

- 拦截页特征（ModSecurity 返回 403 + `This error was generated by Mod_Security` → 尝试注释混淆）
- 参数位置（GET param vs POST body vs Header）
- Content-Type（`application/x-www-form-urlencoded` vs JSON）

## 容错

| 场景 | 处理 |
|------|------|
| 规则文件不存在 | 不使用跳过逻辑，走原始复核流程 |
| `likely_fixed_types` 为空 | 不使用跳过逻辑 |
| Burp 门控请求超时 | 标记 inconclusive，走原始复核 |
| 全部 bypass 变体被拦 | 标记 waf_blocked，该类型跳过 |
| suppression 表不存在 | 自动创建（幂等） |

## 不涉及变更

- `stealth-scanner` — 完全不变
- `src-report` — 完全不变
- `res/rule.txt` — 保留作为参考
- DB schema 中原有表 — 除新增 `vuln_suppressions` 外全不变
