# SRC Skill 体系 v2 — 设计文档

**日期**: 2026-05-28  
**基于**: 2026-05-26-src-redesign-design.md  
**范围**: 4 项改动 + 1 个新 skill

---

## 背景与痛点

| 痛点 | 根因 |
|------|------|
| src-report 重复生成同一漏洞的报告 | findings 表无已报告状态字段 |
| src-report Phase 1 剔除决策无持久化 | 剔除结论只存在对话，下次重跑又重新评审 |
| 无独立审核机制 | 缺少站在平台审核员视角复核报告的 skill |
| stealth-scanner 与报告生成有隐式耦合 | skill 末尾的协作模块暗示自动流转 |
| 报告格式为 .md，不符合实际提交习惯 | src-report 输出 Markdown 文件 |

---

## 一、DB Schema 变更

### 1.1 findings 表新增 6 个字段

```sql
-- src-report Phase 1 评审结果
ALTER TABLE findings ADD COLUMN review_status TEXT DEFAULT NULL;
-- NULL=未评审, 'included'=通过, 'excluded'=剔除
ALTER TABLE findings ADD COLUMN review_notes  TEXT;
-- 剔除原因，如"密钥解密失败，利用条件不满足"

-- src-report Phase 2 写报告后回填
ALTER TABLE findings ADD COLUMN reported_platforms TEXT DEFAULT '';
-- 逗号分隔平台名，如 "edu,补天"
ALTER TABLE findings ADD COLUMN report_file TEXT;
-- 相对于项目根目录的路径，如 "reports/货讯通科技/补天_01_MOC未授权.docx"
-- vuln-auditor 读取时用 os.path.join(PROJECT_ROOT, report_file)

-- vuln-auditor 审核结果
ALTER TABLE findings ADD COLUMN audit_status TEXT DEFAULT 'pending';
-- 'pending' / 'approved' / 'rejected'
ALTER TABLE findings ADD COLUMN audit_notes  TEXT;
-- 打回理由或通过说明
```

### 1.2 迁移策略

新建 `TOOLS/migrate_findings_v2.py`，启动时由 src-report 和 vuln-auditor 自动调用：

```python
COLUMNS = [
    ("review_status",       "TEXT DEFAULT NULL"),
    ("review_notes",        "TEXT"),
    ("reported_platforms",  "TEXT DEFAULT ''"),
    ("report_file",         "TEXT"),
    ("audit_status",        "TEXT DEFAULT 'pending'"),
    ("audit_notes",         "TEXT"),
]

for col, typedef in COLUMNS:
    try:
        conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {typedef}")
    except sqlite3.OperationalError:
        pass  # 列已存在，忽略
```

迁移幂等，对已有 DB 安全重跑。

### 1.3 漏洞生命周期（完整流水线）

```
vuln-review
  └─► findings.test_status = 'confirmed'
       │
       ▼
  src-report Phase 1（评审）
       ├─► review_status = 'excluded' + review_notes   （剔除，不再重复评审）
       └─► review_status = 'included'                  （通过，进入 Phase 2）
                │
                ▼
          src-report Phase 2（写报告）
               └─► reported_platforms += '{平台}', report_file = '...'
                        │
                        ▼
                   vuln-auditor（平台审核员视角）
                        ├─► audit_status = 'rejected' + audit_notes   → 写 memory
                        └─► audit_status = 'approved'                 → 写 memory
```

---

## 二、src-report Skill 变更

### 2.1 Phase 1 — 读取漏洞时的过滤逻辑

Step 3 查询改为：

```sql
SELECT f.id, f.type, f.url, f.param, f.method, f.payload, f.evidence,
       f.risk, f.cvss, f.remediation, f.confirmed_at, f.burp_request_id,
       f.sp_id, f.review_status, f.reported_platforms,
       t.target_name, t.domain as target_domain
FROM findings f
JOIN targets t ON f.target_id = t.id
WHERE (
  -- 未评审，或上次被剔除但操作员手动重置了 review_status
  f.review_status IS NULL OR f.review_status = 'included'
)
AND (
  -- 当前平台未报告过
  f.reported_platforms IS NULL
  OR f.reported_platforms = ''
  OR f.reported_platforms NOT LIKE '%{平台}%'
)
ORDER BY f.risk DESC
```

若所有 findings 均已报告（对当前平台），输出：

```
目标 {目标} 在 {平台} 无待报告漏洞（所有 findings 已报告或已剔除）。
若需重新报告，请手动将 findings.reported_platforms 中对应平台名删除后重跑。
```

### 2.2 Phase 1 — 评审结论回写 DB

Step 4a 决策后立即写 DB，不等到 Phase 2：

```sql
-- 剔除
UPDATE findings SET review_status='excluded', review_notes='{原因}' WHERE id='{id}';

-- 通过
UPDATE findings SET review_status='included' WHERE id='{id}';
```

Step 5 的评审表输出后附加一行：

```
（评审结论已写入 DB，下次跑 src-report 将跳过已剔除条目。如需重审，请将对应 findings.review_status 置 NULL。）
```

### 2.3 Phase 2 — 写报告后回填字段

每写完一个 docx：

```python
# 追加平台（避免覆盖已有平台）
existing = findings_row['reported_platforms'] or ''
platforms = [p for p in existing.split(',') if p]
if '{平台}' not in platforms:
    platforms.append('{平台}')
new_platforms = ','.join(platforms)
```

```sql
UPDATE findings
SET reported_platforms = '{new_platforms}',
    report_file = 'reports/{target_name}/{平台}_{序号}_{漏洞标题}.docx'
WHERE id = '{id}';
```

### 2.4 输出格式 .md → .docx

文件命名规则不变，后缀改为 `.docx`：

```
reports/{target_name}/{平台}_{序号}_{漏洞标题}.docx
```

**python-docx 格式规范**（功能优先，无颜色）：

| 内容 | Word 样式 |
|------|----------|
| 一级标题（漏洞名） | `Heading 1` |
| 二级标题（漏洞概述/PoC 等） | `Heading 2` |
| 三级标题（第 N 步） | `Heading 3` |
| 正文 | `Normal` |
| HTTP 请求/代码块 | `Normal`，字体 Courier New 10pt，段落左右缩进 0.5cm，段落上下各加 6pt 间距 |
| 表格（漏洞属性） | 标准 Word 表格，首行加粗 |
| 占位符说明 | `Normal`，斜体 |

---

## 三、stealth-scanner Skill 变更

### 3.1 删除协作模块

删除 SKILL.md 末尾的 `## 协作` 一节（当前第 696–703 行）：

```markdown
## 协作

- scanner 写入: `pages`, `js_files`, `suspicious_points` (test_status='untested')
- vuln-review 读取上述表, 更新: `suspicious_points.test_status`, `findings`
- WAL 模式 + busy_timeout=5000 处理并发
```

### 3.2 删除 allowed-tools 中的 Skill

```yaml
# 改前
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Grep, Glob, Skill

# 改后
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Grep, Glob
```

stealth-scanner 不再调用任何其他 skill，完全独立。

---

## 四、vuln-review Skill 变更

### 4.1 Step 5 — 复核完成后行为

**改前**（当前 Step 5 末尾）：
```
- 复核完成 → 输出摘要，询问操作员下一步（生成报告 / 继续扫描）
```

**改后**：
```
- 复核完成 → 输出摘要后干净退出，不询问后续步骤
```

vuln-review 不再暗示或建议生成报告，由操作员手动决定调用 src-report。

---

## 五、vuln-auditor Skill（新建）

### 5.1 概述

站在补天平台审核员的视角，对 src-report 已生成的 docx 报告逐条复核：
- 解析 docx，提取 PoC HTTP 请求 / PoC 脚本
- 通过 Burp 发送请求，或运行脚本，核实漏洞可复现
- 打回：更新 DB + 写 memory（打回原因）
- 通过：更新 DB + 若曾被打回则写 memory（复审通过记录）

### 5.2 触发方式

```
Skill(skill="vuln-auditor", args="目标: 货讯通科技")
Skill(skill="vuln-auditor", args="目标: 货讯通科技; finding: F-001,F-002")  # 指定漏洞
```

### 5.3 工作流

#### Step 1 — 解析参数 + DB 就绪检查

```sql
SELECT id, type, url, param, method, payload, evidence,
       risk, report_file, audit_status, audit_notes, review_status
FROM findings
WHERE audit_status = 'pending'
  AND report_file IS NOT NULL
  AND review_status = 'included'
ORDER BY risk DESC;
```

若结果为空：
```
无待审核漏洞（所有 included findings 已审核，或尚无 report_file）。
```

若指定了 `finding: F-001`，只处理对应 ID。

#### Step 2 — 逐条审核

对每条 finding：

**2a. 解析 docx**

```python
from docx import Document

doc = Document(report_file)
poc_section = False
http_lines = []
script_ref = None

for para in doc.paragraphs:
    if 'PoC' in para.text and para.style.name.startswith('Heading'):
        poc_section = True
        continue
    if poc_section:
        # Courier New 字体段落 = 代码块
        if any(run.font.name == 'Courier New' for run in para.runs if run.font.name):
            http_lines.append(para.text)
        # 检查脚本引用（如 "运行: tmp/poc_xxx.py"）
        if 'tmp/' in para.text and '.py' in para.text:
            script_ref = extract_script_path(para.text)
        # 遇到下一个 Heading 则停止
        if para.style.name.startswith('Heading') and http_lines:
            break
```

**2b. 提取预期响应**

继续扫描 PoC 节之后的「预期响应」段落（Courier New 格式，紧跟 HTTP 请求代码块之后）：

```python
expected_response = []
in_expected = False
for para in doc.paragraphs:
    if '预期响应' in para.text:
        in_expected = True
        continue
    if in_expected:
        if any(run.font.name == 'Courier New' for run in para.runs if run.font.name):
            expected_response.append(para.text)
        elif para.style.name.startswith('Heading'):
            break
```

**2c. 发送 Burp 请求**

将解析出的 HTTP 请求通过 Burp MCP 发送：

```python
mcp__burp__send_http1_request(
    method=method,
    url=url,
    headers=headers_dict,
    body=body
)
```

对比响应与 docx 中记录的「预期响应」片段：
- 状态码匹配 + 关键字段存在 → 可复现
- 状态码/响应体与预期明显不符 → 不可复现

**2d. 运行 PoC 脚本（如有）**

```bash
python3 {script_ref}
```

观察脚本 stdout/stderr 是否符合预期输出（docx 中记录）。

**2e. 判定**

| 判定 | 条件 |
|------|------|
| 通过 | HTTP 响应可复现 + 脚本（若有）输出符合预期 |
| 打回 | 任一步骤无法复现，给出具体步骤和实际响应 |
| 升级操作员 | Burp 不可用 / docx 损坏 / PoC 脚本缺失 |

#### Step 3 — 写回 DB

**打回**：
```sql
UPDATE findings
SET audit_status = 'rejected',
    audit_notes  = '{步骤N无法复现: 实际响应 {code}/{body片段}，预期 {expected}}'
WHERE id = '{id}';
```

**通过**：
```sql
UPDATE findings
SET audit_status = 'approved'
WHERE id = '{id}';
```

#### Step 4 — 写 memory

**memory 文件路径**: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\audit_{target}_{finding_id}.md`

**打回时创建/更新**：

```markdown
---
name: audit-{target}-{finding_id}
description: 补天审核记录 — {漏洞类型} @ {url}（{audit_status}）
metadata:
  type: project
  target: {target}
  finding_id: {id}
---

# 审核记录：{漏洞标题}

**Finding ID**: {id}
**漏洞类型**: {type}
**URL**: {url}

## 打回记录

**打回日期**: {date}
**打回原因**: {audit_notes}
**无法复现步骤**: {具体步骤}
**实际响应**: {实际响应摘要}
```

**复审通过时追加**：

```markdown
## 复审通过

**通过日期**: {date}
**修复/补充说明**: {操作员说明 or "重新发送请求可复现"}
```

#### Step 5 — 输出审核摘要

```
=== vuln-auditor 审核摘要 ===
目标: {target}
审核: {n} 条
├─ 通过: {n} 条
│  ├─ F-001 MOC未授权访问 (High)
│  └─ F-002 CORS配置错误 (Medium)
├─ 打回: {n} 条
│  └─ F-003 Actuator信息泄露 (Medium) — 请求返回 404，端点已关闭
└─ 升级操作员: {n} 条
```

### 5.4 Skill 元数据

```yaml
---
name: vuln-auditor
description: 站在补天平台审核员视角复核漏洞报告。解析 docx、发 Burp 请求、运行 PoC 脚本，打回不可复现的漏洞并记录到 memory，通过后更新 audit_status。
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, Glob
---
```

---

## 六、实现任务清单

| 任务 | 文件 | 优先级 |
|------|------|--------|
| 新建 `TOOLS/migrate_findings_v2.py` | TOOLS/ | P0（其余任务前置） |
| 修改 `src-report` SKILL.md（Phase 1 过滤+回写，Phase 2 回填，docx 输出） | .claude/skills/src-report/SKILL.md | P0 |
| 删除 `stealth-scanner` 协作模块 + allowed-tools | .claude/skills/stealth-scanner/SKILL.md | P1 |
| 修改 `vuln-review` Step 5 协作约定 | .claude/skills/vuln-review/SKILL.md | P1 |
| 新建 `vuln-auditor` SKILL.md | .claude/skills/vuln-auditor/SKILL.md | P1 |
| 更新 CLAUDE.md 的 Skill 表 | CLAUDE.md | P2 |
| 更新 MEMORY.md 索引 | memory/MEMORY.md | P2 |

---

## 七、关键约束

- 所有 DB ALTER 操作必须幂等（列已存在则忽略）
- vuln-auditor 只处理 `review_status='included'` 的 findings，不审核被 src-report 剔除的
- src-report 不会重置 `review_status='excluded'` 的条目，除非操作员手动置 NULL
- stealth-scanner 和 vuln-review 保持完全独立，不自动流转到报告生成
- docx 报告中的 HTTP 请求格式必须可被 vuln-auditor 的解析逻辑识别（Courier New 段落）
