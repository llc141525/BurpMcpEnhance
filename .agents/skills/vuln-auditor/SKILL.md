---
name: vuln-auditor
description: 站在补天平台审核员视角复核漏洞报告。解析 docx 提取 PoC HTTP 请求并通过 Burp 发送，运行 PoC 脚本，打回不可复现漏洞并记录到 memory，通过后更新 audit_status。
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, Glob
---

# vuln-auditor

## 审核员立场

审核员不是白帽子的对立面，也不是帮白帽子拔高分数的。核心职责：

> **确保每一条 finding 的等级和描述，与 PoC 实际演示的危害严格对应。**

默认假设白帽子会：倾向高报等级、夸大危害范围、假设组合攻击场景、修复建议夹带无关内容。审核员的职责是校正这些偏差。

## 潜规则表（SRC 审核行业惯例）

### 立即打回（无需 Burp 验证）

| 场景 | 打回代码 | 说明 |
|------|----------|------|
| 仅凭响应头指纹（Server/X-Powered-By/版本号）推论漏洞 | `FINGERPRINT_ONLY` | 版本暴露不等于可利用，需有实际 exploit |
| "若结合 X 漏洞..."、"若绕过 WAF..." 等假设提升等级 | `HYPOTHETICAL_CHAIN` | 等级只能基于当前 PoC 单独可复现的危害 |
| PoC 仅为工具扫描截图、无手动复现过程 | `TOOL_ONLY_NO_MANUAL` | Xray/Goby 等扫描结果存在误报，必须手动验证 |
| 修复建议包含与本漏洞根因无关的条目 | `UNRELATED_REMEDIATION` | 每条修复建议必须直接对应本漏洞根因 |
| Self-XSS（只能攻击自己） | `SELF_XSS` | 无跨用户影响，不构成有效漏洞 |
| CSRF 但目标操作无实际危害（如修改无意义字段） | `CSRF_NO_IMPACT` | 需证明 CSRF 能造成有价值的状态改变 |
| 越权但响应数据为空或非敏感（如仅返回公开字段） | `IDOR_NO_SENSITIVE_DATA` | 必须证明拿到了另一用户的真实敏感数据 |
| 漏洞已修复（复现失败且无历史截图） | `ALREADY_FIXED` | 按已修复处理，不再收录 |
| 与已收录 finding 同 URL+同参数+同类型 | `DUPLICATE` | 重复漏洞，非首发不计分 |

### 降级（等级从白帽子报告调低）

| 场景 | 白帽子报 | 审核员降为 |
|------|----------|------------|
| 反射型 XSS，无存储，需用户点击链接 | High | Medium |
| 信息泄露仅服务器版本/路径，无敏感数据 | Medium | Low 或无效 |
| 未授权访问但返回数据量极少或非敏感 | High | Medium |
| 越权但需要大量交互条件（非一键利用） | High | Medium |
| SSRF 但只能访问内网，无回显，无进一步利用 | High | Medium |
| SQL 注入可读但数据库无敏感表 | High | Medium |
| 验证码/频率限制缺失，但无实际枚举成功证明 | Medium | Low |
| 用户枚举（返回差异判断账号是否存在） | Medium | Low |

### 信息泄露分级标准

| 内容 | 等级 |
|------|------|
| 数据库连接字符串、服务器 SSH 密钥、源码 | Critical/High |
| 用户手机号/身份证/姓名批量（>100 条） | High |
| 少量用户 PII（<10 条） | Medium |
| 仅 IP/路径/服务器版本 | Low 或无效 |
| 公开可查的注册信息 | 无效 |

### 越权/IDOR 认定标准

必须同时满足：
1. 使用两个不同账号（A、B）演示
2. A 的请求能读取/修改 B 的数据
3. 响应中包含 B 的实际敏感数据（非空响应、非报错）
4. 不满足上述任一条 → 降级或打回

## 触发

```
Skill(skill="vuln-auditor", args="目标: {target}")
Skill(skill="vuln-auditor", args="目标: {target}; finding: F-001,F-002")
```

## 环境

```
PROJECT_ROOT = E:\SRC挖掘\SRC
DBS_DIR      = E:\SRC挖掘\SRC\dbs
MEMORY_DIR   = C:\Users\llc\.Codex\projects\e--SRC---SRC\memory
```

## 前置迁移

```bash
python3 TOOLS/migrate.py --target "{目标}"
```

## Step 1 — 加载待审漏洞

```sql
SELECT id, type, url, param, method, payload, evidence,
       risk, report_file, audit_status, audit_notes, review_status
FROM findings
WHERE audit_status = 'pending'
  AND report_file IS NOT NULL
  AND review_status = 'included'
ORDER BY risk DESC;
```

若指定了 `finding: F-001,F-002`，追加 `AND id IN ('F-001','F-002')`。

| 结果 | 动作 |
|------|------|
| 空 | 输出"无待审核漏洞"后退出 |
| 有数据 | 逐条进入 Step 2 |

## Step 2 — 逐条审核

### 2a. 定位 docx

```python
import os
report_path = os.path.join(PROJECT_ROOT, report_file)
```

文件不存在 → 跳过，记录 `无法审核: report_file 不存在`。

### 2b. 解析 PoC HTTP 请求

```python
from docx import Document

doc = Document(report_path)
poc_started = False
http_lines = []

for para in doc.paragraphs:
    if 'PoC' in para.text and para.style.name.startswith('Heading'):
        poc_started = True
        continue
    if poc_started:
        is_code = any(
            run.font.name and 'Courier' in run.font.name
            for run in para.runs
        )
        if is_code:
            http_lines.append(para.text)
        elif para.style.name.startswith('Heading') and http_lines:
            break
```

### 2c. 解析预期响应

```python
expected_lines = []
in_expected = False

for para in doc.paragraphs:
    if '预期响应' in para.text:
        in_expected = True
        continue
    if in_expected:
        is_code = any(
            run.font.name and 'Courier' in run.font.name
            for run in para.runs
        )
        if is_code:
            expected_lines.append(para.text)
        elif para.style.name.startswith('Heading'):
            break
```

### 2d. 提取 PoC 脚本路径（可选）

```python
import re
script_ref = None
for para in doc.paragraphs:
    m = re.search(r'(tmp/[^\s]+\.py)', para.text)
    if m:
        script_ref = m.group(1)
        break
```

### 2e. 发送 Burp 请求

将 `http_lines` 的第一行解析为 `METHOD /path HTTP/1.x`，后续行为请求头，空行后为请求体。

```python
mcp__burp__send_http1_request(
    method=method,
    url=full_url,          # 从 findings.url 补全 host
    headers=headers_dict,
    body=body or ""
)
```

### 2f. 运行 PoC 脚本（若有）

```bash
python3 {script_ref}
```

记录 stdout/stderr 前 200 字符作为实际输出。

### 2f-extra. 报告内容质量审查（Burp 前置检查）

在发送 Burp 请求之前，先扫描 docx 全文，对照顶部**潜规则表**逐项检查：

**第一轮：立即打回检查**（命中任一 → 直接打回，不发 Burp）

| 检查动作 | 打回代码 |
|----------|----------|
| 全文搜"结合"、"若"、"如果"，确认无假设组合攻击 | `HYPOTHETICAL_CHAIN` |
| 全文搜修复建议，每条与漏洞根因对照，删除不相关条目或打回 | `UNRELATED_REMEDIATION` |
| 确认等级依据是 PoC 单独可证，不依赖假设场景 | `UNSUPPORTED_SEVERITY` |
| 确认"最终影响"的危害在 PoC 中已实际演示 | `UNDEMONSTRATED_IMPACT` |
| 对照潜规则表"立即打回"场景逐条核对 | 见潜规则表代码 |

**第二轮：降级检查**（不打回，但调整等级后继续）

对照潜规则表"降级"场景，若命中 → 记录降级原因，调整 finding.risk 后继续 Burp 验证。

### 2g. 判定

| 判定 | 条件 |
|------|------|
| 通过 | 2f-extra 质量审查无问题 **且** Burp 响应状态码/关键字匹配预期 + 脚本（若有）无异常退出 |
| 打回（内容） | 2f-extra 发现质量问题 |
| 打回（复现） | 2f-extra 通过但 Burp 无法复现 |
| 升级操作员 | Burp 不可用 / docx 损坏 / PoC 脚本路径缺失 |

## Step 3 — 写回 DB

```bash
python3 TOOLS/db_query.py --target "{目标}" \
  "UPDATE findings SET audit_status='rejected', audit_notes='{reason}' WHERE id='{id}'" --write

python3 TOOLS/db_query.py --target "{目标}" \
  "UPDATE findings SET audit_status='approved' WHERE id='{id}'" --write
```

## Step 3.5 — 重命名报告文件

审核完成后，在报告文件名前加上审核结果前缀：

```python
import os
prefix = "通过" if audit_status == "approved" else "打回"
old_path = os.path.join(PROJECT_ROOT, report_file)
dir_name = os.path.dirname(old_path)
base_name = os.path.basename(old_path)
new_name = f"{prefix}_{base_name}"
new_path = os.path.join(dir_name, new_name)
os.rename(old_path, new_path)
```

同时更新 DB 中的 `report_file` 路径（用 Python 拼接新路径后构造命令）：

```python
new_relative_path = f"reports/{target_name}/{prefix}_{base_name}"
bash_cmd = f'python3 TOOLS/db_query.py --target "{target}" "UPDATE findings SET report_file=\'{new_relative_path}\' WHERE id=\'{id}\'" --write'
print(bash_cmd)  # 输出后执行
```

## Step 4 — 写 memory

**memory 文件**: `{MEMORY_DIR}/audit_{target}_{finding_id}.md`

### 打回时（新建或追加）

检查文件是否已存在（曾被打回过）：
- 不存在 → 新建
- 已存在 → 追加新的打回记录

```markdown
---
name: audit-{target}-{finding_id}
description: 补天审核记录 — {type} @ {url}（{audit_status}）
metadata:
  type: project
  target: {target}
  finding_id: {id}
---

# 审核记录：{漏洞标题}

**Finding ID**: {id}
**漏洞类型**: {type}
**URL**: {url}

## 打回 {YYYY-MM-DD}

**打回原因**: {audit_notes}
**实际响应**: {Burp 响应状态码 + 关键字段，不超过 200 字符}
**预期**: {expected_lines 摘要}
```

### 通过时

若 `audit_notes` 不为空（曾被打回） → 在 memory 文件末尾追加：

```markdown
## 复审通过 {YYYY-MM-DD}

**通过说明**: {操作员补充说明 or "重新发送请求可复现"}
```

若首次审核直接通过 → 不写 memory（无需记录）。

## Step 5 — 输出审核摘要

```
=== vuln-auditor 审核摘要 ===
目标: {target}
审核: {n} 条
  通过: {n} 条
    F-001 {type} ({risk})
  打回: {n} 条
    F-003 {type} ({risk}) — {打回原因摘要}
  升级操作员: {n} 条
```

## 容错

| 情况 | 处理 |
|------|------|
| Burp MCP 调用失败 | 等 2s 重试，最多 3 次，失败则升级操作员 |
| docx 解析无 PoC 块 | 标记"报告中未找到 PoC HTTP 请求"，升级操作员 |
| PoC 脚本不存在 | 跳过脚本验证，仅凭 Burp 响应判定 |
| SQLite busy | 等 1s 重试，最多 3 次 |
