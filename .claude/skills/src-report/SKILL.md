---
name: src-report
description: 生成面向 SRC 平台提交的漏洞报告。两阶段：Phase 1 证据评审 + 等级复核，Phase 2 逐漏洞写入独立报告文件。管理员可直接复制单个文件内容到 SRC 平台提交。
allowed-tools: mcp__burp__*, Bash, Read, Write, Edit, AskUserQuestion, Glob
---

# src-report

两阶段工作流：先评审（证据筛查 + 等级复核），管理员确认后再写报告。

## Phase 1 — 评审

### Step 1: 解析参数

解析 args 中的 平台 和 目标:

- 平台: edu / 补天 / CNVD（必填）
- 目标: 目标名称（必填）

未指定时的提示:

```text
请指定报告平台和目標：
Skill(skill="src-report", args="平台: 补天; 目标: 货讯通科技")
```

### Step 2: 获取定级规则

向管理员索要该目标的漏洞定级规则。使用 AskUserQuestion：

```text
question: "请提供 {目标} 在 {平台} 的漏洞定级规则（危害等级评定标准）"
header: "定级规则"
options: [
  {label: "我粘贴规则文本", description: "在下一条消息中粘贴完整的定级规则"},
  {label: "使用通用 CVSS 标准", description: "按 CVSS v3.1 评分：Critical(9.0+) / High(7.0+) / Medium(4.0+) / Low(0.1+)"},
  {label: "我口述要点", description: "在下一条消息中简要说明各等级的判定标准"},
]
```

等待管理员回复后，将规则整理为可操作的判定表：

| 等级 | 判定条件 | 典型漏洞类型 |
|------|----------|-------------|
| ... | ... | ... |

### Step 3: 读取漏洞数据

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "SELECT f.id, f.type, f.url, f.param, f.method, f.payload, f.evidence, f.risk, f.cvss,
          f.remediation, f.confirmed_at, f.burp_request_id, f.sp_id,
          t.target_name, t.domain as target_domain
   FROM findings f
   JOIN targets t ON f.target_id = t.id
   ORDER BY f.risk DESC"
```

若返回空:

```text
目标 {目标名} 在 findings 表中无 confirmed 漏洞，请先运行 vuln-review 确认漏洞。
```

### Step 4: 逐条证据审查

对每条 finding 执行以下判定：

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

#### 4b. 等级复核

对证据确凿/充分的漏洞，对照 Step 2 的定级规则重新评定：

- DB 中的 risk 字段仅为扫描器初步判断，不可直接采信
- 按管理员提供的规则逐条对照，给出复核等级
- 若原等级与复核等级不一致，标注调整原因

### Step 5: 输出评审结果

输出评审表给管理员确认：

```markdown
## 评审结果 — {目标} ({平台})

| # | 漏洞 | 原等级 | 证据 | 复核等级 | 决策 |
|---|------|--------|------|----------|------|
| 1 | MOC getAllServiceLoop 未授权 | High | 确凿: 返回300+业务数据 | High | 通过 |
| 2 | CORS 配置错误 | Medium | 充分: 响应头确认但未演示实际窃取 | Medium | 通过 |
| 3 | MyFaces 反序列化 | Medium | **不足**: 密钥解密失败 | — | 剔除 |
| ... | ... | ... | ... | ... | ... |

**剔除原因说明:**
- #3 MyFaces: 10个默认密钥均无法解密ViewState，CVE利用条件不满足，仅为框架指纹
- ...

确认无误后我开始写报告。是否确认？
```

**必须等待管理员确认后才能进入 Phase 2。**

管理员可能的回复：
- "确认" / "开始写" → 进入 Phase 2
- "把 #X 改成 High" → 调整后重新输出评审表
- "#X 也加上吧" → 加入后重新输出评审表

### Step 6: 获取 HTTP 请求

管理员确认后，对每条通过的漏洞获取 Burp 完整请求：

```text
mcp__burp__get_proxy_http_detail(ids="<burp_request_id>")
```

burp_request_id 为空时，从 url/method/param/payload 重构请求，并用 `mcp__burp__get_proxy_http_history_regex` 搜索真实请求补全请求头。

## Phase 2 — 写报告

### Step 7: 创建输出目录 + 写入

```bash
mkdir -p "reports/{target_name}"
```

每漏洞一个独立文件：

```
reports/{target_name}/{平台}_{序号}_{漏洞标题}.md
```

序号为 Phase 1 评审通过的顺序（剔除后重新编号），漏洞标题中文化、不含特殊字符。

写入前先获取每个漏洞的完整 HTTP 请求（Step 6），然后逐条写入。

### Step 8: 利用链分析

对每条漏洞推理攻击路径:

- 单步漏洞 (IDOR): 讲清为什么能越权、后端缺少什么校验
- 多步漏洞 (攻击链): 按步骤编号，每步 = 操作 + 请求/响应 + 成功原因

每条描述至少包含: 攻击入口 → 漏洞原理 → 实际危害

---

## 三套字段模板

### edu 格式

```markdown
# [{target_name}] {漏洞标题}

**分类**: {漏洞类型}
**漏洞等级**: {复核等级}
**漏洞单位**: {target_name}
**开发方**: {开发方或留空}
**漏洞url**: {完整URL，不带backtick}

---

## 漏洞概述

{一句话 + 漏洞原理}

## 利用链

> **第 1 步 — ...**
> ...
>
> **第 N 步 — ...**
> ...

**根因**: ...

**最终影响**: ...

## PoC

```http
{完整 HTTP 请求，可直接导入 Burp Repeater}
```

**预期响应**:

```json
{关键响应片段}
```

> **占位符说明**:
> - {{NAME}}: 含义 + 获取方式

## 修复建议

1. **{建议标题}**: {具体措施}
2. ...
```

### 补天格式

```markdown
# {漏洞标题}

**漏洞类别**: Web安全
**漏洞URL**: {完整URL}
**漏洞类型**: {漏洞类型}
**漏洞等级**: {复核等级}

## 简要描述

{一句话危害}

## 详细细节

### 漏洞概述

{漏洞原理}

### 利用链

> **第 1 步 — ...**
> ...

**最终影响**: ...

### PoC

```http
{完整 HTTP 请求}
```

> **占位符说明**:
> - {{NAME}}: 含义 + 获取方式

## 修复方案

1. {具体措施}
2. ...
```

### CNVD 格式

```markdown
# {漏洞名称}

**涉事单位**: {目标单位名}
**所属IP**: {服务器IP}
**所在省份**: {省份}
**所在城市**: {城市}
**影响对象类型**: Web应用
**漏洞类型**: {漏洞类型}
**漏洞url**: {完整URL}

## 漏洞描述

{完整描述 + PoC + 利用链}

```http
{完整 HTTP 请求}
```

> **占位符说明**:
> - {{NAME}}: 含义 + 获取方式

## 临时解决方案

{临时缓解措施}
```

---

## 输出规范

- 每条漏洞一个独立 .md 文件，可直接复制全文粘贴到 SRC 提交表单
- URL 不带反引号包裹
- 占位符用 `{{大写_下划线}}` 格式，文件末尾附说明块
- 修复建议具体到代码/配置层面
- 文件名不含特殊字符，序号两位数字补零（01_xxx.md, 02_xxx.md）
- 不写汇总表、使用方法、扫描统计
