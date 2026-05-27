---
name: vuln-review
description: 安全漏洞 PoC 验证引擎。读取 stealth-scanner 的可疑点，逐条构造 PoC 并通过 Burp 验证，结果写入 findings 表。报告生成请用 src-report skill。
allowed-tools: mcp__burp__*, mcp__MiniMax__*, Bash, Read, Write, Edit, Skill
---

# vuln-review

只做 PoC 验证，不做攻击面扩大。攻击面探测已移至 stealth-scanner Phase 3。

## 环境常量

```
DBS_DIR=r'E:\SRC挖掘\SRC\dbs'
DB查询工具=TOOLS/db_query.py
```

所有 DB 操作通过 `db_query.py --target "{目标名}"` 执行，自动从 `dbs/` 目录找最新目标 DB。

```bash
# 查询
python3 TOOLS/db_query.py --target "台州学院" "SELECT phase, total_pages, total_suspicious FROM scan_state WHERE id=1"
python3 TOOLS/db_query.py --target "台州学院" "SELECT * FROM suspicious_points WHERE test_status='untested' ORDER BY risk DESC"

# 写入
python3 TOOLS/db_query.py --target "台州学院" "UPDATE suspicious_points SET test_status='confirmed' WHERE id='SP-001'" --write
```

## 入口

### 目标解析

从 args 提取 `目标: {name}`：
- 提供了：直接用
- 未提供：查 `targets` 表取当前 target_name

```sql
SELECT id, target_name, domain, auth_status FROM targets LIMIT 1;
```

### 数据库就绪检查

```sql
SELECT phase, total_pages, total_suspicious FROM scan_state WHERE id=1;
```

| 结果                     | 动作                                                   |
| ------------------------ | ------------------------------------------------------ |
| `phase IS NOT NULL`      | 继续                                                   |
| 无数据 / 无 DB           | 输出"数据库为空，请先运行 stealth-scanner" 并停止      |

若 `dbs/` 目录下没有目标 DB，输出：
```
未找到目标 DB，请先调用 asset-recon 初始化目标数据库：
Skill(skill="asset-recon", args="目标: {目标名}")
```

## 容错规则

1. **重试机制** — Burp MCP 调用失败后：等待 2 秒 → 重试 → 最多 3 次。3 次均失败则跳过该条，记录后继续。
2. **SQLite 读失败** — 等待 1 秒重试，最多 3 次。
3. **高危漏洞** — 发现 RCE/SQL 写 shell/任意文件上传，立即升级操作员，不继续自动化测试。

## MiniMax 路由

路由规则和 prompt 模板由 `mmx-router` skill 定义，详见 `.claude/skills/mmx-router/SKILL.md`。

**铁律**：Burp 响应体 >5KB、DB 结果 >10 行、JS/HTML >5KB — 先给 mmx 处理，Claude 只读精简结果。

## 关键包保留规则

所有 PoC 验证请求必须通过 Burp 发送（`mcp__burp__send_http1_request` 或 `mcp__burp__create_repeater_tab`），确保出现在 Burp 代理历史中。

- PoC 验证：构造 payload 后通过 Burp 发送，不在对话中详细展开请求/响应原文
- 误报也保留：即使判定 false_positive，保留一次 Burp 请求作为参考
- 标注关联：在 suspicious_points 的 notes 中记录 Burp 请求 ID，方便操作员在 Burp UI 中定位

## 代理配置

IP 轮换协议参见 `ip-rotate` skill。**IP 切换不自动触发，仅当操作员明确要求时执行。**

初始化（仅设环境变量，不切节点）：
```powershell
. .\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv
```

操作员说"换 IP"/"切节点"时才执行：
```powershell
Switch-ClashProxy -Region HK
```

## 模式 1: 漏洞复核

触发：`Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")`

### Step 1 — 加载待复核

```sql
SELECT * FROM suspicious_points WHERE test_status='untested' ORDER BY risk DESC;
```

若 args 含 `目标: SP-001,SP-002` 则只加载指定 ID；否则加载所有 untested。

### Step 2 — 逐条 PoC 验证

**代理前置**：确认 `Enable-ClashProxyEnv` 已执行即可，不自动切换节点。

每条验证流程：

1. 读 page 上下文：`SELECT * FROM pages WHERE url='{page_url}'`
2. 构造最小 PoC（不破坏数据）
3. 通过 Burp 发送请求
4. 对比基线：有参 vs 无参响应（状态码、长度、内容差异）
5. 判断结果

### Step 3 — 结果分类

| 判断                     | 操作                                                                                         |
| ------------------------ | -------------------------------------------------------------------------------------------- |
| 确认存在漏洞             | `UPDATE suspicious_points SET test_status='confirmed' WHERE id='SP-{n}'`                    |
| 误报                     | `UPDATE suspicious_points SET test_status='false_positive', notes='{原因}' WHERE id='SP-{n}'` |
| 不确定                   | `UPDATE suspicious_points SET test_status='false_positive', notes='需操作员确认: {原因}'`    |
| 高危（RCE/写shell/上传） | 暂停，升级操作员                                                                             |

### Step 4 — 记录确认的漏洞

```sql
INSERT INTO findings (id, sp_id, target_id, type, url, param, method, payload, evidence, risk, cvss, remediation, confirmed_at, burp_request_id)
VALUES (
  'F-{n}',
  'SP-{n}',
  (SELECT id FROM targets WHERE target_name='{target_name}'),
  '{type}',
  '{url}',
  '{param}',
  '{method}',
  '{payload}',
  '{evidence}',
  '{risk}',
  '{cvss}',
  '{remediation}',
  datetime('now', 'localtime'),
  {burp_request_id}
);
```

### Step 5 — 输出复核摘要

```
=== 漏洞复核结果 ===
复核可疑点: {n} 个
├─ 确认: {n} 个
│  ├─ F-004 路径遍历 (High)  /api/export?file=
│  └─ F-005 IDOR (High)      /api/user/update?uid=
├─ 误报: {n} 个
└─ 升级操作员: {n} 个（高危）
```

## 模式 2: 报告生成

触发：`Skill(skill="vuln-review", args="模式: 报告; 目标: 台州学院")`

输出：
```
请使用 src-report skill 生成报告：
Skill(skill="src-report", args="平台: edu; 目标: 台州学院")
```

## 协作约定

- 发现高危（RCE / SQL 写 shell / 任意文件上传）→ 暂停，升级操作员
- 无法判断 → 标记 `需操作员确认: {原因}`，继续下一条
- 复核完成 → 输出摘要，询问操作员下一步（生成报告 / 继续扫描）