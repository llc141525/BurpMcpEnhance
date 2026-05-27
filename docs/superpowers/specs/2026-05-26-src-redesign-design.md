# SRC 漏洞挖掘系统重构设计规格

> 日期: 2026-05-26
> 目标: 解决 8 个痛点，重构 skill 体系

---

## 1. 背景与痛点-解决方案映射

| # | 痛点 | 解决方案 |
|---|------|----------|
| 1 | 报告 md 格式不对，URL 带 ` ` | src-report 去掉所有 URL 的 backtick 包裹 |
| 2 | 缺被动扫描，攻击面太小 | 新增 `asset-recon` skill（FOFA/ZoomEye 被动侦察） |
| 3 | 三个 session 不交换信息，报告漏细节 | targets 表 + target_name 归属；报告用目标名命名 |
| 4 | 缺每 10 轮总结归纳 | stealth-scanner 内置 10 轮 memory 总结，全项目生效 |
| 5 | stealth-scanner 和 vuln-review 边界模糊 | scanner 接管 Phase 3 攻击面探测；vuln-review 只做 PoC 验证 |
| 6 | 缺资产梳理 skill | 新 skill：FOFA/ZoomEye 被动侦察 + targets 表写入 + 初始化目标 DB |
| 7 | DB 不按目标分类，更换目标后数据丢失 | `dbs/{target}_{date}.db`，资产梳理阶段初始化 |
| 8 | 报告命名是子站点而非目标 | findings.target_id → targets.target_name，报告文件名前缀用目标名 |

---

## 2. 架构总览

```
操作员（决策）
     │
     ▼
┌─────────────────────┐
│   asset-recon       │  ← 新 skill：FOFA/ZoomEye 被动侦察
│  (资产梳理阶段)      │     初始化目标 DB
└──────────┬──────────┘     写入 targets 表
           │                 自动 BFS 入队
           ▼
┌─────────────────────┐
│   stealth-scanner   │  ← 重构：接管 Phase 3 攻击面探测
│   (Session A)       │     BFS + 指纹 + API探测 + 参数fuzz
└──────────┬──────────┘     内置每10轮 memory 总结
           │                 写 pages/js_files/suspicious_points
           ▼
┌─────────────────────┐
│   vuln-review       │  ← 重构：只做 PoC 验证
│   (Session B)       │     读 suspicious_points
└──────────┬──────────┘     写 findings
           │
           ▼
┌─────────────────────┐
│   src-report        │  ← 重构：支持 edu/补天/CNVD 三格式
│   (按需调用)         │     去掉 URL 的 ` ` 包裹
└─────────────────────┘
```

---

## 3. 目录结构

```
e:\SRC挖掘\SRC\
├── CLAUDE.md                    # 项目说明（更新）
├── db_query.py                  # 更新：--target/--init 支持
├── schema.sql                   # 新增：统一 DB schema
├── dbs/                         # 新增：按目标分库的目录
│   ├── 台州学院_2026-05-26.db
│   └── 临海市_2026-05-25.db
├── .claude/skills/
│   ├── asset-recon/             # 新增
│   │   └── SKILL.md
│   ├── stealth-scanner/         # 重构
│   │   └── SKILL.md
│   ├── vuln-review/             # 重构
│   │   └── SKILL.md
│   └── src-report/              # 重构
│       └── SKILL.md
├── TOOLS/
│   ├── fofa_query.py
│   ├── zoomeye_query.py
│   ├── scrapling_fetch.py
│   ├── db_query.py              # 更新
│   └── ...
└── reports/                     # 报告输出目录
    ├── edu提交_台州学院_2026-05-26.md
    ├── 补天提交_台州学院_2026-05-26.md
    └── CNVD提交_台州学院_2026-05-26.md
```

---

## 4. 数据库 schema

### 4.1 新增 `targets` 表

```sql
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,          -- 操作员输入的目标名，如"台州学院"
    domain TEXT,                         -- 主域名
    ip TEXT,                             -- IP 地址
    tech_stack TEXT,                     -- 技术栈描述（多个用逗号分隔）
    requires_auth INTEGER DEFAULT 0,    -- 是否有资产需要登录
    auth_status TEXT DEFAULT 'not_logged_in',  -- not_logged_in / logged_in / failed
    discovered_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);
```

### 4.2 `findings` 表新增 `target_id`

```sql
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    sp_id TEXT,
    target_id INTEGER REFERENCES targets(id),  -- 新增外键
    type TEXT,
    url TEXT,
    param TEXT,
    method TEXT,
    payload TEXT,
    evidence TEXT,
    risk TEXT,
    cvss TEXT,
    remediation TEXT,
    confirmed_at TEXT,
    burp_request_id INTEGER
);
```

### 4.3 `scan_state` 表新增 `target_id`

```sql
CREATE TABLE scan_state (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),  -- 新增外键
    seed_url TEXT,
    phase TEXT DEFAULT 'init',
    ...
);
```

---

## 5. 各 skill 职责边界

### asset-recon（新增）

**触发**: `Skill(skill="asset-recon", args="目标: 台州学院")`

**职责**:
1. 解析目标名称 → 提取主域名（操作员确认）
2. `db_query.py --init --target "{目标名}"` 初始化新 DB
3. 写入 `targets` 表（target_name, domain）
4. 并行调用 FOFA + ZoomEye 查询
5. MiniMax 解析查询结果 → 提取 assets JSON
6. 所有资产写入 `pages` 表（depth=0, status='queued'）
7. 识别 `requires_auth` → 写入 `targets.requires_auth`

**不做什么**:
- 不主动扫描目标服务器（只查搜索引擎）
- 不做登录流程

---

### stealth-scanner（重构）

**触发**: `Skill(skill="stealth-scanner")`

**职责**:
1. `db_query.py --target "{目标名}"` 找到最新 DB
2. BFS 爬取（Phase 2）：抓页面 → 框架指纹 → 子链接入队 → JS 收割
3. 攻击面探测（接管原 Phase 3）：API 方法探测、参数 fuzz、表单交互、认证流探测
4. 写 `suspicious_points`（test_status='untested'）
5. **每 10 轮调用 memory 系统**，写入 `memory/{target_name}_progress.md`

**登录处理**（简化）:
- 只读 `auth_sessions`，失效时提示操作员重新在 Burp 中完成登录
- 不再录制 auth_flow_steps

**Phase 流转**: `init` → `spider` ↔ `probe` → `brute` → `spider`

---

### vuln-review（重构）

**触发**:
```
Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")
Skill(skill="vuln-review", args="模式: 报告")
```

**职责**:
1. PoC 验证（模式: 复核）：逐条读 `suspicious_points` → 构造 payload → Burp 发送 → 判定 confirmed/false_positive → 写入 `findings`
2. 报告生成（模式: 报告）：调用 src-report skill

**不做什么**:
- 不做攻击面扩大（归 scanner）
- 不做可疑点发现（归 scanner）

---

### src-report（重构）

**触发**:
```
Skill(skill="src-report", args="平台: edu; 目标: 台州学院")
Skill(skill="src-report", args="平台: 补天; 目标: 台州学院")
Skill(skill="src-report", args="平台: CNVD; 目标: 台州学院")
```

**三套字段模板**:

**edu 格式：**
```
标题: [{target_name}] {漏洞标题}
分类: {漏洞类型}
漏洞等级: {High/Medium/Low}
漏洞单位: {target_name}
开发方: {开发方或留空}
漏洞url: {完整URL}
内容: {完整漏洞描述 + PoC + 修复建议}
```

**补天格式：**
```
漏洞标题: {漏洞标题}
漏洞类别: {漏洞类型}
漏洞URL: {完整URL}
漏洞类型: {漏洞类型}
漏洞等级: {High/Medium/Low}
简要描述: {一句话危害}
详细细节: {完整描述 + 利用链 + PoC}
修复方案: {具体修复建议}
```

**CNVD 格式：**
```
涉事单位: {目标单位名}
所属IP: {服务器IP}
所在省份: {省份}
所在城市: {城市}
影响对象类型: {Web应用/移动App/...}
漏洞名称: {漏洞标题}
漏洞类型: {漏洞类型}
漏洞url: {完整URL}
漏洞描述: {完整描述 + PoC}
临时解决方案: {临时缓解措施}
```

**格式规则**:
- 所有 URL 不加 backtick
- 报告文件：`reports/{平台}_提交_{target_name}_{日期}.md`

---

## 6. Burp 凭证管理

所有登录凭证统一由操作员管理：
- 操作员手动登录目标站 → 凭证写入 `auth_credentials` 表
- 所有 session 共用 Burp 代理，操作员的登录状态对所有 session 可见
- scanner/vuln-review 失效时提示操作员重新登录

---

## 7. 10 轮记忆总结机制

在 `stealth-scanner` skill 中内置计数器：

```python
# 伪代码（嵌入 scanner skill 的状态机）
call_count = db_query("SELECT call_count FROM scan_state WHERE id=1")['call_count']
call_count += 1

if call_count % 10 == 0:
    write_memory_summary(target_name, scan_state)

db_query("UPDATE scan_state SET call_count=? WHERE id=1", [call_count])
```

**写入位置**: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\{target_name}_progress.md`

**总结格式**:
```markdown
---
name: {target_name}-progress
description: {目标} 扫描进度记忆（自动每10轮更新）
metadata:
  type: project
  target: {target_name}
  last_updated: {datetime}
---

# {目标} 扫描进度 — {datetime}

## 当前状态
- Phase: spider
- 页面: 45 visited / 200 max
- JS: 12 analyzed
- 可疑点: 23 (untested: 18)
- 确认漏洞: 5

## 关键发现
- F-001: 后台 API 越权访问（Critical）
- 多个 /skl/teacher/* 接口未授权

## 待处理
- SP-015: /api/export?file= 参数 fuzz
- SP-018: JWT 密钥硬编码在 JS 中

## 下一步
- 完成 /skl/teacher/* 接口的 PoC 验证
- 继续 BFS 爬取 /admin/* 路径
```

---

## 8. DB 按目标分类

**初始化时机**: `asset-recon` skill 调用时

**DB 路径**: `dbs/{target_name}_{date}.db`

**命名规则**:
- 目标名：中文/英文均可，去掉特殊字符
- 日期：`YYYY-MM-DD` 格式

**查找逻辑**:
1. `glob("dbs/{target_name}_*.db")`
2. 按文件名排序，取最新

**db_query.py 用法**:
```bash
# 自动找最新 DB
python3 TOOLS/db_query.py --target "台州学院" "SELECT * FROM findings"

# 指定日期
python3 TOOLS/db_query.py --file "dbs/台州学院_2026-05-26.db" "SELECT * FROM pages"

# 初始化新 DB
python3 TOOLS/db_query.py --target "台州学院" --init
```
