# SRC 漏洞挖掘系统重构实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 重构 SRC 漏洞挖掘系统的 skill 体系：新增资产梳理 skill、按目标分类 DB、明确 scanner/vuln-review 边界、多平台报告格式支持、全局 10 轮记忆总结。

**Architecture:**
- 新增 `asset-recon` skill：FOFA/ZoomEye 被动侦察，初始化目标 DB，写入 `targets` 表
- `stealth-scanner` 接管 Phase 3 攻击面探测（API 方法探测、参数 fuzz、JS 深度分析），内置每 10 轮对话向 memory 系统追加总结
- `vuln-review` 只做 PoC 验证，去掉攻击面扩大逻辑
- `src-report` 支持 edu/补天/CNVD 三套字段模板，去掉 URL 的 backtick 包裹
- 所有数据按目标分库：`dbs/{target}_{date}.db`

**Tech Stack:** Python, SQLite (WAL + busy_timeout), Scrapling, Burp MCP, MiniMax MCP, Claude memory system

---

## 任务总览

| # | 任务 | 产出文件 |
|---|------|---------|
| 1 | 写设计规格文档 | `docs/superpowers/specs/2026-05-26-src-redesign-design.md` |
| 2 | 创建 `dbs/` 目录 + 更新 `db_query.py` 支持多 DB | `dbs/`, `TOOLS/db_query.py` |
| 3 | 数据库 schema 变更：新增 `targets` 表、`findings.target_id` | SQL migration + schema docs |
| 4 | 新建 `asset-recon` skill | `.claude/skills/asset-recon/SKILL.md` |
| 5 | 重构 `stealth-scanner`：接管 Phase 3 + 10 轮记忆总结 | `.claude/skills/stealth-scanner/SKILL.md` |
| 6 | 重构 `vuln-review`：只做 PoC 验证 | `.claude/skills/vuln-review/SKILL.md` |
| 7 | 重构 `src-report`：三平台格式 + 去掉 backtick | `.claude/skills/src-report/SKILL.md` |
| 8 | 更新 `CLAUDE.md`：反映新架构 | `CLAUDE.md` |
| 9 | 迁移脚本：将旧 scanner.db 数据迁移到新结构（可选） | `TOOLS/migrate_old_db.py` |

---

## Task 1: 写设计规格文档

**Files:**
- Create: `docs/superpowers/specs/2026-05-26-src-redesign-design.md`

- [ ] **Step 1: 创建 docs/superpowers/specs/ 目录**

```bash
mkdir -p "e:/SRC挖掘/SRC/docs/superpowers/specs"
```

- [ ] **Step 2: 写入设计规格文档**

文档包含：
1. 背景与目标（8 个痛点 → 解决方案映射）
2. 架构图（ASCII）
3. 各 skill 职责边界
4. 数据库 schema 变更（新增 targets 表、findings.target_id）
5. 报告格式对比表（edu / 补天 / CNVD 三平台字段）
6. 目录结构（dbs/ 目录）
7. memory 总结机制说明

---

## Task 2: 创建 `dbs/` 目录 + 更新 `db_query.py` 支持多 DB

**Files:**
- Create: `dbs/` 目录（空文件夹，`.gitkeep`）
- Modify: `TOOLS/db_query.py`（支持 `--target` 参数指定目标 DB）

- [ ] **Step 1: 创建目录**

```bash
mkdir -p "e:/SRC挖掘/SRC/dbs"
touch "e:/SRC挖掘/SRC/dbs/.gitkeep"
```

- [ ] **Step 2: 修改 `TOOLS/db_query.py`**

**变更点：**

1. 默认 DB 路径改为 `dbs/{target}_{date}.db`（从环境变量或命令行参数获取）
2. 新增 `--target` 参数，指定目标名
3. 新增 `--init` 参数，初始化新目标 DB（创建所有表）
4. `DEFAULT_DB` 环境变量：`DBS_DIR` = `E:\SRC挖掘\SRC\dbs`

**新的 `db_query.py` 用法：**

```bash
# 针对特定目标查询（自动找最新的目标 DB）
python3 TOOLS/db_query.py --target "台州学院" "SELECT * FROM findings"

# 初始化新目标 DB（资产梳理阶段调用）
python3 TOOLS/db_query.py --target "台州学院" --init

# 指定具体 DB 文件
python3 TOOLS/db_query.py --file "dbs/台州学院_2026-05-26.db" "SELECT * FROM pages"
```

**新增 `--init` 逻辑：**

```python
def init_db(conn):
    """初始化新的目标 DB：创建所有表"""
    tables = [
        SCAN_STATE_SCHEMA,
        PAGES_SCHEMA,
        JS_FILES_SCHEMA,
        SUSPICIOUS_POINTS_SCHEMA,
        FINDINGS_SCHEMA,  # 含 target_id
        TARGETS_SCHEMA,   # 新增
        AUTH_CREDENTIALS_SCHEMA,
        AUTH_FLOW_STEPS_SCHEMA,
        AUTH_SESSIONS_SCHEMA,
    ]
    for schema in tables:
        conn.executescript(schema)
    conn.commit()
```

完整 schema 见 Task 3。

---

## Task 3: 数据库 schema 变更

**Files:**
- Create: `TOOLS/schema.sql`（统一的 schema 定义，供 db_query.py --init 使用）
- Modify: `TOOLS/db_query.py`（新增 --init 和 --target 参数）

- [ ] **Step 1: 创建 `TOOLS/schema.sql`**

```sql
-- targets 表（新增）
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    domain TEXT,
    ip TEXT,
    tech_stack TEXT,
    requires_auth INTEGER DEFAULT 0,
    auth_status TEXT DEFAULT 'not_logged_in',
    discovered_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);

-- scan_state 表（现有，新增 target_id 外键）
CREATE TABLE IF NOT EXISTS scan_state (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    seed_url TEXT,
    phase TEXT DEFAULT 'init',
    started_at TEXT,
    spider_ended_at TEXT,
    reviewed_at TEXT,
    max_depth INTEGER DEFAULT 3,
    max_pages INTEGER DEFAULT 200,
    total_pages INTEGER DEFAULT 0,
    total_js INTEGER DEFAULT 0,
    total_apis INTEGER DEFAULT 0,
    total_forms INTEGER DEFAULT 0,
    total_suspicious INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0
);

-- pages 表（现有）
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    depth INTEGER DEFAULT 0,
    status TEXT DEFAULT 'queued',
    title TEXT,
    links_found INTEGER DEFAULT 0,
    forms_json TEXT,
    js_files_json TEXT,
    api_calls_json TEXT,
    suspicious_params_json TEXT,
    crawled_at TEXT
);

-- js_files 表（现有）
CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    page_url TEXT,
    analyzed INTEGER DEFAULT 0,
    discovered_apis_json TEXT,
    hardcoded_secrets_json TEXT,
    internal_routes_json TEXT,
    debug_switches_json TEXT,
    analyzed_at TEXT
);

-- suspicious_points 表（现有）
CREATE TABLE IF NOT EXISTS suspicious_points (
    id TEXT PRIMARY KEY,
    page_url TEXT,
    url TEXT,
    param TEXT,
    method TEXT DEFAULT 'GET',
    test_type TEXT,
    evidence TEXT,
    source TEXT,
    reasoning TEXT,
    risk TEXT DEFAULT 'Medium',
    test_status TEXT DEFAULT 'untested',
    burp_request_id INTEGER,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    notes TEXT
);

-- findings 表（现有，新增 target_id）
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    sp_id TEXT,
    target_id INTEGER REFERENCES targets(id),
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

-- auth 表（现有，不变）
CREATE TABLE IF NOT EXISTS auth_credentials (...);
CREATE TABLE IF NOT EXISTS auth_flow_steps (...);
CREATE TABLE IF NOT EXISTS auth_sessions (...);
```

- [ ] **Step 2: 更新 `TOOLS/db_query.py`**

新增：
- `init_db()` 函数读取 `schema.sql`
- `--target` 参数：从 `dbs/{target}_{date}.db` 查找最新 DB（glob 匹配）
- `--init` 参数：初始化 DB 后立即写入一条 `targets` 记录

---

## Task 4: 新建 `asset-recon` skill

**Files:**
- Create: `.claude/skills/asset-recon/SKILL.md`
- Modify: `CLAUDE.md`（技能表中加入 asset-recon）

- [ ] **Step 1: 创建 `.claude/skills/asset-recon/SKILL.md`**

**skill 名称**: `asset-recon`
**触发方式**: `Skill(skill="asset-recon", args="目标: 台州学院")`

**职责：**

1. **初始化目标 DB**
   - 操作员输入目标名称（如"台州学院"）
   - 解析主域名（手动确认或自动提取）
   - 调用 `db_query.py --init --target "{目标名}"` 初始化 DB
   - 写入 `targets` 表（target_name, domain）

2. **FOFA/ZoomEye 被动侦察**
   - 调用 `TOOLS/fofa_query.py` 和 `TOOLS/zoomeye_query.py`
   - 对同一目标并行查询，汇总结果
   - 结果写入 `targets` 表（domain, ip, tech_stack, requires_auth）
   - 所有资产自动进入扫描队列（写入 `pages` 表，depth=0）

3. **技术栈识别**
   - 从 FOFA 指纹字段提取：Web Server, Framework, Language, CMS 等
   - 写入 `targets.tech_stack`

4. **不需要登录的资产** → 直接 `status='queued'`
5. **需要登录的资产** → `requires_auth=1, auth_status='not_logged_in'`，在 scanner Phase 1 登录流程中处理

**关键 prompt 模板（FOFA 结果解析）：**

```
解析以下 FOFA/ZoomEye 查询结果，提取：
1. 所有子域名和 IP
2. 技术栈（Web Server, Framework, Language, CMS）
3. 是否可能需要登录（后台域名特征）

原始结果：
{FOFA/ZoomEye JSON 输出}

输出 JSON：
{
  "assets": [
    {"domain": "...", "ip": "...", "port": 80/443, "tech_stack": "...", "requires_auth": true/false}
  ]
}
```

**MiniMax 路由**（遵循 mmx-router skill）：
- FOFA/ZoomEye 查询结果（>10 行）→ `mmx text chat` 解析
- Claude 只读精简的 assets JSON

**调用行为**：
- 每次调用完成一个目标的 FOFA+ZoomEye 查询 + 写入 DB
- 操作员可并行对多个目标调用

**前置检查：**
- `TOOLS/fofa_query.py` 可用（需要 Fofa API key）
- `TOOLS/zoomeye_query.py` 可用（需要 ZoomEye API key）
- `db_query.py --check` 通过

**输出摘要：**

```
=== 资产梳理完成 ===
目标: 台州学院
主域名: tzc.edu.cn
发现资产: N 个
├─ 无需登录: M 个（已入爬虫队列）
└─ 需要登录: K 个（auth_status=pending）
技术栈: Apache + Vue2 + Spring Boot
DB: dbs/台州学院_2026-05-26.db
```

---

## Task 5: 重构 `stealth-scanner` skill

**Files:**
- Modify: `.claude/skills/stealth-scanner/SKILL.md`

**主要变更：**

1. **接管 Phase 3 攻击面探测**（从 vuln-review 移入）
   - API 方法探测（POST/PUT/DELETE/PATCH/OPTIONS）
   - 参数 fuzz（常见参数名注入）
   - 表单交互探测
   - 认证/注册流探测（验证码复用、用户枚举、注册开放等）

2. **去掉 auth 录制逻辑**（Phase 1.2-1.3）
   - 登录流程由操作员手动完成，凭证由 asset-recon 阶段写入 `auth_credentials` 表
   - scanner 只读 `auth_sessions`，失效时提示操作员重新登录

3. **10 轮对话记忆总结**
   - 内置计数器（DB 的 `scan_state` 表或内存变量）
   - 每 10 轮对话（每次 Skill 调用计 1 轮），自动调用 memory 系统
   - 总结内容：当前进度（phase、pages 数量、可疑点数量、发现）、遇到的问题、下一步计划
   - 写入 `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\{target_name}_progress.md`
   - 格式：

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
- Phase: {phase}
- 页面: {n} visited / {total}
- JS: {n} analyzed
- 可疑点: {n} (untested: {n})
- 确认漏洞: {n}

## 关键发现
- {bullet points}

## 待处理
- {bullet points}

## 下一步
- {next steps}
```

4. **DB 路径**：从 `dbs/{target}_{date}.db` 读取（通过 `db_query.py --target`）
5. **Phase 1 登录流程简化**：不再录制流程，只读 `auth_sessions` 尝试使用已有凭证

---

## Task 6: 重构 `vuln-review` skill

**Files:**
- Modify: `.claude/skills/vuln-review/SKILL.md`

**主要变更：**

1. **只做 PoC 验证**，去掉"攻击面扩大"逻辑（Phase 3 相关全部移入 scanner）
2. **去掉"模式 1: 可疑点发现"** —— 这部分归 scanner
3. **保留"模式 2: 漏洞复核"** —— PoC 验证，写入 findings
4. **保留"模式 3: 报告生成"** —— 调用 src-report
5. **DB 路径同 stealth-scanner**，通过 `db_query.py --target` 指定
6. **读取 `targets` 表**获取当前目标上下文（操作员输入或从 scan_state 推断）

**两种模式：**

```
Skill(skill="vuln-review", args="模式: 复核")
Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")
Skill(skill="vuln-review", args="模式: 报告")
```

---

## Task 7: 重构 `src-report` skill

**Files:**
- Modify: `.claude/skills/src-report/SKILL.md`

**主要变更：**

1. **支持三种平台格式**（管理员调用时指定）

```
Skill(skill="src-report", args="平台: edu; 目标: 台州学院")
Skill(skill="src-report", args="平台: 补天; 目标: 台州学院")
Skill(skill="src-report", args="平台: CNVD; 目标: 台州学院")
```

2. **三套字段模板：**

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

3. **去掉所有 URL 的 backtick 包裹** —— 直接写裸 URL

4. **报告文件命名**：`reports/{平台}_提交_{target_name}_{日期}.md`

5. **`--target` 参数**：从 `dbs/{target}_{date}.db` 读取 findings，写入对应 targets 表的 target_name

6. **`findings.target_id` 关联**：读 findings 时 JOIN targets 表，确保报告标题包含目标名

---

## Task 8: 更新 `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

**变更点：**

1. **技能表**加入 `asset-recon`
2. **目录规范**，`dbs/` 目录说明（替代旧的 scanner.db 路径）
3. **工作流程**：资产梳理（asset-recon）→ 扫描（stealth-scanner）→ 复核（vuln-review）→ 报告（src-report）
4. **DB 操作**：`db_query.py --target` 用法
5. **Burp 凭证管理**：登录凭证由 asset-recon 阶段写入 Burp，所有 session 共用 Burp 代理
6. **每 10 轮总结机制**：memory 系统自动积累

---

## Task 9: 迁移脚本（可选）

**Files:**
- Create: `TOOLS/migrate_old_db.py`

**用途：** 将旧的 `scanner.db` 数据迁移到新结构（如果有需要保留的历史数据）

**逻辑：**
1. 读取旧 DB 的所有表
2. 根据 `seed_url` 推断 target_name（如从域名提取"台州学院"）
3. 创建新 DB（`dbs/{target_name}_{date}.db`）
4. 写入 `targets` 表
5. 迁移其余表数据，设置 `target_id`

此任务为可选，如果操作员没有历史数据需要保留可跳过。

---

## 执行顺序

1. Task 1（设计规格）→ Task 2（db_query）→ Task 3（schema）→ Task 4（asset-recon）→ Task 5（stealth-scanner）→ Task 6（vuln-review）→ Task 7（src-report）→ Task 8（CLAUDE.md）

Task 9 独立，可选。

---

## 自检清单

- [ ] 所有 skill 文件路径正确（`.claude/skills/{name}/SKILL.md`）
- [ ] `db_query.py --target --init` 能成功创建含所有表的 DB
- [ ] `asset-recon` skill 能写入 `targets` 表并触发 stealth-scanner 入队
- [ ] `stealth-scanner` Phase 3（攻击面探测）逻辑完整
- [ ] `vuln-review` 不再包含 Phase 3 逻辑
- [ ] `src-report` 三个平台格式正确，URL 无 backtick
- [ ] `CLAUDE.md` 反映新架构
- [ ] 无 placeholder / TODO 残留
