---
name: asset-recon
description: 资产梳理 skill。使用 FOFA/ZoomEye 进行被动侦察，初始化目标 DB，写入 targets 表，自动入队待扫描资产。
allowed-tools: mcp__burp__*, Bash, PowerShell, Read, Write, Edit, Skill, Glob
---

# asset-recon

被动侦察 skill。使用 FOFA 和 ZoomEye 进行资产发现，初始化目标数据库，写入 `targets` 表并将发现的资产自动入爬虫队列。

**触发方式**: `Skill(skill="asset-recon", args="目标: 台州学院")`

**协作约定**:
- asset-recon 只负责被动侦察，不主动扫描目标服务器
- 所有发现的资产自动入 `pages` 表，stealth-scanner 接力扫描
- 操作员可在任意时刻中断，后续调用 asset-recon 可继续（自动找最新 DB）

---

## 环境常量

```
DBS_DIR: E:\SRC挖掘\SRC\dbs
FOFA query:   TOOLS/fofa_query.py
ZoomEye query: TOOLS/zoomeye_query.py
DB query:    TOOLS/db_query.py
```

---

## 入口流程

```
操作员调用: Skill(skill="asset-recon", args="目标: 台州学院")
```

### Step 1 — 解析目标名称

从 `args` 提取 `目标: {name}` 格式。

```
Skill(skill="asset-recon", args="目标: 台州学院")
```

如果没有提供 `目标:` 前缀，输出提示要求操作员提供：
```
[asset-recon] 未提供目标名。请使用以下格式调用：
Skill(skill="asset-recon", args="目标: 目标名称")
```

### Step 2 — 前置检查

并行检查三个依赖组件是否可用：

```bash
# 检查 FOFA key
python3 TOOLS/fofa_query.py --help 2>&1 | head -5

# 检查 ZoomEye key
python3 TOOLS/zoomeye_query.py --help 2>&1 | head -5

# 检查 DB
python3 TOOLS/db_query.py --check
```

将检查结果告知操作员。如 FOFA/ZoomEye key 未配置，记录 warning 并继续（部分可用也继续）。

### Step 3 — 初始化目标 DB

```bash
python3 TOOLS/db_query.py --target "{目标名}" --init
```

输出示例：
```
[asset-recon] 初始化目标 DB: 台州学院_2026-05-26.db
```

这会：
1. 创建 `dbs/{目标名}_{日期}.db`
2. 执行 `schema.sql`（所有表：`targets`、`scan_state`、`pages`、`js_files`、`suspicious_points`、`findings`、`auth_*`）
3. 写入一条 `targets` 记录（`target_name={目标名}`, `domain` 留空）

### Step 4 — 确认主域名

询问操作员确认主域名：

```
请确认主域名（如 tzc.edu.cn）：
```

**等待操作员输入**，然后更新 `targets` 表：

```bash
python3 TOOLS/db_query.py --target "{目标名}" "UPDATE targets SET domain='{domain}' WHERE target_name='{target_name}'" --write
```

### Step 5 — 并行 FOFA + ZoomEye 查询

FOFA 和 ZoomEye 查询**并行执行**，互不依赖。

#### FOFA 查询

```bash
python3 TOOLS/fofa_query.py -q 'domain="{主域名}"' --size 100 --json > tmp/fofa_result.json
```

如果 FOFA API key 未配置或查询失败，输出 `[WARN] FOFA 查询失败: {reason}` 并记录结果为 0 条。

#### ZoomEye 查询

```bash
python3 TOOLS/zoomeye_query.py -q 'site:"{主域名}"' --size 100 --json > tmp/zoomeye_result.json
```

如果 ZoomEye API key 未配置或查询失败，输出 `[WARN] ZoomEye 查询失败: {reason}` 并记录结果为 0 条。

### Step 6 — etl_analyzer 解析结果

对 FOFA 和 ZoomEye 的原始 JSON 输出，调用 etl_analyzer 解析：

```bash
# 合并两个结果文件，提取所有资产
uv run python TOOLS/utils/etl_analyzer.py --task filter_burp --instruction "从以下侦察结果中提取所有资产，输出纯 JSON 数组，每个元素包含：
{\"domain\": \"子域名或IP\", \"ip\": \"IP\", \"port\": 80/443, \"tech_stack\": \"Apache/Vue/Spring等\", \"requires_auth\": true/false, \"notes\": \"备注\"}
只输出 JSON，不要解释。

=== FOFA 结果 ===
\$(cat tmp/fofa_result.json)

=== ZoomEye 结果 ===
\$(cat tmp/zoomeye_result.json)"
```

MiniMax 返回格式示例：
```json
{
  "assets": [
    {"domain": "www.tzc.edu.cn", "ip": "1.2.3.4", "port": 443, "tech_stack": "nginx,PHP", "requires_auth": false, "notes": ""},
    {"domain": "mail.tzc.edu.cn", "ip": "1.2.3.5", "port": 443, "tech_stack": " Exchange", "requires_auth": true, "notes": "需要登录"}
  ]
}
```

### Step 7 — 去重 + 写入 `pages` 表（入队）

解析出 assets JSON 后，对每个 asset：

```bash
# 入队每个资产（depth=0, status=queued）
python3 TOOLS/db_query.py --target "{目标名}" \
  "INSERT INTO pages (url, depth, status, title) VALUES (?, 0, 'queued', ?)" \
  --write --params '["{url}", "{tech_stack}"]'
```

URL 格式：`https://{domain}:{port}` 或 `https://{domain}`（port 为 80/443 时省略）

### Step 8 — 更新 `targets` 表

从所有资产汇总 technology stack 和 requires_auth 标志：

```bash
# 汇总 tech_stack 和 requires_auth 数量
python3 TOOLS/db_query.py --target "{目标名}" \
  "UPDATE targets SET tech_stack='{tech_stacks}', requires_auth={requires_auth_int} WHERE target_name='{target_name}'" \
  --write
```

### Step 9 — 写入 `scan_state`

```bash
python3 TOOLS/db_query.py --target "{目标名}" \
  "INSERT INTO scan_state (id, target_id, seed_url, phase, started_at) VALUES (1, {target_id}, '{main_domain}', 'init', datetime('now','localtime'))" \
  --write
```

### Step 10 — 输出摘要

```
=== 资产梳理完成 ===
目标: {target_name}
主域名: {domain}
FOFA 结果: N 条
ZoomEye 结果: M 条
去重后资产: K 个
├─ 无需登录: J 个（已入爬虫队列）
└─ 需要登录: L 个（auth_status=pending）
技术栈: {tech_stack}
DB: dbs/{target_name}_{date}.db

下一步：
1. 操作员确认主域名后，输入：Skill(skill="stealth-scanner")
2. 或直接开始扫描：Skill(skill="stealth-scanner", args="目标: {target_name}")
```

---

## 异常处理

| 情况 | 处理方式 |
|------|----------|
| 未提供目标名 | 提示操作员提供，终止执行 |
| FOFA key 未配置 | warning 记录，FOFA 结果为 0，继续 ZoomEye |
| ZoomEye key 未配置 | warning 记录，ZoomEye 结果为 0，继续 |
| 两个都失败 | 输出 error，终止执行 |
| 操作员无响应 | 等待操作员输入（Step 4），超时不回滚已完成步骤 |
| DB 已存在 | 检测到同名 DB 存在时询问是否覆盖或追加 |

---

## ETL 分析路由规则

遵循 `mmx-router` skill 规范：
- FOFA/ZoomEye 结果文件 >10 行 → `etl_analyzer.py --task filter_burp` 解析
- Claude 不读原始 JSON，只处理 etl_analyzer 返回的精简 assets 数组
- 解析失败时回退到手动 JSON 解析（逐条读取 sample 字段）

---

## 协作约定

- **被动侦察铁律**：asset-recon 只查询 FOFA/ZoomEye，不向目标服务器发任何请求
- **后续接力**：所有资产写入 `pages` 表后，stealth-scanner 自动接力扫描
- **断点续命**：操作员中断后重新调用 asset-recon，自动找到最新 DB 文件继续
- **auth 标记**：`requires_auth=1` 的资产写入 `targets.requires_auth`，供 stealth-scanner 决定是否需要登录流程