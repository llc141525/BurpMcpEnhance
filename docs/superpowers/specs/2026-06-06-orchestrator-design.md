# 编排层 + JS 分析管道 + TOOLS 重组 设计文档

**日期**: 2026-06-06  
**状态**: 待实现

---

## 背景与问题

### 核心问题：编排层缺失

`SKILL.md` 当前是用自然语言写的伪编排脚本。每次新 session 启动，Claude 必须：
1. 重读整个 SKILL.md
2. 查询 `scan_state` 表理解当前 phase
3. 对照 `memory/*.md` 文件核实进度
4. 手动决定调用哪个脚本、传什么参数
5. 读原始工具输出，手动判断下一步

这导致三个连锁问题：
- **上下文污染**：Claude 的 context window 被项目管理噪音填满，安全判断空间被压缩
- **状态双源头**：`scan_state` 表与 `memory/*.md` 文件各自存一份进度，容易漂移
- **工具链碎片化**：26 个脚本平铺在 TOOLS/，接口不统一，集成 bug 反复出现

### 副问题：JS 分析管道缺失

以台州学院为例：crawl 发现 191 个 JS 文件，`analyzed=0`。大量硬编码密钥、内部 API、认证逻辑藏在 JS 里，但没有自动化管道处理，端点线索全靠手动。

---

## 设计目标

1. **单命令启动**：`python TOOLS/run_scan.py --target X` 替代手动多步骤调度
2. **结构化输出**：Claude 只读摘要标签，不读原始工具输出
3. **DB 单一真相**：`scan_state` 是唯一状态源，`memory/*.md` 变为可选人工摘要
4. **JS 自动分析**：spider 阶段顺带处理 JS，发现的 API/密钥自动写入 `suspicious_points`
5. **TOOLS 目录清晰**：按职责分层，删除死代码，统一接口约定

---

## 不在本次范围

- 认证后攻击面自动化（browser_auth 单独维护）
- business-logic-hunt / manual-replay 集成进主流程
- 多目标并行扫描

---

## 新增文件

### `TOOLS/run_scan.py` — 主编排入口

**职责**：读 `scan_state.phase` → 执行对应 phase handler → 打印结构化摘要 → 退出。

**调用方式**：
```bash
python TOOLS/run_scan.py --target "台州学院"
python TOOLS/run_scan.py --target "台州学院" --once   # 只跑一个批次
```

**Phase 状态机**：

```
init ──→ spider ──→ probe ──→ brute
  │         ↑          │
  │         └──────────┘ (probe 完成后回 spider)
  │
  └→ auth_pending (遇到登录墙，停下等操作员)
```

| Phase | 触发脚本 | 转换条件 |
|-------|---------|---------|
| `init` | `pipeline/init_scan.py` | 成功 → `spider`；遇认证壁垒 → `auth_pending` |
| `spider` | `pipeline/bfs_crawl.py` + `js_analyzer.py` | queue 空 → `probe` |
| `probe` | `pipeline/probe_runner.py --batch 20` | 有新 SP → 打印后停止；无更多 → `brute` |
| `brute` | `pipeline/brutescan.py` | 完成 → `spider` |
| `auth_pending` | 无（重复打印 AUTH_BARRIER 后退出） | 操作员写入 `auth_sessions` 后手动更新 phase → `spider` |

**结构化输出标签**：

```
[INIT_DONE]
  存活资产: 12    需认证: 2    技术栈: Spring Boot, Shiro

[AUTH_BARRIER]
  登录页: https://example.com/login
  操作: 请通过 Burp 手动登录，然后运行 db_query.py 写入 auth_sessions

[SPIDER_BATCH]
  新增页面: +47    JS 文件: +12    队列剩余: 203
  JS 分析 (5/191):
    ✓ api-config.js  → 3 端点, 1 hardcoded key (ACCESS_KEY)
    ✓ router.js      → 7 内部路由
    ✗ vendor.js      → 跳过（低优先级）
  新增 SP: 4 条 (source=js_analysis)
  建议: 发现 ACCESS_KEY，优先 vuln-review

[NEW_SUSPICIOUS_POINTS]
  SP-PR-021  POST /api/user/update  param=userId  arjun  Medium
  SP-PR-022  GET /api/order/detail  param=orderId  方法探测  High
  建议: SP-PR-022 风险较高，发送 vuln-review

[PHASE_TRANSITION]
  spider → probe    队列耗尽，共爬取 309 页
```

**Claude 新角色（调用 run_scan.py 后）**：

| 输出标签 | Claude 行为 |
|---------|------------|
| `INIT_DONE` | 确认存活资产，再次调用 run_scan.py |
| `AUTH_BARRIER` | 告知操作员，等待 |
| `SPIDER_BATCH` | 确认 JS 发现，再次调用 run_scan.py |
| `NEW_SUSPICIOUS_POINTS` | 判断哪些 SP 值得验证，调用 vuln-review |
| `PHASE_TRANSITION` | 再次调用 run_scan.py |

---

### `TOOLS/js_analyzer.py` — JS 批量分析

**职责**：从 `js_files` 表取未分析 JS → 下载内容 → mmx 提取 → 写 `suspicious_points`。

**调用方式**：
```bash
python TOOLS/js_analyzer.py --target "台州学院" --batch 5
python TOOLS/js_analyzer.py --target "台州学院" --url "https://example.com/main.js"
```

**优先级过滤**：

| 优先级 | 匹配规则 |
|--------|---------|
| 高（处理） | 文件名含 `config/api/auth/router/service/main/app/user/order` |
| 中（处理） | 业务域名下自托管，文件名无明显标识 |
| 低（跳过） | `vendor/jquery/bootstrap/chunk-vendors/lodash/react/vue.min` |
| 跳过 | CDN 域名（unpkg/cdnjs/jsdelivr/staticfiles） |

**mmx 提取 prompt（结构化）**：
```
分析以下 JavaScript，以 JSON 返回安全相关信息：
{
  "api_endpoints": [{"path": "...", "method": "GET/POST", "params": [...]}],
  "hardcoded_secrets": [{"type": "apikey/token/password/key", "name": "...", "value": "..."}],
  "internal_routes": ["..."],
  "auth_patterns": ["Bearer/Cookie/X-Custom-Header 描述"]
}
仅返回 JSON，无其他内容。
```

**DB 写入**：
- `api_endpoints` → `suspicious_points`（`test_type='js_endpoint'`，`source='js_analysis'`）
- `hardcoded_secrets` → `suspicious_points`（`test_type='hardcoded_secret'`，`risk='High'`）
- `internal_routes` → `suspicious_points`（`test_type='internal_route'`，`risk='Low'`）
- 更新 `js_files.analyzed=1`，`js_files.discovered_apis_json` / `hardcoded_secrets_json`

---

## TOOLS 目录重组

### 新结构

```
TOOLS/
  run_scan.py          ← 唯一主入口（新增）
  js_analyzer.py       ← JS 分析（新增）
  schema.sql
  requirements.txt

  pipeline/            ← run_scan.py 调用的执行脚本
    __init__.py
    init_scan.py
    bfs_crawl.py
    probe_runner.py
    brutescan.py
    scrapling_fetch.py

  auth/                ← 认证相关
    __init__.py
    browser_auth.py
    chrome_manager.py
    captcha_bypass.py
    feishu_notify.py

  recon/               ← 资产侦察
    __init__.py
    fofa_relay.py
    zoomeye_query.py
    burp-surface.py

  db/                  ← 数据库工具
    __init__.py
    db_query.py
    db_backup.py
    migrate.py
    auth_check.py
    session_dash.py
    log_utils.py
    log_view.py

  utils/               ← 通用工具
    __init__.py
    variant_search.py
    waf_rotate.py
    clash-helper.ps1
```

### 删除 / 归档

| 文件 | 处理 |
|------|------|
| `migrate_old_db.py` | 删除 |
| `start-stealth-browser.ps1` | 删除（stealth-browser MCP 已移除） |
| `ad-hoc/` | 整体移至 `tmp/ad-hoc/` |

### 路径更新范围

移动文件后需更新路径引用的地方：
- `CLAUDE.md` 工具表（路径列）
- `.claude/skills/stealth-scanner/SKILL.md` 工具速查表
- `run_scan.py` 内部调用各 pipeline 脚本的路径

---

## 接口标准化约定

所有 `pipeline/` 下的脚本遵守以下约定：

### 1. DB 路径解析（统一）

```python
# 每个脚本顶部
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # pipeline/ → TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
```

### 2. 结构化输出（统一）

```python
def print_result(tag: str, data: dict) -> None:
    print(f"[{tag}]")
    for k, v in data.items():
        print(f"  {k}: {v}")
```

### 3. 错误处理约定

| 情况 | 行为 |
|------|------|
| 工具未安装（katana/httpx/nuclei/arjun） | `sys.exit("[error] {tool} 未安装，安装: {url}")` |
| DB 找不到 | `sys.exit("[error] 找不到目标 DB: dbs/{target}*.db")` |
| 子进程超时 | `print("[warn] {tool} 超时，跳过")` → 继续主流程 |
| 外部服务不可达（Caido/mmx） | 降级处理，`print("[warn] {service} 不可达，降级")` |
| mmx 返回非 JSON | 记录原始输出到 `tmp/`，跳过该 JS 文件 |

---

## SKILL.md 更新后的核心内容（简化版）

```markdown
## 使用方式

1. 启动: python TOOLS/run_scan.py --target "{目标}"
2. 读输出标签并响应:
   - AUTH_BARRIER → 告知操作员等待登录
   - NEW_SUSPICIOUS_POINTS → 判断哪些发 vuln-review
   - 其他标签 → 再次调用 run_scan.py
3. 无其他步骤
```

---

## 实现顺序

1. TOOLS 目录重组（移文件、删死代码、加 `__init__.py`）
2. 更新 `DBS_DIR` / `PROJECT_ROOT` 路径（各 pipeline 脚本）
3. 实现 `run_scan.py`（phase 状态机 + 结构化输出）
4. 实现 `js_analyzer.py`（mmx 提取 + DB 写入）
5. 更新 `CLAUDE.md` 工具表路径
6. 更新 `SKILL.md` 简化版内容
7. 端到端测试：对台州学院 DB 跑一次完整 spider 批次
