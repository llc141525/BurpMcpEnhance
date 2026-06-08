# Reflection Phase — Design Spec

**Date:** 2026-06-08
**Status:** Approved

## Overview

Reflection phase 在 stealth-scanner 的 `brute` 阶段结束后自动触发，分析当前目标的技术栈和漏洞覆盖缺口，自动安装已知工具（映射表驱动），并由 AI 生成针对性插件脚本填补空白。

---

## 1. 架构

### 状态机扩展

```
init → auth_pending → auth_ready → spider → probe → brute → reflect → done
```

`run_scan.py` 新增 phase 处理：

```python
elif phase == "reflect":
    run_step([sys.executable, "TOOLS/pipeline/reflect.py", "--target", target])
    set_phase(conn, "done")
```

### 目录结构

```
TOOLS/pipeline/reflect.py         ← 主脚本
TOOLS/pipeline/reflect_map.py     ← 静态映射表（独立文件，易维护）
TOOLS/plugins/
    nuclei/                       ← 生成的 nuclei YAML 模板
    scripts/                      ← AI 生成的 Python probe 脚本
    configs/                      ← 参数/字典调整
```

### CLI

```bash
# 正常触发（run_scan.py 调用）
python TOOLS/pipeline/reflect.py --target "台州学院"

# 手动重跑（忽略上次 reflect_ran_at，重新分析）
python TOOLS/pipeline/reflect.py --target "台州学院" --force

# 配置飞书等待超时（分钟，默认 10）
python TOOLS/pipeline/reflect.py --target "台州学院" --feishu-timeout 30
```

---

## 2. 数据模型

### 新增 plugins 表（migration 013）

```sql
CREATE TABLE plugins (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    type              TEXT NOT NULL CHECK(type IN (
                          'nuclei_template', 'python_script',
                          'tool_binary', 'config'
                      )),
    trigger_stack     TEXT,
    covers_vuln_types TEXT,          -- JSON: ["rce","info_leak"]
    file_path         TEXT,          -- 相对项目根的路径
    install_cmd       TEXT,
    source            TEXT DEFAULT 'mapping'
                          CHECK(source IN ('mapping','ai_generated')),
    active            INTEGER DEFAULT 1,  -- mapping=1; ai_generated 审批后=1
    created_at        TEXT DEFAULT (datetime('now','localtime')),
    last_used_at      TEXT
);
```

激活规则：
- `source='mapping'` → 建表时直接 `active=1`
- `source='ai_generated'` → 建表时 `active=0`，审批通过后置 `1`

### scan_state 扩展（migration 013）

```sql
ALTER TABLE scan_state ADD COLUMN reflect_ran_at TEXT;
ALTER TABLE scan_state ADD COLUMN plugins_added_json TEXT;  -- ["spring-actuator","jwt-alg-confusion"]
```

---

## 3. 分析逻辑

### 层一：映射表（reflect_map.py，确定性，无 AI）

```python
STACK_PLUGINS = {
    "Spring Boot": [
        {"name": "spring-actuator",  "type": "nuclei_template",
         "vuln_types": ["info_leak","config_exposure"],
         "install_cmd": "nuclei -update-templates"},
        {"name": "spring4shell",     "type": "nuclei_template",
         "vuln_types": ["rce"],
         "install_cmd": "nuclei -update-templates"},
    ],
    "Shiro":     [{"name": "shiro-deserialization", "type": "nuclei_template",
                   "vuln_types": ["rce"], ...}],
    "ThinkPHP":  [...],
    "FastJSON":  [...],
    "Struts2":   [...],
    "WordPress": [...],
    "Discuz":    [...],
    "JWT":       [{"name": "jwt-none-alg", "type": "python_script",
                   "vuln_types": ["auth_bypass"], ...}],
    "Laravel":   [...],
}
```

reflect.py 遍历 `detected_stacks`，对每个未安装的插件执行 `install_cmd`，写 `plugins` 表 `active=1`。

### 层二：AI 缺口分析（Claude 推理）

输入（从 DB 读取）：

```
已检测技术栈: ["Spring Boot 2.7", "MySQL", "JWT", "Nginx"]
suspicious_points 覆盖分布: {"path_traversal": 3, "sqli": 1, "auth_surface": 8}
findings 已确认类型: ["info_leak"]
映射层已安装插件: ["spring-actuator", "spring4shell", "jwt-none-alg"]
```

Claude 输出结构化缺口列表：

```json
[
  {
    "gap": "Spring Boot + JWT 未测试 alg confusion（RS256→HS256）",
    "vuln_types": ["auth_bypass"],
    "suggest": "python_script",
    "priority": "High"
  },
  {
    "gap": "MySQL 存在但未做二阶注入探测",
    "vuln_types": ["sqli"],
    "suggest": "nuclei_template",
    "priority": "Medium"
  }
]
```

只处理 `High` 和 `Medium` 缺口。`Low` 写入 DB notes 但本轮不生成插件，避免脚本膨胀。

---

## 4. 插件生成

### 映射工具（无 AI）

```python
for plugin in mapped_plugins:
    if plugin["type"] in ("nuclei_template", "tool_binary"):
        subprocess.run(plugin["install_cmd"].split())
    conn.execute("INSERT INTO plugins ... active=1 ON CONFLICT(name) DO NOTHING")
```

### AI 生成插件

每个 High/Medium 缺口生成对应文件：

```
nuclei_template → TOOLS/plugins/nuclei/{name}.yaml
python_script   → TOOLS/plugins/scripts/{name}.py
config          → TOOLS/plugins/configs/{name}.json
```

写入 `plugins` 表 `active=0, source='ai_generated'`。

### 核心工具修改

需修改 `TOOLS/` 核心脚本时（如调整 probe_runner 参数）：

```bash
git checkout -b reflect/{target}/{date}
# 修改相关文件
git commit -m "reflect: {target} — {描述}"
# 飞书/Claude Code 通知 branch 名和 diff 摘要，操作员手动 review & merge
```

---

## 5. 审批流程

AI 生成脚本完成后，走双通道审批：

```
生成完毕（active=0）
    ↓
飞书发汇总消息，等待回复（默认 10 分钟，--feishu-timeout 可调）

    ├─ 飞书回复 "ok"      → UPDATE plugins SET active=1（全部）
    ├─ 飞书回复 "skip 2"  → 除 id=2 外全部 active=1
    ├─ 飞书回复 "no"      → 全部保持 active=0，本轮跳过
    └─ 超时无回复
            ↓
       reflect.py 以 exit code 2 退出，stdout 最后一行输出:
       [APPROVAL_PENDING] {"plugins": [{"id":1,"name":"...","priority":"High"}, ...]}
            ↓
       run_scan.py 检测 exit code 2，解析 JSON
            ↓
       Claude 在 Claude Code 界面 AskUserQuestion 展示待审批列表
            ↓
       操作员选择后 Claude 执行激活命令
```

飞书消息格式：

```
[reflection] {目标} 发现 N 个覆盖缺口，已生成插件草稿：

[1] jwt-alg-confusion.py (High) — Spring Boot + JWT alg confusion
[2] mysql-second-order.yaml (Medium) — MySQL 二阶注入探测

回复 "ok" 全部激活
回复 "skip 2" 跳过第2条
回复 "no" 全部丢弃
（{N}分钟无回复 → Claude Code 审批）
```

---

## 6. 生成插件的调用

`probe_runner.py` 在下一次完整扫描（stealth-scanner 重跑）的 probe 阶段，从 `plugins` 表读取 active 插件并追加执行。同一轮中飞书即时审批通过的插件，操作员可手动重触发 probe phase 使其生效：

```python
active_scripts = conn.execute(
    "SELECT file_path FROM plugins WHERE active=1 AND type='python_script'"
).fetchall()
active_templates = conn.execute(
    "SELECT file_path FROM plugins WHERE active=1 AND type='nuclei_template'"
).fetchall()
# 追加到 nuclei -t 参数
# 逐一调用 active_scripts
```

---

## 7. 不在范围内

- 跨目标共享插件（每个目标 DB 独立，插件表也独立）
- 插件版本管理（用 git history 追踪）
- 自动 merge 核心工具修改（始终需要人工 review）
