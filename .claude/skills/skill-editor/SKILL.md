---
name: skill-editor
description: 分析和修改 SKILL.md 的工具。确保 AI 指令简洁、完整、一致。不引入面向人类的修饰内容。
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# skill-editor

修改 SKILL.md 的专用工具。直接解决三个常见问题：
1. 内容面向人类而非 AI（冗长解释、废话）
2. 无意义的图表/icon 污染上下文
3. 局部修改破坏整体一致性

## 调用方式

```
Skill(skill="skill-editor", args="<action> <target> [more]")
```

| action | target | 说明 |
|--------|--------|------|
| `edit` | skill 名 | 修改已有 skill（默认模式） |
| `create` | skill 名 | 新建 skill |
| `review` | skill 名 | 只审查不修改 |
| `validate` | skill 名 | 只做一致性校验 |
| `list` | — | 列出所有可用 skill |

不指定 action 时默认 `edit`。

## 通用规则（所有 action 共享）

### 1. AI 优先的写作原则

SKILL.md 是写给 AI 读的指令，不是给人看的手册。

| 原则 | 说明 |
|------|------|
| 指令式 | 直接说"做什么"，不解释"为什么这样做" |
| 少废话 | 每段话都指导一个具体行为，不是背景介绍 |
| 结构>描述 | 用表格/列表/伪代码组织逻辑，不用大段文字 |
| 无装饰 | **禁止**：emoji（😊🚀✅）、ASCII art（`===`装饰线）、纯装饰性图标 |
| 参数说明 | 调用参数必须有明确的格式和语义，避免歧义 |

例外：如果你的 SRC/project 规范要求报告/输出带 emoji 或特定格式，保留。只删对 AI 无意义的部分。

### 2. 全量读取

开始修改前**必须**完整读入目标的 SKILL.md 全文。不允许只读部分就做修改。

### 3. 一致性校验

每次修改后自动校验：

| 检查项 | 规则 |
|--------|------|
| `allowed-tools` | 正文中出现的每个工具调用都必须在 `allowed-tools` 列表中。`mcp__xxx__*` 通配符覆盖该 MCP 全部子命令 |
| 引用完整性 | 目录/skill 名必须匹配 YAML frontmatter 的 `name` |
| `name` | 必须匹配目录名（`skill-editor` → `skill-editor`） |
| 表结构引用 | 如果定义/引用了 DB 表，表名和字段必须一致 |
| 模式/入口文档化 | 每个功能入口（Skill 参数格式）必须在文档中明确写出 |
| 死引用 | 正文中提到的文件、路径、表、参数必须在当前上下文中存在 |

### 4. 输出规范

```
=== skill-editor 变更摘要 ===
目标: vuln-review
变更:
  └─ .allowed-tools 添加 mcp__sqlite__*
  └─ 移除 5 个装饰性 emoji
  └─ 更新 2 处 SQL 表名引用以匹配实际 schema

校验:
  ├─ allowed-tools 覆盖: 通过 (12/12)
  ├─ 引用完整性: 通过
  └─ 残留装饰: 无
```

## edit — 修改 Skill

### 输入

```
mode: edit
target: <skill-name>
changes: |
  - 描述要做什么
  - 具体修改意图
```

### 流程

1. **定位** — Glob `.claude/skills/<target>/SKILL.md`。先在项目级找，再在 `~/.claude/skills/` 找
2. **全量读取** — Read 整个 SKILL.md
3. **分析**:
   - 识别所有内部引用（表名、工具名、其他 skill 名）
   - 识别装饰性内容（emoji、ASCII art、无意义图表）
4. **修改**:
   - 应用用户要求的修改
   - 自动清理装饰性内容
   - 保持或修复一致性
5. **校验** — 执行通用规则第 3 节的一致性校验
6. **输出** — 生成变更摘要

### 修改规则

- **不加解释**：不需要在 SKILL.md 里写"这样做是因为考虑到...", 这不是设计文档
- **不加日志**：不在 SKILL.md 里加修改记录、changelog、版本号
- **不加致谢/引用**：不需要写"参考了某框架的文档"
- **参数格式要紧跟用途**：不要让 AI 猜测参数的语义

### 清理规则

删除以下内容（节省上下文）：

| 内容 | 判定标准 |
|------|----------|
| emoji | 所有非代码、非输出格式要求的 emoji |
| ASCII art 分隔线 | `===`、`---`、`***` 等装饰性分隔线（用于结构化列表除外） |
| 无数据表格 | 只有表头没有说明用途的空表格 |
| 啰嗦引言 | `## 概述`、`## 简介`、`## 背景` 等无操作指令的段落 |
| 括号补充 | `（即...）` 等对 AI 无用的同义反复 |
| 装饰性引用块 | 没有实际约束意义的 `> 提示` / `> 注意` |
| 版本历史 | `v1.0`, `更新于 2024-01-01` 等 |

## create — 新建 Skill

### 输入

```
mode: create
target: <skill-name>
description: <一行描述>
allowed-tools: <逗号分隔>
prompt: |
  这个 skill 要做什么的核心指令
```

### 生成规则

1. YAML frontmatter 必须包含 `name`、`description`、`allowed-tools`
2. `name` 必须等于目录名
3. `allowed-tools` 尽量用宽泛匹配而非穷举每个子命令
4. 正文直接写操作指令，不写背景/概述/设计思路
5. 用表格表达条件分支逻辑
6. SQL / 伪代码 / 命令直接嵌入，不加装饰

### 生成检查

- `description` 包含触发条件（什么场景下该用这个 skill）
- `allowed-tools` 覆盖了所有需要的工具
- 每个操作步骤可执行
- 边界情况（无数据、出错、会话过期等）有处理说明
- Skill 的调用参数格式在正文中明确定义

## review — 审查 Skill

### 输入

```
mode: review
target: <skill-name>
```

### 审查清单

1. **装饰性内容** — emoji、ASCII art、空段落、啰嗦引言
2. **一致性** —
   - `allowed-tools` 和实际工具调用匹配
   - 内部引用有效
   - frontmatter 的 `name` 匹配目录名
3. **AI 可读性** —
   - 指令是否直接明确
   - 是否有模棱两可的描述
   - 分支/条件逻辑是否完整
4. **边缘情况** — 是否覆盖了空数据、错误处理、会话过期恢复
5. **上下文效率** — 是否有可删除而不影响功能的冗余内容

### 输出格式

```
=== skill-review: <target> ===

[装饰性内容]
- file.md:12 — emoji 🚀
- file.md:34 — ASCII art 分隔线

[一致性问题]
- (无)

[Ai可读性问题]
- (无)

[边缘情况缺失]
- 没有处理 SQLite 查询返回空的情况

[上下文效率]
- 第 45-78 行的大段背景介绍可删

综合评: 通过/警告/不通过
```

## validate — 一致性校验

### 输入

```
mode: validate
target: <skill-name>
```

### 校验项

1. `name` == 目录名
2. 正文全文中每个形如 `mcp__xxx__yyy`、`Bash`、`Read`、`Write`、`Edit`、`Grep`、`Glob`、`Skill`、`PowerShell` 的调用都出现在 frontmatter 的 `allowed-tools` 中
3. 如果 skill 引用了其他 skill（`Skill(skill="...")`），目标 skill 存在
4. 如果 skill 定义了 DB 表，表操作（SELECT/INSERT/UPDATE/DELETE）引用的字段在表定义中存在
5. 所有文档化的调用参数（Skill args 格式）在正文中是可寻址的

### 校验通过条件

所有 5 项检查均无问题才算「通过」。

## list — 列出 Skills

扫描 `.claude/skills/*/SKILL.md`（项目级）和 `~/.claude/skills/*/SKILL.md`（全局级）的 frontmatter。

输出格式：

```
=== 技能列表 ===

[项目级]
- vuln-review — 安全漏洞分析与复核引擎
- slow-stealth-scanner — Burp + Chrome DevTools 驱动的网站爬虫

[全局级]
- code-review — 代码质量审查
- security-review — 安全审查
- planner — 实现计划
...
```
