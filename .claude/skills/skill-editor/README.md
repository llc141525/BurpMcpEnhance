# skill-editor

分析和修改 SKILL.md 的工具。确保 AI 指令简洁、完整、一致。

## 解决的问题

创建和维护 Claude Code skill 时，AI 写的 skill 普遍有三个问题：

1. **面向人类而非 AI** — skill 是给 AI 读的指令，不是给人看的手册。但 AI 习惯性写冗长的背景解释、设计思路、啰嗦引言。
2. **无意义的装饰污染上下文** — emoji、ASCII art 分隔线、空表格、重复的说明，都在浪费 context window。
3. **局部修改破坏整体** — skill 内部的 `allowed-tools`、表引用、跨段落交叉引用需要一致，但局部 edit 不会自动检查。

skill-editor 针对这三个问题，提供结构化的审查→修改→校验流程。

## 安装

### Claude Code

```bash
# 项目级安装
cd your-project
mkdir -p .claude/skills/skill-editor
# 复制 SKILL.md 和 README.md 到该目录
```

### Manual

将 `skill-editor/` 目录放到：
- 项目级: `.claude/skills/skill-editor/`
- 用户级: `~/.claude/skills/skill-editor/`

## 使用方法

```
Skill(skill="skill-editor", args="<action> <target> [options]")
```

### 审查 skill

```markdown
Skill(skill="skill-editor", args="review target: slow-stealth-scanner")
```

输出装饰性内容、一致性问题、边缘情况缺失、上下文效率评分。

### 修改 skill

```markdown
Skill(skill="skill-editor", args="edit target: vuln-review changes: |
  - 移除 emoji 和装饰性内容
  - 添加 XX 功能处理
")
```

流程：全量读取 → 分析引用关系 → 执行修改 → 自动清理装饰 → 一致性校验 → 输出变更摘要。

### 新建 skill

```markdown
Skill(skill="skill-editor", args="create target: my-skill description: ...")
```

直接生成 AI 指令风格的 SKILL.md，不写背景废话。

### 一致性校验

```markdown
Skill(skill="skill-editor", args="validate target: vuln-review")
```

检查 5 项：`allowed-tools` 覆盖、`name` 匹配目录名、表字段一致性、跨 skill 引用有效性、参数可寻址性。

### 列出所有 skill

```markdown
Skill(skill="skill-editor", args="list")
```

## 命令参考

| 命令 | 用途 |
|------|------|
| `edit` | 修改已有 skill，自动清理装饰 + 一致性校验 |
| `create` | 新建 skill，直接生成 AI 风格指令 |
| `review` | 审查 skill 质量，不修改 |
| `validate` | 只做一致性校验 |
| `list` | 列出所有可用 skill |

## vs 同类工具

| | skill-creator (Anthropic) | skill-extractor (ToB) | skill-editor |
|---|---|---|---|
| 定位 | eval 驱动的 skill 开发框架 | 从对话提取知识生成 skill | 维护/清理/加固已有 skill |
| 内容清理 | 无 | 无 | 专门清理装饰性内容 |
| 一致性校验 | 无 | 无 | allowed-tools/引用/参数校验 |
| 典型场景 | 从0开发+迭代调优 | 做完调试后固化经验 | 接手已存在的 skill 做清理维护 |

三者互补，不冲突。

## 原则

- **AI 优先**: 指令式，不解释"为什么"，每段话指导一个具体行为
- **全量读取**: 修改前必须读完整 SKILL.md，不允许部分读取
- **自动校验**: 每次修改后检查 `allowed-tools` 覆盖、引用完整性、表字段一致性
- **无装饰**: 禁止 emoji、ASCII art 装饰线、空表格、啰嗦引言
