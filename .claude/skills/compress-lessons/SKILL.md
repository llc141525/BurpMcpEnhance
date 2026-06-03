---
name: compress-lessons
description: 压缩 lessons 到 archive。operator 确认某 target 短期内不再返工后调用。
allowed-tools:
  - Read
  - Write
  - Edit
  - Glob
  - Bash
---

# compress-lessons

## 调用方式

```
Skill(skill="compress-lessons", args="target: 货讯通科技")
```

## 执行流程

### 1. 读取 lessons

```
Glob: e:/SRC挖掘/SRC/memory/lessons/{target}/**/*.md
```

对所有匹配文件，逐条提取以下三种类型：

| 类型 | 匹配条件 |
|------|----------|
| attack-patterns | lessons/attack-patterns.md |
| false-positives | lessons/false-positives.md |
| evidence-gaps | lessons/evidence-gaps.md |

每条记录保留原始文本、confidence 值、来源 role、时间。

### 2. 去重合并

相同 `Lesson:` 开头的文本视为重复，只保留 confidence 最高的一条。

排序规则: high > medium > low，同 confidence 按时间倒序。

### 3. 读取 intel

```
Read: e:/SRC挖掘/SRC/memory/intel/{target}.md
```

提取目标范围和关键端点。

### 4. 写 archive

写 `e:/SRC挖掘/SRC/memory/archive/{target}.md`，格式：

```markdown
---
name: {target}
description: {从 intel 提取的一句话描述}
status: archived
archived_at: {当前日期}
---

# {target} — 完结存档

归档时间: {日期}

## Lessons Learned

### attack-patterns (N 条)
按照 `[confidence] lesson` 格式列出。

### false-positives (N 条)
...

### evidence-gaps (N 条)
...

## 已提交漏洞
从 boards/ 或 intel 提取已确认漏洞列表。

## Reference
- intel: memory/intel/{target}.md
- boards: memory/boards/{target}/
- raw lessons: memory/lessons/{target}/
```

### 5. 更新 MEMORY.md

在 `e:/SRC挖掘/SRC/memory/MEMORY.md` 的 `## ── 归档（已完成目标）──` 段追加一行：

```
- [archive/{target}.md](archive/{target}.md) — 描述
```

### 6. archive 上限控制

```
Bash: ls e:/SRC挖掘/SRC/memory/archive/*.md | wc -l
```

超过 20 个文件时，按 `archived_at` 排序，删除最早的文件（用 `rm`）。

不删 `lessons/{target}/` 原文。如果 archive 已存在（同名 target），覆盖写入但 prompt operator 确认。

## 输出摘要

输出格式：

```
=== compress-lessons: {target} ===
lessons 读取: N 条 (attack-patterns: A, false-positives: B, evidence-gaps: C)
去重合并: N → M 条
写入: archive/{target}.md
MEMORY.md: 已追加
archive 总数: 当前 N 个
```
