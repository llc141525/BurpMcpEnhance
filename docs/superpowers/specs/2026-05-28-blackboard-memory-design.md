# 黑板模式记忆系统设计

## 概述

将 SRC 项目当前的平级文件记忆系统重构为**黑板模式（Blackboard Pattern）**，支持多个解耦 Specialist（asset-recon / stealth-scanner / vuln-review / src-report / vuln-auditor）通过共享黑板通信，不直接调用。

## 1. 现状分析

当前 8 个平级 .md 文件的问题：

| 问题 | 表现 |
|------|------|
| **混合生命周期** | 静态配置（Clash/Proxy）与动态进度（货讯通科技_progress）在同一平面 |
| **并发无结构** | 三 Session 模型已运行，但记忆系统没有为并发设计的通信槽 |
| **膨胀不可控** | lessons 和目标情报持续追加，无止境膨胀阈值 |
| **压缩机制缺失** | 无完结总结流程，旧目标进度永远留在索引中 |

## 2. 设计原则

- **解耦**：Specialist 之间不直接调用，只读写黑板
- **生命周期分离**：静态配置 / 动态进度 / 可积累知识 / 归档分离到不同区
- **积累 + 压缩**：运行时 per-target 积累 lessons → 完结时 compress 提纯
- **写隔离**：每个 Specialist 只写自己的 board 格

## 3. 目录结构

```
memory/
├── boards/{target}/          ← 黑板核心 — 并发 Session 各写各的格
│   ├── status.md             ← 当前阶段、进度摘要、各 Session 最新 updated_at
│   ├── asset-recon.md        ← Session A
│   ├── stealth-scanner.md    ← Session B
│   ├── vuln-review.md        ← Session C
│   ├── src-report.md         ← Session D
│   └── vuln-auditor.md       ← Session E
│
├── intel/{target}.md         ← 目标情报（端点树、指纹、有效 payload）
│
├── lessons/{target}/         ← 运行时积累，per-target，按类型分
│   ├── attack-patterns.md    ← 有效的攻击模式 / payload
│   ├── false-positives.md    ← 常误报的类型及判断方法
│   └── evidence-gaps.md      ← 报告被拒的原因
│
├── archive/{target}.md       ← compress 后的最终提炼（完结后写入）
│
├── env/                      ← 静态配置（AI 永不修改，仅 operator 变更）
│   ├── proxy.md              ← Clash API + 代理配置
│   ├── mcp-config.md         ← MCP 服务器配置
│   └── tools.md              ← 工具路径
│
└── workflow/                 ← 方法论（AI 永不修改）
    ├── methodology.md        ← Recon → manual → automated SOP
    └── escalation.md         ← 升级操作员的触发条件
```

## 4. Board 通信协议

### 4.1 格式

每个 `boards/{target}/{role}.md` 使用 YAML frontmatter + sections：

```markdown
---
role: stealth-scanner
target: 台州学院
phase: spider
updated_at: 2026-05-28T14:00:00+08:00
---

## 本轮产出
- page_count: 456
- suspicious_points: 48 (new: 3)
- key_findings:
  - /api/systemConfig 未授权
  - MyFaces ViewState 反序列化

## 给 vuln-review 的消息
- F-042 优先级高，建议优先验证

## 本轮消耗
- api_calls: 24
- pages_visited: 12
```

### 4.2 写入规则

- 每个 role 只写自己的 board 文件，不修改其它 role 的文件
- `status.md` 由各 role 在写入自己 board 后更新自己的 `updated_at` 字段（append 不 overwrite）
- 追加写入，不删历史 — 收方通过 `updated_at` 判断增量
- 给其它 Specialist 的消息写在"给 XXX 的消息"字段中

### 4.3 读取规则

- 读取方按需读取其它 role 的 board 文件，根据 `updated_at` 判断是否有新内容
- 不需要 polling — 每次 work cycle 开始前同步一次

## 5. Lessons 积累与 Compress

### 5.1 运行时积累（per-target）

每个 Specialist 在自己的工作循环结束时，判断能否提炼 lessons：

**attack-patterns.md** — 本轮发现的有效攻击模式
```markdown
## 2026-05-28 | OTP 爆破批量确认 (by vuln-review)
确认 14 weikayun 子域全部存在 OTP 无速率限制
Lesson: 发现某类漏洞后，主动扫同目标所有子域同类端点
Confidence: high
```

**false-positives.md** — 复核打回的误报
```markdown
## 2026-05-28 | actuator/info 误报 (by vuln-auditor)
打回原因：404 页返回 JSON 结构但非实际 actuator
Lesson: actuator 类漏洞必须确认响应含具体版本号
```

**evidence-gaps.md** — 报告被拒的证据缺失
```markdown
## 2026-05-28 | 框架指纹缺少截图 (by src-report)
剔除原因：Typecho 指纹只有响应头，无管理页面截图
Lesson: 框架指纹类必须附带相关页面截图
```

### 5.2 完结压缩（compress-lessons）

当 operator 确认此目标短期内不再返工后，调用专用 skill：

**compress-lessons skill 行为：**

1. 读 `lessons/{target}/*.md` 全部条目
2. 去重合并：相同的 attack pattern 在不同轮次被多条记录，保留 confidence 最高的一条
3. 按价值排序（confidence: high > medium > low，高频命中提前）
4. 写入 `archive/{target}.md`：
   - `## Lessons Learned` 段 — 提炼后的经验
   - `## Closed Vulns` 段 — 已提交漏洞摘要
   - `## Reference` 段 — 指向 intel/ 和 boards/ 的路径
5. 不删 `lessons/{target}/`（archive 是提炼版，原文保留为完整上下文）

**跨 target 消费：**
- `archive/` 中所有文件的 `Lessons Learned` 段在新资产启动时加载到 session
- 限制最多加载 5 个最新 archive（避免膨胀）

## 6. 静态配置迁移

| 当前记忆文件 | 迁移目标 | 变更方式 |
|---|---|---|
| `SRC-overview.md` | **删除** — 内容已固化到 CLAUDE.md | operator 确认后删除 |
| `clash-proxy-setup.md` | `env/proxy.md` | 直接迁移 |
| `network-proxy.md` | `env/proxy.md`（合并） | 合并入 env/proxy.md |
| `mcp-fixes.md` | 配置入 `env/mcp-config.md`，原文存档 | 提取关键配置 |
| `workflow-preferences.md` | `workflow/methodology.md` | 精简为方法论核心 |
| `target-intel.md` | `intel/台州学院.md` | 直接迁移 |
| `货讯通科技_progress.md` | `archive/货讯通科技.md` | 已完成，直接归档 |

## 7. compress-lessons Skill 详细设计

在 `.claude/skills/` 下创建 `compress-lessons/` skill。

### 输入

```yaml
target: 货讯通科技
```

### 执行流程

1. LESSONS 读取 — 读 `memory/lessons/{target}/**/*.md` 全部条目
2. 去重合并 — 按 `Lesson:` 文本去重，保留最高 confidence
3. INTEL 整合 — 读 `memory/intel/{target}.md`，提取关键端点/指纹
4. ARCHIVE 写入 — 写 `memory/archive/{target}.md`
5. MEMORY.md 更新 — 更新索引
6. 输出摘要 — 压缩前后的条目数对比，关键 lesson 列表

### 输出格式

```markdown
# 货讯通科技 — 完结存档

归档时间: 2026-05-28

## Lessons Learned

### attack-patterns (3 条)
1. [high] OTP 爆破批量确认：主域有 OTP 问题的，所有子域同类端点也大概率存在
2. [high] Keycloak 非生产 Admin 控制台常暴露：搜索 keycloak.json 和 /auth/admin/
3. [medium] CORS 反射常伴随凭据泄露：access-control-allow-origin: * + withCredentials=true

### false-positives (2 条)
...

### evidence-gaps (2 条)
...

## 已提交漏洞
- F-001 ~ F-041，共 40 个（含 Critical 1 个）

## Reference
- intel: memory/intel/货讯通科技.md
- boards: memory/boards/货讯通科技/
- raw lessons: memory/lessons/货讯通科技/
```

## 8. 迁移步骤

1. Create 新目录结构（boards/env/workflow/intel/lessons/archive）
2. 迁移静态配置（env/、workflow/）
3. 归档已完成 target（货讯通科技 → archive/）
4. 迁移 intel（target-intel.md → intel/台州学院.md）
5. 删除旧文件
6. 重写 MEMORY.md 为黑板索引
7. 写 compress-lessons skill

## 9. 边界规则

- **env/** 和 **workflow/** — AI 永不自动修改，仅 operator 变更
- **boards/{target}/{role}.md** — 只有该 role 写入，追加不覆盖
- **lessons/{target}/** — 任何 Specialist 可在运行中追加
- **archive/{target}.md** — 仅 compress-lessons skill 写入，写入后不可变
- **MEMORY.md** — 仅 compress-lessons 和迁移时修改
- archive 文件最多保留 20 个，超出时删除最旧
