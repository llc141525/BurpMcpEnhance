# 黑板模式记忆系统迁移计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将当前 8 个平级 .md 记忆文件迁移为黑板模式结构 + 写 compress-lessons skill

**Architecture:** 解耦的目录区（boards/env/workflow/intel/lessons/archive），每个 Specialist 只写自己的 board 格，lessons per-target 积累 → compress 提纯写 archive。静态配置（env/、workflow/）AI 永不修改。

**Tech Stack:** .md 文件 + YAML frontmatter + skill-editor 写 compress-lessons skill

**新位置:** `e:\SRC挖掘\SRC\memory\`（不再是 `~/.claude/projects/` 下）

**约束:**
- 所有临时文件必须放 `tmp/`
- 并发三 Session 模型保持不动
- compress-lessons 用 skill-editor 实现

---

### Task 1: 创建黑板模式目录结构

**Files:**
- Create: `e:\SRC挖掘\SRC\memory\boards\`
- Create: `e:\SRC挖掘\SRC\memory\env\`
- Create: `e:\SRC挖掘\SRC\memory\workflow\`
- Create: `e:\SRC挖掘\SRC\memory\intel\`
- Create: `e:\SRC挖掘\SRC\memory\lessons\`
- Create: `e:\SRC挖掘\SRC\memory\archive\`

- [ ] **Step 1: 创建所有子目录**

```bash
mkdir -p "e:/SRC挖掘/SRC/memory/boards" "e:/SRC挖掘/SRC/memory/env" "e:/SRC挖掘/SRC/memory/workflow" "e:/SRC挖掘/SRC/memory/intel" "e:/SRC挖掘/SRC/memory/lessons" "e:/SRC挖掘/SRC/memory/archive"
```

Expected: 6 directories created, no errors.

---

### Task 2: 迁移静态配置 — env/proxy.md

**Files:**
- Read: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\clash-proxy-setup.md`
- Read: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\network-proxy.md`
- Create: `e:\SRC挖掘\SRC\memory\env\proxy.md`

- [ ] **Step 1: 合并写入 env/proxy.md**

合并 Clash 配置 + 网络代理规则：

```markdown
# Proxy 配置

## Clash Verge API
- API: `http://127.0.0.1:9097`
- Secret: `set-your-secret`
- Proxy Port: `127.0.0.1:9870` (HTTP/SOCKS5 mixed)
- Core: verge-mihomo v1.19.21

## IP 轮换
使用 `TOOLS/clash-helper.ps1`:
```powershell
. .\TOOLS\clash-helper.ps1
Switch-ClashProxy -Region HK    # 切香港节点
Switch-ClashProxy -Region JP    # 切日本节点
Switch-ClashProxy               # 完全随机
Set-ClashMode -Mode global      # 切换模式
```

## 各通道代理方案
| 通道 | 配置方式 |
|------|----------|
| Burp MCP | Burp UI → Project Options → Connections → Upstream Proxy, Host: 127.0.0.1:9870, Dest: \* |
| PowerShell | `$env:HTTP_PROXY="http://127.0.0.1:9870"` |
| Chrome DevTools | 依赖系统代理（Clash system proxy enabled） |

## 网络代理规则
当 WebSearch / WebFetch 因网络限制失败时，立刻用 curl 通过 127.0.0.1:9870 重试。
```

- [ ] **Step 2: 确认写入成功**

```bash
head -3 "e:/SRC挖掘/SRC/memory/env/proxy.md"
```

Expected: shows `# Proxy 配置`

---

### Task 3: 迁移静态配置 — env/mcp-config.md

**Files:**
- Read: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\mcp-fixes.md`
- Create: `e:\SRC挖掘\SRC\memory\env\mcp-config.md`

- [ ] **Step 1: 从 mcp-fixes.md 提取永久配置写入 env/mcp-config.md**

```markdown
# MCP 服务器配置

## SQLite MCP
- 自定义 Python FastMCP 服务器: `TOOLS/sqlite-mcp-server.py`
- 另有 `sqlite-burp` 服务直接查询 Burp 数据库

## Stealth Browser MCP
- 包: `stealth-agent-browser-mcp@0.2.0`
- Viewport: 1366x768
- Locale: zh-CN
- Timezone: Asia/Shanghai
- Headless: false
```

---

### Task 4: 迁移 workflow — workflow/methodology.md

**Files:**
- Read: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\workflow-preferences.md`
- Create: `e:\SRC挖掘\SRC\memory\workflow\methodology.md`

- [ ] **Step 1: 精简写入 workflow/methodology.md**

```markdown
# 方法论

## 标准工作流
1. Operator 通过 Burp 浏览目标 → 捕获全部请求
2. Operator 识别可疑请求/参数 → 告知 Claude 精确目标
3. Claude 做被动分析（无自动化扫描工具）:
   - TOOLS/js-harvest.js (DevTools) → JS 端点收割
   - TOOLS/burp-surface.py → 参数/路径/模式分析
   - WebArchive / crt.sh / GitHub 搜索 → OSINT
4. Claude 通过 Burp MCP 分析（regex 过滤，永不读全量历史）
5. Claude 通过 Burp Repeater 测试（参数 fuzz、PoC 构造）
6. Operator 确认发现 → Claude 写报告

## 测试优先级
业务逻辑缺陷 > 越权 > XSS/SQLi
手动分析 + Burp > 盲目自动化扫描
发现即报告，不批量累积

## 升级触发条件
Claude 遇到以下情况必须暂停并询问 operator：
- 潜在高危（RCE、可写 SQLi、任意文件上传）
- 会话过期且 Stealth Browser 无法重新登录
- WAF/反爬阻挡自动化测试
- 目标返回异常大量响应（可能数据泄露）
- 不确定测试是否在授权范围内
```

---

### Task 5: 迁移 intel — intel/台州学院.md

**Files:**
- Read: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\target-intel.md`
- Create: `e:\SRC挖掘\SRC\memory\intel\台州学院.md`

- [ ] **Step 1: 直接迁移 target-intel.md → intel/台州学院.md**

```markdown
---
name: 台州学院
description: 台州学院 SSO 端点树、加密栈、攻击面情报
---

# 台州学院

## 基本信息
- 锐捷网络 CAS 系统: 统一身份认证平台
- 验证码接口: `/api/captcha/generate/DEFAULT?time={ts}`，160x70 PNG，4 位字母数字混合
- 验证码无频率限制: 4次/秒未触发429/403

## 加密栈
- enc-base64.min.js + mode-ecb.min.js: 前端 ECB 加密密码
- ECB 不安全: 相同明文 → 相同密文，可重放

## API 端点树
- /linkid/protected/api/aggregate/authmethod/usernames/UsernamePassword — 查询用户认证方式
- /api/protected/user/findCaptchaCount/{studentId} — 学号在 URL 路径中
- /api/protected/wechat/checkEqualUser — 用户枚举可能
- /api/service/protected/get/name — 内部服务名称泄露

## 潜在风险点
- 学号枚举: findCaptchaCount/{studentId} 可遍历学号
- 用户枚举: checkEqualUser + authmethod/usernames/ 两个端点
- 验证码绕过: 无频率限制 + 4位字母数字 → 可暴力
- WebAuthn 已启用: webauthn.js
```

---

### Task 6: 归档已完成 target — archive/货讯通科技.md

**Files:**
- Read: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\货讯通科技_progress.md`
- Create: `e:\SRC挖掘\SRC\memory\archive\货讯通科技.md`

- [ ] **Step 1: 将完整进度内容写入归档**

```markdown
---
name: 货讯通科技
description: OOCL/CargoSmart/Weikayun 全量扫描归档 — 40 findings, 包含 Critical
status: archived
archived_at: 2026-05-28
---

# 货讯通科技(CargoSmart/OOCL) — 完结存档

## 目标范围
- oocl.com / oocllogistics.com / weikayun.com / cargosmart.com / schedulingsmart.com

## 已确认漏洞 (F-001~F-041)
- F-001: CORS critical (digital.oocl.com)
- F-002: MOC未授权API (moc.oocl.com) [已修复]
- F-003~F-004: Exchange ECP公网 + ProxyShell路径
- F-005: MyFaces ViewState反序列化
- F-006~F-008: Keycloak Admin公网暴露 (含非生产)
- F-009~F-016: actuator/systemConfig/CORS (多站点)
- F-017~F-031: OTP爆破 (14 weikayun子域)
- F-032~F-033: Zato ESB堆栈泄露 + Admin公网
- F-034: Critical CORS反射+Credentials (全路径)
- F-035~F-036: Keycloak scope枚举 + 匿名注册
- F-037~F-041: 密码重置无验证码 / 信息泄露 / systemConfig

## 关键发现
- 已修复确认: F-002 (moc.oocl.com) 当前返回403
- Weikayun 内部 k8s 主机名泄露: opc-ui-base-external-csopc-prod-i.opc.pdfl.k8s.cargosmart.com
- 扫描受限: yapi.weikayun.com (WAF), www.oocl.com (Cloudflare)

## src-report Phase 1 状态
- 23 个通过 / 13 个剔除 / 新增 F-039~F-041 待评审
- 等待 operator 确认后 Phase 2 写报告
```

---

### Task 7: 重写 MEMORY.md 为黑板索引

**Files:**
- Create: `e:\SRC挖掘\SRC\memory\MEMORY.md`

- [ ] **Step 1: 写入新黑板索引**

```markdown
# SRC 项目记忆 — 黑板模式

## ── 静态配置 ──
- [env/proxy.md](env/proxy.md) — Clash 代理、IP 轮换、各通道方案
- [env/mcp-config.md](env/mcp-config.md) — MCP 服务器配置
- [workflow/methodology.md](workflow/methodology.md) — 标准工作流 + 升级触发条件

## ── 目标情报 ──
- [intel/台州学院.md](intel/台州学院.md) — 锐捷 CAS 端点树、ECB 加密栈、攻击面

## ── 归档（已完成目标）──
- [archive/货讯通科技.md](archive/货讯通科技.md) — 40 findings, OOCL/CargoSmart/Weikayun

## ── session 黑板（运行时生成）──
- boards/{target}/{role}.md — 各 Specialist 写自己的格

## ── lessons（运行时积累）──
- lessons/{target}/  — per-target 经验教训，完结后 compress 入 archive

## ── 边界规则 ──
- env/ + workflow/: AI 永不修改，仅 operator 变更
- boards/{target}/{role}.md: 只追加，不覆盖
- lessons/{target}/: 任何 Specialist 可在运行中追加
- archive/: 仅 compress-lessons skill 写入，写入后不可变
- MEMORY.md: 仅 compress-lessons 或迁移时修改
- archive 最多保留 20 个，超出删最旧
```

---

### Task 8: 删除旧路径文件（在 ~/.claude/projects/ 下的旧记忆）

**Files:**
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\SRC-overview.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\clash-proxy-setup.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\network-proxy.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\mcp-fixes.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\workflow-preferences.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\target-intel.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\货讯通科技_progress.md`
- Delete: `C:\Users\llc\.claude\projects\e--SRC---SRC\memory\MEMORY.md`（旧索引）

- [ ] **Step 1: 确认所有 Task 2-7 的新文件已创建**

```bash
ls -la "e:/SRC挖掘/SRC/memory/" "e:/SRC挖掘/SRC/memory/env/" "e:/SRC挖掘/SRC/memory/workflow/" "e:/SRC挖掘/SRC/memory/intel/" "e:/SRC挖掘/SRC/memory/archive/"
```

Expected: 所有新建文件存在。

- [ ] **Step 2: 删除旧路径的 8 个文件**

```bash
rm "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/SRC-overview.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/clash-proxy-setup.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/network-proxy.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/mcp-fixes.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/workflow-preferences.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/target-intel.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/货讯通科技_progress.md" "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/MEMORY.md"
```

Expected: 8 files removed, no errors。

- [ ] **Step 3: 确认旧路径已空**

```bash
ls "C:/Users/llc/.claude/projects/e--SRC---SRC/memory/"
```

Expected: 无 .md 文件（只剩空目录或空）。

---

### Task 9: 用 skill-editor 写 compress-lessons skill

**Files:**
- Modify: `.claude/skills/compress-lessons/SKILL.md` (skill-editor 会创建)

- [ ] **Step 1: 调用 skill-editor 创建 compress-lessons skill**

skill 行为：

**compress-lessons Skill:**
- input: `target: 货讯通科技`
- 读 `memory/lessons/{target}/**/*.md` 全部条目
- 去重合并：相同 `Lesson:` 文本去重，保留最高 confidence
- 按价值排序：confidence: high > medium > low
- 读 `memory/intel/{target}.md` 提取关键端点/指纹
- 写 `memory/archive/{target}.md`
- 更新 MEMORY.md 索引
- 输出压缩摘要

**边界规则:**
- archive 文件最多 20 个，超出删除最旧
- 不删 `lessons/{target}/` 原文
- `archive/{target}.md` 写入后不可变
- MEMORY.md 只追加 archive 链接，不修改已有条目
