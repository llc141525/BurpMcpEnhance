# Browser Auth Integration Design

**Date:** 2026-06-05  
**Status:** Approved  
**Problem:** 凭证过期、验证码阻断、需认证资产覆盖不到

---

## 1. 目标

| 痛点 | 解决方案 |
|------|---------|
| 凭证过期 | browser-use 自动重新登录，cookies 自动写入 auth_sessions |
| 验证码阻断 | 截图发飞书 → 操作员手机回复 → Playwright 自动填入 |
| 认证资产覆盖不到 | 登录后 browser-use 一次性 surface discovery，入口 URL 写入 BFS 管线 |

---

## 2. 整体架构

```
┌──────────────────────────────────────────────────────────────────┐
│  Chrome.exe                                                       │
│  --remote-debugging-port=9222                                     │
│  --proxy-server=http://127.0.0.1:8181   (Caido)                  │
│  --user-data-dir=.browser-profile                                 │
│  --disable-blink-features=AutomationControlled                   │
└────────────────────────┬─────────────────────────────────────────┘
                         │ CDP WebSocket (ws://localhost:9222)
         ┌───────────────┼────────────────┐
         ▼               ▼                ▼
   patchright       browser-use      Caido Proxy
   (cookie 提取      (auth 导航 +      (录制认证后
    BFS 辅助)         surface scan)     的流量)
         │               │                │
         └───────────────┴────────────────┘
                         │
              TOOLS/chrome_manager.py
              (所有脚本启动时调用，检测/启动 Chrome)
```

**操作员交互渠道：飞书（手机），不是桌面 Chrome。**  
Chrome 窗口在桌面运行但操作员不直接操作它——所有验证码/OTP/扫码均通过飞书完成。

---

## 3. 新增文件

| 文件 | 职责 |
|------|------|
| `TOOLS/chrome_manager.py` | Chrome 生命周期：检测端口 → 启动 → 写 `scan_state.cdp_url` |
| `TOOLS/browser_auth.py` | browser-use agent：登录 + surface discovery + 写 auth_sessions/pages |
| `TOOLS/feishu_notify.py` | lark-cli 封装：发消息/图片 + 轮询对话等待操作员回复 |

---

## 4. 修改文件

| 文件 | 改动 |
|------|------|
| `TOOLS/bfs_crawl.py` | 首行调用 chrome_manager，确保 Chrome 在线 |
| `TOOLS/init_scan.py` | 检测 302/401 → 写 auth_pending → 调 browser_auth.py |
| `.mcp.json` | 移除 stealth-browser，新增 caido（TODO：安装后填 URL） |
| `.claude/skills/stealth-scanner/SKILL.md` | 更新状态机 + 工具速查，使用 skill-editor 修改 |

---

## 5. 删除文件

- `.mcp-browser.json`（stealth-agent-browser-mcp 配置）
- `.mcp.json` 中 `stealth-browser` 条目

---

## 6. chrome_manager.py 设计

**调用方式（其他脚本）：**

```python
result = subprocess.run(
    ["python3", "TOOLS/chrome_manager.py", "--target", target],
    capture_output=True, text=True
)
cdp_url = result.stdout.strip()  # "http://localhost:9222"
```

**内部逻辑：**

```
检测 GET http://localhost:9222/json/version
  ├─ 成功 → 打印 cdp_url，退出
  └─ 失败 → 用 patchright 启动 Chrome subprocess
       flags:
         --remote-debugging-port=9222
         --proxy-server=http://127.0.0.1:8181
         --user-data-dir=E:\SRC挖掘\SRC\.browser-profile
         --disable-blink-features=AutomationControlled
         --no-first-run
         --no-default-browser-check
         --lang=zh-CN
         --window-position=1400,0   (推副屏，不遮主屏)
       → 轮询端口就绪（最多 15s）
       → 写 scan_state.cdp_url = 'http://localhost:9222'
       → 打印 cdp_url
```

**隔离说明：** `--user-data-dir=.browser-profile` 与系统 Chrome 默认路径完全隔离，个人浏览器不受影响。

**容错：**
- 15s 内无响应 → exit(1)，调用方捕获并暂停目标
- 端口被非 Chrome 进程占用 → 自动递增尝试 9223/9224

---

## 7. browser_auth.py 设计

**依赖：** `browser-use`, `langchain-anthropic`, `patchright`  
**LLM：** Claude Haiku（`ANTHROPIC_API_KEY` 环境变量）

**阻断类型检测与处理：**

| 阻断类型 | 检测 | 操作员动作 | 扫描器恢复 |
|----------|------|-----------|-----------|
| QR 码登录 | 页面含 canvas/img QR 元素 | 手机扫飞书里的截图 | 轮询 CDP cookies（最多 3 分钟） |
| 图形验证码 | 页面含 captcha/verify img | 飞书回复验证码文字 | 读回复 → 填表单 → 提交 |
| 手机 OTP | 页面含 OTP/短信输入框 | 飞书回复 4/6 位码 | 读回复 → 填 OTP 框 → 提交 |

**Surface Discovery prompt（固定模板）：**

```
你是一个安全研究员，目标是发现 {target} 登录后可访问的所有功能页面和 API 端点。
请完成以下动作：
1. 访问 dashboard / 首页 / 用户中心
2. 展开所有侧边栏菜单、导航栏、下拉菜单
3. 记录所有可见的页面链接和按钮跳转
4. 不要填写或提交任何表单，不要删除任何数据
5. 完成后输出 JSON：[{"url": "...", "title": "..."}]
```

**约束：** max_steps=20，timeout=120s，域名白名单=目标根域，禁止 DELETE/退出登录。

**输出：** 解析 JSON → 过滤同域 → 写 `pages`（status='queued', source='browser_use'）

---

## 8. feishu_notify.py 设计

**底层：** 调用 `lark-cli`（官方 CLI：github.com/larksuite/cli）

**三种调用模式：**

| 模式 | CLI 调用 | 适用场景 |
|------|---------|---------|
| `send-image` | `lark message send --image <path> --text <msg>` | QR 码（单向） |
| `send-image-wait-reply` | 发图 + 轮询对话消息 | CAPTCHA |
| `send-text-wait-reply` | 发文字 + 轮询对话消息 | OTP |

**轮询策略：** 每 3 秒拉一次对话消息，对比最后已知消息 ID，有新消息则返回内容。  
**超时：** 3 分钟，超时返回 `None`，调用方写 `auth_timeout` 并跳过目标。

---

## 9. Caido 集成

**代理端口：** 8181（避免与 Burp 8080 冲突）  
**Chrome 参数：** `--proxy-server=http://127.0.0.1:8181`  
**MCP 配置：** TODO — 安装 Caido 后填入实际 MCP endpoint URL

**Burp vs Caido 分工：**

| | Burp MCP | Caido MCP |
|---|---|---|
| 流量来源 | 手动测试、manual-replay | browser-use / Playwright 自动化 |
| 主要用途 | 历史分析、业务逻辑猎手 | 认证后 API 发现、参数结构读取 |
| Chrome 代理 | 否 | 是 |

---

## 10. DB Schema 变更

```sql
-- migrations/004_browser_auth.sql
ALTER TABLE scan_state ADD COLUMN cdp_url TEXT DEFAULT NULL;
ALTER TABLE auth_sessions ADD COLUMN cookie_source TEXT DEFAULT 'manual';
```

`pages.source` 列已存在，新增值 `'browser_use'` 无需 schema 变更。

执行：`python3 TOOLS/migrate.py --target "{目标}"`

---

## 11. stealth-scanner 状态机更新

```
init → auth_pending
         │
         ▼
    chrome_manager.py（Chrome 9222）
         │
         ▼
    browser_auth.py（browser-use）
         │
         ├─ QR/CAPTCHA/OTP → feishu_notify.py → 操作员手机回复
         │
         ▼
    cookies → auth_sessions（cookie_source='browser_use'）
    URLs    → pages（source='browser_use', status='queued'）
    phase   → auth_ready
         │
         ▼
    spider（katana BFS，-H "Cookie: ..." 从 auth_sessions 读取）
```

**新增容错状态：**
- `auth_timeout`：飞书超时，跳过目标
- `chrome_error`：Chrome 启动失败，通知操作员

**SKILL.md 修改方式：** 使用 `skill-editor` skill，不直接编辑文件。

---

## 12. 环境变量

| 变量 | 值 | 用途 |
|------|----|------|
| `ANTHROPIC_API_KEY` | `sk-ant-...`（新 key） | browser-use LLM |
| `CAIDO_PROXY_PORT` | `8181` | chrome_manager + Chrome 启动参数 |
| `FEISHU_BOT_TOKEN` | 待配置 | feishu_notify lark-cli 认证 |

---

## 13. 依赖清单

```
# Python (.venv)
browser-use
langchain-anthropic
patchright          # 已安装

# Node.js (node_modules)
rebrowser-playwright  # 已安装，备用

# CLI 工具
lark-cli (larksuite/cli)   # 待安装
caido                       # 待安装
```
