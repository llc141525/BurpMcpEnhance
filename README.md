# Burp Suite MCP Server — 魔改增强版

[English](#english) | [中文](#中文)

---

<a id="english"></a>

# Burp Suite MCP Server — Enhanced Edition

**Two core problems solved:** AI disconnection & Burp freezing under load.

A heavily enhanced fork of the official [PortSwigger mcp-server](https://github.com/PortSwigger/mcp-server).

## The Two Problems This Fork Solves

### 1. AI Keeps Disconnecting

The official server uses **SSE (Server-Sent Events)** — a long-lived HTTP connection that drops constantly under load. Heartbeat self-requests time out. Slow tool calls block the event loop, killing the connection.

**Solution — Streamable HTTP (MCP 2025-03-26):** Replaces persistent SSE with a single POST endpoint. Pure request-response. No long-lived connection means no disconnection.

```
Before: SSE ────── hold connection open ──────> drop ❌
After:  POST ───> response ───> done ✓
        POST ───> response ───> done ✓
        POST ───> response ───> done ✓
```

### 2. Burp Freezes When Data Volume Is High

The official server calls Burp API in real-time on every query. With thousands of proxy records (common during penetration testing), each query blocks Burp's event loop — Burp becomes unresponsive or crashes.

**Solution — Decoupled Architecture:** A background exporter polls Burp API incrementally and writes to local SQLite. MCP tools read from the cache, not Burp directly. Query response drops from seconds to milliseconds.

```
Before: AI query ──> Burp API (real-time) ──> freeze ❌
After:  AI query ──> SQLite cache ──> instant ✓
                   ▲
              Exporter (background, incremental sync)
                   ▲
              Burp API
```

### Full Problem Matrix

| Problem | Root Cause | This Fork's Solution |
|---------|-----------|---------------------|
| **AI keeps disconnecting** | SSE long connection drops under load | **Streamable HTTP transport** — no persistent connections, pure request-response |
| **Burp freezes on large data** | Real-time Burp API calls block the event loop | **Decoupled architecture** — local SQLite cache + background incremental exporter |
| **Scanner issues invisible to AI** | No scanner issue query capability | Full scanner issue sync + query tools |
| **Large responses time out** | Large HTTP bodies block the entire tool call | Async task queue + file-based chunked reading |
| **WSL / remote unreachable** | Strict localhost host checking | `strictLocalhost` toggle for WSL, Docker, remote VMs |
| **Float-vs-int type mismatch** | AI sends `20.0` but server expects `20` | `normalizeJsonElement` auto-converts float integers |

#### SQLite Cache Layer
- Proxy history and scanner issues cached locally
- Paginated queries, detail lookup by ID
- Incremental sync — only new data is pulled
- Cache clear (all / HTTP only / scanner only)

#### Background Exporter
- Coroutine-driven polling, default every 5 seconds
- SHA-256 dedup (method + URL), 5-minute window merging
- Auto prune: 100K HTTP records, 10K scanner issues, expired BLOBs

#### Async Task System
- `submit_task` — enqueue and get a task ID immediately
- `get_task_result` — poll for results
- `read_file` / `delete_file` — manage large response files
- Task types: send HTTP request, create Repeater tab, send to Intruder

#### Better UX
- **Real-time status dashboard** — server, exporter, queue, database health at a glance
- **Chinese UI** — all UI text localized
- **Restart button** — no need to reload the extension
- **Auto-Approve management** — 4 tools to add/remove/list/clear auto-approve targets

## Quick Start

### Prerequisites

- **Java 21+** (mandatory — proxy JAR targets Java 21)
- `jar` command available

### Build

```bash
git clone https://github.com/<your-fork>/burp-mcp-enhance
cd burp-mcp-enhance
./gradlew embedProxyJar
```

Output: `build/libs/burp-mcp-all.jar` (stdio proxy JAR embedded).

### Load into Burp

1. Open Burp Suite → Extensions tab
2. Add → Extension Type = Java
3. Select `build/libs/burp-mcp-all.jar` → Next
4. Enable the server in Burp's MCP tab

### Configure MCP Client

The extension listens on `127.0.0.1:9876`.

#### Streamable HTTP (Recommended, MCP 2025-03-26)

A single POST endpoint. No persistent connections. Never disconnects.

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

> Works with Claude Desktop, Cursor, and any Streamable HTTP-capable client.

#### SSE (Legacy, less stable)

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/sse"
    }
  }
}
```

#### stdio Proxy (for clients that only support stdio)

Uses the bundled `mcp-proxy-all.jar` as a stdio ↔ SSE bridge. Requires Java 21:

```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876/sse"
      ]
    }
  }
}
```

> Extract the proxy JAR via Burp UI: "Extract Proxy Jar" button, or click "Install to Claude Desktop" for auto-configuration.

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| Server Host | Bind address | `127.0.0.1` |
| Server Port | Listen port | `9876` |
| Strict localhost | Disable for WSL/remote | On |
| Keepalive ping | SSE heartbeat | On |
| Keepalive interval | Heartbeat interval (s) | 30s |
| Max response size | Single response limit (KB) | 100KB |
| HTTP request approval | Confirm before sending HTTP | On |
| History access approval | Confirm before reading history | On |

## MCP Tools

### Core Tools
- `send_http1_request` — Send HTTP/1.1 request
- `get_proxy_http_history` — Get proxy HTTP history
- `get_websocket_history` — Get WebSocket history
- `create_repeater_tab` — Create Repeater tab
- `send_to_intruder` — Send to Intruder
- `set_editor_text` — Set editor content
- `set_selection` — Set selected text
- `get_collaborator_payloads` — Generate Collaborator payloads
- `get_collaborator_interactions` — Query Collaborator interactions

### Data Query (cached)
- `list_proxy_http_history` — Paginated HTTP records from local cache
- `get_proxy_http_detail` — Full request/response detail
- `list_scanner_issues` — Scanner issue summary
- `get_scanner_issue_detail` — Full scanner issue detail
- `exporter_stats` — Cache status

### Async Tasks
- `submit_task` — Submit background task
- `get_task_result` — Poll task result

### File Management
- `read_file` — Read temp file
- `delete_file` — Delete temp file

### Auto-Approve Management
- `add_auto_approve_target` — Add auto-approve target
- `remove_auto_approve_target` — Remove auto-approve target
- `list_auto_approve_targets` — List all auto-approve targets
- `clear_auto_approve_targets` — Clear all auto-approve targets

### Database
- `clear_database` — Clear cache (all / HTTP / scanner)

## Architecture

```
┌──────────────────────────────────────────────┐
│                  Burp Suite                   │
│  ┌────────────────────────────────────────┐   │
│  │         MCP Server Extension           │   │
│  │  ┌──────────────┐  ┌────────────────┐  │   │
│  │  │POST /mcp     │  │GET+POST /sse   │  │   │
│  │  │(Streamable   │  │(SSE legacy,    │  │   │
│  │  │ HTTP, ★推荐) │  │ 向后兼容)      │  │   │
│  │  └──────────────┘  └────────────────┘  │   │
│  │  ┌──────────┐  ┌──────────────────┐   │   │
│  │  │Exporter  │─>│  SQLite Database │   │   │
│  │  │(background)│  │  (local cache)  │   │   │
│  │  └──────────┘  └──────────────────┘   │   │
│  └────────────────────────────────────────┘   │
│         ▲                  ▲                  │
│  HTTP POST /mcp      SSE GET /sse             │
└─────────┼──────────────────┼─────────────────┘
          │                  │
   ┌──────┴──────┐    ┌──────┴──────┐
   │ MCP Client  │    │ MCP Client  │
   │(Claude etc) │    │(legacy)     │
   └─────────────┘    └─────────────┘
```

## Development

Tools are defined under `src/main/kotlin/net/portswigger/mcp/tools/`. Add a new tool by creating a `@Serializable` data class and registering it:

```kotlin
@Serializable
data class MyToolArgs(val param: String)

// Register in Tools.kt
mcpTool<MyToolArgs>("tool description") {
    // your logic
}
```

## Build Commands

| Command | Description |
|---------|-------------|
| `./gradlew embedProxyJar` | Build distributable JAR (proxy embedded) |
| `./gradlew test` | Run tests |
| `./gradlew shadowJar` | Build JAR only, no proxy |

---

<a id="中文"></a>

# Burp Suite MCP Server — 魔改增强版

**解决两大核心问题：AI 频繁断连 & Burp 数据量一大就卡死。**

基于 PortSwigger 官方 [mcp-server](https://github.com/PortSwigger/mcp-server) 深度魔改。

## 本版解决的两大问题

### 1. AI 频繁断连

原版服务器使用 **SSE（Server-Sent Events）**—— 一种长连接协议，负载高时反复断开。自请求心跳超时、慢工具调用阻塞事件循环，都会导致连接中断。

**解决方案 — Streamable HTTP（MCP 2025-03-26 新标准）：** 用一个 POST 端点替代持久 SSE 连接。纯请求-响应模式，无长连接 = 永不掉线。

```
改造前： SSE ────── 保持连接打开 ──────> 断开 ❌
改造后： POST ───> 响应 ───> 结束 ✓
        POST ───> 响应 ───> 结束 ✓
        POST ───> 响应 ───> 结束 ✓
```

### 2. Burp 数据量大就卡死

原版每次查询都实时调用 Burp API。挖洞时 Burp 会记录成百上千条数据，每次查詢都阻塞 Burp 事件循环——Burp 直接卡死甚至崩溃。

**解决方案 — 解耦架构：** 后台导出器轮询 Burp API，增量同步到本地 SQLite 数据库。MCP 工具从缓存读取，不直接调 Burp API。查询响应从秒级降到毫秒级。

```
改造前： AI 查询 ──> Burp API（实时）──> 卡死 ❌
改造后： AI 查询 ──> SQLite 缓存 ──> 毫秒响应 ✓
                   ▲
              后台导出器（增量同步）
                   ▲
              Burp API
```

### 完整问题对照

| 痛点 | 原版根因 | 本版改进 |
|------|---------|---------|
| **AI 频繁断连** | SSE 长连接负载下断开 | **Streamable HTTP** — 无持久连接，纯请求-响应 |
| **数据量大卡死** | 实时调 Burp API 阻塞事件循环 | **解耦架构** — SQLite 本地缓存 + 后台增量导出 |
| **扫描结果不可查** | 不支持扫描问题查询 | 全量扫描问题同步 + 查询工具 |
| **大响应超时** | 结果过大直接超时 | 异步任务队列 + 文件分块读取 |
| **WSL/远程不可用** | 严格 localhost 检查 | `strictLocalhost` 开关 |
| **参数类型错误** | AI 发 `20.0` 但系统要 `20` | `normalizeJsonElement` 自动修正 |

#### SQLite 缓存层
- 代理 HTTP 历史 + 扫描问题自动缓存到本地 SQLite
- 分页查询、按 ID 获取详情
- SHA-256 去重（method + URL），5 分钟窗口合并
- 自动清理：10 万 HTTP 记录、1 万扫描问题、过期 BLOB

#### 后台导出器 (Exporter)
- 协程驱动后台轮询，默认每 5 秒同步一次
- 游标增量同步——只拉取新数据
- 自动去重，支持扫描问题同步

#### 异步任务系统
- `submit_task` — 提交后台任务，立即返回 ID
- `get_task_result` — 轮询获取结果
- `read_file` / `delete_file` — 管理大文件
- 支持 HTTP 请求、创建 Repeater、发送到 Intruder

#### 更友好的 UI
- **实时状态仪表板** — 服务器、导出器、队列、数据库一目了然
- **中文界面** — 全 UI 中文化
- **重启按钮** — 无需重载扩展
- **Auto-Approve 管理** — 4 个工具管理自动放行列表

## 快速开始

### 前提条件

- **Java 21+**（必须，代理 JAR 编译目标为 Java 21）
- `jar` 命令可用

### 构建

```bash
git clone https://github.com/<your-fork>/burp-mcp-enhance
cd burp-mcp-enhance
./gradlew embedProxyJar
```

产物在 `build/libs/burp-mcp-all.jar`（内嵌 stdio 代理）。

### 加载到 Burp

1. 打开 Burp Suite → Extensions 标签
2. Add → Extension Type = Java
3. 选择 `build/libs/burp-mcp-all.jar` → Next
4. 在 Burp 的 MCP 标签页中启用服务器

### 配置 MCP 客户端

扩展启动后在 `127.0.0.1:9876` 提供服务。

#### Streamable HTTP（推荐，MCP 2025-03-26 新标准）

单一 POST 端点，无持久连接，永不掉线：

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

> 适用于 Claude Desktop、Cursor 等支持 Streamable HTTP 的客户端。

#### SSE 直连（向后兼容，稳定性较差）

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/sse"
    }
  }
}
```

#### stdio 代理（仅支持 stdio 的旧客户端）

使用内置的 `mcp-proxy-all.jar` 桥接 stdio ↔ SSE。需要 Java 21：

```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876/sse"
      ]
    }
  }
}
```

> 可在 Burp UI 中点击"提取服务器代理 jar"获取，或点击"安装到 Claude Desktop"自动配置。

## 配置说明

| 选项 | 说明 | 默认值 |
|------|------|--------|
| 服务器主机 | 监听地址 | `127.0.0.1` |
| 服务器端口 | 监听端口 | `9876` |
| 严格 localhost 模式 | WSL/远程环境需关闭 | 开启 |
| 启用保活心跳 | SSE 连接保活 | 开启 |
| 保活间隔 | 心跳间隔（秒） | 30s |
| 最大响应大小 | 单次响应上限（KB） | 100KB |
| HTTP 请求审批 | 发送 HTTP 前需确认 | 开启 |
| 历史记录访问审批 | 读取历史前需确认 | 开启 |

## MCP 工具清单

### 核心工具
- `send_http1_request` — 发送 HTTP/1.1 请求
- `get_proxy_http_history` — 获取代理 HTTP 历史
- `get_websocket_history` — 获取 WebSocket 历史
- `create_repeater_tab` — 创建 Repeater 标签
- `send_to_intruder` — 发送到 Intruder
- `set_editor_text` — 设置编辑器内容
- `set_selection` — 设置选中文本
- `get_collaborator_payloads` — 生成 Collaborator 负载
- `get_collaborator_interactions` — 查询 Collaborator 交互

### 数据查询工具（需缓存）
- `list_proxy_http_history` — 从本地缓存分页列出 HTTP 记录
- `get_proxy_http_detail` — 获取完整请求/响应详情
- `list_scanner_issues` — 列出扫描问题摘要
- `get_scanner_issue_detail` — 获取扫描问题完整详情
- `exporter_stats` — 查看缓存状态

### 异步任务工具
- `submit_task` — 提交后台任务
- `get_task_result` — 查询任务结果

### 文件管理工具
- `read_file` — 读取临时文件
- `delete_file` — 删除临时文件

### Auto-Approve 管理工具
- `add_auto_approve_target` — 添加自动放行目标
- `remove_auto_approve_target` — 移除自动放行目标
- `list_auto_approve_targets` — 列出所有自动放行目标
- `clear_auto_approve_targets` — 清除所有自动放行目标

### 数据库管理工具
- `clear_database` — 清除缓存（全部/HTTP 历史/扫描问题）

## 架构说明

```
┌──────────────────────────────────────────────┐
│                  Burp Suite                   │
│  ┌────────────────────────────────────────┐   │
│  │         MCP Server Extension           │   │
│  │  ┌──────────────┐  ┌────────────────┐  │   │
│  │  │POST /mcp     │  │GET+POST /sse   │  │   │
│  │  │(Streamable   │  │(SSE 旧版,     │  │   │
│  │  │ HTTP, ★推荐) │  │ 向后兼容)      │  │   │
│  │  └──────────────┘  └────────────────┘  │   │
│  │  ┌──────────┐  ┌──────────────────┐   │   │
│  │  │Exporter  │─>│  SQLite Database │   │   │
│  │  │(后台同步) │  │  (本地缓存)      │   │   │
│  │  └──────────┘  └──────────────────┘   │   │
│  └────────────────────────────────────────┘   │
│         ▲                  ▲                  │
│  HTTP POST /mcp      SSE GET /sse             │
└─────────┼──────────────────┼─────────────────┘
          │                  │
   ┌──────┴──────┐    ┌──────┴──────┐
   │ MCP Client  │    │ MCP Client  │
   │(Claude etc) │    │(旧版/代理)  │
   └─────────────┘    └─────────────┘
```

## 开发

工具定义在 `src/main/kotlin/net/portswigger/mcp/tools/`，新增工具只需创建 `@Serializable` 数据类并注册：

```kotlin
@Serializable
data class MyToolArgs(val param: String)

// 在 Tools.kt 中注册
mcpTool<MyToolArgs>("工具描述") {
    // 处理逻辑
}
```

## 构建命令

| 命令 | 说明 |
|------|------|
| `./gradlew embedProxyJar` | 构建可分发的 JAR（含内嵌代理） |
| `./gradlew test` | 运行测试 |
| `./gradlew shadowJar` | 仅构建 JAR 本体，不含代理 |
