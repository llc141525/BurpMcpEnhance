# Burp Suite MCP Server — 魔改增强版

[English](#english) | [中文](#中文)

---

<a id="english"></a>

# Burp Suite MCP Server — Enhanced Edition

A heavily enhanced fork of the official [PortSwigger mcp-server](https://github.com/PortSwigger/mcp-server) that solves the notorious **AI disconnection problem** once and for all.

## Why This Fork Exists

The official MCP server uses **SSE (Server-Sent Events)** — a long-lived HTTP connection that constantly breaks:

| Problem | Root Cause | This Fork's Solution |
|---------|-----------|---------------------|
| **AI keeps disconnecting** | SSE connections drop under load. Heartbeat self-requests time out. Slow tool calls block the event loop. | **Streamable HTTP transport** (MCP 2025-03-26) — no persistent connections. Pure request-response. Never disconnects. |
| **Slow queries freeze Burp** | Each query calls Burp API in real-time. Thousands of proxy records = deadlock. | SQLite local cache. Background exporter syncs data incrementally. Paginated queries respond in milliseconds. |
| **Scanner issues invisible to AI** | No scanner issue query capability at all. | Full scanner issue sync + `list_scanner_issues` / `get_scanner_issue_detail` tools. |
| **Large responses time out** | Huge HTTP bodies block the entire tool call. | Async task queue (`submit_task` / `get_task_result`) + file-based chunked reading. |
| **WSL / remote unreachable** | Strict localhost host checking rejects non-local connections. | `strictLocalhost` toggle. Works in WSL, Docker, remote VMs. |
| **Float-vs-int type mismatch** | AI sends `20.0` but the server expects `20`. | `normalizeJsonElement` auto-converts float integers. |

### The Disconnection Crisis — Solved

**Streamable HTTP** (MCP 2025-03-26) replaces SSE with a single POST endpoint. No long-lived connections means:

- **No TCP timeouts** — every request opens a fresh connection
- **No NAT/proxy drop** — no idle connection for NAT to kill
- **No event-loop blocking** — tool execution and transport are cleanly separated
- **No heartbeat needed** — connection lifecycle is per-request
- **Works everywhere** — Claude Desktop, Cursor, any HTTP-capable MCP client

### Beyond Connectivity: What Else You Get

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

基于 PortSwigger 官方 [mcp-server](https://github.com/PortSwigger/mcp-server) 深度魔改，**彻底解决 AI 频繁断连**这一最大痛点。

## 为什么有这个分支

原版 MCP 服务器使用 **SSE（Server-Sent Events）**——一种长连接协议，在网络不稳定时会反复断开：

| 痛点 | 原版根因 | 本版改进 |
|------|---------|---------|
| **AI 频繁断连** | SSE 长连接在负载下断开。自请求心跳超时。慢工具调用阻塞事件循环导致心跳中断。 | **Streamable HTTP 传输**（MCP 2025-03-26 新标准）——纯请求-响应模式，无持久连接，永不掉线 |
| **数据查询卡死 Burp** | 每次查询实时调用 Burp API，大量数据时崩溃 | SQLite 本地缓存 + 后台导出器增量同步，**分页查询毫秒响应** |
| **扫描结果不可查** | 完全不支持扫描问题查询 | 全量扫描问题同步 + 专用查询工具 |
| **大响应超时** | 查询结果过大直接超时 | **异步任务队列** + 文件分块读取 |
| **WSL/远程不可用** | 严格的 localhost 检查 | **strictLocalhost 开关**，WSL/Docker/远程皆可用 |
| **参数类型错误** | AI 发 `20.0` 但系统要 `20` | `normalizeJsonElement` 自动类型修正 |

### 断连问题——彻底解决

**Streamable HTTP**（MCP 2025-03-26 标准）用一个 POST 端点替代 SSE 持久连接：

- **无 TCP 超时** — 每次请求都是新连接
- **无中间层断连** — NAT/代理不会杀死空闲连接
- **无事件循环阻塞** — 工具执行与传输层完全解耦
- **无需心跳** — 连接生命周期就是一次请求
- **广泛兼容** — Claude Desktop、Cursor 等主流 MCP 客户端均支持

**配置方法**：只需将 `url` 指向 `http://127.0.0.1:9876/mcp` 即自动启用，无需额外设置。

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

### 更多增强功能

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
