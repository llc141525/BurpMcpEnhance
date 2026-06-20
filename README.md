# Burp Suite MCP Server -- 魔改增强版

[English](#english) | [中文](#中文)

---

<a id="english"></a>

# Burp Suite MCP Server -- Enhanced Edition

**If your AI keeps disconnecting or Burp freezes under load, you're in the right place.**

This is a hard fork of the official [PortSwigger mcp-server](https://github.com/PortSwigger/mcp-server). The official version has two unfixable design flaws that make it unusable in real work. This fork replaces both from the ground up.

## The Two Problems This Fork Fixes

### 1. AI Disconnects Every Few Minutes

The official server uses SSE (Server-Sent Events) -- a long-lived HTTP connection. SSE was never designed for request-response. Under load it drops. Heartbeat self-requests time out. A slow tool call blocks the event loop and kills the connection. You spend more time reconnecting than actually using the tool.

**What we did:** Replaced SSE with Streamable HTTP (MCP 2025-03-26 spec). A single POST endpoint. Pure request-response. No persistent connection means nothing to disconnect.

```
Official: SSE ----- keep alive ----- keep alive ----- drop
This:     POST -> done  POST -> done  POST -> done
```

### 2. Burp Freezes on Large Data

The official server calls Burp API in real time on every query. During real penetration testing, Burp accumulates thousands of proxy records. Every query blocks Burp's event loop. Burp becomes unresponsive or crashes. This is not a minor slowdown -- it makes the tool unusable past the first few requests.

**What we did:** Decoupled architecture. A background exporter polls Burp API incrementally and writes to local SQLite. MCP tools read from cache, not Burp API. Query time drops from seconds to milliseconds. Burp never blocks.

```
Official: AI query -> Burp API (real-time) -> Burp freezes
This:     AI query -> SQLite cache -> instant
                     ^
                Background exporter (incremental sync)
                     ^
                Burp API
```

### Other Problems That Got Fixed Along the Way

| Problem | Cause | Fix |
|---------|-------|-----|
| **Scanner results invisible to AI** | No scanner issue query API | Full scanner issue sync + query tools |
| **Large responses time out** | Huge HTTP body blocks the tool call | Async task queue + file-based chunked reading |
| **WSL / Docker / remote VM unreachable** | Hardcoded localhost check | `strictLocalhost` toggle |
| **Float-vs-int type mismatch** | AI sends `20.0` but server expects `20` | `normalizeJsonElement` auto-converts |

### What's In the Box

**SQLite Cache Layer**
- Proxy history and scanner issues cached locally
- Paginated queries, detail lookup by ID
- Incremental sync pulls only new data
- Clear cache selectively (all / HTTP only / scanner only)

**Background Exporter**
- Coroutine-driven polling, default every 5 seconds
- SHA-256 dedup (method + URL), 5-minute window merging
- Auto-prune at 100K HTTP records, 10K scanner issues

**Async Task System**
- `submit_task` -- enqueue and get a task ID immediately
- `get_task_result` -- poll for results
- `read_file` / `delete_file` -- manage large response files
- Task types: send HTTP request, create Repeater tab, send to Intruder

**Target Scope & Scanning**
- `manage_scope` -- add/remove/check Burp target scope
- `get_site_map` -- list URLs discovered by Burp (filter by prefix)
- `start_active_scan` -- trigger active audit (Pro only; scanner extensions run automatically)
- `diff_proxy_responses` -- line-level diff of two responses by ID, token-efficient

**GraphQL Recon**
- `graphql_introspect` -- fetch and cache a GraphQL schema
- `graphql_list_types` -- list all types in the cached schema
- `graphql_describe_type` -- show fields and args for one type
- `graphql_query` -- execute arbitrary queries against the target

**Better UX**
- `get_burp_info` -- edition, version, and categorized tool list at a glance
- Real-time status dashboard -- server, exporter, queue, database
- Chinese UI -- all UI text in Chinese
- Restart button -- no need to reload the extension
- `manage_auto_approve_targets` -- single merged tool to add/remove/list/clear auto-approve targets

## Screenshots

### Request Detail Review

Inspect captured requests in a focused detail view, including headers and body payloads.

![Request detail demo](docs/images/request-detail-demo.png)

### Dashboard & Server Settings

Monitor cache/export status and adjust server behavior from the built-in control panel.

![Dashboard demo](docs/images/dashboard-demo.png)

## Quick Start

### Prerequisites

- **Java 21+** (mandatory -- proxy JAR targets Java 21)
- `jar` command available

### Build

```bash
git clone https://github.com/<your-fork>/burp-mcp-enhance
cd burp-mcp-enhance
./gradlew embedProxyJar
```

Output: `build/libs/burp-mcp-all.jar` (stdio proxy JAR embedded).

### Load into Burp

1. Open Burp Suite -> Extensions tab
2. Add -> Extension Type = Java
3. Select `build/libs/burp-mcp-all.jar` -> Next
4. Enable the server in Burp's MCP tab

### Configure MCP Client

The extension listens on `127.0.0.1:9876`.

#### Streamable HTTP (Recommended, MCP 2025-03-26)

Single POST endpoint. No persistent connections. Never disconnects.

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

Works with Claude Desktop, Cursor, and any Streamable HTTP-capable client.

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

Uses the bundled `mcp-proxy-all.jar` as a stdio-SSE bridge. Requires Java 21:

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

### Info
- `get_burp_info` -- Edition, version, and full tool inventory

### HTTP
- `send_http1_request` -- Send HTTP/1.1 request (A-class plugins apply automatically)
- `send_http2_request` -- Send HTTP/2 request
- `create_repeater_tab` -- Create Repeater tab
- `send_to_intruder` -- Send to Intruder

### Proxy History
- `get_proxy_http_history` -- Live proxy history; optional `regex` param for filtering
- `get_proxy_websocket_history` -- WebSocket history; optional `regex` param

### Scope & Scanning
- `manage_scope` -- Add / remove / check URLs in Burp target scope
- `get_site_map` -- URLs discovered by Burp, filterable by prefix
- `start_active_scan` -- Trigger active audit; B-class scanner extensions run automatically *(Pro only)*

### Diff
- `diff_proxy_responses` -- Line-level diff of two responses by history ID; token-efficient

### GraphQL Recon
- `graphql_introspect` -- Fetch & cache a GraphQL schema via introspection
- `graphql_list_types` -- List all types in a cached schema
- `graphql_describe_type` -- Show fields and arguments for a specific type
- `graphql_query` -- Execute arbitrary GraphQL queries or mutations

### Cached Data (SQLite)
- `list_proxy_http_history` -- Paginated HTTP records from local cache
- `get_proxy_http_detail` -- Full request/response by ID
- `list_scanner_issues` -- Scanner issue summary from cache
- `get_scanner_issue_detail` -- Full scanner issue detail
- `exporter_stats` -- Cache status

### Pro Only (Burp Suite Professional)
- `get_scanner_issues` -- Live scanner results from Burp API
- `generate_collaborator_payload` -- Generate a Burp Collaborator OOB payload
- `get_collaborator_interactions` -- Query DNS/HTTP/SMTP callbacks for a payload

### Async Tasks
- `submit_task` -- Submit background task, get ID immediately
- `get_task_result` -- Poll task result

### File Management
- `read_file` -- Read temp file (large response chunks)
- `delete_file` -- Delete temp file

### Utilities
- `url_encode` / `url_decode` -- URL encoding
- `base64_encode` / `base64_decode` -- Base64 encoding
- `generate_random_string` -- Random string generation
- `get_active_editor_contents` -- Read the active Burp editor
- `set_active_editor_contents` -- Write to the active Burp editor

### Configuration
- `manage_auto_approve_targets` -- Add / remove / list / clear auto-approve targets (`action` param)
- `set_task_execution_engine_state` -- Pause or resume Burp's task engine
- `set_proxy_intercept_state` -- Enable or disable proxy intercept
- `clear_database` -- Clear cache (all / HTTP / scanner)

## Architecture

```
+---------------------------------------------------+
|                   Burp Suite                       |
|  +----------------------------------------------+ |
|  |          MCP Server Extension                | |
|  |  +------------------+  +-------------------+ | |
|  |  | POST /mcp        |  | GET+POST /sse     | | |
|  |  | (Streamable HTTP)|  | (SSE legacy)      | | |
|  |  +------------------+  +-------------------+ | |
|  |  +-------------+  +-----------------------+  | |
|  |  | Exporter    |->|  SQLite Database      |  | |
|  |  | (background)|  |  (local cache)        |  | |
|  |  +-------------+  +-----------------------+  | |
|  +----------------------------------------------+ |
|          ^                  ^                     |
|   HTTP POST /mcp      SSE GET /sse                |
+----------+------------------+---------------------+
           |                  |
    +------+------+    +------+------+
    | MCP Client  |    | MCP Client  |
    | (Claude etc)|    | (legacy)    |
    +-------------+    +-------------+
```

## Development

Tools are defined under `src/main/kotlin/net/portswigger/mcp/tools/`. Add a new tool:

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

# Burp Suite MCP Server -- 魔改增强版

**AI 频繁断连？Burp 数据量大就卡死？这个版本把这两个问题彻底解决了。**

基于 PortSwigger 官方 [mcp-server](https://github.com/PortSwigger/mcp-server) 深度魔改。原版有两个设计层级的硬伤，在实际渗透测试中根本没法用。这个版本从底层替换了这两套方案。

## 本版解决的两大问题

### 1. AI 几分钟就断一次

原版用 SSE（Server-Sent Events）长连接。SSE 本来就不是为请求-响应设计的，负载一高就断。自请求心跳超时、某次工具调用慢了卡住事件循环，连接直接挂。实际用起来大半时间在重连，而不是在真正用工具。

**怎么修的：** 替换成 Streamable HTTP（MCP 2025-03-26 新标准）。一个 POST 端点，纯请求-响应。没有长连接，永远不会"断连"。

```
原版：   SSE ----- 保活 ----- 保活 ----- 断开
本版：   POST -> 结束  POST -> 结束  POST -> 结束
```

### 2. Burp 数据量大直接卡死

原版每次查询都实时调 Burp API。挖洞时 Burp 里成百上千条代理记录，查一次卡一次。Burp 事件循环被阻塞，界面无响应甚至崩溃。这不是"有点慢"的问题，是超过几十条请求就直接不能用了。

**怎么修的：** 解耦架构。后台导出器轮询 Burp API，增量写入本地 SQLite。MCP 工具读缓存，不走 Burp API。查询从秒级降到毫秒级。Burp 永远不阻塞。

```
原版： AI 查询 -> Burp API（实时）-> Burp 卡死
本版： AI 查询 -> SQLite 缓存 -> 毫秒返回
                 ^
            后台导出器（增量同步）
                 ^
            Burp API
```

### 顺带修了的其他问题

| 痛点 | 原版根因 | 本版改进 |
|------|---------|---------|
| **扫描结果查不了** | 没提供扫描查询接口 | 全量扫描问题同步 + 查询工具 |
| **大响应直接超时** | 返回结果太大阻塞调用 | 异步任务队列 + 文件分块读取 |
| **WSL/Docker/远程用不了** | 写死了 localhost 检查 | `strictLocalhost` 开关 |
| **参数类型对不上** | AI 发 `20.0` 但系统要 `20` | `normalizeJsonElement` 自动转 |

### 功能一览

**SQLite 缓存层**
- 代理 HTTP 历史 + 扫描问题自动缓存到本地 SQLite
- 分页查询、按 ID 获取详情
- SHA-256 去重（method + URL），5 分钟窗口合并
- 自动清理：10 万 HTTP 记录、1 万扫描问题

**后台导出器**
- 协程驱动后台轮询，默认每 5 秒同步一次
- 游标增量同步，只拉取新数据
- 自动去重，支持扫描问题同步

**异步任务系统**
- `submit_task` -- 提交后台任务，立即返回 ID
- `get_task_result` -- 轮询获取结果
- `read_file` / `delete_file` -- 管理大文件
- 支持 HTTP 请求、创建 Repeater、发送到 Intruder

**目标范围与扫描**
- `manage_scope` -- 添加/删除/检查 Burp 目标范围
- `get_site_map` -- 列出 Burp 发现的 URL（可按前缀过滤）
- `start_active_scan` -- 触发主动扫描（Pro 专属；扫描器扩展自动运行）
- `diff_proxy_responses` -- 按 ID 对比两条响应差异行，省 Token

**GraphQL 侦察**
- `graphql_introspect` -- 获取并缓存 GraphQL schema
- `graphql_list_types` -- 列出缓存 schema 中的所有类型
- `graphql_describe_type` -- 查看指定类型的字段和参数
- `graphql_query` -- 执行任意 GraphQL 查询

**更好的 UI**
- `get_burp_info` -- 版本、版本类型与工具清单一览
- 实时状态仪表板 -- 服务器、导出器、队列、数据库一目了然
- 全中文界面
- 重启按钮 -- 不需要重载扩展
- `manage_auto_approve_targets` -- 单一合并工具管理自动放行列表（add/remove/list/clear）

## 项目展示

### 请求详情查看

可以在详情视图中直接检查捕获到的请求内容，包括请求头和请求体。

![请求详情展示](docs/images/request-detail-demo.png)

### 仪表板与服务配置

内置控制面板可以实时查看缓存/导出状态，并调整服务端行为。

![仪表板展示](docs/images/dashboard-demo.png)

## 快速开始

### 前提条件

- **Java 21+**（必须，代理 JAR 编译目标 Java 21）
- `jar` 命令可用

### 构建

```bash
git clone https://github.com/<your-fork>/burp-mcp-enhance
cd burp-mcp-enhance
./gradlew embedProxyJar
```

产物：`build/libs/burp-mcp-all.jar`（内嵌 stdio 代理）。

### 加载到 Burp

1. 打开 Burp Suite -> Extensions 标签
2. Add -> Extension Type = Java
3. 选择 `build/libs/burp-mcp-all.jar` -> Next
4. 在 Burp 的 MCP 标签页启用服务器

### 配置 MCP 客户端

扩展启动后在 `127.0.0.1:9876` 提供服务。

#### Streamable HTTP（推荐，MCP 2025-03-26 新标准）

一个 POST 端点，无持久连接，永不掉线：

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

适用于 Claude Desktop、Cursor 等支持 Streamable HTTP 的客户端。

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

使用内置 `mcp-proxy-all.jar` 桥接 stdio-SSE。需要 Java 21：

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

### 基础信息
- `get_burp_info` -- 版本类型、版本号与全量工具分类一览

### HTTP
- `send_http1_request` -- 发送 HTTP/1.1 请求（A 类插件自动生效）
- `send_http2_request` -- 发送 HTTP/2 请求
- `create_repeater_tab` -- 创建 Repeater 标签
- `send_to_intruder` -- 发送到 Intruder

### 代理历史
- `get_proxy_http_history` -- 实时代理 HTTP 历史，可选 `regex` 过滤参数
- `get_proxy_websocket_history` -- WebSocket 历史，可选 `regex` 过滤参数

### 范围与扫描
- `manage_scope` -- 添加/删除/检查目标范围
- `get_site_map` -- 列出 Burp 已发现的 URL，可按前缀过滤
- `start_active_scan` -- 触发主动扫描；B 类扫描器扩展自动运行 *(Pro 专属)*

### 差异对比
- `diff_proxy_responses` -- 按历史 ID 对比两条响应的差异行，省 Token

### GraphQL 侦察
- `graphql_introspect` -- 发送 introspection 并缓存 schema
- `graphql_list_types` -- 列出缓存 schema 中所有类型
- `graphql_describe_type` -- 查看指定类型的字段与参数
- `graphql_query` -- 执行任意 GraphQL 查询或 mutation

### 缓存数据查询（SQLite）
- `list_proxy_http_history` -- 从本地缓存分页列出 HTTP 记录
- `get_proxy_http_detail` -- 按 ID 获取完整请求/响应
- `list_scanner_issues` -- 列出缓存中的扫描问题摘要
- `get_scanner_issue_detail` -- 获取扫描问题完整详情
- `exporter_stats` -- 查看缓存状态

### Pro 专属（Burp Suite Professional）
- `get_scanner_issues` -- 实时扫描结果
- `generate_collaborator_payload` -- 生成 Burp Collaborator OOB payload
- `get_collaborator_interactions` -- 查询 DNS/HTTP/SMTP 回调

### 异步任务
- `submit_task` -- 提交后台任务，立即返回 ID
- `get_task_result` -- 查询任务结果

### 文件管理
- `read_file` -- 读取临时文件（大响应分块读取）
- `delete_file` -- 删除临时文件

### 实用工具
- `url_encode` / `url_decode` -- URL 编解码
- `base64_encode` / `base64_decode` -- Base64 编解码
- `generate_random_string` -- 随机字符串生成
- `get_active_editor_contents` -- 读取当前 Burp 编辑器内容
- `set_active_editor_contents` -- 写入当前 Burp 编辑器内容

### 配置管理
- `manage_auto_approve_targets` -- 管理自动放行列表（action: add/remove/list/clear）
- `set_task_execution_engine_state` -- 暂停/恢复 Burp 任务引擎
- `set_proxy_intercept_state` -- 启用/禁用代理拦截
- `clear_database` -- 清除缓存（全部/HTTP 历史/扫描问题）

## 架构说明

```
+---------------------------------------------------+
|                   Burp Suite                       |
|  +----------------------------------------------+ |
|  |          MCP Server Extension                | |
|  |  +------------------+  +-------------------+ | |
|  |  | POST /mcp        |  | GET+POST /sse     | | |
|  |  | (Streamable HTTP)|  | (SSE 旧版)        | | |
|  |  +------------------+  +-------------------+ | |
|  |  +-------------+  +-----------------------+  | |
|  |  | Exporter    |->|  SQLite Database      |  | |
|  |  | (后台同步)   |  |  (本地缓存)           |  | |
|  |  +-------------+  +-----------------------+  | |
|  +----------------------------------------------+ |
|          ^                  ^                     |
|   HTTP POST /mcp      SSE GET /sse                |
+----------+------------------+---------------------+
           |                  |
    +------+------+    +------+------+
    | MCP Client  |    | MCP Client  |
    | (Claude等)  |    | (旧版/代理) |
    +-------------+    +-------------+
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
