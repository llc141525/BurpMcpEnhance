# UI 设计规格：HTTP 历史浏览器 + 界面清理

**日期**：2026-06-20  
**目标**：解决 AI 分析黑盒问题（用户看不到 AI 读取了什么请求），同时精简配置界面的视觉噪音。

---

## 背景与动机

当前 AI（通过 MCP 工具）读取数据库中的 HTTP 历史记录进行安全分析，但用户无法在插件界面中直接看到数据库里有哪些请求、AI 实际分析了什么。原始请求/响应对用户不可见，整个过程是黑盒。

本次改动的根本目的：**让用户能看到数据库中的 HTTP 流量，消除黑盒感**。

---

## 变更一：左侧面板重构为 HTTP 历史浏览器

### 1.1 整体布局（从上到下）

```
┌─────────────────────────────────────────────────┐
│ ● 运行中  HTTP 1234  扫描 56  [清缓存] [重启]       │  状态条（~40px 固定高度）
├─────────────────────────────────────────────────┤
│ 🔍 搜索 URL / Method / 状态码...                  │  搜索框
├─────────────────────────────────────────────────┤
│ Method │ 状态 │ URL                │ 类型 │ 时间  │  表头
│ GET    │ 200  │ /api/users         │ json │ 12:34 │
│ POST   │ 401  │ /auth/login        │ json │ 12:33 │
│ DELETE │ 500  │ /api/item/42       │ json │ 12:31 │
│ ...                                             │
└─────────────────────────────────────────────────┘
```

### 1.2 状态条

- 内容：服务器状态指示灯（StatusDot）+ 状态文字 + HTTP 条数 badge + 扫描条数 badge + 「清缓存」按钮 + 「重启服务器」按钮
- 固定在顶部，不随表格滚动
- 状态信息从 `StatusDashboardPanel` 已有逻辑中提取最核心部分复用

### 1.3 搜索框

- 单行文本输入框，placeholder：`搜索 URL / Method / 状态码…`
- 输入后 300ms 防抖触发过滤
- 过滤逻辑：URL 子串匹配（大小写不敏感）OR Method 完全/前缀匹配 OR 状态码匹配

### 1.4 表格列定义

| 列名 | 数据来源 | 宽度策略 | 备注 |
|------|---------|---------|------|
| Method | `method` | 固定 70px | 大写文字 |
| 状态码 | `status` | 固定 60px | 2xx 绿色 / 4xx 橙色 / 5xx 红色 |
| URL | `url` | 自动扩展填充 | 超长截断 + tooltip 显示完整 |
| 类型 | `content_type` | 固定 90px | 只取主类型，如 `json`、`html` |
| 时间 | `captured_at` | 固定 80px | 格式 `HH:mm:ss` |
| 命中 | `hit_count` | 固定 50px | 去重次数，> 1 时显示 |

- 表格使用 `JTable` + `DefaultTableModel`，行不可编辑
- 默认按 `captured_at` 降序（最新在上）
- 点击列头不排序（简化实现，可后续迭代）

### 1.5 数据加载

- 初始加载最多 500 条（防止大数据集卡顿）
- 在 `Database` 新增方法：
  ```kotlin
  fun queryProxyHttp(filter: String = "", limit: Int = 500): List<ProxyHttpRow>
  ```
  SQL：`SELECT id, method, status, url, content_type, captured_at, hit_count FROM proxy_http_history WHERE url LIKE ? OR method LIKE ? OR CAST(status AS TEXT) LIKE ? ORDER BY captured_at DESC LIMIT ?`
- 左侧面板通过 `StatusDashboardPanel` 现有的 3 秒刷新定时器联动刷新列表（或独立定时器，间隔 5s）

### 1.6 点击行 → 详情弹出对话框

- 触发：双击表格行（单击选中行，双击打开详情）
- 对话框标题：`{METHOD} {URL} — {状态码}`
- 大小：800×600，可拖拽调整，居中于父窗口
- 内容：两个 Tab
  - **请求 Tab**：请求头（只读 `JTextArea`）+ 分隔线 + 请求体（只读 `JTextArea`）
  - **响应 Tab**：响应头（只读 `JTextArea`）+ 分隔线 + 响应体（只读 `JTextArea`）
- 文本区使用等宽字体（`monospaced`），支持纵向滚动
- 底部：「关闭」按钮

### 1.7 新增文件

- `src/main/kotlin/net/portswigger/mcp/config/HttpHistoryPanel.kt` — 左侧主面板
- `src/main/kotlin/net/portswigger/mcp/config/HttpDetailDialog.kt` — 详情对话框
- `src/main/kotlin/net/portswigger/mcp/db/ProxyHttpRow.kt` — 查询结果数据类

### 1.8 删除/废弃

- `StatusDashboardPanel.kt` **删除**（整个 class 不再使用）。`StatusDot` 和 `ServiceIndicatorCard` 类可保留在同文件末尾供 `HttpHistoryPanel` 复用，或移入 `HttpHistoryPanel.kt`。
- 原来的 6 个指标卡（消息队列、文件队列、数据库、导出器、客户端、缓存总览）**不再展示**；仅在状态条保留：服务器状态指示灯、HTTP/扫描条数 badge、清缓存/重启按钮。
- `ConfigUi.bindInfrastructure()` / `unbindInfrastructure()` 中对 `statusDashboard` 的引用改为对 `httpHistoryPanel` 的引用。

---

## 变更二：HTTP 审批联动隐藏「自动放行目标」

### 逻辑

- 「HTTP 请求需要审批」checkbox 默认 **不勾选**（`McpConfig.requireHttpRequestApproval` 当前默认值为 `true`，需改为 `false`）
- 「HTTP 自动放行目标」卡片（`autoApproveTargetsPanel` 所在 Card）初始 `isVisible = config.requireHttpRequestApproval`
- `ServerConfigurationPanel` 向外暴露回调 `onHttpApprovalChanged: ((Boolean) -> Unit)?`，在 HTTP 审批 checkbox 的 `onChange` 中调用
- `ConfigUi` 订阅该回调，动态设置卡片 `isVisible` 并调用 `revalidate()` + `repaint()`

### 效果

- 用户不需要审批 HTTP 时，界面上看不到「自动放行目标」，减少视觉噪音
- 勾选「HTTP 请求需要审批」后，「自动放行目标」卡片即时出现

---

## 变更三：「高级选项」卡片默认折叠

### 实现方式

在 `ConfigUi.buildUi()` 中，对「高级选项」卡片单独包一个可折叠容器（不修改 `Design.createCard()`，避免影响其他卡片）：

```
┌── 高级选项 ──────────────────────────── [▶ 展开] ┐
│  (内容默认隐藏)                                   │
└───────────────────────────────────────────────────┘

点击后：

┌── 高级选项 ──────────────────────────── [▼ 收起] ┐
│  服务器主机: [________]                           │
│  服务器端口: [____]                               │
│  ...                                             │
└───────────────────────────────────────────────────┘
```

- 标题行是一个可点击的 `JPanel`（FlowLayout），右侧放箭头 `JLabel`（`▶`/`▼`）
- 点击整行触发切换，内容区 `isVisible` 取反 + `revalidate()` + `repaint()`
- 状态不持久化（每次插件加载默认收缩）

---

## 变更四：第三方插件面板布局修复

### 问题

`BurpPluginSupportPanel` 中：
1. `refreshRow` 里的说明 `JTextArea` 无宽度限制，撑满行导致文字溢出屏幕右侧
2. `configuredPluginsArea`（手工补充插件名）无换行设置，内容超宽

### 修复

- `refreshRow` 里的说明文字 `JTextArea`：设置 `lineWrap = true`、`wrapStyleWord = true`，并用 `maximumSize = Dimension(280, Int.MAX_VALUE)` 限制最大宽度
- `configuredPluginsArea`：设置 `lineWrap = true`、`wrapStyleWord = true`，用 `JScrollPane` 包裹后加 `maximumSize = Dimension(Int.MAX_VALUE, 120)`
- 整个面板添加 `alignmentX = LEFT_ALIGNMENT` 确认

---

## 文件改动汇总

| 文件 | 操作 | 说明 |
|------|------|------|
| `HttpHistoryPanel.kt` | 新增 | 左侧历史浏览器主面板 |
| `HttpDetailDialog.kt` | 新增 | 请求/响应详情弹窗 |
| `ProxyHttpRow.kt` | 新增 | DB 查询结果数据类 |
| `Database.kt` | 修改 | 新增 `queryProxyHttp()` 方法 |
| `ConfigUi.kt` | 修改 | 左侧替换为 HttpHistoryPanel，联动逻辑，折叠容器 |
| `ServerConfigurationPanel.kt` | 修改 | 暴露 `onHttpApprovalChanged` 回调 |
| `BurpPluginSupportPanel.kt` | 修改 | 修复布局宽度问题 |
| `StatusDashboardPanel.kt` | 删除（StatusDot/ServiceIndicatorCard 移入 HttpHistoryPanel.kt） | 整个面板不再使用 |

---

## 不在本次范围内

- 历史记录列头排序
- 历史记录翻页（limit 500 先够用）
- 请求/响应内容语法高亮
- 导出/复制功能
