# UI HTTP 历史浏览器 + 界面清理 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在插件左侧新增类 Burp 历史记录浏览器，让用户能看到数据库里的 HTTP 流量，消除 AI 分析黑盒感，同时精简配置界面噪音。

**Architecture:** 左侧面板替换为 `HttpHistoryPanel`（状态条 + 搜索框 + JTable），点击行弹出 `HttpDetailDialog`（请求/响应 Tab）。右侧配置区做三项清理：HTTP 审批关联隐藏「自动放行目标」、「高级选项」默认折叠、插件面板布局修复。

**Tech Stack:** Kotlin, Swing (JTable, JTabbedPane, JDialog), SQLite JDBC, JUnit 5

---

## 文件总览

| 文件 | 操作 | 职责 |
|------|------|------|
| `src/main/kotlin/net/portswigger/mcp/db/HttpHistoryRow.kt` | 新建 | UI 列表行数据类（含 capturedAt） |
| `src/main/kotlin/net/portswigger/mcp/db/Database.kt` | 修改 | 新增 `queryProxyHttp()` 带过滤的查询方法 |
| `src/main/kotlin/net/portswigger/mcp/config/HttpDetailDialog.kt` | 新建 | 请求/响应详情弹出对话框 |
| `src/main/kotlin/net/portswigger/mcp/config/HttpHistoryPanel.kt` | 新建 | 左侧历史浏览器主面板（含状态条） |
| `src/main/kotlin/net/portswigger/mcp/config/StatusDashboardPanel.kt` | 删除 | 整体废弃，StatusDot/ServiceIndicatorCard 移入 HttpHistoryPanel.kt |
| `src/main/kotlin/net/portswigger/mcp/config/ConfigUi.kt` | 修改 | 左侧换为 HttpHistoryPanel，高级选项折叠，HTTP 审批联动 |
| `src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt` | 修改 | 暴露 `onHttpApprovalChanged` 回调 |
| `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt` | 修改 | `requireHttpRequestApproval` 默认值 `true` → `false` |
| `src/main/kotlin/net/portswigger/mcp/config/components/BurpPluginSupportPanel.kt` | 修改 | 修复布局宽度（lineWrap + maxSize） |
| `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt` | 修改 | 新增 queryProxyHttp 测试 |

---

## Task 1: HttpHistoryRow 数据类 + Database.queryProxyHttp()

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/db/HttpHistoryRow.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

- [ ] **Step 1: 新建 HttpHistoryRow.kt**

```kotlin
package net.portswigger.mcp.db

data class HttpHistoryRow(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val contentType: String?,
    val capturedAt: Long,
    val hitCount: Int
)
```

- [ ] **Step 2: 写失败测试**

在 `DatabaseTest.kt` 末尾追加：

```kotlin
@Test
fun `queryProxyHttp returns all rows when no filter`() {
    database.upsertProxyHttpHistory(listOf(
        ProxyHttpEntry(1, "GET", 200, "http://example.com/api/users", null, null, null, null, "application/json", null, 1000L),
        ProxyHttpEntry(2, "POST", 401, "http://example.com/auth/login", null, null, null, null, "application/json", null, 2000L)
    ))

    val rows = database.queryProxyHttp(filter = "", limit = 500)
    assertEquals(2, rows.size)
    assertEquals(2, rows[0].id)  // DESC by captured_at
    assertEquals("POST", rows[0].method)
    assertEquals(401, rows[0].status)
    assertEquals(2000L, rows[0].capturedAt)
    assertEquals(1, rows[1].id)
    assertEquals("GET", rows[1].method)
}

@Test
fun `queryProxyHttp filters by URL substring`() {
    database.upsertProxyHttpHistory(listOf(
        ProxyHttpEntry(1, "GET", 200, "http://example.com/api/users", null, null, null, null, "application/json", null, 1000L),
        ProxyHttpEntry(2, "POST", 200, "http://example.com/auth/login", null, null, null, null, "application/json", null, 2000L)
    ))

    val rows = database.queryProxyHttp(filter = "api", limit = 500)
    assertEquals(1, rows.size)
    assertEquals("GET", rows[0].method)
    assertTrue(rows[0].url.contains("api"))
}

@Test
fun `queryProxyHttp filters by method`() {
    database.upsertProxyHttpHistory(listOf(
        ProxyHttpEntry(1, "GET", 200, "http://example.com/a", null, null, null, null, null, null, 1000L),
        ProxyHttpEntry(2, "POST", 200, "http://example.com/b", null, null, null, null, null, null, 2000L)
    ))

    val rows = database.queryProxyHttp(filter = "POST", limit = 500)
    assertEquals(1, rows.size)
    assertEquals("POST", rows[0].method)
}

@Test
fun `queryProxyHttp filters by status code`() {
    database.upsertProxyHttpHistory(listOf(
        ProxyHttpEntry(1, "GET", 200, "http://example.com/a", null, null, null, null, null, null, 1000L),
        ProxyHttpEntry(2, "GET", 404, "http://example.com/b", null, null, null, null, null, null, 2000L)
    ))

    val rows = database.queryProxyHttp(filter = "404", limit = 500)
    assertEquals(1, rows.size)
    assertEquals(404, rows[0].status)
}

@Test
fun `queryProxyHttp respects limit`() {
    database.upsertProxyHttpHistory((1..10).map { i ->
        ProxyHttpEntry(i, "GET", 200, "http://example.com/$i", null, null, null, null, null, null, i.toLong())
    })

    val rows = database.queryProxyHttp(filter = "", limit = 3)
    assertEquals(3, rows.size)
}
```

- [ ] **Step 3: 运行测试确认失败**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" 2>&1 | tail -20
```

预期：编译失败（`queryProxyHttp` 未定义）

- [ ] **Step 4: 在 Database.kt 中实现 queryProxyHttp()**

在 `listProxyHttpHistory()` 方法之后（约第 356 行），追加：

```kotlin
fun queryProxyHttp(filter: String = "", limit: Int = 500): List<HttpHistoryRow> {
    connection.autoCommit = true
    val hasFilter = filter.isNotBlank()
    val sql = if (hasFilter) {
        """SELECT id, method, status, url, content_type, COALESCE(hit_count, 1) as hit_count, captured_at
           FROM proxy_http_history
           WHERE url LIKE ? OR method LIKE ? OR CAST(status AS TEXT) LIKE ?
           ORDER BY captured_at DESC LIMIT ?"""
    } else {
        """SELECT id, method, status, url, content_type, COALESCE(hit_count, 1) as hit_count, captured_at
           FROM proxy_http_history
           ORDER BY captured_at DESC LIMIT ?"""
    }
    val stmt = connection.prepareStatement(sql)
    try {
        if (hasFilter) {
            val like = "%$filter%"
            stmt.setString(1, like)
            stmt.setString(2, like)
            stmt.setString(3, like)
            stmt.setInt(4, limit)
        } else {
            stmt.setInt(1, limit)
        }
        val rs = stmt.executeQuery()
        try {
            val results = mutableListOf<HttpHistoryRow>()
            while (rs.next()) {
                results.add(
                    HttpHistoryRow(
                        id = rs.getInt("id"),
                        method = rs.getString("method"),
                        status = rs.getObject("status") as? Int,
                        url = rs.getString("url"),
                        contentType = rs.getString("content_type"),
                        capturedAt = rs.getLong("captured_at"),
                        hitCount = rs.getInt("hit_count")
                    )
                )
            }
            return results
        } finally {
            rs.close()
        }
    } finally {
        stmt.close()
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" 2>&1 | tail -20
```

预期：`BUILD SUCCESSFUL`，所有 DatabaseTest 通过

- [ ] **Step 6: 提交**

```bash
git add src/main/kotlin/net/portswigger/mcp/db/HttpHistoryRow.kt
git add src/main/kotlin/net/portswigger/mcp/db/Database.kt
git add src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt
git commit -m "feat: add HttpHistoryRow and queryProxyHttp() with text filter"
```

---

## Task 2: HttpDetailDialog — 请求/响应弹出对话框

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/config/HttpDetailDialog.kt`

> UI 组件不做单元测试，在 Task 7 整合后手动验证。

- [ ] **Step 1: 新建 HttpDetailDialog.kt**

```kotlin
package net.portswigger.mcp.config

import net.portswigger.mcp.db.ProxyHttpEntry
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import javax.swing.*

class HttpDetailDialog(
    parent: Component?,
    private val entry: ProxyHttpEntry
) : JDialog(SwingUtilities.getWindowAncestor(parent), ModalityType.APPLICATION_MODAL) {

    init {
        title = "${entry.method} ${entry.url} — ${entry.status ?: "?"}"
        defaultCloseOperation = DISPOSE_ON_CLOSE
        preferredSize = Dimension(800, 600)
        layout = BorderLayout()

        add(buildTabs(), BorderLayout.CENTER)
        add(buildFooter(), BorderLayout.SOUTH)

        pack()
        setLocationRelativeTo(parent)
    }

    private fun buildTabs(): JTabbedPane {
        val tabs = JTabbedPane()
        tabs.addTab("请求", buildRequestTab())
        tabs.addTab("响应", buildResponseTab())
        return tabs
    }

    private fun buildRequestTab(): JComponent {
        return buildSplitPane(
            top = buildTextArea(entry.requestHeaders ?: "（无请求头）"),
            bottom = buildTextArea(entry.requestBody ?: "（无请求体）")
        )
    }

    private fun buildResponseTab(): JComponent {
        return buildSplitPane(
            top = buildTextArea(entry.responseHeaders ?: "（无响应头）"),
            bottom = buildTextArea(entry.responseBody ?: "（无响应体）")
        )
    }

    private fun buildSplitPane(top: JComponent, bottom: JComponent): JSplitPane {
        return JSplitPane(JSplitPane.VERTICAL_SPLIT, wrapScroll(top), wrapScroll(bottom)).apply {
            dividerLocation = 180
            resizeWeight = 0.3
        }
    }

    private fun buildTextArea(text: String): JTextArea {
        return JTextArea(text).apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            lineWrap = false
            wrapStyleWord = false
            background = Design.Colors.surface
            foreground = Design.Colors.onSurface
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        }
    }

    private fun wrapScroll(component: JComponent): JScrollPane {
        return JScrollPane(component).apply {
            border = null
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        }
    }

    private fun buildFooter(): JPanel {
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
            add(Box.createHorizontalGlue())
            add(Design.createFilledButton("关闭").apply {
                addActionListener { dispose() }
            })
        }
    }
}
```

- [ ] **Step 2: 提交**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/HttpDetailDialog.kt
git commit -m "feat: add HttpDetailDialog for request/response detail view"
```

---

## Task 3: HttpHistoryPanel — 左侧历史浏览器主面板

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/config/HttpHistoryPanel.kt`

此文件包含：
- `HttpHistoryPanel`（主面板：状态条 + 搜索框 + 表格）
- 从 `StatusDashboardPanel.kt` 迁移过来的 `StatusDot` 和 `ServiceIndicatorCard` 类

- [ ] **Step 1: 新建 HttpHistoryPanel.kt**

```kotlin
package net.portswigger.mcp.config

import net.portswigger.mcp.ServerState
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.db.HttpHistoryRow
import net.portswigger.mcp.db.ProxyHttpEntry
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel

class HttpHistoryPanel : JPanel() {

    var database: Database? = null
    var onRestartRequested: (() -> Unit)? = null
    var onClearCacheRequested: (() -> Unit)? = null

    private val serverStatusDot = StatusDot()
    private val serverStatusLabel = JLabel("--").apply {
        font = Design.Typography.labelMedium
        foreground = Design.Colors.onSurfaceVariant
    }
    private val httpCountBadge = Design.createBadge("0", Design.Colors.tertiary)
    private val scanCountBadge = Design.createBadge("0", Design.Colors.warning)

    private val searchField = JTextField().apply {
        font = Design.Typography.bodyMedium
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(6, 8, 6, 8)
        )
        toolTipText = "搜索 URL / Method / 状态码"
    }

    private val tableModel = object : DefaultTableModel(
        arrayOf("Method", "状态", "URL", "类型", "时间", "命中"), 0
    ) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val table = JTable(tableModel)
    private val rowIds = mutableListOf<Int>()

    private var searchTimer: Timer? = null
    private var refreshTimer: Timer? = null

    init {
        layout = BorderLayout()
        background = Design.Colors.surface
        border = BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)

        add(buildStatusBar(), BorderLayout.NORTH)
        add(buildCenterPanel(), BorderLayout.CENTER)

        setupSearchDebounce()
    }

    // ── 状态条 ──────────────────────────────────────────────────────────

    private fun buildStatusBar(): JPanel {
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.SM, 0)

            add(serverStatusDot)
            add(Box.createHorizontalStrut(6))
            add(serverStatusLabel)
            add(Box.createHorizontalStrut(Design.Spacing.MD))
            add(httpCountBadge)
            add(Box.createHorizontalStrut(4))
            add(JLabel("HTTP").apply {
                font = Design.Typography.labelSmall
                foreground = Design.Colors.onSurfaceVariant
            })
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(scanCountBadge)
            add(Box.createHorizontalStrut(4))
            add(JLabel("扫描").apply {
                font = Design.Typography.labelSmall
                foreground = Design.Colors.onSurfaceVariant
            })
            add(Box.createHorizontalGlue())
            add(Design.createOutlinedButton("清缓存", Dimension(80, 30)).apply {
                addActionListener { onClearCacheRequested?.invoke() }
            })
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(Design.createFilledButton("重启", Dimension(60, 30)).apply {
                addActionListener { onRestartRequested?.invoke() }
            })
        }
    }

    // ── 搜索框 + 表格 ───────────────────────────────────────────────────

    private fun buildCenterPanel(): JPanel {
        return JPanel(BorderLayout()).apply {
            isOpaque = false

            // 搜索框
            val searchPanel = JPanel(BorderLayout()).apply {
                isOpaque = false
                border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.SM, 0)
                add(JLabel("🔍  ").apply {
                    font = Design.Typography.bodyMedium
                    foreground = Design.Colors.onSurfaceVariant
                }, BorderLayout.WEST)
                add(searchField, BorderLayout.CENTER)
            }
            add(searchPanel, BorderLayout.NORTH)

            // 表格
            configureTable()
            val scrollPane = JScrollPane(table).apply {
                border = BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1)
                verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            }
            add(scrollPane, BorderLayout.CENTER)
        }
    }

    private fun configureTable() {
        table.apply {
            font = Design.Typography.bodyMedium
            rowHeight = 26
            showGrid = false
            intercellSpacing = Dimension(0, 0)
            background = Design.Colors.listBackground
            foreground = Design.Colors.onSurface
            selectionBackground = Design.Colors.listSelectionBackground
            selectionForeground = Design.Colors.listSelectionForeground
            tableHeader.font = Design.Typography.labelMedium
            tableHeader.foreground = Design.Colors.onSurface
            setDefaultRenderer(Any::class.java, HistoryTableCellRenderer())
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        }

        // 列宽
        table.columnModel.apply {
            getColumn(0).preferredWidth = 70;  getColumn(0).maxWidth = 70   // Method
            getColumn(1).preferredWidth = 55;  getColumn(1).maxWidth = 55   // 状态
            getColumn(2).preferredWidth = 500                                // URL（扩展）
            getColumn(3).preferredWidth = 90;  getColumn(3).maxWidth = 90   // 类型
            getColumn(4).preferredWidth = 75;  getColumn(4).maxWidth = 75   // 时间
            getColumn(5).preferredWidth = 45;  getColumn(5).maxWidth = 45   // 命中
        }

        // 双击打开详情
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) {
                    val row = table.selectedRow
                    if (row >= 0 && row < rowIds.size) {
                        openDetail(rowIds[row])
                    }
                }
            }
        })
    }

    private fun openDetail(id: Int) {
        val entry = database?.getProxyHttpDetail(listOf(id))?.firstOrNull() ?: return
        val dialog = HttpDetailDialog(this, entry)
        dialog.isVisible = true
    }

    // ── 搜索防抖 ────────────────────────────────────────────────────────

    private fun setupSearchDebounce() {
        searchField.document.addDocumentListener(object : javax.swing.event.DocumentListener {
            override fun insertUpdate(e: javax.swing.event.DocumentEvent?) = scheduleSearch()
            override fun removeUpdate(e: javax.swing.event.DocumentEvent?) = scheduleSearch()
            override fun changedUpdate(e: javax.swing.event.DocumentEvent?) = scheduleSearch()
        })
    }

    private fun scheduleSearch() {
        searchTimer?.stop()
        searchTimer = Timer(300) { loadData() }.apply { isRepeats = false; start() }
    }

    // ── 数据加载 ────────────────────────────────────────────────────────

    fun loadData() {
        val db = database ?: return
        val filter = searchField.text.trim()
        val rows = db.queryProxyHttp(filter = filter, limit = 500)
        SwingUtilities.invokeLater { updateTable(rows) }

        val stats = db.stats()
        SwingUtilities.invokeLater {
            httpCountBadge.text = stats.proxyHttpCount.toString()
            scanCountBadge.text = stats.scannerIssueCount.toString()
        }
    }

    private fun updateTable(rows: List<HttpHistoryRow>) {
        tableModel.setRowCount(0)
        rowIds.clear()
        val fmt = SimpleDateFormat("HH:mm:ss")
        for (row in rows) {
            val contentType = row.contentType?.substringBefore(";")?.substringAfterLast("/")?.take(12) ?: ""
            val time = fmt.format(Date(row.capturedAt))
            val hits = if (row.hitCount > 1) row.hitCount.toString() else ""
            tableModel.addRow(arrayOf(row.method, row.status?.toString() ?: "?", row.url, contentType, time, hits))
            rowIds.add(row.id)
        }
    }

    // ── 外部 API ────────────────────────────────────────────────────────

    fun updateServerState(state: ServerState) {
        when (state) {
            ServerState.Starting  -> { serverStatusDot.color = StatusDot.ColorYELLOW; serverStatusDot.isPulsing = false; serverStatusLabel.text = "启动中" }
            ServerState.Running   -> { serverStatusDot.color = StatusDot.ColorGREEN;  serverStatusDot.isPulsing = true;  serverStatusLabel.text = "运行中" }
            ServerState.Stopping  -> { serverStatusDot.color = StatusDot.ColorYELLOW; serverStatusDot.isPulsing = false; serverStatusLabel.text = "停止中" }
            ServerState.Stopped   -> { serverStatusDot.color = StatusDot.ColorGRAY;   serverStatusDot.isPulsing = false; serverStatusLabel.text = "已停止" }
            is ServerState.Failed -> { serverStatusDot.color = StatusDot.ColorRED;    serverStatusDot.isPulsing = false; serverStatusLabel.text = "启动失败" }
        }
    }

    fun startRefreshing() {
        loadData()
        refreshTimer?.stop()
        refreshTimer = Timer(5000) { loadData() }.apply { start() }
    }

    fun stopRefreshing() {
        refreshTimer?.stop()
        refreshTimer = null
        searchTimer?.stop()
        searchTimer = null
    }
}

// ── 表格单元格渲染器 ─────────────────────────────────────────────────────────

private class HistoryTableCellRenderer : DefaultTableCellRenderer() {
    private val statusGreen  = Color(0x2E7D32)
    private val statusOrange = Color(0xE65100)
    private val statusRed    = Color(0xB71C1C)
    private val even         = UIManager.getColor("List.background")   ?: Color.WHITE
    private val odd          = UIManager.getColor("List.alternateRowColor") ?: Color(0xFAFAFA)

    override fun getTableCellRendererComponent(
        table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
    ): Component {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        border = BorderFactory.createEmptyBorder(0, 6, 0, 6)
        if (!isSelected) {
            background = if (row % 2 == 0) even else odd
            foreground = if (column == 1) statusColor(value?.toString()) else Design.Colors.onSurface
        }
        return this
    }

    private fun statusColor(status: String?): Color {
        val code = status?.toIntOrNull() ?: return Design.Colors.onSurface
        return when {
            code in 200..299 -> statusGreen
            code in 400..499 -> statusOrange
            code >= 500       -> statusRed
            else              -> Design.Colors.onSurface
        }
    }
}

// ── StatusDot（从 StatusDashboardPanel.kt 迁移）─────────────────────────────

class StatusDot : JComponent() {
    var color: Color = ColorGRAY
        set(value) { field = value; repaint() }

    var isPulsing: Boolean = false
        set(value) {
            if (field != value) { field = value; if (value) startPulse() else stopPulse() }
        }

    private var pulseTimer: Timer? = null
    private var pulsePhase = 0f

    override fun getPreferredSize(): Dimension = Dimension(14, 14)
    override fun getMinimumSize():   Dimension = Dimension(14, 14)

    private fun startPulse() {
        pulseTimer?.stop()
        pulseTimer = Timer(30) { pulsePhase = (pulsePhase + 0.08f) % (Math.PI * 2).toFloat(); repaint() }
        pulseTimer?.start()
    }

    private fun stopPulse() {
        pulseTimer?.stop(); pulseTimer = null; pulsePhase = 0f; repaint()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        val size   = if (isPulsing) (14f * (Math.sin(pulsePhase.toDouble()) * 0.15 + 0.85).toFloat()) else 14f
        val offset = (14 - size) / 2f
        val cy     = (height - 14) / 2f
        g2.color = if (isPulsing) {
            val alpha = ((Math.sin(pulsePhase.toDouble()) * 0.3 + 0.7).toFloat() * 255).toInt()
            Color(color.red, color.green, color.blue, alpha)
        } else color
        g2.fillOval(offset.toInt(), (cy + offset).toInt(), size.toInt(), size.toInt())
        g2.dispose()
    }

    companion object {
        val ColorGREEN  = Color(0x4CAF50)
        val ColorYELLOW = Color(0xFFC107)
        val ColorRED    = Color(0xF44336)
        val ColorGRAY   = Color(0x9E9E9E)
        val ColorBLUE   = Color(0x2196F3)
    }
}
```

- [ ] **Step 2: 编译检查**

```bash
.\gradlew.bat compileKotlin 2>&1 | tail -20
```

预期：`BUILD SUCCESSFUL`

- [ ] **Step 3: 提交**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/HttpHistoryPanel.kt
git add src/main/kotlin/net/portswigger/mcp/config/HttpDetailDialog.kt
git commit -m "feat: add HttpHistoryPanel and HttpDetailDialog"
```

---

## Task 4: McpConfig 默认值修改 + ServerConfigurationPanel 暴露回调

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt`
- Test: `src/test/kotlin/net/portswigger/mcp/config/McpConfigTest.kt`

- [ ] **Step 1: 查看 McpConfigTest.kt，确认测试不会因默认值变更而失败**

读取 `src/test/kotlin/net/portswigger/mcp/config/McpConfigTest.kt` — 如果有测试依赖 `requireHttpRequestApproval == true`，先更新那些测试。

- [ ] **Step 2: 修改 McpConfig.kt 第 34 行**

将：
```kotlin
var requireHttpRequestApproval by storage.boolean(true)
```
改为：
```kotlin
var requireHttpRequestApproval by storage.boolean(false)
```

- [ ] **Step 3: 在 ServerConfigurationPanel.kt 中追加回调属性和调用**

在类顶部的 `private lateinit var` 声明区域之后（约第 26 行），追加：

```kotlin
var onHttpApprovalChanged: ((Boolean) -> Unit)? = null
```

然后找到 `createStandardCheckBox("HTTP 请求需要审批", config.requireHttpRequestApproval)` 的 onChange lambda（约第 50-53 行），修改为：

```kotlin
val httpRequestApprovalCheckBox = createStandardCheckBox(
    "HTTP 请求需要审批", config.requireHttpRequestApproval
) { enabled ->
    config.requireHttpRequestApproval = enabled
    onHttpApprovalChanged?.invoke(enabled)
}
```

- [ ] **Step 4: 运行所有测试确认通过**

```bash
.\gradlew.bat test 2>&1 | tail -20
```

预期：`BUILD SUCCESSFUL`

- [ ] **Step 5: 提交**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt
git add src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt
git commit -m "feat: default HTTP approval to false, expose onHttpApprovalChanged callback"
```

---

## Task 5: ConfigUi 重构 — 左侧换面板 + 高级选项折叠 + HTTP 审批联动

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/ConfigUi.kt`

- [ ] **Step 1: 替换 statusDashboard 字段为 httpHistoryPanel**

将顶部的字段声明：
```kotlin
private val statusDashboard = StatusDashboardPanel()
```
改为：
```kotlin
private val httpHistoryPanel = HttpHistoryPanel()
```

- [ ] **Step 2: 更新 bindInfrastructure() 和 unbindInfrastructure()**

将整个 `bindInfrastructure` 方法替换为：

```kotlin
fun bindInfrastructure(
    messageQueue: Any?,
    fileQueue: Any?,
    database: Any?,
    exporter: Any?,
    activeConnectionProvider: (() -> Int)? = null
) {
    httpHistoryPanel.database = database as? net.portswigger.mcp.db.Database
    httpHistoryPanel.onRestartRequested = { restartServerListener?.invoke() }
    httpHistoryPanel.onClearCacheRequested = {
        val result = Dialogs.showConfirmDialog(
            panel, "确定要清除所有缓存数据吗？\n此操作不可撤销。",
            javax.swing.JOptionPane.YES_NO_OPTION
        )
        if (result == javax.swing.JOptionPane.YES_OPTION) {
            (database as? net.portswigger.mcp.db.Database)?.clearAll()
            httpHistoryPanel.loadData()
        }
    }
    httpHistoryPanel.startRefreshing()
}
```

将 `unbindInfrastructure` 方法替换为：

```kotlin
fun unbindInfrastructure() {
    httpHistoryPanel.stopRefreshing()
    httpHistoryPanel.database = null
}
```

- [ ] **Step 3: 更新 updateServerState() 中的引用**

将 `statusDashboard.updateServerState(state)` 改为 `httpHistoryPanel.updateServerState(state)`

- [ ] **Step 3b: 更新 cleanup() 方法**

将 `cleanup()` 方法（约第 133 行）中的 `statusDashboard.stopRefreshing()` 改为 `httpHistoryPanel.stopRefreshing()`：

```kotlin
fun cleanup() {
    httpHistoryPanel.stopRefreshing()
    listenerHandles.forEach { it.remove() }
    listenerHandles.clear()

    if (::autoApproveTargetsPanel.isInitialized) {
        autoApproveTargetsPanel.cleanup()
    }
}
```

- [ ] **Step 4: 新增可折叠容器辅助方法**

在 `ConfigUi` 类末尾（`buildUi()` 之前或之后）新增：

```kotlin
private fun buildCollapsibleCard(content: JComponent, title: String): JPanel {
    var expanded = false
    val arrowLabel = JLabel("▶").apply {
        font = Design.Typography.labelMedium
        foreground = Design.Colors.onSurfaceVariant
    }
    val contentWrapper = JPanel(BorderLayout()).apply {
        isOpaque = false
        add(content, BorderLayout.CENTER)
        isVisible = false
    }

    val headerPanel = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        isOpaque = false
        border = BorderFactory.createEmptyBorder(Design.Spacing.SM, 0, Design.Spacing.SM, 0)
        cursor = java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)
        add(JLabel(title).apply {
            font = Design.Typography.titleMedium
            foreground = Design.Colors.onSurface
        })
        add(Box.createHorizontalGlue())
        add(arrowLabel)
    }

    val toggle = {
        expanded = !expanded
        contentWrapper.isVisible = expanded
        arrowLabel.text = if (expanded) "▼" else "▶"
        contentWrapper.parent?.revalidate()
        contentWrapper.parent?.repaint()
    }

    headerPanel.addMouseListener(object : java.awt.event.MouseAdapter() {
        override fun mouseClicked(e: java.awt.event.MouseEvent) = toggle()
    })

    val card = Design.createCard(JPanel(BorderLayout()).apply {
        isOpaque = false
        add(headerPanel, BorderLayout.NORTH)
        add(contentWrapper, BorderLayout.CENTER)
    })
    return card
}
```

- [ ] **Step 5: 重写 buildUi()**

将 `buildUi()` 方法替换为：

```kotlin
private fun buildUi() {
    val leftPanel = JPanel(BorderLayout()).apply {
        background = Design.Colors.surface
        add(httpHistoryPanel, BorderLayout.CENTER)
    }

    val rightPanelContent = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = Design.Colors.surface
        border = BorderFactory.createEmptyBorder(
            Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG
        )
    }

    val rightPanel = JScrollPane(rightPanelContent).apply {
        border = null
        background = Design.Colors.surface
        viewport.background = Design.Colors.surface
        verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        verticalScrollBar.unitIncrement = 16
    }

    // 服务器配置卡片
    rightPanelContent.add(Design.createCard(serverConfigurationPanel, "服务器配置"))
    rightPanelContent.add(createVerticalStrut(Design.Spacing.MD))

    // HTTP 自动放行目标卡片（初始可见性由 requireHttpRequestApproval 决定）
    val autoApproveCard = Design.createCard(autoApproveTargetsPanel, "HTTP 自动放行目标").also {
        it.isVisible = config.requireHttpRequestApproval
    }
    rightPanelContent.add(autoApproveCard)
    // 只在 autoApproveCard 可见时需要间距
    val autoApproveStrut = createVerticalStrut(Design.Spacing.MD).also {
        it.isVisible = config.requireHttpRequestApproval
    }
    rightPanelContent.add(autoApproveStrut)

    // 订阅 HTTP 审批变更
    serverConfigurationPanel.onHttpApprovalChanged = { enabled ->
        autoApproveCard.isVisible = enabled
        autoApproveStrut.isVisible = enabled
        rightPanelContent.revalidate()
        rightPanelContent.repaint()
    }

    // 高级选项（默认折叠）
    rightPanelContent.add(buildCollapsibleCard(advancedOptionsPanel, "高级选项"))
    rightPanelContent.add(createVerticalStrut(Design.Spacing.MD))

    rightPanelContent.add(Design.createCard(installationPanel, "安装"))
    rightPanelContent.add(createVerticalStrut(Design.Spacing.MD))
    rightPanelContent.add(Design.createCard(burpPluginSupportPanel, "第三方插件支持"))
    rightPanelContent.add(createVerticalStrut(Design.Spacing.SM))
    rightPanelContent.add(reinstallNotice)
    rightPanelContent.add(createVerticalGlue())

    val columnsPanel = ResponsiveColumnsPanel(leftPanel, rightPanel)
    panel.add(columnsPanel, BorderLayout.CENTER)
}
```

- [ ] **Step 6: 编译检查**

```bash
.\gradlew.bat compileKotlin 2>&1 | tail -30
```

预期：`BUILD SUCCESSFUL`（可能有 StatusDashboardPanel 未使用的 import 警告，下一步删除）

- [ ] **Step 7: 提交**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/ConfigUi.kt
git commit -m "feat: replace left panel with HttpHistoryPanel, add collapsible advanced options, wire HTTP approval visibility"
```

---

## Task 6: 删除 StatusDashboardPanel.kt

**Files:**
- Delete: `src/main/kotlin/net/portswigger/mcp/config/StatusDashboardPanel.kt`

- [ ] **Step 1: 全局搜索 StatusDashboardPanel 引用**

```bash
grep -r "StatusDashboardPanel\|statusDashboard" src/ --include="*.kt" -l
```

确认只剩 `StatusDashboardPanel.kt` 本身，其他文件已无引用。

- [ ] **Step 2: 删除文件**

```bash
git rm src/main/kotlin/net/portswigger/mcp/config/StatusDashboardPanel.kt
```

- [ ] **Step 3: 编译 + 测试**

```bash
.\gradlew.bat test 2>&1 | tail -20
```

预期：`BUILD SUCCESSFUL`

- [ ] **Step 4: 提交**

```bash
git commit -m "chore: remove StatusDashboardPanel (replaced by HttpHistoryPanel)"
```

---

## Task 7: BurpPluginSupportPanel 布局修复

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/components/BurpPluginSupportPanel.kt`

- [ ] **Step 1: 修复 refreshRow 里说明文字的宽度**

找到 `buildPanel()` 中的 `refreshRow` 部分（约第 48-65 行），将说明文字的 `JTextArea` 创建改为：

```kotlin
val infoText = Design.createReadOnlyTextArea(
    "如果 Burp 没暴露完整扩展信息，可以在下面补充插件名。",
    font = Design.Typography.labelMedium,
    foreground = Design.Colors.onSurfaceVariant
).apply {
    lineWrap = true
    wrapStyleWord = true
    maximumSize = Dimension(300, Int.MAX_VALUE)
}
refreshRow.add(infoText)
```

（将原来的 `refreshRow.add(Design.createReadOnlyTextArea(...))` 替换为上面的代码）

- [ ] **Step 2: 修复 configuredPluginsArea 的换行和滚动**

找到 `buildPanel()` 中 `add(configuredPluginsArea)` 的位置（约第 82 行），将直接添加改为用 JScrollPane 包裹：

```kotlin
configuredPluginsArea.apply {
    lineWrap = true
    wrapStyleWord = true
}
val configuredPluginsScroll = JScrollPane(configuredPluginsArea).apply {
    alignmentX = LEFT_ALIGNMENT
    maximumSize = Dimension(Int.MAX_VALUE, 120)
    preferredSize = Dimension(400, 100)
    verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
    horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
    border = BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1)
}
add(configuredPluginsScroll)
```

- [ ] **Step 3: 编译检查**

```bash
.\gradlew.bat compileKotlin 2>&1 | tail -20
```

预期：`BUILD SUCCESSFUL`

- [ ] **Step 4: 提交**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/components/BurpPluginSupportPanel.kt
git commit -m "fix: constrain BurpPluginSupportPanel text areas width to prevent layout overflow"
```

---

## Task 8: 全量测试 + 构建验证

- [ ] **Step 1: 运行所有测试**

```bash
.\gradlew.bat test 2>&1 | tail -30
```

预期：`BUILD SUCCESSFUL`，所有测试通过

- [ ] **Step 2: 构建完整 JAR**

```bash
.\gradlew.bat shadowJar 2>&1 | tail -10
```

预期：`BUILD SUCCESSFUL`，输出 `build/libs/burp-mcp-all.jar`

- [ ] **Step 3: 手动验证清单（加载到 Burp Suite 后逐项确认）**

- [ ] 左侧面板显示状态条（指示灯 + HTTP/扫描条数 + 清缓存/重启按钮）
- [ ] 左侧面板显示搜索框和 HTTP 历史表格
- [ ] 表格按 `captured_at` 降序，状态码带颜色
- [ ] 搜索框输入后 300ms 刷新列表
- [ ] 双击行弹出对话框，显示请求/响应两个 Tab
- [ ] 对话框标题为 `METHOD URL — 状态码`，关闭按钮正常
- [ ] 右侧「HTTP 请求需要审批」默认未勾选
- [ ] 勾选「HTTP 请求需要审批」后「HTTP 自动放行目标」卡片出现；取消勾选后隐藏
- [ ] 「高级选项」卡片默认折叠，点击标题展开/收起正常
- [ ] 「第三方插件支持」面板「手工补充插件名」文字不再溢出屏幕右侧
- [ ] 清缓存按钮弹确认框，确认后刷新列表

- [ ] **Step 4: 最终提交（如有遗留改动）**

```bash
git status
# 如有遗留文件
git add <files>
git commit -m "chore: final cleanup after UI history browser integration"
```
