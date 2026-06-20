package net.portswigger.mcp.config

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.db.HttpHistoryRow
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
    var onReimportRequested: (() -> Unit)? = null
    var activeConnectionProvider: (() -> Int)? = null
    var serverUrlProvider: (() -> String)? = null

    private val serverStatusDot = StatusDot()
    private val serverStatusLabel = JLabel("--").apply {
        font = Design.Typography.labelMedium
        foreground = Design.Colors.onSurfaceVariant
    }
    private val httpCountBadge = Design.createBadge("HTTP 0", Design.Colors.tertiary)
    private val scanCountBadge = Design.createBadge("扫描 0", Design.Colors.warning)
    private val connCountBadge = Design.createBadge("连 0", Design.Colors.primary)
    private val rawDupCountBadge = Design.createBadge("副本 0", Design.Colors.onSurfaceVariant)
    private val serverAddrLabel = JLabel("").apply {
        font = Design.Typography.labelMedium
        foreground = Design.Colors.onSurfaceVariant
    }

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
    private val timeFmt = SimpleDateFormat("HH:mm:ss")
    private lateinit var tableScrollPane: JScrollPane

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
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(serverAddrLabel)
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(httpCountBadge)
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(scanCountBadge)
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(connCountBadge)
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(rawDupCountBadge)
            add(Box.createHorizontalGlue())
            add(Design.createOutlinedButton("导入").apply {
                toolTipText = "重新导入 Burp 历史记录"
                addActionListener { onReimportRequested?.invoke() }
            })
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(Design.createOutlinedButton("清空").apply {
                toolTipText = "清除所有缓存数据"
                addActionListener { onClearCacheRequested?.invoke() }
            })
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(Design.createFilledButton("重启").apply {
                toolTipText = "重启 MCP 服务器"
                addActionListener { onRestartRequested?.invoke() }
            })
        }
    }

    // ── 搜索框 + 表格 ───────────────────────────────────────────────────

    private fun buildCenterPanel(): JPanel {
        return JPanel(BorderLayout()).apply {
            isOpaque = false

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

            configureTable()
            tableScrollPane = JScrollPane(table).apply {
                border = BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1)
                verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            }
            tableScrollPane.addComponentListener(object : java.awt.event.ComponentAdapter() {
                override fun componentResized(e: java.awt.event.ComponentEvent) = resizeUrlColumn()
            })
            add(tableScrollPane, BorderLayout.CENTER)
        }
    }

    private fun configureTable() {
        table.apply {
            font = Design.Typography.bodyMedium
            rowHeight = 26
            setShowGrid(false)
            intercellSpacing = Dimension(0, 0)
            background = Design.Colors.listBackground
            foreground = Design.Colors.onSurface
            selectionBackground = Design.Colors.listSelectionBackground
            selectionForeground = Design.Colors.listSelectionForeground
            tableHeader.font = Design.Typography.labelMedium
            tableHeader.foreground = Design.Colors.onSurface
            setDefaultRenderer(Any::class.java, HistoryTableCellRenderer())
            autoResizeMode = JTable.AUTO_RESIZE_OFF
            autoCreateRowSorter = true
        }

        table.columnModel.apply {
            getColumn(0).apply { minWidth = 52; preferredWidth = 58; maxWidth = 70 }    // Method
            getColumn(1).apply { minWidth = 38; preferredWidth = 42; maxWidth = 50 }    // 状态
            // column 2 = URL managed by resizeUrlColumn()
            getColumn(3).apply { minWidth = 42; preferredWidth = 50; maxWidth = 60 }    // 类型
            getColumn(4).apply { minWidth = 72; preferredWidth = 80; maxWidth = 92 }    // 时间 (HH:mm:ss needs ~76px)
            getColumn(5).apply { minWidth = 28; preferredWidth = 32; maxWidth = 40 }    // 命中
        }

        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) {
                    val viewRow = table.selectedRow
                    if (viewRow >= 0) {
                        val modelRow = table.convertRowIndexToModel(viewRow)
                        if (modelRow < rowIds.size) {
                            openDetail(rowIds[modelRow])
                        }
                    }
                }
            }
        })
    }

    private fun openDetail(id: Int) {
        val db = database ?: return
        CoroutineScope(Dispatchers.IO).launch {
            val entry = db.getProxyHttpDetail(listOf(id), includeDuplicates = true).firstOrNull() ?: return@launch
            SwingUtilities.invokeLater {
                val dialog = HttpDetailDialog(this@HttpHistoryPanel, entry)
                dialog.isVisible = true
            }
        }
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

    private fun resizeUrlColumn() {
        val fixed = 58 + 42 + 50 + 80 + 32   // Method + Status + Type + Time + Hit
        val available = if (::tableScrollPane.isInitialized) tableScrollPane.viewport.width else 0
        if (available > 0) {
            val urlWidth = maxOf(100, available - fixed)
            table.columnModel.getColumn(2).let {
                it.preferredWidth = urlWidth
                it.width = urlWidth
            }
        }
    }

    // ── 数据加载 ────────────────────────────────────────────────────────

    fun loadData() {
        val db = database ?: return
        val filter = searchField.text.trim()
        val connCount = activeConnectionProvider?.invoke() ?: 0
        CoroutineScope(Dispatchers.IO).launch {
            val rows = db.queryProxyHttp(filter = filter, limit = 500)
            val stats = db.stats()
            SwingUtilities.invokeLater {
                updateTable(rows)
                httpCountBadge.text = "HTTP ${stats.proxyHttpCount}"
                scanCountBadge.text = "扫描 ${stats.scannerIssueCount}"
                connCountBadge.text = "连 $connCount"
                rawDupCountBadge.text = "副本 ${stats.rawDuplicateCount}"
                val addr = serverUrlProvider?.invoke()?.let { "· $it" } ?: ""
                serverAddrLabel.text = addr
            }
        }
    }

    private fun updateTable(rows: List<HttpHistoryRow>) {
        tableModel.setRowCount(0)
        rowIds.clear()
        for (row in rows) {
            val contentType = row.contentType?.substringBefore(";")?.substringAfterLast("/")?.take(12) ?: ""
            val time = timeFmt.format(Date(row.capturedAt))
            val hits = row.hitCount.toString()
            tableModel.addRow(arrayOf(row.method, row.status?.toString() ?: "?", row.url, contentType, time, hits))
            rowIds.add(row.id)
        }
        resizeUrlColumn()
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
        SwingUtilities.invokeLater { resizeUrlColumn() }
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
    private val even         = Design.Colors.listBackground
    private val odd          = Design.Colors.surface

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
