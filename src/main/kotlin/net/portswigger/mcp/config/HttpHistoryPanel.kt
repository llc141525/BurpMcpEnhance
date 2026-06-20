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
    var activeConnectionProvider: (() -> Int)? = null

    private val serverStatusDot = StatusDot()
    private val serverStatusLabel = JLabel("--").apply {
        font = Design.Typography.labelMedium
        foreground = Design.Colors.onSurfaceVariant
    }
    private val httpCountBadge = Design.createBadge("HTTP 0", Design.Colors.tertiary)
    private val scanCountBadge = Design.createBadge("扫描 0", Design.Colors.warning)
    private val connCountBadge = Design.createBadge("连 0", Design.Colors.primary)

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
            add(httpCountBadge)
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(scanCountBadge)
            add(Box.createHorizontalStrut(Design.Spacing.SM))
            add(connCountBadge)
            add(Box.createHorizontalGlue())
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
        }

        table.columnModel.apply {
            getColumn(0).apply { minWidth = 55; preferredWidth = 55; maxWidth = 70 }
            getColumn(1).apply { minWidth = 45; preferredWidth = 50; maxWidth = 55 }
            // column 2 = URL, managed by ComponentListener below
            getColumn(3).apply { minWidth = 55; preferredWidth = 65; maxWidth = 75 }
            getColumn(4).apply { minWidth = 60; preferredWidth = 65; maxWidth = 75 }
            getColumn(5).apply { minWidth = 35; preferredWidth = 38; maxWidth = 45 }
        }

        table.addComponentListener(object : java.awt.event.ComponentAdapter() {
            override fun componentResized(e: java.awt.event.ComponentEvent) {
                val fixedTotal = (0..5).filter { it != 2 }.sumOf { table.columnModel.getColumn(it).preferredWidth }
                val urlWidth = maxOf(80, table.width - fixedTotal)
                table.columnModel.getColumn(2).preferredWidth = urlWidth
                table.columnModel.getColumn(2).width = urlWidth
            }
        })

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
