package net.portswigger.mcp.config

import net.portswigger.mcp.ServerState
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.exporter.Exporter
import net.portswigger.mcp.queue.FileQueue
import net.portswigger.mcp.queue.MessageQueue
import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.GridLayout
import java.awt.RenderingHints
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.Timer

class StatusDashboardPanel : JPanel() {

    var messageQueue: MessageQueue? = null
    var fileQueue: FileQueue? = null
    var database: Database? = null
    var exporter: Exporter? = null
    var activeConnectionProvider: (() -> Int)? = null
    var onRestartRequested: (() -> Unit)? = null

    private val refreshStatsTimer = Timer(3000) { refreshAll() }

    private val serverCard = ServiceIndicatorCard("服务器")
    private val exporterCard = ServiceIndicatorCard("导出器")
    private val queueCard = ServiceIndicatorCard("任务队列")
    private val dbCard = ServiceIndicatorCard("数据库")

    private val queueStatsValue = createValueLabel()
    private val fileQueueStatsValue = createValueLabel()
    private val dbStatsValue = createValueLabel()
    private val exporterStatsValue = createValueLabel()
    private val clientStatsValue = createValueLabel()

    private val queuePendingBadge = Design.createBadge("0", Design.Colors.primary)
    private val clientCountBadge = Design.createBadge("0", Design.Colors.primary)
    private val dbHttpBadge = Design.createBadge("0", Design.Colors.tertiary)
    private val dbScanBadge = Design.createBadge("0", Design.Colors.warning)
    private val dbRawDupBadge = Design.createBadge("0", Design.Colors.tertiary)

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = Design.Colors.surface
        alignmentX = Component.LEFT_ALIGNMENT
        border = BorderFactory.createEmptyBorder(Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG)

        buildPanel()
    }

    private fun buildPanel() {
        add(JLabel("Burp MCP Server 状态看板").apply {
            font = Design.Typography.headlineMedium
            foreground = Design.Colors.onSurface
            alignmentX = Component.LEFT_ALIGNMENT
        })
        add(Box.createVerticalStrut(Design.Spacing.MD))

        add(createSectionLabel("服务状态"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(createServiceGrid())
        add(Box.createVerticalStrut(Design.Spacing.LG))

        add(createSectionLabel("运行统计"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(createStatsGrid())
        add(Box.createVerticalStrut(Design.Spacing.LG))

        add(createSectionLabel("管理"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(createManagementRow())
    }

    fun startRefreshing() {
        if (!refreshStatsTimer.isRunning) {
            refreshStatsTimer.start()
        }
    }

    fun stopRefreshing() {
        refreshStatsTimer.stop()
    }

    fun updateServerState(state: ServerState) {
        when (state) {
            ServerState.Starting -> serverCard.setStatus(StatusDot.ColorYELLOW, "启动中")
            ServerState.Running -> serverCard.setStatus(StatusDot.ColorGREEN, "运行中")
            ServerState.Stopping -> serverCard.setStatus(StatusDot.ColorYELLOW, "停止中")
            ServerState.Stopped -> serverCard.setStatus(StatusDot.ColorGRAY, "已停止")
            is ServerState.Failed -> serverCard.setStatus(StatusDot.ColorRED, "启动失败")
        }
    }

    fun refreshAll() {
        refreshIndicators()
        refreshStats()
    }

    private fun createServiceGrid(): JComponent {
        return JPanel(GridLayout(2, 2, Design.Spacing.SM, Design.Spacing.SM)).apply {
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
            maximumSize = Dimension(Int.MAX_VALUE, 220)
            add(Design.createCard(serverCard))
            add(Design.createCard(exporterCard))
            add(Design.createCard(queueCard))
            add(Design.createCard(dbCard))
        }
    }

    private fun createStatsGrid(): JComponent {
        return JPanel(GridLayout(3, 2, Design.Spacing.SM, Design.Spacing.SM)).apply {
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
            maximumSize = Dimension(Int.MAX_VALUE, 320)
            add(createMetricCard("消息队列", queueStatsValue, queuePendingBadge))
            add(createMetricCard("文件队列", fileQueueStatsValue))
            add(createDatabaseMetricCard())
            add(createMetricCard("导出器", exporterStatsValue))
            add(createMetricCard("客户端", clientStatsValue, clientCountBadge))
            add(createMetricCard("缓存总览", createValueLabel().apply {
                text = "HTTP / 扫描数据已纳入数据库统计"
            }))
        }
    }

    private fun createMetricCard(title: String, value: JComponent, badge: JLabel? = null): JComponent {
        val content = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
        }

        val header = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
        }
        header.add(JLabel(title).apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        header.add(Box.createHorizontalStrut(Design.Spacing.SM))
        if (badge != null) {
            badge.isVisible = false
            header.add(badge)
        }
        header.add(Box.createHorizontalGlue())

        content.add(header)
        content.add(Box.createVerticalStrut(Design.Spacing.SM))
        content.add(value)

        return Design.createCard(content)
    }

    private fun createDatabaseMetricCard(): JComponent {
        val content = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
        }

        val header = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
        }
        header.add(JLabel("数据库").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        header.add(Box.createHorizontalStrut(Design.Spacing.SM))
        header.add(dbHttpBadge)
        header.add(Box.createHorizontalStrut(4))
        header.add(JLabel("HTTP").apply {
            font = Design.Typography.labelSmall
            foreground = Design.Colors.onSurfaceVariant
        })
        header.add(Box.createHorizontalStrut(Design.Spacing.SM))
        header.add(dbScanBadge)
        header.add(Box.createHorizontalStrut(4))
        header.add(JLabel("扫描").apply {
            font = Design.Typography.labelSmall
            foreground = Design.Colors.onSurfaceVariant
        })
        header.add(Box.createHorizontalStrut(Design.Spacing.SM))
        header.add(dbRawDupBadge)
        header.add(Box.createHorizontalStrut(4))
        header.add(JLabel("原始重复").apply {
            font = Design.Typography.labelSmall
            foreground = Design.Colors.onSurfaceVariant
        })
        header.add(Box.createHorizontalGlue())

        content.add(header)
        content.add(Box.createVerticalStrut(Design.Spacing.SM))
        content.add(dbStatsValue)

        return Design.createCard(content)
    }

    private fun createManagementRow(): JComponent {
        return JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, 0)).apply {
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT

            add(createManagementButton("清除缓存", outlined = true) {
                val result = Dialogs.showConfirmDialog(
                    this@StatusDashboardPanel,
                    "确定要清除所有缓存数据吗？\n此操作不可撤销。",
                    JOptionPane.YES_NO_OPTION
                )
                if (result == JOptionPane.YES_OPTION) {
                    database?.clearAll()
                    refreshAll()
                }
            })

            add(createManagementButton("重启服务器", outlined = false) {
                val result = Dialogs.showConfirmDialog(
                    this@StatusDashboardPanel,
                    "确定要重启 MCP 服务器吗？\n客户端连接将暂时中断。",
                    JOptionPane.YES_NO_OPTION
                )
                if (result == JOptionPane.YES_OPTION) {
                    onRestartRequested?.invoke()
                }
            })
        }
    }

    private fun createManagementButton(text: String, outlined: Boolean, action: () -> Unit): JButton {
        val button = if (outlined) {
            Design.createOutlinedButton(text, Dimension(140, 42))
        } else {
            Design.createFilledButton(text, Dimension(156, 42))
        }
        button.addActionListener { action() }
        return button
    }

    private fun refreshIndicators() {
        val exporterStats = exporter?.stats
        if (exporterStats != null && exporterStats.isRunning) {
            exporterCard.setStatus(StatusDot.ColorGREEN, "运行中")
            exporterCard.setDetail("已导出 ${exporterStats.totalExported} 条")
        } else {
            exporterCard.setStatus(StatusDot.ColorGRAY, "已停止")
            exporterCard.setDetail("等待导出任务")
        }

        val qStats = messageQueue?.stats
        if (qStats != null) {
            when {
                qStats.processing > 0 -> {
                    queueCard.setStatus(StatusDot.ColorGREEN, "处理中")
                    queueCard.setDetail("${qStats.processing} 个任务正在运行")
                }
                qStats.submitted > 0 -> {
                    queueCard.setStatus(StatusDot.ColorBLUE, "空闲")
                    queueCard.setDetail("累计提交 ${qStats.submitted} 个任务")
                }
                else -> {
                    queueCard.setStatus(StatusDot.ColorGRAY, "空闲")
                    queueCard.setDetail("当前没有排队任务")
                }
            }
        } else {
            queueCard.setStatus(StatusDot.ColorGRAY, "未连接")
            queueCard.setDetail("消息队列不可用")
        }

        val dbStats = database?.stats()
        if (dbStats != null && (dbStats.proxyHttpCount > 0 || dbStats.scannerIssueCount > 0)) {
            dbCard.setStatus(StatusDot.ColorGREEN, "已缓存")
            dbCard.setDetail("HTTP ${dbStats.proxyHttpCount} / 扫描 ${dbStats.scannerIssueCount}")
        } else if (dbStats != null) {
            dbCard.setStatus(StatusDot.ColorGRAY, "空缓存")
            dbCard.setDetail("数据库已连接，但暂时没有数据")
        } else {
            dbCard.setStatus(StatusDot.ColorGRAY, "未连接")
            dbCard.setDetail("数据库不可用")
        }
    }

    private fun refreshStats() {
        val qStats = messageQueue?.stats
        if (qStats != null) {
            queueStatsValue.text = "提交 ${qStats.submitted} | 完成 ${qStats.completed} | 失败 ${qStats.failed} | 处理中 ${qStats.processing}"
            queuePendingBadge.text = qStats.processing.toString()
            queuePendingBadge.isVisible = qStats.processing > 0
        } else {
            queueStatsValue.text = "队列统计不可用"
            queuePendingBadge.isVisible = false
        }

        val fStats = fileQueue?.stats()
        fileQueueStatsValue.text = fStats?.let {
            "文件 ${it.totalFiles} 个 | 大小 ${formatBytes(it.totalSizeBytes)} | 访问 ${it.totalAccesses} 次"
        } ?: "文件队列统计不可用"

        val dStats = database?.stats()
        if (dStats != null) {
            dbStatsValue.text = "共 ${dStats.proxyHttpCount + dStats.scannerIssueCount} 条记录"
            dbHttpBadge.text = dStats.proxyHttpCount.toString()
            dbScanBadge.text = dStats.scannerIssueCount.toString()
            dbRawDupBadge.text = dStats.rawDuplicateCount.toString()
        } else {
            dbStatsValue.text = "数据库统计不可用"
            dbHttpBadge.text = "0"
            dbScanBadge.text = "0"
            dbRawDupBadge.text = "0"
        }

        val eStats = exporter?.stats
        exporterStatsValue.text = eStats?.let {
            "已导出 ${it.totalExported} 条 | 最后导出 ${if (it.lastExportTime > 0) "已执行" else "从未"} | 运行中 ${if (it.isRunning) "是" else "否"}"
        } ?: "导出器统计不可用"

        val connCount = activeConnectionProvider?.invoke() ?: 0
        clientCountBadge.text = connCount.toString()
        clientCountBadge.isVisible = connCount > 0
        clientStatsValue.text = when {
            connCount <= 0 -> "当前无活跃客户端连接"
            connCount == 1 -> "当前有 1 个活跃客户端连接"
            else -> "当前有 $connCount 个活跃客户端连接"
        }
    }

    private fun createSectionLabel(text: String): JLabel {
        return JLabel(text).apply {
            font = Design.Typography.titleMedium
            foreground = Design.Colors.onSurface
            alignmentX = Component.LEFT_ALIGNMENT
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            else -> "%.1f MB".format(bytes.toDouble() / (1024 * 1024))
        }
    }

    companion object {
        private fun createValueLabel(): JTextArea {
            return Design.createReadOnlyTextArea(
                font = Design.Typography.bodyMedium,
                foreground = Design.Colors.onSurfaceVariant
            ).apply {
                alignmentX = Component.LEFT_ALIGNMENT
            }
        }
    }
}

class ServiceIndicatorCard(private val name: String) : JPanel() {
    private val dot = StatusDot()
    private val statusLabel = JLabel("--")
    private val detailLabel = Design.createReadOnlyTextArea(
        font = Design.Typography.labelSmall,
        foreground = Design.Colors.onSurfaceVariant
    )

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        isOpaque = false
        alignmentX = Component.LEFT_ALIGNMENT

        val topRow = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            alignmentX = Component.LEFT_ALIGNMENT
        }

        topRow.add(dot)
        topRow.add(Box.createHorizontalStrut(8))
        topRow.add(JLabel(name).apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        topRow.add(Box.createHorizontalGlue())
        topRow.add(statusLabel.apply {
            font = Design.Typography.labelMedium
            foreground = Design.Colors.onSurfaceVariant
        })

        add(topRow)
        add(Box.createVerticalStrut(Design.Spacing.SM))
        detailLabel.border = BorderFactory.createEmptyBorder(0, 22, 0, 0)
        add(detailLabel)
    }

    fun setStatus(color: Color, text: String) {
        dot.color = color
        dot.isPulsing = color == StatusDot.ColorGREEN
        statusLabel.text = text
    }

    fun setDetail(text: String) {
        detailLabel.text = text
    }
}

class StatusDot : JComponent() {
    var color: Color = ColorGRAY
        set(value) {
            field = value
            repaint()
        }

    var isPulsing: Boolean = false
        set(value) {
            if (field != value) {
                field = value
                if (value) startPulse() else stopPulse()
            }
        }

    private var pulseTimer: Timer? = null
    private var pulsePhase = 0f

    override fun getPreferredSize(): Dimension = Dimension(14, 14)
    override fun getMinimumSize(): Dimension = Dimension(14, 14)

    private fun startPulse() {
        pulseTimer?.stop()
        pulseTimer = Timer(30) {
            pulsePhase = (pulsePhase + 0.08f) % (Math.PI * 2).toFloat()
            repaint()
        }
        pulseTimer?.start()
    }

    private fun stopPulse() {
        pulseTimer?.stop()
        pulseTimer = null
        pulsePhase = 0f
        repaint()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)

        val size = if (isPulsing) {
            val pulse = (Math.sin(pulsePhase.toDouble()) * 0.15 + 0.85).toFloat()
            14f * pulse
        } else {
            14f
        }
        val offset = (14 - size) / 2f
        val cy = (height - 14) / 2f

        g2.color = if (isPulsing) {
            val alpha = ((Math.sin(pulsePhase.toDouble()) * 0.3 + 0.7).toFloat() * 255).toInt()
            Color(color.red, color.green, color.blue, alpha)
        } else {
            color
        }
        g2.fillOval(offset.toInt(), (cy + offset).toInt(), size.toInt(), size.toInt())
        g2.dispose()
    }

    companion object {
        val ColorGREEN = Color(0x4CAF50)
        val ColorYELLOW = Color(0xFFC107)
        val ColorRED = Color(0xF44336)
        val ColorGRAY = Color(0x9E9E9E)
        val ColorBLUE = Color(0x2196F3)
    }
}
