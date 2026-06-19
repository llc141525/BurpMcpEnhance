package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_BALANCED
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_OFF
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_RELAXED
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_STRICT
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ToggleSwitch
import java.awt.FlowLayout
import java.awt.event.ItemEvent
import javax.swing.*
import javax.swing.Box.createHorizontalStrut
import javax.swing.Box.createVerticalStrut

class ServerConfigurationPanel(
    private val config: McpConfig,
    private val enabledToggle: ToggleSwitch,
    private val validationErrorLabel: WarningLabel
) : JPanel() {

    private lateinit var alwaysAllowHttpHistoryCheckBox: JCheckBox
    private lateinit var alwaysAllowWebSocketHistoryCheckBox: JCheckBox
    private lateinit var exportInScopeOnlyCheckBox: JCheckBox
    private lateinit var exportNoiseModeComboBox: JComboBox<ExportNoiseModeOption>
    private lateinit var saveRawDuplicatesCheckBox: JCheckBox
    private lateinit var maxRawDuplicatesSpinner: JSpinner

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = Design.Colors.surface
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
    }

    private fun buildPanel() {
        val enabledPanel = createEnabledPanel()
        add(enabledPanel)
        add(createVerticalStrut(Design.Spacing.MD))

        val configEditingToolingCheckBox = createCheckBoxWithSubtitle(
            "启用可修改配置的工具",
            "警告：可执行代码",
            config.configEditingTooling
        ) { config.configEditingTooling = it }
        add(configEditingToolingCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        val httpRequestApprovalCheckBox = createStandardCheckBox(
            "HTTP 请求需要审批", config.requireHttpRequestApproval
        ) { config.requireHttpRequestApproval = it }
        add(httpRequestApprovalCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        val historyAccessApprovalCheckBox = createHistoryAccessApprovalCheckBox()
        add(historyAccessApprovalCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowHttpHistoryCheckBox = createIndentedCheckBox(
            "始终允许 HTTP 历史记录访问", config.alwaysAllowHttpHistory, config.requireHistoryAccessApproval
        ) { config.alwaysAllowHttpHistory = it }
        add(alwaysAllowHttpHistoryCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        alwaysAllowWebSocketHistoryCheckBox = createIndentedCheckBox(
            "始终允许 WebSocket 历史记录访问",
            config.alwaysAllowWebSocketHistory,
            config.requireHistoryAccessApproval
        ) { config.alwaysAllowWebSocketHistory = it }
        add(alwaysAllowWebSocketHistoryCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        exportInScopeOnlyCheckBox = createStandardCheckBox(
            "仅导出 Scope 内请求", config.exportInScopeOnly
        ) { config.exportInScopeOnly = it }
        add(exportInScopeOnlyCheckBox)
        add(createVerticalStrut(Design.Spacing.SM))

        add(createExportNoiseModePanel())
        add(createVerticalStrut(Design.Spacing.MD))

        add(createRawDuplicatesPanel())

        add(validationErrorLabel)
    }

    private fun createEnabledPanel(): JPanel {
        val enabledPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 4)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }
        enabledPanel.add(JLabel("已启用").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        enabledPanel.add(createHorizontalStrut(Design.Spacing.MD))
        enabledPanel.add(enabledToggle)
        return enabledPanel
    }

    private fun createHistoryAccessApprovalCheckBox(): JCheckBox {
        return createStandardCheckBox(
            "历史记录访问需要审批", config.requireHistoryAccessApproval
        ) { enabled ->
            config.requireHistoryAccessApproval = enabled
            if (!enabled) {
                config.alwaysAllowHttpHistory = false
                config.alwaysAllowWebSocketHistory = false
                alwaysAllowHttpHistoryCheckBox.isSelected = false
                alwaysAllowWebSocketHistoryCheckBox.isSelected = false
            }
            alwaysAllowHttpHistoryCheckBox.isEnabled = enabled
            alwaysAllowWebSocketHistoryCheckBox.isEnabled = enabled
        }
    }

    fun updateHistoryAccessCheckboxes() {
        SwingUtilities.invokeLater {
            alwaysAllowHttpHistoryCheckBox.isSelected = config.alwaysAllowHttpHistory
            alwaysAllowWebSocketHistoryCheckBox.isSelected = config.alwaysAllowWebSocketHistory
        }
    }

    private fun createStandardCheckBox(
        text: String, initialValue: Boolean, onChange: (Boolean) -> Unit
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }

    private fun createIndentedCheckBox(
        text: String, initialValue: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            isEnabled = enabled
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, Design.Spacing.LG, 0, 0)
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }

    private fun createExportNoiseModePanel(): JPanel {
        val options = arrayOf(
            ExportNoiseModeOption(EXPORT_NOISE_MODE_OFF, "关闭", "不过滤浏览器请求噪音"),
            ExportNoiseModeOption(EXPORT_NOISE_MODE_RELAXED, "宽松", "过滤静态资源，如 JS/CSS/图片/字体"),
            ExportNoiseModeOption(EXPORT_NOISE_MODE_BALANCED, "平衡", "额外过滤预检、favicon、manifest、service worker"),
            ExportNoiseModeOption(EXPORT_NOISE_MODE_STRICT, "严格", "额外过滤热更新、prefetch/prerender 等低价值流量")
        )

        exportNoiseModeComboBox = JComboBox(options).apply {
            alignmentX = LEFT_ALIGNMENT
            selectedItem = options.firstOrNull { it.mode == config.exportNoiseMode } ?: options[2]
            addItemListener { event ->
                if (event.stateChange == ItemEvent.SELECTED) {
                    val selected = event.item as? ExportNoiseModeOption ?: return@addItemListener
                    config.exportNoiseMode = selected.mode
                }
            }
        }

        val label = JLabel("导出降噪模式").apply {
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
        }

        val subtitle = JLabel("AI 读取缓存历史时的默认降噪强度").apply {
            font = Design.Typography.labelMedium
            foreground = Design.Colors.onSurfaceVariant
        }

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            border = BorderFactory.createEmptyBorder(0, Design.Spacing.LG, 0, 0)
            add(label)
            add(createVerticalStrut(Design.Spacing.SM))
            add(exportNoiseModeComboBox)
            add(createVerticalStrut(Design.Spacing.SM))
            add(subtitle)
        }
    }

    private fun createRawDuplicatesPanel(): JPanel {
        val panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
        }

        saveRawDuplicatesCheckBox = createStandardCheckBox(
            "保存重复请求的原始数据", config.saveRawDuplicates
        ) { enabled ->
            config.saveRawDuplicates = enabled
            maxRawDuplicatesSpinner.isEnabled = enabled
        }
        panel.add(saveRawDuplicatesCheckBox)
        panel.add(createVerticalStrut(Design.Spacing.SM))

        val spinnerPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(0, Design.Spacing.LG, 0, 0)
        }

        maxRawDuplicatesSpinner = JSpinner(SpinnerNumberModel(
            config.maxRawDuplicatesPerCanonical.coerceIn(1, 100), 1, 100, 1
        )).apply {
            isEnabled = config.saveRawDuplicates
            preferredSize = java.awt.Dimension(60, preferredSize.height)
            addChangeListener {
                config.maxRawDuplicatesPerCanonical = (value as Int)
            }
        }

        spinnerPanel.add(JLabel("每个接口最多保留 ").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        spinnerPanel.add(maxRawDuplicatesSpinner)
        spinnerPanel.add(JLabel(" 条").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        panel.add(spinnerPanel)

        return panel
    }

    private fun createCheckBoxWithSubtitle(
        mainText: String, subtitleText: String, initialValue: Boolean, onChange: (Boolean) -> Unit
    ): JPanel {
        val checkBox = JCheckBox(mainText).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }

        val subtitleLabel = JLabel(subtitleText).apply {
            font = Design.Typography.labelMedium
            foreground = Design.Colors.onSurfaceVariant
        }

        val subtitlePanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(createHorizontalStrut(20))
            add(subtitleLabel)
        }

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            add(checkBox)
            add(subtitlePanel)
        }
    }

}

private data class ExportNoiseModeOption(
    val mode: String,
    val label: String,
    val description: String
) {
    override fun toString(): String = "$label - $description"
}
