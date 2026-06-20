package net.portswigger.mcp.config.components

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.plugins.KNOWN_BURP_PLUGINS
import net.portswigger.mcp.plugins.PluginCategory
import net.portswigger.mcp.plugins.collectBurpPluginInventory
import java.awt.Dimension
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JComponent
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.ListSelectionModel
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class BurpPluginSupportPanel(
    private val api: MontoyaApi,
    private val config: McpConfig
) : JPanel() {

    private val detectedPluginsModel = DefaultListModel<String>()
    private val configuredPluginsArea = JTextArea()
    private val summaryArea = Design.createReadOnlyTextArea()
    private val capabilityArea = Design.createReadOnlyTextArea()

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = Design.Colors.surface
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
        refreshInventory()
    }

    private fun buildPanel() {
        add(Design.createReadOnlyTextArea(
            "这个区域会尝试从 Burp 当前配置里识别已启用的第三方插件，并允许你补充手工维护的插件名。",
            foreground = Design.Colors.onSurfaceVariant
        ))
        add(Box.createVerticalStrut(Design.Spacing.SM))

        val refreshRow = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }

        val refreshButton = Design.createOutlinedButton("刷新插件列表").apply {
            addActionListener { refreshInventory() }
        }
        refreshRow.add(refreshButton)
        refreshRow.add(Box.createHorizontalStrut(Design.Spacing.SM))
        val refreshInfoArea = Design.createReadOnlyTextArea(
            "如果 Burp 没暴露完整扩展信息，可以在下面补充插件名。",
            font = Design.Typography.labelMedium,
            foreground = Design.Colors.onSurfaceVariant
        ).apply {
            lineWrap = true
            wrapStyleWord = true
            maximumSize = Dimension(300, Int.MAX_VALUE)
        }
        refreshRow.add(refreshInfoArea)
        add(refreshRow)
        add(Box.createVerticalStrut(Design.Spacing.MD))

        add(Design.createSectionLabel("当前可用插件"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(createDetectedPluginsPane())
        add(Box.createVerticalStrut(Design.Spacing.MD))

        add(Design.createSectionLabel("手工补充插件名"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        Design.styleInputTextArea(configuredPluginsArea, rows = 5)
        configuredPluginsArea.apply {
            lineWrap = true
            wrapStyleWord = true
            text = config.getKnownBurpPluginsList().joinToString("\n")
            document.addDocumentListener(object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent?) = persistConfiguredPlugins()
                override fun removeUpdate(e: DocumentEvent?) = persistConfiguredPlugins()
                override fun changedUpdate(e: DocumentEvent?) = persistConfiguredPlugins()
            })
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
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(Design.createReadOnlyTextArea(
            "建议每行一个，例如：Active Scan++、Param Miner、Bypass WAF",
            font = Design.Typography.labelMedium,
            foreground = Design.Colors.onSurfaceVariant
        ))
        add(Box.createVerticalStrut(Design.Spacing.MD))

        add(Design.createSectionLabel("插件摘要"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(summaryArea)
        add(Box.createVerticalStrut(Design.Spacing.MD))

        add(Design.createSectionLabel("已知插件能力"))
        add(Box.createVerticalStrut(Design.Spacing.SM))
        add(capabilityArea)
    }

    private fun createDetectedPluginsPane(): JComponent {
        val detectedPluginsList = JList(detectedPluginsModel).apply {
            selectionMode = ListSelectionModel.SINGLE_SELECTION
            font = Design.Typography.bodyMedium
            visibleRowCount = 6
            background = Design.Colors.listBackground
            foreground = Design.Colors.onSurface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.SM,
                Design.Spacing.MD,
                Design.Spacing.SM,
                Design.Spacing.MD
            )
        }

        return JScrollPane(detectedPluginsList).apply {
            alignmentX = LEFT_ALIGNMENT
            preferredSize = Dimension(420, 150)
            minimumSize = Dimension(240, 120)
            maximumSize = Dimension(Int.MAX_VALUE, 180)
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
                BorderFactory.createEmptyBorder(1, 1, 1, 1)
            )
            viewport.background = Design.Colors.listBackground
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        }
    }

    private fun persistConfiguredPlugins() {
        val plugins = configuredPluginsArea.text
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()
        config.setKnownBurpPlugins(plugins)
    }

    fun refreshInventory() {
        val inventory = collectBurpPluginInventory(api, config.getKnownBurpPluginsList())

        detectedPluginsModel.clear()
        if (inventory.effectivePluginNames.isEmpty()) {
            detectedPluginsModel.addElement("未检测到插件，可在下方手工补充。")
        } else {
            inventory.effectivePluginNames.forEach(detectedPluginsModel::addElement)
        }

        summaryArea.text = buildString {
            appendLine("探测来源：${inventory.detectionSource}")
            appendLine("插件数量：${inventory.effectivePluginNames.size}")
            appendLine("请求链路插件：${inventory.matchedKnownPlugins.count { it.autoAppliesToSendHttp }}")
            appendLine("扫描联动插件：${inventory.matchedKnownPlugins.count { it.autoAppliesToActiveScan }}")
            if (inventory.unmatchedPluginNames.isNotEmpty()) {
                appendLine("未归类插件：${inventory.unmatchedPluginNames.joinToString("、")}")
            }
        }.trim()

        capabilityArea.text = buildString {
            appendLine("请求改写/发包联动：")
            KNOWN_BURP_PLUGINS.filter { it.category == PluginCategory.REQUEST_HANDLER }.forEach {
                appendLine("- ${it.name}: ${it.description}")
            }
            appendLine()
            appendLine("主动扫描/发现联动：")
            KNOWN_BURP_PLUGINS.filter { it.category != PluginCategory.REQUEST_HANDLER }.forEach {
                appendLine("- ${it.name}: ${it.description}")
            }
        }.trim()
    }
}
