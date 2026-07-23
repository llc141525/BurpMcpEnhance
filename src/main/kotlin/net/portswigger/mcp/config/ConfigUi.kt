package net.portswigger.mcp.config

import burp.api.montoya.MontoyaApi
import io.ktor.util.network.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.components.*
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.providers.Provider
import java.awt.BorderLayout
import javax.swing.*
import javax.swing.Box.*
import javax.swing.JOptionPane.ERROR_MESSAGE

class ConfigUi(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val providers: List<Provider>
) {

    private val panel = JPanel(BorderLayout())
    val component: JComponent get() = panel

    private val listenerHandles = mutableListOf<ListenerHandle>()
    private val httpHistoryPanel = HttpHistoryPanel()

    private val enabledToggle: ToggleSwitch = Design.createToggleSwitch(false) { enabled ->
        if (suppressToggleEvents) return@createToggleSwitch

        if (enabled) {
            ConfigValidation.validateServerConfig(hostField.text, portField.text)?.let { error ->
                validationErrorLabel.text = error
                validationErrorLabel.isVisible = true
                suppressToggleEvents = true
                enabledToggle.setState(false, animate = true)
                suppressToggleEvents = false
                return@createToggleSwitch
            }
        }

        validationErrorLabel.isVisible = false
        config.enabled = enabled
        toggleListener?.invoke(enabled)
    }
    private val validationErrorLabel = WarningLabel()
    private val hostField = JTextField(15)
    private val portField = JTextField(5)
    private val reinstallNotice = WarningLabel("更改服务器设置后请重新安装")

    private lateinit var serverConfigurationPanel: ServerConfigurationPanel
    private lateinit var advancedOptionsPanel: AdvancedOptionsPanel
    private lateinit var autoApproveTargetsPanel: AutoApproveTargetsPanel
    private lateinit var installationPanel: InstallationPanel
    private lateinit var burpPluginSupportPanel: BurpPluginSupportPanel

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var restartServerListener: (() -> Unit)? = null
    private var suppressToggleEvents: Boolean = false

    init {
        enabledToggle.setState(config.enabled, animate = false)
        hostField.text = config.host
        portField.text = config.port.toString()

        initializeComponents()
        buildUi()
    }

    @Suppress("UNUSED_PARAMETER")
    fun bindInfrastructure(
        messageQueue: Any?,
        fileQueue: Any?,
        database: Any?,
        exporter: Any?,
        activeConnectionProvider: (() -> Int)? = null
    ) {
        httpHistoryPanel.database = database as? Database
        httpHistoryPanel.activeConnectionProvider = activeConnectionProvider
        httpHistoryPanel.serverUrlProvider = { "${config.host}:${config.port}" }
        httpHistoryPanel.onRestartRequested = { restartServerListener?.invoke() }
        httpHistoryPanel.onClearCacheRequested = {
            val result = Dialogs.showConfirmDialog(
                panel, "确定要清除所有缓存数据吗？\n此操作不可撤销。",
                JOptionPane.YES_NO_OPTION
            )
            if (result == JOptionPane.YES_OPTION) {
                (database as? Database)?.clearAll()
                (exporter as? net.portswigger.mcp.exporter.Exporter)?.notifyDatabaseCleared()
                httpHistoryPanel.loadData()
            }
        }
        httpHistoryPanel.onReimportRequested = {
            (exporter as? net.portswigger.mcp.exporter.Exporter)?.reimport()
            javax.swing.Timer(1500) { httpHistoryPanel.loadData() }.apply { isRepeats = false; start() }
        }
        httpHistoryPanel.startRefreshing()
    }

    fun unbindInfrastructure() {
        httpHistoryPanel.stopRefreshing()
        httpHistoryPanel.database = null
    }

    private fun initializeComponents() {
        serverConfigurationPanel = ServerConfigurationPanel(
            config = config, enabledToggle = enabledToggle, validationErrorLabel = validationErrorLabel
        )

        advancedOptionsPanel = AdvancedOptionsPanel(
            config = config, hostField = hostField, portField = portField, reinstallNotice = reinstallNotice
        )

        autoApproveTargetsPanel = AutoApproveTargetsPanel(config = config)

        installationPanel = InstallationPanel(
            config = config, providers = providers, reinstallNotice = reinstallNotice, parentComponent = panel
        )
        burpPluginSupportPanel = BurpPluginSupportPanel(api = api, config = config)

        setupConfigListeners()
    }

    private fun setupConfigListeners() {
        val historyAccessRefreshListener = {
            SwingUtilities.invokeLater {
                serverConfigurationPanel.updateHistoryAccessCheckboxes()
            }
        }
        val handle = config.addHistoryAccessChangeListener(historyAccessRefreshListener)
        listenerHandles.add(handle)
    }

    fun cleanup() {
        httpHistoryPanel.stopRefreshing()
        listenerHandles.forEach { it.remove() }
        listenerHandles.clear()

        if (::autoApproveTargetsPanel.isInitialized) {
            autoApproveTargetsPanel.cleanup()
        }
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) {
        toggleListener = listener
    }

    fun onRestartServerRequested(listener: () -> Unit) {
        restartServerListener = listener
    }

    fun getConfig(): McpConfig {
        config.host = hostField.text
        portField.text.toIntOrNull()?.let { config.port = it }
        if (::advancedOptionsPanel.isInitialized) {
            advancedOptionsPanel.applyConfig()
        }
        return config
    }

    fun updateServerState(state: ServerState) {
        httpHistoryPanel.updateServerState(state)
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true

            val enableAdvancedOptions = state is ServerState.Stopped || state is ServerState.Failed
            if (::advancedOptionsPanel.isInitialized) {
                advancedOptionsPanel.setFieldsEnabled(enableAdvancedOptions)
            }

            when (state) {
                ServerState.Starting, ServerState.Stopping -> {
                    enabledToggle.isEnabled = false
                }

                ServerState.Running -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(true, animate = false)
                }

                ServerState.Stopped -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                }

                is ServerState.Failed -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)

                    val friendlyMessage = when (state.exception) {
                        is UnresolvedAddressException -> "无法解析地址"
                        else -> state.exception.message ?: state.exception.javaClass.simpleName
                    }

                    Dialogs.showMessageDialog(
                        panel, "Burp MCP 服务器启动失败：$friendlyMessage", ERROR_MESSAGE
                    )
                }
            }

            suppressToggleEvents = false
        }
    }

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
            add(createHorizontalGlue())
            add(arrowLabel)
        }
        val innerPanel = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(headerPanel, BorderLayout.NORTH)
            add(contentWrapper, BorderLayout.CENTER)
        }
        val card = Design.createCard(innerPanel)
        headerPanel.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseClicked(e: java.awt.event.MouseEvent) {
                expanded = !expanded
                contentWrapper.isVisible = expanded
                arrowLabel.text = if (expanded) "▼" else "▶"
                card.revalidate()
                card.repaint()
            }
        })
        return card
    }

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

        rightPanelContent.add(Design.createCard(serverConfigurationPanel, "服务器配置"))
        rightPanelContent.add(createVerticalStrut(Design.Spacing.MD))

        val autoApproveCard = Design.createCard(autoApproveTargetsPanel, "HTTP 自动放行目标").also {
            it.isVisible = config.requireHttpRequestApproval
        }
        val autoApproveStrut = createVerticalStrut(Design.Spacing.MD).also {
            it.isVisible = config.requireHttpRequestApproval
        }
        rightPanelContent.add(autoApproveCard)
        rightPanelContent.add(autoApproveStrut)

        serverConfigurationPanel.onHttpApprovalChanged = { enabled ->
            autoApproveCard.isVisible = enabled
            autoApproveStrut.isVisible = enabled
            rightPanelContent.revalidate()
            rightPanelContent.repaint()
        }

        rightPanelContent.add(buildCollapsibleCard(advancedOptionsPanel, "高级选项"))
        rightPanelContent.add(createVerticalStrut(Design.Spacing.MD))
        rightPanelContent.add(buildCollapsibleCard(burpPluginSupportPanel, "第三方插件支持"))
        rightPanelContent.add(createVerticalStrut(Design.Spacing.MD))
        rightPanelContent.add(Design.createCard(installationPanel, "安装"))
        rightPanelContent.add(createVerticalStrut(Design.Spacing.SM))
        rightPanelContent.add(reinstallNotice)
        rightPanelContent.add(createVerticalGlue())

        val columnsPanel = ResponsiveColumnsPanel(leftPanel, rightPanel)
        panel.add(columnsPanel, BorderLayout.CENTER)
    }
}
