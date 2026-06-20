package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.logging.LogWriter
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import java.io.File
import java.util.UUID

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())

        // Generate a unique project ID and database path
        val extensionData = api.persistence().extensionData()
        var projectId = extensionData.getString("projectId")
        if (projectId == null) {
            projectId = UUID.randomUUID().toString()
            extensionData.setString("projectId", projectId)
        }
        // Start file-based logging for diagnostics
        val logDir = File(System.getProperty("user.home"), ".burp-mcp/logs").also { it.mkdirs() }
        val logWriter = LogWriter(logDir).also { it.start() }

        val dbPath = try {
            val dbDir = File(System.getProperty("user.home"), ".burp-mcp/db")
            dbDir.mkdirs()
            File(dbDir, "$projectId.db").absolutePath
        } catch (e: Exception) {
            logWriter.log("WARN", "server", "Failed to create DB directory, falling back to in-memory DB", e)
            ":memory:"
        }

        val serverManager = KtorServerManager(api, dbPath, logWriter)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            api = api,
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                    if (state is ServerState.Running) {
                        configUi.bindInfrastructure(
                            messageQueue = serverManager.messageQueue,
                            fileQueue = serverManager.fileQueue,
                            database = serverManager.database,
                            exporter = serverManager.exporter,
                            activeConnectionProvider = serverManager.activeSseConnections::get
                        )
                    } else if (state is ServerState.Stopped || state is ServerState.Failed) {
                        configUi.unbindInfrastructure()
                    }
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                    if (state is ServerState.Stopped || state is ServerState.Failed) {
                        configUi.unbindInfrastructure()
                    }
                }
            }
        }

        configUi.onRestartServerRequested {
            serverManager.restart(config) { state ->
                configUi.updateServerState(state)
                if (state is ServerState.Running) {
                    configUi.bindInfrastructure(
                        messageQueue = serverManager.messageQueue,
                        fileQueue = serverManager.fileQueue,
                        database = serverManager.database,
                        exporter = serverManager.exporter,
                        activeConnectionProvider = serverManager.activeSseConnections::get
                    )
                } else if (state is ServerState.Failed) {
                    configUi.unbindInfrastructure()
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            logWriter.shutdown()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
                if (state is ServerState.Running) {
                    configUi.bindInfrastructure(
                        messageQueue = serverManager.messageQueue,
                        fileQueue = serverManager.fileQueue,
                        database = serverManager.database,
                        exporter = serverManager.exporter,
                        activeConnectionProvider = serverManager.activeSseConnections::get
                    )
                }
            }
        }
    }
}
