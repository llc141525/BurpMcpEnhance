package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import kotlinx.coroutines.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.exporter.Exporter
import net.portswigger.mcp.queue.FileQueue
import net.portswigger.mcp.queue.MessageQueue
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class KtorServerManager(private val api: MontoyaApi, private val dbPath: String = ":memory:") : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newFixedThreadPool(2) { r ->
        Thread(r, "mcp-server-lifecycle").apply { isDaemon = true }
    }
    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var heartbeatJob: Job? = null
    private var restartJob: Job? = null
    @Volatile
    var messageQueue: MessageQueue? = null
        private set
    @Volatile
    var fileQueue: FileQueue? = null
        private set
    @Volatile
    var database: Database? = null
        private set
    @Volatile
    var exporter: Exporter? = null
        private set

    private val currentState = AtomicReference<ServerState>(ServerState.Stopped)
    private val maxRestartAttempts = 3

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        currentState.set(ServerState.Starting)
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                // Create infrastructure
                messageQueue = MessageQueue()
                fileQueue = FileQueue()
                database = Database(dbPath)
                exporter = Exporter(api, database!!)
                exporter!!.start()

                val mcpServer = createMcpServer()
                server = createEmbeddedServer(config, mcpServer)

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                currentState.set(ServerState.Running)
                callback(ServerState.Running)

                // Start keepalive heartbeat
                startHeartbeat(config, mcpServer)

            } catch (e: Exception) {
                api.logging().logToError(e)
                currentState.set(ServerState.Failed(e))
                callback(ServerState.Failed(e))

                // Schedule automatic restart with exponential backoff
                scheduleRestart(config, callback)
            }
        }
    }

    override fun restart(config: McpConfig, callback: (ServerState) -> Unit) {
        currentState.set(ServerState.Stopping)
        callback(ServerState.Stopping)

        heartbeatJob?.cancel()
        heartbeatJob = null
        restartJob?.cancel()
        restartJob = null

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = createMcpServer()
                server = createEmbeddedServer(config, mcpServer)

                api.logging().logToOutput("Restarted MCP server on ${config.host}:${config.port}")
                currentState.set(ServerState.Running)
                callback(ServerState.Running)
                startHeartbeat(config, mcpServer)
            } catch (e: Exception) {
                api.logging().logToError(e)
                currentState.set(ServerState.Failed(e))
                callback(ServerState.Failed(e))
                scheduleRestart(config, callback)
            }
        }
    }

    private fun createMcpServer(): Server = Server(
        serverInfo = Implementation("burp-suite", "1.1.2"), options = ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = false)
            )
        )
    )

    private fun createEmbeddedServer(config: McpConfig, mcpServer: Server): EmbeddedServer<*, *> {
        return embeddedServer(Netty, port = config.port, host = config.host) {
            install(CORS) {
                allowHost("localhost:${config.port}")
                allowHost("127.0.0.1:${config.port}")
                if (!config.strictLocalhostMode) {
                    allowHost("${config.host}:${config.port}")
                }

                allowMethod(HttpMethod.Get)
                allowMethod(HttpMethod.Post)

                allowHeader(HttpHeaders.ContentType)
                allowHeader(HttpHeaders.Accept)
                allowHeader("Last-Event-ID")

                allowCredentials = false
                allowNonSimpleContentTypes = true
                maxAgeInSeconds = 3600
            }

            intercept(ApplicationCallPipeline.Call) {
                val origin = call.request.header("Origin")
                val host = call.request.header("Host")
                val referer = call.request.header("Referer")
                val userAgent = call.request.header("User-Agent")

                if (origin != null && !isValidOrigin(origin, config)) {
                    api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                } else if (isBrowserRequest(userAgent)) {
                    api.logging().logToOutput("Blocked browser request without Origin header")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                }

                if (host != null && !isValidHost(host, config)) {
                    api.logging().logToOutput("Blocked DNS rebinding attack from host: $host")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                }

                if (referer != null && !isValidReferer(referer, config)) {
                    api.logging().logToOutput("Blocked suspicious request from referer: $referer")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                }

                call.response.header("X-Frame-Options", "DENY")
                call.response.header("X-Content-Type-Options", "nosniff")
                call.response.header("Referrer-Policy", "same-origin")
                call.response.header("Content-Security-Policy", "default-src 'none'")
            }

            mcp {
                mcpServer
            }

            mcpServer.registerTools(api, config, messageQueue, fileQueue, database, exporter)
        }.apply {
            start(wait = false)
        }
    }

    private fun startHeartbeat(config: McpConfig, mcpServer: Server) {
        heartbeatJob?.cancel()
        if (!config.keepaliveEnabled) return

        heartbeatJob = scope.launch {
            while (isActive) {
                delay(config.keepaliveIntervalSec * 1000L)
                api.logging().logToOutput("MCP keepalive heartbeat")
                // SSE keepalive is handled by Ktor server and MCP SDK at the transport level.
                // This heartbeat ensures the server lifecycle coroutine stays active and provides
                // visibility into server status through logs.
            }
        }
    }

    private fun scheduleRestart(config: McpConfig, callback: (ServerState) -> Unit) {
        restartJob?.cancel()

        val attempts = currentState.get()
        if (attempts is ServerState.Failed && attempts.exception is InterruptedException) {
            api.logging().logToOutput("Server interrupted, not scheduling restart")
            return
        }

        restartJob = scope.launch {
            for (i in 1..maxRestartAttempts) {
                val delayMs = 1000L * (1L shl (i - 1))
                api.logging().logToOutput("Automatic restart attempt $i/$maxRestartAttempts in ${delayMs}ms")
                delay(delayMs)

                if (!isActive) return@launch

                api.logging().logToOutput("Automatic restart attempt $i/$maxRestartAttempts")
                start(config, callback)
            }
            api.logging().logToOutput("Max restart attempts reached ($maxRestartAttempts)")
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        currentState.set(ServerState.Stopping)
        callback(ServerState.Stopping)

        heartbeatJob?.cancel()
        heartbeatJob = null
        restartJob?.cancel()
        restartJob = null

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                exporter?.shutdown()
                exporter = null
                database?.close()
                database = null
                messageQueue?.shutdown()
                messageQueue = null
                fileQueue?.shutdown()
                fileQueue = null
                api.logging().logToOutput("Stopped MCP server")
                currentState.set(ServerState.Stopped)
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                currentState.set(ServerState.Failed(e))
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        restartJob?.cancel()
        restartJob = null
        scope.cancel()

        server?.stop(1000, 5000)
        server = null

        exporter?.shutdown()
        exporter = null
        database?.close()
        database = null
        messageQueue?.shutdown()
        messageQueue = null
        fileQueue?.shutdown()
        fileQueue = null

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    private fun isValidOrigin(origin: String, config: McpConfig): Boolean {
        try {
            val url = URI(origin).toURL()
            val hostname = url.host.lowercase()

            if (!config.strictLocalhostMode) return true
            val allowedHosts = setOf("localhost", "127.0.0.1")
            return hostname in allowedHosts
        } catch (_: Exception) {
            return false
        }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false

        val userAgentLower = userAgent.lowercase()
        val browserIndicators = listOf(
            "mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser"
        )

        return browserIndicators.any { userAgentLower.contains(it) }
    }

    private fun isValidHost(host: String, config: McpConfig): Boolean {
        try {
            if (!config.strictLocalhostMode) return true

            val parts = host.split(":")
            val hostname = parts[0].lowercase()
            val port = if (parts.size > 1) parts[1].toIntOrNull() else null

            val allowedHosts = setOf("localhost", "127.0.0.1")
            if (hostname !in allowedHosts) {
                return false
            }

            if (port != null && port != config.port) {
                return false
            }

            return true
        } catch (_: Exception) {
            return false
        }
    }

    private fun isValidReferer(referer: String, config: McpConfig): Boolean {
        try {
            val url = URI(referer).toURL()
            val hostname = url.host.lowercase()

            if (!config.strictLocalhostMode) return true
            val allowedHosts = setOf("localhost", "127.0.0.1")
            return hostname in allowedHosts

        } catch (_: Exception) {
            return false
        }
    }
}
