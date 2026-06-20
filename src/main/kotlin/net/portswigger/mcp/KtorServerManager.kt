package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.sse.*
import io.ktor.sse.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport
import io.modelcontextprotocol.kotlin.sdk.server.StreamableHttpServerTransport
import kotlinx.coroutines.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.exporter.Exporter
import net.portswigger.mcp.logging.LogWriter
import net.portswigger.mcp.queue.FileQueue
import net.portswigger.mcp.queue.MessageQueue
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class KtorServerManager(
    private val api: MontoyaApi,
    private val dbPath: String = ":memory:",
    private val logWriter: LogWriter? = null
) : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newFixedThreadPool(2) { r ->
        Thread(r, "mcp-server-lifecycle").apply { isDaemon = true }
    }
    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var heartbeatJob: Job? = null
    private var healthMonitorJob: Job? = null
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

    @Volatile
    var activeSseConnections = AtomicInteger(0)
        private set

    private val sseTransports = ConcurrentHashMap<String, SseServerTransport>()
    private val streamableTransports = ConcurrentHashMap<String, StreamableHttpServerTransport>()

    private val currentState = AtomicReference<ServerState>(ServerState.Stopped)

    private val maxRestartAttempts = 3

    private fun logInfo(cat: String, msg: String) {
        api.logging().logToOutput(msg)
        logWriter?.log("INFO", cat, msg)
    }

    private fun logError(cat: String, msg: String, err: Throwable? = null) {
        if (err != null) {
            api.logging().logToError(err)
        } else {
            api.logging().logToError(msg)
        }
        logWriter?.log("ERROR", cat, msg, err)
    }

    private fun logWarn(cat: String, msg: String) {
        api.logging().logToOutput(msg)
        logWriter?.log("WARN", cat, msg)
    }

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
                exporter = Exporter(api, database!!, config = config)
                exporter!!.start()

                val mcpServer = createMcpServer()
                server = createEmbeddedServer(config, mcpServer)

                logInfo("server", "Started MCP server on ${config.host}:${config.port}")
                currentState.set(ServerState.Running)
                callback(ServerState.Running)

                // Start health monitoring
                startHeartbeat(config, mcpServer)

            } catch (e: Exception) {
                logError("server", "Server start failed: ${e.message}", e)
                currentState.set(ServerState.Failed(e))
                callback(ServerState.Failed(e))

                // Schedule automatic restart with persistent backoff
                scheduleRestart(config, callback)
            }
        }
    }

    override fun restart(config: McpConfig, callback: (ServerState) -> Unit) {
        currentState.set(ServerState.Stopping)
        callback(ServerState.Stopping)

        heartbeatJob?.cancel()
        heartbeatJob = null
        healthMonitorJob?.cancel()
        healthMonitorJob = null
        restartJob?.cancel()
        restartJob = null

        executor.submit {
            try {
                // Clear all tracked sessions — the old server is about to be stopped.
                sseTransports.clear()
                val transportsToClose = streamableTransports.values.toList()
                streamableTransports.clear()
                transportsToClose.forEach { scope.launch { runCatching { it.close() } } }
                server?.stop(1000, 5000)
                server = null

                val mcpServer = createMcpServer()
                server = createEmbeddedServer(config, mcpServer)

                logInfo("server", "Restarted MCP server on ${config.host}:${config.port}")
                currentState.set(ServerState.Running)
                callback(ServerState.Running)
                startHeartbeat(config, mcpServer)
            } catch (e: Exception) {
                logError("server", "Server restart failed: ${e.message}", e)
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
        val env = applicationEnvironment { }

        // Register tools before any SSE connections are accepted
        mcpServer.registerTools(api, config, messageQueue, fileQueue, database, exporter)

        return embeddedServer(Netty, env, configure = {
            connector {
                host = config.host
                port = config.port
            }
            tcpKeepAlive = true
            requestReadTimeoutSeconds = 3600  // SSE connections are long-lived
            responseWriteTimeoutSeconds = 3600
        }) {
            install(CORS) {
                allowHost("localhost:${config.port}")
                allowHost("127.0.0.1:${config.port}")
                if (!config.strictLocalhostMode) {
                    allowHost("${config.host}:${config.port}")
                }

                allowMethod(HttpMethod.Get)
                allowMethod(HttpMethod.Post)
                allowMethod(HttpMethod.Delete)

                allowHeader(HttpHeaders.ContentType)
                allowHeader(HttpHeaders.Accept)
                allowHeader("Last-Event-ID")
                allowHeader("Mcp-Session-Id")

                allowCredentials = false
                allowNonSimpleContentTypes = true
                maxAgeInSeconds = 3600
            }

            // Content negotiation for JSON responses (required by Streamable HTTP)
            // Must use McpJson (explicitNulls=false) to match SDK serialization,
            // otherwise _meta:null appears in responses and the MCP client rejects it.
            install(ContentNegotiation) {
                json(McpJson)
            }

            // SSE connection tracking
            intercept(ApplicationCallPipeline.Monitoring) {
                if (call.request.uri.startsWith("/sse")) {
                    val count = activeSseConnections.incrementAndGet()
                    logInfo("server", "SSE client connected (active: $count)")
                    try {
                        proceed()
                    } finally {
                        val afterCount = activeSseConnections.decrementAndGet()
                        logInfo("server", "SSE client disconnected (active: $afterCount)")
                    }
                }
            }

            intercept(ApplicationCallPipeline.Call) {
                val origin = call.request.header("Origin")
                val host = call.request.header("Host")
                val referer = call.request.header("Referer")
                val userAgent = call.request.header("User-Agent")

                if (origin != null && !isValidOrigin(origin, config)) {
                    logWarn("security", "Blocked DNS rebinding attack from origin: $origin")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                } else if (isBrowserRequest(userAgent)) {
                    logWarn("security", "Blocked browser request without Origin header")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                }

                if (host != null && !isValidHost(host, config)) {
                    logWarn("security", "Blocked DNS rebinding attack from host: $host")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                }

                if (referer != null && !isValidReferer(referer, config)) {
                    logWarn("security", "Blocked suspicious request from referer: $referer")
                    call.respond(HttpStatusCode.Forbidden)
                    return@intercept
                }

                call.response.header("X-Frame-Options", "DENY")
                call.response.header("X-Content-Type-Options", "nosniff")
                call.response.header("Referrer-Policy", "same-origin")
                call.response.header("Content-Security-Policy", "default-src 'none'")
            }

            install(SSE)

            routing {
                // SSE endpoint at /sse — matches both README config and proxy --sse-url convention.
                sse("/sse") {
                    val transport = SseServerTransport("/sse", this)
                    sseTransports[transport.sessionId] = transport
                    try {
                        mcpServer.createSession(transport)
                        // In SDK 0.8.3, connect() returns immediately after sending the
                        // endpoint event. awaitCancellation() keeps this Ktor SSE handler
                        // suspended (and thus the SSE connection open) until the client
                        // disconnects or the server is stopped.
                        awaitCancellation()
                    } finally {
                        sseTransports.remove(transport.sessionId)
                    }
                }

                post("/sse") {
                    val sessionId = call.request.queryParameters["sessionId"]
                    if (sessionId == null) {
                        call.respond(HttpStatusCode.BadRequest, "sessionId query parameter is not provided")
                        return@post
                    }

                    val transport = sseTransports[sessionId]
                    if (transport == null) {
                        logWarn("server", "Session not found for sessionId: $sessionId")
                        call.respond(HttpStatusCode.NotFound, "Session not found")
                        return@post
                    }

                    transport.handlePostMessage(call)
                }

                // Streamable HTTP transport (MCP spec 2025-03-26)
                // Configure AI clients with: "url": "http://host:port/mcp"
                post("/mcp") {
                    val sessionId = call.request.header("Mcp-Session-Id")

                    if (sessionId != null) {
                        val transport = streamableTransports[sessionId] ?: run {
                            logWarn("server", "Streamable session not found: $sessionId")
                            call.respond(HttpStatusCode.NotFound, "Session not found")
                            return@post
                        }
                        transport.handlePostRequest(null, call)
                    } else {
                        val t = StreamableHttpServerTransport(enableJsonResponse = true)
                        t.setOnSessionInitialized { sid ->
                            streamableTransports[sid] = t
                            logInfo("server", "New Streamable HTTP session: $sid")
                        }
                        t.setOnSessionClosed { sid ->
                            streamableTransports.remove(sid)
                        }
                        try {
                            // createSession() MUST complete before handlePostRequest so
                            // that _onMessage is wired up on the transport. Otherwise the
                            // initialize JSON-RPC message parsed from the POST body is
                            // dispatched to nothing and the client times out.
                            mcpServer.createSession(t)
                            t.handlePostRequest(null, call)
                        } catch (e: Exception) {
                            logError("server", "Streamable session error: ${e.message}", e)
                            call.respond(HttpStatusCode.InternalServerError, "Session error: ${e.message}")
                        }
                    }
                }

                delete("/mcp") {
                    val sessionId = call.request.header("Mcp-Session-Id") ?: run {
                        call.respond(HttpStatusCode.BadRequest, "Mcp-Session-Id header required")
                        return@delete
                    }
                    val transport = streamableTransports[sessionId] ?: run {
                        logWarn("server", "Streamable session not found: $sessionId")
                        call.respond(HttpStatusCode.NotFound, "Session not found")
                        return@delete
                    }
                    transport.handleDeleteRequest(call)
                }
            }
        }.apply {
            start(wait = false)
        }
    }

    internal suspend fun heartbeatPing(
        keepaliveIntervalSec: Int,
        ping: suspend () -> Unit,
        logger: (String) -> Unit
    ) {
        while (true) {
            delay((keepaliveIntervalSec * 1000L).coerceAtLeast(100))
            try {
                ping()
                logger("MCP keepalive ping sent")
            } catch (e: Exception) {
                logger("MCP keepalive ping failed: ${e.message}")
                logWriter?.log("WARN", "heartbeat", "Ping failed: ${e.message}", e)
            }
        }
    }

    private fun startHeartbeat(config: McpConfig, mcpServer: Server) {
        heartbeatJob?.cancel()
        healthMonitorJob?.cancel()
        if (!config.keepaliveEnabled) return

        if (logWriter == null) {
            // Test environment — no health monitoring
            return
        }

        val healthMonitor = HealthMonitor(
            serverCheck = {
                (server != null && currentState.get() == ServerState.Running)
            },
            onUnhealthy = {
                logWarn("heartbeat", "Health monitor triggering restart")
                restart(config) { state ->
                    if (state is ServerState.Failed) {
                        logError("heartbeat", "Auto-restart from health monitor failed: ${state.exception.message}", state.exception)
                    }
                }
            },
            logWriter = logWriter
        )

        healthMonitorJob = scope.launch {
            while (isActive) {
                delay((config.keepaliveIntervalSec * 1000L).coerceAtLeast(100))
                try {
                    healthMonitor.check()
                } catch (e: Exception) {
                    logWriter?.log("WARN", "heartbeat", "Health check error: ${e.message}", e)
                }
            }
        }
    }

    private fun scheduleRestart(config: McpConfig, callback: (ServerState) -> Unit) {
        restartJob?.cancel()

        val attempts = currentState.get()
        if (attempts is ServerState.Failed && attempts.exception is InterruptedException) {
            logInfo("server", "Server interrupted, not scheduling restart")
            return
        }

        restartJob = scope.launch {
            var attempt = 0
            while (isActive) {
                attempt++
                val delayMs = if (attempt <= maxRestartAttempts) {
                    1000L * (1L shl (attempt - 1)) // 1s, 2s, 4s
                } else {
                    val extra = attempt - maxRestartAttempts
                    minOf(30_000L * (1L shl (extra - 1).coerceAtMost(3)), 300_000L)
                    // 30s, 60s, 120s, 240s, 300s, 300s...
                }

                logInfo("server", "Automatic restart attempt $attempt in ${delayMs}ms")
                delay(delayMs)

                if (!isActive) return@launch

                logInfo("server", "Automatic restart attempt $attempt")
                start(config, callback)

                if (currentState.get() == ServerState.Running) {
                    logInfo("server", "Restart succeeded on attempt $attempt")
                    return@launch
                }

                if (attempt == maxRestartAttempts) {
                    logWarn("server", "Fast retry exhausted ($maxRestartAttempts attempts), switching to persistent retry")
                }
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        currentState.set(ServerState.Stopping)
        callback(ServerState.Stopping)

        heartbeatJob?.cancel()
        heartbeatJob = null
        healthMonitorJob?.cancel()
        healthMonitorJob = null
        restartJob?.cancel()
        restartJob = null

        executor.submit {
            try {
                sseTransports.clear()
                val transportsToClose = streamableTransports.values.toList()
                streamableTransports.clear()
                transportsToClose.forEach { scope.launch { runCatching { it.close() } } }
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
                logInfo("server", "Stopped MCP server")
                currentState.set(ServerState.Stopped)
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                logError("server", "Server stop failed: ${e.message}", e)
                currentState.set(ServerState.Failed(e))
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        healthMonitorJob?.cancel()
        healthMonitorJob = null
        restartJob?.cancel()
        restartJob = null
        scope.cancel()

        sseTransports.clear()
        streamableTransports.clear()
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
