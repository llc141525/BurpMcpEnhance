package net.portswigger.mcp.exporter

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import kotlinx.coroutines.*
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_BALANCED
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_OFF
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_RELAXED
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_STRICT
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.db.ProxyHttpEntry
import net.portswigger.mcp.db.ScannerIssueEntry
import net.portswigger.mcp.logging.LogWriter
import java.net.URI
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private val STATIC_ASSET_EXTENSIONS = setOf(
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".mp3", ".txt"
)

private val LOW_VALUE_BROWSER_PATH_SUFFIXES = setOf(
    "/favicon.ico", "/robots.txt", "/manifest.json", "/site.webmanifest",
    "/browserconfig.xml", "/sw.js", "/service-worker.js"
)

private val LOW_VALUE_BROWSER_PATH_FRAGMENTS = setOf(
    "/apple-touch-icon", "/android-chrome-", "/mstile-", "/@vite/client",
    "/__vite_ping", "/__webpack_hmr", "/sockjs-node", "hot-update.", "webpack-hmr"
)

class Exporter(
    private val api: MontoyaApi,
    private val database: Database,
    private val config: McpConfig? = null,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
    private val pollIntervalMs: Long = 30_000,
    private val maxBodySize: Int = 8192
) {
    private var job: Job? = null
    private val _totalExported = AtomicInteger(0)
    private val _lastExportTime = AtomicLong(0)
    private val _isRunning = AtomicInteger(0)

    @Volatile
    private var isExportCycleRunning = false

    @Volatile
    private var lastProxyTimestampMs = 0L

    @Volatile
    private var lastKnownScannerIssueCount: Int? = null

    val stats: ExporterStats
        get() = ExporterStats(
            isRunning = _isRunning.get() == 1,
            totalExported = _totalExported.get(),
            lastExportTime = _lastExportTime.get(),
            dbStats = database.stats()
        )

    fun start() {
        if (_isRunning.getAndSet(1) == 1) return
        job = scope.launch {
            api.logging().logToOutput("MCP Exporter started (poll interval: ${pollIntervalMs}ms)")
            while (isActive) {
                try {
                    if (!isExportCycleRunning) {
                        isExportCycleRunning = true
                        exportProxyHttpHistory()
                        exportScannerIssues()
                        // Prune old data to prevent unbounded growth
                        database.pruneAll()
                        isExportCycleRunning = false
                        _lastExportTime.set(System.currentTimeMillis())
                    } else {
                        api.logging().logToOutput("MCP Exporter: previous cycle still running, skipping this poll")
                    }
                } catch (e: Exception) {
                    isExportCycleRunning = false
                    api.logging().logToError("MCP Exporter error: ${e.message}")
                    LogWriter.instance?.log("ERROR", "exporter", "MCP Exporter error: ${e.message}", e)
                }
                delay(pollIntervalMs)
            }
        }
    }

    fun stop() {
        _isRunning.set(0)
        job?.cancel()
        job = null
    }

    fun shutdown() {
        stop()
        scope.cancel()
    }

    fun noiseModeSummary(): String {
        val mode = config?.exportNoiseMode ?: EXPORT_NOISE_MODE_BALANCED
        val inScopeOnly = config?.exportInScopeOnly == true
        return "mode=$mode, in_scope_only=$inScopeOnly"
    }

    internal suspend fun exportProxyHttpHistory() {
        withContext(Dispatchers.IO) {
            val history = api.proxy().history()
            val newEntries = if (lastProxyTimestampMs > 0) {
                history.filter { it.time().toInstant().toEpochMilli() > lastProxyTimestampMs }
            } else {
                history
            }

            if (newEntries.isEmpty()) return@withContext

            val entries = newEntries
                .filter { shouldExport(it) }
                .mapNotNull { it.toProxyHttpEntry(maxBodySize) }
            if (entries.isNotEmpty()) {
                val maxRaw = if (config?.saveRawDuplicates != false) config?.maxRawDuplicatesPerCanonical ?: 10 else 0
                database.upsertProxyHttpHistory(entries, maxRawDuplicatesPerCanonical = maxRaw)
                _totalExported.addAndGet(entries.size)
            }

            val maxTime = newEntries.maxOfOrNull { it.time().toInstant().toEpochMilli() }
            if (maxTime != null && maxTime > lastProxyTimestampMs) {
                lastProxyTimestampMs = maxTime
            }
        }
    }

    internal suspend fun exportScannerIssues() {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) return
        withContext(Dispatchers.IO) {
            val issues = api.siteMap().issues()
            if (issues.isEmpty()) return@withContext
            val currentCount = issues.size
            if (currentCount == (lastKnownScannerIssueCount ?: -1)) return@withContext
            lastKnownScannerIssueCount = currentCount

            val entries = issues.mapNotNull { it.toScannerIssueEntry(maxBodySize) }
            if (entries.isNotEmpty()) {
                database.upsertScannerIssues(entries)
                _totalExported.addAndGet(entries.size)
            }
        }
    }

    private fun shouldExport(entry: ProxyHttpRequestResponse): Boolean {
        val request = runCatching { entry.request() }.getOrNull() ?: return false
        val url = buildUrl(request) ?: return false

        if (config?.exportInScopeOnly == true && !api.scope().isInScope(url)) {
            return false
        }

        val noiseMode = config?.exportNoiseMode ?: EXPORT_NOISE_MODE_BALANCED
        if (noiseMode != EXPORT_NOISE_MODE_OFF && isBrowserNoise(request, url, noiseMode)) {
            return false
        }

        return true
    }
}

data class ExporterStats(
    val isRunning: Boolean,
    val totalExported: Int,
    val lastExportTime: Long,
    val dbStats: net.portswigger.mcp.db.DbStats
)

private fun ProxyHttpRequestResponse.toProxyHttpEntry(maxBodySize: Int): ProxyHttpEntry? {
    return try {
        val request = this.request()
        val response = this.response()
        val httpService = request.httpService()
        val method = request.method()
        val url = "${if (httpService.secure()) "https" else "http"}://${httpService.host()}${request.path()}"

        val requestHeaders = request.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        val requestBody = request.body()?.toString()?.take(maxBodySize)
        val responseHeaders = response?.headers()?.joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        val responseBody = response?.body()?.toString()?.take(maxBodySize)
        val contentType = response?.headerValue("Content-Type")
        val paramNames = extractParamNames(request.body()?.toString(), request.path())

        ProxyHttpEntry(
            id = this.time().toEpochSecond().toInt().coerceAtLeast(0),
            method = method,
            status = response?.statusCode()?.toInt(),
            url = url,
            requestHeaders = requestHeaders,
            requestBody = requestBody,
            responseHeaders = responseHeaders,
            responseBody = responseBody,
            contentType = contentType,
            paramNames = paramNames?.joinToString(","),
            capturedAt = System.currentTimeMillis(),
            dedupKey = Database.computeDedupKey(method, url)
        )
    } catch (e: Exception) {
        LogWriter.instance?.log("WARN", "exporter", "Failed to convert proxy entry: ${e.message}", e)
        null
    }
}

private fun buildUrl(request: burp.api.montoya.http.message.requests.HttpRequest): String? {
    val httpService = request.httpService()
    val path = request.path() ?: return null
    return "${if (httpService.secure()) "https" else "http"}://${httpService.host()}$path"
}

private fun isBrowserNoise(
    request: burp.api.montoya.http.message.requests.HttpRequest,
    url: String,
    noiseMode: String
): Boolean {
    val parsed = runCatching { URI(url) }.getOrNull()
    val path = parsed?.path?.lowercase(Locale.ROOT) ?: ""
    val method = request.method().uppercase(Locale.ROOT)
    val accept = request.headerValue("Accept")?.lowercase(Locale.ROOT).orEmpty()
    val secFetchDest = request.headerValue("Sec-Fetch-Dest")?.lowercase(Locale.ROOT).orEmpty()
    val purpose = request.headerValue("Purpose")?.lowercase(Locale.ROOT).orEmpty()
    val xPurpose = request.headerValue("X-Purpose")?.lowercase(Locale.ROOT).orEmpty()
    val secPurpose = request.headerValue("Sec-Purpose")?.lowercase(Locale.ROOT).orEmpty()
    val accessControlRequestMethod = request.headerValue("Access-Control-Request-Method")

    if (method !in setOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")) {
        return true
    }

    if (method == "OPTIONS" && !accessControlRequestMethod.isNullOrBlank()) {
        return true
    }

    if (purpose in setOf("prefetch", "prerender") ||
        xPurpose in setOf("prefetch", "prerender") ||
        secPurpose in setOf("prefetch", "prerender")
    ) {
        return true
    }

    if (STATIC_ASSET_EXTENSIONS.any { path.endsWith(it) }) {
        return true
    }

    if (noiseMode == EXPORT_NOISE_MODE_RELAXED) {
        return false
    }

    if (LOW_VALUE_BROWSER_PATH_SUFFIXES.any { path.endsWith(it) }) {
        return true
    }

    if (noiseMode == EXPORT_NOISE_MODE_STRICT &&
        LOW_VALUE_BROWSER_PATH_FRAGMENTS.any { path.contains(it) }
    ) {
        return true
    }

    if (secFetchDest in setOf("image", "style", "script", "font", "video", "audio")) {
        return true
    }

    if (accept.contains("image/") ||
        accept.contains("text/css") ||
        accept.contains("font/") ||
        accept.contains("javascript")
    ) {
        return true
    }

    if (noiseMode == EXPORT_NOISE_MODE_BALANCED) {
        return false
    }

    return false
}

private fun AuditIssue.toScannerIssueEntry(maxBodySize: Int): ScannerIssueEntry? {
    return try {
        val reqRes = this.requestResponses().firstOrNull()
        val issueUrl = reqRes?.request()?.url() ?: "unknown"
        // Combine name + URL hash to reduce collision between same-named issues on different endpoints
        val issueId = (this.name().hashCode() * 31 + issueUrl.hashCode()).coerceAtLeast(0)
        ScannerIssueEntry(
            id = issueId,
            name = this.name(),
            severity = this.severity().name,
            url = issueUrl,
            detail = reqRes?.request()?.body()?.toString()?.take(maxBodySize),
            remediation = this.remediation(),
            capturedAt = System.currentTimeMillis()
        )
    } catch (e: Exception) {
        LogWriter.instance?.log("WARN", "exporter", "Failed to convert scanner issue: ${e.message}", e)
        null
    }
}

internal fun extractParamNames(body: String?, path: String?): List<String>? {
    val params = mutableListOf<String>()
    path?.let {
        val queryStart = it.indexOf('?')
        if (queryStart >= 0) {
            it.substring(queryStart + 1).split("&").forEach { pair ->
                val eqIdx = pair.indexOf('=')
                if (eqIdx > 0) {
                    params.add(pair.substring(0, eqIdx))
                } else if (pair.isNotEmpty()) {
                    params.add(pair)
                }
            }
        }
    }
    body?.let {
        it.split("&").forEach { pair ->
            val eqIdx = pair.indexOf('=')
            if (eqIdx > 0) {
                val name = pair.substring(0, eqIdx)
                if (name !in params) params.add(name)
            }
        }
    }
    return params.take(20).ifEmpty { null }
}
