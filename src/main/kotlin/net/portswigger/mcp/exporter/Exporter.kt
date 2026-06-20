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
import java.net.URLDecoder
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

private val NOISE_QUERY_KEYS = setOf(
    "_", "t", "ts", "timestamp", "cb", "cacheBust", "cache_bust", "nonce", "rnd"
)

private val SENSITIVE_RESPONSE_MARKERS = listOf(
    "\"token\"", "\"accessToken\"", "\"refreshToken\"", "\"secret\"", "\"apiKey\"",
    "\"authorization\"", "\"password\"", "\"session\"", "\"cookie\"", "\"set-cookie\""
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

    fun reimport() {
        lastProxyTimestampMs = 0L
        lastKnownScannerIssueCount = null
        scope.launch {
            try {
                exportProxyHttpHistory()
                exportScannerIssues()
            } catch (e: Exception) {
                api.logging().logToError("MCP Exporter reimport error: ${e.message}")
            }
        }
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
        val responseBody = response?.body()?.toString()?.take(maxBodySize)
        val contentType = response?.headerValue("Content-Type")
        val paramNames = extractParamNames(request.body()?.toString(), request.path())
        val signal = summarizeEndpoint(method, url, response?.statusCode()?.toInt(), contentType, paramNames, responseBody)

        val requestHeaders = request.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        val requestBody = request.body()?.toString()?.take(maxBodySize)
        val responseHeaders = response?.headers()?.joinToString("\r\n") { "${it.name()}: ${it.value()}" }

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
            dedupKey = Database.computeDedupKey(method, signal.canonicalUrl),
            canonicalUrl = signal.canonicalUrl,
            endpointFingerprint = signal.endpointFingerprint,
            requestParamCount = signal.requestParamCount,
            responseSummary = signal.responseSummary,
            sensitiveMarkerCount = signal.sensitiveMarkerCount,
            authRequiredHint = signal.authRequiredHint,
            endpointScore = signal.endpointScore,
            candidateReason = signal.candidateReason
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

private data class EndpointSignal(
    val canonicalUrl: String,
    val endpointFingerprint: String,
    val requestParamCount: Int,
    val responseSummary: String,
    val sensitiveMarkerCount: Int,
    val authRequiredHint: String?,
    val endpointScore: Int,
    val candidateReason: String?
)

private fun summarizeEndpoint(
    method: String,
    url: String,
    status: Int?,
    contentType: String?,
    paramNames: List<String>?,
    responseBody: String?
): EndpointSignal {
    val canonicalUrl = canonicalizeUrl(url)
    val normalizedContentType = contentType?.substringBefore(";")?.trim()?.lowercase(Locale.ROOT)
    val sensitiveMarkerCount = SENSITIVE_RESPONSE_MARKERS.sumOf { marker ->
        responseBody?.contains(marker, ignoreCase = true)?.let { if (it) 1 else 0 } ?: 0
    }
    val authRequiredHint = inferAuthRequiredHint(status, responseBody)
    val requestParamCount = paramNames?.size ?: 0
    val summaryParts = mutableListOf<String>()
    status?.let { summaryParts.add("status=$it") }
    normalizedContentType?.let { summaryParts.add("type=$it") }
    if (requestParamCount > 0) summaryParts.add("params=$requestParamCount")
    if (sensitiveMarkerCount > 0) summaryParts.add("sensitive=$sensitiveMarkerCount")
    authRequiredHint?.let { summaryParts.add("auth=$it") }

    val candidateReasons = mutableListOf<String>()
    var score = 0
    if (requestParamCount > 0) {
        score += 10 + minOf(requestParamCount, 5) * 4
        candidateReasons.add("has_params")
    }
    if (method.uppercase(Locale.ROOT) != "GET") {
        score += 10
        candidateReasons.add("state_change_surface")
    }
    if (normalizedContentType?.contains("json") == true) {
        score += 10
        candidateReasons.add("json_api")
    }
    if (sensitiveMarkerCount > 0) {
        score += 10 + sensitiveMarkerCount * 5
        candidateReasons.add("sensitive_markers")
    }
    if (authRequiredHint != null) {
        score += 15
        candidateReasons.add("auth_gate")
    }
    if ((status ?: 0) >= 500) {
        score += 10
        candidateReasons.add("server_error")
    }
    if (canonicalUrl.contains("/admin", ignoreCase = true) || canonicalUrl.contains("/manage", ignoreCase = true)) {
        score += 10
        candidateReasons.add("admin_surface")
    }

    return EndpointSignal(
        canonicalUrl = canonicalUrl,
        endpointFingerprint = Database.computeDedupKey(method.uppercase(Locale.ROOT), canonicalUrl),
        requestParamCount = requestParamCount,
        responseSummary = summaryParts.joinToString(", ").ifBlank { "status=${status ?: "unknown"}" },
        sensitiveMarkerCount = sensitiveMarkerCount,
        authRequiredHint = authRequiredHint,
        endpointScore = score.coerceAtMost(100),
        candidateReason = candidateReasons.distinct().take(4).joinToString(",").ifBlank { null }
    )
}

private fun canonicalizeUrl(url: String): String {
    val parsed = runCatching { URI(url) }.getOrNull() ?: return url
    val base = buildString {
        append(parsed.scheme ?: "http")
        append("://")
        append(parsed.host ?: parsed.authority.orEmpty())
        if (parsed.port != -1 && parsed.port != 80 && parsed.port != 443) {
            append(":")
            append(parsed.port)
        }
        append(parsed.path ?: "/")
    }
    val rawQuery = parsed.rawQuery ?: return base
    val normalizedQuery = rawQuery
        .split("&")
        .mapNotNull { pair ->
            if (pair.isBlank()) return@mapNotNull null
            val name = pair.substringBefore("=")
            val decoded = runCatching { URLDecoder.decode(name, Charsets.UTF_8.name()) }.getOrDefault(name)
            if (decoded in NOISE_QUERY_KEYS) null else decoded
        }
        .distinct()
        .sorted()
    return if (normalizedQuery.isEmpty()) base else "$base?${normalizedQuery.joinToString("&")}"
}

private fun inferAuthRequiredHint(status: Int?, responseBody: String?): String? {
    val body = responseBody?.lowercase(Locale.ROOT).orEmpty()
    return when {
        status == 401 -> "unauthenticated"
        status == 403 -> "forbidden"
        "login" in body || "sign in" in body || "unauthorized" in body -> "login_required"
        "access denied" in body || "permission" in body -> "forbidden"
        else -> null
    }
}
