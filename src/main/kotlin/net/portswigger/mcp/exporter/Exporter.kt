package net.portswigger.mcp.exporter

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import kotlinx.coroutines.*
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.db.ProxyHttpEntry
import net.portswigger.mcp.db.ScannerIssueEntry
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class Exporter(
    private val api: MontoyaApi,
    private val database: Database,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
    private val pollIntervalMs: Long = 5000,
    private val maxBodySize: Int = 8192
) {
    private var job: Job? = null
    private val _totalExported = AtomicInteger(0)
    private val _lastExportTime = AtomicLong(0)
    private val _isRunning = AtomicInteger(0)

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
                    exportProxyHttpHistory()
                    exportScannerIssues()
                    _lastExportTime.set(System.currentTimeMillis())
                } catch (e: Exception) {
                    api.logging().logToError("MCP Exporter error: ${e.message}")
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

    internal suspend fun exportProxyHttpHistory() {
        withContext(Dispatchers.IO) {
            val maxId = database.getMaxProxyHttpId()
            val history = api.proxy().history()
            val newEntries = if (maxId != null) {
                history.filter { it.time().toEpochSecond() > maxId }
            } else {
                history
            }

            if (newEntries.isEmpty()) return@withContext

            val entries = newEntries.mapNotNull { it.toProxyHttpEntry(maxBodySize) }
            if (entries.isNotEmpty()) {
                database.upsertProxyHttpHistory(entries)
                _totalExported.addAndGet(entries.size)
            }
        }
    }

    internal suspend fun exportScannerIssues() {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) return
        withContext(Dispatchers.IO) {
            val maxId = database.getMaxScannerIssueId()
            val issues = api.siteMap().issues()
            val newIssues = if (maxId != null) {
                issues.filter { it.name().hashCode() > maxId }
            } else {
                issues
            }
            if (newIssues.isEmpty()) return@withContext
            val entries = newIssues.mapNotNull { it.toScannerIssueEntry(maxBodySize) }
            if (entries.isNotEmpty()) {
                database.upsertScannerIssues(entries)
                _totalExported.addAndGet(entries.size)
            }
        }
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
        val url = "${if (httpService.secure()) "https" else "http"}://${httpService.host()}${request.path()}"

        val requestHeaders = request.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        val requestBody = request.body()?.toString()?.take(maxBodySize)
        val responseHeaders = response?.headers()?.joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        val responseBody = response?.body()?.toString()?.take(maxBodySize)
        val contentType = response?.headerValue("Content-Type")
        val paramNames = extractParamNames(request.body()?.toString(), request.path())

        ProxyHttpEntry(
            id = this.time().toEpochSecond().toInt().coerceAtLeast(0),
            method = request.method(),
            status = response?.statusCode()?.toInt(),
            url = url,
            requestHeaders = requestHeaders,
            requestBody = requestBody,
            responseHeaders = responseHeaders,
            responseBody = responseBody,
            contentType = contentType,
            paramNames = paramNames?.joinToString(","),
            capturedAt = System.currentTimeMillis()
        )
    } catch (e: Exception) {
        null
    }
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
