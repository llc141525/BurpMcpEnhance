package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.exporter.Exporter

private const val DETAIL_BODY_MAX_BYTES = 8192

@Serializable
data class ListProxyHttpHistory(override val count: Int = 30, override val offset: Int = 0) : Paginated

@Serializable
data class GetProxyHttpDetail(
    val ids: String,
    val include_duplicates: Boolean = false,
    val include_body: Boolean = false
)

@Serializable
data class ListSecurityCandidates(
    override val count: Int = 20,
    override val offset: Int = 0,
    val minScore: Int = 30,
    val includeLowValue: Boolean = false
) : Paginated

@Serializable
data class ListScannerIssues(override val count: Int = 30, override val offset: Int = 0) : Paginated

@Serializable
data class GetScannerIssueDetail(val ids: String)

@Serializable
data class ExporterStats(val dummy: Boolean = true)

@Serializable
data class ClearDatabase(val target: String = "all")

fun Server.registerExporterTools(database: Database, exporter: Exporter, advancedTools: Boolean = false) {

    mcpTool<ListProxyHttpHistory>(
        "Lists proxy HTTP history from local cache. Returns lightweight entries with id, method, status, url, " +
        "content_type, param_names, hit_count, and candidate summary fields. Prefer list_security_candidates first, " +
        "then use get_proxy_http_detail with specific IDs only when you need request or response evidence. Use count ≤ 20."
    ) {
        val entries = database.listProxyHttpHistory(offset = offset, count = count.coerceAtMost(20))
        if (entries.isEmpty()) {
            "No proxy HTTP history entries found"
        } else {
            buildString {
                appendLine("Export noise mode: ${exporter.noiseModeSummary()}")
                appendLine()
                append(entries.joinToString("\n\n") { entry ->
                    buildString {
                        appendLine("ID: ${entry.id}")
                        appendLine("Method: ${entry.method}")
                        entry.status?.let { appendLine("Status: $it") }
                        appendLine("URL: ${entry.url}")
                        entry.contentType?.let { appendLine("Content-Type: $it") }
                        entry.paramNames?.let { appendLine("Params: ${it.joinToString(", ")}") }
                        if (entry.hitCount > 1) appendLine("Hits: ${entry.hitCount}")
                        if (entry.endpointScore > 0) appendLine("Endpoint-Score: ${entry.endpointScore}")
                        entry.candidateReason?.let { appendLine("Candidate-Reason: $it") }
                        entry.authRequiredHint?.let { appendLine("Auth-Hint: $it") }
                        if (entry.sensitiveMarkerCount > 0) appendLine("Sensitive-Markers: ${entry.sensitiveMarkerCount}")
                        entry.responseSummary?.let { appendLine("Response-Summary: $it") }
                    }
                })
                appendLine()
                append("Tip: use get_export_noise_mode or set_export_noise_mode to inspect or change cache filtering.")
            }
        }
    }

    mcpTool<ListSecurityCandidates>(
        "Lists high-signal proxy cache candidates ranked for security review. Returns only summary fields and no bodies. " +
        "Prefer this before reading raw history. Use minScore to tighten the queue, or includeLowValue=true to see the tail."
    ) {
        val entries = database.listSecurityCandidates(
            offset = offset,
            count = count.coerceAtMost(20),
            minScore = minScore.coerceIn(0, 100),
            includeLowValue = includeLowValue
        )
        if (entries.isEmpty()) {
            "No security candidates found"
        } else {
            buildString {
                appendLine("Export noise mode: ${exporter.noiseModeSummary()}")
                appendLine("Candidate threshold: score >= ${minScore.coerceIn(0, 100)}${if (includeLowValue) " (low-value included)" else ""}")
                appendLine()
                append(entries.joinToString("\n\n") { entry ->
                    buildString {
                        appendLine("ID: ${entry.id}")
                        appendLine("Method: ${entry.method}")
                        entry.status?.let { appendLine("Status: $it") }
                        appendLine("URL: ${entry.url}")
                        appendLine("Endpoint-Score: ${entry.endpointScore}")
                        entry.paramNames?.let { appendLine("Params: ${it.joinToString(", ")}") }
                        if (entry.hitCount > 1) appendLine("Hits: ${entry.hitCount}")
                        entry.candidateReason?.let { appendLine("Candidate-Reason: $it") }
                        entry.authRequiredHint?.let { appendLine("Auth-Hint: $it") }
                        if (entry.sensitiveMarkerCount > 0) appendLine("Sensitive-Markers: ${entry.sensitiveMarkerCount}")
                        entry.responseSummary?.let { appendLine("Response-Summary: $it") }
                    }
                })
            }
        }
    }

    mcpTool<GetProxyHttpDetail>(
        "Gets proxy HTTP history details by IDs. Provide comma-separated IDs (e.g., \"1,2,3\"). " +
        "Prefer list_security_candidates first. This returns request and response evidence for the specified entries. " +
        "By default, bodies are omitted to save tokens. Re-call with include_body=true when you need the body. " +
        "Set include_duplicates=true to also retrieve raw duplicate requests captured for the same endpoint " +
        "(e.g., multiple login attempts or credential-stuffing requests to the same URL). " +
        "Call list_proxy_http_history first to get IDs, then drill down with this tool."
    ) {
        val idList = ids.split(",").mapNotNull { it.trim().toIntOrNull() }
        if (idList.isEmpty()) return@mcpTool "No valid IDs provided: $ids"
        val entries = database.getProxyHttpDetail(
            idList,
            includeDuplicates = include_duplicates,
            includeBodies = include_body
        )
        if (entries.isEmpty()) return@mcpTool "No entries found for IDs: $ids"
        entries.joinToString("\n\n---\n\n") { entry ->
            buildString {
                appendLine("ID: ${entry.id}")
                appendLine("Method: ${entry.method}")
                entry.status?.let { appendLine("Status: $it") }
                appendLine("URL: ${entry.url}")
                entry.contentType?.let { appendLine("Content-Type: $it") }
                if (entry.hitCount > 1) appendLine("Hits: ${entry.hitCount}")
                entry.canonicalUrl?.let { appendLine("Canonical-URL: $it") }
                entry.endpointFingerprint?.let { appendLine("Endpoint-Fingerprint: $it") }
                if (entry.endpointScore > 0) appendLine("Endpoint-Score: ${entry.endpointScore}")
                entry.candidateReason?.let { appendLine("Candidate-Reason: $it") }
                entry.authRequiredHint?.let { appendLine("Auth-Hint: $it") }
                if (entry.sensitiveMarkerCount > 0) appendLine("Sensitive-Markers: ${entry.sensitiveMarkerCount}")
                entry.responseSummary?.let { appendLine("Response-Summary: $it") }
                appendLine()
                appendLine("--- Request ---")
                entry.requestHeaders?.let { appendLine(it) }
                if (include_body && !entry.requestBody.isNullOrBlank()) {
                    val body = entry.requestBody.limitUtf8Bytes(DETAIL_BODY_MAX_BYTES)
                    appendLine()
                    append(body.value)
                    if (body.truncated) {
                        appendLine()
                        appendLine("[Request body truncated to ${DETAIL_BODY_MAX_BYTES / 1024}KB]")
                    }
                } else if (!entry.requestBody.isNullOrBlank()) {
                    appendLine()
                    appendLine("Request body omitted. Re-run with include_body=true to inspect it.")
                }
                appendLine()
                appendLine("--- Response ---")
                entry.responseHeaders?.let { appendLine(it) }
                if (include_body && !entry.responseBody.isNullOrBlank()) {
                    val body = entry.responseBody.limitUtf8Bytes(DETAIL_BODY_MAX_BYTES)
                    appendLine()
                    append(body.value)
                    if (body.truncated) {
                        appendLine()
                        appendLine("[Response body truncated to ${DETAIL_BODY_MAX_BYTES / 1024}KB]")
                    }
                } else if (!entry.responseBody.isNullOrBlank()) {
                    appendLine()
                    appendLine("Response body omitted. Re-run with include_body=true to inspect it.")
                }
                if (entry.duplicates.isNotEmpty()) {
                    appendLine()
                    appendLine("--- Raw Duplicates (${entry.duplicates.size}) ---")
                    entry.duplicates.forEachIndexed { i, dup ->
                        appendLine()
                        appendLine("Duplicate ${i + 1}:")
                        dup.requestHeaders?.let { appendLine(it) }
                        if (include_body && !dup.requestBody.isNullOrBlank()) {
                            val body = dup.requestBody.limitUtf8Bytes(DETAIL_BODY_MAX_BYTES)
                            appendLine()
                            append(body.value)
                            if (body.truncated || dup.requestBodyTruncated) {
                                appendLine()
                                appendLine("[Duplicate request body truncated]")
                            }
                        } else if (dup.requestBodyTruncated) {
                            appendLine()
                            appendLine("Duplicate request body omitted and was truncated at capture time.")
                        }
                    }
                }
            }
        }
    }

    mcpTool<ListScannerIssues>(
        "Lists scanner issues from local cache. Returns lightweight entries with id, name, severity, and url. " +
        "Use get_scanner_issue_detail with specific IDs to get full details."
    ) {
        val entries = database.listScannerIssues(offset = offset, count = count.coerceAtMost(20))
        if (entries.isEmpty()) {
            "No scanner issues found"
        } else {
            entries.joinToString("\n\n") { entry ->
                buildString {
                    appendLine("ID: ${entry.id}")
                    appendLine("Name: ${entry.name}")
                    appendLine("Severity: ${entry.severity}")
                    appendLine("URL: ${entry.url}")
                }
            }
        }
    }

    mcpTool<GetScannerIssueDetail>(
        "Gets full scanner issue details by IDs. Provide comma-separated IDs (e.g., \"1,2,3\"). " +
        "Returns complete issue data including detail and remediation for the specified issues."
    ) {
        val idList = ids.split(",").mapNotNull { it.trim().toIntOrNull() }
        if (idList.isEmpty()) return@mcpTool "No valid IDs provided: $ids"
        val entries = database.getScannerIssueDetail(idList)
        if (entries.isEmpty()) return@mcpTool "No scanner issues found for IDs: $ids"
        entries.joinToString("\n\n---\n\n") { entry ->
            buildString {
                appendLine("ID: ${entry.id}")
                appendLine("Name: ${entry.name}")
                appendLine("Severity: ${entry.severity}")
                appendLine("URL: ${entry.url}")
                entry.detail?.let {
                    appendLine()
                    appendLine("--- Detail ---")
                    append(it)
                }
                entry.remediation?.let {
                    appendLine()
                    appendLine("--- Remediation ---")
                    append(it)
                }
            }
        }
    }

    mcpTool<ExporterStats>(
        "Returns the current status of the MCP Exporter. Shows whether the exporter is running, how many " +
        "entries have been exported, and database statistics."
    ) {
        val stats = exporter.stats
        buildString {
            appendLine("Exporter running: ${stats.isRunning}")
            appendLine("Total exported: ${stats.totalExported}")
            appendLine("Last export: ${if (stats.lastExportTime > 0) "yes" else "never"}")
            appendLine("History seen (last cycle): ${stats.historySeen}")
            appendLine("New entries (last cycle): ${stats.newEntriesSeen}")
            appendLine("Filtered out of scope (last cycle): ${stats.filteredOutOfScope}")
            appendLine("Filtered noise (last cycle): ${stats.filteredNoise}")
            appendLine("Exported (last cycle): ${stats.exportedThisCycle}")
            appendLine("Last cycle duration: ${stats.lastCycleDurationMs} ms")
            stats.lastCycleError?.let { appendLine("Last cycle error: $it") }
            appendLine("Database proxy HTTP entries: ${stats.dbStats.proxyHttpCount}")
            appendLine("Database scanner issues: ${stats.dbStats.scannerIssueCount}")
            if (stats.dbStats.blobCount > 0) appendLine("Database large responses: ${stats.dbStats.blobCount}")
            if (stats.dbStats.rawDuplicateCount > 0) appendLine("Raw duplicate requests: ${stats.dbStats.rawDuplicateCount}")
        }
    }

    if (advancedTools) {
        mcpTool<ClearDatabase>(
            "Clears cached data from the local database. Use target=\"all\" to clear everything, " +
            "\"proxy_history\" to clear only proxy HTTP history, or \"scanner_issues\" to clear only scanner issues."
        ) {
            when (target.lowercase()) {
                "all" -> {
                    database.clearAll()
                    exporter.notifyDatabaseCleared()
                    "Database cleared successfully"
                }
                "proxy_history" -> {
                    database.clearProxyHttpHistory()
                    exporter.notifyDatabaseCleared()
                    "Proxy HTTP history cleared"
                }
                "scanner_issues" -> {
                    database.clearScannerIssues()
                    "Scanner issues cleared"
                }
                else -> "Invalid target: $target. Use \"all\", \"proxy_history\", or \"scanner_issues\"."
            }
        }
    }
}

private data class LimitedBody(val value: String, val truncated: Boolean)

private fun String.limitUtf8Bytes(maxBytes: Int): LimitedBody {
    val bytes = toByteArray(Charsets.UTF_8)
    if (bytes.size <= maxBytes) return LimitedBody(this, false)
    var end = maxBytes
    while (end > 0 && (bytes[end].toInt() and 0xC0) == 0x80) {
        end--
    }
    return LimitedBody(String(bytes, 0, end, Charsets.UTF_8), true)
}
