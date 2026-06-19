package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.exporter.Exporter

@Serializable
data class ListProxyHttpHistory(override val count: Int = 30, override val offset: Int = 0) : Paginated

@Serializable
data class GetProxyHttpDetail(val ids: String, val include_duplicates: Boolean = false)

@Serializable
data class ListScannerIssues(override val count: Int = 30, override val offset: Int = 0) : Paginated

@Serializable
data class GetScannerIssueDetail(val ids: String)

@Serializable
data class ExporterStats(val dummy: Boolean = true)

@Serializable
data class ClearDatabase(val target: String = "all")

fun Server.registerExporterTools(database: Database, exporter: Exporter) {

    mcpTool<ListProxyHttpHistory>(
        "Lists proxy HTTP history from local cache. Returns lightweight entries with id, method, status, url, " +
        "content_type, param_names, and hit_count. Use get_proxy_http_detail with specific IDs to get full request/response data. " +
        "Use count ≤ 20 for smaller responses."
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
                    }
                })
                appendLine()
                append("Tip: use get_export_noise_mode or set_export_noise_mode to inspect or change cache filtering.")
            }
        }
    }

    mcpTool<GetProxyHttpDetail>(
        "Gets full proxy HTTP history details by IDs. Provide comma-separated IDs (e.g., \"1,2,3\"). " +
        "Returns complete request/response data for the specified entries. " +
        "Set include_duplicates=true to also retrieve raw duplicate requests captured for the same endpoint " +
        "(e.g., multiple login attempts or credential-stuffing requests to the same URL). " +
        "Call list_proxy_http_history first to get IDs, then drill down with this tool."
    ) {
        val idList = ids.split(",").mapNotNull { it.trim().toIntOrNull() }
        if (idList.isEmpty()) return@mcpTool "No valid IDs provided: $ids"
        val entries = database.getProxyHttpDetail(idList, includeDuplicates = include_duplicates)
        if (entries.isEmpty()) return@mcpTool "No entries found for IDs: $ids"
        entries.joinToString("\n\n---\n\n") { entry ->
            buildString {
                appendLine("ID: ${entry.id}")
                appendLine("Method: ${entry.method}")
                entry.status?.let { appendLine("Status: $it") }
                appendLine("URL: ${entry.url}")
                entry.contentType?.let { appendLine("Content-Type: $it") }
                if (entry.hitCount > 1) appendLine("Hits: ${entry.hitCount}")
                appendLine()
                appendLine("--- Request ---")
                entry.requestHeaders?.let { appendLine(it) }
                if (!entry.requestBody.isNullOrBlank()) {
                    appendLine()
                    append(entry.requestBody)
                }
                appendLine()
                appendLine("--- Response ---")
                entry.responseHeaders?.let { appendLine(it) }
                if (!entry.responseBody.isNullOrBlank()) {
                    appendLine()
                    append(entry.responseBody)
                    appendLine()
                    appendLine("[Body truncated to 8KB]")
                }
                if (entry.duplicates.isNotEmpty()) {
                    appendLine()
                    appendLine("--- Raw Duplicates (${entry.duplicates.size}) ---")
                    entry.duplicates.forEachIndexed { i, dup ->
                        appendLine()
                        appendLine("Duplicate ${i + 1}:")
                        dup.requestHeaders?.let { appendLine(it) }
                        if (!dup.requestBody.isNullOrBlank()) {
                            appendLine()
                            append(dup.requestBody)
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
            appendLine("Database proxy HTTP entries: ${stats.dbStats.proxyHttpCount}")
            appendLine("Database scanner issues: ${stats.dbStats.scannerIssueCount}")
            if (stats.dbStats.blobCount > 0) appendLine("Database large responses: ${stats.dbStats.blobCount}")
            if (stats.dbStats.rawDuplicateCount > 0) appendLine("Raw duplicate requests: ${stats.dbStats.rawDuplicateCount}")
        }
    }

    mcpTool<ClearDatabase>(
        "Clears cached data from the local database. Use target=\"all\" to clear everything, " +
        "\"proxy_history\" to clear only proxy HTTP history, or \"scanner_issues\" to clear only scanner issues."
    ) {
        when (target.lowercase()) {
            "all" -> {
                database.clearAll()
                "Database cleared successfully"
            }
            "proxy_history" -> {
                database.clearProxyHttpHistory()
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
