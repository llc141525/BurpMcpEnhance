package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import net.portswigger.mcp.db.Database

@Serializable
data class DiffProxyResponses(
    val id1: String,
    val id2: String
)

fun Server.registerDiffTools(database: Database) {

    mcpTool<DiffProxyResponses>(
        "Diffs two HTTP responses from the proxy history DB by their IDs. " +
        "Returns ONLY the changed lines (added/removed), not the full responses. " +
        "Use this instead of reading both full responses — saves tokens for large payloads. " +
        "Get IDs from list_proxy_http_history. " +
        "Useful for comparing baseline vs. tampered request responses to confirm vulnerabilities."
    ) {
        val id1Int = id1.toIntOrNull() ?: return@mcpTool "Invalid ID: $id1 (must be integer)"
        val id2Int = id2.toIntOrNull() ?: return@mcpTool "Invalid ID: $id2 (must be integer)"

        val entries = database.getProxyHttpDetail(listOf(id1Int, id2Int))
        val e1 = entries.firstOrNull { it.id == id1Int }
            ?: return@mcpTool "Entry not found: $id1"
        val e2 = entries.firstOrNull { it.id == id2Int }
            ?: return@mcpTool "Entry not found: $id2"

        val r1 = buildString {
            e1.responseHeaders?.let { appendLine(it) }
            e1.responseBody?.let { append(it) }
        }
        val r2 = buildString {
            e2.responseHeaders?.let { appendLine(it) }
            e2.responseBody?.let { append(it) }
        }

        computeDiff(
            r1, r2,
            label1 = "ID:$id1 ${e1.method} ${e1.url}",
            label2 = "ID:$id2 ${e2.method} ${e2.url}"
        )
    }
}

internal fun computeDiff(text1: String, text2: String, label1: String = "Response 1", label2: String = "Response 2"): String {
    if (text1 == text2) return "Responses are identical."

    val lines1 = text1.lines()
    val lines2 = text2.lines()
    val set1 = lines1.filter { it.isNotBlank() }.toHashSet()
    val set2 = lines2.filter { it.isNotBlank() }.toHashSet()

    val removed = lines1.filter { it.isNotBlank() && it !in set2 }.take(50)
    val added = lines2.filter { it.isNotBlank() && it !in set1 }.take(50)

    return buildString {
        appendLine("--- $label1  (${lines1.size} lines, ${text1.length} bytes)")
        appendLine("+++ $label2  (${lines2.size} lines, ${text2.length} bytes)")
        if (removed.isNotEmpty()) {
            appendLine()
            appendLine("REMOVED (only in first):")
            removed.forEach { appendLine("- $it") }
        }
        if (added.isNotEmpty()) {
            appendLine()
            appendLine("ADDED (only in second):")
            added.forEach { appendLine("+ $it") }
        }
        if (removed.size >= 50 || added.size >= 50) {
            appendLine("\n(diff capped at 50 lines per side — responses differ significantly)")
        }
    }.trimEnd()
}
