package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity

@Serializable
data class ManageScope(
    val action: String,
    val url: String
)

@Serializable
data class GetSiteMap(
    val urlPrefix: String? = null,
    override val count: Int = 20,
    override val offset: Int = 0
) : Paginated

@Serializable
data class StartActiveScan(
    val url: String,
    val auditType: String = "active"
)

fun Server.registerScopeTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<ManageScope>(
        "Manages Burp's target scope. action: 'add' to include URL in scope, " +
        "'remove' to exclude URL from scope, 'check' to test if a URL is currently in scope. " +
        "URL examples: 'https://example.com', 'https://api.example.com/v1/'. " +
        "Always check scope before testing to avoid out-of-scope requests."
    ) {
        when (action.lowercase()) {
            "add" -> {
                api.scope().includeInScope(url)
                "Added to scope: $url"
            }
            "remove" -> {
                api.scope().excludeFromScope(url)
                "Removed from scope: $url"
            }
            "check" -> {
                if (api.scope().isInScope(url)) "In scope: $url" else "NOT in scope: $url"
            }
            else -> "Invalid action: $action. Use 'add', 'remove', or 'check'."
        }
    }

    mcpPaginatedTool<GetSiteMap>(
        "Returns discovered URLs from Burp's site map, populated by proxy traffic. " +
        "Optionally filter by URL prefix (e.g. 'https://api.example.com'). " +
        "Shows method, URL, and status code. Use count ≤ 20 to stay within token limits."
    ) {
        val entries = if (urlPrefix != null) {
            api.siteMap().requestResponses().filter { rr ->
                rr.request()?.url()?.startsWith(urlPrefix) == true
            }
        } else {
            api.siteMap().requestResponses()
        }
        entries.asSequence().map { rr ->
            val req = rr.request()
            val resp = rr.response()
            buildString {
                append("${req?.method() ?: "?"} ${req?.url() ?: "?"}")
                resp?.let { append(" [${it.statusCode()}]") }
            }
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpTool<StartActiveScan>(
            "Starts a Burp active scan of the specified URL (Pro only). " +
            "auditType options: 'active' — active checks (default); 'passive' — passive checks only. " +
            "Installed scanner extensions (Active Scan++, Param Miner, FastjsonScan, ShiroScan, etc.) run automatically. " +
            "Returns immediately. Poll results with list_scanner_issues (DB cache) or get_scanner_issues (live). " +
            "Tip: call manage_scope to add the URL to scope first."
        ) {
            val builtIn = when (auditType.lowercase()) {
                "passive" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                else -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            }
            val auditConfig = AuditConfiguration.auditConfiguration(builtIn)

            val parsed = java.net.URL(url)
            val host = parsed.host
            val port = if (parsed.port == -1) (if (parsed.protocol == "https") 443 else 80) else parsed.port
            val secure = parsed.protocol == "https"
            val path = if (parsed.file.isNullOrEmpty()) "/" else parsed.file

            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(host, port, config, "GET $path", api)
            }
            if (!allowed) return@mcpTool "Request denied by Burp Suite"

            val request = HttpRequest.httpRequest(
                HttpService.httpService(host, port, secure),
                "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
            )
            val response = api.http().sendRequest(request)

            if (response == null) {
                "Failed to fetch URL (no response): $url"
            } else {
                val audit = api.scanner().startAudit(auditConfig)
                audit.addRequestResponse(response)
                "Active scan started: $url (auditType=$auditType). " +
                "Poll results with list_scanner_issues."
            }
        }
    }
}

internal fun normalizeScanRequestContent(content: String): String =
    content.replace("\r", "").replace("\n", "\r\n")

internal fun buildScanRequestText(content: String?, host: String, path: String): String =
    if (!content.isNullOrBlank()) {
        normalizeScanRequestContent(content)
    } else {
        "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
    }
