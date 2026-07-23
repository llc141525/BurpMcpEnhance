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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity

@Serializable
data class ManageScope(
    val action: String,
    val url: String = ""
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
    val auditType: String = "active",
    val content: String? = null
)

fun Server.registerScopeTools(
    api: MontoyaApi,
    config: McpConfig,
    advancedTools: Boolean = false,
    onScopeChanged: () -> Unit = {}
) {

    mcpTool<ManageScope>(
        "Manages Burp's target scope. " +
        "action: 'add' — include URL in scope (url required); " +
        "'ensure' — idempotently include URL only if missing (url required); " +
        "'remove' — exclude URL from scope (url required); " +
        "'check' — test if URL is currently in scope (url required); " +
        "'list' — export all current scope rules as JSON (url not needed); " +
        "'clear' — remove all include rules from scope (url not needed). " +
        "URL examples: 'https://example.com', 'https://api.example.com/v1/'. " +
        "To backup/restore scope: action='list' to get JSON, then use set_project_options " +
        "with that JSON wrapped under a top-level 'project_options' key to restore."
    ) {
        when (action.lowercase()) {
            "add" -> {
                if (url.isBlank()) return@mcpTool "URL is required for action: add"
                api.scope().includeInScope(url)
                onScopeChanged()
                "Added to scope: $url"
            }
            "ensure" -> {
                if (url.isBlank()) return@mcpTool "URL is required for action: ensure"
                if (api.scope().isInScope(url)) {
                    "Scope unchanged: $url is already in scope"
                } else {
                    api.scope().includeInScope(url)
                    onScopeChanged()
                    "Scope added: $url"
                }
            }
            "remove" -> {
                if (url.isBlank()) return@mcpTool "URL is required for action: remove"
                api.scope().excludeFromScope(url)
                onScopeChanged()
                "Removed from scope: $url"
            }
            "check" -> {
                if (url.isBlank()) return@mcpTool "URL is required for action: check"
                if (api.scope().isInScope(url)) "In scope: $url" else "NOT in scope: $url"
            }
            "list" -> {
                val raw = api.burpSuite().exportProjectOptionsAsJson()
                try {
                    val scope = kotlinx.serialization.json.Json.parseToJsonElement(raw)
                        .jsonObject["project_options"]
                        ?.jsonObject?.get("target")
                        ?.jsonObject?.get("scope")
                    "Current scope (project_options.target.scope):\n${scope ?: "not found"}"
                } catch (e: Exception) {
                    "Could not parse scope: ${e.message}\nRaw:\n$raw"
                }
            }
            "clear" -> {
                val raw = api.burpSuite().exportProjectOptionsAsJson()
                try {
                    val cleared = clearScopeIncludes(raw)
                    api.burpSuite().importProjectOptionsFromJson(cleared)
                    onScopeChanged()
                    "All scope include rules cleared."
                } catch (e: Exception) {
                    "Failed to clear scope: ${e.message}"
                }
            }
            else -> "Invalid action: $action. Use 'add', 'ensure', 'remove', 'check', 'list', or 'clear'."
        }
    }

    if (advancedTools) {
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
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpTool<StartActiveScan>(
            "Starts a Burp active scan of the specified URL (Pro only). " +
            "auditType options: 'active' — active checks (default); 'passive' — passive checks only. " +
            "IMPORTANT: pass the full raw HTTP request (request line, headers, cookies, body) via the optional 'content' param " +
            "so request-shape-dependent extensions actually fire — e.g. FastjsonScan needs a POST JSON body, " +
            "ShiroScan needs a rememberMe cookie, Java Deserialization Scanner needs a body. " +
            "Without 'content', the scan falls back to a bare GET of the URL (only query-string params become insertion points). " +
            "Installed scanner extensions (Active Scan++, FastjsonScan, ShiroScan, etc.) run automatically. " +
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
            val scopeCheck = if (api.scope().isInScope(url)) "in scope" else "NOT in scope"
            if (scopeCheck == "NOT in scope") {
                return@mcpTool "Active scan not started: $url is NOT in scope. " +
                    "Call manage_scope(action=\"ensure\", url=\"$url\") first."
            }

            val requestText = buildScanRequestText(content, host, path)

            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(host, port, config, requestText, api)
            }
            if (!allowed) return@mcpTool "Request denied by Burp Suite"

            val request = HttpRequest.httpRequest(
                HttpService.httpService(host, port, secure),
                requestText
            )
            val response = api.http().sendRequest(request)

            if (response == null) {
                "Failed to fetch URL (no response): $url"
            } else {
                val audit = api.scanner().startAudit(auditConfig)
                audit.addRequestResponse(response)
                val mode = if (content.isNullOrBlank()) "bare GET" else "custom request"
                "Active scan started: $url (auditType=$auditType, $mode). " +
                "Scope check: $scopeCheck. Poll results with list_scanner_issues."
            }
        }
    }
}

internal fun clearScopeIncludes(rawProjectOptionsJson: String): String {
    val root = Json.parseToJsonElement(rawProjectOptionsJson).jsonObject
    val projectOptions = root["project_options"]?.jsonObject ?: error("project_options not found")
    val target = projectOptions["target"]?.jsonObject ?: error("project_options.target not found")
    val scope = target["scope"]?.jsonObject ?: error("project_options.target.scope not found")

    val updatedScope = JsonObject(scope + ("include" to JsonArray(emptyList())))
    val updatedTarget = JsonObject(target + ("scope" to updatedScope))
    val updatedProjectOptions = JsonObject(projectOptions + ("target" to updatedTarget))
    val updatedRoot: JsonElement = JsonObject(root + ("project_options" to updatedProjectOptions))
    return Json.encodeToString(JsonElement.serializer(), updatedRoot)
}

internal fun normalizeScanRequestContent(content: String): String =
    content.replace("\r", "").replace("\n", "\r\n")

/**
 * Builds the raw HTTP request text to audit. When [content] is non-blank it is returned with line
 * endings normalized to CRLF (preserving the method, headers, cookies, and body); [host] and [path]
 * are used only to synthesize the bare-GET fallback when no [content] is supplied.
 */
internal fun buildScanRequestText(content: String?, host: String, path: String): String =
    if (!content.isNullOrBlank()) {
        normalizeScanRequestContent(content)
    } else {
        "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
    }
