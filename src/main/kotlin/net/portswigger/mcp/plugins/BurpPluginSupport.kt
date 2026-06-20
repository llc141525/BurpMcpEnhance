package net.portswigger.mcp.plugins

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

data class BurpPluginDescriptor(
    val name: String,
    val category: PluginCategory,
    val description: String,
    val autoAppliesToSendHttp: Boolean = false,
    val autoAppliesToActiveScan: Boolean = false
)

enum class PluginCategory {
    REQUEST_HANDLER,
    SCANNER_EXTENSION,
    DISCOVERY,
    OTHER
}

data class BurpPluginInventory(
    val detectedPlugins: List<String>,
    val knownPlugins: List<BurpPluginDescriptor>,
    val configuredPlugins: List<String>,
    val detectionSource: String
) {
    val effectivePluginNames: List<String>
        get() = (detectedPlugins + configuredPlugins).distinct()

    val matchedKnownPlugins: List<BurpPluginDescriptor>
        get() = effectivePluginNames.mapNotNull { name ->
            KNOWN_BURP_PLUGINS.find { descriptor -> descriptor.name.equals(name, ignoreCase = true) }
        }

    val unmatchedPluginNames: List<String>
        get() = effectivePluginNames.filter { pluginName ->
            KNOWN_BURP_PLUGINS.none { it.name.equals(pluginName, ignoreCase = true) }
        }
}

private val json = Json { ignoreUnknownKeys = true }

val KNOWN_BURP_PLUGINS = listOf(
    BurpPluginDescriptor("Bypass WAF", PluginCategory.REQUEST_HANDLER, "对发出的请求做绕过与变形处理。", autoAppliesToSendHttp = true),
    BurpPluginDescriptor("Knife", PluginCategory.REQUEST_HANDLER, "常用渗透辅助插件，常参与请求构造与变形。", autoAppliesToSendHttp = true),
    BurpPluginDescriptor("403 Bypasser", PluginCategory.REQUEST_HANDLER, "自动尝试 403 绕过变体。", autoAppliesToSendHttp = true),
    BurpPluginDescriptor("autoDecoder", PluginCategory.REQUEST_HANDLER, "自动编解码请求与响应内容。", autoAppliesToSendHttp = true),
    BurpPluginDescriptor("captcha-killer", PluginCategory.REQUEST_HANDLER, "请求链路中的验证码处理支持。", autoAppliesToSendHttp = true),
    BurpPluginDescriptor("Content Type Converter", PluginCategory.REQUEST_HANDLER, "自动在常见内容类型间转换请求体。", autoAppliesToSendHttp = true),
    BurpPluginDescriptor("Active Scan++", PluginCategory.SCANNER_EXTENSION, "增强主动扫描 payload 与检查逻辑。", autoAppliesToActiveScan = true),
    BurpPluginDescriptor("Param Miner", PluginCategory.DISCOVERY, "发现隐藏参数，可联动主动扫描。", autoAppliesToActiveScan = true),
    BurpPluginDescriptor("HTTP Request Smuggler", PluginCategory.SCANNER_EXTENSION, "检测请求走私问题。", autoAppliesToActiveScan = true),
    BurpPluginDescriptor("FastjsonScan", PluginCategory.SCANNER_EXTENSION, "针对 Fastjson 的扫描扩展。", autoAppliesToActiveScan = true),
    BurpPluginDescriptor("ShiroScan", PluginCategory.SCANNER_EXTENSION, "针对 Apache Shiro 的扫描扩展。", autoAppliesToActiveScan = true),
    BurpPluginDescriptor("Struts RCE", PluginCategory.SCANNER_EXTENSION, "针对 Struts RCE 的专项检查。", autoAppliesToActiveScan = true),
    BurpPluginDescriptor("Retire.js", PluginCategory.SCANNER_EXTENSION, "识别存在风险的前端 JS 依赖。", autoAppliesToActiveScan = true)
)

fun collectBurpPluginInventory(api: MontoyaApi, configuredPlugins: List<String>): BurpPluginInventory {
    val userOptionsJson = runCatching { api.burpSuite().exportUserOptionsAsJson() }.getOrNull()
    val detectedPlugins = userOptionsJson?.let(::extractPluginNamesFromUserOptions).orEmpty()
    val detectionSource = if (detectedPlugins.isNotEmpty()) "user_options" else "configured_list"

    return BurpPluginInventory(
        detectedPlugins = detectedPlugins,
        knownPlugins = KNOWN_BURP_PLUGINS,
        configuredPlugins = configuredPlugins,
        detectionSource = detectionSource
    )
}

fun buildBurpInfoSummary(api: MontoyaApi, inventory: BurpPluginInventory): String {
    val version = api.burpSuite().version()
    val edition = version.edition()
    val isPro = edition == BurpSuiteEdition.PROFESSIONAL

    return buildString {
        appendLine("Edition: $edition")
        appendLine("Version: $version")
        appendLine()
        appendLine("Available tool categories:")
        appendLine("  HTTP: send_http1_request, send_http2_request, create_repeater_tab, send_to_intruder")
        appendLine("  Proxy: get_proxy_http_history (+ regex filter), get_proxy_websocket_history")
        appendLine("  Scope: manage_scope, get_site_map")
        appendLine("  Site map: get_site_map")
        appendLine("  Diff: diff_proxy_responses")
        appendLine("  GraphQL: graphql_introspect, graphql_list_types, graphql_describe_type, graphql_query")
        appendLine("  Utilities: url_encode, url_decode, base64_encode, base64_decode, generate_random_string")
        appendLine("  Editor: get_active_editor_contents, set_active_editor_contents")
        appendLine("  Config: manage_auto_approve_targets, set_task_execution_engine_state, set_proxy_intercept_state")
        appendLine()
        appendLine("Third-party plugin support:")
        appendLine("  Detection source: ${inventory.detectionSource}")
        appendLine("  Detected/configured plugins: ${inventory.effectivePluginNames.size}")
        if (inventory.effectivePluginNames.isEmpty()) {
            appendLine("  No third-party plugins detected. You can add known plugin names in the MCP tab UI.")
        } else {
            appendLine("  Available plugins:")
            inventory.effectivePluginNames.forEach { pluginName ->
                appendLine("    - $pluginName")
            }
        }
        appendLine()
        appendLine("Request-handler plugins that can affect send_http1_request if installed:")
        inventory.knownPlugins.filter { it.autoAppliesToSendHttp }.forEach { plugin ->
            appendLine("  - ${plugin.name}")
        }
        appendLine()
        appendLine("Scanner/discovery plugins that can participate in start_active_scan if installed:")
        inventory.knownPlugins.filter { it.autoAppliesToActiveScan }.forEach { plugin ->
            appendLine("  - ${plugin.name}")
        }
        if (isPro) {
            appendLine()
            appendLine("Pro-only tools:")
            appendLine("  Scanner: start_active_scan, get_scanner_issues")
            appendLine("  Collaborator: generate_collaborator_payload, get_collaborator_interactions")
        } else {
            appendLine()
            appendLine("Pro-only tools: not available (requires Burp Suite Professional)")
        }
    }.trimEnd()
}

private fun extractPluginNamesFromUserOptions(userOptionsJson: String): List<String> {
    val root = runCatching { json.parseToJsonElement(userOptionsJson) }.getOrNull() as? JsonObject ?: return emptyList()
    val collected = linkedSetOf<String>()
    collectPluginNamesRecursively(root, collected)
    return collected.toList()
}

private fun collectPluginNamesRecursively(element: JsonElement, sink: MutableSet<String>) {
    when (element) {
        is JsonObject -> {
            val looksLikePluginNode = element.keys.any { key ->
                key.contains("extension", ignoreCase = true) ||
                    key.contains("plugin", ignoreCase = true) ||
                    key.contains("bapp", ignoreCase = true)
            }
            if (looksLikePluginNode) {
                extractNamesFromObject(element).forEach(sink::add)
            }
            element.values.forEach { value -> collectPluginNamesRecursively(value, sink) }
        }
        is JsonArray -> {
            element.forEach { item -> collectPluginNamesRecursively(item, sink) }
        }
        else -> Unit
    }
}

private fun extractNamesFromObject(element: JsonObject): List<String> {
    val candidates = mutableListOf<String>()
    val preferredKeys = listOf("name", "extension_name", "plugin_name", "display_name", "bapp_name")

    preferredKeys.forEach { key ->
        val value = element[key] as? JsonPrimitive
        value?.contentOrNull?.takeIf(::looksLikePluginName)?.let(candidates::add)
    }

    element.values.filterIsInstance<JsonPrimitive>().forEach { primitive ->
        primitive.contentOrNull?.takeIf(::looksLikePluginName)?.let(candidates::add)
    }

    return candidates.distinct()
}

private fun looksLikePluginName(value: String): Boolean {
    if (value.length < 3 || value.length > 80) return false
    val normalized = value.trim()
    if (normalized.startsWith("{") || normalized.startsWith("[")) return false
    if (normalized.contains("/") || normalized.contains("\\")) return false
    return KNOWN_BURP_PLUGINS.any { it.name.equals(normalized, ignoreCase = true) } ||
        normalized.any { it.isLetter() } && normalized.any { it.isWhitespace() || it in "+-._" }
}
