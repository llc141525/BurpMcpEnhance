package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import java.util.concurrent.ConcurrentHashMap

object GraphQLSchemaCache {
    private val cache = ConcurrentHashMap<String, JsonObject>()

    fun store(key: String, schema: JsonObject) { cache[key] = schema }
    fun get(key: String): JsonObject? = cache[key]
    fun keys(): Set<String> = cache.keys.toSet()
    fun clear() { cache.clear() }
}

internal fun resolveTypeRef(typeObj: JsonObject?): String {
    if (typeObj == null) return "Unknown"
    val kind = typeObj["kind"]?.jsonPrimitive?.contentOrNull ?: return "Unknown"
    return when (kind) {
        "NON_NULL" -> resolveTypeRef(typeObj["ofType"]?.jsonObject) + "!"
        "LIST" -> "[${resolveTypeRef(typeObj["ofType"]?.jsonObject)}]"
        else -> typeObj["name"]?.jsonPrimitive?.contentOrNull ?: kind
    }
}

@Serializable
data class GraphqlIntrospect(
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val path: String = "/graphql"
) : HttpServiceParams

@Serializable
data class GraphqlListTypes(val cacheKey: String)

@Serializable
data class GraphqlDescribeType(val cacheKey: String, val typeName: String)

@Serializable
data class GraphqlQuery(
    val query: String,
    val variables: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val path: String = "/graphql"
) : HttpServiceParams

private val introspectionQuery = """
{"query":"{__schema{queryType{name}mutationType{name}types{name kind description fields{name description type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}args{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}}}"}
""".trimIndent()

fun Server.registerGraphQLTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<GraphqlIntrospect>(
        "Sends a GraphQL introspection query to the target and caches the schema in memory. " +
        "Returns a summary of discovered types and root fields (Query/Mutation). " +
        "Cache key format: 'hostname:port/path' (e.g. 'api.example.com:443/graphql'). " +
        "Run this first — subsequent graphql_list_types / graphql_describe_type calls read from the cache. " +
        "Useful for discovering hidden fields, deprecated arguments, and internal types for bug hunting."
    ) {
        val cacheKey = "$targetHostname:$targetPort$path"
        val displayRequest = "POST $path (GraphQL introspection)"

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, displayRequest, api)
        }
        if (!allowed) return@mcpTool "Request denied by Burp Suite"

        val scheme = if (usesHttps) "https" else "http"
        val rawRequest = buildString {
            appendLine("POST $path HTTP/1.1")
            appendLine("Host: $targetHostname:$targetPort")
            appendLine("Content-Type: application/json")
            appendLine("Content-Length: ${introspectionQuery.length}")
            appendLine("Connection: close")
            appendLine()
            append(introspectionQuery)
        }

        val request = HttpRequest.httpRequest(toMontoyaService(), rawRequest)
        val rr = api.http().sendRequest(request)
        val body = rr?.response()?.bodyToString()
            ?: return@mcpTool "No response from $targetHostname:$targetPort$path"

        val root = runCatching { lenientJson.parseToJsonElement(body).jsonObject }.getOrNull()
            ?: return@mcpTool "Failed to parse introspection response as JSON"

        val schema = root["data"]?.jsonObject?.get("__schema")?.jsonObject
            ?: return@mcpTool "Introspection response missing '__schema'. Response: ${body.take(500)}"

        GraphQLSchemaCache.store(cacheKey, schema)

        val types = schema["types"]?.jsonArray
            ?.mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull }
            ?.filterNot { it.startsWith("__") }
            ?: emptyList()

        val queryTypeName = schema["queryType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull
        val mutationTypeName = schema["mutationType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull

        val queryFields = schema["types"]?.jsonArray
            ?.firstOrNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull == queryTypeName }
            ?.jsonObject?.get("fields")?.jsonArray
            ?.mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull }
            ?: emptyList()

        buildString {
            appendLine("Schema cached with key: $cacheKey")
            appendLine()
            appendLine("Query type: $queryTypeName")
            if (mutationTypeName != null) appendLine("Mutation type: $mutationTypeName")
            appendLine()
            appendLine("Root fields (${queryFields.size}): ${queryFields.joinToString(", ")}")
            appendLine()
            appendLine("All types (${types.size}): ${types.take(30).joinToString(", ")}${if (types.size > 30) " …" else ""}")
        }.trimEnd()
    }

    mcpTool<GraphqlListTypes>(
        "Lists all non-introspection types in a cached GraphQL schema. " +
        "Requires graphql_introspect to have been called first with the same cacheKey. " +
        "Shows each type's name and kind (OBJECT, SCALAR, ENUM, INPUT_OBJECT, INTERFACE, UNION). " +
        "Use graphql_describe_type to drill into a specific type's fields and arguments."
    ) {
        val schema = GraphQLSchemaCache.get(cacheKey)
            ?: return@mcpTool "Schema not cached for key: $cacheKey. " +
                "Run graphql_introspect first. Available keys: ${GraphQLSchemaCache.keys().joinToString(", ").ifEmpty { "(none)" }}"

        val types = schema["types"]?.jsonArray
            ?.mapNotNull { it.jsonObject }
            ?.filterNot { it["name"]?.jsonPrimitive?.contentOrNull?.startsWith("__") == true }
            ?: emptyList()

        if (types.isEmpty()) return@mcpTool "No types found in cached schema."

        buildString {
            appendLine("Types in schema '$cacheKey' (${types.size}):")
            appendLine()
            types.forEach { t ->
                val name = t["name"]?.jsonPrimitive?.contentOrNull ?: return@forEach
                val kind = t["kind"]?.jsonPrimitive?.contentOrNull ?: "?"
                append("  $name  [$kind]")
                val desc = t["description"]?.jsonPrimitive?.contentOrNull
                if (!desc.isNullOrBlank()) append("  — $desc")
                appendLine()
            }
        }.trimEnd()
    }

    mcpTool<GraphqlDescribeType>(
        "Describes a specific type from a cached GraphQL schema: lists all fields with their types and arguments. " +
        "Requires graphql_introspect to have been called first. " +
        "Tip: look for fields with unusual arguments or deprecated fields — these are often overlooked attack surfaces."
    ) {
        val schema = GraphQLSchemaCache.get(cacheKey)
            ?: return@mcpTool "Schema not cached for key: $cacheKey. Run graphql_introspect first."

        val typeObj = schema["types"]?.jsonArray
            ?.mapNotNull { it.jsonObject }
            ?.firstOrNull { it["name"]?.jsonPrimitive?.contentOrNull == typeName }
            ?: return@mcpTool "Type '$typeName' not found in cached schema '$cacheKey'."

        val kind = typeObj["kind"]?.jsonPrimitive?.contentOrNull ?: "?"
        val desc = typeObj["description"]?.jsonPrimitive?.contentOrNull
        val fields = typeObj["fields"]?.jsonArray

        buildString {
            appendLine("Type: $typeName  [$kind]")
            if (!desc.isNullOrBlank()) appendLine("Description: $desc")
            appendLine()

            if (fields == null || fields.isEmpty()) {
                appendLine("(no fields)")
            } else {
                appendLine("Fields (${fields.size}):")
                fields.forEach { f ->
                    val fObj = f.jsonObject
                    val fName = fObj["name"]?.jsonPrimitive?.contentOrNull ?: return@forEach
                    val fType = resolveTypeRef(fObj["type"]?.jsonObject)
                    val fDesc = fObj["description"]?.jsonPrimitive?.contentOrNull
                    append("  $fName: $fType")
                    if (!fDesc.isNullOrBlank()) append("  — $fDesc")
                    appendLine()
                    val args = fObj["args"]?.jsonArray
                    if (args != null && args.isNotEmpty()) {
                        args.forEach { a ->
                            val aObj = a.jsonObject
                            val aName = aObj["name"]?.jsonPrimitive?.contentOrNull ?: return@forEach
                            val aType = resolveTypeRef(aObj["type"]?.jsonObject)
                            appendLine("    arg $aName: $aType")
                        }
                    }
                }
            }
        }.trimEnd()
    }

    mcpTool<GraphqlQuery>(
        "Executes an arbitrary GraphQL query or mutation against the target endpoint. " +
        "query: the GraphQL query string (e.g. '{ user(id: \"1\") { id name } }'). " +
        "variables: optional JSON string of variables (e.g. '{\"id\":\"1\"}'). " +
        "Returns the raw JSON response. Use graphql_introspect first to discover available fields."
    ) {
        val displayRequest = "POST $path (GraphQL query)"
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, displayRequest, api)
        }
        if (!allowed) return@mcpTool "Request denied by Burp Suite"

        val bodyJson = buildJsonObject {
            put("query", query)
            if (!variables.isNullOrBlank()) {
                put("variables", lenientJson.parseToJsonElement(variables))
            }
        }
        val bodyObj = bodyJson.toString()

        val rawRequest = buildString {
            appendLine("POST $path HTTP/1.1")
            appendLine("Host: $targetHostname:$targetPort")
            appendLine("Content-Type: application/json")
            appendLine("Content-Length: ${bodyObj.length}")
            appendLine("Connection: close")
            appendLine()
            append(bodyObj)
        }

        val request = HttpRequest.httpRequest(toMontoyaService(), rawRequest)
        val rr = api.http().sendRequest(request)
        rr?.response()?.bodyToString() ?: "No response from $targetHostname:$targetPort$path"
    }
}
