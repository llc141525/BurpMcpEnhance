package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.PromptMessageContent
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import kotlin.experimental.ExperimentalTypeInference

@PublishedApi
internal val lenientJson = Json {
    ignoreUnknownKeys = true
    isLenient = true
}

/** Recursively converts float/double JsonPrimitives that represent whole numbers to integers.
 *  Handles cases like 20.0 -> 20 so tree decoder doesn't fail when target type is Int. */
@PublishedApi
internal fun normalizeJsonElement(element: kotlinx.serialization.json.JsonElement): kotlinx.serialization.json.JsonElement {
    return when (element) {
        is kotlinx.serialization.json.JsonPrimitive -> {
            val value = element.content
            if (element.isString) {
                element
            } else {
                // Check if it's a floating point number that represents a whole number
                val doubleVal = value.toDoubleOrNull()
                if (doubleVal != null && doubleVal == doubleVal.toLong().toDouble() && value.contains('.')) {
                    kotlinx.serialization.json.JsonPrimitive(doubleVal.toLong())
                } else {
                    element
                }
            }
        }
        is kotlinx.serialization.json.JsonObject -> {
            kotlinx.serialization.json.JsonObject(
                element.mapValues { (_, v) -> normalizeJsonElement(v) }
            )
        }
        is kotlinx.serialization.json.JsonArray -> {
            kotlinx.serialization.json.JsonArray(
                element.map { normalizeJsonElement(it) }
            )
        }
    }
}

@PublishedApi
internal const val DEFAULT_MAX_RESPONSE_SIZE = 100_000
@PublishedApi
internal const val DEFAULT_MAX_PAGE_SIZE = 20
@PublishedApi
internal const val DEFAULT_TOOL_TIMEOUT_MS = 120_000L

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> List<PromptMessageContent>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")

    addTool(
        name = toolName,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            try {
                CallToolResult(
                    content = withTimeout(DEFAULT_TOOL_TIMEOUT_MS) {
                        execute(
                            lenientJson.decodeFromJsonElement(
                                I::class.serializer(),
                                normalizeJsonElement(request.arguments)
                            )
                        )
                    }
                )
            } catch (e: TimeoutCancellationException) {
                CallToolResult(
                    content = listOf(TextContent("Error: Tool execution timed out after ${DEFAULT_TOOL_TIMEOUT_MS / 1000}s")),
                    isError = true
                )
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("Error: ${e.message}")),
                    isError = true
                )
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

@PublishedApi
internal fun joinWithSizeLimit(
    items: List<CharSequence>,
    separator: String = "\n\n",
    maxSize: Int = DEFAULT_MAX_RESPONSE_SIZE
): String {
    val sb = StringBuilder()
    var first = true
    for (item in items) {
        val part = if (first) item.toString() else "$separator$item"
        if (sb.length + part.length > maxSize) {
            sb.append("\n\n... (response truncated, request fewer items)")
            break
        }
        sb.append(part)
        first = false
    }
    return sb.toString()
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)

        when {
            offset >= items.size -> {
                "Reached end of items"
            }

            else -> {
                val actualCount = count.coerceAtMost(DEFAULT_MAX_PAGE_SIZE)
                val upperLimit = (offset + actualCount).coerceAtMost(items.size)

                joinWithSizeLimit(
                    items = items.subList(offset, upperLimit).map(mapper)
                )
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val seq = execute(this)
        val paginated = seq.drop(offset).take(count.coerceAtMost(DEFAULT_MAX_PAGE_SIZE)).toList()

        if (paginated.isEmpty()) {
            listOf(TextContent("Reached end of items"))
        } else {
            listOf(TextContent(joinWithSizeLimit(paginated)))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> List<PromptMessageContent>
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            try {
                CallToolResult(
                    content = withTimeout(DEFAULT_TOOL_TIMEOUT_MS) { execute() }
                )
            } catch (e: TimeoutCancellationException) {
                CallToolResult(
                    content = listOf(TextContent("Error: Tool execution timed out after ${DEFAULT_TOOL_TIMEOUT_MS / 1000}s")),
                    isError = true
                )
            }
        }
    )
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> String
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            try {
                CallToolResult(
                    content = listOf(TextContent(withTimeout(DEFAULT_TOOL_TIMEOUT_MS) { execute() }))
                )
            } catch (e: TimeoutCancellationException) {
                CallToolResult(
                    content = listOf(TextContent("Error: Tool execution timed out after ${DEFAULT_TOOL_TIMEOUT_MS / 1000}s")),
                    isError = true
                )
            }
        }
    )
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}

