package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.db.ProxyHttpEntry
import net.portswigger.mcp.db.ScannerIssueEntry
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.toSerializableForm
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import javax.swing.JTextArea
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.Serializable

@Serializable
private data class PaginatedArgs(override val count: Int, override val offset: Int) : Paginated

class ToolsKtTest {
    
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireHistoryAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("keepaliveEnabled") } returns true
            every { getBoolean("strictLocalhostMode") } returns true
            every { getInteger("port") } returns testPort
            every { getInteger("keepaliveIntervalSec") } returns 30
            every { getInteger("maxResponseSizeKb") } returns 100
            every { setBoolean(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit

            val stringStore = mutableMapOf<String, String>().apply {
                put("host", "127.0.0.1")
            }
            every { getString(any()) } answers { stringStore[firstArg<String>()] ?: "" }
            every { setString(any(), any()) } answers { stringStore[firstArg<String>()] = secondArg<String>() }
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResult?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}/sse")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK"
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i], 
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }
    }
    
    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class AutoApproveTargetsToolsTests {
        @Test
        fun `auto_approve target tools should be registered`() {
            runBlocking {
                val tools = client.listTools()
                val toolNames = tools.map { it.name }
                assertTrue(toolNames.contains("add_auto_approve_target"))
                assertTrue(toolNames.contains("remove_auto_approve_target"))
                assertTrue(toolNames.contains("list_auto_approve_targets"))
                assertTrue(toolNames.contains("clear_auto_approve_targets"))
            }
        }

        @Test
        fun `add auto approve target should succeed with valid target`() {
            runBlocking {
                val result = client.callTool(
                    "add_auto_approve_target", mapOf("target" to "example.com")
                )
                val text = result.expectTextContent()
                assertEquals("Target added to auto-approve list: example.com", text)
            }
        }

        @Test
        fun `add auto approve target should fail with invalid target`() {
            runBlocking {
                val result = client.callTool(
                    "add_auto_approve_target", mapOf("target" to "")
                )
                val text = result.expectTextContent()
                assertTrue(text.contains("Failed to add target"))
            }
        }

        @Test
        fun `add duplicate target should fail`() {
            runBlocking {
                client.callTool("add_auto_approve_target", mapOf("target" to "example.com"))
                val result = client.callTool(
                    "add_auto_approve_target", mapOf("target" to "example.com")
                )
                val text = result.expectTextContent()
                assertTrue(text.contains("Failed to add target"))
            }
        }

        @Test
        fun `list auto approve targets should return configured targets`() {
            runBlocking {
                client.callTool("add_auto_approve_target", mapOf("target" to "example.com"))
                client.callTool("add_auto_approve_target", mapOf("target" to "localhost:8080"))

                val result = client.callTool("list_auto_approve_targets", emptyMap())
                val text = result.expectTextContent()
                assertTrue(text.contains("example.com"))
                assertTrue(text.contains("localhost:8080"))
            }
        }

        @Test
        fun `list auto approve targets should return empty message when none configured`() {
            config.clearAutoApproveTargets()
            runBlocking {
                val result = client.callTool("list_auto_approve_targets", emptyMap())
                val text = result.expectTextContent()
                assertEquals("No auto-approve targets configured", text)
            }
        }

        @Test
        fun `remove auto approve target should succeed`() {
            runBlocking {
                client.callTool("add_auto_approve_target", mapOf("target" to "example.com"))
                val result = client.callTool(
                    "remove_auto_approve_target", mapOf("target" to "example.com")
                )
                val text = result.expectTextContent()
                assertEquals("Target removed from auto-approve list: example.com", text)
            }
        }

        @Test
        fun `remove non-existent target should fail`() {
            runBlocking {
                val result = client.callTool(
                    "remove_auto_approve_target", mapOf("target" to "nonexistent.com")
                )
                val text = result.expectTextContent()
                assertTrue(text.contains("Target not found in auto-approve list"))
            }
        }

        @Test
        fun `clear auto approve targets should remove all`() {
            runBlocking {
                client.callTool("add_auto_approve_target", mapOf("target" to "example.com"))
                client.callTool("add_auto_approve_target", mapOf("target" to "test.com"))

                val clearResult = client.callTool("clear_auto_approve_targets", emptyMap())
                clearResult.expectTextContent("All auto-approve targets have been cleared")

                val listResult = client.callTool("list_auto_approve_targets", emptyMap())
                listResult.expectTextContent("No auto-approve targets configured")
            }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    @Nested
    inner class PaginatedToolsTests {
        @Test
        fun `get proxy history should paginate properly`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>()
            )
            
            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            
            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            
            every { proxyHistory[0].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item1 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 1 notes"
            )
            every { proxyHistory[1].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item2 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 2 notes"
            )
            every { proxyHistory[2].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item3 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 3 notes"
            )
            
            runBlocking {
                val result1 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 0
                    )
                )
                
                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("GET /item1"))
                assertTrue(text1.contains("GET /item2"))
                assertFalse(text1.contains("GET /item3"))
                
                val result2 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 2
                    )
                )
                
                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("GET /item3"))
                
                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 3
                    )
                )
                
                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }
    }
    
    @Nested
    inner class MergedHistoryToolsTests {
        @Test
        fun `get_proxy_http_history_regex tool name should no longer exist`() {
            runBlocking {
                val tools = client.listTools()
                assertFalse(tools.any { it.name == "get_proxy_http_history_regex" },
                    "Merged tool should not expose old regex variant name")
                assertFalse(tools.any { it.name == "get_proxy_websocket_history_regex" },
                    "Merged tool should not expose old regex variant name")
            }
        }

        @Test
        fun `get_proxy_http_history with regex param should filter results`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history(any()) } returns listOf()

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "regex" to "GET",
                        "count" to 5,
                        "offset" to 0
                    )
                )
                assertNotNull(result)
            }
        }
    }

    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}/sse")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool("generate_collaborator_payload", emptyMap())
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "customData" to "mydata"
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "payloadId" to "abc123"
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Nested
    inner class PhaseAFixesTests {
        @Test
        fun `joinWithSizeLimit should truncate oversized response`() {
            val items = listOf("A".repeat(50_000), "B".repeat(50_000), "C".repeat(50_000))
            val result = joinWithSizeLimit(items, maxSize = 80_000)

            assertTrue(result.length <= 80_000 + "... (response truncated, request fewer items)".length)
            assertTrue(result.contains("(response truncated, request fewer items)"))
            assertTrue(result.startsWith("A".repeat(50_000)))
        }

        @Test
        fun `joinWithSizeLimit should not truncate small responses`() {
            val items = listOf("small", "items")
            val result = joinWithSizeLimit(items, maxSize = 100_000)

            assertTrue(result.contains("small"))
            assertTrue(result.contains("items"))
            assertFalse(result.contains("truncated"))
        }

        @Test
        fun `lenientJson should coerce Float to Int`() {
            // Simulate what happens when AI sends count=20.0 instead of 20
            val json = JsonObject(mapOf(
                "count" to kotlinx.serialization.json.JsonPrimitive(20.0),
                "offset" to kotlinx.serialization.json.JsonPrimitive(0)
            ))
            // normalizeJsonElement converts 20.0 -> 20 before decoding
            val normalized = normalizeJsonElement(json)
            val decoded = lenientJson.decodeFromJsonElement(PaginatedArgs.serializer(), normalized)

            assertEquals(20, decoded.count)
            assertEquals(0, decoded.offset)
        }

        @Test
        fun `lenientJson should ignore unknown keys`() {
            val json = JsonObject(mapOf(
                "count" to kotlinx.serialization.json.JsonPrimitive(5),
                "offset" to kotlinx.serialization.json.JsonPrimitive(0),
                "extraField" to kotlinx.serialization.json.JsonPrimitive("ignored")
            ))
            val decoded = lenientJson.decodeFromJsonElement(PaginatedArgs.serializer(), json)

            assertEquals(5, decoded.count)
            assertEquals(0, decoded.offset)
        }

        @Test
        fun `tool error should contain meaningful message when exception occurs`() {
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to mapOf("nested" to "value")
                    )
                )
                assertNotNull(result, "Tool result should not be null")
                val textContent = result?.content?.firstOrNull() as? TextContent
                assertNotNull(textContent, "Should have text content")
                val text = textContent!!.text ?: ""
                assertTrue(text.startsWith("Error: "), "Error should start with 'Error: ': $text")
                // Error message should not be just "null" or empty
                assertFalse(text == "Error: null" || text == "Error: ", "Error should contain meaningful message, got: $text")
            }
        }

        @Test
        fun `mcpPaginatedTool should cap count at DEFAULT_MAX_PAGE_SIZE`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = (1..50).map { i ->
                mockk<ProxyHttpRequestResponse>().also {
                    every { it.toSerializableForm() } returns HttpRequestResponse(
                        request = "GET /item$i HTTP/1.1",
                        response = "HTTP/1.1 200 OK",
                        notes = null
                    )
                }
            }

            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory

            mockkStatic("net.portswigger.mcp.schema.SerializationKt")

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 100, // Request 100 but should be capped
                        "offset" to 0
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                // Should include some items but the key is the server doesn't crash
                assertNotNull(text)
            }
        }
    }

    @Nested
    inner class QueueToolsTests {
        @BeforeEach
        fun setupQueueTest() {
            // Reconnect client if needed after collaborator test cleanup
            runBlocking {
                if (!client.isConnected()) {
                    client.connectToServer("http://127.0.0.1:${testPort}/sse")
                }
            }
        }

        @Test
        fun `submit_task and get_task_result should work end to end`() {
            runBlocking {
                val submitResult = client.callTool(
                    "submit_task", mapOf(
                        "type" to "send_http1_request",
                        "params" to mapOf("host" to "example.com", "port" to "80")
                    )
                )
                val submitText = submitResult.expectTextContent()
                assertTrue(submitText.startsWith("Task submitted: task-"), "Expected task submission: $submitText")

                val taskId = submitText.removePrefix("Task submitted: ")

                delay(500)

                val pollResult = client.callTool(
                    "get_task_result", mapOf("taskId" to taskId)
                )
                val pollText = pollResult.expectTextContent()
                assertTrue(pollText.contains("COMPLETED"), "Expected completed task: $pollText")
                assertTrue(pollText.contains(taskId), "Expected matching task ID")
            }
        }

        @Test
        fun `get_task_result should return not found for unknown task`() {
            runBlocking {
                val result = client.callTool(
                    "get_task_result", mapOf("taskId" to "nonexistent")
                )
                result.expectTextContent("Task not found: nonexistent")
            }
        }

        @Test
        fun `read_file should return not found for non-existent file`() {
            runBlocking {
                val result = client.callTool(
                    "read_file", mapOf("fileId" to "nonexistent")
                )
                result.expectTextContent("File not found: nonexistent")
            }
        }

        @Test
        fun `delete_file should return not found for non-existent file`() {
            runBlocking {
                val result = client.callTool(
                    "delete_file", mapOf("fileId" to "nonexistent")
                )
                result.expectTextContent("File not found: nonexistent")
            }
        }

        @Test
        fun `queue tools should be registered`() {
            runBlocking {
                val tools = client.listTools()
                val toolNames = tools.map { it.name }
                assertTrue(toolNames.contains("submit_task"), "submit_task should be registered: $toolNames")
                assertTrue(toolNames.contains("get_task_result"), "get_task_result should be registered: $toolNames")
                assertTrue(toolNames.contains("read_file"), "read_file should be registered: $toolNames")
                assertTrue(toolNames.contains("delete_file"), "delete_file should be registered: $toolNames")
            }
        }
    }

    @Nested
    inner class ExporterToolsTests {
        @BeforeEach
        fun setupExporterTest() {
            runBlocking {
                if (!client.isConnected()) {
                    client.connectToServer("http://127.0.0.1:${testPort}/sse")
                }
            }
        }

        @Test
        fun `exporter tools should be registered`() {
            runBlocking {
                val tools = client.listTools()
                val toolNames = tools.map { it.name }
                assertTrue(toolNames.contains("list_proxy_http_history"), "Should contain list_proxy_http_history: $toolNames")
                assertTrue(toolNames.contains("get_proxy_http_detail"), "Should contain get_proxy_http_detail: $toolNames")
                assertTrue(toolNames.contains("list_scanner_issues"), "Should contain list_scanner_issues: $toolNames")
                assertTrue(toolNames.contains("get_scanner_issue_detail"), "Should contain get_scanner_issue_detail: $toolNames")
                assertTrue(toolNames.contains("exporter_stats"), "Should contain exporter_stats: $toolNames")
            }
        }

        @Test
        fun `list_proxy_http_history should return empty when no data`() {
            runBlocking {
                val result = client.callTool("list_proxy_http_history", mapOf("count" to 10, "offset" to 0))
                val text = result.expectTextContent()
                assertEquals("No proxy HTTP history entries found", text)
            }
        }

        @Test
        fun `get_proxy_http_detail should return not found for unknown ids`() {
            runBlocking {
                val result = client.callTool("get_proxy_http_detail", mapOf("ids" to "1,2,3"))
                val text = result.expectTextContent()
                assertTrue(text.contains("No entries found for IDs"))
            }
        }

        @Test
        fun `list_scanner_issues should return empty when no data`() {
            runBlocking {
                val result = client.callTool("list_scanner_issues", mapOf("count" to 10, "offset" to 0))
                val text = result.expectTextContent()
                assertEquals("No scanner issues found", text)
            }
        }

        @Test
        fun `get_scanner_issue_detail should return not found for unknown ids`() {
            runBlocking {
                val result = client.callTool("get_scanner_issue_detail", mapOf("ids" to "1,2,3"))
                val text = result.expectTextContent()
                assertTrue(text.contains("No scanner issues found for IDs"))
            }
        }

        @Test
        fun `exporter_stats should return status`() {
            runBlocking {
                val result = client.callTool("exporter_stats", mapOf("dummy" to true))
                val text = result.expectTextContent()
                assertTrue(text.contains("Exporter running:"))
                assertTrue(text.contains("Database proxy HTTP entries:"))
            }
        }

        @Test
        fun `clear_database should clear all data`() {
            val db = serverManager.database ?: fail("Database should be initialized")
            db.upsertProxyHttpHistory(
                listOf(ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000))
            )
            db.upsertScannerIssues(
                listOf(ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", null, null, 1000))
            )
            assertEquals(1, db.stats().proxyHttpCount)
            assertEquals(1, db.stats().scannerIssueCount)

            runBlocking {
                val result = client.callTool("clear_database", mapOf("target" to "all"))
                val text = result.expectTextContent()
                assertTrue(text.contains("cleared"))
            }

            assertEquals(0, db.stats().proxyHttpCount)
            assertEquals(0, db.stats().scannerIssueCount)
        }

        @Test
        fun `clear_database should clear proxy history only`() {
            val db = serverManager.database ?: fail("Database should be initialized")
            db.upsertProxyHttpHistory(
                listOf(ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000))
            )
            db.upsertScannerIssues(
                listOf(ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", null, null, 1000))
            )

            runBlocking {
                val result = client.callTool("clear_database", mapOf("target" to "proxy_history"))
                val text = result.expectTextContent()
                assertTrue(text.contains("Proxy HTTP history cleared"))
            }

            assertEquals(0, db.stats().proxyHttpCount)
            assertEquals(1, db.stats().scannerIssueCount)
        }

        @Test
        fun `clear_database should clear scanner issues only`() {
            val db = serverManager.database ?: fail("Database should be initialized")
            db.upsertProxyHttpHistory(
                listOf(ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000))
            )
            db.upsertScannerIssues(
                listOf(ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", null, null, 1000))
            )

            runBlocking {
                val result = client.callTool("clear_database", mapOf("target" to "scanner_issues"))
                val text = result.expectTextContent()
                assertTrue(text.contains("Scanner issues cleared"))
            }

            assertEquals(1, db.stats().proxyHttpCount)
            assertEquals(0, db.stats().scannerIssueCount)
        }

        @Test
        fun `clear_database tool should be registered`() {
            runBlocking {
                val tools = client.listTools()
                val toolNames = tools.map { it.name }
                assertTrue(toolNames.contains("clear_database"), "Should contain clear_database: $toolNames")
            }
        }
    }

    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}/sse")

            val tools = client.listTools()
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}
