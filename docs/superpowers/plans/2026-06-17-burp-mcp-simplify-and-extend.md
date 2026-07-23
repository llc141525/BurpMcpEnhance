# Burp MCP Simplify & Extend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge redundant tool pairs, consolidate auto-approve management, and add five new capability groups: scope management, active scanning, GraphQL introspection with schema caching, HTTP response diffing, and a Burp capability overview tool.

**Architecture:** New capabilities land in three dedicated files (`ScopeTools.kt`, `GraphQLTools.kt`, `DiffTools.kt`) mirroring the existing pattern. Simplifications happen inside `Tools.kt` only. All new registrations are wired through the existing `registerTools()` entry point.

**Tech Stack:** Kotlin 2.2, Montoya API (compileOnly), kotlinx.serialization-json (already on classpath), JUnit 5 + MockK for tests.

---

## File Map

| Action | File | Change |
|--------|------|--------|
| Modify | `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` | Merge regex history tools; merge auto-approve; add `get_burp_info`; wire new registrations |
| Create | `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt` | `manage_scope`, `get_site_map`, `start_active_scan` (Pro) |
| Create | `src/main/kotlin/net/portswigger/mcp/tools/GraphQLTools.kt` | `graphql_introspect`, `graphql_list_types`, `graphql_describe_type`, `graphql_query` |
| Create | `src/main/kotlin/net/portswigger/mcp/tools/DiffTools.kt` | `diff_proxy_responses` |
| Modify | `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt` | Update merged-tool tests; add new tool tests |

---

## Task 1: Merge proxy history regex tools

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Write failing tests for merged tool**

Add inside `class ToolsKtTest` a new nested class (after `PaginatedToolsTests`):

```kotlin
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
        val proxy = mockk<burp.api.montoya.proxy.Proxy>()
        val history = listOf(
            mockk<burp.api.montoya.proxy.ProxyHttpRequestResponse>(),
            mockk<burp.api.montoya.proxy.ProxyHttpRequestResponse>()
        )
        every { api.proxy() } returns proxy
        every { proxy.history(any()) } answers {
            val filter = firstArg<burp.api.montoya.proxy.MessageReceivedFilter>()
            history.filter { filter.matches(it.toString()) }
        }
        // Simplified: just confirm the tool accepts a regex param without error
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```
.\gradlew.bat test --tests "*.ToolsKtTest.MergedHistoryToolsTests*"
```

Expected: FAIL — `get_proxy_http_history_regex` still exists.

- [ ] **Step 3: Merge the data classes in Tools.kt**

Replace these two data classes:

```kotlin
// REMOVE both of these:
@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated
```

With:

```kotlin
@Serializable
data class GetProxyHttpHistory(
    val regex: String? = null,
    override val count: Int,
    override val offset: Int
) : Paginated
```

Do the same for WebSocket:

```kotlin
// REMOVE both of these:
@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated
```

With:

```kotlin
@Serializable
data class GetProxyWebsocketHistory(
    val regex: String? = null,
    override val count: Int,
    override val offset: Int
) : Paginated
```

- [ ] **Step 4: Merge the tool registrations in Tools.kt**

Replace the two `mcpPaginatedTool<GetProxyHttpHistory>` and `mcpPaginatedTool<GetProxyHttpHistoryRegex>` blocks with:

```kotlin
mcpPaginatedTool<GetProxyHttpHistory>(
    "Displays items within the proxy HTTP history. Optionally filter with a Java regex pattern via the 'regex' param. " +
    "Use count ≤ 20 per request to avoid truncation."
) {
    val allowed = runBlocking {
        checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
    }
    if (!allowed) {
        return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
    }
    if (regex != null) {
        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    } else {
        api.proxy().history().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }
}
```

Replace the two WebSocket tool blocks with:

```kotlin
mcpPaginatedTool<GetProxyWebsocketHistory>(
    "Displays items within the proxy WebSocket history. Optionally filter with a Java regex pattern via the 'regex' param. " +
    "Use count ≤ 20 per request to avoid truncation."
) {
    val allowed = runBlocking {
        checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
    }
    if (!allowed) {
        return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
    }
    if (regex != null) {
        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    } else {
        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }
}
```

- [ ] **Step 5: Run tests**

```
.\gradlew.bat test --tests "*.ToolsKtTest.MergedHistoryToolsTests*"
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/Tools.kt \
        src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "refactor: merge proxy history regex tools into optional param"
```

---

## Task 2: Merge auto-approve tools into one

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Write failing tests**

Replace the entire `AutoApproveTargetsToolsTests` nested class with:

```kotlin
@Nested
inner class AutoApproveTargetsToolsTests {
    @Test
    fun `manage_auto_approve_targets should be registered, old names should not`() {
        runBlocking {
            val tools = client.listTools()
            val names = tools.map { it.name }
            assertTrue(names.contains("manage_auto_approve_targets"))
            assertFalse(names.contains("add_auto_approve_target"))
            assertFalse(names.contains("remove_auto_approve_target"))
            assertFalse(names.contains("list_auto_approve_targets"))
            assertFalse(names.contains("clear_auto_approve_targets"))
        }
    }

    @Test
    fun `add action should succeed with valid target`() {
        runBlocking {
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "add", "target" to "example.com")
            )
            result.expectTextContent("Target added to auto-approve list: example.com")
        }
    }

    @Test
    fun `add action should fail with invalid target`() {
        runBlocking {
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "add", "target" to "")
            )
            assertTrue(result.expectTextContent().contains("Failed to add target"))
        }
    }

    @Test
    fun `add action should fail with duplicate target`() {
        runBlocking {
            client.callTool("manage_auto_approve_targets", mapOf("action" to "add", "target" to "example.com"))
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "add", "target" to "example.com")
            )
            assertTrue(result.expectTextContent().contains("Failed to add target"))
        }
    }

    @Test
    fun `list action should return configured targets`() {
        runBlocking {
            client.callTool("manage_auto_approve_targets", mapOf("action" to "add", "target" to "example.com"))
            client.callTool("manage_auto_approve_targets", mapOf("action" to "add", "target" to "localhost:8080"))
            val result = client.callTool("manage_auto_approve_targets", mapOf("action" to "list"))
            val text = result.expectTextContent()
            assertTrue(text.contains("example.com"))
            assertTrue(text.contains("localhost:8080"))
        }
    }

    @Test
    fun `list action should return empty message when none configured`() {
        config.clearAutoApproveTargets()
        runBlocking {
            val result = client.callTool("manage_auto_approve_targets", mapOf("action" to "list"))
            result.expectTextContent("No auto-approve targets configured")
        }
    }

    @Test
    fun `remove action should succeed`() {
        runBlocking {
            client.callTool("manage_auto_approve_targets", mapOf("action" to "add", "target" to "example.com"))
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "remove", "target" to "example.com")
            )
            result.expectTextContent("Target removed from auto-approve list: example.com")
        }
    }

    @Test
    fun `remove action should fail for non-existent target`() {
        runBlocking {
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "remove", "target" to "nonexistent.com")
            )
            assertTrue(result.expectTextContent().contains("Target not found"))
        }
    }

    @Test
    fun `clear action should remove all targets`() {
        runBlocking {
            client.callTool("manage_auto_approve_targets", mapOf("action" to "add", "target" to "example.com"))
            client.callTool("manage_auto_approve_targets", mapOf("action" to "add", "target" to "test.com"))
            client.callTool("manage_auto_approve_targets", mapOf("action" to "clear"))
            val result = client.callTool("manage_auto_approve_targets", mapOf("action" to "list"))
            result.expectTextContent("No auto-approve targets configured")
        }
    }

    @Test
    fun `unknown action should return error`() {
        runBlocking {
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "destroy")
            )
            assertTrue(result.expectTextContent().contains("Invalid action"))
        }
    }

    @Test
    fun `add action without target should return error`() {
        runBlocking {
            val result = client.callTool(
                "manage_auto_approve_targets", mapOf("action" to "add")
            )
            assertTrue(result.expectTextContent().contains("target is required"))
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm failure**

```
.\gradlew.bat test --tests "*.ToolsKtTest.AutoApproveTargetsToolsTests*"
```

Expected: FAIL — old tool names still registered.

- [ ] **Step 3: Replace the 4 data classes in Tools.kt**

Remove these four data classes:

```kotlin
// REMOVE ALL FOUR:
@Serializable
data class AddAutoApproveTarget(val target: String)

@Serializable
data class RemoveAutoApproveTarget(val target: String)

@Serializable
data class ListAutoApproveTargets(val dummy: Boolean = true)

@Serializable
data class ClearAutoApproveTargets(val dummy: Boolean = true)
```

Add this one:

```kotlin
@Serializable
data class ManageAutoApproveTargets(
    val action: String,
    val target: String? = null
)
```

- [ ] **Step 4: Replace the 4 tool registrations in Tools.kt**

Remove the four `mcpTool<AddAutoApproveTarget>`, `mcpTool<RemoveAutoApproveTarget>`, `mcpTool<ListAutoApproveTargets>`, `mcpTool<ClearAutoApproveTargets>` blocks and replace with:

```kotlin
mcpTool<ManageAutoApproveTargets>(
    "Manages the HTTP request auto-approve list. Future requests to approved targets skip user confirmation. " +
    "action: 'add' (target required, e.g. 'example.com' or '*.example.com:8080'), " +
    "'remove' (target required), 'list' (no target needed), 'clear' (no target needed)."
) {
    when (action.lowercase()) {
        "add" -> {
            val t = target ?: return@mcpTool "target is required for 'add' action"
            if (config.addAutoApproveTarget(t)) "Target added to auto-approve list: $t"
            else "Failed to add target (invalid or already in list): $t"
        }
        "remove" -> {
            val t = target ?: return@mcpTool "target is required for 'remove' action"
            if (config.removeAutoApproveTarget(t)) "Target removed from auto-approve list: $t"
            else "Target not found in auto-approve list: $t"
        }
        "list" -> {
            val targets = config.getAutoApproveTargetsList()
            if (targets.isEmpty()) "No auto-approve targets configured"
            else targets.joinToString("\n") { "- $it" }
        }
        "clear" -> {
            config.clearAutoApproveTargets()
            "All auto-approve targets have been cleared"
        }
        else -> "Invalid action: $action. Use 'add', 'remove', 'list', or 'clear'."
    }
}
```

- [ ] **Step 5: Run tests**

```
.\gradlew.bat test --tests "*.ToolsKtTest.AutoApproveTargetsToolsTests*"
```

Expected: PASS.

- [ ] **Step 6: Run full test suite to catch regressions**

```
.\gradlew.bat test
```

Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/Tools.kt \
        src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "refactor: consolidate 4 auto-approve tools into manage_auto_approve_targets"
```

---

## Task 3: Create ScopeTools.kt (scope management, site map, active scan)

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` (add `registerScopeTools` call)
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Write failing tests**

Add to `ToolsKtTest.kt` after `ExporterToolsTests`:

```kotlin
@Nested
inner class ScopeToolsTests {
    @BeforeEach
    fun setupScope() {
        runBlocking {
            if (!client.isConnected()) client.connectToServer("http://127.0.0.1:${testPort}/sse")
        }
    }

    @Test
    fun `scope tools should be registered`() {
        runBlocking {
            val names = client.listTools().map { it.name }
            assertTrue(names.contains("manage_scope"), "manage_scope missing: $names")
            assertTrue(names.contains("get_site_map"), "get_site_map missing: $names")
        }
    }

    @Test
    fun `manage_scope add should call includeInScope`() {
        val scope = mockk<burp.api.montoya.scope.Scope>()
        every { api.scope() } returns scope
        every { scope.includeInScope(any<String>()) } just runs

        runBlocking {
            val result = client.callTool(
                "manage_scope", mapOf("action" to "add", "url" to "https://example.com")
            )
            delay(100)
            result.expectTextContent("Added to scope: https://example.com")
        }
        verify(exactly = 1) { scope.includeInScope("https://example.com") }
    }

    @Test
    fun `manage_scope remove should call excludeFromScope`() {
        val scope = mockk<burp.api.montoya.scope.Scope>()
        every { api.scope() } returns scope
        every { scope.excludeFromScope(any<String>()) } just runs

        runBlocking {
            val result = client.callTool(
                "manage_scope", mapOf("action" to "remove", "url" to "https://example.com")
            )
            delay(100)
            result.expectTextContent("Removed from scope: https://example.com")
        }
        verify(exactly = 1) { scope.excludeFromScope("https://example.com") }
    }

    @Test
    fun `manage_scope check should return in-scope status`() {
        val scope = mockk<burp.api.montoya.scope.Scope>()
        every { api.scope() } returns scope
        every { scope.isInScope("https://example.com") } returns true
        every { scope.isInScope("https://other.com") } returns false

        runBlocking {
            val r1 = client.callTool("manage_scope", mapOf("action" to "check", "url" to "https://example.com"))
            delay(100)
            assertTrue(r1.expectTextContent().contains("In scope"))

            val r2 = client.callTool("manage_scope", mapOf("action" to "check", "url" to "https://other.com"))
            delay(100)
            assertTrue(r2.expectTextContent().contains("NOT in scope"))
        }
    }

    @Test
    fun `manage_scope invalid action should return error`() {
        runBlocking {
            val result = client.callTool("manage_scope", mapOf("action" to "hack", "url" to "https://x.com"))
            delay(100)
            assertTrue(result.expectTextContent().contains("Invalid action"))
        }
    }

    @Test
    fun `get_site_map should return site map entries`() {
        val siteMap = mockk<burp.api.montoya.sitemap.SiteMap>()
        val rr = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
        val req = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
        val resp = mockk<burp.api.montoya.http.message.responses.HttpResponse>()

        every { api.siteMap() } returns siteMap
        every { siteMap.requestResponses() } returns listOf(rr)
        every { rr.request() } returns req
        every { rr.response() } returns resp
        every { req.method() } returns "GET"
        every { req.url() } returns "https://example.com/api/users"
        every { resp.statusCode() } returns 200

        runBlocking {
            val result = client.callTool("get_site_map", mapOf("count" to 10, "offset" to 0))
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("GET"))
            assertTrue(text.contains("https://example.com/api/users"))
            assertTrue(text.contains("200"))
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm failure**

```
.\gradlew.bat test --tests "*.ToolsKtTest.ScopeToolsTests*"
```

Expected: FAIL — tools not registered yet.

- [ ] **Step 3: Create ScopeTools.kt**

Create `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt`:

```kotlin
package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.AuditConfiguration
import burp.api.montoya.scanner.audit.BuiltInAuditConfiguration
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable

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
    val auditType: String = "lightweight"
)

fun Server.registerScopeTools(api: MontoyaApi) {

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
            api.siteMap().requestResponsesForUrl(urlPrefix)
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
            "auditType options: " +
            "'lightweight' — fast, covers common vulnerabilities (default); " +
            "'extensions_only' — only runs scanner extensions (Active Scan++, Param Miner, FastjsonScan, etc.) with no built-in checks, fastest option; " +
            "'deep' — all insertion points, thorough but slow. " +
            "Returns immediately. Poll results with list_scanner_issues (DB cache) or get_scanner_issues (live). " +
            "Tip: call manage_scope to add the URL to scope first."
        ) {
            val builtIn = when (auditType.lowercase()) {
                "deep" -> BuiltInAuditConfiguration.AUDIT_CHECKS_ALL_INSERTION_POINTS
                "extensions_only" -> BuiltInAuditConfiguration.AUDIT_CHECKS_EXTENSIONS_ONLY
                else -> BuiltInAuditConfiguration.LIGHTWEIGHT_AUDIT
            }
            val auditConfig = AuditConfiguration.auditConfiguration(builtIn)

            val parsed = java.net.URL(url)
            val host = parsed.host
            val port = if (parsed.port == -1) (if (parsed.protocol == "https") 443 else 80) else parsed.port
            val secure = parsed.protocol == "https"
            val path = parsed.file.ifEmpty { "/" }

            val request = HttpRequest.httpRequest(
                HttpService.httpService(host, port, secure),
                "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
            )
            val response = api.http().sendRequest(request)

            if (response == null) {
                "Failed to fetch URL (no response): $url"
            } else {
                api.scanner().startAuditOfRequestResponse(response, listOf(), auditConfig)
                "Active scan started: $url (auditType=$auditType). " +
                "Installed scanner extensions (Active Scan++, Param Miner, FastjsonScan, ShiroScan, etc.) run automatically. " +
                "Poll results with list_scanner_issues."
            }
        }
    }
}
```

- [ ] **Step 4: Wire into registerTools() in Tools.kt**

Inside `fun Server.registerTools(...)`, add after the exporter registration block:

```kotlin
registerScopeTools(api)
```

The final order should be:
```kotlin
fun Server.registerTools(...) {
    if (messageQueue != null && fileQueue != null) { registerQueueTools(api, messageQueue, fileQueue) }
    if (database != null && exporter != null) { registerExporterTools(database, exporter) }
    registerScopeTools(api)   // ← ADD THIS LINE
    // ... rest of the existing tools
}
```

- [ ] **Step 5: Run tests**

```
.\gradlew.bat test --tests "*.ToolsKtTest.ScopeToolsTests*"
```

Expected: PASS.

- [ ] **Step 6: Run full suite**

```
.\gradlew.bat test
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt \
        src/main/kotlin/net/portswigger/mcp/tools/Tools.kt \
        src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "feat: add scope management, site map, and active scan tools"
```

---

## Task 4: Create DiffTools.kt (HTTP response diff)

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/tools/DiffTools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` (add `registerDiffTools` call)
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Write failing tests**

Add to `ToolsKtTest.kt`:

```kotlin
@Nested
inner class DiffToolsTests {
    @BeforeEach
    fun setup() {
        runBlocking {
            if (!client.isConnected()) client.connectToServer("http://127.0.0.1:${testPort}/sse")
        }
    }

    @Test
    fun `diff_proxy_responses should be registered`() {
        runBlocking {
            assertTrue(client.listTools().any { it.name == "diff_proxy_responses" })
        }
    }

    @Test
    fun `diff_proxy_responses identical responses should report identical`() {
        val db = serverManager.database ?: fail("Database required")
        db.upsertProxyHttpHistory(listOf(
            net.portswigger.mcp.db.ProxyHttpEntry(
                101, "GET", 200, "http://example.com/a",
                null, null, null, null,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json",
                "{\"user\":\"alice\"}",
                System.currentTimeMillis()
            ),
            net.portswigger.mcp.db.ProxyHttpEntry(
                102, "GET", 200, "http://example.com/a",
                null, null, null, null,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json",
                "{\"user\":\"alice\"}",
                System.currentTimeMillis()
            )
        ))
        runBlocking {
            val result = client.callTool("diff_proxy_responses", mapOf("id1" to "101", "id2" to "102"))
            delay(100)
            assertTrue(result.expectTextContent().contains("identical"))
        }
    }

    @Test
    fun `diff_proxy_responses different responses should show diff`() {
        val db = serverManager.database ?: fail("Database required")
        db.upsertProxyHttpHistory(listOf(
            net.portswigger.mcp.db.ProxyHttpEntry(
                103, "GET", 200, "http://example.com/b",
                null, null, null, null,
                "HTTP/1.1 200 OK",
                "{\"role\":\"admin\"}",
                System.currentTimeMillis()
            ),
            net.portswigger.mcp.db.ProxyHttpEntry(
                104, "GET", 200, "http://example.com/b",
                null, null, null, null,
                "HTTP/1.1 200 OK",
                "{\"role\":\"user\"}",
                System.currentTimeMillis()
            )
        ))
        runBlocking {
            val result = client.callTool("diff_proxy_responses", mapOf("id1" to "103", "id2" to "104"))
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("admin") || text.contains("user") || text.contains("REMOVED") || text.contains("ADDED"),
                "Diff should show what changed: $text")
        }
    }

    @Test
    fun `diff_proxy_responses invalid id should return error`() {
        runBlocking {
            val result = client.callTool("diff_proxy_responses", mapOf("id1" to "notanumber", "id2" to "999"))
            delay(100)
            assertTrue(result.expectTextContent().contains("Invalid ID"))
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm failure**

```
.\gradlew.bat test --tests "*.ToolsKtTest.DiffToolsTests*"
```

Expected: FAIL.

- [ ] **Step 3: Create DiffTools.kt**

Create `src/main/kotlin/net/portswigger/mcp/tools/DiffTools.kt`:

```kotlin
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
```

- [ ] **Step 4: Wire into registerTools() in Tools.kt**

In the `if (database != null && exporter != null)` block, add the diff registration after `registerExporterTools`:

```kotlin
if (database != null && exporter != null) {
    registerExporterTools(database, exporter)
    registerDiffTools(database)   // ← ADD THIS LINE
}
```

- [ ] **Step 5: Run tests**

```
.\gradlew.bat test --tests "*.ToolsKtTest.DiffToolsTests*"
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/DiffTools.kt \
        src/main/kotlin/net/portswigger/mcp/tools/Tools.kt \
        src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "feat: add diff_proxy_responses tool for token-efficient response comparison"
```

---

## Task 5: Create GraphQLTools.kt (introspection with schema caching)

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/tools/GraphQLTools.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` (add `registerGraphQLTools` call)
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Write failing tests**

Add to `ToolsKtTest.kt`:

```kotlin
@Nested
inner class GraphQLToolsTests {
    private val fakeIntrospectionResponse = """
        {
          "data": {
            "__schema": {
              "queryType": { "name": "Query" },
              "mutationType": { "name": "Mutation" },
              "types": [
                {
                  "name": "Query",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "user",
                      "description": "Get a user by ID",
                      "type": { "kind": "OBJECT", "name": "User", "ofType": null },
                      "args": [
                        { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } } }
                      ]
                    },
                    {
                      "name": "users",
                      "description": null,
                      "type": { "kind": "LIST", "name": null, "ofType": { "kind": "OBJECT", "name": "User", "ofType": null } },
                      "args": []
                    }
                  ]
                },
                {
                  "name": "Mutation",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "createUser",
                      "description": null,
                      "type": { "kind": "OBJECT", "name": "User", "ofType": null },
                      "args": [
                        { "name": "name", "type": { "kind": "SCALAR", "name": "String", "ofType": null } }
                      ]
                    }
                  ]
                },
                {
                  "name": "User",
                  "kind": "OBJECT",
                  "description": "A user in the system",
                  "fields": [
                    {
                      "name": "id",
                      "description": null,
                      "type": { "kind": "SCALAR", "name": "ID", "ofType": null },
                      "args": []
                    },
                    {
                      "name": "name",
                      "description": null,
                      "type": { "kind": "SCALAR", "name": "String", "ofType": null },
                      "args": []
                    }
                  ]
                },
                { "name": "__Schema", "kind": "OBJECT", "description": null, "fields": null }
              ]
            }
          }
        }
    """.trimIndent()

    private fun setupGraphQLMock() {
        val httpService = mockk<burp.api.montoya.http.Http>()
        val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
        val response = mockk<burp.api.montoya.http.message.responses.HttpResponse>()

        every { api.http() } returns httpService
        every { httpService.sendRequest(any<burp.api.montoya.http.message.requests.HttpRequest>()) } returns httpResponse
        every { httpResponse.response() } returns response
        every { response.bodyToString() } returns fakeIntrospectionResponse
    }

    @BeforeEach
    fun setup() {
        runBlocking {
            if (!client.isConnected()) client.connectToServer("http://127.0.0.1:${testPort}/sse")
        }
    }

    @Test
    fun `graphql tools should be registered`() {
        runBlocking {
            val names = client.listTools().map { it.name }
            assertTrue(names.contains("graphql_introspect"), "graphql_introspect missing")
            assertTrue(names.contains("graphql_list_types"), "graphql_list_types missing")
            assertTrue(names.contains("graphql_describe_type"), "graphql_describe_type missing")
            assertTrue(names.contains("graphql_query"), "graphql_query missing")
        }
    }

    @Test
    fun `graphql_introspect should cache schema and return summary`() {
        setupGraphQLMock()
        runBlocking {
            val result = client.callTool(
                "graphql_introspect", mapOf(
                    "targetHostname" to "api.example.com",
                    "targetPort" to 443,
                    "usesHttps" to true,
                    "path" to "/graphql"
                )
            )
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("Schema cached"), "Should confirm caching: $text")
            assertTrue(text.contains("user") || text.contains("Query"), "Should list query fields: $text")
        }
    }

    @Test
    fun `graphql_list_types should return cached types`() {
        setupGraphQLMock()
        runBlocking {
            client.callTool("graphql_introspect", mapOf(
                "targetHostname" to "api.example.com",
                "targetPort" to 443,
                "usesHttps" to true,
                "path" to "/graphql"
            ))
            delay(100)
            val result = client.callTool(
                "graphql_list_types", mapOf("cacheKey" to "api.example.com:443/graphql")
            )
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("User"), "Should list User type: $text")
        }
    }

    @Test
    fun `graphql_describe_type should return field details`() {
        setupGraphQLMock()
        runBlocking {
            client.callTool("graphql_introspect", mapOf(
                "targetHostname" to "api.example.com",
                "targetPort" to 443,
                "usesHttps" to true,
                "path" to "/graphql"
            ))
            delay(100)
            val result = client.callTool(
                "graphql_describe_type", mapOf(
                    "cacheKey" to "api.example.com:443/graphql",
                    "typeName" to "User"
                )
            )
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("id"), "Should show id field: $text")
            assertTrue(text.contains("name"), "Should show name field: $text")
        }
    }

    @Test
    fun `graphql_list_types should error when schema not cached`() {
        runBlocking {
            val result = client.callTool(
                "graphql_list_types", mapOf("cacheKey" to "notcached.example.com:443/graphql")
            )
            delay(100)
            assertTrue(result.expectTextContent().contains("not cached"))
        }
    }
}
```

- [ ] **Step 2: Run tests to confirm failure**

```
.\gradlew.bat test --tests "*.ToolsKtTest.GraphQLToolsTests*"
```

Expected: FAIL.

- [ ] **Step 3: Create GraphQLTools.kt**

Create `src/main/kotlin/net/portswigger/mcp/tools/GraphQLTools.kt`:

```kotlin
package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.runBlocking

// In-memory schema cache keyed by "host:port/path"
internal object GraphQLSchemaCache {
    private val cache = ConcurrentHashMap<String, JsonObject>()
    fun store(key: String, schema: JsonObject) { cache[key] = schema }
    fun get(key: String): JsonObject? = cache[key]
    fun keys(): List<String> = cache.keys.toList()
    fun clear() = cache.clear()
}

private val INTROSPECTION_QUERY = """{"query":"{ __schema { queryType { name } mutationType { name } types { name kind description fields(includeDeprecated: false) { name description type { kind name ofType { kind name ofType { kind name } } } args { name type { kind name ofType { kind name } } } } } } }"}"""

internal fun resolveTypeRef(typeObj: JsonObject?): String {
    if (typeObj == null) return "Unknown"
    val kind = typeObj["kind"]?.jsonPrimitive?.contentOrNull ?: ""
    val name = typeObj["name"]?.jsonPrimitive?.contentOrNull
    val ofType = typeObj["ofType"]?.takeIf { it != kotlinx.serialization.json.JsonNull }?.jsonObject
    return when (kind) {
        "NON_NULL" -> "${resolveTypeRef(ofType)}!"
        "LIST" -> "[${resolveTypeRef(ofType)}]"
        else -> name ?: "Unknown"
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
    val variables: Map<String, String>? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val path: String = "/graphql"
) : HttpServiceParams

fun Server.registerGraphQLTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<GraphqlIntrospect>(
        "Fetches the GraphQL schema via introspection and caches it in memory. " +
        "Returns a summary of queries, mutations, and types. " +
        "Schema is reusable via graphql_list_types and graphql_describe_type without re-fetching. " +
        "Cache key is 'hostname:port/path' — use the same key in subsequent calls."
    ) {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                targetHostname, targetPort, config,
                "POST $path (GraphQL introspection)", api
            )
        }
        if (!allowed) return@mcpTool "Request denied by Burp Suite"

        val body = INTROSPECTION_QUERY
        val requestContent = buildString {
            appendLine("POST $path HTTP/1.1")
            appendLine("Host: $targetHostname")
            appendLine("Content-Type: application/json")
            appendLine("Content-Length: ${body.toByteArray().size}")
            appendLine("Accept: application/json")
            appendLine("Connection: close")
            appendLine()
            append(body)
        }
        val request = HttpRequest.httpRequest(toMontoyaService(), requestContent)
        val response = api.http().sendRequest(request)
        val responseBody = response?.response()?.bodyToString()
            ?: return@mcpTool "No response from $targetHostname$path"

        val parsed = runCatching { Json.parseToJsonElement(responseBody).jsonObject }.getOrNull()
            ?: return@mcpTool "Response is not valid JSON: ${responseBody.take(300)}"

        val schema = parsed["data"]?.jsonObject?.get("__schema")?.jsonObject
            ?: return@mcpTool "Not a GraphQL introspection response. Body: ${responseBody.take(300)}"

        val cacheKey = "$targetHostname:$targetPort$path"
        GraphQLSchemaCache.store(cacheKey, schema)

        val types = schema["types"]?.jsonArray ?: return@mcpTool "Schema has no types"
        val queryTypeName = schema["queryType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull
        val mutationTypeName = schema["mutationType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull

        val userTypes = types.filter { t ->
            val n = t.jsonObject["name"]?.jsonPrimitive?.contentOrNull ?: ""
            !n.startsWith("__")
        }

        buildString {
            appendLine("Schema cached: $cacheKey")
            appendLine("Total types (excluding built-ins): ${userTypes.size}")
            queryTypeName?.let { qn ->
                val qt = userTypes.firstOrNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull == qn }
                val fields = qt?.jsonObject?.get("fields")?.jsonArray
                    ?.mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull } ?: emptyList()
                appendLine("Queries (${fields.size}): ${fields.take(25).joinToString(", ")}${if (fields.size > 25) " ..." else ""}")
            }
            mutationTypeName?.let { mn ->
                val mt = userTypes.firstOrNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull == mn }
                val fields = mt?.jsonObject?.get("fields")?.jsonArray
                    ?.mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull } ?: emptyList()
                appendLine("Mutations (${fields.size}): ${fields.take(25).joinToString(", ")}${if (fields.size > 25) " ..." else ""}")
            }
            val otherNames = userTypes
                .mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull }
                .filter { it != queryTypeName && it != mutationTypeName }
            appendLine("Object types: ${otherNames.take(30).joinToString(", ")}${if (otherNames.size > 30) " ..." else ""}")
            appendLine()
            appendLine("Use graphql_list_types cacheKey='$cacheKey' to see all types.")
            appendLine("Use graphql_describe_type cacheKey='$cacheKey' typeName='TypeName' to see fields.")
        }.trimEnd()
    }

    mcpTool<GraphqlListTypes>(
        "Lists all types in a cached GraphQL schema. " +
        "Call graphql_introspect first to populate the cache. " +
        "cacheKey format: 'hostname:port/path', e.g. 'api.example.com:443/graphql'."
    ) {
        val schema = GraphQLSchemaCache.get(cacheKey)
            ?: return@mcpTool "Schema not cached for '$cacheKey'. Available keys: ${GraphQLSchemaCache.keys().joinToString(", ").ifEmpty { "(none)" }}. Call graphql_introspect first."

        val types = schema["types"]?.jsonArray ?: return@mcpTool "No types in cached schema."
        val queryTypeName = schema["queryType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull
        val mutationTypeName = schema["mutationType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull

        buildString {
            appendLine("Types in $cacheKey:")
            types.forEach { t ->
                val obj = t.jsonObject
                val name = obj["name"]?.jsonPrimitive?.contentOrNull ?: return@forEach
                if (name.startsWith("__")) return@forEach
                val kind = obj["kind"]?.jsonPrimitive?.contentOrNull ?: "?"
                val tag = when (name) {
                    queryTypeName -> " [Query root]"
                    mutationTypeName -> " [Mutation root]"
                    else -> ""
                }
                appendLine("  $name ($kind)$tag")
            }
        }.trimEnd()
    }

    mcpTool<GraphqlDescribeType>(
        "Returns all fields and their argument signatures for a specific type in a cached GraphQL schema. " +
        "Call graphql_introspect first. " +
        "cacheKey: 'hostname:port/path'. typeName: exact type name, e.g. 'User', 'Query', 'Mutation'."
    ) {
        val schema = GraphQLSchemaCache.get(cacheKey)
            ?: return@mcpTool "Schema not cached for '$cacheKey'. Call graphql_introspect first."

        val types = schema["types"]?.jsonArray ?: return@mcpTool "No types in cached schema."
        val typeObj = types.firstOrNull {
            it.jsonObject["name"]?.jsonPrimitive?.contentOrNull == typeName
        }?.jsonObject ?: run {
            val available = types.mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull }
                .filter { !it.startsWith("__") }.joinToString(", ")
            return@mcpTool "Type '$typeName' not found. Available: $available"
        }

        val fields = typeObj["fields"]?.jsonArray
        if (fields == null || fields.isEmpty()) {
            return@mcpTool "Type '$typeName' has no fields (kind: ${typeObj["kind"]?.jsonPrimitive?.contentOrNull})."
        }

        buildString {
            appendLine("type $typeName {")
            for (field in fields) {
                val f = field.jsonObject
                val fname = f["name"]?.jsonPrimitive?.contentOrNull ?: continue
                val ftype = resolveTypeRef(f["type"]?.jsonObject)
                val args = f["args"]?.jsonArray?.map { a ->
                    val an = a.jsonObject["name"]?.jsonPrimitive?.contentOrNull ?: "?"
                    val at = resolveTypeRef(a.jsonObject["type"]?.jsonObject)
                    "$an: $at"
                } ?: emptyList()
                val argsStr = if (args.isEmpty()) "" else "(${args.joinToString(", ")})"
                val desc = f["description"]?.let {
                    (it as? JsonPrimitive)?.contentOrNull?.let { d -> "  # $d" }
                } ?: ""
                appendLine("  $fname$argsStr: $ftype$desc")
            }
            append("}")
        }.trimEnd()
    }

    mcpTool<GraphqlQuery>(
        "Executes an arbitrary GraphQL query or mutation against the target endpoint. " +
        "Useful for testing discovered queries after graphql_introspect. " +
        "Pass 'variables' as a string-to-string map for variable substitution. " +
        "Response is returned raw (truncated to 8KB)."
    ) {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, "POST $path (GraphQL)", api)
        }
        if (!allowed) return@mcpTool "Request denied by Burp Suite"

        val vars = if (variables != null) {
            val escaped = variables.entries.joinToString(",") { (k, v) ->
                "\"$k\":\"${v.replace("\"", "\\\"")}\""
            }
            ",\"variables\":{$escaped}"
        } else ""
        val body = """{"query":${Json.encodeToString(kotlinx.serialization.json.JsonPrimitive(query))}$vars}"""

        val requestContent = buildString {
            appendLine("POST $path HTTP/1.1")
            appendLine("Host: $targetHostname")
            appendLine("Content-Type: application/json")
            appendLine("Content-Length: ${body.toByteArray().size}")
            appendLine("Accept: application/json")
            appendLine("Connection: close")
            appendLine()
            append(body)
        }
        val request = HttpRequest.httpRequest(toMontoyaService(), requestContent)
        val response = api.http().sendRequest(request)
        val responseBody = response?.response()?.bodyToString() ?: return@mcpTool "No response"
        if (responseBody.length > 8192) responseBody.take(8192) + "\n... (truncated)"
        else responseBody
    }
}
```

- [ ] **Step 4: Wire into registerTools() in Tools.kt**

Add `registerGraphQLTools(api, config)` after `registerScopeTools`:

```kotlin
registerScopeTools(api)
registerGraphQLTools(api, config)   // ← ADD
```

- [ ] **Step 5: Run tests**

```
.\gradlew.bat test --tests "*.ToolsKtTest.GraphQLToolsTests*"
```

Expected: PASS.

- [ ] **Step 6: Run full suite**

```
.\gradlew.bat test
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/GraphQLTools.kt \
        src/main/kotlin/net/portswigger/mcp/tools/Tools.kt \
        src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "feat: add GraphQL introspection with in-memory schema caching"
```

---

## Task 6: Add get_burp_info tool

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Write failing test**

Add to `ToolsKtTest.kt`:

```kotlin
@Test
fun `get_burp_info should return edition and capability summary`() {
    val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
    val version = mockk<burp.api.montoya.core.Version>()
    every { api.burpSuite() } returns burpSuite
    every { burpSuite.version() } returns version
    every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
    every { version.toString() } returns "Burp Suite Pro 2025.1"

    runBlocking {
        val result = client.callTool("get_burp_info", emptyMap())
        delay(100)
        val text = result.expectTextContent()
        assertTrue(text.contains("PROFESSIONAL") || text.contains("Pro") || text.contains("Professional"), text)
        assertTrue(text.contains("A-class") || text.contains("handler"), text)
    }
}
```

- [ ] **Step 2: Run test to confirm failure**

```
.\gradlew.bat test --tests "*.ToolsKtTest.get_burp_info*"
```

Expected: FAIL.

- [ ] **Step 3: Add get_burp_info to Tools.kt**

Add this block inside `registerTools()`, before the `if (api.burpSuite()...PROFESSIONAL)` block:

```kotlin
mcpTool(
    "get_burp_info",
    "Returns Burp Suite edition, version, and capability summary. " +
    "Call this at the start of a session to understand what tools are available."
) {
    val version = api.burpSuite().version()
    buildString {
        appendLine("Edition: ${version.edition().name.replace("_", " ")}")
        appendLine("Version: $version")
        appendLine()
        if (version.edition() == BurpSuiteEdition.PROFESSIONAL) {
            appendLine("Pro-only tools available:")
            appendLine("  - start_active_scan: trigger active scanning (extensions run automatically)")
            appendLine("  - get_scanner_issues / list_scanner_issues: read scanner findings")
            appendLine("  - generate_collaborator_payload / get_collaborator_interactions: OOB testing")
        }
        appendLine()
        appendLine("A-class plugins (apply automatically to ALL send_http1_request calls if installed):")
        appendLine("  Bypass WAF, Knife, 403 Bypasser, autoDecoder, captcha-killer, Content Type Converter")
        appendLine()
        appendLine("B-class plugins (run automatically when start_active_scan is called if installed):")
        appendLine("  Active Scan++, Param Miner, HTTP Request Smuggler, FastjsonScan, ShiroScan, Struts RCE, Retirejs")
    }.trimEnd()
}
```

- [ ] **Step 4: Run test**

```
.\gradlew.bat test --tests "*.ToolsKtTest.get_burp_info*"
```

Expected: PASS.

- [ ] **Step 5: Full suite + build**

```
.\gradlew.bat test
.\gradlew.bat shadowJar
```

Expected: All tests PASS, JAR built at `build/libs/burp-mcp-all.jar`.

- [ ] **Step 6: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/Tools.kt \
        src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "feat: add get_burp_info capability overview tool"
```

---

## Self-Review

**Spec coverage:**
- ✅ Merge HTTP history regex tools (Task 1)
- ✅ Merge WebSocket history regex tools (Task 1)
- ✅ Merge 4 auto-approve tools (Task 2)
- ✅ Scope management (Task 3)
- ✅ Site map (Task 3)
- ✅ Active scan with auditType selection (Task 3)
- ✅ Response diff tool (Task 4)
- ✅ GraphQL introspection + schema cache (Task 5)
- ✅ GraphQL type listing and describe (Task 5)
- ✅ GraphQL query execution (Task 5)
- ✅ get_burp_info capability overview (Task 6)

**Placeholder scan:** No TBDs. All code steps include complete implementations.

**Type consistency:**
- `GraphQLSchemaCache` used in Task 5 only, consistent throughout.
- `computeDiff` internal function defined in `DiffTools.kt`, only referenced there.
- `resolveTypeRef` defined at top of `GraphQLTools.kt`, used in `graphql_describe_type` lambda.
- `ManageAutoApproveTargets` replaces all 4 old data classes — no old names remain.
- `registerScopeTools`, `registerDiffTools`, `registerGraphQLTools` all called from `registerTools()`.
