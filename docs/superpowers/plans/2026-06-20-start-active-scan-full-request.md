# start_active_scan Full-Request Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `start_active_scan` audit a full raw HTTP request (method + headers + cookies + body) instead of always rebuilding a bare `GET`, so request-shape-dependent scanner extensions (FastjsonScan needs POST JSON, ShiroScan needs a `rememberMe` cookie, Java Deserialization Scanner needs a body) actually fire for AI-driven scans.

**Architecture:** Extract the request-text decision into a pure, unit-testable helper (`buildScanRequestText`). Add an optional `content` field to the `StartActiveScan` tool args; when present, audit that request, otherwise fall back to the current bare-GET behavior. The fix is fully backward-compatible (existing `url`-only calls behave exactly as before). Results remain readable via `get_scanner_issues` (unchanged) — that channel was never the bottleneck; the audited request shape was.

**Tech Stack:** Kotlin, Burp Montoya API, MCP Kotlin SDK, JUnit5 + mockk, Gradle (shadowJar).

---

## Background / Why

`start_active_scan` currently discards the method, body, and cookies of the target and always audits `GET $path HTTP/1.1\r\nHost: ...\r\n\r\n` ([ScopeTools.kt:105-108](../../../src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt#L105-L108)). Confirmed facts:

- **Extension scan checks DO run** under `LEGACY_ACTIVE_AUDIT_CHECKS` (verified via Montoya docs).
- **AI reads every resulting Issue in full** via `get_scanner_issues` → `AuditIssue.toSerializableForm()` ([serialization.kt:10-37](../../../src/main/kotlin/net/portswigger/mcp/schema/serialization.kt#L10-L37)).
- **But** a bare GET gives POST/cookie/body-dependent extensions nothing to audit, so FastjsonScan / ShiroScan / Java Deserialization Scanner effectively never fire through this tool.

This plan removes that bottleneck.

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt` | `start_active_scan` tool: arg schema, request building, audit kickoff | Modify: add `content` arg, extract + call `buildScanRequestText`, update description |
| `src/test/kotlin/net/portswigger/mcp/tools/ScopeToolsTest.kt` | Pure unit tests for request-text helper | Create |
| `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt` | Existing tool integration tests (MCP-client end-to-end) | Modify: add `ActiveScanToolTests` nested class |

Note on placement: `buildScanRequestText` / `normalizeScanRequestContent` are top-level functions in package `net.portswigger.mcp.tools`, so `ScopeToolsTest` (same package) calls them directly with no server/mock harness. The end-to-end wiring is covered separately in `ToolsKtTest` using the established Pro-gated-tool harness.

---

## Task 1: Pure request-text helper (`buildScanRequestText`)

**Files:**
- Create: `src/test/kotlin/net/portswigger/mcp/tools/ScopeToolsTest.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt` (append top-level helpers)

- [ ] **Step 1: Write the failing test**

Create `src/test/kotlin/net/portswigger/mcp/tools/ScopeToolsTest.kt`:

```kotlin
package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ScopeToolsTest {

    @Test
    fun `buildScanRequestText returns bare GET when content is null`() {
        val result = buildScanRequestText(null, "example.com", "/api/user?id=1")
        assertEquals(
            "GET /api/user?id=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            result
        )
    }

    @Test
    fun `buildScanRequestText returns bare GET when content is blank`() {
        val result = buildScanRequestText("   ", "example.com", "/x")
        assertEquals(
            "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            result
        )
    }

    @Test
    fun `buildScanRequestText preserves POST method and body and normalizes LF to CRLF`() {
        val raw = "POST /api/user HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"id\":1}"
        val result = buildScanRequestText(raw, "example.com", "/ignored")
        assertEquals(
            "POST /api/user HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"id\":1}",
            result
        )
    }

    @Test
    fun `buildScanRequestText keeps existing CRLF without doubling carriage returns`() {
        val raw = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
        val result = buildScanRequestText(raw, "ignored", "/ignored")
        assertEquals(raw, result)
    }

    @Test
    fun `normalizeScanRequestContent does not double existing carriage returns`() {
        assertEquals("a\r\nb", normalizeScanRequestContent("a\r\nb"))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew.bat test --tests "net.portswigger.mcp.tools.ScopeToolsTest"`
Expected: FAIL — Kotlin compilation error `unresolved reference: buildScanRequestText` (and `normalizeScanRequestContent`).

- [ ] **Step 3: Write the minimal implementation**

Append these top-level functions to the **end** of `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt` (after the closing brace of `registerScopeTools`; no new imports needed):

```kotlin
internal fun normalizeScanRequestContent(content: String): String =
    content.replace("\r", "").replace("\n", "\r\n")

internal fun buildScanRequestText(content: String?, host: String, path: String): String =
    if (!content.isNullOrBlank()) {
        normalizeScanRequestContent(content)
    } else {
        "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew.bat test --tests "net.portswigger.mcp.tools.ScopeToolsTest"`
Expected: PASS — 5 tests green.

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt src/test/kotlin/net/portswigger/mcp/tools/ScopeToolsTest.kt
git commit -m "feat: add buildScanRequestText helper for active-scan request shaping"
```

---

## Task 2: Wire `content` arg into `start_active_scan`

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt` (data class + Pro block)
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt` (add `ActiveScanToolTests` nested class)

- [ ] **Step 1: Write the failing integration test**

In `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`, insert the following nested class **immediately before** this existing method (around line 1219):

```kotlin
    @Test
    fun `tool name conversion should work properly`() {
```

Insert this block right before that `@Test`:

```kotlin
    @Nested
    inner class ActiveScanToolTests {
        private val scanner = mockk<burp.api.montoya.scanner.Scanner>()
        private val audit = mockk<burp.api.montoya.scanner.audit.Audit>()
        private val httpForScan = mockk<Http>()
        private val capturedScanRequestText = slot<String>()

        @BeforeEach
        fun setupActiveScan() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"

            // AuditConfiguration.auditConfiguration(...) is a Burp-runtime factory; mock it so the test JVM is self-contained.
            mockkStatic(burp.api.montoya.scanner.AuditConfiguration::class)
            every {
                burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(any<burp.api.montoya.scanner.BuiltInAuditConfiguration>())
            } returns mockk(relaxed = true)

            every { api.scanner() } returns scanner
            every { scanner.startAudit(any()) } returns audit
            every { audit.addRequestResponse(any()) } just runs

            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK"
            every { api.http() } returns httpForScan
            every { httpForScan.sendRequest(any<HttpRequest>()) } returns httpResponse

            every {
                HttpRequest.httpRequest(any<burp.api.montoya.http.HttpService>(), capture(capturedScanRequestText))
            } answers {
                mockk<HttpRequest>().also { req -> every { req.toString() } returns secondArg<String>() }
            }

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
        fun cleanupActiveScan() {
            unmockkStatic(burp.api.montoya.scanner.AuditConfiguration::class)
        }

        @Test
        fun `start_active_scan audits provided raw request preserving POST body`() {
            runBlocking {
                val raw = "POST /api/user HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"id\":1}"
                val result = client.callTool(
                    "start_active_scan", mapOf(
                        "url" to "https://example.com/api/user",
                        "content" to raw
                    )
                )
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Active scan started"), "Expected scan to start: $text")
            }

            assertTrue(
                capturedScanRequestText.captured.startsWith("POST /api/user HTTP/1.1"),
                "Audited request should preserve POST method/path: ${capturedScanRequestText.captured}"
            )
            assertTrue(
                capturedScanRequestText.captured.contains("{\"id\":1}"),
                "Audited request should preserve JSON body: ${capturedScanRequestText.captured}"
            )
            verify(exactly = 1) { audit.addRequestResponse(any()) }
        }

        @Test
        fun `start_active_scan falls back to bare GET when content omitted`() {
            runBlocking {
                val result = client.callTool(
                    "start_active_scan", mapOf(
                        "url" to "https://example.com/api/user?id=1"
                    )
                )
                delay(100)
                result.expectTextContent()
            }

            assertTrue(
                capturedScanRequestText.captured.startsWith("GET /api/user?id=1 HTTP/1.1"),
                "Fallback audited request should be a bare GET: ${capturedScanRequestText.captured}"
            )
        }
    }

```

(All referenced helpers — `mockk`, `slot`, `every`, `verify`, `just runs`, `mockkStatic`, `unmockkStatic`, `runBlocking`, `delay`, `BurpSuiteEdition`, `Http`, `HttpRequest`, `ServerState`, `expectTextContent`, `assertTrue` — are already imported/defined in `ToolsKtTest.kt`. The Montoya `Scanner`/`Audit`/`AuditConfiguration` types are referenced by fully-qualified name, matching the file's existing style, so no import changes are required.)

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `./gradlew.bat test --tests "net.portswigger.mcp.tools.ToolsKtTest"`
Expected: FAIL — `start_active_scan audits provided raw request preserving POST body` fails because the current tool ignores the unknown `content` key and still builds a GET, so `capturedScanRequestText.captured` starts with `GET /api/user HTTP/1.1` (assertion message prints the captured GET). The `falls back to bare GET` test passes (it is the regression guard).

- [ ] **Step 3: Add the `content` field to the args data class**

In `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt`, replace:

```kotlin
@Serializable
data class StartActiveScan(
    val url: String,
    val auditType: String = "active"
)
```

with:

```kotlin
@Serializable
data class StartActiveScan(
    val url: String,
    val auditType: String = "active",
    val content: String? = null
)
```

- [ ] **Step 4: Rewire the Pro block to audit the built request and update the description**

In `src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt`, replace the entire `if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) { ... }` block (the `mcpTool<StartActiveScan>(...)` registration) with:

```kotlin
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
                "Poll results with list_scanner_issues."
            }
        }
    }
```

- [ ] **Step 5: Run the active-scan tests to verify they pass**

Run: `./gradlew.bat test --tests "net.portswigger.mcp.tools.ToolsKtTest"`
Expected: PASS — both `ActiveScanToolTests` tests green, all other `ToolsKtTest` tests still green.

- [ ] **Step 6: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/ScopeTools.kt src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "feat: start_active_scan audits full raw request so POST/cookie scanners fire"
```

---

## Task 3: Full regression + build verification

**Files:** none (verification only)

- [ ] **Step 1: Run the entire test suite**

Run: `./gradlew.bat test`
Expected: PASS — BUILD SUCCESSFUL, no failures across all test classes (`ToolsKtTest`, `ScopeToolsTest`, `ExporterTest`, `DatabaseTest`, `KtorServerManagerTest`, etc.).

- [ ] **Step 2: Build the shippable jar**

Run: `./gradlew.bat shadowJar`
Expected: PASS — BUILD SUCCESSFUL; `build/libs/burp-mcp-all.jar` is produced.

- [ ] **Step 3: Confirm no uncommitted production changes remain**

Run: `git status --porcelain`
Expected: empty output (Tasks 1–2 already committed; this task adds no files).

---

## Self-Review

1. **Spec coverage:**
   - "Audit a full raw request instead of forcing GET" → Task 1 (`buildScanRequestText`) + Task 2 Step 4 (lambda rewire). ✓
   - "Backward-compatible bare-GET fallback" → Task 1 (null/blank branch) + Task 2 `falls back to bare GET` test. ✓
   - "POST body / cookies preserved so Fastjson/Shiro fire" → Task 2 `preserving POST body` test asserts method + body survive into the audited request. ✓
   - "AI still reads results" → unchanged `get_scanner_issues` path; explicitly out of scope, no regression risk. ✓
   - "Tool tells the AI how to use `content`" → updated description string in Task 2 Step 4. ✓
2. **Placeholder scan:** No TODO/TBD/"handle edge cases"/"similar to" placeholders; every code and command step is concrete. ✓
3. **Type consistency:** `buildScanRequestText(content: String?, host: String, path: String)` and `normalizeScanRequestContent(content: String)` are defined in Task 1 and called with the identical signature/argument order in both the lambda (Task 2) and `ScopeToolsTest` (Task 1). The new arg `content: String?` matches its use as `content.isNullOrBlank()` and as `buildScanRequestText`'s first argument. ✓

---

## Out of scope (follow-up, not part of this plan)

- Updating the **SRC hunting project** (`E:\SRC挖掘\SRC\CLAUDE.md`) usage guidance to call `start_active_scan` with `content` (full POST/cookie requests) for FastjsonScan/ShiroScan — that lives in a different repository and should be a separate change after this jar ships.
- Re-evaluating which Java scanner extensions to keep vs. delegate to nuclei — separate decision, tracked elsewhere.
