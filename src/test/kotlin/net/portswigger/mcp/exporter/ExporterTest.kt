package net.portswigger.mcp.exporter

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scope.Scope
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.db.Database
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZoneId
import java.time.ZonedDateTime

class ExporterTest {

    private val api = mockk<MontoyaApi>(relaxed = true)
    private val mockLogging = mockk<Logging>(relaxed = true)
    private val persistedObject = mockk<PersistedObject>(relaxed = true)
    private val booleanStore = mutableMapOf<String, Boolean>()
    private val intStore = mutableMapOf<String, Int>()
    private val stringStore = mutableMapOf<String, String>()
    private lateinit var database: Database
    private lateinit var exporter: Exporter
    private lateinit var config: McpConfig

    @BeforeEach
    fun setup() {
        every { api.logging() } returns mockLogging
        booleanStore.clear()
        intStore.clear()
        stringStore.clear()
        booleanStore["filterBrowserNoise"] = true
        intStore["keepaliveIntervalSec"] = 30
        intStore["maxResponseSizeKb"] = 100

        every { persistedObject.getBoolean(any()) } answers { booleanStore[firstArg<String>()] ?: false }
        every { persistedObject.getString(any()) } answers { stringStore[firstArg<String>()] ?: "" }
        every { persistedObject.getInteger(any()) } answers { intStore[firstArg<String>()] ?: 0 }
        every { persistedObject.setBoolean(any(), any()) } answers { booleanStore[firstArg<String>()] = secondArg<Boolean>() }
        every { persistedObject.setString(any(), any()) } answers { stringStore[firstArg<String>()] = secondArg<String>() }
        every { persistedObject.setInteger(any(), any()) } answers { intStore[firstArg<String>()] = secondArg<Int>() }
        config = McpConfig(persistedObject, mockLogging)

        database = Database(":memory:")
        exporter = Exporter(
            api = api,
            database = database,
            config = config,
            pollIntervalMs = 30_000,
            maxBodySize = 8192
        )
    }

    @AfterEach
    fun tearDown() {
        database.close()
    }

    @Test
    fun `exportProxyHttpHistory should only process new entries on subsequent exports`() = runBlocking {
        val entry1 = createMockProxyEntry(1000, "http://example.com/old")
        val entry2 = createMockProxyEntry(2000, "http://example.com/new")
        val proxyMock = mockk<Proxy>(relaxed = true)

        // First export — processes everything since lastProxyTimestampMs starts at 0
        every { api.proxy() } returns proxyMock
        every { proxyMock.history() } returns listOf(entry1)
        exporter.exportProxyHttpHistory()
        assertEquals(1, database.stats().proxyHttpCount)

        // Second export — only entry2 is newer than the previous max timestamp
        every { proxyMock.history() } returns listOf(entry1, entry2)
        exporter.exportProxyHttpHistory()
        assertEquals(2, database.stats().proxyHttpCount, "Only the new entry should be added")
    }

    @Test
    fun `exportProxyHttpHistory should keep same timestamp boundary entries`() = runBlocking {
        val entry1 = createMockProxyEntry(1000, "http://example.com/first")
        val entry2 = createMockProxyEntry(1000, "http://example.com/second")
        val proxyMock = mockk<Proxy>(relaxed = true)

        every { api.proxy() } returns proxyMock
        every { proxyMock.history() } returns listOf(entry1)
        exporter.exportProxyHttpHistory()
        assertEquals(1, database.stats().proxyHttpCount)

        every { proxyMock.history() } returns listOf(entry1, entry2)
        exporter.exportProxyHttpHistory()

        assertEquals(2, database.stats().proxyHttpCount, "Entries sharing the last timestamp must not be skipped")
    }

    @Test
    fun `exportProxyHttpHistory should keep same timestamp same url entries with different request bodies`() = runBlocking {
        val entry1 = createMockProxyEntry(1000, "http://example.com/login", method = "POST", requestBody = """{"user":"alice"}""")
        val entry2 = createMockProxyEntry(1000, "http://example.com/login", method = "POST", requestBody = """{"user":"bob"}""")
        val proxyMock = mockk<Proxy>(relaxed = true)

        every { api.proxy() } returns proxyMock
        every { proxyMock.history() } returns listOf(entry1)
        exporter.exportProxyHttpHistory()

        every { proxyMock.history() } returns listOf(entry1, entry2)
        exporter.exportProxyHttpHistory()

        assertEquals(2, database.stats().proxyHttpCount)
        val ids = database.listProxyHttpHistory().map { it.id }
        val bodies = database.getProxyHttpDetail(ids).map { it.requestBody }
        assertTrue("""{"user":"alice"}""" in bodies)
        assertTrue("""{"user":"bob"}""" in bodies)
    }

    @Test
    fun `notifyDatabaseCleared should reset proxy watermark so old history can be restored`() = runBlocking {
        val entry = createMockProxyEntry(1000, "http://example.com/restored")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()
        assertEquals(1, database.stats().proxyHttpCount)

        database.clearProxyHttpHistory()
        exporter.notifyDatabaseCleared()
        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
        assertEquals("http://example.com/restored", database.listProxyHttpHistory().single().url)
    }

    @Test
    fun `clearing scanner issues should not reset proxy watermark`() = runBlocking {
        val entry = createMockProxyEntry(1000, "http://example.com/not-restored")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()
        database.clearProxyHttpHistory()
        database.clearScannerIssues()
        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should handle empty history gracefully`() = runBlocking {
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns emptyList()
        }

        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should handle first export correctly`() = runBlocking {
        val entry = createMockProxyEntry(1000, "http://example.com/test")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
    }

    @Test
    fun `exporter stats should report history and filter counts`() = runBlocking {
        config.exportInScopeOnly = true
        val scopeMock = mockk<Scope>(relaxed = true)
        every { api.scope() } returns scopeMock
        every { scopeMock.isInScope("http://example.com/in") } returns true
        every { scopeMock.isInScope("http://example.com/out") } returns false
        every { scopeMock.isInScope("http://example.com/app.js") } returns true

        val inScope = createMockProxyEntry(1000, "http://example.com/in", accept = "application/json")
        val outOfScope = createMockProxyEntry(2000, "http://example.com/out", accept = "application/json")
        val staticAsset = createMockProxyEntry(3000, "http://example.com/app.js", secFetchDest = "script")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(inScope, outOfScope, staticAsset)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(3, exporter.stats.historySeen)
        assertEquals(3, exporter.stats.newEntriesSeen)
        assertEquals(1, exporter.stats.filteredOutOfScope)
        assertEquals(1, exporter.stats.filteredNoise)
        assertEquals(1, exporter.stats.exportedThisCycle)
        assertTrue(exporter.stats.lastCycleDurationMs >= 0)
    }

    @Test
    fun `exporter stats should retain the latest cycle error`() = runBlocking {
        val proxyMock = mockk<Proxy>(relaxed = true)
        every { api.proxy() } returns proxyMock
        every { proxyMock.history() } throws IllegalStateException("history unavailable")

        runCatching { exporter.exportProxyHttpHistory() }

        assertEquals("history unavailable", exporter.stats.lastCycleError)
        assertTrue(exporter.stats.lastCycleDurationMs >= 0)
    }

    @Test
    fun `exportProxyHttpHistory should filter browser static assets by default`() = runBlocking {
        val staticEntry = createMockProxyEntry(1000, "http://example.com/app.js", accept = "*/*", secFetchDest = "script")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(staticEntry)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory relaxed mode should keep manifest traffic`() = runBlocking {
        config.exportNoiseMode = "relaxed"
        val manifest = createMockProxyEntry(1000, "http://example.com/manifest.json", accept = "application/manifest+json")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(manifest)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should export out of scope entries when scope filter disabled`() = runBlocking {
        val scopeMock = mockk<Scope>(relaxed = true)
        every { api.scope() } returns scopeMock
        every { scopeMock.isInScope(any<String>()) } returns false

        val entry = createMockProxyEntry(1000, "http://example.com/api/users", accept = "application/json")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should only export in scope entries when enabled`() = runBlocking {
        config.exportInScopeOnly = true
        val scopeMock = mockk<Scope>(relaxed = true)
        every { api.scope() } returns scopeMock
        every { scopeMock.isInScope("http://example.com/api/users") } returns false

        val entry = createMockProxyEntry(1000, "http://example.com/api/users", accept = "application/json")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `scope only filtering should count out of scope entries before writing`() = runBlocking {
        config.exportInScopeOnly = true
        val scopeMock = mockk<Scope>(relaxed = true)
        every { api.scope() } returns scopeMock
        every { scopeMock.isInScope("http://example.com/in") } returns true
        every { scopeMock.isInScope("http://example.com/out") } returns false

        val inScope = createMockProxyEntry(1000, "http://example.com/in", accept = "application/json")
        val outOfScope = createMockProxyEntry(1001, "http://example.com/out", accept = "application/json")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(inScope, outOfScope)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
        assertEquals(2, exporter.stats.newEntriesSeen)
        assertEquals(1, exporter.stats.filteredOutOfScope)
        assertEquals(1, exporter.stats.exportedThisCycle)
    }

    @Test
    fun `explicit reimport should recalculate old history using current scope`() = runBlocking {
        val scopeMock = mockk<Scope>(relaxed = true)
        every { api.scope() } returns scopeMock
        val scoped = createMockProxyEntry(1000, "http://example.com/scoped", accept = "application/json")
        val laterOut = createMockProxyEntry(2000, "http://example.com/out", accept = "application/json")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(scoped, laterOut)
        }

        config.exportInScopeOnly = false
        exporter.exportProxyHttpHistory()
        assertEquals(2, database.stats().proxyHttpCount)

        database.clearProxyHttpHistory()
        config.exportInScopeOnly = true
        every { scopeMock.isInScope("http://example.com/scoped") } returns true
        every { scopeMock.isInScope("http://example.com/out") } returns false

        exporter.resetWatermark()
        exporter.exportProxyHttpHistory()

        assertEquals(listOf("http://example.com/scoped"), database.listProxyHttpHistory().map { it.url })
        assertEquals(1, exporter.stats.filteredOutOfScope)
    }

    @Test
    fun `exportProxyHttpHistory should filter cors preflight requests`() = runBlocking {
        val entry = createMockProxyEntry(
            1000,
            "http://example.com/api/users",
            method = "OPTIONS",
            accessControlRequestMethod = "POST"
        )
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should filter favicon and manifest noise`() = runBlocking {
        val favicon = createMockProxyEntry(1000, "http://example.com/favicon.ico")
        val manifest = createMockProxyEntry(1001, "http://example.com/manifest.json", accept = "application/manifest+json")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(favicon, manifest)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should filter frontend hot reload traffic`() = runBlocking {
        config.exportNoiseMode = "strict"
        val vite = createMockProxyEntry(1000, "http://example.com/@vite/client")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(vite)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(0, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory balanced mode should keep hot reload traffic`() = runBlocking {
        config.exportNoiseMode = "balanced"
        val vite = createMockProxyEntry(1000, "http://example.com/@vite/client")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(vite)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
    }

    @Test
    fun `exporter stores raw duplicates when saveRawDuplicates is true`() = runBlocking {
        booleanStore["saveRawDuplicates"] = true
        intStore["maxRawDuplicatesPerCanonical"] = 10

        val proxyMock = mockk<Proxy>(relaxed = true)
        every { api.proxy() } returns proxyMock

        val entry1 = createMockProxyEntry(1000, "http://example.com/login", method = "POST")
        val entry2 = createMockProxyEntry(2000, "http://example.com/login", method = "POST")

        every { proxyMock.history() } returns listOf(entry1)
        exporter.exportProxyHttpHistory()

        every { proxyMock.history() } returns listOf(entry1, entry2)
        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
        assertEquals(1, database.stats().rawDuplicateCount)
    }

    @Test
    fun `exporter does not store raw duplicates when saveRawDuplicates is false`() = runBlocking {
        booleanStore["saveRawDuplicates"] = false

        val proxyMock = mockk<Proxy>(relaxed = true)
        every { api.proxy() } returns proxyMock

        val entry1 = createMockProxyEntry(1000, "http://example.com/login", method = "POST")
        val entry2 = createMockProxyEntry(2000, "http://example.com/login", method = "POST")

        every { proxyMock.history() } returns listOf(entry1)
        exporter.exportProxyHttpHistory()

        every { proxyMock.history() } returns listOf(entry1, entry2)
        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
        assertEquals(0, database.stats().rawDuplicateCount)
    }

    @Test
    fun `exportProxyHttpHistory should compute candidate summaries`() = runBlocking {
        val entry = createMockProxyEntry(
            timestampSeconds = 1000,
            url = "http://example.com/api/admin/users?id=1&_ts=99",
            method = "POST",
            responseStatus = 403,
            contentType = "application/json; charset=utf-8",
            responseBody = """{"token":"abc","message":"access denied"}"""
        )
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()

        val stored = database.listProxyHttpHistory().first()
        assertTrue(stored.endpointScore >= 30)
        assertNotNull(stored.candidateReason)
        assertEquals("forbidden", stored.authRequiredHint)
        assertTrue(stored.sensitiveMarkerCount >= 1)

        val detail = database.getProxyHttpDetail(listOf(stored.id)).first()
        assertEquals("http://example.com/api/admin/users", detail.canonicalUrl)
        assertNotNull(detail.endpointFingerprint)
        assertTrue(detail.responseSummary?.contains("status=403") == true)
    }

    private fun createMockProxyEntry(
        timestampSeconds: Long,
        url: String,
        method: String = "GET",
        accept: String? = null,
        secFetchDest: String? = null,
        accessControlRequestMethod: String? = null,
        responseStatus: Int? = null,
        contentType: String? = null,
        responseBody: String? = null,
        requestBody: String? = null,
        requestHeaders: List<Pair<String, String>> = emptyList()
    ): ProxyHttpRequestResponse {
        val mockEntry = mockk<ProxyHttpRequestResponse>(relaxed = true)
        val zonedDateTime = ZonedDateTime.ofInstant(
            java.time.Instant.ofEpochSecond(timestampSeconds), ZoneId.systemDefault()
        )
        every { mockEntry.time() } returns zonedDateTime

        val mockRequest = mockk<HttpRequest>(relaxed = true)
        every { mockEntry.request() } returns mockRequest
        every { mockRequest.body() } returns requestBody?.let {
            mockk<burp.api.montoya.core.ByteArray>(relaxed = true).also { body ->
                every { body.toString() } returns it
            }
        }

        val path = java.net.URI(url).rawPath
        val mockService = mockk<HttpService>(relaxed = true)
        every { mockRequest.httpService() } returns mockService
        every { mockService.host() } returns "example.com"
        every { mockService.port() } returns 80
        every { mockService.secure() } returns false
        every { mockRequest.path() } returns path
        every { mockRequest.method() } returns method
        every { mockRequest.headers() } returns requestHeaders.map { (name, value) ->
            mockk<HttpHeader>(relaxed = true).also {
                every { it.name() } returns name
                every { it.value() } returns value
            }
        }
        every { mockRequest.headerValue("Accept") } returns accept
        every { mockRequest.headerValue("Sec-Fetch-Dest") } returns secFetchDest
        every { mockRequest.headerValue("Access-Control-Request-Method") } returns accessControlRequestMethod
        every { mockRequest.headerValue("Purpose") } returns null
        every { mockRequest.headerValue("X-Purpose") } returns null
        every { mockRequest.headerValue("Sec-Purpose") } returns null

        if (responseStatus != null || contentType != null || responseBody != null) {
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>(relaxed = true)
            every { mockEntry.response() } returns mockResponse
            if (responseStatus != null) every { mockResponse.statusCode() } returns responseStatus.toShort()
            every { mockResponse.headerValue("Content-Type") } returns contentType
            every { mockResponse.body() } returns responseBody?.let {
                mockk<burp.api.montoya.core.ByteArray>(relaxed = true).also { body ->
                    every { body.toString() } returns it
                }
            }
            every { mockResponse.headers() } returns emptyList()
        }

        return mockEntry
    }
}
