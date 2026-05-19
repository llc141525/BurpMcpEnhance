package net.portswigger.mcp.exporter

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.db.ProxyHttpEntry
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.ZoneId
import java.time.ZonedDateTime

class ExporterTest {

    private val api = mockk<MontoyaApi>(relaxed = true)
    private val mockLogging = mockk<Logging>(relaxed = true)
    private lateinit var database: Database
    private lateinit var exporter: Exporter

    @BeforeEach
    fun setup() {
        every { api.logging() } returns mockLogging

        database = Database(":memory:")
        exporter = Exporter(
            api = api,
            database = database,
            pollIntervalMs = 5000,
            maxBodySize = 8192
        )
    }

    @AfterEach
    fun tearDown() {
        database.close()
    }

    @Test
    fun `exportProxyHttpHistory should only process entries newer than maxId`() = runBlocking {
        // Arrange: Pre-populate database with some entries
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(id = 1000, method = "GET", status = 200, url = "http://example.com/old",
                    requestHeaders = null, requestBody = null, responseHeaders = null, responseBody = null,
                    contentType = null, paramNames = null, capturedAt = 1000)
            )
        )
        assertEquals(1, database.stats().proxyHttpCount, "Should have 1 pre-existing entry")

        // Mock proxy history with mixed old and new entries
        val oldEntry = createMockProxyEntry(1000, "http://example.com/old")
        val newEntry = createMockProxyEntry(2000, "http://example.com/new")

        val mockProxy = mockk<Proxy>(relaxed = true)
        every { api.proxy() } returns mockProxy
        every { mockProxy.history() } returns listOf(newEntry, oldEntry)

        // Act: Run export
        exporter.exportProxyHttpHistory()

        // Assert: Only 1 new entry should be added (not re-processing the old one)
        assertEquals(2, database.stats().proxyHttpCount, "Total should be 2 (1 old + 1 new)")
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
    fun `exportProxyHttpHistory should handle null maxId for first export`() = runBlocking {
        val entry = createMockProxyEntry(1000, "http://example.com/test")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(entry)
        }

        exporter.exportProxyHttpHistory()

        assertEquals(1, database.stats().proxyHttpCount)
    }

    @Test
    fun `exportProxyHttpHistory should not re-process entries with same timestamp`() = runBlocking {
        // Pre-populate with entry at timestamp 1000
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(id = 1000, method = "GET", status = 200, url = "http://example.com/existing",
                    requestHeaders = null, requestBody = null, responseHeaders = null, responseBody = null,
                    contentType = null, paramNames = null, capturedAt = 1000)
            )
        )

        // Mock history with an entry at the same timestamp
        val sameTsEntry = createMockProxyEntry(1000, "http://example.com/same-ts")
        every { api.proxy() } returns mockk<Proxy>(relaxed = true).apply {
            every { history() } returns listOf(sameTsEntry)
        }

        exporter.exportProxyHttpHistory()

        // Entry with same timestamp should be excluded by > comparison
        assertEquals(1, database.stats().proxyHttpCount, "Entry with same timestamp should be excluded")
    }

    private fun createMockProxyEntry(timestampSeconds: Long, url: String): ProxyHttpRequestResponse {
        val mockEntry = mockk<ProxyHttpRequestResponse>(relaxed = true)
        val zonedDateTime = ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond(timestampSeconds), ZoneId.systemDefault())
        every { mockEntry.time() } returns zonedDateTime

        val mockRequest = mockk<HttpRequest>(relaxed = true)
        every { mockEntry.request() } returns mockRequest
        every { mockRequest.body() } returns null

        val mockService = mockk<HttpService>(relaxed = true)
        every { mockRequest.httpService() } returns mockService
        every { mockService.host() } returns "example.com"
        every { mockService.port() } returns 80
        every { mockService.secure() } returns false
        every { mockRequest.path() } returns "/"
        every { mockRequest.method() } returns "GET"
        every { mockRequest.headers() } returns emptyList()

        return mockEntry
    }
}
