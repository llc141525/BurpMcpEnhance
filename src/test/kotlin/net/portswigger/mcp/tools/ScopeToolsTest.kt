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
