package net.portswigger.mcp.db

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

class DatabaseTest {

    private lateinit var database: Database

    @BeforeEach
    fun setup() {
        database = Database()
    }

    @AfterEach
    fun tearDown() {
        database.close()
    }

    @Test
    fun `empty database stats`() {
        val stats = database.stats()
        assertEquals(0, stats.proxyHttpCount)
        assertEquals(0, stats.scannerIssueCount)
    }

    @Test
    fun `insert and list proxy http history`() {
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, "text/html", null, 1000),
                ProxyHttpEntry(2, "POST", 201, "http://example.com/create", null, null, null, null, "application/json", null, 1001)
            )
        )

        val list = database.listProxyHttpHistory()
        assertEquals(2, list.size)
        assertEquals(2, list[0].id) // DESC order
        assertEquals("POST", list[0].method)
        assertEquals(201, list[0].status)
        assertEquals(1, list[1].id)
        assertEquals("GET", list[1].method)
        assertEquals(200, list[1].status)
    }

    @Test
    fun `get proxy http detail by ids`() {
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "GET", 200, "http://example.com", "Host: example.com", "body1", "Server: nginx", "resp1", "text/html", null, 1000),
                ProxyHttpEntry(2, "POST", 201, "http://example.com/create", "Content-Type: json", "{\"key\":\"value\"}", "Server: nginx", "{\"id\":1}", "application/json", null, 1001)
            )
        )

        val details = database.getProxyHttpDetail(listOf(1, 2))
        assertEquals(2, details.size)

        val first = details.find { it.id == 1 }
        assertNotNull(first)
        assertEquals("GET", first!!.method)
        assertEquals("body1", first.requestBody)
        assertEquals("resp1", first.responseBody)

        val second = details.find { it.id == 2 }
        assertNotNull(second)
        assertEquals("POST", second!!.method)
        assertEquals("{\"key\":\"value\"}", second.requestBody)
    }

    @Test
    fun `get proxy http detail with unknown ids returns empty`() {
        val details = database.getProxyHttpDetail(listOf(999))
        assertTrue(details.isEmpty())
    }

    @Test
    fun `proxy http history pagination`() {
        val entries = (1..10).map { i ->
            ProxyHttpEntry(i, "GET", 200, "http://example.com/$i", null, null, null, null, null, null, 1000 + i.toLong())
        }
        database.upsertProxyHttpHistory(entries)

        val page1 = database.listProxyHttpHistory(offset = 0, count = 3)
        assertEquals(3, page1.size)
        assertEquals(10, page1[0].id)
        assertEquals(8, page1[2].id)

        val page2 = database.listProxyHttpHistory(offset = 3, count = 3)
        assertEquals(3, page2.size)
        assertEquals(7, page2[0].id)
    }

    @Test
    fun `empty proxy history list returns empty`() {
        val list = database.listProxyHttpHistory()
        assertTrue(list.isEmpty())
    }

    @Test
    fun `insert and list scanner issues`() {
        database.upsertScannerIssues(
            listOf(
                ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", "detail1", "fix xss", 1000),
                ScannerIssueEntry(2, "SQLI", "CRITICAL", "http://example.com/sql", "detail2", "fix sqli", 1001)
            )
        )

        val list = database.listScannerIssues()
        assertEquals(2, list.size)
        assertEquals(2, list[0].id)
        assertEquals("SQLI", list[0].name)
        assertEquals("CRITICAL", list[0].severity)
    }

    @Test
    fun `get scanner issue detail by ids`() {
        database.upsertScannerIssues(
            listOf(
                ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", "XSS detail", "Remediation: sanitize", 1000)
            )
        )

        val details = database.getScannerIssueDetail(listOf(1))
        assertEquals(1, details.size)
        assertEquals("XSS", details[0].name)
        assertEquals("XSS detail", details[0].detail)
        assertEquals("Remediation: sanitize", details[0].remediation)
    }

    @Test
    fun `get scanner issue detail with unknown ids returns empty`() {
        val details = database.getScannerIssueDetail(listOf(999))
        assertTrue(details.isEmpty())
    }

    @Test
    fun `max id is null for empty database`() {
        assertNull(database.getMaxProxyHttpId())
        assertNull(database.getMaxScannerIssueId())
    }

    @Test
    fun `max id works after inserts`() {
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(5, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000),
                ProxyHttpEntry(10, "POST", 201, "http://example.com/create", null, null, null, null, null, null, 1001)
            )
        )

        assertEquals(10, database.getMaxProxyHttpId())
    }

    @Test
    fun `clear proxy http history should remove all entries`() {
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000),
                ProxyHttpEntry(2, "POST", 201, "http://example.com/create", null, null, null, null, null, null, 1001)
            )
        )

        assertEquals(2, database.stats().proxyHttpCount)
        database.clearProxyHttpHistory()
        assertEquals(0, database.stats().proxyHttpCount)
        assertTrue(database.listProxyHttpHistory().isEmpty())
    }

    @Test
    fun `clear scanner issues should remove all entries`() {
        database.upsertScannerIssues(
            listOf(
                ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", "detail", "fix", 1000),
                ScannerIssueEntry(2, "SQLI", "CRITICAL", "http://example.com/sqli", "detail", "fix", 1001)
            )
        )

        assertEquals(2, database.stats().scannerIssueCount)
        database.clearScannerIssues()
        assertEquals(0, database.stats().scannerIssueCount)
        assertTrue(database.listScannerIssues().isEmpty())
    }

    @Test
    fun `clear all should remove both tables`() {
        database.upsertProxyHttpHistory(
            listOf(ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000))
        )
        database.upsertScannerIssues(
            listOf(ScannerIssueEntry(1, "XSS", "HIGH", "http://example.com", "detail", "fix", 1000))
        )

        assertEquals(1, database.stats().proxyHttpCount)
        assertEquals(1, database.stats().scannerIssueCount)

        database.clearAll()

        assertEquals(0, database.stats().proxyHttpCount)
        assertEquals(0, database.stats().scannerIssueCount)
    }

    @Test
    fun `upsert replaces existing entry`() {
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "GET", 200, "http://example.com", null, null, null, null, null, null, 1000)
            )
        )

        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "POST", 201, "http://example.com/updated", null, null, null, null, null, null, 1002)
            )
        )

        val list = database.listProxyHttpHistory()
        assertEquals(1, list.size) // Only one entry (upsert)
        assertEquals("POST", list[0].method)
        assertEquals(201, list[0].status)
    }

    @Test
    fun `raw duplicates table is created and stats returns correct count`() {
        // Verify the table exists and stats() correctly queries it (returns 0 for an empty table)
        val stats = database.stats()
        assertEquals(0, stats.rawDuplicateCount)
    }

    @Test
    fun `duplicate login requests are stored in raw duplicates table`() {
        val dedupKey = Database.computeDedupKey("POST", "http://example.com/login")
        val t = System.currentTimeMillis()

        // First: becomes canonical (id=1)
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "POST", 200, "http://example.com/login",
                    "Content-Type: application/json", """{"user":"alice","pass":"secret1"}""",
                    null, null, "application/json", null, t, dedupKey = dedupKey)
            ),
            maxRawDuplicatesPerCanonical = 10
        )

        // Second: should go to raw table, not be discarded
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(2, "POST", 200, "http://example.com/login",
                    "Content-Type: application/json", """{"user":"bob","pass":"secret2"}""",
                    null, null, "application/json", null, t + 1000, dedupKey = dedupKey)
            ),
            maxRawDuplicatesPerCanonical = 10
        )

        val stats = database.stats()
        assertEquals(1, stats.proxyHttpCount)        // still only one canonical
        assertEquals(1, stats.rawDuplicateCount)     // one raw entry
        val canonical = database.getProxyHttpDetail(listOf(1)).first()
        assertEquals(2, canonical.hitCount)          // hit_count=2
    }

    @Test
    fun `getProxyHttpDetail with includeDuplicates returns raw entries on canonical`() {
        val dedupKey = Database.computeDedupKey("POST", "http://example.com/login")
        val t = System.currentTimeMillis()

        // Canonical
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "POST", 200, "http://example.com/login",
                    "Content-Type: application/json", """{"user":"alice"}""",
                    null, null, "application/json", null, t, dedupKey = dedupKey)
            ),
            maxRawDuplicatesPerCanonical = 10
        )
        // Two raw duplicates
        for (i in 2..3) {
            database.upsertProxyHttpHistory(
                listOf(
                    ProxyHttpEntry(i, "POST", 200, "http://example.com/login",
                        "Content-Type: application/json", """{"user":"user$i"}""",
                        null, null, "application/json", null, t + (i * 1000L), dedupKey = dedupKey)
                ),
                maxRawDuplicatesPerCanonical = 10
            )
        }

        // Without includeDuplicates: duplicates list is empty
        val withoutDups = database.getProxyHttpDetail(listOf(1)).first()
        assertTrue(withoutDups.duplicates.isEmpty())

        // With includeDuplicates: both raw entries are returned, newest first
        val withDups = database.getProxyHttpDetail(listOf(1), includeDuplicates = true).first()
        assertEquals(2, withDups.duplicates.size)
        assertEquals(t + 3000L, withDups.duplicates[0].capturedAt) // newest first
        assertEquals(t + 2000L, withDups.duplicates[1].capturedAt)
        assertEquals("""{"user":"user3"}""", withDups.duplicates[0].requestBody)
    }

    @Test
    fun `pruneRawDuplicates keeps only the N most recent raw duplicates per canonical`() {
        val dedupKey = Database.computeDedupKey("POST", "http://example.com/login")
        val t = System.currentTimeMillis()

        // Insert canonical (id=1)
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(1, "POST", 200, "http://example.com/login",
                    "Content-Type: application/json", """{"user":"alice"}""",
                    null, null, "application/json", null, t, dedupKey = dedupKey)
            ),
            maxRawDuplicatesPerCanonical = 3
        )

        // Insert 4 raw duplicates (ids 2..5); pruning keeps only 3 most recent
        for (i in 2..5) {
            database.upsertProxyHttpHistory(
                listOf(
                    ProxyHttpEntry(i, "POST", 200, "http://example.com/login",
                        "Content-Type: application/json", """{"user":"user$i"}""",
                        null, null, "application/json", null, t + (i * 1000L), dedupKey = dedupKey)
                ),
                maxRawDuplicatesPerCanonical = 3
            )
        }

        val stats = database.stats()
        assertEquals(1, stats.proxyHttpCount)    // one canonical
        assertEquals(3, stats.rawDuplicateCount) // only 3 remain after pruning
        val canonical = database.getProxyHttpDetail(listOf(1)).first()
        assertEquals(5, canonical.hitCount)      // hit_count incremented for all 5 upserts
    }

    @Test
    fun `migration adds candidate summary columns for existing database`() {
        val tempFile = Files.createTempFile("mcp-db-migration", ".sqlite")
        Database(tempFile.toString()).close()

        val migrated = Database(tempFile.toString())
        try {
            migrated.upsertProxyHttpHistory(
                listOf(
                    ProxyHttpEntry(
                        id = 99,
                        method = "GET",
                        status = 200,
                        url = "http://example.com/api/users?id=1",
                        requestHeaders = null,
                        requestBody = null,
                        responseHeaders = null,
                        responseBody = "{\"token\":\"abc\"}",
                        contentType = "application/json",
                        paramNames = "id",
                        capturedAt = 1000,
                        canonicalUrl = "http://example.com/api/users?id",
                        endpointFingerprint = "fp-1",
                        requestParamCount = 1,
                        responseSummary = "status=200, type=application/json",
                        sensitiveMarkerCount = 1,
                        authRequiredHint = "login_required",
                        endpointScore = 77,
                        candidateReason = "json_api,sensitive_markers"
                    )
                )
            )

            val summary = migrated.listProxyHttpHistory().first()
            assertEquals(77, summary.endpointScore)
            assertEquals("json_api,sensitive_markers", summary.candidateReason)
            assertEquals("login_required", summary.authRequiredHint)
            assertEquals(1, summary.sensitiveMarkerCount)

            val detail = migrated.getProxyHttpDetail(listOf(99)).first()
            assertEquals("http://example.com/api/users?id", detail.canonicalUrl)
            assertEquals("fp-1", detail.endpointFingerprint)
            assertEquals(1, detail.requestParamCount)
            assertEquals("status=200, type=application/json", detail.responseSummary)
        } finally {
            migrated.close()
        }
    }

    @Test
    fun `listSecurityCandidates orders by score and filters low value by default`() {
        database.upsertProxyHttpHistory(
            listOf(
                ProxyHttpEntry(
                    11, "GET", 200, "http://example.com/health", null, null, null, null,
                    "text/plain", null, 1000, endpointScore = 10, candidateReason = "low_signal"
                ),
                ProxyHttpEntry(
                    12, "POST", 403, "http://example.com/admin/users", null, null, null, null,
                    "application/json", "id", 1001, endpointScore = 72,
                    candidateReason = "auth_gate,admin_surface", authRequiredHint = "forbidden"
                ),
                ProxyHttpEntry(
                    13, "GET", 200, "http://example.com/api/me", null, null, null, null,
                    "application/json", "verbose", 1002, endpointScore = 55,
                    candidateReason = "json_api,has_params"
                )
            )
        )

        val filtered = database.listSecurityCandidates(minScore = 30)
        assertEquals(listOf(12, 13), filtered.map { it.id })

        val inclusive = database.listSecurityCandidates(minScore = 30, includeLowValue = true)
        assertEquals(listOf(12, 13, 11), inclusive.map { it.id })
    }
}
