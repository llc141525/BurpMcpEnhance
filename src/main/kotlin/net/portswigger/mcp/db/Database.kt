package net.portswigger.mcp.db

import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

class Database(dbPath: String = ":memory:") {

    private val dedupWindowMs: Long = 300_000 // 5 minutes

    init {
        Class.forName("org.sqlite.JDBC")
    }

    private val connection: Connection = DriverManager.getConnection("jdbc:sqlite:$dbPath").also { conn ->
        conn.autoCommit = true
        conn.createStatement().apply {
            execute("PRAGMA journal_mode=WAL")
            execute("PRAGMA foreign_keys = ON")
            close()
        }
        createTables(conn)
        migrateSchema(conn)
    }

    private fun createTables(conn: Connection) {
        conn.createStatement().apply {
            execute("""
                CREATE TABLE IF NOT EXISTS proxy_http_history (
                    id INTEGER PRIMARY KEY,
                    method TEXT NOT NULL,
                    status INTEGER,
                    url TEXT NOT NULL,
                    request_headers TEXT,
                    request_body TEXT,
                    response_headers TEXT,
                    response_body TEXT,
                    content_type TEXT,
                    param_names TEXT,
                    captured_at INTEGER NOT NULL
                )
            """.trimIndent())
            execute("""
                CREATE TABLE IF NOT EXISTS scanner_issues (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    url TEXT NOT NULL,
                    detail TEXT,
                    remediation TEXT,
                    captured_at INTEGER NOT NULL
                )
            """.trimIndent())
            execute("""
                CREATE TABLE IF NOT EXISTS large_responses (
                    id TEXT PRIMARY KEY,
                    data BLOB NOT NULL,
                    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                    original_size INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
            """.trimIndent())
            execute("""
                CREATE TABLE IF NOT EXISTS proxy_http_raw_duplicates (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    canonical_id     INTEGER NOT NULL
                                       REFERENCES proxy_http_history(id) ON DELETE CASCADE,
                    method           TEXT NOT NULL,
                    status           INTEGER,
                    url              TEXT NOT NULL,
                    request_headers  TEXT,
                    request_body     TEXT,
                    response_headers TEXT,
                    response_body    TEXT,
                    content_type     TEXT,
                    captured_at      INTEGER NOT NULL
                )
            """.trimIndent())
            execute("""
                CREATE INDEX IF NOT EXISTS idx_raw_dup_canonical
                    ON proxy_http_raw_duplicates(canonical_id, captured_at DESC)
            """.trimIndent())
            close()
        }
    }

    private fun migrateSchema(conn: Connection) {
        conn.createStatement().apply {
            // Add dedup columns — safe to ignore if already present
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN dedup_key TEXT") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER dedup_key: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN hit_count INTEGER DEFAULT 1") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER hit_count: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN canonical_url TEXT") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER canonical_url: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN endpoint_fingerprint TEXT") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER endpoint_fingerprint: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN request_param_count INTEGER") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER request_param_count: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN response_summary TEXT") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER response_summary: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN sensitive_marker_count INTEGER DEFAULT 0") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER sensitive_marker_count: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN auth_required_hint TEXT") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER auth_required_hint: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN endpoint_score INTEGER DEFAULT 0") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER endpoint_score: ${e.message}", e)
            }
            try { execute("ALTER TABLE proxy_http_history ADD COLUMN candidate_reason TEXT") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration ALTER candidate_reason: ${e.message}", e)
            }
            try { execute("CREATE INDEX IF NOT EXISTS idx_history_dedup ON proxy_http_history(dedup_key, captured_at)") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration CREATE INDEX: ${e.message}", e)
            }
            try { execute("CREATE INDEX IF NOT EXISTS idx_history_score ON proxy_http_history(endpoint_score DESC, captured_at DESC)") } catch (e: Exception) {
                net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration CREATE INDEX score: ${e.message}", e)
            }
            close()
        }
    }

    companion object {
        fun computeDedupKey(method: String, url: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            return digest.digest("$method|$url".toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }

    fun upsertProxyHttpHistory(
        entries: List<ProxyHttpEntry>,
        maxRawDuplicatesPerCanonical: Int = 0
    ) {
        connection.autoCommit = false
        try {
            data class RawToInsert(val canonicalId: Int, val entry: ProxyHttpEntry)

            val newEntries = mutableListOf<ProxyHttpEntry>()
            val rawToInsert = mutableListOf<RawToInsert>()

            val dedupCutoff = System.currentTimeMillis() - dedupWindowMs

            val dedupCheckStmt = connection.prepareStatement(
                "SELECT id FROM proxy_http_history WHERE dedup_key = ? AND captured_at > ? LIMIT 1"
            )

            try {
                for (entry in entries) {
                    val dedupKey = entry.dedupKey
                    if (dedupKey != null) {
                        dedupCheckStmt.setString(1, dedupKey)
                        dedupCheckStmt.setLong(2, dedupCutoff)
                        val rs = dedupCheckStmt.executeQuery()
                        if (rs.next()) {
                            val canonicalId = rs.getInt("id")
                            rawToInsert.add(RawToInsert(canonicalId, entry))
                        } else {
                            newEntries.add(entry)
                        }
                        rs.close()
                    } else {
                        newEntries.add(entry)
                    }
                }
            } finally {
                dedupCheckStmt.close()
            }

            // Batch insert new canonical entries
            if (newEntries.isNotEmpty()) {
                val insertStmt = connection.prepareStatement(
                    "INSERT OR REPLACE INTO proxy_http_history " +
                    "(id, method, status, url, request_headers, request_body, response_headers, response_body, " +
                    "content_type, param_names, captured_at, dedup_key, hit_count, canonical_url, " +
                    "endpoint_fingerprint, request_param_count, response_summary, sensitive_marker_count, " +
                    "auth_required_hint, endpoint_score, candidate_reason) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                try {
                    for (entry in newEntries) {
                        insertStmt.setInt(1, entry.id)
                        insertStmt.setString(2, entry.method)
                        if (entry.status != null) insertStmt.setInt(3, entry.status) else insertStmt.setNull(3, java.sql.Types.INTEGER)
                        insertStmt.setString(4, entry.url)
                        insertStmt.setString(5, entry.requestHeaders)
                        insertStmt.setString(6, entry.requestBody)
                        insertStmt.setString(7, entry.responseHeaders)
                        insertStmt.setString(8, entry.responseBody)
                        insertStmt.setString(9, entry.contentType)
                        insertStmt.setString(10, entry.paramNames)
                        insertStmt.setLong(11, entry.capturedAt)
                        if (entry.dedupKey != null) insertStmt.setString(12, entry.dedupKey) else insertStmt.setNull(12, java.sql.Types.VARCHAR)
                        insertStmt.setInt(13, 1)
                        insertStmt.setString(14, entry.canonicalUrl)
                        insertStmt.setString(15, entry.endpointFingerprint)
                        if (entry.requestParamCount != null) insertStmt.setInt(16, entry.requestParamCount) else insertStmt.setNull(16, java.sql.Types.INTEGER)
                        insertStmt.setString(17, entry.responseSummary)
                        insertStmt.setInt(18, entry.sensitiveMarkerCount)
                        insertStmt.setString(19, entry.authRequiredHint)
                        insertStmt.setInt(20, entry.endpointScore)
                        insertStmt.setString(21, entry.candidateReason)
                        insertStmt.addBatch()
                    }
                    insertStmt.executeBatch()
                } finally {
                    insertStmt.close()
                }
            }

            // Store raw duplicates and update hit_count
            if (rawToInsert.isNotEmpty()) {
                if (maxRawDuplicatesPerCanonical > 0) {
                    val rawInsertStmt = connection.prepareStatement(
                        "INSERT INTO proxy_http_raw_duplicates " +
                        "(canonical_id, method, status, url, request_headers, request_body, " +
                        "response_headers, response_body, content_type, captured_at) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    )
                    val canonicalIdsForPruning = mutableSetOf<Int>()
                    try {
                        for (dup in rawToInsert) {
                            rawInsertStmt.setInt(1, dup.canonicalId)
                            rawInsertStmt.setString(2, dup.entry.method)
                            if (dup.entry.status != null) rawInsertStmt.setInt(3, dup.entry.status) else rawInsertStmt.setNull(3, java.sql.Types.INTEGER)
                            rawInsertStmt.setString(4, dup.entry.url)
                            rawInsertStmt.setString(5, dup.entry.requestHeaders)
                            rawInsertStmt.setString(6, dup.entry.requestBody)
                            rawInsertStmt.setString(7, dup.entry.responseHeaders)
                            rawInsertStmt.setString(8, dup.entry.responseBody)
                            rawInsertStmt.setString(9, dup.entry.contentType)
                            rawInsertStmt.setLong(10, dup.entry.capturedAt)
                            rawInsertStmt.addBatch()
                            canonicalIdsForPruning.add(dup.canonicalId)
                        }
                        rawInsertStmt.executeBatch()
                    } finally {
                        rawInsertStmt.close()
                    }
                    for (canonicalId in canonicalIdsForPruning) {
                        pruneRawDuplicates(canonicalId, maxRawDuplicatesPerCanonical)
                    }
                }

                val updateStmt = connection.prepareStatement(
                    "UPDATE proxy_http_history SET hit_count = hit_count + 1 WHERE id = ?"
                )
                try {
                    for (dup in rawToInsert) {
                        updateStmt.setInt(1, dup.canonicalId)
                        updateStmt.addBatch()
                    }
                    updateStmt.executeBatch()
                } finally {
                    updateStmt.close()
                }
            }

            connection.commit()
        } finally {
            connection.autoCommit = true
        }
    }

    private fun pruneRawDuplicates(canonicalId: Int, maxPerCanonical: Int) {
        connection.prepareStatement(
            """DELETE FROM proxy_http_raw_duplicates
               WHERE canonical_id = ?
                 AND id NOT IN (
                   SELECT id FROM proxy_http_raw_duplicates
                   WHERE canonical_id = ?
                   ORDER BY captured_at DESC
                   LIMIT ?
                 )"""
        ).use { stmt ->
            stmt.setInt(1, canonicalId)
            stmt.setInt(2, canonicalId)
            stmt.setInt(3, maxPerCanonical)
            stmt.executeUpdate()
        }
    }

    fun upsertScannerIssues(entries: List<ScannerIssueEntry>) {
        connection.autoCommit = false
        try {
            val stmt = connection.prepareStatement(
                "INSERT OR REPLACE INTO scanner_issues " +
                "(id, name, severity, url, detail, remediation, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            try {
                for (entry in entries) {
                    stmt.setInt(1, entry.id)
                    stmt.setString(2, entry.name)
                    stmt.setString(3, entry.severity)
                    stmt.setString(4, entry.url)
                    stmt.setString(5, entry.detail)
                    stmt.setString(6, entry.remediation)
                    stmt.setLong(7, entry.capturedAt)
                    stmt.addBatch()
                }
                stmt.executeBatch()
            } finally {
                stmt.close()
            }
            connection.commit()
        } finally {
            connection.autoCommit = true
        }
    }

    fun listProxyHttpHistory(offset: Int = 0, count: Int = 30): List<ProxyHttpSummary> {
        connection.autoCommit = true
        val stmt = connection.prepareStatement(
            "SELECT id, method, status, url, content_type, param_names, COALESCE(hit_count, 1) as hit_count, " +
                "endpoint_score, candidate_reason, auth_required_hint, sensitive_marker_count, response_summary " +
                "FROM proxy_http_history ORDER BY id DESC LIMIT ? OFFSET ?"
        )
        try {
            stmt.setInt(1, count)
            stmt.setInt(2, offset)
            val rs = stmt.executeQuery()
            try {
                val results = mutableListOf<ProxyHttpSummary>()
                while (rs.next()) {
                    results.add(
                        ProxyHttpSummary(
                            id = rs.getInt("id"),
                            method = rs.getString("method"),
                            status = rs.getObject("status") as? Int,
                            url = rs.getString("url"),
                            contentType = rs.getString("content_type"),
                            paramNames = rs.getString("param_names")?.split(",")?.filter { it.isNotEmpty() },
                            hitCount = rs.getInt("hit_count"),
                            endpointScore = rs.getInt("endpoint_score"),
                            candidateReason = rs.getString("candidate_reason"),
                            authRequiredHint = rs.getString("auth_required_hint"),
                            sensitiveMarkerCount = rs.getInt("sensitive_marker_count"),
                            responseSummary = rs.getString("response_summary")
                        )
                    )
                }
                return results
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun queryProxyHttp(filter: String = "", limit: Int = 500): List<HttpHistoryRow> {
        connection.autoCommit = true
        val hasFilter = filter.isNotBlank()
        val sql = if (hasFilter) {
            """SELECT id, method, status, url, content_type, COALESCE(hit_count, 1) as hit_count, captured_at
               FROM proxy_http_history
               WHERE url LIKE ? OR method LIKE ? OR CAST(status AS TEXT) LIKE ?
               ORDER BY captured_at DESC, id DESC LIMIT ?"""
        } else {
            """SELECT id, method, status, url, content_type, COALESCE(hit_count, 1) as hit_count, captured_at
               FROM proxy_http_history
               ORDER BY captured_at DESC, id DESC LIMIT ?"""
        }
        val stmt = connection.prepareStatement(sql)
        try {
            if (hasFilter) {
                val like = "%$filter%"
                stmt.setString(1, like)
                stmt.setString(2, like)
                stmt.setString(3, like)
                stmt.setInt(4, limit)
            } else {
                stmt.setInt(1, limit)
            }
            val rs = stmt.executeQuery()
            try {
                val results = mutableListOf<HttpHistoryRow>()
                while (rs.next()) {
                    results.add(
                        HttpHistoryRow(
                            id = rs.getInt("id"),
                            method = rs.getString("method"),
                            status = rs.getObject("status") as? Int,
                            url = rs.getString("url"),
                            contentType = rs.getString("content_type"),
                            capturedAt = rs.getLong("captured_at"),
                            hitCount = rs.getInt("hit_count")
                        )
                    )
                }
                return results
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun getProxyHttpDetail(ids: List<Int>, includeDuplicates: Boolean = false): List<ProxyHttpEntry> {
        if (ids.isEmpty()) return emptyList()
        connection.autoCommit = true
        val placeholders = ids.joinToString(",") { "?" }
        val stmt = connection.prepareStatement(
            "SELECT *, COALESCE(hit_count, 1) as hit_count FROM proxy_http_history WHERE id IN ($placeholders) ORDER BY id DESC"
        )
        try {
            ids.forEachIndexed { index, id -> stmt.setInt(index + 1, id) }
            val rs = stmt.executeQuery()
            try {
                val results = mutableListOf<ProxyHttpEntry>()
                while (rs.next()) {
                    val canonicalId = rs.getInt("id")
                    results.add(
                        ProxyHttpEntry(
                            id = canonicalId,
                            method = rs.getString("method"),
                            status = rs.getObject("status") as? Int,
                            url = rs.getString("url"),
                            requestHeaders = rs.getString("request_headers"),
                            requestBody = rs.getString("request_body"),
                            responseHeaders = rs.getString("response_headers"),
                            responseBody = rs.getString("response_body"),
                            contentType = rs.getString("content_type"),
                            paramNames = rs.getString("param_names"),
                            capturedAt = rs.getLong("captured_at"),
                            canonicalUrl = rs.getString("canonical_url"),
                            endpointFingerprint = rs.getString("endpoint_fingerprint"),
                            requestParamCount = rs.getObject("request_param_count") as? Int,
                            responseSummary = rs.getString("response_summary"),
                            sensitiveMarkerCount = rs.getInt("sensitive_marker_count"),
                            authRequiredHint = rs.getString("auth_required_hint"),
                            endpointScore = rs.getInt("endpoint_score"),
                            candidateReason = rs.getString("candidate_reason"),
                            hitCount = rs.getInt("hit_count"),
                            duplicates = if (includeDuplicates) getRawDuplicates(canonicalId) else emptyList()
                        )
                    )
                }
                return results
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun listSecurityCandidates(
        offset: Int = 0,
        count: Int = 20,
        minScore: Int = 30,
        includeLowValue: Boolean = false
    ): List<ProxyHttpSummary> {
        connection.autoCommit = true
        val stmt = connection.prepareStatement(
            "SELECT id, method, status, url, content_type, param_names, COALESCE(hit_count, 1) as hit_count, " +
                "endpoint_score, candidate_reason, auth_required_hint, sensitive_marker_count, response_summary " +
                "FROM proxy_http_history " +
                "WHERE candidate_reason IS NOT NULL " +
                "AND (? = 1 OR COALESCE(endpoint_score, 0) >= ?) " +
                "ORDER BY COALESCE(endpoint_score, 0) DESC, COALESCE(hit_count, 1) DESC, id DESC LIMIT ? OFFSET ?"
        )
        try {
            stmt.setInt(1, if (includeLowValue) 1 else 0)
            stmt.setInt(2, minScore)
            stmt.setInt(3, count)
            stmt.setInt(4, offset)
            val rs = stmt.executeQuery()
            try {
                val results = mutableListOf<ProxyHttpSummary>()
                while (rs.next()) {
                    results.add(
                        ProxyHttpSummary(
                            id = rs.getInt("id"),
                            method = rs.getString("method"),
                            status = rs.getObject("status") as? Int,
                            url = rs.getString("url"),
                            contentType = rs.getString("content_type"),
                            paramNames = rs.getString("param_names")?.split(",")?.filter { it.isNotEmpty() },
                            hitCount = rs.getInt("hit_count"),
                            endpointScore = rs.getInt("endpoint_score"),
                            candidateReason = rs.getString("candidate_reason"),
                            authRequiredHint = rs.getString("auth_required_hint"),
                            sensitiveMarkerCount = rs.getInt("sensitive_marker_count"),
                            responseSummary = rs.getString("response_summary")
                        )
                    )
                }
                return results
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    private fun getRawDuplicates(canonicalId: Int): List<RawDuplicateEntry> {
        val stmt = connection.prepareStatement(
            """SELECT id, method, status, url, request_headers, request_body,
                      response_headers, response_body, content_type, captured_at
               FROM proxy_http_raw_duplicates
               WHERE canonical_id = ?
               ORDER BY captured_at DESC"""
        )
        return stmt.use { s ->
            s.setInt(1, canonicalId)
            val rs = s.executeQuery()
            val list = mutableListOf<RawDuplicateEntry>()
            while (rs.next()) {
                list.add(
                    RawDuplicateEntry(
                        id = rs.getInt("id"),
                        method = rs.getString("method"),
                        status = rs.getObject("status") as? Int,
                        url = rs.getString("url"),
                        requestHeaders = rs.getString("request_headers"),
                        requestBody = rs.getString("request_body"),
                        responseHeaders = rs.getString("response_headers"),
                        responseBody = rs.getString("response_body"),
                        contentType = rs.getString("content_type"),
                        capturedAt = rs.getLong("captured_at")
                    )
                )
            }
            rs.close()
            list
        }
    }

    fun listScannerIssues(offset: Int = 0, count: Int = 30): List<ScannerIssueSummary> {
        connection.autoCommit = true
        val stmt = connection.prepareStatement(
            "SELECT id, name, severity, url FROM scanner_issues ORDER BY id DESC LIMIT ? OFFSET ?"
        )
        try {
            stmt.setInt(1, count)
            stmt.setInt(2, offset)
            val rs = stmt.executeQuery()
            try {
                val results = mutableListOf<ScannerIssueSummary>()
                while (rs.next()) {
                    results.add(
                        ScannerIssueSummary(
                            id = rs.getInt("id"),
                            name = rs.getString("name"),
                            severity = rs.getString("severity"),
                            url = rs.getString("url")
                        )
                    )
                }
                return results
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun getScannerIssueDetail(ids: List<Int>): List<ScannerIssueEntry> {
        if (ids.isEmpty()) return emptyList()
        connection.autoCommit = true
        val placeholders = ids.joinToString(",") { "?" }
        val stmt = connection.prepareStatement(
            "SELECT * FROM scanner_issues WHERE id IN ($placeholders) ORDER BY id DESC"
        )
        try {
            ids.forEachIndexed { index, id -> stmt.setInt(index + 1, id) }
            val rs = stmt.executeQuery()
            try {
                val results = mutableListOf<ScannerIssueEntry>()
                while (rs.next()) {
                    results.add(
                        ScannerIssueEntry(
                            id = rs.getInt("id"),
                            name = rs.getString("name"),
                            severity = rs.getString("severity"),
                            url = rs.getString("url"),
                            detail = rs.getString("detail"),
                            remediation = rs.getString("remediation"),
                            capturedAt = rs.getLong("captured_at")
                        )
                    )
                }
                return results
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun getMaxProxyHttpId(): Int? {
        connection.autoCommit = true
        val stmt = connection.createStatement()
        try {
            val rs = stmt.executeQuery("SELECT MAX(id) FROM proxy_http_history")
            try {
                return if (rs.next()) {
                    val value = rs.getObject(1)
                    (value as? Int) ?: (value as? Long)?.toInt()
                } else null
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun getMaxScannerIssueId(): Int? {
        connection.autoCommit = true
        val stmt = connection.createStatement()
        try {
            val rs = stmt.executeQuery("SELECT MAX(id) FROM scanner_issues")
            try {
                return if (rs.next()) {
                    val value = rs.getObject(1)
                    (value as? Int) ?: (value as? Long)?.toInt()
                } else null
            } finally {
                rs.close()
            }
        } finally {
            stmt.close()
        }
    }

    fun stats(): DbStats {
        connection.autoCommit = true
        val stmt = connection.createStatement()
        try {
            val httpRs = stmt.executeQuery("SELECT COUNT(*) FROM proxy_http_history")
            val httpCount = if (httpRs.next()) httpRs.getInt(1) else 0
            httpRs.close()

            val scannerRs = stmt.executeQuery("SELECT COUNT(*) FROM scanner_issues")
            val scannerCount = if (scannerRs.next()) scannerRs.getInt(1) else 0
            scannerRs.close()

            val blobRs = stmt.executeQuery("SELECT COUNT(*) FROM large_responses")
            val blobCount = if (blobRs.next()) blobRs.getInt(1) else 0
            blobRs.close()

            val rawDupRs = stmt.executeQuery("SELECT COUNT(*) FROM proxy_http_raw_duplicates")
            val rawDupCount = if (rawDupRs.next()) rawDupRs.getInt(1) else 0
            rawDupRs.close()

            return DbStats(proxyHttpCount = httpCount, scannerIssueCount = scannerCount, blobCount = blobCount, rawDuplicateCount = rawDupCount)
        } finally {
            stmt.close()
        }
    }

    fun clearProxyHttpHistory() {
        connection.createStatement().use { stmt ->
            stmt.execute("DELETE FROM proxy_http_history")
        }
    }

    fun clearScannerIssues() {
        connection.createStatement().use { stmt ->
            stmt.execute("DELETE FROM scanner_issues")
        }
    }

    fun pruneProxyHttpHistory(maxRows: Int = 100_000) {
        connection.autoCommit = true
        val stmt = connection.prepareStatement(
            "DELETE FROM proxy_http_history WHERE id <= (SELECT id FROM proxy_http_history ORDER BY id DESC LIMIT 1 OFFSET ?)"
        )
        try {
            stmt.setInt(1, maxRows)
            stmt.execute()
        } finally {
            stmt.close()
        }
    }

    fun pruneScannerIssues(maxRows: Int = 10_000) {
        connection.autoCommit = true
        val stmt = connection.prepareStatement(
            "DELETE FROM scanner_issues WHERE id <= (SELECT id FROM scanner_issues ORDER BY id DESC LIMIT 1 OFFSET ?)"
        )
        try {
            stmt.setInt(1, maxRows)
            stmt.execute()
        } finally {
            stmt.close()
        }
    }

    fun pruneAll(maxHttpRows: Int = 100_000, maxScannerRows: Int = 10_000) {
        pruneProxyHttpHistory(maxHttpRows)
        pruneScannerIssues(maxScannerRows)
        pruneBlobs()
    }

    fun clearAll() {
        clearProxyHttpHistory()
        clearScannerIssues()
        clearBlobs()
    }

    // ─── BLOB Store (large response storage) ───

    fun storeBlob(data: ByteArray, contentType: String = "application/octet-stream", ttlMs: Long = 600_000): String {
        val id = java.util.UUID.randomUUID().toString()
        val now = System.currentTimeMillis()
        connection.autoCommit = true
        val stmt = connection.prepareStatement(
            "INSERT INTO large_responses (id, data, content_type, original_size, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        try {
            stmt.setString(1, id)
            stmt.setBytes(2, data)
            stmt.setString(3, contentType)
            stmt.setInt(4, data.size)
            stmt.setLong(5, now)
            stmt.setLong(6, now + ttlMs)
            stmt.execute()
        } finally {
            stmt.close()
        }
        return id
    }

    fun readBlob(blobId: String, offset: Int = 0, limit: Int = -1): ByteArray? {
        connection.autoCommit = true
        val stmt = connection.prepareStatement("SELECT data, original_size FROM large_responses WHERE id = ?")
        try {
            stmt.setString(1, blobId)
            val rs = stmt.executeQuery()
            if (!rs.next()) return null
            val bytes = rs.getBytes("data")
            if (offset >= bytes.size) return ByteArray(0)
            val end = if (limit < 0 || (offset + limit) > bytes.size) bytes.size else (offset + limit)
            return bytes.copyOfRange(offset, end)
        } finally {
            stmt.close()
        }
    }

    fun readBlobAsString(blobId: String, offset: Int = 0, limit: Int = -1): String? {
        return readBlob(blobId, offset, limit)?.let { String(it) }
    }

    fun deleteBlob(blobId: String): Boolean {
        connection.autoCommit = true
        val stmt = connection.prepareStatement("DELETE FROM large_responses WHERE id = ?")
        try {
            stmt.setString(1, blobId)
            return stmt.executeUpdate() > 0
        } finally {
            stmt.close()
        }
    }

    fun pruneBlobs() {
        connection.autoCommit = true
        connection.createStatement().execute("DELETE FROM large_responses WHERE expires_at < ${System.currentTimeMillis()}")
    }

    fun clearBlobs() {
        connection.createStatement().use { it.execute("DELETE FROM large_responses") }
    }

    fun close() {
        connection.close()
    }
}

data class ProxyHttpSummary(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val contentType: String?,
    val paramNames: List<String>?,
    val hitCount: Int = 1,
    val endpointScore: Int = 0,
    val candidateReason: String? = null,
    val authRequiredHint: String? = null,
    val sensitiveMarkerCount: Int = 0,
    val responseSummary: String? = null
)

data class ProxyHttpEntry(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val requestHeaders: String?,
    val requestBody: String?,
    val responseHeaders: String?,
    val responseBody: String?,
    val contentType: String?,
    val paramNames: String?,
    val capturedAt: Long,
    val dedupKey: String? = null,
    val canonicalUrl: String? = null,
    val endpointFingerprint: String? = null,
    val requestParamCount: Int? = null,
    val responseSummary: String? = null,
    val sensitiveMarkerCount: Int = 0,
    val authRequiredHint: String? = null,
    val endpointScore: Int = 0,
    val candidateReason: String? = null,
    val hitCount: Int = 1,
    val duplicates: List<RawDuplicateEntry> = emptyList()
)

data class ScannerIssueSummary(
    val id: Int,
    val name: String,
    val severity: String,
    val url: String
)

data class ScannerIssueEntry(
    val id: Int,
    val name: String,
    val severity: String,
    val url: String,
    val detail: String?,
    val remediation: String?,
    val capturedAt: Long
)

data class DbStats(
    val proxyHttpCount: Int,
    val scannerIssueCount: Int,
    val blobCount: Int = 0,
    val rawDuplicateCount: Int = 0
)

data class RawDuplicateEntry(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val requestHeaders: String?,
    val requestBody: String?,
    val responseHeaders: String?,
    val responseBody: String?,
    val contentType: String?,
    val capturedAt: Long
)

data class HttpHistoryRow(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val contentType: String?,
    val capturedAt: Long,
    val hitCount: Int
)
