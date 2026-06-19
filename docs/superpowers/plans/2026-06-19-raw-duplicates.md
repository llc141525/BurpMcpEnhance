# Raw Duplicates 存储 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把去重逻辑从"丢弃重复 raw data"改为"存入独立表 + 外键可查"，让 AI 默认看到 canonical 视图，`get_http_detail` 加 `include_duplicates=true` 时返回原始重复条目。

**Architecture:** 新增 `proxy_http_raw_duplicates` 表，通过 `canonical_id FK → proxy_http_history.id ON DELETE CASCADE` 关联。写入时 canonical 永远取第一条，重复的写 raw 表（每个 canonical 保留最近 N 条）。读取时默认只查 canonical，`include_duplicates=true` 时 JOIN raw 表。

**Tech Stack:** Kotlin, SQLite (JDBC), JUnit 5, MockK, Swing (UI)

---

## 文件变更总览

| 文件 | 类型 |
|---|---|
| `src/main/kotlin/net/portswigger/mcp/db/Database.kt` | 修改 |
| `src/main/kotlin/net/portswigger/mcp/exporter/Exporter.kt` | 修改 |
| `src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt` | 修改 |
| `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt` | 修改 |
| `src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt` | 修改 |
| `src/main/kotlin/net/portswigger/mcp/config/StatusDashboardPanel.kt` | 修改 |
| `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt` | 修改（追加） |

---

## Task 1: 数据类 + Schema 迁移

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

- [ ] **Step 1: 在 `Database.kt` 末尾添加 `RawDuplicateEntry` 数据类，并更新 `DbStats`**

在文件末尾 `DbStats` 定义处做以下修改：

```kotlin
// 更新 DbStats，添加 rawDuplicateCount
data class DbStats(
    val proxyHttpCount: Int,
    val scannerIssueCount: Int,
    val blobCount: Int = 0,
    val rawDuplicateCount: Int = 0   // ← 新增
)

// 新增数据类（放在 DbStats 下方）
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
```

同时在 `ProxyHttpEntry` 数据类末尾添加 `duplicates` 字段：

```kotlin
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
    val hitCount: Int = 1,
    val duplicates: List<RawDuplicateEntry> = emptyList()  // ← 新增
)
```

- [ ] **Step 2: 在 `migrateSchema()` 中添加新表和索引**

在 `migrateSchema` 方法的 `close()` 之前添加：

```kotlin
try {
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
} catch (e: Exception) {
    net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration CREATE raw_duplicates: ${e.message}", e)
}
try {
    execute("""
        CREATE INDEX IF NOT EXISTS idx_raw_dup_canonical
            ON proxy_http_raw_duplicates(canonical_id, captured_at DESC)
    """.trimIndent())
} catch (e: Exception) {
    net.portswigger.mcp.logging.LogWriter.instance?.log("WARN", "db", "Migration CREATE idx_raw_dup: ${e.message}", e)
}
```

- [ ] **Step 3: 在 `DatabaseTest.kt` 末尾添加 schema 测试**

```kotlin
@Test
fun `raw duplicates table is created on migration`() {
    // stats() 能正常返回 rawDuplicateCount 说明表存在
    val stats = database.stats()
    assertEquals(0, stats.rawDuplicateCount)
}
```

- [ ] **Step 4: 运行测试，确认通过**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" --info
```

期望：所有现有测试 + 新测试均 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/db/Database.kt
git add src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt
git commit -m "feat: add RawDuplicateEntry data class, DbStats.rawDuplicateCount, and proxy_http_raw_duplicates schema"
```

---

## Task 2: 写入路径 — 存储原始重复数据

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

- [ ] **Step 1: 先写失败测试**

在 `DatabaseTest.kt` 末尾添加：

```kotlin
@Test
fun `duplicate login requests are stored in raw duplicates table`() {
    val dedupKey = Database.computeDedupKey("POST", "http://example.com/login")
    val t = System.currentTimeMillis()

    // 第一条：成为 canonical（id=1）
    database.upsertProxyHttpHistory(
        listOf(
            ProxyHttpEntry(1, "POST", 200, "http://example.com/login",
                "Content-Type: application/json", """{"user":"alice","pass":"secret1"}""",
                null, null, "application/json", null, t, dedupKey = dedupKey)
        ),
        maxRawDuplicatesPerCanonical = 10
    )

    // 第二条：应写入 raw 表，而非丢弃
    database.upsertProxyHttpHistory(
        listOf(
            ProxyHttpEntry(2, "POST", 200, "http://example.com/login",
                "Content-Type: application/json", """{"user":"bob","pass":"secret2"}""",
                null, null, "application/json", null, t + 1000, dedupKey = dedupKey)
        ),
        maxRawDuplicatesPerCanonical = 10
    )

    val stats = database.stats()
    assertEquals(1, stats.proxyHttpCount)        // 仍只有一条 canonical
    assertEquals(1, stats.rawDuplicateCount)     // 一条 raw
    val canonical = database.getProxyHttpDetail(listOf(1)).first()
    assertEquals(2, canonical.hitCount)          // hit_count=2
}
```

- [ ] **Step 2: 运行测试，确认失败（方法签名不存在）**

```bash
.\gradlew.bat test --tests "*.DatabaseTest.duplicate login requests are stored in raw duplicates table"
```

期望：编译失败（`upsertProxyHttpHistory` 无第二个参数）。

- [ ] **Step 3: 修改 `upsertProxyHttpHistory` 签名和实现**

将 `Database.kt` 中 `upsertProxyHttpHistory` 完整替换为：

```kotlin
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
                "content_type, param_names, captured_at, dedup_key, hit_count) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
```

- [ ] **Step 4: 运行测试，确认通过**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" --info
```

期望：全部 PASS（包括现有测试，因为默认 `maxRawDuplicatesPerCanonical = 0` 与旧行为等价）。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/db/Database.kt
git add src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt
git commit -m "feat: store raw duplicate requests in proxy_http_raw_duplicates table"
```

---

## Task 3: Pruning — 每 canonical 限制 N 条 raw

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

- [ ] **Step 1: 先写失败测试**

在 `DatabaseTest.kt` 末尾添加：

```kotlin
@Test
fun `pruneRawDuplicates keeps only the N most recent entries per canonical`() {
    val dedupKey = Database.computeDedupKey("POST", "http://example.com/login")
    val baseTime = System.currentTimeMillis()

    // 插入 canonical
    database.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(1, "POST", 200, "http://example.com/login",
            null, "body-canonical", null, null, null, null, baseTime, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 3
    )

    // 插入 5 条重复（每次单独 upsert，模拟连续到达）
    for (i in 1..5) {
        database.upsertProxyHttpHistory(
            listOf(ProxyHttpEntry(100 + i, "POST", 200, "http://example.com/login",
                null, "body-dup-$i", null, null, null, null, baseTime + i * 1000L, dedupKey = dedupKey)),
            maxRawDuplicatesPerCanonical = 3
        )
    }

    val stats = database.stats()
    assertEquals(3, stats.rawDuplicateCount)   // 超出的旧条目已被删除，只保留最近 3 条
}
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
.\gradlew.bat test --tests "*.DatabaseTest.pruneRawDuplicates keeps only the N most recent entries per canonical"
```

期望：FAIL（`pruneRawDuplicates` 尚不存在）。

- [ ] **Step 3: 在 `Database.kt` 中添加 `pruneRawDuplicates` 私有方法**

在 `upsertProxyHttpHistory` 方法之后添加：

```kotlin
private fun pruneRawDuplicates(canonicalId: Int, maxPerCanonical: Int) {
    connection.prepareStatement(
        "DELETE FROM proxy_http_raw_duplicates " +
        "WHERE canonical_id = ? AND id NOT IN (" +
        "  SELECT id FROM proxy_http_raw_duplicates " +
        "  WHERE canonical_id = ? ORDER BY captured_at DESC LIMIT ?" +
        ")"
    ).use { stmt ->
        stmt.setInt(1, canonicalId)
        stmt.setInt(2, canonicalId)
        stmt.setInt(3, maxPerCanonical)
        stmt.executeUpdate()
    }
}
```

- [ ] **Step 4: 运行测试，确认通过**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" --info
```

期望：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/db/Database.kt
git add src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt
git commit -m "feat: prune raw duplicates to maxPerCanonical after each insert"
```

---

## Task 4: 读取路径 — `getProxyHttpDetail` 支持 `includeDuplicates`

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

- [ ] **Step 1: 先写失败测试**

在 `DatabaseTest.kt` 末尾添加：

```kotlin
@Test
fun `getProxyHttpDetail with includeDuplicates returns raw entries`() {
    val dedupKey = Database.computeDedupKey("POST", "http://example.com/login")
    val t = System.currentTimeMillis()

    database.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(1, "POST", 200, "http://example.com/login",
            null, """{"user":"alice"}""", null, null, null, null, t, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )
    database.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(2, "POST", 200, "http://example.com/login",
            null, """{"user":"bob"}""", null, null, null, null, t + 1000, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )

    // 不带 include_duplicates
    val withoutDups = database.getProxyHttpDetail(listOf(1))
    assertEquals(0, withoutDups.first().duplicates.size)

    // 带 include_duplicates
    val withDups = database.getProxyHttpDetail(listOf(1), includeDuplicates = true)
    assertEquals(1, withDups.first().duplicates.size)
    assertEquals("""{"user":"bob"}""", withDups.first().duplicates.first().requestBody)
}
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
.\gradlew.bat test --tests "*.DatabaseTest.getProxyHttpDetail with includeDuplicates returns raw entries"
```

期望：编译失败（`getProxyHttpDetail` 无 `includeDuplicates` 参数）。

- [ ] **Step 3: 在 `Database.kt` 中添加 `getRawDuplicates` 私有方法**

在 `pruneRawDuplicates` 方法之后添加：

```kotlin
private fun getRawDuplicates(canonicalIds: List<Int>): Map<Int, List<RawDuplicateEntry>> {
    if (canonicalIds.isEmpty()) return emptyMap()
    val placeholders = canonicalIds.joinToString(",") { "?" }
    val stmt = connection.prepareStatement(
        "SELECT * FROM proxy_http_raw_duplicates " +
        "WHERE canonical_id IN ($placeholders) " +
        "ORDER BY canonical_id, captured_at DESC"
    )
    try {
        canonicalIds.forEachIndexed { i, id -> stmt.setInt(i + 1, id) }
        val rs = stmt.executeQuery()
        val result = mutableMapOf<Int, MutableList<RawDuplicateEntry>>()
        try {
            while (rs.next()) {
                val cid = rs.getInt("canonical_id")
                result.getOrPut(cid) { mutableListOf() }.add(
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
        } finally {
            rs.close()
        }
        return result
    } finally {
        stmt.close()
    }
}
```

- [ ] **Step 4: 更新 `getProxyHttpDetail` 签名，添加 `includeDuplicates` 参数**

把现有的 `fun getProxyHttpDetail(ids: List<Int>): List<ProxyHttpEntry>` 改为：

```kotlin
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
                results.add(
                    ProxyHttpEntry(
                        id = rs.getInt("id"),
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
                        hitCount = rs.getInt("hit_count")
                    )
                )
            }
            if (includeDuplicates && results.isNotEmpty()) {
                val rawMap = getRawDuplicates(results.map { it.id })
                return results.map { it.copy(duplicates = rawMap[it.id] ?: emptyList()) }
            }
            return results
        } finally {
            rs.close()
        }
    } finally {
        stmt.close()
    }
}
```

- [ ] **Step 5: 运行测试，确认通过**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" --info
```

期望：全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/db/Database.kt
git add src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt
git commit -m "feat: add getProxyHttpDetail(includeDuplicates) to return raw duplicate entries"
```

---

## Task 5: 更新 `stats()` 返回 rawDuplicateCount

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/db/Database.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt`

- [ ] **Step 1: 先写失败测试（验证 stats 中的 rawDuplicateCount）**

（Task 2 的测试已覆盖这个 —— 如果 `stats()` 已返回 `rawDuplicateCount`，这一步验证一次 stats 在有数据时正确。）

在 `DatabaseTest.kt` 末尾添加：

```kotlin
@Test
fun `stats returns correct rawDuplicateCount`() {
    val dedupKey = Database.computeDedupKey("POST", "http://example.com/api")
    val t = System.currentTimeMillis()
    database.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(1, "POST", 200, "http://example.com/api",
            null, "body1", null, null, null, null, t, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )
    database.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(2, "POST", 200, "http://example.com/api",
            null, "body2", null, null, null, null, t + 1000, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )
    database.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(3, "POST", 200, "http://example.com/api",
            null, "body3", null, null, null, null, t + 2000, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )
    val stats = database.stats()
    assertEquals(1, stats.proxyHttpCount)
    assertEquals(2, stats.rawDuplicateCount)
}
```

- [ ] **Step 2: 运行测试，确认失败（stats() 还没有查 raw 表）**

```bash
.\gradlew.bat test --tests "*.DatabaseTest.stats returns correct rawDuplicateCount"
```

期望：FAIL（`rawDuplicateCount` 总是 0）。

- [ ] **Step 3: 更新 `stats()` 方法**

把 `Database.kt` 中的 `stats()` 方法替换为：

```kotlin
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

        return DbStats(
            proxyHttpCount = httpCount,
            scannerIssueCount = scannerCount,
            blobCount = blobCount,
            rawDuplicateCount = rawDupCount
        )
    } finally {
        stmt.close()
    }
}
```

- [ ] **Step 4: 运行全部测试，确认通过**

```bash
.\gradlew.bat test --tests "*.DatabaseTest" --info
```

期望：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/db/Database.kt
git add src/test/kotlin/net/portswigger/mcp/db/DatabaseTest.kt
git commit -m "feat: stats() includes rawDuplicateCount from proxy_http_raw_duplicates"
```

---

## Task 6: McpConfig + Exporter 接线

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt`
- Modify: `src/main/kotlin/net/portswigger/mcp/exporter/Exporter.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/exporter/ExporterTest.kt`

- [ ] **Step 1: 在 `McpConfig.kt` 末尾添加两个字段**

在 `McpConfig` class 中现有字段末尾（`_knownBurpPlugins` 之后）添加：

```kotlin
var saveRawDuplicates by storage.boolean(true)
var maxRawDuplicatesPerCanonical by storage.int(10)
```

- [ ] **Step 2: 在 `Exporter.kt` 中将 config 值传入 `upsertProxyHttpHistory`**

找到 `Exporter.kt` 第 126 行附近：

```kotlin
database.upsertProxyHttpHistory(entries)
```

改为：

```kotlin
val maxRaw = if (config.saveRawDuplicates) config.maxRawDuplicatesPerCanonical else 0
database.upsertProxyHttpHistory(entries, maxRawDuplicatesPerCanonical = maxRaw)
```

- [ ] **Step 3: 在 `ExporterTest.kt` 中添加测试**

在 `ExporterTest.kt` 末尾添加（注意 mock setup 中需要给新 config 字段设置默认值）：

```kotlin
@Test
fun `exporter stores raw duplicates when saveRawDuplicates is true`() = runBlocking {
    intStore["maxRawDuplicatesPerCanonical"] = 10
    booleanStore["saveRawDuplicates"] = true

    val proxyMock = mockk<Proxy>(relaxed = true)
    every { api.proxy() } returns proxyMock

    // 两条相同 URL 的请求（不同时间戳）
    val entry1 = createMockProxyEntry(1000, "http://example.com/login")
    val entry2 = createMockProxyEntry(2000, "http://example.com/login")

    every { proxyMock.history() } returns listOf(entry1)
    exporter.exportProxyHttpHistory()

    every { proxyMock.history() } returns listOf(entry1, entry2)
    exporter.exportProxyHttpHistory()

    assertEquals(1, database.stats().proxyHttpCount)
    assertEquals(1, database.stats().rawDuplicateCount)
}
```

- [ ] **Step 4: 运行测试**

```bash
.\gradlew.bat test --tests "*.ExporterTest" --info
```

期望：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/McpConfig.kt
git add src/main/kotlin/net/portswigger/mcp/exporter/Exporter.kt
git add src/test/kotlin/net/portswigger/mcp/exporter/ExporterTest.kt
git commit -m "feat: wire saveRawDuplicates and maxRawDuplicatesPerCanonical from McpConfig to Exporter"
```

---

## Task 7: ExporterTools — `get_http_detail` 添加 `include_duplicates`

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt`
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: 更新 `GetProxyHttpDetail` 数据类，添加 `include_duplicates` 字段**

在 `ExporterTools.kt` 中：

```kotlin
// 旧
@Serializable
data class GetProxyHttpDetail(val ids: String)

// 新
@Serializable
data class GetProxyHttpDetail(val ids: String, val include_duplicates: Boolean = false)
```

- [ ] **Step 2: 更新工具处理器，传递 `include_duplicates` 并渲染 duplicates**

把 `mcpTool<GetProxyHttpDetail>` 的处理体替换为：

```kotlin
mcpTool<GetProxyHttpDetail>(
    "Gets full proxy HTTP history details by IDs. Provide comma-separated IDs (e.g., \"1,2,3\"). " +
    "Returns complete request/response data for the specified entries. " +
    "Set include_duplicates=true to also retrieve raw duplicate requests captured for the same endpoint " +
    "(e.g., multiple account logins to the same URL). " +
    "Call list_proxy_http_history first to get IDs, then drill down with this tool."
) {
    val idList = ids.split(",").mapNotNull { it.trim().toIntOrNull() }
    if (idList.isEmpty()) return@mcpTool "No valid IDs provided: $ids"
    val entries = database.getProxyHttpDetail(idList, includeDuplicates = include_duplicates)
    if (entries.isEmpty()) return@mcpTool "No entries found for IDs: $ids"
    entries.joinToString("\n\n---\n\n") { entry ->
        buildString {
            appendLine("ID: ${entry.id}")
            appendLine("Method: ${entry.method}")
            entry.status?.let { appendLine("Status: $it") }
            appendLine("URL: ${entry.url}")
            entry.contentType?.let { appendLine("Content-Type: $it") }
            if (entry.hitCount > 1) appendLine("Hits: ${entry.hitCount}")
            appendLine()
            appendLine("--- Request ---")
            entry.requestHeaders?.let { appendLine(it) }
            if (!entry.requestBody.isNullOrBlank()) {
                appendLine()
                append(entry.requestBody)
            }
            appendLine()
            appendLine("--- Response ---")
            entry.responseHeaders?.let { appendLine(it) }
            if (!entry.responseBody.isNullOrBlank()) {
                appendLine()
                append(entry.responseBody)
                appendLine()
                appendLine("[Body truncated to 8KB]")
            }
            if (entry.duplicates.isNotEmpty()) {
                appendLine()
                appendLine("--- Raw Duplicates (${entry.duplicates.size}) ---")
                entry.duplicates.forEachIndexed { i, dup ->
                    appendLine()
                    appendLine("Duplicate ${i + 1}:")
                    dup.requestHeaders?.let { appendLine(it) }
                    if (!dup.requestBody.isNullOrBlank()) {
                        appendLine()
                        append(dup.requestBody)
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 3: 在 `ToolsKtTest.kt` 中添加 `include_duplicates` 测试**

在该文件末尾（或适当位置）添加一个测试，验证 `include_duplicates=true` 时 raw 数据出现在输出中。先找一下现有 `get_proxy_http_detail` 测试的位置，仿照其 setup 模式添加：

```kotlin
@Test
fun `get_proxy_http_detail with include_duplicates returns raw entries in output`() = runBlocking {
    val dedupKey = Database.computeDedupKey("POST", "http://target.com/login")
    val t = System.currentTimeMillis()
    db.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(1, "POST", 200, "http://target.com/login",
            "Content-Type: application/json", """{"user":"alice"}""",
            null, null, "application/json", null, t, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )
    db.upsertProxyHttpHistory(
        listOf(ProxyHttpEntry(2, "POST", 200, "http://target.com/login",
            "Content-Type: application/json", """{"user":"bob"}""",
            null, null, "application/json", null, t + 1000, dedupKey = dedupKey)),
        maxRawDuplicatesPerCanonical = 10
    )

    val result = callTool("get_proxy_http_detail", mapOf("ids" to "1", "include_duplicates" to true))
    assertTrue(result.contains("Raw Duplicates"), "Output should contain 'Raw Duplicates' section")
    assertTrue(result.contains("""{"user":"bob"}"""), "Output should contain bob's credentials")
}
```

注：`callTool` 和 `db` 变量名按照该测试文件的实际 helper 命名，若不同请对应修改。

- [ ] **Step 4: 运行测试**

```bash
.\gradlew.bat test --tests "*.ToolsKtTest" --info
```

期望：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt
git add src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt
git commit -m "feat: add include_duplicates param to get_proxy_http_detail MCP tool"
```

---

## Task 8: UI — ServerConfigurationPanel

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt`

- [ ] **Step 1: 在 `ServerConfigurationPanel` 中声明新字段**

在 class 顶部的 `private lateinit var` 字段区域添加：

```kotlin
private lateinit var saveRawDuplicatesCheckBox: JCheckBox
private lateinit var maxRawDuplicatesSpinner: JSpinner
```

- [ ] **Step 2: 在 `buildPanel()` 中，在 `createExportNoiseModePanel()` 调用之后添加 raw duplicates UI**

```kotlin
add(createVerticalStrut(Design.Spacing.MD))
add(createRawDuplicatesPanel())
```

- [ ] **Step 3: 实现 `createRawDuplicatesPanel()` 方法**

在文件末尾（与其他 `private fun create*` 同级）添加：

```kotlin
private fun createRawDuplicatesPanel(): JPanel {
    val panel = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
    }

    saveRawDuplicatesCheckBox = createStandardCheckBox(
        "保存重复请求的原始数据", config.saveRawDuplicates
    ) { enabled ->
        config.saveRawDuplicates = enabled
        maxRawDuplicatesSpinner.isEnabled = enabled
    }
    panel.add(saveRawDuplicatesCheckBox)
    panel.add(createVerticalStrut(Design.Spacing.SM))

    val spinnerPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
        border = BorderFactory.createEmptyBorder(0, 20, 0, 0)
    }

    maxRawDuplicatesSpinner = JSpinner(SpinnerNumberModel(
        config.maxRawDuplicatesPerCanonical.coerceIn(1, 100), 1, 100, 1
    )).apply {
        isEnabled = config.saveRawDuplicates
        preferredSize = java.awt.Dimension(60, preferredSize.height)
        addChangeListener {
            config.maxRawDuplicatesPerCanonical = (value as Int)
        }
    }

    spinnerPanel.add(JLabel("每个接口最多保留 ").apply {
        font = Design.Typography.bodyLarge
        foreground = Design.Colors.onSurface
    })
    spinnerPanel.add(maxRawDuplicatesSpinner)
    spinnerPanel.add(JLabel(" 条").apply {
        font = Design.Typography.bodyLarge
        foreground = Design.Colors.onSurface
    })
    panel.add(spinnerPanel)

    return panel
}
```

- [ ] **Step 4: 构建项目，确认无编译错误**

```bash
.\gradlew.bat shadowJar
```

期望：BUILD SUCCESSFUL。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/components/ServerConfigurationPanel.kt
git commit -m "feat: add saveRawDuplicates toggle and maxRawDuplicatesPerCanonical spinner to config UI"
```

---

## Task 9: UI — StatusDashboardPanel 新增原始重复数统计

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/config/StatusDashboardPanel.kt`

- [ ] **Step 1: 在 `StatusDashboardPanel` 中声明新徽章**

在 class 顶部现有 badge 字段（`dbHttpBadge`、`dbScanBadge`）旁边添加：

```kotlin
private val dbRawDupBadge = Design.createBadge("0", Design.Colors.secondary)
```

- [ ] **Step 2: 在 `createStatsGrid` 或数据库统计行中添加新徽章**

找到文件中渲染数据库统计的地方（搜索 `dbHttpBadge` 或 `dbScanBadge` 使用处），在其后添加 `dbRawDupBadge`。具体形式取决于 `createStatsGrid()` 的实现，参照以下模式：

```kotlin
// 已有：
row.add(dbHttpBadge)
row.add(dbScanBadge)
// 新增：
row.add(dbRawDupBadge)
```

如果有标签，在旁边加：
```kotlin
row.add(JLabel("原始重复").apply { font = Design.Typography.labelSmall; foreground = Design.Colors.onSurface })
row.add(dbRawDupBadge)
```

- [ ] **Step 3: 在 `refreshAll()` 或 stats 刷新方法中更新 `dbRawDupBadge`**

找到更新 `dbHttpBadge` 的代码，在其旁边添加：

```kotlin
dbRawDupBadge.text = "${stats.rawDuplicateCount}"
```

- [ ] **Step 4: 构建项目，确认无编译错误**

```bash
.\gradlew.bat shadowJar
```

期望：BUILD SUCCESSFUL。

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/config/StatusDashboardPanel.kt
git commit -m "feat: show rawDuplicateCount badge in StatusDashboardPanel"
```

---

## Task 10: 全量测试 + 最终构建

**Files:** 无新增

- [ ] **Step 1: 运行全部测试**

```bash
.\gradlew.bat test
```

期望：所有测试 PASS，无失败。

- [ ] **Step 2: 构建最终 JAR**

```bash
.\gradlew.bat shadowJar
```

期望：`build/libs/burp-mcp-all.jar` 生成成功。

- [ ] **Step 3: 验证 ExporterStats 工具输出包含 rawDuplicateCount**

在 `ExporterTools.kt` 中找到 `ExporterStats` 工具的输出代码：

```kotlin
appendLine("Database proxy HTTP entries: ${stats.dbStats.proxyHttpCount}")
appendLine("Database scanner issues: ${stats.dbStats.scannerIssueCount}")
if (stats.dbStats.blobCount > 0) appendLine("Database large responses: ${stats.dbStats.blobCount}")
```

在其后添加：

```kotlin
if (stats.dbStats.rawDuplicateCount > 0) appendLine("Raw duplicate requests: ${stats.dbStats.rawDuplicateCount}")
```

- [ ] **Step 4: 最终 commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/ExporterTools.kt
git commit -m "feat: show rawDuplicateCount in exporter_stats tool output"
```

---

## 自审结果

| Spec 章节 | 对应 Task |
|---|---|
| 新增表 + CASCADE + 索引 | Task 1, 2 |
| 写入路径：first-wins canonical | Task 2 |
| 每 canonical 最近 N 条 pruning | Task 3 |
| `getProxyHttpDetail(includeDuplicates)` | Task 4 |
| stats() rawDuplicateCount | Task 5 |
| Exporter 接线 | Task 6 |
| McpConfig 字段 | Task 6 |
| MCP tool include_duplicates 参数 | Task 7 |
| UI checkbox + spinner | Task 8 |
| UI badge | Task 9 |

所有 spec 章节均有对应 Task，无遗漏。类型一致性：`RawDuplicateEntry`、`DbStats.rawDuplicateCount`、`ProxyHttpEntry.duplicates`、`maxRawDuplicatesPerCanonical` 在所有 Task 中命名一致。
