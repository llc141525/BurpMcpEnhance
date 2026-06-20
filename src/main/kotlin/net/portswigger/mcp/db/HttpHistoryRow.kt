package net.portswigger.mcp.db

data class HttpHistoryRow(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val contentType: String?,
    val capturedAt: Long,
    val hitCount: Int
)
