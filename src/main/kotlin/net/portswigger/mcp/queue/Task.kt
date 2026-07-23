package net.portswigger.mcp.queue

data class Task(
    val id: String,
    val type: String,
    val params: Map<String, String> = emptyMap(),
    val createdAt: Long = System.currentTimeMillis()
)

data class TaskResult(
    val taskId: String,
    val status: TaskStatus,
    val result: String? = null,
    val error: String? = null,
    val completedAt: Long? = null
)

enum class TaskStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
}
