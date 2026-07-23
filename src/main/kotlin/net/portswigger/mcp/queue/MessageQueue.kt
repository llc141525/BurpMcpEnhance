package net.portswigger.mcp.queue

import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

class MessageQueue(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
    private val resultTtlMs: Long = DEFAULT_RESULT_TTL_MS,
    private val cleanupIntervalMs: Long = DEFAULT_CLEANUP_INTERVAL_MS
) {

    private val pendingTasks = ConcurrentLinkedQueue<Task>()
    private val results = ConcurrentHashMap<String, TaskResult>()
    private val taskCounter = AtomicInteger(0)
    private val activeJobs = ConcurrentHashMap<String, Job>()
    private val cleanupJob = scope.launch {
        while (isActive) {
            delay(cleanupIntervalMs)
            cleanup(resultTtlMs)
        }
    }

    private val _stats = MutableQueueStats()
    val stats: QueueStats get() = _stats.snapshot()

    fun submit(type: String, params: Map<String, String> = emptyMap(), processor: suspend (Task) -> String): String {
        val taskId = "task-${taskCounter.incrementAndGet()}-${System.currentTimeMillis()}"
        val task = Task(id = taskId, type = type, params = params)
        pendingTasks.add(task)
        _stats.incrementSubmitted()

        results[taskId] = TaskResult(taskId, TaskStatus.PENDING)

        val job = scope.launch {
            _stats.incrementProcessing()
            results.computeIfPresent(taskId) { _, existing -> existing.copy(status = TaskStatus.RUNNING) }
            try {
                val result = processor(task)
                results[taskId] = TaskResult(
                    taskId = taskId,
                    status = TaskStatus.COMPLETED,
                    result = result,
                    completedAt = System.currentTimeMillis()
                )
                _stats.incrementCompleted()
            } catch (e: CancellationException) {
                results[taskId] = TaskResult(
                    taskId = taskId,
                    status = TaskStatus.CANCELLED,
                    error = "Cancelled",
                    completedAt = System.currentTimeMillis()
                )
                throw e
            } catch (e: Exception) {
                results[taskId] = TaskResult(
                    taskId = taskId,
                    status = TaskStatus.FAILED,
                    error = e.message ?: "Unknown error",
                    completedAt = System.currentTimeMillis()
                )
                _stats.incrementFailed()
            } finally {
                pendingTasks.remove(task)
                _stats.decrementProcessing()
                activeJobs.remove(taskId)
            }
        }

        activeJobs[taskId] = job
        return taskId
    }

    fun getResult(taskId: String): TaskResult? {
        return results[taskId]
    }

    fun cancelTask(taskId: String): Boolean {
        val job = activeJobs[taskId] ?: return false
        job.cancel()
        results[taskId] = TaskResult(
            taskId = taskId,
            status = TaskStatus.CANCELLED,
            error = "Cancelled",
            completedAt = System.currentTimeMillis()
        )
        return true
    }

    fun cleanup(maxAgeMs: Long = 300_000) {
        val cutoff = System.currentTimeMillis() - maxAgeMs
        results.entries.removeAll { (_, result) ->
            result.completedAt != null && result.completedAt < cutoff
        }
    }

    fun clear() {
        activeJobs.values.forEach { it.cancel() }
        activeJobs.clear()
        pendingTasks.clear()
        results.clear()
        _stats.reset()
    }

    fun shutdown() {
        cleanupJob.cancel()
        activeJobs.values.forEach { it.cancel() }
        activeJobs.clear()
        pendingTasks.clear()
        results.clear()
        _stats.reset()
        scope.cancel()
    }

    companion object {
        const val DEFAULT_RESULT_TTL_MS: Long = 300_000
        const val DEFAULT_CLEANUP_INTERVAL_MS: Long = 60_000
    }

    private class MutableQueueStats {
        private var submitted = AtomicInteger(0)
        private var completed = AtomicInteger(0)
        private var failed = AtomicInteger(0)
        private var processing = AtomicInteger(0)

        fun incrementSubmitted() { submitted.incrementAndGet() }
        fun incrementCompleted() { completed.incrementAndGet() }
        fun incrementFailed() { failed.incrementAndGet() }
        fun incrementProcessing() { processing.incrementAndGet() }
        fun decrementProcessing() { processing.decrementAndGet() }
        fun reset() {
            submitted.set(0); completed.set(0); failed.set(0); processing.set(0)
        }

        fun snapshot() = QueueStats(
            submitted = submitted.get(),
            completed = completed.get(),
            failed = failed.get(),
            processing = processing.get()
        )
    }
}

data class QueueStats(
    val submitted: Int,
    val completed: Int,
    val failed: Int,
    val processing: Int
)
