package net.portswigger.mcp.queue

import kotlinx.coroutines.delay
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class MessageQueueTest {

    private lateinit var messageQueue: MessageQueue

    @BeforeEach
    fun setup() {
        messageQueue = MessageQueue()
    }

    @AfterEach
    fun tearDown() {
        messageQueue.shutdown()
    }

    @Test
    fun `submit should return task id and process task`() {
        val taskId = messageQueue.submit("test", emptyMap()) {
            "result-${it.id}"
        }

        assertNotNull(taskId)
        assertTrue(taskId.startsWith("task-"))

        runBlocking {
            var result: TaskResult?
            var attempts = 0
            do {
                delay(50)
                result = messageQueue.getResult(taskId)
                attempts++
            } while (result?.status == TaskStatus.PENDING || result?.status == TaskStatus.RUNNING && attempts < 50)

            assertNotNull(result)
            assertEquals(TaskStatus.COMPLETED, result!!.status)
            assertTrue(result!!.result?.contains(taskId) == true)
        }
    }

    @Test
    fun `submit should handle task failure`() {
        val taskId = messageQueue.submit("test") {
            throw RuntimeException("Task failed intentionally")
        }

        runBlocking {
            var result: TaskResult?
            var attempts = 0
            do {
                delay(50)
                result = messageQueue.getResult(taskId)
                attempts++
            } while (result?.status == TaskStatus.PENDING || result?.status == TaskStatus.RUNNING && attempts < 50)

            assertNotNull(result)
            assertEquals(TaskStatus.FAILED, result!!.status)
            assertEquals("Task failed intentionally", result!!.error)
        }
    }

    @Test
    fun `getResult should return null for unknown task`() {
        val result = messageQueue.getResult("nonexistent")
        assertNull(result)
    }

    @Test
    fun `cancelTask should cancel running task`() {
        val taskId = messageQueue.submit("test") {
            delay(5000)
            "should not complete"
        }

        val cancelled = messageQueue.cancelTask(taskId)
        assertTrue(cancelled)

        runBlocking {
            delay(200)
            val result = messageQueue.getResult(taskId)
            assertNotNull(result)
            assertEquals(TaskStatus.CANCELLED, result!!.status)
        }
    }

    @Test
    fun `cancelTask should return false for unknown task`() {
        assertFalse(messageQueue.cancelTask("nonexistent"))
    }

    @Test
    fun `cleanup should remove old completed tasks`() {
        val taskId = messageQueue.submit("test") { "quick result" }

        runBlocking {
            delay(200)
            messageQueue.cleanup(maxAgeMs = 0)
            val result = messageQueue.getResult(taskId)
            assertNull(result)
        }
    }

    @Test
    fun `cleanup should remove old failed and cancelled tasks`() {
        val failedTaskId = messageQueue.submit("test") { throw RuntimeException("boom") }
        val cancelledTaskId = messageQueue.submit("test") {
            delay(5000)
            "should not complete"
        }

        assertTrue(messageQueue.cancelTask(cancelledTaskId))

        runBlocking {
            delay(200)
            assertEquals(TaskStatus.FAILED, messageQueue.getResult(failedTaskId)?.status)
            assertEquals(TaskStatus.CANCELLED, messageQueue.getResult(cancelledTaskId)?.status)

            messageQueue.cleanup(maxAgeMs = 0)

            assertNull(messageQueue.getResult(failedTaskId))
            assertNull(messageQueue.getResult(cancelledTaskId))
        }
    }

    @Test
    fun `cleanup should not remove pending or running tasks`() {
        val runningTaskId = messageQueue.submit("test") {
            delay(5000)
            "should not complete"
        }

        runBlocking {
            delay(100)
            messageQueue.cleanup(maxAgeMs = 0)

            val result = messageQueue.getResult(runningTaskId)
            assertNotNull(result)
            assertEquals(TaskStatus.RUNNING, result!!.status)
        }
    }

    @Test
    fun `periodic cleanup should remove expired completed results`() {
        messageQueue.shutdown()
        messageQueue = MessageQueue(resultTtlMs = 0, cleanupIntervalMs = 50)

        val taskId = messageQueue.submit("test") { "quick result" }

        runBlocking {
            delay(300)
            assertNull(messageQueue.getResult(taskId))
        }
    }

    @Test
    fun `shutdown should stop cleanup job and cancel active tasks`() {
        messageQueue.shutdown()
        messageQueue = MessageQueue(resultTtlMs = 0, cleanupIntervalMs = 50)
        val taskCancelled = CompletableDeferred<Boolean>()

        messageQueue.submit("test") {
            try {
                delay(5000)
                "should not complete"
            } finally {
                taskCancelled.complete(true)
            }
        }

        runBlocking {
            delay(100)
            messageQueue.shutdown()

            assertTrue(taskCancelled.await())
        }
    }

    @Test
    fun `clear should remove all tasks`() {
        messageQueue.submit("test") { "result 1" }
        messageQueue.submit("test") { "result 2" }

        messageQueue.clear()

        runBlocking {
            delay(200)
            assertEquals(0, messageQueue.stats.submitted) // stats reset
        }
    }

    @Test
    fun `stats should track queue metrics`() {
        messageQueue.submit("test") { "result 1" }
        messageQueue.submit("test") { "result 2" }

        runBlocking {
            delay(200)
            val stats = messageQueue.stats
            assertEquals(2, stats.completed)
            assertEquals(0, stats.failed)
        }
    }

    @Test
    fun `stats should track failures`() {
        messageQueue.submit("test") { throw RuntimeException("fail") }

        runBlocking {
            delay(200)
            val stats = messageQueue.stats
            assertEquals(1, stats.failed)
        }
    }

    @Test
    fun `concurrent submissions should not interfere`() {
        val taskIds = (1..10).map {
            messageQueue.submit("test") {
                delay(10)
                "result-$it"
            }
        }

        assertEquals(10, taskIds.distinct().size)

        runBlocking {
            delay(500)
            val completed = taskIds.mapNotNull { messageQueue.getResult(it) }
                .filter { it.status == TaskStatus.COMPLETED }
            assertEquals(10, completed.size)
        }
    }
}
