package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class McpConfigTest {

    private lateinit var persistedObject: PersistedObject
    private lateinit var config: McpConfig
    private lateinit var mockLogging: Logging

    @BeforeEach
    fun setup() {
        val storage = mutableMapOf<String, Any>()

        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers {
                val key = firstArg<String>()
                storage[key] as? Boolean ?: when (key) {
                    "enabled" -> true
                    "requireHttpRequestApproval" -> false
                    "keepaliveEnabled" -> true
                    "strictLocalhostMode" -> true
                    "filterBrowserNoise" -> true
                    else -> false
                }
            }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers {
                val key = firstArg<String>()
                storage[key] as? Int ?: when (key) {
                    "keepaliveIntervalSec" -> 30
                    "maxResponseSizeKb" -> 100
                    "maxRawDuplicatesPerCanonical" -> 10
                    "maxRawDuplicateBodySize" -> 8192
                    else -> 0
                }
            }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }

        mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
    }

    @Test
    fun `addAutoApproveTarget should add new target`() {
        val result = config.addAutoApproveTarget("example.com")

        assertTrue(result)
        assertEquals("example.com", config.autoApproveTargets)
        verify { persistedObject.setString("_autoApproveTargets", "example.com") }
    }

    @Test
    fun `addAutoApproveTarget should not add duplicate target`() {
        config.addAutoApproveTarget("example.com")
        val result = config.addAutoApproveTarget("example.com")

        assertFalse(result)
        assertEquals("example.com", config.autoApproveTargets)
    }

    @Test
    fun `addAutoApproveTarget should trim whitespace`() {
        val result = config.addAutoApproveTarget("  example.com  ")

        assertTrue(result)
        assertEquals("example.com", config.autoApproveTargets)
    }

    @Test
    fun `addAutoApproveTarget should not add empty target`() {
        val result = config.addAutoApproveTarget("   ")

        assertFalse(result)
        assertEquals("", config.autoApproveTargets)
    }

    @Test
    fun `addAutoApproveTarget should handle multiple targets`() {
        config.addAutoApproveTarget("example.com")
        config.addAutoApproveTarget("test.org")

        assertEquals("example.com\ntest.org", config.autoApproveTargets)
        assertEquals(listOf("example.com", "test.org"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `addAutoApproveTarget should reject comma-injected multi-host string`() {
        val poisoned = "example.com,127.0.0.1,*.attacker.com,169.254.169.254"

        val result = config.addAutoApproveTarget(poisoned)

        assertFalse(result)
        assertEquals("", config.autoApproveTargets)
        assertEquals(emptyList<String>(), config.getAutoApproveTargetsList())
    }

    @Test
    fun `addAutoApproveTarget should reject targets containing whitespace`() {
        assertFalse(config.addAutoApproveTarget("evil.com 127.0.0.1"))
        assertFalse(config.addAutoApproveTarget("evil.com\t127.0.0.1"))
        assertFalse(config.addAutoApproveTarget("evil.com\n127.0.0.1"))
        assertEquals("", config.autoApproveTargets)
    }

    @Test
    fun `removeAutoApproveTarget should remove existing target`() {
        config.addAutoApproveTarget("example.com")
        config.addAutoApproveTarget("test.org")

        val result = config.removeAutoApproveTarget("example.com")

        assertTrue(result)
        assertEquals("test.org", config.autoApproveTargets)
        assertEquals(listOf("test.org"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `removeAutoApproveTarget should return false for non-existing target`() {
        config.addAutoApproveTarget("example.com")

        val result = config.removeAutoApproveTarget("notfound.com")

        assertFalse(result)
        assertEquals("example.com", config.autoApproveTargets)
    }

    @Test
    fun `clearAutoApproveTargets should remove all targets`() {
        config.addAutoApproveTarget("example.com")
        config.addAutoApproveTarget("test.org")

        config.clearAutoApproveTargets()

        assertEquals("", config.autoApproveTargets)
        assertEquals(emptyList<String>(), config.getAutoApproveTargetsList())
    }

    @Test
    fun `getAutoApproveTargetsList should handle empty config`() {
        assertEquals(emptyList<String>(), config.getAutoApproveTargetsList())
    }

    @Test
    fun `getAutoApproveTargetsList should parse newline-separated values`() {
        val storage = mutableMapOf<String, Any>("_autoApproveTargets" to "example.com\ntest.org\n*.api.com")
        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }
        config = McpConfig(persistedObject, mockLogging)

        assertEquals(
            listOf("example.com", "test.org", "*.api.com"), config.getAutoApproveTargetsList()
        )
    }

    @Test
    fun `getAutoApproveTargetsList should handle malformed input`() {
        val storage = mutableMapOf<String, Any>("_autoApproveTargets" to "example.com\n\n  \ntest.org")
        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }
        config = McpConfig(persistedObject, mockLogging)

        assertEquals(
            listOf("example.com", "test.org"), config.getAutoApproveTargetsList()
        )
    }

    @Test
    fun `invalid entries are removed from auto-approve list on startup`() {
        val storage = mutableMapOf<String, Any>("_autoApproveTargets" to "example.com\ninvalid,entry\ntest.org\nbad entry")
        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers { storage[firstArg()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { storage[firstArg()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { storage[firstArg()] = secondArg<Int>() }
        }
        config = McpConfig(persistedObject, mockLogging)

        assertEquals(listOf("example.com", "test.org"), config.getAutoApproveTargetsList())
    }

    @Test
    fun `targets change listener should be notified`() {
        var notificationCount = 0
        val listener = {
            notificationCount++
            Unit
        }

        config.addTargetsChangeListener(listener)
        config.addAutoApproveTarget("example.com")

        assertEquals(1, notificationCount)
    }

    @Test
    fun `targets change listener should handle exceptions`() {
        val badListener = { throw RuntimeException("Test exception") }
        val goodListener = { /* do nothing */ }

        config.addTargetsChangeListener(badListener)
        config.addTargetsChangeListener(goodListener)

        assertDoesNotThrow {
            config.addAutoApproveTarget("example.com")
        }
    }

    @Test
    fun `autoApproveTargets setter should only notify on actual changes`() {
        var notificationCount = 0
        val listener = {
            notificationCount++
            Unit
        }

        config.addTargetsChangeListener(listener)

        config.autoApproveTargets = "example.com"
        assertEquals(1, notificationCount)

        config.autoApproveTargets = "example.com"
        assertEquals(1, notificationCount)

        config.autoApproveTargets = "test.org"
        assertEquals(2, notificationCount)
    }

    @Test
    fun `configEditingTooling should persist correctly`() {
        assertFalse(config.configEditingTooling)

        config.configEditingTooling = true
        assertTrue(config.configEditingTooling)
        verify { persistedObject.setBoolean("configEditingTooling", true) }

        config.configEditingTooling = false
        assertFalse(config.configEditingTooling)
        verify { persistedObject.setBoolean("configEditingTooling", false) }
    }

    @Test
    fun `requireHttpRequestApproval should persist correctly`() {
        assertFalse(config.requireHttpRequestApproval)

        config.requireHttpRequestApproval = false
        assertFalse(config.requireHttpRequestApproval)
        verify { persistedObject.setBoolean("requireHttpRequestApproval", false) }

        config.requireHttpRequestApproval = true
        assertTrue(config.requireHttpRequestApproval)
        verify { persistedObject.setBoolean("requireHttpRequestApproval", true) }
    }

    @Test
    fun `requireHistoryAccessApproval should default to false when unset`() {
        val storage = mutableMapOf<String, Any>()
        val unsetStorage = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg()] as? String }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int }
            every { setBoolean(any(), any()) } answers { storage[firstArg()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { storage[firstArg()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { storage[firstArg()] = secondArg<Int>() }
        }

        val unsetConfig = McpConfig(unsetStorage, mockLogging)

        assertFalse(unsetConfig.requireHistoryAccessApproval)
    }

    @Test
    fun `requireHistoryAccessApproval should preserve persisted true`() {
        val storage = mutableMapOf<String, Any>("requireHistoryAccessApproval" to true)
        val persistedTrueStorage = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg()] as? String }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int }
            every { setBoolean(any(), any()) } answers { storage[firstArg()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { storage[firstArg()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { storage[firstArg()] = secondArg<Int>() }
        }

        val persistedTrueConfig = McpConfig(persistedTrueStorage, mockLogging)

        assertTrue(persistedTrueConfig.requireHistoryAccessApproval)
    }

    @Test
    fun `keepaliveEnabled should default to true`() {
        assertTrue(config.keepaliveEnabled)
    }

    @Test
    fun `keepaliveEnabled should persist correctly`() {
        config.keepaliveEnabled = false
        assertFalse(config.keepaliveEnabled)
        verify { persistedObject.setBoolean("keepaliveEnabled", false) }

        config.keepaliveEnabled = true
        assertTrue(config.keepaliveEnabled)
        verify { persistedObject.setBoolean("keepaliveEnabled", true) }
    }

    @Test
    fun `keepaliveIntervalSec should default to 30`() {
        assertEquals(30, config.keepaliveIntervalSec)
    }

    @Test
    fun `keepaliveIntervalSec should persist correctly`() {
        config.keepaliveIntervalSec = 60
        assertEquals(60, config.keepaliveIntervalSec)
        verify { persistedObject.setInteger("keepaliveIntervalSec", 60) }

        config.keepaliveIntervalSec = 15
        assertEquals(15, config.keepaliveIntervalSec)
        verify { persistedObject.setInteger("keepaliveIntervalSec", 15) }
    }

    @Test
    fun `maxResponseSizeKb should default to 100`() {
        assertEquals(100, config.maxResponseSizeKb)
    }

    @Test
    fun `maxResponseSizeKb should persist correctly`() {
        config.maxResponseSizeKb = 500
        assertEquals(500, config.maxResponseSizeKb)
        verify { persistedObject.setInteger("maxResponseSizeKb", 500) }

        config.maxResponseSizeKb = 50
        assertEquals(50, config.maxResponseSizeKb)
        verify { persistedObject.setInteger("maxResponseSizeKb", 50) }
    }

    @Test
    fun `strictLocalhostMode should default to true`() {
        assertTrue(config.strictLocalhostMode)
    }

    @Test
    fun `strictLocalhostMode should persist correctly`() {
        config.strictLocalhostMode = false
        assertFalse(config.strictLocalhostMode)
        verify { persistedObject.setBoolean("strictLocalhostMode", false) }

        config.strictLocalhostMode = true
        assertTrue(config.strictLocalhostMode)
        verify { persistedObject.setBoolean("strictLocalhostMode", true) }
    }

    @Test
    fun `export filter flags should default and persist correctly`() {
        assertFalse(config.exportInScopeOnly)
        assertTrue(config.filterBrowserNoise)
        assertEquals("balanced", config.exportNoiseMode)

        config.exportInScopeOnly = true
        config.filterBrowserNoise = false

        assertTrue(config.exportInScopeOnly)
        assertFalse(config.filterBrowserNoise)
        verify { persistedObject.setBoolean("exportInScopeOnly", true) }
        verify { persistedObject.setBoolean("filterBrowserNoise", false) }
    }

    @Test
    fun `raw duplicate settings should default off and coerce persisted limits`() {
        assertFalse(config.saveRawDuplicates)
        assertEquals(10, config.maxRawDuplicatesPerCanonical)
        assertEquals(8192, config.maxRawDuplicateBodySize)

        config.saveRawDuplicates = true
        config.maxRawDuplicatesPerCanonical = -1
        config.maxRawDuplicateBodySize = 100_000

        assertTrue(config.saveRawDuplicates)
        assertEquals(0, config.maxRawDuplicatesPerCanonical)
        assertEquals(65_536, config.maxRawDuplicateBodySize)
        verify { persistedObject.setInteger("maxRawDuplicatesPerCanonical", 0) }
        verify { persistedObject.setInteger("maxRawDuplicateBodySize", 65_536) }
    }

    @Test
    fun `exportNoiseMode should normalize and persist correctly`() {
        config.exportNoiseMode = "STRICT"

        assertEquals("strict", config.exportNoiseMode)
        assertTrue(config.filterBrowserNoise)
        verify { persistedObject.setString("_exportNoiseMode", "strict") }

        config.exportNoiseMode = "off"
        assertEquals("off", config.exportNoiseMode)
        assertFalse(config.filterBrowserNoise)
        verify { persistedObject.setString("_exportNoiseMode", "off") }
    }

    @Test
    fun `history access change listener should be notified`() {
        var notificationCount = 0
        val listener = { notificationCount++; Unit }

        config.addHistoryAccessChangeListener(listener)

        config.alwaysAllowHttpHistory = true
        assertEquals(1, notificationCount)

        config.alwaysAllowWebSocketHistory = true
        assertEquals(2, notificationCount)
    }
}
