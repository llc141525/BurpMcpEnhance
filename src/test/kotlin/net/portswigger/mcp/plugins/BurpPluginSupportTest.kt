package net.portswigger.mcp.plugins

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Version
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.db.DbStats
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BurpPluginSupportTest {

    @Test
    fun `burp info summary reports plugin impact diagnostics without claiming causality`() {
        val api = mockk<MontoyaApi>()
        val burpSuite = mockk<BurpSuite>()
        val version = mockk<Version>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
        every { version.toString() } returns "Burp Suite Professional 2026.7"

        val inventory = BurpPluginInventory(
            detectedPlugins = listOf("Bypass WAF", "Active Scan++"),
            knownPlugins = KNOWN_BURP_PLUGINS,
            configuredPlugins = listOf("FastjsonScan", "Custom Helper"),
            detectionSource = "user_options"
        )
        val diagnostics = BurpPluginImpactDiagnostics(
            dbStats = DbStats(proxyHttpCount = 100_000, scannerIssueCount = 25),
            exporterLastCycleDurationMs = 1_234,
            exporterHistorySeen = 100_500,
            exporterNewEntriesSeen = 500
        )

        val text = buildBurpInfoSummary(api, inventory, diagnostics)

        assertTrue(text.contains("Detected plugins: 2"), text)
        assertTrue(text.contains("Configured plugins: 2"), text)
        assertTrue(text.contains("Effective plugins: 4"), text)
        assertTrue(text.contains("Request-handler plugins currently known/configured: 1"), text)
        assertTrue(text.contains("Scanner/discovery plugins currently known/configured: 2"), text)
        assertTrue(text.contains("MCP cache HTTP history rows: 100000"), text)
        assertTrue(text.contains("MCP cache scanner issue rows: 25"), text)
        assertTrue(text.contains("Last Exporter cycle duration: 1234ms"), text)
        assertTrue(text.contains("History growth last cycle: seen=100500 new=500"), text)
        assertTrue(text.contains("MCP base cache and HTTP tools do not depend on third-party plugins."), text)
        assertTrue(text.contains("A/B test"), text)
        assertTrue(text.contains("same traffic"), text)
        assertTrue(text.contains("CPU, heap memory, history growth rate, and Exporter cycle duration"), text)
        assertTrue(text.contains("may participate in active scanning"), text)
        assertFalse(text.contains("must be disabled"), text)
        assertFalse(text.contains("definitely causes"), text)
    }
}
