package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities
import javax.swing.Timer

class HttpHistoryPanelTest {

    @Test
    fun `startRefreshing uses low frequency automatic refresh`() {
        val panel = HttpHistoryPanel()
        try {
            SwingUtilities.invokeAndWait {
                panel.startRefreshing()
            }

            val timer = panel.privateTimer("refreshTimer")
            assertEquals(HttpHistoryPanel.AUTO_REFRESH_INTERVAL_MS, timer.delay)
            assertEquals(15_000, timer.delay)
        } finally {
            SwingUtilities.invokeAndWait {
                panel.stopRefreshing()
            }
        }
    }

    @Test
    fun `search debounce remains responsive`() {
        val panel = HttpHistoryPanel()
        try {
            SwingUtilities.invokeAndWait {
                panel.privateTextField("searchField").text = "api"
            }

            val timer = panel.privateTimer("searchTimer")
            assertEquals(HttpHistoryPanel.SEARCH_DEBOUNCE_MS, timer.delay)
            assertEquals(300, timer.delay)
            assertEquals(false, timer.isRepeats)
        } finally {
            SwingUtilities.invokeAndWait {
                panel.stopRefreshing()
            }
        }
    }

    private fun HttpHistoryPanel.privateTimer(name: String): Timer {
        val ref = AtomicReference<Timer>()
        SwingUtilities.invokeAndWait {
            val field = HttpHistoryPanel::class.java.getDeclaredField(name)
            field.isAccessible = true
            ref.set(field.get(this) as Timer)
        }
        return ref.get()
    }

    private fun HttpHistoryPanel.privateTextField(name: String): javax.swing.JTextField {
        val field = HttpHistoryPanel::class.java.getDeclaredField(name)
        field.isAccessible = true
        return field.get(this) as javax.swing.JTextField
    }
}
