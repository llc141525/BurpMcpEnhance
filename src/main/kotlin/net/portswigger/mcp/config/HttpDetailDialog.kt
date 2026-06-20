package net.portswigger.mcp.config

import net.portswigger.mcp.db.ProxyHttpEntry
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import javax.swing.*

class HttpDetailDialog(
    parent: Component?,
    private val entry: ProxyHttpEntry
) : JDialog(SwingUtilities.getWindowAncestor(parent), ModalityType.APPLICATION_MODAL) {

    init {
        title = "${entry.method} ${entry.url} — ${entry.status ?: "?"}"
        defaultCloseOperation = DISPOSE_ON_CLOSE
        preferredSize = Dimension(800, 600)
        layout = BorderLayout()

        add(buildTabs(), BorderLayout.CENTER)
        add(buildFooter(), BorderLayout.SOUTH)

        pack()
        setLocationRelativeTo(parent)
    }

    private fun buildTabs(): JTabbedPane {
        val tabs = JTabbedPane()
        tabs.addTab("请求", buildRequestTab())
        tabs.addTab("响应", buildResponseTab())
        return tabs
    }

    private fun buildRequestTab(): JComponent {
        return buildSplitPane(
            top = buildTextArea(entry.requestHeaders ?: "（无请求头）"),
            bottom = buildTextArea(entry.requestBody ?: "（无请求体）")
        )
    }

    private fun buildResponseTab(): JComponent {
        return buildSplitPane(
            top = buildTextArea(entry.responseHeaders ?: "（无响应头）"),
            bottom = buildTextArea(entry.responseBody ?: "（无响应体）")
        )
    }

    private fun buildSplitPane(top: JComponent, bottom: JComponent): JSplitPane {
        return JSplitPane(JSplitPane.VERTICAL_SPLIT, wrapScroll(top), wrapScroll(bottom)).apply {
            dividerLocation = 180
            resizeWeight = 0.3
        }
    }

    private fun buildTextArea(text: String): JTextArea {
        return JTextArea(text).apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            lineWrap = false
            wrapStyleWord = false
            background = Design.Colors.surface
            foreground = Design.Colors.onSurface
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        }
    }

    private fun wrapScroll(component: JComponent): JScrollPane {
        return JScrollPane(component).apply {
            border = null
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        }
    }

    private fun buildFooter(): JPanel {
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
            add(Box.createHorizontalGlue())
            add(Design.createFilledButton("关闭").apply {
                addActionListener { dispose() }
            })
        }
    }
}
