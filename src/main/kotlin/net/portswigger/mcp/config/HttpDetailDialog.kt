package net.portswigger.mcp.config

import net.portswigger.mcp.db.ProxyHttpEntry
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import javax.swing.*

class HttpDetailDialog(
    parent: Component?,
    private val entry: ProxyHttpEntry
) : JDialog(SwingUtilities.getWindowAncestor(parent), ModalityType.APPLICATION_MODAL) {

    private data class EntryView(
        val requestHeaders: String?,
        val requestBody: String?,
        val responseHeaders: String?,
        val responseBody: String?,
        val label: String
    )

    private val allViews: List<EntryView> = run {
        val list = mutableListOf<EntryView>()
        list.add(EntryView(entry.requestHeaders, entry.requestBody, entry.responseHeaders, entry.responseBody, "规范"))
        entry.duplicates.forEachIndexed { i, dup ->
            list.add(EntryView(dup.requestHeaders, dup.requestBody, dup.responseHeaders, dup.responseBody, "副本 ${i + 1}"))
        }
        list
    }
    private var currentIndex = 0

    private lateinit var reqHeadersArea: JTextArea
    private lateinit var reqBodyArea: JTextArea
    private lateinit var respHeadersArea: JTextArea
    private lateinit var respBodyArea: JTextArea
    private lateinit var navLabel: JLabel
    private lateinit var prevButton: JButton
    private lateinit var nextButton: JButton

    init {
        title = "${entry.method} ${entry.url} — ${entry.status ?: "?"}"
        defaultCloseOperation = DISPOSE_ON_CLOSE
        preferredSize = Dimension(880, 650)
        layout = BorderLayout()

        add(buildTabs(), BorderLayout.CENTER)
        add(buildFooter(), BorderLayout.SOUTH)

        rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
            .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "escape")
        rootPane.actionMap.put("escape", object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) = dispose()
        })

        navigateTo(0)
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
        reqHeadersArea = buildTextArea("")
        reqBodyArea = buildTextArea("")
        return buildSplitPane(wrapScroll(reqHeadersArea), wrapScroll(reqBodyArea))
    }

    private fun buildResponseTab(): JComponent {
        respHeadersArea = buildTextArea("")
        respBodyArea = buildTextArea("")
        return buildSplitPane(wrapScroll(respHeadersArea), wrapScroll(respBodyArea))
    }

    private fun buildSplitPane(top: JComponent, bottom: JComponent): JSplitPane {
        return JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom).apply {
            dividerLocation = 200
            resizeWeight = 0.35
        }
    }

    private fun buildTextArea(text: String): JTextArea {
        return JTextArea(text).apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 14)
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
        navLabel = JLabel("")
        prevButton = Design.createOutlinedButton("◀ 上一条").apply {
            addActionListener { navigateTo(currentIndex - 1) }
        }
        nextButton = Design.createFilledButton("下一条 ▶").apply {
            addActionListener { navigateTo(currentIndex + 1) }
        }

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

            if (allViews.size > 1) {
                add(prevButton)
                add(Box.createHorizontalStrut(8))
                add(navLabel.apply {
                    font = Design.Typography.bodyMedium
                    foreground = Design.Colors.onSurfaceVariant
                })
                add(Box.createHorizontalStrut(8))
                add(nextButton)
            }

            add(Box.createHorizontalGlue())
            add(Design.createFilledButton("关闭").apply {
                addActionListener { dispose() }
            })
        }
    }

    private fun navigateTo(index: Int) {
        if (index < 0 || index >= allViews.size) return
        currentIndex = index
        val v = allViews[index]

        if (::reqHeadersArea.isInitialized) {
            reqHeadersArea.text = v.requestHeaders ?: "（无请求头）"
            reqHeadersArea.caretPosition = 0
            reqBodyArea.text = if (v.requestBody.isNullOrBlank()) "（无请求体）" else formatBody(v.requestBody)
            reqBodyArea.caretPosition = 0
            respHeadersArea.text = v.responseHeaders ?: "（无响应头）"
            respHeadersArea.caretPosition = 0
            respBodyArea.text = if (v.responseBody.isNullOrBlank()) "（无响应体）" else formatBody(v.responseBody)
            respBodyArea.caretPosition = 0
        }

        if (allViews.size > 1 && ::navLabel.isInitialized) {
            navLabel.text = "${v.label}  (${index + 1} / ${allViews.size})"
            prevButton.isEnabled = index > 0
            nextButton.isEnabled = index < allViews.size - 1
        }
    }

    private fun formatBody(text: String?): String {
        if (text == null) return ""
        val trimmed = text.trim()
        return when {
            trimmed.startsWith("{") || trimmed.startsWith("[") ->
                try { prettyPrintJson(trimmed) } catch (e: Exception) { text }
            trimmed.startsWith("<") ->
                try { prettyPrintXml(trimmed) } catch (e: Exception) { text }
            else -> text
        }
    }

    private fun prettyPrintJson(json: String): String {
        val sb = StringBuilder()
        var indent = 0
        var inString = false
        var escape = false
        for (ch in json) {
            if (escape) { sb.append(ch); escape = false; continue }
            if (ch == '\\' && inString) { sb.append(ch); escape = true; continue }
            if (ch == '"') { inString = !inString; sb.append(ch); continue }
            if (inString) { sb.append(ch); continue }
            when (ch) {
                '{', '[' -> { sb.append(ch); sb.append('\n'); indent++; repeat(indent * 2) { sb.append(' ') } }
                '}', ']' -> { sb.append('\n'); indent--; repeat(indent * 2) { sb.append(' ') }; sb.append(ch) }
                ',' -> { sb.append(ch); sb.append('\n'); repeat(indent * 2) { sb.append(' ') } }
                ':' -> sb.append(": ")
                ' ', '\n', '\r', '\t' -> {}
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }

    private fun prettyPrintXml(xml: String): String {
        return try {
            val factory = javax.xml.transform.TransformerFactory.newInstance()
            val transformer = factory.newTransformer().apply {
                setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes")
                setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes")
                setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
            }
            val result = javax.xml.transform.stream.StreamResult(java.io.StringWriter())
            transformer.transform(
                javax.xml.transform.stream.StreamSource(java.io.StringReader(xml)),
                result
            )
            result.writer.toString().trim()
        } catch (e: Exception) {
            xml
        }
    }
}
