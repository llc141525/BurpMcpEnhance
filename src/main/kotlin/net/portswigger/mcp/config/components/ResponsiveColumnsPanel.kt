package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane

class ResponsiveColumnsPanel(private val leftPanel: JPanel, private val rightPanel: JScrollPane) : JPanel() {
    private val minWidthForTwoColumns = 960
    private val minWidthForLargePadding = 700
    private var lastLayout = Layout.SINGLE_COLUMN
    private var lastPaddingSize = PaddingSize.SMALL
    private var isInitialized = false

    enum class Layout { SINGLE_COLUMN, TWO_COLUMNS }
    enum class PaddingSize { SMALL, LARGE }

    init {
        isInitialized = true
        updateLayout()
    }

    override fun updateUI() {
        super.updateUI()
        if (isInitialized) {
            updateLayout() // Reapply layout with updated theme colors
        }
    }

    override fun doLayout() {
        super.doLayout()
        val currentLayout = if (width >= minWidthForTwoColumns) Layout.TWO_COLUMNS else Layout.SINGLE_COLUMN
        val currentPaddingSize = if (width >= minWidthForLargePadding) PaddingSize.LARGE else PaddingSize.SMALL

        if (currentLayout != lastLayout || currentPaddingSize != lastPaddingSize) {
            lastLayout = currentLayout
            lastPaddingSize = currentPaddingSize
            updateLayout()
        }
    }

    private fun updateLayout() {
        removeAll()

        val padding = when (lastPaddingSize) {
            PaddingSize.LARGE -> Design.Spacing.LG
            PaddingSize.SMALL -> Design.Spacing.SM
        }

        if (rightPanel.viewport.view is JPanel) {
            val contentPanel = rightPanel.viewport.view as JPanel
            contentPanel.border = BorderFactory.createEmptyBorder(padding, padding, padding, padding)
        }

        when (lastLayout) {
            Layout.TWO_COLUMNS -> {
                layout = BorderLayout()

                val leftScroll = JScrollPane(leftPanel).apply {
                    border = BorderFactory.createEmptyBorder(padding, padding, padding, Design.Spacing.SM)
                    viewport.background = Design.Colors.surface
                    background = Design.Colors.surface
                    horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
                    verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                    minimumSize = Dimension(300, 0)
                    preferredSize = Dimension(530, 0)
                    verticalScrollBar.unitIncrement = 16
                }

                rightPanel.border = BorderFactory.createEmptyBorder(padding, Design.Spacing.SM, padding, padding)

                add(JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightPanel).apply {
                    resizeWeight = 0.43
                    dividerSize = 8
                    border = null
                    isContinuousLayout = true
                    setDividerLocation(530)
                }, BorderLayout.CENTER)
            }

            Layout.SINGLE_COLUMN -> {
                layout = BorderLayout()
                val singleColumnPanel = JPanel().apply {
                    layout = BoxLayout(this, BoxLayout.Y_AXIS)
                    background = Design.Colors.surface
                }

                val headerWrapper = JPanel(BorderLayout()).apply {
                    isOpaque = false
                    border = BorderFactory.createEmptyBorder(padding, padding, Design.Spacing.MD, padding)
                    add(leftPanel, BorderLayout.CENTER)
                }

                singleColumnPanel.add(headerWrapper)

                val scrollWrapper = JPanel(BorderLayout()).apply {
                    isOpaque = false
                    add(rightPanel, BorderLayout.CENTER)
                }
                singleColumnPanel.add(scrollWrapper)

                add(singleColumnPanel, BorderLayout.CENTER)
            }
        }

        revalidate()
        repaint()
    }
}
