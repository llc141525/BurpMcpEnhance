package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import java.lang.ref.WeakReference
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

private const val TARGET_SEPARATOR = "\n"
private const val PLUGIN_SEPARATOR = "\n"
const val EXPORT_NOISE_MODE_OFF = "off"
const val EXPORT_NOISE_MODE_RELAXED = "relaxed"
const val EXPORT_NOISE_MODE_BALANCED = "balanced"
const val EXPORT_NOISE_MODE_STRICT = "strict"
private val VALID_EXPORT_NOISE_MODES = setOf(
    EXPORT_NOISE_MODE_OFF,
    EXPORT_NOISE_MODE_RELAXED,
    EXPORT_NOISE_MODE_BALANCED,
    EXPORT_NOISE_MODE_STRICT
)

fun normalizeExportNoiseMode(value: String?): String {
    val normalized = value?.trim()?.lowercase().orEmpty()
    return if (normalized in VALID_EXPORT_NOISE_MODES) normalized else EXPORT_NOISE_MODE_BALANCED
}

class McpConfig(storage: PersistedObject, private val logging: Logging) {

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(true)
    var requireHistoryAccessApproval by storage.boolean(true)
    var keepaliveEnabled by storage.boolean(true)
    var keepaliveIntervalSec by storage.int(30)
    var maxResponseSizeKb by storage.int(100)
    var strictLocalhostMode by storage.boolean(true)
    var exportInScopeOnly by storage.boolean(false)
    var filterBrowserNoise by storage.boolean(true)
    private var _exportNoiseMode by storage.string("")
    private var _knownBurpPlugins by storage.stringList("")
    var saveRawDuplicates by storage.boolean(true)
    var maxRawDuplicatesPerCanonical by storage.int(10)

    var exportNoiseMode: String
        get() {
            val configured = _exportNoiseMode.trim()
            if (configured.isNotEmpty()) return normalizeExportNoiseMode(configured)
            return if (filterBrowserNoise) EXPORT_NOISE_MODE_BALANCED else EXPORT_NOISE_MODE_OFF
        }
        set(value) {
            val normalized = normalizeExportNoiseMode(value)
            _exportNoiseMode = normalized
            filterBrowserNoise = normalized != EXPORT_NOISE_MODE_OFF
        }

    private var _alwaysAllowHttpHistory by storage.boolean(false)
    var alwaysAllowHttpHistory: Boolean
        get() = _alwaysAllowHttpHistory
        set(value) {
            if (_alwaysAllowHttpHistory != value) {
                _alwaysAllowHttpHistory = value
                notifyHistoryAccessChanged()
            }
        }

    private var _alwaysAllowWebSocketHistory by storage.boolean(false)
    var alwaysAllowWebSocketHistory: Boolean
        get() = _alwaysAllowWebSocketHistory
        set(value) {
            if (_alwaysAllowWebSocketHistory != value) {
                _alwaysAllowWebSocketHistory = value
                notifyHistoryAccessChanged()
            }
        }

    private var _autoApproveTargets by storage.stringList("")
    private val targetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val historyAccessChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            if (_autoApproveTargets != value) {
                _autoApproveTargets = value
                notifyTargetsChanged()
            }
        }

    var knownBurpPlugins: String
        get() = _knownBurpPlugins
        set(value) {
            _knownBurpPlugins = value
        }

    init {
        val current = getAutoApproveTargetsList()
        val valid = current.filter { TargetValidation.isValidTarget(it) }
        if (valid.size != current.size) {
            _autoApproveTargets = valid.joinToString(TARGET_SEPARATOR)
        }
        if (_exportNoiseMode.isNotBlank()) {
            val normalizedMode = normalizeExportNoiseMode(_exportNoiseMode)
            if (normalizedMode != _exportNoiseMode) {
                _exportNoiseMode = normalizedMode
            }
        }
    }

    fun addAutoApproveTarget(target: String): Boolean {
        val trimmed = target.trim()
        if (!TargetValidation.isValidTarget(trimmed)) return false
        val currentTargets = getAutoApproveTargetsList()
        if (currentTargets.contains(trimmed)) return false
        val newTargets = currentTargets + trimmed
        autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
        return true
    }

    fun removeAutoApproveTarget(target: String): Boolean {
        val currentTargets = getAutoApproveTargetsList()
        val newTargets = currentTargets.filter { it != target.trim() }
        if (newTargets.size != currentTargets.size) {
            autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
            return true
        }
        return false
    }

    fun getAutoApproveTargetsList(): List<String> {
        return if (_autoApproveTargets.isBlank()) {
            emptyList()
        } else {
            _autoApproveTargets.split(TARGET_SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }
        }
    }

    fun clearAutoApproveTargets() {
        autoApproveTargets = ""
    }

    fun getKnownBurpPluginsList(): List<String> {
        return if (_knownBurpPlugins.isBlank()) {
            emptyList()
        } else {
            _knownBurpPlugins.split(PLUGIN_SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        }
    }

    fun setKnownBurpPlugins(plugins: List<String>) {
        knownBurpPlugins = plugins.map { it.trim() }.filter { it.isNotEmpty() }.distinct().joinToString(PLUGIN_SEPARATOR)
    }

    fun exportNoiseModeDescription(): String {
        return when (exportNoiseMode) {
            EXPORT_NOISE_MODE_OFF -> "Do not filter browser noise."
            EXPORT_NOISE_MODE_RELAXED -> "Filter static assets like JS, CSS, images, fonts, and media."
            EXPORT_NOISE_MODE_BALANCED -> "Also filter CORS preflight, favicon, manifest, robots, and service-worker traffic."
            EXPORT_NOISE_MODE_STRICT -> "Also filter frontend hot-reload and browser prefetch/prerender traffic."
            else -> "Unknown"
        }
    }

    fun addTargetsChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        targetsChangeListeners.add(registration)
        return ListenerHandle { removeTargetsChangeListener(registration) }
    }

    private fun removeTargetsChangeListener(registration: ListenerRegistration) {
        targetsChangeListeners.remove(registration)
    }

    private fun notifyTargetsChanged() {
        cleanupStaleListeners(targetsChangeListeners)
        val listeners = targetsChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Targets change listener failed: ${e.message}")
            }
        }
    }

    fun addHistoryAccessChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        historyAccessChangeListeners.add(registration)
        return ListenerHandle { removeHistoryAccessChangeListener(registration) }
    }

    private fun removeHistoryAccessChangeListener(registration: ListenerRegistration) {
        historyAccessChangeListeners.remove(registration)
    }

    private fun notifyHistoryAccessChanged() {
        cleanupStaleListeners(historyAccessChangeListeners)
        val listeners = historyAccessChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("History access change listener failed: ${e.message}")
            }
        }
    }

    private fun cleanupStaleListeners(listenerList: CopyOnWriteArrayList<ListenerRegistration>) {
        val staleListeners = listenerList.filter { it.listener.get() == null }
        listenerList.removeAll(staleListeners)
    }

    fun cleanup() {
        targetsChangeListeners.clear()
        historyAccessChangeListeners.clear()
    }
}

fun PersistedObject.boolean(default: Boolean = false) =
    PersistedDelegate(getter = { key -> getBoolean(key) ?: default }, setter = { key, value -> setBoolean(key, value) })

fun PersistedObject.string(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

fun PersistedObject.int(default: Int) =
    PersistedDelegate(getter = { key -> getInteger(key) ?: default }, setter = { key, value -> setInteger(key, value) })

fun PersistedObject.stringList(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

class PersistedDelegate<T>(
    private val getter: (name: String) -> T, private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}

class ListenerRegistration(listener: () -> Unit) {
    val listener: WeakReference<() -> Unit> = WeakReference(listener)
}

fun interface ListenerHandle {
    fun remove()
}
