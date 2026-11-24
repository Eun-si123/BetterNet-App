package io.betternet.next

import java.util.ArrayDeque

/** Only explicit, code-defined states are accepted. No arbitrary string, IP,
 * hostname, package name, bearer credential, exception or packet can enter.
 * Process-memory only; user alone chooses whether to view/copy the snapshot.
 */
internal enum class RestrictedDebugEvent {
    SELECTION_CHANGED,
    CONFIG_UPDATED,
    SCOPE_CLEARED,
    HTTPS_PREFLIGHT_PASSED,
    HTTPS_PREFLIGHT_FAILED,
    START_REQUESTED,
    START_REQUEST_FAILED,
    START_REFUSED,
    START_ACCEPTED,
    STOP_REQUESTED,
    TIME_LIMIT_REACHED,
    VPN_REVOKED,
    SERVICE_DESTROYED,
    WORKER_TERMINATED,
    WORKER_FAILED,
    TUN_BUDGET_EXCEEDED,
}

/** Bounded in-process diagnostic journal. Do NOT add an arbitrary-string
 * overload, persistent storage, network upload or automatic clipboard use.
 * Relative timing cannot reveal absolute calendar dates or the local network.
 */
internal class RestrictedDebugEventJournal(
    private val nowMillis: () -> Long = { System.nanoTime() / 1_000_000L },
    private val maxEvents: Int = 64,
) {
    init { require(maxEvents in 1..256) }
    private data class Entry(val elapsedMillis: Long, val event: RestrictedDebugEvent)
    private val entries = ArrayDeque<Entry>()
    private var initialMillis: Long? = null

    @Synchronized
    fun record(event: RestrictedDebugEvent) {
        val now = nowMillis()
        val origin = initialMillis ?: now.also { initialMillis = it }
        val elapsed = (now - origin).coerceAtLeast(0L)
        if (entries.size == maxEvents) entries.removeFirst()
        entries.addLast(Entry(elapsed, event))
    }

    @Synchronized
    fun clear() {
        entries.clear()
        initialMillis = null
    }

    @Synchronized
    fun snapshot(): String {
        val header = "BetterNet A1 DEBUG EVENTS (local, voluntary, no auto-upload)\n" +
            "Times are approximate seconds since first recorded event.\n" +
            "No VPN success is implied by these events.\n" +
            "Copying the preview puts it on the system clipboard, where other apps may read it.\n"
        val events = entries.joinToString("\n") { entry ->
            "+${entry.elapsedMillis / 1000}s ${entry.event.name}"
        }
        return header + if (entries.isEmpty()) "(no events)" else events
    }
}

/** State is intentionally cleared at process death, not persisted across runs. */
internal object RestrictedDebugEvents {
    val journal = RestrictedDebugEventJournal()

    /** Release builds never collect even the fixed diagnostic event codes. */
    fun record(debuggable: Boolean, event: RestrictedDebugEvent) {
        if (debuggable) journal.record(event)
    }
}
