package io.betternet.next

/**
 * Fail-closed ownership of one dormant, already-established TUN worker.
 * Android may revoke VPN consent while a future activation path is adopting
 * the descriptor. No thread, network, or VPN is started here. Cancellation
 * only signals the worker and closes its owned descriptor; joining remains
 * the responsibility of a background service owner, never on the main thread.
 */
/** Adoption rejection after the candidate worker has taken descriptor cleanup ownership. */
internal class RestrictedTunAdoptionRejected(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal class RestrictedTunLifecycle {
    private val lock = Any()
    private var cancelled = false
    private var worker: RestrictedTunWorker? = null

    fun adopt(candidate: RestrictedTunWorker): RestrictedTunWorker {
        val rejection = synchronized(lock) {
            when {
                cancelled -> "VPN lifecycle already revoked"
                worker != null -> "TUN worker already owned"
                else -> { worker = candidate; null }
            }
        }
        if (rejection != null) {
            // The caller transferred ownership of the descriptor: rejection
            // must release it, including when revoke raced with adoption.
            try { candidate.requestStop() } catch (error: Throwable) {
                throw RestrictedTunAdoptionRejected(rejection, error)
            }
            throw RestrictedTunAdoptionRejected(rejection)
        }
        return candidate
    }

    /** Do not open a new gateway operation after Android revoked this owner. */
    fun requireNotCancelled() {
        synchronized(lock) {
            check(!cancelled) { "VPN lifecycle already revoked" }
        }
    }

    fun cancel() {
        val current = synchronized(lock) {
            if (cancelled) null else {
                cancelled = true
                worker
            }
        }
        current?.requestStop()
    }
}
