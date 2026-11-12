package io.betternet.next

import java.util.concurrent.atomic.AtomicBoolean

/**
 * One-use, in-memory handoff for a future explicitly approved activation.
 * Not an Android VPN permission grant: the service must still verify OS consent,
 * package identity and network state immediately before establishing a TUN.
 * The future UI must only issue this after explicit user confirmation.
 */
internal class RestrictedActivationTicket private constructor(
    private val selectedApp: AppChoice,
    private val configuration: RestrictedTestConfiguration,
) {
    private val consumed = AtomicBoolean(false)

    fun consume(app: AppChoice?, config: RestrictedTestConfiguration) {
        // Consume even on mismatch: a stale/misrouted handoff cannot be retried.
        check(consumed.compareAndSet(false, true)) { "Activation ticket already consumed" }
        check(app === selectedApp && config === configuration) {
            "Activation ticket does not match the approved session"
        }
    }

    companion object {
        /** Dormant API; no current Activity or service start path issues tickets. */
        fun forFutureExplicitConfirmation(
            selectedApp: AppChoice,
            configuration: RestrictedTestConfiguration,
        ) = RestrictedActivationTicket(selectedApp, configuration)
    }
}
