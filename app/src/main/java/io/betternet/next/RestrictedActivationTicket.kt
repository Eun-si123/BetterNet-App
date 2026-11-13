package io.betternet.next

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit

/**
 * One-use, in-memory handoff for a future explicitly approved activation.
 * Not an Android VPN permission grant: the service must still verify OS consent,
 * package identity and network state immediately before establishing a TUN.
 * The future UI must only issue this after explicit user confirmation.
 */
internal class RestrictedActivationTicket private constructor(
    private val selectedApp: AppChoice,
    private val configuration: RestrictedTestConfiguration,
    private val issuedAtNanos: Long,
    private val monotonicNanos: () -> Long,
) {
    private val consumed = AtomicBoolean(false)

    fun consume(app: AppChoice?, config: RestrictedTestConfiguration) {
        // Consume even on mismatch: a stale/misrouted handoff cannot be retried.
        check(consumed.compareAndSet(false, true)) { "Activation ticket already consumed" }
        val age = monotonicNanos() - issuedAtNanos
        check(age >= 0 && age <= TimeUnit.SECONDS.toNanos(60)) {
            "Activation ticket expired or monotonic clock moved backwards"
        }
        check(app === selectedApp && config === configuration) {
            "Activation ticket does not match the approved session"
        }
    }

    companion object {
        /** Dormant API; no current Activity or service start path issues tickets. */
        fun forFutureExplicitConfirmation(
            selectedApp: AppChoice,
            configuration: RestrictedTestConfiguration,
            monotonicNanos: () -> Long = System::nanoTime,
        ) = RestrictedActivationTicket(selectedApp, configuration, monotonicNanos(), monotonicNanos)
    }
}
