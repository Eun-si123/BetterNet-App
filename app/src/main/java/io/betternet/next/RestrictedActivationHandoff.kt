package io.betternet.next

import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * Process-local, single-pending-session handoff for a future explicit UI ->
 * service start. An Intent may carry only the opaque handle, never the bearer
 * credential or a serialized AppChoice. Process death invalidates the handle.
 * This registry does not issue Android VPN permission or start a service.
 */
internal class RestrictedActivationHandoff(
    private val random: SecureRandom = SecureRandom(),
    private val monotonicNanos: () -> Long = System::nanoTime,
) {
    internal class Session(
        val ticket: RestrictedActivationTicket,
        val app: AppChoice,
        val configuration: RestrictedTestConfiguration,
    )

    private data class Pending(val handle: String, val session: Session, val issuedAt: Long)
    private var pending: Pending? = null
    // An instance-local sequence prevents replay even when SecureRandom repeats
    // an older output (A, B, A). Process death discards the registry and all
    // tickets; 192 random bits also distinguish independent instances.
    private var nextSequence = 0L

    @Synchronized
    fun stage(ticket: RestrictedActivationTicket, app: AppChoice,
              configuration: RestrictedTestConfiguration): String {
        // A failed replacement must not leave an older consent session claimable.
        pending = null
        check(nextSequence != Long.MAX_VALUE) { "Activation handle sequence exhausted" }
        nextSequence++
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        for (i in 0 until 8) {
            bytes[i] = (nextSequence ushr (56 - i * 8)).toByte()
        }
        val handle = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        pending = Pending(handle, Session(ticket, app, configuration), monotonicNanos())
        return handle
    }

    @Synchronized
    fun take(handle: String?): Session? {
        val current = pending ?: return null
        // A malformed or mismatched start is not allowed to steal the session.
        val age = monotonicNanos() - current.issuedAt
        if (age < 0 || age > TimeUnit.SECONDS.toNanos(60)) {
            pending = null
            return null
        }
        if (handle == null || handle != current.handle) return null
        pending = null
        return current.session
    }

    @Synchronized
    fun clear() { pending = null }
}
