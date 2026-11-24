package io.betternet.next

import java.util.concurrent.atomic.AtomicBoolean

/**
 * A single-owner lifecycle loop for an ALREADY established restricted TUN.
 * The future VPN service must supply the owner thread, Android elapsedRealtime
 * clock, explicit OS consent and an authenticated, protected gateway first.
 * No thread, VPN, socket or network operation is started by this class.
 *
 * requestStop() is safe from Android's lifecycle thread: it only signals
 * cancellation and releases the TUN descriptor. The owner is responsible for
 * closing the dispatcher after its bounded TUN/gateway waits return. A future
 * service must join its owner thread before replacing the session.
 */
internal class RestrictedTunPump(
    private val session: RestrictedTunSession,
    private val revalidate: () -> Unit = {},
    private val maxRunMillis: Long = Long.MAX_VALUE,
    private val nowMillis: () -> Long,
) {
    init { require(maxRunMillis > 0) }
    private val started = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)

    /** Run on exactly one caller-owned background thread, at most once. */
    fun runUntilStopped() {
        check(started.compareAndSet(false, true)) { "TUN pump already started" }
        var failure: Throwable? = null
        try {
            var startedAt = -1L
            while (!stopRequested.get()) {
                if (maxRunMillis != Long.MAX_VALUE) {
                    val now = nowMillis()
                    if (startedAt < 0) startedAt = now
                    val elapsed = now - startedAt
                    // A debug test must release the selected app's route after
                    // a fixed interval; rollback or clock changes end it too.
                    if (now < 0 || elapsed < 0 || elapsed >= maxRunMillis) break
                }
                // An established TUN can outlive the original app identity,
                // OS permission or underlying network. Fail before the next
                // packet/gateway cycle rather than trusting activation-time state.
                revalidate()
                if (stopRequested.get() || !session.pumpOneCycle(nowMillis)) break
            }
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            stopRequested.set(true)
            try {
                session.close()
            } catch (closeError: Throwable) {
                if (failure == null) throw closeError
                // A cleanup callback may rethrow the very same Throwable.
                // Java rejects self-suppression and would hide the real cause.
                if (failure !== closeError) failure.addSuppressed(closeError)
            }
        }
    }

    /** Never close the dispatcher from a different thread. */
    fun requestStop() {
        stopRequested.set(true)
        session.requestStop()
    }
}
