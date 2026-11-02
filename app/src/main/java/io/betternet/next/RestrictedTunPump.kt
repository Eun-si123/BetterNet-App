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
    private val nowMillis: () -> Long,
) {
    private val started = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)

    /** Run on exactly one caller-owned background thread, at most once. */
    fun runUntilStopped() {
        check(started.compareAndSet(false, true)) { "TUN pump already started" }
        var failure: Throwable? = null
        try {
            while (!stopRequested.get()) {
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
                if (failure != null) failure.addSuppressed(closeError)
                else throw closeError
            }
        }
    }

    /** Never close the dispatcher from a different thread. */
    fun requestStop() {
        stopRequested.set(true)
        session.requestStop()
    }
}
