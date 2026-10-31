package io.betternet.next

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Single-owner thread for an ALREADY established, explicitly consented TUN.
 * Construction never starts a thread, VPN or network operation. The future
 * service must only call start() after checking OS consent, selected-app scope
 * and an authenticated, protected gateway configuration.
 *
 * requestStop() may run on a lifecycle thread. stopAndJoin() must run on a
 * background thread, never the Android main thread; it is bounded because
 * a gateway read or a Linux TUN read may not wake immediately on fd close.
 */
internal class RestrictedTunWorker(private val pump: RestrictedTunPump) {
    private val started = AtomicBoolean(false)
    @Volatile var failure: Throwable? = null
        private set

    private val owner = Thread({
        try {
            pump.runUntilStopped()
        } catch (error: Throwable) {
            // Retain the actual failure for the owner to inspect after join.
            // An uncaught worker exception must not silently kill the service.
            failure = error
        }
    }, "BetterNet-RestrictedTun")

    fun start() {
        check(started.compareAndSet(false, true)) { "TUN worker already started" }
        try {
            owner.start()
        } catch (error: Throwable) {
            try { pump.requestStop() } catch (closeError: Throwable) {
                error.addSuppressed(closeError)
            }
            throw error
        }
    }

    fun requestStop() = pump.requestStop()

    /** True only after the owner has completed its dispatcher/fd cleanup. */
    fun stopAndJoin(timeoutMs: Long): Boolean {
        require(timeoutMs in 1..10_000) { "TUN worker join must be bounded" }
        check(started.get()) { "TUN worker has not started" }
        check(Thread.currentThread() !== owner) { "TUN worker cannot join itself" }
        requestStop()
        owner.join(timeoutMs)
        return !owner.isAlive
    }
}
