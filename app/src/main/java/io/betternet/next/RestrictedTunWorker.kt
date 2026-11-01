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
internal class RestrictedTunWorker(
    private val pump: RestrictedTunPump,
    private val launchThread: (Thread) -> Unit = { it.start() },
) {
    private val started = AtomicBoolean(false)
    private val launchLock = Any()
    // CAS alone is insufficient: join() on a not-yet-started Thread returns
    // immediately, falsely reporting shutdown while start() is still launching.
    private var launched = false
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

    fun start() = synchronized(launchLock) {
        check(started.compareAndSet(false, true)) { "TUN worker already started" }
        try {
            launchThread(owner)
            launched = true
        } catch (error: Throwable) {
            try { pump.requestStop() } catch (closeError: Throwable) {
                error.addSuppressed(closeError)
            }
            throw error
        }
    }

    fun requestStop() = pump.requestStop()

    /** Request cancellation, then wait for owner-thread cleanup. */
    fun stopAndJoin(timeoutMs: Long): Boolean {
        validateJoin(timeoutMs)
        requestStop()
        return awaitStopped(timeoutMs)
    }

    /** Observe natural completion/failure without cancelling an active worker. */
    fun awaitStopped(timeoutMs: Long): Boolean {
        validateJoin(timeoutMs)
        owner.join(timeoutMs)
        return !owner.isAlive
    }

    private fun validateJoin(timeoutMs: Long) {
        require(timeoutMs in 1..10_000) { "TUN worker join must be bounded" }
        synchronized(launchLock) {
            check(launched) { "TUN worker has not started" }
        }
        check(Thread.currentThread() !== owner) { "TUN worker cannot join itself" }
    }
}
