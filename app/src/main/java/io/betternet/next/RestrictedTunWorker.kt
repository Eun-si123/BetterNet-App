package io.betternet.next

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
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
    // Launch may block in Thread.start(). Waiting for it must count toward
    // the join deadline; holding a monitor would make a bounded join unbounded.
    private val launchFinished = CountDownLatch(1)
    @Volatile private var launched = false
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
            launchThread(owner)
            launched = true
        } catch (error: Throwable) {
            try { pump.requestStop() } catch (closeError: Throwable) {
                error.addSuppressed(closeError)
            }
            throw error
        } finally {
            launchFinished.countDown()
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
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        if (!launchFinished.await(timeoutMs, TimeUnit.MILLISECONDS)) return false
        check(launched) { "TUN worker has not started" }
        val remainingNanos = deadline - System.nanoTime()
        if (remainingNanos > 0) {
            // Java join(0) waits forever; round a positive sub-ms remainder up.
            val remainingMs = TimeUnit.NANOSECONDS.toMillis(remainingNanos) +
                if (remainingNanos % 1_000_000L == 0L) 0L else 1L
            owner.join(remainingMs)
        }
        return !owner.isAlive
    }

    private fun validateJoin(timeoutMs: Long) {
        require(timeoutMs in 1..10_000) { "TUN worker join must be bounded" }
        check(started.get()) { "TUN worker has not started" }
        check(Thread.currentThread() !== owner) { "TUN worker cannot join itself" }
    }
}
