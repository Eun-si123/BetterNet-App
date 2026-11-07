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
 * onTerminated runs once after cleanup: on the owner thread after a normal
 * launch, or on the launching thread if launch failed before the owner started.
 * A future service may use it to schedule foreground-service shutdown, but
 * must never join the owner from this callback. Callback errors are retained.
 */
internal class RestrictedTunWorker(
    private val pump: RestrictedTunPump,
    private val onTerminated: (Throwable?) -> Unit = {},
    private val launchThread: (Thread) -> Unit = { it.start() },
) {
    private val started = AtomicBoolean(false)
    private val terminationNotified = AtomicBoolean(false)
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
        } finally {
            notifyTerminated()
        }
    }, "BetterNet-RestrictedTun")

    private fun notifyTerminated() {
        if (!terminationNotified.compareAndSet(false, true)) return
        try {
            onTerminated(failure)
        } catch (callbackError: Throwable) {
            val original = failure
            if (original == null) failure = callbackError
            else if (callbackError !== original) original.addSuppressed(callbackError)
        }
    }

    fun start() {
        check(started.compareAndSet(false, true)) { "TUN worker already started" }
        try {
            launchThread(owner)
            // A custom launcher returning without starting the owner is not a
            // successful activation. Never report an unstarted thread as joined.
            check(owner.state != Thread.State.NEW) { "TUN worker thread was not launched" }
            launched = true
        } catch (error: Throwable) {
            val neverLaunched = owner.state == Thread.State.NEW
            // A launcher may throw after actually starting the thread. It is
            // still joinable and must finish its own cleanup/notification.
            if (neverLaunched) failure = error else launched = true
            try { pump.requestStop() } catch (closeError: Throwable) {
                // A failing launcher and descriptor cleanup can surface the
                // same Throwable instance; self-suppression must not mask it.
                if (closeError !== error) error.addSuppressed(closeError)
            }
            // No owner thread exists to call back in this case. Notify only
            // after cancellation/descriptor release, and never twice if a
            // launcher actually started the thread before throwing.
            if (neverLaunched) notifyTerminated()
            throw error
        } finally {
            launchFinished.countDown()
        }
    }

    fun requestStop() = pump.requestStop()

    /** Request cancellation, then wait for owner-thread cleanup. */
    fun stopAndJoin(timeoutMs: Long): Boolean {
        validateJoin(timeoutMs)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        // Descriptor cancellation can fail after the stop flag was already set.
        // The worker may still be blocked in a poll/gateway callback; never
        // skip the bounded owner join merely because fd closure threw.
        var stopFailure: Throwable? = null
        try { requestStop() } catch (error: Throwable) { stopFailure = error }
        val remaining = deadline - System.nanoTime()
        val joined = try {
            if (remaining <= 0) false else {
                val millis = TimeUnit.NANOSECONDS.toMillis(remaining) +
                    if (remaining % 1_000_000L == 0L) 0L else 1L
                awaitStopped(millis)
            }
        } catch (joinFailure: Throwable) {
            val original = stopFailure ?: throw joinFailure
            if (joinFailure !== original) original.addSuppressed(joinFailure)
            throw original
        }
        if (stopFailure != null) throw stopFailure
        return joined
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
