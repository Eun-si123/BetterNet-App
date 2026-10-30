package io.betternet.next

import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns an ALREADY established, explicitly consented test TUN descriptor.
 * No code constructs or starts a VPN here. All pump methods and close() must
 * run on one serialized owner thread; a future worker must arrange cancellation
 * by requesting descriptor cancellation and joining that thread before reusing the session.
 * Closing an fd from another thread is NOT guaranteed to interrupt a blocked
 * Linux read; a live worker must use bounded readiness polling and verify
 * cancellation on a real Android device before activation.
 *
 * Gateway reads may block. The caller must use a bounded socket read timeout
 * and schedule them only when appropriate; this is not an event loop.
 */
internal class RestrictedTunSession(
    private val dispatcher: RestrictedTestTunDispatcher,
    private val input: InputStream,
    private val output: OutputStream,
    private val closeDescriptor: () -> Unit,
    private val waitForReadable: (() -> Boolean)? = null,
) : Closeable {
    private var closed = false
    private val stopRequested = AtomicBoolean(false)
    private val descriptorReleased = AtomicBoolean(false)

    /** May be called by Android onRevoke/onDestroy from another thread.
     * Signals cancellation and closes the descriptor without touching the
     * single-owner dispatcher. An already blocked read might NOT wake merely
     * because another thread closed its fd (Linux semantics); live activation
     * must separately provide a verified wakeup/poll strategy and join owner.
     * Gateway reads still require their own bounded socket timeout.
     */
    fun requestStop() {
        stopRequested.set(true)
        releaseDescriptorOnce()
    }

    private fun releaseDescriptorOnce() {
        if (descriptorReleased.compareAndSet(false, true)) closeDescriptor()
    }

    fun pumpOneTunPacket(nowMillis: Long): Boolean = guarded {
        // Android supplies a bounded poll: an idle TUN must not monopolize
        // the owner thread or prevent cancellation and gateway scheduling.
        if (waitForReadable != null) {
            val readable = waitForReadable()
            if (stopRequested.get()) return@guarded false
            if (!readable) return@guarded true
        }
        if (!dispatcher.pumpOneTunPacket(input, output, nowMillis)) {
            close()
            false
        } else true
    }

    fun pumpOneGatewayReply(nowMillis: Long): Boolean =
        guarded { dispatcher.pumpOneGatewayReply(output, nowMillis) }

    fun pumpPendingRetry(nowMillis: Long): Boolean =
        guarded { dispatcher.pumpPendingRetry(output, nowMillis) }

    private inline fun guarded(action: () -> Boolean): Boolean {
        if (closed) return false
        if (stopRequested.get()) { close(); return false }
        try {
            val result = action()
            if (stopRequested.get()) { close(); return false }
            return result
        } catch (failure: Exception) {
            // Closing the TUN fd from requestStop() normally interrupts read()
            // with IOException. Treat that as cancellation, not a new failure.
            if (stopRequested.get() && failure is IOException && !closed) {
                close()
                return false
            }
            try { close() } catch (closeFailure: Exception) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
    }

    /**
     * Normal owner close releases the bridge before the TUN descriptor.
     * Cross-thread cancellation releases the descriptor first to request
     * read() interruption; when the owner returns it closes the bridge.
     * Streams share the Android fd; never close their wrappers independently.
     */
    override fun close() {
        if (closed) return
        closed = true
        var failure: Exception? = null
        try { dispatcher.close() } catch (error: Exception) { failure = error }
        try { releaseDescriptorOnce() } catch (error: Exception) {
            if (failure == null) failure = error
            else failure.addSuppressed(error)
        }
        if (failure != null) throw failure
    }
}
