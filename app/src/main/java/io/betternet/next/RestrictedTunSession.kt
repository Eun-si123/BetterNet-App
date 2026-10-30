package io.betternet.next

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

/**
 * Owns an ALREADY established, explicitly consented test TUN descriptor.
 * No code constructs or starts a VPN here. All pump methods and close() must
 * run on one serialized owner thread; a future worker must arrange cancellation
 * by closing its descriptor and joining that thread before reusing the session.
 *
 * Gateway reads may block. The caller must use a bounded socket read timeout
 * and schedule them only when appropriate; this is not an event loop.
 */
internal class RestrictedTunSession(
    private val dispatcher: RestrictedTestTunDispatcher,
    private val input: InputStream,
    private val output: OutputStream,
    private val closeDescriptor: () -> Unit,
) : Closeable {
    private var closed = false

    fun pumpOneTunPacket(nowMillis: Long): Boolean = guarded {
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
        try {
            return action()
        } catch (failure: Exception) {
            try { close() } catch (closeFailure: Exception) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
    }

    /**
     * Close the authenticated bridge BEFORE releasing the TUN descriptor.
     * Streams can share one underlying Android fd: do not independently close
     * their wrappers or accidentally close that fd twice.
     */
    override fun close() {
        if (closed) return
        closed = true
        var failure: Exception? = null
        try { dispatcher.close() } catch (error: Exception) { failure = error }
        try { closeDescriptor() } catch (error: Exception) {
            if (failure == null) failure = error
            else failure.addSuppressed(error)
        }
        if (failure != null) throw failure
    }
}
