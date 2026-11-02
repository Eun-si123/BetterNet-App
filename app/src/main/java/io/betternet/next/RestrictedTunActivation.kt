package io.betternet.next

import java.io.Closeable

/**
 * Single-use, fail-closed transaction for a future explicitly consented VPN.
 * Revalidate mutable Android state immediately before TUN establishment.
 * On any failure, release the descriptor and cancel the session owner; never
 * fall back to an unscoped VPN. No caller currently invokes this transaction.
 */
internal fun <D : Closeable, W> establishRestrictedTunTransaction(
    revalidate: () -> Unit,
    establish: () -> D?,
    attach: (D) -> W,
    start: (W) -> Unit,
    rollback: () -> Unit,
): W {
    var descriptor: D? = null
    try {
        revalidate()
        descriptor = establish() ?: throw IllegalStateException("Android refused restricted TUN establishment")
        val worker = attach(descriptor)
        start(worker)
        return worker // Worker now owns the descriptor and must be stopped/joined by its owner.
    } catch (failure: Throwable) {
        // Signal the owner first, before any cross-thread descriptor close.
        try { rollback() } catch (rollbackFailure: Throwable) {
            failure.addSuppressed(rollbackFailure)
        }
        try { descriptor?.close() } catch (closeFailure: Throwable) {
            failure.addSuppressed(closeFailure)
        }
        throw failure
    }
}
