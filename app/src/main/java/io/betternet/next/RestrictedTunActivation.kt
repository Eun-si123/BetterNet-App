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
    var transferredToWorker = false
    try {
        revalidate()
        descriptor = establish() ?: throw IllegalStateException("Android refused restricted TUN establishment")
        val worker = attach(descriptor)
        // The worker now owns the descriptor even if its start() fails.
        // Rollback must signal that owner; closing the same fd again here
        // can race a running owner or obscure the original launch failure.
        transferredToWorker = true
        start(worker)
        return worker // Worker now owns the descriptor and must be stopped/joined by its owner.
    } catch (failure: Throwable) {
        // Signal the owner first, before any cross-thread descriptor close.
        try { rollback() } catch (rollbackFailure: Throwable) {
            if (rollbackFailure !== failure) failure.addSuppressed(rollbackFailure)
        }
        if (!transferredToWorker) {
            try { descriptor?.close() } catch (closeFailure: Throwable) {
                if (closeFailure !== failure) failure.addSuppressed(closeFailure)
            }
        }
        throw failure
    }
}

/**
 * Foreground ownership is acquired only after a fresh preflight, before TUN
 * establishment. If promotion or activation fails, remove the notification;
 * the caller's activation rollback separately cancels any worker/descriptor.
 * On success the service owns foreground teardown via onRevoke/onDestroy.
 * No caller currently starts this activation from an Android component.
 */
internal fun <T> withRestrictedForegroundOwnership(
    revalidate: () -> Unit,
    promote: () -> Unit,
    activate: () -> T,
    demote: () -> Unit,
): T {
    revalidate()
    try {
        promote()
        return activate()
    } catch (failure: Throwable) {
        // Promotion can throw after partially entering foreground mode. The
        // best-effort cleanup must not mask the original security/OS failure.
        try { demote() } catch (cleanup: Throwable) {
            if (cleanup !== failure) failure.addSuppressed(cleanup)
        }
        throw failure
    }
}

/**
 * Explicit notification STOP and unexpected service starts share this
 * fail-closed shutdown. Stop the Android service even if descriptor cancellation
 * throws; never leave an active foreground notification after a failed stop.
 */
internal fun stopRestrictedServiceFailClosed(cancel: () -> Unit, stop: () -> Unit) {
    var failure: Throwable? = null
    try { cancel() } catch (error: Throwable) { failure = error }
    try { stop() } catch (error: Throwable) {
        if (failure == null) failure = error
        else if (error !== failure) failure.addSuppressed(error)
    }
    if (failure != null) throw failure
}
