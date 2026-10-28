package io.betternet.next

import android.content.Intent
import android.net.VpnService
import java.net.InetSocketAddress
import java.net.Socket

/**
 * A deliberately inactive A1 boundary. No code starts this service, asks for
 * consent, establishes a TUN, or forwards packets until a safe gateway exists.
 */
class SelectedAppVpnService : VpnService() {
    /** Future activation must use this scoped builder, never an unscoped fallback. */
    internal fun newSelectedAppBuilder(selectedPackage: String?): Builder {
        return Builder().apply {
            // NameNotFoundException must abort activation, not widen to all apps.
            addOnlySelectedApplication(selectedPackage, packageName) { allowed ->
                addAllowedApplication(allowed)
                Unit
            }
        }
    }

    /** A future TLS gateway dial must protect its socket before connecting. */
    internal fun newProtectedGatewaySocket(address: InetSocketAddress, timeoutMs: Int): Socket =
        connectProtectedSocket(address, timeoutMs, { socket -> protect(socket) })

    // Explicit starts are not an activation mechanism. A future authenticated
    // forwarding implementation must introduce a separately reviewed path.
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopSelf(startId)
        return START_NOT_STICKY
    }
}

/** Reject missing, self, and malformed selections before touching a VPN builder. */
internal fun requireSelectedPackage(selectedPackage: String?, ownPackage: String): String {
    require(!selectedPackage.isNullOrBlank()) { "A selected app is required" }
    require(selectedPackage == selectedPackage.trim()) { "Invalid selected app" }
    require(selectedPackage != ownPackage) { "Cannot route BetterNet through itself" }
    return selectedPackage
}

/** Add exactly one app. Never recover from lookup failure with a broad route. */
internal fun addOnlySelectedApplication(
    selectedPackage: String?,
    ownPackage: String,
    addAllowedApplication: (String) -> Unit,
) {
    addAllowedApplication(requireSelectedPackage(selectedPackage, ownPackage))
}

/**
 * A dormant socket-recursion guard. Accept only an already resolved address:
 * name resolution must later use an explicitly chosen underlying Network.
 * This helper never performs TLS or starts a connection unless called.
 */
internal fun connectProtectedSocket(
    address: InetSocketAddress,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    createSocket: () -> Socket = { Socket() },
): Socket {
    require(!address.isUnresolved) { "Gateway address must be resolved on the underlying network" }
    require(timeoutMs in 1..10_000) { "Gateway connect timeout must be bounded" }
    val socket = createSocket()
    try {
        check(protect(socket)) { "Gateway socket could not be excluded from the VPN" }
        socket.connect(address, timeoutMs)
        return socket
    } catch (failure: Throwable) {
        try {
            socket.close()
        } catch (closeFailure: Throwable) {
            failure.addSuppressed(closeFailure)
        }
        throw failure
    }
}
