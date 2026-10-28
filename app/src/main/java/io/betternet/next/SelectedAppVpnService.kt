package io.betternet.next

import android.content.Intent
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

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

    /** Dormant TLS dial: protect before TCP connect; verify gateway certificate and name. */
    internal fun newVerifiedGatewaySocket(address: InetSocketAddress, serverName: String, timeoutMs: Int): SSLSocket =
        connectVerifiedGatewayTls(address, serverName, timeoutMs, { socket -> protect(socket) })

    /**
     * Dormant A1 path: DNS and socket binding use the SAME explicitly supplied
     * non-VPN underlying network. Never fall back to default DNS or routing.
     */
    internal fun newUnderlyingNetworkGatewaySocket(
        manager: ConnectivityManager, network: Network, hostname: String,
        port: Int, timeoutMs: Int,
    ): SSLSocket {
        val capabilities = manager.getNetworkCapabilities(network)
        require(capabilities != null &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            "A non-VPN underlying Internet network is required"
        }
        require(timeoutMs in 1..10_000) { "Gateway timeout must be bounded" }
        val address = resolveGatewayAddress(hostname, port) { network.getAllByName(it) }
        return connectVerifiedGatewayTls(
            address, hostname, timeoutMs, { socket -> protect(socket) },
            bind = { socket -> network.bindSocket(socket) },
        )
    }

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
    bind: (Socket) -> Unit = {},
): Socket {
    require(!address.isUnresolved) { "Gateway address must be resolved on the underlying network" }
    require(timeoutMs in 1..10_000) { "Gateway connect timeout must be bounded" }
    val socket = createSocket()
    try {
        check(protect(socket)) { "Gateway socket could not be excluded from the VPN" }
        bind(socket) // Binding failures close the socket, never use default routing.
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

/** DNS must be performed by the chosen underlying Network, never system DNS. */
internal fun resolveGatewayAddress(
    hostname: String, port: Int, lookup: (String) -> Array<InetAddress>,
): InetSocketAddress {
    require(isValidGatewayName(hostname)) { "Invalid gateway DNS name" }
    require(port in 1..65535) { "Invalid gateway port" }
    val addresses = lookup(hostname)
    require(addresses.isNotEmpty()) { "Underlying network returned no gateway addresses" }
    return InetSocketAddress(addresses.first(), port)
}
