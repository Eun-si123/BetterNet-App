package io.betternet.next

import android.content.Intent
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.InetAddress
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.io.IOException
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
        return onUnderlyingNetworkGateway(manager, network, hostname, port, timeoutMs) { address, remaining ->
            connectVerifiedGatewayTls(
                address, hostname, remaining, { socket -> protect(socket) },
                bind = { socket -> network.bindSocket(socket) },
            )
        }
    }

    /** Same-network DNS, protection and binding for the authenticated test tunnel.
     * Still dormant: no caller, VPN activation or outbound connection in the app.
     */
    internal fun newUnderlyingNetworkAuthenticatedTestTunnel(
        manager: ConnectivityManager, network: Network, gatewayName: String,
        gatewayPort: Int, timeoutMs: Int, destinationHost: String,
        destinationPort: Int, bearerToken: String,
    ): SSLSocket {
        return onUnderlyingNetworkGateway(
            manager, network, gatewayName, gatewayPort, timeoutMs
        ) { address, remaining ->
            connectAuthenticatedTestTunnel(
                address, gatewayName, remaining, { socket -> protect(socket) },
                destinationHost, destinationPort, bearerToken,
                bind = { socket -> network.bindSocket(socket) },
            )
        }
    }

    private fun <T> onUnderlyingNetworkGateway(
        manager: ConnectivityManager, network: Network, hostname: String,
        port: Int, timeoutMs: Int, dial: (InetSocketAddress, Int) -> T,
    ): T {
        val capabilities = manager.getNetworkCapabilities(network)
        require(capabilities != null &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            "A non-VPN underlying Internet network is required"
        }
        // All attempts resolve and bind on this exact non-VPN network; each
        // fresh socket is protected before connecting, even on IPv6/IPv4 fallback.
        return connectWithGatewayAddressFallback(
            hostname, port, timeoutMs, { network.getAllByName(it) }, dial
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
        try {
            socket.connect(address, timeoutMs)
        } catch (failure: SocketTimeoutException) {
            // Only a TCP connect timeout may trigger another resolved-address
            // attempt. A TLS handshake or authenticated CONNECT timeout must
            // not replay the credential or start another gateway connection.
            throw GatewayTcpConnectTimeout(failure)
        }
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

private class GatewayTcpConnectTimeout(cause: SocketTimeoutException) :
    SocketTimeoutException("Gateway TCP connect timed out") {
    init { initCause(cause) }
}

/** DNS must be performed by the chosen underlying Network, never system DNS. */
internal fun resolveGatewayAddress(
    hostname: String, port: Int, lookup: (String) -> Array<InetAddress>,
): InetSocketAddress = resolveGatewayAddresses(hostname, port, lookup).first()

private fun resolveGatewayAddresses(
    hostname: String, port: Int, lookup: (String) -> Array<InetAddress>,
): List<InetSocketAddress> {
    require(isValidGatewayName(hostname)) { "Invalid gateway DNS name" }
    require(port in 1..65535) { "Invalid gateway port" }
    // Cap retries even when a resolver supplies a very long address list.
    val addresses = lookup(hostname).distinct().take(4)
    require(addresses.isNotEmpty()) { "Underlying network returned no gateway addresses" }
    return addresses.map { InetSocketAddress(it, port) }
}

/**
 * One shared timeout across a bounded IPv6/IPv4 address list. Retry only
 * TCP connect reachability failures; never retry a TLS handshake/CONNECT
 * timeout, TLS identity failure, failed protection or network binding.
 * The dial callback must close each failed socket before throwing.
 */
internal fun <T> connectWithGatewayAddressFallback(
    hostname: String, port: Int, timeoutMs: Int,
    lookup: (String) -> Array<InetAddress>,
    dial: (InetSocketAddress, Int) -> T,
    nowNanos: () -> Long = System::nanoTime,
): T {
    require(timeoutMs in 1..10_000) { "Gateway timeout must be bounded" }
    val deadline = nowNanos() + timeoutMs * 1_000_000L
    val addresses = resolveGatewayAddresses(hostname, port, lookup)
    var lastFailure: IOException? = null
    for (address in addresses) {
        val remaining = deadline - nowNanos()
        if (remaining <= 0L) break
        val attemptTimeout = ((remaining / 1_000_000L) +
            if (remaining % 1_000_000L == 0L) 0L else 1L).coerceIn(1L, 10_000L).toInt()
        try {
            return dial(address, attemptTimeout)
        } catch (failure: IOException) {
            if (failure !is ConnectException && failure !is NoRouteToHostException &&
                failure !is GatewayTcpConnectTimeout) throw failure
            lastFailure = failure
        }
    }
    throw lastFailure ?: SocketTimeoutException("Gateway address attempts exceeded deadline")
}
