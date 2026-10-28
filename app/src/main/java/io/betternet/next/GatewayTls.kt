package io.betternet.next

import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Protect and connect first; never let a caller bypass VPN recursion protection. */
internal fun connectVerifiedGatewayTls(
    address: InetSocketAddress, serverName: String, timeoutMs: Int,
    protect: (Socket) -> Boolean,
    socketFactory: () -> Socket = { Socket() },
    tlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    bind: (Socket) -> Unit = {},
): SSLSocket {
    // Validate identity before even opening a TCP connection.
    require(isValidGatewayName(serverName)) { "Invalid TLS gateway hostname" }
    return establishVerifiedGatewayTls(
        connectProtectedSocket(address, timeoutMs, protect, socketFactory, bind), address, serverName, tlsFactory
    )
}

/**
 * TLS identity boundary for a future gateway. The caller supplies a socket
 * already protected by VpnService.protect() and connected on the underlying
 * network; the hostname is for SNI and certificate verification, not DNS.
 * No production call site exists until the forwarding protocol is reviewed.
 */
internal fun establishVerifiedGatewayTls(
    protectedSocket: Socket,
    resolvedAddress: InetSocketAddress,
    serverName: String,
    factory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
): SSLSocket {
    try {
        require(!resolvedAddress.isUnresolved) { "Gateway address must be resolved" }
        require(protectedSocket.isConnected && !protectedSocket.isClosed) { "Protected socket must be connected" }
        require(isValidGatewayName(serverName)) { "Invalid TLS gateway hostname" }
        require(resolvedAddress.port in 1..65535) { "Invalid gateway port" }
        val tls = factory.createSocket(protectedSocket, serverName, resolvedAddress.port, true) as SSLSocket
        try {
            tls.useClientMode = true
            tls.soTimeout = 10_000
            val secureProtocols = tls.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
            check(secureProtocols.isNotEmpty()) { "No acceptable TLS protocol" }
            tls.enabledProtocols = secureProtocols.toTypedArray()
            val parameters = tls.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            tls.sslParameters = parameters
            tls.startHandshake() // CA trust and hostname verification must succeed
            return tls
        } catch (failure: Throwable) {
            try { tls.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
            throw failure
        }
    } catch (failure: Throwable) {
        try { protectedSocket.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
        throw failure
    }
}

internal fun isValidGatewayName(name: String): Boolean {
    if (name.length !in 1..253 || name != name.trim() || name.endsWith('.')) return false
    return name.split('.').all { label ->
        label.length in 1..63 && label.first().isLetterOrDigit() &&
            label.last().isLetterOrDigit() &&
            label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
    }
}
