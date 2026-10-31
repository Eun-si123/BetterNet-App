package io.betternet.next

import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Dormant, explicitly scoped HTTPS or DNS-over-TLS path through an authenticated CONNECT
 * gateway. The destination TLS identity is verified independently of the
 * gateway's TLS identity. The destination hostname is resolved by the gateway,
 * not by the Android device; no default-network DNS lookup is permitted here.
 *
 * No production caller, gateway deployment, VPN activation or traffic capture.
 */
internal fun connectVerifiedDestinationTlsThroughGateway(
    gatewayAddress: InetSocketAddress,
    gatewayName: String,
    destinationName: String,
    destinationPort: Int,
    bearerToken: String,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    gatewayTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    destinationTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    bind: (Socket) -> Unit = {},
): SSLSocket {
    // Reject unsafe destinations before opening a gateway socket.
    require(isValidGatewayName(destinationName)) { "Invalid destination TLS hostname" }
    require(destinationPort == 443 || destinationPort == 853) { "Only HTTPS or DNS-over-TLS is allowed" }
    require(timeoutMs in 1..10_000) { "Destination TLS timeout must be bounded" }
    val tunnel = connectAuthenticatedTestTunnel(
        gatewayAddress, gatewayName, timeoutMs, protect, destinationName, destinationPort,
        bearerToken, tlsFactory = gatewayTlsFactory, bind = bind
    )
    try {
        val inner = destinationTlsFactory.createSocket(tunnel, destinationName, destinationPort, true) as SSLSocket
        try {
            inner.useClientMode = true
            inner.soTimeout = timeoutMs
            val allowed = inner.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
            check(allowed.isNotEmpty()) { "No acceptable destination TLS protocol" }
            inner.enabledProtocols = allowed.toTypedArray()
            inner.sslParameters = inner.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
            }
            inner.startHandshake()
            return inner
        } catch (failure: Throwable) {
            try { inner.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
            throw failure
        }
    } catch (failure: Throwable) {
        try { tunnel.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
        throw failure
    }
}
