package io.betternet.next

import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Dormant single-query A1 composition: a validated TUN DNS/UDP request,
 * one caller-supplied, already authenticated and hostname-verified TLS socket,
 * and at most one correlated TUN reply. No VPN activation or network dial here.
 *
 * The caller must obtain the TLS socket on a protected, bound underlying network;
 * this function cannot authenticate an application-level gateway or authorize
 * arbitrary DNS forwarding. Do not wire it to a live VPN until those gates pass.
 */
internal fun exchangeOneTunDnsQueryOverTls(
    tls: SSLSocket,
    request: TunIngressResult.Packet,
    pending: PendingDnsReplies,
    output: OutputStream,
    mtu: Int,
    timeoutMs: Int,
): Boolean = tls.use {
    require(mtu in 1280..9000) { "TUN MTU must be bounded" }
    require(timeoutMs in 1..10_000) { "DNS exchange timeout must be bounded" }
    val snapshot = request.copy(bytes = request.bytes.clone())
    val handle = pending.register(snapshot) ?: return@use false
    try {
        exchangeRegisteredTunDnsQuery(tls, snapshot, handle, pending, output, mtu, timeoutMs) { _, _ -> true } != null
    } finally {
        pending.cancel(handle)
    }
}

/** A correlated response must also pass the caller's destination authorization
 * BEFORE any DNS answer is written to the selected app's TUN descriptor.
 * Null approval means no TUN output and no new TCP destination capability.
 */
private fun <T : Any> exchangeRegisteredTunDnsQuery(
    tls: SSLSocket,
    snapshot: TunIngressResult.Packet,
    handle: Long,
    pending: PendingDnsReplies,
    output: OutputStream,
    mtu: Int,
    timeoutMs: Int,
    approve: (ByteArray, ByteArray) -> T?,
): T? {
    val header = parseTunPacketHeader(snapshot.bytes, snapshot.bytes.size) ?: return null
    val query = snapshot.bytes.copyOfRange(header.transportOffset + 8, snapshot.bytes.size)
    val response = exchangeOneDnsMessageOverTls(tls, query, timeoutMs)
    val approved = approve(query, response) ?: return null
    val reply = pending.consume(handle, response, mtu) ?: return null
    // Never retry an uncertain partial TUN write or return an authorization
    // when its matching DNS answer failed to reach the selected app.
    output.write(reply)
    return approved
}

/**
 * Dormant end-to-end DNS slice: one selected-app TUN DNS datagram through a
 * protected, credential-bearing CONNECT test tunnel and independently verified
 * DNS-over-TLS peer, back to one correlated IP datagram. The gateway is only a
 * test peer; this does not start a VPN or prove public Internet connectivity.
 */
internal fun exchangeOneTunDnsQueryThroughGateway(
    gatewayAddress: InetSocketAddress,
    gatewayName: String,
    dnsServerName: String,
    bearerToken: String,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    request: TunIngressResult.Packet,
    pending: PendingDnsReplies,
    output: OutputStream,
    mtu: Int,
    gatewayTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    destinationTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    bind: (Socket) -> Unit = {},
): Boolean = exchangeOneTunDnsQueryThroughGatewayChecked(
    gatewayAddress, gatewayName, dnsServerName, bearerToken, timeoutMs,
    protect, request, pending, output, mtu, gatewayTlsFactory, destinationTlsFactory, bind
) { _, _ -> true } != null

/**
 * A1 test-only DNS-to-TCP authorization seam. Return a short-lived binding
 * ONLY after the independently approved address appears in the correlated,
 * verified DoT response AND its matching DNS reply is delivered to the TUN.
 * An unapproved or malformed answer is withheld, not offered to the app.
 *
 * This remains dormant: no VPN activation, listener, real Internet dial or
 * gateway deployment. The caller must later own the explicit app consent,
 * same-network socket protection, packet scheduling and session teardown.
 */
internal fun exchangeOneTunDnsQueryThroughGatewayAndBindTestDestination(
    gatewayAddress: InetSocketAddress,
    gatewayName: String,
    dnsServerName: String,
    bearerToken: String,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    request: TunIngressResult.Packet,
    pending: PendingDnsReplies,
    output: OutputStream,
    mtu: Int,
    expectedHost: String,
    allowedTestAddress: InetAddress,
    gatewayTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    destinationTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    bind: (Socket) -> Unit = {},
    // The TUN dispatcher and TCP flow leases use elapsed/monotonic milliseconds.
    // A wall-clock timestamp here would silently reject every legitimate SYN
    // when the future session owner passes Android elapsedRealtime().
    clockMillis: () -> Long = { android.os.SystemClock.elapsedRealtime() },
): DnsDestinationBinding? {
    require(isValidGatewayName(expectedHost)) { "Invalid test destination hostname" }
    return exchangeOneTunDnsQueryThroughGatewayChecked(
        gatewayAddress, gatewayName, dnsServerName, bearerToken, timeoutMs,
        protect, request, pending, output, mtu, gatewayTlsFactory, destinationTlsFactory, bind
    ) { query, response ->
        DnsDestinationBinding.fromCorrelatedResponse(
            query, response, expectedHost, allowedTestAddress, clockMillis()
        )
    }
}

private fun <T : Any> exchangeOneTunDnsQueryThroughGatewayChecked(
    gatewayAddress: InetSocketAddress,
    gatewayName: String,
    dnsServerName: String,
    bearerToken: String,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    request: TunIngressResult.Packet,
    pending: PendingDnsReplies,
    output: OutputStream,
    mtu: Int,
    gatewayTlsFactory: SSLSocketFactory,
    destinationTlsFactory: SSLSocketFactory,
    bind: (Socket) -> Unit,
    approve: (ByteArray, ByteArray) -> T?,
): T? {
    require(mtu in 1280..9000) { "TUN MTU must be bounded" }
    require(timeoutMs in 1..10_000) { "DNS timeout must be bounded" }
    // Reserve both a pending reply and a live-dial lease BEFORE any socket or
    // credential use. A reply TTL cannot free an in-progress dial lease.
    if (!pending.reserveGatewayDial()) return null
    try {
        val snapshot = request.copy(bytes = request.bytes.clone())
        val handle = pending.register(snapshot) ?: return null
        try {
            val tls = connectVerifiedDestinationTlsThroughGateway(
                gatewayAddress, gatewayName, dnsServerName, 853, bearerToken,
                timeoutMs, protect, gatewayTlsFactory, destinationTlsFactory, bind
            )
            return tls.use {
                exchangeRegisteredTunDnsQuery(
                    it, snapshot, handle, pending, output, mtu, timeoutMs, approve
                )
            }
        } finally {
            pending.cancel(handle)
        }
    } finally {
        pending.releaseGatewayDial()
    }
}
