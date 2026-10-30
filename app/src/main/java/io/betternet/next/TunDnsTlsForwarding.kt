package io.betternet.next

import java.io.OutputStream
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
        exchangeRegisteredTunDnsQuery(tls, snapshot, handle, pending, output, mtu, timeoutMs)
    } finally {
        pending.cancel(handle)
    }
}

/** Shared exchange path; registration must already be complete before network I/O. */
private fun exchangeRegisteredTunDnsQuery(
    tls: SSLSocket,
    snapshot: TunIngressResult.Packet,
    handle: Long,
    pending: PendingDnsReplies,
    output: OutputStream,
    mtu: Int,
    timeoutMs: Int,
): Boolean {
    val header = parseTunPacketHeader(snapshot.bytes, snapshot.bytes.size) ?: return false
    val query = snapshot.bytes.copyOfRange(header.transportOffset + 8, snapshot.bytes.size)
    val response = exchangeOneDnsMessageOverTls(tls, query, timeoutMs)
    val reply = pending.consume(handle, response, mtu) ?: return false
    // Never retry an uncertain partial TUN write.
    output.write(reply)
    return true
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
): Boolean {
    require(mtu in 1280..9000) { "TUN MTU must be bounded" }
    require(timeoutMs in 1..10_000) { "DNS timeout must be bounded" }
    // Reserve both a pending reply and a live-dial lease BEFORE any socket or
    // credential use. A reply TTL cannot free an in-progress dial lease.
    if (!pending.reserveGatewayDial()) return false
    try {
        val snapshot = request.copy(bytes = request.bytes.clone())
        val handle = pending.register(snapshot) ?: return false
        try {
            val tls = connectVerifiedDestinationTlsThroughGateway(
                gatewayAddress, gatewayName, dnsServerName, 853, bearerToken,
                timeoutMs, protect, gatewayTlsFactory, destinationTlsFactory, bind
            )
            return tls.use {
                exchangeRegisteredTunDnsQuery(it, snapshot, handle, pending, output, mtu, timeoutMs)
            }
        } finally {
            pending.cancel(handle)
        }
    } finally {
        pending.releaseGatewayDial()
    }
}
