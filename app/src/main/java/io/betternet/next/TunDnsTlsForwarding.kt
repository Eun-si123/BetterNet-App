package io.betternet.next

import java.io.OutputStream
import javax.net.ssl.SSLSocket

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
    // Own the query bytes before registering or sending: the TUN read buffer
    // can be reused or mutated by its caller on another thread.
    val snapshot = request.copy(bytes = request.bytes.clone())
    val handle = pending.register(snapshot) ?: return@use false
    try {
        val header = parseTunPacketHeader(snapshot.bytes, snapshot.bytes.size)
            ?: return@use false
        val query = snapshot.bytes.copyOfRange(header.transportOffset + 8, snapshot.bytes.size)
        val response = exchangeOneDnsMessageOverTls(tls, query, timeoutMs)
        val reply = pending.consume(handle, response, mtu) ?: return@use false
        // One datagram, one write; do not retry an uncertain partial write.
        output.write(reply)
        true
    } finally {
        // Release capacity even on TLS failure, rejection or output I/O error.
        pending.cancel(handle)
    }
}
