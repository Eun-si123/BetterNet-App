package io.betternet.next

import java.io.IOException
import java.io.InputStream

/**
 * One bounded, read-only ingress step for a future packet-oriented Android TUN
 * descriptor. It must not be used on a TCP stream: a TUN read yields one IP
 * datagram, whereas stream reads can split or coalesce application data.
 *
 * This code neither opens a VPN nor forwards, logs, or transmits packets.
 */
internal sealed class TunIngressResult {
    data class Packet(val bytes: ByteArray, val header: TunPacketHeader) : TunIngressResult()
    object Rejected : TunIngressResult()
    object EndOfStream : TunIngressResult()
}

/**
 * Read at most one datagram, with one extra byte to detect oversize frames.
 * Distinguish EOF from invalid packets so a future pump can stop on shutdown.
 * A zero-byte read is an error, not a reason to spin in a tight loop.
 */
internal fun readOneTunDatagram(input: InputStream, mtu: Int): TunIngressResult {
    require(mtu in 1280..9000) { "TUN MTU must be bounded and support IPv6" }
    val buffer = ByteArray(mtu + 1)
    val count = input.read(buffer)
    if (count == -1) return TunIngressResult.EndOfStream
    if (count == 0) throw IOException("TUN read returned no packet")
    if (count > mtu) return TunIngressResult.Rejected
    val header = parseTunPacketHeader(buffer, count) ?: return TunIngressResult.Rejected
    return TunIngressResult.Packet(buffer.copyOf(count), header)
}
