package io.betternet.next

/**
 * Bounded, offline handshake bookkeeping for exactly one TCP/443 TUN flow.
 * This does not open a socket, establish a VPN, or forward application bytes.
 * The SYN-ACK deliberately advertises a zero receive window: a later flow
 * controller must be reviewed before accepting payload or advertising space.
 * Caller supplies a fresh unpredictable server ISN and monotonic time.
 */
internal class OfflineTcpHandshake(private val lifetimeMillis: Long = 15_000L) {
    init { require(lifetimeMillis in 1..60_000L) }

    private data class Flow(
        val source: java.net.InetAddress,
        val destination: java.net.InetAddress,
        val sourcePort: Int,
        val destinationPort: Int,
        val clientNext: Long,
        val serverNext: Long,
        val startedAt: Long,
    )

    private var flow: Flow? = null
    private var acked = false
    private var pendingResponseBytes = 0

    fun begin(syn: TunIngressResult.Packet, serverIsn: Long, mtu: Int, nowMillis: Long): ByteArray? {
        if (nowMillis < 0) return null
        expire(nowMillis)
        if (flow != null) return null // One flow, no duplicate SYN-ACK or replacement.
        val synAck = buildTcpSynAck(syn, serverIsn, mtu) ?: return null
        // Never trust the caller-supplied header; the builder already validated
        // the complete packet and its checksum, so parse the same bytes again.
        val header = parseTunPacketHeader(syn.bytes, syn.bytes.size) ?: return null
        val offset = header.transportOffset
        flow = Flow(
            header.source, header.destination, header.sourcePort, header.destinationPort,
            (read32(syn.bytes, offset + 4) + 1) and 0xffff_ffffL,
            (serverIsn + 1) and 0xffff_ffffL, nowMillis,
        )
        acked = false
        pendingResponseBytes = 0
        return synAck
    }

    /** Accept only the exact, payload-free third handshake ACK. */
    fun acceptFinalAck(packet: TunIngressResult.Packet, nowMillis: Long): Boolean {
        expire(nowMillis)
        val expected = flow ?: return false
        if (acked) return false
        val bytes = packet.bytes
        val header = parseTunPacketHeader(bytes, bytes.size) ?: return false
        if (header.protocol != 6 || header.source != expected.source ||
            header.destination != expected.destination ||
            header.sourcePort != expected.sourcePort ||
            header.destinationPort != expected.destinationPort ||
            header.transportHeaderBytes != 20 ||
            header.transportOffset + 20 != bytes.size) return false
        val offset = header.transportOffset
        if ((bytes[offset + 12].toInt() and 15) != 0 ||
            (bytes[offset + 13].toInt() and 255) != 0x10 ||
            read16(bytes, offset + 18) != 0 ||
            read32(bytes, offset + 4) != expected.clientNext ||
            read32(bytes, offset + 8) != expected.serverNext) return false
        acked = true
        return true
    }

    /**
     * Prepare at most one bounded outbound TCP data segment after the handshake.
     * A future gateway controller must own delivery/retransmission before use.
     * The receive window remains zero; client application bytes are NOT accepted.
     */
    fun offerResponse(payload: ByteArray, mtu: Int, nowMillis: Long): ByteArray? {
        expire(nowMillis)
        val current = flow ?: return null
        if (!acked || pendingResponseBytes != 0) return null
        val reply = buildTcpDataReply(
            current.destination, current.source,
            current.destinationPort, current.sourcePort,
            current.serverNext, current.clientNext, payload, mtu,
        ) ?: return null
        pendingResponseBytes = payload.size
        return reply
    }

    /** Advance the server sequence only on an exact, checksummed peer ACK. */
    fun acceptResponseAck(packet: TunIngressResult.Packet, nowMillis: Long): Boolean {
        expire(nowMillis)
        val current = flow ?: return false
        if (!acked || pendingResponseBytes == 0) return false
        val bytes = packet.bytes
        val header = parseTunPacketHeader(bytes, bytes.size) ?: return false
        if (header.protocol != 6 || header.source != current.source ||
            header.destination != current.destination ||
            header.sourcePort != current.sourcePort ||
            header.destinationPort != current.destinationPort ||
            header.transportHeaderBytes != 20 ||
            header.transportOffset + 20 != bytes.size) return false
        val offset = header.transportOffset
        if ((bytes[offset + 12].toInt() and 15) != 0 ||
            (bytes[offset + 13].toInt() and 255) != 0x10 ||
            read16(bytes, offset + 18) != 0 ||
            read32(bytes, offset + 4) != current.clientNext ||
            read32(bytes, offset + 8) !=
                ((current.serverNext + pendingResponseBytes) and 0xffff_ffffL)) return false
        flow = current.copy(serverNext = (current.serverNext + pendingResponseBytes) and 0xffff_ffffL)
        pendingResponseBytes = 0
        return true
    }

    fun isEstablished(nowMillis: Long): Boolean {
        expire(nowMillis)
        return acked
    }

    fun close() {
        flow = null
        acked = false
        pendingResponseBytes = 0
    }

    private fun expire(nowMillis: Long) {
        val current = flow ?: return
        // Negative or non-monotonic time is not a reason to extend a lease.
        if (nowMillis < current.startedAt || nowMillis - current.startedAt >= lifetimeMillis) close()
    }

    private fun read16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 255) shl 8) or (bytes[at + 1].toInt() and 255)

    private fun read32(bytes: ByteArray, at: Int): Long =
        (read16(bytes, at).toLong() shl 16) or read16(bytes, at + 2).toLong()
}
