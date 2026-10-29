package io.betternet.next

import java.io.InputStream
import java.io.IOException
import java.io.OutputStream

/**
 * Bounded, offline handshake bookkeeping for exactly one TCP/443 TUN flow.
 * This does not open a socket or establish a VPN. The caller must supply a
 * previously authenticated, protected CONNECT stream before forwarding bytes.
 * The SYN-ACK defaults to a zero receive window. A caller may explicitly opt
 * into a maximum 1024-byte, one-segment offline staging window; it may
 * reopen the same bounded window only after a successful tunnel write/flush.
 * That is local acceptance, NOT proof of remote delivery.
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
    private var pendingResponsePacket: ByteArray? = null
    private var responseSentAt = -1L
    private var responseRetries = 0
    private var pendingClientPayload: ByteArray? = null
    private var receiveWindow = 0
    private var lastSeenAt = -1L

    fun begin(syn: TunIngressResult.Packet, serverIsn: Long, mtu: Int, nowMillis: Long,
              clientWindow: Int = 0): ByteArray? {
        if (nowMillis < 0) return null
        expire(nowMillis)
        if (flow != null) return null // One flow, no duplicate SYN-ACK or replacement.
        if (clientWindow !in 0..1024) return null
        val synAck = buildTcpSynAck(syn, serverIsn, mtu, clientWindow) ?: return null
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
        pendingResponsePacket = null
        responseSentAt = -1L
        responseRetries = 0
        pendingClientPayload = null
        receiveWindow = clientWindow
        lastSeenAt = nowMillis
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
     * Stage exactly one in-order client payload without acknowledging it.
     * The returned bytes are a defensive copy; only forwardStagedClientPayload
     * can advance the ACK after a successful write to a caller-owned stream.
     */
    fun stageClientPayload(packet: TunIngressResult.Packet, nowMillis: Long): ByteArray? {
        expire(nowMillis)
        val current = flow ?: return null
        if (!acked || receiveWindow == 0 || pendingClientPayload != null) return null
        val bytes = packet.bytes
        val header = parseTunPacketHeader(bytes, bytes.size) ?: return null
        if (header.protocol != 6 || header.source != current.source ||
            header.destination != current.destination ||
            header.sourcePort != current.sourcePort ||
            header.destinationPort != current.destinationPort ||
            header.transportHeaderBytes != 20) return null
        val offset = header.transportOffset
        val count = bytes.size - offset - 20
        val flags = bytes[offset + 13].toInt() and 255
        if (count !in 1..receiveWindow ||
            (bytes[offset + 12].toInt() and 15) != 0 ||
            (flags != 0x10 && flags != 0x18) ||
            read16(bytes, offset + 18) != 0 ||
            read32(bytes, offset + 4) != current.clientNext ||
            read32(bytes, offset + 8) != current.serverNext ||
            pendingResponseBytes != 0) return null
        val staged = bytes.copyOfRange(offset + 20, bytes.size)
        pendingClientPayload = staged
        return staged.copyOf()
    }

    /**
     * Forward one staged segment to a caller-provided authenticated CONNECT
     * tunnel's raw output stream (NOT a separately terminated destination TLS
     * socket). Only then emit an ACK. A successful write/flush is local transport
     * acceptance, not proof that the destination received the bytes.
     *
     * If the write or flush fails, the segment may have been partly transmitted:
     * close the stream and discard the flow instead of risking a duplicate write.
     * The caller still owns closing the associated tunnel on normal completion.
     * nextReceiveWindow is explicitly opt-in: only reopen the bounded client
     * window if the authenticated stream is ready for another segment.
     */
    fun forwardStagedClientPayload(
        tunnelOutput: OutputStream, nowMillis: Long, nextReceiveWindow: Int = 0,
    ): ByteArray? {
        require(nextReceiveWindow in 0..1024) { "Receive window must be bounded" }
        expire(nowMillis)
        val current = flow ?: return null
        val payload = pendingClientPayload ?: return null
        val next = (current.clientNext + payload.size) and 0xffff_ffffL
        val ack = buildTcpDeliveryAck(
            current.destination, current.source,
            current.destinationPort, current.sourcePort,
            current.serverNext, next, nextReceiveWindow,
        ) ?: return null
        try {
            tunnelOutput.write(payload)
            tunnelOutput.flush()
        } catch (failure: Exception) {
            close()
            try { tunnelOutput.close() } catch (closeFailure: Exception) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
        flow = current.copy(clientNext = next)
        pendingClientPayload = null
        receiveWindow = nextReceiveWindow
        return ack
    }

    /**
     * Prepare at most one bounded outbound TCP data segment after the handshake.
     * A future gateway controller must own delivery/retransmission before use.
     * Client application bytes are only accepted when a bounded window was
     * explicitly advertised by the caller after a successful tunnel write.
     */
    fun offerResponse(payload: ByteArray, mtu: Int, nowMillis: Long): ByteArray? {
        expire(nowMillis)
        val current = flow ?: return null
        if (!acked || pendingResponseBytes != 0 || pendingClientPayload != null) return null
        val reply = buildTcpDataReply(
            current.destination, current.source,
            current.destinationPort, current.sourcePort,
            current.serverNext, current.clientNext, payload, mtu,
        ) ?: return null
        pendingResponseBytes = payload.size
        pendingResponsePacket = reply.copyOf()
        responseSentAt = nowMillis
        responseRetries = 0
        return reply
    }

    /**
     * Reissue only the exact unacknowledged server segment. A caller must
     * serialize writes to TUN and schedule retries using monotonic time.
     * Exponential backoff (500/1000/2000 ms), three retries maximum; never
     * reread the gateway stream or advance the server sequence on a retry.
     * The fixed flow lease still bounds total lifetime.
     */
    fun retryPendingResponse(nowMillis: Long): ByteArray? {
        expire(nowMillis)
        if (!acked || pendingResponseBytes == 0 || responseRetries >= 3) return null
        val packet = pendingResponsePacket ?: return null
        val delayMillis = 500L shl responseRetries
        if (nowMillis - responseSentAt < delayMillis) return null
        responseRetries++
        responseSentAt = nowMillis
        return packet.copyOf()
    }

    /**
     * Read at most one MTU-sized segment from a caller-owned, authenticated
     * CONNECT tunnel and prepare its TUN reply. Never consume stream bytes if
     * the flow cannot accept another unacknowledged response segment.
     *
     * The caller must configure a bounded socket read timeout and serialize
     * access to this offline flow. EOF or a read failure retires the flow; a
     * zero-byte read does not advance it. No VPN or socket is created here.
     */
    fun readTunnelResponse(tunnelInput: InputStream, mtu: Int, nowMillis: Long): ByteArray? {
        require(mtu in 1280..9000) { "TUN MTU must support IPv6 and be bounded" }
        expire(nowMillis)
        val current = flow ?: return null
        if (!acked || pendingResponseBytes != 0 || pendingClientPayload != null) return null
        val ipBytes = if (current.source.address.size == 4) 20 else 40
        val buffer = ByteArray(minOf(1460, mtu - ipBytes - 20))
        val read = try {
            tunnelInput.read(buffer, 0, buffer.size)
        } catch (failure: IOException) {
            close()
            try { tunnelInput.close() } catch (closeFailure: IOException) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
        if (read < 0) {
            close()
            tunnelInput.close()
            return null
        }
        if (read == 0) return null
        return offerResponse(buffer.copyOf(read), mtu, nowMillis)
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
        pendingResponsePacket = null
        responseSentAt = -1L
        responseRetries = 0
        return true
    }

    /**
     * Retire only an exact, checksummed client RST for the established tuple.
     * A forged/stale RST must not discard a live flow. No RST is generated or
     * sent to the network by this offline controller.
     */
    fun acceptClientReset(packet: TunIngressResult.Packet, nowMillis: Long): Boolean {
        expire(nowMillis)
        val current = flow ?: return false
        if (!acked) return false
        val bytes = packet.bytes
        val header = parseTunPacketHeader(bytes, bytes.size) ?: return false
        if (header.protocol != 6 || header.source != current.source ||
            header.destination != current.destination ||
            header.sourcePort != current.sourcePort ||
            header.destinationPort != current.destinationPort ||
            header.transportHeaderBytes != 20 ||
            header.transportOffset + 20 != bytes.size) return false
        val offset = header.transportOffset
        val flags = bytes[offset + 13].toInt() and 255
        val acknowledgement = read32(bytes, offset + 8)
        val expectedPendingAck = (current.serverNext + pendingResponseBytes) and 0xffff_ffffL
        if ((bytes[offset + 12].toInt() and 15) != 0 ||
            read16(bytes, offset + 18) != 0 ||
            flags != 0x14 || // RST | ACK; no SYN/FIN/PSH/ECN/NS.
            read32(bytes, offset + 4) != current.clientNext ||
            (acknowledgement != current.serverNext &&
                acknowledgement != expectedPendingAck)) return false
        close()
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
        pendingResponsePacket = null
        responseSentAt = -1L
        responseRetries = 0
        pendingClientPayload = null
        receiveWindow = 0
        lastSeenAt = -1L
    }

    private fun expire(nowMillis: Long) {
        val current = flow ?: return
        // Reject rollback relative to the most recent operation, not merely
        // the initial SYN. The lease also has a fixed absolute deadline.
        if (nowMillis < lastSeenAt || nowMillis - current.startedAt >= lifetimeMillis) {
            close()
        } else {
            lastSeenAt = nowMillis
        }
    }

    private fun read16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 255) shl 8) or (bytes[at + 1].toInt() and 255)

    private fun read32(bytes: ByteArray, at: Int): Long =
        (read16(bytes, at).toLong() shl 16) or read16(bytes, at + 2).toLong()
}
