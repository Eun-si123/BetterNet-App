package io.betternet.next

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress

/**
 * Dormant single-flow integration seam: one TUN datagram at a time, through an
 * already authenticated CONNECT byte stream, and back to the TUN packet sink.
 * The caller must own gateway authentication, VPN consent, socket protection,
 * packet-pump serialization and read timeouts. Supply onClose to release the
 * caller-owned gateway socket on terminal TUN/flow failure. Without onClose,
 * the bridge closes both provided streams rather than leaking them.
 * The allowed destination IP must be resolved and authorized independently
 * before creating the CONNECT tunnel; only its TCP/443 flow can use it.
 *
 * This class NEVER opens a VPN, connects to a network, or selects an app.
 * Do not activate it until those boundaries and safe FIN handling are wired.
 */
internal class OfflineTcpTunBridge(
    private val tunnelInput: InputStream,
    private val tunnelOutput: OutputStream,
    private val mtu: Int,
    private val serverIsn: Long,
    private val clientWindow: Int = 1024,
    private val upstreamHalfClose: (() -> Unit)? = null,
    private val onClose: (() -> Unit)? = null,
    private val allowedDestination: InetAddress,
) {
    private val tcp = OfflineTcpHandshake()
    // The supplied ISN is single-use. A replacement flow needs a new bridge
    // with a fresh unpredictable ISN, never a replayable SYN-ACK sequence.
    private var started = false
    // Keep only the initial SYN transport bytes and checksummed SYN-ACK.
    // Retransmitted SYNs must never create a second authenticated CONNECT.
    private var initialSynSegment: ByteArray? = null
    private var initialSynHeader: TunPacketHeader? = null
    private var initialSynAck: ByteArray? = null
    private var lastSynAckAt = -1L
    private var synAckRetries = 0
    // Once the caller closes the bridge, TUN EOFs or a packet-pump failure
    // must never restart this single-use authenticated stream.
    private var closed = false

    init {
        require(mtu in 1280..9000)
        require(serverIsn in 0..0xffff_ffffL)
        require(clientWindow in 1..1024)
    }

    /** Returns false when TUN ends or the bridge is retired. Rejected frames never reach the gateway. */
    fun pumpOneTunPacket(tunInput: InputStream, tunOutput: OutputStream, nowMillis: Long): Boolean {
        if (closed) return false
        try {
            // Expire before reading: non-TCP packets take an early return below
            // and must not keep an authenticated gateway socket alive forever.
            retireIfFlowEnded(nowMillis)
            if (closed) return false
            when (val ingress = readOneTunDatagram(tunInput, mtu)) {
                TunIngressResult.EndOfStream -> { close(); return false }
                TunIngressResult.Rejected -> {
                    retireIfFlowEnded(nowMillis)
                    return true
                }
                is TunIngressResult.Packet -> {
                    val packet = ingress.bytes
                    val offset = ingress.header.transportOffset
                    if (ingress.header.protocol != 6) return true
                    val flags = packet[offset + 13].toInt() and 0xff
                    val reply = when {
                        flags == 0x02 -> {
                            if (!started) {
                                if (ingress.header.destination != allowedDestination) null
                                else tcp.begin(ingress, serverIsn, mtu, nowMillis,
                                    clientWindow)?.also {
                                    started = true
                                    initialSynSegment = packet.copyOfRange(offset, packet.size)
                                    initialSynHeader = ingress.header
                                    initialSynAck = it.copyOf()
                                    lastSynAckAt = nowMillis
                                }
                            } else retryInitialSynAck(ingress, nowMillis)
                        }
                        flags == 0x10 && tcp.acceptFinalAck(ingress, nowMillis) -> {
                            initialSynSegment = null
                            initialSynHeader = null
                            initialSynAck = null
                            null
                        }
                        flags == 0x14 -> {
                            if (tcp.acceptClientReset(ingress, nowMillis)) close()
                            null
                        }
                        flags == 0x11 && upstreamHalfClose != null ->
                            tcp.acceptClientFin(ingress, nowMillis, upstreamHalfClose)
                        else -> {
                            if (tcp.stageClientPayload(ingress, nowMillis) != null) {
                                tcp.forwardStagedClientPayload(tunnelOutput, nowMillis, clientWindow)
                            } else {
                                tcp.acknowledgeForwardedReplay(ingress, nowMillis)
                                    ?: run { tcp.acceptResponseAck(ingress, nowMillis); null }
                            }
                        }
                    }
                    if (reply != null) writeTun(tunOutput, reply)
                }
            }
            retireIfFlowEnded(nowMillis)
            return true
        } catch (failure: Exception) {
            try { close() } catch (closeFailure: Exception) { failure.addSuppressed(closeFailure) }
            throw failure
        }
    }

    /**
     * Recover from a lost SYN-ACK without another gateway dial. Only an
     * checksum-validated SYN for the original flow is eligible. A TCP timestamp
     * value may advance between SYN retransmissions; all other transport fields,
     * including the timestamp echo and option layout, must remain identical.
     * IPv4 packet IDs and hop limits may legitimately differ.
     * Three exponential-backoff retries fit inside the fixed 15s flow lease.
     */
    private fun retryInitialSynAck(packet: TunIngressResult.Packet, nowMillis: Long): ByteArray? {
        val initial = initialSynSegment ?: return null
        val original = initialSynHeader ?: return null
        val response = initialSynAck ?: return null
        // TCP checksum equality is not a substitute for checking the IP tuple:
        // compensating address changes can preserve the pseudo-header sum.
        if (packet.header.ipVersion != original.ipVersion ||
            packet.header.source != original.source ||
            packet.header.destination != original.destination ||
            packet.header.sourcePort != original.sourcePort ||
            packet.header.destinationPort != original.destinationPort) return null
        if (tcp.isEstablished(nowMillis) || synAckRetries >= 3) return null
        if (!sameSynWithUpdatedTimestamp(
                initial, packet.bytes.copyOfRange(packet.header.transportOffset, packet.bytes.size)
            )) return null
        val delay = 500L shl synAckRetries
        if (nowMillis < lastSynAckAt || nowMillis - lastSynAckAt < delay) return null
        synAckRetries++
        lastSynAckAt = nowMillis
        return response.copyOf()
    }

    /**
     * TCP timestamps can advance on a retransmitted SYN even though the flow
     * tuple, sequence and negotiated options have not changed. Both segments
     * have already passed the full IP/TCP checksum and SYN-option validators.
     * Ignore only the TCP checksum and TSval (not TSecr); do not permit any
     * changes to MSS, window, flags, sequence or other option bytes.
     */
    private fun sameSynWithUpdatedTimestamp(original: ByteArray, candidate: ByteArray): Boolean {
        if (original.size != candidate.size || original.size < 20) return false
        val expected = original.copyOf()
        val actual = candidate.copyOf()
        for (at in 16..17) {
            expected[at] = 0
            actual[at] = 0
        }
        var at = 20
        while (at < expected.size) {
            when (val kind = expected[at].toInt() and 255) {
                0 -> break
                1 -> at++
                else -> {
                    if (at + 2 > expected.size) return false
                    val size = expected[at + 1].toInt() and 255
                    if (size < 2 || size > expected.size - at) return false
                    if (kind == 8 && size == 10) {
                        for (i in at + 2 until at + 6) {
                            expected[i] = 0
                            actual[i] = 0
                        }
                    }
                    at += size
                }
            }
        }
        return expected.contentEquals(actual)
    }

    /** May block; caller must provide a bounded tunnel read timeout and a ready flow. */
    fun pumpOneGatewayReply(tunOutput: OutputStream, nowMillis: Long): Boolean {
        if (closed) return false
        val emitted = emit(tunOutput) { tcp.readTunnelResponse(tunnelInput, mtu, nowMillis) }
        retireIfFlowEnded(nowMillis)
        return emitted
    }

    /** Retransmit only the exact previously emitted packet after its deadline. */
    fun pumpPendingRetry(tunOutput: OutputStream, nowMillis: Long): Boolean {
        if (closed) return false
        val emitted = emit(tunOutput) { tcp.retryPendingResponse(nowMillis) }
        retireIfFlowEnded(nowMillis)
        return emitted
    }

    /** Release the socket on a normal two-sided FIN or an expired flow lease. */
    internal fun retireIfFlowEnded(nowMillis: Long): Boolean {
        if (started && !tcp.hasLiveFlow(nowMillis)) close()
        return closed
    }

    private fun emit(tunOutput: OutputStream, packet: () -> ByteArray?): Boolean {
        try {
            val bytes = packet() ?: return false
            writeTun(tunOutput, bytes)
            return true
        } catch (failure: Exception) {
            try { close() } catch (closeFailure: Exception) { failure.addSuppressed(closeFailure) }
            throw failure
        }
    }

    private fun writeTun(output: OutputStream, packet: ByteArray) {
        output.write(packet)
        output.flush()
    }

    /** Terminal, idempotent cleanup. A supplied callback owns socket closure;
     * otherwise both stream handles are closed even if one close fails.
     */
    fun close() {
        if (closed) return
        closed = true
        initialSynSegment = null
        initialSynHeader = null
        initialSynAck = null
        tcp.close()
        if (onClose != null) {
            onClose.invoke()
            return
        }
        var firstFailure: Exception? = null
        try { tunnelInput.close() } catch (failure: Exception) { firstFailure = failure }
        try { tunnelOutput.close() } catch (failure: Exception) {
            if (firstFailure == null) firstFailure = failure
            else firstFailure.addSuppressed(failure)
        }
        if (firstFailure != null) throw firstFailure
    }
}
