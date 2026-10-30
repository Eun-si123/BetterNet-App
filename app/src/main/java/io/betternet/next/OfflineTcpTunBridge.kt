package io.betternet.next

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress

/**
 * Dormant single-flow integration seam: one TUN datagram at a time, through an
 * already authenticated CONNECT byte stream, and back to the TUN packet sink.
 * The caller must own gateway authentication, VPN consent, socket protection,
 * packet-pump serialization and read timeouts. Supply onClose to release the
 * caller-owned gateway socket on terminal TUN/flow failure.
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
                            if (started || ingress.header.destination != allowedDestination) null
                            else tcp.begin(ingress, serverIsn, mtu, nowMillis,
                                clientWindow)?.also { started = true }
                        }
                        flags == 0x10 && tcp.acceptFinalAck(ingress, nowMillis) -> null
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
    private fun retireIfFlowEnded(nowMillis: Long) {
        if (started && !tcp.hasLiveFlow(nowMillis)) close()
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

    /** Terminal, idempotent cleanup. The caller supplies stream/socket closure. */
    fun close() {
        if (closed) return
        closed = true
        tcp.close()
        onClose?.invoke()
    }
}
