package io.betternet.next

import java.io.InputStream
import java.io.OutputStream

/**
 * Dormant single-flow integration seam: one TUN datagram at a time, through an
 * already authenticated CONNECT byte stream, and back to the TUN packet sink.
 * The caller must own gateway authentication, VPN consent, socket protection,
 * packet-pump serialization, read timeouts and closing both streams.
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
) {
    private val tcp = OfflineTcpHandshake()
    // The supplied ISN is single-use. A replacement flow needs a new bridge
    // with a fresh unpredictable ISN, never a replayable SYN-ACK sequence.
    private var started = false

    init {
        require(mtu in 1280..9000)
        require(serverIsn in 0..0xffff_ffffL)
        require(clientWindow in 1..1024)
    }

    /** Returns false only on TUN EOF. Rejected frames never reach the gateway. */
    fun pumpOneTunPacket(tunInput: InputStream, tunOutput: OutputStream, nowMillis: Long): Boolean {
        try {
            when (val ingress = readOneTunDatagram(tunInput, mtu)) {
                TunIngressResult.EndOfStream -> return false
                TunIngressResult.Rejected -> return true
                is TunIngressResult.Packet -> {
                    val packet = ingress.bytes
                    val offset = ingress.header.transportOffset
                    if (ingress.header.protocol != 6) return true
                    val flags = packet[offset + 13].toInt() and 0xff
                    val reply = when {
                        flags == 0x02 -> {
                            if (started) null else tcp.begin(ingress, serverIsn, mtu, nowMillis,
                                clientWindow)?.also { started = true }
                        }
                        flags == 0x10 && tcp.acceptFinalAck(ingress, nowMillis) -> null
                        flags == 0x14 -> { tcp.acceptClientReset(ingress, nowMillis); null }
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
            return true
        } catch (failure: Exception) {
            tcp.close() // No stale ACK/retry state after an uncertain write.
            throw failure
        }
    }

    /** May block; caller must provide a bounded tunnel read timeout and a ready flow. */
    fun pumpOneGatewayReply(tunOutput: OutputStream, nowMillis: Long): Boolean =
        emit(tunOutput) { tcp.readTunnelResponse(tunnelInput, mtu, nowMillis) }

    /** Retransmit only the exact previously emitted packet after its deadline. */
    fun pumpPendingRetry(tunOutput: OutputStream, nowMillis: Long): Boolean =
        emit(tunOutput) { tcp.retryPendingResponse(nowMillis) }

    private fun emit(tunOutput: OutputStream, packet: () -> ByteArray?): Boolean {
        try {
            val bytes = packet() ?: return false
            writeTun(tunOutput, bytes)
            return true
        } catch (failure: Exception) {
            tcp.close()
            throw failure
        }
    }

    private fun writeTun(output: OutputStream, packet: ByteArray) {
        output.write(packet)
        output.flush()
    }

    fun close() = tcp.close()
}
