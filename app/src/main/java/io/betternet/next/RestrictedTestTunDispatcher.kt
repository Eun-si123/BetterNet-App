package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

/**
 * Dormant, single-threaded packet dispatcher for one selected-app test TUN.
 * The caller owns OS consent, the TUN descriptor, protected/bound TLS sockets,
 * gateway credentials, and serialized scheduling. Neither callback may use a
 * network path unless its own authentication and authorization gates pass.
 *
 * The DNS callback must write a correlated, approved reply to the TUN before
 * returning its binding; the TCP callback must create an authenticated CONNECT
 * bridge and deliver the initial SYN-ACK before returning. No Android service
 * invokes this class, and this class never activates a VPN or opens a socket.
 */
internal class RestrictedTestTunDispatcher(
    private val plan: RestrictedTestTunPlan,
    private val exchangeDns: (TunIngressResult.Packet, OutputStream) -> DnsDestinationBinding?,
    private val connectTcp: (DnsDestinationBinding, TunIngressResult.Packet, OutputStream, Long) -> OfflineTcpTunBridge,
) : Closeable {
    private var closed = false
    private var binding: DnsDestinationBinding? = null
    private var bridge: OfflineTcpTunBridge? = null

    /**
     * Called even when a bounded TUN poll finds no datagram. Otherwise a
     * quiescent TUN can retain an expired authenticated gateway indefinitely.
     * All dispatcher calls remain serialized on the session owner thread.
     */
    fun expireIdleFlow(nowMillis: Long) {
        if (!closed && bridge?.retireIfFlowEnded(nowMillis) == true) bridge = null
    }

    /** Returns false on EOF or terminal failure; rejected packets have no side effects. */
    fun pumpOneTunPacket(input: InputStream, output: OutputStream, nowMillis: Long): Boolean {
        if (closed) return false
        try {
            // Even unrelated/unsupported packets must not prolong an expired
            // authenticated gateway lease or prevent its socket from closing.
            expireIdleFlow(nowMillis)
            val ingress = readOneTunDatagram(input, plan.mtu)
            if (ingress === TunIngressResult.EndOfStream) {
                close()
                return false
            }
            if (ingress !is TunIngressResult.Packet) return true
            val h = ingress.header
            // Exact source and route checks precede either callback, including
            // gateway credential use. No default route or unrelated app fallback.
            if (h.source != plan.clientAddress) return true
            when {
                h.protocol == 17 && h.destination == plan.virtualDnsAddress &&
                    h.destinationPort == 53 && bridge == null -> {
                    // A failed or rejected new DNS query cannot retain an old grant.
                    binding = null
                    val approved = exchangeDns(ingress, output)
                    if (approved?.address == plan.allowedHttpsAddress) binding = approved
                }
                h.protocol == 6 && h.destination == plan.allowedHttpsAddress &&
                    h.destinationPort == 443 -> {
                    val active = bridge
                    if (active != null) {
                        if (!active.pumpOneTunPacket(ByteArrayInputStream(ingress.bytes), output, nowMillis)) {
                            active.close()
                            bridge = null
                        }
                    } else {
                        val approved = binding
                        if (approved != null && approved.allows(ingress, nowMillis)) {
                            // Single use even if the CONNECT dial fails.
                            binding = null
                            bridge = connectTcp(approved, ingress, output, nowMillis)
                        }
                    }
                }
            }
            return true
        } catch (failure: Exception) {
            try { close() } catch (closeFailure: Exception) { failure.addSuppressed(closeFailure) }
            throw failure
        }
    }

    /** Caller must schedule bounded gateway reads, not block the TUN reader indefinitely. */
    fun pumpOneGatewayReply(output: OutputStream, nowMillis: Long): Boolean = try {
        if (!closed) bridge?.pumpOneGatewayReply(output, nowMillis) ?: false else false
    } catch (failure: Exception) {
        try { close() } catch (closeFailure: Exception) { failure.addSuppressed(closeFailure) }
        throw failure
    }

    fun pumpPendingRetry(output: OutputStream, nowMillis: Long): Boolean = try {
        if (!closed) bridge?.pumpPendingRetry(output, nowMillis) ?: false else false
    } catch (failure: Exception) {
        try { close() } catch (closeFailure: Exception) { failure.addSuppressed(closeFailure) }
        throw failure
    }

    override fun close() {
        if (closed) return
        closed = true
        binding = null
        val active = bridge
        bridge = null
        active?.close()
    }
}
