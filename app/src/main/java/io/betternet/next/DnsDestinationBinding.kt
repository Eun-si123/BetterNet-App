package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocketFactory

/**
 * One short-lived A/AAAA mapping for a restricted test destination. This is
 * NOT a DNS resolver or proof of upstream authenticity: the caller must obtain
 * the reply from the independently verified DNS-over-TLS CONNECT path and
 * correlate it to the original selected-app TUN query before invoking this.
 * The permitted test IP must come from an independent owner-approved allowlist,
 * NEVER from the same untrusted DNS answer being checked.
 *
 * Reject CNAMEs, multiple answers, compression beyond a pointer to the
 * question, and extra records for now. Unsupported legitimate DNS answers
 * fail closed rather than silently authorizing an unrelated TCP destination.
 */
internal class DnsDestinationBinding private constructor(
    val hostname: String,
    val address: InetAddress,
    private val createdAtMillis: Long,
    private val ttlMillis: Long,
) {
    fun allows(syn: TunIngressResult.Packet, nowMillis: Long): Boolean {
        val header = parseTunPacketHeader(syn.bytes, syn.bytes.size) ?: return false
        if (header.protocol != 6 || header.destinationPort != 443 ||
            header.destination != address || nowMillis < createdAtMillis ||
            nowMillis - createdAtMillis >= ttlMillis) return false
        val offset = header.transportOffset
        return (syn.bytes[offset + 13].toInt() and 0xff) == 0x02
    }

    companion object {
        fun fromCorrelatedResponse(
            query: ByteArray, response: ByteArray, expectedHost: String,
            allowedTestAddress: InetAddress, nowMillis: Long,
        ): DnsDestinationBinding? {
            if (!isValidGatewayName(expectedHost) || nowMillis < 0 ||
                !isSupportedDnsQueryMessage(query) || response.size !in 17..1232 ||
                !hasMatchingDnsQuestion(query, 0, query.size, response)) return null
            fun u16(bytes: ByteArray, offset: Int): Int =
                ((bytes[offset].toInt() and 255) shl 8) or (bytes[offset + 1].toInt() and 255)
            if (u16(response, 6) != 1 || u16(response, 8) != 0 || u16(response, 10) != 0 ||
                (response[3].toInt() and 0x0f) != 0) return null
            var at = 12
            val labels = mutableListOf<String>()
            while (at < query.size) {
                val size = query[at++].toInt() and 255
                if (size == 0) break
                if (size !in 1..63 || at + size > query.size) return null
                val label = query.copyOfRange(at, at + size).toString(Charsets.US_ASCII)
                if (!label.all { it in 'a'..'z' || it in 'A'..'Z' ||
                    it in '0'..'9' || it == '-' }) return null
                labels.add(label)
                at += size
            }
            val questionNameEnd = at
            if (labels.joinToString(".").lowercase() != expectedHost.lowercase() ||
                at + 4 > query.size) return null
            val type = u16(query, at)
            if (type != 1 && type != 28) return null
            at += 4
            // Only an answer pointing to the exact question name is supported.
            if (at + 2 > response.size || u16(response, at) != 0xc00c) return null
            at += 2
            if (at + 10 > response.size || u16(response, at) != type ||
                u16(response, at + 2) != 1) return null
            val ttl = ((response[at + 4].toLong() and 255) shl 24) or
                ((response[at + 5].toLong() and 255) shl 16) or
                ((response[at + 6].toLong() and 255) shl 8) or
                (response[at + 7].toLong() and 255)
            val length = u16(response, at + 8)
            at += 10
            if (ttl == 0L || length != (if (type == 1) 4 else 16) ||
                at + length != response.size) return null
            // The query question was uncompressed and echoed byte-for-byte.
            if (questionNameEnd < 13) return null
            val resolvedAddress = InetAddress.getByAddress(response.copyOfRange(at, at + length))
            // A compromised or misconfigured resolver must not turn the test
            // gateway into an arbitrary destination or private-network proxy.
            if (resolvedAddress != allowedTestAddress) return null
            return DnsDestinationBinding(expectedHost.lowercase(), resolvedAddress,
                nowMillis, minOf(ttl, 60L) * 1000L)
        }
    }
}

/**
 * Preflight an explicitly approved test DNS question BEFORE resolving or
 * authenticating to a gateway. A syntactically valid query for another host
 * must not leak through the selected-app tunnel just because the response
 * would later fail destination authorization.
 *
 * The DNS question type follows the independently approved destination IP,
 * not the TUN IP family (IPv6 apps can legitimately ask for A records).
 */
internal fun isApprovedTestDnsQuestion(
    query: ByteArray, expectedHost: String, allowedTestAddress: InetAddress,
): Boolean {
    if (!isValidGatewayName(expectedHost) || !isSupportedDnsQueryMessage(query)) return false
    var at = 12
    for (label in expectedHost.split('.')) {
        if (at >= query.size || (query[at].toInt() and 255) != label.length) return false
        at++
        for (character in label) {
            if (at >= query.size ||
                (query[at++].toInt() and 255).toChar().lowercaseChar() != character.lowercaseChar()) {
                return false
            }
        }
    }
    if (at + 5 > query.size || query[at++] != 0.toByte()) return false
    val questionType = ((query[at].toInt() and 255) shl 8) or
        (query[at + 1].toInt() and 255)
    val approvedType = if (allowedTestAddress.address.size == 4) 1 else 28
    return questionType == approvedType &&
        query[at + 2] == 0.toByte() && query[at + 3] == 1.toByte()
}

/**
 * Dormant A1 composition. A DNS-correlated IP and a matching, validated SYN
 * must be present BEFORE the bearer credential or gateway socket is used.
 * CONNECT pins the numeric DNS-authorized IP, not a second hostname lookup.
 * This does not prove that a remote gateway enforces its requested target.
 * The caller still owns OS consent, single-app TUN scope and pump scheduling.
 * The initial SYN is already consumed by the TUN dispatcher; after CONNECT
 * succeeds, emit its SYN-ACK here so the first packet is never silently lost.
 * If the TUN write fails, close the authenticated tunnel immediately.
 */
internal fun connectDnsBoundTestTcpBridge(
    binding: DnsDestinationBinding,
    syn: TunIngressResult.Packet,
    nowMillis: Long,
    tunOutput: OutputStream,
    gatewayAddress: InetSocketAddress,
    gatewayName: String,
    bearerToken: String,
    timeoutMs: Int,
    mtu: Int,
    serverIsn: Long,
    protect: (Socket) -> Boolean,
    tlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    bind: (Socket) -> Unit = {},
): OfflineTcpTunBridge {
    require(binding.allows(syn, nowMillis) &&
        buildTcpSynAck(syn, serverIsn, mtu) != null) {
        "A fresh authorized TCP SYN is required before gateway access"
    }
    val tunnel = connectAuthenticatedPinnedIpTestTunnel(
        gatewayAddress, gatewayName, timeoutMs, protect, binding.address, 443,
        bearerToken, tlsFactory = tlsFactory, bind = bind
    )
    return try {
        // CONNECT has its own whole-response deadline. Once authenticated,
        // a long gateway read must not starve TUN ACKs, retries or cancellation.
        // A read timeout means "no bytes yet", not EOF or a second CONNECT.
        tunnel.soTimeout = 200
        val bridge = OfflineTcpTunBridge(tunnel.inputStream, tunnel.outputStream, mtu, serverIsn,
            allowedDestination = binding.address, onClose = { tunnel.close() })
        check(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tunOutput, nowMillis)) {
            "Initial authorized SYN could not start the bridge"
        }
        bridge
    } catch (failure: Throwable) {
        try { tunnel.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
        throw failure
    }
}
