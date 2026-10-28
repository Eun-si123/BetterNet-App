package io.betternet.next

import java.io.EOFException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLSocket

/**
 * One bounded DNS-over-TLS (RFC 7858) wire exchange over a caller-provided,
 * already certificate- and hostname-verified TLS socket. This is not a DNS
 * resolver, a VPN pump, or a gateway connection. In particular, the future
 * caller must establish the protected, authenticated gateway path separately
 * and correlate the returned message using PendingDnsReplies before TUN output.
 *
 * One query per socket: any error closes the socket to avoid framing desync.
 */
internal fun exchangeOneDnsMessageOverTls(
    tls: SSLSocket,
    query: ByteArray,
    timeoutMs: Int,
): ByteArray {
    try {
        require(timeoutMs in 1..10_000) { "DNS exchange timeout must be bounded" }
        require(query.size in 17..1232) { "DNS query size outside test budget" }
        require((query[2].toInt() and 0xfe) == 0 &&
            (query[3].toInt() and 0x4f) == 0 &&
            query[4] == 0.toByte() && query[5] == 1.toByte()) {
            "Only a standard single-question DNS query is supported"
        }
        require(tls.useClientMode && tls.sslParameters.endpointIdentificationAlgorithm == "HTTPS") {
            "DNS transport must use verified TLS endpoint identity"
        }
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        tls.outputStream.write(byteArrayOf((query.size ushr 8).toByte(), query.size.toByte()))
        tls.outputStream.write(query)
        tls.outputStream.flush()
        val lengthBytes = ByteArray(2)
        readExactDnsTls(tls, lengthBytes, deadline)
        val size = ((lengthBytes[0].toInt() and 255) shl 8) or (lengthBytes[1].toInt() and 255)
        if (size !in 17..1232) throw IOException("DNS-over-TLS response outside size budget")
        return ByteArray(size).also { readExactDnsTls(tls, it, deadline) }
    } catch (failure: Throwable) {
        try { tls.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
        throw failure
    }
}

private fun readExactDnsTls(tls: SSLSocket, bytes: ByteArray, deadline: Long) {
    var offset = 0
    while (offset < bytes.size) {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0) throw SocketTimeoutException("DNS-over-TLS response deadline exceeded")
        tls.soTimeout = ((remaining + 999_999L) / 1_000_000L).coerceIn(1L, 10_000L).toInt()
        val count = tls.inputStream.read(bytes, offset, bytes.size - offset)
        if (count < 0) throw EOFException("DNS-over-TLS response truncated")
        if (count == 0) throw IOException("DNS-over-TLS read returned zero bytes")
        offset += count
    }
    if (System.nanoTime() - deadline >= 0) {
        throw SocketTimeoutException("DNS-over-TLS response deadline exceeded")
    }
}
