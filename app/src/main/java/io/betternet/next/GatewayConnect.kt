package io.betternet.next

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Dormant restricted HTTP/1.1 CONNECT test client. This single entry point
 * protects the socket, verifies the gateway TLS identity, then authenticates
 * with a bearer credential. No Android activity or VPN service calls it yet.
 * It does not provide a gateway server, DNS, TUN or general Internet routing.
 */
internal fun connectAuthenticatedTestTunnel(
    gatewayAddress: InetSocketAddress,
    gatewayName: String,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    destinationHost: String,
    destinationPort: Int,
    bearerToken: String,
    tlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    bind: (Socket) -> Unit = {},
): SSLSocket {
    // Fail before any socket creation on malformed destination or credential.
    require(isValidGatewayName(destinationHost)) { "Invalid test destination" }
    require(destinationPort in 1..65535) { "Invalid test port" }
    // Base64url opaque tokens only; never interpolate untrusted CR/LF into HTTP.
    require(bearerToken.length in 16..256 &&
        bearerToken.all { it in 'A'..'Z' || it in 'a'..'z' ||
            it in '0'..'9' || it == '-' || it == '_' }) {
        "Invalid gateway credential"
    }
    val gatewayTls = connectVerifiedGatewayTls(
        gatewayAddress, gatewayName, timeoutMs, protect, tlsFactory = tlsFactory, bind = bind
    )
    try {
        val authority = "$destinationHost:$destinationPort"
        val request = "CONNECT $authority HTTP/1.1\r\n" +
            "Host: $authority\r\n" +
            "Proxy-Authorization: Bearer $bearerToken\r\n\r\n"
        gatewayTls.outputStream.write(request.toByteArray(StandardCharsets.US_ASCII))
        gatewayTls.outputStream.flush()

        // Read exactly the CONNECT header, one byte at a time: buffered readers
        // could consume the first tunneled bytes and silently corrupt the stream.
        val header = ByteArrayOutputStream()
        val suffix = IntArray(4)
        while (header.size() < 8192) {
            val next = gatewayTls.inputStream.read()
            if (next < 0) throw IOException("Gateway closed before CONNECT response")
            if (next > 0x7e || (next < 0x20 && next != 0x0d && next != 0x0a && next != 0x09)) {
                throw IOException("Invalid gateway response")
            }
            header.write(next)
            suffix[0] = suffix[1]
            suffix[1] = suffix[2]
            suffix[2] = suffix[3]
            suffix[3] = next
            if (header.size() >= 4 && suffix.contentEquals(intArrayOf(13, 10, 13, 10))) {
                val lines = String(header.toByteArray(), StandardCharsets.US_ASCII)
                    .dropLast(4).split("\r\n")
                if (!lines[0].matches(Regex("HTTP/1\\.1 200(?: [ -~]*)?"))) {
                    throw IOException("Gateway CONNECT rejected")
                }
                for (line in lines.drop(1)) {
                    val colon = line.indexOf(':')
                    if (colon <= 0 || line.substring(0, colon).any {
                        !it.isLetterOrDigit() && it != '-'
                    } || line.substring(colon + 1).any { it == '\r' || it == '\n' }) {
                        throw IOException("Invalid gateway response header")
                    }
                    if (line.substring(0, colon).equals("Content-Length", true) ||
                        line.substring(0, colon).equals("Transfer-Encoding", true)) {
                        throw IOException("Unexpected CONNECT response body")
                    }
                }
                return gatewayTls
            }
        }
        throw IOException("Gateway CONNECT response exceeds limit")
    } catch (failure: Throwable) {
        try { gatewayTls.close() } catch (closeFailure: Throwable) { failure.addSuppressed(closeFailure) }
        throw failure
    }
}
