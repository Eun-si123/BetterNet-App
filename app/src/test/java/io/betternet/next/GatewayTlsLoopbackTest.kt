package io.betternet.next

import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.SecureRandom
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.junit.Assert.*
import org.junit.Test

/**
 * Real JSSE handshakes over loopback only. A fresh, throwaway test certificate
 * is generated locally by the JDK keytool; no external server, VPN or relay.
 * The test-only trust store never changes production/platform TLS trust.
 */
class GatewayTlsLoopbackTest {
    private data class Contexts(val server: SSLContext, val trustedClient: SSLContext)

    private fun contexts(): Contexts {
        val file = Files.createTempFile("betternet-test-tls-", ".p12")
        Files.delete(file)
        val password = UUID.randomUUID().toString().replace("-", "")
        try {
            val tool = java.io.File(System.getProperty("java.home"), "bin/keytool").absolutePath
            val process = ProcessBuilder(
                tool, "-genkeypair", "-alias", "gateway-test", "-keyalg", "EC",
                "-groupname", "secp256r1", "-validity", "1", "-storetype", "PKCS12",
                "-keystore", file.toString(), "-storepass", password, "-keypass", password,
                "-dname", "CN=gateway.example", "-ext", "SAN=dns:gateway.example", "-noprompt",
            ).redirectErrorStream(true).start()
            val completed = process.waitFor(20, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                fail("Test certificate generation timed out")
            }
            val output = process.inputStream.bufferedReader().use { it.readText() }
            assertEquals("Test certificate generation failed: $output", 0, process.exitValue())

            val identity = KeyStore.getInstance("PKCS12")
            Files.newInputStream(file).use { identity.load(it, password.toCharArray()) }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(identity, password.toCharArray())

            val trust = KeyStore.getInstance("PKCS12")
            trust.load(null, null)
            trust.setCertificateEntry("loopback-only", identity.getCertificate("gateway-test"))
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(trust)

            val server = SSLContext.getInstance("TLS").apply {
                init(kmf.keyManagers, null, SecureRandom())
            }
            val client = SSLContext.getInstance("TLS").apply {
                init(null, tmf.trustManagers, SecureRandom())
            }
            return Contexts(server, client)
        } finally {
            Files.deleteIfExists(file)
        }
    }

    private fun withServer(
        context: SSLContext,
        serverAction: (SSLSocket) -> Unit,
        clientAction: (InetSocketAddress) -> Unit,
    ) {
        val listener = context.serverSocketFactory.createServerSocket(
            0, 1, InetAddress.getLoopbackAddress()
        ) as SSLServerSocket
        listener.soTimeout = 8_000
        val serverFailure = AtomicReference<Throwable?>()
        val worker = Thread {
            try {
                listener.use { bound ->
                    (bound.accept() as SSLSocket).use { peer ->
                        peer.soTimeout = 5_000
                        serverAction(peer)
                    }
                }
            } catch (error: Throwable) {
                serverFailure.set(error)
            }
        }.apply { isDaemon = true; start() }
        try {
            clientAction(InetSocketAddress(InetAddress.getLoopbackAddress(), listener.localPort))
        } finally {
            listener.close()
            worker.join(8_000)
        }
        assertFalse("Loopback TLS server hung", worker.isAlive)
        serverFailure.get()?.let { throw AssertionError("Loopback TLS server failed", it) }
    }

    @Test fun trustedMatchingHostnameExchangesRealHttpsBytes() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val reader = peer.inputStream.bufferedReader()
            assertEquals("GET /probe HTTP/1.1", reader.readLine())
            assertEquals("Host: gateway.example", reader.readLine())
            assertEquals("", reader.readLine())
            peer.outputStream.write(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray()
            )
            peer.outputStream.flush()
        }) { address ->
            val events = mutableListOf<String>()
            connectVerifiedGatewayTls(
                address, "gateway.example", 3_000,
                { events.add("protected"); true },
                tlsFactory = tls.trustedClient.socketFactory,
            ).use { socket ->
                assertEquals(listOf("protected"), events)
                socket.outputStream.write(
                    "GET /probe HTTP/1.1\r\nHost: gateway.example\r\n\r\n".toByteArray()
                )
                socket.outputStream.flush()
                val response = socket.inputStream.bufferedReader().readText()
                assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
                assertTrue(response.endsWith("\r\n\r\nOK"))
            }
        }
    }

    @Test fun authenticatedConnectPreservesFirstTunneledBytes() {
        val tls = contexts()
        val token = "TestOnlyOpaqueToken0123456789"
        val events = mutableListOf<String>()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val lines = peer.inputStream.bufferedReader()
            assertEquals("CONNECT allowed.example:443 HTTP/1.1", lines.readLine())
            assertEquals("Host: allowed.example:443", lines.readLine())
            assertEquals("Proxy-Authorization: Bearer $token", lines.readLine())
            assertEquals("", lines.readLine())
            peer.outputStream.write(
                "HTTP/1.1 200 Connection Established\r\nX-Test: ok\r\n\r\nTUNNEL".toByteArray()
            )
            peer.outputStream.flush()
        }) { address ->
            connectAuthenticatedTestTunnel(
                address, "gateway.example", 3_000, { events.add("protected"); true },
                "allowed.example", 443, token,
                tlsFactory = tls.trustedClient.socketFactory,
                bind = { events.add("bound") },
            ).use {
                    assertEquals(listOf("protected", "bound"), events)
                    assertEquals("CONNECT must restore the caller-bounded TLS read timeout", 3_000, it.soTimeout)
                    val bytes = ByteArray(6)
                    var offset = 0
                    while (offset < bytes.size) {
                        val count = it.inputStream.read(bytes, offset, bytes.size - offset)
                        assertTrue(count > 0)
                        offset += count
                    }
                    assertEquals("TUNNEL", String(bytes))
            }
        }
    }

    @Test fun slowDripConnectResponseExpiresOnWholeHeaderDeadline() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val lines = peer.inputStream.bufferedReader()
            while (lines.readLine()?.isNotEmpty() == true) { }
            // Each byte arrives within the old per-read 10s timeout, but the
            // incomplete response must still expire within the overall budget.
            try {
                for (byte in "HTTP/1.1 200".toByteArray(Charsets.US_ASCII)) {
                    peer.outputStream.write(byte.toInt())
                    peer.outputStream.flush()
                    Thread.sleep(150)
                }
            } catch (_: java.io.IOException) { /* client closed after deadline */ }
        }) { address ->
            try {
                connectAuthenticatedTestTunnel(
                    address, "gateway.example", 500, { true },
                    "allowed.example", 443, "TestOnlyOpaqueToken0123456789",
                    tlsFactory = tls.trustedClient.socketFactory,
                ).close()
                fail("Slow-drip CONNECT must never establish a tunnel")
            } catch (_: java.net.SocketTimeoutException) {
                // The whole-header deadline, not the last-byte timeout, fired.
            }
        }
    }

    @Test fun gatewayRejectsCredentialAndClientClosesTunnel() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val lines = peer.inputStream.bufferedReader()
            while (lines.readLine()?.isNotEmpty() == true) { }
            peer.outputStream.write(
                "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n".toByteArray()
            )
            peer.outputStream.flush()
        }) { address ->
            try {
                connectAuthenticatedTestTunnel(
                    address, "gateway.example", 3_000, { true },
                    "allowed.example", 443, "WrongTestOnlyToken012345",
                    tlsFactory = tls.trustedClient.socketFactory,
                ).close()
                fail("Gateway must reject unauthorized CONNECT")
            } catch (_: java.io.IOException) {
                // The server rejected the credential; the client closes the socket.
            }
        }
    }

    @Test fun malformedSuccessAndOversizedHeadersFailClosed() {
        val tls = contexts()
        val badResponses = listOf(
            "HTTP/1.1 200 Connection Established\r\nContent-Length: 1\r\n\r\nX",
            "HTTP/1.1 200 Connection Established\r\nX-Pad: " +
                "a".repeat(8192) + "\r\n\r\n",
        )
        for (response in badResponses) {
            withServer(tls.server, { peer ->
                peer.startHandshake()
                val lines = peer.inputStream.bufferedReader()
                while (lines.readLine()?.isNotEmpty() == true) { }
                peer.outputStream.write(response.toByteArray())
                peer.outputStream.flush()
            }) { address ->
                try {
                    connectAuthenticatedTestTunnel(
                        address, "gateway.example", 3_000, { true },
                        "allowed.example", 443, "TestOnlyOpaqueToken0123456789",
                        tlsFactory = tls.trustedClient.socketFactory,
                    ).close()
                    fail("Malformed CONNECT response must not establish tunnel")
                } catch (_: java.io.IOException) {
                    // Reject body-bearing 200 or an unbounded response header.
                }
            }
        }
    }

    @Test fun invalidCredentialFailsBeforeAnyNetworkOperation() {
        var protected = false
        try {
            connectAuthenticatedTestTunnel(
                InetSocketAddress.createUnresolved("gateway.example", 443),
                "gateway.example", 3_000, { protected = true; true },
                "allowed.example", 443, "bad\r\nInjected: yes",
            ).close()
            fail("Credential CRLF injection must fail")
        } catch (_: IllegalArgumentException) {
            assertFalse(protected)
        }
    }

    @Test fun trustedCertificateWithWrongHostnameIsRejected() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            try { peer.startHandshake() } catch (_: SSLException) { /* client rejects peer */ }
        }) { address ->
            try {
                connectVerifiedGatewayTls(
                    address, "wrong.example", 3_000, { true },
                    tlsFactory = tls.trustedClient.socketFactory,
                ).close()
                fail("TLS hostname mismatch must abort")
            } catch (_: SSLException) {
                // HTTPS endpoint identification rejects the certificate SAN mismatch.
            }
        }
    }

    @Test fun untrustedCertificateIsRejectedWithoutDisablingValidation() {
        val tls = contexts()
        val defaultTrust = SSLContext.getInstance("TLS").apply { init(null, null, SecureRandom()) }
        withServer(tls.server, { peer ->
            try { peer.startHandshake() } catch (_: SSLException) { /* client rejects peer */ }
        }) { address ->
            try {
                connectVerifiedGatewayTls(
                    address, "gateway.example", 3_000, { true },
                    tlsFactory = defaultTrust.socketFactory,
                ).close()
                fail("Untrusted test certificate must abort")
            } catch (_: SSLException) {
                // Default JVM trust store must not accept our ephemeral certificate.
            }
        }
    }

    /** A test-only authenticated CONNECT relay and HTTPS origin; both bind loopback. */
    @Test fun authenticatedLoopbackConnectCarriesEndToEndHttps() {
        val tls = contexts()
        val token = "TestOnlyOpaqueToken0123456789"
        val origin = tls.server.serverSocketFactory.createServerSocket(
            0, 1, InetAddress.getLoopbackAddress()
        ) as SSLServerSocket
        origin.soTimeout = 8_000
        val originFailure = AtomicReference<Throwable?>()
        val originWorker = Thread {
            try {
                origin.use { listener ->
                    (listener.accept() as SSLSocket).use { peer ->
                        peer.soTimeout = 5_000
                        peer.startHandshake()
                        val reader = peer.inputStream.bufferedReader()
                        assertEquals("GET /real-https HTTP/1.1", reader.readLine())
                        assertEquals("Host: gateway.example", reader.readLine())
                        assertEquals("", reader.readLine())
                        peer.outputStream.write(
                            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nORIGIN"
                                .toByteArray(Charsets.US_ASCII)
                        )
                        peer.outputStream.flush()
                    }
                }
            } catch (error: Throwable) {
                originFailure.set(error)
            }
        }.apply { isDaemon = true; start() }
        try {
            withServer(tls.server, { gateway ->
                gateway.startHandshake()
                // Byte-at-a-time parsing prevents swallowing the first nested TLS byte.
                val request = java.io.ByteArrayOutputStream()
                val end = "\r\n\r\n".toByteArray(Charsets.US_ASCII)
                var matched = 0
                while (request.size() < 8192 && matched < 4) {
                    val b = gateway.inputStream.read()
                    if (b < 0) throw java.io.EOFException("CONNECT request truncated")
                    request.write(b)
                    matched = if (b == (end[matched].toInt() and 255)) matched + 1
                        else if (b == 13) 1 else 0
                }
                assertEquals("CONNECT header exceeded limit", 4, matched)
                val lines = String(request.toByteArray(), Charsets.US_ASCII).split("\r\n")
                assertEquals("CONNECT allowed.example:" + origin.localPort + " HTTP/1.1", lines[0])
                assertEquals("Host: allowed.example:" + origin.localPort, lines[1])
                val presented = lines[2].removePrefix("Proxy-Authorization: Bearer ")
                assertTrue("Gateway must verify token before dialing upstream",
                    java.security.MessageDigest.isEqual(
                        token.toByteArray(Charsets.US_ASCII),
                        presented.toByteArray(Charsets.US_ASCII)
                    )
                )
                java.net.Socket(InetAddress.getLoopbackAddress(), origin.localPort).use { upstream ->
                    upstream.soTimeout = 5_000
                    gateway.outputStream.write(
                        "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII)
                    )
                    gateway.outputStream.flush()
                    val forward = Thread {
                        try {
                            gateway.inputStream.copyTo(upstream.outputStream)
                        } catch (_: java.io.IOException) {
                            // Closing the test tunnel terminates this half of the relay.
                        }
                    }.apply { isDaemon = true; start() }
                    upstream.inputStream.copyTo(gateway.outputStream)
                    gateway.outputStream.flush()
                    upstream.close()
                    forward.join(5_000)
                }
            }) { address ->
                val protection = mutableListOf<String>()
                connectAuthenticatedTestTunnel(
                    address, "gateway.example", 3_000,
                    { protection.add("protected"); true },
                    "allowed.example", origin.localPort, token,
                    tlsFactory = tls.trustedClient.socketFactory,
                ).use { tunnel ->
                    assertEquals(listOf("protected"), protection)
                    (tls.trustedClient.socketFactory.createSocket(
                        tunnel, "gateway.example", origin.localPort, false
                    ) as SSLSocket).use { endToEnd ->
                        endToEnd.soTimeout = 5_000
                        endToEnd.sslParameters = endToEnd.sslParameters.apply {
                            endpointIdentificationAlgorithm = "HTTPS"
                        }
                        endToEnd.startHandshake()
                        endToEnd.outputStream.write(
                            "GET /real-https HTTP/1.1\r\nHost: gateway.example\r\n\r\n"
                                .toByteArray(Charsets.US_ASCII)
                        )
                        endToEnd.outputStream.flush()
                        val response = endToEnd.inputStream.bufferedReader().readText()
                        assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
                        assertTrue(response.endsWith("\r\n\r\nORIGIN"))
                    }
                }
            }
        } finally {
            origin.close()
            originWorker.join(8_000)
        }
        assertFalse("TLS origin hung", originWorker.isAlive)
        originFailure.get()?.let { throw AssertionError("TLS origin failed", it) }
    }


    @Test fun loopbackGatewayRejectsWrongCredentialBeforeAnyUpstreamConnection() {
        val tls = contexts()
        val expected = "CorrectTestOnlyToken0123456789"
        val upstreamDialed = java.util.concurrent.atomic.AtomicBoolean(false)
        withServer(tls.server, { gateway ->
            gateway.startHandshake()
            val reader = gateway.inputStream.bufferedReader()
            assertEquals("CONNECT allowed.example:443 HTTP/1.1", reader.readLine())
            assertEquals("Host: allowed.example:443", reader.readLine())
            val authHeader = reader.readLine()
            assertEquals("", reader.readLine())
            val actual = authHeader.removePrefix("Proxy-Authorization: Bearer ")
            if (java.security.MessageDigest.isEqual(
                    expected.toByteArray(Charsets.US_ASCII),
                    actual.toByteArray(Charsets.US_ASCII)
                )) {
                upstreamDialed.set(true)
            } else {
                gateway.outputStream.write(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
                        .toByteArray(Charsets.US_ASCII)
                )
                gateway.outputStream.flush()
            }
        }) { address ->
            try {
                connectAuthenticatedTestTunnel(
                    address, "gateway.example", 3_000, { true },
                    "allowed.example", 443, "WrongTestOnlyToken0123456789",
                    tlsFactory = tls.trustedClient.socketFactory,
                ).close()
                fail("Wrong credential must not establish a tunnel")
            } catch (_: java.io.IOException) {
                assertFalse("No upstream dial is allowed before authentication", upstreamDialed.get())
            }
        }
    }

    private fun dnsQuery(): ByteArray = byteArrayOf(
        0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 'a'.code.toByte(), 4, 't'.code.toByte(), 'e'.code.toByte(),
        's'.code.toByte(), 't'.code.toByte(), 0, 0, 1, 0, 1,
    )

    @Test fun verifiedTlsExchangesRealLengthFramedDnsBytes() {
        val tls = contexts()
        val query = dnsQuery()
        val response = query.clone().apply { this[2] = 0x81.toByte(); this[3] = 0x80.toByte() }
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val prefix = peer.inputStream.readNBytes(2)
            assertEquals(2, prefix.size)
            assertEquals(query.size, ((prefix[0].toInt() and 255) shl 8) or (prefix[1].toInt() and 255))
            val received = peer.inputStream.readNBytes(query.size)
            assertArrayEquals(query, received)
            peer.outputStream.write(byteArrayOf(0, response.size.toByte()))
            peer.outputStream.write(response)
            peer.outputStream.flush()
        }) { address ->
            connectVerifiedGatewayTls(address, "gateway.example", 3_000, { true },
                tlsFactory = tls.trustedClient.socketFactory).use { socket ->
                assertArrayEquals(response, exchangeOneDnsMessageOverTls(socket, query, 3_000))
            }
        }
    }

    @Test fun dnsTlsRejectsOversizedReplyAndClosesConnection() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val prefix = peer.inputStream.readNBytes(2)
            val length = ((prefix[0].toInt() and 255) shl 8) or (prefix[1].toInt() and 255)
            assertEquals(dnsQuery().size, length)
            assertEquals(length, peer.inputStream.readNBytes(length).size)
            peer.outputStream.write(byteArrayOf(0x04, 0xd1.toByte())) // 1233 > budget
            peer.outputStream.flush()
        }) { address ->
            connectVerifiedGatewayTls(address, "gateway.example", 3_000, { true },
                tlsFactory = tls.trustedClient.socketFactory).use { socket ->
                try {
                    exchangeOneDnsMessageOverTls(socket, dnsQuery(), 3_000)
                    fail("Oversized DNS response must be rejected")
                } catch (_: java.io.IOException) {
                    assertTrue("Framing failure must close the socket", socket.isClosed)
                }
            }
        }
    }

    @Test fun dnsTlsRejectsTruncatedResponseAndClosesConnection() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val prefix = peer.inputStream.readNBytes(2)
            val length = ((prefix[0].toInt() and 255) shl 8) or (prefix[1].toInt() and 255)
            peer.inputStream.readNBytes(length)
            peer.outputStream.write(byteArrayOf(0, 25, 1, 2, 3))
            peer.outputStream.flush()
        }) { address ->
            connectVerifiedGatewayTls(address, "gateway.example", 3_000, { true },
                tlsFactory = tls.trustedClient.socketFactory).use { socket ->
                try {
                    exchangeOneDnsMessageOverTls(socket, dnsQuery(), 3_000)
                    fail("Truncated DNS response must fail closed")
                } catch (_: java.io.EOFException) {
                    assertTrue(socket.isClosed)
                }
            }
        }
    }

    @Test fun invalidDnsQueryRejectedBeforeAnyNetworkWrite() {
        val tls = contexts()
        withServer(tls.server, { peer ->
            peer.startHandshake()
            peer.soTimeout = 500
            try {
                assertEquals(-1, peer.inputStream.read())
            } catch (_: java.net.SocketTimeoutException) { /* no query bytes were sent */ }
        }) { address ->
            connectVerifiedGatewayTls(address, "gateway.example", 3_000, { true },
                tlsFactory = tls.trustedClient.socketFactory).use { socket ->
                try {
                    exchangeOneDnsMessageOverTls(socket, dnsQuery().apply { this[2] = 0x81.toByte() }, 3_000)
                    fail("DNS response cannot be submitted as a query")
                } catch (_: IllegalArgumentException) { /* rejected before output */ }
            }
        }
    }


    private fun setDns16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun dnsChecksum(bytes: ByteArray, start: Int, length: Int, initial: Int = 0): Int {
        var sum = initial
        for (i in 0 until length step 2) {
            sum += (bytes[start + i].toInt() and 255) shl 8
            if (i + 1 < length) sum += bytes[start + i + 1].toInt() and 255
        }
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        return sum.inv() and 65535
    }

    private fun tunDnsRequest(ipv6: Boolean): TunIngressResult.Packet {
        val dns = dnsQuery()
        val offset = if (ipv6) 40 else 20
        val bytes = ByteArray(offset + 8 + dns.size)
        bytes[0] = if (ipv6) 0x60 else 0x45
        if (ipv6) {
            setDns16(bytes, 4, 8 + dns.size)
            bytes[6] = 17
            bytes[7] = 64
            bytes[8] = 0x20
            bytes[9] = 0x01
            bytes[23] = 1
            bytes[24] = 0x20
            bytes[25] = 0x01
            bytes[39] = 2
        } else {
            setDns16(bytes, 2, bytes.size)
            bytes[8] = 64
            bytes[9] = 17
            bytes[12] = 192.toByte()
            bytes[14] = 2
            bytes[15] = 10
            bytes[16] = 198.toByte()
            bytes[17] = 51
            bytes[18] = 100
            bytes[19] = 2
            setDns16(bytes, 10, dnsChecksum(bytes, 0, 20))
        }
        setDns16(bytes, offset, 49152)
        setDns16(bytes, offset + 2, 53)
        setDns16(bytes, offset + 4, 8 + dns.size)
        dns.copyInto(bytes, offset + 8)
        if (ipv6) {
            val addresses = bytes.copyOfRange(8, 24) + bytes.copyOfRange(24, 40)
            val pseudo = (dnsChecksum(addresses, 0, 32).inv() and 65535) +
                17 + 8 + dns.size
            val value = dnsChecksum(bytes, offset, 8 + dns.size, pseudo)
            setDns16(bytes, offset + 6, if (value == 0) 65535 else value)
        }
        return TunIngressResult.Packet(bytes, parseTunPacketHeader(bytes, bytes.size)!!)
    }

    @Test fun verifiedTlsDnsExchangeWritesOneCorrelatedIpv4AndIpv6TunReply() {
        for (ipv6 in listOf(false, true)) {
            val tls = contexts()
            val query = dnsQuery()
            val response = query.clone().apply { this[2] = 0x81.toByte(); this[3] = 0x80.toByte() }
            val request = tunDnsRequest(ipv6)
            withServer(tls.server, { peer ->
                peer.startHandshake()
                val prefix = peer.inputStream.readNBytes(2)
                assertEquals(query.size, ((prefix[0].toInt() and 255) shl 8) or
                    (prefix[1].toInt() and 255))
                assertArrayEquals(query, peer.inputStream.readNBytes(query.size))
                peer.outputStream.write(byteArrayOf(0, response.size.toByte()) + response)
                peer.outputStream.flush()
            }) { address ->
                val pending = PendingDnsReplies(maxPending = 1)
                val out = java.io.ByteArrayOutputStream()
                val socket = connectVerifiedGatewayTls(
                    address, "gateway.example", 3_000, { true },
                    tlsFactory = tls.trustedClient.socketFactory
                )
                assertTrue(exchangeOneTunDnsQueryOverTls(socket, request, pending, out, 1280, 3_000))
                assertTrue("Single-use TLS socket must close on success", socket.isClosed)
                assertArrayEquals(buildDnsUdpReply(request, response, 1280), out.toByteArray())
                assertNotNull("Successful reply must release pending slot", pending.register(request))
            }
        }
    }

    @Test fun mismatchedDnsReplyNeverReachesTunAndReleasesSlot() {
        val tls = contexts()
        val request = tunDnsRequest(false)
        val response = dnsQuery().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
            this[13] = 'b'.code.toByte()
        }
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val prefix = peer.inputStream.readNBytes(2)
            val length = ((prefix[0].toInt() and 255) shl 8) or (prefix[1].toInt() and 255)
            peer.inputStream.readNBytes(length)
            peer.outputStream.write(byteArrayOf(0, response.size.toByte()) + response)
            peer.outputStream.flush()
        }) { address ->
            val pending = PendingDnsReplies(maxPending = 1)
            val out = java.io.ByteArrayOutputStream()
            val socket = connectVerifiedGatewayTls(
                address, "gateway.example", 3_000, { true },
                tlsFactory = tls.trustedClient.socketFactory
            )
            assertFalse(exchangeOneTunDnsQueryOverTls(socket, request, pending, out, 1280, 3_000))
            assertEquals(0, out.size())
            assertTrue(socket.isClosed)
            assertNotNull(pending.register(request))
        }
    }

    @Test fun tlsFramingErrorNeverWritesTunAndReleasesPendingSlot() {
        val tls = contexts()
        val request = tunDnsRequest(false)
        withServer(tls.server, { peer ->
            peer.startHandshake()
            val prefix = peer.inputStream.readNBytes(2)
            val length = ((prefix[0].toInt() and 255) shl 8) or (prefix[1].toInt() and 255)
            peer.inputStream.readNBytes(length)
            peer.outputStream.write(byteArrayOf(0x04, 0xd1.toByte()))
            peer.outputStream.flush()
        }) { address ->
            val pending = PendingDnsReplies(maxPending = 1)
            val out = java.io.ByteArrayOutputStream()
            val socket = connectVerifiedGatewayTls(
                address, "gateway.example", 3_000, { true },
                tlsFactory = tls.trustedClient.socketFactory
            )
            try {
                exchangeOneTunDnsQueryOverTls(socket, request, pending, out, 1280, 3_000)
                fail("Oversized TLS reply must be rejected")
            } catch (_: java.io.IOException) {
                assertTrue(socket.isClosed)
                assertEquals(0, out.size())
                assertNotNull(pending.register(request))
            }
        }
    }

    @Test fun malformedTunDnsQueryCannotSendOverTls() {
        val socket = (javax.net.ssl.SSLContext.getDefault().socketFactory.createSocket()
            as SSLSocket)
        val request = tunDnsRequest(false)
        val malformed = request.copy(bytes = request.bytes.clone().apply { this[30] = 0x81.toByte() })
        val pending = PendingDnsReplies(maxPending = 1)
        assertFalse(exchangeOneTunDnsQueryOverTls(
            socket, malformed, pending, java.io.ByteArrayOutputStream(), 1280, 3_000
        ))
        assertTrue(socket.isClosed)
        assertNotNull(pending.register(request))
    }

}
