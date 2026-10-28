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
                address, "gateway.example", 3_000, { true },
                "allowed.example", 443, token,
                tlsFactory = tls.trustedClient.socketFactory,
            ).use {
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
}
