package io.betternet.next

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.junit.Assert.*
import org.junit.Test

/** Real loopback TLS, no external network, VPN, or retained test credentials. */
class GatewaySharedDeadlineTest {
    private fun contexts(): Pair<SSLContext, SSLContext> {
        val keyStorePath = Files.createTempFile("betternet-budget-", ".p12")
        Files.delete(keyStorePath)
        val password = "DisposableLocalOnly012345"
        try {
            val keytool = java.io.File(System.getProperty("java.home"), "bin/keytool").absolutePath
            val process = ProcessBuilder(
                keytool, "-genkeypair", "-alias", "budget-test", "-keyalg", "EC",
                "-groupname", "secp256r1", "-validity", "1", "-storetype", "PKCS12",
                "-keystore", keyStorePath.toString(), "-storepass", password, "-keypass", password,
                "-dname", "CN=gateway.example", "-ext", "SAN=dns:gateway.example", "-noprompt",
            ).redirectErrorStream(true).start()
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                error("Disposable loopback certificate generation timed out")
            }
            assertEquals(0, process.exitValue())
            val identity = KeyStore.getInstance("PKCS12")
            Files.newInputStream(keyStorePath).use { identity.load(it, password.toCharArray()) }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(identity, password.toCharArray())
            val trusted = KeyStore.getInstance("PKCS12")
            trusted.load(null, null)
            trusted.setCertificateEntry("local-only", identity.getCertificate("budget-test"))
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(trusted)
            return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, SecureRandom()) } to
                SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, SecureRandom()) }
        } finally {
            Files.deleteIfExists(keyStorePath)
        }
    }

    @Test fun delayedTlsHandshakeCannotGetFreshTimeAfterSuccessfulTcpConnect() {
        val (serverTls, clientTls) = contexts()
        val sawCredential = AtomicBoolean(false)
        val acceptedTcp = AtomicBoolean(false)
        val listener = serverTls.serverSocketFactory.createServerSocket(
            0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
        listener.soTimeout = 3000
        val server = Thread({
            try {
                listener.use { bound ->
                    (bound.accept() as SSLSocket).use { peer ->
                        acceptedTcp.set(true)
                        peer.soTimeout = 2000
                        try {
                            // Each phase alone is faster than the 600ms
                            // timeout. Together they exceed its shared budget.
                            Thread.sleep(1050)
                            peer.startHandshake()
                            val reader = peer.inputStream.bufferedReader()
                            val lines = mutableListOf<String>()
                            while (true) {
                                val line = reader.readLine() ?: break
                                if (line.isEmpty()) break
                                lines.add(line)
                            }
                            sawCredential.set(lines.any { it.startsWith("Proxy-Authorization:") })
                            peer.outputStream.write("HTTP/1.1 200 OK\r\n\r\n".toByteArray())
                            peer.outputStream.flush()
                        } catch (_: java.io.IOException) { /* Expired client closed TLS. */ }
                    }
                }
            } catch (_: java.io.IOException) { /* Test stopped listener. */ }
        }, "BetterNet-StalledTLS").apply { isDaemon = true; start() }
        try {
            try {
                connectAuthenticatedTestTunnel(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), listener.localPort),
                    "gateway.example", 1200, { true }, "allowed.example", 443,
                    "TestOnlyOpaqueToken0123456789", clientTls.socketFactory,
                    bind = { Thread.sleep(350) },
                ).close()
                fail("Shared budget must expire before TLS can authorize CONNECT")
            } catch (_: SocketTimeoutException) { }
        } finally {
            listener.close()
            server.join(4000)
        }
        assertFalse(server.isAlive)
        assertTrue("TCP successfully connected before the TLS budget elapsed", acceptedTcp.get())
        assertFalse("TLS must not authenticate after the shared deadline", sawCredential.get())
    }

    @Test fun blockingNetworkBindCannotRenewConnectDeadlineOrSendBearer() {
        val (serverTls, clientTls) = contexts()
        val sawCredential = AtomicBoolean(false)
        val acceptedTcp = AtomicBoolean(false)
        val listener = serverTls.serverSocketFactory.createServerSocket(
            0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
        listener.soTimeout = 3000
        val server = Thread({
            try {
                listener.use { bound ->
                    (bound.accept() as SSLSocket).use { peer ->
                        acceptedTcp.set(true)
                        peer.soTimeout = 2000
                        try {
                            peer.startHandshake()
                            val reader = peer.inputStream.bufferedReader()
                            val requestLines = mutableListOf<String>()
                            while (true) {
                                val line = reader.readLine() ?: break
                                if (line.isEmpty()) break
                                requestLines.add(line)
                            }
                            sawCredential.set(requestLines.any { it.startsWith("Proxy-Authorization:") })
                            peer.outputStream.write("HTTP/1.1 200 OK\r\n\r\n".toByteArray())
                            peer.outputStream.flush()
                        } catch (_: java.io.IOException) {
                            // A correctly expired client closes before the TLS
                            // handshake or credential exchange can complete.
                        }
                    }
                }
            } catch (_: java.io.IOException) { /* Listener closed by test cleanup. */ }
        }, "BetterNet-BudgetLoopback").apply { isDaemon = true; start() }
        try {
            val address = InetSocketAddress(InetAddress.getLoopbackAddress(), listener.localPort)
            try {
                connectAuthenticatedTestTunnel(
                    address, "gateway.example", 250, { true }, "allowed.example", 443,
                    "TestOnlyOpaqueToken0123456789", clientTls.socketFactory,
                    bind = { Thread.sleep(400) },
                ).close()
                fail("An already-expired gateway transaction must never succeed")
            } catch (_: SocketTimeoutException) { /* shared deadline; no auth bytes */ }
        } finally {
            listener.close()
            server.join(4000)
        }
        assertFalse("Loopback worker must terminate", server.isAlive)
        assertFalse("Expired pre-connect binding must not even dial TCP", acceptedTcp.get())
        assertFalse("No bearer may be sent after the connect budget elapsed", sawCredential.get())
    }
}
