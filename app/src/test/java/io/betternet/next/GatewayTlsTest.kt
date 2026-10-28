package io.betternet.next

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.io.IOException
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import org.junit.Assert.*
import org.junit.Test

class GatewayTlsTest {
    private val address = InetSocketAddress(InetAddress.getLoopbackAddress(), 443)
    private class ConnectedSocket : Socket() {
        var closed = false
        override fun isConnected() = true
        override fun isClosed() = closed
        override fun close() { closed = true }
    }

    private class TestTlsSocket(
        private val events: MutableList<String>,
        private val failHandshake: Boolean = false,
        private val protocols: Array<String> = arrayOf("TLSv1.3", "TLSv1.2", "TLSv1.1"),
    ) : SSLSocket() {
        var closed = false
        private var enabled = protocols
        private var params = SSLParameters()
        override fun getSupportedProtocols() = protocols
        override fun getEnabledProtocols() = enabled
        override fun setEnabledProtocols(p: Array<String>) { enabled = p; events.add("protocols") }
        override fun getSSLParameters() = params
        override fun setSSLParameters(p: SSLParameters) { params = p; events.add("identity:" + p.endpointIdentificationAlgorithm) }
        override fun setSoTimeout(timeout: Int) { events.add("timeout:$timeout") }
        override fun startHandshake() {
            events.add("handshake")
            if (failHandshake) throw IOException("bad certificate")
        }
        override fun close() { closed = true; events.add("tls-close") }
        override fun getSupportedCipherSuites() = emptyArray<String>()
        override fun getEnabledCipherSuites() = emptyArray<String>()
        override fun setEnabledCipherSuites(suites: Array<String>) {}
        override fun getSession(): SSLSession = throw UnsupportedOperationException()
        override fun addHandshakeCompletedListener(listener: HandshakeCompletedListener) {}
        override fun removeHandshakeCompletedListener(listener: HandshakeCompletedListener) {}
        override fun setUseClientMode(mode: Boolean) {}
        override fun getUseClientMode() = true
        override fun setNeedClientAuth(need: Boolean) {}
        override fun getNeedClientAuth() = false
        override fun setWantClientAuth(want: Boolean) {}
        override fun getWantClientAuth() = false
        override fun setEnableSessionCreation(flag: Boolean) {}
        override fun getEnableSessionCreation() = true
    }

    private class TestFactory(private val tls: TestTlsSocket, private val events: MutableList<String>) : SSLSocketFactory() {
        override fun getDefaultCipherSuites() = emptyArray<String>()
        override fun getSupportedCipherSuites() = emptyArray<String>()
        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
            events.add("wrap:$host:$port:$autoClose")
            return tls
        }
        override fun createSocket(host: String, port: Int): Socket = throw AssertionError("Unexpected DNS dial")
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket = throw AssertionError("Unexpected DNS dial")
        override fun createSocket(host: InetAddress, port: Int): Socket = throw AssertionError("Unexpected direct dial")
        override fun createSocket(host: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket = throw AssertionError("Unexpected direct dial")
    }

    @Test fun enablesIdentityVerificationBeforeHandshake() {
        val events = mutableListOf<String>()
        val tls = TestTlsSocket(events)
        val raw = ConnectedSocket()
        assertSame(tls, establishVerifiedGatewayTls(raw, address, "gateway.example", TestFactory(tls, events)))
        assertEquals(listOf("wrap:gateway.example:443:true", "timeout:10000", "protocols", "identity:HTTPS", "handshake"), events)
        assertArrayEquals(arrayOf("TLSv1.3", "TLSv1.2"), tls.enabledProtocols)
        assertFalse(raw.closed)
    }

    @Test fun protectionFailureNeverWrapsOrConnectsTls() {
        val events = mutableListOf<String>()
        val raw = ConnectedSocket()
        val tls = TestTlsSocket(events)
        try {
            connectVerifiedGatewayTls(address, "gateway.example", 500, { false }, { raw }, TestFactory(tls, events))
            fail("VPN protection refusal must abort before TLS")
        } catch (_: IllegalStateException) {
            assertTrue(raw.closed)
            assertTrue(events.isEmpty())
        }
    }

    @Test fun handshakeFailureClosesBothSockets() {
        val events = mutableListOf<String>()
        val tls = TestTlsSocket(events, failHandshake = true)
        val raw = ConnectedSocket()
        try {
            establishVerifiedGatewayTls(raw, address, "gateway.example", TestFactory(tls, events))
            fail("TLS failure must abort")
        } catch (_: IOException) {
            assertTrue(tls.closed)
            assertTrue(raw.closed)
        }
    }

    @Test fun rejectsInvalidNamesAndUnresolvedAddressesWithoutWrapping() {
        for (name in listOf("", " gateway.example", "gateway.example.", "bad_name", "-bad.example", "bad..example")) {
            val events = mutableListOf<String>()
            val raw = ConnectedSocket()
            val tls = TestTlsSocket(events)
            try {
                establishVerifiedGatewayTls(raw, address, name, TestFactory(tls, events))
                fail("Invalid hostname must abort: $name")
            } catch (_: IllegalArgumentException) {
                assertTrue(raw.closed)
                assertTrue(events.isEmpty())
            }
        }
        val events = mutableListOf<String>()
        val raw = ConnectedSocket()
        try {
            establishVerifiedGatewayTls(raw, InetSocketAddress.createUnresolved("gateway.example", 443), "gateway.example", TestFactory(TestTlsSocket(events), events))
            fail("Unresolved address must abort")
        } catch (_: IllegalArgumentException) {
            assertTrue(raw.closed)
            assertTrue(events.isEmpty())
        }
    }

    @Test fun rejectsLegacyOnlyTlsBeforeHandshake() {
        val events = mutableListOf<String>()
        val tls = TestTlsSocket(events, protocols = arrayOf("TLSv1.1", "TLSv1"))
        val raw = ConnectedSocket()
        try {
            establishVerifiedGatewayTls(raw, address, "gateway.example", TestFactory(tls, events))
            fail("Legacy-only TLS must abort")
        } catch (_: IllegalStateException) {
            assertTrue(tls.closed)
            assertTrue(raw.closed)
            assertFalse(events.contains("handshake"))
        }
    }
}
