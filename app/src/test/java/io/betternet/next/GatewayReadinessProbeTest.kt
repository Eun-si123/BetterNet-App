package io.betternet.next

import org.junit.Assert.fail
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.ConnectException
import org.junit.Test

/** No network, credential, VPN permission or Android service in these tests. */
class GatewayReadinessProbeTest {
    @Test fun readOnlyProbeRequiresPinnedObservableNonVpnInternet() {
        requireReadOnlyGatewayProbeScope(true, true, false, true)
        for (invalid in listOf(
            listOf(false, true, false, true), // default network changed
            listOf(true, false, false, true), // network visibility incomplete
            listOf(true, true, true, true),  // another VPN appeared
            listOf(true, true, false, false), // no Internet capability
        )) {
            try {
                requireReadOnlyGatewayProbeScope(invalid[0], invalid[1], invalid[2], invalid[3])
                fail("Unsafe gateway probe scope must be rejected: $invalid")
            } catch (_: IllegalStateException) { }
        }
    }
    @Test fun gatewayProbeFallsBackAcrossFamiliesOnlyOnTcpConnectFailure() {
        val first = InetAddress.getByName("2001:db8::2")
        val second = InetAddress.getByName("192.0.2.2")
        val attempted = mutableListOf<InetAddress>()
        var closed = 0
        var checks = 0
        probePinnedGatewayTls("gateway.example", 443,
            verify = { checks++ },
            lookup = { arrayOf(first, second) },
            dial = { address, timeout ->
                attempted.add(address.address)
                connectProtectedSocket(address, timeout, { true }, createSocket = {
                    object : Socket() {
                        override fun connect(endpoint: SocketAddress?, timeout: Int) {
                            if (address.address == first) throw ConnectException("unreachable")
                        }
                        override fun close() { closed++ }
                    }
                })
            })
        assertEquals(listOf(first, second), attempted)
        assertEquals(2, closed) // failed first TCP socket and successful second socket
        assertTrue("Scope must be rechecked around DNS, dial and close", checks >= 6)
    }

    @Test fun gatewayProbeNeverRetriesTlsIdentityFailure() {
        val attempted = mutableListOf<InetAddress>()
        val addresses = arrayOf(InetAddress.getByName("2001:db8::2"),
            InetAddress.getByName("192.0.2.2"))
        try {
            probePinnedGatewayTls("gateway.example", 443,
                verify = {}, lookup = { addresses },
                dial = { address, _ ->
                    attempted.add(address.address)
                    throw IOException("TLS certificate rejected")
                })
            fail("TLS identity rejection must terminate the probe")
        } catch (_: IOException) {
            assertEquals(listOf(addresses[0]), attempted)
        }
    }

    @Test fun gatewayProbeClosesConnectedSocketIfAuthorizationWithdrawn() {
        val address = InetAddress.getByName("192.0.2.2")
        var authorized = true
        var closed = false
        try {
            probePinnedGatewayTls("gateway.example", 443,
                verify = { check(authorized) },
                lookup = { arrayOf(address) },
                dial = { _, _ ->
                    authorized = false
                    object : Socket() { override fun close() { closed = true } }
                })
            fail("Revoked consent must reject a connected socket")
        } catch (_: IllegalStateException) {
            assertTrue(closed)
        }
    }

    @Test fun gatewayProbeNeverDialsAfterAuthorizationChangesDuringDns() {
        var authorized = true
        var dialed = false
        try {
            probePinnedGatewayTls("gateway.example", 443,
                verify = { check(authorized) },
                lookup = {
                    authorized = false
                    arrayOf(InetAddress.getByName("192.0.2.2"))
                },
                dial = { _, _ -> dialed = true; Socket() })
            fail("Revoked authorization must reject DNS results")
        } catch (_: IllegalStateException) {
            assertTrue(!dialed)
        }
    }

}
