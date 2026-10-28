package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Assert.assertTrue
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import org.junit.Test

class SelectedAppVpnServiceTest {
    @Test fun acceptsOneExplicitOtherPackage() {
        assertEquals("com.example.browser", requireSelectedPackage("com.example.browser", "io.betternet.next"))
    }

    @Test fun refusesMissingSelectionRatherThanDefaultingToWholeDevice() {
        for (value in listOf(null, "", "  ", "\n")) {
            assertRejected(value)
        }
    }

    @Test fun refusesOwnPackageToAvoidRecursiveRouting() {
        assertRejected("io.betternet.next")
    }

    @Test fun refusesWhitespacePaddedPackage() {
        assertRejected(" com.example.browser")
        assertRejected("com.example.browser ")
    }

    @Test fun addsExactlyOneAppAndNeverAddsSelf() {
        val allowed = mutableListOf<String>()
        addOnlySelectedApplication("com.example.browser", "io.betternet.next", { allowed.add(it); Unit })
        assertEquals(listOf("com.example.browser"), allowed)
    }

    @Test fun invalidScopeNeverTouchesBuilder() {
        val allowed = mutableListOf<String>()
        try {
            addOnlySelectedApplication(null, "io.betternet.next", { allowed.add(it); Unit })
            fail("Missing selection must fail")
        } catch (_: IllegalArgumentException) {
            assertEquals(emptyList<String>(), allowed)
        }
    }

    @Test fun missingInstalledPackageErrorMustPropagate() {
        val failure = IllegalStateException("package no longer installed")
        try {
            addOnlySelectedApplication("com.example.gone", "io.betternet.next") { throw failure }
            fail("Package lookup failure must abort")
        } catch (caught: IllegalStateException) {
            assertEquals(failure, caught)
        }
    }

    private val resolvedGateway = InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 443)

    private class RecordingSocket(private val events: MutableList<String>, private val failConnect: Boolean = false) : Socket() {
        override fun connect(endpoint: SocketAddress?, timeout: Int) {
            events.add("connect:$timeout")
            if (failConnect) throw IOException("simulated connection failure")
        }
        override fun close() { events.add("close") }
    }

    @Test fun gatewaySocketIsProtectedBeforeAnyConnect() {
        val events = mutableListOf<String>()
        val socket = RecordingSocket(events)
        val result = connectProtectedSocket(resolvedGateway, 500, { events.add("protect"); true }, { socket })
        assertEquals(socket, result)
        assertEquals(listOf("protect", "connect:500"), events)
    }

    @Test fun protectionRefusalNeverConnectsAndClosesSocket() {
        val events = mutableListOf<String>()
        try {
            connectProtectedSocket(resolvedGateway, 500, { events.add("protect"); false }, { RecordingSocket(events) })
            fail("Unprotected socket must not connect")
        } catch (_: IllegalStateException) {
            assertEquals(listOf("protect", "close"), events)
        }
    }

    @Test fun protectionExceptionClosesSocketWithoutConnecting() {
        val events = mutableListOf<String>()
        try {
            connectProtectedSocket(resolvedGateway, 500, { events.add("protect"); throw SecurityException("revoked") }, { RecordingSocket(events) })
            fail("Protection failure must abort")
        } catch (_: SecurityException) {
            assertEquals(listOf("protect", "close"), events)
        }
    }

    @Test fun connectFailureClosesProtectedSocket() {
        val events = mutableListOf<String>()
        try {
            connectProtectedSocket(resolvedGateway, 500, { events.add("protect"); true }, { RecordingSocket(events, true) })
            fail("Connection failure must propagate")
        } catch (_: IOException) {
            assertEquals(listOf("protect", "connect:500", "close"), events)
        }
    }

    @Test fun unresolvedDnsAndUnboundedTimeoutAreRejectedBeforeSocketCreation() {
        var created = false
        val factory = { created = true; RecordingSocket(mutableListOf()) }
        for ((address, timeout) in listOf(
            InetSocketAddress.createUnresolved("example.invalid", 443) to 500,
            resolvedGateway to 0,
            resolvedGateway to 10_001,
        )) {
            try {
                connectProtectedSocket(address, timeout, { true }, factory)
                fail("Unsafe dial arguments must fail")
            } catch (_: IllegalArgumentException) {
                assertTrue(!created)
            }
        }
    }

    private fun assertRejected(packageName: String?) {
        try {
            requireSelectedPackage(packageName, "io.betternet.next")
            fail("Expected invalid selection to be rejected: $packageName")
        } catch (_: IllegalArgumentException) {
            // Fail closed, never silently widen to an unscoped VPN.
        }
    }
}
