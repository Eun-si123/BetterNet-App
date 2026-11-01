package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Assert.assertTrue
import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLHandshakeException
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

    @Test fun underlyingNetworkCapabilityGateFailsClosedOnLossOrVpnHandover() {
        // A stale Android Network handle must never become a default-route or
        // VPN-recursive fallback between DNS, protection, binding or retries.
        requireNonVpnInternetCapabilities(hasInternet = true, isVpn = false)
        for ((internet, vpn) in listOf(false to false, false to true, true to true)) {
            try {
                requireNonVpnInternetCapabilities(internet, vpn)
                fail("Unsafe underlying network must be rejected")
            } catch (_: IllegalArgumentException) { }
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

    @Test fun underlyingBindingRunsAfterProtectionAndBeforeConnect() {
        val events = mutableListOf<String>()
        val socket = RecordingSocket(events)
        connectProtectedSocket(resolvedGateway, 500,
            { events.add("protect"); true }, { socket }, { events.add("bind") })
        assertEquals(listOf("protect", "bind", "connect:500"), events)
    }

    @Test fun bindingFailureClosesSocketWithoutDialingDefaultNetwork() {
        val events = mutableListOf<String>()
        try {
            connectProtectedSocket(resolvedGateway, 500,
                { events.add("protect"); true }, { RecordingSocket(events) },
                { events.add("bind"); throw IOException("network lost") })
            fail("Binding failure must abort")
        } catch (_: IOException) {
            assertEquals(listOf("protect", "bind", "close"), events)
        }
    }

    @Test fun protectionRefusalNeverAttemptsBinding() {
        val events = mutableListOf<String>()
        try {
            connectProtectedSocket(resolvedGateway, 500,
                { events.add("protect"); false }, { RecordingSocket(events) },
                { events.add("bind") })
            fail("Protection failure must abort")
        } catch (_: IllegalStateException) {
            assertEquals(listOf("protect", "close"), events)
        }
    }

    @Test fun underlyingDnsIsExplicitAndFailsClosed() {
        val events = mutableListOf<String>()
        val address = resolveGatewayAddress("gateway.example", 443) { host ->
            events.add("lookup:" + host)
            arrayOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        }
        assertEquals(resolvedGateway, address)
        assertEquals(listOf("lookup:gateway.example"), events)
        for (host in listOf("bad_name", "gateway.example.", " gateway.example")) {
            try {
                resolveGatewayAddress(host, 443) { throw AssertionError("Must not resolve invalid host") }
                fail("Invalid hostname must be rejected")
            } catch (_: IllegalArgumentException) { }
        }
        try {
            resolveGatewayAddress("gateway.example", 443) { emptyArray() }
            fail("Empty DNS response must not fall back")
        } catch (_: IllegalArgumentException) { }
        val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        val ipv6Address = resolveGatewayAddress("gateway.example", 443) { arrayOf(ipv6) }
        assertEquals(ipv6, ipv6Address.address)
        for (port in listOf(0, 65536)) {
            try {
                resolveGatewayAddress("gateway.example", port) {
                    throw AssertionError("Invalid port must not trigger DNS")
                }
                fail("Invalid port must be rejected")
            } catch (_: IllegalArgumentException) { }
        }
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

    @Test fun ipv6ReachabilityFailureFallsBackToIpv4OnSameResolvedList() {
        val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        val ipv4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val attempted = mutableListOf<String>()
        var lookups = 0
        var clock = 0L
        val chosen = connectWithGatewayAddressFallback(
            "gateway.example", 443, 1_000,
            { name ->
                assertEquals("gateway.example", name)
                lookups++
                arrayOf(ipv6, ipv4)
            },
            { address, timeout ->
                attempted.add("${address.address.hostAddress}:$timeout")
                connectProtectedSocket(address, timeout, { true }, {
                    object : Socket() {
                        override fun connect(endpoint: SocketAddress?, timeout: Int) {
                            if (address.address == ipv6) {
                                clock += 300_000_000L
                                throw NoRouteToHostException("IPv6 path unavailable")
                            }
                        }
                    }
                }).close()
                address
            },
            { clock },
        )
        assertEquals(ipv4, chosen.address)
        assertEquals(1, lookups)
        assertEquals(listOf("${ipv6.hostAddress}:1000", "${ipv4.hostAddress}:700"), attempted)
    }

    @Test fun fourAddressCapDoesNotHideTheOtherIpFamily() {
        for (firstIsV6 in listOf(true, false)) {
            val v6 = (1..4).map { index ->
                InetAddress.getByAddress(ByteArray(16).apply {
                    this[0] = 0x20
                    this[1] = 0x01
                    this[15] = index.toByte()
                })
            }
            val v4 = (1..4).map { index ->
                InetAddress.getByAddress(byteArrayOf(198.toByte(), 51, 100, index.toByte()))
            }
            val preferred = if (firstIsV6) v6 else v4
            val fallback = if (firstIsV6) v4 else v6
            val attempts = mutableListOf<InetAddress>()
            val chosen = connectWithGatewayAddressFallback(
                "gateway.example", 443, 1_000,
                { (preferred + fallback).toTypedArray() },
                { address, timeout ->
                    attempts.add(address.address)
                    if (address.address == fallback.first()) address
                    else {
                        connectProtectedSocket(address, timeout, { true }, {
                            object : Socket() {
                                override fun connect(endpoint: SocketAddress?, timeout: Int) {
                                    throw NoRouteToHostException("First address family unavailable")
                                }
                            }
                        }).close()
                        throw AssertionError("Unreachable address unexpectedly connected")
                    }
                },
            )
            assertEquals(fallback.first(), chosen.address)
            assertEquals(listOf(preferred.first(), fallback.first()), attempts)
        }
    }

    @Test fun eachFallbackAttemptProtectsAndBindsItsOwnSocketBeforeDial() {
        val first = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        val second = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val events = mutableListOf<String>()
        var created = 0
        connectWithGatewayAddressFallback(
            "gateway.example", 443, 1_000,
            { arrayOf(first, second) },
            { address, timeout ->
                connectProtectedSocket(address, timeout,
                    { events.add("protect"); true },
                    {
                        created++
                        object : Socket() {
                            override fun connect(endpoint: SocketAddress?, timeout: Int) {
                                events.add("connect")
                                if (created == 1) throw NoRouteToHostException("IPv6 unavailable")
                            }
                            override fun close() { events.add("close") }
                        }
                    },
                    { events.add("bind") },
                )
            },
        )
        assertEquals(2, created)
        assertEquals(listOf("protect", "bind", "connect", "close",
            "protect", "bind", "connect"), events)
    }

    @Test fun noRetryOnTlsIdentityOrProtectionFailure() {
        val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        val ipv4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        for (failure in listOf(
            SSLHandshakeException("Untrusted gateway"),
            IllegalStateException("VPN protection refused"),
            IOException("Underlying network binding failed"),
        )) {
            var attempts = 0
            try {
                connectWithGatewayAddressFallback(
                    "gateway.example", 443, 500,
                    { arrayOf(ipv6, ipv4) },
                    { _, _ -> attempts++; throw failure },
                )
                fail("Unsafe retry or accepted failure")
            } catch (caught: Exception) {
                assertTrue(caught === failure)
                assertEquals(1, attempts)
            }
        }
    }

    @Test fun retriesAreCappedAndShareOneDeadline() {
        val addresses = (1..6).map { InetAddress.getByAddress(byteArrayOf(127, 0, 0, it.toByte())) }
        var attempts = 0
        var clock = 0L
        try {
            connectWithGatewayAddressFallback(
                "gateway.example", 443, 900,
                { addresses.toTypedArray() },
                { _, timeout ->
                    attempts++
                    assertEquals(900, timeout)
                    connectProtectedSocket(
                        resolvedGateway, timeout, { true }, {
                            object : Socket() {
                                override fun connect(endpoint: SocketAddress?, timeout: Int) {
                                    throw ConnectException("unreachable")
                                }
                            }
                        },
                    )
                },
                { clock },
            )
            fail("All addresses failed")
        } catch (failure: IOException) {
            assertTrue(failure.cause is ConnectException)
            assertEquals(4, attempts)
        }
        attempts = 0
        try {
            connectWithGatewayAddressFallback(
                "gateway.example", 443, 900,
                { addresses.toTypedArray() },
                { _, timeout ->
                    attempts++
                    assertEquals(900, timeout)
                    clock += 900_000_000L
                    throw SocketTimeoutException("deadline consumed")
                },
                { clock },
            )
            fail("Must not dial after deadline")
        } catch (_: SocketTimeoutException) {
            assertEquals(1, attempts)
        }
    }

    @Test fun tcpConnectTimeoutMayRetryButTlsOrConnectTimeoutNeverDoes() {
        val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        val ipv4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        var attempts = 0
        var closed = 0
        connectWithGatewayAddressFallback(
            "gateway.example", 443, 1_000,
            { arrayOf(ipv6, ipv4) },
            { address, timeout ->
                connectProtectedSocket(address, timeout, { true }, {
                    attempts++
                    object : Socket() {
                        override fun connect(endpoint: SocketAddress?, timeout: Int) {
                            if (attempts == 1) throw SocketTimeoutException("TCP dial timed out")
                        }
                        override fun close() { closed++ }
                    }
                })
            },
        ).close()
        assertEquals("TCP dial timeout can try another same-network address", 2, attempts)
        assertEquals("Both sockets must be closed", 2, closed)

        attempts = 0
        val postConnectTimeout = SocketTimeoutException("TLS or CONNECT read timed out")
        try {
            connectWithGatewayAddressFallback(
                "gateway.example", 443, 1_000,
                { arrayOf(ipv6, ipv4) },
                { _, _ -> attempts++; throw postConnectTimeout },
            )
            fail("A post-connect timeout must not retry authentication")
        } catch (failure: SocketTimeoutException) {
            assertTrue(failure === postConnectTimeout)
            assertEquals(1, attempts)
        }
    }

    @Test fun postConnectReachabilityExceptionsNeverReplayGatewayCredentials() {
        // A TLS/CONNECT layer can also throw these IOException subclasses.
        // Only failures tagged by connectProtectedSocket's TCP dial may retry.
        val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
        val ipv4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        for (failure in listOf(
            ConnectException("Connection failed after authentication"),
            NoRouteToHostException("Route lost after authentication"),
        )) {
            var attempts = 0
            try {
                connectWithGatewayAddressFallback(
                    "gateway.example", 443, 1_000,
                    { arrayOf(ipv6, ipv4) },
                    { _, _ -> attempts++; throw failure },
                )
                fail("Post-connect failure must not retry credentials")
            } catch (caught: IOException) {
                assertTrue(caught === failure)
                assertEquals(1, attempts)
            }
        }
    }

    @Test fun invalidOrEmptyDnsCannotDialAnyGateway() {
        var lookups = 0
        var attempts = 0
        for (name in listOf("bad_name", "gateway.example")) {
            try {
                connectWithGatewayAddressFallback(
                    name, 443, 1_000,
                    { lookups++; emptyArray() },
                    { _, _ -> attempts++; "unexpected" },
                )
                fail("Unsafe DNS result accepted")
            } catch (_: IllegalArgumentException) { }
        }
        assertEquals(1, lookups)
        assertEquals(0, attempts)
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
