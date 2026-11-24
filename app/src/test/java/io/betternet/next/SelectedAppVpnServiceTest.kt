package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
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
    @Test fun gatewayBoundaryChecksBeforeAndAfterBlockingNetworkOperations() {
        val events = mutableListOf<String>()
        var valid = true
        val check = {
            events.add("verify")
            check(valid) { "VPN scope changed" }
        }
        val result = withFreshRestrictedGatewayScope(check) {
            events.add("network")
            "resolved"
        }
        assertEquals("resolved", result)
        assertEquals(listOf("verify", "network", "verify"), events)

        events.clear()
        valid = false
        try {
            withFreshRestrictedGatewayScope(check) {
                events.add("network")
                "should never run"
            }
            fail("Revoked scope must prevent gateway access")
        } catch (_: IllegalStateException) {
            assertEquals(listOf("verify"), events)
        }

        events.clear()
        valid = true
        try {
            withFreshRestrictedGatewayScope(check) {
                events.add("network")
                valid = false // Consent revoked while DNS or binding blocked.
                "stale result"
            }
            fail("Stale network result must never be returned")
        } catch (_: IllegalStateException) {
            assertEquals(listOf("verify", "network", "verify"), events)
        }
    }

    @Test fun gatewaySocketClosesIfUnderlyingNetworkChangesDuringTlsDial() {
        val events = mutableListOf<String>()
        var valid = true
        val socket = RecordingSocket(events)
        val verify = {
            events.add("verify")
            check(valid) { "Underlying network is no longer safe" }
        }
        assertEquals(socket, withFreshRestrictedGatewaySocketScope(verify) {
            events.add("dial")
            socket
        })
        assertEquals(listOf("verify", "dial", "verify"), events)

        events.clear()
        valid = false
        try {
            withFreshRestrictedGatewaySocketScope(verify) {
                events.add("dial")
                socket
            }
            fail("Invalid network must never initiate a dial")
        } catch (_: IllegalStateException) {
            assertEquals(listOf("verify"), events)
        }

        events.clear()
        valid = true
        try {
            withFreshRestrictedGatewaySocketScope(verify) {
                events.add("dial")
                valid = false // Network disappeared while TLS/CONNECT blocked.
                socket
            }
            fail("Stale socket must not escape")
        } catch (expected: IllegalStateException) {
            assertEquals("Underlying network is no longer safe", expected.message)
            assertEquals(listOf("verify", "dial", "verify", "close"), events)
        }
    }

    @Test fun gatewaySocketCleanupFailureDoesNotHideRevocation() {
        val revocation = IllegalStateException("Network changed")
        val cleanup = IOException("Socket close failed")
        val events = mutableListOf<String>()
        val socket = object : Socket() {
            override fun close() { events.add("close"); throw cleanup }
        }
        var checks = 0
        try {
            withFreshRestrictedGatewaySocketScope(
                { if (++checks == 2) throw revocation },
                { events.add("dial"); socket },
            )
            fail("Post-dial revocation must abort")
        } catch (caught: IllegalStateException) {
            assertTrue(caught === revocation)
            assertEquals(listOf(cleanup), caught.suppressed.toList())
            assertEquals(listOf("dial", "close"), events)
        }
    }

    @Test fun socketCloseRethrowingRevocationDoesNotMaskOriginalFailure() {
        val revoked = IllegalStateException("VPN scope revoked")
        val socket = object : Socket() {
            override fun close() { throw revoked }
        }
        var checks = 0
        try {
            withFreshRestrictedGatewaySocketScope(
                { if (++checks == 2) throw revoked },
                { socket },
            )
            fail("Revoked scope must abort")
        } catch (caught: IllegalStateException) {
            assertTrue(caught === revoked)
            assertTrue(caught.suppressed.isEmpty())
        }
    }

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

    @Test fun refusesMalformedPackageNamesBeforeVpnBuilder() {
        for (value in listOf("notapackage", "com..browser", ".com.browser",
            "com.browser.", "1com.browser", "com.2browser", "com.browser/other",
            "com.browser\u0000", "com.browser\nother", "com." + "a".repeat(253))) {
            assertRejected(value)
        }
        assertEquals("com.example_app.browser2",
            requireSelectedPackage("com.example_app.browser2", "io.betternet.next"))
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

    @Test fun dormantActivationRequiresPreparedOsAndObservableNonVpnUnderlyingNetwork() {
        requireDormantActivationPreflight(true, true, false, true, false, true)
        // Every failure must reject the whole preparation, rather than
        // silently switching to a default network or broad VPN route.
        for (unsafe in listOf(
            listOf(false, true, false, true, false, true), // stale Network handle
            listOf(true, false, false, true, false, true), // unknown capabilities
            listOf(true, true, true, true, false, true), // another VPN visible
            listOf(true, true, false, false, false, true), // no Internet capability
            listOf(true, true, false, true, true, true), // underlying became VPN
            listOf(true, true, false, true, false, false), // OS consent revoked
        )) {
            try {
                requireDormantActivationPreflight(
                    unsafe[0], unsafe[1], unsafe[2], unsafe[3], unsafe[4], unsafe[5],
                )
                fail("Unsafe dormant activation must be rejected: $unsafe")
            } catch (_: IllegalStateException) { }
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

    @Test fun cancelledBudgetAfterNetworkBindingNeverConnectsAndClosesSocket() {
        val events = mutableListOf<String>()
        val socket = RecordingSocket(events)
        val expired = java.net.SocketTimeoutException("Gateway budget elapsed")
        try {
            connectProtectedSocket(resolvedGateway, 500,
                { events.add("protect"); true }, { socket },
                { events.add("bind") },
                connectTimeout = { events.add("deadline"); throw expired },
            )
            fail("An expired bound socket must not attempt outbound TCP")
        } catch (failure: java.net.SocketTimeoutException) {
            assertSame(expired, failure)
        }
        assertEquals(listOf("protect", "bind", "deadline", "close"), events)
    }

    @Test fun remainingConnectTimeoutIsBoundedByTheOriginalBudget() {
        val events = mutableListOf<String>()
        val socket = RecordingSocket(events)
        connectProtectedSocket(resolvedGateway, 500, { true }, { socket },
            connectTimeout = { 125 })
        assertEquals(listOf("connect:125"), events)
        val refused = RecordingSocket(events)
        try {
            connectProtectedSocket(resolvedGateway, 500, { true }, { refused },
                connectTimeout = { 501 })
            fail("A caller must not extend the original connect budget")
        } catch (_: IllegalArgumentException) { }
        assertEquals(listOf("connect:125", "close"), events)
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

    @Test fun protectedSocketCloseRethrowingOriginalFailureDoesNotMaskIt() {
        val revoked = SecurityException("VPN protection revoked")
        val events = mutableListOf<String>()
        val socket = object : Socket() {
            override fun close() { events.add("close"); throw revoked }
            override fun connect(endpoint: SocketAddress?, timeout: Int) {
                throw AssertionError("Unprotected socket must never connect")
            }
        }
        try {
            connectProtectedSocket(resolvedGateway, 500, { throw revoked }, { socket })
            fail("Revoked VPN protection must abort")
        } catch (caught: SecurityException) {
            assertTrue(caught === revoked)
            assertTrue(caught.suppressed.isEmpty())
            assertEquals(listOf("close"), events)
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

    @Test fun socketCleanupSameThrowablePreservesOriginalFailure() {
        val original = IOException("binding and close shared failure")
        var connected = false
        val socket = object : Socket() {
            override fun connect(endpoint: SocketAddress?, timeout: Int) { connected = true }
            override fun close() { throw original }
        }
        try {
            connectProtectedSocket(resolvedGateway, 500, { true }, { socket }, { throw original })
            fail("Binding must fail")
        } catch (caught: IOException) {
            assertTrue(caught === original)
            assertEquals(0, caught.suppressed.size)
            assertTrue(!connected)
        }
    }

    @Test fun socketCleanupDistinctThrowableIsSuppressed() {
        val original = IOException("binding failed")
        val cleanup = IOException("close failed")
        val socket = object : Socket() { override fun close() { throw cleanup } }
        try {
            connectProtectedSocket(resolvedGateway, 500, { true }, { socket }, { throw original })
            fail("Binding must fail")
        } catch (caught: IOException) {
            assertTrue(caught === original)
            assertEquals(listOf(cleanup), caught.suppressed.toList())
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

    @Test fun blackholedFirstFamilyLeavesTimeForOtherFamily() {
        // The old entire-budget TCP dial could starve a reachable IPv4
        // address after the initial IPv6 SYN packets were blackholed.
        val v6 = InetAddress.getByName("2001:db8::2")
        val v4 = InetAddress.getByName("192.0.2.2")
        val events = mutableListOf<String>()
        var clockNanos = 0L
        val chosen = connectWithGatewayTcpFallback(
            "gateway.example", 443, 1000,
            { arrayOf(v6, v4) },
            { address, totalBudget, tcpBudget ->
                events += address.address.hostAddress.orEmpty() + ":" + totalBudget + "/" + tcpBudget
                connectProtectedSocket(address, totalBudget,
                    protect = { events += "protect"; true },
                    createSocket = {
                        object : Socket() {
                            override fun connect(endpoint: SocketAddress?, timeout: Int) {
                                events += "tcp:" + timeout
                                if (address.address == v6) {
                                    assertEquals(500, timeout)
                                    clockNanos += timeout * 1_000_000L
                                    throw SocketTimeoutException("IPv6 blackhole")
                                }
                            }
                            override fun close() { events += "close" }
                        }
                    },
                    bind = { events += "bind" },
                    connectTimeout = { tcpBudget },
                ).close()
                address
            },
            { clockNanos },
        )
        assertEquals(v4, chosen.address)
        assertEquals(listOf(
            v6.hostAddress.orEmpty() + ":1000/500", "protect", "bind", "tcp:500", "close",
            v4.hostAddress.orEmpty() + ":500/500", "protect", "bind", "tcp:500", "close",
        ), events)
    }

    @Test fun networkSwitchDuringBlackholedTcpNeverTriesUnapprovedFallback() {
        // A dead IPv6 dial legitimately permits IPv4 fallback, but NOT after
        // the user's verified physical Network changes to a different one.
        val ipv6 = InetAddress.getByName("2001:db8::2")
        val ipv4 = InetAddress.getByName("192.0.2.2")
        var currentNetwork = 42L
        var socketsCreated = 0
        var closedSockets = 0
        val caught = assertThrows(IllegalArgumentException::class.java) {
            connectWithGatewayTcpFallback(
                "gateway.example", 443, 1_000,
                { arrayOf(ipv6, ipv4) },
                { candidate, transaction, tcpOnly ->
                    withFreshRestrictedGatewaySocketScope(
                        verify = { requireApprovedRestrictedNetworkHandle(42L, currentNetwork) },
                        dial = {
                            connectProtectedSocket(candidate, transaction,
                                protect = { true },
                                createSocket = {
                                    socketsCreated++
                                    object : Socket() {
                                        override fun connect(endpoint: SocketAddress?, timeout: Int) {
                                            assertEquals(tcpOnly, timeout)
                                            if (candidate.address == ipv6) {
                                                currentNetwork = 43L
                                                throw SocketTimeoutException("IPv6 timed out; default changed")
                                            }
                                            fail("Must not connect IPv4 on an unapproved Network")
                                        }
                                        override fun close() { closedSockets++ }
                                    }
                                },
                                connectTimeout = { tcpOnly },
                            )
                        },
                    )
                },
            )
        }
        assertEquals("Underlying Network changed since user authorization", caught.message)
        assertEquals(1, socketsCreated)
        assertEquals(1, closedSockets)
    }

    @Test fun fallbackNeverReplaysTlsOrConnectFailureOrProtectionRefusal() {
        val first = InetAddress.getByName("2001:db8::2")
        val second = InetAddress.getByName("192.0.2.2")
        for (failure in listOf(
            javax.net.ssl.SSLHandshakeException("Rejected certificate"),
            SocketTimeoutException("Post-connect TLS/CONNECT timeout"),
            SecurityException("VPN protection revoked"),
        )) {
            var attempts = 0
            try {
                connectWithGatewayTcpFallback("gateway.example", 443, 1000,
                    { arrayOf(first, second) },
                    { _, _, _ -> attempts++; throw failure },
                )
                fail("Must not try a second address after TLS/auth/scope failure")
            } catch (caught: Exception) {
                assertSame(failure, caught)
                assertEquals(1, attempts)
            }
        }
    }

    @Test fun singleAddressUsesEntireBudgetAndNoExtraDnsQueries() {
        val first = InetAddress.getByName("192.0.2.2")
        var lookups = 0
        val budgets = mutableListOf<Pair<Int, Int>>()
        val chosen = connectWithGatewayTcpFallback("gateway.example", 443, 750,
            { lookups++; arrayOf(first) },
            { address, total, tcp -> budgets += total to tcp; address },
            { 0L },
        )
        assertEquals(first, chosen.address)
        assertEquals(1, lookups)
        assertEquals(listOf(750 to 750), budgets)
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
