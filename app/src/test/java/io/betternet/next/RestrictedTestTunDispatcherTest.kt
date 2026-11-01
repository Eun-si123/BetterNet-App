package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** Offline, checksummed IPv4/IPv6 fixtures. No VPN, gateway or network I/O. */
class RestrictedTestTunDispatcherTest {
    private val packets = TunTcpSynAckTest()
    private val bindings = DnsDestinationBindingTest()

    private fun plan(syn: TunIngressResult.Packet): RestrictedTestTunPlan = RestrictedTestTunPlan(
        syn.header.source,
        InetAddress.getByName(if (syn.header.ipVersion == 4) "198.18.0.1" else "fd00::1"),
        syn.header.destination, 1280,
    )

    private fun put16(b: ByteArray, offset: Int, value: Int) {
        b[offset] = (value ushr 8).toByte()
        b[offset + 1] = value.toByte()
    }

    private fun words(b: ByteArray, offset: Int, count: Int): Int {
        var sum = 0
        for (i in 0 until count step 2) {
            sum += (b[offset + i].toInt() and 255) shl 8
            if (i + 1 < count) sum += b[offset + i + 1].toInt() and 255
        }
        return sum
    }

    private fun checksum(initial: Int): Int {
        var sum = initial
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        return sum.inv() and 65535
    }

    private fun udp(plan: RestrictedTestTunPlan, destination: InetAddress = plan.virtualDnsAddress,
                    destinationPort: Int = 53, payload: ByteArray = byteArrayOf()): ByteArray {
        val ipv6 = plan.clientAddress.address.size == 16
        val ip = if (ipv6) 40 else 20
        val b = ByteArray(ip + 8 + payload.size)
        b[0] = (if (ipv6) 0x60 else 0x45).toByte()
        if (ipv6) {
            put16(b, 4, 8 + payload.size)
            b[6] = 17; b[7] = 64
        } else {
            put16(b, 2, b.size)
            b[8] = 64; b[9] = 17
        }
        val src = if (ipv6) 8 else 12
        val dst = if (ipv6) 24 else 16
        plan.clientAddress.address.copyInto(b, src)
        destination.address.copyInto(b, dst)
        put16(b, ip, 49153)
        put16(b, ip + 2, destinationPort)
        put16(b, ip + 4, 8 + payload.size)
        payload.copyInto(b, ip + 8)
        val size = plan.clientAddress.address.size
        val sum = words(b, src, size) + words(b, dst, size) +
            (8 + payload.size) + 17 + words(b, ip, 8 + payload.size)
        val udpChecksum = checksum(sum)
        put16(b, ip + 6, if (udpChecksum == 0) 65535 else udpChecksum)
        if (!ipv6) put16(b, 10, checksum(words(b, 0, 20)))
        assertNotNull(parseTunPacketHeader(b, b.size))
        return b
    }

    private fun feed(dispatcher: RestrictedTestTunDispatcher, packet: ByteArray,
                     output: ByteArrayOutputStream = ByteArrayOutputStream(), time: Long = 100): Boolean =
        dispatcher.pumpOneTunPacket(ByteArrayInputStream(packet), output, time)

    @Test fun dormantCompositionDoesNotResolveGatewayUntilExactApprovedDnsQuestion() {
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            var lookups = 0
            val dispatcher = newDormantRestrictedGatewayDispatcher(
                plan = p, gatewayName = "gateway.example", gatewayPort = 443,
                dnsServerName = "dns.example", approvedHost = "dns.example",
                bearerToken = "ABCDEFGHIJKLMNOP", timeoutMs = 1000,
                lookupOnUnderlyingNetwork = {
                    lookups++
                    throw IOException("Approved DNS reached the underlying-network lookup")
                },
                protect = { throw AssertionError("No socket should be created") },
                bindToUnderlyingNetwork = { throw AssertionError("No bind expected") },
                elapsedRealtimeMillis = { 100L },
            )
            val output = ByteArrayOutputStream()
            // No DNS grant: even an otherwise valid SYN cannot dial.
            assertTrue(feed(dispatcher, syn.bytes, output))
            assertTrue(feed(dispatcher, udp(p), output)) // no DNS question
            assertTrue(feed(dispatcher, udp(p, p.allowedHttpsAddress), output))
            val wrong = DnsDestinationBindingTest().query(if (version == 4) 1 else 28)
                .clone().apply { this[13] = 'x'.code.toByte() }
            assertTrue(feed(dispatcher, udp(p, payload = wrong), output))
            assertEquals(0, lookups)
            assertEquals(0, output.size())
            val approved = bindings.query(if (version == 4) 1 else 28)
            try {
                feed(dispatcher, udp(p, payload = approved), output)
                fail("Expected only the approved query to reach gateway lookup")
            } catch (expected: IOException) {
                assertTrue(expected.message!!.contains("underlying-network lookup"))
            }
            assertEquals(1, lookups)
            assertEquals(0, output.size())
            dispatcher.close()
        }
    }

    @Test fun revokeWhileDnsGatewayIsBlockedSuppressesLateTunWrites() {
        // Regression: the old session checked cancellation only AFTER the
        // callback returned, so an in-flight DNS reply could write after revoke.
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val descriptorCloses = AtomicInteger()
            val output = ByteArrayOutputStream()
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, tunOutput ->
                    entered.countDown()
                    check(release.await(3, TimeUnit.SECONDS))
                    tunOutput.write(byteArrayOf(0x7f)) // must be rejected after revoke
                    bindings.bindingFor(syn)
                },
                { _, _, _, _ -> throw AssertionError("No TCP gateway allowed") },
            )
            val session = RestrictedTunSession(dispatcher,
                ByteArrayInputStream(udp(p)), output,
                { descriptorCloses.incrementAndGet() })
            val executor = Executors.newSingleThreadExecutor()
            try {
                val pending = executor.submit<Boolean> { session.pumpOneTunPacket(100) }
                assertTrue("DNS callback did not enter", entered.await(3, TimeUnit.SECONDS))
                session.requestStop() // simulates Android VPN permission revoke
                release.countDown()
                assertFalse(pending.get(3, TimeUnit.SECONDS))
                assertEquals("No post-revoke TUN bytes", 0, output.size())
                assertEquals(1, descriptorCloses.get())
                assertFalse(session.pumpOneTunPacket(101))
            } finally {
                release.countDown()
                executor.shutdownNow()
                session.close()
            }
        }
    }

    @Test fun readinessWaitCannotUsePrePollTimeToAcceptExpiredDnsGrant() {
        // Simulate a delayed Android TUN poll crossing the DNS grant deadline.
        // The old pre-poll clock sample would have allowed a stale SYN to dial.
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            val frames = listOf(udp(p), syn.bytes)
            var frameIndex = 0
            val input = object : java.io.InputStream() {
                override fun read(): Int = throw AssertionError("Only datagram reads expected")
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    val frame = frames[frameIndex++]
                    frame.copyInto(b, off)
                    return frame.size
                }
            }
            var clock = 100L
            var polls = 0
            var dials = 0
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> bindings.bindingFor(syn, 100) },
                { _, _, _, _ -> dials++; throw AssertionError("Expired grant reached gateway") })
            val session = RestrictedTunSession(dispatcher, input, ByteArrayOutputStream(),
                closeDescriptor = {}, waitForReadable = {
                    if (++polls == 2) clock = 30_100L
                    true
                })
            try {
                assertTrue(session.pumpOneCycle { clock }) // DNS grant at 100ms.
                assertTrue(session.pumpOneCycle { clock }) // SYN arrives after expiry.
                assertEquals(0, dials)
                assertEquals(2, polls)
                assertEquals(2, frameIndex)
            } finally {
                session.close()
            }
        }
    }

    @Test fun onlyExactSourceAndRoutesReachCallbacksForBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            var dns = 0
            var tcp = 0
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> dns++; bindings.bindingFor(syn) },
                { _, _, _, _ -> tcp++; throw AssertionError("Must not dial") })
            val wrongSource = RestrictedTestTunPlan(
                InetAddress.getByAddress(ByteArray(if (version == 4) 4 else 16) { 77 }),
                p.virtualDnsAddress, p.allowedHttpsAddress, 1280)
            val otherDispatcher = RestrictedTestTunDispatcher(wrongSource,
                { _, _ -> throw AssertionError("Other app DNS") },
                { _, _, _, _ -> throw AssertionError("Other app TCP") })
            assertTrue(feed(otherDispatcher, udp(p)))
            assertTrue(feed(otherDispatcher, syn.bytes))
            assertTrue(feed(dispatcher, udp(p, p.allowedHttpsAddress)))
            assertTrue(feed(dispatcher, udp(p, destinationPort = 5353)))
            assertTrue(feed(dispatcher, packets.request(version, destinationPort = 80).bytes))
            assertTrue(feed(dispatcher, syn.bytes)) // no DNS grant yet
            assertEquals(0, dns)
            assertEquals(0, tcp)
            dispatcher.close()
            otherDispatcher.close()
        }
    }

    @Test fun dnsGrantIsSingleUseAndSynIsDeliveredToOneBridge() {
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            var dns = 0
            var dials = 0
            var releases = 0
            val output = ByteArrayOutputStream()
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> dns++; bindings.bindingFor(syn) },
                { approved, initial, tunOutput, time ->
                    dials++
                    assertEquals(p.allowedHttpsAddress, approved.address)
                    val bridge = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf()),
                        ByteArrayOutputStream(), p.mtu, 123L, allowedDestination = approved.address,
                        onClose = { releases++ })
                    assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(initial.bytes), tunOutput, time))
                    bridge
                })
            assertTrue(feed(dispatcher, udp(p), output))
            assertTrue(feed(dispatcher, syn.bytes, output))
            assertEquals(1, dns)
            assertEquals(1, dials)
            assertNotNull(parseTunPacketHeader(output.toByteArray(), output.size()))
            assertTrue(feed(dispatcher, syn.bytes, ByteArrayOutputStream()))
            assertEquals(1, dials)
            dispatcher.close()
            dispatcher.close()
            assertEquals(1, releases)
            assertFalse(feed(dispatcher, udp(p)))
        }
    }

    @Test fun rejectedOrExpiredDnsGrantCannotOpenGateway() {
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            var shouldApprove = true
            var dials = 0
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> if (shouldApprove) bindings.bindingFor(syn) else null },
                { _, _, _, _ -> dials++; throw AssertionError("No dial allowed") })
            assertTrue(feed(dispatcher, udp(p)))
            assertTrue(feed(dispatcher, syn.bytes, time = 30_100)) // 30s TTL expired
            assertEquals(0, dials)
            assertTrue(feed(dispatcher, udp(p)))
            shouldApprove = false
            assertTrue(feed(dispatcher, udp(p))) // revokes previous grant
            assertTrue(feed(dispatcher, syn.bytes))
            assertEquals(0, dials)
            dispatcher.close()
        }
    }

    @Test fun callbackFailureClosesSessionAndCannotRetryCredentialUse() {
        val syn = packets.request(4)
        val p = plan(syn)
        var calls = 0
        val dispatcher = RestrictedTestTunDispatcher(p,
            { _, _ -> bindings.bindingFor(syn) },
            { _, _, _, _ -> calls++; throw IOException("CONNECT failed") })
        assertTrue(feed(dispatcher, udp(p)))
        try {
            feed(dispatcher, syn.bytes)
            fail("Gateway failure must propagate")
        } catch (_: IOException) { }
        assertFalse(feed(dispatcher, syn.bytes))
        assertEquals(1, calls)
    }

    @Test fun unrelatedUdpStillRetiresExpiredGatewayFlow() {
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            var releases = 0
            var dnsCalls = 0
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> dnsCalls++; bindings.bindingFor(syn) },
                { approved, initial, output, time ->
                    OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf()),
                        ByteArrayOutputStream(), p.mtu, 123L, allowedDestination = approved.address,
                        onClose = { releases++ }).also {
                        assertTrue(it.pumpOneTunPacket(ByteArrayInputStream(initial.bytes), output, time))
                    }
                })
            assertTrue(feed(dispatcher, udp(p)))
            assertTrue(feed(dispatcher, syn.bytes))
            assertEquals(0, releases)
            // This datagram does not target the DNS route or HTTPS route.
            assertTrue(feed(dispatcher, udp(p, p.allowedHttpsAddress), time = 15_101))
            assertEquals(1, releases)
            assertTrue(feed(dispatcher, udp(p), time = 15_102))
            assertEquals(2, dnsCalls) // new DNS is allowed only after retirement
            dispatcher.close()
            assertEquals(1, releases)
        }
    }

    @Test fun idleTunPollRetiresExpiredGatewayWithoutReadingOrClosingTun() {
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            val datagrams = listOf(udp(p), syn.bytes)
            var reads = 0
            var gatewayCloses = 0
            var descriptorCloses = 0
            var polls = 0
            val input = object : java.io.InputStream() {
                override fun read(): Int = throw AssertionError("Use packet-oriented read")
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    if (reads >= datagrams.size) throw AssertionError("Idle poll read TUN")
                    val packet = datagrams[reads++]
                    packet.copyInto(b, off)
                    return packet.size
                }
            }
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> bindings.bindingFor(syn) },
                { approved, initial, output, time ->
                    OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf()),
                        ByteArrayOutputStream(), p.mtu, 123L,
                        allowedDestination = approved.address,
                        onClose = { gatewayCloses++ }).also {
                        assertTrue(it.pumpOneTunPacket(ByteArrayInputStream(initial.bytes), output, time))
                    }
                })
            val session = RestrictedTunSession(dispatcher, input, ByteArrayOutputStream(),
                { descriptorCloses++ }, waitForReadable = { ++polls <= 2 })
            assertTrue(session.pumpOneTunPacket(100)) // DNS grant
            assertTrue(session.pumpOneTunPacket(101)) // authenticated test flow
            assertEquals(0, gatewayCloses)
            assertTrue(session.pumpOneTunPacket(15_102)) // idle; flow lease elapsed
            assertEquals(1, gatewayCloses)
            assertEquals(2, reads)
            assertEquals(0, descriptorCloses) // session remains usable
            assertTrue(session.pumpOneTunPacket(15_103))
            assertEquals(1, gatewayCloses) // no duplicate close
            session.close()
            assertEquals(1, descriptorCloses)
        }
    }

    @Test fun sessionCycleRefreshesClockAfterGatewayReadAndRetiresExpiredFlow() {
        // The real session -> dispatcher -> bridge path must pass the clock
        // callback through. A pre-read snapshot would emit stale gateway bytes.
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val p = plan(syn)
            val frames = listOf(udp(p), syn.bytes, packets.finalAck(syn, 123L).bytes)
            var nextFrame = 0
            var clock = 100L
            var closes = 0
            var descriptorCloses = 0
            val input = object : java.io.InputStream() {
                override fun read(): Int = throw AssertionError("Use packet read")
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    val frame = frames[nextFrame++]
                    frame.copyInto(b, off)
                    return frame.size
                }
            }
            val dispatcher = RestrictedTestTunDispatcher(p,
                { _, _ -> bindings.bindingFor(syn, 100) },
                { approved, initial, output, time ->
                    val upstream = object : java.io.InputStream() {
                        override fun read(): Int = throw AssertionError("Use bounded read")
                        override fun read(b: ByteArray, off: Int, len: Int): Int {
                            clock = 15_101L // Expired while waiting for upstream bytes.
                            b[off] = 42
                            return 1
                        }
                    }
                    OfflineTcpTunBridge(upstream, ByteArrayOutputStream(), p.mtu, 123L,
                        allowedDestination = approved.address, onClose = { closes++ }).also {
                        assertTrue(it.pumpOneTunPacket(ByteArrayInputStream(initial.bytes), output, time))
                    }
                })
            val output = ByteArrayOutputStream()
            val session = RestrictedTunSession(dispatcher, input, output,
                { descriptorCloses++ }, waitForReadable = { nextFrame < frames.size })
            try {
                assertTrue(session.pumpOneCycle { clock }) // DNS authorization
                assertTrue(session.pumpOneCycle { clock }) // SYN and SYN-ACK
                output.reset()
                assertTrue(session.pumpOneCycle { clock }) // ACK, then delayed read
                assertEquals(0, output.size()) // No expired gateway data.
                assertEquals(1, closes)
                assertEquals(0, descriptorCloses)
            } finally {
                session.close()
            }
            assertEquals(1, descriptorCloses)
            assertEquals(1, closes)
        }
    }

    @Test fun gatewayReadFailureClosesWholeDispatcher() {
        val syn = packets.request(4)
        val p = plan(syn)
        var releases = 0
        val dispatcher = RestrictedTestTunDispatcher(p,
            { _, _ -> bindings.bindingFor(syn) },
            { approved, initial, output, time ->
                val failing = object : java.io.InputStream() {
                    override fun read(): Int = throw IOException("gateway read failed")
                    override fun read(b: ByteArray, off: Int, len: Int): Int =
                        throw IOException("gateway read failed")
                }
                OfflineTcpTunBridge(failing, ByteArrayOutputStream(), p.mtu, 123L,
                    allowedDestination = approved.address, onClose = { releases++ }).also {
                    assertTrue(it.pumpOneTunPacket(ByteArrayInputStream(initial.bytes), output, time))
                    assertTrue(it.pumpOneTunPacket(ByteArrayInputStream(
                        packets.finalAck(syn, 123L).bytes), output, time + 1))
                }
            })
        assertTrue(feed(dispatcher, udp(p)))
        assertTrue(feed(dispatcher, syn.bytes))
        try {
            dispatcher.pumpOneGatewayReply(ByteArrayOutputStream(), 102)
            fail("Gateway failure must abort session")
        } catch (_: IOException) { }
        assertEquals(1, releases)
        assertFalse(feed(dispatcher, syn.bytes))
    }

    @Test fun tunEofClosesSessionWithoutGatewayDial() {
        val syn = packets.request(4)
        val dispatcher = RestrictedTestTunDispatcher(plan(syn),
            { _, _ -> throw AssertionError("No DNS") },
            { _, _, _, _ -> throw AssertionError("No gateway") })
        assertFalse(dispatcher.pumpOneTunPacket(ByteArrayInputStream(byteArrayOf()),
            ByteArrayOutputStream(), 100))
        assertFalse(feed(dispatcher, syn.bytes))
    }
}
