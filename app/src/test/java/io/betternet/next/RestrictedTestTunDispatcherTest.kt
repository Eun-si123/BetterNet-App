package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
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
                    destinationPort: Int = 53): ByteArray {
        val ipv6 = plan.clientAddress.address.size == 16
        val ip = if (ipv6) 40 else 20
        val b = ByteArray(ip + 8)
        b[0] = (if (ipv6) 0x60 else 0x45).toByte()
        if (ipv6) {
            put16(b, 4, 8)
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
        put16(b, ip + 4, 8)
        val size = plan.clientAddress.address.size
        val sum = words(b, src, size) + words(b, dst, size) + 8 + 17 + words(b, ip, 8)
        val udpChecksum = checksum(sum)
        put16(b, ip + 6, if (udpChecksum == 0) 65535 else udpChecksum)
        if (!ipv6) put16(b, 10, checksum(words(b, 0, 20)))
        assertNotNull(parseTunPacketHeader(b, b.size))
        return b
    }

    private fun feed(dispatcher: RestrictedTestTunDispatcher, packet: ByteArray,
                     output: ByteArrayOutputStream = ByteArrayOutputStream(), time: Long = 100): Boolean =
        dispatcher.pumpOneTunPacket(ByteArrayInputStream(packet), output, time)

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
