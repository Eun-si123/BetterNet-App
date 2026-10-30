package io.betternet.next

import java.net.InetAddress
import java.net.InetSocketAddress
import org.junit.Assert.*
import org.junit.Test

/** No real DNS, Android VPN or network use: fixed synthetic DNS answers. */
class DnsDestinationBindingTest {
    internal fun query(type: Int): ByteArray = byteArrayOf(
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        3, 'd'.code.toByte(), 'n'.code.toByte(), 's'.code.toByte(),
        7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
        'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
        0, 0, type.toByte(), 0, 1,
    )

    internal fun response(query: ByteArray, address: ByteArray, ttl: Int = 30): ByteArray =
        query.clone().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
            this[7] = 1 // one answer
        } + byteArrayOf(
            0xc0.toByte(), 0x0c, 0, query[query.size - 3], 0, 1,
            0, 0, 0, ttl.toByte(), 0, address.size.toByte(),
        ) + address

    internal fun bindingFor(syn: TunIngressResult.Packet, now: Long = 100): DnsDestinationBinding {
        val q = query(if (syn.header.ipVersion == 4) 1 else 28)
        return DnsDestinationBinding.fromCorrelatedResponse(
            q, response(q, syn.header.destination.address), "dns.example",
            syn.header.destination, now
        )!!
    }

    @Test fun authorizesOnlyMatchingIpv4AndIpv6SynUntilTtl() {
        val packets = TunTcpSynAckTest()
        for (version in listOf(4, 6)) {
            val syn = packets.request(version)
            val binding = bindingFor(syn)
            assertEquals("dns.example", binding.hostname)
            assertEquals(syn.header.destination, binding.address)
            assertTrue(binding.allows(syn, 100))
            assertTrue(binding.allows(syn, 30_099))
            assertFalse(binding.allows(syn, 30_100))
            assertFalse(binding.allows(syn, 99))
            assertFalse(binding.allows(packets.request(version, destinationSeed = 80), 100))
            assertFalse(binding.allows(packets.request(version, destinationPort = 80), 100))
            assertFalse(binding.allows(packets.request(version, flags = 0x10), 100))
        }
    }

    @Test fun rejectsUnrelatedOrMalformedDnsAnswers() {
        for (version in listOf(4, 6)) {
            val syn = TunTcpSynAckTest().request(version)
            val q = query(if (version == 4) 1 else 28)
            val good = response(q, syn.header.destination.address)
            fun parse(query: ByteArray = q, response: ByteArray = good,
                      host: String = "dns.example",
                      allowed: InetAddress = syn.header.destination) =
                DnsDestinationBinding.fromCorrelatedResponse(query, response, host, allowed, 100)
            assertNotNull(parse())
            assertNull(parse(host = "other.example"))
            // Even a valid, correlated DNS reply cannot authorize a different
            // IP from the independently approved test destination.
            assertNull(parse(allowed = InetAddress.getByAddress(
                ByteArray(if (version == 4) 4 else 16) { 1 })))
            assertNull(parse(response = good.clone().apply { this[1] = 0x35 })) // wrong DNS ID
            assertNull(parse(response = good.clone().apply { this[3] = 0x83.toByte() })) // NXDOMAIN
            assertNull(parse(response = good.clone().apply { this[7] = 2 })) // multiple answers
            assertNull(parse(response = good.clone().apply { this[9] = 1 })) // authority
            assertNull(parse(response = good.clone().apply { this[11] = 1 })) // extra records
            assertNull(parse(response = good.clone().apply { this[q.size] = 0 })) // wrong name
            assertNull(parse(response = good.clone().apply { this[q.size + 3] = 5 })) // CNAME
            assertNull(parse(response = good.clone().apply { this[q.size + 9] = 0 })) // zero TTL
            assertNull(parse(response = good + byteArrayOf(0))) // trailing bytes
            assertNull(parse(response = good.copyOf(good.size - 1))) // short RDATA
            assertNull(parse(response = response(q, syn.header.destination.address, 0)))
            assertNull(parse(query = q.clone().apply { this[2] = 0x81.toByte() }))
        }
    }

    @Test fun invalidSynCannotOpenOrProtectGatewaySocket() {
        val packets = TunTcpSynAckTest()
        val syn = packets.request(4)
        val binding = bindingFor(syn)
        var protectionCalls = 0
        for (invalid in listOf(
            packets.request(4, destinationSeed = 80),
            packets.request(4, destinationPort = 80),
            packets.request(4, flags = 0x10),
        )) {
            try {
                connectDnsBoundTestTcpBridge(
                    binding, invalid, 100,
                    InetSocketAddress(InetAddress.getLoopbackAddress(), 9), "gateway.example",
                    "TestOnlyOpaqueToken0123456789", 1000, 1280, 99,
                    { protectionCalls++; true },
                )
                fail("Invalid SYN was accepted")
            } catch (_: IllegalArgumentException) { }
        }
        assertEquals(0, protectionCalls)
    }
}
