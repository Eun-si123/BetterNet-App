package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

class TunDnsReplyTest {
    private fun u16(b: ByteArray, i: Int): Int =
        ((b[i].toInt() and 255) shl 8) or (b[i + 1].toInt() and 255)

    private fun set16(b: ByteArray, i: Int, n: Int) {
        b[i] = (n ushr 8).toByte()
        b[i + 1] = n.toByte()
    }

    private fun sum(b: ByteArray, start: Int, length: Int): Int {
        var s = 0
        for (i in 0 until length step 2) {
            s += (b[start + i].toInt() and 255) shl 8
            if (i + 1 < length) s += b[start + i + 1].toInt() and 255
        }
        return s
    }

    private fun checksum(initial: Int): Int {
        var s = initial
        while (s > 65535) s = (s and 65535) + (s ushr 16)
        return s.inv() and 65535
    }

    private fun udpChecksum(b: ByteArray, ipv6: Boolean): Int {
        val offset = if (ipv6) 40 else 20
        val addrSize = if (ipv6) 16 else 4
        val sourceOffset = if (ipv6) 8 else 12
        val destOffset = if (ipv6) 24 else 16
        val length = b.size - offset
        return checksum(sum(b, sourceOffset, addrSize) + sum(b, destOffset, addrSize) +
            length + 17 + sum(b, offset, length))
    }

    private fun dnsQuery(): ByteArray = ByteArray(12).apply {
        this[0] = 0x12; this[1] = 0x34
        this[2] = 0x01; this[5] = 0x01
    }

    private fun dnsResponse(): ByteArray = dnsQuery().apply {
        this[2] = 0x81.toByte(); this[3] = 0x80.toByte()
    }

    private fun request(ipv6: Boolean): TunIngressResult.Packet {
        val offset = if (ipv6) 40 else 20
        val b = ByteArray(offset + 8 + 12)
        b[0] = if (ipv6) 0x60 else 0x45
        if (ipv6) {
            set16(b, 4, 20)
            b[6] = 17; b[7] = 64
            b[8] = 0x20; b[9] = 0x01; b[23] = 1
            b[24] = 0x20; b[25] = 0x01; b[39] = 2
        } else {
            set16(b, 2, b.size)
            b[8] = 64; b[9] = 17
            b[12] = 192.toByte(); b[13] = 0; b[14] = 2; b[15] = 10
            b[16] = 198.toByte(); b[17] = 51; b[18] = 100; b[19] = 2
            set16(b, 10, checksum(sum(b, 0, 20)))
        }
        set16(b, offset, 49152)
        set16(b, offset + 2, 53)
        set16(b, offset + 4, 20)
        dnsQuery().copyInto(b, offset + 8)
        val udpSum = udpChecksum(b, ipv6)
        set16(b, offset + 6, if (udpSum == 0) 65535 else udpSum)
        return TunIngressResult.Packet(b, parseTunPacketHeader(b, b.size)!!)
    }

    @Test fun createsIpv4DnsReplyWithCorrectAddressesAndChecksums() {
        val original = request(false)
        val reply = buildDnsUdpReply(original, dnsResponse(), 1280)!!
        assertEquals(40, reply.size)
        assertEquals(0, checksum(sum(reply, 0, 20)))
        assertEquals(0, udpChecksum(reply, false))
        val parsed = parseTunPacketHeader(reply, reply.size)!!
        assertEquals("198.51.100.2", parsed.source.hostAddress)
        assertEquals("192.0.2.10", parsed.destination.hostAddress)
        assertEquals(53, parsed.sourcePort)
        assertEquals(49152, parsed.destinationPort)
        assertEquals(0x4000, u16(reply, 6))
        assertArrayEquals(dnsResponse(), reply.copyOfRange(28, reply.size))
    }

    @Test fun createsIpv6DnsReplyWithMandatoryChecksum() {
        val original = request(true)
        val reply = buildDnsUdpReply(original, dnsResponse(), 1280)!!
        assertEquals(60, reply.size)
        assertNotEquals(0, u16(reply, 46))
        assertEquals(0, udpChecksum(reply, true))
        val parsed = parseTunPacketHeader(reply, reply.size)!!
        assertEquals(6, parsed.ipVersion)
        assertEquals(53, parsed.sourcePort)
        assertEquals(49152, parsed.destinationPort)
        assertArrayEquals(dnsResponse(), reply.copyOfRange(48, reply.size))
    }

    @Test fun refusesUncorrelatedOrMalformedDnsAndCorruptUdp() {
        val original = request(false)
        val wrongId = dnsResponse().apply { this[0] = 0x77 }
        assertNull(buildDnsUdpReply(original, wrongId, 1280))
        assertNull(buildDnsUdpReply(original, dnsQuery(), 1280))
        assertNull(buildDnsUdpReply(original, ByteArray(11), 1280))
        assertNull(buildDnsUdpReply(original, ByteArray(1233), 1500))
        val broken = original.bytes.clone().apply { this[28] = 0x55 }
        assertNull(buildDnsUdpReply(
            TunIngressResult.Packet(broken, original.header), dnsResponse(), 1280
        ))
        val nonDns = original.bytes.clone().apply {
            set16(this, 22, 80)
        }
        assertNull(buildDnsUdpReply(
            TunIngressResult.Packet(nonDns, original.header), dnsResponse(), 1280
        ))
    }

    @Test fun respectsMtuAndDoesNotModifyInput() {
        val original = request(true)
        val before = original.bytes.clone()
        val maxPayload = ByteArray(1232).apply {
            this[0] = 0x12; this[1] = 0x34; this[2] = 0x80.toByte()
        }
        assertNotNull(buildDnsUdpReply(original, maxPayload, 1280))
        assertArrayEquals(before, original.bytes)
        for (mtu in listOf(0, 1279, 9001)) {
            try {
                buildDnsUdpReply(original, dnsResponse(), mtu)
                fail("Accepted invalid MTU")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
