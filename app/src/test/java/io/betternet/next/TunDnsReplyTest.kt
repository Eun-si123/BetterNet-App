package io.betternet.next

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
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

    // One real DNS IN/A question: a.test. An ID-only 12-byte header is not a query.
    private fun dnsQuery(): ByteArray = ByteArray(12).apply {
        this[0] = 0x12; this[1] = 0x34
        this[2] = 0x01; this[5] = 0x01
    } + byteArrayOf(1, 'a'.code.toByte(), 4, 't'.code.toByte(),
        'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), 0, 0, 1, 0, 1)

    private fun dnsResponse(): ByteArray = dnsQuery().apply {
        this[2] = 0x81.toByte(); this[3] = 0x80.toByte()
    }

    private fun request(ipv6: Boolean): TunIngressResult.Packet {
        val offset = if (ipv6) 40 else 20
        val b = ByteArray(offset + 8 + dnsQuery().size)
        b[0] = if (ipv6) 0x60 else 0x45
        if (ipv6) {
            set16(b, 4, 8 + dnsQuery().size)
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
        set16(b, offset + 4, 8 + dnsQuery().size)
        dnsQuery().copyInto(b, offset + 8)
        val udpSum = udpChecksum(b, ipv6)
        set16(b, offset + 6, if (udpSum == 0) 65535 else udpSum)
        return TunIngressResult.Packet(b, parseTunPacketHeader(b, b.size)!!)
    }

    @Test fun createsIpv4DnsReplyWithCorrectAddressesAndChecksums() {
        val original = request(false)
        val reply = buildDnsUdpReply(original, dnsResponse(), 1280)!!
        assertEquals(28 + dnsResponse().size, reply.size)
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
        assertEquals(48 + dnsResponse().size, reply.size)
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

    @Test fun rejectsSameIdButDifferentDnsQuestionOrClass() {
        for (ipv6 in listOf(false, true)) {
            val original = request(ipv6)
            // Same ID and QR, but another name, type, or class must not pass.
            for (index in listOf(13, 20, 22)) {
                val changed = dnsResponse().apply { this[index] = (this[index].toInt() xor 1).toByte() }
                assertNull(buildDnsUdpReply(original, changed, 1280))
            }
            // A truncated response question and an invalid question count are rejected.
            assertNull(buildDnsUdpReply(original, dnsResponse().copyOf(17), 1280))
            assertNull(buildDnsUdpReply(original, dnsResponse().apply { this[5] = 2 }, 1280))
        }
    }

    @Test fun rejectsCompressedMalformedAndTruncatedDnsQuestions() {
        val original = request(false)
        // Compression pointers are deliberately unsupported in the question.
        assertNull(buildDnsUdpReply(original, dnsResponse().apply { this[12] = 0xc0.toByte() }, 1280))
        assertNull(buildDnsUdpReply(original, dnsResponse().apply { this[12] = 64 }, 1280))
        // Even a same-ID DNS error response must contain the same full question.
        assertNull(buildDnsUdpReply(original, dnsResponse().copyOf(12), 1280))
        for (change in listOf<(ByteArray) -> Unit>(
            { it[28 + 12] = 64 }, // invalid label length
            { it[28 + 5] = 2 }, // multiple questions unsupported
        )) {
            val brokenQuery = original.bytes.clone().apply {
                change(this)
                set16(this, 26, 0)
                set16(this, 26, udpChecksum(this, false))
            }
            // Check the DNS boundary, not an unrelated UDP checksum failure.
            assertEquals(0, udpChecksum(brokenQuery, false))
            assertNull(buildDnsUdpReply(
                TunIngressResult.Packet(brokenQuery, original.header), dnsResponse(), 1280
            ))
        }
    }

    @Test fun rejectsNonStandardDnsOpcodeAndTruncatedResponses() {
        val original = request(true)
        assertNull(buildDnsUdpReply(original, dnsResponse().apply { this[2] = 0x89.toByte() }, 1280))
        assertNull(buildDnsUdpReply(original, dnsResponse().apply { this[2] = 0x83.toByte() }, 1280))
        // NXDOMAIN is a legitimate authenticated response to the same question.
        assertNotNull(buildDnsUdpReply(original, dnsResponse().apply { this[3] = 0x83.toByte() }, 1280))
    }

    @Test fun writesExactlyOneIpv4OrIpv6DnsDatagramWithoutActivation() {
        for (ipv6 in listOf(false, true)) {
            val original = request(ipv6)
            val out = ByteArrayOutputStream()
            assertTrue(writeOneDnsTunReply(out, original, dnsResponse(), 1280))
            val expected = buildDnsUdpReply(original, dnsResponse(), 1280)!!
            assertArrayEquals(expected, out.toByteArray())
            assertEquals(if (ipv6) 6 else 4,
                parseTunPacketHeader(out.toByteArray(), out.size())!!.ipVersion)
        }
    }

    @Test fun rejectsInvalidDnsReplyBeforeAnyOutput() {
        val original = request(false)
        val out = ByteArrayOutputStream()
        assertFalse(writeOneDnsTunReply(out, original,
            dnsResponse().apply { this[0] = 0x77 }, 1280))
        assertFalse(writeOneDnsTunReply(out, original, ByteArray(11), 1280))
        assertEquals(0, out.size())
    }

    @Test fun propagatesOutputFailureWithoutRetry() {
        var attempts = 0
        val broken = object : OutputStream() {
            override fun write(b: Int) { throw AssertionError("Byte-wise fallback forbidden") }
            override fun write(b: ByteArray) {
                attempts++
                throw IOException("TUN descriptor closed")
            }
        }
        try {
            writeOneDnsTunReply(broken, request(true), dnsResponse(), 1280)
            fail("I/O failure must propagate to future VPN lifecycle owner")
        } catch (_: IOException) { }
        assertEquals(1, attempts)
    }

    @Test fun respectsMtuAndDoesNotModifyInput() {
        val original = request(true)
        val before = original.bytes.clone()
        val maxPayload = ByteArray(1232).apply {
            dnsResponse().copyInto(this)
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
