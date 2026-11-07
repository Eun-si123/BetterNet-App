package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

class TunPacketHeaderTest {
    private fun set16(bytes: ByteArray, at: Int, value: Int) {
        bytes[at] = (value ushr 8).toByte()
        bytes[at + 1] = value.toByte()
    }

    private fun sealIpv4Header(bytes: ByteArray) {
        set16(bytes, 10, 0)
        var sum = 0
        for (i in 0 until 20 step 2) {
            sum += ((bytes[i].toInt() and 0xff) shl 8) or (bytes[i + 1].toInt() and 0xff)
        }
        while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
        set16(bytes, 10, sum.inv() and 0xffff)
    }

    private fun sealUdpChecksum(bytes: ByteArray, ipv6: Boolean) {
        val offset = if (ipv6) 40 else 20
        val addressBytes = if (ipv6) 16 else 4
        val source = if (ipv6) 8 else 12
        val destination = if (ipv6) 24 else 16
        fun sumWords(start: Int, length: Int): Int {
            var sum = 0
            for (at in start until start + length step 2) {
                sum += (bytes[at].toInt() and 255) * 256 +
                    (bytes[at + 1].toInt() and 255)
            }
            return sum
        }
        set16(bytes, offset + 6, 0)
        var sum = sumWords(source, addressBytes) + sumWords(destination, addressBytes) +
            (bytes.size - offset) + 17 + sumWords(offset, bytes.size - offset)
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        val result = sum.inv() and 65535
        set16(bytes, offset + 6, if (result == 0) 65535 else result)
    }

    private fun ipv4Udp(): ByteArray = ByteArray(30).apply {
        this[0] = 0x45
        set16(this, 2, size)
        this[8] = 64; this[9] = 17
        this[12] = 192.toByte(); this[13] = 0; this[14] = 2; this[15] = 10
        this[16] = 198.toByte(); this[17] = 51; this[18] = 100; this[19] = 2
        set16(this, 20, 12345); set16(this, 22, 53); set16(this, 24, 10)
        this[28] = 0x12; this[29] = 0x34
        sealIpv4Header(this)
        sealUdpChecksum(this, false)
    }

    private fun ipv4Tcp(): ByteArray = ByteArray(40).apply {
        this[0] = 0x45
        set16(this, 2, size)
        this[9] = 6
        this[12] = 192.toByte(); this[13] = 0; this[14] = 2; this[15] = 10
        this[16] = 198.toByte(); this[17] = 51; this[18] = 100; this[19] = 2
        set16(this, 20, 43210); set16(this, 22, 443)
        this[32] = 0x50 // TCP data offset = 20 bytes
        // Construct a valid TCP checksum; the parser now rejects the old
        // header-only fixture with an absent/incorrect checksum.
        var tcpSum = 6 + 20
        for (range in listOf(12 until 20, 20 until 40)) {
            for (at in range step 2) {
                tcpSum += ((this[at].toInt() and 0xff) shl 8) or
                    (this[at + 1].toInt() and 0xff)
            }
        }
        while (tcpSum > 0xffff) tcpSum = (tcpSum and 0xffff) + (tcpSum ushr 16)
        set16(this, 36, tcpSum.inv() and 0xffff)
        sealIpv4Header(this)
    }

    private fun ipv6Udp(): ByteArray = ByteArray(48).apply {
        this[0] = 0x60
        set16(this, 4, 8)
        this[6] = 17
        this[8] = 0x20; this[9] = 0x01; this[10] = 0x0d; this[11] = 0x0b; this[23] = 1
        this[24] = 0x20; this[25] = 0x01; this[26] = 0x0d; this[27] = 0x0b; this[39] = 2
        set16(this, 40, 12345); set16(this, 42, 53); set16(this, 44, 8)
        sealUdpChecksum(this, true)
    }

    @Test fun recognizesIpv4TcpWithoutSendingAnything() {
        val result = parseTunPacketHeader(ipv4Tcp(), 40)!!
        assertEquals(4, result.ipVersion)
        assertEquals(6, result.protocol)
        assertEquals("192.0.2.10", result.source.hostAddress)
        assertEquals("198.51.100.2", result.destination.hostAddress)
        assertEquals(43210, result.sourcePort)
        assertEquals(443, result.destinationPort)
        assertEquals(20, result.transportOffset)
        assertEquals(20, result.transportHeaderBytes)
    }

    @Test fun recognizesIpv6UdpDnsHeader() {
        val result = parseTunPacketHeader(ipv6Udp(), 48)!!
        assertEquals(6, result.ipVersion)
        assertEquals(17, result.protocol)
        assertEquals(53, result.destinationPort)
        assertEquals(40, result.transportOffset)
        assertEquals(8, result.transportHeaderBytes)
    }

    @Test fun acceptsValidUdpChecksumsAndIpv4OptionalZeroChecksum() {
        for (ipv6 in listOf(false, true)) {
            val packet = if (ipv6) ipv6Udp() else ipv4Udp()
            assertEquals(17, parseTunPacketHeader(packet, packet.size)!!.protocol)
        }
        val optional = ipv4Udp().apply { set16(this, 26, 0) }
        assertNotNull(parseTunPacketHeader(optional, optional.size))
    }

    @Test fun rejectsUdpChecksumCorruptionAndPseudoHeaderMismatch() {
        for (ipv6 in listOf(false, true)) {
            val packet = if (ipv6) ipv6Udp() else ipv4Udp()
            val checksumOffset = if (ipv6) 46 else 26
            val damagedChecksum = packet.clone().apply {
                this[checksumOffset] = (this[checksumOffset].toInt() xor 1).toByte()
            }
            assertNull(parseTunPacketHeader(damagedChecksum, damagedChecksum.size))
            val damagedAddress = packet.clone().apply {
                this[if (ipv6) 8 else 12] = (this[if (ipv6) 8 else 12].toInt() xor 1).toByte()
                if (!ipv6) sealIpv4Header(this)
            }
            assertNull(parseTunPacketHeader(damagedAddress, damagedAddress.size))
        }
        val payload = ipv4Udp().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertNull(parseTunPacketHeader(payload, payload.size))
    }

    @Test fun refusesTruncatedAndForgedLengths() {
        val tcp = ipv4Tcp()
        assertNull(parseTunPacketHeader(tcp, 19))
        assertNull(parseTunPacketHeader(tcp, 39))
        assertNull(parseTunPacketHeader(tcp, 41))
        assertNull(parseTunPacketHeader(tcp, 0))
        assertNull(parseTunPacketHeader(tcp, -1))
        val udp = ipv6Udp()
        assertNull(parseTunPacketHeader(udp, 47))
        set16(udp, 44, 9)
        assertNull(parseTunPacketHeader(udp, 48))
    }

    @Test fun refusesCorruptedIpv4HeadersAndUnsupportedOptions() {
        val tcp = ipv4Tcp()
        tcp[8] = (tcp[8] + 1).toByte() // TTL changed without updating checksum
        assertNull(parseTunPacketHeader(tcp, 40))
        tcp[8] = (tcp[8] - 1).toByte()
        assertNotNull(parseTunPacketHeader(tcp, 40))
        tcp[0] = 0x46 // IPv4 options unsupported even if checksum is repaired
        assertNull(parseTunPacketHeader(tcp, 40))
    }

    @Test fun refusesIpv6UdpWithMissingMandatoryChecksum() {
        val udp = ipv6Udp()
        set16(udp, 46, 0)
        assertNull(parseTunPacketHeader(udp, 48))
    }

    @Test fun refusesFragmentsExtensionsAndInvalidHeaders() {
        val tcp = ipv4Tcp()
        set16(tcp, 6, 0x2000) // More fragments
        sealIpv4Header(tcp)
        assertNull(parseTunPacketHeader(tcp, 40))
        set16(tcp, 6, 0x0001) // Nonzero fragment offset
        sealIpv4Header(tcp)
        assertNull(parseTunPacketHeader(tcp, 40))
        set16(tcp, 6, 0)
        sealIpv4Header(tcp)
        tcp[32] = 0x40 // Too-short TCP header
        assertNull(parseTunPacketHeader(tcp, 40))
        tcp[32] = 0x60 // TCP options exceed packet
        assertNull(parseTunPacketHeader(tcp, 40))
        val udp = ipv6Udp()
        udp[6] = 44 // IPv6 fragment extension
        assertNull(parseTunPacketHeader(udp, 48))
        udp[6] = 17
        udp[0] = 0x40 // Invalid IPv6 version
        assertNull(parseTunPacketHeader(udp, 48))
    }
}
