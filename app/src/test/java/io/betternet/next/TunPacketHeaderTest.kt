package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

class TunPacketHeaderTest {
    private fun set16(bytes: ByteArray, at: Int, value: Int) {
        bytes[at] = (value ushr 8).toByte()
        bytes[at + 1] = value.toByte()
    }

    private fun ipv4Tcp(): ByteArray = ByteArray(40).apply {
        this[0] = 0x45
        set16(this, 2, size)
        this[9] = 6
        this[12] = 192.toByte(); this[13] = 0; this[14] = 2; this[15] = 10
        this[16] = 198.toByte(); this[17] = 51; this[18] = 100; this[19] = 2
        set16(this, 20, 43210); set16(this, 22, 443)
        this[32] = 0x50 // TCP data offset = 20 bytes
    }

    private fun ipv6Udp(): ByteArray = ByteArray(48).apply {
        this[0] = 0x60
        set16(this, 4, 8)
        this[6] = 17
        this[8] = 0x20; this[9] = 0x01; this[10] = 0x0d; this[11] = 0x0b; this[23] = 1
        this[24] = 0x20; this[25] = 0x01; this[26] = 0x0d; this[27] = 0x0b; this[39] = 2
        set16(this, 40, 12345); set16(this, 42, 53); set16(this, 44, 8)
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

    @Test fun refusesFragmentsExtensionsAndInvalidHeaders() {
        val tcp = ipv4Tcp()
        set16(tcp, 6, 0x2000) // More fragments
        assertNull(parseTunPacketHeader(tcp, 40))
        set16(tcp, 6, 0x0001) // Nonzero fragment offset
        assertNull(parseTunPacketHeader(tcp, 40))
        set16(tcp, 6, 0)
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
