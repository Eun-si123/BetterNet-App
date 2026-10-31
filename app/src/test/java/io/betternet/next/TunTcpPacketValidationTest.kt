package io.betternet.next

import java.io.ByteArrayInputStream
import org.junit.Assert.*
import org.junit.Test

/** Offline packet fixtures; no VPN, sockets or outbound network traffic. */
class TunTcpPacketValidationTest {
    private fun put16(bytes: ByteArray, at: Int, value: Int) {
        bytes[at] = (value ushr 8).toByte()
        bytes[at + 1] = value.toByte()
    }

    private fun wordSum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var at = offset
        while (at + 1 < offset + length) {
            sum += ((bytes[at].toInt() and 255) shl 8) or (bytes[at + 1].toInt() and 255)
            at += 2
        }
        if (at < offset + length) sum += (bytes[at].toInt() and 255) shl 8
        return sum
    }

    private fun checksum(sumInput: Int): Int {
        var sum = sumInput
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        return sum.inv() and 65535
    }

    private fun tcpPacket(ipVersion: Int, payload: ByteArray = byteArrayOf(), tcpOptions: Int = 0): ByteArray {
        val ipHeader = if (ipVersion == 4) 20 else 40
        val tcpLength = 20 + tcpOptions + payload.size
        val packet = ByteArray(ipHeader + tcpLength)
        val addressBytes = if (ipVersion == 4) 4 else 16
        val sourceOffset = if (ipVersion == 4) 12 else 8
        val destOffset = if (ipVersion == 4) 16 else 24
        packet[0] = (if (ipVersion == 4) 0x45 else 0x60).toByte()
        if (ipVersion == 4) {
            put16(packet, 2, packet.size)
            packet[8] = 64
            packet[9] = 6
        } else {
            put16(packet, 4, tcpLength)
            packet[6] = 6
            packet[7] = 64
        }
        for (i in 0 until addressBytes) {
            packet[sourceOffset + i] = (i + 1).toByte()
            packet[destOffset + i] = (i + 33).toByte()
        }
        put16(packet, ipHeader, 12345)
        put16(packet, ipHeader + 2, 443)
        packet[ipHeader + 12] = ((20 + tcpOptions) / 4 shl 4).toByte()
        packet[ipHeader + 13] = 0x02 // SYN (fixture, not a real connection)
        put16(packet, ipHeader + 14, 4096)
        payload.copyInto(packet, ipHeader + 20 + tcpOptions)
        val pseudo = wordSum(packet, sourceOffset, addressBytes) +
            wordSum(packet, destOffset, addressBytes) + tcpLength + 6
        put16(packet, ipHeader + 16, checksum(pseudo + wordSum(packet, ipHeader, tcpLength)))
        if (ipVersion == 4) put16(packet, 10, checksum(wordSum(packet, 0, ipHeader)))
        return packet
    }

    @Test fun acceptsChecksummedIpv4AndIpv6TcpIncludingOddPayloadAndOptions() {
        for (version in listOf(4, 6)) {
            val packet = tcpPacket(version, byteArrayOf(1, 2, 3), tcpOptions = 4)
            val header = parseTunPacketHeader(packet, packet.size)
            assertNotNull("IPv$version", header)
            assertEquals(6, header!!.protocol)
            assertEquals(24, header.transportHeaderBytes)
            assertEquals(443, header.destinationPort)
            assertTrue(readOneTunDatagram(ByteArrayInputStream(packet), 1500) is TunIngressResult.Packet)
        }
    }

    @Test fun rejectsCorruptTcpPayloadOrChecksumInBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val original = tcpPacket(version, byteArrayOf(1, 2, 3))
            val badPayload = original.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
            val tcpOffset = if (version == 4) 20 else 40
            val badChecksum = original.clone().apply { this[tcpOffset + 16] = (this[tcpOffset + 16].toInt() xor 1).toByte() }
            assertNull(parseTunPacketHeader(badPayload, badPayload.size))
            assertNull(parseTunPacketHeader(badChecksum, badChecksum.size))
            assertSame(TunIngressResult.Rejected,
                readOneTunDatagram(ByteArrayInputStream(badPayload), 1500))
        }
    }

    @Test fun rejectsTcpPseudoHeaderAddressMismatchEvenWithValidIpv4HeaderChecksum() {
        val packet = tcpPacket(4)
        packet[12] = 9 // Mutate source address, then repair *only* the IPv4 header checksum.
        put16(packet, 10, 0)
        put16(packet, 10, checksum(wordSum(packet, 0, 20)))
        assertNull(parseTunPacketHeader(packet, packet.size))
    }

    @Test fun rejectsTruncatedTcpOptionsAndWrongIpv6PayloadLength() {
        val packet = tcpPacket(6, tcpOptions = 4)
        val invalidOffset = packet.clone().apply { this[40 + 12] = 0xf0.toByte() }
        assertNull(parseTunPacketHeader(invalidOffset, invalidOffset.size))
        val invalidLength = packet.clone().apply { this[5] = (this[5].toInt() + 1).toByte() }
        assertNull(parseTunPacketHeader(invalidLength, invalidLength.size))
    }
}
