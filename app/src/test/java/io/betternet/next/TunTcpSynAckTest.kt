package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

/** Offline TCP handshake fixtures: no VPN, gateway, listener, or Internet I/O. */
class TunTcpSynAckTest {
    private fun u16(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 255) shl 8) or (b[at + 1].toInt() and 255)
    private fun u32(b: ByteArray, at: Int): Long =
        (u16(b, at).toLong() shl 16) or u16(b, at + 2).toLong()
    private fun put16(b: ByteArray, at: Int, value: Int) {
        b[at] = (value ushr 8).toByte()
        b[at + 1] = value.toByte()
    }
    private fun put32(b: ByteArray, at: Int, value: Long) {
        put16(b, at, (value ushr 16).toInt())
        put16(b, at + 2, value.toInt())
    }
    private fun sum(b: ByteArray, at: Int, count: Int): Int {
        var s = 0
        for (i in 0 until count step 2) {
            s += (b[at + i].toInt() and 255) shl 8
            if (i + 1 < count) s += b[at + i + 1].toInt() and 255
        }
        return s
    }
    private fun checksum(initial: Int): Int {
        var s = initial
        while (s > 65535) s = (s and 65535) + (s ushr 16)
        return s.inv() and 65535
    }
    private fun tcpChecksum(b: ByteArray, version: Int): Int {
        val ip = if (version == 4) 20 else 40
        val addrSize = if (version == 4) 4 else 16
        val src = if (version == 4) 12 else 8
        val dst = if (version == 4) 16 else 24
        val length = b.size - ip
        return checksum(sum(b, src, addrSize) + sum(b, dst, addrSize) +
            length + 6 + sum(b, ip, length))
    }
    private fun request(
        version: Int, flags: Int = 2, options: ByteArray = byteArrayOf(),
        payload: ByteArray = byteArrayOf(), ack: Long = 0,
        destinationPort: Int = 443,
    ): TunIngressResult.Packet {
        require(options.size % 4 == 0)
        val ip = if (version == 4) 20 else 40
        val b = ByteArray(ip + 20 + options.size + payload.size)
        b[0] = (if (version == 4) 0x45 else 0x60).toByte()
        if (version == 4) {
            put16(b, 2, b.size)
            b[8] = 64; b[9] = 6
        } else {
            put16(b, 4, b.size - ip)
            b[6] = 6; b[7] = 64
        }
        val src = if (version == 4) 12 else 8
        val dst = if (version == 4) 16 else 24
        val addrSize = if (version == 4) 4 else 16
        for (i in 0 until addrSize) {
            b[src + i] = (i + 1).toByte()
            b[dst + i] = (i + 33).toByte()
        }
        put16(b, ip, 49152)
        put16(b, ip + 2, destinationPort)
        put32(b, ip + 4, 0xffff_ffffL)
        put32(b, ip + 8, ack)
        b[ip + 12] = ((20 + options.size) / 4 shl 4).toByte()
        b[ip + 13] = flags.toByte()
        put16(b, ip + 14, 8192)
        options.copyInto(b, ip + 20)
        payload.copyInto(b, ip + 20 + options.size)
        put16(b, ip + 16, tcpChecksum(b, version))
        if (version == 4) put16(b, 10, checksum(sum(b, 0, 20)))
        return TunIngressResult.Packet(b, parseTunPacketHeader(b, b.size)!!)
    }

    @Test fun returnsChecksummedIpv4AndIpv6SynAckWithWrappedAcknowledgement() {
        for (version in listOf(4, 6)) {
            // Client advertises MSS and SACK-permitted; server does not
            // accidentally advertise window scaling or other capabilities.
            val syn = request(version, options = byteArrayOf(2, 4, 5, 0xB4.toByte(), 4, 2, 1, 1))
            val reply = buildTcpSynAck(syn, 0x1234_5678L, 1280)!!
            val ip = if (version == 4) 20 else 40
            assertEquals(ip + 24, reply.size)
            assertEquals(0, tcpChecksum(reply, version))
            if (version == 4) assertEquals(0, checksum(sum(reply, 0, 20)))
            val parsed = parseTunPacketHeader(reply, reply.size)!!
            assertEquals(version, parsed.ipVersion)
            assertEquals(syn.header.source, parsed.destination)
            assertEquals(syn.header.destination, parsed.source)
            assertEquals(443, parsed.sourcePort)
            assertEquals(49152, parsed.destinationPort)
            assertEquals(0x1234_5678L, u32(reply, ip + 4))
            assertEquals(0L, u32(reply, ip + 8)) // 2^32 wrap
            assertEquals(0x12, reply[ip + 13].toInt() and 255)
            assertEquals(0, u16(reply, ip + 14)) // no receive capacity promised
            assertEquals(2, reply[ip + 20].toInt())
            assertEquals(4, reply[ip + 21].toInt())
            assertEquals(1280 - ip - 20, u16(reply, ip + 22))
        }
    }

    @Test fun rejectsMalformedOrUnsupportedSynWithoutAllocatingFlowState() {
        for (version in listOf(4, 6)) {
            for (bad in listOf(
                request(version, flags = 0x12), // ACK before handshake
                request(version, flags = 0x03), // SYN+FIN
                request(version, ack = 1),
                request(version, payload = byteArrayOf(1, 2, 3)), // SYN data unsupported
                request(version, destinationPort = 80),
                request(version, options = byteArrayOf(2, 3, 0, 0)), // invalid MSS length
                request(version, options = byteArrayOf(30, 2, 0, 0)), // unknown option
                request(version, options = byteArrayOf(3, 3, 15, 0)), // invalid scale
                request(version, options = byteArrayOf(0, 1, 0, 0)), // nonzero EOL padding
            )) {
                assertNull("IPv$version", buildTcpSynAck(bad, 123L, 1280))
            }
            val good = request(version)
            assertNull(buildTcpSynAck(good, -1, 1280))
            assertNull(buildTcpSynAck(good, 0x1_0000_0000L, 1280))
            val corrupt = good.bytes.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
            assertNull(buildTcpSynAck(good.copy(bytes = corrupt), 123L, 1280))
        }
    }


    private fun finalAck(syn: TunIngressResult.Packet, serverIsn: Long, flags: Int = 0x10,
                         sequence: Long = 0L, acknowledgement: Long = (serverIsn + 1) and 0xffff_ffffL,
                         payload: ByteArray = byteArrayOf(), sourcePort: Int = 49152): TunIngressResult.Packet {
        val version = syn.header.ipVersion
        val ip = if (version == 4) 20 else 40
        val b = syn.bytes.copyOf(ip + 20 + payload.size)
        if (version == 4) put16(b, 2, b.size) else put16(b, 4, b.size - ip)
        put16(b, ip, sourcePort)
        put32(b, ip + 4, sequence)
        put32(b, ip + 8, acknowledgement)
        b[ip + 12] = 0x50
        b[ip + 13] = flags.toByte()
        payload.copyInto(b, ip + 20)
        put16(b, ip + 16, 0)
        if (version == 4) put16(b, 10, 0)
        put16(b, ip + 16, tcpChecksum(b, version))
        if (version == 4) put16(b, 10, checksum(sum(b, 0, 20)))
        return TunIngressResult.Packet(b, parseTunPacketHeader(b, b.size)!!)
    }

    @Test fun tracksExactlyOneHandshakeAndWraparoundForBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val handshake = OfflineTcpHandshake(1000)
            val syn = request(version)
            val reply = handshake.begin(syn, 0xffff_ffffL, 1280, 100)!!
            assertEquals(0x12, reply[if (version == 4) 33 else 53].toInt() and 255)
            assertFalse(handshake.isEstablished(101))
            assertNull(handshake.begin(syn, 1L, 1280, 102))
            assertTrue(handshake.acceptFinalAck(finalAck(syn, 0xffff_ffffL), 103))
            assertTrue(handshake.isEstablished(104))
            assertFalse(handshake.acceptFinalAck(finalAck(syn, 0xffff_ffffL), 105))
            assertFalse(handshake.isEstablished(1100)) // expired, no immortal flow
            assertNotNull(handshake.begin(syn, 2L, 1280, 1101))
            handshake.close()
            assertFalse(handshake.isEstablished(1102))
        }
    }

    @Test fun rejectsCrossFlowReplaysPayloadAndWrongSequenceWithoutChangingState() {
        for (version in listOf(4, 6)) {
            val handshake = OfflineTcpHandshake()
            val syn = request(version)
            assertNotNull(handshake.begin(syn, 123L, 1280, 500))
            for (bad in listOf(
                finalAck(syn, 123L, acknowledgement = 125),
                finalAck(syn, 123L, sequence = 1),
                finalAck(syn, 123L, flags = 0x18),
                finalAck(syn, 123L, payload = byteArrayOf(1)),
                finalAck(syn, 123L, sourcePort = 49153),
            )) {
                assertFalse(handshake.acceptFinalAck(bad, 501))
                assertFalse(handshake.isEstablished(502))
            }
            assertFalse(handshake.acceptFinalAck(finalAck(syn, 123L), 499))
            assertFalse(handshake.isEstablished(503)) // clock rollback drops state
            assertNotNull(handshake.begin(syn, 124L, 1280, 504))
            assertTrue(handshake.acceptFinalAck(finalAck(syn, 124L), 505))
        }
    }

    @Test fun expiredHandshakeRejectsLateAckAndCanBeSafelyReplaced() {
        val handshake = OfflineTcpHandshake(10)
        val syn = request(4)
        assertNotNull(handshake.begin(syn, 50, 1280, 100))
        assertFalse(handshake.acceptFinalAck(finalAck(syn, 50), 110))
        assertNotNull(handshake.begin(syn, 60, 1280, 111))
        assertFalse(handshake.acceptFinalAck(finalAck(syn, 50), 112))
        assertTrue(handshake.acceptFinalAck(finalAck(syn, 60), 113))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnboundedMtu() {
        buildTcpSynAck(request(4), 123L, 1000)
    }
}
