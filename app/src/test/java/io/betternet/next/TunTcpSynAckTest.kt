package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
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

    @Test fun returnsBoundedChecksummedDataAndTracksExactAcknowledgement() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val handshake = OfflineTcpHandshake(1000)
            val serverIsn = 0xffff_fffdL
            assertNotNull(handshake.begin(syn, serverIsn, 1280, 100))
            val payload = "hello".toByteArray(Charsets.US_ASCII)
            assertNull(handshake.offerResponse(payload, 1280, 101)) // third ACK missing
            assertTrue(handshake.acceptFinalAck(finalAck(syn, serverIsn), 102))
            assertNull(handshake.offerResponse(byteArrayOf(), 1280, 103))
            assertNull(handshake.offerResponse(ByteArray(2000), 1280, 103))
            val response = handshake.offerResponse(payload, 1280, 104)!!
            val ip = if (version == 4) 20 else 40
            assertEquals(ip + 20 + payload.size, response.size)
            assertEquals(0, tcpChecksum(response, version))
            if (version == 4) assertEquals(0, checksum(sum(response, 0, 20)))
            val header = parseTunPacketHeader(response, response.size)!!
            assertEquals(syn.header.destination, header.source)
            assertEquals(syn.header.source, header.destination)
            assertEquals(443, header.sourcePort)
            assertEquals(49152, header.destinationPort)
            assertEquals(0xffff_fffeL, u32(response, ip + 4))
            assertEquals(0L, u32(response, ip + 8))
            assertEquals(0x18, response[ip + 13].toInt() and 255)
            assertEquals(0, u16(response, ip + 14))
            assertArrayEquals(payload, response.copyOfRange(ip + 20, response.size))
            assertNull(handshake.offerResponse(payload, 1280, 105)) // one in-flight only

            assertFalse(handshake.acceptResponseAck(finalAck(syn, serverIsn, acknowledgement = 2), 106))
            assertFalse(handshake.acceptResponseAck(finalAck(syn, serverIsn,
                acknowledgement = 3, flags = 0x18), 107))
            assertFalse(handshake.acceptResponseAck(finalAck(syn, serverIsn,
                acknowledgement = 3, sourcePort = 49153), 108))
            assertFalse(handshake.acceptResponseAck(finalAck(syn, serverIsn,
                acknowledgement = 3, sequence = 1), 109))
            assertTrue(handshake.acceptResponseAck(finalAck(syn, serverIsn,
                acknowledgement = 3), 110))
            assertFalse(handshake.acceptResponseAck(finalAck(syn, serverIsn,
                acknowledgement = 3), 111))
            val second = handshake.offerResponse(byteArrayOf(42), 1280, 112)!!
            assertEquals(3L, u32(second, ip + 4)) // wrapped and advanced
            assertFalse(handshake.acceptResponseAck(finalAck(syn, serverIsn,
                acknowledgement = 4), 110)) // clock rollback fails closed
            assertFalse(handshake.isEstablished(113))
        }
    }

    @Test fun responseReplyRejectsInvalidMtuPayloadAndAddressFamily() {
        val syn = request(4)
        val handshake = OfflineTcpHandshake(100)
        assertNotNull(handshake.begin(syn, 123L, 1280, 10))
        assertTrue(handshake.acceptFinalAck(finalAck(syn, 123L), 11))
        assertNull(handshake.offerResponse(ByteArray(1241), 1280, 12))
        assertNotNull(handshake.offerResponse(ByteArray(1240), 1280, 13))
        assertFalse(handshake.acceptResponseAck(finalAck(syn, 123L, acknowledgement = 1364), 110))
        assertFalse(handshake.isEstablished(111))
        assertNull(buildTcpDataReply(syn.header.source, java.net.InetAddress.getByAddress(ByteArray(16)),
            443, 49152, 1, 1, byteArrayOf(1), 1280))
    }

    @Test fun stagesBoundedClientDataAndAcknowledgesOnlyAfterConfirmedDelivery() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val state = OfflineTcpHandshake(1000)
            val serverIsn = 0xffff_fffeL
            val synAck = state.begin(syn, serverIsn, 1280, 100, clientWindow = 1024)!!
            val ip = if (version == 4) 20 else 40
            assertEquals(1024, u16(synAck, ip + 14))
            assertTrue(state.acceptFinalAck(finalAck(syn, serverIsn), 101))
            assertNull(state.forwardStagedClientPayload(ByteArrayOutputStream(), 102))
            val data = byteArrayOf(71, 69, 84)
            val incoming = finalAck(syn, serverIsn, flags = 0x10,
                acknowledgement = 0xffff_ffffL, payload = data)
            val staged = state.stageClientPayload(incoming, 103)!!
            assertArrayEquals(data, staged)
            staged[0] = 0 // Caller must not mutate the internal staged bytes.
            assertNull(state.stageClientPayload(incoming, 104)) // no second buffered segment
            assertNull(state.offerResponse(byteArrayOf(1), 1280, 105)) // no response before delivery
            val tunnelOutput = ByteArrayOutputStream()
            val ack = state.forwardStagedClientPayload(tunnelOutput, 106)!!
            assertArrayEquals(data, tunnelOutput.toByteArray())
            assertEquals(0, tcpChecksum(ack, version))
            if (version == 4) assertEquals(0, checksum(sum(ack, 0, 20)))
            assertEquals(0x10, ack[ip + 13].toInt() and 255)
            assertEquals(0, u16(ack, ip + 14)) // no further client window promised
            assertEquals(3L, u32(ack, ip + 8)) // wrapped client sequence + 3
            assertEquals(0xffff_ffffL, u32(ack, ip + 4))
            assertNull(state.forwardStagedClientPayload(ByteArrayOutputStream(), 107))
            assertNull(state.stageClientPayload(incoming, 108)) // zero-window after delivery
        }
    }

    @Test fun forwardsMultipleClientSegmentsOnlyAfterExplicitBoundedWindowReopen() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val state = OfflineTcpHandshake(1000)
            val isn = 0xffff_fffeL
            val ip = if (version == 4) 20 else 40
            assertNotNull(state.begin(syn, isn, 1280, 100, clientWindow = 4))
            assertTrue(state.acceptFinalAck(finalAck(syn, isn), 101))
            val first = finalAck(syn, isn, flags = 0x18,
                acknowledgement = 0xffff_ffffL, payload = byteArrayOf(1, 2, 3))
            assertNotNull(state.stageClientPayload(first, 102))
            val output = ByteArrayOutputStream()
            try {
                state.forwardStagedClientPayload(output, 103, nextReceiveWindow = 1025)
                fail("Unbounded advertised window")
            } catch (_: IllegalArgumentException) { }
            assertEquals(0, output.size()) // validation must precede any write
            val firstAck = state.forwardStagedClientPayload(output, 104, nextReceiveWindow = 4)!!
            assertEquals(4, u16(firstAck, ip + 14))
            assertEquals(0, tcpChecksum(firstAck, version))
            assertEquals(3L, u32(firstAck, ip + 8))
            val stale = finalAck(syn, isn, flags = 0x18,
                acknowledgement = 0xffff_ffffL, payload = byteArrayOf(7))
            assertNull(state.stageClientPayload(stale, 105))
            val second = finalAck(syn, isn, flags = 0x18, sequence = 3,
                acknowledgement = 0xffff_ffffL, payload = byteArrayOf(4, 5))
            assertArrayEquals(byteArrayOf(4, 5), state.stageClientPayload(second, 106))
            val secondAck = state.forwardStagedClientPayload(output, 107)!!
            assertEquals(0, u16(secondAck, ip + 14)) // default fail-closed
            assertEquals(5L, u32(secondAck, ip + 8))
            assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5), output.toByteArray())
            assertNull(state.stageClientPayload(finalAck(syn, isn, flags = 0x18,
                sequence = 5, acknowledgement = 0xffff_ffffL,
                payload = byteArrayOf(6)), 108))
            // Full offline round trip on the same flow: gateway reply -> TUN.
            val reply = state.readTunnelResponse(ByteArrayInputStream(byteArrayOf(9, 8)), 1280, 109)!!
            assertEquals(5L, u32(reply, ip + 8))
            assertArrayEquals(byteArrayOf(9, 8), reply.copyOfRange(ip + 20, reply.size))
            assertTrue(state.acceptResponseAck(finalAck(syn, isn,
                sequence = 5, acknowledgement = 1), 110))
        }
    }

    @Test fun clientIngressRejectsWrongSequenceAckTupleChecksumAndOversize() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val state = OfflineTcpHandshake(1000)
            assertNotNull(state.begin(syn, 99L, 1280, 200, clientWindow = 4))
            assertTrue(state.acceptFinalAck(finalAck(syn, 99L), 201))
            val valid = finalAck(syn, 99L, flags = 0x18,
                acknowledgement = 100L, payload = byteArrayOf(1, 2, 3, 4))
            val corrupted = valid.bytes.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
            for (bad in listOf(
                finalAck(syn, 99L, flags = 0x18, sequence = 1,
                    acknowledgement = 100L, payload = byteArrayOf(1)),
                finalAck(syn, 99L, flags = 0x18, acknowledgement = 101L, payload = byteArrayOf(1)),
                finalAck(syn, 99L, flags = 0x18, acknowledgement = 100L,
                    sourcePort = 49153, payload = byteArrayOf(1)),
                finalAck(syn, 99L, flags = 0x18, acknowledgement = 100L,
                    payload = ByteArray(5)),
                finalAck(syn, 99L, flags = 0x11, acknowledgement = 100L,
                    payload = byteArrayOf(1)),
                valid.copy(bytes = corrupted),
            )) assertNull(state.stageClientPayload(bad, 202))
            assertArrayEquals(byteArrayOf(1, 2, 3, 4), state.stageClientPayload(valid, 203))
            assertNull(state.forwardStagedClientPayload(ByteArrayOutputStream(), 1200)) // expired, no stale ACK
            assertFalse(state.isEstablished(1201))
        }
        assertNull(OfflineTcpHandshake().begin(request(4), 1L, 1280, 1, clientWindow = 1025))
    }

    @Test fun failedTunnelWriteOrFlushNeverAcknowledgesAndClosesFlow() {
        for (version in listOf(4, 6)) {
            for (failOnFlush in listOf(false, true)) {
                val syn = request(version)
                val state = OfflineTcpHandshake(1000)
                assertNotNull(state.begin(syn, 7, 1280, 100, clientWindow = 16))
                assertTrue(state.acceptFinalAck(finalAck(syn, 7), 101))
                val data = finalAck(syn, 7, flags = 0x18,
                    acknowledgement = 8, payload = byteArrayOf(1, 2, 3))
                assertNotNull(state.stageClientPayload(data, 102))
                var closed = false
                val broken = object : OutputStream() {
                    override fun write(b: Int) { throw IOException("partial write") }
                    override fun write(b: ByteArray, off: Int, len: Int) {
                        if (!failOnFlush) throw IOException("partial write")
                    }
                    override fun flush() {
                        if (failOnFlush) throw IOException("flush failed")
                    }
                    override fun close() { closed = true }
                }
                try {
                    state.forwardStagedClientPayload(broken, 103)
                    fail("Expected tunnel failure")
                } catch (_: IOException) { }
                assertTrue(closed)
                assertFalse(state.isEstablished(104))
                assertNull(state.forwardStagedClientPayload(ByteArrayOutputStream(), 105))
                // A new flow may begin, but no stale ACK can be issued.
                assertNotNull(state.begin(syn, 8, 1280, 106, clientWindow = 16))
            }
        }
    }

    @Test fun exactClientResetRetiresFlowButSpoofedOrMalformedResetCannot() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val flow = OfflineTcpHandshake()
            val isn = 0xffff_fffeL
            assertNotNull(flow.begin(syn, isn, 1280, 100, clientWindow = 8))
            val reset = finalAck(syn, isn, flags = 0x14)
            assertFalse(flow.acceptClientReset(reset, 101)) // no handshake yet
            assertTrue(flow.acceptFinalAck(finalAck(syn, isn), 102))
            assertNotNull(flow.offerResponse(byteArrayOf(7, 8, 9), 1280, 103))
            val badChecksum = reset.bytes.clone().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            for (bad in listOf(
                finalAck(syn, isn, flags = 0x14, sequence = 1),
                finalAck(syn, isn, flags = 0x14, acknowledgement = 123),
                finalAck(syn, isn, flags = 0x14, sourcePort = 49153),
                finalAck(syn, isn, flags = 0x15),
                finalAck(syn, isn, flags = 0x14, payload = byteArrayOf(1)),
                reset.copy(bytes = badChecksum),
            )) {
                assertFalse(flow.acceptClientReset(bad, 104))
                assertTrue(flow.isEstablished(105))
            }
            // A reset acknowledging in-flight bytes is accepted, including wraparound.
            assertTrue(flow.acceptClientReset(finalAck(syn, isn, flags = 0x14,
                acknowledgement = 2), 106))
            assertFalse(flow.isEstablished(107))
            assertNull(flow.retryPendingResponse(108))
            assertNull(flow.stageClientPayload(finalAck(syn, isn, flags = 0x18,
                payload = byteArrayOf(1)), 109))
            // Reusing the old reset cannot affect a fresh flow with a different ISN.
            assertNotNull(flow.begin(syn, 55, 1280, 110))
            assertTrue(flow.acceptFinalAck(finalAck(syn, 55), 111))
            assertFalse(flow.acceptClientReset(reset, 112))
            assertTrue(flow.acceptClientReset(finalAck(syn, 55, flags = 0x14), 113))
            assertFalse(flow.isEstablished(114))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnboundedMtu() {
        buildTcpSynAck(request(4), 123L, 1000)
    }

    @Test fun readsOnlyOneMtuBoundedGatewaySegmentUntilClientAckForBothFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val flow = OfflineTcpHandshake()
            val isn = 0x1234L
            assertNotNull(flow.begin(syn, isn, 1280, 100))
            val sourceBytes = ByteArray(1400) { (it % 251).toByte() }
            val stream = ByteArrayInputStream(sourceBytes)
            assertNull(flow.readTunnelResponse(stream, 1280, 101)) // not established
            assertEquals(sourceBytes.size, stream.available())
            assertTrue(flow.acceptFinalAck(finalAck(syn, isn), 102))
            val first = flow.readTunnelResponse(stream, 1280, 103)!!
            val ip = if (version == 4) 20 else 40
            val segmentSize = 1280 - ip - 20
            assertEquals(0, tcpChecksum(first, version))
            assertArrayEquals(sourceBytes.copyOfRange(0, segmentSize),
                first.copyOfRange(ip + 20, first.size))
            assertEquals(sourceBytes.size - segmentSize, stream.available())
            assertNull(flow.readTunnelResponse(stream, 1280, 104)) // no read-ahead
            assertEquals(sourceBytes.size - segmentSize, stream.available())
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = (isn + 1 + segmentSize) and 0xffff_ffffL), 105))
            val second = flow.readTunnelResponse(stream, 1280, 106)!!
            assertArrayEquals(sourceBytes.copyOfRange(segmentSize, sourceBytes.size),
                second.copyOfRange(ip + 20, second.size))
            assertEquals(0, stream.available())
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = (isn + 1 + sourceBytes.size) and 0xffff_ffffL), 107))
            assertNull(flow.readTunnelResponse(stream, 1280, 108)) // EOF retires flow
            assertFalse(flow.isEstablished(109))
        }
    }

    @Test fun retriesOnlyExactUnacknowledgedResponseWithBoundedBackoff() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val flow = OfflineTcpHandshake(10_000)
            val isn = 0xffff_fffeL
            assertNotNull(flow.begin(syn, isn, 1280, 100))
            assertTrue(flow.acceptFinalAck(finalAck(syn, isn), 101))
            assertNull(flow.retryPendingResponse(102))
            val initial = flow.offerResponse(byteArrayOf(7, 8, 9), 1280, 200)!!
            assertFalse(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = 3), 201)) // wrong ACK must retain cached bytes
            assertNull(flow.retryPendingResponse(699))
            val first = flow.retryPendingResponse(700)!!
            assertArrayEquals(initial, first)
            first[first.lastIndex] = 0 // defensive copy; cached packet stays intact
            assertNull(flow.retryPendingResponse(1699))
            assertArrayEquals(initial, flow.retryPendingResponse(1700))
            assertNull(flow.retryPendingResponse(3699))
            assertArrayEquals(initial, flow.retryPendingResponse(3700))
            assertNull(flow.retryPendingResponse(8000)) // retry budget exhausted
            assertNull(flow.offerResponse(byteArrayOf(1), 1280, 8001))
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = 2), 8002)) // sequence wraps: 0xffffffff + 3 -> 2
            assertNull(flow.retryPendingResponse(8003))
            assertNotNull(flow.offerResponse(byteArrayOf(42), 1280, 8004))
            assertNull(flow.retryPendingResponse(8503)) // fresh retry clock
            assertNotNull(flow.retryPendingResponse(8504))
            assertFalse(flow.isEstablished(10_100)) // hard lease retires flow
            assertNull(flow.retryPendingResponse(10_101))
        }
    }

    @Test fun retryNeverRevivesFlowAfterClockRollbackOrClose() {
        val syn = request(4)
        val flow = OfflineTcpHandshake(5000)
        assertNotNull(flow.begin(syn, 123, 1280, 100))
        assertTrue(flow.acceptFinalAck(finalAck(syn, 123), 101))
        assertNotNull(flow.offerResponse(byteArrayOf(1), 1280, 102))
        assertNull(flow.retryPendingResponse(101)) // rollback closes state
        assertFalse(flow.isEstablished(103))
        assertNotNull(flow.begin(syn, 124, 1280, 104))
        assertTrue(flow.acceptFinalAck(finalAck(syn, 124), 105))
        assertNotNull(flow.offerResponse(byteArrayOf(2), 1280, 106))
        flow.close()
        assertNull(flow.retryPendingResponse(1000))
    }

    @Test fun gatewayReadFailureClosesFlowAndDoesNotGenerateResponse() {
        val syn = request(4)
        val flow = OfflineTcpHandshake()
        assertNotNull(flow.begin(syn, 99, 1280, 1))
        assertTrue(flow.acceptFinalAck(finalAck(syn, 99), 2))
        var closed = false
        val broken = object : InputStream() {
            override fun read(): Int = throw IOException("simulated tunnel read failure")
            override fun read(b: ByteArray, off: Int, len: Int): Int = throw IOException("simulated tunnel read failure")
            override fun close() { closed = true }
        }
        try {
            flow.readTunnelResponse(broken, 1280, 3)
            fail("Expected a gateway read failure")
        } catch (expected: IOException) {
            assertEquals("simulated tunnel read failure", expected.message)
        }
        assertTrue(closed)
        assertFalse(flow.isEstablished(4))
        assertNull(flow.offerResponse(byteArrayOf(1), 1280, 5))
    }
}
