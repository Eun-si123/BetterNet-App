package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.SocketTimeoutException
import java.io.OutputStream
import org.junit.Assert.*
import org.junit.Test

/** Offline TCP handshake fixtures: no VPN, gateway, listener, or Internet I/O. */
class TunTcpSynAckTest {
    internal fun u16(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 255) shl 8) or (b[at + 1].toInt() and 255)
    internal fun u32(b: ByteArray, at: Int): Long =
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
    internal fun tcpChecksum(b: ByteArray, version: Int): Int {
        val ip = if (version == 4) 20 else 40
        val addrSize = if (version == 4) 4 else 16
        val src = if (version == 4) 12 else 8
        val dst = if (version == 4) 16 else 24
        val length = b.size - ip
        return checksum(sum(b, src, addrSize) + sum(b, dst, addrSize) +
            length + 6 + sum(b, ip, length))
    }
    internal fun request(
        version: Int, flags: Int = 2, options: ByteArray = byteArrayOf(),
        payload: ByteArray = byteArrayOf(), ack: Long = 0,
        destinationPort: Int = 443, destinationSeed: Int = 33,
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
            b[dst + i] = (i + destinationSeed).toByte()
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


    internal fun finalAck(syn: TunIngressResult.Packet, serverIsn: Long, flags: Int = 0x10,
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

    @Test fun duplicateSynRetransmitsOnlyOriginalSynAckWithinBoundedBudget() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val output = ByteArrayOutputStream()
            var closes = 0
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(),
                1280, 123L, allowedDestination = syn.header.destination,
                onClose = { closes++ },
            )
            fun deliver(packet: TunIngressResult.Packet, time: Long): ByteArray {
                output.reset()
                assertTrue(bridge.pumpOneTunPacket(
                    ByteArrayInputStream(packet.bytes), output, time
                ))
                return output.toByteArray()
            }
            val first = deliver(syn, 100)
            assertTrue(first.isNotEmpty())
            assertTrue(deliver(syn, 599).isEmpty())
            assertTrue(deliver(request(version, destinationSeed = 34), 600).isEmpty())
            assertTrue(deliver(request(version, options = byteArrayOf(1, 1, 1, 1)), 600).isEmpty())
            // A retransmitted IP packet may have a different hop limit/TTL;
            // only its validated TCP segment needs to match the original.
            val changedIp = syn.bytes.clone()
            changedIp[if (version == 4) 8 else 7] = 63
            if (version == 4) {
                put16(changedIp, 10, 0)
                put16(changedIp, 10, checksum(sum(changedIp, 0, 20)))
            }
            val changedSyn = TunIngressResult.Packet(
                changedIp, parseTunPacketHeader(changedIp, changedIp.size)!!
            )
            assertArrayEquals(first, deliver(changedSyn, 600))
            assertTrue(deliver(syn, 1599).isEmpty())
            assertArrayEquals(first, deliver(syn, 1600))
            assertTrue(deliver(syn, 3599).isEmpty())
            assertArrayEquals(first, deliver(syn, 3600))
            assertTrue(deliver(syn, 8000).isEmpty()) // retry budget exhausted
            assertEquals(0, closes)
            assertTrue(deliver(finalAck(syn, 123L), 8001).isEmpty())
            assertTrue(deliver(syn, 9000).isEmpty()) // established: no SYN-ACK replay
            bridge.close()
            assertEquals(1, closes)
        }
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
        val syn = request(4, options = byteArrayOf(2, 4, 5, 0xB4.toByte()))
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

    @Test fun responseAckWithClientPayloadMatchesSeparateAckAndPayloadForBothFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val isn = 0xffff_fffeL
            val expectedAck = 1L // server SYN (0xffffffff) + one + 2 reply bytes, modulo 2^32
            val payload = byteArrayOf(11, 22, 33)
            fun flow(): OfflineTcpHandshake = OfflineTcpHandshake(1000).also {
                assertNotNull(it.begin(syn, isn, 1280, 100, clientWindow = 4))
                assertTrue(it.acceptFinalAck(finalAck(syn, isn), 101))
                assertNotNull(it.offerResponse(byteArrayOf(9, 8), 1280, 102))
            }
            val combined = flow()
            val separate = flow()
            val incoming = finalAck(syn, isn, flags = 0x18,
                acknowledgement = expectedAck, payload = payload)
            assertArrayEquals(payload, combined.stageClientPayload(incoming, 103))
            assertNull(combined.retryPendingResponse(603)) // combined ACK retired reply
            val combinedOut = ByteArrayOutputStream()
            val combinedAck = combined.forwardStagedClientPayload(combinedOut, 604)!!
            assertTrue(separate.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = expectedAck), 103))
            assertArrayEquals(payload, separate.stageClientPayload(incoming, 104))
            val separateOut = ByteArrayOutputStream()
            val separateAck = separate.forwardStagedClientPayload(separateOut, 604)!!
            assertArrayEquals(payload, combinedOut.toByteArray())
            assertArrayEquals(separateOut.toByteArray(), combinedOut.toByteArray())
            assertArrayEquals(separateAck, combinedAck)
            assertEquals(0, tcpChecksum(combinedAck, version))
            val ip = if (version == 4) 20 else 40
            assertEquals(expectedAck, u32(combinedAck, ip + 4))
            assertEquals(payload.size.toLong(), u32(combinedAck, ip + 8))
        }
    }

    @Test fun malformedPiggybackAckNeverRetiresResponseOrForwardsClientBytes() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val isn = 123L
            val flow = OfflineTcpHandshake(1000)
            assertNotNull(flow.begin(syn, isn, 1280, 100, clientWindow = 4))
            assertTrue(flow.acceptFinalAck(finalAck(syn, isn), 101))
            val response = flow.offerResponse(byteArrayOf(9, 8), 1280, 102)!!
            val good = finalAck(syn, isn, flags = 0x18,
                acknowledgement = 126L, payload = byteArrayOf(1, 2))
            val corrupted = good.bytes.clone().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            for (invalid in listOf(
                finalAck(syn, isn, flags = 0x18, acknowledgement = 124L,
                    payload = byteArrayOf(1, 2)), // stale ACK
                finalAck(syn, isn, flags = 0x18, acknowledgement = 127L,
                    payload = byteArrayOf(1, 2)), // unsent server bytes
                finalAck(syn, isn, flags = 0x18, sequence = 1,
                    acknowledgement = 126L, payload = byteArrayOf(1, 2)),
                finalAck(syn, isn, flags = 0x18, acknowledgement = 126L,
                    sourcePort = 49153, payload = byteArrayOf(1, 2)),
                finalAck(syn, isn, flags = 0x11, acknowledgement = 126L,
                    payload = byteArrayOf(1, 2)), // FIN with data not supported
                finalAck(syn, isn, flags = 0x18, acknowledgement = 126L,
                    payload = ByteArray(5) { 1 }), // exceeds advertised window
                good.copy(bytes = corrupted),
            )) assertNull(flow.stageClientPayload(invalid, 103))
            assertArrayEquals(response, flow.retryPendingResponse(603))
            assertArrayEquals(byteArrayOf(1, 2), flow.stageClientPayload(good, 604))
            val upstream = ByteArrayOutputStream()
            assertNotNull(flow.forwardStagedClientPayload(upstream, 605))
            assertArrayEquals(byteArrayOf(1, 2), upstream.toByteArray())
        }
    }

    @Test fun bridgeForwardsCombinedResponseAckAndNextClientPayload() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val upstream = ByteArrayOutputStream()
            val tun = ByteArrayOutputStream()
            val bridge = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf(9, 8)),
                upstream, 1280, 123L, clientWindow = 4,
                allowedDestination = syn.header.destination)
            try {
                assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tun, 100))
                assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(
                    finalAck(syn, 123L).bytes), tun, 101))
                assertTrue(bridge.pumpOneGatewayReply(tun, 102))
                val piggyback = finalAck(syn, 123L, flags = 0x18,
                    acknowledgement = 126L, payload = byteArrayOf(4, 5))
                assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(piggyback.bytes), tun, 103))
                assertArrayEquals(byteArrayOf(4, 5), upstream.toByteArray())
                assertEquals(0, tcpChecksum(tun.toByteArray().takeLast(
                    if (version == 4) 40 else 60).toByteArray(), version))
            } finally { bridge.close() }
        }
    }

    @Test fun lostClientAckReplaysOnlyExactPreviouslyFlushedSegment() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val state = OfflineTcpHandshake(1000)
            val isn = 0xffff_fffeL
            val ip = if (version == 4) 20 else 40
            assertNotNull(state.begin(syn, isn, 1280, 100, clientWindow = 4))
            assertTrue(state.acceptFinalAck(finalAck(syn, isn), 101))
            val first = finalAck(syn, isn, flags = 0x18,
                acknowledgement = 0xffff_ffffL, payload = byteArrayOf(1, 2, 3))
            assertNull(state.acknowledgeForwardedReplay(first, 102)) // not flushed
            assertNotNull(state.stageClientPayload(first, 103))
            assertNull(state.acknowledgeForwardedReplay(first, 104)) // still staged
            val output = ByteArrayOutputStream()
            val originalAck = state.forwardStagedClientPayload(output, 105,
                nextReceiveWindow = 4)!!
            assertEquals(0, tcpChecksum(originalAck, version))
            assertArrayEquals(originalAck, state.acknowledgeForwardedReplay(first, 106))
            assertArrayEquals(byteArrayOf(1, 2, 3), output.toByteArray())
            assertNull(state.acknowledgeForwardedReplay(finalAck(syn, isn,
                flags = 0x18, acknowledgement = 0xffff_ffffL,
                payload = byteArrayOf(1, 2, 4)), 107)) // different bytes
            assertNull(state.acknowledgeForwardedReplay(finalAck(syn, isn,
                flags = 0x18, acknowledgement = 0xffff_ffffL,
                sourcePort = 49153, payload = byteArrayOf(1, 2, 3)), 108))
            assertNull(state.acknowledgeForwardedReplay(finalAck(syn, isn,
                flags = 0x18, sequence = 1, acknowledgement = 0xffff_ffffL,
                payload = byteArrayOf(1, 2, 3)), 109))
            val corrupt = first.bytes.clone().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            assertNull(state.acknowledgeForwardedReplay(first.copy(bytes = corrupt), 110))
            val next = finalAck(syn, isn, flags = 0x18, sequence = 3,
                acknowledgement = 0xffff_ffffL, payload = byteArrayOf(4))
            assertNotNull(state.stageClientPayload(next, 111))
            assertNotNull(state.forwardStagedClientPayload(output, 112))
            assertNull(state.acknowledgeForwardedReplay(first, 113)) // only last segment
            val lastAck = state.acknowledgeForwardedReplay(next, 114)!!
            assertEquals(4L, u32(lastAck, ip + 8))
            assertEquals(0, u16(lastAck, ip + 14)) // no accidental window reopening
            assertArrayEquals(byteArrayOf(1, 2, 3, 4), output.toByteArray())
            state.close()
            assertNull(state.acknowledgeForwardedReplay(next, 115))
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
                // Same monotonic instant for each negative case: time rollback
                // intentionally retires the flow and would mask RST validation.
                assertFalse(flow.acceptClientReset(bad, 105))
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

    @Test fun finHalfCloseOnlyAfterValidatedUpstreamShutdownForBothFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val flow = OfflineTcpHandshake()
            val isn = 0xffff_ffffL
            assertNotNull(flow.begin(syn, isn, 1280, 100, clientWindow = 8))
            val fin = finalAck(syn, isn, flags = 0x11)
            var shutdowns = 0
            assertNull(flow.acceptClientFin(fin, 101) { shutdowns++ }) // no handshake
            assertTrue(flow.acceptFinalAck(finalAck(syn, isn), 102))
            val corrupt = fin.bytes.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
            for (bad in listOf(
                finalAck(syn, isn, flags = 0x11, sequence = 1),
                finalAck(syn, isn, flags = 0x11, acknowledgement = 7),
                finalAck(syn, isn, flags = 0x11, sourcePort = 49153),
                finalAck(syn, isn, flags = 0x19),
                finalAck(syn, isn, flags = 0x11, payload = byteArrayOf(9)),
                fin.copy(bytes = corrupt),
            )) {
                assertNull(flow.acceptClientFin(bad, 103) { shutdowns++ })
                assertTrue(flow.isEstablished(103))
            }
            assertEquals(0, shutdowns)
            assertNotNull(flow.offerResponse(byteArrayOf(1), 1280, 104))
            assertNull(flow.acceptClientFin(fin, 105) { shutdowns++ }) // pending response
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn, acknowledgement = 1), 106))
            // The FIN must acknowledge the response that was just accepted;
            // the original pre-response FIN is stale and must not half-close.
            assertNull(flow.acceptClientFin(fin, 107) { shutdowns++ })
            val acknowledgedFin = finalAck(syn, isn, flags = 0x11, acknowledgement = 1)
            val ack = flow.acceptClientFin(acknowledgedFin, 107) { shutdowns++ }!!
            val ip = if (version == 4) 20 else 40
            assertEquals(1, shutdowns)
            assertEquals(0, tcpChecksum(ack, version))
            assertEquals(0x10, ack[ip + 13].toInt() and 255)
            assertEquals(0, u16(ack, ip + 14))
            assertEquals(1L, u32(ack, ip + 8)) // client ISN wraps, FIN consumes one
            assertEquals(1L, u32(ack, ip + 4))
            assertNull(flow.acceptClientFin(fin, 108) { shutdowns++ })
            assertEquals(1, shutdowns)
            assertNull(flow.stageClientPayload(finalAck(syn, isn, flags = 0x18,
                sequence = 1, acknowledgement = 1, payload = byteArrayOf(4)), 109))
            // A FIN does not discard the gateway-to-client response half.
            assertNotNull(flow.offerResponse(byteArrayOf(5), 1280, 110))
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn,
                sequence = 1, acknowledgement = 2), 111))
            assertTrue(flow.isEstablished(112))
        }
    }

    @Test fun finHalfCloseFailureNeverAcknowledgesAndRetiresFlow() {
        val syn = request(4)
        val flow = OfflineTcpHandshake()
        assertNotNull(flow.begin(syn, 9, 1280, 100))
        assertTrue(flow.acceptFinalAck(finalAck(syn, 9), 101))
        try {
            flow.acceptClientFin(finalAck(syn, 9, flags = 0x11), 102) {
                throw IOException("upstream shutdown failed")
            }
            fail("Expected half-close failure")
        } catch (expected: IOException) {
            assertEquals("upstream shutdown failed", expected.message)
        }
        assertFalse(flow.isEstablished(103))
        assertNull(flow.offerResponse(byteArrayOf(1), 1280, 104))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnboundedMtu() {
        buildTcpSynAck(request(4), 123L, 1000)
    }

    @Test fun readsOnlyOneMtuBoundedGatewaySegmentUntilClientAckForBothFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version, options = byteArrayOf(2, 4, 5, 0xB4.toByte()))
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
            val fin = flow.readTunnelResponse(stream, 1280, 108)!! // EOF half-closes
            assertEquals(0x11, fin[ip + 13].toInt() and 255)
            assertEquals(0, tcpChecksum(fin, version))
            assertEquals((isn + 1 + sourceBytes.size) and 0xffff_ffffL, u32(fin, ip + 4))
            assertTrue(flow.isEstablished(109)) // wait for peer FIN and exact ACK
            assertNull(flow.readTunnelResponse(stream, 1280, 110))
            assertFalse(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = (isn + 1 + sourceBytes.size) and 0xffff_ffffL), 111))
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = (isn + 2 + sourceBytes.size) and 0xffff_ffffL), 112))
            assertNull(flow.readTunnelResponse(stream, 1280, 113))
            assertTrue(flow.isEstablished(114))
        }
    }

    @Test fun respectsPeerMssAndConservativeDefaultsOnBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val ip = if (version == 4) 20 else 40
            val peerLimit = 256
            // A duplicate MSS must never enlarge the peer's smaller limit.
            val syn = request(version, options = byteArrayOf(
                2, 4, 5, 0xB4.toByte(), 2, 4, 1, 0
            ))
            val flow = OfflineTcpHandshake()
            assertNotNull(flow.begin(syn, 99, 1280, 100))
            assertTrue(flow.acceptFinalAck(finalAck(syn, 99), 101))
            assertNull(flow.offerResponse(ByteArray(peerLimit + 1), 1280, 102))
            val stream = ByteArrayInputStream(ByteArray(600) { 42 })
            val first = flow.readTunnelResponse(stream, 1280, 103)!!
            assertEquals(peerLimit, first.size - ip - 20)
            assertEquals(0, tcpChecksum(first, version))
            assertEquals(600 - peerLimit, stream.available())
            assertNull(flow.readTunnelResponse(stream, 1280, 104))
            assertTrue(flow.acceptResponseAck(finalAck(syn, 99,
                acknowledgement = 100L + peerLimit), 105))
            val second = flow.readTunnelResponse(stream, 1280, 106)!!
            assertEquals(peerLimit, second.size - ip - 20)
            assertEquals(0, tcpChecksum(second, version))

            // No MSS option: the TCP default is 536 (IPv4) or 1220 (IPv6).
            val noMss = request(version)
            val defaultFlow = OfflineTcpHandshake()
            assertNotNull(defaultFlow.begin(noMss, 99, 1280, 100))
            assertTrue(defaultFlow.acceptFinalAck(finalAck(noMss, 99), 101))
            val expectedDefault = if (version == 4) 536 else 1220
            assertNull(defaultFlow.offerResponse(ByteArray(expectedDefault + 1), 1280, 102))
            assertNotNull(defaultFlow.offerResponse(ByteArray(expectedDefault), 1280, 103))
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

    @Test fun gatewayReadTimeoutIsIdleNotFinAndLaterReplyStillWorksForBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val upstream = ByteArrayOutputStream()
            val reply = "HTTP/1.1 200 OK\r\n\r\n".toByteArray()
            var reads = 0
            var closes = 0
            val input = object : InputStream() {
                private val remaining = ByteArrayInputStream(reply)
                override fun read(): Int = throw AssertionError("Use bounded buffer read")
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    reads++
                    if (reads <= 2) throw SocketTimeoutException("idle gateway")
                    return remaining.read(b, off, len)
                }
                override fun close() { closes++ }
            }
            val bridge = OfflineTcpTunBridge(input, upstream, 1280, 123L,
                allowedDestination = syn.header.destination)
            val tun = ByteArrayOutputStream()
            try {
                assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tun, 100))
                assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(
                    finalAck(syn, 123L).bytes), tun, 101))
                tun.reset()
                assertFalse(bridge.pumpOneGatewayReply(tun, 102))
                assertFalse(bridge.pumpOneGatewayReply(tun, 103))
                assertEquals(0, tun.size()) // no synthetic FIN or data on idle
                assertEquals(0, closes)
                assertFalse(bridge.pumpPendingRetry(tun, 104))
                assertTrue(bridge.pumpOneGatewayReply(tun, 105))
                val ip = if (version == 4) 20 else 40
                assertArrayEquals(reply, tun.toByteArray().copyOfRange(ip + 20, tun.size()))
                assertEquals(0, tcpChecksum(tun.toByteArray(), version))
                assertEquals(3, reads)
            } finally { bridge.close() }
            assertEquals(1, closes)

            // A peer that only times out must not hold the authenticated
            // gateway past the fixed 15-second flow lease.
            var expiredReads = 0
            var expiredCloses = 0
            val alwaysIdle = object : InputStream() {
                override fun read(): Int = throw AssertionError("Use buffer read")
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    expiredReads++
                    throw SocketTimeoutException("idle")
                }
                override fun close() { expiredCloses++ }
            }
            val stale = OfflineTcpTunBridge(alwaysIdle, ByteArrayOutputStream(),
                1280, 123L, allowedDestination = syn.header.destination)
            val staleTun = ByteArrayOutputStream()
            assertTrue(stale.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), staleTun, 100))
            assertTrue(stale.pumpOneTunPacket(ByteArrayInputStream(
                finalAck(syn, 123L).bytes), staleTun, 101))
            staleTun.reset()
            assertFalse(stale.pumpOneGatewayReply(staleTun, 102))
            assertFalse(stale.pumpOneGatewayReply(staleTun, 15_100))
            assertEquals(1, expiredReads) // lease expires before another read
            assertEquals(1, expiredCloses)
            assertEquals(0, staleTun.size())
            assertFalse(stale.pumpOneGatewayReply(staleTun, 15_101))
        }
    }

    @Test fun zeroLengthGatewayReadRetiresBridgeWithoutAckOrRetryForBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            var streamClosed = false
            val zeroRead = object : InputStream() {
                override fun read(): Int = 0
                override fun read(b: ByteArray, off: Int, len: Int): Int = 0
                override fun close() { streamClosed = true }
            }
            val bridge = OfflineTcpTunBridge(zeroRead, ByteArrayOutputStream(), 1280, 99, allowedDestination = syn.header.destination)
            val tunOutput = ByteArrayOutputStream()
            assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tunOutput, 100))
            assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(finalAck(syn, 99).bytes),
                tunOutput, 101))
            tunOutput.reset()
            try {
                bridge.pumpOneGatewayReply(tunOutput, 102)
                fail("A zero-byte gateway read must not be retried or treated as EOF")
            } catch (expected: IOException) {
                assertEquals("Gateway stream returned zero bytes", expected.message)
            }
            assertTrue(streamClosed)
            assertEquals(0, tunOutput.size()) // no data or spurious FIN
            assertFalse(bridge.pumpOneGatewayReply(tunOutput, 103))
            assertFalse(bridge.pumpPendingRetry(tunOutput, 104))
            assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tunOutput, 105))
        }
    }

    @Test fun gatewayEofFinRetransmitsAndClosesOnlyAfterBothHalvesForBothFamilies() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val flow = OfflineTcpHandshake(10_000)
            val isn = 0xffff_ffffL
            val ip = if (version == 4) 20 else 40
            assertNotNull(flow.begin(syn, isn, 1280, 100))
            assertTrue(flow.acceptFinalAck(finalAck(syn, isn), 101))
            val eof = ByteArrayInputStream(byteArrayOf())
            val fin = flow.readTunnelResponse(eof, 1280, 200)!!
            assertEquals(ip + 20, fin.size)
            assertEquals(0x11, fin[ip + 13].toInt() and 255)
            assertEquals(0, tcpChecksum(fin, version))
            assertEquals(0L, u32(fin, ip + 4)) // server sequence wrapped
            assertEquals(0L, u32(fin, ip + 8)) // client sequence wrapped
            assertNull(flow.offerResponse(byteArrayOf(9), 1280, 201))
            assertNull(flow.readTunnelResponse(eof, 1280, 202))
            assertFalse(flow.acceptResponseAck(finalAck(syn, isn, acknowledgement = 0), 203))
            assertFalse(flow.acceptResponseAck(finalAck(syn, isn,
                acknowledgement = 1, flags = 0x18), 204))
            val corrupt = finalAck(syn, isn, acknowledgement = 1)
            val corrupted = corrupt.bytes.clone().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            assertFalse(flow.acceptResponseAck(corrupt.copy(bytes = corrupted), 205))
            assertNull(flow.retryPendingResponse(699))
            val retransmit = flow.retryPendingResponse(700)!!
            assertArrayEquals(fin, retransmit)
            retransmit[retransmit.lastIndex] = 0 // defensive copy
            assertNull(flow.retryPendingResponse(1699))
            assertArrayEquals(fin, flow.retryPendingResponse(1700))
            assertTrue(flow.acceptResponseAck(finalAck(syn, isn, acknowledgement = 1), 1701))
            assertNull(flow.retryPendingResponse(2201))
            assertNull(flow.offerResponse(byteArrayOf(1), 1280, 2202))
            var halfCloses = 0
            val clientFin = finalAck(syn, isn, flags = 0x11, acknowledgement = 1)
            val ack = flow.acceptClientFin(clientFin, 2203) { halfCloses++ }!!
            assertEquals(1, halfCloses)
            assertEquals(0x10, ack[ip + 13].toInt() and 255)
            assertEquals(0, tcpChecksum(ack, version))
            assertEquals(1L, u32(ack, ip + 4))
            assertEquals(1L, u32(ack, ip + 8))
            assertFalse(flow.isEstablished(2204))
        }
    }

    @Test fun clientHalfCloseThenGatewayEofFinAckRetiresFlow() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val flow = OfflineTcpHandshake()
            assertNotNull(flow.begin(syn, 123, 1280, 100))
            assertTrue(flow.acceptFinalAck(finalAck(syn, 123), 101))
            assertNotNull(flow.acceptClientFin(finalAck(syn, 123, flags = 0x11), 102) { })
            val fin = flow.readTunnelResponse(ByteArrayInputStream(byteArrayOf()), 1280, 103)!!
            val ip = if (version == 4) 20 else 40
            assertEquals(1L, u32(fin, ip + 8)) // acknowledges client's FIN
            assertFalse(flow.acceptResponseAck(finalAck(syn, 123,
                acknowledgement = 125), 104)) // stale client sequence
            assertTrue(flow.acceptResponseAck(finalAck(syn, 123,
                sequence = 1, acknowledgement = 125), 105))
            assertFalse(flow.isEstablished(106))
            assertNull(flow.retryPendingResponse(107))
        }
    }

    @Test fun gatewayEofCloseFailureRetiresFlowWithoutFin() {
        val syn = request(4)
        val flow = OfflineTcpHandshake()
        assertNotNull(flow.begin(syn, 42, 1280, 100))
        assertTrue(flow.acceptFinalAck(finalAck(syn, 42), 101))
        val broken = object : InputStream() {
            override fun read(): Int = -1
            override fun read(b: ByteArray, off: Int, len: Int): Int = -1
            override fun close() { throw IOException("close failed") }
        }
        try {
            flow.readTunnelResponse(broken, 1280, 102)
            fail("Expected stream close failure")
        } catch (expected: IOException) {
            assertEquals("close failed", expected.message)
        }
        assertFalse(flow.isEstablished(103))
        assertNull(flow.retryPendingResponse(104))
    }

    @Test fun dormantBridgePumpsFullOfflineRequestReplyForIpv4AndIpv6() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val serverIsn = 100L
            val tunnelWritten = ByteArrayOutputStream()
            val gatewayReply = "HTTP/1.1 200 OK\r\n\r\n".toByteArray()
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(gatewayReply), tunnelWritten, 1280, serverIsn, allowedDestination = syn.header.destination
            )
            val tunWritten = ByteArrayOutputStream()
            fun deliver(packet: TunIngressResult.Packet, time: Long): ByteArray {
                tunWritten.reset()
                assertTrue(bridge.pumpOneTunPacket(
                    ByteArrayInputStream(packet.bytes), tunWritten, time))
                return tunWritten.toByteArray()
            }
            val synAck = deliver(syn, 100)
            assertEquals(0x12, synAck[if (version == 4) 33 else 53].toInt() and 255)
            assertEquals(1024, u16(synAck, if (version == 4) 34 else 54))
            assertTrue(deliver(finalAck(syn, serverIsn), 101).isEmpty())
            val requestBytes = "GET / HTTP/1.1\r\n\r\n".toByteArray()
            val ack = deliver(finalAck(syn, serverIsn, flags = 0x18,
                payload = requestBytes), 102)
            assertArrayEquals(requestBytes, tunnelWritten.toByteArray())
            val ip = if (version == 4) 20 else 40
            assertEquals(requestBytes.size.toLong(), u32(ack, ip + 8))
            assertEquals(1024, u16(ack, ip + 14))
            // If the first ACK is lost, retransmit that ACK but never the
            // upstream bytes. A replay is not another HTTP request.
            val replayAck = deliver(finalAck(syn, serverIsn, flags = 0x18,
                payload = requestBytes), 103)
            assertArrayEquals(ack, replayAck)
            assertArrayEquals(requestBytes, tunnelWritten.toByteArray())
            tunWritten.reset()
            assertTrue(bridge.pumpOneGatewayReply(tunWritten, 104))
            val response = tunWritten.toByteArray()
            assertArrayEquals(gatewayReply, response.copyOfRange(ip + 20, response.size))
            assertEquals(0, tcpChecksum(response, version))
            assertEquals(1024, u16(response, ip + 14)) // data reply must not close the reopened window
            assertFalse(bridge.pumpOneGatewayReply(tunWritten, 105)) // wait for ACK
            assertTrue(deliver(finalAck(syn, serverIsn, sequence = requestBytes.size.toLong(),
                acknowledgement = serverIsn + 1 + gatewayReply.size), 106).isEmpty())
            bridge.close()
            tunWritten.reset()
            assertFalse(bridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), tunWritten, 107)) // terminal, no ISN reuse
            assertEquals(0, tunWritten.size())
        }
    }

    @Test fun dormantBridgeRequiresAuthorizedDestinationBeforeAnyTcpForwarding() {
        for (version in listOf(4, 6)) {
            val allowed = request(version)
            val other = request(version, destinationSeed = 71)
            val gatewayWritten = ByteArrayOutputStream()
            val tunWritten = ByteArrayOutputStream()
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf(1)), gatewayWritten, 1280, 123L,
                allowedDestination = allowed.header.destination,
            )
            // A different but well-formed destination cannot claim this CONNECT
            // tunnel, even if its port, TCP sequence and handshake match.
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(other.bytes), tunWritten, 100))
            assertEquals(0, tunWritten.size())
            assertEquals(0, gatewayWritten.size())
            // Rejecting the wrong SYN must not consume the single-use bridge.
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(allowed.bytes), tunWritten, 101))
            assertTrue(tunWritten.size() > 0)
            tunWritten.reset()
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(allowed, 123L).bytes), tunWritten, 102))
            val payload = "restricted HTTPS".toByteArray()
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(other, 123L, flags = 0x18,
                    payload = payload).bytes), tunWritten, 103))
            assertEquals(0, gatewayWritten.size())
            assertEquals(0, tunWritten.size())
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(allowed, 123L, flags = 0x18,
                    payload = payload).bytes), tunWritten, 104))
            assertArrayEquals(payload, gatewayWritten.toByteArray())
            assertTrue(tunWritten.size() > 0)
            bridge.close()
        }
    }

    @Test fun dormantBridgeTunEofAndExplicitCloseAreTerminal() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val gatewayWritten = ByteArrayOutputStream()
            val bridge = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf(1)),
                gatewayWritten, 1280, 321, allowedDestination = syn.header.destination)
            val tunWritten = ByteArrayOutputStream()
            assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tunWritten, 100))
            assertTrue(tunWritten.size() > 0)
            tunWritten.reset()
            // An exhausted TUN descriptor is a shutdown, not a reusable read slot.
            assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(byteArrayOf()), tunWritten, 101))
            assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tunWritten, 102))
            assertFalse(bridge.pumpOneGatewayReply(tunWritten, 103))
            assertFalse(bridge.pumpPendingRetry(tunWritten, 104))
            assertEquals(0, tunWritten.size())
            assertEquals(0, gatewayWritten.size())
            bridge.close() // Idempotent.

            val resetBridge = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf(1)),
                ByteArrayOutputStream(), 1280, 321, allowedDestination = syn.header.destination)
            assertTrue(resetBridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), ByteArrayOutputStream(), 110))
            assertTrue(resetBridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(syn, 321).bytes), ByteArrayOutputStream(), 111))
            assertTrue(resetBridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(syn, 321, flags = 0x14).bytes),
                ByteArrayOutputStream(), 112))
            assertFalse(resetBridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), tunWritten, 113))

            val neverStarted = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf(1)),
                ByteArrayOutputStream(), 1280, 321, allowedDestination = syn.header.destination)
            neverStarted.close()
            assertFalse(neverStarted.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), tunWritten, 105))
        }
    }

    @Test fun dormantBridgeTunWriteFailureRetiresBeforeAnotherPacket() {
        val syn = request(4)
        val bridge = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf(1)),
            ByteArrayOutputStream(), 1280, 321, allowedDestination = syn.header.destination)
        val brokenTun = object : OutputStream() {
            override fun write(b: Int) { throw IOException("TUN output failed") }
            override fun write(b: ByteArray) { throw IOException("TUN output failed") }
        }
        try {
            bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), brokenTun, 100)
            fail("Expected TUN output failure")
        } catch (expected: IOException) {
            assertEquals("TUN output failed", expected.message)
        }
        assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes),
            ByteArrayOutputStream(), 101))
        assertFalse(bridge.pumpOneGatewayReply(ByteArrayOutputStream(), 102))
    }

    @Test fun dormantBridgeRejectsCorruptAndUnestablishedPacketsWithoutTunnelWrites() {
        val syn = request(4)
        val gatewayWritten = ByteArrayOutputStream()
        val bridge = OfflineTcpTunBridge(ByteArrayInputStream(byteArrayOf(1)),
            gatewayWritten, 1280, 321, allowedDestination = syn.header.destination)
        val tunWritten = ByteArrayOutputStream()
        val invalid = syn.bytes.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(invalid), tunWritten, 1))
        assertTrue(tunWritten.toByteArray().isEmpty())
        assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(finalAck(syn, 321,
            flags = 0x18, payload = byteArrayOf(5)).bytes), tunWritten, 2))
        assertTrue(gatewayWritten.toByteArray().isEmpty())
        assertFalse(bridge.pumpOneGatewayReply(tunWritten, 3))
        assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(byteArrayOf()), tunWritten, 4))
    }

    @Test fun dormantBridgeClosesBothGatewayStreamsWithoutCallback() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            var inputCloses = 0
            var outputCloses = 0
            val input = object : ByteArrayInputStream(byteArrayOf(1)) {
                override fun close() { inputCloses++ }
            }
            val output = object : ByteArrayOutputStream() {
                override fun close() { outputCloses++ }
            }
            val bridge = OfflineTcpTunBridge(input, output, 1280, 321,
                allowedDestination = syn.header.destination)
            assertFalse(bridge.pumpOneTunPacket(
                ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(), 100))
            bridge.close()
            assertEquals(1, inputCloses)
            assertEquals(1, outputCloses)
            assertFalse(bridge.pumpOneGatewayReply(ByteArrayOutputStream(), 101))
        }
    }

    @Test fun dormantBridgeClosesSecondGatewayStreamAfterFirstCloseFailure() {
        val syn = request(4)
        var outputCloses = 0
        val input = object : ByteArrayInputStream(byteArrayOf(1)) {
            override fun close() { throw IOException("input close failed") }
        }
        val output = object : ByteArrayOutputStream() {
            override fun close() { outputCloses++; throw IOException("output close failed") }
        }
        val bridge = OfflineTcpTunBridge(input, output, 1280, 321,
            allowedDestination = syn.header.destination)
        try {
            bridge.close()
            fail("Expected gateway stream cleanup failure")
        } catch (expected: IOException) {
            assertEquals("input close failed", expected.message)
            assertEquals(1, expected.suppressed.size)
            assertEquals("output close failed", expected.suppressed[0].message)
        }
        assertEquals(1, outputCloses)
        bridge.close()
        assertEquals(1, outputCloses)
        assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes),
            ByteArrayOutputStream(), 101))
    }

    @Test fun dormantBridgeClosesGatewayOnceOnTunEofAndReset() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            var releases = 0
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf(1)), ByteArrayOutputStream(), 1280, 321,
                onClose = { releases++ },
                allowedDestination = syn.header.destination,
            )
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), ByteArrayOutputStream(), 100))
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(syn, 321).bytes), ByteArrayOutputStream(), 101))
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(syn, 321, flags = 0x14).bytes),
                ByteArrayOutputStream(), 102))
            bridge.close()
            assertEquals(1, releases)
            assertFalse(bridge.pumpOneGatewayReply(ByteArrayOutputStream(), 103))

            val eof = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf(1)), ByteArrayOutputStream(), 1280, 321,
                onClose = { releases++ },
                allowedDestination = syn.header.destination,
            )
            assertFalse(eof.pumpOneTunPacket(
                ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(), 104))
            eof.close()
            assertEquals(2, releases)
        }
    }

    @Test fun dormantBridgePreservesTunWriteFailureWhenCleanupAlsoFails() {
        val syn = request(4)
        var releases = 0
        val bridge = OfflineTcpTunBridge(
            ByteArrayInputStream(byteArrayOf(1)), ByteArrayOutputStream(), 1280, 321,
            onClose = { releases++; throw IOException("gateway close failed") },
            allowedDestination = syn.header.destination,
        )
        val broken = object : OutputStream() {
            override fun write(b: Int) { throw IOException("TUN write failed") }
            override fun write(b: ByteArray) { throw IOException("TUN write failed") }
        }
        try {
            bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), broken, 100)
            fail("Expected TUN failure")
        } catch (expected: IOException) {
            assertEquals("TUN write failed", expected.message)
            assertEquals(1, expected.suppressed.size)
            assertEquals("gateway close failed", expected.suppressed[0].message)
        }
        assertEquals(1, releases)
        assertFalse(bridge.pumpOneTunPacket(
            ByteArrayInputStream(syn.bytes), ByteArrayOutputStream(), 101))
    }


    @Test fun dormantBridgeReleasesGatewayOnNaturalFinInEitherOrder() {
        for (version in listOf(4, 6)) for (clientFirst in listOf(true, false)) {
            val syn = request(version)
            val serverIsn = 321L
            var releases = 0
            var halfCloses = 0
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(), 1280, serverIsn,
                upstreamHalfClose = { halfCloses++ }, onClose = { releases++ },
                allowedDestination = syn.header.destination,
            )
            val tunOutput = ByteArrayOutputStream()
            fun deliver(packet: TunIngressResult.Packet, time: Long): ByteArray {
                tunOutput.reset()
                assertTrue(bridge.pumpOneTunPacket(
                    ByteArrayInputStream(packet.bytes), tunOutput, time))
                return tunOutput.toByteArray()
            }
            assertTrue(deliver(syn, 100).isNotEmpty())
            assertTrue(deliver(finalAck(syn, serverIsn), 101).isEmpty())
            if (clientFirst) {
                assertTrue(deliver(finalAck(syn, serverIsn, flags = 0x11), 102).isNotEmpty())
                assertEquals(1, halfCloses)
            }
            tunOutput.reset()
            assertTrue(bridge.pumpOneGatewayReply(tunOutput, 103))
            val fin = tunOutput.toByteArray()
            val ip = if (version == 4) 20 else 40
            assertEquals(0x11, fin[ip + 13].toInt() and 255)
            assertEquals(0, tcpChecksum(fin, version))
            assertEquals(0, releases) // FIN emission alone must not close the flow.
            val clientSequence = if (clientFirst) 1L else 0L
            assertTrue(deliver(finalAck(syn, serverIsn, sequence = clientSequence,
                acknowledgement = serverIsn + 2), 104).isEmpty())
            if (!clientFirst) {
                assertEquals(0, releases) // The client may still send its FIN.
                assertTrue(deliver(finalAck(syn, serverIsn, flags = 0x11,
                    acknowledgement = serverIsn + 2), 105).isNotEmpty())
                assertEquals(1, halfCloses)
            }
            assertEquals(1, releases)
            assertFalse(bridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), tunOutput, 106))
            assertFalse(bridge.pumpOneGatewayReply(tunOutput, 107))
            bridge.close()
            assertEquals(1, releases)
        }
    }

    @Test fun nonTcpDatagramsCannotKeepExpiredGatewayFlowAlive() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            val ip = if (version == 4) 20 else 40
            val udp = ByteArray(ip + 8)
            syn.bytes.copyInto(udp, endIndex = ip)
            if (version == 4) {
                put16(udp, 2, udp.size)
                udp[9] = 17 // UDP
                udp[10] = 0; udp[11] = 0
            } else {
                put16(udp, 4, 8)
                udp[6] = 17 // UDP
            }
            put16(udp, ip, 49152)
            put16(udp, ip + 2, 53)
            put16(udp, ip + 4, 8)
            if (version == 4) {
                put16(udp, 10, checksum(sum(udp, 0, 20)))
            } else {
                put16(udp, ip + 6, checksum(
                    sum(udp, 8, 16) + sum(udp, 24, 16) + 8 + 17 + sum(udp, ip, 8)
                ))
            }
            assertEquals(17, parseTunPacketHeader(udp, udp.size)!!.protocol)
            var releases = 0
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf(1)), ByteArrayOutputStream(), 1280, 321,
                onClose = { releases++ }, allowedDestination = syn.header.destination,
            )
            val tunOutput = ByteArrayOutputStream()
            assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), tunOutput, 100))
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(syn, 321).bytes), tunOutput, 101))
            // An unrelated UDP datagram is ignored while the flow is live.
            assertTrue(bridge.pumpOneTunPacket(ByteArrayInputStream(udp), tunOutput, 102))
            assertEquals(0, releases)
            // At expiry, retire before even consuming another unrelated frame.
            val mustNotRead = object : InputStream() {
                override fun read(): Int = throw AssertionError("Expired flow read TUN")
                override fun read(b: ByteArray, off: Int, len: Int): Int =
                    throw AssertionError("Expired flow read TUN")
            }
            assertFalse(bridge.pumpOneTunPacket(mustNotRead, tunOutput, 15_100))
            assertEquals(1, releases)
            assertFalse(bridge.pumpOneTunPacket(ByteArrayInputStream(udp), tunOutput, 15_101))
            bridge.close()
            assertEquals(1, releases)
        }
    }

    @Test fun dormantBridgeReleasesGatewayOnExpiredFlowWithoutRetry() {
        for (version in listOf(4, 6)) {
            val syn = request(version)
            var releases = 0
            val bridge = OfflineTcpTunBridge(
                ByteArrayInputStream(byteArrayOf(1)), ByteArrayOutputStream(), 1280, 321,
                onClose = { releases++ },
                allowedDestination = syn.header.destination,
            )
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), ByteArrayOutputStream(), 100))
            assertTrue(bridge.pumpOneTunPacket(
                ByteArrayInputStream(finalAck(syn, 321).bytes), ByteArrayOutputStream(), 101))
            assertFalse(bridge.pumpPendingRetry(ByteArrayOutputStream(), 15_100))
            assertEquals(1, releases)
            assertFalse(bridge.pumpOneTunPacket(
                ByteArrayInputStream(syn.bytes), ByteArrayOutputStream(), 15_101))
            bridge.close()
            assertEquals(1, releases)
        }
    }
}
