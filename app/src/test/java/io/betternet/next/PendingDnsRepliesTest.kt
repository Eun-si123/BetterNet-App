package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

class PendingDnsRepliesTest {
    private fun put16(b: ByteArray, offset: Int, value: Int) {
        b[offset] = (value ushr 8).toByte()
        b[offset + 1] = value.toByte()
    }

    private fun checksum(b: ByteArray, start: Int, length: Int, initial: Int = 0): Int {
        var sum = initial
        for (i in 0 until length step 2) {
            sum += (b[start + i].toInt() and 255) shl 8
            if (i + 1 < length) sum += b[start + i + 1].toInt() and 255
        }
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        return sum.inv() and 65535
    }

    private fun query() = byteArrayOf(
        0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 'a'.code.toByte(), 4, 't'.code.toByte(),
        'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(),
        0, 0, 1, 0, 1,
    )

    private fun response() = query().apply {
        this[2] = 0x81.toByte()
        this[3] = 0x80.toByte()
    }

    private fun request(ipv6: Boolean = false): TunIngressResult.Packet {
        val offset = if (ipv6) 40 else 20
        val dns = query()
        val bytes = ByteArray(offset + 8 + dns.size)
        bytes[0] = if (ipv6) 0x60 else 0x45
        if (ipv6) {
            put16(bytes, 4, 8 + dns.size)
            bytes[6] = 17
            bytes[7] = 64
            bytes[8] = 0x20
            bytes[9] = 0x01
            bytes[23] = 1
            bytes[24] = 0x20
            bytes[25] = 0x01
            bytes[39] = 2
        } else {
            put16(bytes, 2, bytes.size)
            bytes[8] = 64
            bytes[9] = 17
            bytes[12] = 192.toByte()
            bytes[14] = 2
            bytes[15] = 10
            bytes[16] = 198.toByte()
            bytes[17] = 51
            bytes[18] = 100
            bytes[19] = 2
            put16(bytes, 10, checksum(bytes, 0, 20))
        }
        put16(bytes, offset, 49152)
        put16(bytes, offset + 2, 53)
        put16(bytes, offset + 4, 8 + dns.size)
        dns.copyInto(bytes, offset + 8)
        if (ipv6) {
            val pseudo = bytes.copyOfRange(8, 40)
            val sum = (checksum(pseudo, 0, 32).inv() and 65535) + 17 + 8 + dns.size
            val value = checksum(bytes, offset, 8 + dns.size, sum)
            put16(bytes, offset + 6, if (value == 0) 65535 else value)
        }
        return TunIngressResult.Packet(bytes, parseTunPacketHeader(bytes, bytes.size)!!)
    }

    @Test fun ipv4AndIpv6ResponsesAreConsumedExactlyOnce() {
        for (ipv6 in listOf(false, true)) {
            val pending = PendingDnsReplies()
            val request = request(ipv6)
            val handle = pending.register(request)!!
            val result = pending.consume(handle, response(), 1280)
            assertArrayEquals(buildDnsUdpReply(request, response(), 1280), result)
            assertNull(pending.consume(handle, response(), 1280))
            assertNull(pending.consume(handle + 1, response(), 1280))
        }
    }

    @Test fun malformedOrUnrelatedResponseConsumesSlotWithoutOutput() {
        val pending = PendingDnsReplies()
        val handle = pending.register(request())!!
        assertNull(pending.consume(handle, response().apply { this[0] = 0x77 }, 1280))
        assertNull(pending.consume(handle, response(), 1280))
        assertNull(pending.consume(-1, response(), 1280))
    }

    @Test fun rejectsInvalidQueriesBeforeAllocatingSlots() {
        val pending = PendingDnsReplies(maxPending = 1)
        val good = request()
        val invalid = good.bytes.clone().apply { this[28 + 12] = 0xc0.toByte() }
        assertNull(pending.register(good.copy(bytes = invalid)))
        val notDns = good.bytes.clone().apply { put16(this, 22, 80) }
        assertNull(pending.register(good.copy(bytes = notDns)))
        assertNotNull(pending.register(good))
        assertNull(pending.register(good))
    }

    @Test fun capacityExpiryAndClearAreBounded() {
        var now = 100L
        val pending = PendingDnsReplies(clockNanos = { now }, maxPending = 2, ttlNanos = 10)
        val first = pending.register(request())!!
        val second = pending.register(request())!!
        assertNull(pending.register(request()))
        now = 109
        assertNotNull(pending.consume(first, response(), 1280))
        now = 110
        assertNull(pending.consume(second, response(), 1280))
        val next = pending.register(request())!!
        pending.clear()
        assertNull(pending.consume(next, response(), 1280))
    }

    @Test fun gatewayDialLeaseSurvivesReplyExpiryUntilExplicitRelease() {
        var now = 100L
        val pending = PendingDnsReplies(clockNanos = { now }, maxPending = 1, ttlNanos = 10)
        assertTrue(pending.reserveGatewayDial())
        val handle = pending.register(request())!!
        now = 110
        assertNull(pending.consume(handle, response(), 1280))
        assertFalse("Expired DNS reply cannot free a live socket lease", pending.reserveGatewayDial())
        pending.clear()
        assertFalse(pending.reserveGatewayDial())
        pending.cancel(handle)
        pending.releaseGatewayDial()
        assertTrue(pending.reserveGatewayDial())
        pending.releaseGatewayDial()
    }

    @Test fun cancelledExchangeReleasesCapacityAndCannotBeReplayed() {
        val pending = PendingDnsReplies(maxPending = 1)
        val handle = pending.register(request())!!
        assertNull(pending.register(request()))
        pending.cancel(handle)
        assertNull(pending.consume(handle, response(), 1280))
        assertNotNull(pending.register(request()))
        pending.cancel(handle) // idempotent, does not cancel another request
    }

    @Test fun snapshotsInputAndFailsClosedOnMismatchedQuestion() {
        val pending = PendingDnsReplies()
        val original = request()
        val handle = pending.register(original)!!
        original.bytes[28] = 0x77
        assertNotNull(pending.consume(handle, response(), 1280))
        val other = pending.register(request())!!
        assertNull(pending.consume(other, response().apply { this[13] = 'b'.code.toByte() }, 1280))
    }
}
