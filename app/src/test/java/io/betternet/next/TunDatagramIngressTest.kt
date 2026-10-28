package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.*
import org.junit.Test

class TunDatagramIngressTest {
    private fun validIpv4Udp(): ByteArray = ByteArray(28).apply {
        this[0] = 0x45
        this[2] = 0; this[3] = 28
        this[8] = 64; this[9] = 17
        this[12] = 192.toByte(); this[13] = 0; this[14] = 2; this[15] = 1
        this[16] = 198.toByte(); this[17] = 51; this[18] = 100; this[19] = 2
        this[20] = 0x30; this[21] = 0x39 // source port 12345
        this[22] = 0; this[23] = 53
        this[24] = 0; this[25] = 8
        var sum = 0
        for (i in 0 until 20 step 2) {
            sum += ((this[i].toInt() and 0xff) shl 8) or (this[i + 1].toInt() and 0xff)
        }
        while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
        this[10] = (sum.inv() ushr 8).toByte()
        this[11] = sum.inv().toByte()
    }

    @Test fun readsExactlyOneValidatedPacketWithoutSending() {
        val source = validIpv4Udp()
        val result = readOneTunDatagram(ByteArrayInputStream(source), 1500)
        assertTrue(result is TunIngressResult.Packet)
        result as TunIngressResult.Packet
        assertArrayEquals(source, result.bytes)
        assertEquals(53, result.header.destinationPort)
        source[0] = 0 // The returned bytes do not alias the source.
        assertEquals(0x45, result.bytes[0].toInt() and 0xff)
    }

    @Test fun rejectsInvalidAndOversizedDatagrams() {
        val corrupted = validIpv4Udp().apply { this[8] = 63 }
        assertSame(TunIngressResult.Rejected, readOneTunDatagram(ByteArrayInputStream(corrupted), 1500))
        assertSame(TunIngressResult.Rejected,
            readOneTunDatagram(ByteArrayInputStream(ByteArray(1501)), 1500))
    }

    @Test fun distinguishesEofAndZeroReadWithoutBusyLoop() {
        assertSame(TunIngressResult.EndOfStream,
            readOneTunDatagram(ByteArrayInputStream(byteArrayOf()), 1500))
        val zero = object : InputStream() {
            override fun read(): Int = 0
            override fun read(b: ByteArray, off: Int, len: Int): Int = 0
        }
        try {
            readOneTunDatagram(zero, 1500)
            fail("Zero-byte TUN read must not cause a spin")
        } catch (_: IOException) { }
    }

    @Test fun refusesUnboundedOrIpv6IncompatibleMtuBeforeRead() {
        val input = object : InputStream() {
            override fun read(): Int = throw AssertionError("Must not read")
        }
        for (mtu in listOf(0, 1279, 9001, Int.MAX_VALUE)) {
            try {
                readOneTunDatagram(input, mtu)
                fail("Accepted invalid MTU $mtu")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
