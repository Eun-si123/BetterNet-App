package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import org.junit.Assert.*
import org.junit.Test

/** Fully offline failure-boundary regression. No VPN or sockets are opened. */
class TunFailureProvenanceTest {
    private fun inactiveDispatcher(): RestrictedTestTunDispatcher {
        val syn = TunTcpSynAckTest().request(4)
        return RestrictedTestTunDispatcher(
            RestrictedTestTunPlan(syn.header.source, InetAddress.getByName("198.18.0.1"),
                syn.header.destination, 1280),
            { _, _ -> throw AssertionError("DNS must remain dormant") },
            { _, _, _, _ -> throw AssertionError("Gateway must remain dormant") },
        )
    }

    @Test fun ownerPumpPreservesTheExactFailureWhenDescriptorCleanupRethrowsIt() {
        val original = IOException("initial VPN owner validation error")
        var descriptorCloses = 0
        val session = RestrictedTunSession(
            inactiveDispatcher(), ByteArrayInputStream(byteArrayOf()),
            ByteArrayOutputStream(),
            { descriptorCloses++; throw original },
        )
        val pump = RestrictedTunPump(session, revalidate = { throw original }, nowMillis = { 1L })
        try {
            pump.runUntilStopped()
            fail("Owner validation must fail without swallowing or replacing the root cause")
        } catch (failure: IOException) {
            assertSame("The original error identity must survive cleanup", original, failure)
            assertEquals("The same throwable cannot be its own suppressed cause", 0, failure.suppressed.size)
        }
        assertEquals(1, descriptorCloses)
    }

    @Test fun bridgeCloseRetainsOriginalErrorWhenBothStreamClosuresRethrowIt() {
        val syn = TunTcpSynAckTest().request(4)
        val original = IOException("shared stream close error")
        var inputCloses = 0
        var outputCloses = 0
        val input = object : ByteArrayInputStream(byteArrayOf()) {
            override fun close() { inputCloses++; throw original }
        }
        val output = object : OutputStream() {
            override fun write(value: Int) { }
            override fun close() { outputCloses++; throw original }
        }
        val bridge = OfflineTcpTunBridge(input, output, 1280, 1L,
            allowedDestination = syn.header.destination)
        try {
            bridge.close()
            fail("A failed stream close must propagate its first error")
        } catch (failure: IOException) {
            assertSame(original, failure)
            assertEquals(0, failure.suppressed.size)
        }
        assertEquals(1, inputCloses)
        assertEquals("Second stream still gets its cleanup attempt", 1, outputCloses)
        bridge.close()
        assertEquals(1, inputCloses)
        assertEquals(1, outputCloses)
    }

    @Test fun ownerPumpStillAttachesDistinctCleanupFailureToRootCause() {
        val original = IOException("original owner failure")
        val cleanup = IOException("descriptor cleanup failure")
        val session = RestrictedTunSession(
            inactiveDispatcher(), ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(),
            { throw cleanup },
        )
        val pump = RestrictedTunPump(session, revalidate = { throw original }, nowMillis = { 1L })
        try {
            pump.runUntilStopped()
            fail("Owner failure must propagate")
        } catch (failure: IOException) {
            assertSame(original, failure)
            assertArrayEquals(arrayOf(cleanup), failure.suppressed)
        }
    }

    @Test fun tcpBridgePreservesTheExactTunWriteFailureWhenSocketCloseRethrowsIt() {
        val syn = TunTcpSynAckTest().request(4)
        val original = IOException("TUN write failed")
        var closes = 0
        val bridge = OfflineTcpTunBridge(
            ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(),
            mtu = 1280, serverIsn = 1234L, allowedDestination = syn.header.destination,
            onClose = { closes++; throw original },
        )
        val sink = object : OutputStream() {
            override fun write(value: Int): Unit = throw original
            override fun write(bytes: ByteArray, offset: Int, length: Int): Unit = throw original
        }
        try {
            bridge.pumpOneTunPacket(ByteArrayInputStream(syn.bytes), sink, 1L)
            fail("TUN write failure must escape the bridge")
        } catch (failure: IOException) {
            assertSame("The first write error must not be masked", original, failure)
            assertEquals(0, failure.suppressed.size)
        }
        assertEquals(1, closes)
        assertFalse("A failed bridge cannot be reused", bridge.pumpOneTunPacket(
            ByteArrayInputStream(syn.bytes), sink, 2L))
        bridge.close()
        assertEquals(1, closes)
    }
}
