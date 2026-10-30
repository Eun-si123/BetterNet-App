package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** No VPN service, descriptor or external network is opened in these tests. */
class RestrictedTunSessionTest {
    private fun dispatcher(version: Int): RestrictedTestTunDispatcher {
        val syn = TunTcpSynAckTest().request(version)
        val dns = InetAddress.getByName(if (version == 4) "198.18.0.1" else "fd00::1")
        return RestrictedTestTunDispatcher(
            RestrictedTestTunPlan(syn.header.source, dns, syn.header.destination, 1280),
            { _, _ -> throw AssertionError("Unexpected DNS request") },
            { _, _, _, _ -> throw AssertionError("Unexpected gateway dial") },
        )
    }

    @Test fun eofReleasesOwnedDescriptorExactlyOnceForBothIpFamilies() {
        for (version in listOf(4, 6)) {
            val syn = TunTcpSynAckTest().request(version)
            var releases = 0
            val session = RestrictedTunSession(
                dispatcher(version), ByteArrayInputStream(syn.bytes),
                ByteArrayOutputStream(), { releases++ },
            )
            assertTrue(session.pumpOneTunPacket(100))
            assertFalse(session.pumpOneGatewayReply(101))
            assertFalse(session.pumpPendingRetry(101))
            assertEquals(0, releases)
            assertFalse(session.pumpOneTunPacket(102)) // EOF is terminal
            assertEquals(1, releases)
            assertFalse(session.pumpOneTunPacket(103))
            assertFalse(session.pumpOneGatewayReply(103))
            session.close()
            assertEquals(1, releases)
        }
    }

    @Test fun tunReadFailureClosesDescriptorAndPreventsFurtherPumps() {
        var reads = 0
        var releases = 0
        val broken = object : InputStream() {
            override fun read(): Int { reads++; throw IOException("read failed") }
            override fun read(b: ByteArray, off: Int, len: Int): Int = read()
        }
        val session = RestrictedTunSession(
            dispatcher(4), broken, ByteArrayOutputStream(), { releases++ },
        )
        try {
            session.pumpOneTunPacket(100)
            fail("TUN read failure must be propagated")
        } catch (expected: IOException) {
            assertEquals("read failed", expected.message)
        }
        assertEquals(1, reads)
        assertEquals(1, releases)
        assertFalse(session.pumpOneTunPacket(101))
        assertEquals(1, reads)
        assertEquals(1, releases)
    }

    @Test fun failedDescriptorCloseIsSuppressedWithoutHidingOriginalReadFailure() {
        val broken = object : InputStream() {
            override fun read(): Int = throw IOException("read failed")
            override fun read(b: ByteArray, off: Int, len: Int): Int = read()
        }
        val session = RestrictedTunSession(
            dispatcher(6), broken, ByteArrayOutputStream(),
            { throw IOException("descriptor close failed") },
        )
        try {
            session.pumpOneTunPacket(100)
            fail("Read error must not be replaced by cleanup error")
        } catch (expected: IOException) {
            assertEquals("read failed", expected.message)
            assertEquals(1, expected.suppressed.size)
            assertEquals("descriptor close failed", expected.suppressed[0].message)
        }
        assertFalse(session.pumpOneTunPacket(101))
    }

    @Test fun explicitClosePreventsAnyInputOrGatewayAccess() {
        val forbidden = object : InputStream() {
            override fun read(): Int = throw AssertionError("Closed session read input")
        }
        var releases = 0
        val session = RestrictedTunSession(
            dispatcher(4), forbidden, ByteArrayOutputStream(), { releases++ },
        )
        session.close()
        assertFalse(session.pumpOneTunPacket(100))
        assertFalse(session.pumpOneGatewayReply(100))
        assertFalse(session.pumpPendingRetry(100))
        session.close()
        assertEquals(1, releases)
    }

    @Test fun crossThreadStopHandlesInterruptibleTunReadAndReleasesDescriptorOnce() {
        val entered = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val releases = AtomicInteger()
        // Simulates a descriptor whose blocked read wakes on close. Actual
        // Android TUN fd wakeup must be tested separately before activation.
        val blocked = object : InputStream() {
            override fun read(): Int = throw IOException("Use packet read")
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                entered.countDown()
                if (!interrupted.await(3, TimeUnit.SECONDS)) {
                    throw IOException("TUN read did not unblock")
                }
                throw IOException("TUN descriptor closed")
            }
        }
        val session = RestrictedTunSession(
            dispatcher(4), blocked, ByteArrayOutputStream(),
            { releases.incrementAndGet(); interrupted.countDown() },
        )
        val worker = Executors.newSingleThreadExecutor()
        try {
            val result = worker.submit<Boolean> { session.pumpOneTunPacket(100) }
            assertTrue("Worker never entered TUN read", entered.await(3, TimeUnit.SECONDS))
            session.requestStop() // Android lifecycle callback, not the pump owner.
            assertFalse(result.get(3, TimeUnit.SECONDS))
            assertFalse(session.pumpOneTunPacket(101))
            session.requestStop()
            session.close()
            assertEquals(1, releases.get())
        } finally {
            interrupted.countDown()
            worker.shutdownNow()
        }
    }

}
