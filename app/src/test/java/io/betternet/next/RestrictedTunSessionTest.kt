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

    @Test fun boundedReadinessWaitDoesNotReadOrCloseAnIdleTun() {
        val syn = TunTcpSynAckTest().request(4)
        var polls = 0
        var reads = 0
        var releases = 0
        val input = object : InputStream() {
            private val bytes = ByteArrayInputStream(syn.bytes)
            override fun read(): Int = bytes.read()
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                reads++
                return bytes.read(b, off, len)
            }
        }
        val session = RestrictedTunSession(
            dispatcher(4), input, ByteArrayOutputStream(), { releases++ },
            waitForReadable = { ++polls >= 3 },
        )
        assertTrue(session.pumpOneTunPacket(100))
        assertTrue(session.pumpOneTunPacket(101))
        assertEquals(0, reads)
        assertEquals(0, releases)
        assertTrue(session.pumpOneTunPacket(102))
        assertEquals(1, reads)
        assertFalse(session.pumpOneTunPacket(103)) // EOF
        assertEquals(2, reads)
        assertEquals(1, releases)
        assertEquals(4, polls)
    }

    @Test fun stopDuringReadinessWaitNeverReadsTun() {
        val entered = CountDownLatch(1)
        val wake = CountDownLatch(1)
        val releases = AtomicInteger()
        val input = object : InputStream() {
            override fun read(): Int = throw AssertionError("Cancelled TUN must not be read")
            override fun read(b: ByteArray, off: Int, len: Int): Int = read()
        }
        val session = RestrictedTunSession(
            dispatcher(6), input, ByteArrayOutputStream(),
            { releases.incrementAndGet(); wake.countDown() },
            waitForReadable = {
                entered.countDown()
                assertTrue(wake.await(3, TimeUnit.SECONDS))
                true // Even if poll reports ready, cancellation takes priority.
            },
        )
        val worker = Executors.newSingleThreadExecutor()
        try {
            val result = worker.submit<Boolean> { session.pumpOneTunPacket(100) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            session.requestStop()
            assertFalse(result.get(3, TimeUnit.SECONDS))
            assertEquals(1, releases.get())
            assertFalse(session.pumpOneTunPacket(101))
        } finally {
            wake.countDown()
            worker.shutdownNow()
        }
    }

    @Test fun oneCycleRefreshesClockAndStopsBeforeGatewayAfterTunEof() {
        val syn = TunTcpSynAckTest().request(4)
        var releases = 0
        var clockReads = 0
        val session = RestrictedTunSession(
            dispatcher(4), ByteArrayInputStream(syn.bytes),
            ByteArrayOutputStream(), { releases++ }, waitForReadable = { true },
        )
        val clock = { (++clockReads).toLong() }
        assertTrue(session.pumpOneCycle(clock))
        assertEquals(3, clockReads) // TUN, gateway, retry use fresh timestamps.
        assertFalse(session.pumpOneCycle(clock)) // EOF; no gateway or retry.
        assertEquals(4, clockReads)
        assertEquals(1, releases)
        assertFalse(session.pumpOneCycle(clock)) // Closed: do not even read clock.
        assertEquals(4, clockReads)
    }

    @Test fun oneCycleHonorsStopBetweenTunAndGatewayWithoutAnotherPoll() {
        val syn = TunTcpSynAckTest().request(6)
        var releases = 0
        var clockReads = 0
        lateinit var session: RestrictedTunSession
        session = RestrictedTunSession(
            dispatcher(6), ByteArrayInputStream(syn.bytes),
            ByteArrayOutputStream(), { releases++ }, waitForReadable = { true },
        )
        assertFalse(session.pumpOneCycle {
            clockReads++
            if (clockReads == 2) session.requestStop()
            clockReads.toLong()
        })
        assertEquals(2, clockReads) // Retry must not run after cancellation.
        assertEquals(1, releases)
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
