package io.betternet.next

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** JVM-only lifecycle tests: no VPN, TUN descriptor or gateway is opened. */
class RestrictedTunWorkerTest {
    private fun dispatcher(): RestrictedTestTunDispatcher {
        val syn = TunTcpSynAckTest().request(4)
        return RestrictedTestTunDispatcher(
            RestrictedTestTunPlan(syn.header.source,
                InetAddress.getByName("198.18.0.1"), syn.header.destination, 1280),
            { _, _ -> throw AssertionError("Unexpected DNS") },
            { _, _, _, _ -> throw AssertionError("Unexpected gateway") },
        )
    }

    private val forbiddenInput = object : InputStream() {
        override fun read(): Int = throw AssertionError("No TUN read expected")
        override fun read(b: ByteArray, off: Int, len: Int): Int = read()
    }

    @Test fun lifecycleStopJoinsOwnerAndReleasesDescriptorExactlyOnce() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closes = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), {
                closes.incrementAndGet()
                release.countDown()
            }, waitForReadable = {
                entered.countDown()
                assertTrue(release.await(3, TimeUnit.SECONDS))
                false
            })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L })
        assertEquals(0, closes.get()) // Construction must be inert.
        worker.start()
        assertTrue(entered.await(3, TimeUnit.SECONDS))
        assertTrue(worker.stopAndJoin(3000))
        assertNull(worker.failure)
        worker.requestStop()
        assertEquals(1, closes.get())
        try {
            worker.start()
            fail("A second owner must never start")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN worker already started", expected.message)
        }
    }

    @Test fun boundedJoinDoesNotPretendBlockedOwnerHasStopped() {
        val entered = CountDownLatch(1)
        val unblock = CountDownLatch(1)
        val closes = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), { closes.incrementAndGet() },
            waitForReadable = {
                entered.countDown()
                assertTrue(unblock.await(3, TimeUnit.SECONDS))
                false
            })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L })
        worker.start()
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            assertFalse(worker.stopAndJoin(20))
            assertEquals(1, closes.get()) // Cancellation closes the fd once.
        } finally {
            unblock.countDown()
        }
        assertTrue(worker.stopAndJoin(3000))
        assertNull(worker.failure)
        assertEquals(1, closes.get())
    }

    @Test fun workerCapturesFailureAndCleansUpWithoutUncaughtCrash() {
        val closes = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), { closes.incrementAndGet() },
            waitForReadable = { throw IOException("poll failed") })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L })
        worker.start()
        // A finished worker can be joined after cancellation without hiding failure.
        assertTrue(worker.stopAndJoin(3000))
        assertEquals("poll failed", (worker.failure as IOException).message)
        assertEquals(1, closes.get())
    }

    @Test fun invalidJoinCannotStartOrBlockWorker() {
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), {}, waitForReadable = { false })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L })
        try {
            worker.stopAndJoin(100)
            fail("Cannot join a worker that was never started")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN worker has not started", expected.message)
        }
        worker.requestStop()
        worker.start()
        assertTrue(worker.stopAndJoin(1000))
        assertNull(worker.failure)
        try {
            worker.stopAndJoin(0)
            fail("Unbounded or zero joins are forbidden")
        } catch (expected: IllegalArgumentException) {
            assertEquals("TUN worker join must be bounded", expected.message)
        }
    }
}
