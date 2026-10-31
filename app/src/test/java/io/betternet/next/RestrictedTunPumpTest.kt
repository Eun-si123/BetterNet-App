package io.betternet.next

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

/** Offline owner-thread lifecycle checks; no Android VPN or external gateway. */
class RestrictedTunPumpTest {
    private fun dispatcher(): RestrictedTestTunDispatcher {
        val syn = TunTcpSynAckTest().request(4)
        return RestrictedTestTunDispatcher(
            RestrictedTestTunPlan(syn.header.source,
                InetAddress.getByName("198.18.0.1"), syn.header.destination, 1280),
            { _, _ -> throw AssertionError("Unexpected DNS") },
            { _, _, _, _ -> throw AssertionError("Unexpected gateway dial") },
        )
    }

    private fun forbiddenInput() = object : InputStream() {
        override fun read(): Int = throw AssertionError("Cancelled TUN was read")
        override fun read(b: ByteArray, off: Int, len: Int): Int = read()
    }

    @Test fun crossThreadStopCancelsIdleOwnerAndClosesDescriptorOnce() {
        val enteredPoll = CountDownLatch(1)
        val releasedPoll = CountDownLatch(1)
        val descriptorCloses = AtomicInteger()
        val session = RestrictedTunSession(
            dispatcher(), forbiddenInput(), ByteArrayOutputStream(),
            { descriptorCloses.incrementAndGet(); releasedPoll.countDown() },
            waitForReadable = {
                enteredPoll.countDown()
                assertTrue(releasedPoll.await(3, TimeUnit.SECONDS))
                false
            },
        )
        val pump = RestrictedTunPump(session) { 100L }
        val owner = Executors.newSingleThreadExecutor()
        try {
            val task = owner.submit { pump.runUntilStopped() }
            assertTrue("Owner did not enter idle poll", enteredPoll.await(3, TimeUnit.SECONDS))
            pump.requestStop()
            task.get(3, TimeUnit.SECONDS)
            pump.requestStop()
            assertEquals(1, descriptorCloses.get())
            assertFalse(session.pumpOneTunPacket(101))
        } finally {
            releasedPoll.countDown()
            owner.shutdownNow()
        }
    }

    @Test fun stopBeforeStartNeverTouchesTunOrClock() {
        val releases = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput(),
            ByteArrayOutputStream(), { releases.incrementAndGet() })
        val pump = RestrictedTunPump(session) { throw AssertionError("Clock read after stop") }
        pump.requestStop()
        pump.runUntilStopped()
        assertEquals(1, releases.get())
        try {
            pump.runUntilStopped()
            fail("A second owner must not be accepted")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN pump already started", expected.message)
        }
    }

    @Test fun pollFailurePropagatesAndClosesOwnedDescriptor() {
        val releases = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput(),
            ByteArrayOutputStream(), { releases.incrementAndGet() },
            waitForReadable = { throw IOException("TUN poll failed") })
        val pump = RestrictedTunPump(session) { 100L }
        try {
            pump.runUntilStopped()
            fail("Owner must observe the I/O failure")
        } catch (expected: IOException) {
            assertEquals("TUN poll failed", expected.message)
        }
        assertEquals(1, releases.get())
        pump.requestStop()
        assertEquals(1, releases.get())
    }
}
