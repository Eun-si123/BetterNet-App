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
        val enteredPoll = CountDownLatch(1)
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), { closes.incrementAndGet() },
            waitForReadable = {
                enteredPoll.countDown()
                throw IOException("poll failed")
            })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L })
        worker.start()
        // Observe the natural failure without racing a cancellation against it.
        assertTrue(enteredPoll.await(3, TimeUnit.SECONDS))
        assertTrue(worker.awaitStopped(3000))
        assertEquals("poll failed", (worker.failure as IOException).message)
        assertTrue(worker.stopAndJoin(3000)) // Idempotent after completion.
        assertEquals(1, closes.get())
    }

    @Test fun terminationCallbackRunsOnceAfterCleanupForNormalStopAndFailure() {
        for (shouldFail in listOf(false, true)) {
            val closes = AtomicInteger()
            val notices = AtomicInteger()
            var observedFailure: Throwable? = null
            val session = RestrictedTunSession(dispatcher(), forbiddenInput,
                ByteArrayOutputStream(), { closes.incrementAndGet() },
                waitForReadable = {
                    if (shouldFail) throw IOException("poll failed")
                    false
                })
            val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L },
                onTerminated = { error ->
                    assertEquals(1, closes.get()) // Owner has already cleaned up.
                    observedFailure = error
                    notices.incrementAndGet()
                })
            assertEquals(0, notices.get()) // Construction must not notify.
            if (!shouldFail) worker.requestStop()
            worker.start()
            assertTrue(worker.awaitStopped(3000))
            assertEquals(1, notices.get())
            assertEquals(1, closes.get())
            if (shouldFail) {
                assertEquals("poll failed", (worker.failure as IOException).message)
                assertSame(worker.failure, observedFailure)
            } else {
                assertNull(worker.failure)
                assertNull(observedFailure)
            }
            assertTrue(worker.stopAndJoin(3000))
            assertEquals(1, notices.get())
        }
    }

    @Test fun callbackFailureDoesNotHideOriginalPumpFailureOrCrashOwner() {
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), {}, waitForReadable = { throw IOException("poll failed") })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L },
            onTerminated = { throw IllegalStateException("monitor failed") })
        worker.start()
        assertTrue(worker.awaitStopped(3000))
        assertEquals("poll failed", (worker.failure as IOException).message)
        assertEquals(listOf("monitor failed"), worker.failure!!.suppressed.map { it.message })

        val normal = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(), {},
                waitForReadable = { false })) { 100L },
            onTerminated = { throw IllegalStateException("monitor failed") })
        normal.requestStop()
        normal.start()
        assertTrue(normal.awaitStopped(3000))
        assertEquals("monitor failed", (normal.failure as IllegalStateException).message)
    }

    @Test fun joinCannotReportStoppedWhileThreadLaunchIsPending() {
        val launchEntered = CountDownLatch(1)
        val allowLaunch = CountDownLatch(1)
        val joinEntered = CountDownLatch(1)
        val joinFinished = CountDownLatch(1)
        val closes = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), { closes.incrementAndGet() },
            waitForReadable = { false })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L }) { thread ->
            launchEntered.countDown()
            check(allowLaunch.await(3, TimeUnit.SECONDS))
            thread.start()
        }
        val starter = Thread { worker.start() }
        var joinResult = false
        val joiner = Thread {
            joinEntered.countDown()
            joinResult = worker.stopAndJoin(3000)
            joinFinished.countDown()
        }
        starter.start()
        try {
            assertTrue(launchEntered.await(3, TimeUnit.SECONDS))
            joiner.start()
            assertTrue(joinEntered.await(3, TimeUnit.SECONDS))
            assertFalse("Join must not claim completion before launch finishes",
                joinFinished.await(50, TimeUnit.MILLISECONDS))
        } finally {
            allowLaunch.countDown()
        }
        starter.join(3000)
        joiner.join(3000)
        assertFalse(starter.isAlive)
        assertFalse(joiner.isAlive)
        assertTrue(joinResult)
        assertNull(worker.failure)
        assertEquals(1, closes.get())
    }

    @Test fun joinDeadlineIncludesPendingThreadLaunch() {
        val launchEntered = CountDownLatch(1)
        val allowLaunch = CountDownLatch(1)
        val closes = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), { closes.incrementAndGet() },
            waitForReadable = { false })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L }) { thread ->
            launchEntered.countDown()
            check(allowLaunch.await(3, TimeUnit.SECONDS))
            thread.start()
        }
        val starter = Thread { worker.start() }
        starter.start()
        try {
            assertTrue(launchEntered.await(3, TimeUnit.SECONDS))
            // A blocked launch must not consume an unbounded part of this join.
            assertFalse(worker.stopAndJoin(30))
            assertEquals(1, closes.get())
            assertTrue(starter.isAlive)
        } finally {
            allowLaunch.countDown()
        }
        starter.join(3000)
        assertFalse(starter.isAlive)
        assertTrue(worker.stopAndJoin(3000))
        assertNull(worker.failure)
        assertEquals(1, closes.get())
    }

    @Test fun failedThreadLaunchCannotBeMistakenForCompletedWorker() {
        val notices = AtomicInteger()
        val closes = AtomicInteger()
        val session = RestrictedTunSession(dispatcher(), forbiddenInput,
            ByteArrayOutputStream(), { closes.incrementAndGet() },
            waitForReadable = { false })
        val worker = RestrictedTunWorker(RestrictedTunPump(session) { 100L },
            launchThread = { throw IllegalStateException("launch rejected") },
            onTerminated = { notices.incrementAndGet() })
        try {
            worker.start()
            fail("Thread launch must fail")
        } catch (expected: IllegalStateException) {
            assertEquals("launch rejected", expected.message)
        }
        assertEquals(1, closes.get())
        assertEquals(1, notices.get()) // Launch failure must notify after cleanup.
        try {
            worker.awaitStopped(100)
            fail("Never claim an unlaunched thread has stopped")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN worker has not started", expected.message)
        }
    }

    @Test fun failedLaunchCallbackErrorCannotHideLaunchFailure() {
        val closes = AtomicInteger()
        val worker = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { closes.incrementAndGet() }, waitForReadable = { false })) { 100L },
            onTerminated = { throw IOException("shutdown notification failed") },
            launchThread = { throw IllegalStateException("launch rejected") })
        try {
            worker.start()
            fail("Launch failure must propagate")
        } catch (expected: IllegalStateException) {
            assertEquals("launch rejected", expected.message)
            assertSame(expected, worker.failure)
            assertEquals(listOf("shutdown notification failed"),
                expected.suppressed.map { it.message })
        }
        assertEquals(1, closes.get())
    }

    @Test fun launcherReturningWithoutStartingWorkerFailsClosedAndNotifies() {
        val closes = AtomicInteger()
        val notices = AtomicInteger()
        var reported: Throwable? = null
        val worker = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { closes.incrementAndGet() }, waitForReadable = { false })) { 100L },
            onTerminated = { error ->
                assertEquals(1, closes.get())
                reported = error
                notices.incrementAndGet()
            },
            launchThread = { /* Simulate a launcher that silently drops the thread. */ })
        try {
            worker.start()
            fail("An unstarted worker must never be accepted")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN worker thread was not launched", expected.message)
        }
        assertEquals(1, closes.get())
        assertEquals(1, notices.get())
        assertSame(worker.failure, reported)
        try {
            worker.awaitStopped(100)
            fail("A worker that never ran cannot be joined")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN worker has not started", expected.message)
        }
    }

    @Test fun launcherThrowingAfterStartingWorkerDoesNotNotifyBeforeCleanup() {
        val entered = CountDownLatch(1)
        val released = CountDownLatch(1)
        val closes = AtomicInteger()
        val notices = AtomicInteger()
        val worker = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { closes.incrementAndGet(); released.countDown() },
                waitForReadable = {
                    entered.countDown()
                    assertTrue(released.await(3, TimeUnit.SECONDS))
                    false
                })) { 100L },
            onTerminated = {
                assertEquals(1, closes.get())
                notices.incrementAndGet()
            },
            launchThread = { thread ->
                thread.start()
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                throw IllegalStateException("launcher failed after start")
            })
        try {
            worker.start()
            fail("Launch failure must propagate")
        } catch (expected: IllegalStateException) {
            assertEquals("launcher failed after start", expected.message)
        }
        // A thread that started owns its own terminal notification.
        assertTrue(worker.awaitStopped(3000))
        assertEquals(1, notices.get())
        assertEquals(1, closes.get())
    }

    @Test fun lifecycleRevokeBeforeAdoptionRejectsAndReleasesDescriptor() {
        val lifecycle = RestrictedTunLifecycle()
        lifecycle.cancel()
        val closes = AtomicInteger()
        val worker = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { closes.incrementAndGet() }, waitForReadable = { false })) { 100L })
        try {
            lifecycle.adopt(worker)
            fail("Revoked lifecycle must not adopt a TUN")
        } catch (expected: IllegalStateException) {
            assertEquals("VPN lifecycle already revoked", expected.message)
        }
        assertEquals(1, closes.get())
        lifecycle.cancel()
        assertEquals(1, closes.get())
    }

    @Test fun descriptorCloseFailureCannotReopenRevokedLifecycle() {
        val lifecycle = RestrictedTunLifecycle()
        val closes = AtomicInteger()
        val worker = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(), {
                closes.incrementAndGet()
                throw IOException("simulated descriptor close failure")
            }, waitForReadable = { false })) { 100L })
        lifecycle.adopt(worker)
        try {
            lifecycle.cancel()
            fail("Descriptor close failure must be observable")
        } catch (expected: IOException) {
            assertEquals("simulated descriptor close failure", expected.message)
        }
        // onDestroy() may follow onRevoke(); no repeated close or adoption.
        lifecycle.cancel()
        assertEquals(1, closes.get())
        val replacementCloses = AtomicInteger()
        val replacement = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { replacementCloses.incrementAndGet() }, waitForReadable = { false })) { 100L })
        try {
            lifecycle.adopt(replacement)
            fail("A failed descriptor close must not re-authorize the VPN")
        } catch (expected: IllegalStateException) {
            assertEquals("VPN lifecycle already revoked", expected.message)
        }
        assertEquals(1, replacementCloses.get())
    }

    @Test fun lifecycleRevokeCancelsAdoptedWorkerWithoutStartingIt() {
        val lifecycle = RestrictedTunLifecycle()
        val closes = AtomicInteger()
        val worker = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { closes.incrementAndGet() }, waitForReadable = { false })) { 100L })
        assertSame(worker, lifecycle.adopt(worker))
        assertEquals(0, closes.get())
        lifecycle.cancel()
        lifecycle.cancel() // onRevoke() and onDestroy() may both run.
        assertEquals(1, closes.get())
        worker.start()
        assertTrue(worker.awaitStopped(3000))
        assertNull(worker.failure)
    }

    @Test fun lifecycleRevokeStopsRunningOwnerAndReleasesDescriptorOnce() {
        val lifecycle = RestrictedTunLifecycle()
        val entered = CountDownLatch(1)
        val released = CountDownLatch(1)
        val closes = AtomicInteger()
        val worker = lifecycle.adopt(RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(), {
                closes.incrementAndGet()
                released.countDown()
            }, waitForReadable = {
                entered.countDown()
                assertTrue(released.await(3, TimeUnit.SECONDS))
                false
            })) { 100L }))
        worker.start()
        assertTrue(entered.await(3, TimeUnit.SECONDS))
        lifecycle.cancel()
        lifecycle.cancel()
        assertTrue(worker.awaitStopped(3000))
        assertNull(worker.failure)
        assertEquals(1, closes.get())
    }

    @Test fun lifecycleRejectsSecondWorkerAndClosesOnlyRejectedDescriptor() {
        val lifecycle = RestrictedTunLifecycle()
        val firstCloses = AtomicInteger()
        val secondCloses = AtomicInteger()
        fun worker(closes: AtomicInteger) = RestrictedTunWorker(RestrictedTunPump(
            RestrictedTunSession(dispatcher(), forbiddenInput, ByteArrayOutputStream(),
                { closes.incrementAndGet() }, waitForReadable = { false })) { 100L })
        val first = lifecycle.adopt(worker(firstCloses))
        try {
            lifecycle.adopt(worker(secondCloses))
            fail("Second worker must not replace the first")
        } catch (expected: IllegalStateException) {
            assertEquals("TUN worker already owned", expected.message)
        }
        assertEquals(0, firstCloses.get())
        assertEquals(1, secondCloses.get())
        lifecycle.cancel()
        first.start()
        assertTrue(first.awaitStopped(3000))
        assertEquals(1, firstCloses.get())
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
