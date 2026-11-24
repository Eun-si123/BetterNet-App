package io.betternet.next

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

/** No Android Looper, service, real VPN, network or credential needed. */
class RestrictedDebugStopWatchdogTest {
    private class FakeQueue {
        var queued: Runnable? = null
        var delay: Long? = null
        var removes = 0
        fun schedule(task: Runnable, millis: Long): Boolean {
            queued = task
            delay = millis
            return true
        }
        fun remove(task: Runnable) {
            removes++
            if (queued === task) queued = null
        }
        fun fire() { queued?.run() }
    }

    @Test fun independentWatchdogStopsBlockedPumpAfterFixedDeadlineOnlyOnce() {
        val queue = FakeQueue()
        var stops = 0
        val watchdog = RestrictedDebugStopWatchdog(
            schedule = queue::schedule,
            unschedule = queue::remove,
            requestStop = { stops++ },
        )
        watchdog.arm()
        assertEquals(RESTRICTED_DEBUG_MAX_RUNTIME_MS, queue.delay)
        assertEquals(120_000L, queue.delay)
        assertEquals(0, stops)
        val task = queue.queued!!
        // Simulate an owner stuck in Android DNS: no pump-loop callback runs.
        task.run()
        task.run()
        assertEquals("The deadline must cancel even without pump progress", 1, stops)
        watchdog.cancel()
        assertEquals(1, stops)
        assertNull(queue.queued)
    }

    @Test fun selectionChangeOrRevokeSuppressesQueuedTimeout() {
        val queue = FakeQueue()
        var stops = 0
        val watchdog = RestrictedDebugStopWatchdog(
            queue::schedule, queue::remove, { stops++ },
        )
        watchdog.arm()
        val stale = queue.queued!!
        watchdog.cancel()
        stale.run()  // Already dequeued callback racing a cancellation.
        assertEquals(0, stops)
        assertNull(queue.queued)
        try {
            watchdog.arm()
            fail("One service owner must never renew a previous user grant")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message!!.contains("cannot be rearmed"))
        }
    }

    @Test fun schedulingFailureDoesNotLeaveLiveCallback() {
        val queue = FakeQueue()
        var cancels = 0
        val watchdog = RestrictedDebugStopWatchdog(
            schedule = { task, delay ->
                queue.schedule(task, delay)
                false
            },
            unschedule = { task -> cancels++; queue.remove(task) },
            requestStop = { fail("Unscheduled timeout cannot run") },
        )
        try {
            watchdog.arm()
            fail("An unarmed timeout must prevent activation")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message!!.contains("Could not schedule"))
        }
        assertEquals(1, cancels)
        assertNull(queue.queued)
    }

    @Test fun scheduleThrowKeepsOriginalErrorAndRevokesCallback() {
        val queue = FakeQueue()
        val primary = IOException("Unable to schedule deadline")
        val watchdog = RestrictedDebugStopWatchdog(
            schedule = { task, delay ->
                queue.schedule(task, delay)
                throw primary
            },
            unschedule = { task -> queue.remove(task) },
            requestStop = { fail("No active timer") },
        )
        try {
            watchdog.arm()
            fail("Scheduling exception must fail closed")
        } catch (actual: IOException) {
            assertSame(primary, actual)
            assertNull(queue.queued)
        }
    }

    @Test fun changingConfigurationClearsPendingPermissionBeforeServiceStopRequest() {
        val handoff = RestrictedActivationHandoff()
        val selected = AppChoice("com.example.browser", "Browser", 10001, "sha")
        val config = RestrictedTestConfiguration(
            "gateway.example", 443, "dns.example", "www.example.org",
            "1.1.1.1", "ABCDEFGHIJKLMNOP"
        )
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(
            selected, config
        )
        val handle = handoff.stage(ticket, selected, config, 42L)
        var stopCalls = 0
        revokeRestrictedDebugScope(handoff) {
            stopCalls++
            assertNull("Old handoff must already be invalid before stopping", handoff.take(handle))
        }
        assertEquals(1, stopCalls)
        assertNull(handoff.take(handle))
    }

    @Test fun failedServiceStopStillCannotReplayOldConfiguration() {
        val handoff = RestrictedActivationHandoff()
        val selected = AppChoice("com.example.browser", "Browser", 10001, "sha")
        val config = RestrictedTestConfiguration(
            "gateway.example", 443, "dns.example", "www.example.org",
            "1.1.1.1", "ABCDEFGHIJKLMNOP"
        )
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(
            selected, config
        )
        val handle = handoff.stage(ticket, selected, config, 42L)
        val failure = IOException("test stop operation failed")
        try {
            revokeRestrictedDebugScope(handoff) { throw failure }
            fail("Stop failure cannot be ignored")
        } catch (actual: IOException) {
            assertSame(failure, actual)
        }
        assertNull(handoff.take(handle))
    }
}
