package io.betternet.next

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

/** Pure JVM verification: no Android clipboard, file, credential or network. */
class RestrictedDebugEventsTest {
    @Test fun onlyPredefinedCodeAndProcessRelativeTimeAppear() {
        var now = 30_000L
        val log = RestrictedDebugEventJournal({ now }, maxEvents = 3)
        log.record(RestrictedDebugEvent.START_REQUESTED)
        now += 1_300
        log.record(RestrictedDebugEvent.START_ACCEPTED)
        val text = log.snapshot()
        assertTrue(text.contains("+0s START_REQUESTED"))
        assertTrue(text.contains("+1s START_ACCEPTED"))
        assertFalse(text.contains("30000"))
        assertFalse(text.contains("Bearer"))
        assertFalse(text.contains("gateway.example"))
        assertFalse(text.contains("com.example.browser"))
        assertFalse(text.contains("Authorization"))
        assertTrue(text.contains("no auto-upload"))
        assertTrue(text.contains("No VPN success"))
    }

    @Test fun ringBufferEvictsOnlyOldestAndNeverGrowsBeyondCap() {
        var now = 1_000L
        val log = RestrictedDebugEventJournal({ now }, maxEvents = 2)
        log.record(RestrictedDebugEvent.CONFIG_UPDATED)
        now += 1_000
        log.record(RestrictedDebugEvent.START_REQUESTED)
        now += 1_000
        log.record(RestrictedDebugEvent.START_REFUSED)
        val snapshot = log.snapshot()
        assertFalse(snapshot.contains("CONFIG_UPDATED"))
        assertTrue(snapshot.contains("+1s START_REQUESTED"))
        assertTrue(snapshot.contains("+2s START_REFUSED"))
        assertEquals(2, snapshot.lineSequence().count { it.startsWith("+") })
    }

    @Test fun explicitClearErasesAndResetsRelativeClock() {
        var now = 100L
        val log = RestrictedDebugEventJournal({ now })
        log.record(RestrictedDebugEvent.VPN_REVOKED)
        now += 1000
        log.clear()
        assertTrue(log.snapshot().endsWith("(no events)"))
        log.record(RestrictedDebugEvent.SERVICE_DESTROYED)
        val snapshot = log.snapshot()
        assertTrue(snapshot.contains("+0s SERVICE_DESTROYED"))
        assertFalse(snapshot.contains("VPN_REVOKED"))
    }

    @Test fun clockRollbackCannotRevealAbsoluteTimeOrNegativeEventAge() {
        var now = 5_000L
        val log = RestrictedDebugEventJournal({ now })
        log.record(RestrictedDebugEvent.START_REQUESTED)
        now = 4_000
        log.record(RestrictedDebugEvent.START_REFUSED)
        assertEquals(2, log.snapshot().lineSequence().count { it.startsWith("+0s") })
        assertFalse(log.snapshot().contains("-1s"))
    }

    @Test fun invalidStorageSizeIsRejectedBeforeAnyEvents() {
        for (size in listOf(-1, 0, 257, 1000)) {
            try {
                RestrictedDebugEventJournal({ 0L }, size)
                fail("Invalid debug event capacity: " + size)
            } catch (_: IllegalArgumentException) {}
        }
    }

    @Test fun concurrentEventsRemainBoundedAndValidWithoutUntrustedStrings() {
        val log = RestrictedDebugEventJournal({ 100L }, maxEvents = 64)
        val pool = Executors.newFixedThreadPool(4)
        try {
            val jobs = (0 until 4).map {
                pool.submit {
                    repeat(150) {
                        log.record(RestrictedDebugEvent.START_REQUESTED)
                        log.record(RestrictedDebugEvent.START_REFUSED)
                    }
                }
            }
            jobs.forEach { it.get(5, TimeUnit.SECONDS) }
        } finally { pool.shutdownNow() }
        val rows = log.snapshot().lineSequence().filter { it.startsWith("+") }.toList()
        assertEquals(64, rows.size)
        assertTrue(rows.all {
            it == "+0s START_REQUESTED" || it == "+0s START_REFUSED"
        })
    }

    @Test fun releaseGateCollectsNothingWhileDebugGateRecordsCodes() {
        val journal = RestrictedDebugEvents.journal
        journal.clear()
        try {
            RestrictedDebugEvents.record(false, RestrictedDebugEvent.START_ACCEPTED)
            assertTrue(journal.snapshot().endsWith("(no events)"))
            RestrictedDebugEvents.record(true, RestrictedDebugEvent.START_REFUSED)
            assertTrue(journal.snapshot().contains("START_REFUSED"))
            assertFalse(journal.snapshot().contains("START_ACCEPTED"))
        } finally { journal.clear() }
    }

    @Test fun quotaFailureIsClassifiableWithoutLeakingAmounts() {
        val problem = RestrictedTunByteBudgetExceeded()
        assertEquals("Restricted TUN byte budget exceeded", problem.message)
        assertTrue(problem is java.io.IOException)
        val log = RestrictedDebugEventJournal({ 100L })
        log.record(RestrictedDebugEvent.TUN_BUDGET_EXCEEDED)
        val snapshot = log.snapshot()
        assertTrue(snapshot.contains("TUN_BUDGET_EXCEEDED"))
        assertFalse(snapshot.contains("8388608"))
        assertFalse(snapshot.contains("192.168"))
    }
}
