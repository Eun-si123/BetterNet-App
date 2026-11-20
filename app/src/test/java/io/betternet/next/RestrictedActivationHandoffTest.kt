package io.betternet.next

import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class RestrictedActivationHandoffTest {
    private fun session(): Triple<RestrictedActivationTicket, AppChoice, RestrictedTestConfiguration> {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = RestrictedTestConfiguration("gateway.example.com", 443,
            "dns.example.com", "example.com", "1.1.1.1", "abcdefghijklmnop")
        return Triple(RestrictedActivationTicket.forFutureExplicitConfirmation(app, config), app, config)
    }

    @Test fun handleIsOpaqueOneUseAndDoesNotExposeCredential() {
        val registry = RestrictedActivationHandoff()
        val (ticket, app, config) = session()
        val handle = registry.stage(ticket, app, config)
        assertEquals(64, handle.length)
        assertFalse(handle.contains("abcdefghijklmnop"))
        assertNull(registry.take(null))
        assertNull(registry.take("bad"))
        val taken = registry.take(handle)!!
        assertSame(ticket, taken.ticket)
        assertSame(app, taken.app)
        assertSame(config, taken.configuration)
        assertNull(registry.take(handle))
    }

    @Test fun replacementCancellationAndProcessRestartInvalidateOldHandles() {
        val registry = RestrictedActivationHandoff()
        val (firstTicket, firstApp, firstConfig) = session()
        val first = registry.stage(firstTicket, firstApp, firstConfig)
        val (secondTicket, secondApp, secondConfig) = session()
        val second = registry.stage(secondTicket, secondApp, secondConfig)
        assertNotEquals(first, second)
        assertNull(registry.take(first))
        registry.clear()
        assertNull(registry.take(second))
        val third = registry.stage(secondTicket, secondApp, secondConfig)
        assertNull(RestrictedActivationHandoff().take(third))
    }

    @Test fun expiredOrClockReversedSessionCannotBeTaken() {
        var now = 1_000_000_000_000L
        val registry = RestrictedActivationHandoff(monotonicNanos = { now })
        val (ticket, app, config) = session()
        val expired = registry.stage(ticket, app, config)
        now += TimeUnit.SECONDS.toNanos(61)
        assertNull(registry.take(expired))
        now -= TimeUnit.SECONDS.toNanos(61)
        assertNull(registry.take(expired))
        val reversed = registry.stage(ticket, app, config)
        now--
        assertNull(registry.take(reversed))
    }

    @Test fun repeatingRandomAcrossMultipleSessionsNeverReissuesOldHandle() {
        val repeatingRandom = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) { bytes.fill(7) }
        }
        val registry = RestrictedActivationHandoff(random = repeatingRandom)
        val (ticket, app, config) = session()
        val first = registry.stage(ticket, app, config)
        registry.clear()
        val second = registry.stage(ticket, app, config)
        assertNotEquals(first, second)
        assertNull(registry.take(first))
        assertSame(ticket, registry.take(second)?.ticket)
        val third = registry.stage(ticket, app, config)
        assertNotEquals(first, third)
        assertNotEquals(second, third)
        assertNull(registry.take(first))
        assertNull(registry.take(second))
        assertSame(ticket, registry.take(third)?.ticket)
    }

    @Test fun failedReplacementDoesNotLeaveOldSessionClaimable() {
        var fail = false
        val random = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                if (fail) throw IllegalStateException("random unavailable")
                bytes.fill(42)
            }
        }
        val registry = RestrictedActivationHandoff(random = random)
        val (ticket, app, config) = session()
        val previous = registry.stage(ticket, app, config)
        fail = true
        try {
            registry.stage(ticket, app, config)
            fail("Expected random failure")
        } catch (expected: IllegalStateException) {
            assertEquals("random unavailable", expected.message)
        }
        assertNull(registry.take(previous))
    }

    @Test fun pendingSessionStillValidAtSixtySeconds() {
        var now = 10_000_000_000L
        val registry = RestrictedActivationHandoff(monotonicNanos = { now })
        val (ticket, app, config) = session()
        val handle = registry.stage(ticket, app, config)
        now += TimeUnit.SECONDS.toNanos(60)
        assertSame(ticket, registry.take(handle)?.ticket)
    }

    @Test fun simultaneousConsumersCannotBothClaimSession() {
        val registry = RestrictedActivationHandoff()
        val (ticket, app, config) = session()
        val handle = registry.stage(ticket, app, config)
        val ready = CountDownLatch(2)
        val go = CountDownLatch(1)
        val claimed = AtomicInteger()
        val pool = Executors.newFixedThreadPool(2)
        try {
            val jobs = (1..2).map { pool.submit {
                ready.countDown()
                check(go.await(5, TimeUnit.SECONDS))
                if (registry.take(handle) != null) claimed.incrementAndGet()
            } }
            assertTrue(ready.await(5, TimeUnit.SECONDS))
            go.countDown()
            jobs.forEach { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, claimed.get())
        } finally { go.countDown(); pool.shutdownNow() }
    }
}
