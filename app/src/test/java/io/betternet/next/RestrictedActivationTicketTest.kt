package io.betternet.next

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class RestrictedActivationTicketTest {
    // These tests exercise the one-shot primitive without creating a VPN,
    // Android permission dialog, gateway socket or background worker.
    private fun config() = RestrictedTestConfiguration(
        "gateway.example.com", 443, "dns.example.com", "example.com",
        "1.1.1.1", "abcdefghijklmnop"
    )

    @Test fun ticketIsConsumedExactlyOnce() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config)
        ticket.consume(app, config)
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
    }

    @Test fun wrongConfigurationBurnsTicket() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config)
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config()) }
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
    }

    @Test fun simultaneousConsumersOnlyOneSucceeds() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config)
        val ready = CountDownLatch(2)
        val release = CountDownLatch(1)
        val successes = AtomicInteger()
        val rejected = AtomicInteger()
        val pool = Executors.newFixedThreadPool(2)
        try {
            val tasks = (1..2).map {
                pool.submit {
                    ready.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    try {
                        ticket.consume(app, config)
                        successes.incrementAndGet()
                    } catch (_: IllegalStateException) {
                        rejected.incrementAndGet()
                    }
                }
            }
            assertTrue("both consumers should be ready", ready.await(5, TimeUnit.SECONDS))
            release.countDown()
            tasks.forEach { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, successes.get())
            assertEquals(1, rejected.get())
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun staleConfirmationCannotActivateAndCannotBeReused() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        var now = TimeUnit.SECONDS.toNanos(10)
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config) { now }
        now += TimeUnit.SECONDS.toNanos(61)
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
        now = TimeUnit.SECONDS.toNanos(11)
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
    }

    @Test fun monotonicClockRollbackRejectsActivation() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        var now = TimeUnit.SECONDS.toNanos(10)
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config) { now }
        now--
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
    }

    @Test fun missingAppBurnsTicket() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config)
        assertThrows(IllegalStateException::class.java) { ticket.consume(null, config) }
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
    }
}
