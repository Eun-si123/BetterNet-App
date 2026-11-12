package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

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

    @Test fun missingAppBurnsTicket() {
        val app = AppChoice("com.example.test", "Test", 123, "signer")
        val config = config()
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(app, config)
        assertThrows(IllegalStateException::class.java) { ticket.consume(null, config) }
        assertThrows(IllegalStateException::class.java) { ticket.consume(app, config) }
    }
}
