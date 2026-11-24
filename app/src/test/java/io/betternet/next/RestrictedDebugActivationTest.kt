package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

/** Pure JVM tests: no Android VPN, service, network, external token or TUN. */
class RestrictedDebugActivationTest {
    private fun app() = AppChoice("com.example.browser", "Browser", 123, "signer")
    private fun config() = RestrictedTestConfiguration(
        "gateway.example", 443, "dns.example", "example.com",
        "1.1.1.1", "ABCDEFGHIJKLMNOP",
    )
    private fun stage(registry: RestrictedActivationHandoff): Pair<String, RestrictedActivationHandoff.Session> {
        val selected = app()
        val cfg = config()
        val ticket = RestrictedActivationTicket.forFutureExplicitConfirmation(selected, cfg)
        val handle = registry.stage(ticket, selected, cfg)
        return handle to RestrictedActivationHandoff.Session(ticket, selected, cfg)
    }

    @Test fun onlyExactSingleUseDebugStartClaimsOpaqueHandoff() {
        val registry = RestrictedActivationHandoff()
        val (handle, approved) = stage(registry)
        assertFalse(handle.contains("ABCDEFGHIJKLMNOP"))
        assertNull(claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, "invalid", true, registry))
        assertNull(claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, handle, true, registry))
        val next = stage(registry)
        assertNull(claimRestrictedDebugSession("unrecognized.ACTION", next.first, true, registry))
        assertNull(claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, next.first, true, registry))
        val third = stage(registry)
        assertNull(claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, third.first, false, registry))
        assertNull(claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, third.first, true, registry))
        val fourth = stage(registry)
        val taken = claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, fourth.first, true, registry)
        assertNotNull(taken)
        assertSame(fourth.second.app, taken!!.app)
        assertSame(fourth.second.configuration, taken.configuration)
        assertSame(fourth.second.ticket, taken.ticket)
        assertNull(claimRestrictedDebugSession(ACTION_START_RESTRICTED_DEBUG, fourth.first, true, registry))
    }

    @Test fun debugStartRequiresBothOsPreparationAndRecentVerifiedGateway() {
        for (debug in listOf(false, true)) {
            for (prepared in listOf(false, true)) {
                for (verified in listOf(false, true)) {
                    assertEquals(debug && prepared && verified,
                        canOfferRestrictedDebugStart(debug, prepared, verified))
                }
            }
        }
    }

    @Test fun verifiedGatewayLeaseIsExactScopeTimeBoundAndSinglePurpose() {
        data class NetworkHandle(val id: Int)
        var now = 5_000L
        val lease = VerifiedGatewayTestLease { now }
        val selected = app()
        val configured = config()
        val wifi = NetworkHandle(10)
        assertFalse(lease.validFor(selected, configured, wifi))
        lease.approve(selected, configured, wifi)
        assertTrue(lease.validFor(selected, configured, NetworkHandle(10)))
        assertFalse(lease.validFor(app(), configured, wifi)) // equal fields, different selection
        assertFalse(lease.validFor(selected, config(), wifi))
        assertFalse(lease.validFor(selected, configured, NetworkHandle(20)))
        assertFalse(lease.validFor(selected, configured, null))
        now += 60_000
        assertTrue(lease.validFor(selected, configured, wifi))
        now++
        assertFalse(lease.validFor(selected, configured, wifi))
        lease.approve(selected, configured, wifi)
        now--
        assertFalse(lease.validFor(selected, configured, wifi))
        lease.clear()
        assertFalse(lease.validFor(selected, configured, wifi))
    }

    @Test fun negativeAndClockRollbackFailClosed() {
        var now = 1_000L
        val lease = VerifiedGatewayTestLease { now }
        val selected = app()
        val configured = config()
        val underlying = Any()
        lease.approve(selected, configured, underlying)
        now = 999L
        assertFalse(lease.validFor(selected, configured, underlying))
        lease.clear()
        now = 5_000L
        assertFalse(lease.validFor(selected, configured, underlying))
    }
}
