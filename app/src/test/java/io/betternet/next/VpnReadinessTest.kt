package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnReadinessTest {
    @Test fun noSelectionAlwaysBlocksReadiness() {
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, false, true))
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, true, true))
    }

    @Test fun existingVpnTakesPriorityEvenIfPrepared() {
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, false))
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, true))
    }

    @Test fun distinguishesOsConsentFromPriorPreparation() {
        assertEquals(VpnReadiness.NEEDS_CONSENT, vpnReadiness(true, false, false))
        assertEquals(VpnReadiness.PREPARED, vpnReadiness(true, false, true))
    }
}
