package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnReadinessTest {
    @Test fun noSelectionAlwaysBlocksReadiness() {
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, false, true, true))
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, true, false, true))
    }

    @Test fun anyVisibleVpnTakesPriorityEvenWithoutDefaultNetwork() {
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, false, false))
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, true, true))
    }

    @Test fun missingDefaultNetworkIsNotMistakenForReadiness() {
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE, vpnReadiness(true, false, false, false))
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE, vpnReadiness(true, false, false, true))
    }

    @Test fun distinguishesOsConsentFromPriorPreparationWhenNetworkObservable() {
        assertEquals(VpnReadiness.NEEDS_CONSENT, vpnReadiness(true, false, true, false))
        assertEquals(VpnReadiness.PREPARED, vpnReadiness(true, false, true, true))
    }
}
