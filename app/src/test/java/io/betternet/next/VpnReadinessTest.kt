package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnReadinessTest {
    @Test fun noSelectionAlwaysBlocksReadiness() {
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, false, true, true, true))
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, true, false, true, true))
    }

    @Test fun anyVisibleVpnTakesPriorityEvenWithoutDefaultNetwork() {
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, false, true, false))
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, true, true, true))
    }

    @Test fun missingDefaultNetworkIsNotMistakenForReadiness() {
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE, vpnReadiness(true, false, false, true, false))
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE, vpnReadiness(true, false, false, true, true))
    }

    @Test fun unknownCapabilitiesOnAnyVisibleNetworkBlockReadiness() {
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE,
            vpnReadiness(true, false, true, false, true))
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE,
            vpnReadiness(true, false, true, false, false))
        // A VPN we can positively identify still takes precedence over unknown networks.
        assertEquals(VpnReadiness.VPN_ACTIVE,
            vpnReadiness(true, true, true, false, false))
    }

    @Test fun distinguishesOsConsentFromPriorPreparationWhenNetworkObservable() {
        assertEquals(VpnReadiness.NEEDS_CONSENT, vpnReadiness(true, false, true, true, false))
        assertEquals(VpnReadiness.PREPARED, vpnReadiness(true, false, true, true, true))
    }
}
