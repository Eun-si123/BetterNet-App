package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnReadinessTest {
    @Test fun noSelectionAlwaysBlocksReadiness() {
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, true, false, true, true, true))
        assertEquals(VpnReadiness.NO_APP, vpnReadiness(false, true, true, false, true, true))
    }

    @Test fun anyVisibleVpnTakesPriorityEvenWithoutDefaultNetwork() {
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, true, false, true, false))
        assertEquals(VpnReadiness.VPN_ACTIVE, vpnReadiness(true, true, true, true, true, true))
    }

    @Test fun missingDefaultNetworkIsNotMistakenForReadiness() {
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE, vpnReadiness(true, true, false, false, true, false))
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE, vpnReadiness(true, true, false, false, true, true))
    }

    @Test fun unknownCapabilitiesOnAnyVisibleNetworkBlockReadiness() {
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE,
            vpnReadiness(true, true, false, true, false, true))
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE,
            vpnReadiness(true, true, false, true, false, false))
        // A VPN we can positively identify still takes precedence over unknown networks.
        assertEquals(VpnReadiness.VPN_ACTIVE,
            vpnReadiness(true, true, true, true, false, false))
    }

    @Test fun distinguishesOsConsentFromPriorPreparationWhenNetworkObservable() {
        assertEquals(VpnReadiness.NEEDS_CONSENT, vpnReadiness(true, true, false, true, true, false))
        assertEquals(VpnReadiness.PREPARED, vpnReadiness(true, true, false, true, true, true))
    }

    @Test fun staleAppSelectionBlocksEvenIfPermissionWasPreviouslyPrepared() {
        assertEquals(VpnReadiness.APP_UNAVAILABLE,
            vpnReadiness(true, false, false, true, true, true))
        assertEquals(VpnReadiness.APP_UNAVAILABLE,
            vpnReadiness(true, false, false, true, true, false))
        assertEquals(false, canRequestVpnConsent(true, true, VpnReadiness.APP_UNAVAILABLE))
        // A visible VPN must still be reported even when the app has vanished.
        assertEquals(VpnReadiness.VPN_ACTIVE,
            vpnReadiness(true, false, true, true, true, false))
    }

    @Test fun internetCapabilityIsRequiredButValidationIsNot() {
        // The Android adapter passes false when the default network lacks
        // NET_CAPABILITY_INTERNET, even if it has a capabilities object.
        assertEquals(VpnReadiness.NETWORK_UNAVAILABLE,
            vpnReadiness(true, true, false, false, true, false))
        // A non-validated network with INTERNET is intentionally eligible;
        // this is permission preparation, not a reachability claim.
        assertEquals(VpnReadiness.NEEDS_CONSENT,
            vpnReadiness(true, true, false, true, true, false))
    }

    @Test fun consentPromptRequiresSelectionConfigurationAndObservableNonVpnNetwork() {
        assertEquals(true, canRequestVpnConsent(true, true, VpnReadiness.NEEDS_CONSENT))
        for (state in VpnReadiness.entries) {
            if (state != VpnReadiness.NEEDS_CONSENT) {
                assertEquals(false, canRequestVpnConsent(true, true, state))
            }
        }
        assertEquals(false, canRequestVpnConsent(false, true, VpnReadiness.NEEDS_CONSENT))
        assertEquals(false, canRequestVpnConsent(true, false, VpnReadiness.NEEDS_CONSENT))
        assertEquals(false, canRequestVpnConsent(true, true, null))
    }
}
