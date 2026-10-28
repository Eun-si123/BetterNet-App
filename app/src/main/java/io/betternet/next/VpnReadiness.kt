package io.betternet.next

/** Read-only UI assessment; never implies an established or safe tunnel. */
internal enum class VpnReadiness { NO_APP, VPN_ACTIVE, NETWORK_UNAVAILABLE, NEEDS_CONSENT, PREPARED }

internal fun vpnReadiness(
    selected: Boolean,
    visibleVpn: Boolean,
    defaultNetworkAvailable: Boolean,
    allVisibleNetworksObservable: Boolean,
    prepared: Boolean,
): VpnReadiness = when {
    !selected -> VpnReadiness.NO_APP
    visibleVpn -> VpnReadiness.VPN_ACTIVE
    !defaultNetworkAvailable || !allVisibleNetworksObservable -> VpnReadiness.NETWORK_UNAVAILABLE
    prepared -> VpnReadiness.PREPARED
    else -> VpnReadiness.NEEDS_CONSENT
}
