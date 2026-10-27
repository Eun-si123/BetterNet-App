package io.betternet.next

/** Read-only UI assessment; never implies an established or safe tunnel. */
internal enum class VpnReadiness { NO_APP, VPN_ACTIVE, NEEDS_CONSENT, PREPARED }

internal fun vpnReadiness(selected: Boolean, activeVpn: Boolean, prepared: Boolean): VpnReadiness = when {
    !selected -> VpnReadiness.NO_APP
    activeVpn -> VpnReadiness.VPN_ACTIVE
    prepared -> VpnReadiness.PREPARED
    else -> VpnReadiness.NEEDS_CONSENT
}
