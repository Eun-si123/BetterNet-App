package io.betternet.next

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.Socket

/**
 * An explicitly user-triggered, credential-free gateway TLS handshake.
 * No VPN is started, no CONNECT/HTTP bytes are sent, and no TUN is touched.
 * This is NOT selected-app Internet forwarding or proof of A1.
 */
internal fun probeGatewayTlsWithoutVpn(
    manager: ConnectivityManager,
    network: Network,
    packages: PackageManager,
    ownPackage: String,
    selectedApp: AppChoice,
    gatewayName: String,
    gatewayPort: Int,
    stillAuthorized: () -> Boolean,
) {
    require(isValidGatewayName(gatewayName) && gatewayPort in 1..65535)
    val verify = {
        check(stillAuthorized()) { "Gateway probe authorization was withdrawn" }
        val pinned = requireSelectedPackage(selectedApp.packageName, ownPackage)
        requirePinnedSelectedApp(selectedApp, ownPackage,
            readInstalledAppIdentity(packages, pinned))
        val networks = manager.allNetworks
        val caps = networks.map { manager.getNetworkCapabilities(it) }
        val underlying = caps.getOrNull(networks.indexOf(network))
        requireReadOnlyGatewayProbeScope(
            manager.activeNetwork == network && networks.contains(network),
            caps.all { it != null },
            caps.any { it?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true },
            underlying?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true,
        )
    }
    verify()
    val address = resolveGatewayAddress(gatewayName, gatewayPort) { host ->
        verify()
        network.getAllByName(host).also { verify() }
    }
    // Only one address is attempted. Never fall back to Android's default
    // resolver or network if the pinned network becomes unavailable.
    withFreshRestrictedGatewaySocketScope(verify) {
        val socket = Socket()
        try {
            verify()
            network.bindSocket(socket)
            verify()
            socket.connect(address, 3_000)
            verify()
            establishVerifiedGatewayTls(socket, address, gatewayName, handshakeTimeoutMs = 3_000)
        } catch (failure: Throwable) {
            try { socket.close() } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
    }.use { /* TLS handshake only: do not send a credential or request. */ }
}

/** Reject a stale/default VPN route even if a previously chosen Network remains visible. */
internal fun requireReadOnlyGatewayProbeScope(
    pinnedDefaultNetwork: Boolean,
    allNetworksObservable: Boolean,
    anotherVpnVisible: Boolean,
    underlyingInternetCapable: Boolean,
) {
    check(pinnedDefaultNetwork && allNetworksObservable &&
        !anotherVpnVisible && underlyingInternetCapable) {
        "Gateway probe requires the same observable non-VPN Internet network"
    }
}
