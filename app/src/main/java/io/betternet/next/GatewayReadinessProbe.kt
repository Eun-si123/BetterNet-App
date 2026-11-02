package io.betternet.next

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress

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
    val verify = readOnlyGatewayProbeVerifier(
        manager, network, packages, ownPackage, selectedApp, stillAuthorized
    )
    probePinnedGatewayTls(gatewayName, gatewayPort, verify,
        lookup = { host -> network.getAllByName(host) },
        dial = { address, remaining ->
            // This is a VPN-free, read-only probe. No VpnService exists to
            // protect a socket; instead pin it to the inspected Network and
            // reject any changed/hidden VPN state before and after each step.
            // Reuse the TCP-only failure tags so an unreachable first IPv6/IPv4
            // address can fall back without retrying TLS identity failures.
            val attemptDeadline = System.nanoTime() + remaining.toLong() * 1_000_000L
            val socket = connectProtectedSocket(address, remaining,
                protect = { verify(); true },
                bind = { raw -> verify(); network.bindSocket(raw); verify() })
            try {
                verify()
                // TCP and TLS share the remaining per-attempt deadline; a
                // slow TCP connect must not earn a fresh full TLS timeout.
                establishVerifiedGatewayTls(socket, address, gatewayName,
                    handshakeTimeoutMs = remainingResponseTimeoutMs(
                        attemptDeadline, System.nanoTime()))
            } catch (failure: Throwable) {
                try { socket.close() } catch (cleanup: Throwable) {
                    if (cleanup !== failure) failure.addSuppressed(cleanup)
                }
                throw failure
            }
        })
}

/**
 * Bounded dual-stack readiness check: only TCP-connect failures permit a
 * different DNS address. TLS identity, network authorization, binding and
 * cancellation failures are terminal; no token or HTTP bytes are sent.
 * Injected operations let JVM tests verify this without Android or a network.
 */
internal fun probePinnedGatewayTls(
    gatewayName: String,
    gatewayPort: Int,
    verify: () -> Unit,
    lookup: (String) -> Array<InetAddress>,
    dial: (InetSocketAddress, Int) -> Closeable,
) {
    verify()
    connectWithGatewayAddressFallback(
        gatewayName, gatewayPort, 3_000,
        lookup = { host -> withFreshRestrictedGatewayScope(verify) { lookup(host) } },
        dial = { address, remaining ->
            withFreshRestrictedGatewaySocketScope(verify) { dial(address, remaining) }
        },
    ).use { verify() }
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


/** Shared single-app, observable non-VPN gate for explicitly confirmed probes.
 * This gate must be checked around each potentially blocking network operation.
 */
internal fun readOnlyGatewayProbeVerifier(
    manager: ConnectivityManager,
    network: Network,
    packages: PackageManager,
    ownPackage: String,
    selectedApp: AppChoice,
    stillAuthorized: () -> Boolean,
): () -> Unit = {
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
