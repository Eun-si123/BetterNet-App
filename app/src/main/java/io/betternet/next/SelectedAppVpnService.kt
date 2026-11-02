package io.betternet.next

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileInputStream
import java.io.FileOutputStream
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.InetAddress
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

/**
 * A deliberately inactive A1 boundary. No code starts this service, asks for
 * consent, establishes a TUN, or forwards packets until a safe gateway exists.
 */
class SelectedAppVpnService : VpnService() {
    private val tunLifecycle = RestrictedTunLifecycle()

    override fun onRevoke() {
        // Even if closing the TUN descriptor fails, Android's revocation
        // callback must still run; otherwise the service can remain alive.
        try {
            tunLifecycle.cancel()
        } finally {
            super.onRevoke()
        }
    }

    override fun onDestroy() {
        try {
            tunLifecycle.cancel()
        } finally {
            super.onDestroy()
        }
    }

    /** Future activation must use this scoped builder, never an unscoped fallback. */
    internal fun newSelectedAppBuilder(selectedApp: AppChoice?): Builder {
        // The Activity's earlier consent check is not an activation grant.
        // Re-read UID and current APK signers before creating any builder.
        val pkg = requireSelectedPackage(selectedApp?.packageName, packageName)
        val allowed = requirePinnedSelectedApp(selectedApp, packageName,
            readInstalledAppIdentity(packageManager, pkg))
        return Builder().apply { addAllowedApplication(allowed) }
    }

    /**
     * Dormant test-only TUN configuration: one selected app and only two
     * single-host routes (approved HTTPS destination + virtual DNS endpoint).
     * This does not establish a TUN or request Android VPN consent.
     */
    internal fun newRestrictedTestTunBuilder(
        selectedApp: AppChoice?, configuration: RestrictedTestConfiguration,
    ): Builder {
        val builder = newSelectedAppBuilder(selectedApp)
        // Derive routes from the validated, owner-approved configuration; a
        // caller must not substitute an unrelated destination-only plan.
        applyRestrictedTestTunPlan(configuration.newTunPlan(),
            addAddress = { address, prefix -> builder.addAddress(address, prefix); Unit },
            addRoute = { address, prefix -> builder.addRoute(address, prefix); Unit },
            addDnsServer = { address -> builder.addDnsServer(address); Unit },
            setMtu = { mtu -> builder.setMtu(mtu); Unit },
        )
        return builder
    }

    /**
     * Dormant A1 activation preflight. Assemble the exact single-app builder
     * and protected-network dispatcher together, but NEVER establish the TUN,
     * start a worker, or connect to the gateway. The eventual activation path
     * must repeat these checks immediately before Builder.establish(): Android
     * consent, package identity and networks can all change after this call.
     */
    internal fun prepareDormantRestrictedTestActivation(
        manager: ConnectivityManager,
        underlyingNetwork: Network,
        selectedApp: AppChoice?,
        configuration: RestrictedTestConfiguration,
        timeoutMs: Int,
    ): DormantRestrictedTestActivation {
        // Validate app identity and exact host routes before any OS consent
        // inspection. This builder has no side effects until establish().
        val builder = newRestrictedTestTunBuilder(selectedApp, configuration)
        requireFreshRestrictedTestPrerequisites(manager, underlyingNetwork, selectedApp)
        val dispatcher = newUnderlyingNetworkRestrictedTestDispatcher(
            manager, underlyingNetwork, selectedApp, configuration, timeoutMs,
        )
        return DormantRestrictedTestActivation(builder, dispatcher)
    }

    /**
     * Dormant activation boundary, deliberately NOT called by the Activity or
     * onStartCommand. A future user-confirmed service start may invoke this only
     * after explicit OS consent and foreground-service/lifecycle review.
     * No background, implicit, or whole-device activation path is provided.
     * A worker returned here still needs a background owner to monitor failure,
     * stop/join on shutdown, and handle Android network/permission changes.
     */
    internal fun activateExplicitRestrictedTestTun(
        manager: ConnectivityManager,
        underlyingNetwork: Network,
        selectedApp: AppChoice?,
        configuration: RestrictedTestConfiguration,
        timeoutMs: Int,
    ): RestrictedTunWorker {
        val prepared = prepareDormantRestrictedTestActivation(
            manager, underlyingNetwork, selectedApp, configuration, timeoutMs,
        )
        return establishRestrictedTunTransaction(
            revalidate = {
                requireFreshRestrictedTestPrerequisites(manager, underlyingNetwork, selectedApp)
            },
            establish = { prepared.builder.establish() },
            attach = { descriptor -> newRestrictedTunWorker(
                descriptor, prepared.dispatcher, manager, underlyingNetwork, selectedApp) },
            start = { worker -> worker.start() },
            rollback = {
                // Never close a possibly running worker's dispatcher from a
                // second thread. Before start, it owns no network resources;
                // after start, cancellation lets the owner close it.
                tunLifecycle.cancel()
            },
        )
    }

    /**
     * Check the active TUN owner and scope at each sensitive gateway boundary,
     * not only at the start of a potentially blocking TUN pump cycle. The
     * established VPN is visible in allNetworks, so only the explicit
     * underlying Network is checked here (no pre-activation other-VPN gate).
     */
    private fun requireActiveRestrictedTestPrerequisites(
        manager: ConnectivityManager, network: Network, selectedApp: AppChoice?,
    ) {
        tunLifecycle.requireNotCancelled()
        val pkg = requireSelectedPackage(selectedApp?.packageName, packageName)
        requirePinnedSelectedApp(selectedApp, packageName,
            readInstalledAppIdentity(packageManager, pkg))
        check(VpnService.prepare(this) == null) { "VPN permission was revoked" }
        requireUnderlyingInternetNetwork(manager, network)
    }

    /** Mutable consent, app identity and network capabilities are never cached. */
    private fun requireFreshRestrictedTestPrerequisites(
        manager: ConnectivityManager, underlyingNetwork: Network, selectedApp: AppChoice?,
    ) {
        val pkg = requireSelectedPackage(selectedApp?.packageName, packageName)
        requirePinnedSelectedApp(selectedApp, packageName,
            readInstalledAppIdentity(packageManager, pkg))
        val networks = manager.allNetworks
        val capabilities = networks.map { manager.getNetworkCapabilities(it) }
        val underlyingIndex = networks.indexOf(underlyingNetwork)
        val underlying = capabilities.getOrNull(underlyingIndex)
        requireDormantActivationPreflight(
            underlyingIndex >= 0,
            capabilities.all { it != null },
            capabilities.any { it?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true },
            underlying?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true,
            underlying?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true,
            VpnService.prepare(this) == null,
        )
    }

    /**
     * Dormant adapter for a future explicitly consented, established TUN.
     * Does NOT call Builder.establish(), request consent or start the service.
     * The session exclusively owns the supplied descriptor and its shared fd.
     * A caller must serialize packet/gateway pumps and enforce cancellation.
     */
    internal fun ownEstablishedRestrictedTestTun(
        descriptor: ParcelFileDescriptor,
        dispatcher: RestrictedTestTunDispatcher,
    ): RestrictedTunSession = RestrictedTunSession(
        dispatcher,
        FileInputStream(descriptor.fileDescriptor),
        FileOutputStream(descriptor.fileDescriptor),
        closeDescriptor = { descriptor.close() },
        waitForReadable = { pollRestrictedTunReadable(descriptor) },
    )

    /**
     * Construct, but do not start, the single-owner TUN worker. Only a future
     * explicit-consent service path may call start() after establishing a
     * restricted TUN and validating its protected authenticated gateway.
     */
    internal fun newRestrictedTunWorker(
        descriptor: ParcelFileDescriptor,
        dispatcher: RestrictedTestTunDispatcher,
        manager: ConnectivityManager,
        underlyingNetwork: Network,
        selectedApp: AppChoice?,
    ): RestrictedTunWorker = tunLifecycle.adopt(RestrictedTunWorker(
        RestrictedTunPump(
            ownEstablishedRestrictedTestTun(descriptor, dispatcher),
            revalidate = {
                // The established VPN itself is now visible in allNetworks,
                // so do NOT reuse the pre-activation other-VPN rejection here.
                requireActiveRestrictedTestPrerequisites(manager, underlyingNetwork, selectedApp)
            },
            nowMillis = SystemClock::elapsedRealtime,
        ),
        onTerminated = {
            // Even an unexpected pump failure must not leave a future
            // foreground service running without an owned TUN. The callback
            // runs after owner-thread cleanup and never joins its own thread.
            stopSelf()
        },
    ))

    /** A future TLS gateway dial must protect its socket before connecting. */
    internal fun newProtectedGatewaySocket(address: InetSocketAddress, timeoutMs: Int): Socket =
        connectProtectedSocket(address, timeoutMs, { socket -> protect(socket) })

    /** Dormant TLS dial: protect before TCP connect; verify gateway certificate and name. */
    internal fun newVerifiedGatewaySocket(address: InetSocketAddress, serverName: String, timeoutMs: Int): SSLSocket =
        connectVerifiedGatewayTls(address, serverName, timeoutMs, { socket -> protect(socket) })

    /**
     * Dormant A1 path: DNS and socket binding use the SAME explicitly supplied
     * non-VPN underlying network. Never fall back to default DNS or routing.
     */
    internal fun newUnderlyingNetworkGatewaySocket(
        manager: ConnectivityManager, network: Network, hostname: String,
        port: Int, timeoutMs: Int,
    ): SSLSocket {
        return onUnderlyingNetworkGateway(manager, network, hostname, port, timeoutMs) { address, remaining ->
            connectVerifiedGatewayTls(
                address, hostname, remaining, { socket -> protect(socket) },
                bind = { socket -> network.bindSocket(socket) },
            )
        }
    }

    /** Same-network DNS, protection and binding for the authenticated test tunnel.
     * Still dormant: no caller, VPN activation or outbound connection in the app.
     */
    internal fun newUnderlyingNetworkAuthenticatedTestTunnel(
        manager: ConnectivityManager, network: Network, gatewayName: String,
        gatewayPort: Int, timeoutMs: Int, destinationHost: String,
        destinationPort: Int, bearerToken: String,
    ): SSLSocket {
        return onUnderlyingNetworkGateway(
            manager, network, gatewayName, gatewayPort, timeoutMs
        ) { address, remaining ->
            connectAuthenticatedTestTunnel(
                address, gatewayName, remaining, { socket -> protect(socket) },
                destinationHost, destinationPort, bearerToken,
                bind = { socket -> network.bindSocket(socket) },
            )
        }
    }

    /**
     * Dormant Android adapter for the approved DNS -> pinned-IP TCP dispatcher.
     * Unlike a generic resolver/socket callback, every operation is tied to
     * the same explicitly selected underlying Network. Recheck its capabilities
     * at each DNS lookup, socket protection and binding: an old network choice
     * must not silently become a VPN route after a connectivity change.
     *
     * Construction does not touch the network, establish a TUN, ask for VPN
     * consent, or start the service. The future activation owner must still
     * validate installed app scope via newRestrictedTestTunBuilder(), verify
     * OS consent, and own a cancellable established-TUN worker.
     */
    internal fun newUnderlyingNetworkRestrictedTestDispatcher(
        manager: ConnectivityManager,
        network: Network,
        selectedApp: AppChoice?,
        configuration: RestrictedTestConfiguration,
        timeoutMs: Int,
    ): RestrictedTestTunDispatcher {
        val pkg = requireSelectedPackage(selectedApp?.packageName, packageName)
        requirePinnedSelectedApp(selectedApp, packageName,
            readInstalledAppIdentity(packageManager, pkg))
        // Route, DNS grant and CONNECT authority must originate from one
        // validated configuration, not independently supplied arguments.
        return newDormantRestrictedGatewayDispatcher(
            configuration.newTunPlan(), configuration.gatewayName,
            configuration.gatewayPort, configuration.dnsServerName,
            configuration.approvedHost, configuration.bearerToken, timeoutMs,
            lookupOnUnderlyingNetwork = { host ->
                withFreshRestrictedGatewayScope(
                    { requireActiveRestrictedTestPrerequisites(manager, network, selectedApp) },
                    { network.getAllByName(host) },
                )
            },
            protect = { socket ->
                withFreshRestrictedGatewayScope(
                    { requireActiveRestrictedTestPrerequisites(manager, network, selectedApp) },
                    { protect(socket) },
                )
            },
            bindToUnderlyingNetwork = { socket ->
                withFreshRestrictedGatewayScope(
                    { requireActiveRestrictedTestPrerequisites(manager, network, selectedApp) },
                    { network.bindSocket(socket) },
                )
            },
            elapsedRealtimeMillis = SystemClock::elapsedRealtime,
        )
    }

    private fun requireUnderlyingInternetNetwork(manager: ConnectivityManager, network: Network) {
        val capabilities = manager.getNetworkCapabilities(network)
        requireNonVpnInternetCapabilities(
            capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true,
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true,
        )
    }

    private fun <T> onUnderlyingNetworkGateway(
        manager: ConnectivityManager, network: Network, hostname: String,
        port: Int, timeoutMs: Int, dial: (InetSocketAddress, Int) -> T,
    ): T {
        requireUnderlyingInternetNetwork(manager, network)
        // Revalidate at each DNS lookup and retry, not just at method entry.
        // Protection and binding remain mandatory in the dial callback.
        return connectWithGatewayAddressFallback(
            hostname, port, timeoutMs,
            { host ->
                requireUnderlyingInternetNetwork(manager, network)
                network.getAllByName(host)
            },
            { address, remaining ->
                requireUnderlyingInternetNetwork(manager, network)
                dial(address, remaining)
            },
        )
    }

    // Explicit starts are not an activation mechanism. A future authenticated
    // forwarding implementation must introduce a separately reviewed path.
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopSelf(startId)
        return START_NOT_STICKY
    }
}

/**
 * A DNS lookup, socket protection or binding call may block while Android
 * revokes VPN ownership or the selected package changes. Check on BOTH sides;
 * a revoked result must never be used for the next connect step.
 */
internal inline fun <T> withFreshRestrictedGatewayScope(
    verify: () -> Unit, operation: () -> T,
): T {
    verify()
    val result = operation()
    verify()
    return result
}

/** Preflight artifacts only: holding these does not authorize TUN establishment. */
internal class DormantRestrictedTestActivation(
    val builder: VpnService.Builder,
    val dispatcher: RestrictedTestTunDispatcher,
)

/** Fail closed on unknown networks, other VPNs, or missing OS permission. */
internal fun requireDormantActivationPreflight(
    underlyingPresent: Boolean,
    allNetworksObservable: Boolean,
    anyVisibleVpn: Boolean,
    underlyingHasInternet: Boolean,
    underlyingIsVpn: Boolean,
    osPrepared: Boolean,
) {
    check(underlyingPresent && allNetworksObservable && !anyVisibleVpn &&
        underlyingHasInternet && !underlyingIsVpn && osPrepared) {
        "Restricted VPN activation prerequisites are not satisfied"
    }
}

/**
 * Bound each idle TUN wait so the single owner can service gateway work and
 * observe lifecycle cancellation. Poll is not VPN activation. A real device
 * still needs cancellation/read races verified before enabling this adapter.
 */
private fun pollRestrictedTunReadable(descriptor: ParcelFileDescriptor): Boolean {
    val entry = StructPollfd().apply {
        fd = descriptor.fileDescriptor
        events = OsConstants.POLLIN.toShort()
    }
    val count = try {
        Os.poll(arrayOf(entry), 100)
    } catch (error: ErrnoException) {
        throw IOException("TUN readiness poll failed", error)
    }
    if (count == 0) return false
    val events = entry.revents.toInt()
    if (events and (OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL) != 0) {
        throw IOException("TUN descriptor is no longer readable")
    }
    return events and OsConstants.POLLIN != 0
}

/** Pure, fail-closed capability gate shared by all Android underlying-network paths. */
internal fun requireNonVpnInternetCapabilities(hasInternet: Boolean, isVpn: Boolean) {
    require(hasInternet && !isVpn) { "A non-VPN underlying Internet network is required" }
}

/** Reject missing, self, and malformed selections before touching a VPN builder. */
internal fun requireSelectedPackage(selectedPackage: String?, ownPackage: String): String {
    require(!selectedPackage.isNullOrBlank()) { "A selected app is required" }
    require(selectedPackage == selectedPackage.trim()) { "Invalid selected app" }
    require(selectedPackage != ownPackage) { "Cannot route BetterNet through itself" }
    return selectedPackage
}

/** Add exactly one app. Never recover from lookup failure with a broad route. */
internal fun addOnlySelectedApplication(
    selectedPackage: String?,
    ownPackage: String,
    addAllowedApplication: (String) -> Unit,
) {
    addAllowedApplication(requireSelectedPackage(selectedPackage, ownPackage))
}

/**
 * A dormant socket-recursion guard. Accept only an already resolved address:
 * name resolution must later use an explicitly chosen underlying Network.
 * This helper never performs TLS or starts a connection unless called.
 */
internal fun connectProtectedSocket(
    address: InetSocketAddress,
    timeoutMs: Int,
    protect: (Socket) -> Boolean,
    createSocket: () -> Socket = { Socket() },
    bind: (Socket) -> Unit = {},
): Socket {
    require(!address.isUnresolved) { "Gateway address must be resolved on the underlying network" }
    require(timeoutMs in 1..10_000) { "Gateway connect timeout must be bounded" }
    val socket = createSocket()
    try {
        check(protect(socket)) { "Gateway socket could not be excluded from the VPN" }
        bind(socket) // Binding failures close the socket, never use default routing.
        try {
            socket.connect(address, timeoutMs)
        } catch (failure: SocketTimeoutException) {
            // Only failures raised by the actual TCP connect are retryable.
            // The same exception types can occur later, after credentials
            // have been sent, and must never replay an authenticated CONNECT.
            throw GatewayTcpConnectTimeout(failure)
        } catch (failure: ConnectException) {
            throw GatewayTcpConnectFailure(failure)
        } catch (failure: NoRouteToHostException) {
            throw GatewayTcpConnectFailure(failure)
        }
        return socket
    } catch (failure: Throwable) {
        try {
            socket.close()
        } catch (closeFailure: Throwable) {
            failure.addSuppressed(closeFailure)
        }
        throw failure
    }
}

private class GatewayTcpConnectTimeout(cause: SocketTimeoutException) :
    SocketTimeoutException("Gateway TCP connect timed out") {
    init { initCause(cause) }
}

private class GatewayTcpConnectFailure(cause: IOException) :
    IOException("Gateway TCP connect failed", cause)

/** DNS must be performed by the chosen underlying Network, never system DNS. */
internal fun resolveGatewayAddress(
    hostname: String, port: Int, lookup: (String) -> Array<InetAddress>,
): InetSocketAddress = resolveGatewayAddresses(hostname, port, lookup).first()

private fun resolveGatewayAddresses(
    hostname: String, port: Int, lookup: (String) -> Array<InetAddress>,
): List<InetSocketAddress> {
    require(isValidGatewayName(hostname)) { "Invalid gateway DNS name" }
    require(port in 1..65535) { "Invalid gateway port" }
    // Preserve the resolver's first-family preference, but do not let four
    // unreachable AAAA (or A) records hide a usable address of the other
    // family behind the four-attempt limit. This is sequential fallback, not
    // parallel Happy Eyeballs; every attempt still uses the same Network.
    val unique = lookup(hostname).distinct()
    val firstFamily = unique.firstOrNull()?.address?.size
    val primary = unique.filter { it.address.size == firstFamily }.iterator()
    val secondary = unique.filter { it.address.size != firstFamily }.iterator()
    val addresses = mutableListOf<InetAddress>()
    while (addresses.size < 4 && (primary.hasNext() || secondary.hasNext())) {
        if (primary.hasNext()) addresses.add(primary.next())
        if (addresses.size < 4 && secondary.hasNext()) addresses.add(secondary.next())
    }
    require(addresses.isNotEmpty()) { "Underlying network returned no gateway addresses" }
    return addresses.map { InetSocketAddress(it, port) }
}

/**
 * One shared timeout across a bounded IPv6/IPv4 address list. Retry only
 * failures explicitly tagged at the TCP connect boundary; never retry a
 * TLS handshake/CONNECT error (even ConnectException), TLS identity failure,
 * failed protection or network binding.
 * The dial callback must close each failed socket before throwing.
 */
internal fun <T> connectWithGatewayAddressFallback(
    hostname: String, port: Int, timeoutMs: Int,
    lookup: (String) -> Array<InetAddress>,
    dial: (InetSocketAddress, Int) -> T,
    nowNanos: () -> Long = System::nanoTime,
): T {
    require(timeoutMs in 1..10_000) { "Gateway timeout must be bounded" }
    val deadline = nowNanos() + timeoutMs * 1_000_000L
    val addresses = resolveGatewayAddresses(hostname, port, lookup)
    var lastFailure: IOException? = null
    for (address in addresses) {
        val remaining = deadline - nowNanos()
        if (remaining <= 0L) break
        val attemptTimeout = ((remaining / 1_000_000L) +
            if (remaining % 1_000_000L == 0L) 0L else 1L).coerceIn(1L, 10_000L).toInt()
        try {
            return dial(address, attemptTimeout)
        } catch (failure: IOException) {
            if (failure !is GatewayTcpConnectFailure &&
                failure !is GatewayTcpConnectTimeout) throw failure
            lastFailure = failure
        }
    }
    throw lastFailure ?: SocketTimeoutException("Gateway address attempts exceeded deadline")
}

/**
 * A single-family, owner-approved test-only routing plan. This does NOT
 * authorize a destination by itself: the DNS/TCP gateway path must still
 * check its independent allowlist and authenticated transport.
 */
internal data class RestrictedTestTunPlan(
    val clientAddress: InetAddress,
    val virtualDnsAddress: InetAddress,
    val allowedHttpsAddress: InetAddress,
    val mtu: Int,
) {
    init {
        require(mtu in 1280..9000) { "Test TUN MTU must be bounded" }
        val addresses = listOf(clientAddress, virtualDnsAddress, allowedHttpsAddress)
        require(addresses.all { it.address.size == clientAddress.address.size }) {
            "Test TUN routes must use one IP family"
        }
        require(addresses.distinct().size == addresses.size) {
            "Test TUN addresses must be distinct"
        }
        require(addresses.none {
            it.isAnyLocalAddress || it.isLoopbackAddress ||
                it.isMulticastAddress || it.isLinkLocalAddress
        }) { "Invalid test TUN address" }
    }
}

/**
 * Isolated builder seam for exact-route regression tests. Never add a
 * default route (0/0), and ensure the DNS endpoint is actually routed into
 * the selected-app TUN rather than accidentally using underlying DNS.
 */
internal fun applyRestrictedTestTunPlan(
    plan: RestrictedTestTunPlan,
    addAddress: (InetAddress, Int) -> Unit,
    addRoute: (InetAddress, Int) -> Unit,
    addDnsServer: (InetAddress) -> Unit,
    setMtu: (Int) -> Unit,
) {
    val prefix = plan.clientAddress.address.size * 8
    addAddress(plan.clientAddress, prefix)
    addRoute(plan.virtualDnsAddress, prefix)
    addRoute(plan.allowedHttpsAddress, prefix)
    addDnsServer(plan.virtualDnsAddress)
    setMtu(plan.mtu)
}
