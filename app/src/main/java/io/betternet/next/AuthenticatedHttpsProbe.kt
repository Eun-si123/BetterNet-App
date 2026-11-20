package io.betternet.next

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets

/**
 * One explicitly confirmed HTTPS HEAD request through an authenticated TLS
 * gateway, without starting a VPN or capturing another app's traffic.
 * CONNECT uses the user-approved numeric public IP, never gateway-side DNS.
 * This is a gateway-path diagnostic, NOT selected-app A1 forwarding.
 */
internal fun probeApprovedHttpsThroughGatewayWithoutVpn(
    manager: ConnectivityManager,
    network: Network,
    packages: PackageManager,
    ownPackage: String,
    selectedApp: AppChoice,
    configuration: RestrictedTestConfiguration,
    stillAuthorized: () -> Boolean,
): Int {
    val verify = readOnlyGatewayProbeVerifier(
        manager, network, packages, ownPackage, selectedApp, stillAuthorized
    )
    verify()
    return connectWithGatewayAddressFallback(
        configuration.gatewayName, configuration.gatewayPort, 3_000,
        lookup = { host -> withFreshRestrictedGatewayScope(verify) { network.getAllByName(host) } },
        dial = { address: InetSocketAddress, remaining: Int ->
            withFreshRestrictedGatewaySocketScope(verify) {
                // No VPN is active in this diagnostic. Pin the raw socket to
                // the inspected non-VPN Network; reject any visible VPN.
                val tunnel = connectAuthenticatedPinnedIpTestTunnel(
                    address, configuration.gatewayName, remaining,
                    protect = { verify(); true },
                    destinationIp = configuration.approvedAddress,
                    destinationPort = 443,
                    bearerToken = configuration.bearerToken,
                    bind = { socket -> verify(); network.bindSocket(socket); verify() },
                )
                establishVerifiedDestinationTlsOnTunnel(
                    tunnel, configuration.approvedHost, 443, remaining
                )
            }
        },
    ).use { https ->
        verify()
        readBoundedHttpsHeadStatus(
            configuration.approvedHost, https.inputStream, https.outputStream,
            verify = verify, setReadTimeout = { https.soTimeout = it },
        ).also { verify() }
    }
}

/** Read only the first HTTPS response line; no body, cookies or redirects.
 * A 4xx/5xx is a real authenticated response, not a successful web request.
 * Both response size and total read time are bounded to prevent slow peers.
 */
internal fun readBoundedHttpsHeadStatus(
    hostname: String,
    input: InputStream,
    output: OutputStream,
    verify: () -> Unit,
    setReadTimeout: (Int) -> Unit,
    timeoutMs: Int = 3_000,
    nowNanos: () -> Long = System::nanoTime,
): Int {
    require(isValidGatewayName(hostname)) { "Invalid HTTPS test hostname" }
    require(timeoutMs in 1..10_000) { "HTTPS test timeout must be bounded" }
    verify()
    val deadline = nowNanos() + timeoutMs * 1_000_000L
    val request = "HEAD / HTTP/1.1\r\nHost: $hostname\r\nConnection: close\r\n\r\n"
    output.write(request.toByteArray(StandardCharsets.US_ASCII))
    output.flush()
    val line = StringBuilder()
    while (line.length < 128) {
        verify()
        setReadTimeout(remainingResponseTimeoutMs(deadline, nowNanos()))
        val next = input.read()
        if (next < 0) throw IOException("HTTPS peer closed before status")
        if (next == 10) {
            if (line.isEmpty() || line.last() != '\r') throw IOException("Invalid HTTPS status terminator")
            // 1xx is interim, not proof that the origin returned a final response.
            val statusLine = line.dropLast(1).toString()
            val match = Regex("HTTP/1\\.[01] ([2-5][0-9]{2})(?: [ -~]*)?").matchEntire(statusLine)
                ?: throw IOException("Invalid HTTPS status")
            verify()
            return match.groupValues[1].toInt()
        }
        if (next != 13 && next !in 32..126) throw IOException("Invalid HTTPS status byte")
        line.append(next.toChar())
    }
    throw IOException("HTTPS status line exceeds limit")
}
