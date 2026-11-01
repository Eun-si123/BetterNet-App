package io.betternet.next

import java.net.InetAddress

/**
 * User-entered, memory-only configuration for a future single-app A1 test.
 * Construction does not resolve a hostname, dial a socket, request VPN consent,
 * establish a TUN, or persist a credential. Never log this object.
 */
internal class RestrictedTestConfiguration(
    val gatewayName: String,
    val gatewayPort: Int,
    val dnsServerName: String,
    val approvedHost: String,
    numericApprovedIp: String,
    val bearerToken: String,
) {
    val approvedAddress: InetAddress = parseNumericApprovedAddress(numericApprovedIp)

    init {
        require(isValidGatewayName(gatewayName)) { "Invalid gateway name" }
        require(gatewayPort in 1..65535) { "Invalid gateway port" }
        require(isValidGatewayName(dnsServerName)) { "Invalid DNS server name" }
        require(isValidGatewayName(approvedHost)) { "Invalid destination name" }
        require(bearerToken.length in 16..256 && bearerToken.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
        }) { "Invalid gateway credential" }
        // An owner-approved public test destination must not be an accidental
        // private-network proxy. The gateway enforces its own allowlist too.
        require(!approvedAddress.isAnyLocalAddress && !approvedAddress.isLoopbackAddress &&
            !approvedAddress.isLinkLocalAddress && !approvedAddress.isMulticastAddress &&
            !approvedAddress.isSiteLocalAddress &&
            !(approvedAddress.address.size == 16 &&
                (approvedAddress.address[0].toInt() and 0xfe) == 0xfc)
        ) { "A non-local test destination is required" }
        // Validate against the exact TUN addresses before accepting the config.
        newTunPlan()
    }

    fun newTunPlan(): RestrictedTestTunPlan {
        // Documentation/benchmark addresses are only virtual local TUN endpoints.
        // They are not relay addresses and are never sent to the gateway.
        val ipv6 = approvedAddress.address.size == 16
        val client = if (ipv6) byteArrayOf(
            0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        ) else byteArrayOf(198.toByte(), 18, 0, 2)
        val dns = client.copyOf().apply { this[lastIndex] = 1 }
        return RestrictedTestTunPlan(
            InetAddress.getByAddress(client), InetAddress.getByAddress(dns),
            approvedAddress, 1280
        )
    }

    // A credential must never appear in crash logs or accidental UI interpolation.
    override fun toString(): String =
        "RestrictedTestConfiguration(gateway=$gatewayName:$gatewayPort, " +
            "destination=$approvedHost, credential=[redacted])"
}

/** Only numeric IPv4/IPv6 literals are accepted; no DNS lookup for an IP allowlist. */
private fun parseNumericApprovedAddress(value: String): InetAddress {
    require(value.isNotEmpty() && value == value.trim() && '%' !in value) {
        "A numeric destination IP is required"
    }
    if (':' in value) {
        require(value.all { it in '0'..'9' || it in 'a'..'f' ||
            it in 'A'..'F' || it == ':' || it == '.' }) { "Invalid IPv6 literal" }
        return try {
            InetAddress.getByName(value).also { require(it.address.size == 16) }
        } catch (_: java.net.UnknownHostException) {
            throw IllegalArgumentException("Invalid IPv6 literal")
        }
    }
    val parts = value.split('.')
    require(parts.size == 4 && parts.all {
        it.length in 1..3 && it.all(Char::isDigit) &&
            (it.length == 1 || it[0] != '0') && (it.toIntOrNull()?.let { number -> number in 0..255 } == true)
    }) { "Invalid IPv4 literal" }
    return InetAddress.getByAddress(parts.map { it.toInt().toByte() }.toByteArray())
}
