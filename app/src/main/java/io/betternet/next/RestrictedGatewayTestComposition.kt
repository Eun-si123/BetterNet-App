package io.betternet.next

import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLSocketFactory

/**
 * Dormant A1 composition of the already restricted DNS and TCP gateways.
 * The owner must independently approve every name/IP, supply DNS lookup and
 * socket binding on one non-VPN underlying Network, protect each socket, and
 * obtain OS consent before ever attaching this dispatcher to a real TUN.
 * Construction does not resolve a name, open a socket or activate a VPN.
 */
internal fun newDormantRestrictedGatewayDispatcher(
    plan: RestrictedTestTunPlan,
    gatewayName: String,
    gatewayPort: Int,
    dnsServerName: String,
    approvedHost: String,
    bearerToken: String,
    timeoutMs: Int,
    lookupOnUnderlyingNetwork: (String) -> Array<InetAddress>,
    protect: (Socket) -> Boolean,
    bindToUnderlyingNetwork: (Socket) -> Unit,
    elapsedRealtimeMillis: () -> Long,
    nextServerIsn: () -> Long = { SecureRandom().nextInt().toLong() and 0xffff_ffffL },
    gatewayTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    dnsTlsFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
): RestrictedTestTunDispatcher {
    // Configuration is an owner-approved test allowlist, not derived from DNS.
    require(isValidGatewayName(gatewayName) && gatewayPort in 1..65535)
    require(isValidGatewayName(dnsServerName) && isValidGatewayName(approvedHost))
    require(timeoutMs in 1..10_000)
    require(bearerToken.length in 16..256 && bearerToken.all {
        it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
    })
    val pending = PendingDnsReplies(maxPending = 1)
    return RestrictedTestTunDispatcher(plan,
        exchangeDns = { packet, output ->
            // No DNS lookup or credential use for an unrelated question.
            if (!isSupportedDnsTunQuery(packet)) null else {
                val header = parseTunPacketHeader(packet.bytes, packet.bytes.size)
                val question = header?.let {
                    packet.bytes.copyOfRange(it.transportOffset + 8, packet.bytes.size)
                }
                if (question == null || !isApprovedTestDnsQuestion(
                        question, approvedHost, plan.allowedHttpsAddress
                    )) null
                else connectWithGatewayAddressFallback(
                    gatewayName, gatewayPort, timeoutMs, lookupOnUnderlyingNetwork,
                    dial = { address, remaining ->
                        exchangeOneTunDnsQueryThroughGatewayAndBindTestDestination(
                            address, gatewayName, dnsServerName, bearerToken, remaining,
                            protect, packet, pending, output, plan.mtu,
                            approvedHost, plan.allowedHttpsAddress,
                            gatewayTlsFactory, dnsTlsFactory, bindToUnderlyingNetwork,
                            elapsedRealtimeMillis,
                        )
                    },
                )
            }
        },
        connectTcp = { binding, syn, output, now ->
            // A forged/stale SYN must not even resolve the gateway hostname.
            require(binding.allows(syn, now) && buildTcpSynAck(syn, 0L, plan.mtu) != null) {
                "A fresh DNS-authorized SYN is required"
            }
            val serverIsn = nextServerIsn()
            require(serverIsn in 0..0xffff_ffffL)
            connectWithGatewayAddressFallback(
                gatewayName, gatewayPort, timeoutMs, lookupOnUnderlyingNetwork,
                dial = { address, remaining ->
                    connectDnsBoundTestTcpBridge(
                        binding, syn, now, output, address, gatewayName,
                        bearerToken, remaining, plan.mtu, serverIsn,
                        protect, gatewayTlsFactory, bindToUnderlyingNetwork,
                    )
                },
            )
        },
    )
}
