package io.betternet.next

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** No Android VPN, socket or external network is opened. */
class RestrictedTestTunPlanTest {
    private fun ip(value: String) = InetAddress.getByName(value)

    @Test fun ipv4AndIpv6HaveOnlyExactHostRoutesAndExplicitDns() {
        for ((client, dns, destination, prefix) in listOf(
            listOf("198.18.0.2", "198.18.0.1", "203.0.113.42", "32"),
            listOf("fd00::2", "fd00::1", "2001:db8::42", "128"),
        )) {
            val events = mutableListOf<String>()
            applyRestrictedTestTunPlan(
                RestrictedTestTunPlan(ip(client), ip(dns), ip(destination), 1280),
                { address, length -> events.add("address:${address.hostAddress}/$length") },
                { address, length -> events.add("route:${address.hostAddress}/$length") },
                { address -> events.add("dns:${address.hostAddress}") },
                { mtu -> events.add("mtu:$mtu") },
            )
            assertEquals(listOf(
                "address:${ip(client).hostAddress}/$prefix",
                "route:${ip(dns).hostAddress}/$prefix",
                "route:${ip(destination).hostAddress}/$prefix",
                "dns:${ip(dns).hostAddress}",
                "mtu:1280",
            ), events)
        }
    }

    @Test fun invalidPlansFailBeforeAnyBuilderMutation() {
        val valid = listOf(ip("198.18.0.2"), ip("198.18.0.1"), ip("203.0.113.42"))
        val invalid = listOf(
            Triple(valid[0], valid[0], valid[2]),
            Triple(valid[0], valid[1], valid[1]),
            Triple(valid[0], ip("fd00::1"), valid[2]),
            Triple(valid[0], ip("0.0.0.0"), valid[2]),
            Triple(valid[0], valid[1], ip("127.0.0.1")),
            Triple(valid[0], valid[1], ip("224.0.0.1")),
        )
        for ((client, dns, destination) in invalid) {
            try {
                RestrictedTestTunPlan(client, dns, destination, 1280)
                fail("Invalid plan accepted")
            } catch (_: IllegalArgumentException) { }
        }
        for (mtu in listOf(0, 1279, 9001)) {
            try {
                RestrictedTestTunPlan(valid[0], valid[1], valid[2], mtu)
                fail("Invalid MTU accepted")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
