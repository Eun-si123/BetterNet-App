package io.betternet.next

import org.junit.Assert.*
import java.net.InetAddress
import org.junit.Test

class RestrictedTestConfigurationTest {
    private fun config(ip: String = "8.8.8.8", token: String = "abcdefghijklmnop") =
        RestrictedTestConfiguration("gateway.example", 443, "dns.example",
            "test.example", ip, token)

    @Test fun publicIpv4ConfigurationBuildsOnlyTwoHostRoutes() {
        val plan = config().newTunPlan()
        assertEquals(4, plan.clientAddress.address.size)
        assertEquals("8.8.8.8", plan.allowedHttpsAddress.hostAddress)
        assertEquals(1280, plan.mtu)
        assertNotEquals(plan.clientAddress, plan.virtualDnsAddress)
    }

    @Test fun publicIpv6ConfigurationKeepsOneFamily() {
        val plan = config("2606:4700:4700::1111").newTunPlan()
        assertEquals(16, plan.clientAddress.address.size)
        assertEquals(16, plan.virtualDnsAddress.address.size)
        assertEquals(16, plan.allowedHttpsAddress.address.size)
    }

    @Test fun neverAcceptsDnsNamesOrAmbiguousNumericAddressesAsPinnedIps() {
        for (ip in listOf("example.com", "8.8.8", "008.8.8.8",
            "8.8.8.999", "fe80::1%wlan0", "2001:db8::zz")) {
            assertThrows(IllegalArgumentException::class.java) { config(ip) }
        }
    }

    @Test fun privateAndLocalTargetsCannotBecomeGatewayAllowlist() {
        for (ip in listOf("127.0.0.1", "10.0.0.1", "192.168.1.1",
            "169.254.1.1", "::1", "fc00::1", "fe80::1", "ff02::1")) {
            assertThrows(IllegalArgumentException::class.java) { config(ip) }
        }
    }

    @Test fun sharedAndReservedDestinationsCannotBeApprovedAsPublicInternet() {
        // These are not ordinary public Internet destinations even though
        // InetAddress.isSiteLocalAddress may return false for them.
        for (ip in listOf("0.0.0.1", "100.64.0.1", "100.127.255.254",
            "192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1",
            "198.19.255.254", "198.51.100.7", "203.0.113.10",
            "240.0.0.1", "255.255.255.255", "2001:db8::1",
            "2002:c0a8:101::1", "2001:0::1")) {
            assertThrows("Unexpectedly approved $ip", IllegalArgumentException::class.java) {
                config(ip)
            }
        }
    }

    @Test fun ordinaryPublicIpv4AndIpv6DestinationsRemainAvailable() {
        for (ip in listOf("1.1.1.1", "8.8.8.8", "2001:4860:4860::8888",
            "2606:4700:4700::1111")) {
            assertEquals(InetAddress.getByName(ip), config(ip).approvedAddress)
        }
    }

    @Test fun rejectsInvalidGatewayAndCredentialsWithoutNetwork() {
        assertThrows(IllegalArgumentException::class.java) {
            RestrictedTestConfiguration("bad\r\n", 443, "dns.example",
                "test.example", "8.8.8.8", "abcdefghijklmnop")
        }
        assertThrows(IllegalArgumentException::class.java) { config(token = "short") }
        assertThrows(IllegalArgumentException::class.java) { config(token = "abcdefghijklmnop\r\n") }
    }

    @Test fun debugDescriptionNeverIncludesSecret() {
        val token = "SuperSecretToken_123"
        val description = config(token = token).toString()
        assertFalse(description.contains(token))
        assertTrue(description.contains("[redacted]"))
    }
}
