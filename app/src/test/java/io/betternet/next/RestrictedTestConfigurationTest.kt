package io.betternet.next

import org.junit.Assert.*
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
