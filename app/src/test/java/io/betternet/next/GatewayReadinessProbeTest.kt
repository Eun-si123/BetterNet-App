package io.betternet.next

import org.junit.Assert.fail
import org.junit.Test

/** No network, credential, VPN permission or Android service in these tests. */
class GatewayReadinessProbeTest {
    @Test fun readOnlyProbeRequiresPinnedObservableNonVpnInternet() {
        requireReadOnlyGatewayProbeScope(true, true, false, true)
        for (invalid in listOf(
            listOf(false, true, false, true), // default network changed
            listOf(true, false, false, true), // network visibility incomplete
            listOf(true, true, true, true),  // another VPN appeared
            listOf(true, true, false, false), // no Internet capability
        )) {
            try {
                requireReadOnlyGatewayProbeScope(invalid[0], invalid[1], invalid[2], invalid[3])
                fail("Unsafe gateway probe scope must be rejected: $invalid")
            } catch (_: IllegalStateException) { }
        }
    }
}
