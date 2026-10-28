package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class SelectedAppVpnServiceTest {
    @Test fun acceptsOneExplicitOtherPackage() {
        assertEquals("com.example.browser", requireSelectedPackage("com.example.browser", "io.betternet.next"))
    }

    @Test fun refusesMissingSelectionRatherThanDefaultingToWholeDevice() {
        for (value in listOf(null, "", "  ", "\n")) {
            assertRejected(value)
        }
    }

    @Test fun refusesOwnPackageToAvoidRecursiveRouting() {
        assertRejected("io.betternet.next")
    }

    @Test fun refusesWhitespacePaddedPackage() {
        assertRejected(" com.example.browser")
        assertRejected("com.example.browser ")
    }

    @Test fun addsExactlyOneAppAndNeverAddsSelf() {
        val allowed = mutableListOf<String>()
        addOnlySelectedApplication("com.example.browser", "io.betternet.next", { allowed.add(it); Unit })
        assertEquals(listOf("com.example.browser"), allowed)
    }

    @Test fun invalidScopeNeverTouchesBuilder() {
        val allowed = mutableListOf<String>()
        try {
            addOnlySelectedApplication(null, "io.betternet.next", { allowed.add(it); Unit })
            fail("Missing selection must fail")
        } catch (_: IllegalArgumentException) {
            assertEquals(emptyList<String>(), allowed)
        }
    }

    @Test fun missingInstalledPackageErrorMustPropagate() {
        val failure = IllegalStateException("package no longer installed")
        try {
            addOnlySelectedApplication("com.example.gone", "io.betternet.next") { throw failure }
            fail("Package lookup failure must abort")
        } catch (caught: IllegalStateException) {
            assertEquals(failure, caught)
        }
    }

    private fun assertRejected(packageName: String?) {
        try {
            requireSelectedPackage(packageName, "io.betternet.next")
            fail("Expected invalid selection to be rejected: $packageName")
        } catch (_: IllegalArgumentException) {
            // Fail closed, never silently widen to an unscoped VPN.
        }
    }
}
