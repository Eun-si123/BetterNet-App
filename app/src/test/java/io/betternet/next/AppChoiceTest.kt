package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class AppChoiceTest {
    @Test fun selectionIdentityRejectsReinstalledOrMissingPackage() {
        val selected = AppChoice("com.example.browser", "Browser", 10001, "signer-A")
        assertEquals(true, selectedAppStillInstalled(selected, listOf(
            AppChoice("com.example.browser", "Localized browser", 10001)), "signer-A"))
        assertEquals(false, selectedAppStillInstalled(selected, listOf(
            AppChoice("com.example.browser", "Replacement", 10002)), "signer-A"))
        assertEquals(false, selectedAppStillInstalled(selected, listOf(
            AppChoice("com.example.mail", "Mail", 10001)), "signer-A"))
        assertEquals(false, selectedAppStillInstalled(selected, emptyList(), "signer-A"))
        assertEquals(false, selectedAppStillInstalled(
            AppChoice("com.example.browser", "Unknown", -1, "signer-A"), listOf(selected), "signer-A"))
    }

    @Test fun signingIdentityMustStillMatchBeforeConsent() {
        val selected = AppChoice("com.example.browser", "Browser", 10001, "signer-A")
        val current = listOf(AppChoice("com.example.browser", "Browser", 10001))
        // Even if Android reuses a UID for a different signer, deny consent.
        assertEquals(false, selectedAppStillInstalled(selected, current, "signer-B"))
        assertEquals(false, selectedAppStillInstalled(selected, current, null))
        assertEquals(false, selectedAppStillInstalled(selected, current, ""))
        assertEquals(false, selectedAppStillInstalled(
            selected.copy(signerFingerprint = null), current, "signer-A"))
        assertEquals(false, selectedAppStillInstalled(
            selected.copy(signerFingerprint = ""), current, "signer-A"))
    }

    @Test fun signerSetFingerprintIsCanonicalAndRejectsUnknownSigners() {
        val first = "first signer".toByteArray()
        val second = "second signer".toByteArray()
        assertEquals(signerSetFingerprint(listOf(first, second)),
            signerSetFingerprint(listOf(second, first)))
        assertNotEquals(signerSetFingerprint(listOf(first)),
            signerSetFingerprint(listOf(second)))
        assertEquals(null, signerSetFingerprint(emptyList()))
        assertEquals(null, signerSetFingerprint(listOf(first, byteArrayOf())))
    }

    @Test fun invalidUidCannotBeSelected() {
        assertEquals(emptyList<AppChoice>(), selectableApps(listOf(
            AppChoice("com.example.browser", "Unknown", -1),
            AppChoice("com.example.mail", "System", 0),
        ), "io.betternet.next"))
    }

    @Test fun removesOwnAppAndInvalidEntries() {
        val candidates = listOf(
            AppChoice("io.betternet.next", "BetterNet", 10001),
            AppChoice("", "Invalid", 10001),
            AppChoice("com.example.browser", "Browser", 10001),
        )
        assertEquals(listOf(AppChoice("com.example.browser", "Browser", 10001)),
            selectableApps(candidates, "io.betternet.next"))
    }

    @Test fun collapsesMultipleLauncherActivitiesToOneApp() {
        val candidates = listOf(
            AppChoice("com.example.browser", "Browser shortcut", 10001),
            AppChoice("com.example.browser", "Browser", 10001),
            AppChoice("com.example.mail", "Mail", 10001),
        )
        val choices = selectableApps(candidates, "io.betternet.next")
        assertEquals(2, choices.size)
        assertEquals(AppChoice("com.example.browser", "Browser", 10001), choices.first())
    }

    @Test fun caseFoldedDuplicateLabelsAreStableAcrossQueryOrder() {
        val candidates = listOf(
            AppChoice("com.example.browser", "browser", 10001),
            AppChoice("com.example.browser", "Browser", 10001),
            AppChoice("com.example.mail", "Mail", 10001),
        )
        val forward = selectableApps(candidates, "io.betternet.next")
        val reversed = selectableApps(candidates.reversed(), "io.betternet.next")
        assertEquals(forward, reversed)
        assertEquals("Browser", forward.first().label)
    }

    @Test fun sortsWithoutDependingOnDeviceLocale() {
        val candidates = listOf(
            AppChoice("com.example.z", "zebra", 10001),
            AppChoice("com.example.b", "Alpha", 10001),
            AppChoice("com.example.a", "alpha", 10001),
        )
        assertEquals(listOf("com.example.a", "com.example.b", "com.example.z"),
            selectableApps(candidates, "io.betternet.next").map { it.packageName })
    }
}
