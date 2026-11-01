package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class AppChoiceTest {
    @Test fun selectionIdentityRejectsReinstalledOrMissingPackage() {
        val selected = AppChoice("com.example.browser", "Browser", 10001)
        assertEquals(true, selectedAppStillInstalled(selected, listOf(
            AppChoice("com.example.browser", "Localized browser", 10001))))
        assertEquals(false, selectedAppStillInstalled(selected, listOf(
            AppChoice("com.example.browser", "Replacement", 10002))))
        assertEquals(false, selectedAppStillInstalled(selected, listOf(
            AppChoice("com.example.mail", "Mail", 10001))))
        assertEquals(false, selectedAppStillInstalled(selected, emptyList()))
        assertEquals(false, selectedAppStillInstalled(
            AppChoice("com.example.browser", "Unknown", -1), listOf(selected)))
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
