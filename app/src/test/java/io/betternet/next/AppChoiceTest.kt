package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class AppChoiceTest {
    @Test fun removesOwnAppAndInvalidEntries() {
        val candidates = listOf(
            AppChoice("io.betternet.next", "BetterNet"),
            AppChoice("", "Invalid"),
            AppChoice("com.example.browser", "Browser"),
        )
        assertEquals(listOf(AppChoice("com.example.browser", "Browser")),
            selectableApps(candidates, "io.betternet.next"))
    }

    @Test fun collapsesMultipleLauncherActivitiesToOneApp() {
        val candidates = listOf(
            AppChoice("com.example.browser", "Browser shortcut"),
            AppChoice("com.example.browser", "Browser"),
            AppChoice("com.example.mail", "Mail"),
        )
        val choices = selectableApps(candidates, "io.betternet.next")
        assertEquals(2, choices.size)
        assertEquals(AppChoice("com.example.browser", "Browser"), choices.first())
    }

    @Test fun sortsWithoutDependingOnDeviceLocale() {
        val candidates = listOf(
            AppChoice("com.example.z", "zebra"),
            AppChoice("com.example.b", "Alpha"),
            AppChoice("com.example.a", "alpha"),
        )
        assertEquals(listOf("com.example.a", "com.example.b", "com.example.z"),
            selectableApps(candidates, "io.betternet.next").map { it.packageName })
    }
}
