package io.betternet.next

import java.util.Locale

/** Only launcher-visible applications can be explicitly selected for future testing. */
// The package name alone is not a durable identity: an uninstalled app can be
// replaced by a different package instance while the Activity is still alive.
// Capture the Android-assigned UID at selection time and recheck it before
// requesting device-level VPN permission. This is not a signature pin and a
// future VPN activation must independently revalidate its selected app.
internal data class AppChoice(val packageName: String, val label: String, val uid: Int)

internal fun selectedAppStillInstalled(selected: AppChoice, current: List<AppChoice>): Boolean =
    selected.uid > 0 && current.any {
        it.packageName == selected.packageName && it.uid == selected.uid
    }

internal fun selectableApps(candidates: List<AppChoice>, ownPackage: String): List<AppChoice> =
    candidates.asSequence()
        .filter { it.packageName.isNotBlank() && it.packageName != ownPackage && it.uid > 0 }
        .sortedWith(compareBy({ it.label.lowercase(Locale.ROOT) }, { it.packageName }, { it.label }))
        .distinctBy { it.packageName }
        .toList()
