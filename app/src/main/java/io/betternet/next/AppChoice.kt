package io.betternet.next

import java.util.Locale

/** Only launcher-visible applications can be explicitly selected for future testing. */
internal data class AppChoice(val packageName: String, val label: String)

internal fun selectableApps(candidates: List<AppChoice>, ownPackage: String): List<AppChoice> =
    candidates.asSequence()
        .filter { it.packageName.isNotBlank() && it.packageName != ownPackage }
        .sortedWith(compareBy({ it.label.lowercase(Locale.ROOT) }, { it.packageName }))
        .distinctBy { it.packageName }
        .toList()
