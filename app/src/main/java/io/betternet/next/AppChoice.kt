package io.betternet.next

import java.util.Locale
import java.security.MessageDigest
import java.util.Base64

/** Only launcher-visible applications can be explicitly selected for future testing. */
// The package name alone is not a durable identity: an uninstalled app can be
// replaced by a different package instance while the Activity is still alive.
// Pin both the UID and current APK signer set at selection time. Launcher
// candidates are deliberately unpinned until the user actually selects one.
// A future VPN activation must revalidate identity and OS consent again.
internal data class AppChoice(
    val packageName: String, val label: String, val uid: Int,
    val signerFingerprint: String? = null,
)

internal fun selectedAppStillInstalled(
    selected: AppChoice, current: List<AppChoice>, currentSignerFingerprint: String?,
): Boolean =
    selected.uid > 0 && !selected.signerFingerprint.isNullOrBlank() &&
        selected.signerFingerprint == currentSignerFingerprint && current.any {
            it.packageName == selected.packageName && it.uid == selected.uid
        }

internal fun selectableApps(candidates: List<AppChoice>, ownPackage: String): List<AppChoice> =
    candidates.asSequence()
        .filter { it.packageName.isNotBlank() && it.packageName != ownPackage && it.uid > 0 }
        .sortedWith(compareBy({ it.label.lowercase(Locale.ROOT) }, { it.packageName }, { it.label }))
        .distinctBy { it.packageName }
        .toList()

/** Canonical digest of the *current* signer set; ordering from PackageManager
 * is not an app identity. Reject missing/empty certificate data.
 */
internal fun signerSetFingerprint(signers: List<ByteArray>): String? {
    if (signers.isEmpty() || signers.any { it.isEmpty() }) return null
    val digest = MessageDigest.getInstance("SHA-256")
    val encoder = Base64.getUrlEncoder().withoutPadding()
    return signers.map { encoder.encodeToString(digest.digest(it)) }
        .sorted().joinToString(".")
}
