package io.betternet.next

import java.util.Locale
import android.content.pm.PackageManager
import android.os.Build
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

/** One PackageManager snapshot; no package-name/UID-only fallback on missing signers. */
internal data class InstalledAppIdentity(val uid: Int, val signerFingerprint: String)

@Suppress("DEPRECATION")
internal fun readInstalledAppIdentity(manager: PackageManager, pkg: String): InstalledAppIdentity? = try {
    val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
    val info = manager.getPackageInfo(pkg, flags)
    val signers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        info.signingInfo?.apkContentsSigners else info.signatures
    val fingerprint = signerSetFingerprint(signers?.map { it.toByteArray() }.orEmpty())
    val uid = info.applicationInfo?.uid
    // VpnService.Builder.addAllowedApplication() routes by UID, not by APK.
    // A shared UID could silently capture another app's traffic. Reject
    // legacy sharedUserId even if Android's package-visibility filtering hides
    // the other packages from getPackagesForUid().
    if (uid == null || uid <= 0 || fingerprint == null ||
        !hasExclusiveVpnUid(pkg, info.sharedUserId, manager.getPackagesForUid(uid))) null
    else InstalledAppIdentity(uid, fingerprint)
} catch (_: PackageManager.NameNotFoundException) {
    null
} catch (_: SecurityException) {
    null
}

/**
 * A single-app VPN scope is possible only for a UID not shared with other
 * packages. Android 11+ may filter getPackagesForUid() by package visibility;
 * a non-null declared sharedUserId is therefore an independent hard reject.
 * Unknown, incomplete or ambiguous package snapshots must fail closed.
 */
internal fun hasExclusiveVpnUid(
    selectedPackage: String, declaredSharedUserId: String?, uidPackages: Array<String>?,
): Boolean = declaredSharedUserId == null && uidPackages?.singleOrNull() == selectedPackage

/** A future VPN builder must recheck identity independently of Activity consent. */
internal fun requirePinnedSelectedApp(
    selected: AppChoice?, ownPackage: String, current: InstalledAppIdentity?,
): String {
    val pkg = requireSelectedPackage(selected?.packageName, ownPackage)
    require(selected != null && current != null && selected.uid > 0 &&
        !selected.signerFingerprint.isNullOrBlank() &&
        selected.uid == current.uid && selected.signerFingerprint == current.signerFingerprint) {
        "Selected app identity changed or is unavailable"
    }
    return pkg
}

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
