package io.betternet.next

import java.util.concurrent.TimeUnit

/** An Intent carries only this opaque one-use handle, never an app identity or token. */
internal const val ACTION_START_RESTRICTED_DEBUG = "io.betternet.next.START_RESTRICTED_DEBUG"
internal const val EXTRA_RESTRICTED_HANDLE = "io.betternet.next.EXTRA_RESTRICTED_HANDLE"

/** Process death loses credentials and pending activation. No persistent storage. */
internal object RestrictedDebugActivationRegistry {
    val handoff = RestrictedActivationHandoff()
}

/** Reject any unknown, non-debug, expired or mismatched service start.
 * A bogus start revokes the pending handle rather than preserving a stale grant.
 */
internal fun claimRestrictedDebugSession(
    action: String?, handle: String?, debugBuild: Boolean,
    handoff: RestrictedActivationHandoff,
): RestrictedActivationHandoff.Session? {
    if (!debugBuild || action != ACTION_START_RESTRICTED_DEBUG) {
        handoff.clear()
        return null
    }
    val session = handoff.take(handle)
    if (session == null) handoff.clear()
    return session
}

/** A successful, user-requested verified HTTPS diagnostic is a short-lived
 * prerequisite for offering the dangerous test button. This is NOT evidence
 * that the VPN tunnel itself works. Exact app/config/network object identities
 * prevent permission reuse after a selection or network change. Android
 * Network handles compare by their opaque netId, not object reference.
 */
internal class VerifiedGatewayTestLease(
    private val clockMillis: () -> Long = { android.os.SystemClock.elapsedRealtime() },
) {
    private var selected: AppChoice? = null
    private var config: RestrictedTestConfiguration? = null
    private var network: Any? = null
    private var verifiedAtMillis = -1L

    fun approve(app: AppChoice, configuration: RestrictedTestConfiguration, underlying: Any) {
        selected = app
        config = configuration
        network = underlying
        verifiedAtMillis = clockMillis()
    }

    fun validFor(app: AppChoice?, configuration: RestrictedTestConfiguration?, underlying: Any?): Boolean {
        val now = clockMillis()
        val elapsed = now - verifiedAtMillis
        return verifiedAtMillis >= 0 && elapsed >= 0 &&
            elapsed <= TimeUnit.SECONDS.toMillis(60) &&
            app != null && app === selected &&
            configuration != null && configuration === config &&
            underlying != null && underlying == network
    }

    fun clear() {
        selected = null
        config = null
        network = null
        verifiedAtMillis = -1L
    }
}

/** Android consent and VPN capability remain independently checked in service. */
internal fun canOfferRestrictedDebugStart(
    isDebugBuild: Boolean, prepared: Boolean, verifiedGateway: Boolean,
): Boolean = isDebugBuild && prepared && verifiedGateway
