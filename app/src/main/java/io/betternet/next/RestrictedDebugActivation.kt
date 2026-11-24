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

/** Fail closed if the explicit test is delivered after the default Network
 * switches. A live Android Network's opaque handle is positive; an unknown
 * network must not silently become a metered cellular fallback. Only the
 * service checks the live Android Network immediately before activation.
 */
internal fun requireApprovedRestrictedNetworkHandle(
    approved: Long, actual: Long,
) {
    require(approved > 0L && actual > 0L && approved == actual) {
        "Underlying Network changed since user authorization"
    }
}


/** Debug consent is a time-limited test, not a persistent VPN permission. */
internal const val RESTRICTED_DEBUG_MAX_RUNTIME_MS = 120_000L

/** Invalidate the pending one-shot approval before requesting cancellation of
 * the selected-app test. Reconfiguring an active test must not leave the
 * previously approved server/token/route running in the background.
 */
internal fun revokeRestrictedDebugScope(
    handoff: RestrictedActivationHandoff, requestStop: () -> Unit,
) {
    handoff.clear()
    requestStop()
}

/** Independent main-looper stop backstop. The packet pump also has its own
 * deadline; the owner may block in an OS DNS/bind call, so waiting for its next
 * iteration is insufficient. This watchdog requests immediate descriptor
 * cancellation and stopSelf, but cannot guarantee scheduling while Android
 * is freezing the process. No network, timers or Android services start here.
 */
internal class RestrictedDebugStopWatchdog(
    private val schedule: (Runnable, Long) -> Boolean,
    private val unschedule: (Runnable) -> Unit,
    private val requestStop: () -> Unit,
) {
    private val issued = java.util.concurrent.atomic.AtomicBoolean(false)
    private val active = java.util.concurrent.atomic.AtomicBoolean(false)
    private val timeoutTask = Runnable {
        if (active.compareAndSet(true, false)) requestStop()
    }

    fun arm() {
        check(issued.compareAndSet(false, true)) {
            "Restricted debug stop deadline cannot be rearmed"
        }
        active.set(true)
        try {
            check(schedule(timeoutTask, RESTRICTED_DEBUG_MAX_RUNTIME_MS)) {
                "Could not schedule restricted debug stop deadline"
            }
        } catch (error: Throwable) {
            active.set(false)
            try { unschedule(timeoutTask) } catch (cleanup: Throwable) {
                if (cleanup !== error) error.addSuppressed(cleanup)
            }
            throw error
        }
    }

    fun cancel() {
        active.set(false)
        unschedule(timeoutTask)
    }
}
