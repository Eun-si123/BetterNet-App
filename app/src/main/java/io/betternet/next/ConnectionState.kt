package io.betternet.next

/** Pure interpretation only: validated is not a speed or reachability guarantee. */
internal data class ConnectionState(
    val present: Boolean,
    val validated: Boolean,
    val captivePortal: Boolean,
    val metered: Boolean,
    val kind: Kind,
) {
    enum class Kind { NONE, WIFI, CELLULAR, ETHERNET, VPN, OTHER }
    enum class Assessment { DISCONNECTED, CAPTIVE, UNVALIDATED, VALIDATED }
    fun assessment(): Assessment = when {
        !present -> Assessment.DISCONNECTED
        captivePortal -> Assessment.CAPTIVE
        !validated -> Assessment.UNVALIDATED
        else -> Assessment.VALIDATED
    }
}
