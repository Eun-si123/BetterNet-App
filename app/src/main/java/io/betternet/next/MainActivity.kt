package io.betternet.next

import android.app.Activity
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.util.TypedValue
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Local-only prototype: no VPN, external requests, telemetry or route changes. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dp = resources.displayMetrics.density
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
            val pad = (24 * dp).toInt()
            setPadding(pad, pad, pad, pad)
        }
        root.addView(TextView(this).apply {
            setText(R.string.app_name)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 26f)
        })
        root.addView(TextView(this).apply {
            setText(R.string.preview_scope)
            setPadding(0, (16 * dp).toInt(), 0, (16 * dp).toInt())
        })
        val status = TextView(this).apply {
            setText(R.string.not_checked)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
        }
        root.addView(status)
        root.addView(Button(this).apply {
            setText(R.string.refresh_network)
            setOnClickListener { status.text = currentNetworkDescription() }
        })
        setContentView(root)
    }

    private fun currentNetworkDescription(): String {
        val manager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = manager.activeNetwork?.let { manager.getNetworkCapabilities(it) }
        val state = ConnectionState(
            present = caps != null,
            validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
            captivePortal = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true,
            metered = caps != null && manager.isActiveNetworkMetered,
            kind = when {
                caps == null -> ConnectionState.Kind.NONE
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> ConnectionState.Kind.VPN
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> ConnectionState.Kind.WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> ConnectionState.Kind.CELLULAR
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> ConnectionState.Kind.ETHERNET
                else -> ConnectionState.Kind.OTHER
            },
        )
        val assessment = when (state.assessment()) {
            ConnectionState.Assessment.DISCONNECTED -> R.string.state_disconnected
            ConnectionState.Assessment.CAPTIVE -> R.string.state_captive
            ConnectionState.Assessment.UNVALIDATED -> R.string.state_unvalidated
            ConnectionState.Assessment.VALIDATED -> R.string.state_validated
        }
        val kind = when (state.kind) {
            ConnectionState.Kind.NONE -> R.string.type_none
            ConnectionState.Kind.WIFI -> R.string.type_wifi
            ConnectionState.Kind.CELLULAR -> R.string.type_cellular
            ConnectionState.Kind.ETHERNET -> R.string.type_ethernet
            ConnectionState.Kind.VPN -> R.string.type_vpn
            ConnectionState.Kind.OTHER -> R.string.type_other
        }
        val cost = if (state.metered) R.string.metered_yes else R.string.metered_no
        return getString(R.string.network_summary,
            getString(assessment), getString(kind), getString(cost))
    }
}
