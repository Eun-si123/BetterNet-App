package io.betternet.next

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Bundle
import android.util.TypedValue
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Local-only prototype: selection and read-only VPN readiness never grant access or route traffic. */
class MainActivity : Activity() {
    private var selectedApp: AppChoice? = null
    private var vpnStatus: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dp = resources.displayMetrics.density
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
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

        val selectedStatus = TextView(this).apply {
            setText(R.string.no_app_selected)
            setPadding(0, (16 * dp).toInt(), 0, 0)
        }
        root.addView(selectedStatus)
        val readiness = TextView(this).apply {
            setText(R.string.vpn_readiness_not_checked)
            setPadding(0, (16 * dp).toInt(), 0, 0)
        }
        vpnStatus = readiness
        val checkVpnButton = Button(this).apply {
            setText(R.string.check_vpn_readiness)
            isEnabled = false
            setOnClickListener { checkVpnReadiness() }
        }
        val clearButton = Button(this).apply {
            setText(R.string.clear_app_selection)
            isEnabled = false
            setOnClickListener {
                selectedApp = null
                selectedStatus.setText(R.string.no_app_selected)
                vpnStatus?.setText(R.string.vpn_readiness_not_checked)
                checkVpnButton.isEnabled = false
                isEnabled = false
            }
        }
        root.addView(Button(this).apply {
            setText(R.string.select_test_app)
            setOnClickListener {
                val choices = availableLauncherApps()
                if (choices.isEmpty()) {
                    AlertDialog.Builder(this@MainActivity)
                        .setMessage(R.string.no_selectable_apps)
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                } else {
                    val labels = choices.map { "${it.label} (${it.packageName})" }.toTypedArray()
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle(R.string.select_test_app)
                        .setItems(labels) { _, index ->
                            selectedApp = choices[index]
                            selectedStatus.text = selectedApp?.let { chosen ->
                                getString(R.string.selected_app_summary, chosen.label, chosen.packageName)
                            } ?: getString(R.string.no_app_selected)
                            clearButton.isEnabled = true
                            checkVpnButton.isEnabled = true
                            vpnStatus?.setText(R.string.vpn_readiness_not_checked)
                        }
                        .setNegativeButton(android.R.string.cancel, null)
                        .show()
                }
            }
        })
        root.addView(clearButton)
        root.addView(readiness)
        root.addView(checkVpnButton)
        // Keep the selection and clear controls reachable on small screens or large fonts.
        setContentView(ScrollView(this).apply {
            fitsSystemWindows = true
            isFillViewport = true
            addView(root)
        })
    }

    override fun onResume() {
        super.onResume()
        // Permission and network ownership can change while this activity is backgrounded.
        vpnStatus?.setText(R.string.vpn_readiness_not_checked)
    }

    private fun checkVpnReadiness() {
        if (selectedApp == null) {
            vpnStatus?.setText(R.string.vpn_readiness_no_app)
            return
        }
        val manager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        // The default network alone may not expose a VPN visible on another network.
        // Even allNetworks is only a snapshot of networks visible to this app, not
        // proof that no other VPN exists on the device.
        val (visibleVpn, defaultNetworkAvailable) = try {
            val defaultCaps = manager.activeNetwork?.let { manager.getNetworkCapabilities(it) }
            val vpnOnDefault = defaultCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            val vpnOnOtherVisibleNetwork = manager.allNetworks.any { network ->
                manager.getNetworkCapabilities(network)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            (vpnOnDefault || vpnOnOtherVisibleNetwork) to (defaultCaps != null)
        } catch (_: SecurityException) {
            vpnStatus?.setText(R.string.vpn_readiness_unavailable)
            return
        }
        // Never interpret an unobservable default network as VPN readiness.
        // Never launch the returned consent Intent, start a service or create a TUN.
        val prepared = if (defaultNetworkAvailable && !visibleVpn) {
            try {
                VpnService.prepare(this) == null
            } catch (_: SecurityException) {
                vpnStatus?.setText(R.string.vpn_readiness_unavailable)
                return
            }
        } else false
        vpnStatus?.setText(when (vpnReadiness(true, visibleVpn, defaultNetworkAvailable, prepared)) {
            VpnReadiness.NO_APP -> R.string.vpn_readiness_no_app
            VpnReadiness.VPN_ACTIVE -> R.string.vpn_readiness_vpn_active
            VpnReadiness.NETWORK_UNAVAILABLE -> R.string.vpn_readiness_network_unavailable
            VpnReadiness.NEEDS_CONSENT -> R.string.vpn_readiness_consent_required
            VpnReadiness.PREPARED -> R.string.vpn_readiness_prepared
        })
    }

    private fun availableLauncherApps(): List<AppChoice> {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val candidates = packageManager.queryIntentActivities(launcher, 0).mapNotNull { info ->
            val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
            // Launcher aliases may have misleading activity labels. Consent is per package,
            // so show the canonical application label rather than a shortcut label.
            val appLabel = info.activityInfo.applicationInfo?.loadLabel(packageManager)
            AppChoice(pkg, appLabel?.toString()?.trim().orEmpty().ifBlank { pkg })
        }
        return selectableApps(candidates, packageName)
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
