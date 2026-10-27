package io.betternet.next

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.util.TypedValue
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Local-only prototype: app selection never grants VPN access or routes traffic. */
class MainActivity : Activity() {
    private var selectedApp: AppChoice? = null

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
        val clearButton = Button(this).apply {
            setText(R.string.clear_app_selection)
            isEnabled = false
            setOnClickListener {
                selectedApp = null
                selectedStatus.setText(R.string.no_app_selected)
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
                        }
                        .setNegativeButton(android.R.string.cancel, null)
                        .show()
                }
            }
        })
        root.addView(clearButton)
        // Keep the selection and clear controls reachable on small screens or large fonts.
        setContentView(ScrollView(this).apply {
            fitsSystemWindows = true
            isFillViewport = true
            addView(root)
        })
    }

    private fun availableLauncherApps(): List<AppChoice> {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val candidates = packageManager.queryIntentActivities(launcher, 0).mapNotNull { info ->
            val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
            val label = info.loadLabel(packageManager)?.toString()?.trim().orEmpty().ifBlank { pkg }
            AppChoice(pkg, label)
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
