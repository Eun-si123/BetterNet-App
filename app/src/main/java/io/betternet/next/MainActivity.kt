package io.betternet.next

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.util.TypedValue
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Local-only prototype: selection and read-only VPN readiness never grant access or route traffic. */
class MainActivity : Activity() {
    private companion object { const val VPN_CONSENT_REQUEST = 301 }
    private var selectedApp: AppChoice? = null
    private var testConfiguration: RestrictedTestConfiguration? = null
    private var vpnStatus: TextView? = null
    private var consentButton: Button? = null

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
        val configurationStatus = TextView(this).apply {
            setText(R.string.test_config_not_set)
            setPadding(0, (16 * dp).toInt(), 0, 0)
        }
        val configureButton = Button(this).apply {
            setText(R.string.configure_test_path)
            isEnabled = false
            setOnClickListener {
                if (selectedApp != null) {
                    showRestrictedTestConfigurationDialog { configuration ->
                        testConfiguration = configuration
                        consentButton?.isEnabled = true
                        configurationStatus.text = getString(R.string.test_config_summary,
                            configuration.gatewayName, configuration.gatewayPort,
                            configuration.approvedHost, configuration.approvedAddress.hostAddress)
                    }
                }
            }
        }
        val checkVpnButton = Button(this).apply {
            setText(R.string.check_vpn_readiness)
            isEnabled = false
            setOnClickListener { checkVpnReadiness() }
        }
        val requestConsentButton = Button(this).apply {
            setText(R.string.request_vpn_consent)
            isEnabled = false
            setOnClickListener { requestVpnConsent() }
        }
        consentButton = requestConsentButton
        val clearButton = Button(this).apply {
            setText(R.string.clear_app_selection)
            isEnabled = false
            setOnClickListener {
                selectedApp = null
                testConfiguration = null
                requestConsentButton.isEnabled = false
                configurationStatus.setText(R.string.test_config_not_set)
                configureButton.isEnabled = false
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
                            // Reject an unobservable signer rather than silently
                            // downgrading to package-name/UID-only consent.
                            selectedApp = currentSignerFingerprint(choices[index].packageName)?.let {
                                choices[index].copy(signerFingerprint = it)
                            }
                            testConfiguration = null
                            requestConsentButton.isEnabled = false
                            configurationStatus.setText(R.string.test_config_not_set)
                            configureButton.isEnabled = selectedApp != null
                            selectedStatus.text = selectedApp?.let { chosen ->
                                getString(R.string.selected_app_summary, chosen.label, chosen.packageName)
                            } ?: getString(R.string.no_app_selected)
                            clearButton.isEnabled = selectedApp != null
                            checkVpnButton.isEnabled = selectedApp != null
                            vpnStatus?.setText(if (selectedApp == null)
                                R.string.vpn_readiness_app_unavailable else R.string.vpn_readiness_not_checked)
                        }
                        .setNegativeButton(android.R.string.cancel, null)
                        .show()
                }
            }
        })
        root.addView(clearButton)
        root.addView(configurationStatus)
        root.addView(configureButton)
        root.addView(readiness)
        root.addView(checkVpnButton)
        root.addView(requestConsentButton)
        // Keep the selection and clear controls reachable on small screens or large fonts.
        setContentView(ScrollView(this).apply {
            fitsSystemWindows = true
            isFillViewport = true
            addView(root)
        })
    }

    override fun onResume() {
        super.onResume()
        // Consent may have changed in the system dialog or while backgrounded.
        if (selectedApp != null && testConfiguration != null) checkVpnReadiness()
        else vpnStatus?.setText(R.string.vpn_readiness_not_checked)
    }

    /**
     * Only stages an owner-approved configuration in this Activity's memory.
     * No credential is stored, logged, transmitted or passed to the dormant VPN.
     * A future activation must revalidate app selection, consent and allowlists.
     */
    private fun showRestrictedTestConfigurationDialog(
        onConfigured: (RestrictedTestConfiguration) -> Unit,
    ) {
        val dp = resources.displayMetrics.density
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding((16 * dp).toInt(), 0, (16 * dp).toInt(), 0)
        }
        fun field(hintRes: Int, type: Int = InputType.TYPE_CLASS_TEXT): EditText =
            EditText(this).apply {
                setHint(hintRes)
                inputType = type
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                fields.addView(this)
            }
        val gatewayName = field(R.string.test_gateway_name)
        val gatewayPort = field(R.string.test_gateway_port, InputType.TYPE_CLASS_NUMBER)
        val dnsName = field(R.string.test_dns_name)
        val approvedHost = field(R.string.test_destination_host)
        val approvedIp = field(R.string.test_destination_ip)
        val token = field(R.string.test_gateway_token,
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
        val error = TextView(this)
        fields.addView(error)
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.configure_test_path)
            .setMessage(R.string.test_config_warning)
            .setView(ScrollView(this).apply { addView(fields) })
            .setPositiveButton(R.string.save_test_config, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                try {
                    val configuration = RestrictedTestConfiguration(
                        gatewayName.text.toString(), gatewayPort.text.toString().toIntOrNull() ?: 0,
                        dnsName.text.toString(), approvedHost.text.toString(),
                        approvedIp.text.toString(), token.text.toString())
                    onConfigured(configuration)
                    dialog.dismiss()
                } catch (_: IllegalArgumentException) {
                    // Do not echo credentials or arbitrary exception text to UI/logs.
                    error.setText(R.string.test_config_invalid)
                }
            }
        }
        dialog.setOnDismissListener { token.text.clear() }
        dialog.show()
    }

    /**
     * This is permission preparation only. No service start, TUN establishment,
     * packet forwarding, or gateway connection is reachable from this screen.
     * The user must confirm both our explanation and Android's system dialog.
     */
    private fun requestVpnConsent() {
        if (!canRequestVpnConsent(selectedApp != null, testConfiguration != null, observeVpnReadiness())) {
            checkVpnReadiness()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.request_vpn_consent)
            .setMessage(R.string.vpn_consent_warning)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.continue_to_system_consent) { _, _ ->
                // Recheck immediately: network/VPN ownership can change while
                // the confirmation dialog is visible.
                if (!canRequestVpnConsent(selectedApp != null, testConfiguration != null, observeVpnReadiness())) {
                    checkVpnReadiness()
                    return@setPositiveButton
                }
                try {
                    val consentIntent = VpnService.prepare(this)
                    if (consentIntent != null) startActivityForResult(consentIntent, VPN_CONSENT_REQUEST)
                    else checkVpnReadiness()
                } catch (_: SecurityException) {
                    vpnStatus?.setText(R.string.vpn_readiness_unavailable)
                } catch (_: ActivityNotFoundException) {
                    vpnStatus?.setText(R.string.vpn_readiness_unavailable)
                }
            }
            .show()
    }

    @Deprecated("Android Activity result callback for the platform VPN consent dialog")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_CONSENT_REQUEST) {
            // Never interpret RESULT_OK as permission to start a VPN. Recheck
            // Android's current state; selection/configuration may have reset.
            checkVpnReadiness()
        }
    }

    private fun checkVpnReadiness() {
        vpnStatus?.setText(when (observeVpnReadiness()) {
            null -> R.string.vpn_readiness_unavailable
            VpnReadiness.NO_APP -> R.string.vpn_readiness_no_app
            VpnReadiness.APP_UNAVAILABLE -> R.string.vpn_readiness_app_unavailable
            VpnReadiness.VPN_ACTIVE -> R.string.vpn_readiness_vpn_active
            VpnReadiness.NETWORK_UNAVAILABLE -> R.string.vpn_readiness_network_unavailable
            VpnReadiness.NEEDS_CONSENT -> R.string.vpn_readiness_consent_required
            VpnReadiness.PREPARED -> R.string.vpn_readiness_prepared
        })
    }

    /** Snapshot only; absence of a visible VPN is not proof of coexistence. */
    private fun observeVpnReadiness(): VpnReadiness? {
        val selected = selectedApp ?: return VpnReadiness.NO_APP
        val manager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        return try {
            // The app can be removed or lose its launcher entry after selection.
            // Never request device-level VPN permission for a stale scope.
            val selectedStillAvailable = selectedAppStillInstalled(
                selected, availableLauncherApps(), currentSignerFingerprint(selected.packageName))
            val defaultCaps = manager.activeNetwork?.let { manager.getNetworkCapabilities(it) }
            var vpnFound = defaultCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            var observationComplete = true
            for (network in manager.allNetworks) {
                val caps = manager.getNetworkCapabilities(network)
                if (caps == null) observationComplete = false
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpnFound = true
            }
            // INTERNET is only a declared capability, not proof of reachability.
            // Do not require VALIDATED: restricted networks may lack it.
            val available = defaultCaps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            val prepared = if (selectedStillAvailable && available && observationComplete && !vpnFound) {
                VpnService.prepare(this) == null
            } else false
            vpnReadiness(true, selectedStillAvailable, vpnFound, available, observationComplete, prepared)
        } catch (_: SecurityException) {
            null
        }
    }

    /** Read the *current* APK signers, not the signing lineage/history. A
     * rotation may require reselecting the app; it must never silently widen
     * an existing consent scope. Only an in-memory digest is retained.
     */
    @Suppress("DEPRECATION")
    private fun currentSignerFingerprint(pkg: String): String? = try {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val info = packageManager.getPackageInfo(pkg, flags)
        val signers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            info.signingInfo?.apkContentsSigners else info.signatures
        signerSetFingerprint(signers?.map { it.toByteArray() }.orEmpty())
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: SecurityException) {
        null
    }

    private fun availableLauncherApps(): List<AppChoice> {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val candidates = packageManager.queryIntentActivities(launcher, 0).mapNotNull { info ->
            val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
            // Launcher aliases may have misleading activity labels. Consent is per package,
            // so show the canonical application label rather than a shortcut label.
            val appInfo = info.activityInfo.applicationInfo ?: return@mapNotNull null
            if (appInfo.packageName != pkg) return@mapNotNull null
            val appLabel = appInfo.loadLabel(packageManager)
            AppChoice(pkg, appLabel?.toString()?.trim().orEmpty().ifBlank { pkg }, appInfo.uid)
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
