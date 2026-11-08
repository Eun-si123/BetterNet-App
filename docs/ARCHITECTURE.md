# Architecture and technical boundaries

**Design review document, 2026-11-08.** Separate what actually exists on `main`, code in the [open implementation Draft PR #7](https://github.com/Eun-si123/BetterNet-App/pull/7), and proposed future interfaces. Do not read a diagram as an active Android service.

## Existing Android default branch (`MAIN`)

- [`MainActivity.kt`](../app/src/main/java/io/betternet/next/MainActivity.kt): local network-state display and app-choice UI; no production traffic forwarding.
- [`AppChoice.kt`](../app/src/main/java/io/betternet/next/AppChoice.kt), [`VpnReadiness.kt`](../app/src/main/java/io/betternet/next/VpnReadiness.kt), [`ConnectionState.kt`](../app/src/main/java/io/betternet/next/ConnectionState.kt): local selection, readonly readiness and status primitives.
- [`AndroidManifest.xml`](../app/src/main/AndroidManifest.xml): network-state permission and launcher activity; does **not** declare an active VPN service in this default-branch revision.
- [Android CI](../.github/workflows/android.yml) builds JVM tests/lint/debug APK. Neither an APK nor CI results establish selected-app connectivity.

## Under review in Draft PR #7 (`DRAFT PR`, not default-branch code)

The feature PR adds a dormant `SelectedAppVpnService` boundary, `RestrictedTun*` ownership/lifecycle/pump, per-packet ingress and DNS/TCP primitives, verified TLS and scoped HTTP CONNECT clients, diagnostic probes and a **loopback-only** Python reference gateway. They have isolated gateway/Android CI coverage, but a real device's selected-app HTTPS response is **NOT RUN**. No home-server deployment or general Internet relay is in use.

This is the intended future high-level path **only after consent and A1 proof**:

```text
User / Android UI  -- explicit app + network + fallback choice -->  Scoped Android VPN controller
        |                                                            |
  local privacy/report preview                              Android VpnService permission
        |                                                            |
        +---- optional user-confirmed report                 TUN / packet owner (one app)
                                                                     |
                                                         validated DNS/TCP/UDP dispatch
                                                                     |
                                                         protected + bound socket
                                                                     |
                                                           authenticated TLS/CONNECT
                                                                     |
                                                        approved gateway / exit policy
                                                                     |
                                                             remote HTTPS destination
```

The TUN controller must *never* connect its own gateway through its own VPN recursion. The actual user app's HTTPS destination identity must be checked by its endpoint TLS, separate from authenticating the gateway. Some HTTPS variants use QUIC/UDP and need new approval/testing, not hidden fallback to arbitrary interception.

## Proposed design boundaries — **not implemented**

| Boundary | Responsibility | Safeguard / failure behavior |
| --- | --- | --- |
| Android UI and consent | App selection, profile, operator/cost display, Stop, log review | Never infer OS VPN approval; no one-click hidden full-device interception |
| Capability registry (internal, static/versioned) | Track **installed/available** separately from **enabled/disabled** and enforce dependencies before any optional task | No arbitrary third-party code loading, no implicit permission escalation, no false APK-size claims |
| Route policy | Evaluate direct vs authenticated relay, battery/data budgets, configured strictness | Strict block policy is never silently downgraded; direct fallback clearly surfaced |
| Path adapter | Android protected/bound sockets, TCP/UDP where actually supported | Respect chosen non-VPN underlying network; changes revalidated |
| Gateway/volunteer client | Authenticate selected operator, authorize destination, quotas and protocol | Fail on invalid trust, expired credentials, quota, or host mismatch; don't use unknown fallback |
| Optional sharing feature | Built-in send/receive with independent sessions and integrity | Explicit peer/recipient, grants, revocation, consent, no broad access to local storage |
| Telemetry/reporting | Local bounded diagnostic stream and opt-in preview/export | No remote collector by default; scrub and separate explicit send confirmation |

The default APK should remain small. Future installation/removal strategies must be designed for the actual channel: GitHub APKs lack automatic Play Feature Delivery; possible future Play App Bundles can use audited on-demand dynamic modules. See [feature packaging and lifecycle](FEATURE_MODULES.md). This is a **design** and does not mean modules can currently be removed.

Avoid a universal packet/plugin interface until an actual accepted feature requires one. Modules may share a small validated transport/identity API, but package and permission boundaries must follow the actual implementation and Android restrictions.

## Connection lifecycle and failure path (proposed)

`OFF → USER_SELECTED → OS_CONSENTED → NETWORK_PRECHECK → AUTHENTICATED → ACTIVE → STOPPING → OFF`.

A failed prerequisite returns a visible failure without starting capture. Revoke, underlying network loss, app uninstall/identity change, socket-protection failure and process restarts must stop the owned session. Do not revive a TUN worker after its cancellation without a new explicit, validated transition. The path's deadline must cover sequential authorization steps; timeouts do not prove a hard interruption of a blocking OS call.

**Important Android risk:** a claimed strict/block mode cannot promise zero-leak behavior if the VPN process crashes and the operating system routes outside the tunnel. It needs a real-device-supported Android lockdown/always-on policy, OS/version matrix and explicit disclosure. Current Draft PR #7 deliberately disables always-on eligibility. Treat strict as **design-only / unavailable for public claim** until OS behavior is independently proven. Daily direct fallback also must respect the explicitly chosen per-app scope and any external VPN.

## Network and server protocol evolution

Initial A1 is a narrow selected-app HTTPS proof. Transport adaptations, volunteer discovery, multiple hops, transfer scheduling, or a broader UDP/QUIC path have independent gates; do not add a remote-access server or expose a listener because the architecture diagram mentions one. Volunteer node role/cost/identity policy belongs in [server nodes](SERVER_NODES.md), security issues in [security and privacy](SECURITY_PRIVACY.md), completion claims in [verification](TEST_STRATEGY.md).

**Independent codebases:** BetterNet-private is a separately held experimental research area with a similar broad purpose. BetterNet-App does not build against it. Built-in sharing can pursue goals similar to DataNetShare but does not require DataNetShare's code, protocol, install or server. See [feature modules](FEATURE_MODULES.md).
