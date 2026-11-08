# Security and privacy boundaries

**Scope:** prospective Android client, first-party built-in sharing, authenticated Linux gateway, optional volunteer nodes and user-controlled diagnostics. **This document does not grant permission to collect traffic, publish a service or activate a VPN.** Current implementation evidence is in [status](STATUS.md).

## Threat model and trust boundaries

| Boundary / threat | Minimum response and evidence |
| --- | --- |
| User-selected vs unrelated Android app | One explicit app scope, Android OS permission, no whole-device fallback, separate unselected-app capture check on physical hardware |
| VPN socket recursion and network switch | Protect and bind underlying sockets to the intended non-VPN network; recheck network and app identity across asynchronous operations; stop safely on revoke |
| Gateway impostor / malicious volunteer exit | Authenticate server identity and TLS, separate directory verification from node self-registration, revocation; disclose destination metadata visible to operators |
| DNS and destination substitution | Check question identity, approved address/host/port, bounded TTL/lease and independent HTTPS destination TLS; no arbitrary unchecked relay destination |
| Partial packet/write, replay, crash | Bounded state, idempotent cleanup and no unsafe replay of an uncertain write; tests for STOP, reinstall, lost gateway and process exit |
| Untrusted sharing peer/file name | Explicit receiver approval, authenticated scope, safe filesystem grant, integrity verification, path traversal defense, no default public shares |
| Diagnostic/report leak | No background upload; preview/redact/select exact fields, show recipient and allow no-send; redact before export |
| Paid/volunteer node misuse | Operator consent, limits/quotas, abuse reports, directory revocation; fees never imply security verification |
| Malformed data or resource exhaustion | Length/count/time quotas, parser rejection, bounded CPU/memory/bandwidth, cancellation and cleanup; unknown packets rejected by default |

Exit nodes and network providers can still observe IP addresses, DNS metadata, connection timing and transferred bytes. Transport TLS protects appropriately encrypted payloads, **not** every metadata field or the trustworthiness of the receiving operator. Do not promise anonymity, universal censorship bypass, zero tracking or access when no reachable physical network exists.

## Proposed Android safety policy

1. Request consent for the specific scoped function. No automatic whole-phone capture or background service started by reading a roadmap or opening diagnostics.
2. Choose a known safe underlying Android `Network`; bind/protect gateway sockets and fail closed on unavailable or changed network identity, missing consent or invalid credentials. Revalidation must happen after blocking work.
3. On gateway outage: **daily use** may knowingly fall back to direct access, visibly; **strict** asks for a verified OS-supported block/lockdown behavior and never silently falls back. No strict security claim until real-device crash/reboot/leak tests are done. Existing Draft PR #7 has always-on deliberately disabled.
4. No blanket bypass of other VPNs. Unexpected starts/restarts, revoke, stopped app, stale server trust and failed cleanup must not leave a hidden forwarding session active.
5. Network probes can cost money and leak destination metadata. Require explicit request for optional external probes and show the affected network and endpoint category.

## Diagnostic data: preview-before-send contract

**Default:** no upload, no centrally hosted collector and no network-activity recording unless a bounded local diagnostic is user-enabled. When enabled, show the user the contents and recipients **before** any optional send.

- **Local review:** structured categories (device/OS version, app version, network category, duration, error codes, per-path aggregates), field-level deletion, selective export and obvious cancel/no-send. Keep local collection bounded, temporary and deletable. Allow offline report copy.
- **Minimization:** no full URLs, request/response bodies, credentials, Authorization headers, chat messages, files, plaintext contents or user identities by default. IP, DNS names, timestamps and stable device identifiers can still reveal sensitive information, so offer redaction and warning even for supposedly anonymized logs. No debug log can accidentally print bearer tokens.
- **Separate confirmation:** reveal the exact outgoing report (including attachments), recipient/service, policy and likely data cost. A second explicit confirmation sends; exporting to a local file alone never uploads. Failure/retry requires maintaining consent boundaries, with a visible cancel action.
- **Lifecycle:** define on-device retention, encryption/storage controls and recipient retention **before implementing** upload. Delete/clear operations must be tested; transmitted data cannot be promised to disappear from third-party operators on command.
- **Operator logs:** independently governed and disclosed; a client's choice to report a crash is not consent for a volunteer server to retain payload or extend log retention.

No actual report collector, credential provisioner, email receiver or cloud endpoint is selected or deployed by this draft.

## Built-in sharing trust policy

Sharing lives **inside BetterNet**, but is off until its own approval. Use user-selected Android document grants, authenticated receiver identity, per-session authorization, integrity checks, size/concurrency quotas and expiry. Do not auto-serve a personal folder, turn on peer discovery, expose NAT ports or seed content on volunteers. Protect receiver privacy, local storage paths, interrupted-file cleanup and fail-closed cancel. Research/experiments in BetterNet-private and feature ideas from DataNetShare do not authorize copying private source or live identifiers into public code.

## Gate to more privileges

Any expansion to whole-device routing, UDP services, additional Android permissions, remote listener, sharing discovery, volunteer node or diagnostics collector needs a new documented trust/data-flow change, reviewable consent UI, negative tests, on-device evidence and explicit approval where real systems/data are affected. Use [the test strategy](TEST_STRATEGY.md) and [operator policy](SERVER_NODES.md); never weaken gates merely to pass CI.
