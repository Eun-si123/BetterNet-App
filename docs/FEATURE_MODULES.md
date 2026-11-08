# Built-in and optional Internet capabilities

**Decision confirmed:** BetterNet should contain an **optional, first-party sharing/transfer capability itself**, rather than requiring a separately installed DataNetShare app or always-on external integration. This is a **future requirement**, not an implemented module. The broad feature families in [the roadmap](PRODUCT_ROADMAP.md) are examples, not a fixed maximum feature list.

## Product packaging principles

- Keep a **small, reliable Android connectivity core**; optional user-facing capabilities are first-party modules, not arbitrary executable plugins.
- The same installed BetterNet app can expose sharing once available; the user does not need a second application, a DataNetShare server or a public volunteer relay by default.
- Each module is **off or unavailable until its own gates pass**. Removing/disabling a module cannot affect basic network status, app choice or a user-selected active safe path.
- UI levels remain simple automatic, guided and expert; controls become visible only when implemented and supported by the device/network. The user can change one feature without needing expert network knowledge.
- Versioned internal module contracts need to state capabilities, Android permissions, stored data, background/network work, resource budget, cancellation, effects on routing and tests. Do **not** invent a dynamic plugin runtime before there is a demonstrated need.
- Shared security is mandatory, not an optional toggle: OS permissions, source/receiver identity, network trust, quota and no secret logging apply to every profile.

## User control: installed size **and** enabled state

**Owner-confirmed requirement:** users can activate or deactivate individual optional features **and avoid unwanted app-size growth**. A switch by itself does **not** shrink an already installed APK or delete compiled code. Design and label these as distinct operations:

| State/action | What the user gets | Storage implication |
| --- | --- | --- |
| Not installed | Capability unavailable; show its purpose and approximate package size | Optional code/assets must be absent from the installed distribution for genuine savings |
| Installed, disabled | No sessions, background probes, listeners or permission request for that feature | Installed code may still occupy space; clearly say `Disabled`, **not** `Removed` |
| Installed, enabled | Feature usable after explicit consent/dependency checks | Explain data, battery and storage cost; security gates remain |
| Remove optional component | Stop, revoke grants, delete permitted downloaded component/cache and show retained settings/data separately | Free removable bytes only where packaging truly supports it; report actual result |

**Small core rule:** start with a safe base app (status, configuration, consent/safety controls, essential connectivity) and avoid bundling rarely used large features, translation/model assets or diagnostics data into every installation. The storage UI eventually shows base app size, optional component sizes, locally retained cache/log data, dependencies and expected removal savings. Do not introduce a heavy dependency for a tiny setting or claim that static Kotlin packages are uninstallable merely because they live in separate source modules.

**Distribution-dependent implementation:**

- **Public GitHub APK / sideload previews:** a normal single APK contains its packaged compiled features. Runtime OFF conserves background resources, **not** its APK bytes. At first use a lightweight base and optional user-fetched **signed/hash-verified non-executable data/resources** if genuinely needed. If later significant executable features must be omit-able, evaluate explicit, consistently signed **Lite/Full APK variants** or audited bundle/split-APK distribution with a clear upgrade/migration and uninstall path; do not invent a remote DEX/plugin loader or silently download executable code.
- **Possible future Google Play distribution:** Android App Bundles / Play Feature Delivery support on-demand and removable dynamic feature modules, with store-specific installation and removal APIs. This is **not automatically available to someone installing a single GitHub APK**. The feature architecture should not depend on Google Play services to perform essential core functions. Official guidance: [Play Feature Delivery](https://developer.android.com/guide/playcore/feature-delivery), [on-demand features](https://developer.android.com/guide/playcore/feature-delivery/on-demand), and [AAB vs APK](https://developer.android.com/guide/app-bundle/faq).

**Lifecycle and safety:** dependency resolution must show why a prerequisite is required, without auto-enabling unrelated optional modules. Turning a feature OFF cancels its jobs and closes its sessions; removal cannot leave active VPN/TUN traffic, downloaded executables, credentials, privileged grants, receiver advertisements or partial transfers. Define whether cached user files/settings are preserved or securely removed **before** deletion; never delete personal shared files just to free app space. For each platform/channel, validate fresh install, offline/metered download denial, interrupted install, failed integrity verification, disable during transfer, forced stop, reinstall, removal, rollback and user data retention. Only display actual **measured** footprint savings.

These controls are a **planned product capability**, not a claim that BetterNet-App currently supports feature download, module removal or fine-grained active VPN toggling.

## Candidate module matrix (all `PLANNED` unless explicitly verified elsewhere)

| Capability | Scope and dependencies | Independent pass/fail |
| --- | --- | --- |
| Connectivity analysis | Local, user-controlled network observation | Accurate status, no unexpected network/data consumption |
| Route optimization | Real accepted A1 path, measured quality | OFF/ON benefit under specified conditions, safe direct/strict fallback |
| Interactive optimization | Supported transport and queue control | p50/p95 RTT, jitter, loss and user outcome improve; no false low-ping claims |
| Streaming/messaging support | App-specific, TCP/QUIC/UDP as validated | Real video stall or message delivery evidence; no silent unsupported path |
| Data-cost controls | Selected metered/mobile network and user budget | Quotas hold; no background surprise charges |
| Built-in sharing/transfer | Explicit sender and receiver; independent protocol | Contents/integrity/recovery/consent tests; no DataNetShare runtime dependency |
| Local diagnostic export | Bounded redacted events and recipient approval | Exact preview, selective redaction, cancel without upload |
| Community node selection | Vetting and user-selected operators | Signed directory, revocation and unverified-node consent; no open proxy |

## Built-in sharing: proposed first milestone after accepted A1

**MVP user story:** From BetterNet, a user selects one or more files via Android's document picker, chooses a verified receiver/session, confirms transfer, and receives an integrity-confirmed completion state. The receiver explicitly accepts and can cancel/reject. Local share paths may use a separate authenticated device-to-device session; a volunteer relay is optional, not presumed necessary.

**Minimum acceptance conditions:**

1. **No extra app dependency.** A fresh BetterNet installation with the sharing feature enabled can send to a compatible BetterNet receiver without installing or launching DataNetShare. A disabled sharing module does not alter existing connectivity behavior.
2. **Permission isolation.** Use Android Storage Access Framework grants or appropriately scoped APIs, never blanket filesystem access by default. Never share private app secrets, arbitrary directories, tokens or files without user selection.
3. **Authentication/integrity.** Sender and receiver explicitly approve session identity/authorization. Verify file size, content hash/chunk integrity, complete destination and replay/rename collisions before advertising `Complete`.
4. **Interruption semantics.** Resume after loss only if identity, digest, destination and chunk state are verified. Support retry/cancel/partial data cleanup, idempotent completion and no silent duplication.
5. **Network adaptation.** Allow direct/local transfer and authenticated optional relay if needed; show metered-data, cost, throughput, battery and supported background restrictions. No assumption that all NATs/firewalls allow P2P.
6. **Interoperability/ownership.** Reuse **concepts**, not unreviewed source or protocol payloads, from DataNetShare; first-party standalone protocol and test fixtures are independently authored. Cross-product protocol compatibility requires its own explicit specification, version negotiation and consent later.
7. **Resource limits.** Size and concurrency bounds, CPU/storage/disk-full failure checks, rate caps, safe paths, no open inbound listener without consent, and tests for attacker-controlled filenames and malformed manifests.

**Not included by default:** whole-device VPN routing, background seeding for strangers, automatic public sharing, unknown peer discovery, permission inheritance from other apps or open internet hosting. Any of those requires separate user-facing consent and security review.

## Prioritization and proposal template

For every additional capability record: user problem and the networks where it helps; first testable user outcome; existing prerequisites; security/privacy/OS/cost impact; supported app/protocol; STOP/rollback path; observed OFF/ON evidence; long-term maintenance burden. Prioritize real A1 selected-app HTTPS ahead of optional sharing implementation until that gate is truly met.
