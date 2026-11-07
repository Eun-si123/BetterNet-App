# BetterNet App — Android-first product roadmap

**Status:** draft product direction, 2026-11-08. This document proposes work; it does not indicate that features are implemented, deployed, released, or physically tested.

**Vision:** BetterNet is a broadly useful, adaptable **Internet capability platform**—not only a VPN, a ping booster, or a tool for bad networks. Help with ordinary browsing, messaging, streaming, calls, gaming, collaboration, large transfers, reliable sharing and future Internet-oriented workflows in **good, average, congested, costly, mobile, restricted and severely degraded environments**. Pursue resilience, meaningful latency/throughput improvements, efficient data use, safe reachability and useful user-controlled networking features together. Optional examples are **not** a fixed list of modes or a promise that every workload benefits. Do not claim universal acceleration, zero ping, guaranteed continuity, anonymity or guaranteed access through every restriction.

**Owner direction (confirmed 2026-11-08):** Android first, with later Windows/Linux expansion. Serve ordinary Internet use in unreliable/low-bandwidth/high-cost/restricted environments, not only file-transfer workloads. Reliability, meaningful speed and reachability all matter. Support independently operated authenticated Ubuntu/Linux servers, a vetted server directory **and** self-registered/manual volunteer servers. Let early adopters download a **public, clearly labelled GitHub experimental APK**, without enabling unverified VPN forwarding. Default daily-use mode may fall back to direct Internet on relay failure; an explicit privacy/strict mode blocks instead. Start acceptance workloads with **browsers, messengers and YouTube**. Battery, mobile-data and performance trade-offs are **chosen by each user**. Offer easy automatic setup alongside configurable expert modes. Both free and donation-supported/paid operator nodes may be available with transparent prices and opt-in consent. Users must be able to **preview and selectively send** redacted diagnostics; unsolicited telemetry remains off. Curated trust is granted by accountable project/community verification, not automatically by registration. Public license, detailed node review/appeals, diagnostic retention and Android device policy remain undecided.

## Current verified boundary

The repository's default branch remains **pre-alpha**. Draft [PR #7](https://github.com/Eun-si123/BetterNet-App/pull/7) has substantial dormant single-app VPN, TLS/CONNECT, DNS/TCP, lifecycle and isolated gateway test development. Successful CI and localhost TLS tests do **not** prove that an Android app can browse through BetterNet. No physical A1 selected-app HTTPS completion, production relay deployment or general-purpose acceleration is verified. Do not count those as complete.

For implementation versus plans, use the [documentation hub](README.md) and [dated status ledger](STATUS.md). The [built-in sharing capability](FEATURE_MODULES.md) is an optional first-party BetterNet feature, **not** a separate DataNetShare install, mandatory API integration or currently implemented transfer. The [decision register](DECISIONS.md) distinguishes user-confirmed product choices from unresolved operational policy.

This roadmap adds product detail to [Milestone A](MILESTONE_A.md). A0–A3 in Milestone A remain the *immediate technical acceptance gates*. Later phases below are candidates, not commitments to expose server infrastructure or roll out traffic interception.

## Product rules

- **A direct path can win.** Compare the same workload OFF/direct and ON/BetterNet; when tunnelling costs more, loses reliability or adds delay, do not pretend an improvement. A user-visible route/quality decision is preferable to automatic blind tunnelling.
- **Fail safely before extending scope.** First support exactly one explicitly selected Android app; never route all apps on a missing selection. Expand to multiple apps, optional whole-device and other platforms only after the respective checks. Respect Android VPN consent, coexistence and notification-based Stop.
- **No default personal server.** Never hardcode or deploy to a contributor's home server, address, account, DDNS domain or personal network as a product dependency. Test with throwaway loopback networks or a separately consented, operator-controlled test node.
- **Honest privacy boundary.** Encrypt/authenticate clients and gateways, protect/bind sockets to the intended underlying network, and verify appropriate TLS destination identity. A volunteer exit operator may observe destination metadata, time and traffic volume even for HTTPS; disclose that. No payload collection or background telemetry by default.
- **Measured resource costs.** Reliability cannot come at unbounded battery, CPU, data or relay costs. Let users choose trade-offs, especially on metered networks.
- **Independent public development.** Do not copy private BetterNet research source/config/identifiers, or export private logs and credentials into the public app without explicit source, license and privacy review.
- **Evidence-based phases.** Record every actual test environment, unsupported protocol, known failure, performance baseline and rollback. Successful CI is not device-level acceptance. PR counts are not a progress metric.
- **Resource-constrained users are first-class.** Keep the Android client lightweight, power and data budgets visible, setup and diagnostics usable on low-end hardware, and essential status usable when offline. Evaluate limited data plans, cheap devices, unstable radio, expensive metered links and low-bandwidth networks. Optional relay capacity cannot guarantee a free or functional Internet connection where no viable physical path exists.
- **No imaginary zero-latency mode.** A "lowest ping" profile may reduce queueing, select a genuinely shorter route or avoid unnecessary relay hops, but cannot beat propagation distance, radio scheduling or congestion outside our control. A throughput-oriented relay can *increase* ping; use matched OFF/ON measurements and show negative outcomes.
- **Expandable without being a kitchen sink.** Ship a lightweight and secure automatic connectivity core plus optional versioned capabilities (not an unrestricted third-party plugin execution platform): transport optimizers, diagnostics, selective per-app routing, data-aware transfers, resumable sharing, and other useful Internet features. Add capabilities only with real use cases, bounded permissions, compatibility/recovery tests and a maintained off switch. Disabling a module must not silently re-enable it or bypass VPN/network/privacy consent.
- **Private research and public product, shared mission.** BetterNet-private is a separate experimental/private personal testing space for networking ideas; BetterNet-App is the safe, independently implemented public user-facing application pursuing a comparable broad purpose. A research idea or successful private trial is **not** a public implementation or a public release criterion. Public promotion requires an explicit source/license/privacy review, independently authored code and verified product tests; no automatic mirroring or public export of private data.

## Extensible Internet capability families (long-term candidates)

The following are **examples, not a maximum feature list**. Different users and environments benefit from different combinations. Avoid a monolithic mandatory bundle: document versioned capability contracts, dependencies, Android permission/traffic scope, cost and tests for each opt-in feature. Simple mode presents recommended, supported capabilities; guided and expert modes expose individual switches. A disconnected or untrusted capability must not make the base application unusable.

| Family | Illustrative capabilities | Acceptance requirement before exposure |
| --- | --- | --- |
| Connection health and recovery | Quality checks, interruption recovery, congestion avoidance, path choice and multipath | Same workload OFF/ON, resource and privacy limits, no unsupported continuity claims |
| Interactive responsiveness | Queue/latency/jitter optimization, game/voice profile where protocol permits | RTT **and** p95 jitter / loss under matched load; do not claim magic low ping |
| Streaming and messaging | Browser/media session quality, streaming stall reduction, continuity under network transitions | Real browser, messenger and video tests including TCP/QUIC/UDP when supported |
| Bandwidth and data efficiency | Bulk-transfer scheduling, compression only for appropriate plaintext, metered-data controls and caching where legal | Data/battery/CPU cost, destination integrity, content/privacy and safe rollback |
| Transfer and sharing | Optional device-to-device sharing, authenticated resumption and selected features **similar in goal** to DataNetShare | Independent clean-room design; explicit recipient consent, integrity and secret exclusion; do not copy repositories together by default |
| Diagnostics and user tools | Per-path measurements, packet-loss explanations, local redacted logs, user-controlled exports and troubleshooting | No silent data collection or background upload; support offline view and user-edited reports |
| Community networking | Verified and manually added relays, role-scoped nodes and later optional peer-assisted paths | Operator trust, consent, abuse prevention, quotas and independent path checks |

Prioritize **Phase 1 real Android connectivity first**. New capability proposals need user value, hard dependencies, a one-sentence exit test and a resource/maintenance cost; reject features that add complexity without clear benefit. Later APIs can reuse concepts without coupling public builds to DataNetShare, TeamForge or any private codebase.

## User experience and configurable optimization policy

**Default experience:** install → understand what BetterNet can and cannot improve → select supported app(s) and explicitly approve Android VPN permission → choose a verified reachable node or direct mode → start/stop with one clear control. The final automatic node choice may only use a published, reviewed and authenticated directory; when no safe node is available, explain why and stay in direct/diagnostic mode. Installation, server enrollment and VPN permission are never silently assumed. This is a *future design*, not an implemented flow.

**Interface levels:** The named presets below illustrate the first useful UX, **not** an exhaustive or permanent list. Future profiles and independent capability toggles may be proposed based on measured value; users must be able to inspect what each profile activates.

| Level | Intended user | Visible controls |
| --- | --- | --- |
| Simple / Automatic | First-time users | One connection switch, automatic measured route, current policy, Stop and clear connection status |
| Guided presets | Anyone with a clear goal | Latency-first, Stability-first, Balanced (recommended), Data-saving, and Custom profiles with simple descriptions |
| Advanced / Expert | Power users and researchers | Per-app policy, transport and path enable/disable, explicit relay/server choice, health thresholds, timers, battery/data limits, retries, logs export with redaction and rollback |

All presets share the same security and Android-permission gates. They do not claim to fix a particular app until that app/protocol is physically supported. **Latency-first** prioritizes interactive queues and measured RTT/jitter over bulk throughput, but cannot promise faster physical ping. **Stability-first** may trade higher latency and extra transmission for fewer task interruptions. **Data-saving** minimizes probes, duplicate paths and overhead; performance may decrease. **Balanced** applies measured conservative defaults. **Custom** selects individual features only after their prerequisites are satisfied.

**Failure policy:** Daily-use mode can switch back to **direct Internet** when a relay becomes unusable, clearly displaying the change. Privacy / strict mode must **block, not leak via direct fallback**. Make the trade-off visible before the first VPN start, provide session status, and record repeatable no-leak/no-capture tests. Never silently switch a strict user to direct, another volunteer operator, mobile data, or an unknown network. A manual override must be explicit and revocable.

**Mobile resource policy:** Every user can select data/battery/performance preference with safe defaults; advanced controls may permit more battery or metered-data use when allowed by Android and network policy. No unexplained automatic cellular spending. Respect low-power/data-saver constraints unless the user explicitly chooses a supported override; report actual cost rather than claiming "free speed."

## Transparent diagnostics and user-controlled reports

**Default: no background telemetry upload.** A tester can generate or enable a **bounded local diagnostics log** explicitly, inspect it on the device and decide whether to share anything. The review screen must show **exactly what will be sent and to which service/recipient**, not just a generic “send diagnostics” button. Allow category selection, redaction preview, removal of individual entries or fields, and cancel without upload. Explain that IP addresses, times, DNS names and unique error details may still identify users even after automated scrubbing; warn before sending sensitive fields. Never show/share passwords, bearer tokens, auth headers, private keys or full user payloads by default.

A transmission is **separately confirmed** after review; a crash, automated retry, background job or log export never substitutes for consent. Support saving/copying a scrubbed report locally without uploading, clear/delete locally held diagnostics, a finite storage/retention cap, secure-at-rest considerations and an auditable user-visible status for sent reports. The exact remote collector, optional report format, retention windows and operator access rules remain a policy gate—**no collection server is authorized or deployed by this draft**. Volunteer operators have separately scoped operational logs and must disclose retention and recipient; client log opt-in does not waive gateway privacy requirements.

## Server installation, selection and volunteer governance

**Two simultaneous routes:** (1) a **curated, verified and signed directory** with operator identity, revocation and health data; (2) **independent community self-registration and manual address entry**. A self-registered node is never *automatically* considered trustworthy or promoted to the curated set. An accountable project/community review process issues and revokes curated trust, with auditable criteria, reports, transparent decisions and an appeal path to define before launch. Unreviewed nodes require an explicit warning and opt-in; a self-hosted operator can keep a node private and share its authenticated address directly.

**Server operator UX:** one supported Linux/Ubuntu installation path (e.g. packaged service or container) with a secure default configuration, first-run identity and TLS provisioning, a readable status/check command, safe update/rollback and reversible removal. Offer a guided admin UI/CLI that translates advanced options into understandable labels; an expert configuration file/API can expose bounded port/destination access, user authentication, concurrency, memory/CPU/bandwidth/data quotas, metered-use rules, relay uptime, logging retention, access policy and geographic/abuse limits. All powerful choices require validation and an explainable effective-config preview. Zero-configuration convenience must **not** mean an open proxy.

**Economics and fairness:** Support **free volunteer nodes**, **optional donation-supported nodes** and **clearly disclosed paid nodes**, all selectable rather than compulsory. A paid node is not inherently better or more trustworthy. Display cost per GB/time or any quota before connection; require an explicit purchase/payment flow when introduced, prevent surprise metered usage, and preserve a no-purchase diagnostic/direct mode. Operators choose reasonable quotas, eligible roles, data caps and capacity reservations. The public directory must clearly differentiate verified identity, independent reliability metrics, payment status and moderation reports. This roadmap does not launch billing or accept payments.

**Potential node roles (not yet commitments):** authenticated ingress gateway, restricted HTTPS/DNS exit relay, diagnostics/measurement node and later optional volunteer transit/peer assist. Roles may share software but must have independent permissions, credentials and quotas. Do not assume all roles require storing traffic, decrypting HTTPS, publishing a public IP, or exposing a home network. Operators select which roles and destinations to support; default role is narrow, inbound private/unexposed unless deliberately enabled, with explicit operator consent and abuse safeguards.

**Network limitations:** If the phone has no working physical link to a node, the app cannot generate connectivity from nothing. Some restrictive networks block the protocol or destination; the program should identify the failure, avoid infinite reconnect/data burn, and choose only authorized fallback options. Relays can change routing/queueing and improve effective task success in some conditions; they may also add expense, delay and privacy risk.

## Phase 0 — foundation and safe developer preview

**Goal:** Provide an understandable, independently buildable Android pre-alpha that does not unexpectedly route or transmit traffic.

- Android package, platform network information, selected-app UI, user-controlled diagnostic actions, VPN coexistence/readiness, safe consent flow, clear Stop affordance.
- Testable platform boundaries, deterministic Kotlin/Android unit tests, isolated loopback gateway tests, Android Lint and APK checksum/provenance from CI.
- English/Korean basics with future low-bandwidth-country localization needs, accessibility, low-end-Android performance budgets, useful error messages, visible limitations and an easy way to report redacted, opt-in diagnostics.
- Decide an open-source license and contribution/security process before describing the repository as OSS. Public visibility by itself is not a reuse license; decide independently whether the volunteer server software uses the same license.
- **Early preview lane:** offer opt-in, explicitly labelled experimental/diagnostic APKs with reproducible source SHA and known risks. No auto-activation of unfinished VPN functions.

**Exit:** Clean build and install/upgrade/rollback checks on actual Android; no implicit VPN capture, unselected-app capture or secret leakage; CI identifies exact source of APK. Physical checks remain **NOT RUN** until performed.

## Phase 1 — first real selected-app Internet transaction

**Goal:** One explicitly selected app makes a **real** HTTPS request through a protected, authenticated BetterNet transport and receives the actual reply, while all other apps are unaffected.

**Delivery slices (finish prerequisites in order):**

1. **Explicit selection and lifecycle:** one app identity, Android VPN permission and foreground-service operation, owned TUN, Stop/revoke/restart/other VPN checks, no implicit full-device fallback.
2. **Network and trust:** verified operator gateway on a chosen non-VPN Android `Network`; DNS on that network, protected and bound socket, authenticated encrypted tunnel, narrow allowed target/port and resource caps.
3. **Packet correctness:** DNS/DoT, IPv4 and IPv6 packet validation and responses, TCP/443 state and ACK/retransmission/FIN/RST, safe write failure handling, MTU and fragmentation policy, timeouts, resource boundedness and anti-loop checks.
4. **Real app test:** use a test browser/selected app and independently verified HTTPS endpoint, compare observed destination response with expected response, show that a different unselected app's traffic is not routed. Only promote supported protocols; UDP/QUIC, games and calls require their own future acceptance tests.
5. **Failure and recovery:** wrong DNS answer, failed TLS identity, expired gateway, network change, revoked VPN, background execution, abruptly lost gateway, interrupted TUN read, app upgrade/uninstall, and deliberate Stop; no silent privacy-policy bypass.

**Exit:** Physical Android trace and repeatable genuine selected-app HTTPS response, unselected-app non-capture, correct cleanup and failure cases; no open relay. A loopback simulated packet response is **not** A1 acceptance.

## Phase 2 — evidence-driven everyday reliability

**Goal:** Demonstrate that BetterNet can improve success and reduce real interruptions, and correctly decline to intervene when direct service is better.

- Run matched ON vs OFF/direct experiments with jitter, packet loss (burst and random), bandwidth limits, congestion, high RTT, brief outages and Wi-Fi/cellular changes; randomize order and repeat.
- First measure **browsers and messengers**; add **YouTube video playback** as the early explicit target with realistic streaming protocols/quality adaptation, then latency-sensitive calls/games after the required UDP/QUIC support exists. Test actual app compatibility rather than generalizing from a synthetic benchmark. Also test good/ordinary networks and compare against OFF/direct, not only worst-case impairments.
- Track task success, p50/p95/p99 stalls and latency, recovery time, retransmissions, traffic overhead, CPU, battery and metered-data cost. Measure adverse outcomes and show confidence/variation.
- Validate no needlessly long service wake locks, crash loops, connection leaks or costly probes; enforce stop/rollback.
- Release narrowly scoped **public GitHub experimental APK previews** where the specific supported flows pass physical tests. Clearly mark unsupported cases, provenance and known risks. Developer-only diagnostic builds may be shared earlier but must leave incomplete VPN forwarding disabled.

**Exit:** Reproducible repeat-run results and physical observations showing at least one real benefit; honest no-benefit/direct cases and regressions documented. No broad speed-up claims without evidence.

## Phase 3 — adaptive connectivity and transports

**Goal:** Automatically improve reliability where measurements justify it, while minimizing surprise and wasted resources.

- Per-path health, hysteresis, retry/backoff and circuit breaking, safe handover, resumable application operations where possible, and no accidental duplicate writes. Users can select Balanced, Stability-first, Latency-first, Data-saving or a documented Custom profile.
- Android Wi-Fi/mobile analysis; optional multi-network/multipath usage if platform permits, with selectable battery and metered-data preferences.
- Verified alternative transports (TCP/TLS, HTTP CONNECT and QUIC/HTTP3 where useful), UDP and HTTP/3 compatibility, and real-time application support through separate tests.
- Restricted-network handling based on measured connectivity, available paths and applicable laws/policies. No claim that every firewall or network block is bypassable.

**Exit:** A/B measurements improve tail latency, task completion or recovery under defined conditions; failover does not oscillate, leak data to prohibited routes or drain battery/data unexpectedly.

## Phase 4 — authenticated Linux/Ubuntu gateways and volunteer network

**Goal:** Let users choose independently operated relay nodes, rather than requiring a developer's home server.

- Container/service-managed Linux gateway with clear permissions, limited file/network access, dedicated service account, explicit bind, quotas, concurrency limits, health checks, logs with short retention, updates and safe restart.
- Node operator consent, verified node identity and signed metadata, token/key rotation and revocation, abuse reporting, authenticated clients and restrictive port/destination policy. **No unauthenticated public open proxy.**
- Initial user experience: **both** a vetted/signed directory and self-registered or manually added operators, with unverified operator nodes opt-in only. Display operator/trust level, fees/data rules, region and recent health in an honest way; distinguish authenticated identity from assurance of good behavior.
- Threat-model malicious exits, impersonation/Sybil nodes, correlated traffic, DNS/TLS manipulation, traffic logs, replay, abuse, resource exhaustion and censorship-network uncertainty. Design credential compromise recovery and removal of unsafe nodes.
- Volunteer opt-in is explicit. An exit node can attract abuse and network/hosting complaints; operators must be able to cap usage, stop participation and rotate identities. Multi-hop or P2P are future research candidates, not first-release requirements.

**Exit:** Test at least two independent **authorized** operator nodes, rotation/revocation and failure simulations, safe directory behavior and transparent visibility limits. Do not silently enroll any personal machine.

## Phase 5 — beta and stable product

**Goal:** Ordinary Android users understand, use and stop BetterNet without a developer, and its public claims match independent evidence.

- Simple one-control onboarding, app/server/path selection, selectable battery/metered presets, clear notifications, incident/status UX, accessible UI, visible daily/direct versus strict/block fallback, and readable redacted diagnostics. Guided versus expert UIs expose the same validated engine.
- Android version/OEM, background/reboot/permission/revoke, captive portal, dual-SIM/metered, TUN and other-VPN compatibility matrix.
- Release signing, dependency/security reviews, provenance, privacy/data policy, public license, documented support contact, repeatable regression and rollback procedure.
- Gradual **preview → limited beta → stable** rollout; keep debug APKs separate from signed beta/stable builds.

**Exit:** Signed review of device test matrix, privacy, threat model, support and rollback; no known critical leak, unauthorized capture or unbounded relay vulnerability. Real metrics, not hypothetical benefit.

## Phase 6 — optional cross-platform and broader participation

Windows/Linux clients, user-selected multiple apps or whole-device mode, advanced volunteer discovery, multipath, peer-assisted paths and further transport adaptations belong here when Android gates and portable protocols justify the investment. Do not postpone a useful Android release merely to support every platform in advance.

## Distribution and verification lanes

| Lane | Who can use it | Allowable claim | Safety gate |
| --- | --- | --- | --- |
| Developer/diagnostic APK | Early technical testers | App/network observations and explicitly chosen diagnostics | CI, version/checksum, no implicit VPN |
| A1 experimental path | Opt-in Android testers | Tested selected-app HTTPS subset, no more | On-device A1 pass, correct Stop/failure handling, trusted test gateway |
| Limited public beta | Interested users | Supported workloads with documented conditions and regressions | Repeated Phase 2 evidence, privacy and rollback |
| Stable | General users | Independently measured, explicitly supported capabilities | Phase 5 device/security/release gate |

For each APK document source SHA, signed/unsigned status, Android version, test device, checked route/protocol, known failures, potential data charges and what is **not** implemented. Never describe developer CI alone as proof of a working accelerator.

## Confirmed product decisions

1. **Connection fallback:** automatic/direct recovery for everyday use, but a separate explicit strict/privacy mode **blocks instead of silently using direct Internet**. The user can choose modes; detailed on-device copy and the default consent wording still need review.
2. **Server ecosystem:** both a curated verified/signed directory **and** independent self-registration/manual servers. Unverified nodes never inherit verified trust automatically; individual user/host consent remains mandatory.
3. **Initial apps:** browsers, messengers and YouTube/video are the first real-world categories. Support must still be proven separately for HTTP/3, QUIC, UDP, DRM and each Android app. Games/real-time calls remain long-term goals.
4. **Distribution:** interested users may publicly download experimental APK builds from GitHub, with clear test-only/unsupported labels. No unfinished network capture is implicitly enabled.
5. **User choice:** selectable battery, metered-data and speed/reliability/latency policies, with a low-effort automatic interface and separately guided and expert configuration. Ping/latency mode is **an example**, not a feature limit. Operator software also offers both simple secure defaults and explicit advanced configuration.
6. **Business model:** both free volunteer capacity and clearly identified optional donation-supported or paid relays are acceptable; costs and limitations must be understandable before opting in.
7. **Diagnostics:** default external reporting off; users may inspect, edit/redact and selectively send the exact report after separately confirming the recipient. Local review and no-send are first-class options.
8. **Trust governance:** curated trust needs project/community verification and revocation; registration is open but does not itself confer a verified badge.
9. **Scope and research:** BetterNet may grow into many useful Internet capabilities, including optional sharing/transfer features in the spirit of DataNetShare. BetterNet-private explores comparable goals privately, while public implementation and test evidence remain independent.

## Owner decisions still open

1. **Volunteer economics details:** whether to add financial transactions inside the application or only display operator-provided external pricing, supported payment intermediaries, dispute/refund and abuse policies, fair-use limits and currency/low-income accessibility.
2. **Node moderation implementation:** concrete community roles and accountability, signed directory hosting, review criteria, appeal handling and transparent operator trust expiry. Community review is approved in principle, not a fully specified process.
3. **Diagnostic retention:** explicit retention windows, optional report receiving service and access rules, data minimization/scrubbing specification, server logs and export/deletion controls. User review and opt-in are confirmed, but not a deployed backend.
4. **First concrete A1 test environment:** which safe Android test browser/messenger, gateway provider and independently controlled endpoint, plus Android min-version and inexpensive-device budget. Do not use a personal/home server without explicit consent.
5. **License/maintainership:** public client and volunteer gateway licenses, security reporting and community responsibilities. No license has been granted yet.
6. **Optional feature boundary:** first genuinely valuable sharing/transfer or general Internet utility to develop after real selected-app A1 verification; which APIs need future compatibility with DataNetShare without merging codebases.

Unresolved policies do **not** authorize activating a VPN, deploying a remote relay, using a home server, publishing personal details, transmitting telemetry or selecting a license.
