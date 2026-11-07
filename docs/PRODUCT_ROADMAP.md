# BetterNet App — Android-first product roadmap

**Status:** draft product direction, 2026-11-08. This document proposes work; it does not indicate that features are implemented, deployed, released, or physically tested.

**Vision:** Make the *whole experience of everyday Internet use* more dependable under poor Wi-Fi/mobile coverage, congestion, packet loss, long latency, intermittent connectivity and restrictive networks. Include browsing, messaging, video, real-time calls and gaming as long-term workloads—not merely file downloads. Pursue **reliability, meaningful speed, and reachability together**. Do not claim universal acceleration, guaranteed continuity, anonymity, or guaranteed access through every restriction.

**Owner direction:** Android first. Keep the design portable so Windows/Linux and other platforms may follow, without delaying Android. Later support authenticated operator-run Linux/Ubuntu gateways and voluntarily operated relays. Make an experimental APK available to interested testers before the polished public beta, **without silently enabling unfinished VPN routing**. The owner has not yet decided the server enrollment/trust policy, traffic fallback policy, first priority apps, public license, or precise preview distribution rules.

## Current verified boundary

The repository's default branch remains **pre-alpha**. Draft [PR #7](https://github.com/Eun-si123/BetterNet-App/pull/7) has substantial dormant single-app VPN, TLS/CONNECT, DNS/TCP, lifecycle and isolated gateway test development. Successful CI and localhost TLS tests do **not** prove that an Android app can browse through BetterNet. No physical A1 selected-app HTTPS completion, production relay deployment or general-purpose acceleration is verified. Do not count those as complete.

This roadmap adds product detail to [Milestone A](MILESTONE_A.md). A0–A3 in Milestone A remain the *immediate technical acceptance gates*. Later phases below are candidates, not commitments to expose server infrastructure or roll out traffic interception.

## Product rules

- **A direct path can win.** Compare the same workload OFF/direct and ON/BetterNet; when tunnelling costs more, loses reliability or adds delay, do not pretend an improvement. A user-visible route/quality decision is preferable to automatic blind tunnelling.
- **Fail safely before extending scope.** First support exactly one explicitly selected Android app; never route all apps on a missing selection. Expand to multiple apps, optional whole-device and other platforms only after the respective checks. Respect Android VPN consent, coexistence and notification-based Stop.
- **No default personal server.** Never hardcode or deploy to a contributor's home server, address, account, DDNS domain or personal network as a product dependency. Test with throwaway loopback networks or a separately consented, operator-controlled test node.
- **Honest privacy boundary.** Encrypt/authenticate clients and gateways, protect/bind sockets to the intended underlying network, and verify appropriate TLS destination identity. A volunteer exit operator may observe destination metadata, time and traffic volume even for HTTPS; disclose that. No payload collection or background telemetry by default.
- **Measured resource costs.** Reliability cannot come at unbounded battery, CPU, data or relay costs. Let users choose trade-offs, especially on metered networks.
- **Independent public development.** Do not copy private BetterNet research source/config/identifiers, or export private logs and credentials into the public app without explicit source, license and privacy review.
- **Evidence-based phases.** Record every actual test environment, unsupported protocol, known failure, performance baseline and rollback. Successful CI is not device-level acceptance. PR counts are not a progress metric.

## Phase 0 — foundation and safe developer preview

**Goal:** Provide an understandable, independently buildable Android pre-alpha that does not unexpectedly route or transmit traffic.

- Android package, platform network information, selected-app UI, user-controlled diagnostic actions, VPN coexistence/readiness, safe consent flow, clear Stop affordance.
- Testable platform boundaries, deterministic Kotlin/Android unit tests, isolated loopback gateway tests, Android Lint and APK checksum/provenance from CI.
- English/Korean basics, accessibility, useful error messages, visible limitations and an easy way to report redacted diagnostics.
- Decide an open-source license and contribution/security process before describing the repository as OSS. Public visibility by itself is not a reuse license.
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
- First measure browsing, messaging and uploads; then video stalls/start time and latency-sensitive calls/games after UDP support exists. Test actual app compatibility rather than generalizing from a synthetic benchmark.
- Track task success, p50/p95/p99 stalls and latency, recovery time, retransmissions, traffic overhead, CPU, battery and metered-data cost. Measure adverse outcomes and show confidence/variation.
- Validate no needlessly long service wake locks, crash loops, connection leaks or costly probes; enforce stop/rollback.
- Release narrowly scoped **opt-in technical previews** where the specific supported flows pass physical tests. Clearly mark unsupported cases.

**Exit:** Reproducible repeat-run results and physical observations showing at least one real benefit; honest no-benefit/direct cases and regressions documented. No broad speed-up claims without evidence.

## Phase 3 — adaptive connectivity and transports

**Goal:** Automatically improve reliability where measurements justify it, while minimizing surprise and wasted resources.

- Per-path health, hysteresis, retry/backoff and circuit breaking, safe handover, resumable application operations where possible, and no accidental duplicate writes.
- Android Wi-Fi/mobile analysis; optional multi-network/multipath usage if platform permits, with selectable battery and metered-data preferences.
- Verified alternative transports (TCP/TLS, HTTP CONNECT and QUIC/HTTP3 where useful), UDP and HTTP/3 compatibility, and real-time application support through separate tests.
- Restricted-network handling based on measured connectivity, available paths and applicable laws/policies. No claim that every firewall or network block is bypassable.

**Exit:** A/B measurements improve tail latency, task completion or recovery under defined conditions; failover does not oscillate, leak data to prohibited routes or drain battery/data unexpectedly.

## Phase 4 — authenticated Linux/Ubuntu gateways and volunteer network

**Goal:** Let users choose independently operated relay nodes, rather than requiring a developer's home server.

- Container/service-managed Linux gateway with clear permissions, limited file/network access, dedicated service account, explicit bind, quotas, concurrency limits, health checks, logs with short retention, updates and safe restart.
- Node operator consent, verified node identity and signed metadata, token/key rotation and revocation, abuse reporting, authenticated clients and restrictive port/destination policy. **No unauthenticated public open proxy.**
- Initial user experience: manually added operator-controlled servers or a vetted signed directory (pending owner decision). Display operator/trust level, fees/data rules, region and recent health in an honest way; distinguish authenticated identity from assurance of good behavior.
- Threat-model malicious exits, impersonation/Sybil nodes, correlated traffic, DNS/TLS manipulation, traffic logs, replay, abuse, resource exhaustion and censorship-network uncertainty. Design credential compromise recovery and removal of unsafe nodes.
- Volunteer opt-in is explicit. An exit node can attract abuse and network/hosting complaints; operators must be able to cap usage, stop participation and rotate identities. Multi-hop or P2P are future research candidates, not first-release requirements.

**Exit:** Test at least two independent **authorized** operator nodes, rotation/revocation and failure simulations, safe directory behavior and transparent visibility limits. Do not silently enroll any personal machine.

## Phase 5 — beta and stable product

**Goal:** Ordinary Android users understand, use and stop BetterNet without a developer, and its public claims match independent evidence.

- Simple onboarding, app/server/path selection, battery/metered presets, clear notifications, incident/status UX, accessible UI, safe fallback choice and readable diagnostics.
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

## Owner decisions not yet locked in

1. **Traffic fallback:** server/network drop should (a) connect directly, (b) block until recovered, or (c) ask/show a selectable policy. Direct fallback may defeat a privacy expectation, so never silently impose it.
2. **Node trust and selection:** manual servers, an audited/approved signed directory, or both; acceptance/revocation criteria for volunteer operators; how to identify unverified nodes.
3. **First workloads and devices:** Android apps/categories for A1/A2 acceptance; Android minimum OS and supported devices; whether browser, messenger, video or game tests come first.
4. **Early APK distribution:** public GitHub prerelease or invite-only track, warning copy and tester feedback scope. Owner also needs to choose a public license and server software openness policy.
5. **Trade-offs:** allowed extra mobile data/battery for reliability and how to handle metered networks, cellular background traffic and battery saver.

These questions are open design decisions. They do **not** authorize activating a VPN, deploying a remote relay, using a home server, publishing personal details, transmitting telemetry or selecting a license.
