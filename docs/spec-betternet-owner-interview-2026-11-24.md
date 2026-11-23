# BetterNet — owner interview specification (Q1–Q23)

> **Date:** 2026-11-24 (KST) · **Status:** owner-confirmed product direction, **not** implementation or deployment approval.
> **Baseline:** `Eun-si123/BetterNet-App` `main` at `cdf4257fbf2007b9fc928d6957c943b933a7f56b` when reviewed; `BetterNet-private` is a separate, private research workspace.
> **Authority:** This is the durable source for the 23-question owner interview. [PRODUCT_SPEC.md](PRODUCT_SPEC.md) remains the canonical product summary, [DECISIONS.md](DECISIONS.md) the confirmed/open register, [MILESTONE_A.md](MILESTONE_A.md) the next engineering acceptance gate, and [STATUS.md](STATUS.md) the evidence ledger. If the code or these dated snapshots disagree, inspect the actual branch and tests; **do not** infer that a planned feature is shipped.

## Product intent and success

**Owner's aspiration:** Make BetterNet useful worldwide—especially where connectivity is extremely slow, unstable, costly or restricted—without limiting it to a VPN, a ping booster or one tool. Its name should reflect a meaningfully better Internet experience. The product must also have a use on healthy networks through user-selected, optional Internet capabilities.

**Primary user outcome:** A person can complete a real, important Internet task that would otherwise fail or be prohibitively slow, or demonstrably complete it more reliably, responsively or economically. BetterNet cannot create a physical network path from nothing, guarantee censorship circumvention or universally decrease ping.

Four complementary success pillars, **not interchangeable scores**:
1. **Usability under severe conditions:** real browsing, messaging, communication, download and other supported tasks survive the conditions that are technically addressable.
2. **Measured benefit:** compare the same workload with BetterNet OFF/direct and ON, including worse outcomes and byte/energy costs; prioritize completion and recovery over vanity metrics.
3. **User agency:** an accessible recommendation-based default alongside opt-in modules, customizable dashboard, per-app/per-feature policies and explicit removal where actual packaging permits.
4. **Trust and reach:** safe operation, privacy controls, understandable explanations, low-resource accessibility, optional free/community/self-hosted participation and staged real-world adoption.

**Principle:** “Support everything” in the interview means **keep the architecture extensible and test useful features separately**; it does *not* require simultaneous development, shipping every mode, silently granting permissions, bypassing a budget or declaring all features supported.

## Interview coverage and traceability

| Question | Owner's answer / additional nuance | Interpretation and status |
| --- | --- | --- |
| Q1 · Identity | D: customizable combination | Long-term modular Internet-capability platform; **direction confirmed** |
| Q2 · First run | B: recommended starter + user choice | Lightweight safe default; add/remove features intentionally; **confirmed** |
| Q3 · Initial value | A+C: real connectivity plus analysis/control | Real network path and explainable local diagnostics; **confirmed** |
| Q4 · Home UI | D: user-customizable home, different user preferences | Editable widgets/shortcuts with useful defaults; **confirmed direction**, UI not built |
| Q5 · Automatic switch | B: only within preauthorized budget; freely configurable | Explicit metered/battery/path consent; no unauthorized switching; **confirmed** |
| Q6 · Packaging | C: lightweight now, genuine modularity later; **GitHub only for now** | No present Play dependency or promise that an APK toggle removes code; **confirmed channel**, future packaging open |
| Q7 · Nodes | C: self-hosted + public, but owner unsure about operational detail | Both paths intended; governance/first pilot still **open** |
| Q8 · Other VPNs | C: use compatible functions alongside an existing VPN; wider compatibility desirable | No silent VPN replacement/bypass; integration research later; **confirmed direction** |
| Q9 · First workload | A browser first, but all real tasks eventually; extreme low-resource regions matter | A1 real Android browser HTTPS first; no permanent browser-only scope; **confirmed** |
| Q10 · Bad conditions | A+B+C+D: slow, intermittent, high-loss/high-RTT, restricted | Separate and compound impairment profiles; **confirmed coverage**, not support claims |
| Q11 · Offline | D in the long run; online implementation **first** | Prioritize live connectivity; design durable checkpoints early; advanced offline later |
| Q12 · Resource tradeoffs | A+B+C+D: economy, balanced, performance, per-app customization | Mutually exclusive presets / applicable overrides, **not** all active simultaneously |
| Q13 · Unverified exits | B with C+D: warn and let user decide; verify servers via official tools | Explicit consent for unverified nodes; automatic discovery defaults to curated; trust details unresolved |
| Q14 · Server verification | D: phased external, owner-run, optional agent | Consent-based limited checks; **no covert access/backdoor**; attestation not proof of malware absence |
| Q15 · Operator policy | C as base, owner also values A–D | Operator-authorized role/purpose quotas, safe default, optional wider support |
| Q16 · Logs and privacy | A+B+C+D + optional Tor-like privacy approach | Aggregate minimum, bounded security logs, explicit diagnostic opt-in, disclosed policy; anonymous routing separate research |
| Q17 · Privacy threats | A+B+C+D: operator, ISP/Wi-Fi, websites, censorship | Threat-model **separately**; no false promise one mode solves all |
| Q18 · Lightweight web | D: several supported approaches; start with easier things | First ordinary HTTPS; later opted-in browser-based simplification; no silent TLS MITM |
| Q19 · Bandwidth | D: automatic priority + user override | No unbounded starvation or unsupported control outside app/OS authority |
| Q20 · Risk policy | D, with A+B+C selectable | Stable / balanced / aggressive / per-app policies, trial-and-rollback within safety bounds |
| Q21 · Economics | D: volunteer, free, donation, paid, self-hosted | Transparent cost/quota; **billing and licenses not approved** |
| Q22 · Release | A is essential; “all” adds experimental, staged and feature-level gates | High safety bar for active routing; diagnostic-only GitHub preview may be earlier, clearly labeled |
| Q23 · Success | A+B+C+D; aspiration: BetterNet spread worldwide | Real outcomes + evidence + customization + trust and accessibility, not mere marketing/reach |

## Experience contracts

### Onboarding, dashboard, and feature management

- Start with **recommended simple mode** and a functional, lightweight local status screen. Never require a user to select protocols before seeing basic status.
- Provide a **customizable dashboard** of supported, actually available measurements and features; allow reorder/show/hide without hiding emergency Stop, current routing/privacy status, network/data-cost warning, or consent revocation.
- Features have distinct states: **not installed**, **installed but OFF**, **ON**, and **unavailable/unsupported**. Show dependencies, permissions, background cost, storage cost and cancellation effects. OFF stops work; it does not magically shrink an APK.
- **Current distribution: GitHub APK only.** Keep the base APK lean. Do not assume Google Play Dynamic Feature Delivery. Evaluate signed Lite/Full variants or an audited split delivery **only when needed** to remove executable bytes; separately downloadable non-executable resources may be offered with integrity and explicit consent. Never add an arbitrary remote-Dex/plugin loader as a shortcut.
- Removing an optional feature must stop tasks/receivers and revoke its grants without silently deleting user-created documents. Preserve user settings or request explicit deletion consent. Verify genuine installed-byte savings and update/reinstall compatibility.

### Network adaptation and resource budgets

- Offer resource-saving, balanced and performance-oriented profiles, plus per-app/per-feature overrides **where Android and the actual forwarding implementation permit them**. Start with conservative **balanced** defaults.
- Suggested effective decision priority: **OS/security and authentication invariants > user consent, strict/no-leak intent, operator authorization and hard data limits > explicit per-app/path preferences > automatic optimization > observed quality preference**. An override cannot waive hard gates.
- Any paid/metered cellular transition requires advance user permission and a bounded, visible budget. Auto must not spend unexpected mobile data or bypass an existing VPN/default-network policy.
- Apply measured bounded trial → compare → promote/revert; hysteresis/cooldown prevents path flapping. Keep fallback visible. Daily-use direct fallback may be permitted by consent; strict mode must not silently direct-fallback and **cannot be advertised as leakproof** until OS lockdown/crash/reboot tests pass.
- Respect latency-sensitive interactive work while retaining bounded progress for necessary background work. Only control flows BetterNet legitimately owns; don't claim arbitrary traffic shaping on unrelated apps.
- A VPN coexistence conflict should preserve compatible non-VPN capabilities and explain the choice. Never silently disable a third-party VPN or take whole-device traffic.

### Workload, severe networks and online/offline boundary

- **A1**: one explicitly selected real Android browser completes a genuine HTTPS request via an authenticated, bounded BetterNet path; a different app remains unaffected. This is the first product proof—not just TLS handshake or localhost tests.
- **A2**: compare OFF/ON real browsing first, then messaging, video, games/voice and different protocols **only after their own verification**. Measure both favorable and negative effects on good and impaired networks.
- Include individually and jointly: very low throughput (illustrative 50/100/200 kbit/s), high RTT/jitter, random/burst loss, periodic disconnections, network handovers, and reachable-but-restricted protocols. These values are **test proposals**, not demonstrated device performance or promises.
- Connection loss: safe Stop and reconnection first; provide resume/checkpoints for **BetterNet-owned** durable work after validated identity/state/integrity checks. Arbitrary third-party HTTPS actions cannot be assumed resumable.
- Rich offline queues/caches, lightweight browsing and content simplification are **later, opt-in** capabilities after online A1/A2. Never modify, decrypt or store another application's end-to-end encrypted payload without legitimate support/consent.

### Nodes, operators and privacy

- Support vetted directory plus user-added self-hosted/community nodes. **Manual registration is not a trust badge.** Default automatic picks curated nodes only; disclose unverified status and require explicit user opt-in.
- Server operators may choose authenticated roles (restricted relay, approved Internet exit where permitted, diagnostics, transfer), destination/protocol limitations, clients, concurrent sessions, quotas, logging and Stop. No unrestricted public proxy or publicly reachable default listener.
- **Official verification levels**: external authenticated/protocol/health checks → operator-run signed integrity/config inspection → opt-in limited monitoring agent. Every level reports scope, time, limitations and revocation. No unauthorized command execution, covert persistence or claim that any verifier proves a system malware-free. Treat self-reported proofs as weaker than independent evidence.
- **Privacy levels**: aggregate operational statistics by default; narrowly scoped, time-limited security logs only when justified and disclosed; detailed client diagnostics require review of exact fields/recipient and separate consent, with no unsolicited upload. Operator-specific policy and actual retention must be visible before selection. An operator can independently record metadata, so an app toggle cannot guarantee universal no-logging.
- **Privacy/anti-censorship options** (including possible existing Tor ecosystem integration) are research candidates with separately modeled threats, compatibility, latency, cost and exit/website tracking limits. No guaranteed anonymity, anti-fingerprinting, unblockability or zero metadata.
- Free, donated, paid and self-operated nodes may coexist with prices, caps, region and trust displayed independently. The decision does **not** approve any payment integration, official hosted exit, or globally available service.

## Verification and safe-release contract

| Gate | Required evidence | Not established by documentation |
| --- | --- | --- |
| A0 · local safe base | Exact-source Android build/CI + physical install/UI/lifecycle + no traffic capture without consent | Installation or VPN success merely from APK build |
| A1 · real browser HTTPS | Selected-app physical Android end-to-end request through authenticated destination path; correct response, second app excluded, negative TLS/DNS/IPv4/IPv6/MTU/revoke/Stop tests | Local loopback TLS, synthetic echoes, TUN parsing, Draft PR code |
| A2 · useful improvement | Matched randomized/repeated OFF/ON task outcomes, success/recovery p50/p95/p99, jitter/loss, bytes/energy/CPU, worsening cases and cost on healthy+compound poor profiles | One impressive synthetic percentage |
| A3 · safe Auto | Stable decision rules, observed fallback/revert, flapping/strict/consent/budget/third-party VPN negative tests on appropriate devices | A policy diagram or shadow-only recommendation |
| Separate optional capabilities | Feature-specific permissions, integrity, disabling, storage footprint, failures and real-device UX | Existence of a checkbox or source module |
| Server/community/privacy release | Operator consent, auth, quota, independent trust checks, revocation, data retention, malicious-node response and disclosed limitations | A self-hosted node or self-signed clean scan |
| GitHub release readiness | Signed/provenanced APK, clear diagnostic-preview vs active-routing distinction, reproducible rollback, privacy/security review and actual physical acceptance | Uploaded APK and successful CI alone |

**As reviewed:** Public `main` is pre-alpha; A1 physical selected-app Internet success is **NOT RUN**, A2 not established, A3 prospective. Draft PR #7 contains substantial dormant isolated implementation but must not be presented as a live release. `BetterNet-private` experimental evidence cannot be counted as public-app acceptance or copied without separate source/license/privacy review.

## Design challenge / pre-spec risk review (not an independent adversarial audit)

| Severity | Tension or failure scenario | Required disposition |
| --- | --- | --- |
| Critical | “All features” delays the first real working connection indefinitely | **Resolve by stages:** online A1/A2 first; everything else separately gated |
| Critical | Strict privacy profile silently leaks on Android process crash | **Unresolved OS gate:** no strict/leakproof public claims until supported OS lockdown and device matrix verified |
| Critical | Unvetted exit or dishonest “clean scan” hides malicious operator activity | Consent + limited verification levels; no absolute trust claim, keys/revocation/reputation procedure needed |
| Major | GitHub single APK advertises per-module code removal | Distinguish OFF vs removal; no space-saving claim without real packaging proof |
| Major | Multi-route aggressive mode burns mobile data or breaks active sessions | Bounded consent, hard budgets, per-app authority, rollback and end-to-end transition tests |
| Major | Minimal/no logs conflicts with abuse investigation and payment disputes | Publish a bounded policy per node; separate client diagnostics from operator logs; retention still open |
| Major | Tor-like option slows fragile networks or gives false anonymity | Optional only; document threat models, compatibility and actual negative outcomes |
| Major | Too many settings make novice experience unusable | Recommendation-first, progressive disclosure, measured default widgets and accessible always-visible Stop |
| Major | Community exits become abusive open proxies and cost operators money | Role scope, authentication, limits, operator consent and abuse/revocation process |

**Open governance and product decisions:** `OPEN-001` licensing; `OPEN-002` billing/regions/refunds; `OPEN-003` verifier roles, directory key custody/appeals; `OPEN-004` exact retention/report recipient; `OPEN-005` separately approved physical Android/gateway test setup; `OPEN-006` sharing's first LAN/remote scope. Also open: precise GitHub executable-module distribution/removal solution; privacy routing threat-model and supported protocol matrix; accessibility/localization and deployment funding. **No question here authorizes deploying a home node, collecting new data, charging users, merging Draft code or shipping a VPN.**

## Decisions Log

| ID | Topic | Decision | Rationale | Source | Date |
|---|---|---|---|---|---|
| D1 | Q1 product identity | Customizable modular Internet-capability platform | Not one-purpose VPN or booster | Interview | 2026-11-24 |
| D2 | Q2 onboarding | Recommended safe starter; opt-in optional features | Novice usability and choice | Interview | 2026-11-24 |
| D3 | Q3 initial value | Real connectivity plus explanation/control | Usability and transparent decisions | Interview | 2026-11-24 |
| D4 | Q4 home | Customizable dashboard; essential safety/status persistent | Users value different functions | Interview | 2026-11-24 |
| D5 | Q5 route switch | Automatic only inside user-approved budgets | Prevent surprise data/cost/policy bypass | Interview | 2026-11-24 |
| D6 | Q6 distribution | Lightweight **GitHub APK now**; real modular packaging later | No present Play reliance; storage truth | Interview | 2026-11-24 |
| D7 | Q7 nodes | Self-hosted and public nodes intended; operating details open | User choice, uncertain governance | Interview | 2026-11-24 |
| D8 | Q8 VPN coexistence | Preserve compatible features; no silent replacement | Respect existing VPN authority | Interview | 2026-11-24 |
| D9 | Q9 first workload | Real Android browser first, broader workload later | First verifiable user outcome | Interview | 2026-11-24 |
| D10 | Q10 hostile networks | Cover slow, interrupted, lossy/high-RTT, restricted | Diverse and combined real-world failures | Interview | 2026-11-24 |
| D11 | Q11 offline | Online before advanced offline; keep future resume boundaries | Fast path to usable product | Interview | 2026-11-24 |
| D12 | Q12 resource profiles | Economy/balanced/performance/custom; user overrides | Different budgets and contexts | Interview | 2026-11-24 |
| D13 | Q13 unverified node | Clear risk/consent, manual opt-in and official review candidates | Choice with honest trust | Interview | 2026-11-24 |
| D14 | Q14 verification | External → owner-run → optional monitor, consent and bounded authority | Avoid backdoor-like “official” control | Interview | 2026-11-24 |
| D15 | Q15 operator control | Operator-defined authenticated scopes and roles, safe defaults | Avoid abuse and open proxy | Interview | 2026-11-24 |
| D16 | Q16 log policy | Minimum aggregates + bounded security logs + opt-in detail + node policy | Privacy and accountable operation | Interview | 2026-11-24 |
| D17 | Q17 privacy aims | Operator/ISP/website/restriction threats; opt-in dedicated approaches | Different threats demand different solutions | Interview | 2026-11-24 |
| D18 | Q18 lightweight browsing | Preserve original path first; opt-in simplification later | Easy verified steps before hard features | Interview | 2026-11-24 |
| D19 | Q19 traffic priority | Adapt automatically under explicit per-app priorities | Protect responsiveness without taking away control | Interview | 2026-11-24 |
| D20 | Q20 optimizer risk | Stable/balanced/aggressive choices with bounded rollback | Control experimentation and failure impact | Interview | 2026-11-24 |
| D21 | Q21 node economics | Volunteer/free/donation/paid/self-hosted coexist | Accessibility and operator sustainability | Interview | 2026-11-24 |
| D22 | Q22 release | High bar for active core; distinguish experimental and feature-by-feature release | Avoid shipping unsafe Internet routing | Interview | 2026-11-24 |
| D23 | Q23 success | Real extreme-network usability, measurable benefit, customization and trust; worldwide ambition | Define success by people and outcomes | Interview | 2026-11-24 |

## Dependency Graph & Implementation Order

```text
GitHub-only small safe Android base (A0; current pre-alpha)
      |
      v
A1: one selected browser -> real DNS/TCP/HTTPS -> bounded authenticated gateway
      |                                |
      |                                +-> independent destination response / unrelated app exclusion
      v
A2: same real tasks OFF vs ON -> impaired + ordinary profiles -> honest result
      |
      v
A3: consent/budget-aware Auto policy -> revert, explain and stop
      |
      +----> modular dashboard + validated per-feature settings / packaging evidence
      +----> operator node pilot -> role/auth/quota -> verification/curated directory
      +----> other verified workloads (messenger/video/UDP/game/voice)
      +----> BetterNet-owned durable jobs -> optional sharing -> later richer offline
      +----> optional privacy-routing research -> separate threat model and evidence
      |
      v
Staged GitHub release gates -> independent real-user evidence -> wider participation
```

**Implementation order of record:** [Milestone A](MILESTONE_A.md) A0 → A1 → A2 → A3; later milestones must create their own independent acceptance checks. Preserve private/public separation and do not use this interview to skip actual Android tests. See [verification](TEST_STRATEGY.md), [security](SECURITY_PRIVACY.md), [modules](FEATURE_MODULES.md) and [server policy](SERVER_NODES.md).
