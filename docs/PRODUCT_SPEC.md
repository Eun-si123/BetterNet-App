# Product specification — BetterNet App

**Status: approved direction, not approved deployment or feature completion.** This spec refines [the roadmap](PRODUCT_ROADMAP.md); [Milestone A](MILESTONE_A.md) controls the next implementation acceptance gate.

## Problem and intended outcomes

People should use ordinary Internet services more dependably whether their network is fast, ordinary, heavily loaded, congested, expensive, intermittently reachable or heavily constrained. BetterNet is not defined by one trick (VPN, relay, lower ping, transfer, bypass): it is an extensible, **user-controlled Internet capability platform**.

**Prioritize Android first.** Make the default configuration simple, lightweight, and friendly to low-end phones and costly mobile-data plans. Advanced users may opt into individually measured capabilities. Longer-term Windows/Linux remains aspirational and cannot block an Android usable release.

## User journeys

| Persona/use | Desired outcome | Non-negotiable constraint |
| --- | --- | --- |
| Everyday user on weak/mobile Internet | Open a page, send a message or play a video with less disruption | Understand current status, turn off quickly, and avoid unexpected mobile charges |
| Low-resource phone/data-limited user | Keep useful connectivity with minimal background work | Small app footprint, explicit data/battery budget, no endless probes |
| Latency-sensitive user | Lower avoidable queueing and jitter where supported | Measure improvements vs direct, never promise impossible ping reductions |
| Expert user | Choose approved apps, paths, transports and resource rules | Security/permission gates do not become optional in expert mode |
| Volunteer/operator | Host narrowly scoped authenticated capabilities with easy setup | Not an open proxy; enforce caps, stop, trust status and abuse response |
| Optional sharer/receiver | Share selected files **inside BetterNet** without installing DataNetShare | Explicit peer consent, integrity and access controls; works independently |

## Experiences and functional requirements

- **Start/stop & consent:** Present supported apps, role of any gateway, network/cost policy, direct-vs-strict fallback and what traffic is affected. No implicit VPN start, whole-device capture, server enrollment or emergency invisible fallback.
- **Adaptive capabilities:** Suggest direct/no-tunnel when better. Provide an open-ended set of optional profiles/capabilities; latency-first, stability-first, balanced, data-saving and expert are starting examples, not a hardcoded feature universe.
- **Initial compatibility:** Real web browsers, messaging and YouTube/video tests take precedence over optional transfer/peer features. Individual UDP/QUIC/DRM requirements need separate actual evidence.
- **User-selectable footprint:** Each optional feature is controllable independently; its installation status, enablement, background cost and storage overhead are visible. Users can remove truly separately delivered capabilities without losing the basic app, while a mere disable switch must never be described as uninstalling code. The packaging strategy differs for public GitHub APKs and future Play-delivered modules; see [feature modules](FEATURE_MODULES.md).
- **Optional integrated sharing:** BetterNet owns the user-facing send/receive experience, independent protocol and updates. Sharing can be disabled or uninstalled as an internal optional package where feasible; absence of DataNetShare must not prevent basic use. No assumption of existing TeamForge/DataNetShare compatibility.
- **Operator selection:** Curated project/community-verified directory plus unverified self-registration/manual nodes. Trust level, observed quality, pricing, capacity and operator identity are distinct fields; user must see uncertainty.
- **Pricing and resources:** Free, voluntary donation and paid nodes may coexist. Users select battery, data, latency/stability preferences; no purchase, paid relay or mobile handover is triggered without transparent opt-in.
- **Diagnostics:** Show a locally inspectable report and exactly which recipient will receive it; allow selective redaction, no-send, and local export. No default background telemetry.

## Non-functional requirements

- **Safety:** Fail closed on missing app selection, expired consent, invalid node identity, TLS verification failure, revocation, and strict fallback. No inadvertent interception of unrelated apps.
- **Real-world resilience:** Test loss, delay, jitter, handover, restarts, capacity exhaustion and no usable path. The app cannot create Internet access from a physically nonexistent connection.
- **Reproducibility:** Version-bounded build, APK provenance, deterministic unit tests, network impairment comparisons, real-device traces and recorded failure cases. Declare `NOT RUN` honestly.
- **Privacy:** Do not export browsing payloads or private logs; disclose that exit operators may observe destination metadata, time and volume even with HTTPS. Explicit consent for optional reports.
- **Maintainability:** Feature-level boundaries and compatibility checks, not hypothetical plugin machinery or duplicated project code. Prefer independently testable primitives and one documentation owner per fact.

## First accepted milestone and exclusions

A1 succeeds only when a genuinely selected Android app gets an independently verified HTTPS response **through the protected authenticated BetterNet path** and a distinct unselected app's traffic remains outside it. A loopback gateway test and Android CI cannot replace device evidence. Until then, public experimental APKs are diagnostic builds with no unsupported active VPN functionality.

Not part of A1: high-throughput general VPN, arbitrary public exits, nonconsensual telemetry, DataNetShare source integration, payment processing, desktop ports, unlimited UDP/QUIC, anonymity guarantees, or an unsupported latency promise. These can become later opt-in proposals with their own risk and test gates.

Decisions approved by the owner versus policy questions still open are tracked in [the decision register](DECISIONS.md).
