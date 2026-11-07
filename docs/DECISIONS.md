# Product and engineering decision register

**Updated:** 2026-11-08. `CONFIRMED` means the user selected a direction, **not** that code or a deployment exists. `PROPOSED` is a recommendation only. Keep this short: detailed requirement belongs in [the specification](PRODUCT_SPEC.md), evidence in [status](STATUS.md), and test criteria in [verification](TEST_STRATEGY.md).

## Confirmed by the project owner

| ID | Decision | Rationale / scope |
| --- | --- | --- |
| DEC-001 | **Android first**, desktop later | Deliver usable phone experience before broad platform work |
| DEC-002 | Broad Internet capability product | Bad networks matter, but also optimize ordinary/good networks; gaming, messaging, browsing, streaming and future tools are legitimate candidates |
| DEC-003 | Simple automatic + guided + expert configuration | Users and server operators choose desired complexity; profile examples are not a fixed feature limit |
| DEC-004 | Direct fallback for daily mode; block for strict mode | User can choose; blocked mode cannot be promised leakproof without real Android OS verification |
| DEC-005 | Curated/verified **and** community/self-registered/manual node paths | Trust is independent from registration; project/community reviews and revocation required for curated mark |
| DEC-006 | Free volunteer, optional donation-supported and optional paid nodes | Disclose cost and quotas; no paid server purchase or billing launched by this decision |
| DEC-007 | Diagnostics are optional, previewable and user-editable before send | Default no external telemetry; separate confirmation of exact recipient and report contents |
| DEC-008 | Early public GitHub experimental APK | Clearly mark pre-alpha/unsupported functions, never auto-start unfinished VPN |
| DEC-009 | User-selectable battery, data and optimization trade-offs | No forced extra background/mobile spending; latency-only is one possible policy |
| DEC-010 | Initial real-world Android workloads: browsers, messengers, YouTube | HTTP/3/UDP/DRM/other protocols require independent tests |
| DEC-011 | **Built-in optional sharing/transfer inside BetterNet** | No separate DataNetShare app/server dependency; maintain independent public implementation and modular boundaries |
| DEC-012 | BetterNet-private = separate research/experiments; BetterNet-App = public product | Similar broad purpose; no automatic copying private code, settings, identities, logs, protocols or test evidence |
| DEC-013 | **User-controlled feature enable/disable and storage footprint** | Do not force everyone to install or run every optional capability. Separate runtime OFF from physical component removal; only promise space savings when delivery can actually omit/remove installed bytes |

## Recommended engineering defaults (not owner approvals to deploy)

- Preserve smallest coherent A1 implementation first; first prove a real selected Android app's HTTPS response, not merely packet parsing.
- Use strict per-app permission and authenticated transport; unverified volunteer nodes are opt-in. Do not automatically enroll any personal infrastructure.
- Prefer direct when measured better. No guaranteed ping improvement; prioritize actual p95 reliability and user outcome.
- Build a limited first-party capability module only once there is a real supported use case; no arbitrary third-party code execution by default.
- Separate preview, beta and stable releases; maintain accessible signed artifacts, privacy policy and rollback criteria.

## Open decisions (must not be inferred)

| ID | Question / decision maker | Work that must wait |
| --- | --- | --- |
| OPEN-001 | Client and operator-server licenses; owner | OSS claims, licensing and relicensing obligations |
| OPEN-002 | User-visible terms, payment processor, fees/refunds and regions; owner + operator policy | Billing and paid node transaction code |
| OPEN-003 | Exact community verifier roles, appeals, directory keys/hosting, moderation retention; owner + community governance | Trust badges and production public node directory |
| OPEN-004 | Diagnostics schema, maximum on-device/remote retention and exact optional recipient/collector; owner + privacy review | Any telemetry receiving endpoint or automatic upload |
| OPEN-005 | Approved actual Android test devices, separate non-personal test gateway, first browser/app/test host and OS support; owner/testers | A1 device PASS, live relay deployment or public active VPN preview |
| OPEN-006 | Prioritized sharing first release: same-LAN, authenticated remote relay, or both; owner/user research | First sharing transfer protocol design and network privileges |

## How to change a decision

Record who approved it and when, affected privacy/cost/security scope, alternatives considered, change to the acceptance gate and evidence needed. Keep unresolved choices explicitly **OPEN**. If a new choice conflicts with a confirmed one, ask the owner before altering behavior; a speculative PR or scheduled agent is not a user approval.
