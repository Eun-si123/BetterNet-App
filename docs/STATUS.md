# BetterNet App — implementation and evidence snapshot

**Snapshot:** 2026-11-08. Source of truth is current GitHub code and exact-head CI; this dated file must be refreshed whenever a release/merge changes the conclusions. Not a live dashboard.

## Branch separation

| Place | State | What has actually been established |
| --- | --- | --- |
| `main` at `614fcb0` | `MAIN`, pre-alpha | Android network-state display, selected-app choice/readiness, basic JVM tests and debug APK CI; **no** VPN service or production gateway code in `main` at this snapshot |
| [Implementation Draft PR #7](https://github.com/Eun-si123/BetterNet-App/pull/7) at `eb6fd59` | `DRAFT PR`, not merged | Dormant selected-app VPN preparation, protected gateway TLS/CONNECT, DNS/TCP TUN primitives and restricted localhost reference gateway; exact-head [Android CI PASS](https://github.com/Eun-si123/BetterNet-App/actions/runs/42389436890), including isolated tests; **no** real selected-app public Internet success |
| [Product documentation Draft PR #11](https://github.com/Eun-si123/BetterNet-App/pull/11) | `DRAFT PR`, not merged at snapshot | Roadmap, decisions and documentation organization; does **not** ship user features |

Even if a test checks TCP packets, DNS replies, TLS authentication, retries, or a localhost gateway, its success alone does **not** show Android selected-app Internet forwarding. A debug APK generated from `main` does not contain pending PR #7 code. Likewise, a PR #7 test APK should never be described as the general-release application.

## Acceptance gate ledger

| Gate | Status | What will prove it |
| --- | --- | --- |
| A0 — safe Android foundation | `PARTIAL / MAIN` | Real-device install/UI/lifecycle checks, no implicit routing, build provenance and security review |
| A1 — verified selected-app HTTPS | `NOT RUN (DEVICE)` | Explicit Android VPN consent + chosen app completes independent HTTPS request via authenticated gateway, actual response verified, unselected app unaffected, safe Stop/revoke/failure |
| A2 — measurable user benefit | `NOT RUN` | Matched repeated OFF/ON *real workload* results for task success, latency, stalls, recovery, energy and bytes under specified conditions |
| A3 — adaptive path/transport | `PLANNED` | Proven decisions and no new instability, leaks or unexpected data costs |
| Built-in sharing module | `PLANNED`, no code yet | Opt-in app-local sharing, independent protocol, authentication, data integrity, resume/failures, no installation or runtime dependency on DataNetShare |
| Volunteer directory and paid/free nodes | `PLANNED`, no deployment | Authenticated trust and revocation, explicit operator consent, quotas, abuse protection and independent remote-node checks |
| User-reviewed diagnostic submission | `PLANNED`, no collection endpoint | Local preview, selectable/redactable exact payload, recipient/confirmation, no automatic upload and deletion/export verification |

## Near-term sequencing

1. Keep the next Android implementation focused on **A1 genuine selected-app HTTPS**, not optional modules or volunteer directory implementation.
2. Run failure/cleanup and selected-vs-unselected app tests on real Android with a separately approved safe test endpoint. Owner/tester has **not** completed physical A1 review.
3. Only once A1 is real, expand app coverage and assess what actually improves on good **and** bad networks. Use measured profiles, not marketing promises.
4. Develop optional built-in sharing and richer node selection behind their own user-permission, privacy and verification gates. No copying DataNetShare or BetterNet-private private source.

## Rules for status updates

Record: date, repository/ref/commit SHA, test environment, command or reproducible steps, real vs fixture endpoint, expected and observed results, pass/fail/blocked, unresolved risks, and whether traffic/credentials reached any external device. If unavailable, write **NOT RUN**, not “probably PASS.” Reconcile with current branch and tests before changing these entries.
