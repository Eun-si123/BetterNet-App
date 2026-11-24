# BetterNet App — verified implementation snapshot

**As of:** 2026-11-24 (KST). This is a dated evidence ledger, **not** a live
dashboard. GitHub branch heads, Actions and physical device evidence take
precedence over this snapshot.

## Branch separation and source truth

| Location | State | Verified limitations |
| --- | --- | --- |
| Public main at 9ee93d3 | Pre-alpha baseline | Does not include A1 experimental VPN; PR #21 CI recovery merged |
| [A1 implementation Draft #7](https://github.com/Eun-si123/BetterNet-App/pull/7) at 4637073 | Unmerged | Restricted gateway and TUN components; not device-proven |
| [Explicit debug start Draft #20](https://github.com/Eun-si123/BetterNet-App/pull/20) at 82d1277 | Stacked on #7 | Consent-based, memory-only, one-use test start; no device proof |
| [A1 stability Draft #22](https://github.com/Eun-si123/BetterNet-App/pull/22) | Stacked on #20 | Network pin, dual-stack TCP, browser DNS, 120s/8 MiB limits, and opt-in local event diagnostics; at this source revision 356 local JVM PASS at f11d171; crossed TCP regression under review; device NOT RUN |
| [TCP-focused Draft #19](https://github.com/Eun-si123/BetterNet-App/pull/19) | Its fix is integrated into #22 | Preserve as focused review; do not separately double-merge |

These pending PRs are **not** on main and are **not** releases. The exact
latest SHA and GitHub CI must be rechecked before claiming any new pass.

## Milestone acceptance ledger

| Milestone | Status | Missing acceptance proof |
| --- | --- | --- |
| A0 — Android foundation | PARTIAL | Physical install/UI and no-implicit-VPN |
| A1 — selected-app real HTTPS | NOT RUN (DEVICE) | Approved gateway, actual browser HTTPS reply, unrelated app not captured, Stop/revoke/timeout |
| A2 — measurable network improvement | NOT RUN | Matched repeated OFF/ON workload in good and impaired networks |
| A3 — adaptive paths and fallback | PLANNED | User-controlled decision, failure behavior and non-regression |
| Built-in sharing and optional modules | PLANNED | Permission, compatibility and data integrity checks |
| Community relays | PLANNED | Trust, opt-in, quotas, authentication and abuse protection |
| User-reviewed diagnostic submission | PLANNED | Local preview/redaction and explicit send consent |

## Reproducible A1 draft evidence

At previously verified source f11d171 in the controlled Ubuntu mini-PC environment:
- 356 Android JVM tests PASS, 0 failures/skips (33 suites)
- Android Lint and debug/unsigned release APK build PASS
- VPN merged manifest and APK high-confidence secret scan PASS
- Documentation checks and 28 Python script unit tests PASS; gateway tests 9 PASS
- Disposable Linux loopback tests 9/9 baseline + 9/9 under 25±5 ms
  delay and 3% loss PASS
- GitHub Android CI and feature-contract CI passed on f11d171; subsequent heads need independent verification

**No connected Android test handset, no approved external gateway test,
no real HTTPS browser traffic, and no unrelated-app isolation proof.**
All these results remain local fixture or static/build evidence. A passing
GitHub Actions run would not establish A1 DEVICE PASS.

## Optional A1 debug event evidence (unmerged review)

A1 Draft #22 now also proposes a process-only 64-code event journal with
manual View, Copy and Clear controls in **debug builds**. Every entry is an
enum code and approximate relative seconds, not a token, endpoint, app name
or packet. Nothing is automatically sent, saved or copied. The user can
inspect the exact text before deciding to copy it to the Android clipboard.
This is review/fixture evidence only, **not** hardware verification of the
real browser/tunnel lifecycle.

## Read-only test-phone preflight

From the repo root, on Windows or Linux with Python and Android platform-tools:

    python scripts/a1_android_preflight.py

Pass --adb for an explicit platform-tools binary or --serial when multiple
devices are attached. This command checks the authorized ADB device count,
Android API level (26+), installed BetterNet package and debug-package
eligibility via Android run-as. It redacts the device serial, reads no private
files and never starts VPN/traffic, installs an app or sends tokens. A
preflight PASS is **not A1 PASS**; without a connected phone it reports
NOT RUN (BLOCKED). After a connected test phone and an independently
authorized gateway exist, use [the A1 protocol](TEST_STRATEGY.md).

## Reporting and acceptance

Include exact source/build SHA, OS/device, authorized destination, local vs
device environment, expected and observed results, sanitized failure logs,
PASS/FAIL/NOT RUN, and whether any traffic or credential left the device.
Never infer a released feature from a Draft PR or a network speedup from a
successful parser/localhost unit test.
