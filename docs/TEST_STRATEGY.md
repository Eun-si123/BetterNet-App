# Validation, QA and release evidence

**No claim without a relevant test.** Documentation and unit tests are useful; none substitutes for a real Android selected-app HTTPS request. Each test report must distinguish local fixture, CI, emulator, real device and live network. See [status](STATUS.md) and [Milestone A](MILESTONE_A.md).

## Evidence ladder

| Level | What it proves | What it **does not** prove |
| --- | --- | --- |
| Static/code/document checks | Compilation, expected security checks, link integrity and structure | Runtime packet delivery, real network improvement |
| Unit tests | Parser, state transitions, refusal, failure handling and controlled fake components | Android lifecycle, real VPN consent or actual destination access |
| Isolated integration / localhost TLS | Verified TLS, CONNECT framing, DNS/TCP over controlled loopback, error/cleanup | Public Internet, volunteer node trust, mobile radio behavior |
| Android emulator | Selected API/OS integration under emulator limitations | OEM/background/physical radio and data-charge behavior |
| **Physical Android selected app** | Actual end-to-end app result, OS permission, TUN and route boundaries | Performance benefit across networks without comparisons |
| Matched real-workload OFF vs ON | Repeatable benefit or regression in a specified environment | General improvement for every app/network |
| Safe operator pilot | Authorized node authentication, revocation, quota and live robustness | Public free relay service readiness or anonymity |

## Gate-by-gate verification matrix

| Gate | Positive test | Must-fail / negative cases | Status |
| --- | --- | --- | --- |
| A0 | Build APK; launch, inspect local network/app status | Missing app, rejected permission, no accidental gateway or VPN start | `PARTIAL`; physical checks `NOT RUN` |
| A1 | Explicit app's real HTTPS request returns correct independent endpoint response through approved relay | Other app not captured, wrong TLS cert, revoked consent, disconnect, OS kill/reboot, TCP/IPv4/IPv6/MTU, wrong DNS, quota and stop race | `NOT RUN (DEVICE)` |
| A2 | Same browser/message/video task with BetterNet OFF vs ON over controlled impairment and ordinary network | Tunnel worse than direct; battery/data cost, packet loss burst, path switching; no fabricated speedup | `NOT RUN` |
| A3 | Auto route/transport choices recover better when justified | Flapping, direct fallback violating strict policy, user data cap, unknown relay, QUIC/UDP failure | `PLANNED` |
| Built-in sharing | Send/accept/verify a selected file inside two compatible BetterNet installs | No DataNetShare install, unauthorized receiver, wrong hash, interrupted/duplicate/resume, path traversal, no port exposure | `PLANNED` |
| User-controlled optional features | Enable/disable each feature and measure core-only vs installed footprint for the **actual distribution channel** | OFF must stop background work; invalid dependency, interrupted install, false space saving, uninstall during transfer, retained user files and reinstallation | `PLANNED` |
| Diagnostics | User chooses log → sees exact redacted payload and recipient → sends or declines | No upload on open/cancel/crash, removal of sensitive fields, retention limits and recipient mismatch | `PLANNED` |
| Community nodes | Signed verified list + manually added unverified node; operator permission and quotas | Forged directory, revoked node, unpaid surprise fees, abuse, resource exhaustion and expired identity | `PLANNED` |

These are criteria, **not a claim that tests currently exist**. Do not infer any percentage of completion from checked boxes.

## First physical Android A1 test procedure (do not run without approved endpoint)

1. Record device model, Android build, source SHA, debug/signature identity, selected app package/version, exact test URL and separately approved gateway address/trust mode. The tests must avoid personal server infrastructure unless explicitly authorized.
2. Capture a baseline without BetterNet: selected browser loads an independently verifiable HTTPS response; one unrelated app uses its normal path. Record DNS, TCP or HTTP/3 behavior actually used.
3. Explicitly select **one** app, choose supported non-VPN Android network, inspect cost/privacy policy, request OS VPN permission, and start supported scoped route. Verify owned TUN and gateway protection before treating any packet as routed.
4. Repeat the same endpoint request with BetterNet, verify source/destination response and successful browser display, independent upstream auth and certificate identity. Confirm a different app's traffic did not enter BetterNet.
5. Stop, revoke VPN, disconnect Wi-Fi/cellular, switch background/foreground, lose gateway mid-transfer and test bounded cleanup. When strict policy is claimed, additionally verify actual Android lockdown and no direct escape on crash and restart; **not proven at present**.
6. Record exact PASS/FAIL/BLOCKED with logs scrubbed locally and screenshots only when necessary. Include unintended traffic, hangs and metered-data cost. Roll back to no VPN after tests.

**First workload candidates:** controlled HTTPS browser (A1); browser and messenger actions next; YouTube playback, QUIC/UDP, DRM and adaptive bitrate separately, never assumed from a TCP-only success. No claim about unsupported games/voice.

## A2 performance design

- Record baseline network/path, geography, device/OS, selected app, server trust, Wi-Fi/mobile and cost constraints. Compare BetterNet OFF/direct vs ON using **same task** and network impairment; randomize AB/BA order and repeat enough to show variability.
- Include good networks, ordinary mobile, constrained rate, jitter, random and burst losses, high RTT, mid-session outage and route switching. An unavailable physical Internet path is a separately classified failure, not proof of a magical fallback.
- Report task success, p50/p95/p99 completion/stalls, jitter/RTT, time-to-recovery, video rebuffering, bytes overhead, CPU/wake time, energy and data cost. Include worsened cases and confidence/uncertainty; pre-define workload and success condition before testing.
- A latency-first profile should show lower **avoidable** delay without claiming to defeat propagation; a stability profile may trade throughput/energy for successful task completion. No single headline percent can substitute for per-condition evidence.

## APK footprint and user-choice evidence

For each future optional component measure **baseline signed APK/download size, on-device installed code/resources, cache/log/data, and peak install/update storage**, not just the build file size. Compare fresh core-only vs option installed on representative low-end Android and the chosen distribution channel. Verify each user-visible toggle only enables supported behavior and OFF stops its network/CPU/battery usage. On-demand downloadable files must have explicit consent, integrity/signature verification and an offline failure path. If a GitHub universal APK embeds optional code, label OFF accurately and do not count any reclaimed APK bytes until a real uninstaller/distribution demonstrates it. Validate preserving user-created files/settings on removal according to an explicit policy; never silently erase them.

## CI and change management

- Default branch: GitHub Actions compiles Android JVM tests, Lint and Debug APK with SHA/artifact checksums. Draft PR #7 adds isolated loopback and netem tests but has not been merged; always check the exact workflow tied to the commit.
- Documentation PRs run `python3 -m unittest discover -s scripts -p 'test_check_docs.py'` and `python3 scripts/check_docs.py` where available; link checks must also detect broken references and reject leaving the repository root.
- Keep release signing, secrets and third-party DNS/network requests out of documentation checks. A CI pass cannot establish user-device VPN behavior.
- Failures are useful evidence. Before retrying: record initial reproduction, isolate source/test/environment regression, fix the cause, repeat at the same gate and link new exact-head CI.

## Release evidence template

`Date | repo ref + full SHA | app version/OS/device | test stage | selected app and protocol | fixture or genuine endpoint | expected result | observed result | PASS/FAIL/BLOCKED/NOT RUN | privacy/traffic boundary | known limitations | rollback`.

A public experimental APK may be **diagnostic-only** while A1 forwarding is unverified; never turn its presence into a claim of full Internet optimization. Signed beta and stable require separately documented user/security acceptance.
