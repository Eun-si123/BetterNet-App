# Milestone A — authentic selected-app Internet connectivity

Status: **A0 foundation in progress; A1–A3 not proven**. Research phases stay as references rather than blocking all product work. The [Android-first product roadmap](PRODUCT_ROADMAP.md) records owner-confirmed usability, optional optimization, user/server configuration and future volunteer-node direction; those long-term goals do not waive the A1 device-level acceptance gate.

## User outcome

One explicitly selected, consenting Android app completes a genuine HTTPS request through an actual BetterNet network path, receives an authentic reply and doesn't cause any unrelated app's traffic to be captured.

## Acceptance gates

- **A0: Public project foundation.** Independent Android app, safe local network-state display, localization, unit tests and CI. No VPN capture or automatic outbound traffic.
- **A1: Real selected-app forwarding.** Select one test app and restricted test destination; verify real TCP, DNS and response delivery through a protected authenticated/encrypted transport to a secure, bounded gateway. Account for IPv4/IPv6, MTU, fragmentation, socket recursion, consent, VPN coexistence, failures and resource limits. No synthetic UDP echo counts as proof.
- **A2: Measurable value.** Same workload with BetterNet OFF/ON under Linux-host-simulated impairment; compare task success, p50/p95, recovery, overhead, data cost and battery. A direct/no-change choice is valid when the tunnel is worse.
- **A3: Auto and restricted environments.** Only validated routing, scheduling and transport adaptation; later protocol-blocking and vetted relays, without unsupported anonymity or universal unblockability promises.

## Documentation and acceptance evidence

See the [documentation hub](README.md) for sources of truth, [current implementation status](STATUS.md) for `main` vs Draft PR vs real-device evidence, and [test strategy](TEST_STRATEGY.md) for repeatable acceptance and negative cases. Optional in-app sharing is [planned independently](FEATURE_MODULES.md) and **must not** be mistaken for current A1 forwarding or a runtime dependency on DataNetShare.

## Agent work priority

Advance the **nearest unmet gate**, rather than opening unrelated file-transfer/benchmark PRs every hour. Treat urgent, verified security/privacy/integrity defects separately. Reuse existing work, run exact-source CI and label physical tests NOT RUN until completed. Never migrate private source or operational data into this public repo without a separate explicit license/privacy review.
