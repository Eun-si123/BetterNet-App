# Milestone A — authentic selected-app Internet connectivity

Status: **A0 foundation in progress; A1–A3 not proven**. Research phases stay as references rather than blocking all product work.

## User outcome

One explicitly selected, consenting Android app completes a genuine HTTPS request through an actual BetterNet network path, receives an authentic reply and doesn't cause any unrelated app's traffic to be captured.

## Acceptance gates

- **A0: Public project foundation.** Independent Android app, safe local network-state display, localization, unit tests and CI. No VPN capture or automatic outbound traffic.
- **A1: Real selected-app forwarding.** Select one test app and restricted test destination; verify real TCP, DNS and response delivery through a protected authenticated/encrypted transport to a secure, bounded gateway. Account for IPv4/IPv6, MTU, fragmentation, socket recursion, consent, VPN coexistence, failures and resource limits. No synthetic UDP echo counts as proof.
- **A2: Measurable value.** Same workload with BetterNet OFF/ON under Linux-host-simulated impairment; compare task success, p50/p95, recovery, overhead, data cost and battery. A direct/no-change choice is valid when the tunnel is worse.
- **A3: Auto and restricted environments.** Only validated routing, scheduling and transport adaptation; later protocol-blocking and vetted relays, without unsupported anonymity or universal unblockability promises.

## Single budget for restricted gateway connection

The dormant A1 authenticated CONNECT path uses one monotonic timeout for
protected-network binding, TCP connection, gateway TLS handshake and reading
the CONNECT acceptance header. It rechecks the deadline **after** potentially
blocking stages and before transmitting bearer credentials. A stale bound
socket must not initiate a TCP connection; if a stage expires, resources close
and no connection is accepted. Loopback regression tests cover time consumed
by a slow network bind and TLS handshake. This limits successful connection
acceptance; underlying OS blocking calls and TLS writes are not a hard
wall-clock cancellation guarantee. No gateway is deployed or VPN activated.

## Dual-stack TCP fallback inside the single gateway budget (A1 Draft)

The restricted gateway paths now reserve a bounded **TCP-only** slice for early
IPv6/IPv4 addresses, leaving time to attempt an alternate address when the
first TCP connection blackholes. The original **shared transaction deadline**
still applies to TLS identity verification, CONNECT authorization, and
credential use; the TCP-only slice does not truncate a successful TLS
handshake. Only an explicitly tagged **TCP-connect** failure may try another
resolved address. TLS identity failures, revoked VPN scope, failed network
binding, or errors after authentication **must not be replayed** to another
address. No default network, unapproved app, or destination is substituted.

Local JVM tests include a simulated blackholed first family, single-address
budget, retry refusal, and an actual isolated loopback TLS handshake longer
than its TCP-only cap. This is a **Draft PR correctness improvement**, not a
VPN activation or physical-device A1 completion.

## DNS name correlation interoperability

A dormant A1 DNS-over-TLS response may echo the original QNAME with different
ASCII letter case. RFC 4343 defines such names as equivalent. BetterNet now
accepts **case-only** differences in a verified, outstanding DNS question while
continuing to require exact transaction ID, label layout, QTYPE, QCLASS, and
approved IP address. This avoids discarding valid normalized DNS answers and
does not permit unrelated questions, unauthenticated DNS, or a new gateway
route. It is a pure offline correctness test, **not** real selected-app A1
connectivity proof.

## Agent work priority

Advance the **nearest unmet gate**, rather than opening unrelated file-transfer/benchmark PRs every hour. Treat urgent, verified security/privacy/integrity defects separately. Reuse existing work, run exact-source CI and label physical tests NOT RUN until completed. Never migrate private source or operational data into this public repo without a separate explicit license/privacy review.
