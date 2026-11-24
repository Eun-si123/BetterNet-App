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

## Restricted debug-only user-confirmed activation (draft, A1 NOT PROVEN)

An additional proposed Android debug path can **request** a temporary test
VPN only after all of: explicitly selected launcher app with current pinned
UID/signing identity; memory-only validated destination/gateway/token; user
approved authenticated HTTPS HEAD probe **within 60 seconds on the same Android
Network**; Android OS VPN preparation; a separate warning and positive button.
The Intent carries a 64-character opaque, one-use, process-local handoff handle
and **never** a credential, address list or user-selected app. The service
rechecks Android permission, installed-app identity and network scope before
foreground promotion and establishing exactly two host routes: virtual DNS and
the independently approved public HTTPS IP. The TUN owner stops after about
two minutes of monotonic runtime; notification Stop, app clear, revoke, network
loss and service destruction request cancellation. No arbitrary destination,
full-device route, on-demand module or persistent server is enabled.

This debug path **must refuse every production/release-build start**, unknown
actions, missing/expired/replayed handles, stale gateway tests and non-approved
VPN/network states. It is source-level/JVM evidence only until tested on Android
hardware. Running a debug build, showing a foreground notice or obtaining
the OS grant is **not** proof of A1 Internet forwarding or unrelated-app
exclusion. Test only an authorized gateway and independent HTTPS endpoint; the
repository's reference gateway still binds loopback only and is not deployed.

## A1 debug handoff is pinned to the tested underlying network

The Activity places the opaque Android Network handle (not a credential or
raw Network object) in its one-use process-local activation session.
The Service compares the current default Network handle before starting,
then checks that same Network is still default in the last pre-establishment
validation. Switching Wi-Fi to mobile data while a request is queued must
abort instead of silently using an unapproved metered route. Missing/zero,
mismatched, expired, and replayed handoffs fail closed. Once the VPN begins,
the OS may set the VPN itself as default, so ongoing checks keep using the
approved underlying Network without requiring it to remain the default.

These are JVM/race-gate checks, not Android hardware or metered cost proof.

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

## A1 browser parallel DNS A/AAAA handling (draft, device not proven)

The A1 test TUN accepts **only one independently approved DNS-correlated
destination IP**. Real Android resolvers can nevertheless ask A and AAAA in
either order. A legitimate *complementary* query for the **same hostname** and
unsupported family must not revoke the already authenticated, unconsumed
grant while it is still fresh. It may not create a new authorization, renew
the TTL or cause a credential-bearing gateway dial. Any failed approved-family
lookup, malformed query, different hostname, unexpected QTYPE or expired grant
retains fail-closed behavior. The explicitly approved *debug test hostname*
now gets a **local policy-filtered NOERROR/NODATA response** for the unsupported
A/AAAA family, with no gateway contact, new IP authorization or TTL renewal.
This is **not a claim about the authoritative upstream DNS records**; it
only describes the currently permitted test routing scope. No general
DNS rewriting, content interception or new route is enabled. Real Android
A1 validation remains necessary to check browser resolver interoperability.

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
