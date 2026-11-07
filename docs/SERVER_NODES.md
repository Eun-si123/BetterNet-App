# Linux/Ubuntu gateways and volunteer node policy

**Design-only future capability.** The existing [implementation Draft PR #7](https://github.com/Eun-si123/BetterNet-App/pull/7) contains a **localhost-only reference gateway** for integration tests; it is not a production server, not an enrolled volunteer, not externally exposed and not a general public proxy. This document contains **no deployment commands to run on personal infrastructure**.

## Operator experience: simple to expert

| Level | Intention | Guardrails |
| --- | --- | --- |
| First-run / simple | Single supported Linux/Ubuntu package or container, safe defaults, health/status and reversible Stop | No listening on all public interfaces without explicit opt-in; narrow role/port/destination policy, identity and quotas |
| Guided | Easy names for authorized clients, relay role, capacity and optional usage allowance | Review effective config, reject conflicting rules, expose estimated operator bandwidth/cost |
| Expert | Per-role limits, CPU/RAM/bandwidth caps, access policy, TLS identity/renewal, logs retention, rate controls, abuse workflow, updates/rollback | Never disable authentication or make a general open proxy by selecting an optimization preset |

Operators can choose ingress gateway, restricted exit, measurement, and possibly later peer/transit roles **individually**. Default to disabled or loopback/local-only until explicitly exposed, with service account isolation and limited filesystem/network privileges. Do not infer hosting capability from a locally running server game, a domain, NAT port mapping or an unrelated home lab.

## Node discovery and trust

**Both** a signed curated directory and self-registered/manual nodes will be designed. Curated status is issued by accountable project/community review, not by self-registration, low ping or payment. The directory must be replay-resistant/versioned, keys rotatable and revocable, with operator identity claims, service role, protocol version, region, current health and fee/quota disclosures. Operators may remain private and manually share authenticated connection details without directory listing. Unreviewed entries require a visible opt-in and cannot silently become preferred paths.

Review rules, moderator identities, appeal mechanisms, directory hosts, credentials, retention and emergency revocation are still **OPEN** in [the decision register](DECISIONS.md). Never present an automatic latency probe as proof that a stranger's exit node is honest.

## Privacy, usage and finances

- **Free / donation / paid** are acceptable choices. Show whether fees are optional, what each quota measures, recipient/operator identity, data/CPU caps and the consequences of exceeding limits. The existence of a paid tier does not authorize payment collection in the Android app.
- Exits can observe destination metadata/time/traffic volume even when downstream HTTPS payloads are encrypted. Operator logging must have explicit categories, minimization, retention and public disclosure; no content interception by default.
- Use authenticated clients and role-limited destinations, concurrency/time/byte quotas, abuse detection/response, credential rotation/revocation and resource isolation. A public exit node must not become a spam/DDOS/open proxy relay.
- Distinguish connection health from operator reputation and billing; a reachable or fast node may still be unsafe.
- Any volunteer can stop operating a node. Client failover must follow the user's direct-fallback/strict policy, respect metered-data limits and never enroll a new node automatically.

## Before first **authorized** remote gateway pilot

1. Choose a **separately approved** machine and independently controlled test destination; no personal home server or credentials inferred from project history.
2. Define exposure/network ports, dedicated account/container boundary, TLS identity, role and exact allowed destinations, quotas, client credentials and log retention.
3. Verify localhost tests, TLS auth failure, malformed CONNECT, unauthorized target, quota, memory exhaustion, loss of network, restart, revocation and stop/rollback in isolation.
4. On the approved test node, repeat with a real Android selected app, non-captured app and genuine response; log exact evidence under [test strategy](TEST_STRATEGY.md). Use reversible firewall rules and no unrestricted wildcard access.
5. Obtain operator acceptance, published limitations, abuse-report contact, cost disclosure, and governance decision before listing a public volunteer service.

This roadmap does not expose a listener, open NAT/firewall ports, enroll a server, pay an operator, create a key, or authorize external sharing. Build and testing of a safe operator agent may happen after A1 while keeping production participation explicitly opted in.
