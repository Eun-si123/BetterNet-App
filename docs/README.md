# BetterNet App documentation hub

**Read this first.** BetterNet is an Android-first, modular Internet-capability product in **pre-alpha**. These documents are planning, engineering and verification references; a proposed capability is not evidence that it runs. `main` is deliberately more limited than the open implementation Draft PR.

## Find what you need

| Question | Authoritative document | Audience |
| --- | --- | --- |
| What does BetterNet aim to solve, and why? | [Product specification](PRODUCT_SPEC.md) | Users, contributors, product |
| Which phases and future capabilities are intended? | [Product roadmap](PRODUCT_ROADMAP.md) | Everyone |
| What must work **next**? | [Milestone A acceptance gates](MILESTONE_A.md) | Implementers |
| What is **actually implemented and verified**? | [Status and evidence](STATUS.md) | Testers, reviewers |
| How do components and trust boundaries connect? | [Architecture](ARCHITECTURE.md) | Engineers |
| How do optional capabilities, including sharing, fit? | [Built-in capability design](FEATURE_MODULES.md) | Product, engineers |
| What can be collected or exposed? | [Security and privacy](SECURITY_PRIVACY.md) | Users, reviewers |
| What must be tested before claiming success? | [Verification strategy](TEST_STRATEGY.md) | QA, release reviewers |
| How are gateways/volunteers operated? | [Server and node policy](SERVER_NODES.md) | Future operators |
| What has the owner decided, and what remains open? | [Decision register](DECISIONS.md) | Everyone |

For first-time repo contributors also read [AGENTS.md](../AGENTS.md) and [the project README](../README.md).

## One source of truth per question

- **Product intent and long horizon:** `PRODUCT_ROADMAP.md`, confirmed decisions in `DECISIONS.md`.
- **Immediate technical pass/fail:** `MILESTONE_A.md`; it overrides long-range features when choosing the next implementation work.
- **Actual code, tests and branch status:** `STATUS.md` with source SHA and links; code and completed CI runs override prose if they disagree.
- **Interfaces and boundaries:** `ARCHITECTURE.md` + `SECURITY_PRIVACY.md`. Design proposals are explicitly labelled, not deployed systems.
- **User-facing claims:** must trace to `TEST_STRATEGY.md` evidence and a supported release. `PASS (CI)` is never `PASS (Android device)`.
- **A decision not recorded as confirmed in `DECISIONS.md` remains undecided.** An open decision is not authorization to deploy, transmit or change privacy defaults.

## Definition of status words

| Label | Meaning |
| --- | --- |
| `MAIN` | In default-branch source; does **not** imply a real device pass |
| `DRAFT PR` | Under review and not part of default-branch APK |
| `CI PASS` | Exact source revision passed an identified build/test workflow |
| `LOCAL PASS` | Named isolated test ran in a local test environment |
| `DEVICE PASS` | Explicit real Android device, build, flow and observable result recorded |
| `NOT RUN` | Required acceptance scenario has not been executed |
| `PLANNED` | Roadmap/architecture only; not implemented |
| `BLOCKED` | Failed prerequisite or evidence, with actionable blocker recorded |

Never turn these labels into percentages of product completion.

## Changes, reviews and release traceability

1. Pick the nearest unmet acceptance gate from `MILESTONE_A.md`; separately classify any verified urgent privacy/security/integrity issue.
2. State the user-visible outcome, source/branch, boundaries, expected failure modes, and a reproducible test plan in the PR.
3. Keep code and documentation aligned: new capability → `FEATURE_MODULES.md`; new data path → `ARCHITECTURE.md` and `SECURITY_PRIVACY.md`; changed tests → `TEST_STRATEGY.md`; owner choice → `DECISIONS.md`; claimed completion → `STATUS.md` with exact proof.
4. Verify local Markdown links with `python3 scripts/check_docs.py` from the repository root, then run focused tests and exact-head CI. Explain separately what remains `NOT RUN`.
5. For independent public apps, do not paste private research, configs or secret logs into PR descriptions or tests. Require explicit source/license/privacy review before an independently implemented public variant.
6. Do not merge a large Draft, activate selected-app VPN, publish a release or deploy an operator node just because documentation describes it.

**Maintenance rule:** update the smallest authoritative document, link to it elsewhere, and avoid a second stale copy of the same status. No new process/agent framework is required just to manage docs.
