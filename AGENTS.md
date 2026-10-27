# BetterNet App — Agent contract

This is a PUBLIC user-facing repository. No copying of source, code, logs, secrets, configuration, private research findings or personal identities from any private repository without explicit source/license/privacy review.

Read docs/MILESTONE_A.md before work. Make one selected Android app use a genuine safe BetterNet network path and prove it with honest end-to-end evidence before expanding to whole-device routing, unrelated file transfer or additional protocols.

Default to no routing capture and no network requests. New forwarding needs opt-in app selection, OS VPN permissions, authenticated/encrypted transports, bounded gateways, safe DNS/TCP/IPv4/IPv6 behavior, quotas, testable failure/rollback, and exclusion of unrelated apps. No unauthenticated public relays or unintended data disclosure.

PRs must state one acceptance gate, minimal implementation, exact build/test results and pending real-device checks. CI or packet parsing alone isn't proof that Internet access works. No PR churn solely to satisfy an hourly schedule.

Owner-directed Agent commits: public username Eun-si123, official GitHub no-reply email, and a Co-authored-by trailer for the named contributing Agent (name must end in Agent). Preserve independent contributors' own identities. No force pushes, unapproved releases, or unverified optimization claims.

Public visibility is not an OSS license; owner will decide licensing separately.

## Lean implementation and boundary validation

- Prefer the smallest **coherent** change, not merely fewer lines. Inline one-use logic when clearer; add helpers or abstractions for genuine reuse, separate responsibilities, or testability—not hypothetical complexity.
- Validate untrusted data at each trust boundary and carry validated values/types internally; avoid repeating equivalent null/format checks. Revalidate changed state, permissions, and new trust boundaries where needed.
- Preserve concrete security, integrity, concurrency, network, lifecycle, recovery, and resource-limit safeguards. Use `try/catch` where handling, cleanup, translation, or diagnostics add value; never silently swallow failures.
- Choose focused tests proportional to regression risk. Never remove meaningful guards, failure tests, or quality gates just to shorten code.
