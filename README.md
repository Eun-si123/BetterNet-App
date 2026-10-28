# BetterNet App

Public, Android-first application for **usable everyday Internet on slow, unstable, congested and expensive networks**, with future research into restricted connectivity.

**Current state: pre-alpha. Not a VPN or Internet accelerator.** The app can currently show Android's local network type, validation and metered state after a button press. It makes no network requests and does not route another app's traffic. After choosing a test app, a read-only VPN readiness check can report whether Android would require consent or a VPN is visible on the default network; it never launches the consent dialog, starts a VPN, or proves connectivity. You can select one launcher-visible test app for a future connectivity test; the selection is memory-only, resets when the activity is recreated, grants no VPN permission and captures no traffic.

## Build

Requires JDK 17 and Android SDK 36.

```sh
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

The new package is `io.betternet.next`, separate from existing BetterNet Developer installations. Never install a debug build over a previously signed release.

Read [Milestone A](docs/MILESTONE_A.md) before proposing work. The previous private BetterNet research repository stays private; this is an independent implementation, not a public mirror.

A dormant `VpnService` component now has a fail-closed single-app builder boundary for A1. It does not start, request VPN consent, establish a TUN, or send traffic. Android package lookup failures must not fall back to whole-device routing. The selected app is not yet connected to this service; gateway, DNS/TCP, IPv4/IPv6, MTU and VPN lifecycle work remain unimplemented. A dormant gateway-socket guard rejects unresolved addresses and unbounded connect timeouts, and requires VPN socket protection before dialing; it performs no network operation unless explicitly called and provides no TLS or Internet forwarding yet.

No license has been selected yet. Public visibility does not grant reuse rights automatically.

A dormant TLS gateway dial boundary now requires VPN socket protection before connecting, verifies the gateway DNS name using the platform TLS trust store and HTTPS endpoint identification, rejects legacy TLS protocols, and bounds the handshake timeout. It is **not** wired into a VPN, does not send requests, does not authenticate an application-level gateway session, and does not prove Internet connectivity.
