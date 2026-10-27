# BetterNet App

Public, Android-first application for **usable everyday Internet on slow, unstable, congested and expensive networks**, with future research into restricted connectivity.

**Current state: pre-alpha. Not a VPN or Internet accelerator.** The app can currently show Android's local network type, validation and metered state after a button press. It makes no network requests and does not route another app's traffic. You can select one launcher-visible test app for a future connectivity test; the selection is memory-only, resets when the activity is recreated, grants no VPN permission and captures no traffic.

## Build

Requires JDK 17 and Android SDK 36.

```sh
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

The new package is `io.betternet.next`, separate from existing BetterNet Developer installations. Never install a debug build over a previously signed release.

Read [Milestone A](docs/MILESTONE_A.md) before proposing work. The previous private BetterNet research repository stays private; this is an independent implementation, not a public mirror.

No license has been selected yet. Public visibility does not grant reuse rights automatically.
