# Security Policy

## Reporting a vulnerability

**Please report security vulnerabilities privately.** This repository has GitHub Private Vulnerability Reporting enabled. Open the [Security tab](https://github.com/Eun-si123/BetterNet-App/security), select **Advisories**, then **Report a vulnerability**.

Do not post unpatched exploit details, real API keys, tokens, passwords, personal data, or live-user traffic in public Issues, discussions, PRs or logs. Redact screenshots and diagnostic output before attaching them.

A helpful private report includes the affected commit or version, the relevant Android OS/device and app configuration, reproduction conditions, expected versus observed behavior, potential impact and a minimal test using synthetic data. If you are unsure about severity, send the report privately anyway.

## Scope and supported versions

BetterNet-App is an **experimental Android application** under active development. Neither debug builds nor research prototypes should be assumed production-ready. The project does not promise support for unreleased branches, historical test builds or an unverified network-relay deployment. Check the repository's [status and roadmap](../docs/STATUS.md) for currently tested capabilities.

Please test only systems and accounts you own or are expressly authorized to assess. Avoid denial of service, attempts to access other users' data, disruption of infrastructure or unauthorized third-party scanning.

## Remediation and disclosure

The maintainer will evaluate reports against the current code and available evidence, assess reachability and affected versions, and coordinate a fix and appropriate public disclosure where feasible. No guaranteed response deadline or automatic bounty payment is offered. GitHub Dependabot, CodeQL and secret-scanning alerts are useful signals, not guarantees that every vulnerability will be detected.

For **accidentally exposed credentials**, stop using the credential and rotate/revoke it through its provider; deleting a Git commit alone does not invalidate the token.
