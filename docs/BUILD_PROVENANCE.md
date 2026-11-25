# BetterNet-App debug APK provenance (opt-in)

The Android CI workflow builds a **test-only unsigned debug APK**. A normal pull
request or push to main runs existing unit tests, lint, APK secret scanning,
and dependency checks. It does **not** request an OIDC signing certificate or
create an attestation for every temporary test build.

When a maintainer wants a verifiable test APK, manually dispatch the
same trusted Android CI workflow on the main branch:

    gh workflow run android.yml --repo Eun-si123/BetterNet-App --ref main

The manual run rebuilds the APK from the exact main commit and executes all
normal checks. After a successful build, a separate attest job runs with
narrowly scoped permissions (contents: read, id-token: write, attestations: write).
Regular pull request and push build jobs retain read-only token permissions.

The attestation job downloads the APK built earlier in **the same workflow run**,
rechecks SHA-256 of the APK and build-info file, confirms both recorded commit
SHAs match GitHub's workflow commit, checks APK ZIP integrity, then records
GitHub SLSA build provenance with actions/attest.

## Verification

Download the attested APK from the successful manual GitHub Actions run.
With a recent GitHub CLI version supporting attestation verification:

    gh attestation verify app-debug.apk -R Eun-si123/BetterNet-App

The attestation binds the APK bytes and SHA-256 to a specific repository,
workflow and build identity. It does **not** certify app security, release
readiness, physical Android testing, or Android APK release signing.

Untrusted fork PRs cannot trigger the privileged attestation job; manual
workflow runs from a non-main branch skip the attestation. Never reuse an
attestation for another commit or different APK bytes. Test APK artifacts
expire after seven days in GitHub Actions; attestation retention is separate.

For production distribution, implement a separate signed-release process
and verify release artifacts against their own attestations.

Reference: https://docs.github.com/en/actions/concepts/security/artifact-attestations
