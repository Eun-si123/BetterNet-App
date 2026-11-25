# Gradle build dependency integrity

The Gradle wrapper distribution ZIP is SHA-256 pinned. Android build
dependencies, plugin JARs and their Maven metadata are also verified using
Gradle's native `gradle/verification-metadata.xml` SHA-256 allowlist. Gradle
checks these hashes automatically during artifact resolution, including in CI.
An unexpected dependency version, downloaded artifact or changed artifact
without an approved checksum **fails the build**.

## Adding or upgrading a dependency

The initial list was generated in a **read-only GitHub Actions PR** on the
same Android SDK 36 / JDK 17 build that assembled the APK, ran unit tests and
lint. It was reviewed before committing. For intentional dependency changes:

1. Generate a fresh list in a trusted environment with the existing wrapper:
   `./gradlew --write-verification-metadata sha256 :app:assembleDebug :app:testDebugUnitTest :app:lintDebug`
2. Review upstream release provenance and the SHA-256 metadata diff. Do not
   automatically accept newly observed hashes from untrusted forks.
3. Commit the changed build files and `gradle/verification-metadata.xml` in
   the **same PR**; verify that Android CI, CodeQL and dependency graph pass.
4. Run `python3 scripts/check_gradle_dependency_verification.py` and
   `python3 -m unittest scripts.test_check_gradle_dependency_verification`.

Never bypass verification with `--dependency-verification off` or broad
`trusted-artifacts` exceptions. Other OSes and SDK configurations can load
additional artifacts, requiring separately verified checksums.

**Threat model:** Checksums protect against changed/downloaded dependencies;
they do not prove that the initially trusted version is free of vulnerabilities
or that the original publisher was uncompromised. The nine build-tool alerts
remain open in [security issue #29](https://github.com/Eun-si123/BetterNet-App/issues/29).
Debug/release runtime-classpath checks and GitHub APK provenance are separate
controls, not substitutes for patched upstream dependencies.
