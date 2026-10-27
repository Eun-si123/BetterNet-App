#!/usr/bin/env bash
# Verify a downloaded CI debug artifact against the CURRENT PR head and merge SHA.
# Obtain expected SHAs from GitHub immediately before installing the APK; a past
# green CI run does not prove that a subsequently changed stacked base was tested.
set -euo pipefail
if [[ $# -ne 3 || ! "$2" =~ ^[0-9a-f]{40}$ || ! "$3" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Usage: $0 <artifact-directory> <current-source-head-sha> <current-pr-merge-sha>" >&2
  exit 2
fi
cd "$1"
for file in app-debug.apk BUILD_INFO.txt SHA256SUMS; do
  if [[ ! -f "$file" || -L "$file" ]]; then
    echo "Missing or unsafe artifact file: $file" >&2
    exit 1
  fi
done
if [[ "$(awk '{print $2}' SHA256SUMS)" != $'app-debug.apk\nBUILD_INFO.txt' ]]; then
  echo "Unexpected checksum manifest entries" >&2
  exit 1
fi
sha256sum --check --strict --status SHA256SUMS || {
  echo "Artifact checksum mismatch" >&2
  exit 1
}
grep -Fxq "source_commit=$2" BUILD_INFO.txt || {
  echo "Stale source commit in artifact" >&2
  exit 1
}
grep -Fxq "built_commit=$3" BUILD_INFO.txt || {
  echo "Stale PR merge commit in artifact; obtain a new CI build" >&2
  exit 1
}
unzip -tqq app-debug.apk || {
  echo "APK ZIP integrity check failed" >&2
  exit 1
}
echo "PASS: checksums, source head, PR merge SHA and APK ZIP integrity"
