#!/usr/bin/env bash
# Exercise the reference TLS gateway under controlled impairment, never on host networking.
set -euo pipefail

if (( EUID != 0 )); then
  exec sudo -n bash "$0" "$@"
fi
for tool in ip tc python3; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
namespace="bn-a1-${BASHPID}-${RANDOM}"
created=0
cleanup() {
  if (( created )); then
    ip netns del "$namespace" || { echo "Could not remove isolated namespace" >&2; return 1; }
  fi
}
trap cleanup EXIT

# No veth, default route, forwarding, public listener or host qdisc is created.
ip netns add "$namespace"
created=1
ip netns exec "$namespace" ip link set lo up
cd "$repo_root"
echo "Baseline: isolated loopback without impairment"
ip netns exec "$namespace" python3 -m unittest discover -s gateway/tests -q

# Only this disposable namespace's loopback is impaired.
ip netns exec "$namespace" tc qdisc add dev lo root netem \
  delay 25ms 5ms loss 3%
echo "Impaired: isolated loopback, 25ms +/- 5ms delay and 3% loss"
ip netns exec "$namespace" python3 -m unittest discover -s gateway/tests -q
stats="$(ip netns exec "$namespace" tc -s qdisc show dev lo)"
printf '%s\n' "$stats"
if ! grep -Eq 'Sent [1-9][0-9]* bytes [1-9][0-9]* pkt' <<<"$stats"; then
  echo "No loopback traffic traversed the netem qdisc" >&2
  exit 1
fi
