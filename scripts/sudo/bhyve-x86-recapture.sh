#!/bin/sh
# Second pass: re-run any probe whose first-pass capture is EMPTY, this time
# capturing FULL stdout (not just =true/false lines) so non-boolean report!()
# probes and crash/hang/timeout cases are distinguishable. Writes /tmp/x86full/<name>
# with a leading status line (EXIT=<code> or TIMEOUT) then the raw probe output.
cd /root/carrick || exit 1
# Local OCI registry serving the amd64 conformance images (override for your host).
REGISTRY="${REGISTRY:-127.0.0.1:5005}"
export CARRICK_INSECURE_REGISTRIES="$REGISTRY" CARRICK_RUN_ID=rec CARRICK_EXPOSED_CPUS=2
IMG="$REGISTRY/carrick-go-conformance:1.24"
mkdir -p /tmp/x86full
reap() {
  pkill -9 -f "carrick:rec" 2>/dev/null
  for vm in $(ls /dev/vmm/ 2>/dev/null); do bhyvectl --destroy --vm="$vm" 2>/dev/null; done
}
reap
for p in /tmp/x86p/*; do
  case "$p" in *.d) continue ;; esac
  [ -x "$p" ] && [ -f "$p" ] || continue
  name=$(basename "$p")
  # only re-run probes that came back empty in the filtered first pass
  [ -s /tmp/x86out/"$name" ] && continue
  out=$(timeout 30 ./target/release/carrick run -v "$p":/p --platform linux/amd64 "$IMG" /p 2>&1)
  code=$?
  if [ "$code" = 124 ]; then
    printf 'STATUS=TIMEOUT\n' > /tmp/x86full/"$name"
  else
    printf 'STATUS=EXIT_%s\n' "$code" > /tmp/x86full/"$name"
  fi
  printf '%s\n' "$out" | grep -vE '^.\[2m|^\[2m' >> /tmp/x86full/"$name" 2>/dev/null
  reap
done
touch /tmp/x86_recapture_done
