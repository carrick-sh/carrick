#!/bin/sh
# Full x86 conformance-probe enumeration on bhyve, resumable + SSH-drop-proof
# (run under nohup). Captures each probe's report!() lines to /tmp/x86out/<name>.
cd /root/carrick || exit 1
# Local OCI registry serving the amd64 conformance images (override for your host).
REGISTRY="${REGISTRY:-127.0.0.1:5005}"
export CARRICK_INSECURE_REGISTRIES="$REGISTRY" CARRICK_RUN_ID=en9 CARRICK_EXPOSED_CPUS=2
# debian-slim, NOT go-conformance: the probes are static musl and don't need the
# Go toolchain; the huge go-conformance rootfs was extracted per run (~3GB, 89K
# files) making each run ~15s. debian-slim drops it to ~0.8s (proven via DTrace).
IMG="$REGISTRY/carrick-debian:bookworm-slim-amd64"
mkdir -p /tmp/x86out
reap() {
  pkill -9 -f "carrick:en9" 2>/dev/null
  for vm in $(ls /dev/vmm/ 2>/dev/null); do bhyvectl --destroy --vm="$vm" 2>/dev/null; done
}
reap
for p in /tmp/x86p/*; do
  case "$p" in *.d) continue ;; esac
  [ -x "$p" ] && [ -f "$p" ] || continue
  name=$(basename "$p")
  [ -e /tmp/x86out/"$name" ] && continue
  out=$(timeout 30 ./target/release/carrick run -v "$p":/p --platform linux/amd64 "$IMG" /p 2>&1); code=$?
  if [ "$code" = 124 ]; then printf 'EXIT=TIMEOUT\n' > /tmp/x86out/"$name"
  else printf 'EXIT=%s\n' "$code" > /tmp/x86out/"$name"; fi
  printf '%s\n' "$out" | grep -vE '^.\[2m|^\[2m' >> /tmp/x86out/"$name" 2>/dev/null
  reap
done
touch /tmp/x86_enum_done
