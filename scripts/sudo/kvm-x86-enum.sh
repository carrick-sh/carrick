#!/bin/sh
# Full x86 conformance-probe enumeration on the Linux/KVM host. For each probe we
# capture BOTH the NATIVE Linux run (the oracle — ground truth, since probes are
# oracle-gated) and the carrick/KVM run, so the diff = carrick's x86_64-on-Linux
# gaps. Resumable + nohup-safe. Full stdout (not filtered) so raw-value probes diff.
cd /root/carrick || exit 1
# Local OCI registry serving the amd64 conformance images (override for your host).
REGISTRY="${REGISTRY:-127.0.0.1:5005}"
export CARRICK_INSECURE_REGISTRIES="$REGISTRY" CARRICK_RUN_ID=kvmen
# debian-slim, NOT go-conformance: probes are static musl; the Go-toolchain rootfs
# was extracted per run (~6GB I/O), making each carrick run ~5s. debian-slim → ~0.7s.
IMG="$REGISTRY/carrick-debian:bookworm-slim-amd64"
mkdir -p /tmp/kvmnat /tmp/kvmcar
reap() { pkill -9 -f "carrick:kvmen" 2>/dev/null; }
reap
for p in /tmp/x86p/*; do
  case "$p" in *.d) continue ;; esac
  [ -x "$p" ] && [ -f "$p" ] || continue
  name=$(basename "$p")
  [ -e /tmp/kvmcar/"$name" ] && continue
  # native Linux x86_64 = oracle
  nout=$(timeout 20 "$p" 2>&1); ncode=$?
  printf 'EXIT=%s\n' "$ncode" > /tmp/kvmnat/"$name"
  printf '%s\n' "$nout" >> /tmp/kvmnat/"$name"
  # carrick / KVM
  cout=$(timeout 40 ./target/release/carrick run -v "$p":/p "$IMG" /p 2>&1); ccode=$?
  if [ "$ccode" = 124 ]; then printf 'EXIT=TIMEOUT\n' > /tmp/kvmcar/"$name"
  else printf 'EXIT=%s\n' "$ccode" > /tmp/kvmcar/"$name"; fi
  printf '%s\n' "$cout" | grep -vE '^.\[2m|^\[2m' >> /tmp/kvmcar/"$name"
  reap
done
touch /tmp/kvm_enum_done
