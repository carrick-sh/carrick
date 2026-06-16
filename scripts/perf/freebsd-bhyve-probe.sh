#!/bin/sh
# Run one static x86_64 perf probe under carrick-bhyve (FreeBSD), guest stdout
# to $OUT. Designed to be the `-c` target of dtrace so $target binds to the
# carrick process (exec keeps the pid). Probes are the cross-built
# conformance-probes/perf_* binaries staged into $PROBES on the box.
#
# Env knobs (all optional):
#   CARRICK_BIN  carrick binary             (default: /path/to/carrick/target/release/carrick)
#   PROBES       host dir of perf_* probes  (default: /root/ppx86)
#   IMG          OCI image for the guest    (default: debian:bookworm-slim)
#   PROBE        probe binary name          (default: perf_trap_floor)
#   OUT          guest stdout sink          (default: /root/guest.out)
set -u
: "${CARRICK_BIN:=/path/to/carrick/target/release/carrick}"
: "${PROBES:=/root/ppx86}"
: "${IMG:=debian:bookworm-slim}"
: "${PROBE:=perf_trap_floor}"
: "${OUT:=/root/guest.out}"

# clean any leaked vmm nodes from a previous run (bhyve leaks /dev/vmm nodes)
for vm in $(ls /dev/vmm/ 2>/dev/null); do bhyvectl --destroy --vm="$vm" >/dev/null 2>&1; done

exec env CARRICK_EXPOSED_CPUS=4 "$CARRICK_BIN" run --name perftrace \
	--platform linux/amd64 --fs host -v "$PROBES:/probes" -e BENCH_NPROC=4 \
	"$IMG" "/probes/$PROBE" >"$OUT" 2>&1
