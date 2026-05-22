#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
usage: scripts/run-thread-stress.sh [--dry-run] [--max-traps N] [--carrick-bin PATH]

Build and run the threaded guest stress fixture with a tiny rootfs, then print
JSON metrics for wall time, child CPU time, trap throughput, and reporter load.

Environment:
  CARRICK_BIN               Override the carrick binary path.
  CARRICK_STRESS_MAX_TRAPS  Override the default max trap count.
USAGE
}

dry_run=0
max_traps="${CARRICK_STRESS_MAX_TRAPS:-20000}"
carrick_bin="${CARRICK_BIN:-target/debug/carrick}"
fixture="fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-thread-stress"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            dry_run=1
            shift
            ;;
        --max-traps)
            max_traps="$2"
            shift 2
            ;;
        --carrick-bin)
            carrick_bin="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$dry_run" -eq 1 ]]; then
    python3 - "$carrick_bin" "$fixture" "$max_traps" <<'PY'
import json
import sys

carrick_bin, fixture, max_traps = sys.argv[1:]
print(json.dumps({
    "command": [
        carrick_bin,
        "run-elf",
        fixture,
        "--rootfs-layer",
        "<generated-rootfs.tar.gz>",
        "--max-traps",
        max_traps,
    ],
    "fixture": fixture,
    "metrics": [
        "wall_seconds",
        "cpu_seconds",
        "cpu_utilization_percent",
        "traps",
        "syscall_invocations",
        "syscalls_per_second",
        "unhandled_syscall_invocations",
    ],
    "rootfs_file": "/etc/motd",
}, indent=2, sort_keys=True))
PY
    exit 0
fi

if [[ -z "${CARRICK_BIN:-}" ]]; then
    cargo build --quiet --bin carrick
fi
if [[ "$(uname -s)" == "Darwin" && -x "$carrick_bin" ]]; then
    codesign --force --sign - --entitlements scripts/entitlements.plist "$carrick_bin" >/dev/null 2>&1 || true
fi
scripts/build-linux-fixtures.sh >/dev/null

tmp_root="${TMPDIR:-/private/tmp}"
stress_dir="$(mktemp -d "${tmp_root%/}/carrick-thread-stress.XXXXXX")"
trap 'rm -rf "$stress_dir"' EXIT

mkdir -p "$stress_dir/root/etc"
printf 'thread stress fixture\n' > "$stress_dir/root/etc/motd"
tar -C "$stress_dir/root" -czf "$stress_dir/rootfs.tar.gz" etc/motd

python3 - "$carrick_bin" "$fixture" "$stress_dir/rootfs.tar.gz" "$max_traps" <<'PY'
import json
import resource
import subprocess
import sys
import time

carrick_bin, fixture, layer, max_traps = sys.argv[1:]
cmd = [
    carrick_bin,
    "run-elf",
    fixture,
    "--rootfs-layer",
    layer,
    "--max-traps",
    max_traps,
]

usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
started = time.perf_counter()
proc = subprocess.run(cmd, capture_output=True, text=True)
wall = time.perf_counter() - started
usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)

cpu_seconds = (
    usage_after.ru_utime
    + usage_after.ru_stime
    - usage_before.ru_utime
    - usage_before.ru_stime
)
metrics = {
    "command": cmd,
    "cpu_seconds": round(cpu_seconds, 6),
    "cpu_utilization_percent": round((cpu_seconds / wall * 100.0) if wall else 0.0, 3),
    "exit_status": proc.returncode,
    "wall_seconds": round(wall, 6),
}

if proc.returncode == 0:
    run = json.loads(proc.stdout)
    traps = run.get("traps")
    metrics["guest_exit_code"] = run.get("exit_code")
    metrics["guest_stdout"] = run.get("stdout")
    metrics["traps"] = traps
    summary = run.get("report", {}).get("summary", {})
    syscalls = summary.get("syscall_invocations") or traps
    metrics["syscall_invocations"] = syscalls
    metrics["syscalls_per_second"] = round((syscalls / wall) if syscalls and wall else 0.0, 3)
    metrics["unhandled_syscall_invocations"] = summary.get("unhandled_syscall_invocations")
else:
    metrics["stderr"] = proc.stderr

print(json.dumps(metrics, indent=2, sort_keys=True))
sys.exit(proc.returncode)
PY
