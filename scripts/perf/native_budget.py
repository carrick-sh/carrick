#!/usr/bin/env python3
"""Host-call budget for one Carrick native run: what the kernel time is SPENT ON.

Why this exists
---------------
The obvious instrument -- `profile-997 { @[stack()] = count(); @[ustack()] = ... }`
-- does not work on macOS/arm64 for this runtime, and the reason is worth
stating so nobody spends another week on it:

  * `ustack()` cannot unwind JIT frames. Translated guest code carries no unwind
    information, so user stacks in the hot path are garbage.
  * `stack()` mostly cannot unwind either. Measured on a cold go-build: five of
    the top six kernel "stacks" are a single frame, and the hottest leaf is
    `ml_set_interrupts_enabled_with_debug` -- a sampling artifact, not a cost.
    Leaf-only attribution is flat: the top 26 leaves cover 35.6% of kernel
    samples with no dominant entry.

Both halves fail for the same class of reason, and conflating them is what kept
the KERNEL side of this campaign unmeasured for three tasks -- attributing user
PCs in a JIT genuinely needs a range classifier, but attributing kernel time
needs no JIT unwinding at all.

What works instead is exact counting and `vtimestamp` timing of NAMED entry
points: host syscalls and mach traps. No stack walking, not sampled, and one
17-second pass produces a ranked table.

Lifecycle vs workload
---------------------
Campaign Decision 13 excludes engine container setup and teardown from the
metric. A whole-run capture cannot honour that on its own, so this tool runs the
workload TWICE -- once as a trivial guest command (the lifecycle floor) and once
for real -- and reports `delta = full - floor`. Rank work off the delta;
`unlinkat` traffic that lives entirely in rootfs teardown is outside the metric
however large it looks.

Safety
------
Kernel providers only: `syscall:::`, `mach_trap:::`, `proc:::`. No pid provider,
no USDT/fasttrap, and no `copyin` in any probe -- an in-probe `copyin` killed
guests 2/2, and a `dtrace -p` detach leaked `SIGTRAP` into a live build. The
script self-terminates on a tick rather than waiting for a signal, because it
runs as root and `pkill` is not in the passwordless sudo set.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
from collections.abc import Sequence

SCHEMA = "carrick.native-host-call-budget.v1"
DEFAULT_IMAGE = "localhost:5005/carrick-go-conformance:1.24"
# The go-build reference workload, as the conformance suite runs it.
DEFAULT_WORKLOAD = (
    'cd /tmp && printf "package main\\nfunc main(){println(\\"ok\\")}\\n" > h.go '
    "&& GOCACHE=/tmp/gc /usr/local/go/bin/go build -o /tmp/h ./h.go "
    "&& /tmp/h && echo BUILD_OK"
)
# A guest that starts and immediately exits: everything it costs is lifecycle.
FLOOR_WORKLOAD = "true"

D_SCRIPT = r"""
#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option aggsize=64m
#pragma D option dynvarsize=64m

proc:::exec-success
/execname == "carrick"/
{
	tracked[pid] = 1;
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
}

proc:::exit
/tracked[pid]/
{
	tracked[pid] = 0;
}

syscall:::entry
/tracked[pid]/
{
	self->ts = vtimestamp;
}

syscall:::return
/tracked[pid] && self->ts/
{
	@sc_ns[probefunc] = sum(vtimestamp - self->ts);
	@sc_n[probefunc] = count();
	self->ts = 0;
}

mach_trap:::entry
/tracked[pid]/
{
	self->mts = vtimestamp;
}

mach_trap:::return
/tracked[pid] && self->mts/
{
	@mt_ns[probefunc] = sum(vtimestamp - self->mts);
	@mt_n[probefunc] = count();
	self->mts = 0;
}

tick-1s
{
	elapsed++;
}

tick-1s
/elapsed >= __DEADLINE__/
{
	exit(0);
}

END
{
	printa("SC_NS %s %@u\n", @sc_ns);
	printa("SC_N %s %@u\n", @sc_n);
	printa("MT_NS %s %@u\n", @mt_ns);
	printa("MT_N %s %@u\n", @mt_n);
}
"""


def require_passwordless_dtrace() -> None:
    probe = subprocess.run(
        ["sudo", "-n", "/usr/sbin/dtrace", "-V"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise SystemExit(
            "passwordless `sudo /usr/sbin/dtrace` is required; check `sudo -n -l`"
        )


def parse_aggregations(text: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {
        "syscall_ns": {},
        "syscall_n": {},
        "machtrap_ns": {},
        "machtrap_n": {},
    }
    tags = {
        "SC_NS": "syscall_ns",
        "SC_N": "syscall_n",
        "MT_NS": "machtrap_ns",
        "MT_N": "machtrap_n",
    }
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[0] not in tags:
            continue
        try:
            out[tags[fields[0]]][fields[1]] = int(fields[2])
        except ValueError:
            continue
    return out


def capture(
    repo: pathlib.Path,
    command: str,
    *,
    label: str,
    image: str,
    deadline_s: int,
    settle_s: float,
    scratch: pathlib.Path,
) -> dict[str, object]:
    script = scratch / f"budget-{label}.d"
    script.write_text(D_SCRIPT.replace("__DEADLINE__", str(deadline_s)))
    raw = scratch / f"budget-{label}.raw"
    consumer = subprocess.Popen(
        ["sudo", "-n", "/usr/sbin/dtrace", "-s", str(script), "-o", str(raw)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    # The consumer must be enabled before the guest starts, or the run's early
    # process creations are missed and every child stays untracked.
    time.sleep(settle_s)
    binary = repo / "target/release/carrick"
    environment = dict(os.environ)
    environment["CARRICK_RUN_ID"] = f"budget-{label}-{os.getpid()}"
    started = time.monotonic_ns()
    guest = subprocess.run(
        [
            str(binary),
            "run",
            "--exec-backend",
            "native",
            "--raw",
            "--fs",
            "host",
            "--rm",
            "-w",
            "/tmp",
            image,
            "/bin/sh",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    wall_ns = time.monotonic_ns() - started
    consumer.wait()
    stderr = consumer.stderr.read().decode(errors="replace") if consumer.stderr else ""
    if consumer.returncode != 0:
        raise SystemExit(f"dtrace consumer failed for {label}: {stderr[:400]}")
    aggregations = parse_aggregations(raw.read_text(errors="replace"))
    return {
        "label": label,
        "command": command,
        "guest_exit": guest.returncode,
        "guest_ok": guest.returncode == 0,
        "wall_ms": wall_ns // 1_000_000,
        "stdout": guest.stdout[-2000:],
        "stderr": guest.stderr[-2000:],
        **aggregations,
        "syscall_total_n": sum(aggregations["syscall_n"].values()),
        "syscall_total_ns": sum(aggregations["syscall_ns"].values()),
        "machtrap_total_n": sum(aggregations["machtrap_n"].values()),
        "machtrap_total_ns": sum(aggregations["machtrap_ns"].values()),
    }


def subtract(full: dict[str, object], floor: dict[str, object]) -> dict[str, dict[str, int]]:
    """`full - floor` per name, so the report ranks WORKLOAD cost.

    Clamped at zero: a floor run can out-count a full run for a call the
    workload does not use, and a negative "cost" is noise, not a saving.
    """
    delta: dict[str, dict[str, int]] = {}
    for key in ("syscall_ns", "syscall_n", "machtrap_ns", "machtrap_n"):
        merged: dict[str, int] = {}
        full_map = full[key]  # type: ignore[index]
        floor_map = floor[key]  # type: ignore[index]
        assert isinstance(full_map, dict) and isinstance(floor_map, dict)
        for name in set(full_map) | set(floor_map):
            value = full_map.get(name, 0) - floor_map.get(name, 0)
            if value > 0:
                merged[name] = value
        delta[key] = merged
    return delta


def render(payload: dict[str, object], top: int) -> None:
    for section, ns_key, n_key, unit in (
        ("workload-attributable host syscalls", "syscall_ns", "syscall_n", "syscall"),
        ("workload-attributable mach traps", "machtrap_ns", "machtrap_n", "trap"),
    ):
        delta = payload["delta"]
        assert isinstance(delta, dict)
        by_ns: dict[str, int] = delta[ns_key]
        by_n: dict[str, int] = delta[n_key]
        total_ns = sum(by_ns.values())
        if not total_ns:
            print(f"\n== {section} == (none)")
            continue
        print(f"\n== {section} == {total_ns / 1e6:,.0f} ms on-CPU, {sum(by_n.values()):,} calls")
        print(f"{'on-CPU ms':>11} {'share':>6} {'calls':>10} {'us/call':>8}  {unit}")
        for name, ns in sorted(by_ns.items(), key=lambda item: -item[1])[:top]:
            calls = by_n.get(name, 0)
            per = f"{ns / calls / 1000:.1f}" if calls else "-"
            print(f"{ns / 1e6:>11,.1f} {100 * ns / total_ns:>5.1f}% {calls:>10,} {per:>8}  {name}")


def diff(before: pathlib.Path, after: pathlib.Path, top: int) -> int:
    a = json.loads(before.read_text())
    b = json.loads(after.read_text())
    print(f"before: {a['git_commit'][:12]}  after: {b['git_commit'][:12]}")
    for key, label in (("syscall_n", "host syscall count"), ("syscall_ns", "host syscall on-CPU ns")):
        left = a["delta"][key]
        right = b["delta"][key]
        total_a, total_b = sum(left.values()), sum(right.values())
        change = 100 * (total_b - total_a) / total_a if total_a else 0.0
        print(f"\n== {label} == {total_a:,} -> {total_b:,} ({change:+.1f}%)")
        moved = sorted(
            ((right.get(name, 0) - left.get(name, 0), name) for name in set(left) | set(right)),
            key=lambda item: -abs(item[0]),
        )
        for value, name in moved[:top]:
            base = left.get(name, 0)
            pct = f"{100 * value / base:+.1f}%" if base else "new"
            print(f"  {value:>+12,}  {pct:>8}  {name}")
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("target/perf/native-budget.json"))
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--workload", default=DEFAULT_WORKLOAD)
    parser.add_argument("--top", type=int, default=18)
    parser.add_argument(
        "--deadline-seconds",
        type=int,
        default=75,
        help="self-exit deadline for the dtrace consumer; must exceed the run",
    )
    parser.add_argument("--settle-seconds", type=float, default=4.0)
    parser.add_argument(
        "--no-floor",
        action="store_true",
        help="skip the lifecycle-floor run; the report then mixes container setup and teardown in",
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        type=pathlib.Path,
        metavar=("BEFORE", "AFTER"),
        help="compare two saved budgets instead of capturing",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.diff:
        return diff(args.diff[0], args.diff[1], args.top)
    require_passwordless_dtrace()
    repo = pathlib.Path(__file__).resolve().parents[2]
    binary = repo / "target/release/carrick"
    if not binary.is_file():
        raise SystemExit(f"missing release binary: {binary}; run `just build`")
    scratch = pathlib.Path(
        os.environ.get("TMPDIR", "/tmp")
    ) / f"carrick-budget-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)

    runs: dict[str, dict[str, object]] = {}
    if not args.no_floor:
        # The floor guest exits in a couple of seconds, but the consumer only
        # stops on its own tick, so give it its own short deadline rather than
        # idling for the workload's.
        runs["floor"] = capture(
            repo,
            FLOOR_WORKLOAD,
            label="floor",
            image=args.image,
            deadline_s=max(15, args.deadline_seconds // 4),
            settle_s=args.settle_seconds,
            scratch=scratch,
        )
    runs["full"] = capture(
        repo,
        args.workload,
        label="full",
        image=args.image,
        deadline_s=args.deadline_seconds,
        settle_s=args.settle_seconds,
        scratch=scratch,
    )
    if not runs["full"]["guest_ok"]:
        raise SystemExit(
            "the workload guest failed; a budget from a failed run is meaningless\n"
            f"exit={runs['full']['guest_exit']}\n"
            f"stdout: {runs['full'].get('stdout', '')[-800:]}\n"
            f"stderr: {runs['full'].get('stderr', '')[-800:]}"
        )

    empty = {"syscall_ns": {}, "syscall_n": {}, "machtrap_ns": {}, "machtrap_n": {}}
    delta = subtract(runs["full"], runs.get("floor", empty))  # type: ignore[arg-type]
    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    payload = {
        "schema": SCHEMA,
        "git_commit": commit,
        "git_dirty": bool(dirty),
        "image": args.image,
        "runs": runs,
        "delta": delta,
        "floor_subtracted": not args.no_floor,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=1, sort_keys=True))
    if "floor" in runs:
        print(
            f"floor  wall={runs['floor']['wall_ms']:,} ms  "
            f"syscalls={runs['floor']['syscall_total_n']:,}  "
            f"on-CPU={runs['floor']['syscall_total_ns'] / 1e6:,.0f} ms"
        )
    print(
        f"full   wall={runs['full']['wall_ms']:,} ms  "
        f"syscalls={runs['full']['syscall_total_n']:,}  "
        f"on-CPU={runs['full']['syscall_total_ns'] / 1e6:,.0f} ms"
    )
    render(payload, args.top)
    print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
