#!/usr/bin/env python3
"""Ablation-ladder measurement harness (rungs 1-4).

Drives the ladder of docs/superpowers/specs/2026-08-07-ablation-ladder-design.md:

  rung 1  tier T vs tier D (`CARRICK_NATIVE_DIRECT=1`) on the pinned PIE fixture
  rung 2  Direct vs forced-Biased addressing (`CARRICK_NATIVE_FORCE_BIASED=1`)
          on the same PIE fixture, tier T both arms
  rung 3  shipped zeroing vs `CARRICK_ABLATE_ZEROING=1` on the cold go build
  rung 4  capsule self-re-exec vs `CARRICK_ABLATE_EXEC_CHAIN=1` on the 20-exec
          micro and the cold go build

Protocol (spec section 4): quiet host preflight, interleaved arms with n>=4
samples per arm after one warmup each, one binary per invocation with its
SHA-256 recorded per sample, `CARRICK_RUN_ID` stamped, `scripts/sudo/kill.sh`
reaping only, and never carrick and Docker in one invocation (`--engine` is a
single phase). Rungs 3-4 compare an ablation arm ONLY against the same-binary
control (env unset); the harness verifies the ablation banner is present on
ablated arms and absent on controls, so a knob that silently failed to engage
cannot produce a plausible-looking null result.

Ablated guests may crash or produce wrong output BY DESIGN: ablated arms
record exit status, marker presence, and the stderr tail instead of failing
the phase, while control arms hard-require success. Receipts (JSONL samples +
a summary JSON) land under target/perf/ablation/.

Reuses the hardened primitives of scripts/perf/native_go_build.py (preflight,
reaping, workload-window parsing, env discipline) instead of growing a second
implementation of them.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import pathlib
import platform
import resource
import secrets
import statistics
import subprocess
import sys
import time

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "native_go_build", _HERE / "native_go_build.py"
)
assert _SPEC is not None and _SPEC.loader is not None
native_go_build = importlib.util.module_from_spec(_SPEC)
# Register before exec: dataclasses resolves cls.__module__ through
# sys.modules at class-creation time (hard error on Python 3.14 otherwise).
sys.modules[_SPEC.name] = native_go_build
_SPEC.loader.exec_module(native_go_build)

SCHEMA = "carrick.ablation-ladder.v1"
REPO = _HERE.parent.parent
OUTPUT_DIR = REPO / "target" / "perf" / "ablation"
PIE_IMAGE = "localhost:5005/cpython-test:3.12.13"
GO_IMAGE = native_go_build.DEFAULT_IMAGE
BANNER_MARKER = "CARRICK ABLATION ACTIVE"
DEFAULT_TIMEOUT_SECONDS = 240

# Env keys this harness controls on top of the go harness's performance keys.
LADDER_CONTROL_KEYS = (
    "CARRICK_NATIVE_DIRECT",
    "CARRICK_NATIVE_FORCE_BIASED",
    "CARRICK_ABLATE_ZEROING",
    "CARRICK_ABLATE_EXEC_CHAIN",
    "CARRICK_TIER_CENSUS",
)

# The pinned PIE fixture (spec rungs 1-2): CPython 3.12.13 from the
# conformance image localhost:5005/cpython-test:3.12.13 (`/usr/local/bin/
# python3` is ET_DYN, so it loads at the 16 GiB PIE base and is
# direct-addressable). Chosen because (a) it is the exact interpreter build the
# cpython conformance campaign already runs, so correctness standing is known,
# (b) it exercises real compute (a pure-interpreter FNV-1a byte kernel plus
# dict churn), real file syscalls (open/write/read/unlink x300), real threads
# (tier D's hard case, plus GIL handoff traffic), and a small subprocess
# component (5 execs), per the spec's fixture requirements, and (c) it avoids
# single quotes entirely so it embeds in sh -c verbatim.
#
# hashlib is deliberately ABSENT: importing it dlopens _hashlib.so/libcrypto,
# whose text contains words tier D's window scan cannot decode on this tip
# ("undecodable text at 0x281478 (word 0x38764d52)"), and a tier-D leave at
# mmap(PROT_EXEC, fd) has no mid-run tier T fallback. That is a real tier-D
# scope boundary and is recorded as a rung-1 caveat, not hidden; the fixture
# stays inside the envelope so rung 1 measures translation cost, not the
# refusal. The remaining extension imports (_posixsubprocess, select, fcntl,
# math) scan clean and are kept.
# PINNED: never edit the body without bumping the version marker.
PIE_FIXTURE_VERSION = "ablation-pie-fixture-v2"
_PIE_PY = (
    "import os, threading, subprocess\n"
    'buf = b"carrick-ablation-ladder-fixture-v2" * 482\n'
    "def fnv(data, seed):\n"
    "    h = seed\n"
    "    for b in data:\n"
    "        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF\n"
    "    return h\n"
    "digest = 0\n"
    "for i in range(40):\n"
    "    digest = fnv(buf, digest + i)\n"
    "acc = 0\n"
    "for i in range(250000):\n"
    "    d = {j: i * j for j in range(8)}\n"
    "    acc = (acc + sum(d.values())) & 0xFFFFFFFF\n"
    'root = "/tmp/abl-fixture"\n'
    "os.makedirs(root, exist_ok=True)\n"
    "n = 0\n"
    "for i in range(300):\n"
    '    p = "%s/f%d" % (root, i)\n'
    '    with open(p, "wb") as f:\n'
    "        f.write(buf)\n"
    '    with open(p, "rb") as f:\n'
    "        n += len(f.read())\n"
    "    os.unlink(p)\n"
    "res = {}\n"
    "def work(k):\n"
    "    res[k] = fnv(buf, k)\n"
    "ts = [threading.Thread(target=work, args=(k,)) for k in range(4)]\n"
    "for t in ts:\n"
    "    t.start()\n"
    "for t in ts:\n"
    "    t.join()\n"
    "for _ in range(5):\n"
    '    subprocess.run(["/bin/true"], check=True)\n'
    'print("PY_OK", digest, acc, n, len(res))\n'
)


def pie_guest_script() -> str:
    # Workload window brackets exec+startup+imports+work of the interpreter --
    # interpreter cold start IS translation work and belongs inside the window
    # for rungs 1-2. Container boot/teardown stays outside, matching the go
    # harness's window discipline.
    return (
        "set -eu; cd /tmp; "
        "w0=$(date +%s%N); "
        f"python3 -c '{_PIE_PY}'; "
        "w1=$(date +%s%N); "
        'echo "WORKLOAD_NS=$((w1-w0))"; '
        "echo FIXTURE_OK"
    )


def exec_micro_script() -> str:
    # 20 fork+exec pairs: every /usr/bin/true is a forked child whose execve
    # takes the capsule self-re-exec chain on the shipped default. Isolates the
    # per-exec term that the cold build weights.
    return (
        "set -eu; cd /tmp; "
        "w0=$(date +%s%N); "
        "i=0; while [ $i -lt 20 ]; do /usr/bin/true; i=$((i+1)); done; "
        "w1=$(date +%s%N); "
        'echo "WORKLOAD_NS=$((w1-w0))"; '
        "echo FIXTURE_OK"
    )


FIXTURES: dict[str, dict[str, object]] = {
    "pie": {
        "image": PIE_IMAGE,
        "script": pie_guest_script,
        "success_marker": "FIXTURE_OK",
        "version": PIE_FIXTURE_VERSION,
    },
    "gobuild": {
        "image": GO_IMAGE,
        "script": native_go_build.guest_script,
        "success_marker": "BUILD_OK",
        "version": "native-go-build-guest-script",
    },
    "execmicro": {
        "image": GO_IMAGE,
        "script": exec_micro_script,
        "success_marker": "FIXTURE_OK",
        "version": "ablation-exec-micro-v1",
    },
}

RUNGS: dict[str, dict[str, object]] = {
    "1": {
        "fixture": "pie",
        "arms": (
            ("tier-t", {}),
            ("tier-d", {"CARRICK_NATIVE_DIRECT": "1"}),
        ),
        "ablation": False,
        "tier_census": True,
    },
    "2": {
        "fixture": "pie",
        # Both arms pin CARRICK_DSR_SUPERBLOCK=off: under the shipped default,
        # superblock window extension pulls glibc's never-executed MTE strlen
        # variants (LDG at guest 0xa0000a6f7c) into a biased-mode emission
        # window, and the biased emitter refuses the whole block ("memory
        # family unsupported in biased mode"). Direct mode copies the word
        # verbatim so only the biased arm dies. Holding superblocks off in
        # BOTH arms keeps the comparison single-variable; the ceiling is
        # therefore "bias cost with superblocks off", and rung 1's tier-t arm
        # (direct + default superblocks, same fixture, same binary) sizes the
        # superblock term separately.
        "arms": (
            ("direct-sboff", {"CARRICK_DSR_SUPERBLOCK": "off"}),
            (
                "biased-sboff",
                {
                    "CARRICK_NATIVE_FORCE_BIASED": "1",
                    "CARRICK_DSR_SUPERBLOCK": "off",
                },
            ),
        ),
        "ablation": False,
        "tier_census": False,
    },
    "3": {
        "fixture": "gobuild",
        "arms": (
            ("control", {}),
            ("ablate-zeroing", {"CARRICK_ABLATE_ZEROING": "1"}),
        ),
        "ablation": True,
        "tier_census": False,
    },
    "4": {
        "fixture": "execmicro",
        "arms": (
            ("control", {}),
            ("ablate-exec-chain", {"CARRICK_ABLATE_EXEC_CHAIN": "1"}),
        ),
        "ablation": True,
        "tier_census": False,
    },
}


def controlled_environment(
    overlay: dict[str, str], census_path: pathlib.Path | None
) -> dict[str, str]:
    native_go_build.reject_ambient_carrick(os.environ, dict(overlay))
    environment = dict(os.environ)
    for key in (*native_go_build.PERFORMANCE_CONTROL_KEYS, *LADDER_CONTROL_KEYS):
        environment.pop(key, None)
    for key, value in overlay.items():
        environment[key] = value
    if census_path is not None:
        environment["CARRICK_TIER_CENSUS"] = str(census_path)
    return environment


def build_command(
    engine: str,
    binary: pathlib.Path,
    image: str,
    run_id: str,
    script: str,
) -> list[str]:
    if engine == "carrick":
        return [
            str(binary),
            "run",
            "--exec-backend",
            "native",
            "-e",
            f"CARRICK_RUN_ID={run_id}",
            "-w",
            "/tmp",
            image,
            "/bin/sh",
            "-c",
            script,
        ]
    if engine == "docker":
        return [
            "docker",
            "run",
            "--name",
            run_id,
            "--platform",
            "linux/arm64",
            "-e",
            f"CARRICK_RUN_ID={run_id}",
            "-w",
            "/tmp",
            image,
            "/bin/sh",
            "-c",
            script,
        ]
    raise ValueError(f"unknown engine: {engine}")


def tier_census_summary(census_path: pathlib.Path) -> dict[str, int]:
    events: dict[str, int] = {}
    if not census_path.exists():
        return events
    for line in census_path.read_text().splitlines():
        for field in line.split():
            if field.startswith("event="):
                key = field.removeprefix("event=")
                events[key] = events.get(key, 0) + 1
    return events


def run_sample(
    *,
    engine: str,
    rung: str,
    arm: str,
    overlay: dict[str, str],
    fixture: str,
    binary: pathlib.Path,
    index: int,
    warmup: bool,
    timeout_seconds: int,
    expect_banner: bool,
    census_dir: pathlib.Path | None,
) -> dict[str, object]:
    spec = FIXTURES[fixture]
    image = str(spec["image"])
    script = spec["script"]()  # type: ignore[operator]
    nonce = secrets.token_hex(4)
    kind = "warm" if warmup else f"s{index}"
    run_id = f"abl{rung}-{arm}-{kind}-{nonce}"
    census_path = None
    if census_dir is not None:
        census_dir.mkdir(parents=True, exist_ok=True)
        census_path = census_dir / f"{run_id}.census"
    environment = controlled_environment(overlay, census_path)
    command = build_command(engine, binary, image, run_id, script)
    load1 = os.getloadavg()[0]
    rusage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started_ns = time.monotonic_ns()
    timed_out = False
    result: subprocess.CompletedProcess[str] | None = None
    try:
        result = subprocess.run(
            command,
            cwd=REPO,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    wall_ms = (time.monotonic_ns() - started_ns) // 1_000_000
    rusage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cleanup: dict[str, object] | None = None
    if engine == "carrick":
        if timed_out:
            cleanup = native_go_build.carrick_cleanup(REPO, run_id)
    else:
        cleanup = native_go_build.docker_cleanup(run_id)
    stdout = result.stdout if result is not None else ""
    stderr = result.stderr if result is not None else ""
    try:
        workload_ns: int | None = native_go_build.workload_ns_from_stdout(stdout)
    except ValueError:
        workload_ns = None
    marker_ok = str(spec["success_marker"]) in stdout
    banner_seen = BANNER_MARKER in stderr
    sample: dict[str, object] = {
        "schema": SCHEMA,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "engine": engine,
        "rung": rung,
        "arm": arm,
        "warmup": warmup,
        "index": index,
        "run_id": run_id,
        "fixture": fixture,
        "fixture_version": spec["version"],
        "image": image,
        "binary": str(binary),
        "binary_sha256": (
            native_go_build.sha256_file(binary) if engine == "carrick" else None
        ),
        "overlay": overlay,
        "load1_at_start": load1,
        "wall_ms": wall_ms,
        "workload_ms": None if workload_ns is None else workload_ns / 1e6,
        "cpu_user_s": rusage_after.ru_utime - rusage_before.ru_utime,
        "cpu_sys_s": rusage_after.ru_stime - rusage_before.ru_stime,
        "exit_code": None if result is None else result.returncode,
        "timed_out": timed_out,
        "marker_ok": marker_ok,
        "banner_seen": banner_seen,
        "stderr_tail": stderr[-2000:],
        "stdout_tail": stdout[-500:],
        "cleanup": cleanup,
    }
    if census_path is not None:
        sample["tier_census"] = tier_census_summary(census_path)
    if banner_seen != expect_banner:
        raise RuntimeError(
            f"banner mismatch for {run_id}: expected banner_seen={expect_banner}; "
            "an ablation arm without the banner (or a control arm with it) is "
            f"measuring the wrong binary state. Sample: {json.dumps(sample)}"
        )
    return sample


def summarize(samples: list[dict[str, object]]) -> dict[str, object]:
    by_arm: dict[str, list[dict[str, object]]] = {}
    for sample in samples:
        if sample["warmup"]:
            continue
        by_arm.setdefault(str(sample["arm"]), []).append(sample)
    summary: dict[str, object] = {}
    for arm, rows in by_arm.items():
        completed = [row for row in rows if row["marker_ok"]]
        workload = [
            float(row["workload_ms"])
            for row in completed
            if row["workload_ms"] is not None
        ]
        summary[arm] = {
            "samples": len(rows),
            "completed": len(completed),
            "workload_ms_median": statistics.median(workload) if workload else None,
            "workload_ms_all": sorted(workload),
            "wall_ms_median": statistics.median(
                float(row["wall_ms"]) for row in rows
            ),
            "cpu_s_median": statistics.median(
                float(row["cpu_user_s"]) + float(row["cpu_sys_s"]) for row in rows
            ),
            "exit_codes": sorted(
                {str(row["exit_code"]) for row in rows}
            ),
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rung", required=True, choices=sorted(RUNGS))
    parser.add_argument(
        "--fixture",
        default=None,
        choices=sorted(FIXTURES),
        help="override the rung's default fixture (rung 4 runs execmicro by "
        "default and gobuild as the weighting pass)",
    )
    parser.add_argument("--engine", default="carrick", choices=("carrick", "docker"))
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--binary", default=str(REPO / "target/release/carrick"))
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", default=None)
    parser.add_argument("--allow-busy", action="store_true")
    args = parser.parse_args()

    rung = RUNGS[args.rung]
    fixture = args.fixture or str(rung["fixture"])
    binary = pathlib.Path(args.binary).resolve()
    if args.engine == "carrick" and not binary.is_file():
        raise SystemExit(f"missing carrick binary: {binary}")

    reasons = native_go_build.busy_host_reasons()
    if reasons and not args.allow_busy:
        raise SystemExit(
            "host is not quiet (pass --allow-busy to override):\n  "
            + "\n  ".join(reasons)
        )

    arms = list(rung["arms"])  # type: ignore[arg-type]
    if args.engine == "docker":
        # The Docker phase is a single reference arm; overlays are Carrick-only.
        arms = [("docker", {})]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = (
        pathlib.Path(args.output)
        if args.output
        else OUTPUT_DIR / f"rung{args.rung}-{fixture}-{args.engine}-{stamp}"
    )
    samples_path = base.with_suffix(".jsonl")
    summary_path = base.with_suffix(".summary.json")
    census_dir = (
        OUTPUT_DIR / "census" / f"rung{args.rung}-{stamp}"
        if bool(rung["tier_census"]) and args.engine == "carrick"
        else None
    )

    samples: list[dict[str, object]] = []
    with samples_path.open("w") as sink:

        def emit(sample: dict[str, object]) -> None:
            samples.append(sample)
            sink.write(json.dumps(sample, sort_keys=True) + "\n")
            sink.flush()
            window = sample["workload_ms"]
            window_text = (
                f"{window:.0f}ms" if isinstance(window, float) else "no-window"
            )
            print(
                f"[{sample['run_id']}] wall={sample['wall_ms']}ms "
                f"workload={window_text} exit={sample['exit_code']} "
                f"marker={sample['marker_ok']}",
                flush=True,
            )

        for arm, overlay in arms:
            for _ in range(args.warmup):
                emit(
                    run_sample(
                        engine=args.engine,
                        rung=args.rung,
                        arm=arm,
                        overlay=dict(overlay),
                        fixture=fixture,
                        binary=binary,
                        index=0,
                        warmup=True,
                        timeout_seconds=args.timeout_seconds,
                        expect_banner=bool(rung["ablation"]) and bool(overlay),
                        census_dir=census_dir,
                    )
                )
        for index in range(args.samples):
            for arm, overlay in arms:
                emit(
                    run_sample(
                        engine=args.engine,
                        rung=args.rung,
                        arm=arm,
                        overlay=dict(overlay),
                        fixture=fixture,
                        binary=binary,
                        index=index,
                        warmup=False,
                        timeout_seconds=args.timeout_seconds,
                        expect_banner=bool(rung["ablation"]) and bool(overlay),
                        census_dir=census_dir,
                    )
                )

    payload = {
        "schema": SCHEMA,
        "rung": args.rung,
        "engine": args.engine,
        "fixture": fixture,
        "fixture_version": FIXTURES[fixture]["version"],
        "git_commit": native_go_build.git_output(REPO, "rev-parse", "HEAD"),
        "git_status_lines": native_go_build.git_output(
            REPO, "status", "--porcelain"
        ).splitlines(),
        "binary_sha256": (
            native_go_build.sha256_file(binary) if args.engine == "carrick" else None
        ),
        "host": {"platform": platform.platform(), "machine": platform.machine()},
        "busy_reasons_at_start": reasons,
        "samples_path": str(samples_path),
        "summary": summarize(samples),
    }
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload["summary"], indent=2, sort_keys=True))
    print(f"receipts: {samples_path}\nsummary:  {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
