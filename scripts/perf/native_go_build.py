#!/usr/bin/env python3
"""Measure Carrick's Darwin/native go-build reference workload reproducibly."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Sequence


SCHEMA = "carrick.native-go-build.v1"
DEFAULT_IMAGE = "localhost:5005/carrick-go-conformance:1.24"
DEFAULT_TIMEOUT_SECONDS = 180


def build_carrick_command(repo: pathlib.Path, run_id: str) -> list[str]:
    script = (
        'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; '
        'printf "package main\\nfunc main(){println(\\"ok\\")}\\n" > h.go; '
        'GOCACHE="/tmp/gc-$CARRICK_RUN_ID" '
        "/usr/local/go/bin/go build -o h ./h.go; "
        "./h; echo BUILD_OK"
    )
    return [
        str(repo / "target/release/carrick"),
        "run",
        "--exec-backend",
        "native",
        "-e",
        f"CARRICK_RUN_ID={run_id}",
        "-w",
        "/tmp",
        DEFAULT_IMAGE,
        "/bin/sh",
        "-c",
        script,
    ]


def median_ms(samples: Sequence[int]) -> int:
    if not samples:
        raise ValueError("at least one sample is required")
    return int(statistics.median(samples))


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(repo: pathlib.Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def busy_host_reasons() -> list[str]:
    reasons: list[str] = []
    process_list = subprocess.run(
        ["ps", "-eo", "pid=,args="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    own_pid = os.getpid()
    for line in process_list.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        if pid == own_pid:
            continue
        args = fields[1]
        if "while :" in args:
            reasons.append(f"orphaned spin loop: pid={pid} args={args}")
        executable = pathlib.Path(args.split(maxsplit=1)[0]).name
        if executable in {"cargo", "rustc"}:
            reasons.append(f"active compiler: pid={pid} args={args}")
        if "target/release/carrick" in args:
            reasons.append(f"active Carrick process: pid={pid} args={args}")
    logical_cpus = os.cpu_count() or 1
    one_minute_load = os.getloadavg()[0]
    if one_minute_load > logical_cpus:
        reasons.append(
            f"one-minute load {one_minute_load:.2f} exceeds "
            f"{logical_cpus} logical CPUs"
        )
    return reasons


def scoped_cleanup(repo: pathlib.Path, run_id: str) -> None:
    subprocess.run(
        [str(repo / "scripts/sudo/kill.sh"), run_id],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def run_sample(
    repo: pathlib.Path,
    index: int,
    timeout_seconds: int,
) -> dict[str, object]:
    run_id = f"native-go-build-{os.getpid()}-{time.time_ns()}-{index}"
    command = build_carrick_command(repo, run_id)
    environment = os.environ.copy()
    environment["CARRICK_RUN_ID"] = run_id
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            command,
            cwd=repo,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    finally:
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        scoped_cleanup(repo, run_id)
    combined = result.stdout + result.stderr
    if result.returncode != 0 or "BUILD_OK" not in combined:
        raise RuntimeError(
            f"go-build sample {index} failed: run_id={run_id} "
            f"rc={result.returncode}\n{combined[-8000:]}"
        )
    return {
        "index": index,
        "run_id": run_id,
        "elapsed_ms": elapsed_ms,
        "return_code": result.returncode,
        "build_ok": True,
    }


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("target/perf/native-go-build.json"),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--allow-busy",
        action="store_true",
        help="run despite active compilers, Carrick processes, spin loops, or load",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.samples <= 0:
        raise SystemExit("--samples must be positive")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")

    repo = pathlib.Path(__file__).resolve().parents[2]
    binary = repo / "target/release/carrick"
    if not binary.is_file():
        raise SystemExit(f"missing signed release binary: {binary}; run `just build`")

    reasons = busy_host_reasons()
    if reasons and not args.allow_busy:
        rendered = "\n".join(f"- {reason}" for reason in reasons)
        raise SystemExit(f"host is not idle enough for a performance claim:\n{rendered}")

    started_at = utc_now()
    sample_rows = [
        run_sample(repo, index + 1, args.timeout_seconds)
        for index in range(args.samples)
    ]
    durations = [int(sample["elapsed_ms"]) for sample in sample_rows]
    dirty_lines = git_output(repo, "status", "--porcelain").splitlines()
    payload = {
        "schema": SCHEMA,
        "started_at": started_at,
        "finished_at": utc_now(),
        "git_commit": git_output(repo, "rev-parse", "HEAD"),
        "git_dirty": bool(dirty_lines),
        "git_status": dirty_lines,
        "binary": str(binary),
        "binary_sha256": sha256_file(binary),
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "load_average": list(os.getloadavg()),
            "busy_override": bool(args.allow_busy),
            "preflight_reasons": reasons,
        },
        "sample_count": len(sample_rows),
        "samples": sample_rows,
        "median_ms": median_ms(durations),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
