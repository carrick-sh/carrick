#!/usr/bin/env python3
"""Repeat the canonical Tier-D Node app with scoped cleanup and receipts.

This is a correctness/reliability gate, not a latency benchmark.  It runs one
Carrick process tree at a time, requires the fixture's exact successful output,
and appends a provenance-bound JSON record after every iteration so a timeout
or interrupted campaign cannot turn partial evidence into a plausible green.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


IMAGE = "localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0"
FIXTURE = "/opt/nodejs-conformance/fixtures/app-smoke.js"
NODE = "/opt/node-src/v24/out/Release/node"
EXPECTED_STDOUT = b"app-smoke ok\n"
CHILD_SCRIPT = r'''const cp=require("child_process");
process.stderr.write("phase=before-child\n");
const r=cp.spawnSync(process.execPath,["-e","process.stdout.write(process.argv[1])","child-ok"],{encoding:"utf8"});
process.stderr.write("phase=after-child\n");
console.log(JSON.stringify({status:r.status,signal:r.signal,stdout:r.stdout,stderr:r.stderr,error:r.error&&String(r.error)}));
process.exit(r.status===0&&r.stdout==="child-ok"?0:1);'''
CHILD_EXPECTED_STDOUT = (
    b'{"status":0,"signal":null,"stdout":"child-ok","stderr":""}\n'
)
CHILD_EXPECTED_STDERR = b"phase=before-child\nphase=after-child\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_output(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], check=True, stdout=subprocess.PIPE
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/carrick"))
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-prefix", default="tierd-node-reliability")
    parser.add_argument("--workload", choices=("app", "child"), default="app")
    args = parser.parse_args()

    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.output.exists():
        parser.error(f"refusing to overwrite existing receipt: {args.output}")

    binary = args.binary.resolve()
    binary_bytes = binary.read_bytes()
    git_sha = git_output("rev-parse", "HEAD").decode().strip()
    status = git_output("status", "--porcelain=v1", "--untracked-files=all")
    diff = git_output("diff", "--binary", "HEAD")
    campaign = f"{args.run_prefix}-{time.time_ns()}"
    args.output.parent.mkdir(parents=True, exist_ok=True)

    workload_args, expected_stdout, expected_stderr = {
        "app": ([FIXTURE], EXPECTED_STDOUT, b""),
        "child": (["--", "-e", CHILD_SCRIPT], CHILD_EXPECTED_STDOUT, CHILD_EXPECTED_STDERR),
    }[args.workload]
    base_command = [
        str(binary),
        "run",
        "--max-traps",
        "100000000",
        "--raw",
        "--fs",
        "host",
        "--entrypoint",
        NODE,
        "--exec-backend",
        "native",
        "--native-page-profile",
        "native16k",
        IMAGE,
        *workload_args,
    ]

    failures = 0
    with args.output.open("x", encoding="utf-8") as receipt:
        for iteration in range(1, args.iterations + 1):
            run_id = f"{campaign}-{iteration:03d}"
            command = base_command.copy()
            command[2:2] = ["--name", run_id]
            environment = os.environ.copy()
            environment["CARRICK_RUN_ID"] = run_id
            environment["CARRICK_NATIVE_DIRECT"] = "1"
            started = time.monotonic_ns()
            timed_out = False
            try:
                completed = subprocess.run(
                    command,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=args.timeout,
                    check=False,
                )
                returncode = completed.returncode
                stdout = completed.stdout
                stderr = completed.stderr
            except subprocess.TimeoutExpired as error:
                timed_out = True
                returncode = None
                stdout = error.stdout or b""
                stderr = error.stderr or b""
                subprocess.run(
                    ["scripts/sudo/kill.sh", run_id],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
            except KeyboardInterrupt:
                subprocess.run(
                    ["scripts/sudo/kill.sh", run_id],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
                raise
            elapsed_ns = time.monotonic_ns() - started
            passed = (
                not timed_out
                and returncode == 0
                and stdout == expected_stdout
                and stderr == expected_stderr
            )
            if not passed:
                failures += 1
            record = {
                "schema": "carrick.tier-d-node-reliability.v1",
                "campaign": campaign,
                "workload": args.workload,
                "iteration": iteration,
                "run_id": run_id,
                "passed": passed,
                "timed_out": timed_out,
                "returncode": returncode,
                "elapsed_ns": elapsed_ns,
                "stdout_sha256": sha256(stdout),
                "stderr_sha256": sha256(stderr),
                "stdout_tail": stdout[-2000:].decode("utf-8", "replace"),
                "stderr_tail": stderr[-2000:].decode("utf-8", "replace"),
                "provenance": {
                    "git_sha": git_sha,
                    "git_status_sha256": sha256(status),
                    "git_diff_sha256": sha256(diff),
                    "binary_sha256": sha256(binary_bytes),
                    "platform": platform.platform(),
                    "command": command,
                },
            }
            receipt.write(json.dumps(record, sort_keys=True) + "\n")
            receipt.flush()
            print(
                f"{iteration:03d}/{args.iterations:03d} "
                f"{'PASS' if passed else 'FAIL'} "
                f"elapsed_ms={elapsed_ns / 1_000_000:.1f} rc={returncode}",
                flush=True,
            )

    print(
        json.dumps(
            {
                "campaign": campaign,
                "iterations": args.iterations,
                "passed": args.iterations - failures,
                "failed": failures,
                "receipt": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
