#!/usr/bin/env python3
"""Run the curated static-musl LTP gate through FreeBSD native x86 DSR.

Each case owns a process group and a file-backed merged output stream so forked
LTP workers cannot disappear behind the top-level RunResult buffers. The JSONL
artifact retains the ordered raw TPASS/TFAIL/TBROK/TCONF lines for a later
same-binary native-amd64 Linux oracle comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable

SCHEMA_VERSION = 1
FIXTURE = "ltp-20260529-x86_64-musl-static-pie"
RESULT_MARKERS = ("TPASS", "TFAIL", "TBROK", "TCONF")


@dataclass(frozen=True)
class Case:
    name: str
    relative_binary: Path
    args: tuple[str, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_cases(path: Path) -> list[Case]:
    cases: list[Case] = []
    names: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            fields = shlex.split(stripped, comments=True, posix=True)
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: {error}") from error
        if len(fields) < 2:
            raise ValueError(f"{path}:{line_number}: expected name and relative binary")
        name = fields[0]
        if name in names:
            raise ValueError(f"{path}:{line_number}: duplicate case {name!r}")
        relative = Path(fields[1])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"{path}:{line_number}: binary path must stay below --ltp-bin-root")
        names.add(name)
        cases.append(Case(name, relative, tuple(fields[2:])))
    if not cases:
        raise ValueError(f"{path}: no cases declared")
    return cases


def assertion_lines(output: str) -> list[str]:
    return [
        line.rstrip("\r")
        for line in output.splitlines()
        if any(f"{marker}:" in line for marker in RESULT_MARKERS)
    ]


def assertion_counts(lines: Iterable[str]) -> dict[str, int]:
    counts = {marker: 0 for marker in RESULT_MARKERS}
    for line in lines:
        for marker in RESULT_MARKERS:
            if f"{marker}:" in line:
                counts[marker] += 1
                break
    return counts


def local_status(exit_code: int | None, timed_out: bool, counts: dict[str, int]) -> str:
    if timed_out:
        return "timeout"
    if exit_code == 125:
        return "runner_error"
    if counts["TFAIL"] or counts["TBROK"]:
        return "ltp_failure"
    if counts["TCONF"] and not counts["TPASS"]:
        # LTP uses a nonzero process status for a clean configuration skip.
        return "conf"
    if exit_code != 0:
        return "nonzero_exit"
    if counts["TPASS"]:
        return "pass"
    if counts["TCONF"]:
        return "conf"
    return "no_assertions"


def terminate_group(process: subprocess.Popen[bytes], grace_seconds: float = 2.0) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass


def run_case(
    case: Case,
    *,
    runner: Path,
    ltp_bin_root: Path,
    rootfs: Path,
    log_dir: Path,
    timeout_seconds: float,
) -> dict[str, object]:
    binary = (ltp_bin_root / case.relative_binary).resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"{case.name}: missing LTP binary: {binary}")

    log_path = log_dir / f"{case.name}.log"
    command = [str(runner), str(binary), *case.args]
    environment = os.environ.copy()
    environment.update(
        {
            "CARRICK_MMAP_ARENA_GIB": "1",
            "CARRICK_NATIVE_RAW_OUTPUT": "1",
            "CARRICK_NATIVE_ROOTFS": str(rootfs),
            "CARRICK_RUN_ID": f"native-x86-ltp-{os.getpid()}-{case.name}",
        }
    )

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    with log_path.open("wb") as output:
        process = subprocess.Popen(
            command,
            cwd=str(ltp_bin_root),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_group(process)
            exit_code = process.returncode
        finally:
            # A successfully exited runner may still have an accidental worker;
            # scope cleanup to this case's process group rather than broad pkill.
            terminate_group(process, grace_seconds=0.25)
    elapsed_ms = round((time.monotonic() - started) * 1000, 3)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)

    output_text = log_path.read_text(encoding="utf-8", errors="replace")
    assertions = assertion_lines(output_text)
    counts = assertion_counts(assertions)
    status = local_status(exit_code, timed_out, counts)
    helper_hashes = {
        relative: sha256_file(rootfs / relative)
        for relative in ("bin/sh", "bin/zcat")
        if (rootfs / relative).is_file()
    }
    return {
        "schema": SCHEMA_VERSION,
        "fixture": FIXTURE,
        "case": case.name,
        "binary": str(binary),
        "binary_sha256": sha256_file(binary),
        "runner_sha256": sha256_file(runner),
        "rootfs_helpers_sha256": helper_hashes,
        "argv": [str(binary), *case.args],
        "exit_code": exit_code,
        "timed_out": timed_out,
        "local_status": status,
        "assertions": assertions,
        "counts": counts,
        "wall_ms": elapsed_ms,
        "user_ms": round((after.ru_utime - before.ru_utime) * 1000, 3),
        "sys_ms": round((after.ru_stime - before.ru_stime) * 1000, 3),
        "log": str(log_path),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument(
        "--runner",
        type=Path,
        default=repo / "target/debug/examples/native_run",
        help="native_run executable",
    )
    parser.add_argument("--ltp-bin-root", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument(
        "--cases",
        type=Path,
        default=repo / "scripts/native-x86-ltp-cases.txt",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=60.0)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    runner = args.runner.resolve()
    ltp_bin_root = args.ltp_bin_root.resolve()
    rootfs = args.rootfs.resolve()
    cases_path = args.cases.resolve()
    output_path = args.output.resolve()
    log_dir = (args.log_dir or output_path.with_suffix(output_path.suffix + ".logs")).resolve()

    if not runner.is_file():
        print(f"error: missing native runner: {runner}", file=sys.stderr)
        return 2
    if not ltp_bin_root.is_dir():
        print(f"error: missing LTP binary root: {ltp_bin_root}", file=sys.stderr)
        return 2
    if not rootfs.is_dir():
        print(f"error: missing prepared rootfs: {rootfs}", file=sys.stderr)
        return 2
    missing_helpers = [
        str(rootfs / relative)
        for relative in ("bin/sh", "bin/zcat")
        if not (rootfs / relative).is_file()
    ]
    if missing_helpers:
        print(
            f"error: prepared rootfs is missing helper(s): {', '.join(missing_helpers)}",
            file=sys.stderr,
        )
        return 2
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return 2

    try:
        cases = load_cases(cases_path)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    log_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    failed = False
    with temporary.open("w", encoding="utf-8") as artifact:
        for case in cases:
            try:
                row = run_case(
                    case,
                    runner=runner,
                    ltp_bin_root=ltp_bin_root,
                    rootfs=rootfs,
                    log_dir=log_dir,
                    timeout_seconds=args.timeout,
                )
            except OSError as error:
                print(f"error: {error}", file=sys.stderr)
                return 2
            artifact.write(json.dumps(row, sort_keys=True) + "\n")
            artifact.flush()
            print(
                f"{case.name}: {row['local_status']} "
                f"TPASS={row['counts']['TPASS']} wall_ms={row['wall_ms']}",
                file=sys.stderr,
            )
            failed |= row["local_status"] not in {"pass", "conf"}
    temporary.replace(output_path)
    print(f"wrote {len(cases)} case(s) to {output_path}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
