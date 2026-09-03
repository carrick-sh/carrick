#!/usr/bin/env python3
"""Capture isolated release-mode receipts for exec terminal ownership handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


SCHEMA = "carrick.atomic-exec-terminal-handoff-abba.v1"
PREFIX = "CARRICK_EXEC_TERMINAL_PERF|"
OPERATIONS = ("generic_exit_claim", "exec_error_to_terminal")
REDUCER_TEST_SUFFIX = "clone_admission_terminal_claim_cost_receipt"
CENSUS_POLL_SECONDS = 0.1
PROCESS_GROUP_GRACE_SECONDS = 5.0
PROCESS_GROUP_POLL_SECONDS = 0.05
SAMPLE_FIELDS = frozenset(
    {
        "operation",
        "sample",
        "iterations",
        "elapsed_ns",
        "ns_per_transition",
        "contender_admissions",
    }
)
FOREIGN_PROCESS_PATTERNS = (
    re.compile(r"(?:^|\s)\S*carrick\s+run(?:\s|$)"),
    re.compile(r"carrick[-_]conformance"),
    re.compile(r"conformance[-_]next(?:[-_/]|\b)"),
    re.compile(r"docker\s+build(?:\s|$)"),
    re.compile(
        r"(?:^|\s)\S*carrick_runtime-[0-9A-Fa-f]+\s+"
        rf"\S*{REDUCER_TEST_SUFFIX}(?:\s|$)"
    ),
)
RUNNER_PROCESS_PATTERN = re.compile(
    r"^(?:\S*/)?(?:python(?:\d+(?:\.\d+)*)?|Python)\s+\S*atomic_exec_terminal_handoff_abba\.py(?:\s|$)"
)
MACHO_UUID = re.compile(r"^UUID: ([0-9A-Fa-f-]{36}) \(")


def abba_refs(baseline: str, candidate: str) -> list[tuple[str, str]]:
    return [("A1", baseline), ("B1", candidate), ("B2", candidate), ("A2", baseline)]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(
    command: list[str], *, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)


def require_command(
    command: list[str], *, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    completed = run_command(command, cwd=cwd, env=env)
    if completed.returncode != 0:
        raise ValueError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def resolve_ref(repo: Path, ref: str) -> str:
    return require_command(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo).stdout.strip()


def macho_uuid(executable: Path) -> str:
    executable = executable.resolve()
    dwarfdump = dwarfdump_path()
    if dwarfdump is None:
        raise ValueError("dwarfdump is required to identify the test executable")
    output = require_command([str(dwarfdump), "--uuid", str(executable)], cwd=executable.parent).stdout
    for line in output.splitlines():
        matched = MACHO_UUID.match(line)
        if matched:
            return matched.group(1).upper()
    raise ValueError(f"no Mach-O UUID found for {executable}")


def dwarfdump_path() -> Path | None:
    system_dwarfdump = Path("/usr/bin/dwarfdump")
    if system_dwarfdump.is_file():
        return system_dwarfdump
    discovered = shutil.which("dwarfdump")
    return Path(discovered) if discovered is not None else None


def executable_identity(executable: Path) -> dict[str, str]:
    return {
        "path": str(executable.resolve()),
        "sha256": sha256_file(executable),
        "macho_uuid": macho_uuid(executable),
    }


def record_executable_identity(
    identities: dict[str, dict[str, str]], ref: str, identity: dict[str, str]
) -> None:
    prior = identities.get(ref)
    comparable = {key: identity[key] for key in ("sha256", "macho_uuid")}
    if prior is not None and {key: prior[key] for key in comparable} != comparable:
        raise ValueError(f"executable identity changed for ref {ref}")
    identities.setdefault(ref, identity)


def parse_test_executable(build_stdout: str) -> Path:
    executable: Path | None = None
    for line in build_stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "carrick_runtime"
            and message.get("profile", {}).get("test") is True
            and message.get("executable")
        ):
            candidate = Path(message["executable"])
            if executable is not None and executable != candidate:
                raise ValueError("cargo reported multiple carrick_runtime test executables")
            executable = candidate
    if executable is None:
        raise ValueError("cargo did not report a carrick_runtime test executable")
    return executable


def discover_reducer_test_name(executable: Path) -> str:
    listed = require_command([str(executable), "--list"], cwd=executable.parent).stdout
    names = [
        line.removesuffix(": test")
        for line in listed.splitlines()
        if line.endswith(": test") and line.removesuffix(": test").endswith(REDUCER_TEST_SUFFIX)
    ]
    if len(names) != 1:
        raise ValueError(f"expected exactly one reducer test, found {names!r}")
    return names[0]


def reducer_command(executable: Path, test_name: str) -> list[str]:
    return [str(executable), test_name, "--ignored", "--nocapture", "--exact"]


def parse_samples(output: str) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for line in output.splitlines():
        if PREFIX not in line:
            continue
        try:
            row = json.loads(line.split(PREFIX, 1)[1])
        except json.JSONDecodeError as error:
            raise ValueError(f"malformed reducer sample: {line}") from error
        if not isinstance(row, dict):
            raise ValueError("reducer sample must be a JSON object")
        samples.append(row)
    return samples


def validate_samples(rows: list[dict[str, Any]], *, iterations: int, samples: int) -> None:
    by_operation: dict[str, list[dict[str, Any]]] = {operation: [] for operation in OPERATIONS}
    for row in rows:
        row_fields = frozenset(row)
        if row_fields != SAMPLE_FIELDS:
            missing = sorted(SAMPLE_FIELDS - row_fields)
            extra = sorted(row_fields - SAMPLE_FIELDS)
            raise ValueError(f"reducer sample schema mismatch: missing={missing} extra={extra}")
        operation = row.get("operation")
        if operation not in by_operation:
            raise ValueError(f"unknown reducer operation: {operation!r}")
        if not isinstance(row["iterations"], int) or isinstance(row["iterations"], bool):
            raise ValueError(f"{operation} iteration count is invalid")
        if row["iterations"] != iterations:
            raise ValueError(f"{operation} iteration count differs from requested {iterations}")
        if (
            not isinstance(row["contender_admissions"], int)
            or isinstance(row["contender_admissions"], bool)
        ):
            raise ValueError(f"{operation} contender admission count is invalid")
        if row["contender_admissions"] != 0:
            raise ValueError(f"{operation} admitted a contender")
        if not isinstance(row["sample"], int) or isinstance(row["sample"], bool):
            raise ValueError(f"{operation} sample index is invalid")
        if not isinstance(row["elapsed_ns"], int) or isinstance(row["elapsed_ns"], bool):
            raise ValueError(f"{operation} elapsed timing is invalid")
        if row["elapsed_ns"] <= 0:
            raise ValueError(f"{operation} elapsed timing must be positive")
        if (
            not isinstance(row["ns_per_transition"], (int, float))
            or isinstance(row["ns_per_transition"], bool)
            or not math.isfinite(row["ns_per_transition"])
            or row["ns_per_transition"] <= 0
        ):
            raise ValueError(f"{operation} timing is invalid")
        expected_ns_per_transition = row["elapsed_ns"] / row["iterations"]
        if not math.isclose(
            row["ns_per_transition"],
            expected_ns_per_transition,
            rel_tol=1e-12,
            abs_tol=0.0,
        ):
            raise ValueError(f"{operation} ns_per_transition does not match elapsed_ns / iterations")
        by_operation[operation].append(row)
    for operation, operation_rows in by_operation.items():
        if len(operation_rows) != samples:
            raise ValueError(f"{operation} expected {samples} samples, found {len(operation_rows)}")
        indices = [row["sample"] for row in operation_rows]
        if sorted(indices) != list(range(samples)):
            raise ValueError(f"{operation} has missing or duplicate sample indices")


def nearest_rank_p95(values: list[float]) -> float:
    if not values:
        raise ValueError("cannot aggregate empty samples")
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * 0.95) - 1]


def aggregate(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    result: dict[str, dict[str, float]] = {}
    for operation in OPERATIONS:
        values = [float(row["ns_per_transition"]) for row in rows if row["operation"] == operation]
        ordered = sorted(values)
        midpoint = len(ordered) // 2
        median = ordered[midpoint] if len(ordered) % 2 else (ordered[midpoint - 1] + ordered[midpoint]) / 2
        result[operation] = {"median_ns_per_transition": median, "p95_ns_per_transition": nearest_rank_p95(values)}
    return result


def performance_verdict(
    *,
    baseline_median: float,
    baseline_p95: float,
    candidate_median: float,
    candidate_p95: float,
    contender_admissions: int,
) -> dict[str, Any]:
    timings = (baseline_median, baseline_p95, candidate_median, candidate_p95)
    if any(
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
        for value in timings
    ):
        raise ValueError("timings must be finite and positive")
    median_ratio = candidate_median / baseline_median
    p95_ratio = candidate_p95 / baseline_p95
    return {
        "generic_median_ratio": median_ratio,
        "generic_p95_ratio": p95_ratio,
        "contender_admissions": contender_admissions,
        "accepted": median_ratio <= 1.05 and p95_ratio <= 1.10 and contender_admissions == 0,
    }


def foreign_processes(exclude_pids: set[int]) -> list[dict[str, Any]]:
    completed = require_command(["ps", "-axo", "pid=,command="], cwd=Path.cwd())
    matches: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        pid = int(fields[0])
        command = fields[1]
        if pid in exclude_pids:
            continue
        if matches_foreign_process(command):
            matches.append({"pid": pid, "command": command})
    return matches


def matches_foreign_process(command: str) -> bool:
    return RUNNER_PROCESS_PATTERN.search(command) is not None or any(
        pattern.search(command) for pattern in FOREIGN_PROCESS_PATTERNS
    )


def clean_census(phase: str, exclude_pids: set[int]) -> dict[str, Any]:
    matches = foreign_processes(exclude_pids)
    if matches:
        raise ValueError(f"foreign workload present during {phase}: {matches!r}")
    return {"phase": phase, "observations": 1, "matches": []}


def monitor_child_census(child: Any, phase: str) -> dict[str, Any]:
    observations = 0
    while True:
        matches = foreign_processes({os.getpid(), child.pid})
        observations += 1
        if matches:
            raise ValueError(f"foreign workload present during {phase}: {matches!r}")
        if child.poll() is not None:
            return {"phase": phase, "observations": observations, "matches": []}
        time.sleep(CENSUS_POLL_SECONDS)


def process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for_process_group_exit(
    child: subprocess.Popen[str], process_group_id: int, timeout: float
) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        child.poll()
        if not process_group_exists(process_group_id):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(PROCESS_GROUP_POLL_SECONDS, remaining))


class MonitoredChild:
    """Own one start-new-session child and finalize its complete process group."""

    def __init__(self, child: subprocess.Popen[str]) -> None:
        self.child = child
        # start_new_session makes the just-spawned child the leader of its new group.
        self.process_group_id = child.pid
        self.cleanup: dict[str, Any] | None = None

    @classmethod
    def spawn(
        cls, command: list[str], *, cwd: Path, env: dict[str, str] | None, stdout: Any, stderr: Any
    ) -> "MonitoredChild":
        return cls(
            subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                text=True,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        )

    def __enter__(self) -> "MonitoredChild":
        return self

    def __exit__(self, exception_type: Any, exception: BaseException | None, traceback: Any) -> bool:
        try:
            self.cleanup = self.finalize()
        except BaseException as cleanup_error:
            if exception is not None:
                raise BaseExceptionGroup(
                    "monitored command invalidation and process-group cleanup failed",
                    [exception, cleanup_error],
                ) from cleanup_error
            raise
        return False

    def reap_direct_child(self) -> None:
        if self.child.poll() is not None:
            return
        try:
            self.child.wait(timeout=PROCESS_GROUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.kill(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.child.wait()

    def finalize(self) -> dict[str, Any]:
        self.child.poll()
        terminated = False
        escalated = False
        if process_group_exists(self.process_group_id):
            terminated = True
            try:
                os.killpg(self.process_group_id, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError as error:
                raise RuntimeError(f"cannot terminate process group {self.process_group_id}") from error
            else:
                if not wait_for_process_group_exit(
                    self.child, self.process_group_id, PROCESS_GROUP_GRACE_SECONDS
                ):
                    escalated = True
                    try:
                        os.killpg(self.process_group_id, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError as error:
                        raise RuntimeError(f"cannot kill process group {self.process_group_id}") from error
                    if not wait_for_process_group_exit(
                        self.child, self.process_group_id, PROCESS_GROUP_GRACE_SECONDS
                    ):
                        raise RuntimeError(f"process group {self.process_group_id} survived SIGKILL")
        self.reap_direct_child()
        if process_group_exists(self.process_group_id):
            raise RuntimeError(f"process group {self.process_group_id} survived finalization")
        return {
            "process_group_id": self.process_group_id,
            "terminated": terminated,
            "escalated": escalated,
        }


def monitored_command(
    command: list[str], *, cwd: Path, env: dict[str, str] | None, phase: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    with (
        tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stdout_file,
        tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr_file,
    ):
        with MonitoredChild.spawn(
            command, cwd=cwd, env=env, stdout=stdout_file, stderr=stderr_file
        ) as monitored:
            census = monitor_child_census(monitored.child, phase)
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read()
            stderr = stderr_file.read()
            completed = subprocess.CompletedProcess(command, monitored.child.returncode, stdout, stderr)
            if completed.returncode != 0:
                raise ValueError(
                    f"command failed ({completed.returncode}): {' '.join(command)}\n"
                    f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
                )
        if monitored.cleanup is None:
            raise RuntimeError("monitored child did not produce cleanup evidence")
        census["cleanup"] = monitored.cleanup
    return completed, census


def parse_power_state(battery: str, thermal: str, custom: str) -> dict[str, str]:
    source = re.search(r"^Now drawing from '([^']+)'", battery, re.MULTILINE)
    if source is None:
        raise ValueError("pmset battery output did not identify the active power source")
    power_source = source.group(1)
    source_block = custom.split(f"{power_source}:\n", 1)
    if len(source_block) != 2:
        raise ValueError("pmset custom output omitted the active power-source settings")
    low_power_mode = re.search(r"^\s*lowpowermode\s+(\S+)", source_block[1], re.MULTILINE)
    if low_power_mode is None:
        raise ValueError("pmset custom output omitted lowpowermode")
    notes: dict[str, str] = {}
    for key, description in (
        ("thermal_warning", "thermal warning level"),
        ("performance_warning", "performance warning level"),
        ("cpu_power_status", "CPU power status"),
    ):
        note = re.search(rf"^Note: (.+{re.escape(description)}.+)$", thermal, re.MULTILINE)
        if note is None:
            raise ValueError(f"pmset thermal output omitted {description}")
        notes[key] = note.group(1)
    return {
        "power_source": power_source,
        "low_power_mode": low_power_mode.group(1),
        **notes,
    }


def power_state(repo: Path) -> dict[str, str]:
    return parse_power_state(
        require_command(["pmset", "-g", "batt"], cwd=repo).stdout,
        require_command(["pmset", "-g", "therm"], cwd=repo).stdout,
        require_command(["pmset", "-g", "custom"], cwd=repo).stdout,
    )


def validate_stable_power_state(
    label: str, before: dict[str, str], after: dict[str, str]
) -> None:
    if before != after:
        raise ValueError(
            f"power state changed during {label}: before={before!r} after={after!r}"
        )


def cpu_model(repo: Path) -> str:
    model = require_command(["sysctl", "-n", "machdep.cpu.brand_string"], cwd=repo).stdout.strip()
    if not model:
        raise ValueError("sysctl did not report a CPU model")
    return model


def host_identity(repo: Path) -> dict[str, str]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "node": platform.node(),
        "python": sys.version,
        "rustc": require_command(["rustc", "--version"], cwd=repo).stdout.strip(),
        "cpu_model": cpu_model(repo),
    }


@contextmanager
def temporary_worktree(repo: Path, commit: str):
    with tempfile.TemporaryDirectory(prefix="carrick-atomic-handoff-") as temporary:
        worktree = Path(temporary) / "source"
        require_command(["git", "worktree", "add", "--detach", str(worktree), commit], cwd=repo)
        try:
            yield worktree
        finally:
            require_command(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo)


def build_and_run_arm(
    *,
    repo: Path,
    commit: str,
    worktree: Path,
    label: str,
    iterations: int,
    warmups: int,
    samples: int,
    identities: dict[str, dict[str, str]],
) -> dict[str, Any]:
    census = [clean_census("before_build", {os.getpid()})]
    arm_power_before = power_state(repo)
    build_command = [
        "cargo", "test", "--release", "-p", "carrick-runtime", "--lib", "--no-run", "--message-format=json",
    ]
    build, build_census = monitored_command(
        build_command, cwd=worktree, env=None, phase="build"
    )
    census.append(build_census)
    executable = parse_test_executable(build.stdout)
    identity = executable_identity(executable)
    record_executable_identity(identities, commit, identity)
    test_name = discover_reducer_test_name(executable)
    environment = {
        **os.environ,
        "CARRICK_HANDOFF_PERF_ITERATIONS": str(iterations),
        "CARRICK_HANDOFF_PERF_WARMUPS": str(warmups),
        "CARRICK_HANDOFF_PERF_SAMPLES": str(samples),
        "RUST_TEST_THREADS": "1",
    }
    test_command = reducer_command(executable, test_name)
    census.append(clean_census("before_reducer", {os.getpid()}))
    test, reducer_census = monitored_command(
        test_command, cwd=worktree, env=environment, phase="reducer"
    )
    census.append(reducer_census)
    rows = parse_samples(test.stdout)
    validate_samples(rows, iterations=iterations, samples=samples)
    census.append(clean_census("post_arm", {os.getpid()}))
    arm_power_after = power_state(repo)
    validate_stable_power_state(label, arm_power_before, arm_power_after)
    return {
        "label": label,
        "source_commit": commit,
        "worktree": str(worktree),
        "build_command": build_command,
        "test_command": test_command,
        "executable": identity,
        "power_state_before": arm_power_before,
        "power_state_after": arm_power_after,
        "census": census,
        "rows": rows,
        "aggregate": aggregate(rows),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--single")
    mode.add_argument("--baseline")
    parser.add_argument("--candidate")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=100_000)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args(argv)
    if args.baseline and not args.candidate:
        parser.error("--candidate is required with --baseline")
    if args.single and args.candidate:
        parser.error("--candidate is only valid with --baseline")
    if args.iterations < 100_000 or args.warmups < 5 or args.samples < 30:
        parser.error("iterations, warmups, and samples must meet the approved minimums")
    return args


def publish_receipt(output: Path, receipt: dict[str, Any]) -> None:
    """Publish a completed receipt without exposing a partially-written file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as destination:
            temporary = Path(destination.name)
            json.dump(receipt, destination, indent=2, sort_keys=True)
            destination.write("\n")
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        # A receipt belongs to this invocation only.  Remove any prior one before
        # measuring so an invalid run cannot leave stale evidence at this path.
        args.output.unlink(missing_ok=True)
        repo = args.repo.resolve()
        identities: dict[str, dict[str, str]] = {}
        if args.single:
            commit = resolve_ref(repo, args.single)
            with temporary_worktree(repo, commit) as worktree:
                arms = [
                    build_and_run_arm(
                        repo=repo, commit=commit, worktree=worktree, label="S1",
                        iterations=args.iterations, warmups=args.warmups, samples=args.samples,
                        identities=identities,
                    )
                ]
            receipt: dict[str, Any] = {
                "schema": SCHEMA,
                "mode": "single",
                "host": host_identity(repo),
                "parameters": {"iterations": args.iterations, "warmups": args.warmups, "samples": args.samples},
                "arm_order": [{"label": "S1", "ref": commit}],
                "executable_identities": identities,
                "arms": arms,
                "accepted": None,
            }
        else:
            baseline = resolve_ref(repo, args.baseline)
            candidate = resolve_ref(repo, args.candidate)
            if baseline == candidate:
                raise ValueError("baseline and candidate resolve to the same commit")
            order = abba_refs(baseline, candidate)
            with (
                temporary_worktree(repo, baseline) as baseline_worktree,
                temporary_worktree(repo, candidate) as candidate_worktree,
            ):
                worktrees = {baseline: baseline_worktree, candidate: candidate_worktree}
                arms = [
                    build_and_run_arm(
                        repo=repo, commit=commit, worktree=worktrees[commit], label=label,
                        iterations=args.iterations, warmups=args.warmups, samples=args.samples,
                        identities=identities,
                    )
                    for label, commit in order
                ]
            by_commit: dict[str, list[dict[str, Any]]] = {baseline: [], candidate: []}
            for arm in arms:
                by_commit[arm["source_commit"]].extend(arm["rows"])
            baseline_aggregate = aggregate(by_commit[baseline])
            candidate_aggregate = aggregate(by_commit[candidate])
            contenders = sum(int(row["contender_admissions"]) for arm in arms for row in arm["rows"])
            verdict = performance_verdict(
                baseline_median=baseline_aggregate["generic_exit_claim"]["median_ns_per_transition"],
                baseline_p95=baseline_aggregate["generic_exit_claim"]["p95_ns_per_transition"],
                candidate_median=candidate_aggregate["generic_exit_claim"]["median_ns_per_transition"],
                candidate_p95=candidate_aggregate["generic_exit_claim"]["p95_ns_per_transition"],
                contender_admissions=contenders,
            )
            receipt = {
                "schema": SCHEMA,
                "mode": "paired",
                "host": host_identity(repo),
                "parameters": {"iterations": args.iterations, "warmups": args.warmups, "samples": args.samples},
                "arm_order": [{"label": label, "ref": commit} for label, commit in order],
                "executable_identities": identities,
                "arms": arms,
                "aggregate": {"baseline": baseline_aggregate, "candidate": candidate_aggregate},
                "ratios": verdict,
                "accepted": verdict["accepted"],
            }
        publish_receipt(args.output, receipt)
        return 0 if receipt["accepted"] is not False else 1
    except Exception as error:
        print(f"invalid receipt: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
