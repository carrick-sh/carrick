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
import tempfile
import time
from collections.abc import Sequence


SCHEMA = "carrick.native-go-build.v3"
DEFAULT_IMAGE = "localhost:5005/carrick-go-conformance:1.24"
DEFAULT_TIMEOUT_SECONDS = 180
ENGINE_CARRICK = "carrick"
ENGINE_DOCKER = "docker"
ENGINE_BOTH = "both"
VARIANT_DEFAULT = "default"
VARIANT_PRECURSOR = "precursor"
VARIANT_CANDIDATE = "candidate"
PERFORMANCE_CONTROL_KEYS = (
    "CARRICK_DSR_ARTIFACT_SPIKE",
    "CARRICK_DSR_SHARED_TRANSLATION",
    "CARRICK_DSR_DIRECT_BINDINGS",
    "CARRICK_DSR_PROFILE",
    "CARRICK_DSR_ARTIFACT_REPORT",
    "CARRICK_DSR_ARTIFACT_VALIDATE_FRESH",
    "CARRICK_DSR_ARTIFACT_MIN_SOURCE_WORDS",
    "CARRICK_DSR_KEEP_CONTAINER_CACHE",
    "CARRICK_ARTIFACT",
    "CARRICK_DISABLE_VDSO",
    "CARRICK_VDSO_MODE",
    "CARRICK_NATIVE_TRACE_SYSCALLS",
    "CARRICK_NATIVE_REFUSE_POSTFORK_THREADS",
    "CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS",
    "CARRICK_DSR_SUPERBLOCK",
)
HARNESS_CARRICK_ALLOWLIST = frozenset()
VARIANT_OVERLAYS: dict[str, dict[str, str | None]] = {
    VARIANT_DEFAULT: {
        "CARRICK_DSR_ARTIFACT_SPIKE": None,
        "CARRICK_DSR_SHARED_TRANSLATION": None,
        "CARRICK_DSR_DIRECT_BINDINGS": None,
    },
    VARIANT_PRECURSOR: {
        "CARRICK_DSR_ARTIFACT_SPIKE": "1",
        "CARRICK_DSR_SHARED_TRANSLATION": "1",
        "CARRICK_DSR_DIRECT_BINDINGS": None,
    },
    VARIANT_CANDIDATE: {
        "CARRICK_DSR_ARTIFACT_SPIKE": "1",
        "CARRICK_DSR_SHARED_TRANSLATION": "1",
        "CARRICK_DSR_DIRECT_BINDINGS": "1",
    },
}


class SampleEvidenceError(RuntimeError):
    """One failed sample together with all evidence collected for it."""

    def __init__(self, message: str, sample: dict[str, object]):
        super().__init__(message)
        self.sample = sample


def guest_script() -> str:
    # The workload window brackets only the guest work (compile plus execute)
    # with in-guest clock reads, so engine-side container setup and teardown
    # stay outside it on both engines. The 2026-07-28 direction makes this
    # window the primary overhead metric; full process wall time remains a
    # secondary diagnostic.
    return (
        'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; '
        'printf "package main\\nfunc main(){println(\\"ok\\")}\\n" > h.go; '
        "w0=$(date +%s%N); "
        'GOCACHE="/tmp/gc-$CARRICK_RUN_ID" '
        "/usr/local/go/bin/go build -o h ./h.go; "
        "./h; "
        "w1=$(date +%s%N); "
        'echo "WORKLOAD_NS=$((w1-w0))"; '
        "echo BUILD_OK"
    )


def workload_ns_from_stdout(stdout: str) -> int:
    markers = [
        line.strip()
        for line in stdout.splitlines()
        if line.strip().startswith("WORKLOAD_NS=")
    ]
    if len(markers) != 1:
        raise ValueError(
            f"expected exactly one WORKLOAD_NS marker, found {len(markers)}"
        )
    value = markers[0].removeprefix("WORKLOAD_NS=")
    if not value.isdigit():
        raise ValueError(f"WORKLOAD_NS is not a nonnegative integer: {value!r}")
    workload_ns = int(value)
    if workload_ns <= 0:
        raise ValueError(f"WORKLOAD_NS must be positive: {workload_ns}")
    return workload_ns


def requested_engines(value: str) -> tuple[str, ...]:
    if value == ENGINE_BOTH:
        return (ENGINE_CARRICK, ENGINE_DOCKER)
    if value in {ENGINE_CARRICK, ENGINE_DOCKER}:
        return (value,)
    raise ValueError(f"unknown engine: {value}")


def build_command(
    repo: pathlib.Path,
    engine: str,
    run_id: str,
    *,
    binary: pathlib.Path | None = None,
    image: str = DEFAULT_IMAGE,
) -> list[str]:
    if engine == ENGINE_CARRICK:
        carrick = repo / "target/release/carrick" if binary is None else binary
        return [
            str(carrick),
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
            guest_script(),
        ]
    if engine == ENGINE_DOCKER:
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
            guest_script(),
        ]
    raise ValueError(f"unknown engine: {engine}")


def build_carrick_command(
    repo: pathlib.Path,
    run_id: str,
    *,
    binary: pathlib.Path | None = None,
    image: str = DEFAULT_IMAGE,
) -> list[str]:
    return build_command(
        repo,
        ENGINE_CARRICK,
        run_id,
        binary=binary,
        image=image,
    )


def median_ms(samples: Sequence[int]) -> int:
    if not samples:
        raise ValueError("at least one sample is required")
    return int(statistics.median(samples))


def carrick_over_docker_ratio(
    carrick_samples: Sequence[int],
    docker_samples: Sequence[int],
) -> float:
    docker_median = median_ms(docker_samples)
    if docker_median == 0:
        raise ValueError("Docker median must be nonzero")
    return median_ms(carrick_samples) / docker_median


def summarize_phases(
    samples_by_engine: dict[str, list[dict[str, object]]],
) -> dict[str, dict[str, object]]:
    phases: dict[str, dict[str, object]] = {}
    for engine, rows in samples_by_engine.items():
        durations = [int(row["elapsed_ms"]) for row in rows]
        workloads = [int(row["workload_ms"]) for row in rows]
        phases[engine] = {
            "sample_count": len(rows),
            "samples": rows,
            "median_ms": median_ms(durations),
            "workload_median_ms": median_ms(workloads),
        }
    return phases


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


def normalized_overlay(
    overlay: dict[str, str | None] | None,
) -> dict[str, str | None]:
    supplied = {} if overlay is None else dict(overlay)
    unknown = set(supplied) - set(PERFORMANCE_CONTROL_KEYS)
    if unknown:
        raise ValueError(
            "unknown performance-control key(s): " + ", ".join(sorted(unknown))
        )
    return {
        key: supplied.get(key)
        for key in PERFORMANCE_CONTROL_KEYS
    }


def fixed_variant_overlay(variant: str) -> dict[str, str | None]:
    try:
        selected = VARIANT_OVERLAYS[variant]
    except KeyError as error:
        raise ValueError(f"unknown variant: {variant}") from error
    return normalized_overlay(selected)


def variant_environment(
    ambient: os._Environ[str] | dict[str, str],
    variant: str,
    engine: str,
    extra_overlay: dict[str, str | None] | None = None,
) -> tuple[dict[str, str], dict[str, str | None]]:
    selected = fixed_variant_overlay(variant)
    if extra_overlay is not None:
        for key, value in normalized_overlay(extra_overlay).items():
            if value is not None:
                selected[key] = value
    if engine == ENGINE_DOCKER and any(
        value is not None for value in selected.values()
    ):
        raise ValueError("Docker accepts only the default variant without Carrick overlays")
    environment = dict(ambient)
    for key in PERFORMANCE_CONTROL_KEYS:
        environment.pop(key, None)
    for key, value in selected.items():
        if value is not None:
            environment[key] = value
    return environment, selected


def reject_ambient_carrick(
    ambient: os._Environ[str] | dict[str, str],
    selected_overlay: dict[str, str | None],
) -> None:
    # The harness applies selected_overlay only after this check. Even known
    # controls are contamination when inherited from the caller.
    allowed = set(HARNESS_CARRICK_ALLOWLIST)
    rejected = sorted(
        key
        for key in ambient
        if key.startswith("CARRICK_") and key not in allowed
    )
    if rejected:
        raise RuntimeError(
            "ambient Carrick controls are not accepted: " + ", ".join(rejected)
        )


def write_json_atomic(path: pathlib.Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as temporary:
        temporary_path = pathlib.Path(temporary.name)
        json.dump(payload, temporary, indent=2, sort_keys=True)
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(temporary_path, path)


def repository_is_git(repo: pathlib.Path) -> bool:
    if not (repo / ".git").exists():
        return False
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def own_ancestor_pids() -> set[int]:
    """PIDs on this process's ancestry chain (shells, terminals, agents).

    A launching shell's argv quotes this script's own path, which the
    workload census would otherwise misread as a concurrent harness. The
    ancestry chain is the launcher, never a foreign workload.
    """
    result = subprocess.run(
        ["ps", "-eo", "pid=,ppid="],
        check=True,
        capture_output=True,
        text=True,
    )
    parent_of: dict[int, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            parent_of[int(fields[0])] = int(fields[1])
        except ValueError:
            continue
    ancestors: set[int] = set()
    cursor = os.getpid()
    while cursor in parent_of and cursor not in ancestors and cursor > 1:
        cursor = parent_of[cursor]
        ancestors.add(cursor)
    return ancestors


def foreign_rows(
    rows: Sequence[tuple[int, str]],
    *,
    own_pid: int,
    ancestor_pids: set[int],
) -> list[str]:
    foreign = []
    for pid, command in rows:
        if pid == own_pid or pid in ancestor_pids:
            continue
        if (
            "target/release/carrick run" in command
            or "scripts/perf/native_go_build.py" in command
            or "scripts/perf/native_go_build_screen.py" in command
            or "scripts/perf/direct_binding_mechanism.py" in command
        ):
            foreign.append(f"pid={pid} command={command}")
    return foreign


def foreign_workload_census() -> list[str]:
    result = subprocess.run(
        ["ps", "-eo", "pid=,args="],
        check=True,
        capture_output=True,
        text=True,
    )
    rows: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            rows.append((int(fields[0]), fields[1]))
        except ValueError:
            continue
    return foreign_rows(
        rows,
        own_pid=os.getpid(),
        ancestor_pids=own_ancestor_pids(),
    )


def running_docker_oracles() -> list[str]:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "failed to census running Docker containers: "
            + (result.stderr.strip() or result.stdout.strip())
        )
    oracles = []
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) != 3:
            continue
        _container_id, name, image = fields
        if image == "registry" or image.startswith("registry:"):
            continue
        identifying_text = f"{name} {image}".lower()
        if (
            "native-go-build" in identifying_text
            or "carrick" in identifying_text
            or "conformance" in identifying_text
            or "carrick run" in identifying_text
        ):
            oracles.append(line)
    return oracles


def sample_provenance(
    repo: pathlib.Path,
    engine: str,
    controlled_environment: dict[str, str | None],
    *,
    reject_contamination: bool = True,
    binary_path: pathlib.Path | None = None,
    image_ref: str = DEFAULT_IMAGE,
) -> dict[str, object]:
    binary = repo / "target/release/carrick" if binary_path is None else binary_path
    status = git_output(repo, "status", "--porcelain").splitlines()
    if status and reject_contamination:
        raise RuntimeError("performance sample requires a clean git worktree")
    foreign = foreign_workload_census()
    docker_oracles = running_docker_oracles()
    if (foreign or docker_oracles) and reject_contamination:
        raise RuntimeError(
            "foreign workload census is not empty: "
            + json.dumps({"processes": foreign, "docker": docker_oracles})
        )
    return {
        "git_commit": git_output(repo, "rev-parse", "HEAD"),
        "git_status": status,
        "binary_path": str(binary),
        "binary_sha256": sha256_file(binary) if binary.is_file() else None,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "node": platform.node(),
        },
        "image_ref": image_ref,
        "image": docker_image_provenance(image_ref),
        "controlled_environment": controlled_environment,
        "foreign_processes": foreign,
        "docker_oracles": docker_oracles,
        "engine": engine,
    }


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


def carrick_cleanup(repo: pathlib.Path, run_id: str) -> dict[str, object]:
    result = subprocess.run(
        [str(repo / "scripts/sudo/kill.sh"), run_id],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return {
        "status": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def docker_cleanup(run_id: str) -> dict[str, object]:
    result = subprocess.run(
        ["docker", "rm", "-f", run_id],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    # Docker returns nonzero when a naturally exited `--rm`-style container
    # is already absent; this harness does not use `--rm`, so retain it as a
    # fatal cleanup result.
    return {
        "status": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def docker_image_provenance(image: str = DEFAULT_IMAGE) -> dict[str, object]:
    result = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{json .Architecture}}\n{{json .Id}}\n{{json .RepoDigests}}",
            image,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"failed to inspect Docker image {image}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    lines = result.stdout.splitlines()
    if len(lines) != 3:
        raise RuntimeError(
            "Docker image provenance must contain architecture, ID, and digests"
        )
    try:
        architecture = json.loads(lines[0])
        image_id = json.loads(lines[1])
        repo_digests = json.loads(lines[2])
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Docker image provenance is not valid JSON: {result.stdout!r}"
        ) from error
    if architecture != "arm64":
        raise RuntimeError(
            f"Docker oracle image must be native arm64, got {architecture!r}"
        )
    if not isinstance(image_id, str) or not image_id:
        raise RuntimeError("Docker image ID is missing")
    if not isinstance(repo_digests, list) or not all(
        isinstance(digest, str) for digest in repo_digests
    ):
        raise RuntimeError("Docker image RepoDigests are malformed")
    return {
        "architecture": architecture,
        "id": image_id,
        "repo_digests": repo_digests,
    }


def validate_docker_image() -> str:
    return str(docker_image_provenance()["architecture"])


def combined_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    def text(output: str | bytes | None) -> str:
        if output is None:
            return ""
        if isinstance(output, bytes):
            return output.decode(errors="replace")
        return output

    return text(stdout) + text(stderr)


def run_sample(
    repo: pathlib.Path,
    engine: str,
    index: int,
    timeout_seconds: int,
    captured_output: pathlib.Path | None = None,
    environment_overlay: dict[str, str | None] | None = None,
) -> dict[str, object]:
    run_id = f"native-go-build-{engine}-{os.getpid()}-{time.time_ns()}-{index}"
    command = build_command(repo, engine, run_id)
    normalized = normalized_overlay(environment_overlay)
    if engine == ENGINE_DOCKER and any(value is not None for value in normalized.values()):
        raise ValueError("Docker samples reject Carrick-only environment overlays")
    reject_ambient_carrick(os.environ, normalized)
    environment = dict(os.environ)
    for key in PERFORMANCE_CONTROL_KEYS:
        environment.pop(key, None)
    for key, value in normalized.items():
        if value is not None:
            environment[key] = value
    environment["CARRICK_RUN_ID"] = run_id
    # Task 14's exact screen is a Carrick-only gate. The legacy Docker phase
    # retains its image provenance at campaign scope and accepts no overlay.
    strict_evidence = engine == ENGINE_CARRICK and repository_is_git(repo)
    pre_provenance = (
        sample_provenance(repo, engine, normalized) if strict_evidence else None
    )
    started = time.monotonic_ns()
    result: subprocess.CompletedProcess[str] | None = None
    timeout: subprocess.TimeoutExpired | None = None
    cleanup_error: Exception | None = None
    cleanup_evidence: dict[str, object] | None = None
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
    except subprocess.TimeoutExpired as error:
        timeout = error
    finally:
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        try:
            if engine == ENGINE_CARRICK:
                cleanup_evidence = carrick_cleanup(repo, run_id)
            else:
                cleanup_evidence = docker_cleanup(run_id)
        except Exception as error:
            cleanup_error = error
    post_provenance = None
    provenance_error: Exception | None = None
    if strict_evidence:
        try:
            post_provenance = sample_provenance(repo, engine, normalized)
        except Exception as error:
            provenance_error = error
    if timeout is not None:
        combined = combined_output(timeout.stdout, timeout.stderr)
        stdout = combined_output(timeout.stdout, None)
        stderr = combined_output(None, timeout.stderr)
    else:
        assert result is not None
        combined = combined_output(result.stdout, result.stderr)
        stdout = combined_output(result.stdout, None)
        stderr = combined_output(None, result.stderr)
    if captured_output is not None:
        captured_output.parent.mkdir(parents=True, exist_ok=True)
        captured_output.write_text(combined)
    if timeout is not None:
        if cleanup_error is not None:
            raise timeout from cleanup_error
        raise timeout
    assert result is not None
    build_ok = stdout.splitlines().count("BUILD_OK") == 1
    workload_ns: int | None = None
    workload_error: str | None = None
    try:
        workload_ns = workload_ns_from_stdout(stdout)
    except ValueError as error:
        workload_error = str(error)
    if cleanup_error is not None:
        cleanup_evidence = {
            "status": 125,
            "stdout": "",
            "stderr": f"cleanup launch failed: {cleanup_error}",
        }
    sample = {
        "engine": engine,
        "index": index,
        "run_id": run_id,
        "elapsed_ms": elapsed_ms,
        "workload_ns": workload_ns,
        "workload_ms": (
            workload_ns // 1_000_000 if workload_ns is not None else None
        ),
        "return_code": result.returncode,
        "build_ok": build_ok,
        "command": {
            "argv": command,
            "status": result.returncode,
            "build_ok": build_ok,
        },
        "environment_overlay": normalized,
        "controlled_environment": {
            key: environment.get(key) for key in PERFORMANCE_CONTROL_KEYS
        },
        "provenance": {
            "pre": pre_provenance,
            "post": post_provenance,
        },
        "cleanup": cleanup_evidence,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }
    if result.returncode != 0 or not build_ok:
        sample_error = SampleEvidenceError(
            f"go-build sample {index} failed: run_id={run_id} "
            f"rc={result.returncode}\n{combined[-8000:]}",
            sample,
        )
        if cleanup_error is not None:
            raise sample_error from cleanup_error
        raise sample_error
    if workload_error is not None:
        raise SampleEvidenceError(
            f"go-build sample {index} workload window is invalid: "
            f"run_id={run_id} {workload_error}",
            sample,
        )
    if cleanup_error is not None:
        raise SampleEvidenceError(
            f"go-build sample {index} cleanup failed: run_id={run_id}",
            sample,
        ) from cleanup_error
    if cleanup_evidence is not None and int(cleanup_evidence.get("status", 1)) != 0:
        raise SampleEvidenceError(
            (
                f"go-build sample {index} cleanup failed: run_id={run_id} "
                f"status={cleanup_evidence.get('status')} "
                f"stdout={cleanup_evidence.get('stdout', '')!r} "
                f"stderr={cleanup_evidence.get('stderr', '')!r}"
            ),
            sample,
        )
    if provenance_error is not None:
        raise SampleEvidenceError(
            f"go-build sample {index} post-provenance failed: {provenance_error}",
            sample,
        ) from provenance_error
    if strict_evidence and pre_provenance != post_provenance:
        raise SampleEvidenceError(
            "sample provenance drifted: "
            + json.dumps(
                {"pre": pre_provenance, "post": post_provenance},
                sort_keys=True,
            ),
            sample,
        )
    return sample


def run_phase(
    repo: pathlib.Path,
    engine: str,
    samples: int,
    timeout_seconds: int,
    captured_output_dir: pathlib.Path | None = None,
    environment_overlay: dict[str, str | None] | None = None,
) -> list[dict[str, object]]:
    if engine == ENGINE_DOCKER:
        validate_docker_image()
    return [
        run_sample(
            repo,
            engine,
            index + 1,
            timeout_seconds,
            (
                captured_output_dir / f"{engine}-{index + 1}.log"
                if captured_output_dir is not None
                else None
            ),
            environment_overlay,
        )
        for index in range(samples)
    ]


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine",
        choices=(ENGINE_CARRICK, ENGINE_DOCKER, ENGINE_BOTH),
        default=ENGINE_CARRICK,
        help="measure Carrick, native-arm64 Docker, or both in separate phases",
    )
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument(
        "--variant",
        choices=(VARIANT_DEFAULT, VARIANT_PRECURSOR, VARIANT_CANDIDATE),
        default=VARIANT_DEFAULT,
        help="select one fixed, scrubbed Carrick feature overlay",
    )
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
        "--superblock",
        help=(
            "CARRICK_DSR_SUPERBLOCK overlay for the Carrick phase: "
            "'off', 'on', or a segment count. Omitted leaves the binary default, "
            "so a paired screen must set it EXPLICITLY on both arms"
        ),
    )
    parser.add_argument(
        "--allow-busy",
        action="store_true",
        help="run despite active compilers, Carrick processes, spin loops, or load",
    )
    parser.add_argument(
        "--captured-output-dir",
        type=pathlib.Path,
        help=(
            "retain each sample's complete stdout/stderr as "
            "<engine>-<sample>.log"
        ),
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
    engines = requested_engines(args.engine)
    if ENGINE_DOCKER in engines and args.variant != VARIANT_DEFAULT:
        raise SystemExit("Docker accepts only --variant default")
    selected_overlay = fixed_variant_overlay(args.variant)
    if args.superblock is not None:
        if ENGINE_DOCKER in engines:
            raise SystemExit("--superblock is a Carrick control; Docker takes no overlay")
        selected_overlay["CARRICK_DSR_SUPERBLOCK"] = args.superblock
    reject_ambient_carrick(os.environ, selected_overlay)
    if ENGINE_CARRICK in engines and not binary.is_file():
        raise SystemExit(f"missing signed release binary: {binary}; run `just build`")

    reasons = busy_host_reasons()
    if reasons and not args.allow_busy:
        rendered = "\n".join(f"- {reason}" for reason in reasons)
        raise SystemExit(f"host is not idle enough for a performance claim:\n{rendered}")

    started_at = utc_now()
    samples_by_engine = {
        engine: run_phase(
            repo,
            engine,
            args.samples,
            args.timeout_seconds,
            args.captured_output_dir,
            selected_overlay,
        )
        for engine in engines
    }
    phases = summarize_phases(samples_by_engine)
    dirty_lines = git_output(repo, "status", "--porcelain").splitlines()
    payload = {
        "schema": SCHEMA,
        "started_at": started_at,
        "finished_at": utc_now(),
        "git_commit": git_output(repo, "rev-parse", "HEAD"),
        "git_dirty": bool(dirty_lines),
        "git_status": dirty_lines,
        "image": DEFAULT_IMAGE,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "load_average": list(os.getloadavg()),
            "busy_override": bool(args.allow_busy),
            "preflight_reasons": reasons,
        },
        "phases": phases,
    }
    if ENGINE_CARRICK in engines:
        payload["binary"] = str(binary)
        payload["binary_sha256"] = sha256_file(binary)
    if ENGINE_DOCKER in engines:
        payload["docker"] = {
            **docker_image_provenance(),
            "platform": "linux/arm64",
        }
    if engines == (ENGINE_CARRICK, ENGINE_DOCKER):
        payload["ratio"] = {
            "carrick_over_docker": carrick_over_docker_ratio(
                [
                    int(row["elapsed_ms"])
                    for row in samples_by_engine[ENGINE_CARRICK]
                ],
                [
                    int(row["elapsed_ms"])
                    for row in samples_by_engine[ENGINE_DOCKER]
                ],
            ),
            # Primary overhead metric: the in-guest workload window, which
            # excludes engine container setup and teardown on both sides.
            "carrick_over_docker_workload": carrick_over_docker_ratio(
                [
                    int(row["workload_ms"])
                    for row in samples_by_engine[ENGINE_CARRICK]
                ],
                [
                    int(row["workload_ms"])
                    for row in samples_by_engine[ENGINE_DOCKER]
                ],
            ),
        }
    payload["variant"] = args.variant
    payload["environment_overlay"] = selected_overlay
    write_json_atomic(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
