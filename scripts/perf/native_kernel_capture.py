#!/usr/bin/env python3
"""Capture and validate paired Darwin/AArch64 native-kernel profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence

import native_go_build
import native_kernel_attribution


RECEIPT_SCHEMA = "carrick.native-kernel-capture.v2"
PROFILE = "native-wall"
MONITOR_INTERVAL_SECONDS = 0.01
MONITOR_INTERVAL_MILLISECONDS = 10
WATCHDOG_JOIN_SECONDS = 1
WATCHDOG_THREAD_NAME = "native-kernel-trace-deadline-watchdog"
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,39}")
ARTIFACT_NAMES = (
    "raw_trace",
    "summary_jsonl",
    "command_stdout",
    "command_stderr",
    "command_status",
    "cleanup_stdout",
    "cleanup_stderr",
)
DROP_FIELDS = (
    "principal_drops",
    "aggregation_drops",
    "dynamic_drops",
    "dynamic_rinse_drops",
    "dynamic_dirty_drops",
    "other_drops",
)


class EvidenceError(RuntimeError):
    """Raised when evidence cannot satisfy the fail-closed contract."""


def _absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


@dataclass(frozen=True)
class CaptureConfig:
    repo: pathlib.Path
    binary: pathlib.Path
    artifact_dir: pathlib.Path
    run_id: str
    image: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or self.timeout_seconds <= 0
        ):
            raise EvidenceError("timeout must be positive")
        if not RUN_ID_PATTERN.fullmatch(self.run_id):
            raise EvidenceError(
                "run ID must be 1-40 conservative alphanumeric/hyphen characters"
            )
        if not self.image:
            raise EvidenceError("image must be non-empty")
        object.__setattr__(self, "repo", _absolute(self.repo))
        object.__setattr__(self, "binary", _absolute(self.binary))
        object.__setattr__(self, "artifact_dir", _absolute(self.artifact_dir))


@dataclass(frozen=True)
class PlannedPaths:
    artifact_dir: pathlib.Path
    runs: dict[str, dict[str, pathlib.Path]]
    analysis: pathlib.Path

    def all_outputs(self) -> dict[str, pathlib.Path]:
        outputs: dict[str, pathlib.Path] = {}
        for lane in ("a", "b"):
            for name, path in self.runs[lane].items():
                outputs[f"{lane}.{name}"] = path
        outputs["analysis"] = self.analysis
        return outputs


def planned_paths(artifact_dir: pathlib.Path) -> PlannedPaths:
    root = _absolute(pathlib.Path(artifact_dir))
    suffixes = {
        "raw_trace": "raw.trace",
        "summary_jsonl": "summary.jsonl",
        "command_stdout": "command.stdout",
        "command_stderr": "command.stderr",
        "command_status": "command.status.json",
        "cleanup_stdout": "cleanup.stdout",
        "cleanup_stderr": "cleanup.stderr",
        "receipt": "receipt.json",
    }
    runs = {
        lane: {
            name: root / f"{lane}.{suffix}"
            for name, suffix in suffixes.items()
        }
        for lane in ("a", "b")
    }
    return PlannedPaths(
        artifact_dir=root,
        runs=runs,
        analysis=root / "analysis.json",
    )


def _lexists(path: pathlib.Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _preflight(layout: PlannedPaths) -> None:
    root = layout.artifact_dir
    if _lexists(root):
        mode = os.lstat(root).st_mode
        if not stat.S_ISDIR(mode):
            raise EvidenceError("artifact directory is not a real directory")
    for label, path in layout.all_outputs().items():
        if _lexists(path):
            raise EvidenceError(f"planned output already exists: {label}={path}")


def _write_bytes_exclusive(path: pathlib.Path, raw: bytes) -> None:
    try:
        with path.open("xb") as destination:
            destination.write(raw)
            destination.flush()
            os.fsync(destination.fileno())
    except FileExistsError as error:
        raise EvidenceError(f"output appeared during capture: {path}") from error


def _write_json_exclusive(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise EvidenceError(f"output already exists: {path}") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _process_rows(listing: str) -> dict[int, dict[str, object]]:
    rows: dict[int, dict[str, object]] = {}
    for line in listing.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) != 3:
            continue
        try:
            pid = int(fields[0])
            ppid = int(fields[1])
        except ValueError:
            continue
        if pid <= 0 or ppid < 0 or pid in rows:
            raise EvidenceError("malformed process snapshot")
        rows[pid] = {
            "pid": pid,
            "ppid": ppid,
            "command": fields[2],
        }
    return rows


def _safe_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return []


def _basename(token: str) -> str:
    return pathlib.PurePath(token).name.lower()


def _is_python(executable: str) -> bool:
    return re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable) is not None


def _python_target(arguments: list[str]) -> tuple[str, str] | None:
    options_with_values = {"-W", "-X"}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-m":
            if index + 1 < len(arguments):
                return ("module", arguments[index + 1])
            return None
        if argument == "-c":
            return None
        if argument in options_with_values:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        return ("script", argument)
    return None


def _foreign_workload_category(command: str) -> str | None:
    tokens = _safe_tokens(command)
    if not tokens:
        return None
    executable = _basename(tokens[0])
    arguments = tokens[1:]
    native_go_scripts = {
        "native_go_build.py",
        "native_go_build_screen.py",
    }
    if executable in native_go_scripts:
        return "native-go-build"
    if _is_python(executable):
        target = _python_target(arguments)
        if target is not None:
            target_kind, target_value = target
            if (
                target_kind == "module"
                and target_value
                in {
                    "native_go_build",
                    "scripts.perf.native_go_build",
                    "scripts.perf.native_go_build_screen",
                }
            ) or (
                target_kind == "script"
                and _basename(target_value) in native_go_scripts
            ):
                return "native-go-build"
    if executable == "go" and arguments[:1] == ["build"]:
        return "go-build"
    if executable == "carrick" and arguments[:1] in (["run"], ["trace"]):
        return "carrick"
    if executable == "dtrace":
        for index, argument in enumerate(arguments):
            if (
                argument == "-s"
                and index + 1 < len(arguments)
                and _basename(arguments[index + 1]) == "native-wall.d"
            ):
                return "native-wall"
    for index, argument in enumerate(arguments):
        if argument in {"--profile=native-wall", "profile=native-wall"}:
            return "native-wall"
        if (
            argument == "--profile"
            and index + 1 < len(arguments)
            and arguments[index + 1] == "native-wall"
        ):
            return "native-wall"
    return None


def _looks_like_foreign_workload(command: str) -> bool:
    return _foreign_workload_category(command) is not None


def _normalized_command_shape(
    command: str,
    *,
    depth: int,
) -> dict[str, object]:
    tokens = _safe_tokens(command)
    if not tokens:
        return {
            "depth": depth,
            "executable": "<unparseable>",
            "script": None,
        }
    executable = _basename(tokens[0])
    script: str | None = None
    if _is_python(executable):
        target = _python_target(tokens[1:])
        if target is not None:
            target_kind, target_value = target
            if target_kind == "module":
                script = target_value.rsplit(".", 1)[-1]
            elif target_value.lower().endswith(".py"):
                script = pathlib.PurePath(target_value).name
    return {
        "depth": depth,
        "executable": executable,
        "script": script,
    }


def classify_process_snapshot(
    listing: str,
    *,
    self_pid: int | None = None,
    owned_lineage: set[int] | None = None,
) -> dict[str, object]:
    """Resolve launcher ancestry once, then classify only independent peers."""
    rows = _process_rows(listing)
    runner_pid = os.getpid() if self_pid is None else self_pid
    current = runner_pid
    raw_ancestry: list[dict[str, object]] = []
    seen: set[int] = set()
    while current:
        if current in seen:
            raise EvidenceError("cyclic launcher ancestry in process snapshot")
        seen.add(current)
        row = rows.get(current)
        if row is None:
            raise EvidenceError(
                f"broken launcher ancestry in process snapshot at pid {current}"
            )
        raw_ancestry.append(row)
        current = int(row["ppid"])
    owned_tree = set() if owned_lineage is None else set(owned_lineage)
    changed = True
    while changed:
        changed = False
        for pid, row in rows.items():
            if pid not in owned_tree and int(row["ppid"]) in owned_tree:
                owned_tree.add(pid)
                changed = True
    if owned_lineage is not None:
        owned_lineage.update(owned_tree)
    trusted = seen | owned_tree
    foreign = [
        row
        for pid, row in sorted(rows.items())
        if pid not in trusted
        and _looks_like_foreign_workload(str(row["command"]))
    ]
    return {
        "launcher_ancestry": [
            _normalized_command_shape(
                str(row["command"]),
                depth=depth,
            )
            for depth, row in enumerate(raw_ancestry)
        ],
        "foreign_workloads": foreign,
    }


def _run(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError(
            f"external command failed: {command[0]}: {error}"
        ) from error


def _clean_head(repo: pathlib.Path) -> str:
    status = _run(["git", "status", "--porcelain"], cwd=repo)
    if status.returncode != 0:
        raise EvidenceError("cannot inspect repository status")
    if status.stdout:
        raise EvidenceError("capture requires a clean git HEAD")
    head = _run(["git", "rev-parse", "HEAD"], cwd=repo)
    value = head.stdout.strip()
    if head.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise EvidenceError("cannot resolve repository HEAD")
    return value


def _binary_provenance(binary: pathlib.Path) -> dict[str, object]:
    if not _lexists(binary):
        raise EvidenceError(f"signed binary is absent: {binary}")
    mode = os.lstat(binary).st_mode
    if not stat.S_ISREG(mode):
        raise EvidenceError(f"signed binary is not a regular file: {binary}")
    signature = _run(["codesign", "--verify", "--strict", str(binary)])
    if signature.returncode != 0:
        raise EvidenceError("binary does not pass codesign verification")
    dof = _run(["otool", "-l", str(binary)])
    if dof.returncode != 0 or "__dof_carrick" not in dof.stdout:
        raise EvidenceError("binary is missing __DATA,__dof_carrick")
    return {
        "path": str(binary),
        "size": os.lstat(binary).st_size,
        "sha256": sha256_file(binary),
        "codesign_verified": True,
        "dof_present": True,
        "dof_listing_sha256": _sha256_bytes(dof.stdout.encode()),
    }


def _docker_oracles() -> list[str]:
    try:
        return native_go_build.running_docker_oracles()
    except RuntimeError as error:
        raise EvidenceError(str(error)) from error


def _image_provenance(image: str) -> dict[str, object]:
    try:
        return native_go_build.docker_image_provenance(image)
    except RuntimeError as error:
        raise EvidenceError(str(error)) from error


def _capture_snapshot(config: CaptureConfig) -> dict[str, object]:
    head = _clean_head(config.repo)
    binary = _binary_provenance(config.binary)
    image = _image_provenance(config.image)
    process_result = _run(["ps", "-eo", "pid=,ppid=,args="])
    if process_result.returncode != 0:
        raise EvidenceError("failed to take process snapshot")
    process_state = classify_process_snapshot(process_result.stdout)
    docker_oracles = _docker_oracles()
    foreign = process_state["foreign_workloads"]
    if foreign:
        raise EvidenceError(
            "foreign workload census is not empty: "
            + json.dumps(foreign, sort_keys=True)
        )
    if docker_oracles:
        raise EvidenceError(
            "Docker oracle census is not empty: "
            + json.dumps(docker_oracles, sort_keys=True)
        )
    host = os.uname()
    return {
        "repo": str(config.repo),
        "head": head,
        "git_dirty": False,
        "binary": binary,
        "image_ref": config.image,
        "image": image,
        "host": {
            "sysname": host.sysname,
            "nodename": host.nodename,
            "release": host.release,
            "version": host.version,
            "machine": host.machine,
        },
        "launcher_ancestry": process_state["launcher_ancestry"],
        "foreign_workloads": foreign,
        "docker_oracles": docker_oracles,
    }


def _monitor_sample(
    sequence: int,
    phase: str,
    *,
    owned_lineage: set[int],
) -> dict[str, object]:
    process_result = _run(
        ["ps", "-eo", "pid=,ppid=,args="],
        timeout=5,
    )
    if process_result.returncode != 0:
        raise EvidenceError("process census returned a failure status")
    process_state = classify_process_snapshot(
        process_result.stdout,
        owned_lineage=owned_lineage,
    )
    foreign = process_state["foreign_workloads"]
    if not isinstance(foreign, list):
        raise EvidenceError("process census returned malformed evidence")
    categories = sorted(
        {
            category
            for row in foreign
            if isinstance(row, dict)
            for category in [
                _foreign_workload_category(str(row.get("command", "")))
            ]
            if category is not None
        }
    )

    docker_result = _run(
        ["docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"],
        timeout=5,
    )
    if docker_result.returncode != 0:
        raise EvidenceError("Docker census returned a failure status")
    docker_count = 0
    for line in docker_result.stdout.splitlines():
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
            docker_count += 1
    return {
        "sequence": sequence,
        "phase": phase,
        "foreign_workload_count": len(foreign),
        "foreign_workload_categories": categories,
        "docker_oracle_count": docker_count,
    }


class _TraceDeadlineWatchdog:
    def __init__(
        self,
        process: subprocess.Popen[str],
        deadline: float,
    ) -> None:
        self._process = process
        self._deadline = deadline
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._started = False
        self._timed_out = False
        self._completed_in_budget = False
        self._failed = False

    def _record_failure(self) -> None:
        with self._lock:
            self._failed = True

    def _kill_fail_closed(self) -> None:
        try:
            self._process.kill()
        except Exception:
            self._record_failure()

    def start(self) -> None:
        try:
            thread = threading.Thread(
                target=self._run,
                name=WATCHDOG_THREAD_NAME,
                daemon=True,
            )
            self._thread = thread
            thread.start()
        except Exception:
            self._record_failure()
            self._cancel.set()
            self._kill_fail_closed()
            return
        with self._lock:
            self._started = True

    def _run(self) -> None:
        try:
            remaining = max(0.0, self._deadline - time.monotonic())
            try:
                self._process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                if self._cancel.is_set():
                    return
                with self._lock:
                    self._timed_out = True
                self._kill_fail_closed()
                return
            except Exception:
                self._record_failure()
                self._kill_fail_closed()
                return
            observed_at = time.monotonic()
            if self._cancel.is_set():
                return
            with self._lock:
                if observed_at < self._deadline:
                    self._completed_in_budget = True
                else:
                    self._timed_out = True
        except Exception:
            self._record_failure()
            self._kill_fail_closed()

    def remaining_seconds(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    def _join(self) -> None:
        with self._lock:
            started = self._started
            thread = self._thread
        if not started or thread is None:
            return
        try:
            thread.join(timeout=WATCHDOG_JOIN_SECONDS)
            if thread.is_alive():
                self._record_failure()
        except Exception:
            self._record_failure()

    def join_after_deadline(self) -> None:
        self._join()

    def cancel_and_join(self) -> None:
        self._cancel.set()
        self._join()

    @property
    def timed_out(self) -> bool:
        with self._lock:
            return self._timed_out

    @property
    def failed(self) -> bool:
        with self._lock:
            return self._failed

    def completion_exceeded_deadline(self, observed_at: float) -> bool:
        with self._lock:
            return (
                observed_at >= self._deadline
                and not self._completed_in_budget
            )


class _ContaminationMonitor:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._first_poll = threading.Event()
        self._lock = threading.Lock()
        self._poll_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._loop,
            name="native-kernel-contamination-monitor",
            daemon=True,
        )
        self._started = False
        self._stopped = False
        self._poll_error: str | None = None
        self._contaminated = False
        self._samples: list[dict[str, object]] = []
        self._next_sequence = 1
        self._owned_lineage: set[int] = set()

    def start(self) -> None:
        try:
            self._thread.start()
            self._started = True
        except Exception:
            self._poll_error = "monitor launch failed"
            self._first_poll.set()
            return
        if not self._first_poll.wait(timeout=6):
            with self._lock:
                self._poll_error = "initial monitor poll did not complete"
            self._stop.set()

    def _loop(self) -> None:
        try:
            while not self._stop.is_set():
                if not self._sample("interval"):
                    break
                self._first_poll.set()
                if self._stop.wait(MONITOR_INTERVAL_SECONDS):
                    break
        finally:
            self._first_poll.set()

    def _sample_locked(self, phase: str) -> bool:
        with self._lock:
            if self._poll_error is not None:
                return False
            sequence = self._next_sequence
        try:
            sample = _monitor_sample(
                sequence,
                phase,
                owned_lineage=self._owned_lineage,
            )
        except Exception:
            with self._lock:
                self._poll_error = "monitor poll failed"
            return False
        with self._lock:
            self._samples.append(sample)
            self._next_sequence += 1
            if (
                sample["foreign_workload_count"] != 0
                or sample["docker_oracle_count"] != 0
            ):
                self._contaminated = True
        return True

    def _sample(self, phase: str) -> bool:
        with self._poll_lock:
            return self._sample_locked(phase)

    def sample_launch_boundary(self) -> None:
        self._sample("launch-boundary")

    def launch_owned_process(
        self,
        launcher: Callable[[], subprocess.Popen[str]],
        on_launch: Callable[[subprocess.Popen[str], float], None],
    ) -> subprocess.Popen[str]:
        with self._poll_lock:
            process = launcher()
            launched_at = time.monotonic()
            if (
                isinstance(process.pid, bool)
                or not isinstance(process.pid, int)
                or process.pid <= 0
            ):
                try:
                    process.kill()
                finally:
                    process.wait()
                raise EvidenceError("trace Popen returned an invalid PID")
            self._owned_lineage.add(process.pid)
            on_launch(process, launched_at)
            self._sample_locked("interval")
            return process

    def stop(self) -> None:
        self._stop.set()
        if self._started:
            self._thread.join(timeout=6)
            if self._thread.is_alive():
                with self._lock:
                    self._poll_error = "monitor did not stop"
            else:
                self._sample("post-cleanup-boundary")
        with self._lock:
            self._stopped = True

    def evidence(self) -> dict[str, object]:
        with self._lock:
            samples = [dict(sample) for sample in self._samples]
            return {
                "started": self._started,
                "stopped": self._stopped,
                "interval_milliseconds": MONITOR_INTERVAL_MILLISECONDS,
                "sample_count": len(samples),
                "contaminated": self._contaminated,
                "poll_error": self._poll_error,
                "samples": samples,
            }


def _controlled_environment(
    host_run_id: str,
) -> tuple[dict[str, str], dict[str, object]]:
    selected = native_go_build.normalized_overlay(None)
    try:
        native_go_build.reject_ambient_carrick(os.environ, selected)
    except RuntimeError as error:
        raise EvidenceError(str(error)) from error
    environment = dict(os.environ)
    for key in native_go_build.PERFORMANCE_CONTROL_KEYS:
        environment.pop(key, None)
    environment["CARRICK_RUN_ID"] = host_run_id
    normalized_for_hash = dict(environment)
    normalized_for_hash["CARRICK_RUN_ID"] = "<base>-<lane>-host"
    determinant: dict[str, object] = {
        "effective_environment_sha256": _sha256_json(normalized_for_hash),
        "performance_controls": {
            key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS
        },
        "host_run_id_policy": "<base>-<lane>-host",
        "guest_run_id_policy": "<base>-<lane>-guest",
    }
    return environment, determinant


def _target_command(
    config: CaptureConfig,
    guest_run_id: str,
) -> list[str]:
    return [
        "run",
        "--exec-backend",
        "native",
        "-e",
        f"CARRICK_RUN_ID={guest_run_id}",
        "-w",
        "/tmp",
        config.image,
        "/bin/sh",
        "-c",
        native_go_build.guest_script(),
    ]


def _trace_command(
    config: CaptureConfig,
    paths: dict[str, pathlib.Path],
    guest_run_id: str,
) -> tuple[list[str], list[str]]:
    target = _target_command(config, guest_run_id)
    command = [
        str(config.binary),
        "trace",
        "--profile",
        PROFILE,
        "--trace-out",
        str(paths["raw_trace"]),
        "--summary-jsonl",
        str(paths["summary_jsonl"]),
        "--",
        *target,
    ]
    return command, target


def _determinants(
    config: CaptureConfig,
    environment: dict[str, object],
) -> dict[str, object]:
    return {
        "invocation": {
            "binary": str(config.binary),
            "trace_subcommand": "trace",
            "profile": PROFILE,
            "target_subcommand": "run",
            "exec_backend": "native",
            "guest_working_directory": "/tmp",
            "image": config.image,
            "guest_program": ["/bin/sh", "-c", native_go_build.guest_script()],
        },
        "environment": environment,
        "timeout_policy": {
            "seconds": config.timeout_seconds,
            "cleanup_seconds": 30,
        },
        "producer_sha256": sha256_file(pathlib.Path(__file__)),
        "acceptance_sha256": sha256_file(
            pathlib.Path(native_kernel_attribution.__file__)
        ),
    }


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _terminate_and_collect(
    process: subprocess.Popen[str],
) -> tuple[str, str, Exception | None]:
    failure: Exception | None = None
    try:
        if process.poll() is None:
            process.kill()
    except Exception as error:
        failure = error
    try:
        stdout, stderr = process.communicate(timeout=WATCHDOG_JOIN_SECONDS)
        return _text(stdout), _text(stderr), failure
    except subprocess.TimeoutExpired as error:
        if failure is None:
            failure = EvidenceError("trace process did not terminate")
        return _text(error.stdout), _text(error.stderr), failure
    except Exception as error:
        if failure is None:
            failure = error
        return "", "", failure


def _cleanup(
    config: CaptureConfig,
    host_run_id: str,
) -> tuple[dict[str, object], str, str]:
    argv = [str(config.repo / "scripts/sudo/kill.sh"), host_run_id]
    try:
        result = subprocess.run(
            argv,
            cwd=config.repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        stdout = _text(result.stdout)
        stderr = _text(result.stderr)
        status_value = result.returncode
        launch_error = None
    except Exception as error:
        stdout = ""
        stderr = f"cleanup command raised: {error}\n"
        status_value = 125
        launch_error = f"{type(error).__name__}: {error}"
    return (
        {
            "argv": argv,
            "argv_sha256": _sha256_json(argv),
            "status": status_value,
            "launch_error": launch_error,
        },
        stdout,
        stderr,
    )


def _natural_number(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{description} must be an integer")
    if value < 0:
        raise EvidenceError(f"{description} must be a natural integer")
    return value


def _integer(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{description} must be an integer")
    return value


def _add(total: int, value: int, description: str) -> int:
    if total > (1 << 64) - 1 - value:
        raise EvidenceError(f"{description} exceeds u64")
    return total + value


def _read_summary(path: pathlib.Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"summary JSONL is unavailable: {error}") from error
    try:
        text = raw.decode()
    except UnicodeDecodeError as error:
        raise EvidenceError("summary JSONL is not UTF-8") from error
    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise EvidenceError("summary JSONL is empty or contains a blank row")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvidenceError(
                f"summary JSONL line {line_number} is invalid"
            ) from error
        if not isinstance(row, dict):
            raise EvidenceError(
                f"summary JSONL line {line_number} is not an object"
            )
        rows.append(row)
    first = rows[0]
    fixed = {
        field: first.get(field)
        for field in (
            "schema",
            "profile",
            "run_id",
            "git_sha",
            "git_dirty",
            "binary_sha256",
            "command",
            "host",
            "completion",
        )
    }
    if fixed["schema"] != "carrick.dsr-profile.v1" or fixed["profile"] != PROFILE:
        raise EvidenceError("summary JSONL schema/profile is wrong")
    pc_total = 0
    stack_total = 0
    completion_rows = 0
    census = {"create": 0, "exit": 0, "live-at-end": 0}
    seen_census: set[str] = set()
    for line_number, row in enumerate(rows, 1):
        if any(row.get(field) != value for field, value in fixed.items()):
            raise EvidenceError(
                f"summary JSONL provenance changed at line {line_number}"
            )
        scope = row.get("scope")
        metric = row.get("metric")
        if not isinstance(scope, dict) or not isinstance(metric, dict):
            raise EvidenceError(
                f"summary JSONL scope/metric is malformed at line {line_number}"
            )
        phase = scope.get("phase")
        metric_type = metric.get("type")
        if metric_type == "completion":
            completion_rows += 1
        if phase == "cpu-kernel-pc":
            if metric_type != "exact":
                raise EvidenceError("kernel PC summary metric is not exact")
            count = _natural_number(metric.get("count"), "kernel PC count")
            pc_total = _add(pc_total, count, "kernel PC total")
        if phase == "cpu-kernel-stack":
            if metric_type != "stack-trace":
                raise EvidenceError("kernel stack summary metric is malformed")
            count = _natural_number(metric.get("count"), "kernel stack count")
            stack_total = _add(stack_total, count, "kernel stack total")
        if phase == "process-lifecycle":
            kind = scope.get("kind")
            if kind not in census:
                raise EvidenceError("summary has an unknown descendant census kind")
            count = _natural_number(
                metric.get("count"),
                f"descendant census {kind}",
            )
            census[str(kind)] = _add(
                census[str(kind)],
                count,
                f"descendant census {kind}",
            )
            seen_census.add(str(kind))
    if completion_rows != 1:
        raise EvidenceError("summary must contain exactly one completion row")
    if "live-at-end" not in seen_census:
        raise EvidenceError("summary lacks the live-at-end descendant census")
    if census["live-at-end"] != 0 or census["create"] != census["exit"]:
        raise EvidenceError("descendant census does not reconcile")
    if pc_total <= 0 or pc_total != stack_total:
        raise EvidenceError("kernel PC/stack reconciliation failed")
    completion_value = fixed["completion"]
    if not isinstance(completion_value, dict):
        raise EvidenceError("summary completion is malformed")
    target_exit_reason = _natural_number(
        completion_value.get("target_exit_reason"),
        "summary completion target_exit_reason",
    )
    incomplete_pairs = _natural_number(
        completion_value.get("incomplete_pairs"),
        "summary completion incomplete_pairs",
    )
    if (
        completion_value.get("complete") is not True
        or completion_value.get("bounded") is not False
        or target_exit_reason != 1
        or completion_value.get("high_cardinality_overflow") is not False
        or incomplete_pairs != 0
    ):
        raise EvidenceError("summary completion/drop state is not accepted")
    drops = completion_value.get("drops")
    if not isinstance(drops, dict) or drops.get("interrupted") is not False:
        raise EvidenceError("summary completion/drop state is not accepted")
    if set(drops) != {"interrupted", *DROP_FIELDS}:
        raise EvidenceError("summary completion has an unknown drop counter")
    for field in DROP_FIELDS:
        if _natural_number(drops.get(field), f"summary drops.{field}") != 0:
            raise EvidenceError("summary completion/drop state is not accepted")
    return {
        "provenance": fixed,
        "completion": completion_value,
        "descendant_census": census,
        "reconciliation": {
            "completion_rows": completion_rows,
            "kernel_pc_count": pc_total,
            "kernel_stack_count": stack_total,
        },
    }


def _artifact_binding(path: pathlib.Path, name: str) -> dict[str, object]:
    if not _lexists(path):
        raise EvidenceError(f"artifact {name} is absent")
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"artifact {name} is not a regular file")
    return {
        "path": str(_absolute(path)),
        "size": metadata.st_size,
        "sha256": sha256_file(path),
    }


def _available_artifacts(
    paths: dict[str, pathlib.Path],
) -> dict[str, dict[str, object]]:
    return {
        name: _artifact_binding(paths[name], name)
        for name in ARTIFACT_NAMES
        if _lexists(paths[name])
    }


def _receipt_payload(
    *,
    capture_id: str,
    capture_root: pathlib.Path,
    lane: str,
    host_run_id: str,
    guest_run_id: str,
    command: list[str],
    target: list[str],
    command_status: dict[str, object],
    cleanup: dict[str, object],
    paths: dict[str, pathlib.Path],
    pre: dict[str, object],
    post: dict[str, object] | None,
    determinants: dict[str, object],
    summary: dict[str, object] | None,
    monitor: dict[str, object],
    errors: list[str],
) -> dict[str, object]:
    artifacts = _available_artifacts(paths)
    command_stdout = artifacts.get("command_stdout")
    command_stderr = artifacts.get("command_stderr")
    cleanup_stdout = artifacts.get("cleanup_stdout")
    cleanup_stderr = artifacts.get("cleanup_stderr")
    command_status["stdout_sha256"] = (
        None if command_stdout is None else command_stdout["sha256"]
    )
    command_status["stderr_sha256"] = (
        None if command_stderr is None else command_stderr["sha256"]
    )
    cleanup["stdout_sha256"] = (
        None if cleanup_stdout is None else cleanup_stdout["sha256"]
    )
    cleanup["stderr_sha256"] = (
        None if cleanup_stderr is None else cleanup_stderr["sha256"]
    )
    accepted = not errors
    return {
        "schema": RECEIPT_SCHEMA,
        "outcome": "accepted" if accepted else "rejected",
        "capture_id": capture_id,
        "capture_root": str(capture_root),
        "lane": lane,
        "host_run_id": host_run_id,
        "guest_run_id": guest_run_id,
        "trace_argv": command,
        "target_argv": target,
        "command": command_status,
        "cleanup": cleanup,
        "provenance": {"pre": pre, "post": post},
        "determinants": determinants,
        "completion": None if summary is None else summary["completion"],
        "descendant_census": (
            None if summary is None else summary["descendant_census"]
        ),
        "reconciliation": (
            None if summary is None else summary["reconciliation"]
        ),
        "monitor": monitor,
        "artifacts": artifacts,
        "evidence_errors": errors,
    }


def _capture_one(
    config: CaptureConfig,
    lane: str,
    paths: dict[str, pathlib.Path],
    pre: dict[str, object],
    environment_determinant: dict[str, object],
) -> tuple[pathlib.Path, dict[str, object]]:
    host_run_id = f"{config.run_id}-{lane}-host"
    guest_run_id = f"{config.run_id}-{lane}-guest"
    environment, rebuilt_environment = _controlled_environment(host_run_id)
    if rebuilt_environment != environment_determinant:
        raise EvidenceError("controlled environment changed before capture")
    determinants = _determinants(config, environment_determinant)
    command, target = _trace_command(config, paths, guest_run_id)
    result: subprocess.CompletedProcess[str] | None = None
    timed_out = False
    launch_error: Exception | None = None
    stdout = ""
    stderr = ""
    cleanup: dict[str, object]
    cleanup_stdout: str
    cleanup_stderr: str
    monitor = _ContaminationMonitor()
    monitor.start()
    initial_monitor = monitor.evidence()
    initial_monitor_blocked = (
        initial_monitor["poll_error"] is not None
        or initial_monitor["contaminated"] is True
        or initial_monitor["started"] is not True
    )
    if not initial_monitor_blocked:
        monitor.sample_launch_boundary()
    launch_monitor = monitor.evidence()
    monitor_blocked = (
        launch_monitor["poll_error"] is not None
        or launch_monitor["contaminated"] is True
        or launch_monitor["started"] is not True
    )
    process: subprocess.Popen[str] | None = None
    watchdog: _TraceDeadlineWatchdog | None = None

    def trace_launched(
        candidate: subprocess.Popen[str],
        launched_at: float,
    ) -> None:
        nonlocal process, watchdog
        process = candidate
        watchdog = _TraceDeadlineWatchdog(
            candidate,
            launched_at + config.timeout_seconds,
        )
        watchdog.start()

    try:
        if not monitor_blocked:
            try:
                process = monitor.launch_owned_process(
                    lambda: subprocess.Popen(
                        command,
                        cwd=config.repo,
                        env=environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    ),
                    trace_launched,
                )
                execution_monitor = monitor.evidence()
                execution_blocked = (
                    execution_monitor["poll_error"] is not None
                    or execution_monitor["contaminated"] is True
                )
                if execution_blocked:
                    collected_stdout, collected_stderr, termination_error = (
                        _terminate_and_collect(process)
                    )
                    stdout = collected_stdout
                    stderr = collected_stderr
                    if termination_error is not None:
                        launch_error = termination_error
                else:
                    if watchdog is None:
                        raise EvidenceError(
                            "trace deadline watchdog failed"
                        )
                    remaining = watchdog.remaining_seconds()
                    if remaining <= 0:
                        watchdog.join_after_deadline()
                        remaining = WATCHDOG_JOIN_SECONDS
                    process_stdout, process_stderr = process.communicate(
                        timeout=remaining
                    )
                    communicate_finished_at = time.monotonic()
                    watchdog.cancel_and_join()
                    stdout = _text(process_stdout)
                    stderr = _text(process_stderr)
                    if (
                        watchdog.timed_out
                        or watchdog.completion_exceeded_deadline(
                            communicate_finished_at
                        )
                    ):
                        timed_out = True
                    if watchdog.failed:
                        launch_error = EvidenceError(
                            "trace deadline watchdog failed"
                        )
                    if process.returncode is None:
                        raise EvidenceError(
                            "trace process did not return a status"
                        )
                    result = subprocess.CompletedProcess(
                        command,
                        process.returncode,
                        stdout,
                        stderr,
                    )
            except subprocess.TimeoutExpired as error:
                timed_out = True
                stdout = _text(error.stdout)
                stderr = _text(error.stderr)
                if process is not None:
                    collected_stdout, collected_stderr, termination_error = (
                        _terminate_and_collect(process)
                    )
                    if collected_stdout:
                        stdout = collected_stdout
                    if collected_stderr:
                        stderr = collected_stderr
                    if termination_error is not None:
                        launch_error = termination_error
                    if process.returncode is not None:
                        result = subprocess.CompletedProcess(
                            command,
                            process.returncode,
                            stdout,
                            stderr,
                        )
            except Exception as error:
                launch_error = error
                stderr = (
                    f"trace command raised: {type(error).__name__}: {error}\n"
                )
                if process is not None:
                    (
                        collected_stdout,
                        collected_stderr,
                        termination_error,
                    ) = _terminate_and_collect(process)
                    if collected_stdout:
                        stdout = collected_stdout
                    if collected_stderr:
                        stderr = collected_stderr
                    if termination_error is not None:
                        launch_error = termination_error
                    if process.returncode is not None:
                        result = subprocess.CompletedProcess(
                            command,
                            process.returncode,
                            stdout,
                            stderr,
                        )
    finally:
        if watchdog is not None:
            watchdog.cancel_and_join()
            if watchdog.timed_out:
                timed_out = True
            if watchdog.failed:
                launch_error = EvidenceError(
                    "trace deadline watchdog failed"
                )
        cleanup, cleanup_stdout, cleanup_stderr = _cleanup(config, host_run_id)
        monitor.stop()
    monitor_evidence = monitor.evidence()

    _write_bytes_exclusive(paths["command_stdout"], stdout.encode())
    _write_bytes_exclusive(paths["command_stderr"], stderr.encode())
    _write_bytes_exclusive(paths["cleanup_stdout"], cleanup_stdout.encode())
    _write_bytes_exclusive(paths["cleanup_stderr"], cleanup_stderr.encode())
    status_value = None if result is None else result.returncode
    build_ok_count = stdout.splitlines().count("BUILD_OK")
    command_status = {
        "status": status_value,
        "timed_out": timed_out,
        "launch_error": (
            None
            if launch_error is None
            else f"{type(launch_error).__name__}: {launch_error}"
        ),
        "build_ok_count": build_ok_count,
    }
    _write_json_exclusive(paths["command_status"], command_status)

    errors: list[str] = []
    if monitor_evidence["poll_error"] is not None:
        errors.append("contamination monitor poll failed")
    if monitor_evidence["contaminated"] is True:
        errors.append("contamination monitor observed overlap")
    if timed_out:
        errors.append("trace command timed out")
    elif launch_error is not None:
        errors.append(f"trace command raised: {launch_error}")
    elif result is None:
        errors.append("trace command did not return a status")
    elif result.returncode != 0:
        errors.append(f"trace command failed with status {result.returncode}")
    if build_ok_count != 1:
        errors.append("trace command did not emit exactly one BUILD_OK")
    if cleanup["status"] != 0:
        errors.append(f"cleanup failed with status {cleanup['status']}")

    summary: dict[str, object] | None = None
    if _lexists(paths["summary_jsonl"]):
        try:
            summary = _read_summary(paths["summary_jsonl"])
        except EvidenceError as error:
            errors.append(str(error))
    elif not errors:
        errors.append("summary JSONL is absent")
    if not _lexists(paths["raw_trace"]) and not errors:
        errors.append("raw trace is absent")

    post: dict[str, object] | None = None
    try:
        post = _capture_snapshot(config)
    except EvidenceError as error:
        errors.append(f"post-capture provenance failed: {error}")
    if post is not None and pre != post:
        errors.append("capture provenance changed between pre and post")
    try:
        _, post_environment = _controlled_environment(host_run_id)
    except EvidenceError as error:
        errors.append(f"controlled environment changed during capture: {error}")
    else:
        if post_environment != environment_determinant:
            errors.append("controlled environment changed during capture")

    if summary is not None:
        provenance = _mapping(
            summary.get("provenance"),
            "summary provenance",
        )
        expected = {
            "run_id": host_run_id,
            "git_sha": pre["head"],
            "git_dirty": False,
            "binary_sha256": pre["binary"]["sha256"],
            "command": target,
        }
        for field, value in expected.items():
            if provenance.get(field) != value:
                errors.append(f"summary {field} differs from frozen capture")

    payload = _receipt_payload(
        capture_id=config.run_id,
        capture_root=config.artifact_dir,
        lane=lane,
        host_run_id=host_run_id,
        guest_run_id=guest_run_id,
        command=command,
        target=target,
        command_status=command_status,
        cleanup=cleanup,
        paths=paths,
        pre=pre,
        post=post,
        determinants=determinants,
        summary=summary,
        monitor=monitor_evidence,
        errors=errors,
    )
    _write_json_exclusive(paths["receipt"], payload)
    if errors:
        raise EvidenceError(errors[0])
    if post is None:
        raise EvidenceError("post-capture provenance is absent")
    return paths["receipt"], post


def _read_receipt(path: pathlib.Path) -> dict[str, Any]:
    if not _lexists(path):
        raise EvidenceError(f"receipt is absent: {path}")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise EvidenceError(f"receipt is not a regular file: {path}")
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot parse receipt: {path}") from error
    if not isinstance(value, dict):
        raise EvidenceError("receipt must be a JSON object")
    if value.get("schema") != RECEIPT_SCHEMA:
        raise EvidenceError("receipt schema is unknown or missing")
    return value


def _mapping(value: object, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{description} must be an object")
    return value


def _validate_artifacts(
    receipt_path: pathlib.Path,
    payload: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    artifacts = _mapping(payload.get("artifacts"), "receipt artifacts")
    if set(artifacts) != set(ARTIFACT_NAMES):
        raise EvidenceError("accepted receipt artifact set is incomplete")
    lane = payload.get("lane")
    if lane not in {"a", "b"}:
        raise EvidenceError("receipt lane must be a or b")
    expected = planned_paths(receipt_path.parent).runs[str(lane)]
    if receipt_path != expected["receipt"]:
        raise EvidenceError("receipt path differs from fixed layout")
    seen: set[pathlib.Path] = set()
    validated: dict[str, dict[str, Any]] = {}
    for name in ARTIFACT_NAMES:
        binding = _mapping(artifacts.get(name), f"artifact {name}")
        if set(binding) != {"path", "size", "sha256"}:
            raise EvidenceError(f"artifact {name} binding is malformed")
        raw_path = binding.get("path")
        if not isinstance(raw_path, str) or not pathlib.Path(raw_path).is_absolute():
            raise EvidenceError(f"artifact {name} path must be absolute")
        _natural_number(binding.get("size"), f"artifact {name}.size")
        if not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("sha256", ""))):
            raise EvidenceError(f"artifact {name} SHA-256 is malformed")
        path = pathlib.Path(raw_path)
        if path != expected[name]:
            raise EvidenceError(f"artifact {name} path differs from fixed layout")
        if path in seen:
            raise EvidenceError("receipt artifact paths must be distinct")
        seen.add(path)
        actual = _artifact_binding(path, name)
        if binding != actual:
            raise EvidenceError(f"artifact {name} size or SHA-256 changed")
        validated[name] = binding
    return validated


def _validate_completion(payload: dict[str, Any]) -> None:
    completion = _mapping(payload.get("completion"), "receipt completion")
    target_exit_reason = _integer(
        completion.get("target_exit_reason"),
        "completion target_exit_reason",
    )
    incomplete_pairs = _integer(
        completion.get("incomplete_pairs"),
        "completion incomplete_pairs",
    )
    if (
        completion.get("complete") is not True
        or completion.get("bounded") is not False
        or target_exit_reason != 1
        or completion.get("high_cardinality_overflow") is not False
        or incomplete_pairs < 0
        or incomplete_pairs != 0
    ):
        raise EvidenceError("receipt completion/drop state is not accepted")
    drops = _mapping(completion.get("drops"), "receipt completion drops")
    if drops.get("interrupted") is not False:
        raise EvidenceError("receipt completion/drop state is not accepted")
    if set(drops) != {"interrupted", *DROP_FIELDS}:
        raise EvidenceError("receipt completion has an unknown drop counter")
    for field in DROP_FIELDS:
        if (
            _natural_number(
                drops.get(field),
                f"completion drops.{field}",
            )
            != 0
        ):
            raise EvidenceError("receipt completion/drop state is not accepted")


def _validate_snapshot(
    snapshot: dict[str, Any],
    description: str,
) -> None:
    if set(snapshot) != {
        "repo",
        "head",
        "git_dirty",
        "binary",
        "image_ref",
        "image",
        "host",
        "launcher_ancestry",
        "foreign_workloads",
        "docker_oracles",
    }:
        raise EvidenceError("receipt provenance fields are not version-one exact")
    repo = snapshot.get("repo")
    if not isinstance(repo, str) or not pathlib.Path(repo).is_absolute():
        raise EvidenceError("receipt repository path is not absolute")
    head = snapshot.get("head")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise EvidenceError("receipt HEAD is malformed")
    if snapshot.get("git_dirty") is not False:
        raise EvidenceError("receipt HEAD is dirty")
    binary = _mapping(snapshot.get("binary"), "receipt binary")
    binary_path = binary.get("path")
    if (
        set(binary)
        != {
            "path",
            "size",
            "sha256",
            "codesign_verified",
            "dof_present",
            "dof_listing_sha256",
        }
        or not isinstance(binary_path, str)
        or not pathlib.Path(binary_path).is_absolute()
        or _natural_number(
            binary.get("size"),
            f"{description}.binary.size",
        )
        <= 0
        or not re.fullmatch(r"[0-9a-f]{64}", str(binary.get("sha256", "")))
        or binary.get("codesign_verified") is not True
        or binary.get("dof_present") is not True
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(binary.get("dof_listing_sha256", "")),
        )
    ):
        raise EvidenceError("receipt binary provenance is malformed")
    image_ref = snapshot.get("image_ref")
    image = _mapping(snapshot.get("image"), "receipt image")
    if (
        not isinstance(image_ref, str)
        or not image_ref
        or set(image) != {"architecture", "id", "repo_digests"}
        or image.get("architecture") != "arm64"
        or not isinstance(image.get("id"), str)
        or not image.get("id")
        or not isinstance(image.get("repo_digests"), list)
        or any(
            not isinstance(digest, str) or not digest
            for digest in image.get("repo_digests", [])
        )
    ):
        raise EvidenceError("receipt image identity is not native arm64")
    host = _mapping(snapshot.get("host"), "receipt host")
    if set(host) != {"sysname", "nodename", "release", "version", "machine"}:
        raise EvidenceError("receipt host provenance is malformed")
    ancestry = snapshot.get("launcher_ancestry")
    if not isinstance(ancestry, list) or not ancestry:
        raise EvidenceError("receipt launcher ancestry is malformed")
    ancestry_rows = [
        _mapping(row, "receipt launcher ancestry row")
        for row in ancestry
    ]
    for index, row in enumerate(ancestry_rows):
        if set(row) != {"depth", "executable", "script"}:
            raise EvidenceError("receipt launcher ancestry is malformed")
        depth = _natural_number(
            row.get("depth"),
            f"{description}.launcher_ancestry[{index}].depth",
        )
        executable = row.get("executable")
        script = row.get("script")
        if (
            depth != index
            or not isinstance(executable, str)
            or not executable
            or "/" in executable
            or (script is not None and not isinstance(script, str))
            or (isinstance(script, str) and "/" in script)
        ):
            raise EvidenceError("receipt launcher ancestry is malformed")


def _validate_monitor(payload: dict[str, Any]) -> None:
    monitor = _mapping(payload.get("monitor"), "receipt monitor")
    if set(monitor) != {
        "started",
        "stopped",
        "interval_milliseconds",
        "sample_count",
        "contaminated",
        "poll_error",
        "samples",
    }:
        raise EvidenceError("receipt monitor fields are malformed")
    interval = _natural_number(
        monitor.get("interval_milliseconds"),
        "monitor.interval_milliseconds",
    )
    sample_count = _natural_number(
        monitor.get("sample_count"),
        "monitor.sample_count",
    )
    samples = monitor.get("samples")
    if not isinstance(samples, list):
        raise EvidenceError("receipt monitor samples are malformed")
    if (
        monitor.get("started") is not True
        or monitor.get("stopped") is not True
        or interval != MONITOR_INTERVAL_MILLISECONDS
        or sample_count == 0
        or sample_count != len(samples)
        or monitor.get("contaminated") is not False
        or monitor.get("poll_error") is not None
    ):
        raise EvidenceError("receipt monitor did not remain clean and active")
    allowed_categories = {
        "native-go-build",
        "go-build",
        "carrick",
        "native-wall",
    }
    allowed_phases = {
        "interval",
        "launch-boundary",
        "post-cleanup-boundary",
    }
    phases: list[str] = []
    for index, value in enumerate(samples):
        sample = _mapping(value, f"monitor.samples[{index}]")
        if set(sample) != {
            "sequence",
            "phase",
            "foreign_workload_count",
            "foreign_workload_categories",
            "docker_oracle_count",
        }:
            raise EvidenceError(f"monitor.samples[{index}] is malformed")
        sequence = _natural_number(
            sample.get("sequence"),
            f"monitor.samples[{index}].sequence",
        )
        foreign_count = _natural_number(
            sample.get("foreign_workload_count"),
            f"monitor.samples[{index}].foreign_workload_count",
        )
        docker_count = _natural_number(
            sample.get("docker_oracle_count"),
            f"monitor.samples[{index}].docker_oracle_count",
        )
        categories = sample.get("foreign_workload_categories")
        categories_are_strings = isinstance(categories, list) and all(
            isinstance(category, str) for category in categories
        )
        phase = sample.get("phase")
        if (
            sequence != index + 1
            or phase not in allowed_phases
            or foreign_count != 0
            or docker_count != 0
            or not categories_are_strings
            or (
                categories_are_strings
                and categories != sorted(set(categories))
            )
            or (
                categories_are_strings
                and any(
                    category not in allowed_categories
                    for category in categories
                )
            )
        ):
            raise EvidenceError(
                f"monitor.samples[{index}] contains contaminated evidence"
            )
        phases.append(str(phase))
    if phases.count("launch-boundary") != 1:
        raise EvidenceError("receipt monitor lacks launch boundary")
    if phases.count("post-cleanup-boundary") != 1:
        raise EvidenceError("receipt monitor lacks post-cleanup boundary")
    launch_index = phases.index("launch-boundary")
    cleanup_index = phases.index("post-cleanup-boundary")
    if launch_index > cleanup_index:
        raise EvidenceError("receipt monitor boundary order is reversed")
    if not any(
        phase == "interval"
        for phase in phases[launch_index + 1 : cleanup_index]
    ):
        raise EvidenceError("receipt monitor lacks execution interval sample")


def validate_receipt(path: pathlib.Path) -> dict[str, Any]:
    receipt_path = _absolute(pathlib.Path(path))
    payload = _read_receipt(receipt_path)
    if payload.get("outcome") != "accepted":
        raise EvidenceError("receipt outcome is not accepted")
    lane = payload.get("lane")
    capture_id = payload.get("capture_id")
    capture_root = payload.get("capture_root")
    if lane not in {"a", "b"}:
        raise EvidenceError("receipt lane must be a or b")
    if (
        not isinstance(capture_id, str)
        or not RUN_ID_PATTERN.fullmatch(capture_id)
    ):
        raise EvidenceError("receipt capture identifier is malformed")
    if (
        not isinstance(capture_root, str)
        or not pathlib.Path(capture_root).is_absolute()
        or pathlib.Path(capture_root) != receipt_path.parent
    ):
        raise EvidenceError("receipt capture root differs from receipt layout")
    if (
        payload.get("host_run_id") != f"{capture_id}-{lane}-host"
        or payload.get("guest_run_id") != f"{capture_id}-{lane}-guest"
    ):
        raise EvidenceError("receipt run IDs do not use exact capture derivation")
    artifacts = _validate_artifacts(receipt_path, payload)
    command = _mapping(payload.get("command"), "receipt command")
    command_status = _integer(command.get("status"), "command.status")
    build_ok_receipt = _integer(
        command.get("build_ok_count"),
        "command.build_ok_count",
    )
    if (
        command_status != 0
        or command.get("timed_out") is not False
        or command.get("launch_error") is not None
    ):
        raise EvidenceError("receipt command status is not accepted")
    stdout_path = pathlib.Path(artifacts["command_stdout"]["path"])
    try:
        build_ok_count = stdout_path.read_text().splitlines().count("BUILD_OK")
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError("command stdout artifact is not UTF-8") from error
    if build_ok_receipt != 1 or build_ok_count != 1:
        raise EvidenceError("receipt requires exactly one BUILD_OK")
    if command.get("stdout_sha256") != artifacts["command_stdout"]["sha256"]:
        raise EvidenceError("receipt command stdout hash differs")
    if command.get("stderr_sha256") != artifacts["command_stderr"]["sha256"]:
        raise EvidenceError("receipt command stderr hash differs")
    try:
        status_document = json.loads(
            pathlib.Path(artifacts["command_status"]["path"]).read_text()
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("command status artifact is invalid JSON") from error
    if not isinstance(status_document, dict):
        raise EvidenceError("command status artifact is invalid JSON")
    _integer(status_document.get("status"), "command artifact status")
    _integer(
        status_document.get("build_ok_count"),
        "command artifact build_ok_count",
    )
    for field in ("status", "timed_out", "launch_error", "build_ok_count"):
        if status_document.get(field) != command.get(field):
            raise EvidenceError("command status artifact differs from receipt")

    host_run_id = payload.get("host_run_id")
    guest_run_id = payload.get("guest_run_id")
    if not isinstance(host_run_id, str) or not isinstance(guest_run_id, str):
        raise EvidenceError("receipt run IDs are missing")
    provenance = _mapping(payload.get("provenance"), "receipt provenance")
    pre = _mapping(provenance.get("pre"), "receipt pre provenance")
    post = _mapping(provenance.get("post"), "receipt post provenance")
    _validate_snapshot(pre, "provenance.pre")
    _validate_snapshot(post, "provenance.post")
    cleanup = _mapping(payload.get("cleanup"), "receipt cleanup")
    argv = cleanup.get("argv")
    cleanup_status = _integer(cleanup.get("status"), "cleanup.status")
    expected_cleanup_argv = [
        str(pathlib.Path(str(pre.get("repo"))) / "scripts/sudo/kill.sh"),
        host_run_id,
    ]
    if (
        not isinstance(argv, list)
        or argv != expected_cleanup_argv
        or cleanup.get("argv_sha256") != _sha256_json(argv)
        or cleanup_status != 0
        or cleanup.get("launch_error") is not None
    ):
        raise EvidenceError(
            "cleanup argv does not name the fixed helper and exact run ID"
        )
    if cleanup.get("stdout_sha256") != artifacts["cleanup_stdout"]["sha256"]:
        raise EvidenceError("receipt cleanup stdout hash differs")
    if cleanup.get("stderr_sha256") != artifacts["cleanup_stderr"]["sha256"]:
        raise EvidenceError("receipt cleanup stderr hash differs")

    if pre != post:
        raise EvidenceError("receipt provenance changed between pre and post")
    if pre.get("git_dirty") is not False:
        raise EvidenceError("receipt HEAD is dirty")
    if pre.get("foreign_workloads") != []:
        raise EvidenceError("receipt foreign workload census is not empty")
    if pre.get("docker_oracles") != []:
        raise EvidenceError("receipt Docker oracle census is not empty")
    binary = _mapping(pre.get("binary"), "receipt binary")
    if binary.get("dof_present") is not True:
        raise EvidenceError("receipt binary lacks DOF presence")

    determinants = _mapping(payload.get("determinants"), "receipt determinants")
    expected_invocation = {
        "binary": binary.get("path"),
        "trace_subcommand": "trace",
        "profile": PROFILE,
        "target_subcommand": "run",
        "exec_backend": "native",
        "guest_working_directory": "/tmp",
        "image": pre.get("image_ref"),
        "guest_program": [
            "/bin/sh",
            "-c",
            native_go_build.guest_script(),
        ],
    }
    if determinants.get("invocation") != expected_invocation:
        raise EvidenceError("receipt invocation is not fixed")
    expected_controls: dict[str, object] = {
        key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS
    }
    receipt_environment = _mapping(
        determinants.get("environment"),
        "receipt environment",
    )
    if (
        set(receipt_environment)
        != {
            "effective_environment_sha256",
            "performance_controls",
            "host_run_id_policy",
            "guest_run_id_policy",
        }
        or receipt_environment.get("performance_controls") != expected_controls
        or receipt_environment.get("host_run_id_policy")
        != "<base>-<lane>-host"
        or receipt_environment.get("guest_run_id_policy")
        != "<base>-<lane>-guest"
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt_environment.get("effective_environment_sha256", "")),
        )
    ):
        raise EvidenceError("receipt environment is not fixed")
    timeout_policy = _mapping(
        determinants.get("timeout_policy"),
        "receipt timeout policy",
    )
    timeout_seconds = _natural_number(
        timeout_policy.get("seconds"),
        "determinants.timeout_policy.seconds",
    )
    cleanup_seconds = _natural_number(
        timeout_policy.get("cleanup_seconds"),
        "determinants.timeout_policy.cleanup_seconds",
    )
    if timeout_seconds <= 0 or cleanup_seconds != 30:
        raise EvidenceError("receipt timeout policy is not fixed")
    if determinants.get("producer_sha256") != sha256_file(pathlib.Path(__file__)):
        raise EvidenceError("receipt producer hash differs from current producer")
    if determinants.get("acceptance_sha256") != sha256_file(
        pathlib.Path(native_kernel_attribution.__file__)
    ):
        raise EvidenceError("receipt acceptance hash differs from current analyzer")

    expected_target = [
        "run",
        "--exec-backend",
        "native",
        "-e",
        f"CARRICK_RUN_ID={guest_run_id}",
        "-w",
        "/tmp",
        str(pre.get("image_ref")),
        "/bin/sh",
        "-c",
        native_go_build.guest_script(),
    ]
    if payload.get("target_argv") != expected_target:
        raise EvidenceError("receipt target invocation is not fixed")
    expected_trace = [
        str(binary.get("path")),
        "trace",
        "--profile",
        PROFILE,
        "--trace-out",
        artifacts["raw_trace"]["path"],
        "--summary-jsonl",
        artifacts["summary_jsonl"]["path"],
        "--",
        *expected_target,
    ]
    if payload.get("trace_argv") != expected_trace:
        raise EvidenceError("receipt trace invocation is not fixed")

    _validate_monitor(payload)
    _validate_completion(payload)
    descendant_census = _mapping(
        payload.get("descendant_census"),
        "receipt descendant_census",
    )
    if set(descendant_census) != {"create", "exit", "live-at-end"}:
        raise EvidenceError("receipt descendant census is malformed")
    for field in ("create", "exit", "live-at-end"):
        _natural_number(
            descendant_census.get(field),
            f"descendant_census.{field}",
        )
    reconciliation = _mapping(
        payload.get("reconciliation"),
        "receipt reconciliation",
    )
    if set(reconciliation) != {
        "completion_rows",
        "kernel_pc_count",
        "kernel_stack_count",
    }:
        raise EvidenceError("receipt reconciliation is malformed")
    for field in (
        "completion_rows",
        "kernel_pc_count",
        "kernel_stack_count",
    ):
        _natural_number(
            reconciliation.get(field),
            f"reconciliation.{field}",
        )
    summary = _read_summary(pathlib.Path(artifacts["summary_jsonl"]["path"]))
    if payload.get("completion") != summary["completion"]:
        raise EvidenceError("receipt completion differs from summary")
    if payload.get("descendant_census") != summary["descendant_census"]:
        raise EvidenceError("receipt descendant census differs from summary")
    if payload.get("reconciliation") != summary["reconciliation"]:
        raise EvidenceError("receipt reconciliation differs from summary")
    summary_provenance = _mapping(
        summary.get("provenance"),
        "summary provenance",
    )
    expected_summary = {
        "run_id": host_run_id,
        "git_sha": pre.get("head"),
        "git_dirty": False,
        "binary_sha256": binary.get("sha256"),
        "command": payload.get("target_argv"),
    }
    for field, value in expected_summary.items():
        if summary_provenance.get(field) != value:
            raise EvidenceError(f"summary {field} differs from receipt")
    return payload


def compare_receipts(
    paths: Sequence[pathlib.Path],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(paths) != 2:
        raise EvidenceError("exactly two receipt paths are required")
    normalized = tuple(_absolute(pathlib.Path(path)) for path in paths)
    if normalized[0] == normalized[1]:
        raise EvidenceError("receipt paths must be distinct")
    raw = tuple(_read_receipt(path) for path in normalized)
    first_pre = _mapping(
        _mapping(raw[0].get("provenance"), "receipt provenance").get("pre"),
        "receipt pre provenance",
    )
    second_pre = _mapping(
        _mapping(raw[1].get("provenance"), "receipt provenance").get("pre"),
        "receipt pre provenance",
    )
    first_determinants = _mapping(
        raw[0].get("determinants"),
        "receipt determinants",
    )
    second_determinants = _mapping(
        raw[1].get("determinants"),
        "receipt determinants",
    )
    comparisons = (
        (
            "capture identifier",
            raw[0].get("capture_id"),
            raw[1].get("capture_id"),
        ),
        (
            "capture root",
            raw[0].get("capture_root"),
            raw[1].get("capture_root"),
        ),
        ("repository", first_pre.get("repo"), second_pre.get("repo")),
        ("host", first_pre.get("host"), second_pre.get("host")),
        (
            "ancestry",
            first_pre.get("launcher_ancestry"),
            second_pre.get("launcher_ancestry"),
        ),
        ("HEAD", first_pre.get("head"), second_pre.get("head")),
        ("binary", first_pre.get("binary"), second_pre.get("binary")),
        ("image", first_pre.get("image"), second_pre.get("image")),
        (
            "invocation",
            first_determinants.get("invocation"),
            second_determinants.get("invocation"),
        ),
        (
            "environment",
            first_determinants.get("environment"),
            second_determinants.get("environment"),
        ),
        (
            "timeout",
            first_determinants.get("timeout_policy"),
            second_determinants.get("timeout_policy"),
        ),
        (
            "producer",
            first_determinants.get("producer_sha256"),
            second_determinants.get("producer_sha256"),
        ),
        (
            "acceptance",
            first_determinants.get("acceptance_sha256"),
            second_determinants.get("acceptance_sha256"),
        ),
    )
    for label, first, second in comparisons:
        if first != second:
            raise EvidenceError(f"receipt determinant changed: {label}")
    validated = tuple(validate_receipt(path) for path in normalized)
    if validated[0].get("lane") != "a" or validated[1].get("lane") != "b":
        raise EvidenceError("receipt order must be A then B")
    host_ids = {payload.get("host_run_id") for payload in validated}
    guest_ids = {payload.get("guest_run_id") for payload in validated}
    if len(host_ids) != 2 or len(guest_ids) != 2 or host_ids.intersection(guest_ids):
        raise EvidenceError("A/B host and guest run IDs must be unique")
    return validated[0], validated[1]


def analyze_receipts(
    receipt_paths: Sequence[pathlib.Path],
    output: pathlib.Path,
) -> pathlib.Path:
    output_path = _absolute(pathlib.Path(output))
    if _lexists(output_path):
        raise EvidenceError(f"analysis output already exists: {output_path}")
    receipts = compare_receipts(receipt_paths)
    summaries = tuple(
        pathlib.Path(receipt["artifacts"]["summary_jsonl"]["path"])
        for receipt in receipts
    )
    document = native_kernel_attribution.analyze_profiles(summaries)
    if document.get("result") == "rejected":
        errors = document.get("evidence_errors")
        raise EvidenceError(
            "profile analyzer rejected: "
            + json.dumps(errors, sort_keys=True)
        )
    sources = document.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise EvidenceError("profile analyzer did not bind exactly two sources")
    receipt_sources = []
    for index, (receipt_path, receipt, source) in enumerate(
        zip(receipt_paths, receipts, sources, strict=True)
    ):
        summary_binding = receipt["artifacts"]["summary_jsonl"]
        if source.get("sha256") != summary_binding["sha256"]:
            raise EvidenceError("profile analyzer source hash differs from receipt")
        run = document["runs"][index]
        reconciliation = receipt["reconciliation"]
        if (
            run.get("kernel_pc_count")
            != reconciliation["kernel_pc_count"]
            or run.get("kernel_stack_count")
            != reconciliation["kernel_stack_count"]
        ):
            raise EvidenceError("profile analyzer reconciliation differs from receipt")
        normalized_receipt = _absolute(pathlib.Path(receipt_path))
        receipt_sources.append(
            {
                "path": str(normalized_receipt),
                "size": os.lstat(normalized_receipt).st_size,
                "sha256": sha256_file(normalized_receipt),
            }
        )
    document["receipt_sources"] = receipt_sources
    _write_json_exclusive(output_path, document)
    return output_path


def capture_pair(config: CaptureConfig) -> pathlib.Path:
    layout = planned_paths(config.artifact_dir)
    _preflight(layout)
    _, environment_determinant = _controlled_environment(
        f"{config.run_id}-a-host"
    )
    first_snapshot = _capture_snapshot(config)
    layout.artifact_dir.mkdir(parents=True, exist_ok=True)
    receipt_a, second_snapshot = _capture_one(
        config,
        "a",
        layout.runs["a"],
        first_snapshot,
        environment_determinant,
    )
    receipt_b, _ = _capture_one(
        config,
        "b",
        layout.runs["b"],
        second_snapshot,
        environment_determinant,
    )
    return analyze_receipts((receipt_a, receipt_b), layout.analysis)


def _positive_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer") from error
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return timeout


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--repo", required=True, type=pathlib.Path)
    capture.add_argument("--binary", required=True, type=pathlib.Path)
    capture.add_argument("--artifact-dir", required=True, type=pathlib.Path)
    capture.add_argument("--run-id", required=True)
    capture.add_argument("--image", required=True)
    capture.add_argument("--timeout", required=True, type=_positive_timeout)
    analyze = subparsers.add_parser("analyze")
    analyze.add_argument(
        "--receipt",
        action="append",
        required=True,
        type=pathlib.Path,
    )
    analyze.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    if args.command == "analyze" and len(args.receipt) != 2:
        parser.error("analyze requires exactly two --receipt paths")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "capture":
            output = capture_pair(
                CaptureConfig(
                    repo=args.repo,
                    binary=args.binary,
                    artifact_dir=args.artifact_dir,
                    run_id=args.run_id,
                    image=args.image,
                    timeout_seconds=args.timeout,
                )
            )
        else:
            output = analyze_receipts(args.receipt, args.output)
    except EvidenceError as error:
        print(f"native kernel capture rejected: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
