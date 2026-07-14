#!/usr/bin/env python3
"""Strict native compiler performance workload and evidence tooling.

Absolute timing authority comes from untraced runs.  In-process profile records
provide reconciled counts and (only after the ABBA tax gate) duration shares.
DTrace data is retained as proportional attribution and is never a wall-time
input to the optimization decision.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence


WORKLOAD_SCHEMA = "carrick.native-compiler-workload.v1"
RESULT_SCHEMA = "carrick.native-compiler-budget.v1"
PROTOCOL_PREFIX = "NATIVEPERF1"
FRAME_FIELDS = {
    "core": {"gateway_entries", "reconciled_exits", "overflowed"},
    "exits": {
        "exit_syscall",
        "exit_resolve_direct",
        "exit_resolve_indirect",
        "exit_sensitive",
        "exit_fault",
        "exit_kick",
        "exit_stale_generation",
        "exit_unsupported",
    },
    "sensitive": {
        "sensitive_exclusive",
        "sensitive_read_tpidr",
        "sensitive_write_tpidr",
        "sensitive_read_ctr",
        "sensitive_read_dczid",
        "sensitive_dc_zva",
        "sensitive_dc_cvau",
        "sensitive_ic_ivau",
    },
    "phases-a": {
        "phase_prepare_index_ns",
        "phase_prepare_index_count",
        "phase_translate_ns",
        "phase_translate_count",
        "phase_translated_run_ns",
        "phase_translated_run_count",
        "phase_finish_exit_ns",
        "phase_finish_exit_count",
    },
    "phases-b": {
        "phase_sensitive_emulation_ns",
        "phase_sensitive_emulation_count",
        "phase_syscall_dispatch_ns",
        "phase_syscall_dispatch_count",
        "phase_loop_quiesce_ns",
        "phase_loop_quiesce_count",
        "phase_blocked_ns",
        "phase_blocked_count",
    },
    "resolver-thread": {
        "translate_phase_nested_ns",
        "resolver_exits",
        "one_entry_hits",
        "gateway_entries",
        "syscall_exits",
        "direct_resolver_exits",
    },
    "resolver-process": {
        "translations",
        "duplicate_publications",
        "cache_lookups",
        "cache_lookup_hits",
        "invalidated_blocks",
    },
    "resolver-times": {
        "nested_translation_ns",
        "nested_translation_decode_ns",
        "nested_translation_plan_ns",
        "nested_translation_emit_ns",
        "nested_translation_publication_ns",
    },
    "cache-gauge": {"cache_used_bytes", "cache_capacity_bytes"},
}
REQUIRED_FRAMES = frozenset(FRAME_FIELDS)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class BudgetError(RuntimeError):
    """Evidence is malformed, incomplete, or cannot be trusted."""


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BudgetError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: pathlib.Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BudgetError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise BudgetError(f"top-level JSON must be an object: {path}")
    return value


def _sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise BudgetError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


@dataclasses.dataclass(frozen=True)
class HashedFile:
    guest_path: str
    fixture_path: str | None
    sha256: str


@dataclasses.dataclass(frozen=True)
class WorkloadManifest:
    schema: str
    name: str
    image: str
    image_digest: str
    workdir: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    files: tuple[HashedFile, ...]
    executable_sha256: str
    expected_exit: int
    expected_stdout_sha256: str
    max_traps: int
    native_page_profile: str
    capture: tuple[tuple[str, object], ...]
    manifest_path: pathlib.Path = dataclasses.field(compare=False, repr=False)


MANIFEST_FIELDS = {
    "schema",
    "name",
    "image",
    "image_digest",
    "workdir",
    "argv",
    "env",
    "files",
    "executable_sha256",
    "expected_exit",
    "expected_stdout_sha256",
    "max_traps",
    "native_page_profile",
    "capture",
}
FILE_FIELDS = {"guest_path", "fixture_path", "sha256"}


def _require_type(mapping: Mapping[str, object], key: str, kind: type):
    value = mapping.get(key)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise BudgetError(f"manifest field {key!r} must be {kind.__name__}")
    return value


def _require_hash(value: str, name: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise BudgetError(f"{name} must be a lowercase SHA-256")
    return value


def load_manifest(path: str | os.PathLike[str]) -> WorkloadManifest:
    manifest_path = pathlib.Path(path).resolve()
    raw = _read_json(manifest_path)
    unknown = set(raw) - MANIFEST_FIELDS
    missing = MANIFEST_FIELDS - set(raw)
    if unknown:
        raise BudgetError(f"unknown manifest field(s): {', '.join(sorted(unknown))}")
    if missing:
        raise BudgetError(f"missing manifest field(s): {', '.join(sorted(missing))}")
    schema = _require_type(raw, "schema", str)
    if schema != WORKLOAD_SCHEMA:
        raise BudgetError(f"unknown workload schema: {schema}")
    image_digest = _require_type(raw, "image_digest", str)
    if not IMAGE_DIGEST_RE.fullmatch(image_digest):
        raise BudgetError("image_digest must be sha256:<64 lowercase hex digits>")
    workdir = _require_type(raw, "workdir", str)
    if not workdir.startswith("/"):
        raise BudgetError("workdir must be an absolute guest path")
    argv_raw = _require_type(raw, "argv", list)
    if not argv_raw or not all(isinstance(item, str) for item in argv_raw):
        raise BudgetError("argv must be a non-empty string array")
    argv = tuple(argv_raw)
    if not argv[0].startswith("/"):
        raise BudgetError("argv[0] must be an absolute guest executable")
    env_raw = _require_type(raw, "env", list)
    env: list[tuple[str, str]] = []
    for entry in env_raw:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not all(isinstance(item, str) for item in entry)
        ):
            raise BudgetError("environment entries must be [key, value] string pairs")
        env.append((entry[0], entry[1]))
    if env != sorted(env) or len({key for key, _ in env}) != len(env):
        raise BudgetError("environment must be sorted with unique keys")
    files_raw = _require_type(raw, "files", list)
    if not files_raw:
        raise BudgetError("files must include at least the guest executable/input identity")
    files: list[HashedFile] = []
    guest_paths: set[str] = set()
    for entry in files_raw:
        if not isinstance(entry, dict):
            raise BudgetError("files entries must be objects")
        if set(entry) != FILE_FIELDS:
            raise BudgetError("file entries require exactly guest_path, fixture_path, sha256")
        guest_path = entry.get("guest_path")
        fixture_path = entry.get("fixture_path")
        sha256 = entry.get("sha256")
        if not isinstance(guest_path, str) or not guest_path.startswith("/"):
            raise BudgetError("file guest_path must be absolute")
        if fixture_path is not None and not isinstance(fixture_path, str):
            raise BudgetError("file fixture_path must be a relative string or null")
        if isinstance(fixture_path, str) and pathlib.PurePath(fixture_path).is_absolute():
            raise BudgetError("file fixture_path must be relative")
        if not isinstance(sha256, str):
            raise BudgetError("file sha256 must be a string")
        _require_hash(sha256, f"sha256 for {guest_path}")
        if guest_path in guest_paths:
            raise BudgetError(f"duplicate guest file path: {guest_path}")
        guest_paths.add(guest_path)
        if fixture_path is not None:
            fixture = (manifest_path.parent / fixture_path).resolve()
            try:
                fixture.relative_to(manifest_path.parent.parent)
            except ValueError as error:
                raise BudgetError(f"fixture escapes performance fixture root: {fixture_path}") from error
            actual = _sha256_path(fixture)
            if actual != sha256:
                raise BudgetError(
                    f"sha256 mismatch for {fixture_path}: expected {sha256}, got {actual}"
                )
        files.append(HashedFile(guest_path, fixture_path, sha256))
    capture = _require_type(raw, "capture", dict)
    expected_exit = _require_type(raw, "expected_exit", int)
    max_traps = _require_type(raw, "max_traps", int)
    if expected_exit < 0 or expected_exit > 255:
        raise BudgetError("expected_exit must be between 0 and 255")
    if max_traps <= 0:
        raise BudgetError("max_traps must be positive")
    executable_sha256 = _require_type(raw, "executable_sha256", str)
    expected_stdout_sha256 = _require_type(raw, "expected_stdout_sha256", str)
    _require_hash(executable_sha256, "executable_sha256")
    _require_hash(expected_stdout_sha256, "expected_stdout_sha256")
    return WorkloadManifest(
        schema=schema,
        name=_require_type(raw, "name", str),
        image=_require_type(raw, "image", str),
        image_digest=image_digest,
        workdir=workdir,
        argv=argv,
        env=tuple(env),
        files=tuple(files),
        executable_sha256=executable_sha256,
        expected_exit=expected_exit,
        expected_stdout_sha256=expected_stdout_sha256,
        max_traps=max_traps,
        native_page_profile=_require_type(raw, "native_page_profile", str),
        capture=tuple(sorted(capture.items())),
        manifest_path=manifest_path,
    )


def stdout_digest(manifest: WorkloadManifest, stdout: bytes) -> str:
    capture = dict(manifest.capture)
    normalization = capture.get("stdout_normalization", "none")
    if normalization == "go-test-duration":
        stdout = re.sub(rb"\([0-9]+(?:\.[0-9]+)?s\)", b"(<duration>)", stdout)
    elif normalization != "none":
        raise BudgetError(f"unknown stdout normalization: {normalization}")
    return hashlib.sha256(stdout).hexdigest()


def validate_work_product(manifest: WorkloadManifest, stderr_lines: Iterable[str]) -> None:
    capture = dict(manifest.capture)
    expected_path = capture.get("expected_output_guest_path")
    expected_digest = capture.get("expected_output_sha256")
    if expected_path is None and expected_digest is None:
        return
    if not isinstance(expected_path, str) or not expected_path.startswith("/"):
        raise BudgetError("work-product contract has invalid guest path")
    if not isinstance(expected_digest, str) or not HASH_RE.fullmatch(expected_digest):
        raise BudgetError("work-product contract has invalid SHA-256")
    records = [line.strip() for line in stderr_lines if line.startswith("NATIVEWORK1|")]
    if not records:
        raise BudgetError("missing work-product completion record")
    if len(records) != 1:
        raise BudgetError("duplicate work-product completion records")
    match = re.fullmatch(r"NATIVEWORK1\|output_sha256=([0-9a-f]{64})", records[0])
    if match is None:
        raise BudgetError("malformed work-product completion record")
    if match.group(1) != expected_digest:
        raise BudgetError(
            f"work-product digest mismatch: expected {expected_digest}, got {match.group(1)}"
        )


@dataclasses.dataclass(frozen=True)
class ProfileThread:
    pid: int
    tid: int
    era: int
    frames: frozenset[str]
    values: tuple[tuple[str, int], ...]

    @property
    def gateway_entries(self) -> int:
        return dict(self.values)["core.gateway_entries"]

    def value(self, frame: str, field: str) -> int:
        return dict(self.values)[f"{frame}.{field}"]


@dataclasses.dataclass(frozen=True)
class ProfileRun:
    threads: tuple[ProfileThread, ...]


def _parse_decimal(value: str, field: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise BudgetError(f"profile field {field} is not an unsigned decimal integer")
    parsed = int(value)
    if parsed > 2**64 - 1:
        raise BudgetError(f"profile field {field} overflows u64")
    return parsed


def _protocol_fields(line: str) -> tuple[str, dict[str, str]]:
    parts = line.strip().split("|")
    if len(parts) < 3 or parts[0] != PROTOCOL_PREFIX:
        raise BudgetError("malformed native profile prefix")
    kind = parts[1]
    fields: dict[str, str] = {}
    for item in parts[2:]:
        if "=" not in item:
            raise BudgetError(f"malformed native profile field: {item}")
        key, value = item.split("=", 1)
        if not key or key in fields:
            raise BudgetError(f"duplicate protocol field: {key}")
        fields[key] = value
    return kind, fields


def parse_nativeperf(lines: Iterable[str]) -> ProfileRun:
    groups: dict[tuple[int, int, int], dict[str, dict[str, int]]] = {}
    saw_protocol = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith(PROTOCOL_PREFIX + "|"):
            continue
        saw_protocol = True
        kind, fields = _protocol_fields(line)
        if kind == "invalid":
            reason = fields.get("reason", "malformed")
            raise BudgetError(f"invalid native profile record: {reason}")
        if kind != "thread":
            raise BudgetError(f"unknown native profile record kind: {kind}")
        common = {"complete", "pid", "tid", "era", "frame"}
        if not common.issubset(fields):
            raise BudgetError("profile frame is missing identity fields")
        if fields["complete"] != "1":
            raise BudgetError("incomplete native profile record")
        frame = fields["frame"]
        if frame not in FRAME_FIELDS:
            raise BudgetError(f"unknown profile frame: {frame}")
        extras = set(fields) - common
        unknown = extras - FRAME_FIELDS[frame]
        missing = FRAME_FIELDS[frame] - extras
        if unknown:
            raise BudgetError(f"unknown field(s) in {frame}: {', '.join(sorted(unknown))}")
        if missing:
            raise BudgetError(f"missing field(s) in {frame}: {', '.join(sorted(missing))}")
        key = tuple(_parse_decimal(fields[name], name) for name in ("pid", "tid", "era"))
        group = groups.setdefault(key, {})
        if frame in group:
            raise BudgetError(
                f"duplicate frame {frame} for duplicate thread identity pid/tid/era {key}"
            )
        group[frame] = {
            name: _parse_decimal(fields[name], name) for name in FRAME_FIELDS[frame]
        }
    if not saw_protocol:
        raise BudgetError("no NATIVEPERF1 records found")
    threads: list[ProfileThread] = []
    for (pid, tid, era), frames in sorted(groups.items()):
        missing = REQUIRED_FRAMES - set(frames)
        if missing:
            raise BudgetError(
                f"missing profile frames for {(pid, tid, era)}: {', '.join(sorted(missing))}"
            )
        values = tuple(
            sorted(
                (f"{frame}.{field}", value)
                for frame, frame_values in frames.items()
                for field, value in frame_values.items()
            )
        )
        threads.append(ProfileThread(pid, tid, era, frozenset(frames), values))
    return ProfileRun(tuple(threads))


def validate_profile(run: ProfileRun) -> None:
    if not run.threads:
        raise BudgetError("native profile has no complete threads")
    identities: set[tuple[int, int, int]] = set()
    for thread in run.threads:
        identity = (thread.pid, thread.tid, thread.era)
        if identity in identities:
            raise BudgetError(f"duplicate thread identity: {identity}")
        identities.add(identity)
        gateway = thread.gateway_entries
        reconciled = thread.value("core", "reconciled_exits")
        if thread.value("core", "overflowed") != 0:
            raise BudgetError(f"profile overflow for {identity}")
        exits = sum(thread.value("exits", field) for field in FRAME_FIELDS["exits"])
        if gateway != reconciled or gateway != exits:
            raise BudgetError(
                f"exit reconciliation mismatch for {identity}: gateway={gateway}, "
                f"reconciled={reconciled}, exits={exits}"
            )
        sensitive = sum(
            thread.value("sensitive", field) for field in FRAME_FIELDS["sensitive"]
        )
        if sensitive != thread.value("exits", "exit_sensitive"):
            raise BudgetError(f"sensitive reconciliation mismatch for {identity}")
        for field in (
            "phase_prepare_index_count",
            "phase_translated_run_count",
            "phase_finish_exit_count",
        ):
            if thread.value("phases-a", field) != gateway:
                raise BudgetError(f"phase reconciliation mismatch for {identity}: {field}")
        if thread.value("phases-b", "phase_loop_quiesce_count") != gateway:
            raise BudgetError(f"phase reconciliation mismatch for {identity}: loop quiesce")
        syscall = thread.value("exits", "exit_syscall")
        if (
            thread.value("phases-b", "phase_syscall_dispatch_count") != syscall
            or thread.value("phases-b", "phase_blocked_count") != syscall
        ):
            raise BudgetError(f"syscall phase reconciliation mismatch for {identity}")
        if thread.value("resolver-thread", "gateway_entries") != gateway:
            raise BudgetError(f"resolver gateway reconciliation mismatch for {identity}")
        if thread.value("resolver-thread", "syscall_exits") != syscall:
            raise BudgetError(f"resolver syscall reconciliation mismatch for {identity}")
        if thread.value("resolver-thread", "direct_resolver_exits") != thread.value(
            "exits", "exit_resolve_direct"
        ):
            raise BudgetError(f"direct resolver reconciliation mismatch for {identity}")
        nested = thread.value("resolver-times", "nested_translation_ns")
        nested_active_parts = sum(
            thread.value("resolver-times", field)
            for field in (
                "nested_translation_decode_ns",
                "nested_translation_plan_ns",
                "nested_translation_emit_ns",
            )
        )
        if nested_active_parts > nested:
            raise BudgetError(f"nested translation subphases exceed total for {identity}")
        # Resolver time is a process-epoch delta assigned exactly once; it is
        # intentionally not compared with one thread's prepare phase.  The
        # cache-gauge frame is likewise a point-in-time gauge, never a delta.


def profile_decision_inputs(profile: ProfileRun, cpu_ns: int) -> tuple[tuple[str, float], ...]:
    if cpu_ns <= 0:
        raise BudgetError("profile decision requires positive measured CPU time")
    validate_profile(profile)
    hottest = max(profile.threads, key=lambda thread: thread.gateway_entries)
    gateway = hottest.gateway_entries
    if gateway <= 0:
        raise BudgetError("hottest profile thread has no gateway exits")
    translation_ns = sum(
        thread.value("resolver-times", "nested_translation_ns") for thread in profile.threads
    )
    syscall_ns = sum(
        thread.value("phases-b", "phase_syscall_dispatch_ns") for thread in profile.threads
    )
    blocked_ns = sum(thread.value("phases-b", "phase_blocked_ns") for thread in profile.threads)
    values = {
        "sensitive_exclusive": hottest.value("sensitive", "sensitive_exclusive") / gateway,
        "resolver_recurrence": (
            hottest.value("exits", "exit_resolve_direct")
            + hottest.value("exits", "exit_resolve_indirect")
        )
        / gateway,
        "cold_translation_ns": float(translation_ns),
        "syscall_dispatch_ns": float(syscall_ns),
        "blocked_residual_ns": float(blocked_ns),
    }
    return tuple(sorted(values.items()))


def parse_toolexec_capture(data: bytes) -> list[tuple[str, ...]]:
    if not data:
        raise BudgetError("empty toolexec capture")
    if not data.endswith(b"\0\0"):
        raise BudgetError("incomplete toolexec capture")
    records: list[tuple[str, ...]] = []
    for raw_record in data.split(b"\0\0"):
        if not raw_record:
            continue
        fields = raw_record.split(b"\0")
        try:
            decoded = tuple(field.decode("utf-8") for field in fields)
        except UnicodeDecodeError as error:
            raise BudgetError("toolexec capture is not UTF-8") from error
        if len(decoded) < 2 or decoded[0] != "TOOLEXEC1" or not decoded[1].startswith("/"):
            raise BudgetError("malformed toolexec record")
        records.append(decoded[1:])
    if not records:
        raise BudgetError("toolexec capture contains no records")
    return records


def abba_schedule(samples: int = 5) -> tuple[str, ...]:
    if samples <= 0:
        raise BudgetError("ABBA samples must be positive")
    result = ["off-warmup", "on-warmup"]
    index = 1
    while index + 1 <= samples:
        result.extend((f"off-{index}", f"on-{index}", f"on-{index + 1}", f"off-{index + 1}"))
        index += 2
    if index <= samples:
        result.extend((f"off-{index}", f"on-{index}"))
    return tuple(result)


def resolve_run_schedule(value: str) -> tuple[tuple[str, str, int], ...]:
    expected = abba_schedule(samples=5)
    labels = expected if value == "abba-5" else tuple(item.strip() for item in value.split(","))
    if labels != expected:
        raise BudgetError(
            "run schedule must be the complete ABBA warmup plus five-sample sequence"
        )
    entries = []
    for label in labels:
        plane = "untraced" if label.startswith("off-") else "profiled"
        repetition = 0 if label.endswith("warmup") else int(label.rsplit("-", 1)[1])
        entries.append((label, plane, repetition))
    return tuple(entries)


def validate_no_live_carrick(ps_output: str) -> None:
    offenders = []
    for line in ps_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid, separator, command = stripped.partition(" ")
        command = command.strip()
        name = pathlib.PurePath(command).name
        if separator and pid.isdecimal() and (name == "carrick" or name.startswith("carrick:")):
            offenders.append(pid)
    if offenders:
        raise BudgetError(f"live Carrick process blocks Docker phase: {', '.join(offenders)}")


def _assert_no_live_carrick() -> None:
    result = subprocess.run(
        ["ps", "-axo", "pid=,comm="], check=True, text=True, capture_output=True
    )
    validate_no_live_carrick(result.stdout)


def _assert_run_id_absent(run_id: str) -> None:
    result = subprocess.run(
        ["ps", "-axo", "pid=,command="], check=True, text=True, capture_output=True
    )
    matches = [line.strip() for line in result.stdout.splitlines() if run_id in line]
    if matches:
        raise BudgetError(f"scoped Carrick descendants remain after cleanup: {matches[0]}")


@dataclasses.dataclass(frozen=True)
class TimeRecord:
    wall_ns: int
    user_ns: int
    system_ns: int
    peak_rss_bytes: int


def _seconds_ns(value: str) -> int:
    try:
        seconds = float(value)
    except ValueError as error:
        raise BudgetError(f"invalid time value: {value}") from error
    if seconds < 0 or not (seconds < float("inf")):
        raise BudgetError(f"invalid time value: {value}")
    return round(seconds * 1_000_000_000)


def parse_time_l(text: str) -> TimeRecord:
    timing = re.search(
        r"(?m)^\s*([0-9]+(?:\.[0-9]+)?) real\s+([0-9]+(?:\.[0-9]+)?) user\s+([0-9]+(?:\.[0-9]+)?) sys\s*$",
        text,
    )
    rss = re.search(r"(?m)^\s*([0-9]+)\s+maximum resident set size\s*$", text)
    if timing is None or rss is None:
        raise BudgetError("malformed /usr/bin/time -l output")
    return TimeRecord(
        _seconds_ns(timing.group(1)),
        _seconds_ns(timing.group(2)),
        _seconds_ns(timing.group(3)),
        int(rss.group(1)),
    )


@dataclasses.dataclass(frozen=True)
class RunRecord:
    schema: str
    workload: str
    plane: str
    repetition: int
    run_id: str
    binary_sha256: str
    wall_ns: int
    user_ns: int
    system_ns: int
    peak_rss_bytes: int
    exit_status: int
    work_units: int
    cleanup_ok: bool
    profile: ProfileRun | None
    decision_inputs: tuple[tuple[str, float], ...] = ()
    dtrace_wall_shares: tuple[tuple[str, float], ...] = ()
    schedule_label: str = ""

    @classmethod
    def synthetic(cls, **shares: float) -> "RunRecord":
        return cls(
            RESULT_SCHEMA,
            "synthetic",
            "profiled",
            1,
            "synthetic",
            "0" * 64,
            1,
            1,
            0,
            1,
            0,
            1,
            True,
            None,
            tuple(sorted(shares.items())),
        )

    def with_dtrace_wall_shares(self, shares: Mapping[str, float]) -> "RunRecord":
        return dataclasses.replace(self, dtrace_wall_shares=tuple(sorted(shares.items())))


@dataclasses.dataclass(frozen=True)
class DecisionRecord:
    schema: str
    selected_slice: str
    share: float
    basis: str
    supporting_run_ids: tuple[str, ...]
    profile_tax: float | None
    duration_evidence_usable: bool


COUNT_DECISIONS = (
    ("sensitive_exclusive", "sensitive-exclusive"),
    ("resolver_recurrence", "resolver-recurrence"),
)
DURATION_DECISIONS = (
    ("cold_translation_and_first_resolution", "cold-translation-aot-design"),
    ("syscall_dispatch", "syscall-dispatch"),
    ("blocked_residual", "blocked-residual"),
)


def analyze(records: Sequence[RunRecord]) -> DecisionRecord:
    if not records:
        raise BudgetError("analysis requires at least one valid run")
    for record in records:
        if record.schema != RESULT_SCHEMA or not record.cleanup_ok or record.exit_status != 0:
            raise BudgetError("analysis record is invalid or incomplete")
    measured = [record for record in records if not record.schedule_label.endswith("warmup")]
    if not measured:
        raise BudgetError("analysis requires at least one measured run after warmups")
    expected_labels = {
        *(f"off-{index}" for index in range(1, 6)),
        *(f"on-{index}" for index in range(1, 6)),
    }
    labels = [record.schedule_label for record in measured]
    if len(labels) != len(expected_labels) or set(labels) != expected_labels:
        raise BudgetError("analysis requires the complete measured ABBA label set exactly once")
    for record in measured:
        mode, _, repetition = record.schedule_label.partition("-")
        expected_plane = "untraced" if mode == "off" else "profiled"
        if record.plane != expected_plane or record.repetition != int(repetition):
            raise BudgetError("measured ABBA label, plane, and repetition do not agree")
    if len({record.workload for record in measured}) != 1 or len(
        {record.binary_sha256 for record in measured}
    ) != 1:
        raise BudgetError("analysis requires one workload and binary across measured ABBA runs")
    profiled = [record for record in measured if record.plane == "profiled"]
    untraced = [record for record in measured if record.plane == "untraced"]
    profile_inputs = []
    for record in profiled:
        values = dict(record.decision_inputs)
        if len(values) != len(record.decision_inputs) or any(
            key not in values for key, _ in COUNT_DECISIONS
        ):
            raise BudgetError("profiled count evidence is missing or duplicated")
        profile_inputs.append(values)
    duration_usable = True
    profile_tax: float | None = None
    if duration_usable:
        off_wall = statistics.median(record.wall_ns for record in untraced)
        on_wall = statistics.median(record.wall_ns for record in profiled)
        if off_wall <= 0:
            raise BudgetError("untraced ABBA wall median must be positive")
        profile_tax = on_wall / off_wall - 1.0
        duration_usable = profile_tax <= 0.10
    count_shares: dict[str, float] = {}
    for key, _ in COUNT_DECISIONS:
        values = [inputs[key] for inputs in profile_inputs]
        if any(value < 0 or value > 1 for value in values):
            raise BudgetError(f"analysis share outside [0,1]: {key}")
        count_shares[key] = sum(values) / len(values)
    for key, selected in COUNT_DECISIONS:
        if count_shares[key] >= 0.30:
            return DecisionRecord(
                RESULT_SCHEMA,
                selected,
                count_shares[key],
                "reconciled-profile-counts",
                tuple(record.run_id for record in profiled),
                profile_tax,
                duration_usable,
            )
    duration_shares: dict[str, float] = {}
    if duration_usable:
        untraced_cpu = statistics.median(
            record.user_ns + record.system_ns for record in untraced
        )
        if untraced_cpu <= 0:
            raise BudgetError("untraced ABBA CPU median must be positive")
        duration_values = profile_inputs
        cold = statistics.median(value.get("cold_translation_ns", 0.0) for value in duration_values)
        duration_shares = {
            "syscall_dispatch": statistics.median(
                value.get("syscall_dispatch_ns", 0.0) for value in duration_values
            )
            / untraced_cpu,
            "blocked_residual": statistics.median(
                value.get("blocked_residual_ns", 0.0) for value in duration_values
            )
            / untraced_cpu,
        }
        if all("first_resolution_ns" in value for value in duration_values):
            first = statistics.median(value["first_resolution_ns"] for value in duration_values)
            duration_shares["cold_translation_and_first_resolution"] = (
                cold + first
            ) / untraced_cpu
        if any(value < 0 or value > 1 for value in duration_shares.values()):
            raise BudgetError("duration evidence does not reconcile to untraced CPU")
        support = tuple(record.run_id for record in measured if record.plane in {"untraced", "profiled"})
        for key, selected in DURATION_DECISIONS:
            if duration_shares.get(key, 0.0) >= 0.30:
                return DecisionRecord(
                    RESULT_SCHEMA,
                    selected,
                    duration_shares[key],
                    "low-tax-profile-durations-over-untraced-cpu",
                    support,
                    profile_tax,
                    True,
                )
    combined = [
        (count_shares[key], order, selected)
        for order, (key, selected) in enumerate(COUNT_DECISIONS)
    ]
    if duration_usable:
        offset = len(combined)
        combined.extend(
            (duration_shares[key], offset + order, selected)
            for order, (key, selected) in enumerate(DURATION_DECISIONS)
            if key in duration_shares
        )
    ranked = sorted(combined, key=lambda item: (-item[0], item[1]))
    if len(ranked) >= 2 and ranked[0][0] + ranked[1][0] >= 0.60:
        selected = f"{ranked[0][2]}+{ranked[1][2]}"
        return DecisionRecord(
            RESULT_SCHEMA,
            selected,
            ranked[0][0] + ranked[1][0],
            "two-term",
            tuple(record.run_id for record in profiled),
            profile_tax,
            duration_usable,
        )
    if profile_tax is not None and profile_tax > 0.10:
        raise BudgetError(
            f"duration evidence unavailable: ABBA profile tax {profile_tax:.3f} exceeds 0.10"
        )
    raise BudgetError("no two-term slice explains at least 60%")


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def _git_clean(repo: pathlib.Path) -> tuple[str, bool]:
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, capture_output=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo,
            check=True,
            text=True,
            capture_output=True,
        ).stdout
    )
    return sha, dirty


def _atomic_write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    temp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(temp, path)


def _append_jsonl(path: pathlib.Path, value: object) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        written = os.write(fd, encoded.encode())
        if written != len(encoded.encode()):
            raise BudgetError("short JSONL append")
        os.fsync(fd)
    finally:
        os.close(fd)


def _record_json(record: RunRecord) -> dict[str, object]:
    value = dataclasses.asdict(record)
    if record.profile is not None:
        value["profile"] = {
            "threads": [
                {
                    "pid": thread.pid,
                    "tid": thread.tid,
                    "era": thread.era,
                    "frames": sorted(thread.frames),
                    "values": dict(thread.values),
                }
                for thread in record.profile.threads
            ]
        }
    return value


def _assert_image_identity(manifest: WorkloadManifest) -> None:
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", manifest.image],
        check=True,
        text=True,
        capture_output=True,
    )
    if result.stdout.strip() != manifest.image_digest:
        raise BudgetError(
            f"image digest mismatch: expected {manifest.image_digest}, got {result.stdout.strip()}"
        )


def _assert_guest_identities(manifest: WorkloadManifest) -> None:
    guest_files = [item for item in manifest.files if item.fixture_path is None]
    paths = sorted({manifest.argv[0], *(item.guest_path for item in guest_files)})
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            manifest.image,
            "sha256sum",
            *paths,
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    observed = {}
    for line in result.stdout.splitlines():
        digest, separator, path = line.partition("  ")
        if not separator:
            raise BudgetError(f"malformed guest sha256sum output: {line}")
        observed[path] = digest
    expected = {item.guest_path: item.sha256 for item in guest_files}
    expected[manifest.argv[0]] = manifest.executable_sha256
    for path, digest in expected.items():
        if observed.get(path) != digest:
            raise BudgetError(
                f"guest sha256 mismatch for {path}: expected {digest}, got {observed.get(path)}"
            )


def _time_command(command: list[str], cwd: pathlib.Path, env: Mapping[str, str], artifact: pathlib.Path):
    stdout_path = artifact / "stdout"
    stderr_path = artifact / "stderr"
    time_path = artifact / "time.txt"
    artifact.mkdir(parents=True, exist_ok=True)
    started = time.monotonic_ns()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(
            ["/usr/bin/time", "-l", *command],
            cwd=cwd,
            env=dict(env),
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    wall_ns = time.monotonic_ns() - started
    stderr_bytes = stderr_path.read_bytes()
    stderr_text = stderr_bytes.decode("utf-8", "replace")
    match = re.search(
        r"(?ms)(\s*[0-9.]+ real\s+[0-9.]+ user\s+[0-9.]+ sys\s+.*)$", stderr_text
    )
    if match is None:
        raise BudgetError("/usr/bin/time -l trailer not found")
    time_text = match.group(1)
    time_path.write_text(time_text, encoding="utf-8")
    timing = parse_time_l(time_text)
    return result.returncode, dataclasses.replace(timing, wall_ns=wall_ns), stdout_path, stderr_path


def _fixture_mount(manifest: WorkloadManifest) -> pathlib.Path | None:
    fixture_paths = [item for item in manifest.files if item.fixture_path is not None]
    if not fixture_paths:
        return None
    common = os.path.commonpath(
        [str((manifest.manifest_path.parent / item.fixture_path).resolve()) for item in fixture_paths]
    )
    root = pathlib.Path(common)
    return root.parent if root.is_file() else root


def materialized_guest_command(
    manifest: WorkloadManifest,
) -> tuple[pathlib.Path | None, tuple[str, ...]]:
    fixture = _fixture_mount(manifest)
    if fixture is None:
        return None, manifest.argv
    steps: list[str] = []
    for item in manifest.files:
        if item.fixture_path is None:
            continue
        host = (manifest.manifest_path.parent / item.fixture_path).resolve()
        try:
            relative = host.relative_to(fixture)
        except ValueError as error:
            raise BudgetError(f"fixture is outside workload mount root: {host}") from error
        source = pathlib.PurePosixPath("/native-compiler-w2") / pathlib.PurePosixPath(
            relative.as_posix()
        )
        destination = pathlib.PurePosixPath(item.guest_path)
        steps.append(f"mkdir -p {sh_quote(str(destination.parent))}")
        steps.append(f"cp {sh_quote(str(source))} {sh_quote(str(destination))}")
    for index, arg in enumerate(manifest.argv[:-1]):
        if arg == "-o":
            output_parent = pathlib.PurePosixPath(manifest.argv[index + 1]).parent
            steps.append(f"mkdir -p {sh_quote(str(output_parent))}")
    capture = dict(manifest.capture)
    expected_output = capture.get("expected_output_guest_path")
    if expected_output is None:
        steps.append('exec "$@"')
    else:
        if not isinstance(expected_output, str) or not expected_output.startswith("/"):
            raise BudgetError("work-product contract has invalid guest path")
        steps.extend(
            (
                '"$@"',
                "result=$?",
                'if [ "$result" -ne 0 ]; then exit "$result"; fi',
                f"digest=$(sha256sum {sh_quote(expected_output)})",
                'digest=${digest%% *}',
                "printf 'NATIVEWORK1|output_sha256=%s\\n' \"$digest\" >&2",
            )
        )
    return fixture, ("/bin/sh", "-c", "; ".join(steps), "replay", *manifest.argv)


def _carrick_command(repo: pathlib.Path, manifest: WorkloadManifest, run_id: str) -> list[str]:
    command = [
        str(repo / "target/release/carrick"),
        "run",
        "--name",
        run_id,
        "--max-traps",
        str(manifest.max_traps),
        "--raw",
        "--fs",
        "host",
        "-w",
        manifest.workdir,
        "--exec-backend",
        "native",
        "--native-page-profile",
        manifest.native_page_profile,
    ]
    for key, value in manifest.env:
        command.extend(("-e", f"{key}={value}"))
    fixture, guest_argv = materialized_guest_command(manifest)
    if fixture is not None:
        command.extend(("-v", f"{fixture}:/native-compiler-w2:ro"))
    command.extend((manifest.image, *guest_argv))
    return command


def _docker_command(manifest: WorkloadManifest) -> list[str]:
    command = ["docker", "run", "--rm", "--platform", "linux/arm64", "-w", manifest.workdir]
    for key, value in manifest.env:
        command.extend(("-e", f"{key}={value}"))
    fixture, guest_argv = materialized_guest_command(manifest)
    if fixture is not None:
        command.extend(("-v", f"{fixture}:/native-compiler-w2:ro"))
    command.extend((manifest.image, *guest_argv))
    return command


def run_phase(
    manifest: WorkloadManifest,
    *,
    engine: str,
    plane: str,
    repetition: int,
    artifacts: pathlib.Path,
    results: pathlib.Path,
    schedule_label: str = "",
) -> RunRecord:
    if engine not in {"carrick", "docker"}:
        raise BudgetError(f"unknown engine: {engine}")
    if plane not in {"untraced", "profiled", "dtrace"}:
        raise BudgetError(f"unknown plane: {plane}")
    if engine == "docker" and plane != "untraced":
        raise BudgetError("Docker is only an untraced oracle phase")
    repo = _repo_root()
    git_sha, dirty = _git_clean(repo)
    if dirty:
        raise BudgetError("dirty Git state invalidates a measured run")
    _assert_no_live_carrick()
    _assert_image_identity(manifest)
    _assert_guest_identities(manifest)
    binary = repo / "target/release/carrick"
    binary_sha = _sha256_path(binary) if engine == "carrick" else "0" * 64
    run_id = f"nativeperf-{manifest.name}-{repetition}-{uuid.uuid4().hex[:8]}"
    artifact = artifacts / run_id
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["CARRICK_RUN_ID"] = run_id
    command = _carrick_command(repo, manifest, run_id) if engine == "carrick" else _docker_command(manifest)
    if plane == "profiled":
        env["CARRICK_DSR_PROFILE"] = "1"
    if plane == "dtrace":
        command = [str(binary), "trace", "--profile", "dsr", "--", *command[1:]]
    artifact.mkdir(parents=True, exist_ok=False)
    manifest_snapshot = artifact / "manifest.json"
    shutil.copyfile(manifest.manifest_path, manifest_snapshot)
    _atomic_write_json(
        artifact / "provenance.json",
        {
            "schema": RESULT_SCHEMA,
            "git_sha": git_sha,
            "git_dirty": False,
            "binary_sha256": binary_sha,
            "image_digest": manifest.image_digest,
            "command": command,
            "engine": engine,
            "plane": plane,
            "manifest_sha256": _sha256_path(manifest_snapshot),
            "schedule_label": schedule_label,
        },
    )
    status, timing, stdout_path, stderr_path = _time_command(command, repo, env, artifact)
    cleanup_ok = True
    if engine == "carrick":
        cleanup = subprocess.run(
            ["sudo", "-n", "scripts/sudo/kill.sh", run_id],
            cwd=repo,
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
        (artifact / "cleanup.txt").write_text(cleanup.stdout + cleanup.stderr, encoding="utf-8")
        cleanup_ok = cleanup.returncode == 0
        if cleanup_ok:
            _assert_run_id_absent(run_id)
        else:
            raise BudgetError(f"scoped cleanup failed for {run_id}")
    stdout_sha = stdout_digest(manifest, stdout_path.read_bytes())
    if status != manifest.expected_exit or stdout_sha != manifest.expected_stdout_sha256:
        raise BudgetError(
            f"workload result mismatch: status={status}, stdout_sha256={stdout_sha}"
        )
    stderr_lines = stderr_path.read_text(encoding="utf-8", errors="replace").splitlines()
    validate_work_product(manifest, stderr_lines)
    profile = None
    if plane == "profiled":
        profile = parse_nativeperf(stderr_lines)
        validate_profile(profile)
    record = RunRecord(
        RESULT_SCHEMA,
        manifest.name,
        plane,
        repetition,
        run_id,
        binary_sha,
        timing.wall_ns,
        timing.user_ns,
        timing.system_ns,
        timing.peak_rss_bytes,
        status,
        1,
        cleanup_ok,
        profile,
        profile_decision_inputs(profile, timing.user_ns + timing.system_ns)
        if profile is not None
        else (),
        (),
        schedule_label,
    )
    _atomic_write_json(artifact / "record.json", _record_json(record))
    _append_jsonl(results, _record_json(record))
    return record


def _docker_image_digest(image: str) -> str:
    return subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def _docker_cp(container: str, guest: str, host: pathlib.Path) -> None:
    host.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["docker", "cp", f"{container}:{guest}", str(host)], check=True)


def _candidate_input_paths(argv: tuple[str, ...], workdir: str) -> tuple[str, ...]:
    excluded_indices: set[int] = set()
    for index, arg in enumerate(argv[:-1]):
        if arg in {"-o", "-trimpath", "-p", "-lang", "-goversion", "-buildid", "-asmhdr"}:
            excluded_indices.add(index + 1)
    paths: set[str] = set()
    for index, arg in enumerate(argv[1:], start=1):
        if index in excluded_indices or arg.startswith("-"):
            continue
        candidate = arg if arg.startswith("/") else str(pathlib.PurePosixPath(workdir) / arg)
        paths.add(str(pathlib.PurePosixPath(candidate)))
    for index, arg in enumerate(argv[:-1]):
        if arg in {"-importcfg", "-embedcfg"}:
            value = argv[index + 1]
            paths.add(value if value.startswith("/") else str(pathlib.PurePosixPath(workdir) / value))
    return tuple(sorted(paths))


def _safe_fixture_name(guest_path: str) -> str:
    return guest_path.lstrip("/")


def _write_manifest(path: pathlib.Path, raw: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def capture_w2(
    repo: pathlib.Path,
    manifest_path: pathlib.Path,
    fixture_dir: pathlib.Path,
    package: str | None = None,
) -> dict[str, object]:
    _assert_no_live_carrick()
    image = "localhost:5005/carrick-go-conformance:1.24"
    capture_root = pathlib.Path(tempfile.mkdtemp(prefix="carrick-w2-capture-", dir=repo / "target"))
    container = f"carrick-w2-capture-{uuid.uuid4().hex[:10]}"
    wrapper = repo / "scripts/perf/native-compiler-toolexec.sh"
    capture_log = capture_root / "toolexec.bin"
    env_log = capture_root / "environment.bin"
    command = [
        "docker",
        "create",
        "--name",
        container,
        "--platform",
        "linux/arm64",
        "-w",
        "/usr/local/go/src/go/types",
        "-v",
        f"{wrapper}:/capture/native-compiler-toolexec.sh:ro",
        "-v",
        f"{capture_root}:/capture/out",
        "-e",
        "CARRICK_TOOLEXEC_LOG=/capture/out/toolexec.bin",
        "-e",
        "GOFLAGS=-work -toolexec=/capture/native-compiler-toolexec.sh",
        image,
        "/bin/sh",
        "-c",
        "env -0 > /capture/out/environment.bin; exec /conformance/go_types.test -test.v -test.run '^TestImplicitsInfo$' -test.short",
    ]
    try:
        subprocess.run(command, cwd=repo, check=True, text=True, capture_output=True)
        result = subprocess.run(
            ["docker", "start", "-a", container], cwd=repo, check=False, capture_output=True
        )
        if result.returncode != 0:
            raise BudgetError(
                f"Docker W1 capture failed with {result.returncode}: "
                + result.stderr.decode("utf-8", "replace")[-2000:]
            )
        records = parse_toolexec_capture(capture_log.read_bytes())
        candidates = [
            argv
            for argv in records
            if argv[0].endswith("/compile") or argv[0].endswith("/cgo")
            if "-V=full" not in argv
            if _candidate_input_paths(argv, "/usr/local/go/src/go/types")
        ]
        if not candidates:
            raise BudgetError("W1 capture produced no linux_arm64/compile or cgo child")
        if package is not None:
            candidates = [
                candidate
                for candidate in candidates
                if "-p" in candidate
                and candidate[candidate.index("-p") + 1] == package
            ]
            if not candidates:
                raise BudgetError(f"W1 capture produced no compiler child for package {package}")
        argv = min(candidates, key=lambda value: (len(_candidate_input_paths(value, "/usr/local/go/src/go/types")), len(value), value))
        shutil.rmtree(fixture_dir, ignore_errors=True)
        fixture_dir.mkdir(parents=True)
        guest_inputs = list(_candidate_input_paths(argv, "/usr/local/go/src/go/types"))
        copied: dict[str, pathlib.Path] = {}
        for guest in guest_inputs:
            host = fixture_dir / _safe_fixture_name(guest)
            try:
                _docker_cp(container, guest, host)
            except subprocess.CalledProcessError as error:
                raise BudgetError(f"captured input disappeared before materialization: {guest}") from error
            copied[guest] = host
        for guest, host in list(copied.items()):
            if guest.endswith("importcfg") or guest.endswith("embedcfg"):
                for line in host.read_text(encoding="utf-8", errors="strict").splitlines():
                    if line.startswith("packagefile ") and "=" in line:
                        dependency = line.split("=", 1)[1]
                        if dependency.startswith("/") and dependency not in copied:
                            dep_host = fixture_dir / _safe_fixture_name(dependency)
                            _docker_cp(container, dependency, dep_host)
                            copied[dependency] = dep_host
        executable_copy = capture_root / "tool"
        _docker_cp(container, argv[0], executable_copy)
        env_values = [item.decode("utf-8") for item in env_log.read_bytes().split(b"\0") if item]
        volatile = {"HOSTNAME", "PWD", "SHLVL", "_"}
        captured_env = sorted(
            tuple(item.split("=", 1))
            for item in env_values
            if "=" in item and item.split("=", 1)[0] not in volatile
        )
        capture_only_keys = {"CARRICK_TOOLEXEC_LOG", "GOFLAGS"}
        env = [item for item in captured_env if item[0] not in capture_only_keys]
        capture_env = [item for item in captured_env if item[0] in capture_only_keys]
        stdout_sha = hashlib.sha256(b"").hexdigest()
        files = [
            {
                "guest_path": guest,
                "fixture_path": os.path.relpath(host, manifest_path.parent),
                "sha256": _sha256_path(host),
            }
            for guest, host in sorted(copied.items())
        ]
        raw: dict[str, object] = {
            "schema": WORKLOAD_SCHEMA,
            "name": "w2-smallest-captured-compile" if package is None else f"w2-{package.replace('/', '-')}",
            "image": image,
            "image_digest": _docker_image_digest(image),
            "workdir": "/usr/local/go/src/go/types",
            "argv": list(argv),
            "env": [list(item) for item in env],
            "files": files,
            "executable_sha256": _sha256_path(executable_copy),
            "expected_exit": 0,
            "expected_stdout_sha256": stdout_sha,
            "max_traps": 1_000_000,
            "native_page_profile": "native16k",
            "capture": {
                "source": "docker-toolexec",
                "captured_argv_index": records.index(argv),
                "candidate_count": len(candidates),
                "w1_stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "w1_stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                "capture_environment": [list(item) for item in capture_env],
            },
        }
        _write_manifest(manifest_path, raw)
        loaded = load_manifest(manifest_path)
        replay_digests = []
        replay_output_digests = []
        for repetition in (1, 2):
            replay, output_digest = _replay_w2_docker(loaded, fixture_dir)
            if replay.returncode != loaded.expected_exit:
                raise BudgetError(f"Docker W2 replay {repetition} exited {replay.returncode}")
            digest = stdout_digest(loaded, replay.stdout)
            if digest != loaded.expected_stdout_sha256:
                raise BudgetError(f"Docker W2 replay {repetition} stdout digest mismatch")
            replay_digests.append(digest)
            replay_output_digests.append(output_digest)
            (capture_root / f"replay-{repetition}.stdout").write_bytes(replay.stdout)
            (capture_root / f"replay-{repetition}.stderr").write_bytes(replay.stderr)
        raw["capture"] = {
            **dict(raw["capture"]),
            "docker_replay_stdout_sha256": replay_digests,
            "docker_replay_output_sha256": replay_output_digests,
            "expected_output_guest_path": next(
                (argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg == "-o"),
                None,
            ),
            "expected_output_sha256": replay_output_digests[0],
        }
        if len(set(replay_output_digests)) != 1:
            raise BudgetError("Docker W2 replay work-product digests do not match")
        _write_manifest(manifest_path, raw)
        return raw
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=False, capture_output=True)


def _replay_w2_docker(
    manifest: WorkloadManifest, fixture_dir: pathlib.Path
) -> tuple[subprocess.CompletedProcess[bytes], str]:
    copies = []
    for item in manifest.files:
        if item.fixture_path is None:
            continue
        source = pathlib.PurePosixPath("/fixture") / pathlib.PurePosixPath(item.guest_path).relative_to("/")
        destination = pathlib.PurePosixPath(item.guest_path)
        copies.append(f"mkdir -p {sh_quote(str(destination.parent))}; cp {sh_quote(str(source))} {sh_quote(str(destination))}")
    output_dirs = []
    output_path: pathlib.PurePosixPath | None = None
    for index, arg in enumerate(manifest.argv[:-1]):
        if arg == "-o":
            output_path = pathlib.PurePosixPath(manifest.argv[index + 1])
            output_dirs.append(f"mkdir -p {sh_quote(str(output_path.parent))}")
    if output_path is None:
        raise BudgetError("captured W2 command has no -o work product")
    script = "; ".join([*copies, *output_dirs, 'exec "$@"'])
    with tempfile.TemporaryDirectory(prefix="carrick-w2-output-") as output_temp:
        command = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            "-w",
            manifest.workdir,
            "-v",
            f"{fixture_dir}:/fixture:ro",
            "-v",
            f"{output_temp}:{output_path.parent}",
        ]
        for key, value in manifest.env:
            command.extend(("-e", f"{key}={value}"))
        command.extend((manifest.image, "/bin/sh", "-c", script, "replay", *manifest.argv))
        result = subprocess.run(command, check=False, capture_output=True)
        output_host = pathlib.Path(output_temp) / output_path.name
        if result.returncode == 0 and not output_host.is_file():
            raise BudgetError("Docker W2 replay produced no work product")
        output_digest = _sha256_path(output_host) if output_host.is_file() else ""
        return result, output_digest


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _validate_command(paths: list[str]) -> int:
    _assert_no_live_carrick()
    for path in paths:
        manifest = load_manifest(path)
        _assert_image_identity(manifest)
        _assert_guest_identities(manifest)
        print(f"valid {manifest.name}: {path}")
    return 0


def _analyze_command(path: pathlib.Path) -> int:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = json.loads(line, object_pairs_hook=_pairs_no_duplicates)
        records.append(RunRecord(**raw))
    print(json.dumps(dataclasses.asdict(analyze(records)), sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifests", nargs="+")
    capture_parser = subparsers.add_parser("capture-w2")
    capture_parser.add_argument(
        "--manifest", default="scripts/perf/manifests/native-compiler-w2-v1.json"
    )
    capture_parser.add_argument(
        "--fixture-dir", default="scripts/perf/fixtures/native-compiler-w2-v1"
    )
    capture_parser.add_argument("--package")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("manifest")
    run_parser.add_argument("--engine", choices=("carrick", "docker"), required=True)
    run_parser.add_argument("--plane", choices=("untraced", "profiled", "dtrace"))
    run_mode = run_parser.add_mutually_exclusive_group(required=True)
    run_mode.add_argument("--repetition", type=int)
    run_mode.add_argument(
        "--schedule",
        help="complete ABBA schedule: 'abba-5' or the exact comma-separated labels",
    )
    run_parser.add_argument("--artifacts", type=pathlib.Path, required=True)
    run_parser.add_argument("--results", type=pathlib.Path, required=True)
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("results", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return _validate_command(args.manifests)
        if args.command == "capture-w2":
            repo = _repo_root()
            raw = capture_w2(
                repo,
                (repo / args.manifest).resolve(),
                (repo / args.fixture_dir).resolve(),
                package=args.package,
            )
            print(json.dumps(raw["capture"], sort_keys=True))
            return 0
        if args.command == "run":
            manifest = load_manifest(args.manifest)
            if args.schedule is not None:
                if args.engine != "carrick" or args.plane is not None:
                    raise BudgetError(
                        "ABBA schedule requires --engine carrick and derives each plane"
                    )
                records = []
                for label, plane, repetition in resolve_run_schedule(args.schedule):
                    records.append(
                        run_phase(
                            manifest,
                            engine="carrick",
                            plane=plane,
                            repetition=repetition,
                            artifacts=args.artifacts,
                            results=args.results,
                            schedule_label=label,
                        )
                    )
                print(json.dumps([_record_json(record) for record in records], sort_keys=True))
            else:
                if args.plane is None or args.repetition is None:
                    raise BudgetError("single run requires --plane and --repetition")
                record = run_phase(
                    manifest,
                    engine=args.engine,
                    plane=args.plane,
                    repetition=args.repetition,
                    artifacts=args.artifacts,
                    results=args.results,
                )
                print(json.dumps(_record_json(record), sort_keys=True))
            return 0
        if args.command == "analyze":
            return _analyze_command(args.results)
        raise AssertionError(args.command)
    except (BudgetError, OSError, subprocess.SubprocessError) as error:
        print(f"native_compiler_budget: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
