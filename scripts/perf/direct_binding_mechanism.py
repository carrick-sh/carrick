#!/usr/bin/env python3
"""Capture and compare receipt-bound direct-binding mechanism evidence."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence

import native_compiler_budget
import native_go_build


SCHEMA = "carrick.direct-binding-mechanism.v1"
RECEIPT_SCHEMA = "carrick.direct-binding-capture-receipt.v1"
PAIR_SCHEMA = "carrick.direct-binding-capture-pair.v1"
SUMMARY_SCHEMA = "carrick.dsr-profile.v1"
PROFILE = "dsr-indirect"
BINDING_EVENT_KINDS = frozenset(range(7, 13))
CLEAR_REASONS = frozenset(range(1, 5))
VALIDATION_REASONS = frozenset(range(1, 7))
VARIANT_KEYS = frozenset(
    {
        "CARRICK_DSR_ARTIFACT_SPIKE",
        "CARRICK_DSR_SHARED_TRANSLATION",
        "CARRICK_DSR_DIRECT_BINDINGS",
    }
)


class EvidenceError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ArtifactBinding:
    path: pathlib.Path
    size: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class CaptureReceipt:
    path: pathlib.Path
    payload: dict[str, object]
    sha256: str

    @property
    def valid_for_followup(self) -> bool:
        try:
            validate_receipt(self, require_variant=None)
            parse_trace(self)
        except EvidenceError:
            return False
        return True


@dataclasses.dataclass(frozen=True)
class CaptureConfig:
    repo: pathlib.Path
    output_dir: pathlib.Path
    variant: str
    run_id: str
    timeout_seconds: int = native_go_build.DEFAULT_TIMEOUT_SECONDS
    binary: pathlib.Path | None = None
    image: str = native_go_build.DEFAULT_IMAGE

    @property
    def resolved_repo(self) -> pathlib.Path:
        return self.repo.resolve()

    @property
    def resolved_binary(self) -> pathlib.Path:
        binary = (
            self.repo / "target/release/carrick"
            if self.binary is None
            else self.binary
        )
        if not binary.is_absolute():
            binary = self.repo / binary
        return binary.resolve()


@dataclasses.dataclass(frozen=True)
class CaptureEnvironment:
    subprocess: dict[str, str]
    controlled: dict[str, str | None]


@dataclasses.dataclass(frozen=True)
class CleanupEvidence:
    status: int
    stdout: str
    stderr: str
    descendants: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class MechanismRun:
    receipt: CaptureReceipt
    raw_path: pathlib.Path
    metrics: dict[tuple[tuple[str, str], ...], int]
    binding_events: dict[int, int]
    gateway_kinds: dict[int, int]
    gateway_total: int
    direct_total: int
    indirect_total: int
    translation_attempts: int
    binding_cells: dict[tuple[int, int], int]
    publication_cells: dict[tuple[int, int], int]
    clear_cells: dict[tuple[int, int, int], int]
    validation_reasons: dict[int, int]
    unit_loads: dict[tuple[int, int, int, int], int]
    native_gateway: int
    native_exits: dict[int, int]


@dataclasses.dataclass(frozen=True)
class ManifestRecord:
    unit: str
    source: int
    target: int
    ordinal: int
    cell: int | None


def select_exit_record(
    records: Sequence[ManifestRecord],
    source: int,
    target: int,
    cell: int | None,
    ordinal: int | None,
) -> ManifestRecord:
    candidates = [
        record
        for record in records
        if record.source == source and record.target == target
    ]
    if cell is not None and ordinal is not None:
        exact = [
            record
            for record in candidates
            if record.cell == cell and record.ordinal == ordinal
        ]
        if len(exact) == 1:
            return exact[0]
    if not candidates:
        raise EvidenceError("missing eligible exit-time manifest record")
    if len(candidates) != 1:
        raise EvidenceError("ambiguous eligible exit-time manifest record")
    candidate = candidates[0]
    if candidate.cell != cell or (
        cell is not None and candidate.ordinal != ordinal
    ):
        raise EvidenceError("miss metadata does not match eligible manifest record")
    return candidate


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return native_go_build.sha256_file(path)


def sha256_json(payload: object) -> str:
    return sha256_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )


def bind_artifact(path: pathlib.Path) -> dict[str, object]:
    return {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def write_json_atomic(path: pathlib.Path, payload: dict[str, object]) -> None:
    native_go_build.write_json_atomic(path, payload)


def write_json_atomic_exclusive(
    path: pathlib.Path,
    payload: dict[str, object],
) -> None:
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
    try:
        os.link(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _strict_json(path: pathlib.Path) -> dict[str, object]:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate JSON field {key!r} in {path}")
            result[key] = value
        return result

    try:
        payload = json.loads(path.read_text(), object_pairs_hook=reject_duplicates)
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot parse receipt {path}: {error}") from error
    if not isinstance(payload, dict):
        raise EvidenceError("receipt must be a JSON object")
    return payload


def parse_receipt(path: pathlib.Path) -> CaptureReceipt:
    resolved = path.resolve()
    payload = _strict_json(resolved)
    if payload.get("schema") != RECEIPT_SCHEMA:
        raise EvidenceError("unknown or missing capture receipt schema")
    return CaptureReceipt(resolved, payload, sha256_file(resolved))


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must be an object")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise EvidenceError(f"{name} must be an array")
    return value


def _receipt_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{name} is not an integer")
    return value


def _artifact(receipt: CaptureReceipt, name: str) -> ArtifactBinding:
    artifacts = _mapping(receipt.payload.get("artifacts"), "artifacts")
    expected_names = {
        "raw_trace",
        "summary_jsonl",
        "command_stdout",
        "command_stderr",
    }
    if set(artifacts) != expected_names:
        raise EvidenceError(
            "receipt artifact set must be exactly "
            + ", ".join(sorted(expected_names))
        )
    capture_directory = receipt.path.parent.resolve()
    resolved_paths = []
    for artifact_name in sorted(expected_names):
        artifact_row = _mapping(
            artifacts.get(artifact_name),
            f"artifact {artifact_name}",
        )
        try:
            artifact_path = pathlib.Path(str(artifact_row["path"])).resolve()
        except KeyError as error:
            raise EvidenceError(
                f"artifact {artifact_name} binding is incomplete"
            ) from error
        if artifact_path.parent != capture_directory:
            raise EvidenceError(
                f"artifact {artifact_name} is outside the receipt capture directory"
            )
        resolved_paths.append(artifact_path)
    if len(set(resolved_paths)) != len(resolved_paths):
        raise EvidenceError("receipt artifacts must have distinct paths")
    row = _mapping(artifacts.get(name), f"artifact {name}")
    try:
        path = pathlib.Path(str(row["path"])).resolve()
        size = _receipt_int(row["size"], f"artifact {name}.size")
        digest = str(row["sha256"])
    except KeyError as error:
        raise EvidenceError(f"artifact {name} binding is incomplete") from error
    if not path.is_file():
        raise EvidenceError(f"bound artifact {name} is missing: {path}")
    if path.stat().st_size != size or sha256_file(path) != digest:
        raise EvidenceError(f"artifact {name} hash mismatch")
    return ArtifactBinding(path, size, digest)


def _snapshot(receipt: CaptureReceipt, when: str) -> dict[str, object]:
    provenance = _mapping(receipt.payload.get("provenance"), "provenance")
    snapshot = _mapping(provenance.get(when), f"provenance.{when}")
    required = {
        "git_commit",
        "git_status",
        "repository",
        "binary_path",
        "binary_sha256",
        "host",
        "image_ref",
        "image",
        "controlled_environment",
        "foreign_processes",
        "docker_oracles",
    }
    missing = required - set(snapshot)
    if missing:
        raise EvidenceError(
            f"provenance.{when} missing field(s): {', '.join(sorted(missing))}"
        )
    return snapshot


def _summary_completion(receipt: CaptureReceipt) -> dict[str, object]:
    summary = _mapping(receipt.payload.get("summary"), "summary")
    completion = _mapping(summary.get("completion"), "summary completion")
    required = {
        "complete",
        "bounded",
        "target_exit_reason",
        "high_cardinality_overflow",
        "incomplete_pairs",
        "cardinality",
        "drops",
    }
    missing = required - set(completion)
    if missing:
        raise EvidenceError(
            "summary completion missing field(s): " + ", ".join(sorted(missing))
        )
    drops = _mapping(completion["drops"], "summary completion drops")
    for field in (
        "principal_drops",
        "aggregation_drops",
        "dynamic_drops",
        "other_drops",
        "interrupted",
    ):
        if field not in drops:
            raise EvidenceError(f"summary completion drops missing {field}")
    return completion


def _exact_build_ok(receipt: CaptureReceipt) -> bool:
    stdout = _artifact(receipt, "command_stdout").path.read_text(
        errors="replace"
    )
    return stdout.splitlines().count("BUILD_OK") == 1


def validate_receipt(
    receipt: CaptureReceipt, require_variant: str | None
) -> None:
    if sha256_file(receipt.path) != receipt.sha256:
        raise EvidenceError("receipt hash mismatch after parse")
    for name in (
        "raw_trace",
        "summary_jsonl",
        "command_stdout",
        "command_stderr",
    ):
        _artifact(receipt, name)
    if require_variant is not None and receipt.payload.get("variant") != require_variant:
        raise EvidenceError(f"receipt is not the fixed {require_variant} variant")
    variant = receipt.payload.get("variant")
    if variant not in {"precursor", "candidate"}:
        raise EvidenceError("receipt variant is not fixed precursor or candidate")
    pre = _snapshot(receipt, "pre")
    post = _snapshot(receipt, "post")
    if pre != post:
        raise EvidenceError("capture provenance drift between pre and post snapshots")
    if _list(pre["git_status"], "git status"):
        raise EvidenceError("capture git provenance is dirty")
    if _list(pre["foreign_processes"], "foreign process census"):
        raise EvidenceError("capture has foreign Carrick or benchmark processes")
    if _list(pre["docker_oracles"], "Docker oracle census"):
        raise EvidenceError("capture overlaps a running Docker oracle")
    if receipt.payload.get("environment_sha256") != sha256_json(
        pre["controlled_environment"]
    ):
        raise EvidenceError("controlled environment hash mismatch")
    if receipt.payload.get("image_sha256") != sha256_json(pre["image"]):
        raise EvidenceError("resolved image hash mismatch")
    controlled = _mapping(
        pre["controlled_environment"],
        "controlled environment",
    )
    if controlled != _expected_controlled_environment(str(variant)):
        raise EvidenceError(f"receipt is not the fixed {variant} environment")
    inputs = _mapping(receipt.payload.get("inputs"), "inputs")
    if set(inputs) != {
        "repository",
        "binary",
        "image",
        "profile",
        "summary_schema",
    }:
        raise EvidenceError("receipt inputs are incomplete or contain unknown fields")
    repository_input = pathlib.Path(str(inputs["repository"]))
    binary_input = pathlib.Path(str(inputs["binary"]))
    repository = repository_input.resolve()
    binary = binary_input.resolve()
    image = str(inputs["image"])
    if pathlib.Path(str(pre["repository"])).resolve() != repository:
        raise EvidenceError("repository input differs from frozen provenance")
    if pathlib.Path(str(pre["binary_path"])).resolve() != binary:
        raise EvidenceError("binary input differs from frozen provenance")
    if str(pre["image_ref"]) != image:
        raise EvidenceError("image input differs from frozen provenance")
    if inputs["profile"] != PROFILE or inputs["summary_schema"] != SUMMARY_SCHEMA:
        raise EvidenceError("profile or summary schema input is not fixed")
    if not binary.is_file() or sha256_file(binary) != pre["binary_sha256"]:
        raise EvidenceError("binary input hash differs from frozen provenance")
    run_id = receipt.payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise EvidenceError("receipt run ID is missing")
    run_command = native_go_build.build_carrick_command(
        repository_input,
        run_id,
        binary=binary_input,
        image=image,
    )
    artifact_rows = _mapping(receipt.payload.get("artifacts"), "artifacts")
    expected_argv = [
        str(binary_input),
        "trace",
        "--profile",
        PROFILE,
        "--trace-out",
        str(_mapping(artifact_rows["raw_trace"], "raw artifact")["path"]),
        "--summary-jsonl",
        str(_mapping(artifact_rows["summary_jsonl"], "summary artifact")["path"]),
        "--",
        *run_command[1:],
    ]
    if receipt.payload.get("argv") != expected_argv:
        raise EvidenceError("receipt run ID does not match the exact argv")
    if receipt.payload.get("workload") != native_go_build.guest_script():
        raise EvidenceError("receipt does not bind the fixed workload")
    command = _mapping(receipt.payload.get("command"), "command")
    command_status = _receipt_int(command.get("status"), "command.status")
    if command_status != 0:
        raise EvidenceError(f"command status is nonzero: {command.get('status')}")
    if not _exact_build_ok(receipt) or command.get("build_ok") is not True:
        raise EvidenceError("stdout does not contain exactly one exact BUILD_OK line")
    cleanup = _mapping(receipt.payload.get("cleanup"), "cleanup")
    cleanup_status = _receipt_int(cleanup.get("status"), "cleanup.status")
    if cleanup_status != 0:
        raise EvidenceError(
            "cleanup status is nonzero: "
            f"{cleanup.get('status')} stdout={cleanup.get('stdout')!r} "
            f"stderr={cleanup.get('stderr')!r}"
        )
    if _list(cleanup.get("descendants"), "cleanup descendants"):
        raise EvidenceError("cleanup left stamped descendants")
    completion = _summary_completion(receipt)
    if completion["bounded"] is True:
        raise EvidenceError("bounded capture is truncated evidence")
    if completion["complete"] is not True:
        raise EvidenceError("capture summary is interrupted or incomplete")
    if _receipt_int(
        completion["target_exit_reason"],
        "summary completion.target_exit_reason",
    ) != 1:
        raise EvidenceError("capture target was interrupted")
    if completion["high_cardinality_overflow"] is True:
        raise EvidenceError("capture summary reports high-cardinality overflow")
    if _receipt_int(
        completion["incomplete_pairs"],
        "summary completion.incomplete_pairs",
    ) != 0:
        raise EvidenceError("capture summary reports incomplete probe pairs")
    drops = _mapping(completion["drops"], "summary completion drops")
    if bool(drops["interrupted"]):
        raise EvidenceError("capture summary reports interruption")
    if any(
        _receipt_int(drops[field], f"summary completion drops.{field}") != 0
        for field in (
            "principal_drops",
            "aggregation_drops",
            "dynamic_drops",
            "other_drops",
        )
    ):
        raise EvidenceError("capture summary reports DTrace drops")
    summary = _mapping(receipt.payload.get("summary"), "summary")
    if summary.get("git_sha") != pre["git_commit"]:
        raise EvidenceError("summary git SHA differs from frozen provenance")
    if summary.get("git_dirty") is not False:
        raise EvidenceError("summary reports dirty or unknown git provenance")
    if summary.get("binary_sha256") != pre["binary_sha256"]:
        raise EvidenceError("summary binary SHA differs from frozen provenance")
    if summary.get("host") != pre["host"]:
        raise EvidenceError("summary host differs from frozen provenance")
    if summary.get("command") != run_command[1:]:
        raise EvidenceError("summary command differs from exact run command")


def _parse_protocol_fields(line: str) -> tuple[str, dict[str, str]]:
    parts = line.strip().split("|")
    if len(parts) < 2 or parts[0] != "DSRPROF1":
        raise EvidenceError("malformed DSRPROF1 row")
    fields = {}
    for raw in parts[2:]:
        if "=" not in raw:
            raise EvidenceError(f"malformed DSRPROF1 field: {raw}")
        key, value = raw.split("=", 1)
        if not key or key in fields:
            raise EvidenceError(f"duplicate DSRPROF1 field: {key}")
        fields[key] = value
    return parts[1], fields


def _integer(value: str, name: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise EvidenceError(f"invalid integer {name}={value!r}") from error
    if parsed < 0:
        raise EvidenceError(f"negative integer {name}")
    return parsed


def _raw_metric_key(
    record_type: str, fields: Mapping[str, str]
) -> tuple[tuple[str, str], ...]:
    numeric_scope = {"pid", "tid", "source_pc", "target_pc"}
    return tuple(
        sorted(
            [("record_type", record_type)]
            + [
                (
                    key,
                    str(_integer(value, key)) if key in numeric_scope else value,
                )
                for key, value in fields.items()
                if key not in {"value", "value_ns"}
            ]
        )
    )


def _summary_scope_key(row: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    scope = _mapping(row.get("scope"), "summary scope")
    return tuple(
        sorted(
            [("record_type", "count")]
            + [(key, str(value)) for key, value in scope.items()]
        )
    )


def _summary_aggregate_key(
    raw_key: tuple[tuple[str, str], ...]
) -> tuple[tuple[str, str], ...]:
    supported = {"record_type", "phase", "pid", "tid", "kind", "source_pc", "target_pc"}
    return tuple((key, value) for key, value in raw_key if key in supported)


def synthetic_summary_rows(
    raw_rows: Sequence[str],
    *,
    run_id: str,
    git_sha: str,
    binary_sha256: str,
    host: str,
    bounded: bool,
) -> list[dict[str, object]]:
    completion = {
        "complete": not bounded,
        "bounded": bounded,
        "target_exit_reason": 1,
        "high_cardinality_overflow": False,
        "incomplete_pairs": 0,
        "cardinality": {"indirect_sources": 0, "indirect_pairs": 0},
        "drops": {
            "principal_drops": 0,
            "aggregation_drops": 0,
            "dynamic_drops": 0,
            "other_drops": 0,
            "interrupted": False,
        },
    }
    aggregates: dict[tuple[tuple[str, str], ...], int] = defaultdict(int)
    for line in raw_rows:
        record_type, fields = _parse_protocol_fields(line)
        if record_type == "complete":
            continue
        key = _summary_aggregate_key(_raw_metric_key(record_type, fields))
        aggregates[key] += _integer(fields["value"], "value")
    rows = []
    for key, value in sorted(aggregates.items()):
        scope = {
            field: (_integer(raw, field) if field in {"pid", "tid", "source_pc", "target_pc"} else raw)
            for field, raw in key
            if field != "record_type"
        }
        rows.append(
            {
                "schema": "carrick.dsr-profile.v1",
                "profile": PROFILE,
                "run_id": run_id,
                "git_sha": git_sha,
                "git_dirty": False,
                "binary_sha256": binary_sha256,
                "command": ["fixture"],
                "host": host,
                "scope": scope,
                "metric": {"type": "exact", "count": value},
                "sampling_interval": None,
                "completion": completion,
            }
        )
    return rows


def _parse_summary(
    receipt: CaptureReceipt,
) -> tuple[dict[tuple[tuple[str, str], ...], int], dict[str, object]]:
    path = _artifact(receipt, "summary_jsonl").path
    rows = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvidenceError(f"invalid summary JSONL line {number}") from error
        if not isinstance(row, dict):
            raise EvidenceError("summary JSONL row must be an object")
        rows.append(row)
    if not rows:
        raise EvidenceError("summary JSONL is empty")
    first = rows[0]
    if first.get("schema") != SUMMARY_SCHEMA:
        raise EvidenceError("summary schema is not the fixed DSR profile schema")
    if first.get("profile") != PROFILE:
        raise EvidenceError("summary profile is not dsr-indirect")
    stable_fields = (
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
    for row in rows:
        if any(row.get(field) != first.get(field) for field in stable_fields):
            raise EvidenceError("summary JSONL provenance or completion drifts between rows")
    summary_receipt = _mapping(receipt.payload.get("summary"), "summary")
    if first.get("run_id") != receipt.payload.get("run_id"):
        raise EvidenceError("summary run ID differs from receipt")
    for summary_field, row_field in (
        ("run_id", "run_id"),
        ("git_sha", "git_sha"),
        ("git_dirty", "git_dirty"),
        ("binary_sha256", "binary_sha256"),
        ("host", "host"),
    ):
        if summary_receipt.get(summary_field) != first.get(row_field):
            raise EvidenceError(f"summary {summary_field} differs from receipt copy")
    if summary_receipt.get("completion") != first.get("completion"):
        raise EvidenceError("summary completion differs from receipt copy")
    if summary_receipt.get("command") != first.get("command"):
        raise EvidenceError("summary command differs from receipt copy")
    metrics: dict[tuple[tuple[str, str], ...], int] = {}
    for row in rows:
        metric = _mapping(row.get("metric"), "summary metric")
        if metric.get("type") != "exact" or "count" not in metric:
            continue
        key = _summary_scope_key(row)
        if key in metrics:
            raise EvidenceError("duplicate summary metric scope")
        metrics[key] = _receipt_int(metric["count"], "summary metric.count")
    return metrics, first


def _native_vector(stderr_path: pathlib.Path) -> tuple[int, dict[int, int]]:
    try:
        profile = native_compiler_budget.parse_nativeperf(
            stderr_path.read_text(errors="replace").splitlines()
        )
        native_compiler_budget.validate_profile(profile)
    except Exception as error:
        raise EvidenceError(f"NATIVEPERF profile is incomplete or invalid: {error}") from error
    if profile.supervisor is None:
        raise EvidenceError("NATIVEPERF profile has no supervisor record")
    process_by_pid: dict[int, int] = {}
    for thread in profile.threads:
        process_by_pid[thread.pid] = max(
            process_by_pid.get(thread.pid, 0),
            thread.value("process", "process_cpu_ns"),
        )
    if sum(process_by_pid.values()) != profile.supervisor.children_cpu_ns:
        raise EvidenceError("NATIVEPERF supervisor children CPU does not reconcile")
    exits = {
        1: sum(thread.value("exits", "exit_syscall") for thread in profile.threads),
        2: sum(
            thread.value("exits", "exit_resolve_direct") for thread in profile.threads
        ),
        3: sum(
            thread.value("exits", "exit_resolve_indirect") for thread in profile.threads
        ),
        4: sum(thread.value("exits", "exit_fault") for thread in profile.threads),
        5: sum(thread.value("exits", "exit_kick") for thread in profile.threads),
        6: sum(thread.value("exits", "exit_sensitive") for thread in profile.threads),
        7: sum(
            thread.value("exits", "exit_unsupported") for thread in profile.threads
        ),
    }
    gateway = sum(thread.gateway_entries for thread in profile.threads)
    return gateway, exits


def _record_specialized_metric(
    fields: Mapping[str, str],
    value: int,
    *,
    binding_events: dict[int, int],
    gateway_kinds: dict[int, int],
    binding_cells: dict[tuple[int, int], int],
    publication_cells: dict[tuple[int, int], int],
    clear_cells: dict[tuple[int, int, int], int],
    validation_reasons: dict[int, int],
    unit_loads: dict[tuple[int, int, int, int], int],
) -> None:
    phase = fields.get("phase")
    pid = _integer(fields.get("pid", "0"), "pid")
    if phase == "binding-event":
        kind = _integer(fields.get("kind", ""), "binding event kind")
        if kind not in BINDING_EVENT_KINDS:
            raise EvidenceError(f"unknown binding event kind {kind}")
        binding_events[kind] = binding_events.get(kind, 0) + value
    elif phase == "gateway-kind":
        kind = _integer(fields.get("kind", ""), "gateway kind")
        if kind not in range(1, 8):
            raise EvidenceError(f"unknown gateway kind {kind}")
        gateway_kinds[kind] = gateway_kinds.get(kind, 0) + value
    elif phase == "binding-cell":
        cell = _integer(fields.get("cell_va", ""), "binding cell")
        if pid == 0 or cell == 0 or cell % 8 != 0:
            raise EvidenceError("binding-cell identity is zero or invalid")
        identity = (pid, cell)
        binding_cells[identity] = binding_cells.get(identity, 0) + value
    elif phase == "binding-publish-cell":
        cell = _integer(fields.get("cell_va", ""), "publication cell")
        if pid == 0 or cell == 0 or cell % 8 != 0:
            raise EvidenceError("publication cell identity is zero or invalid")
        identity = (pid, cell)
        publication_cells[identity] = (
            publication_cells.get(identity, 0) + value
        )
    elif phase == "binding-clear-cell":
        cell = _integer(fields.get("cell_va", ""), "clear cell")
        if pid == 0 or cell == 0 or cell % 8 != 0:
            raise EvidenceError("clear cell identity is zero or invalid")
        reason = _integer(fields.get("kind", ""), "clear reason")
        if reason not in CLEAR_REASONS:
            raise EvidenceError(f"clear reason {reason} is zero or unknown")
        identity = (pid, cell, reason)
        clear_cells[identity] = clear_cells.get(identity, 0) + value
    elif phase == "binding-validation":
        source = _integer(
            fields.get("source_pc", ""),
            "validation source",
        )
        if pid == 0 or source == 0 or source % 4 != 0:
            raise EvidenceError("validation source identity is zero or invalid")
        _integer(fields.get("cell_va", ""), "validation cell")
        reason = _integer(fields.get("kind", ""), "validation reason")
        if reason not in VALIDATION_REASONS:
            raise EvidenceError(
                f"validation reason {reason} is zero or unknown"
            )
        validation_reasons[reason] = (
            validation_reasons.get(reason, 0) + value
        )
    elif phase == "binding-unit":
        unit_id = _integer(fields.get("unit_id", ""), "unit ID")
        record_count = _integer(
            fields.get("record_count", ""),
            "unit record count",
        )
        binding_data_bytes = _integer(
            fields.get("binding_data_bytes", ""),
            "unit binding data bytes",
        )
        if pid == 0 or unit_id == 0:
            raise EvidenceError("binding unit identity is zero or invalid")
        identity = (pid, unit_id, record_count, binding_data_bytes)
        unit_loads[identity] = unit_loads.get(identity, 0) + value


def parse_trace(
    receipt: CaptureReceipt,
    *,
    validate_lifecycle: bool = True,
) -> MechanismRun:
    if validate_lifecycle:
        validate_receipt(receipt, require_variant=None)
    elif sha256_file(receipt.path) != receipt.sha256:
        raise EvidenceError("receipt hash mismatch after parse")
    raw_path = _artifact(receipt, "raw_trace").path
    metrics: dict[tuple[tuple[str, str], ...], int] = {}
    completion = None
    binding_events: dict[int, int] = {}
    gateway_kinds: dict[int, int] = defaultdict(int)
    binding_cells: dict[tuple[int, int], int] = defaultdict(int)
    publication_cells: dict[tuple[int, int], int] = defaultdict(int)
    clear_cells: dict[tuple[int, int, int], int] = defaultdict(int)
    validation_reasons: dict[int, int] = defaultdict(int)
    unit_loads: dict[tuple[int, int, int, int], int] = defaultdict(int)
    for line in raw_path.read_text(errors="replace").splitlines():
        if not line.startswith("DSRPROF1|"):
            continue
        record_type, fields = _parse_protocol_fields(line)
        if record_type == "complete":
            if completion is not None:
                raise EvidenceError("duplicate raw DTrace completion row")
            completion = fields
            continue
        if record_type != "count" or "value" not in fields:
            continue
        key = _raw_metric_key(record_type, fields)
        if key in metrics:
            raise EvidenceError("duplicate raw DTrace metric")
        value = _integer(fields["value"], "value")
        metrics[key] = value
        _record_specialized_metric(
            fields,
            value,
            binding_events=binding_events,
            gateway_kinds=gateway_kinds,
            binding_cells=binding_cells,
            publication_cells=publication_cells,
            clear_cells=clear_cells,
            validation_reasons=validation_reasons,
            unit_loads=unit_loads,
        )
    if completion is None:
        raise EvidenceError("raw DTrace stream has no completion row")
    if completion.get("profile") != "dsr-indirect":
        raise EvidenceError("raw DTrace stream has the wrong profile")
    if bool(_integer(completion.get("bounded", "1"), "bounded")):
        raise EvidenceError("raw DTrace stream is bounded")
    if _integer(completion.get("target_exit_reason", "0"), "target exit reason") != 1:
        raise EvidenceError("raw DTrace target was interrupted")
    if set(binding_events) != BINDING_EVENT_KINDS:
        missing = sorted(BINDING_EVENT_KINDS - set(binding_events))
        raise EvidenceError(f"binding event vector lacks explicit zero kind(s): {missing}")
    for phase, event_kind, specialized_total in (
        ("binding-publish-cell", 8, sum(publication_cells.values())),
        ("binding-clear-cell", 10, sum(clear_cells.values())),
        ("binding-validation", 11, sum(validation_reasons.values())),
        ("binding-unit", 12, sum(unit_loads.values())),
    ):
        if specialized_total != binding_events[event_kind]:
            raise EvidenceError(
                f"{phase} total does not reconcile with kind={event_kind}"
            )
    present_phases = {dict(key).get("phase") for key in metrics}
    for required_phase in (
        "gateway-total",
        "direct-total",
        "indirect-total",
        "translation-attempts",
    ):
        if required_phase not in present_phases:
            raise EvidenceError(
                f"raw trace is missing required {required_phase} metric"
            )
    summary_metrics, _ = _parse_summary(receipt)
    raw_aggregated: dict[tuple[tuple[str, str], ...], int] = defaultdict(int)
    for key, value in metrics.items():
        raw_aggregated[_summary_aggregate_key(key)] += value
    if raw_aggregated != summary_metrics:
        raise EvidenceError("raw/summary overlapping metrics do not reconcile")

    def phase_total(phase: str) -> int:
        values = [
            value
            for key, value in metrics.items()
            if dict(key).get("phase") == phase
        ]
        if not values:
            raise EvidenceError(f"raw trace is missing required {phase} metric")
        return sum(values)

    gateway_total = phase_total("gateway-total")
    direct_total = phase_total("direct-total")
    indirect_total = phase_total("indirect-total")
    translation_attempts = phase_total("translation-attempts")
    native_gateway, native_exits = _native_vector(
        _artifact(receipt, "command_stderr").path
    )
    if (
        gateway_total != native_gateway
        or direct_total != native_exits[2]
        or indirect_total != native_exits[3]
        or dict(gateway_kinds) != native_exits
    ):
        raise EvidenceError(
            "raw DTrace and NATIVEPERF gateway exit vectors do not reconcile"
        )
    clear_by_cell: dict[tuple[int, int], int] = defaultdict(int)
    for (pid, cell, _reason), value in clear_cells.items():
        clear_by_cell[(pid, cell)] += value
    for identity, publishes in publication_cells.items():
        if publishes > 1 + clear_by_cell.get(identity, 0):
            raise EvidenceError(
                f"publication invariant failed for pid/cell {identity}"
            )
    if sum(publication_cells.values()) > len(binding_cells) + sum(clear_cells.values()):
        raise EvidenceError("global publication invariant failed")
    return MechanismRun(
        receipt=receipt,
        raw_path=raw_path,
        metrics=metrics,
        binding_events=dict(sorted(binding_events.items())),
        gateway_kinds=dict(sorted(gateway_kinds.items())),
        gateway_total=gateway_total,
        direct_total=direct_total,
        indirect_total=indirect_total,
        translation_attempts=translation_attempts,
        binding_cells=dict(binding_cells),
        publication_cells=dict(publication_cells),
        clear_cells=dict(clear_cells),
        validation_reasons=dict(validation_reasons),
        unit_loads=dict(unit_loads),
        native_gateway=native_gateway,
        native_exits=native_exits,
    )


def _common_environment(receipt: CaptureReceipt) -> dict[str, object]:
    environment = dict(_mapping(_snapshot(receipt, "pre")["controlled_environment"], "controlled environment"))
    for key in VARIANT_KEYS:
        environment.pop(key, None)
    return environment


def _run_payload(run: MechanismRun) -> dict[str, object]:
    return {
        "run_id": run.receipt.payload["run_id"],
        "binding_events": {
            str(kind): run.binding_events[kind] for kind in sorted(run.binding_events)
        },
        "gateway_kinds": {
            str(kind): run.gateway_kinds[kind] for kind in sorted(run.gateway_kinds)
        },
        "gateway_total": run.gateway_total,
        "direct_total": run.direct_total,
        "indirect_total": run.indirect_total,
        "translation_attempts": run.translation_attempts,
        "binding_cells": [
            {"pid": pid, "cell": cell, "value": value}
            for (pid, cell), value in sorted(run.binding_cells.items())
        ],
        "publication_cells": [
            {"pid": pid, "cell": cell, "value": value}
            for (pid, cell), value in sorted(run.publication_cells.items())
        ],
        "clear_cells": [
            {"pid": pid, "cell": cell, "reason": reason, "value": value}
            for (pid, cell, reason), value in sorted(run.clear_cells.items())
        ],
        "validation_reasons": {
            str(reason): value
            for reason, value in sorted(run.validation_reasons.items())
        },
        "unit_loads": [
            {
                "pid": pid,
                "unit_id": unit_id,
                "record_count": record_count,
                "binding_data_bytes": binding_data_bytes,
                "value": value,
            }
            for (
                pid,
                unit_id,
                record_count,
                binding_data_bytes,
            ), value in sorted(run.unit_loads.items())
        ],
    }


def _summary_metrics_payload(
    metrics: Mapping[tuple[tuple[str, str], ...], int],
) -> list[dict[str, object]]:
    numeric_scope = {"pid", "tid", "source_pc", "target_pc"}
    rows = []
    for key, count in sorted(metrics.items()):
        scope: dict[str, object] = {}
        for field, value in key:
            if field == "record_type":
                continue
            scope[field] = (
                _integer(value, field) if field in numeric_scope else value
            )
        rows.append({"scope": scope, "count": count})
    return rows


def _partial_run_payload(receipt: CaptureReceipt) -> dict[str, object]:
    errors: dict[str, list[str]] = {
        "raw_aggregates": [],
        "specialized": [],
        "summary": [],
        "nativeperf": [],
        "reconciliation": [],
    }
    metrics: dict[tuple[tuple[str, str], ...], int] = {}
    completion = None
    binding_events: dict[int, int] = {}
    gateway_kinds: dict[int, int] = {}
    binding_cells: dict[tuple[int, int], int] = {}
    publication_cells: dict[tuple[int, int], int] = {}
    clear_cells: dict[tuple[int, int, int], int] = {}
    validation_reasons: dict[int, int] = {}
    unit_loads: dict[tuple[int, int, int, int], int] = {}
    try:
        raw_path = _artifact(receipt, "raw_trace").path
        raw_lines = raw_path.read_text(errors="replace").splitlines()
    except (EvidenceError, OSError) as error:
        errors["raw_aggregates"].append(str(error))
        raw_lines = []
    for line in raw_lines:
        if not line.startswith("DSRPROF1|"):
            continue
        try:
            record_type, fields = _parse_protocol_fields(line)
        except EvidenceError as error:
            errors["raw_aggregates"].append(str(error))
            continue
        if record_type == "complete":
            if completion is not None:
                errors["raw_aggregates"].append(
                    "duplicate raw DTrace completion row"
                )
            else:
                completion = fields
            continue
        if record_type != "count" or "value" not in fields:
            continue
        try:
            value = _integer(fields["value"], "value")
        except EvidenceError as error:
            errors["raw_aggregates"].append(str(error))
            continue
        try:
            key = _raw_metric_key(record_type, fields)
            if key in metrics:
                raise EvidenceError("duplicate raw DTrace metric")
            metrics[key] = value
        except EvidenceError as error:
            errors["raw_aggregates"].append(str(error))
        try:
            _record_specialized_metric(
                fields,
                value,
                binding_events=binding_events,
                gateway_kinds=gateway_kinds,
                binding_cells=binding_cells,
                publication_cells=publication_cells,
                clear_cells=clear_cells,
                validation_reasons=validation_reasons,
                unit_loads=unit_loads,
            )
        except EvidenceError as error:
            errors["specialized"].append(str(error))
    if completion is None:
        errors["raw_aggregates"].append(
            "raw DTrace stream has no completion row"
        )
    else:
        if completion.get("profile") != PROFILE:
            errors["raw_aggregates"].append(
                "raw DTrace stream has the wrong profile"
            )
        try:
            if bool(_integer(completion.get("bounded", "1"), "bounded")):
                errors["raw_aggregates"].append(
                    "raw DTrace stream is bounded"
                )
        except EvidenceError as error:
            errors["raw_aggregates"].append(str(error))
        try:
            if (
                _integer(
                    completion.get("target_exit_reason", "0"),
                    "target exit reason",
                )
                != 1
            ):
                errors["raw_aggregates"].append(
                    "raw DTrace target was interrupted"
                )
        except EvidenceError as error:
            errors["raw_aggregates"].append(str(error))
    if set(binding_events) != BINDING_EVENT_KINDS:
        missing = sorted(BINDING_EVENT_KINDS - set(binding_events))
        errors["raw_aggregates"].append(
            f"binding event vector lacks explicit zero kind(s): {missing}"
        )
    for phase, event_kind, specialized_total in (
        ("binding-publish-cell", 8, sum(publication_cells.values())),
        ("binding-clear-cell", 10, sum(clear_cells.values())),
        ("binding-validation", 11, sum(validation_reasons.values())),
        ("binding-unit", 12, sum(unit_loads.values())),
    ):
        if (
            event_kind in binding_events
            and specialized_total != binding_events[event_kind]
        ):
            errors["reconciliation"].append(
                f"{phase} total does not reconcile with kind={event_kind}"
            )

    def partial_phase_total(phase: str) -> int | None:
        values = [
            value
            for key, value in metrics.items()
            if dict(key).get("phase") == phase
        ]
        if not values:
            errors["raw_aggregates"].append(
                f"raw trace is missing required {phase} metric"
            )
            return None
        return sum(values)

    gateway_total = partial_phase_total("gateway-total")
    direct_total = partial_phase_total("direct-total")
    indirect_total = partial_phase_total("indirect-total")
    translation_attempts = partial_phase_total("translation-attempts")

    summary_metrics: dict[tuple[tuple[str, str], ...], int] = {}
    try:
        summary_metrics, _ = _parse_summary(receipt)
    except (EvidenceError, OSError) as error:
        errors["summary"].append(str(error))
    if not errors["raw_aggregates"] and not errors["summary"]:
        raw_aggregated: dict[tuple[tuple[str, str], ...], int] = defaultdict(int)
        for key, value in metrics.items():
            raw_aggregated[_summary_aggregate_key(key)] += value
        if raw_aggregated != summary_metrics:
            errors["reconciliation"].append(
                "raw/summary overlapping metrics do not reconcile"
            )

    native_gateway = None
    native_exits: dict[int, int] = {}
    try:
        native_gateway, native_exits = _native_vector(
            _artifact(receipt, "command_stderr").path
        )
    except (EvidenceError, OSError) as error:
        errors["nativeperf"].append(str(error))
    if (
        native_gateway is not None
        and gateway_total is not None
        and direct_total is not None
        and indirect_total is not None
        and not errors["nativeperf"]
        and (
            gateway_total != native_gateway
            or direct_total != native_exits[2]
            or indirect_total != native_exits[3]
            or gateway_kinds != native_exits
        )
    ):
        errors["reconciliation"].append(
            "raw DTrace and NATIVEPERF gateway exit vectors do not reconcile"
        )

    clear_by_cell: dict[tuple[int, int], int] = defaultdict(int)
    for (pid, cell, _reason), value in clear_cells.items():
        clear_by_cell[(pid, cell)] += value
    for identity, publishes in publication_cells.items():
        if publishes > 1 + clear_by_cell.get(identity, 0):
            errors["reconciliation"].append(
                f"publication invariant failed for pid/cell {identity}"
            )
    if sum(publication_cells.values()) > len(binding_cells) + sum(
        clear_cells.values()
    ):
        errors["reconciliation"].append(
            "global publication invariant failed"
        )

    return {
        "run_id": receipt.payload.get("run_id"),
        "binding_events": {
            str(kind): value
            for kind, value in sorted(binding_events.items())
        },
        "gateway_kinds": {
            str(kind): value for kind, value in sorted(gateway_kinds.items())
        },
        "gateway_total": gateway_total,
        "direct_total": direct_total,
        "indirect_total": indirect_total,
        "translation_attempts": translation_attempts,
        "binding_cells": [
            {"pid": pid, "cell": cell, "value": value}
            for (pid, cell), value in sorted(binding_cells.items())
        ],
        "publication_cells": [
            {"pid": pid, "cell": cell, "value": value}
            for (pid, cell), value in sorted(publication_cells.items())
        ],
        "clear_cells": [
            {"pid": pid, "cell": cell, "reason": reason, "value": value}
            for (pid, cell, reason), value in sorted(clear_cells.items())
        ],
        "validation_reasons": {
            str(reason): value
            for reason, value in sorted(validation_reasons.items())
        },
        "unit_loads": [
            {
                "pid": pid,
                "unit_id": unit_id,
                "record_count": record_count,
                "binding_data_bytes": binding_data_bytes,
                "value": value,
            }
            for (
                pid,
                unit_id,
                record_count,
                binding_data_bytes,
            ), value in sorted(unit_loads.items())
        ],
        "summary_metrics": _summary_metrics_payload(summary_metrics),
        "native_gateway": native_gateway,
        "native_exits": {
            str(kind): value for kind, value in sorted(native_exits.items())
        },
        "evidence_errors": errors,
    }


def compare(
    precursor: CaptureReceipt,
    candidate: CaptureReceipt,
) -> dict[str, object]:
    precursor_run = parse_trace(precursor)
    candidate_run = parse_trace(candidate)
    validate_receipt(precursor, require_variant="precursor")
    validate_receipt(candidate, require_variant="candidate")
    precursor_snapshot = _snapshot(precursor, "pre")
    candidate_snapshot = _snapshot(candidate, "pre")
    for field in ("git_commit", "binary_sha256", "host", "image"):
        if precursor_snapshot[field] != candidate_snapshot[field]:
            raise EvidenceError(f"capture pair differs in frozen {field}")
    if _common_environment(precursor) != _common_environment(candidate):
        raise EvidenceError("capture pair differs in controlled environment")

    precursor_eligible = precursor_run.binding_events[7]
    candidate_eligible = candidate_run.binding_events[7]
    precursor_direct = precursor_run.direct_total
    candidate_direct = candidate_run.direct_total
    precursor_gateway = precursor_run.gateway_total
    candidate_gateway = candidate_run.gateway_total
    s = precursor_eligible - candidate_eligible
    d = precursor_direct - candidate_direct
    g = precursor_gateway - candidate_gateway
    reasons = []
    if precursor_eligible <= 0:
        reasons.append("precursor eligible count is zero")
    if 100 * candidate_eligible > 5 * precursor_eligible:
        reasons.append("candidate eligible exits exceed five percent of precursor")
    if s <= 0 or 100 * d < 95 * s:
        reasons.append("direct-exit reduction does not explain eligible collapse")
    if d <= 0 or 100 * g < 95 * d:
        reasons.append("gateway reduction does not explain direct-exit reduction")
    indirect_growth = max(
        0, candidate_run.indirect_total - precursor_run.indirect_total
    )
    if 100 * indirect_growth > 5 * d:
        reasons.append("indirect growth exceeds five percent of direct reduction")
    gateway_deltas = {
        kind: candidate_run.gateway_kinds[kind] - precursor_run.gateway_kinds[kind]
        for kind in range(1, 8)
    }
    positive_non_direct_growth = sum(
        max(0, delta)
        for kind, delta in gateway_deltas.items()
        if kind != 2
    )
    if 100 * positive_non_direct_growth > 5 * d:
        reasons.append("non-direct growth exceeds five percent of direct reduction")
    if candidate_run.gateway_kinds[4] != 0:
        reasons.append("candidate fault exits are nonzero")
    if candidate_run.gateway_kinds[7] != 0:
        reasons.append("candidate unsupported exits are nonzero")
    if reasons:
        raise EvidenceError("; ".join(reasons))
    return {
        "schema": SCHEMA,
        "accepted": True,
        "rejection_reasons": [],
        "receipts": {
            "precursor": {
                "path": str(precursor.path),
                "sha256": precursor.sha256,
            },
            "candidate": {
                "path": str(candidate.path),
                "sha256": candidate.sha256,
            },
        },
        "runs": {
            "precursor": _run_payload(precursor_run),
            "candidate": _run_payload(candidate_run),
        },
        "collapse": {"S": s, "D": d, "G": g},
        "gateway_kind_deltas": {
            str(kind): delta for kind, delta in gateway_deltas.items()
        },
        "indirect_growth": indirect_growth,
        "total_positive_non_direct_growth": positive_non_direct_growth,
        "integer_gates": {
            "precursor_eligible_positive": precursor_eligible > 0,
            "candidate_eligible_le_5_percent": (
                100 * candidate_eligible <= 5 * precursor_eligible
            ),
            "direct_reduction_ge_95_percent_of_collapse": 100 * d >= 95 * s,
            "gateway_reduction_ge_95_percent_of_direct": 100 * g >= 95 * d,
            "indirect_growth_le_5_percent_of_direct": (
                100 * indirect_growth <= 5 * d
            ),
            "non_direct_growth_le_5_percent_of_direct": (
                100 * positive_non_direct_growth <= 5 * d
            ),
            "candidate_fault_zero": candidate_run.gateway_kinds[4] == 0,
            "candidate_unsupported_zero": candidate_run.gateway_kinds[7] == 0,
        },
        "timing_claim": None,
    }


def _expected_controlled_environment(variant: str) -> dict[str, str | None]:
    controlled = native_go_build.fixed_variant_overlay(variant)
    controlled["CARRICK_DSR_PROFILE"] = "1"
    return controlled


def _capture_environment(
    variant: str,
    *,
    run_id: str | None,
) -> CaptureEnvironment:
    controlled = _expected_controlled_environment(variant)
    native_go_build.reject_ambient_carrick(os.environ, controlled)
    environment = dict(os.environ)
    for key in native_go_build.PERFORMANCE_CONTROL_KEYS:
        environment.pop(key, None)
    for key, value in controlled.items():
        if value is not None:
            environment[key] = value
    if run_id is not None:
        environment["CARRICK_RUN_ID"] = run_id
    return CaptureEnvironment(environment, controlled)


def capture_environment(variant: str) -> dict[str, str]:
    return _capture_environment(variant, run_id=None).subprocess


def synthetic_snapshot(variant: str) -> dict[str, object]:
    controlled = _expected_controlled_environment(variant)
    return {
        "git_commit": "a" * 40,
        "git_status": [],
        "repository": "/fixture/repo",
        "binary_path": "/fixture/repo/target/release/carrick",
        "binary_sha256": "b" * 64,
        "host": "fixture-host",
        "image_ref": native_go_build.DEFAULT_IMAGE,
        "image": {"id": "sha256:image", "repo_digests": ["image@sha256:digest"]},
        "controlled_environment": controlled,
        "foreign_processes": [],
        "docker_oracles": [],
    }


def capture_snapshot(
    config: CaptureConfig,
    capture: CaptureEnvironment,
) -> dict[str, object]:
    snapshot = native_go_build.sample_provenance(
        config.resolved_repo,
        native_go_build.ENGINE_CARRICK,
        capture.controlled,
        reject_contamination=False,
        binary_path=config.resolved_binary,
        image_ref=config.image,
    )
    return {
        "git_commit": snapshot["git_commit"],
        "git_status": snapshot["git_status"],
        "repository": str(config.resolved_repo),
        "binary_path": str(config.resolved_binary),
        "binary_sha256": snapshot["binary_sha256"],
        "host": str(_mapping(snapshot["host"], "host identity")["node"]),
        "image_ref": config.image,
        "image": snapshot["image"],
        "controlled_environment": capture.controlled,
        "foreign_processes": snapshot["foreign_processes"],
        "docker_oracles": snapshot["docker_oracles"],
    }


def _failed_snapshot(
    config: CaptureConfig,
    capture: CaptureEnvironment,
    error: Exception,
) -> dict[str, object]:
    return {
        "git_commit": "unknown",
        "git_status": [f"snapshot-error: {error}"],
        "repository": str(config.resolved_repo),
        "binary_path": str(config.resolved_binary),
        "binary_sha256": "unknown",
        "host": "unknown",
        "image_ref": config.image,
        "image": {"error": str(error)},
        "controlled_environment": capture.controlled,
        "foreign_processes": [f"snapshot-error: {error}"],
        "docker_oracles": [],
    }


def _snapshot_or_error(
    config: CaptureConfig,
    capture: CaptureEnvironment,
) -> dict[str, object]:
    try:
        return capture_snapshot(config, capture)
    except Exception as error:
        return _failed_snapshot(config, capture, error)


def _preflight_reasons(snapshot: Mapping[str, object]) -> list[str]:
    reasons = []
    if snapshot.get("git_status"):
        reasons.append("git status is not clean")
    if snapshot.get("foreign_processes"):
        reasons.append("foreign Carrick or benchmark process census is not empty")
    if snapshot.get("docker_oracles"):
        reasons.append("Docker oracle census is not empty")
    if snapshot.get("binary_sha256") in {None, "unknown"}:
        reasons.append("signed binary identity is unavailable")
    image = snapshot.get("image")
    if not isinstance(image, dict) or "error" in image:
        reasons.append("resolved image identity is unavailable")
    return reasons


def _capture_paths(config: CaptureConfig) -> dict[str, pathlib.Path]:
    directory = (config.output_dir / config.variant).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    return {
        "raw_trace": directory / "trace.log",
        "summary_jsonl": directory / "summary.jsonl",
        "command_stdout": directory / "stdout.log",
        "command_stderr": directory / "stderr.log",
        "receipt": directory / "receipt.json",
    }


def _trace_command(config: CaptureConfig, paths: Mapping[str, pathlib.Path]) -> list[str]:
    run = native_go_build.build_carrick_command(
        config.resolved_repo,
        config.run_id,
        binary=config.resolved_binary,
        image=config.image,
    )
    return [
        str(config.resolved_binary),
        "trace",
        "--profile",
        PROFILE,
        "--trace-out",
        str(paths["raw_trace"]),
        "--summary-jsonl",
        str(paths["summary_jsonl"]),
        "--",
        *run[1:],
    ]


def _run_trace(
    config: CaptureConfig,
    paths: Mapping[str, pathlib.Path],
    capture: CaptureEnvironment,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _trace_command(config, paths),
        cwd=config.resolved_repo,
        env=capture.subprocess,
        capture_output=True,
        text=True,
        timeout=config.timeout_seconds,
        check=False,
    )


def _descendants(run_id: str) -> tuple[str, ...]:
    process_list = subprocess.run(
        ["ps", "-eo", "pid=,args="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return tuple(
        line.strip()
        for line in process_list.splitlines()
        if run_id in line and str(os.getpid()) not in line.split(maxsplit=1)[:1]
    )


def _cleanup(config: CaptureConfig) -> CleanupEvidence:
    result = subprocess.run(
        [str(config.repo / "scripts/sudo/kill.sh"), config.run_id],
        cwd=config.repo,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return CleanupEvidence(
        result.returncode,
        result.stdout,
        result.stderr,
        _descendants(config.run_id),
    )


def _summary_copy(path: pathlib.Path) -> dict[str, object]:
    try:
        first = next(
            json.loads(line)
            for line in path.read_text().splitlines()
            if line.strip()
        )
    except (OSError, StopIteration, json.JSONDecodeError):
        return {
            "run_id": None,
            "git_sha": None,
            "git_dirty": None,
            "binary_sha256": None,
            "host": None,
            "completion": {
                "complete": False,
                "bounded": False,
                "target_exit_reason": 0,
                "high_cardinality_overflow": False,
                "incomplete_pairs": 0,
                "cardinality": {
                    "indirect_sources": 0,
                    "indirect_pairs": 0,
                },
                "drops": {
                    "principal_drops": 0,
                    "aggregation_drops": 0,
                    "dynamic_drops": 0,
                    "other_drops": 0,
                    "interrupted": False,
                },
            },
        }
    return {
        key: first.get(key)
        for key in (
            "run_id",
            "git_sha",
            "git_dirty",
            "binary_sha256",
            "command",
            "host",
            "completion",
        )
    }


def capture_one(config: CaptureConfig) -> CaptureReceipt:
    if config.variant not in {"precursor", "candidate"}:
        raise EvidenceError("capture variant must be fixed precursor or candidate")
    capture = _capture_environment(config.variant, run_id=config.run_id)
    paths = _capture_paths(config)
    pre = _snapshot_or_error(config, capture)
    command = _trace_command(config, paths)
    preflight_reasons = _preflight_reasons(pre)
    if preflight_reasons:
        status = 125
        stdout = ""
        stderr = "preflight rejected capture: " + "; ".join(preflight_reasons) + "\n"
    else:
        try:
            result = _run_trace(config, paths, capture)
            status = result.returncode
            stdout = result.stdout or ""
            stderr = result.stderr or ""
        except subprocess.TimeoutExpired as error:
            status = 124
            stdout = native_go_build.combined_output(error.stdout, None)
            stderr = native_go_build.combined_output(None, error.stderr)
        except Exception as error:
            status = 125
            stdout = ""
            stderr = f"trace launch failed: {error}\n"
    paths["command_stdout"].write_text(stdout)
    paths["command_stderr"].write_text(stderr)
    for name in ("raw_trace", "summary_jsonl"):
        if not paths[name].exists():
            paths[name].write_text("")
    post = _snapshot_or_error(config, capture)
    try:
        cleanup = _cleanup(config)
    except Exception as error:
        cleanup = CleanupEvidence(
            status=125,
            stdout="",
            stderr=f"cleanup launch failed: {error}\n",
            descendants=(),
        )
    payload = {
        "schema": RECEIPT_SCHEMA,
        "variant": config.variant,
        "run_id": config.run_id,
        "inputs": {
            "repository": str(config.resolved_repo),
            "binary": str(config.resolved_binary),
            "image": config.image,
            "profile": PROFILE,
            "summary_schema": SUMMARY_SCHEMA,
        },
        "argv": command,
        "workload": native_go_build.guest_script(),
        "provenance": {"pre": pre, "post": post},
        "command": {
            "status": status,
            "build_ok": stdout.splitlines().count("BUILD_OK") == 1,
        },
        "cleanup": dataclasses.asdict(cleanup),
        "summary": _summary_copy(paths["summary_jsonl"]),
        "environment_sha256": sha256_json(pre["controlled_environment"]),
        "image_sha256": sha256_json(pre["image"]),
        "artifacts": {
            name: bind_artifact(paths[name])
            for name in (
                "raw_trace",
                "summary_jsonl",
                "command_stdout",
                "command_stderr",
            )
        },
    }
    write_json_atomic(paths["receipt"], payload)
    return parse_receipt(paths["receipt"])


def _capture_pair(
    repo: pathlib.Path,
    output_dir: pathlib.Path,
    output: pathlib.Path,
    timeout_seconds: int,
    binary: pathlib.Path | None = None,
    image: str = native_go_build.DEFAULT_IMAGE,
) -> dict[str, object]:
    stamp = f"{os.getpid()}-{time.time_ns()}"
    precursor = capture_one(
        CaptureConfig(
            repo=repo,
            output_dir=output_dir,
            variant="precursor",
            run_id=f"direct-binding-precursor-{stamp}",
            timeout_seconds=timeout_seconds,
            binary=binary,
            image=image,
        )
    )
    try:
        validate_receipt(precursor, require_variant="precursor")
        parse_trace(precursor)
    except EvidenceError as error:
        payload = {
            "schema": PAIR_SCHEMA,
            "accepted": False,
            "rejection_reasons": [str(error)],
            "precursor": {
                "path": str(precursor.path),
                "sha256": precursor.sha256,
            },
            "candidate": None,
            "available_runs": _available_run_payloads(precursor, None),
        }
        write_json_atomic_exclusive(output, payload)
        return payload
    candidate = capture_one(
        CaptureConfig(
            repo=repo,
            output_dir=output_dir,
            variant="candidate",
            run_id=f"direct-binding-candidate-{stamp}",
            timeout_seconds=timeout_seconds,
            binary=binary,
            image=image,
        )
    )
    try:
        payload = compare(precursor, candidate)
    except EvidenceError as error:
        payload = {
            "schema": SCHEMA,
            "accepted": False,
            "rejection_reasons": [str(error)],
            "precursor": {
                "path": str(precursor.path),
                "sha256": precursor.sha256,
            },
            "candidate": {
                "path": str(candidate.path),
                "sha256": candidate.sha256,
            },
            "available_runs": _available_run_payloads(precursor, candidate),
        }
    write_json_atomic_exclusive(output, payload)
    return payload


def _capture_collisions(
    output_dir: pathlib.Path,
    output: pathlib.Path,
) -> list[pathlib.Path]:
    targets = (
        output.resolve(),
        (output_dir / "precursor").resolve(),
        (output_dir / "candidate").resolve(),
    )
    return [path for path in targets if os.path.lexists(path)]


def _collision_rejection(
    collisions: Sequence[pathlib.Path],
) -> dict[str, object]:
    return {
        "schema": PAIR_SCHEMA,
        "accepted": False,
        "rejection_reasons": [
            "capture evidence already exists: "
            + ", ".join(str(path) for path in collisions)
        ],
        "precursor": None,
        "candidate": None,
        "available_runs": {},
    }


def capture_pair(
    repo: pathlib.Path,
    output_dir: pathlib.Path,
    output: pathlib.Path,
    timeout_seconds: int,
    binary: pathlib.Path | None = None,
    image: str = native_go_build.DEFAULT_IMAGE,
) -> dict[str, object]:
    collisions = _capture_collisions(output_dir, output)
    if collisions:
        return _collision_rejection(collisions)
    try:
        return _capture_pair(
            repo,
            output_dir,
            output,
            timeout_seconds,
            binary,
            image,
        )
    except (EvidenceError, OSError, RuntimeError, ValueError) as error:
        collisions = _capture_collisions(output_dir, output)
        if isinstance(error, FileExistsError) or output.resolve() in collisions:
            payload = _collision_rejection(collisions)
            if output.resolve() in collisions:
                return payload
        else:
            payload = {
                "schema": PAIR_SCHEMA,
                "accepted": False,
                "rejection_reasons": [str(error)],
                "precursor": None,
                "candidate": None,
                "available_runs": {},
            }
        write_json_atomic_exclusive(output, payload)
        return payload


def _available_run_payloads(
    precursor: CaptureReceipt | None,
    candidate: CaptureReceipt | None,
) -> dict[str, object]:
    available = {}
    for name, receipt in (("precursor", precursor), ("candidate", candidate)):
        if receipt is None:
            continue
        available[name] = _partial_run_payload(receipt)
    return available


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture-pair", "compare"))
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("target/perf/direct-binding-mechanism.json"),
    )
    parser.add_argument(
        "--artifact-dir",
        type=pathlib.Path,
        default=pathlib.Path("target/perf/direct-binding-captures"),
    )
    parser.add_argument("--repo", type=pathlib.Path)
    parser.add_argument("--binary", type=pathlib.Path)
    parser.add_argument("--image", default=native_go_build.DEFAULT_IMAGE)
    parser.add_argument("--precursor-receipt", type=pathlib.Path)
    parser.add_argument("--candidate-receipt", type=pathlib.Path)
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=native_go_build.DEFAULT_TIMEOUT_SECONDS,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo = (
        pathlib.Path(__file__).resolve().parents[2]
        if args.repo is None
        else args.repo
    )
    if args.mode == "capture-pair":
        payload = capture_pair(
            repo,
            args.artifact_dir,
            args.output,
            args.timeout_seconds,
            args.binary,
            args.image,
        )
    else:
        if args.precursor_receipt is None or args.candidate_receipt is None:
            raise SystemExit("compare requires both receipt paths")
        precursor_receipt = None
        candidate_receipt = None
        try:
            precursor_receipt = parse_receipt(args.precursor_receipt)
            candidate_receipt = parse_receipt(args.candidate_receipt)
            payload = compare(
                precursor_receipt,
                candidate_receipt,
            )
        except EvidenceError as error:
            payload = {
                "schema": SCHEMA,
                "accepted": False,
                "rejection_reasons": [str(error)],
                "precursor_receipt": str(args.precursor_receipt),
                "candidate_receipt": str(args.candidate_receipt),
                "available_runs": _available_run_payloads(
                    precursor_receipt,
                    candidate_receipt,
                ),
            }
        write_json_atomic(args.output, payload)
    return 0 if payload["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
