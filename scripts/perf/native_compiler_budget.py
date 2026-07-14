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
import gzip
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
class W1Capture:
    kind: str
    go_version: str
    source: str
    stdout_normalization: str


@dataclasses.dataclass(frozen=True)
class DockerReplay:
    exit_status: int
    stdout_sha256: str
    output_sha256: str


@dataclasses.dataclass(frozen=True)
class W2Capture:
    kind: str
    source: str
    candidate_count: int
    capture_environment: tuple[tuple[str, str], ...]
    replay_environment: tuple[tuple[str, str], ...]
    captured_argv_index: int
    expected_output_guest_path: str
    expected_output_sha256: str
    docker_replays: tuple[DockerReplay, DockerReplay]
    w1_stdout_sha256: str
    w1_stderr_sha256: str
    w1_profile_evidence_path: str
    w1_profile_evidence_sha256: str
    rejected_candidates: tuple[tuple[tuple[str, object], ...], ...]
    representativeness: tuple[tuple[str, object], ...]


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
    capture: W1Capture | W2Capture
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
W1_CAPTURE_FIELDS = {"kind", "go_version", "source", "stdout_normalization"}
W2_CAPTURE_FIELDS = {
    "kind",
    "source",
    "candidate_count",
    "capture_environment",
    "replay_environment",
    "captured_argv_index",
    "expected_output_guest_path",
    "expected_output_sha256",
    "docker_replays",
    "w1_stdout_sha256",
    "w1_stderr_sha256",
    "w1_profile_evidence_path",
    "w1_profile_evidence_sha256",
    "rejected_candidates",
    "representativeness",
}
REPLAY_FIELDS = {"exit_status", "stdout_sha256", "output_sha256"}
REPRESENTATIVENESS_FIELDS = {
    "accepted_rule",
    "profile_cleanup_status",
    "profile_stderr_sha256",
    "profile_summary_sha256",
    "w1_profile_sha256",
    "w1_hottest",
    "w2_hottest",
}
HOTTEST_FIELDS = {
    "gateway_entries",
    "exit_resolve_direct",
    "exit_resolve_indirect",
    "exit_sensitive",
    "sensitive_exclusive",
}
REJECTED_CANDIDATE_FIELDS = {
    "aggregate_gateway_entries",
    "candidate",
    "hottest_exit_resolve_direct",
    "hottest_exit_resolve_indirect",
    "hottest_exit_sensitive",
    "hottest_gateway_entries",
    "hottest_sensitive_exclusive",
    "reason",
    "status",
    "stderr_sha256",
}


def _require_type(mapping: Mapping[str, object], key: str, kind: type):
    value = mapping.get(key)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise BudgetError(f"manifest field {key!r} must be {kind.__name__}")
    return value


def _require_hash(value: str, name: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise BudgetError(f"{name} must be a lowercase SHA-256")
    return value


def _string_pairs(value: object, name: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise BudgetError(f"{name} must be a sorted array of string pairs")
    pairs = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 2 or not all(
            isinstance(item, str) for item in entry
        ):
            raise BudgetError(f"{name} must be a sorted array of string pairs")
        pairs.append((entry[0], entry[1]))
    if pairs != sorted(pairs) or len({key for key, _ in pairs}) != len(pairs):
        raise BudgetError(f"{name} must be sorted with unique keys")
    return tuple(pairs)


def _parse_capture(raw: dict[str, object], env: tuple[tuple[str, str], ...]) -> W1Capture | W2Capture:
    kind = raw.get("kind")
    if kind == "w1-go-test":
        unknown = set(raw) - W1_CAPTURE_FIELDS
        missing = W1_CAPTURE_FIELDS - set(raw)
        if unknown:
            raise BudgetError(f"unknown W1 capture field(s): {', '.join(sorted(unknown))}")
        if missing:
            raise BudgetError(f"missing W1 capture field(s): {', '.join(sorted(missing))}")
        values = {key: raw[key] for key in W1_CAPTURE_FIELDS}
        if not all(isinstance(value, str) for value in values.values()):
            raise BudgetError("W1 capture fields must be strings")
        normalization = values["stdout_normalization"]
        if normalization not in {"none", "go-test-duration"}:
            raise BudgetError("unknown W1 stdout normalization")
        return W1Capture(
            kind="w1-go-test",
            go_version=values["go_version"],
            source=values["source"],
            stdout_normalization=normalization,
        )
    if kind != "w2-toolexec":
        raise BudgetError(f"unknown capture schema variant: {kind!r}")
    unknown = set(raw) - W2_CAPTURE_FIELDS
    missing = W2_CAPTURE_FIELDS - set(raw)
    if unknown:
        raise BudgetError(f"unknown W2 capture field(s): {', '.join(sorted(unknown))}")
    if missing:
        raise BudgetError(f"missing W2 capture field(s): {', '.join(sorted(missing))}")
    capture_environment = _string_pairs(raw["capture_environment"], "capture environment")
    replay_environment = _string_pairs(raw["replay_environment"], "replay environment")
    if replay_environment != env:
        raise BudgetError("W2 replay environment does not match workload environment")
    capture_only = {"CARRICK_TOOLEXEC_LOG", "GOFLAGS"}
    if capture_only & {key for key, _ in env} or capture_only & {
        key for key, _ in replay_environment
    }:
        raise BudgetError("capture-only environment leaked into workload replay")
    if not capture_only <= {key for key, _ in capture_environment}:
        raise BudgetError("capture environment omits required capture-only variables")
    replays_raw = raw["docker_replays"]
    if not isinstance(replays_raw, list) or len(replays_raw) != 2:
        raise BudgetError("W2 capture requires exactly two Docker replays")
    replays = []
    for entry in replays_raw:
        if not isinstance(entry, dict) or set(entry) != REPLAY_FIELDS:
            raise BudgetError("Docker replay requires exactly status/stdout/output fields")
        status = entry["exit_status"]
        stdout_sha = entry["stdout_sha256"]
        output_sha = entry["output_sha256"]
        if not isinstance(status, int) or isinstance(status, bool) or not isinstance(
            stdout_sha, str
        ) or not isinstance(output_sha, str):
            raise BudgetError("Docker replay fields have invalid types")
        _require_hash(stdout_sha, "Docker replay stdout_sha256")
        _require_hash(output_sha, "Docker replay output_sha256")
        replays.append(DockerReplay(status, stdout_sha, output_sha))
    if replays[0] != replays[1]:
        raise BudgetError("W2 requires matching Docker replay status/stdout/output digests")
    expected_output = raw["expected_output_sha256"]
    expected_path = raw["expected_output_guest_path"]
    if not isinstance(expected_output, str) or not isinstance(expected_path, str):
        raise BudgetError("W2 output contract fields must be strings")
    _require_hash(expected_output, "W2 expected output")
    if not expected_path.startswith("/") or replays[0].output_sha256 != expected_output:
        raise BudgetError("W2 Docker replay does not satisfy the output contract")
    representative = raw["representativeness"]
    if not isinstance(representative, dict) or set(representative) != REPRESENTATIVENESS_FIELDS:
        raise BudgetError("W2 representativeness has unknown or missing determinant fields")
    if not isinstance(representative["accepted_rule"], str):
        raise BudgetError("representativeness accepted_rule must be a string")
    if (
        not isinstance(representative["profile_cleanup_status"], int)
        or isinstance(representative["profile_cleanup_status"], bool)
        or representative["profile_cleanup_status"] != 0
    ):
        raise BudgetError("representativeness profile cleanup must be successful")
    for hash_field in (
        "profile_stderr_sha256",
        "profile_summary_sha256",
        "w1_profile_sha256",
    ):
        value = representative[hash_field]
        if not isinstance(value, str):
            raise BudgetError(f"representativeness {hash_field} must be a SHA-256")
        _require_hash(value, f"representativeness {hash_field}")
    for hottest_name in ("w1_hottest", "w2_hottest"):
        hottest = representative[hottest_name]
        if not isinstance(hottest, dict) or set(hottest) != HOTTEST_FIELDS or not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in hottest.values()
        ):
            raise BudgetError(f"representativeness {hottest_name} is malformed")
        if sum(
            hottest[key]
            for key in ("exit_resolve_direct", "exit_resolve_indirect", "exit_sensitive")
        ) > hottest["gateway_entries"] or hottest["sensitive_exclusive"] > hottest[
            "exit_sensitive"
        ]:
            raise BudgetError(f"representativeness {hottest_name} counts do not reconcile")
    rejected = raw["rejected_candidates"]
    if not isinstance(rejected, list):
        raise BudgetError("rejected candidates must be an array of objects")
    for entry in rejected:
        if not isinstance(entry, dict) or set(entry) != REJECTED_CANDIDATE_FIELDS:
            raise BudgetError("rejected candidate has unknown or missing fields")
        for name in REJECTED_CANDIDATE_FIELDS - {"candidate", "reason", "stderr_sha256"}:
            if not isinstance(entry[name], int) or isinstance(entry[name], bool) or entry[name] < 0:
                raise BudgetError(f"rejected candidate {name} must be non-negative")
        if not isinstance(entry["candidate"], str) or not isinstance(entry["reason"], str):
            raise BudgetError("rejected candidate name and reason must be strings")
        if not isinstance(entry["stderr_sha256"], str):
            raise BudgetError("rejected candidate stderr_sha256 must be a SHA-256")
        _require_hash(entry["stderr_sha256"], "rejected candidate stderr_sha256")
        if (
            entry["hottest_exit_resolve_direct"]
            + entry["hottest_exit_resolve_indirect"]
            + entry["hottest_exit_sensitive"]
            > entry["hottest_gateway_entries"]
            or entry["hottest_sensitive_exclusive"] > entry["hottest_exit_sensitive"]
            or entry["hottest_gateway_entries"] > entry["aggregate_gateway_entries"]
        ):
            raise BudgetError("rejected candidate counts do not reconcile")
    candidate_count = raw["candidate_count"]
    captured_index = raw["captured_argv_index"]
    if not isinstance(candidate_count, int) or candidate_count <= 0:
        raise BudgetError("candidate_count must be positive")
    if not isinstance(captured_index, int) or captured_index < 0:
        raise BudgetError("captured_argv_index must be non-negative")
    for name in ("w1_stdout_sha256", "w1_stderr_sha256"):
        value = raw[name]
        if not isinstance(value, str):
            raise BudgetError(f"{name} must be a SHA-256")
        _require_hash(value, name)
    evidence_path = raw["w1_profile_evidence_path"]
    evidence_sha = raw["w1_profile_evidence_sha256"]
    if not isinstance(evidence_path, str) or pathlib.PurePosixPath(evidence_path).is_absolute():
        raise BudgetError("w1_profile_evidence_path must be relative")
    if not isinstance(evidence_sha, str):
        raise BudgetError("w1_profile_evidence_sha256 must be a SHA-256")
    _require_hash(evidence_sha, "w1_profile_evidence_sha256")
    source = raw["source"]
    if not isinstance(source, str):
        raise BudgetError("W2 source must be a string")
    return W2Capture(
        kind="w2-toolexec",
        source=source,
        candidate_count=candidate_count,
        capture_environment=capture_environment,
        replay_environment=replay_environment,
        captured_argv_index=captured_index,
        expected_output_guest_path=expected_path,
        expected_output_sha256=expected_output,
        docker_replays=(replays[0], replays[1]),
        w1_stdout_sha256=str(raw["w1_stdout_sha256"]),
        w1_stderr_sha256=str(raw["w1_stderr_sha256"]),
        w1_profile_evidence_path=evidence_path,
        w1_profile_evidence_sha256=evidence_sha,
        rejected_candidates=tuple(tuple(sorted(entry.items())) for entry in rejected),
        representativeness=tuple(sorted(representative.items())),
    )


def validate_w1_profile_evidence(
    manifest_path: pathlib.Path, capture: W2Capture
) -> None:
    path = (manifest_path.parent / capture.w1_profile_evidence_path).resolve()
    if _sha256_path(path) != capture.w1_profile_evidence_sha256:
        raise BudgetError("W1 profile evidence SHA-256 mismatch")
    raw = _exact_mapping(
        _read_json(path),
        {
            "schema",
            "run_id",
            "binary_sha256",
            "manifest_sha256",
            "raw_profile_source",
            "raw_profile_sha256",
            "raw_profile_evidence_path",
            "complete_thread_groups",
            "frames_per_group",
            "required_frames",
            "hottest",
            "outcome",
            "cleanup",
            "timing",
        },
        "W1 profile evidence",
    )
    if raw["schema"] != "carrick.native-compiler-w1-profile-evidence.v1":
        raise BudgetError("unknown W1 profile evidence schema")
    for name in ("binary_sha256", "manifest_sha256", "raw_profile_sha256"):
        value = _string(raw[name], f"W1 evidence {name}")
        _require_hash(value, f"W1 evidence {name}")
    w1_manifest = manifest_path.with_name("native-compiler-w1-v1.json")
    if w1_manifest.is_file() and raw["manifest_sha256"] != _sha256_path(w1_manifest):
        raise BudgetError("W1 evidence manifest hash differs from the tree declaration")
    representative = dict(capture.representativeness)
    if raw["raw_profile_sha256"] != representative["w1_profile_sha256"]:
        raise BudgetError("W1 evidence raw profile hash differs from capture determinant")
    if not isinstance(raw["raw_profile_source"], str) or not raw["raw_profile_source"].startswith(
        "target/native-compiler-task2-review/"
    ):
        raise BudgetError("W1 evidence raw source path is not the retained bounded run")
    if _nonnegative_int(raw["complete_thread_groups"], "complete thread groups") == 0:
        raise BudgetError("W1 evidence has no complete thread groups")
    if _nonnegative_int(raw["frames_per_group"], "frames per group") != len(REQUIRED_FRAMES):
        raise BudgetError("W1 evidence does not have nine frames per group")
    if raw["required_frames"] != sorted(REQUIRED_FRAMES):
        raise BudgetError("W1 evidence required frame set is incomplete")
    hottest = _exact_mapping(raw["hottest"], HOTTEST_FIELDS | {"pid", "tid", "era"}, "W1 hottest")
    if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in hottest.values()):
        raise BudgetError("W1 hottest fields must be non-negative integers")
    if {name: hottest[name] for name in HOTTEST_FIELDS} != representative["w1_hottest"]:
        raise BudgetError("W1 evidence hottest counters differ from representativeness")
    outcome = _exact_mapping(
        raw["outcome"],
        {
            "kind",
            "exit_status",
            "work_units_completed",
            "work_units_expected",
            "ceiling_marker_thread_id",
            "ceiling_marker_traps",
            "ceiling_profile_identity",
            "gateway_entries",
            "gateway_limit",
        },
        "W1 evidence outcome",
    )
    marker = MaxTrapsMarker(
        _nonnegative_int(outcome["ceiling_marker_thread_id"], "ceiling marker thread id"),
        _nonnegative_int(outcome["ceiling_marker_traps"], "ceiling marker traps"),
    )
    identity_raw = outcome["ceiling_profile_identity"]
    if not isinstance(identity_raw, list) or len(identity_raw) != 3:
        raise BudgetError("W1 evidence ceiling identity must be pid/tid/era")
    identity = tuple(
        _nonnegative_int(item, "W1 evidence ceiling identity") for item in identity_raw
    )
    gateway_entries = _nonnegative_int(outcome["gateway_entries"], "W1 gateway entries")
    gateway_limit = _nonnegative_int(outcome["gateway_limit"], "W1 gateway limit")
    if identity != (hottest["pid"], hottest["tid"], hottest["era"]):
        raise BudgetError("W1 evidence ceiling identity differs from hottest group")
    if gateway_entries != hottest["gateway_entries"]:
        raise BudgetError("W1 evidence outcome gateway count differs from hottest group")
    derived = classify_outcome(
        engine="carrick",
        status=_nonnegative_int(outcome["exit_status"], "W1 exit status"),
        expected_status=0,
        stdout_matches=False,
        gateway_entries=gateway_entries,
        gateway_limit=gateway_limit,
        max_traps_marker=marker,
        ceiling_profile_identity=identity,
    )
    if (
        outcome["kind"] != derived.kind
        or outcome["work_units_completed"] != derived.work_units_completed
        or outcome["work_units_expected"] != derived.work_units_expected
    ):
        raise BudgetError("W1 evidence typed outcome does not reconcile")
    evidence_rel = _string(raw["raw_profile_evidence_path"], "W1 raw evidence path")
    if not evidence_rel or pathlib.PurePosixPath(evidence_rel).is_absolute():
        raise BudgetError("W1 raw evidence path must be a relative artifact path")
    artifact_path = (path.parent / evidence_rel).resolve()
    try:
        artifact_path.relative_to(path.parent.resolve())
    except ValueError as error:
        raise BudgetError(
            f"W1 raw evidence path escapes the evidence root: {evidence_rel}"
        ) from error
    try:
        compressed = artifact_path.read_bytes()
    except OSError as error:
        raise BudgetError(f"W1 raw profile artifact is missing: {artifact_path}") from error
    try:
        raw_bytes = gzip.decompress(compressed)
    except (OSError, gzip.BadGzipFile) as error:
        raise BudgetError(f"W1 raw profile artifact is not gzip data: {artifact_path}") from error
    if hashlib.sha256(raw_bytes).hexdigest() != raw["raw_profile_sha256"]:
        raise BudgetError("W1 raw profile artifact content hash mismatch")
    profile_lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
    profile = parse_nativeperf(profile_lines)
    validate_profile(profile)
    if len(profile.threads) != raw["complete_thread_groups"]:
        raise BudgetError("W1 raw profile thread-group count differs from the summary")
    hottest_thread = max(profile.threads, key=lambda thread: thread.gateway_entries)
    parsed_hottest = {
        "gateway_entries": hottest_thread.gateway_entries,
        "exit_resolve_direct": hottest_thread.value("exits", "exit_resolve_direct"),
        "exit_resolve_indirect": hottest_thread.value("exits", "exit_resolve_indirect"),
        "exit_sensitive": hottest_thread.value("exits", "exit_sensitive"),
        "sensitive_exclusive": hottest_thread.value("sensitive", "sensitive_exclusive"),
    }
    if parsed_hottest != {name: hottest[name] for name in HOTTEST_FIELDS} or (
        hottest_thread.pid,
        hottest_thread.tid,
        hottest_thread.era,
    ) != identity:
        raise BudgetError("W1 raw profile hottest thread differs from the summary")
    parsed_marker = parse_max_traps_marker(profile_lines)
    if parsed_marker != marker:
        raise BudgetError("W1 raw profile max-traps marker differs from the summary")
    if reconcile_max_traps_marker(profile, parsed_marker, gateway_limit) != identity:
        raise BudgetError("W1 raw profile ceiling does not bind the summary identity")
    cleanup = _exact_mapping(
        raw["cleanup"], {"status", "descendants_absent", "receipt_sha256"}, "W1 cleanup"
    )
    if cleanup["status"] != "clean" or cleanup["descendants_absent"] is not True:
        raise BudgetError("W1 evidence cleanup is not clean")
    _require_hash(_string(cleanup["receipt_sha256"], "cleanup receipt hash"), "cleanup receipt hash")
    timing = _exact_mapping(
        raw["timing"], {"wall_ns", "user_ns", "system_ns", "peak_rss_bytes"}, "W1 timing"
    )
    for name, value in timing.items():
        _nonnegative_int(value, f"W1 timing {name}")


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
    capture_raw = _require_type(raw, "capture", dict)
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
    capture = _parse_capture(capture_raw, tuple(env))
    if isinstance(capture, W2Capture):
        validate_w1_profile_evidence(manifest_path, capture)
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
        capture=capture,
        manifest_path=manifest_path,
    )


def stdout_digest(manifest: WorkloadManifest, stdout: bytes) -> str:
    normalization = (
        manifest.capture.stdout_normalization
        if isinstance(manifest.capture, W1Capture)
        else "none"
    )
    if normalization == "go-test-duration":
        stdout = re.sub(rb"\([0-9]+(?:\.[0-9]+)?s\)", b"(<duration>)", stdout)
    elif normalization != "none":
        raise BudgetError(f"unknown stdout normalization: {normalization}")
    return hashlib.sha256(stdout).hexdigest()


def validate_work_product(manifest: WorkloadManifest, stderr_lines: Iterable[str]) -> None:
    if not isinstance(manifest.capture, W2Capture):
        return
    expected_path = manifest.capture.expected_output_guest_path
    expected_digest = manifest.capture.expected_output_sha256
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
        if thread.value("phases-b", "phase_sensitive_emulation_count") != thread.value(
            "exits", "exit_sensitive"
        ):
            raise BudgetError(f"sensitive emulation phase reconciliation mismatch for {identity}")
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


SENSITIVE_ORDER = (
    ("sensitive_exclusive", "exclusive"),
    ("sensitive_read_tpidr", "read-tpidr"),
    ("sensitive_write_tpidr", "write-tpidr"),
    ("sensitive_read_ctr", "read-ctr"),
    ("sensitive_read_dczid", "read-dczid"),
    ("sensitive_dc_zva", "dc-zva"),
    ("sensitive_dc_cvau", "dc-cvau"),
    ("sensitive_ic_ivau", "ic-ivau"),
)
ON_CPU_PHASES = (
    ("phases-a", "phase_prepare_index_ns", "prepare-index"),
    ("phases-a", "phase_translate_ns", "translation"),
    ("phases-a", "phase_translated_run_ns", "translated-run"),
    ("phases-a", "phase_finish_exit_ns", "finish-exit"),
    ("phases-b", "phase_sensitive_emulation_ns", "sensitive-emulation"),
    ("phases-b", "phase_syscall_dispatch_ns", "syscall-dispatch"),
    ("phases-b", "phase_loop_quiesce_ns", "loop-quiesce"),
)


COUNT_SCOPES = ("hottest-thread", "aggregate-threads")


@dataclasses.dataclass(frozen=True)
class CountEvidence:
    scope: str
    sensitive_shares: tuple[tuple[str, float], ...]
    resolver_exit_share: float
    resolver_recurring_pc_verified: bool


@dataclasses.dataclass(frozen=True)
class AdditiveCpuEvidence:
    exclusive_terms_ns: tuple[tuple[str, int], ...]
    exclusive_sum_ns: int
    blocked_ns: int
    residual_ns: int
    residual_share: float
    nested_translation_ns: int
    first_resolution_ns: int | None


def derive_count_evidence(profile: ProfileRun, *, scope: str) -> CountEvidence:
    if scope not in COUNT_SCOPES:
        raise BudgetError(f"unknown count-evidence thread scope: {scope}")
    validate_profile(profile)
    threads = profile.threads
    if scope == "hottest-thread":
        threads = (max(threads, key=lambda thread: thread.gateway_entries),)
    gateway = sum(thread.gateway_entries for thread in threads)
    if gateway <= 0:
        raise BudgetError("profile has no gateway exits")
    sensitive_shares = tuple(
        (
            name,
            sum(thread.value("sensitive", field) for thread in threads) / gateway,
        )
        for field, name in SENSITIVE_ORDER
    )
    resolver_exits = sum(
        thread.value("exits", "exit_resolve_direct")
        + thread.value("exits", "exit_resolve_indirect")
        for thread in threads
    )
    # NATIVEPERF1 deliberately has no guest-PC cardinality.  Exit volume alone
    # cannot prove recurrence; Plane C must supply that independent fact before
    # a resolver slice is selectable.
    return CountEvidence(scope, sensitive_shares, resolver_exits / gateway, False)


def derive_additive_cpu_evidence(profile: ProfileRun, cpu_ns: int) -> AdditiveCpuEvidence:
    if cpu_ns <= 0:
        raise BudgetError("additive profile requires positive measured CPU time")
    validate_profile(profile)
    terms = tuple(
        (
            name,
            sum(thread.value(frame, field) for thread in profile.threads),
        )
        for frame, field, name in ON_CPU_PHASES
    )
    exclusive_sum = sum(value for _, value in terms)
    residual = cpu_ns - exclusive_sum
    if residual < 0:
        raise BudgetError(
            f"negative additive residual: cpu={cpu_ns}, exclusive={exclusive_sum}"
        )
    residual_share = residual / cpu_ns
    if residual_share > 0.02:
        raise BudgetError(
            f"additive CPU reconciliation differs by more than 2%: {residual_share:.6f}"
        )
    blocked_ns = sum(
        thread.value("phases-b", "phase_blocked_ns") for thread in profile.threads
    )
    nested_translation_ns = sum(
        thread.value("resolver-times", "nested_translation_ns") for thread in profile.threads
    )
    return AdditiveCpuEvidence(
        exclusive_terms_ns=terms,
        exclusive_sum_ns=exclusive_sum,
        blocked_ns=blocked_ns,
        residual_ns=residual,
        residual_share=residual_share,
        nested_translation_ns=nested_translation_ns,
        # Task 1 does not emit first-resolution latency.  Leaving this typed as
        # unavailable is the explicit design reconciliation: AOT cannot be
        # selected from nested translation alone.
        first_resolution_ns=None,
    )


def profile_decision_inputs(profile: ProfileRun, cpu_ns: int) -> tuple[tuple[str, float], ...]:
    if cpu_ns <= 0:
        raise BudgetError("profile decision requires positive measured CPU time")
    counts = derive_count_evidence(profile, scope="hottest-thread")
    sensitive = dict(counts.sensitive_shares)
    values = {
        "sensitive_exclusive": sensitive["exclusive"],
        "resolver_recurrence": counts.resolver_exit_share,
        "cold_translation_ns": float(
            sum(
                thread.value("resolver-times", "nested_translation_ns")
                for thread in profile.threads
            )
        ),
        "syscall_dispatch_ns": float(
            sum(
                thread.value("phases-b", "phase_syscall_dispatch_ns")
                for thread in profile.threads
            )
        ),
        "blocked_residual_ns": float(
            sum(
                thread.value("phases-b", "phase_blocked_ns")
                for thread in profile.threads
            )
        ),
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


@dataclasses.dataclass(frozen=True)
class OracleReceipt:
    schema: str
    manifest_sha256: str
    image_digest: str
    executable_sha256: str
    guest_files: tuple[tuple[str, str], ...]
    oracle_status: str


@dataclasses.dataclass(frozen=True)
class CleanupReceipt:
    status: str
    exit_status: int | None
    descendants_absent: bool
    stdout: str
    stderr: str


@dataclasses.dataclass(frozen=True)
class RunOutcome:
    kind: str
    exit_status: int
    work_units_completed: int
    work_units_expected: int
    gateway_entries: int | None
    gateway_limit: int
    ceiling_marker_thread_id: int | None = None
    ceiling_marker_traps: int | None = None
    ceiling_profile_identity: tuple[int, int, int] | None = None


@dataclasses.dataclass(frozen=True)
class MaxTrapsMarker:
    thread_id: int
    traps: int


@dataclasses.dataclass(frozen=True)
class DtraceEvidence:
    complete: bool
    bounded: bool
    incomplete_pairs: int
    raw_path: str
    raw_sha256: str
    drops: tuple[tuple[str, int | bool], ...]
    per_pid_gateway_counts: tuple[tuple[int, int], ...]
    exit_mix: tuple[tuple[int, int], ...]
    ordering: tuple[tuple[str, int, int | None, int], ...]


def validate_oracle_receipt(manifest: WorkloadManifest, receipt: OracleReceipt) -> None:
    if receipt.schema != "carrick.native-compiler-oracle-preflight.v1":
        raise BudgetError("unknown oracle preflight schema")
    if receipt.oracle_status != "verified":
        raise BudgetError("oracle preflight is not verified")
    if receipt.manifest_sha256 != _sha256_path(manifest.manifest_path):
        raise BudgetError("oracle preflight manifest identity mismatch")
    if receipt.image_digest != manifest.image_digest:
        raise BudgetError("oracle preflight image identity mismatch")
    if receipt.executable_sha256 != manifest.executable_sha256:
        raise BudgetError("oracle preflight executable identity mismatch")
    expected_files = tuple(sorted((item.guest_path, item.sha256) for item in manifest.files))
    if receipt.guest_files != expected_files:
        raise BudgetError("oracle preflight guest-file identity mismatch")


MAX_TRAPS_RE = re.compile(
    r"^native Darwin guest thread ([0-9]+) error: guest did not exit after ([0-9]+) traps$"
)


def parse_max_traps_marker(lines: Sequence[str]) -> MaxTrapsMarker | None:
    markers = [
        MaxTrapsMarker(int(match.group(1)), int(match.group(2)))
        for line in lines
        if (match := MAX_TRAPS_RE.fullmatch(line))
    ]
    if not markers:
        return None
    if len(set(markers)) != 1:
        raise BudgetError("conflicting max-traps markers in Carrick stderr")
    return markers[0]


def reconcile_max_traps_marker(
    profile: ProfileRun, marker: MaxTrapsMarker, gateway_limit: int
) -> tuple[int, int, int]:
    matches = [
        (thread.pid, thread.tid, thread.era)
        for thread in profile.threads
        if thread.tid == marker.thread_id and thread.gateway_entries == gateway_limit
    ]
    if marker.traps != gateway_limit or len(matches) != 1:
        raise BudgetError("max-traps marker does not bind one exact profile group at the ceiling")
    return matches[0]


def classify_outcome(
    *,
    engine: str,
    status: int,
    expected_status: int,
    stdout_matches: bool,
    gateway_entries: int | None,
    gateway_limit: int,
    max_traps_marker: MaxTrapsMarker | None = None,
    ceiling_profile_identity: tuple[int, int, int] | None = None,
) -> RunOutcome:
    if engine not in {"carrick", "docker"}:
        raise BudgetError(f"unknown outcome engine: {engine}")
    if max_traps_marker is not None:
        if engine != "carrick" or max_traps_marker.traps != gateway_limit:
            raise BudgetError("max-traps marker does not reconcile to the profile ceiling")
        if gateway_entries is None:
            # Untraced/dtrace planes have no profile: the marker alone types the
            # ceiling, and a profile identity would be unverifiable.
            if ceiling_profile_identity is not None:
                raise BudgetError("ceiling profile identity requires profile evidence")
        elif (
            gateway_entries != gateway_limit
            or ceiling_profile_identity is None
            or ceiling_profile_identity[1] != max_traps_marker.thread_id
        ):
            raise BudgetError("max-traps marker does not reconcile to the profile ceiling")
    if max_traps_marker is None and ceiling_profile_identity is not None:
        raise BudgetError("ceiling profile identity lacks a max-traps marker")
    if max_traps_marker is not None:
        kind = "max-traps"
    elif status == expected_status and stdout_matches:
        kind = "completed"
    else:
        kind = "failed"
    return RunOutcome(
        kind=kind,
        exit_status=status,
        work_units_completed=1 if kind == "completed" else 0,
        work_units_expected=1,
        gateway_entries=gateway_entries,
        gateway_limit=gateway_limit,
        ceiling_marker_thread_id=(
            None if max_traps_marker is None else max_traps_marker.thread_id
        ),
        ceiling_marker_traps=None if max_traps_marker is None else max_traps_marker.traps,
        ceiling_profile_identity=ceiling_profile_identity,
    )


def baseline_schedule(samples: int = 5) -> tuple[tuple[str, str, str, int], ...]:
    if samples <= 0:
        raise BudgetError("baseline samples must be positive")
    schedule = []
    for engine in ("carrick", "docker"):
        schedule.extend(((engine, "w1", "warmup", 0), (engine, "w2", "warmup", 0)))
        for repetition in range(1, samples + 1):
            schedule.extend(
                (
                    (engine, "w1", "measured", repetition),
                    (engine, "w2", "measured", repetition),
                )
            )
    return tuple(schedule)


def carrick_transaction(
    repo: pathlib.Path,
    artifact: pathlib.Path,
    run_id: str,
    operation,
    *,
    cleanup_runner=None,
    absence_checker=None,
):
    artifact.mkdir(parents=True, exist_ok=True)
    if cleanup_runner is None:
        cleanup_runner = lambda scoped_id: subprocess.run(
            ["sudo", "-n", "scripts/sudo/kill.sh", scoped_id],
            cwd=repo,
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
    if absence_checker is None:
        absence_checker = _assert_run_id_absent
    operation_error: BaseException | None = None
    result = None
    try:
        result = operation()
    except BaseException as error:
        operation_error = error
    cleanup_error: BaseException | None = None
    cleanup_result = None
    descendants_absent = False
    try:
        cleanup_result = cleanup_runner(run_id)
        if cleanup_result.returncode != 0:
            raise BudgetError(f"scoped cleanup failed for {run_id}")
        absence_checker(run_id)
        descendants_absent = True
    except BaseException as error:
        cleanup_error = error
    receipt = CleanupReceipt(
        status="clean" if cleanup_error is None else "failed",
        exit_status=getattr(cleanup_result, "returncode", None),
        descendants_absent=descendants_absent,
        stdout=getattr(cleanup_result, "stdout", "") or "",
        stderr=getattr(cleanup_result, "stderr", "") or "",
    )
    _atomic_write_json(artifact / "cleanup.json", dataclasses.asdict(receipt))
    if cleanup_error is not None:
        raise BudgetError(f"scoped cleanup failed for {run_id}: {cleanup_error}") from cleanup_error
    if operation_error is not None:
        raise operation_error
    return result, receipt


def dtrace_command(binary: pathlib.Path, guest_command: Sequence[str], artifact: pathlib.Path) -> list[str]:
    return [
        str(binary),
        "trace",
        "--profile",
        "dsr",
        "--trace-out",
        str(artifact / "dtrace.raw"),
        "--summary-jsonl",
        str(artifact / "dtrace-summary.jsonl"),
        "--",
        *guest_command,
    ]


@dataclasses.dataclass(frozen=True)
class DtraceRaw:
    sha256: str
    ordering: tuple[tuple[str, int, int | None, int], ...]
    counts: tuple[tuple[tuple[str, int, int], int], ...]
    bounded: bool
    target_exit_reason: int


DTRACE_RAW_FIELDS = {
    "sample": {"phase", "pid", "kind", "duration_ns", "interval"},
    "count": {"phase", "pid", "kind", "value"},
    "incomplete": {"phase", "pid", "kind", "value"},
    "total": {"phase", "pid", "kind", "value_ns"},
    "minimum": {"phase", "pid", "kind", "value_ns"},
    "maximum": {"phase", "pid", "kind", "value_ns"},
    "high-water": {"metric", "pid", "used", "capacity"},
    "complete": {"profile", "bounded", "target_exit_reason"},
}


def parse_dtrace_raw(path: pathlib.Path) -> DtraceRaw:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise BudgetError(f"cannot read DTrace raw trace {path}: {error}") from error
    ordering: list[tuple[str, int, int | None, int]] = []
    counts: dict[tuple[str, int, int], int] = {}
    completes: list[tuple[bool, int]] = []
    for number, line in enumerate(lines, 1):
        parts = line.split("|")
        if len(parts) < 3 or parts[0] != "DSRPROF1":
            raise BudgetError(f"malformed DTrace raw record {number}")
        kind = parts[1]
        required = DTRACE_RAW_FIELDS.get(kind)
        if required is None:
            raise BudgetError(f"unknown DTrace raw record kind on record {number}: {kind}")
        fields: dict[str, str] = {}
        for item in parts[2:]:
            key, separator, value = item.partition("=")
            if not separator or not key or key in fields:
                raise BudgetError(f"malformed DTrace raw field on record {number}: {item}")
            fields[key] = value
        allowed = required | ({"tid"} if "phase" in required else set())
        if set(fields) - allowed or required - set(fields):
            raise BudgetError(f"DTrace raw record {number} has unknown or missing fields")
        if completes:
            raise BudgetError("DTrace raw records continue after the completion record")
        if kind == "complete":
            if fields["profile"] != "dsr" or fields["bounded"] not in {"0", "1"}:
                raise BudgetError("DTrace raw completion record is malformed")
            completes.append(
                (
                    fields["bounded"] == "1",
                    _parse_decimal(fields["target_exit_reason"], "target_exit_reason"),
                )
            )
            continue
        if kind == "high-water":
            if not fields["metric"]:
                raise BudgetError(f"DTrace raw record {number} lacks a metric name")
            _parse_decimal(fields["pid"], "pid")
            _parse_decimal(fields["used"], "used")
            _parse_decimal(fields["capacity"], "capacity")
            continue
        phase = fields["phase"]
        if not phase:
            raise BudgetError(f"DTrace raw record {number} lacks a phase")
        pid = _parse_decimal(fields["pid"], "pid")
        if kind == "incomplete":
            # Incomplete records name the pending pair by kind; only a zero
            # count is acceptable evidence.
            if not fields["kind"]:
                raise BudgetError(f"DTrace raw record {number} lacks an exit kind")
            if _parse_decimal(fields["value"], "value") != 0:
                raise BudgetError(f"DTrace raw record {number} reports incomplete pairs")
            continue
        exit_kind = _parse_decimal(fields["kind"], "kind")
        if kind == "sample":
            tid = _parse_decimal(fields["tid"], "tid") if "tid" in fields else None
            _parse_decimal(fields["duration_ns"], "duration_ns")
            _parse_decimal(fields["interval"], "interval")
            ordering.append((phase, pid, tid, exit_kind))
        elif kind == "count":
            value = _parse_decimal(fields["value"], "value")
            key = (phase, pid, exit_kind)
            counts[key] = counts.get(key, 0) + value
        else:
            _parse_decimal(fields["value_ns"], "value_ns")
    if len(completes) != 1:
        raise BudgetError("DTrace raw trace requires exactly one final completion record")
    bounded, target_exit_reason = completes[0]
    return DtraceRaw(
        sha256=_sha256_path(path),
        ordering=tuple(ordering),
        counts=tuple(sorted(counts.items())),
        bounded=bounded,
        target_exit_reason=target_exit_reason,
    )


def parse_dtrace_summary(
    path: pathlib.Path, *, expected_run_id: str, raw_path: pathlib.Path
) -> DtraceEvidence:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        try:
            row = json.loads(line, object_pairs_hook=_pairs_no_duplicates)
        except json.JSONDecodeError as error:
            raise BudgetError(f"malformed DTrace summary row {line_number}: {error}") from error
        if not isinstance(row, dict):
            raise BudgetError("DTrace summary rows must be objects")
        allowed = {
            "schema",
            "profile",
            "run_id",
            "git_sha",
            "git_dirty",
            "binary_sha256",
            "command",
            "host",
            "scope",
            "metric",
            "sampling_interval",
            "completion",
        }
        if set(row) - allowed or allowed - {"git_dirty", "sampling_interval"} - set(row):
            raise BudgetError("DTrace summary row has unknown or missing fields")
        if row["schema"] != "carrick.dsr-profile.v1" or row["profile"] != "dsr":
            raise BudgetError("DTrace summary schema/profile mismatch")
        if row["run_id"] != expected_run_id:
            raise BudgetError("DTrace summary run-id mismatch")
        rows.append(row)
    if not rows:
        raise BudgetError("DTrace summary is empty")
    completion = rows[0]["completion"]
    completion_fields = {
        "complete",
        "bounded",
        "target_exit_reason",
        "high_cardinality_overflow",
        "incomplete_pairs",
        "cardinality",
        "drops",
    }
    if not isinstance(completion, dict) or set(completion) != completion_fields:
        raise BudgetError("DTrace completion record is malformed")
    if any(row["completion"] != completion for row in rows):
        raise BudgetError("DTrace completion metadata differs across rows")
    drops = completion["drops"]
    drop_fields = {
        "interrupted",
        "principal_drops",
        "aggregation_drops",
        "dynamic_drops",
        "other_drops",
    }
    if not isinstance(drops, dict) or set(drops) != drop_fields:
        raise BudgetError("DTrace drop record is malformed")
    if completion["incomplete_pairs"] != 0:
        raise BudgetError("DTrace summary has incomplete pairs")
    if any(bool(value) for value in drops.values()):
        raise BudgetError("DTrace summary reports drops or interruption")
    if completion["bounded"] or not completion["complete"] or completion[
        "target_exit_reason"
    ] != 1:
        raise BudgetError("DTrace summary did not complete naturally and unbounded")
    if completion["high_cardinality_overflow"]:
        raise BudgetError("DTrace summary overflowed cardinality")
    phase_pid_counts: dict[tuple[str, int], int] = {}
    kind_counts: dict[tuple[str, int, int], int] = {}
    exit_mix: dict[int, int] = {}
    completion_rows = 0
    for row in rows:
        scope = row["scope"]
        metric = row["metric"]
        if not isinstance(scope, dict) or not isinstance(metric, dict):
            raise BudgetError("DTrace scope/metric must be objects")
        if set(scope) - {"phase", "pid", "tid", "kind", "source_pc", "target_pc"}:
            raise BudgetError("DTrace scope has unknown fields")
        metric_type = metric.get("type")
        if metric_type not in {
            "exact",
            "sampled-duration",
            "high-water",
            "completion",
            "incomplete-pair",
        }:
            raise BudgetError(f"unknown DTrace metric type: {metric_type!r}")
        if metric_type == "completion":
            if set(metric) != {"type"} or scope:
                raise BudgetError("DTrace completion metric is malformed")
            completion_rows += 1
            continue
        phase = scope.get("phase")
        pid = scope.get("pid")
        raw_kind = scope.get("kind")
        kind = None
        if raw_kind is not None:
            if (
                not isinstance(raw_kind, str)
                or not raw_kind.isascii()
                or not raw_kind.isdecimal()
                or (len(raw_kind) > 1 and raw_kind.startswith("0"))
            ):
                raise BudgetError("DTrace kind must be a canonical decimal string")
            kind = int(raw_kind)
        if metric_type == "incomplete-pair":
            raise BudgetError("DTrace summary contains an incomplete metric row")
        if metric_type != "exact":
            continue
        if set(metric) - {"type", "count", "total_ns", "minimum_ns", "maximum_ns"}:
            raise BudgetError("DTrace exact metric has unknown fields")
        count = metric.get("count")
        if count is None:
            continue
        if not isinstance(count, int) or count < 0 or not isinstance(pid, int) or not isinstance(
            phase, str
        ):
            raise BudgetError("DTrace count metric lacks typed phase/pid/count")
        if kind is None:
            raise BudgetError("DTrace count metric lacks an exit kind")
        phase_pid_counts[(phase, pid)] = phase_pid_counts.get((phase, pid), 0) + count
        kind_counts[(phase, pid, kind)] = kind_counts.get((phase, pid, kind), 0) + count
        if phase == "run":
            exit_mix[kind] = exit_mix.get(kind, 0) + count
    if completion_rows != 1:
        raise BudgetError("DTrace summary requires exactly one completion row")
    run_counts = {pid: count for (phase, pid), count in phase_pid_counts.items() if phase == "run"}
    prepare_counts = {
        pid: count for (phase, pid), count in phase_pid_counts.items() if phase == "prepare"
    }
    if not run_counts or run_counts != prepare_counts:
        raise BudgetError("DTrace per-PID prepare/run count mismatch")
    raw = parse_dtrace_raw(raw_path)
    if raw.counts != tuple(sorted(kind_counts.items())):
        raise BudgetError("DTrace raw count aggregates do not reconcile with the summary")
    if raw.bounded != completion["bounded"] or raw.target_exit_reason != completion[
        "target_exit_reason"
    ]:
        raise BudgetError("DTrace raw completion does not reconcile with the summary")
    return DtraceEvidence(
        complete=True,
        bounded=False,
        incomplete_pairs=0,
        raw_path=raw_path.name,
        raw_sha256=raw.sha256,
        drops=tuple(sorted(drops.items())),
        per_pid_gateway_counts=tuple(sorted(run_counts.items())),
        exit_mix=tuple(sorted(exit_mix.items())),
        ordering=raw.ordering,
    )


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
    record: str
    engine: str
    workload: str
    plane: str
    repetition: int
    schedule_label: str
    run_id: str
    binary_sha256: str
    manifest_sha256: str
    preflight_sha256: str | None
    timing: TimeRecord
    monotonic_elapsed_ns: int | None
    outcome: RunOutcome
    cleanup: CleanupReceipt
    profile: ProfileRun | None
    dtrace: DtraceEvidence | None = None

    @classmethod
    def synthetic(
        cls,
        *,
        profile: ProfileRun | None = None,
        outcome: RunOutcome | None = None,
        plane: str = "profiled",
        repetition: int = 1,
        run_id: str = "synthetic",
        schedule_label: str = "",
        wall_ns: int = 1,
        cpu_ns: int = 1,
    ) -> "RunRecord":
        if outcome is None:
            gateway = (
                max(thread.gateway_entries for thread in profile.threads)
                if profile is not None
                else None
            )
            outcome = RunOutcome("completed", 0, 1, 1, gateway, 1_000_000)
        return cls(
            RESULT_SCHEMA,
            "run",
            "carrick",
            "synthetic",
            plane,
            repetition,
            schedule_label,
            run_id,
            "b" * 64,
            "1" * 64,
            "2" * 64,
            TimeRecord(wall_ns, cpu_ns, 0, 1),
            wall_ns,
            outcome,
            CleanupReceipt("clean", 0, True, "", ""),
            profile,
        )

    @property
    def wall_ns(self) -> int:
        return self.timing.wall_ns

    @property
    def user_ns(self) -> int:
        return self.timing.user_ns

    @property
    def system_ns(self) -> int:
        return self.timing.system_ns

    @property
    def peak_rss_bytes(self) -> int:
        return self.timing.peak_rss_bytes


@dataclasses.dataclass(frozen=True)
class DecisionRecord:
    schema: str
    record: str
    selected_slice: str
    share: float
    basis: str
    scope: str
    supporting_run_ids: tuple[str, ...]
    profile_tax: float | None
    duration_evidence_usable: bool


def _resolver_recurrence_verified(records: Sequence[RunRecord]) -> bool:
    # The broad Plane C row retains exact ordering and mix but no source-PC
    # recurrence.  Never promote resolver volume into recurrence without that
    # independently produced field.
    return False


def _mean(values: Sequence[float], name: str) -> float:
    if not values or any(value < 0 or value > 1 for value in values):
        raise BudgetError(f"analysis share outside [0,1]: {name}")
    return sum(values) / len(values)


def analyze(records: Sequence[RunRecord]) -> DecisionRecord:
    if not records:
        raise BudgetError("analysis requires evidence records")
    if any(record.schema != RESULT_SCHEMA or record.record != "run" for record in records):
        raise BudgetError("analysis record has unknown schema/tag")
    if any(record.outcome.kind != "completed" for record in records):
        raise BudgetError("analysis accepts completed outcomes only")
    abba = [record for record in records if record.schedule_label.startswith(("off-", "on-"))]
    if tuple(record.schedule_label for record in abba) != abba_schedule(samples=5):
        raise BudgetError("analysis requires exact ABBA order including warmups")
    for record in abba:
        expected_plane = "untraced" if record.schedule_label.startswith("off-") else "profiled"
        expected_repetition = (
            0
            if record.schedule_label.endswith("warmup")
            else int(record.schedule_label.rsplit("-", 1)[1])
        )
        if (
            record.engine != "carrick"
            or record.plane != expected_plane
            or record.repetition != expected_repetition
            or record.cleanup.status != "clean"
            or not record.cleanup.descendants_absent
        ):
            raise BudgetError("ABBA engine/plane/repetition/cleanup metadata is invalid")
    if len({record.workload for record in abba}) != 1 or len(
        {record.binary_sha256 for record in abba}
    ) != 1 or len({record.manifest_sha256 for record in abba}) != 1 or len(
        {record.preflight_sha256 for record in abba}
    ) != 1:
        raise BudgetError("analysis requires one workload, binary, manifest, and preflight")
    measured = [record for record in abba if not record.schedule_label.endswith("warmup")]
    untraced = [record for record in measured if record.plane == "untraced"]
    profiled = [record for record in measured if record.plane == "profiled"]
    if len(untraced) != 5 or len(profiled) != 5:
        raise BudgetError("analysis requires five measured ABBA samples per mode")
    if any(record.profile is None for record in profiled):
        raise BudgetError("profiled count evidence is missing")
    off_wall = statistics.median(record.wall_ns for record in untraced)
    on_wall = statistics.median(record.wall_ns for record in profiled)
    if off_wall <= 0:
        raise BudgetError("untraced ABBA wall median must be positive")
    profile_tax = on_wall / off_wall - 1.0
    duration_usable = profile_tax <= 0.10
    # The additive duration model is a validity gate on every profiled run:
    # a negative or >2% residual invalidates the evidence before any decision,
    # including count-based ones.
    additive = [
        derive_additive_cpu_evidence(record.profile, record.user_ns + record.system_ns)
        for record in profiled
        if record.profile is not None
    ]
    scoped_counts = {
        scope: [
            derive_count_evidence(record.profile, scope=scope)
            for record in profiled
            if record.profile is not None
        ]
        for scope in COUNT_SCOPES
    }
    scoped_sensitive = {
        scope: {
            name: _mean(
                [dict(evidence.sensitive_shares)[name] for evidence in count_evidence], name
            )
            for _, name in SENSITIVE_ORDER
        }
        for scope, count_evidence in scoped_counts.items()
    }
    sensitive_slice_by_scope = {
        scope: next((name for _, name in SENSITIVE_ORDER if shares[name] >= 0.30), None)
        for scope, shares in scoped_sensitive.items()
    }
    if len(set(sensitive_slice_by_scope.values())) != 1:
        raise BudgetError(
            "count-evidence thread scopes disagree on the sensitive slice: "
            + ", ".join(
                f"{scope}={name}" for scope, name in sorted(sensitive_slice_by_scope.items())
            )
        )
    agreed_sensitive = sensitive_slice_by_scope["hottest-thread"]
    if agreed_sensitive is not None:
        return DecisionRecord(
            RESULT_SCHEMA,
            "decision",
            f"sensitive-{agreed_sensitive}",
            scoped_sensitive["hottest-thread"][agreed_sensitive],
            "reconciled-profile-counts",
            "hottest-thread+aggregate-threads",
            tuple(record.run_id for record in profiled),
            profile_tax,
            duration_usable,
        )
    resolver_by_scope = {
        scope: _mean(
            [evidence.resolver_exit_share for evidence in count_evidence],
            "resolver-exit-share",
        )
        for scope, count_evidence in scoped_counts.items()
    }
    if all(share >= 0.30 for share in resolver_by_scope.values()) and _resolver_recurrence_verified(
        records
    ):
        return DecisionRecord(
            RESULT_SCHEMA,
            "decision",
            "resolver-recurrence",
            resolver_by_scope["hottest-thread"],
            "reconciled-profile-counts-plus-recurring-pc-proof",
            "hottest-thread+aggregate-threads",
            tuple(record.run_id for record in profiled),
            profile_tax,
            duration_usable,
        )
    duration_shares: dict[str, float] = {}
    if duration_usable:
        untraced_cpu = statistics.median(record.user_ns + record.system_ns for record in untraced)
        if untraced_cpu <= 0:
            raise BudgetError("untraced ABBA CPU median must be positive")
        syscall_ns = statistics.median(
            dict(evidence.exclusive_terms_ns)["syscall-dispatch"] for evidence in additive
        )
        duration_shares["syscall-dispatch"] = syscall_ns / untraced_cpu
        if any(value < 0 or value > 1 for value in duration_shares.values()):
            raise BudgetError("duration evidence does not reconcile to untraced CPU")
        if duration_shares["syscall-dispatch"] >= 0.30:
            return DecisionRecord(
                RESULT_SCHEMA,
                "decision",
                "syscall-dispatch",
                duration_shares["syscall-dispatch"],
                "low-tax-exclusive-profile-duration-over-untraced-cpu",
                "process-cpu",
                tuple(record.run_id for record in abba),
                profile_tax,
                True,
            )
        blocked_ns = statistics.median(evidence.blocked_ns for evidence in additive)
        # Aggregated thread blocked time can exceed process wall; the trigger
        # saturates at 1.0 rather than pretending to be a partition share, and
        # the basis names the saturation so 1.0 is never ambiguous.
        blocked_ratio = blocked_ns / off_wall
        blocked_share = min(blocked_ratio, 1.0)
        if blocked_share >= 0.30:
            basis = "low-tax-blocked-off-cpu-over-untraced-wall"
            if blocked_ratio > 1.0:
                basis += "-saturated"
            return DecisionRecord(
                RESULT_SCHEMA,
                "decision",
                "blocked-residual",
                blocked_share,
                basis,
                "process-wall",
                tuple(record.run_id for record in abba),
                profile_tax,
                True,
            )

    # Two-term fallback is evaluated within one denominator only.  Count and
    # CPU fractions are never added to one another.
    def two_term_best(terms: list[tuple[float, str]]) -> tuple[float, str, str] | None:
        candidates = sorted(
            (
                (left[0] + right[0], left[1], right[1])
                for index, left in enumerate(terms)
                for right in terms[index + 1 :]
                if left[0] + right[0] >= 0.60
            ),
            key=lambda item: (item[0], item[1], item[2]),
        )
        return candidates[0] if candidates else None

    count_best = {}
    for scope in COUNT_SCOPES:
        count_terms = [
            (share, f"sensitive-{name}") for name, share in scoped_sensitive[scope].items()
        ]
        if _resolver_recurrence_verified(records):
            count_terms.append((resolver_by_scope[scope], "resolver-recurrence"))
        count_best[scope] = two_term_best(count_terms)
    selected_pairs = {
        None if best is None else (best[1], best[2]) for best in count_best.values()
    }
    if len(selected_pairs) != 1:
        raise BudgetError("count-evidence thread scopes disagree on the two-term slice")
    best = count_best["hottest-thread"]
    if best is not None:
        share, left, right = best
        return DecisionRecord(
            RESULT_SCHEMA,
            "decision",
            f"{left}+{right}",
            share,
            "two-term-profile-counts",
            "hottest-thread+aggregate-threads",
            tuple(record.run_id for record in profiled),
            profile_tax,
            duration_usable,
        )
    duration_best = (
        two_term_best([(share, name) for name, share in duration_shares.items()])
        if duration_usable
        else None
    )
    if duration_best is not None:
        share, left, right = duration_best
        return DecisionRecord(
            RESULT_SCHEMA,
            "decision",
            f"{left}+{right}",
            share,
            "two-term-profile-durations",
            "process-cpu",
            tuple(record.run_id for record in profiled),
            profile_tax,
            duration_usable,
        )
    if not duration_usable:
        raise BudgetError(
            f"duration evidence unavailable: ABBA profile tax {profile_tax:.3f} exceeds 0.10"
        )
    raise BudgetError("no independently verified slice satisfies the committed rule")


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


def _profile_json(profile: ProfileRun | None) -> object:
    if profile is None:
        return None
    return {
        "threads": [
            {
                "pid": thread.pid,
                "tid": thread.tid,
                "era": thread.era,
                "frames": sorted(thread.frames),
                "values": dict(thread.values),
            }
            for thread in profile.threads
        ]
    }


def _dtrace_json(evidence: DtraceEvidence | None) -> object:
    if evidence is None:
        return None
    return {
        "complete": evidence.complete,
        "bounded": evidence.bounded,
        "incomplete_pairs": evidence.incomplete_pairs,
        "raw_path": evidence.raw_path,
        "raw_sha256": evidence.raw_sha256,
        "drops": dict(evidence.drops),
        "per_pid_gateway_counts": [list(item) for item in evidence.per_pid_gateway_counts],
        "exit_mix": [list(item) for item in evidence.exit_mix],
        "ordering": [list(item) for item in evidence.ordering],
    }


def run_record_json(record: RunRecord) -> dict[str, object]:
    return {
        "schema": record.schema,
        "record": record.record,
        "engine": record.engine,
        "workload": record.workload,
        "plane": record.plane,
        "repetition": record.repetition,
        "schedule_label": record.schedule_label,
        "run_id": record.run_id,
        "provenance": {
            "binary_sha256": record.binary_sha256,
            "manifest_sha256": record.manifest_sha256,
            "preflight_sha256": record.preflight_sha256,
        },
        "timing": {
            "wall_ns": record.timing.wall_ns,
            "user_ns": record.timing.user_ns,
            "system_ns": record.timing.system_ns,
            "peak_rss_bytes": record.timing.peak_rss_bytes,
            "monotonic_elapsed_ns": record.monotonic_elapsed_ns,
        },
        "outcome": dataclasses.asdict(record.outcome),
        "cleanup": dataclasses.asdict(record.cleanup),
        "profile": _profile_json(record.profile),
        "dtrace": _dtrace_json(record.dtrace),
    }


def decision_record_json(record: DecisionRecord) -> dict[str, object]:
    value = dataclasses.asdict(record)
    value["supporting_run_ids"] = list(record.supporting_run_ids)
    return value


def _exact_mapping(value: object, fields: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BudgetError(f"{name} must be an object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        raise BudgetError(f"unknown {name} field(s): {', '.join(sorted(unknown))}")
    if missing:
        raise BudgetError(f"missing {name} field(s): {', '.join(sorted(missing))}")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BudgetError(f"{name} must be a non-negative integer")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise BudgetError(f"{name} must be a string")
    return value


def _parse_profile_json(value: object) -> ProfileRun | None:
    if value is None:
        return None
    raw = _exact_mapping(value, {"threads"}, "profile")
    threads_raw = raw["threads"]
    if not isinstance(threads_raw, list):
        raise BudgetError("profile threads must be an array")
    threads = []
    for entry in threads_raw:
        thread = _exact_mapping(entry, {"pid", "tid", "era", "frames", "values"}, "profile thread")
        frames = thread["frames"]
        values = thread["values"]
        if not isinstance(frames, list) or frames != sorted(REQUIRED_FRAMES):
            raise BudgetError("profile thread frames are not the exact required set")
        if not isinstance(values, dict) or not all(isinstance(key, str) for key in values):
            raise BudgetError("profile thread values must be an object")
        expected_keys = {
            f"{frame}.{field}"
            for frame, fields in FRAME_FIELDS.items()
            for field in fields
        }
        unknown_keys = set(values) - expected_keys
        missing_keys = expected_keys - set(values)
        if unknown_keys or missing_keys:
            raise BudgetError(
                "profile value keys are not the exact flattened frame set: "
                + ", ".join(sorted(unknown_keys | missing_keys))
            )
        parsed_values = tuple(
            sorted((key, _nonnegative_int(item, f"profile value {key}")) for key, item in values.items())
        )
        threads.append(
            ProfileThread(
                _nonnegative_int(thread["pid"], "profile pid"),
                _nonnegative_int(thread["tid"], "profile tid"),
                _nonnegative_int(thread["era"], "profile era"),
                frozenset(frames),
                parsed_values,
            )
        )
    profile = ProfileRun(tuple(threads))
    validate_profile(profile)
    return profile


def _parse_dtrace_json(value: object) -> DtraceEvidence | None:
    if value is None:
        return None
    raw = _exact_mapping(
        value,
        {
            "complete",
            "bounded",
            "incomplete_pairs",
            "raw_path",
            "raw_sha256",
            "drops",
            "per_pid_gateway_counts",
            "exit_mix",
            "ordering",
        },
        "dtrace",
    )
    if raw["complete"] is not True or raw["bounded"] is not False:
        raise BudgetError("DTrace typed evidence is incomplete or bounded")
    raw_artifact_path = _string(raw["raw_path"], "DTrace raw_path")
    if not raw_artifact_path:
        raise BudgetError("DTrace raw_path must be a non-empty artifact name")
    _require_hash(_string(raw["raw_sha256"], "DTrace raw_sha256"), "DTrace raw_sha256")
    drops = raw["drops"]
    if not isinstance(drops, dict) or not all(
        isinstance(key, str)
        and (
            item is False
            or (isinstance(item, int) and not isinstance(item, bool) and item == 0)
        )
        for key, item in drops.items()
    ):
        raise BudgetError("DTrace typed drops must be an object")

    def pairs(name: str) -> tuple[tuple[int, int], ...]:
        value = raw[name]
        if not isinstance(value, list) or not all(
            isinstance(item, list)
            and len(item) == 2
            and all(isinstance(part, int) and not isinstance(part, bool) and part >= 0 for part in item)
            for item in value
        ):
            raise BudgetError(f"DTrace typed {name} is malformed")
        return tuple((item[0], item[1]) for item in value)

    ordering_raw = raw["ordering"]
    if not isinstance(ordering_raw, list):
        raise BudgetError("DTrace typed ordering is malformed")
    ordering = []
    for item in ordering_raw:
        if (
            not isinstance(item, list)
            or len(item) != 4
            or not isinstance(item[0], str)
            or not item[0]
            or not isinstance(item[1], int)
            or isinstance(item[1], bool)
            or item[1] < 0
            or not (
                item[2] is None
                or (isinstance(item[2], int) and not isinstance(item[2], bool) and item[2] >= 0)
            )
            or not isinstance(item[3], int)
            or isinstance(item[3], bool)
            or item[3] < 0
        ):
            raise BudgetError("DTrace typed ordering is malformed")
        ordering.append((item[0], item[1], item[2], item[3]))
    if _nonnegative_int(raw["incomplete_pairs"], "DTrace incomplete pairs") != 0:
        raise BudgetError("DTrace typed evidence must have zero incomplete pairs")
    return DtraceEvidence(
        True,
        False,
        0,
        raw_artifact_path,
        str(raw["raw_sha256"]),
        tuple(sorted(drops.items())),
        pairs("per_pid_gateway_counts"),
        pairs("exit_mix"),
        tuple(ordering),
    )


ABBA_LABEL_RE = re.compile(r"^(off|on)-(warmup|[1-9][0-9]*)$")
BASELINE_LABEL_RE = re.compile(r"^baseline-(w1|w2)-(warmup|measured)-(0|[1-9][0-9]*)$")
DOCKER_BINARY_SENTINEL = "0" * 64


def _validate_run_cross_fields(record: RunRecord) -> None:
    if record.engine == "docker":
        if record.plane != "untraced":
            raise BudgetError("Docker rows must be untraced oracle phases")
        if record.preflight_sha256 is not None:
            raise BudgetError("Docker rows must not carry a Carrick preflight receipt")
        if record.binary_sha256 != DOCKER_BINARY_SENTINEL:
            raise BudgetError("Docker rows must carry the placeholder binary identity")
        if record.cleanup.status != "not-required" or not record.cleanup.descendants_absent:
            raise BudgetError("Docker rows must record not-required cleanup")
        if record.outcome.kind == "max-traps":
            raise BudgetError("Docker rows cannot reach the Carrick trap ceiling")
    else:
        if record.preflight_sha256 is None:
            raise BudgetError("Carrick rows require a Docker-only preflight receipt")
        if record.binary_sha256 == DOCKER_BINARY_SENTINEL:
            raise BudgetError("Carrick rows must carry the measured binary identity")
        if record.cleanup.status != "clean" or not record.cleanup.descendants_absent:
            raise BudgetError("Carrick rows require clean scoped cleanup")
    if (record.plane == "profiled") != (record.profile is not None):
        raise BudgetError("profile evidence must match the profiled plane")
    if (record.plane == "dtrace") != (record.dtrace is not None):
        raise BudgetError("DTrace evidence must match the dtrace plane")
    if record.profile is not None:
        expected_gateway = max(
            thread.gateway_entries for thread in record.profile.threads
        )
        if record.outcome.gateway_entries != expected_gateway:
            raise BudgetError("outcome gateway count does not reconcile with the profile")
    elif record.outcome.gateway_entries is not None:
        raise BudgetError("gateway count requires profile evidence")
    label = record.schedule_label
    if label:
        abba = ABBA_LABEL_RE.fullmatch(label)
        baseline = BASELINE_LABEL_RE.fullmatch(label)
        if abba:
            if record.engine != "carrick":
                raise BudgetError("ABBA rows must run under Carrick")
            expected_plane = "untraced" if abba.group(1) == "off" else "profiled"
            expected_repetition = (
                0 if abba.group(2) == "warmup" else int(abba.group(2))
            )
            if record.plane != expected_plane or record.repetition != expected_repetition:
                raise BudgetError("ABBA label does not match plane/repetition")
        elif baseline:
            expected_repetition = int(baseline.group(3))
            if baseline.group(2) == "warmup" and expected_repetition != 0:
                raise BudgetError("baseline warmup label must be repetition zero")
            if record.plane != "untraced" or record.repetition != expected_repetition:
                raise BudgetError("baseline label does not match plane/repetition")
        else:
            raise BudgetError(f"unknown schedule label: {label}")


def parse_result_row(value: object) -> RunRecord:
    raw = _exact_mapping(
        value,
        {
            "schema",
            "record",
            "engine",
            "workload",
            "plane",
            "repetition",
            "schedule_label",
            "run_id",
            "provenance",
            "timing",
            "outcome",
            "cleanup",
            "profile",
            "dtrace",
        },
        "run",
    )
    if raw["schema"] != RESULT_SCHEMA or raw["record"] != "run":
        raise BudgetError("unknown result schema/tag")
    engine = _string(raw["engine"], "engine")
    plane = _string(raw["plane"], "plane")
    if engine not in {"carrick", "docker"} or plane not in {"untraced", "profiled", "dtrace"}:
        raise BudgetError("unknown engine or plane")
    provenance = _exact_mapping(
        raw["provenance"],
        {"binary_sha256", "manifest_sha256", "preflight_sha256"},
        "provenance",
    )
    timing = _exact_mapping(
        raw["timing"],
        {"wall_ns", "user_ns", "system_ns", "peak_rss_bytes", "monotonic_elapsed_ns"},
        "timing",
    )
    outcome = _exact_mapping(
        raw["outcome"],
        {
            "kind",
            "exit_status",
            "work_units_completed",
            "work_units_expected",
            "gateway_entries",
            "gateway_limit",
            "ceiling_marker_thread_id",
            "ceiling_marker_traps",
            "ceiling_profile_identity",
        },
        "outcome",
    )
    cleanup = _exact_mapping(
        raw["cleanup"],
        {"status", "exit_status", "descendants_absent", "stdout", "stderr"},
        "cleanup",
    )
    if not isinstance(outcome["kind"], str) or outcome["kind"] not in {
        "completed",
        "max-traps",
        "failed",
    }:
        raise BudgetError("unknown outcome kind")
    gateway_entries = outcome["gateway_entries"]
    if gateway_entries is not None:
        gateway_entries = _nonnegative_int(gateway_entries, "gateway entries")
    ceiling_marker = outcome["ceiling_marker_traps"]
    if ceiling_marker is not None:
        ceiling_marker = _nonnegative_int(ceiling_marker, "ceiling marker traps")
    marker_thread_id = outcome["ceiling_marker_thread_id"]
    if marker_thread_id is not None:
        marker_thread_id = _nonnegative_int(marker_thread_id, "ceiling marker thread id")
    identity_raw = outcome["ceiling_profile_identity"]
    ceiling_identity = None
    if identity_raw is not None:
        if not isinstance(identity_raw, (list, tuple)) or len(identity_raw) != 3:
            raise BudgetError("ceiling profile identity must be pid/tid/era")
        ceiling_identity = tuple(
            _nonnegative_int(item, "ceiling profile identity") for item in identity_raw
        )
    monotonic = timing["monotonic_elapsed_ns"]
    if monotonic is not None:
        monotonic = _nonnegative_int(monotonic, "monotonic diagnostic")
    outcome_kind = _string(outcome["kind"], "outcome kind")
    exit_status = _nonnegative_int(outcome["exit_status"], "exit status")
    completed = _nonnegative_int(outcome["work_units_completed"], "completed work units")
    expected = _nonnegative_int(outcome["work_units_expected"], "expected work units")
    gateway_limit = _nonnegative_int(outcome["gateway_limit"], "gateway limit")
    if expected == 0 or completed > expected:
        raise BudgetError("outcome work-unit metadata is invalid")
    if outcome_kind == "completed" and completed != expected:
        raise BudgetError("completed outcome did not complete every work unit")
    if outcome_kind == "max-traps":
        if ceiling_marker != gateway_limit or marker_thread_id is None:
            raise BudgetError("max-traps outcome lacks ceiling evidence")
        if gateway_entries is None:
            if ceiling_identity is not None:
                raise BudgetError("profile-less max-traps outcome carries a profile identity")
        elif (
            gateway_entries != gateway_limit
            or ceiling_identity is None
            or ceiling_identity[1] != marker_thread_id
        ):
            raise BudgetError("max-traps outcome lacks ceiling evidence")
    if outcome_kind != "max-traps" and any(
        value is not None for value in (ceiling_marker, marker_thread_id, ceiling_identity)
    ):
        raise BudgetError("non-max-traps outcome carries ceiling evidence")
    cleanup_status = _string(cleanup["status"], "cleanup status")
    if cleanup_status not in {"clean", "failed", "not-required"}:
        raise BudgetError("unknown cleanup status")
    if not isinstance(cleanup["descendants_absent"], bool):
        raise BudgetError("cleanup descendants_absent must be a boolean")
    binary_sha = _string(provenance["binary_sha256"], "binary_sha256")
    manifest_sha = _string(provenance["manifest_sha256"], "manifest_sha256")
    _require_hash(binary_sha, "binary_sha256")
    _require_hash(manifest_sha, "manifest_sha256")
    preflight = provenance["preflight_sha256"]
    if preflight is not None:
        preflight = _string(preflight, "preflight_sha256")
        _require_hash(preflight, "preflight_sha256")
    record = RunRecord(
        schema=RESULT_SCHEMA,
        record="run",
        engine=engine,
        workload=_string(raw["workload"], "workload"),
        plane=plane,
        repetition=_nonnegative_int(raw["repetition"], "repetition"),
        schedule_label=_string(raw["schedule_label"], "schedule_label"),
        run_id=_string(raw["run_id"], "run_id"),
        binary_sha256=binary_sha,
        manifest_sha256=manifest_sha,
        preflight_sha256=preflight,
        timing=TimeRecord(
            _nonnegative_int(timing["wall_ns"], "wall_ns"),
            _nonnegative_int(timing["user_ns"], "user_ns"),
            _nonnegative_int(timing["system_ns"], "system_ns"),
            _nonnegative_int(timing["peak_rss_bytes"], "peak_rss_bytes"),
        ),
        monotonic_elapsed_ns=monotonic,
        outcome=RunOutcome(
            outcome_kind,
            exit_status,
            completed,
            expected,
            gateway_entries,
            gateway_limit,
            marker_thread_id,
            ceiling_marker,
            ceiling_identity,
        ),
        cleanup=CleanupReceipt(
            cleanup_status,
            None
            if cleanup["exit_status"] is None
            else _nonnegative_int(cleanup["exit_status"], "cleanup exit status"),
            cleanup["descendants_absent"],
            _string(cleanup["stdout"], "cleanup stdout"),
            _string(cleanup["stderr"], "cleanup stderr"),
        ),
        profile=_parse_profile_json(raw["profile"]),
        dtrace=_parse_dtrace_json(raw["dtrace"]),
    )
    _validate_run_cross_fields(record)
    return record


def _parse_decision_row(value: object) -> DecisionRecord:
    raw = _exact_mapping(
        value,
        {
            "schema",
            "record",
            "selected_slice",
            "share",
            "basis",
            "scope",
            "supporting_run_ids",
            "profile_tax",
            "duration_evidence_usable",
        },
        "decision",
    )
    if raw["schema"] != RESULT_SCHEMA or raw["record"] != "decision":
        raise BudgetError("unknown decision schema/tag")
    run_ids = raw["supporting_run_ids"]
    if not isinstance(run_ids, list) or not all(isinstance(item, str) for item in run_ids):
        raise BudgetError("decision supporting_run_ids must be strings")
    share = raw["share"]
    profile_tax = raw["profile_tax"]
    if not isinstance(share, (int, float)) or isinstance(share, bool) or not 0 <= share <= 1:
        raise BudgetError("decision share must be a number in [0,1]")
    if profile_tax is not None and (
        not isinstance(profile_tax, (int, float)) or isinstance(profile_tax, bool)
    ):
        raise BudgetError("decision profile_tax must be numeric or null")
    if not isinstance(raw["duration_evidence_usable"], bool):
        raise BudgetError("decision duration_evidence_usable must be boolean")
    scope = _string(raw["scope"], "decision scope")
    if not scope:
        raise BudgetError("decision scope must name the evidence denominator")
    return DecisionRecord(
        RESULT_SCHEMA,
        "decision",
        _string(raw["selected_slice"], "selected slice"),
        float(share),
        _string(raw["basis"], "decision basis"),
        scope,
        tuple(run_ids),
        None if profile_tax is None else float(profile_tax),
        raw["duration_evidence_usable"],
    )


def analyze_evidence(path: pathlib.Path, *, check: bool) -> DecisionRecord:
    runs = []
    decisions = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        try:
            raw = json.loads(line, object_pairs_hook=_pairs_no_duplicates)
        except json.JSONDecodeError as error:
            raise BudgetError(f"invalid evidence JSON row {line_number}: {error}") from error
        if not isinstance(raw, dict):
            raise BudgetError("evidence rows must be objects")
        tag = raw.get("record")
        if tag == "run":
            runs.append(parse_result_row(raw))
        elif tag == "decision":
            decisions.append(_parse_decision_row(raw))
        else:
            raise BudgetError(f"unknown evidence record tag: {tag!r}")
    if len(decisions) != 1:
        raise BudgetError("evidence must contain exactly one decision row")
    derived = analyze(runs)
    if check and decision_record_json(derived) != decision_record_json(decisions[0]):
        raise BudgetError("checked decision row does not match raw run evidence")
    return derived


def _record_json(record: RunRecord) -> dict[str, object]:
    return run_record_json(record)


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


def _assert_guest_identities(manifest: WorkloadManifest) -> dict[str, str]:
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
    return observed


def create_oracle_receipt(manifest: WorkloadManifest, path: pathlib.Path) -> OracleReceipt:
    """Perform the Docker-only identity preflight and persist its result."""
    _assert_no_live_carrick()
    _assert_image_identity(manifest)
    _assert_guest_identities(manifest)
    receipt = OracleReceipt(
        "carrick.native-compiler-oracle-preflight.v1",
        _sha256_path(manifest.manifest_path),
        manifest.image_digest,
        manifest.executable_sha256,
        tuple(sorted((item.guest_path, item.sha256) for item in manifest.files)),
        "verified",
    )
    _atomic_write_json(path, dataclasses.asdict(receipt))
    return receipt


def load_oracle_receipt(path: pathlib.Path) -> OracleReceipt:
    raw = _exact_mapping(
        _read_json(path),
        {
            "schema",
            "manifest_sha256",
            "image_digest",
            "executable_sha256",
            "guest_files",
            "oracle_status",
        },
        "oracle preflight",
    )
    guest_files = _string_pairs(raw["guest_files"], "oracle preflight guest_files")
    receipt = OracleReceipt(
        _string(raw["schema"], "oracle preflight schema"),
        _string(raw["manifest_sha256"], "oracle preflight manifest_sha256"),
        _string(raw["image_digest"], "oracle preflight image_digest"),
        _string(raw["executable_sha256"], "oracle preflight executable_sha256"),
        guest_files,
        _string(raw["oracle_status"], "oracle preflight status"),
    )
    _require_hash(receipt.manifest_sha256, "oracle preflight manifest_sha256")
    _require_hash(receipt.executable_sha256, "oracle preflight executable_sha256")
    if not IMAGE_DIGEST_RE.fullmatch(receipt.image_digest):
        raise BudgetError("oracle preflight image_digest is malformed")
    return receipt


def _time_command(command: list[str], cwd: pathlib.Path, env: Mapping[str, str], artifact: pathlib.Path):
    stdout_path = artifact / "stdout"
    stderr_path = artifact / "stderr"
    time_path = artifact / "time.txt"
    artifact.mkdir(parents=True, exist_ok=True)
    started = time.monotonic_ns()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(
            ["/usr/bin/time", "-l", "-o", str(time_path), *command],
            cwd=cwd,
            env=dict(env),
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    monotonic_elapsed_ns = time.monotonic_ns() - started
    _atomic_write_json(
        artifact / "monotonic-diagnostic.json",
        {
            "schema": RESULT_SCHEMA,
            "record": "monotonic-diagnostic",
            "elapsed_ns": monotonic_elapsed_ns,
            "authority": False,
        },
    )
    timing = parse_time_l(time_path.read_text(encoding="utf-8"))
    return result.returncode, timing, stdout_path, stderr_path


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
    *,
    mount_path: pathlib.Path | None = None,
) -> tuple[pathlib.Path | None, tuple[str, ...]]:
    fixture = _fixture_mount(manifest)
    if fixture is None:
        return None, manifest.argv
    steps: list[str] = ["set -eu"]
    for item in manifest.files:
        if item.fixture_path is None:
            continue
        host = (manifest.manifest_path.parent / item.fixture_path).resolve()
        try:
            relative = host.relative_to(fixture)
        except ValueError as error:
            raise BudgetError(f"fixture is outside workload mount root: {host}") from error
        source_root = (
            pathlib.PurePosixPath(str(mount_path))
            if mount_path is not None
            else pathlib.PurePosixPath("/native-compiler-w2")
        )
        source = source_root / pathlib.PurePosixPath(relative.as_posix())
        destination = pathlib.PurePosixPath(item.guest_path)
        steps.append(f"mkdir -p {sh_quote(str(destination.parent))}")
        steps.append(f"cp {sh_quote(str(source))} {sh_quote(str(destination))}")
    for index, arg in enumerate(manifest.argv[:-1]):
        if arg == "-o":
            output_parent = pathlib.PurePosixPath(manifest.argv[index + 1]).parent
            steps.append(f"mkdir -p {sh_quote(str(output_parent))}")
    if not isinstance(manifest.capture, W2Capture):
        steps.append('exec "$@"')
    else:
        expected_output = manifest.capture.expected_output_guest_path
        if not isinstance(expected_output, str) or not expected_output.startswith("/"):
            raise BudgetError("work-product contract has invalid guest path")
        steps.extend(
            (
                f"rm -f {sh_quote(expected_output)}",
                '"$@"',
                f"test -f {sh_quote(expected_output)}",
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
    preflight_path: pathlib.Path | None = None,
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
    preflight_sha: str | None = None
    if engine == "carrick":
        if preflight_path is None:
            raise BudgetError("Carrick measurement requires a Docker-only preflight receipt")
        receipt = load_oracle_receipt(preflight_path)
        validate_oracle_receipt(manifest, receipt)
        preflight_sha = _sha256_path(preflight_path)
    else:
        _assert_no_live_carrick()
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
        command = dtrace_command(binary, command[1:], artifact)
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
            "preflight_sha256": preflight_sha,
            "schedule_label": schedule_label,
        },
    )
    def operation():
        status, timing, stdout_path, stderr_path = _time_command(command, repo, env, artifact)
        stdout_sha = stdout_digest(manifest, stdout_path.read_bytes())
        stderr_lines = stderr_path.read_text(encoding="utf-8", errors="replace").splitlines()
        profile = None
        if plane == "profiled":
            profile = parse_nativeperf(stderr_lines)
            validate_profile(profile)
        gateway_entries = (
            max(thread.gateway_entries for thread in profile.threads)
            if profile is not None
            else None
        )
        max_traps_marker = parse_max_traps_marker(stderr_lines)
        ceiling_identity = (
            reconcile_max_traps_marker(profile, max_traps_marker, manifest.max_traps)
            if profile is not None and max_traps_marker is not None
            else None
        )
        outcome = classify_outcome(
            engine=engine,
            status=status,
            expected_status=manifest.expected_exit,
            stdout_matches=stdout_sha == manifest.expected_stdout_sha256,
            gateway_entries=gateway_entries,
            gateway_limit=manifest.max_traps,
            max_traps_marker=max_traps_marker,
            ceiling_profile_identity=ceiling_identity,
        )
        if outcome.kind == "completed":
            validate_work_product(manifest, stderr_lines)
        dtrace = None
        if plane == "dtrace":
            dtrace = parse_dtrace_summary(
                artifact / "dtrace-summary.jsonl",
                expected_run_id=run_id,
                raw_path=artifact / "dtrace.raw",
            )
        diagnostic = _read_json(artifact / "monotonic-diagnostic.json")
        monotonic = _nonnegative_int(diagnostic.get("elapsed_ns"), "monotonic elapsed_ns")
        return timing, monotonic, outcome, profile, dtrace

    if engine == "carrick":
        operation_result, cleanup = carrick_transaction(repo, artifact, run_id, operation)
    else:
        operation_result = operation()
        cleanup = CleanupReceipt("not-required", None, True, "", "")
        _atomic_write_json(artifact / "cleanup.json", dataclasses.asdict(cleanup))
    timing, monotonic, outcome, profile, dtrace = operation_result
    record = RunRecord(
        schema=RESULT_SCHEMA,
        record="run",
        engine=engine,
        workload=manifest.name,
        plane=plane,
        repetition=repetition,
        schedule_label=schedule_label,
        run_id=run_id,
        binary_sha256=binary_sha,
        manifest_sha256=_sha256_path(manifest_snapshot),
        preflight_sha256=preflight_sha,
        timing=timing,
        monotonic_elapsed_ns=monotonic,
        outcome=outcome,
        cleanup=cleanup,
        profile=profile,
        dtrace=dtrace,
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
    prior_capture: dict[str, object] | None = None
    if manifest_path.is_file():
        prior_raw = _read_json(manifest_path)
        value = prior_raw.get("capture")
        if isinstance(value, dict):
            prior_capture = value
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
        expected_output_path = next(
            (argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg == "-o"),
            None,
        )
        if expected_output_path is None:
            raise BudgetError("captured W2 compiler child has no -o output")
        if prior_capture is None or not all(
            key in prior_capture
            for key in (
                "rejected_candidates",
                "representativeness",
                "w1_profile_evidence_path",
                "w1_profile_evidence_sha256",
            )
        ):
            raise BudgetError(
                "capture requires retained reviewed candidate and representativeness determinants"
            )
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
                "kind": "w2-toolexec",
                "source": "docker-toolexec",
                "captured_argv_index": records.index(argv),
                "candidate_count": len(candidates),
                "w1_stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "w1_stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                "capture_environment": [list(item) for item in capture_env],
                "replay_environment": [list(item) for item in env],
                "expected_output_guest_path": expected_output_path,
                "expected_output_sha256": "0" * 64,
                "docker_replays": [
                    {"exit_status": 0, "stdout_sha256": stdout_sha, "output_sha256": "0" * 64},
                    {"exit_status": 0, "stdout_sha256": stdout_sha, "output_sha256": "0" * 64},
                ],
                "rejected_candidates": prior_capture["rejected_candidates"],
                "representativeness": prior_capture["representativeness"],
                "w1_profile_evidence_path": prior_capture["w1_profile_evidence_path"],
                "w1_profile_evidence_sha256": prior_capture["w1_profile_evidence_sha256"],
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
            "docker_replays": [
                {
                    "exit_status": 0,
                    "stdout_sha256": stdout_digest,
                    "output_sha256": output_digest,
                }
                for stdout_digest, output_digest in zip(
                    replay_digests, replay_output_digests, strict=True
                )
            ],
            "expected_output_sha256": replay_output_digests[0],
        }
        if len(set(replay_output_digests)) != 1:
            raise BudgetError("Docker W2 replay work-product digests do not match")
        _write_manifest(manifest_path, raw)
        return raw
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=False, capture_output=True)


def w2_replay_script(manifest: WorkloadManifest) -> tuple[str, pathlib.PurePosixPath]:
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
    return "; ".join(["set -eu", *copies, *output_dirs, 'exec "$@"']), output_path


def _replay_w2_docker(
    manifest: WorkloadManifest, fixture_dir: pathlib.Path
) -> tuple[subprocess.CompletedProcess[bytes], str]:
    script, output_path = w2_replay_script(manifest)
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


def _analyze_command(path: pathlib.Path, *, check: bool) -> int:
    decision = analyze_evidence(path, check=check)
    print(json.dumps(decision_record_json(decision), sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifests", nargs="+")
    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("manifest")
    preflight_parser.add_argument("--output", type=pathlib.Path, required=True)
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
    run_parser.add_argument("--preflight", type=pathlib.Path)
    baseline_parser = subparsers.add_parser("baseline")
    baseline_parser.add_argument("--w1", required=True)
    baseline_parser.add_argument("--w2", required=True)
    baseline_parser.add_argument("--preflight-w1", type=pathlib.Path, required=True)
    baseline_parser.add_argument("--preflight-w2", type=pathlib.Path, required=True)
    baseline_parser.add_argument("--artifacts", type=pathlib.Path, required=True)
    baseline_parser.add_argument("--results", type=pathlib.Path, required=True)
    baseline_parser.add_argument("--samples", type=int, default=5)
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("--input", type=pathlib.Path, required=True)
    analyze_parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return _validate_command(args.manifests)
        if args.command == "preflight":
            manifest = load_manifest(args.manifest)
            receipt = create_oracle_receipt(manifest, args.output)
            print(json.dumps(dataclasses.asdict(receipt), sort_keys=True))
            return 0
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
        if args.command == "baseline":
            manifests = {"w1": load_manifest(args.w1), "w2": load_manifest(args.w2)}
            preflights = {"w1": args.preflight_w1, "w2": args.preflight_w2}
            records = []
            # `baseline_schedule` is deliberately engine-major: every Carrick
            # sample completes and is reaped before the first Docker sample.
            for engine, workload, sample_kind, repetition in baseline_schedule(args.samples):
                records.append(
                    run_phase(
                        manifests[workload],
                        engine=engine,
                        plane="untraced",
                        repetition=repetition,
                        artifacts=args.artifacts,
                        results=args.results,
                        schedule_label=f"baseline-{workload}-{sample_kind}-{repetition}",
                        preflight_path=preflights[workload] if engine == "carrick" else None,
                    )
                )
            print(json.dumps([run_record_json(record) for record in records], sort_keys=True))
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
                            preflight_path=args.preflight,
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
                    preflight_path=args.preflight,
                )
                print(json.dumps(_record_json(record), sort_keys=True))
            return 0
        if args.command == "analyze":
            return _analyze_command(args.input, check=args.check)
        raise AssertionError(args.command)
    except (BudgetError, OSError, subprocess.SubprocessError) as error:
        print(f"native_compiler_budget: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
