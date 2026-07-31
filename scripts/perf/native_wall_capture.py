#!/usr/bin/env python3
"""Capture receipt-bound native lifecycle observability evidence."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import native_go_build  # noqa: E402
import native_go_build_abba  # noqa: E402


CAPTURE_SCHEMA = "carrick.native-m2-lifecycle-capture.v2"
LIFECYCLE_PREFIX = "TRANSLATED_LIFECYCLE|"
SUMMARY_PREFIX = "TRANSLATED_LIFECYCLE_SUMMARY|"
RUN_ID_PREFIX = "native-m2-lifecycle-"
HOST_TIMEOUT_SECONDS = 120
EXPECTED_IMAGE = native_go_build.DEFAULT_IMAGE
RUN_ID_RESERVATION_DIR = pathlib.Path("target/perf/native-m2-lifecycle-run-ids")
CARRICK_ENV_ALLOWLIST = frozenset(("CARRICK_DSR_PROFILE", "CARRICK_RUN_ID"))
SAFE_LAUNCH_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
SAFE_LAUNCH_ENV_KEYS = frozenset(
    ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL")
)
DOF_SECTION = "__dof_carrick"
SUPPORTED_DOF_SEGMENTS = frozenset(("__TEXT", "__DATA"))
DOF_EVIDENCE_FIELDS = frozenset(
    ("section", "segment", "size", "otool_listing_sha256")
)
LIFECYCLE_REDUCER = (
    "set -eu; "
    "(i=0; while [ \"$i\" -lt 500000 ]; do i=$((i + 1)); done; "
    "exec /bin/sh -c 'i=0; while [ \"$i\" -lt 500000 ]; "
    "do i=$((i + 1)); done; echo CHILD_EXEC_OK') & "
    "child=$!; wait \"$child\"; echo PARENT_WAIT_OK"
)

MILESTONES = (
    "target-birth",
    "parent-reset",
    "parent-private",
    "parent-ready",
    "parent-first-run",
    "child-birth",
    "fork-repair-begin",
    "child-preexec-reset",
    "child-preexec-private",
    "child-preexec-ready",
    "fork-repair-end",
    "child-fork-post",
    "child-preexec-first-run",
    "reexec-preflight-begin",
    "reexec-begin",
    "exec",
    "exec-success",
    "reexec-end",
    "child-postexec-reset",
    "child-postexec-private",
    "child-postexec-ready",
    "host-image-base",
    "host-image-catalog",
    "guest-image-base",
    "host-jit-range",
    "child-postexec-first-run",
    "child-exit",
    "parent-wait4",
    "root-exit",
)

SUMMARY_FIELDS = frozenset(
    (
        "schema",
        "complete",
        "lifecycle_ok",
        "root_exit_status",
        "target_birth",
        "child_birth",
        "parent_catalog_ok",
        "child_preexec_catalog_ok",
        "child_postexec_catalog_ok",
        "parent_run",
        "child_preexec_run",
        "child_postexec_run",
        "fork_repair_begin",
        "fork_repair_end",
        "child_fork_post",
        "preflight",
        "reexec_begin",
        "exec",
        "exec_success",
        "exec_failure",
        "reexec_end",
        "metadata_ok",
        "child_exit",
        "child_exit_status",
        "wait4_success",
        "unexpected_events",
        "identity_violations",
        "catalog_violations",
        "metadata_violations",
        "run_violations",
        "pending",
        "dtrace_drops",
        "dtrace_errors",
    )
)

SUMMARY_ONE_FIELDS = frozenset(
    (
        "schema",
        "complete",
        "lifecycle_ok",
        "target_birth",
        "child_birth",
        "parent_catalog_ok",
        "child_preexec_catalog_ok",
        "child_postexec_catalog_ok",
        "parent_run",
        "child_preexec_run",
        "child_postexec_run",
        "fork_repair_begin",
        "fork_repair_end",
        "child_fork_post",
        "preflight",
        "reexec_begin",
        "exec",
        "exec_success",
        "reexec_end",
        "metadata_ok",
        "child_exit",
        "wait4_success",
    )
)

SUMMARY_ZERO_FIELDS = frozenset(
    (
        "root_exit_status",
        "exec_failure",
        "child_exit_status",
        "unexpected_events",
        "identity_violations",
        "catalog_violations",
        "metadata_violations",
        "run_violations",
        "pending",
        "dtrace_drops",
        "dtrace_errors",
    )
)

RUN_ID_RE = re.compile(
    r"^native-m2-lifecycle-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class EvidenceError(RuntimeError):
    """The capture cannot be accepted as closed observability evidence."""


@dataclasses.dataclass(frozen=True)
class LifecycleCaptureConfig:
    repo: pathlib.Path
    receipt: pathlib.Path
    overlay: pathlib.Path
    timeout_seconds: int
    trace_out: pathlib.Path
    summary_jsonl: pathlib.Path
    stdout: pathlib.Path
    capture_receipt: pathlib.Path
    script: pathlib.Path

    def __post_init__(self) -> None:
        if (
            type(self.timeout_seconds) is not int
            or self.timeout_seconds != HOST_TIMEOUT_SECONDS
        ):
            raise EvidenceError("lifecycle host timeout must be exactly 120 seconds")
        outputs = (
            self.trace_out.resolve(),
            self.summary_jsonl.resolve(),
            self.stdout.resolve(),
            self.capture_receipt.resolve(),
        )
        if len(set(outputs)) != len(outputs):
            raise EvidenceError("lifecycle output paths must be distinct")
        expected_script = (
            self.repo.resolve()
            / "scripts/dtrace/native-translated-range-catalog.d"
        )
        if self.script.resolve() != expected_script:
            raise EvidenceError("lifecycle capture requires the maintained DTrace script")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _regular_bytes(path: pathlib.Path, description: str) -> bytes:
    absolute = path.resolve()
    try:
        metadata = absolute.stat()
    except FileNotFoundError as error:
        raise EvidenceError(f"{description} is absent: {absolute}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{description} is not a regular file: {absolute}")
    return absolute.read_bytes()


def _descriptor(path: pathlib.Path, raw: bytes | None = None) -> dict[str, object]:
    content = _regular_bytes(path, "receipt-bound artifact") if raw is None else raw
    return {
        "path": str(path.resolve()),
        "size": len(content),
        "sha256": _sha256_bytes(content),
    }


def _parse_wire_record(line: str, prefix: str) -> dict[str, str]:
    if not line.startswith(prefix):
        raise EvidenceError(f"wire record lacks {prefix.rstrip('|')}")
    fields: dict[str, str] = {}
    for token in line[len(prefix) :].split("|"):
        if "=" not in token:
            raise EvidenceError(f"wire record has malformed token: {token!r}")
        key, value = token.split("=", 1)
        if not key or key in fields:
            raise EvidenceError(f"wire record has duplicate or empty field: {key!r}")
        fields[key] = value
    return fields


def _wire_int(fields: Mapping[str, str], key: str) -> int:
    try:
        value = fields[key]
    except KeyError as error:
        raise EvidenceError(f"lifecycle record lacks {key}") from error
    try:
        return int(value, 0)
    except ValueError as error:
        raise EvidenceError(f"lifecycle {key} is not an integer: {value!r}") from error


def _expect_identity(
    event: Mapping[str, str],
    *,
    kind: str,
    pid: int,
    generation: int,
    epoch: int,
) -> None:
    if _wire_int(event, "pid") != pid:
        raise EvidenceError(f"{kind} PID identity drifted")
    if _wire_int(event, "incarnation") != 1:
        raise EvidenceError(f"{kind} incarnation identity drifted")
    if _wire_int(event, "generation") != generation:
        raise EvidenceError(f"{kind} image generation drifted")
    if _wire_int(event, "epoch") != epoch:
        raise EvidenceError(f"{kind} runtime epoch drifted")


def _half_open_range(event: Mapping[str, str], description: str) -> tuple[int, int]:
    start = _wire_int(event, "start")
    end = _wire_int(event, "end")
    if start >= end:
        raise EvidenceError(f"{description} has invalid range bounds")
    return start, end


def parse_lifecycle_trace(raw: str) -> dict[str, Any]:
    """Parse and independently validate the schema-1 lifecycle wire stream."""

    if not raw or not raw.strip():
        raise EvidenceError("empty trace cannot prove lifecycle ownership")
    event_lines = [line for line in raw.splitlines() if line.startswith(LIFECYCLE_PREFIX)]
    summary_lines = [line for line in raw.splitlines() if line.startswith(SUMMARY_PREFIX)]
    if len(summary_lines) != 1:
        raise EvidenceError(
            "lifecycle trace requires exactly one summary, "
            f"found {len(summary_lines)}"
        )

    events = [_parse_wire_record(line, LIFECYCLE_PREFIX) for line in event_lines]
    actual_kinds = [event.get("kind", "") for event in events]
    for kind in MILESTONES:
        count = actual_kinds.count(kind)
        if count != 1:
            raise EvidenceError(
                f"lifecycle milestone {kind} must appear exactly once, found {count}"
            )
    unexpected = [kind for kind in actual_kinds if kind not in MILESTONES]
    if unexpected:
        label = unexpected[0] or "unnamed"
        raise EvidenceError(f"unexpected or disarmed lifecycle event: {label}")
    if tuple(actual_kinds) != MILESTONES:
        raise EvidenceError("lifecycle milestone order is invalid")
    for expected, event in enumerate(events, start=1):
        if _wire_int(event, "schema") != 1:
            raise EvidenceError("lifecycle event schema is not 1")
        if _wire_int(event, "ordinal") != expected:
            raise EvidenceError("lifecycle event ordinal is gapped or reordered")

    by_kind = {str(event["kind"]): event for event in events}
    target_pid = _wire_int(by_kind["target-birth"], "pid")
    child_pid = _wire_int(by_kind["child-birth"], "pid")
    if target_pid <= 0 or child_pid <= 0 or target_pid == child_pid:
        raise EvidenceError("target and child PID identities are invalid")

    parent_expected = {
        "target-birth": 0,
        "parent-reset": 1,
        "parent-private": 1,
        "parent-ready": 1,
        "parent-first-run": 1,
        "parent-wait4": 1,
        "root-exit": 1,
    }
    for kind, epoch in parent_expected.items():
        _expect_identity(
            by_kind[kind], kind=kind, pid=target_pid, generation=1, epoch=epoch
        )

    preexec_expected = {
        "child-birth": 1,
        "fork-repair-begin": 1,
        "child-preexec-reset": 2,
        "child-preexec-private": 2,
        "child-preexec-ready": 2,
        "fork-repair-end": 2,
        "child-fork-post": 2,
        "child-preexec-first-run": 2,
        "reexec-preflight-begin": 2,
        "reexec-begin": 2,
        "exec": 2,
    }
    for kind, epoch in preexec_expected.items():
        _expect_identity(
            by_kind[kind], kind=kind, pid=child_pid, generation=1, epoch=epoch
        )

    for kind in ("exec-success", "reexec-end"):
        _expect_identity(
            by_kind[kind], kind=kind, pid=child_pid, generation=2, epoch=0
        )
    for kind in (
        "child-postexec-reset",
        "child-postexec-private",
        "child-postexec-ready",
        "host-image-base",
        "host-image-catalog",
        "guest-image-base",
        "host-jit-range",
        "child-postexec-first-run",
        "child-exit",
    ):
        _expect_identity(
            by_kind[kind], kind=kind, pid=child_pid, generation=2, epoch=1
        )

    if _wire_int(by_kind["child-birth"], "parent_pid") != target_pid:
        raise EvidenceError("child birth parent identity drifted")
    for kind in (
        "parent-private",
        "child-preexec-private",
        "child-postexec-private",
    ):
        if _wire_int(by_kind[kind], "sequence") != 1:
            raise EvidenceError(f"{kind} catalog sequence is not exactly 1")
    for kind in ("parent-ready", "child-preexec-ready", "child-postexec-ready"):
        if _wire_int(by_kind[kind], "frontier") != 1:
            raise EvidenceError(f"{kind} catalog frontier is not exactly 1")

    parent_range = _half_open_range(by_kind["parent-private"], "parent catalog")
    child_preexec_range = _half_open_range(
        by_kind["child-preexec-private"], "child pre-exec catalog"
    )
    if child_preexec_range != parent_range:
        raise EvidenceError("child pre-exec catalog range differs from parent")
    for kind in ("parent-first-run", "child-preexec-first-run"):
        cache_pc = _wire_int(by_kind[kind], "cache_pc")
        if not parent_range[0] <= cache_pc < parent_range[1]:
            raise EvidenceError(f"{kind} sample is outside its private range")

    postexec_range = _half_open_range(
        by_kind["child-postexec-private"], "child post-exec catalog"
    )
    jit_range = _half_open_range(by_kind["host-jit-range"], "host JIT metadata")
    if jit_range != postexec_range:
        raise EvidenceError("host JIT metadata range differs from post-exec catalog")
    postexec_pc = _wire_int(by_kind["child-postexec-first-run"], "cache_pc")
    if not postexec_range[0] <= postexec_pc < postexec_range[1]:
        raise EvidenceError("child post-exec sample is outside its private range")

    if _wire_int(by_kind["child-exit"], "status") != 0:
        raise EvidenceError("child exit status is nonzero")
    wait = by_kind["parent-wait4"]
    if (
        _wire_int(wait, "child_pid") != child_pid
        or _wire_int(wait, "retval") != child_pid
        or _wire_int(wait, "errno") != 0
    ):
        raise EvidenceError("parent wait4 did not positively reap the exited child")
    if _wire_int(by_kind["root-exit"], "status") != 0:
        raise EvidenceError("root exit status is nonzero")

    summary_text = _parse_wire_record(summary_lines[0], SUMMARY_PREFIX)
    if set(summary_text) != SUMMARY_FIELDS:
        raise EvidenceError(
            "lifecycle summary fields are not schema-1 exact: "
            f"unknown={sorted(set(summary_text) - SUMMARY_FIELDS)} "
            f"missing={sorted(SUMMARY_FIELDS - set(summary_text))}"
        )
    summary = {key: _wire_int(summary_text, key) for key in SUMMARY_FIELDS}
    for key in SUMMARY_ONE_FIELDS:
        if summary[key] != 1:
            raise EvidenceError(f"lifecycle summary {key} must equal 1")
    for key in SUMMARY_ZERO_FIELDS:
        if summary[key] != 0:
            raise EvidenceError(f"lifecycle summary {key} must equal 0")

    return {
        **summary,
        "target_pid": target_pid,
        "child_pid": child_pid,
        "event_count": len(events),
    }


@dataclasses.dataclass(frozen=True)
class _DClause:
    provider: str
    predicate: str
    actions: str


def _strip_d_comments(source: str) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if quote is not None:
            output.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
            index += 1
            continue
        if current in ('"', "'"):
            quote = current
            output.append(current)
            index += 1
            continue
        if current == "/" and following == "*":
            index += 2
            while index < len(source):
                if source[index] == "\n":
                    output.append("\n")
                if source[index : index + 2] == "*/":
                    index += 2
                    break
                index += 1
            continue
        if current == "/" and following == "/":
            index += 2
            while index < len(source) and source[index] != "\n":
                index += 1
            continue
        output.append(current)
        index += 1
    return "".join(output)


def _scan_d_delimited(source: str, start: int, opening: str, closing: str) -> int:
    depth = 1
    index = start + 1
    quote: str | None = None
    escaped = False
    while index < len(source):
        current = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
        elif current in ('"', "'"):
            quote = current
        elif current == opening:
            depth += 1
        elif current == closing:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise EvidenceError("maintained lifecycle script has an unclosed D clause")


def _parse_dtrace_clauses(source: str) -> tuple[str, list[_DClause]]:
    executable = _strip_d_comments(source)
    header = re.compile(
        r"(?m)^(?P<provider>(?:dtrace|proc|carrick\*):::[A-Za-z0-9_-]+|"
        r"tick-[0-9]+s)[ \t]*$"
    )
    clauses: list[_DClause] = []
    for match in header.finditer(executable):
        position = match.end()
        while position < len(executable) and executable[position].isspace():
            position += 1
        predicate = ""
        if position < len(executable) and executable[position] == "/":
            end = position + 1
            escaped = False
            while end < len(executable):
                if executable[end] == "/" and not escaped:
                    break
                escaped = executable[end] == "\\" and not escaped
                if executable[end] != "\\":
                    escaped = False
                end += 1
            if end >= len(executable):
                raise EvidenceError("maintained lifecycle script has an unclosed predicate")
            predicate = executable[position + 1 : end]
            position = end + 1
            while position < len(executable) and executable[position].isspace():
                position += 1
        if position >= len(executable) or executable[position] != "{":
            raise EvidenceError(
                f"maintained lifecycle provider {match.group('provider')} lacks actions"
            )
        end = _scan_d_delimited(executable, position, "{", "}")
        clauses.append(
            _DClause(
                provider=match.group("provider"),
                predicate=predicate,
                actions=executable[position + 1 : end],
            )
        )
    return executable, clauses


def _compact_d(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _require_d_clause(
    clauses: Sequence[_DClause],
    provider: str,
    *,
    predicate: Sequence[str],
    actions: Sequence[str],
    description: str,
    exact_predicate: bool = False,
    exact_actions: bool = False,
    ordered_actions: bool = False,
    unique_assignment_targets: Sequence[str] = (),
    unique_call_names: Sequence[str] = (),
) -> None:
    expected_predicate = [_compact_d(item) for item in predicate]
    expected_actions = [_compact_d(item) for item in actions]
    for clause in clauses:
        if clause.provider != provider:
            continue
        actual_predicate = _compact_d(clause.predicate)
        actual_actions = _compact_d(clause.actions)
        actual_action_statements = _split_d_top_level(clause.actions, ";")
        predicate_matches = (
            actual_predicate == expected_predicate[0]
            if exact_predicate
            else all(item in actual_predicate for item in expected_predicate)
        )
        if ordered_actions:
            width = len(expected_actions)
            actions_match = any(
                actual_action_statements[index : index + width]
                == tuple(expected_actions)
                for index in range(len(actual_action_statements) - width + 1)
            )
        elif exact_actions:
            actions_match = all(
                item in actual_action_statements for item in expected_actions
            )
        else:
            actions_match = all(item in actual_actions for item in expected_actions)
        assignments_match = all(
            sum(
                statement.startswith(_compact_d(target))
                for statement in actual_action_statements
            )
            == 1
            for target in unique_assignment_targets
        )
        calls_match = all(
            sum(
                statement.startswith(f"{_compact_d(name)}(")
                for statement in actual_action_statements
            )
            == 1
            for name in unique_call_names
        )
        if predicate_matches and actions_match and assignments_match and calls_match:
            return
    raise EvidenceError(f"maintained lifecycle script lacks {description} clause")


def _d_index_arities(source: str, name: str) -> set[int]:
    arities: set[int] = set()
    for match in re.finditer(rf"\b{re.escape(name)}\[", source):
        end = _scan_d_delimited(source, match.end() - 1, "[", "]")
        contents = source[match.end() : end]
        depth = 0
        commas = 0
        quote: str | None = None
        escaped = False
        for current in contents:
            if quote is not None:
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    quote = None
            elif current in ('"', "'"):
                quote = current
            elif current == "[":
                depth += 1
            elif current == "]":
                depth -= 1
            elif current == "," and depth == 0:
                commas += 1
        arities.add(commas + 1)
    return arities


def _split_d_top_level(source: str, separator: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    index = 0
    depth = 0
    quote: str | None = None
    escaped = False
    while index < len(source):
        current = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
            index += 1
            continue
        if current in ('"', "'"):
            quote = current
            index += 1
            continue
        if current in "([{":
            depth += 1
            index += 1
            continue
        if current in ")]}" and depth > 0:
            depth -= 1
            index += 1
            continue
        if depth == 0 and source.startswith(separator, index):
            part = _compact_d(source[start:index])
            if part:
                parts.append(part)
            index += len(separator)
            start = index
            continue
        index += 1
    final = _compact_d(source[start:])
    if final:
        parts.append(final)
    return tuple(parts)


def _d_index_expressions(source: str, name: str) -> list[tuple[str, ...]]:
    expressions: list[tuple[str, ...]] = []
    for match in re.finditer(rf"\b{re.escape(name)}\[", source):
        end = _scan_d_delimited(source, match.end() - 1, "[", "]")
        expressions.append(
            _split_d_top_level(source[match.end() : end], ",")
        )
    return expressions


def _expected_d_identity_accesses() -> dict[str, Counter[tuple[str, ...]]]:
    pid_inc = "incarnation[pid]"
    pid_gen = f"image_generation[pid,{pid_inc}]"
    pid_epoch = f"runtime_epoch[pid,{pid_inc}]"
    dynamic = ("pid", pid_inc, pid_gen, pid_epoch)
    dynamic_epoch_zero = ("pid", pid_inc, pid_gen, "(uint64_t)0")
    target = (
        "$target",
        "incarnation[$target]",
        "(uint64_t)1",
        "(uint64_t)0",
    )
    created = (
        "this->child_pid",
        "this->child_incarnation",
        "(uint64_t)1",
        "this->child_epoch",
    )
    parent = ("pid", pid_inc, "(uint64_t)1", "(uint64_t)1")
    child_preexec = ("pid", pid_inc, "(uint64_t)1", "(uint64_t)2")
    child_postexec = ("pid", pid_inc, "(uint64_t)2", "(uint64_t)1")
    closed_child = (
        "lifecycle_child_pid",
        "incarnation[lifecycle_child_pid]",
        "(uint64_t)2",
        "(uint64_t)1",
    )

    def counted(*entries: tuple[tuple[str, ...], int]) -> Counter[tuple[str, ...]]:
        result: Counter[tuple[str, ...]] = Counter()
        for expression, count in entries:
            result[expression] += count
        return result

    expected = {
        "catalog_live": counted(
            (target, 1),
            (created, 1),
            (dynamic, 10),
            (dynamic_epoch_zero, 1),
            (parent, 1),
            (child_preexec, 1),
            (child_postexec, 1),
        ),
        "pending_by_pid": counted(
            (target, 1),
            (created, 1),
            (dynamic, 5),
            (dynamic_epoch_zero, 1),
        ),
        "ready_seen": counted(
            (parent, 3),
            (child_preexec, 3),
            (child_postexec, 3),
            (dynamic, 1),
        ),
        "private_count": counted(
            (parent, 4), (child_preexec, 4), (child_postexec, 4)
        ),
        "private_start": counted(
            (parent, 2),
            (child_preexec, 2),
            (child_postexec, 4),
            (dynamic, 1),
        ),
        "private_end": counted(
            (parent, 2),
            (child_preexec, 2),
            (child_postexec, 4),
            (dynamic, 1),
        ),
    }
    for name in (
        "metadata_host_base",
        "metadata_host_catalog",
        "metadata_guest_base",
        "metadata_jit_range",
    ):
        expected[name] = counted(
            (target, 1),
            (dynamic_epoch_zero, 1),
            (child_postexec, 4),
            (closed_child, 1),
        )
    expected["metadata_complete"] = counted(
        (target, 1),
        (dynamic_epoch_zero, 1),
        (child_postexec, 1),
        (closed_child, 1),
    )

    target_announcement = (*target, "(uint64_t)0")
    dynamic_announcement = (*dynamic, "(uint64_t)arg2")
    for name in ("ann_epoch", "ann_start", "ann_end"):
        expected[name] = counted(
            (target_announcement, 1), (dynamic_announcement, 7)
        )
    expected["ann_ordinal"] = counted(
        (target_announcement, 1),
        (dynamic_announcement, 12),
        ((*dynamic, "this->run_unit"), 1),
    )

    target_pending = (*target, "0")
    dynamic_pending = (*dynamic, "arg0")
    pending_counts = {
        "pending_present": 7,
        "pending_epoch": 5,
        "pending_unit": 6,
        "pending_start": 6,
        "pending_end": 6,
        "pending_commit_ordinal": 8,
    }
    for name, count in pending_counts.items():
        expected[name] = counted(
            (target_pending, 1), (dynamic_pending, count)
        )
    return expected


def _require_milestone_contract(
    clauses: Sequence[_DClause],
    kind: str,
    provider: str,
    predicate_terms: Sequence[str],
    action_statements: Sequence[str],
) -> None:
    token = f"|kind={kind}|"
    matches = [clause for clause in clauses if token in clause.actions]
    if len(matches) != 1:
        raise EvidenceError(
            f"maintained lifecycle milestone {kind} must have one clause"
        )
    clause = matches[0]
    actual_predicates = set(_split_d_top_level(clause.predicate, "&&"))
    actual_actions = set(_split_d_top_level(clause.actions, ";"))
    expected_predicates = {_compact_d(term) for term in predicate_terms}
    expected_actions = {
        _compact_d(statement)
        for statement in (*action_statements, "lifecycle_ordinal++")
    }
    if (
        clause.provider != provider
        or not expected_predicates <= actual_predicates
        or not expected_actions <= actual_actions
    ):
        raise EvidenceError(
            f"maintained lifecycle milestone {kind} provider, stage, or state action drifted"
        )


def validate_dtrace_source(source: str) -> dict[str, int]:
    """Fail closed on executable lifecycle structure, not comments or labels."""

    executable, clauses = _parse_dtrace_clauses(source)
    providers = {clause.provider for clause in clauses}
    required_providers = (
        "proc:::create",
        "proc:::exec",
        "proc:::exec-success",
        "proc:::exec-failure",
        "proc:::exit",
        "carrick*:::dsr-cache-lifecycle",
        "carrick*:::host-image-base",
        "carrick*:::host-image-catalog",
        "carrick*:::guest-image-base",
        "carrick*:::host-jit-range",
        "carrick*:::syscall-return",
        "carrick*:::guest-exit",
    )
    missing = [provider for provider in required_providers if provider not in providers]
    if missing:
        raise EvidenceError(
            "maintained lifecycle script lacks executable provider/probe: "
            + ", ".join(missing)
        )

    schema2 = executable.count('printf("TRANSLATED_RANGE_SUMMARY|schema=2|')
    lifecycle = executable.count(
        'printf("TRANSLATED_LIFECYCLE_SUMMARY|schema=1|'
    )
    if schema2 != 1 or lifecycle != 1:
        raise EvidenceError(
            "maintained lifecycle script requires exactly one schema-2 and "
            "exactly one lifecycle summary"
        )
    ticks = [clause.provider for clause in clauses if clause.provider.startswith("tick-")]
    if ticks != ["tick-30s"]:
        raise EvidenceError("maintained lifecycle script must self-bound at 30 seconds")

    action_text = "\n".join(clause.actions for clause in clauses)
    for milestone in MILESTONES:
        if action_text.count(f"|kind={milestone}|") != 1:
            raise EvidenceError(
                f"maintained lifecycle milestone {milestone} lacks one executable clause"
            )
    if action_text.count("|kind=shared-run-begin|") != 1:
        raise EvidenceError(
            "maintained lifecycle requires exactly one shared run wire producer"
        )

    stage = "lifecycle_stage[pid, incarnation[pid]]"
    child = "pid == lifecycle_child_pid"
    milestone_contracts = (
        (
            "target-birth",
            "dtrace:::BEGIN",
            (),
            (
                "lifecycle_target_birth = 1",
                "parent_private_start = (uint64_t)0",
                "parent_private_end = (uint64_t)0",
                "tracked[$target] = 1",
                "lifecycle_stage[$target, incarnation[$target]] = 1",
            ),
        ),
        (
            "parent-reset",
            "carrick*:::host-translated-range-reset",
            ("pid == $target", f"{stage} == 1"),
            (
                "runtime_epoch[pid, incarnation[pid]] = (uint64_t)1",
                "catalog_pending++",
                f"{stage} = 2",
            ),
        ),
        (
            "parent-private",
            "carrick*:::host-translated-private-range",
            ("pid == $target", f"{stage} == 2"),
            (
                "parent_private_start = (uint64_t)arg2",
                "parent_private_end = (uint64_t)arg3",
                f"{stage} = 3",
            ),
        ),
        (
            "parent-ready",
            "carrick*:::host-translated-range-ready",
            ("pid == $target", f"{stage} == 3"),
            (
                "parent_catalog_ok++",
                "catalog_pending--",
                f"{stage} = 4",
            ),
        ),
        (
            "parent-first-run",
            "carrick*:::dsr-run-begin",
            ("pid == $target", f"{stage} == 4"),
            ("parent_run++", f"{stage} = 5"),
        ),
        (
            "child-birth",
            "proc:::create",
            (
                "birth_valid[args[0]->pr_pid, incarnation[args[0]->pr_pid]] == 1",
            ),
            ("lifecycle_child_birth++",),
        ),
        (
            "fork-repair-begin",
            "carrick*:::dsr-cache-lifecycle",
            (child, "arg1 == 1", f"{stage} == 1"),
            ("fork_repair_begin++", "repair_pending++", f"{stage} = 2"),
        ),
        (
            "child-preexec-reset",
            "carrick*:::host-translated-range-reset",
            (child, f"{stage} == 2"),
            (
                "runtime_epoch[pid, incarnation[pid]] = (uint64_t)2",
                "catalog_pending++",
                f"{stage} = 3",
            ),
        ),
        (
            "child-preexec-private",
            "carrick*:::host-translated-private-range",
            (child, f"{stage} == 3"),
            (f"{stage} = 4",),
        ),
        (
            "child-preexec-ready",
            "carrick*:::host-translated-range-ready",
            (child, f"{stage} == 4"),
            (
                "child_preexec_catalog_ok++",
                "catalog_pending--",
                f"{stage} = 5",
            ),
        ),
        (
            "fork-repair-end",
            "carrick*:::dsr-cache-lifecycle",
            (child, "arg1 == 2", f"{stage} == 5"),
            ("fork_repair_end++", "repair_pending--", f"{stage} = 6"),
        ),
        (
            "child-fork-post",
            "carrick*:::fork-post",
            (child, "arg0 == 0", f"{stage} == 6"),
            ("child_fork_post++", f"{stage} = 7"),
        ),
        (
            "child-preexec-first-run",
            "carrick*:::dsr-run-begin",
            (child, f"{stage} == 7"),
            ("child_preexec_run++", f"{stage} = 8"),
        ),
        (
            "reexec-preflight-begin",
            "carrick*:::dsr-cache-lifecycle",
            (child, "arg1 == 37", f"{stage} == 8"),
            ("reexec_preflight++", f"{stage} = 9"),
        ),
        (
            "reexec-begin",
            "carrick*:::dsr-cache-lifecycle",
            (child, "arg1 == 25", f"{stage} == 9"),
            ("reexec_begin++", "reexec_pending++", f"{stage} = 10"),
        ),
        (
            "exec",
            "proc:::exec",
            (child, f"{stage} == 10"),
            ("exec_seen++", f"{stage} = 11"),
        ),
        (
            "exec-success",
            "proc:::exec-success",
            (child, f"{stage} == 11"),
            ("exec_success++", f"{stage} = 12"),
        ),
        (
            "reexec-end",
            "carrick*:::dsr-cache-lifecycle",
            (child, "arg1 == 26", f"{stage} == 12"),
            ("reexec_end++", "reexec_pending--", f"{stage} = 13"),
        ),
        (
            "child-postexec-reset",
            "carrick*:::host-translated-range-reset",
            (child, f"{stage} == 13"),
            (
                "runtime_epoch[pid, incarnation[pid]] = (uint64_t)1",
                "catalog_pending++",
                f"{stage} = 14",
            ),
        ),
        (
            "child-postexec-private",
            "carrick*:::host-translated-private-range",
            (child, f"{stage} == 14"),
            (f"{stage} = 15",),
        ),
        (
            "child-postexec-ready",
            "carrick*:::host-translated-range-ready",
            (child, f"{stage} == 15"),
            (
                "child_postexec_catalog_ok++",
                "catalog_pending--",
                f"{stage} = 16",
            ),
        ),
        (
            "host-image-base",
            "carrick*:::host-image-base",
            (child, f"{stage} == 16"),
            (
                "metadata_host_base[pid, incarnation[pid], (uint64_t)2, (uint64_t)1]++",
                f"{stage} = 17",
            ),
        ),
        (
            "host-image-catalog",
            "carrick*:::host-image-catalog",
            (child, f"{stage} == 17"),
            (
                "metadata_host_catalog[pid, incarnation[pid], (uint64_t)2, (uint64_t)1]++",
                f"{stage} = 18",
            ),
        ),
        (
            "guest-image-base",
            "carrick*:::guest-image-base",
            (child, f"{stage} == 18"),
            (
                "metadata_guest_base[pid, incarnation[pid], (uint64_t)2, (uint64_t)1]++",
                f"{stage} = 19",
            ),
        ),
        (
            "host-jit-range",
            "carrick*:::host-jit-range",
            (child, f"{stage} == 19"),
            (
                "metadata_jit_range[pid, incarnation[pid], (uint64_t)2, (uint64_t)1]++",
                f"{stage} = 20",
            ),
        ),
        (
            "child-postexec-first-run",
            "carrick*:::dsr-run-begin",
            (child, f"{stage} == 20"),
            ("child_postexec_run++", f"{stage} = 21"),
        ),
        (
            "child-exit",
            "carrick*:::guest-exit",
            (child, f"{stage} == 21", "(int)arg1 == 0"),
            (
                "child_exit_seen++",
                "child_exit_status = (int)arg1",
                f"{stage} = 22",
            ),
        ),
        (
            "parent-wait4",
            "carrick*:::syscall-return",
            (
                "pid == $target",
                f"{stage} == 5",
                "lifecycle_stage[lifecycle_child_pid, incarnation[lifecycle_child_pid]] == 22",
            ),
            ("wait4_success++", f"{stage} = 6"),
        ),
        (
            "root-exit",
            "carrick*:::guest-exit",
            ("pid == $target", f"{stage} == 6", "(int)arg1 == 0"),
            (
                "root_exit_seen = 1",
                "root_exit_status = (int)arg1",
                f"{stage} = 7",
            ),
        ),
    )
    for kind, provider, predicate_terms, action_statements in milestone_contracts:
        _require_milestone_contract(
            clauses,
            kind,
            provider,
            predicate_terms,
            action_statements,
        )

    _require_d_clause(
        clauses,
        "carrick*:::guest-exit",
        predicate=("pid == lifecycle_child_pid", "(int)arg1 != 0"),
        actions=("unexpected_events++", "identity_violations++"),
        description="nonzero child guest-exit rejection",
    )
    _require_d_clause(
        clauses,
        "carrick*:::guest-exit",
        predicate=(
            "pid == lifecycle_child_pid",
            "(uint64_t)arg0 == (uint64_t)pid",
            "(int)arg1 == 0",
        ),
        actions=("child_exit_seen++", "|kind=child-exit|"),
        description="child guest-exit authority",
    )
    _require_d_clause(
        clauses,
        "carrick*:::guest-exit",
        predicate=("pid == $target", "(int)arg1 != 0"),
        actions=("root_exit_status = (int)arg1", "identity_violations++"),
        description="nonzero root guest-exit rejection",
    )
    _require_d_clause(
        clauses,
        "carrick*:::guest-exit",
        predicate=("pid == $target", "(int)arg1 == 0"),
        actions=("root_exit_seen = 1", "|kind=root-exit|"),
        description="root guest-exit authority",
    )
    for clause in clauses:
        if clause.provider == "proc:::exit" and any(
            token in clause.actions
            for token in ("root_exit_status", "child_exit_status", "|kind=child-exit|", "|kind=root-exit|")
        ):
            raise EvidenceError("proc exit must perform cleanup only, not decode exit code")
    _require_d_clause(
        clauses,
        "proc:::exit",
        predicate=("tracked[pid]",),
        actions=("tracked[pid] = 0", "pid_live[pid] = 0", "live_owners--"),
        description="proc-exit ownership cleanup",
        exact_predicate=True,
    )
    _require_d_clause(
        clauses,
        "proc:::exec",
        predicate=("tracked[pid]",),
        actions=("exec_inflight[pid, incarnation[pid]] = 1", "execution_armed[pid, incarnation[pid]] = 0"),
        description="all-tracked-owner exec disarm",
        exact_predicate=True,
    )
    _require_d_clause(
        clauses,
        "proc:::exec-success",
        predicate=("tracked[pid]",),
        actions=(
            "image_generation[pid, incarnation[pid]] + 1",
            "runtime_epoch[pid, incarnation[pid]] = (uint64_t)0",
            "execution_armed[pid, incarnation[pid]] = 1",
        ),
        description="all-tracked-owner exec-success generation advance",
        exact_predicate=True,
    )
    _require_d_clause(
        clauses,
        "proc:::exec-failure",
        predicate=("tracked[pid]",),
        actions=("exec_failure++", "identity_violations++"),
        description="all-tracked-owner exec-failure rejection",
        exact_predicate=True,
    )
    for provider in (
        "carrick*:::host-image-base",
        "carrick*:::host-image-catalog",
        "carrick*:::guest-image-base",
        "carrick*:::host-jit-range",
    ):
        _require_d_clause(
            clauses,
            provider,
            predicate=(
                "pid == lifecycle_child_pid",
                "lifecycle_stage[pid, incarnation[pid]] >= 10",
            ),
            actions=("metadata_violations++", "unexpected_events++"),
            description=f"stage-10 reexec metadata rejection for {provider}",
        )

    _require_d_clause(
        clauses,
        "proc:::create",
        predicate=("tracked[pid]",),
        actions=(
            "this->child_pid = args[0]->pr_pid",
            "this->child_incarnation = incarnation[this->child_pid]",
            (
                "this->child_epoch = runtime_epoch[this->child_pid, "
                "this->child_incarnation]"
            ),
            (
                "catalog_live[this->child_pid, this->child_incarnation, "
                "(uint64_t)1, this->child_epoch] = 0"
            ),
            (
                "pending_by_pid[this->child_pid, this->child_incarnation, "
                "(uint64_t)1, this->child_epoch] = 0"
            ),
        ),
        description="created owner clause-local identity binding",
        exact_actions=True,
        ordered_actions=True,
        unique_assignment_targets=(
            "this->child_pid",
            "this->child_incarnation",
            "this->child_epoch",
        ),
    )
    _require_d_clause(
        clauses,
        "carrick*:::dsr-run-begin",
        predicate=(
            "pending_start[pid, incarnation[pid]",
            "pending_end[pid, incarnation[pid]",
        ),
        actions=(
            (
                "this->run_unit = pending_unit[pid, incarnation[pid], "
                "image_generation[pid, incarnation[pid]], "
                "runtime_epoch[pid, incarnation[pid]], arg0]"
            ),
            (
                "this->run_start = pending_start[pid, incarnation[pid], "
                "image_generation[pid, incarnation[pid]], "
                "runtime_epoch[pid, incarnation[pid]], arg0]"
            ),
            (
                "this->run_end = pending_end[pid, incarnation[pid], "
                "image_generation[pid, incarnation[pid]], "
                "runtime_epoch[pid, incarnation[pid]], arg0]"
            ),
            (
                "this->run_announcement_ordinal = ann_ordinal[pid, "
                "incarnation[pid], image_generation[pid, incarnation[pid]], "
                "runtime_epoch[pid, incarnation[pid]], this->run_unit]"
            ),
            (
                "this->run_commit_ordinal = pending_commit_ordinal[pid, "
                "incarnation[pid], image_generation[pid, incarnation[pid]], "
                "runtime_epoch[pid, incarnation[pid]], arg0]"
            ),
            (
                'printf("TRANSLATED_RANGE|ordinal=%d|process_ordinal=%d|'
                "kind=shared-run-begin|pid=%d|incarnation=%d|tid=%d|"
                "unit_id=%d|start=%#x|end=%#x|announcement_ordinal=%d|"
                "commit_ordinal=%d|run_ordinal=%d|guest_pc=%#x|cache_pc=%#x|"
                'generation=%d\\n", ordinal, process_ordinal[pid], pid, '
                "incarnation[pid], arg0, this->run_unit, this->run_start, "
                "this->run_end, this->run_announcement_ordinal, "
                "this->run_commit_ordinal, ordinal, arg1, arg2, arg3)"
            ),
        ),
        description="shared run clause-local identity binding",
        exact_actions=True,
        ordered_actions=True,
        unique_assignment_targets=(
            "this->run_unit",
            "this->run_start",
            "this->run_end",
            "this->run_announcement_ordinal",
            "this->run_commit_ordinal",
        ),
        unique_call_names=("printf",),
    )

    expected_arities = {
        "catalog_live": 4,
        "pending_by_pid": 4,
        "ready_seen": 4,
        "private_count": 4,
        "private_start": 4,
        "private_end": 4,
        "metadata_host_base": 4,
        "metadata_host_catalog": 4,
        "metadata_guest_base": 4,
        "metadata_jit_range": 4,
        "metadata_complete": 4,
        "ann_epoch": 5,
        "ann_start": 5,
        "ann_end": 5,
        "ann_ordinal": 5,
        "pending_present": 5,
        "pending_epoch": 5,
        "pending_unit": 5,
        "pending_start": 5,
        "pending_end": 5,
        "pending_commit_ordinal": 5,
    }
    for name, arity in expected_arities.items():
        actual = _d_index_arities(executable, name)
        if actual != {arity}:
            raise EvidenceError(
                f"maintained lifecycle {name} identity tuple arity is {sorted(actual)}, "
                f"expected {arity}"
            )
    for name, expected in _expected_d_identity_accesses().items():
        actual = Counter(_d_index_expressions(executable, name))
        if actual != expected:
            raise EvidenceError(
                f"maintained lifecycle {name} generation/epoch identity tuple drifted"
            )

    return {
        "schema2_summaries": schema2,
        "lifecycle_summaries": lifecycle,
        "self_bound_seconds": 30,
        "guest_exit_authority": 1,
    }


def _load_default_overlay(path: pathlib.Path) -> tuple[dict[str, None], bytes]:
    raw = _regular_bytes(path, "native-default overlay")

    class ObjectPairs(list):
        pass

    try:
        payload = json.loads(raw, object_pairs_hook=ObjectPairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise EvidenceError("native-default overlay is not valid JSON") from error
    if not isinstance(payload, ObjectPairs):
        raise EvidenceError("native-default overlay must be a JSON object")
    keys = tuple(key for key, _value in payload)
    if (
        keys != native_go_build.PERFORMANCE_CONTROL_KEYS
        or len(set(keys)) != len(keys)
    ):
        raise EvidenceError(
            "native-default overlay must contain performance controls exactly "
            "once in canonical order"
        )
    if any(type(key) is not str or value is not None for key, value in payload):
        raise EvidenceError(
            "lifecycle capture requires the complete sharing-disabled native-default overlay"
        )
    expected = {key: None for key in keys}
    return expected, raw


def _parse_dof_otool_listing(raw: bytes) -> dict[str, object]:
    """Return the one supported, nonempty DOF section in an otool listing."""

    if type(raw) is not bytes:
        raise EvidenceError("DOF otool listing is not raw bytes")
    try:
        listing = raw.decode()
    except UnicodeDecodeError as error:
        raise EvidenceError("DOF otool listing is not UTF-8 text") from error
    if not listing.strip():
        raise EvidenceError("DOF otool listing is empty")

    lines = listing.splitlines()
    target_indexes = [
        index
        for index, line in enumerate(lines)
        if line.strip() == f"sectname {DOF_SECTION}"
    ]
    if len(target_indexes) != 1:
        raise EvidenceError(
            f"DOF inspection requires exactly one sectname {DOF_SECTION}, "
            f"found {len(target_indexes)}"
        )
    target_index = target_indexes[0]

    load_starts = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(r"Load command [0-9]+", line.strip())
    ]
    load_start = next(
        (index for index in reversed(load_starts) if index < target_index),
        None,
    )
    if load_start is None:
        raise EvidenceError("DOF section is outside a Mach-O load command")
    load_end = next(
        (index for index in load_starts if index > target_index),
        len(lines),
    )
    command_lines = lines[load_start:load_end]

    section_starts = [
        load_start + index
        for index, line in enumerate(command_lines)
        if line.strip() == "Section"
    ]
    section_start = next(
        (index for index in reversed(section_starts) if index < target_index),
        None,
    )
    if section_start is None:
        raise EvidenceError("DOF sectname is outside a structural Section block")
    section_end = next(
        (index for index in section_starts if index > target_index),
        load_end,
    )
    if target_index != section_start + 1:
        raise EvidenceError("DOF Section block has malformed field order")

    header_lines = lines[load_start + 1 : section_starts[0]]
    commands = [
        line.strip().split(None, 1)[1]
        for line in header_lines
        if line.strip().startswith("cmd ")
    ]
    if commands != ["LC_SEGMENT_64"]:
        raise EvidenceError("DOF section is not in one LC_SEGMENT_64 load command")
    load_segments = [
        line.strip().split(None, 1)[1]
        for line in header_lines
        if line.strip().startswith("segname ")
    ]
    if len(load_segments) != 1:
        raise EvidenceError("DOF load command has malformed segment identity")

    section_lines = lines[section_start + 1 : section_end]

    def section_field(name: str) -> str:
        prefix = name + " "
        values = [
            line.strip().split(None, 1)[1]
            for line in section_lines
            if line.strip().startswith(prefix)
        ]
        if len(values) != 1:
            raise EvidenceError(f"DOF Section block has malformed {name} field")
        return values[0]

    section_name = section_field("sectname")
    segment = section_field("segname")
    size_token = section_field("size")
    if section_name != DOF_SECTION:
        raise EvidenceError("DOF Section block identity drifted")
    if segment != load_segments[0]:
        raise EvidenceError("DOF section segment differs from its load command")
    if segment not in SUPPORTED_DOF_SEGMENTS:
        raise EvidenceError(
            f"DOF section is in unsupported loadable segment {segment!r}"
        )
    if re.fullmatch(r"0x[0-9a-fA-F]+", size_token) is None:
        raise EvidenceError("DOF section size is malformed")
    size = int(size_token, 16)
    if size <= 0:
        raise EvidenceError("DOF section size must be positive")

    return {
        "section": section_name,
        "segment": segment,
        "size": size,
        "otool_listing_sha256": _sha256_bytes(raw),
    }


def _dof_from_otool(binary: pathlib.Path) -> dict[str, object]:
    result = subprocess.run(
        ["otool", "-l", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        stdout = result.stdout.decode(errors="replace").strip()
        raise EvidenceError(
            "DOF inspection failed: " + (stderr or stdout)
        )
    return _parse_dof_otool_listing(result.stdout)


def _validated_dof_evidence(
    value: object, description: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != DOF_EVIDENCE_FIELDS:
        raise EvidenceError(f"{description} DOF evidence field set is not exact")
    section = value.get("section")
    segment = value.get("segment")
    size = value.get("size")
    listing_sha = value.get("otool_listing_sha256")
    if section != DOF_SECTION:
        raise EvidenceError(f"{description} DOF section identity is invalid")
    if segment not in SUPPORTED_DOF_SEGMENTS:
        raise EvidenceError(f"{description} DOF segment is unsupported")
    if type(size) is not int or size <= 0:
        raise EvidenceError(f"{description} DOF section size is invalid")
    if (
        type(listing_sha) is not str
        or re.fullmatch(r"[0-9a-f]{64}", listing_sha) is None
    ):
        raise EvidenceError(f"{description} DOF otool listing hash is invalid")
    return {
        "section": section,
        "segment": segment,
        "size": size,
        "otool_listing_sha256": listing_sha,
    }


def _revalidate_dof(
    ops: object,
    binary: pathlib.Path,
    expected: Mapping[str, object],
    description: str,
) -> None:
    current = _validated_dof_evidence(
        ops.inspect_dof(binary), description
    )
    if current != expected:
        raise EvidenceError(f"{description} DOF evidence drifted")


def _delimited_process_token(command: str, token: str) -> bool:
    start = 0
    while True:
        index = command.find(token, start)
        if index < 0:
            return False
        following = index + len(token)
        if following == len(command) or command[following] in " \t\\\"'":
            return True
        start = index + 1


def matching_run_processes(
    records: Sequence[tuple[int, str]],
    *,
    run_id: str,
) -> list[tuple[int, str]]:
    """Match every exact scoped shape consumed by scripts/sudo/kill.sh."""

    if not RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("process census run ID is malformed")
    guest_title = f"carrick:{run_id}:"
    tokens = (
        f"CARRICK_RUN_ID={run_id}",
        f"--name {run_id}",
        f"run_id={run_id}",
    )
    matches: list[tuple[int, str]] = []
    for process_id, command in records:
        if type(process_id) is not int or process_id <= 0 or type(command) is not str:
            raise EvidenceError("process census record is malformed")
        if "scripts/sudo/kill.sh" in command:
            continue
        if guest_title in command or (
            "carrick trace" in command
            and any(_delimited_process_token(command, token) for token in tokens)
        ):
            matches.append((process_id, command))
    return matches


class SystemBoundary:
    def verify_arm(self, receipt: pathlib.Path):
        return native_go_build_abba.load_and_verify_arm(receipt)

    def inspect_dof(self, binary: pathlib.Path) -> dict[str, object]:
        return _dof_from_otool(binary)

    def running_docker_oracles(self) -> list[str]:
        return native_go_build.running_docker_oracles()

    def process_records(self) -> list[tuple[int, str]]:
        result = subprocess.run(
            ["ps", "-axww", "-o", "pid=", "-o", "command="],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            raise EvidenceError(
                "exact-run-ID census failed: "
                + (result.stderr.strip() or result.stdout.strip())
            )
        records: list[tuple[int, str]] = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            fields = stripped.split(None, 1)
            if len(fields) != 2:
                raise EvidenceError(f"process census line is malformed: {line!r}")
            try:
                process_id = int(fields[0])
            except ValueError as error:
                raise EvidenceError(
                    f"process census PID is malformed: {fields[0]!r}"
                ) from error
            records.append((process_id, fields[1]))
        return records

    def uuid4(self) -> uuid.UUID:
        return uuid.uuid4()

    def reap(self, repo: pathlib.Path, run_id: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(repo / "scripts/sudo/kill.sh"), run_id],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def checkpoint(self, phase: str) -> None:
        del phase

    def launch(
        self,
        argv: list[str],
        *,
        cwd: pathlib.Path,
        env: dict[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


def _executed_image_ref(arm: object) -> str:
    image_ref = str(arm.image_ref)
    if image_ref != EXPECTED_IMAGE:
        raise EvidenceError(
            f"lifecycle capture requires exact campaign image {EXPECTED_IMAGE}"
        )
    if getattr(arm, "role", None) != "candidate":
        raise EvidenceError("lifecycle capture requires a candidate arm receipt")
    repository = image_ref.split("@", 1)[0]
    last_slash = repository.rfind("/")
    last_colon = repository.rfind(":")
    if last_colon > last_slash:
        repository = repository[:last_colon]
    matches = [
        digest
        for digest in arm.image_repo_digests
        if digest.split("@", 1)[0] == repository
    ]
    if len(matches) != 1:
        raise EvidenceError(
            "arm receipt requires exactly one repository-matching immutable image digest"
        )
    return str(matches[0])


def _snapshot_inputs(
    config: LifecycleCaptureConfig, arm: object, overlay_raw: bytes
) -> dict[str, dict[str, object]]:
    return {
        "binary": _descriptor(pathlib.Path(arm.binary_path)),
        "script": _descriptor(config.script),
        "arm_receipt": _descriptor(config.receipt),
        "overlay": _descriptor(config.overlay, overlay_raw),
    }


def _verify_input_snapshot(
    config: LifecycleCaptureConfig,
    arm: object,
    expected: Mapping[str, Mapping[str, object]],
) -> None:
    current = _snapshot_inputs(
        config,
        arm,
        _regular_bytes(config.overlay, "native-default overlay"),
    )
    for name in expected:
        if current[name] != expected[name]:
            raise EvidenceError(f"{name.replace('_', ' ')} input drifted")


def _safe_launch_environment(run_id: str) -> dict[str, str]:
    environment = {
        "HOME": str(pathlib.Path.home()),
        "PATH": SAFE_LAUNCH_PATH,
        "TMPDIR": tempfile.gettempdir(),
        "LANG": "C",
        "LC_ALL": "C",
        "CARRICK_DSR_PROFILE": "1",
        "CARRICK_RUN_ID": run_id,
    }
    if set(environment) != SAFE_LAUNCH_ENV_KEYS | CARRICK_ENV_ALLOWLIST:
        raise EvidenceError("safe lifecycle launch environment is not exact")
    return environment


def _controlled_environment(run_id: str) -> tuple[dict[str, str], dict[str, object]]:
    environment = _safe_launch_environment(run_id)
    controls = {
        key: environment.get(key)
        for key in native_go_build.PERFORMANCE_CONTROL_KEYS
    }
    expected_controls = {
        key: "1" if key == "CARRICK_DSR_PROFILE" else None
        for key in native_go_build.PERFORMANCE_CONTROL_KEYS
    }
    if controls != expected_controls:
        raise EvidenceError("effective lifecycle environment is not profile-only")
    carrick_environment = {
        key: value
        for key, value in environment.items()
        if key.startswith("CARRICK_")
    }
    expected_carrick_environment = {
        "CARRICK_DSR_PROFILE": "1",
        "CARRICK_RUN_ID": run_id,
    }
    if carrick_environment != expected_carrick_environment:
        raise EvidenceError("effective lifecycle Carrick environment is not exact")
    evidence = {
        "performance_controls": controls,
        "carrick_environment": carrick_environment,
        "run_id": run_id,
        "launch_environment": environment,
        "effective_environment_sha256": _sha256_json(environment),
    }
    evidence["sha256"] = _sha256_json(evidence)
    return environment, evidence


def _write_bytes_atomic(path: pathlib.Path, content: bytes) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise EvidenceError(f"accepted artifact destination already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise EvidenceError(
                f"accepted artifact destination already exists: {path}"
            ) from error
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


@dataclasses.dataclass(frozen=True)
class _OwnedTraceTemp:
    path: pathlib.Path
    descriptor: int
    device: int
    inode: int


def _reserve_trace_temp(destination: pathlib.Path) -> _OwnedTraceTemp:
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".capture",
        dir=destination.parent,
    )
    metadata = os.fstat(descriptor)
    return _OwnedTraceTemp(
        path=pathlib.Path(name),
        descriptor=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _trace_temp_is_owned(temporary: _OwnedTraceTemp) -> bool:
    try:
        metadata = temporary.path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    return metadata.st_dev == temporary.device and metadata.st_ino == temporary.inode


def _read_owned_trace_temp(temporary: _OwnedTraceTemp) -> bytes:
    if not _trace_temp_is_owned(temporary):
        raise EvidenceError("lifecycle trace temporary identity drifted")
    metadata = os.fstat(temporary.descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError("lifecycle trace temporary is not a regular file")
    os.fsync(temporary.descriptor)
    os.lseek(temporary.descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(temporary.descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _publish_owned_trace_temp(
    temporary: _OwnedTraceTemp, destination: pathlib.Path
) -> None:
    destination = destination.resolve()
    if not _trace_temp_is_owned(temporary):
        raise EvidenceError("lifecycle trace temporary identity drifted before publication")
    try:
        os.link(temporary.path, destination, follow_symlinks=False)
    except FileExistsError as error:
        raise EvidenceError(
            f"accepted artifact destination already exists: {destination}"
        ) from error
    published = destination.stat(follow_symlinks=False)
    if published.st_dev != temporary.device or published.st_ino != temporary.inode:
        destination.unlink(missing_ok=True)
        raise EvidenceError("published lifecycle trace identity drifted")
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    temporary.path.unlink()


def _cleanup_owned_trace_temp(temporary: _OwnedTraceTemp | None) -> None:
    if temporary is None:
        return
    try:
        if _trace_temp_is_owned(temporary):
            temporary.path.unlink()
    finally:
        os.close(temporary.descriptor)


def reserve_run_id(repo: pathlib.Path, run_id: str) -> pathlib.Path:
    """Durably reserve a lifecycle identity across processes with O_EXCL."""

    if not RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("lifecycle run ID is not a canonical UUID4 identity")
    directory = (repo.resolve() / RUN_ID_RESERVATION_DIR).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / run_id
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise EvidenceError(f"lifecycle run ID is already reserved or reused: {run_id}") from error
    content = (run_id + "\n").encode()
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return path


def _marker_result(stdout: str) -> dict[str, object]:
    lines = stdout.splitlines()
    child_count = lines.count("CHILD_EXEC_OK")
    parent_count = lines.count("PARENT_WAIT_OK")
    if child_count != 1 or parent_count != 1:
        raise EvidenceError("lifecycle stdout markers must each appear exactly once")
    child_index = lines.index("CHILD_EXEC_OK")
    parent_index = lines.index("PARENT_WAIT_OK")
    if child_index >= parent_index:
        raise EvidenceError("lifecycle stdout marker order is invalid")
    return {
        "child_exec_ok": child_count,
        "parent_wait_ok": parent_count,
        "ordered": True,
        "sha256": _sha256_json(
            ["CHILD_EXEC_OK", "PARENT_WAIT_OK"]
        ),
    }


def _reap_error(label: str, result: subprocess.CompletedProcess[str]) -> EvidenceError:
    detail = result.stderr.strip() or result.stdout.strip()
    suffix = f": {detail}" if detail else ""
    return EvidenceError(f"{label} failed with status {result.returncode}{suffix}")


def capture_lifecycle(
    config: LifecycleCaptureConfig,
    *,
    boundary: object | None = None,
) -> dict[str, Any]:
    """Capture one launch-owned fork/exec lifecycle proof."""

    ops = SystemBoundary() if boundary is None else boundary
    repo = config.repo.resolve()
    if not repo.is_dir():
        raise EvidenceError(f"capture repository is absent: {repo}")
    for path in (
        config.trace_out,
        config.summary_jsonl,
        config.stdout,
        config.capture_receipt,
    ):
        if os.path.lexists(path.resolve()):
            raise EvidenceError(f"capture output already exists: {path.resolve()}")

    _overlay, overlay_raw = _load_default_overlay(config.overlay)
    try:
        script_text = _regular_bytes(
            config.script, "maintained lifecycle script"
        ).decode()
    except UnicodeDecodeError as error:
        raise EvidenceError("maintained lifecycle script is not UTF-8") from error
    validate_dtrace_source(script_text)
    arm = ops.verify_arm(config.receipt.resolve())
    if pathlib.Path(arm.path).resolve() != config.receipt.resolve():
        raise EvidenceError("verified arm receipt identity drifted")
    binary = pathlib.Path(arm.binary_path).resolve()
    dof = _validated_dof_evidence(
        ops.inspect_dof(binary), "arm binary"
    )
    executed_image = _executed_image_ref(arm)
    inputs = _snapshot_inputs(config, arm, overlay_raw)
    if inputs["binary"]["sha256"] != arm.binary_sha256:
        raise EvidenceError("arm binary hash differs from verified receipt")
    if ops.running_docker_oracles():
        raise EvidenceError("Docker oracle is running before lifecycle capture")

    run_uuid = ops.uuid4()
    run_id = RUN_ID_PREFIX + str(run_uuid)
    if run_uuid.version != 4 or not RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("lifecycle run ID is not a canonical UUID4 identity")
    reservation = reserve_run_id(repo, run_id)
    initial_matches = matching_run_processes(
        ops.process_records(), run_id=run_id
    )
    if initial_matches:
        raise EvidenceError(
            "generated lifecycle run ID is already present in the process census"
        )

    trace_temporary = _reserve_trace_temp(config.trace_out)
    primary_error: BaseException | None = None
    result: subprocess.CompletedProcess[str] | None = None
    parsed: dict[str, Any] | None = None
    markers: dict[str, object] | None = None
    command: list[str] | None = None
    environment_evidence: dict[str, object] | None = None
    final_cleanup: subprocess.CompletedProcess[str] | None = None
    trace_raw: bytes | None = None
    cleanup_attempts = 0
    try:
        try:
            pre_cleanup = ops.reap(repo, run_id)
            if pre_cleanup.returncode != 0:
                raise _reap_error("pre-launch reap", pre_cleanup)
            ops.checkpoint("after-pre-reap")
            ops.checkpoint("before-launch")

            reverified = ops.verify_arm(config.receipt.resolve())
            if reverified != arm or _executed_image_ref(reverified) != executed_image:
                raise EvidenceError("arm receipt verification drifted before launch")
            _revalidate_dof(ops, binary, dof, "arm binary before launch")
            _verify_input_snapshot(config, arm, inputs)
            _load_default_overlay(config.overlay)
            validate_dtrace_source(config.script.read_text())

            environment, environment_evidence = _controlled_environment(run_id)
            command = [
                str(binary),
                "trace",
                "--script",
                str(config.script.resolve()),
                "--trace-out",
                str(trace_temporary.path.resolve()),
                "--",
                "run",
                "--exec-backend",
                "native",
                "--pull",
                "never",
                executed_image,
                "/bin/sh",
                "-c",
                LIFECYCLE_REDUCER,
            ]
            try:
                result = ops.launch(
                    command,
                    cwd=repo,
                    env=environment,
                    timeout=config.timeout_seconds,
                )
            except subprocess.TimeoutExpired as error:
                raise EvidenceError(
                    f"lifecycle trace command timed out after {HOST_TIMEOUT_SECONDS} seconds"
                ) from error
            ops.checkpoint("after-launch")
            if result.returncode != 0:
                raise EvidenceError(
                    f"lifecycle trace command failed with status {result.returncode}: "
                    + (result.stderr.strip() or result.stdout.strip())
                )
            trace_raw = _read_owned_trace_temp(trace_temporary)
            if not trace_raw.strip():
                raise EvidenceError("empty trace cannot prove lifecycle ownership")
            try:
                trace_text = trace_raw.decode()
            except UnicodeDecodeError as error:
                raise EvidenceError("lifecycle raw trace is not UTF-8 text") from error
            parsed = parse_lifecycle_trace(trace_text)
            markers = _marker_result(result.stdout)

            reverified = ops.verify_arm(config.receipt.resolve())
            if reverified != arm or _executed_image_ref(reverified) != executed_image:
                raise EvidenceError("arm receipt verification drifted after launch")
            _revalidate_dof(ops, binary, dof, "arm binary after launch")
            _verify_input_snapshot(config, arm, inputs)
            _load_default_overlay(config.overlay)
            validate_dtrace_source(config.script.read_text())
            ops.checkpoint("before-publish")
        except BaseException as error:
            primary_error = error
        finally:
            cleanup_errors: list[BaseException] = []
            for attempt in range(1, 3):
                cleanup_attempts = attempt
                try:
                    candidate = ops.reap(repo, run_id)
                except BaseException as error:
                    cleanup_errors.append(error)
                    continue
                if candidate.returncode != 0:
                    cleanup_errors.append(_reap_error(f"final reap attempt {attempt}", candidate))
                    continue
                final_cleanup = candidate
                break
            try:
                final_matches = matching_run_processes(
                    ops.process_records(), run_id=run_id
                )
            except BaseException as error:
                cleanup_errors.append(error)
                final_matches = []
            if final_matches:
                cleanup_errors.append(
                    EvidenceError("exact-run-ID leftover remains after final reap")
                )
            if cleanup_errors:
                cleanup_error = cleanup_errors[0]
                if primary_error is None:
                    primary_error = cleanup_error
                else:
                    primary_error = EvidenceError(
                        f"capture failed and cleanup also failed: {cleanup_error}"
                    )

        if primary_error is not None:
            raise primary_error
        if final_cleanup is None:
            raise EvidenceError("final reap did not complete successfully")
        if result is None or parsed is None or markers is None or command is None:
            raise EvidenceError("lifecycle capture finished without a closed command result")
        if environment_evidence is None or trace_raw is None:
            raise EvidenceError("lifecycle capture lacks closed environment or trace evidence")
        if ops.running_docker_oracles():
            raise EvidenceError("Docker oracle is running after lifecycle capture")

        reverified = ops.verify_arm(config.receipt.resolve())
        if reverified != arm or _executed_image_ref(reverified) != executed_image:
            raise EvidenceError("arm receipt verification drifted before publication")
        _revalidate_dof(ops, binary, dof, "arm binary before publication")
        _verify_input_snapshot(config, arm, inputs)
        _load_default_overlay(config.overlay)
        validate_dtrace_source(config.script.read_text())

        stdout_raw = result.stdout.encode()
        _write_bytes_atomic(config.stdout, stdout_raw)
        summary_record = {key: parsed[key] for key in sorted(SUMMARY_FIELDS)}
        summary_record["target_pid"] = parsed["target_pid"]
        summary_record["child_pid"] = parsed["child_pid"]
        summary_record["event_count"] = parsed["event_count"]
        summary_raw = _canonical_json_bytes(summary_record) + b"\n"
        _write_bytes_atomic(config.summary_jsonl, summary_raw)
        _publish_owned_trace_temp(trace_temporary, config.trace_out)

        artifacts = {
            **inputs,
            "run_id_reservation": _descriptor(reservation),
            "raw_trace": _descriptor(config.trace_out, trace_raw),
            "summary_jsonl": _descriptor(config.summary_jsonl, summary_raw),
            "stdout": _descriptor(config.stdout, stdout_raw),
        }
        payload: dict[str, Any] = {
            "schema": CAPTURE_SCHEMA,
            "outcome": "accepted",
            "observability_only": True,
            "cpu_evidence": False,
            "run_id": run_id,
            "artifacts": artifacts,
            "dof": dof,
            "environment": environment_evidence,
            "argv": command,
            "argv_sha256": _sha256_json(command),
            "reducer": LIFECYCLE_REDUCER,
            "reducer_sha256": _sha256_bytes(LIFECYCLE_REDUCER.encode()),
            "markers": markers,
            "lifecycle_summary": summary_record,
            "timeout_seconds": config.timeout_seconds,
            "cleanup": {
                "argv": [str(repo / "scripts/sudo/kill.sh"), run_id],
                "status": final_cleanup.returncode,
                "attempts": cleanup_attempts,
                "census": [],
                "stdout": final_cleanup.stdout,
                "stderr": final_cleanup.stderr,
                "stdout_sha256": _sha256_bytes(final_cleanup.stdout.encode()),
                "stderr_sha256": _sha256_bytes(final_cleanup.stderr.encode()),
            },
        }
        payload["closure"] = {
            "algorithm": "sha256",
            "scope": "canonical-payload-without-closure",
            "sha256": _sha256_json(payload),
        }
        native_go_build.write_json_atomic(
            config.capture_receipt.resolve(), payload, exclusive=True
        )
        return payload
    finally:
        _cleanup_owned_trace_temp(trace_temporary)


def _load_json_object(path: pathlib.Path, description: str) -> dict[str, Any]:
    raw = _regular_bytes(path, description)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise EvidenceError(f"{description} is not valid JSON") from error
    if type(payload) is not dict:
        raise EvidenceError(f"{description} must be a JSON object")
    return payload


def validate_capture_receipt(
    path: pathlib.Path,
    *,
    boundary: object | None = None,
) -> dict[str, Any]:
    """Reload and independently verify every accepted lifecycle claim."""

    ops = SystemBoundary() if boundary is None else boundary
    payload = _load_json_object(path.resolve(), "lifecycle capture receipt")
    required_fields = {
        "schema",
        "outcome",
        "observability_only",
        "cpu_evidence",
        "run_id",
        "artifacts",
        "dof",
        "environment",
        "argv",
        "argv_sha256",
        "reducer",
        "reducer_sha256",
        "markers",
        "lifecycle_summary",
        "timeout_seconds",
        "cleanup",
        "closure",
    }
    if set(payload) != required_fields:
        raise EvidenceError("capture receipt field set is not exact")
    closure = payload["closure"]
    if type(closure) is not dict or set(closure) != {
        "algorithm",
        "scope",
        "sha256",
    }:
        raise EvidenceError("capture receipt lacks its non-self-referential closure")
    without_closure = dict(payload)
    without_closure.pop("closure")
    if (
        closure.get("algorithm") != "sha256"
        or closure.get("scope") != "canonical-payload-without-closure"
        or closure.get("sha256") != _sha256_json(without_closure)
    ):
        raise EvidenceError("capture receipt closure hash differs")
    if (
        payload.get("schema") != CAPTURE_SCHEMA
        or payload.get("outcome") != "accepted"
        or payload.get("observability_only") is not True
        or payload.get("cpu_evidence") is not False
        or payload.get("timeout_seconds") != HOST_TIMEOUT_SECONDS
    ):
        raise EvidenceError("capture receipt acceptance fields are invalid")
    run_id = payload.get("run_id")
    if type(run_id) is not str or not RUN_ID_RE.fullmatch(run_id):
        raise EvidenceError("capture receipt run ID is malformed")
    recorded_dof = _validated_dof_evidence(
        payload.get("dof"), "capture receipt"
    )

    artifacts = payload.get("artifacts")
    required_artifacts = {
        "binary",
        "script",
        "arm_receipt",
        "overlay",
        "run_id_reservation",
        "raw_trace",
        "summary_jsonl",
        "stdout",
    }
    if type(artifacts) is not dict or set(artifacts) != required_artifacts:
        raise EvidenceError("capture receipt artifact set is not exact")
    artifact_paths: dict[str, pathlib.Path] = {}
    artifact_raw: dict[str, bytes] = {}
    for name, descriptor in artifacts.items():
        if type(descriptor) is not dict or set(descriptor) != {
            "path",
            "size",
            "sha256",
        }:
            raise EvidenceError(f"{name} artifact descriptor is malformed")
        if (
            type(descriptor["path"]) is not str
            or type(descriptor["size"]) is not int
            or descriptor["size"] < 0
            or type(descriptor["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", descriptor["sha256"]) is None
        ):
            raise EvidenceError(f"{name} artifact descriptor is malformed")
        artifact_path = pathlib.Path(descriptor["path"])
        if (
            not artifact_path.is_absolute()
            or str(artifact_path.resolve()) != descriptor["path"]
        ):
            raise EvidenceError(f"{name} artifact path is not canonical absolute")
        raw = _regular_bytes(artifact_path, f"receipt {name} artifact")
        if (
            descriptor["size"] != len(raw)
            or descriptor["sha256"] != _sha256_bytes(raw)
        ):
            raise EvidenceError(f"{name.replace('_', ' ')} artifact hash differs")
        artifact_paths[name] = artifact_path
        artifact_raw[name] = raw
    if len(set(artifact_paths.values())) != len(artifact_paths):
        raise EvidenceError("capture receipt artifact paths are not distinct")

    script_path = artifact_paths["script"]
    try:
        repo = script_path.parents[2]
    except IndexError as error:
        raise EvidenceError("capture receipt script path has no repository root") from error
    if script_path != repo / "scripts/dtrace/native-translated-range-catalog.d":
        raise EvidenceError("capture receipt does not name the maintained lifecycle script")
    try:
        script_text = artifact_raw["script"].decode()
    except UnicodeDecodeError as error:
        raise EvidenceError("receipt lifecycle script is not UTF-8") from error
    validate_dtrace_source(script_text)

    overlay, overlay_raw = _load_default_overlay(artifact_paths["overlay"])
    expected_overlay = {
        key: None for key in native_go_build.PERFORMANCE_CONTROL_KEYS
    }
    if overlay_raw != artifact_raw["overlay"] or overlay != expected_overlay:
        raise EvidenceError("capture receipt native-default overlay is not exact")

    reservation_path = artifact_paths["run_id_reservation"]
    expected_reservation = (repo / RUN_ID_RESERVATION_DIR / run_id).resolve()
    if reservation_path != expected_reservation:
        raise EvidenceError("capture receipt run-ID reservation path differs")
    if artifact_raw["run_id_reservation"] != (run_id + "\n").encode():
        raise EvidenceError("capture receipt run-ID reservation content differs")

    try:
        arm = ops.verify_arm(artifact_paths["arm_receipt"])
    except Exception as error:
        raise EvidenceError("capture receipt arm re-verification failed") from error
    if pathlib.Path(arm.path).resolve() != artifact_paths["arm_receipt"]:
        raise EvidenceError("capture receipt arm identity drifted")
    binary_path = pathlib.Path(arm.binary_path).resolve()
    if binary_path != artifact_paths["binary"]:
        raise EvidenceError("capture receipt binary path differs from verified arm")
    if arm.binary_sha256 != artifacts["binary"]["sha256"]:
        raise EvidenceError("capture receipt binary hash differs from verified arm")
    _revalidate_dof(
        ops,
        binary_path,
        recorded_dof,
        "capture receipt binary",
    )
    executed_image = _executed_image_ref(arm)

    argv = payload.get("argv")
    reducer = payload.get("reducer")
    if type(argv) is not list or not all(type(item) is str for item in argv):
        raise EvidenceError("capture receipt argv is malformed")
    if payload.get("argv_sha256") != _sha256_json(argv):
        raise EvidenceError("capture receipt argv hash differs")
    if (
        reducer != LIFECYCLE_REDUCER
        or payload.get("reducer_sha256")
        != _sha256_bytes(LIFECYCLE_REDUCER.encode())
    ):
        raise EvidenceError("capture receipt reducer hash differs")
    raw_trace_path = artifact_paths["raw_trace"]
    try:
        trace_index = argv.index("--trace-out") + 1
        trace_temporary = pathlib.Path(argv[trace_index])
    except (ValueError, IndexError) as error:
        raise EvidenceError("capture receipt trace temporary is absent") from error
    if (
        not trace_temporary.is_absolute()
        or str(trace_temporary.resolve()) != str(trace_temporary)
        or trace_temporary == raw_trace_path
        or trace_temporary.parent != raw_trace_path.parent
        or not trace_temporary.name.startswith(f".{raw_trace_path.name}.")
        or not trace_temporary.name.endswith(".capture")
    ):
        raise EvidenceError("capture receipt trace temporary identity is invalid")
    expected_argv = [
        str(binary_path),
        "trace",
        "--script",
        str(script_path),
        "--trace-out",
        str(trace_temporary),
        "--",
        "run",
        "--exec-backend",
        "native",
        "--pull",
        "never",
        executed_image,
        "/bin/sh",
        "-c",
        LIFECYCLE_REDUCER,
    ]
    if argv != expected_argv:
        raise EvidenceError("capture receipt trace invocation is not exact")

    environment = payload.get("environment")
    required_environment = {
        "performance_controls",
        "carrick_environment",
        "run_id",
        "launch_environment",
        "effective_environment_sha256",
        "sha256",
    }
    if type(environment) is not dict or set(environment) != required_environment:
        raise EvidenceError("capture receipt environment field set is not exact")
    controls = environment["performance_controls"]
    expected_controls = {
        key: "1" if key == "CARRICK_DSR_PROFILE" else None
        for key in native_go_build.PERFORMANCE_CONTROL_KEYS
    }
    if (
        type(controls) is not dict
        or set(controls) != set(native_go_build.PERFORMANCE_CONTROL_KEYS)
        or _canonical_json_bytes(controls)
        != _canonical_json_bytes(expected_controls)
    ):
        raise EvidenceError(
            "capture receipt performance environment is not profile-only"
        )
    expected_carrick_environment = {
        "CARRICK_DSR_PROFILE": "1",
        "CARRICK_RUN_ID": run_id,
    }
    if environment["carrick_environment"] != expected_carrick_environment:
        raise EvidenceError("capture receipt Carrick environment is not exact")
    if environment["run_id"] != run_id:
        raise EvidenceError("capture receipt environment run ID differs")
    expected_launch_environment = _safe_launch_environment(run_id)
    if environment["launch_environment"] != expected_launch_environment:
        raise EvidenceError("capture receipt launch environment is not exact")
    if (
        type(environment["effective_environment_sha256"]) is not str
        or re.fullmatch(
            r"[0-9a-f]{64}", environment["effective_environment_sha256"]
        )
        is None
    ):
        raise EvidenceError("capture receipt effective environment hash is malformed")
    if environment["effective_environment_sha256"] != _sha256_json(
        expected_launch_environment
    ):
        raise EvidenceError("capture receipt effective environment hash differs")
    environment_without_hash = dict(environment)
    environment_without_hash.pop("sha256")
    if environment["sha256"] != _sha256_json(environment_without_hash):
        raise EvidenceError("capture receipt environment hash differs")

    try:
        stdout_text = artifact_raw["stdout"].decode()
    except UnicodeDecodeError as error:
        raise EvidenceError("capture receipt stdout is not UTF-8") from error
    if payload.get("markers") != _marker_result(stdout_text):
        raise EvidenceError("capture receipt marker evidence differs")

    cleanup = payload.get("cleanup")
    required_cleanup = {
        "argv",
        "status",
        "attempts",
        "census",
        "stdout",
        "stderr",
        "stdout_sha256",
        "stderr_sha256",
    }
    expected_cleanup_argv = [str(repo / "scripts/sudo/kill.sh"), run_id]
    if type(cleanup) is not dict or set(cleanup) != required_cleanup:
        raise EvidenceError("capture receipt cleanup field set is not exact")
    if (
        cleanup["argv"] != expected_cleanup_argv
        or cleanup["status"] != 0
        or cleanup["attempts"] != 1
        or cleanup["census"] != []
    ):
        raise EvidenceError("capture receipt cleanup proof is not accepting")
    for field in ("stdout_sha256", "stderr_sha256"):
        if (
            type(cleanup[field]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", cleanup[field]) is None
        ):
            raise EvidenceError(f"capture receipt cleanup {field} is malformed")
    for stream in ("stdout", "stderr"):
        if type(cleanup[stream]) is not str:
            raise EvidenceError(f"capture receipt cleanup {stream} is malformed")
        if cleanup[f"{stream}_sha256"] != _sha256_bytes(
            cleanup[stream].encode()
        ):
            raise EvidenceError(f"capture receipt cleanup {stream} hash differs")

    try:
        trace_text = artifact_raw["raw_trace"].decode()
    except UnicodeDecodeError as error:
        raise EvidenceError("capture receipt raw trace is not UTF-8") from error
    parsed = parse_lifecycle_trace(trace_text)
    recorded_summary = payload.get("lifecycle_summary")
    if type(recorded_summary) is not dict or recorded_summary != parsed:
        raise EvidenceError("capture receipt lifecycle summary is malformed")
    expected_summary_raw = _canonical_json_bytes(recorded_summary) + b"\n"
    if artifact_raw["summary_jsonl"] != expected_summary_raw:
        raise EvidenceError("capture receipt summary JSONL differs")
    return payload


def _positive_timeout(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer") from error
    if parsed != 120:
        raise argparse.ArgumentTypeError("lifecycle timeout must be exactly 120")
    return parsed


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    capture = subcommands.add_parser(
        "capture-lifecycle", help="capture one fork/exec lifecycle proof"
    )
    capture.add_argument("--receipt", required=True, type=pathlib.Path)
    capture.add_argument("--overlay", required=True, type=pathlib.Path)
    capture.add_argument(
        "--timeout-seconds", required=True, type=_positive_timeout
    )
    capture.add_argument("--trace-out", required=True, type=pathlib.Path)
    capture.add_argument("--summary-jsonl", required=True, type=pathlib.Path)
    capture.add_argument("--stdout", required=True, type=pathlib.Path)
    capture.add_argument("--capture-receipt", required=True, type=pathlib.Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo = pathlib.Path(__file__).resolve().parents[2]
    try:
        payload = capture_lifecycle(
            LifecycleCaptureConfig(
                repo=repo,
                receipt=args.receipt,
                overlay=args.overlay,
                timeout_seconds=args.timeout_seconds,
                trace_out=args.trace_out,
                summary_jsonl=args.summary_jsonl,
                stdout=args.stdout,
                capture_receipt=args.capture_receipt,
                script=repo / "scripts/dtrace/native-translated-range-catalog.d",
            )
        )
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
