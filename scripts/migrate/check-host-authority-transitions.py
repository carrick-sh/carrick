#!/usr/bin/env python3
"""Normalize and review compiler-resolved host-authority diagnostics.

This module deliberately consumes only Cargo/Clippy JSON.  Rust name
resolution, cfg selection, target reachability, imports, and macro resolution
belong to the pinned compiler that produced the diagnostics.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any


CLIPPY_CODE = "clippy::disallowed_methods"
OPERATION_MESSAGE = re.compile(r"use of a disallowed method `([^`]+)`")
OPERATION_PATH = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+"
)
CATALOG_ID = re.compile(r"\b(HA-CATALOG-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b")
REVIEW_ID = re.compile(r"HA-([0-9]{6})")

ACTUAL_FIELDS = {"catalog_id", "operation", "source", "expansion", "profiles"}
REVIEW_FIELDS = {
    "review_id",
    *ACTUAL_FIELDS,
    "classification",
    "evidence",
    "rationale",
}
POINT_FIELDS = {
    "file",
    "byte_start",
    "byte_end",
    "line",
    "column",
    "line_start",
    "line_end",
    "column_start",
    "column_end",
}
CLASSIFICATION_AUTHORITIES = {
    "forbidden_semantic": {"guest_answer", "host_target"},
    "declared_backing": {"authorized_backing"},
    "declared_substrate": {"authenticated_carrier"},
}
GENERIC_RESOURCES = {
    "authenticated carrier",
    "authorized backing",
    "backing object",
    "carrier resource",
    "filesystem operation",
    "guest answer",
    "host resource",
    "host target",
    "network operation",
    "process state",
}


class InventoryError(Exception):
    """Compiler census evidence cannot satisfy the checked review contract."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def diagnostic_identity(row: Mapping[str, object]) -> str:
    """Return the review-preservation identity for one resolved diagnostic."""
    return _canonical_json(
        {
            "operation": row.get("operation"),
            "source": row.get("source"),
            "expansion": row.get("expansion"),
        }
    )


def _sort_key(row: Mapping[str, object]) -> tuple[object, ...]:
    source = row.get("source")
    if not isinstance(source, Mapping):
        return (str(row.get("operation")), "", 0, 0, "")
    return (
        str(row.get("operation")),
        str(source.get("file")),
        int(source.get("byte_start", 0))
        if isinstance(source.get("byte_start"), int)
        else 0,
        int(source.get("byte_end", 0))
        if isinstance(source.get("byte_end"), int)
        else 0,
        int(source.get("line_start", 0))
        if isinstance(source.get("line_start"), int)
        else 0,
        int(source.get("column_start", 0))
        if isinstance(source.get("column_start"), int)
        else 0,
        _canonical_json(row.get("expansion")),
    )


def _cargo_object(raw: object, index: int) -> dict[str, object]:
    if isinstance(raw, str):
        try:
            value: Any = json.loads(raw)
        except json.JSONDecodeError as error:
            raise InventoryError(
                f"malformed JSON message at input row {index}: {error}"
            ) from error
    else:
        value = raw
    if not isinstance(value, dict):
        raise InventoryError(f"Cargo JSON message {index} is not an object")
    return value


def _workspace_file(file_name: object, root: Path, label: str) -> str:
    if not isinstance(file_name, str) or not file_name:
        raise InventoryError(f"{label} has no source file")
    if file_name.startswith("ROOT/"):
        candidate = root / file_name.removeprefix("ROOT/")
    else:
        path = Path(file_name)
        candidate = path if path.is_absolute() else root / path
    normalized = candidate.resolve(strict=False)
    try:
        relative = normalized.relative_to(root)
    except ValueError as error:
        raise InventoryError(f"{label} path is outside root: {file_name}") from error
    posix = relative.as_posix()
    parsed = PurePosixPath(posix)
    if posix in {"", "."} or ".." in parsed.parts:
        raise InventoryError(f"{label} path is outside root: {file_name}")
    return posix


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InventoryError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InventoryError(f"{label} must be a non-negative integer")
    return value


def _span_coordinates(span: Mapping[str, object], label: str) -> dict[str, int]:
    byte_start = _nonnegative_int(span.get("byte_start"), f"{label} byte_start")
    byte_end = _nonnegative_int(span.get("byte_end"), f"{label} byte_end")
    line_start = _positive_int(span.get("line_start"), f"{label} line_start")
    line_end = _positive_int(span.get("line_end"), f"{label} line_end")
    column_start = _positive_int(
        span.get("column_start"), f"{label} column_start"
    )
    column_end = _positive_int(span.get("column_end"), f"{label} column_end")
    if byte_end <= byte_start:
        raise InventoryError(f"{label} has a reversed or empty byte span")
    if line_end < line_start or (
        line_end == line_start and column_end <= column_start
    ):
        raise InventoryError(f"{label} has a reversed or empty source span")
    return {
        "byte_start": byte_start,
        "byte_end": byte_end,
        "line_start": line_start,
        "line_end": line_end,
        "column_start": column_start,
        "column_end": column_end,
    }


def _span_point(span: object, root: Path, label: str) -> dict[str, object]:
    if not isinstance(span, Mapping):
        raise InventoryError(f"{label} is not a compiler span")
    coordinates = _span_coordinates(span, label)
    return {
        "file": _workspace_file(span.get("file_name"), root, label),
        **coordinates,
        "line": coordinates["line_start"],
        "column": coordinates["column_start"],
    }


def _outermost_expansion(
    primary: Mapping[str, object], root: Path
) -> dict[str, object] | None:
    expansion = primary.get("expansion")
    outermost = None
    visited: set[int] = set()
    while expansion is not None:
        if not isinstance(expansion, Mapping):
            raise InventoryError("malformed macro expansion in compiler primary span")
        marker = id(expansion)
        if marker in visited:
            raise InventoryError("cyclic macro expansion in compiler primary span")
        visited.add(marker)
        callsite = expansion.get("span")
        outermost = _span_point(callsite, root, "macro expansion callsite span")
        assert isinstance(callsite, Mapping)
        expansion = callsite.get("expansion")
    return outermost


def _catalog_reason(children: object) -> str | None:
    if children is None:
        return None
    if not isinstance(children, list):
        raise InventoryError("Clippy diagnostic children are not a list")
    matches: list[str] = []
    for child in children:
        if not isinstance(child, Mapping):
            raise InventoryError("Clippy diagnostic child is not an object")
        if child.get("level") != "note":
            continue
        message = child.get("message")
        if not isinstance(message, str):
            raise InventoryError("Clippy diagnostic note has no message")
        found = CATALOG_ID.findall(message)
        if "HA-CATALOG-" in message and not found:
            raise InventoryError(f"malformed catalog reason child: {message!r}")
        matches.extend(found)
    if len(matches) > 1:
        raise InventoryError(f"conflicting catalog reason children: {matches}")
    return matches[0] if matches else None


def _validate_point(point: object, label: str) -> None:
    if not isinstance(point, Mapping) or set(point) != POINT_FIELDS:
        raise InventoryError(f"invalid {label} span: {point!r}")
    file_name = point.get("file")
    if not isinstance(file_name, str) or not file_name:
        raise InventoryError(f"invalid {label} source file: {point!r}")
    path = PurePosixPath(file_name)
    if path.is_absolute() or ".." in path.parts or file_name in {"", "."}:
        raise InventoryError(f"invalid {label} source file: {point!r}")
    coordinates = _span_coordinates(point, f"{label} span")
    if point.get("line") != coordinates["line_start"]:
        raise InventoryError(f"{label} span line alias does not match line_start")
    if point.get("column") != coordinates["column_start"]:
        raise InventoryError(f"{label} span column alias does not match column_start")


def _validate_profiles(profiles: object, label: str) -> list[str]:
    if not isinstance(profiles, list) or not profiles:
        raise InventoryError(f"{label} profiles must be a non-empty list")
    if not all(isinstance(profile, str) and profile for profile in profiles):
        raise InventoryError(f"{label} contains an invalid profile ID")
    if profiles != sorted(set(profiles)):
        raise InventoryError(f"{label} profiles must be unique and sorted")
    return profiles


def _validate_actual_row(row: object, label: str) -> dict[str, object]:
    if not isinstance(row, dict) or set(row) != ACTUAL_FIELDS:
        raise InventoryError(f"invalid {label} row schema: {row!r}")
    catalog_id = row.get("catalog_id")
    if catalog_id is not None and (
        not isinstance(catalog_id, str) or CATALOG_ID.fullmatch(catalog_id) is None
    ):
        raise InventoryError(f"invalid {label} catalog ID: {row!r}")
    operation = row.get("operation")
    if not isinstance(operation, str) or OPERATION_PATH.fullmatch(operation) is None:
        raise InventoryError(f"invalid {label} operation: {row!r}")
    _validate_point(row.get("source"), f"{label} primary")
    expansion = row.get("expansion")
    if expansion is not None:
        _validate_point(expansion, f"{label} expansion")
    _validate_profiles(row.get("profiles"), label)
    return row


def normalize_messages(
    messages: Iterable[object], profile_id: str, root: Path
) -> list[dict[str, object]]:
    """Normalize one profile's Cargo/Clippy JSON diagnostic stream."""
    if not isinstance(profile_id, str) or not profile_id:
        raise InventoryError("profile ID must be a non-empty string")
    workspace = Path(root).resolve(strict=False)
    rows: list[dict[str, object]] = []
    identities: set[str] = set()
    for index, raw in enumerate(messages, start=1):
        cargo = _cargo_object(raw, index)
        if cargo.get("reason") != "compiler-message":
            continue
        reason = cargo.get("message")
        if not isinstance(reason, Mapping):
            raise InventoryError(f"compiler message {index} has no diagnostic object")
        code = reason.get("code")
        if not isinstance(code, Mapping) or code.get("code") != CLIPPY_CODE:
            continue
        text = reason.get("message")
        match = OPERATION_MESSAGE.fullmatch(text) if isinstance(text, str) else None
        if match is None or OPERATION_PATH.fullmatch(match.group(1)) is None:
            raise InventoryError(f"unknown Clippy operation message: {text!r}")
        operation = match.group(1)
        spans = reason.get("spans")
        if not isinstance(spans, list):
            raise InventoryError("Clippy operation diagnostic has no span list")
        primary_spans = [
            span
            for span in spans
            if isinstance(span, Mapping) and span.get("is_primary") is True
        ]
        if len(primary_spans) != 1:
            raise InventoryError(
                f"Clippy operation requires exactly one primary span, got {len(primary_spans)}"
            )
        primary = primary_spans[0]
        row = {
            "catalog_id": _catalog_reason(reason.get("children")),
            "operation": operation,
            "source": _span_point(primary, workspace, "compiler primary span"),
            "expansion": _outermost_expansion(primary, workspace),
            "profiles": [profile_id],
        }
        _validate_actual_row(row, "normalized")
        identity = diagnostic_identity(row)
        if identity in identities:
            raise InventoryError(f"duplicate diagnostic identity: {identity}")
        identities.add(identity)
        rows.append(row)
    return sorted(rows, key=_sort_key)


def merge_profiles(
    profile_rows: Iterable[Iterable[dict[str, object]]],
) -> list[dict[str, object]]:
    """Merge profile membership only for exactly identical diagnostics."""
    merged: dict[str, dict[str, object]] = {}
    for batch_index, batch in enumerate(profile_rows, start=1):
        batch_identities: set[str] = set()
        for raw_row in batch:
            row = _validate_actual_row(raw_row, f"profile batch {batch_index}")
            profiles = row["profiles"]
            assert isinstance(profiles, list)
            if len(profiles) != 1:
                raise InventoryError("unmerged profile row must name exactly one profile")
            identity = diagnostic_identity(row)
            if identity in batch_identities:
                raise InventoryError(
                    f"duplicate diagnostic identity in profile batch {batch_index}: {identity}"
                )
            batch_identities.add(identity)
            prior = merged.get(identity)
            if prior is None:
                merged[identity] = {
                    **row,
                    "source": dict(row["source"]),
                    "expansion": (
                        dict(row["expansion"])
                        if isinstance(row["expansion"], Mapping)
                        else None
                    ),
                    "profiles": list(profiles),
                }
                continue
            if prior["catalog_id"] != row["catalog_id"]:
                raise InventoryError(
                    f"catalog ID disagreement for diagnostic identity: {identity}"
                )
            prior_profiles = prior["profiles"]
            assert isinstance(prior_profiles, list)
            if profiles[0] in prior_profiles:
                raise InventoryError(
                    f"duplicate profile diagnostic identity for {profiles[0]}: {identity}"
                )
            prior_profiles.append(profiles[0])
            prior_profiles.sort()
    return sorted(merged.values(), key=_sort_key)


def _review_number(review_id: object, row: Mapping[str, object]) -> int:
    if not isinstance(review_id, str):
        raise InventoryError(f"invalid review ID: {row!r}")
    match = REVIEW_ID.fullmatch(review_id)
    if match is None:
        raise InventoryError(f"invalid review ID: {row!r}")
    return int(match.group(1))


def _normalized_resource(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _validate_review(row: dict[str, object], *, allow_unreviewed: bool) -> None:
    classification = row.get("classification")
    evidence = row.get("evidence")
    rationale = row.get("rationale")
    if classification == "legacy_unreachable":
        raise InventoryError(f"legacy_unreachable is invalid for a compiled row: {row}")
    if classification == "unreviewed":
        if not allow_unreviewed:
            raise InventoryError(f"unreviewed inventory row: {row}")
        if evidence != {} or rationale != "":
            raise InventoryError(f"invalid unreviewed evidence or rationale: {row}")
        return
    allowed = CLASSIFICATION_AUTHORITIES.get(classification)
    if allowed is None:
        raise InventoryError(f"invalid inventory classification: {row}")
    if not isinstance(evidence, dict) or set(evidence) != {"authority", "resource"}:
        raise InventoryError(f"invalid structured evidence schema: {row}")
    if evidence.get("authority") not in allowed:
        raise InventoryError(f"evidence authority does not match classification: {row}")
    resource = evidence.get("resource")
    if not isinstance(resource, str) or not resource.strip():
        raise InventoryError(f"empty evidence resource: {row}")
    if _normalized_resource(resource) in GENERIC_RESOURCES:
        raise InventoryError(f"generic evidence resource: {row}")
    if not isinstance(rationale, str) or not rationale.strip():
        raise InventoryError(f"empty inventory rationale: {row}")


def _reviewed_index(
    rows: Sequence[dict[str, object]], *, allow_unreviewed: bool
) -> tuple[dict[str, dict[str, object]], int]:
    indexed: dict[str, dict[str, object]] = {}
    review_ids: dict[str, str] = {}
    maximum = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != REVIEW_FIELDS:
            raise InventoryError(f"invalid reviewed row schema: {row!r}")
        actual = {field: row[field] for field in ACTUAL_FIELDS}
        _validate_actual_row(actual, "reviewed")
        identity = diagnostic_identity(actual)
        if identity in indexed:
            raise InventoryError(f"duplicate reviewed diagnostic identity: {identity}")
        number = _review_number(row.get("review_id"), row)
        review_id = row["review_id"]
        assert isinstance(review_id, str)
        prior_identity = review_ids.get(review_id)
        if prior_identity is not None:
            raise InventoryError(
                f"review ID collision for {review_id}: {prior_identity} and {identity}"
            )
        review_ids[review_id] = identity
        maximum = max(maximum, number)
        _validate_review(row, allow_unreviewed=allow_unreviewed)
        indexed[identity] = row
    return indexed, maximum


def _actual_index(rows: Sequence[dict[str, object]]) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        valid = _validate_actual_row(row, "actual")
        identity = diagnostic_identity(valid)
        if identity in indexed:
            raise InventoryError(f"duplicate actual diagnostic identity: {identity}")
        indexed[identity] = valid
    return indexed


def _profile_set(profiles: object, label: str) -> set[str]:
    if not isinstance(profiles, Sequence) or isinstance(profiles, (str, bytes)):
        raise InventoryError(f"{label} profiles must be a sequence")
    values = list(profiles)
    if not values or not all(isinstance(value, str) and value for value in values):
        raise InventoryError(f"{label} profiles contain invalid IDs")
    if len(values) != len(set(values)):
        raise InventoryError(f"{label} profiles contain duplicate IDs")
    return set(values)


def validate(
    actual: list[dict[str, object]],
    expected: list[dict[str, object]],
    executed_profiles: Sequence[str],
    required_profiles: Sequence[str],
) -> None:
    """Require exact reviewed rows for every profile declared as executed."""
    executed = _profile_set(executed_profiles, "executed")
    required = _profile_set(required_profiles, "required")
    if executed != required:
        missing = sorted(required - executed)
        extra = sorted(executed - required)
        raise InventoryError(
            f"profile execution mismatch: missing={missing}, unexpected={extra}"
        )
    actual_by_identity = _actual_index(actual)
    reviewed_by_identity, _ = _reviewed_index(expected, allow_unreviewed=False)

    for row in actual_by_identity.values():
        profiles = set(row["profiles"])
        if not profiles <= executed:
            raise InventoryError(
                f"actual row contains an unexecuted profile: {sorted(profiles - executed)}"
            )

    projected: dict[str, dict[str, object]] = {}
    for identity, reviewed in reviewed_by_identity.items():
        profiles = sorted(set(reviewed["profiles"]) & executed)
        if not profiles:
            continue
        projected[identity] = {
            field: (profiles if field == "profiles" else reviewed[field])
            for field in ACTUAL_FIELDS
        }

    if actual_by_identity != projected:
        actual_ids = set(actual_by_identity)
        expected_ids = set(projected)
        new = sorted(actual_ids - expected_ids)
        removed = sorted(expected_ids - actual_ids)
        changed = sorted(
            identity
            for identity in actual_ids & expected_ids
            if actual_by_identity[identity] != projected[identity]
        )
        raise InventoryError(
            f"inventory drift: new={new}, removed={removed}, changed={changed}"
        )


def refresh(
    actual: list[dict[str, object]],
    expected: list[dict[str, object]],
    complete: bool,
) -> list[dict[str, object]]:
    """Create a complete candidate without transferring reviews across identity."""
    if complete is not True:
        raise InventoryError("partial refresh cannot rewrite the canonical inventory")
    actual_by_identity = _actual_index(actual)
    reviewed_by_identity, maximum = _reviewed_index(
        expected, allow_unreviewed=True
    )
    rows: list[dict[str, object]] = []
    next_number = maximum
    for identity, row in sorted(
        actual_by_identity.items(), key=lambda item: _sort_key(item[1])
    ):
        prior = reviewed_by_identity.get(identity)
        if prior is None:
            next_number += 1
            review = {
                "review_id": f"HA-{next_number:06d}",
                "classification": "unreviewed",
                "evidence": {},
                "rationale": "",
            }
        else:
            review = {
                "review_id": prior["review_id"],
                "classification": prior["classification"],
                "evidence": dict(prior["evidence"]),
                "rationale": prior["rationale"],
            }
        rows.append(
            {
                "review_id": review["review_id"],
                **row,
                "classification": review["classification"],
                "evidence": review["evidence"],
                "rationale": review["rationale"],
            }
        )
    return rows


def main(argv: Sequence[str]) -> int:
    """Fail closed until Task 3 installs matrix execution and CLI routing."""
    print(
        "compiler authority census matrix orchestration is not configured yet",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
