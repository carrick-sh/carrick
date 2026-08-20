#!/usr/bin/env python3
"""Normalize and review compiler-resolved host-authority diagnostics.

This module deliberately consumes only Cargo/Clippy JSON.  Rust name
resolution, cfg selection, target reachability, imports, and macro resolution
belong to the pinned compiler that produced the diagnostics.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple


CLIPPY_CODE = "clippy::disallowed_methods"
OPERATION_MESSAGE = re.compile(r"use of a disallowed method `([^`]+)`")
OPERATION_PATH = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+"
)
CATALOG_ID = re.compile(r"HA-CATALOG-[A-Z0-9]+(?:-[A-Z0-9]+)*")
CATALOG_TOKEN = re.compile(r"HA-CATALOG-[^:\s]+")
REVIEW_ID = re.compile(r"HA-([0-9]{6})")
CATALOG_REASON = re.compile(r"^(HA-CATALOG-[A-Z0-9]+(?:-[A-Z0-9]+)*):")

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "scripts" / "migrate" / "host-authority-build-matrix.json"
INVENTORY_PATH = (
    ROOT / "scripts" / "migrate" / "host-authority-transition-inventory.json"
)
CLIPPY_CONFIG_PATH = ROOT / "clippy.toml"

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


class Profile(NamedTuple):
    """One exact product compilation selected by the checked matrix."""

    id: str
    host: str
    command: tuple[str, ...]


class Matrix(NamedTuple):
    """Validated product matrix and its pinned compiler identities."""

    schema: int
    rustc_release: str
    clippy_release: str
    required_profiles: tuple[str, ...]
    profiles: dict[str, Profile]


def _expected_profile_commands() -> dict[str, tuple[str, ...]]:
    commands = {
        "macos-cli-default": (
            "cargo",
            "clippy",
            "-p",
            "carrick-cli",
            "--bin",
            "carrick",
            "--message-format=json",
            "--",
            "--force-warn",
            CLIPPY_CODE,
        ),
        "macos-runtime-default": (
            "cargo",
            "clippy",
            "-p",
            "carrick-runtime",
            "--lib",
            "--message-format=json",
            "--",
            "--force-warn",
            CLIPPY_CODE,
        ),
        "macos-hvf-default": (
            "cargo",
            "clippy",
            "-p",
            "carrick-vmm-hvf",
            "--lib",
            "--message-format=json",
            "--",
            "--force-warn",
            CLIPPY_CODE,
        ),
    }
    for host, features in (
        ("linux", "syscall-shim,platform-linux"),
        ("freebsd", "platform-freebsd"),
        ("netbsd", "platform-netbsd"),
    ):
        for target, package, target_args in (
            ("cli", "carrick-cli", ("--bin", "carrick")),
            ("runtime", "carrick-runtime", ("--lib",)),
        ):
            commands[f"{host}-{target}"] = (
                "cargo",
                "clippy",
                "-p",
                package,
                "--no-default-features",
                "--features",
                features,
                *target_args,
                "--message-format=json",
                "--",
                "--force-warn",
                CLIPPY_CODE,
            )
    return commands


EXPECTED_PROFILE_COMMANDS = _expected_profile_commands()
EXPECTED_PROFILE_HOSTS = {
    profile_id: profile_id.split("-", 1)[0]
    for profile_id in EXPECTED_PROFILE_COMMANDS
}


def _json_file(path: Path, label: str) -> object:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise InventoryError(f"missing {label}: {path}") from error
    except json.JSONDecodeError as error:
        raise InventoryError(f"malformed {label} JSON at {path}: {error}") from error


def load_matrix(path: Path) -> Matrix:
    """Load and fail closed on any drift in the checked nine-profile matrix."""
    raw = _json_file(Path(path), "host-authority build matrix")
    if not isinstance(raw, dict) or set(raw) != {
        "schema",
        "toolchain",
        "required_profiles",
        "profiles",
    }:
        raise InventoryError("invalid host-authority build matrix schema")
    if raw.get("schema") != 1:
        raise InventoryError("unsupported host-authority build matrix schema")
    toolchain = raw.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "rustc_release",
        "clippy_release",
    }:
        raise InventoryError("invalid matrix toolchain requirements")
    rustc_release = toolchain.get("rustc_release")
    clippy_release = toolchain.get("clippy_release")
    if rustc_release != "1.96.0" or clippy_release != "0.1.96":
        raise InventoryError(
            "matrix toolchain must pin rustc 1.96.0 and Clippy 0.1.96"
        )

    required_raw = raw.get("required_profiles")
    if not isinstance(required_raw, list) or not all(
        isinstance(profile_id, str) and profile_id for profile_id in required_raw
    ):
        raise InventoryError("matrix required profiles must be a nonempty string list")
    if not required_raw or len(required_raw) != len(set(required_raw)):
        raise InventoryError("matrix required profile IDs must be nonempty and unique")
    if set(required_raw) != set(EXPECTED_PROFILE_COMMANDS):
        missing = sorted(set(EXPECTED_PROFILE_COMMANDS) - set(required_raw))
        extra = sorted(set(required_raw) - set(EXPECTED_PROFILE_COMMANDS))
        raise InventoryError(
            f"matrix required profile set is incomplete: missing={missing}, extra={extra}"
        )

    profiles_raw = raw.get("profiles")
    if not isinstance(profiles_raw, list) or not profiles_raw:
        raise InventoryError("matrix profiles must be a nonempty list")
    profiles: dict[str, Profile] = {}
    for index, raw_profile in enumerate(profiles_raw, start=1):
        if not isinstance(raw_profile, dict) or set(raw_profile) != {
            "id",
            "host",
            "command",
        }:
            raise InventoryError(f"invalid matrix profile {index} schema")
        profile_id = raw_profile.get("id")
        host = raw_profile.get("host")
        command = raw_profile.get("command")
        if not isinstance(profile_id, str) or not profile_id:
            raise InventoryError(f"invalid matrix profile ID at row {index}")
        if profile_id in profiles:
            raise InventoryError(f"duplicate matrix profile ID: {profile_id}")
        if not isinstance(host, str) or not host:
            raise InventoryError(f"invalid host for matrix profile {profile_id}")
        if not isinstance(command, list) or not command or not all(
            isinstance(argument, str) and argument for argument in command
        ):
            raise InventoryError(f"invalid command for matrix profile {profile_id}")
        if "--message-format=json" not in command:
            raise InventoryError(
                f"matrix profile {profile_id} omits required JSON message format"
            )
        if "--force-warn" not in command or CLIPPY_CODE not in command:
            raise InventoryError(
                f"matrix profile {profile_id} omits required force-warn lint"
            )
        expected_command = EXPECTED_PROFILE_COMMANDS.get(profile_id)
        expected_host = EXPECTED_PROFILE_HOSTS.get(profile_id)
        if expected_command is None or expected_host is None:
            raise InventoryError(f"undeclared matrix profile ID: {profile_id}")
        if host != expected_host:
            raise InventoryError(
                f"matrix profile {profile_id} has wrong host {host!r}"
            )
        if tuple(command) != expected_command:
            raise InventoryError(
                f"matrix profile {profile_id} does not compile its exact product target"
            )
        profiles[profile_id] = Profile(profile_id, host, tuple(command))

    if set(profiles) != set(required_raw):
        missing = sorted(set(required_raw) - set(profiles))
        extra = sorted(set(profiles) - set(required_raw))
        raise InventoryError(
            f"matrix profile declarations disagree: missing={missing}, extra={extra}"
        )
    ordered = {profile_id: profiles[profile_id] for profile_id in required_raw}
    return Matrix(
        schema=1,
        rustc_release=rustc_release,
        clippy_release=clippy_release,
        required_profiles=tuple(required_raw),
        profiles=ordered,
    )


def current_host_id() -> str:
    """Return the matrix host ID for the current native execution host."""
    host = platform.system().casefold()
    mapped = {
        "darwin": "macos",
        "linux": "linux",
        "freebsd": "freebsd",
        "netbsd": "netbsd",
    }
    try:
        return mapped[host]
    except KeyError as error:
        raise InventoryError(f"unsupported host for authority census: {host}") from error


def select_profiles(
    matrix: Matrix,
    selector: str | None,
    current_host: str | None = None,
) -> list[Profile]:
    """Select a nonempty current-host subset, preserving matrix order."""
    host = current_host or current_host_id()
    if selector is None:
        selected = [
            profile for profile in matrix.profiles.values() if profile.host == host
        ]
    else:
        patterns = [pattern.strip() for pattern in selector.split(",")]
        if not patterns or any(not pattern for pattern in patterns):
            raise InventoryError("profile selection must be nonempty")
        matched_ids: list[str] = []
        for pattern in patterns:
            matches = [
                profile_id
                for profile_id in matrix.required_profiles
                if fnmatch.fnmatchcase(profile_id, pattern)
            ]
            if not matches:
                raise InventoryError(f"profile selector matched no profile: {pattern}")
            for profile_id in matches:
                if profile_id in matched_ids:
                    raise InventoryError(
                        f"profile selection contains duplicate ID: {profile_id}"
                    )
                matched_ids.append(profile_id)
        selected = [matrix.profiles[profile_id] for profile_id in matched_ids]
    if not selected:
        raise InventoryError(f"no authority census profile is available on {host}")
    unavailable = [profile.id for profile in selected if profile.host != host]
    if unavailable:
        raise InventoryError(
            f"profiles unavailable on current host {host}: {sorted(unavailable)}"
        )
    return selected


def _completed_text(
    command: Sequence[str],
    *,
    runner: Any,
    cwd: Path,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return runner(
        list(command),
        cwd=cwd,
        env=dict(env) if env is not None else None,
        shell=False,
        capture_output=True,
        text=True,
        check=False,
    )


def _command_failure(label: str, result: subprocess.CompletedProcess[str]) -> None:
    stderr = result.stderr.strip() if isinstance(result.stderr, str) else ""
    detail = stderr or "<captured stderr was empty>"
    raise InventoryError(
        f"{label} failed with exit {result.returncode}; captured stderr: {detail}"
    )


def verify_toolchain(
    matrix: Matrix,
    runner: Any = subprocess.run,
    root: Path = ROOT,
) -> dict[str, str]:
    """Verify and return the exact pinned compiler identities for the receipt."""
    identities: dict[str, str] = {}
    checks = (
        ("rustc", ["rustc", "-V"], matrix.rustc_release),
        ("clippy", ["cargo", "clippy", "-V"], matrix.clippy_release),
    )
    for label, command, release in checks:
        result = _completed_text(command, runner=runner, cwd=Path(root))
        if result.returncode != 0:
            _command_failure(f"{label} identity check", result)
        identity = result.stdout.strip() if isinstance(result.stdout, str) else ""
        prefix = f"{label} {release}"
        if not identity.startswith(prefix):
            raise InventoryError(
                f"{label} identity mismatch: required {prefix!r}, got {identity!r}"
            )
        identities[label] = identity
    return identities


def run_profile(
    profile: Profile,
    runner: Any = subprocess.run,
    *,
    root: Path = ROOT,
    current_host: str | None = None,
) -> list[dict[str, object]]:
    """Compile one available product profile and parse its Cargo JSON stream."""
    host = current_host or current_host_id()
    if profile.host != host:
        raise InventoryError(
            f"profile {profile.id} is unavailable on current host {host}"
        )
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(
        Path(root) / "target" / "host-authority-census" / profile.id
    )
    result = _completed_text(
        profile.command,
        runner=runner,
        cwd=Path(root),
        env=environment,
    )
    if result.returncode != 0:
        _command_failure(f"authority census profile {profile.id}", result)
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise InventoryError(
            f"authority census profile {profile.id} produced no Cargo JSON messages"
        )
    messages: list[dict[str, object]] = []
    for index, line in enumerate(lines, start=1):
        try:
            message: Any = json.loads(line)
        except json.JSONDecodeError as error:
            raise InventoryError(
                f"profile {profile.id} emitted malformed Cargo JSON row {index}: {error}"
            ) from error
        if not isinstance(message, dict):
            raise InventoryError(
                f"profile {profile.id} Cargo JSON row {index} is not an object"
            )
        messages.append(message)
    return messages


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def diagnostic_identity(row: Mapping[str, object]) -> str:
    """Return the review-preservation identity for one resolved diagnostic."""
    return _canonical_json(
        {
            "catalog_id": row.get("catalog_id"),
            "operation": row.get("operation"),
            "source": row.get("source"),
            "expansion": row.get("expansion"),
        }
    )


def _diagnostic_site_identity(row: Mapping[str, object]) -> str:
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


def _workspace_file_or_none(
    file_name: object, root: Path, label: str
) -> str | None:
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
    except ValueError:
        return None
    posix = relative.as_posix()
    parsed = PurePosixPath(posix)
    if posix in {"", "."} or ".." in parsed.parts:
        raise InventoryError(f"{label} path is outside root: {file_name}")
    return posix


def _workspace_file(file_name: object, root: Path, label: str) -> str:
    relative = _workspace_file_or_none(file_name, root, label)
    if relative is None:
        raise InventoryError(f"{label} path is outside root: {file_name}")
    return relative


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


def _workspace_expansion_point(
    span: object, root: Path, label: str
) -> dict[str, object] | None:
    if not isinstance(span, Mapping):
        raise InventoryError(f"{label} is not a compiler span")
    coordinates = _span_coordinates(span, label)
    file_name = _workspace_file_or_none(span.get("file_name"), root, label)
    if file_name is None:
        return None
    return {
        "file": file_name,
        **coordinates,
        "line": coordinates["line_start"],
        "column": coordinates["column_start"],
    }


def _outermost_expansion(
    primary: Mapping[str, object], root: Path
) -> dict[str, object] | None:
    expansion = primary.get("expansion")
    had_expansion = expansion is not None
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
        workspace_callsite = _workspace_expansion_point(
            callsite, root, "macro expansion callsite span"
        )
        if workspace_callsite is not None:
            outermost = workspace_callsite
        assert isinstance(callsite, Mapping)
        expansion = callsite.get("expansion")
    if had_expansion and outermost is None:
        raise InventoryError("macro expansion chain has no workspace callsite")
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
        tokens = CATALOG_TOKEN.findall(message)
        if "HA-CATALOG-" in message:
            if len(tokens) != 1 or CATALOG_ID.fullmatch(tokens[0]) is None:
                raise InventoryError(f"malformed catalog reason child: {message!r}")
            matches.append(tokens[0])
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
    if not isinstance(catalog_id, str) or CATALOG_ID.fullmatch(catalog_id) is None:
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


def _validate_operation_catalog(operation_catalog: object) -> dict[str, str]:
    if not isinstance(operation_catalog, Mapping) or not operation_catalog:
        raise InventoryError("operation catalog must be a non-empty mapping")
    snapshot: dict[str, str] = {}
    catalog_owners: dict[str, str] = {}
    for operation, catalog_id in operation_catalog.items():
        if (
            not isinstance(operation, str)
            or OPERATION_PATH.fullmatch(operation) is None
        ):
            raise InventoryError(f"invalid operation catalog path: {operation!r}")
        if (
            not isinstance(catalog_id, str)
            or CATALOG_ID.fullmatch(catalog_id) is None
        ):
            raise InventoryError(
                f"invalid operation catalog ID for {operation}: {catalog_id!r}"
            )
        prior = catalog_owners.get(catalog_id)
        if prior is not None and prior != operation:
            raise InventoryError(
                f"operation catalog ID conflict: {catalog_id} maps {prior} and {operation}"
            )
        catalog_owners[catalog_id] = operation
        snapshot[operation] = catalog_id
    return snapshot


def normalize_messages(
    messages: Iterable[object],
    profile_id: str,
    root: Path,
    operation_catalog: Mapping[str, str],
) -> list[dict[str, object]]:
    """Normalize one profile's Cargo/Clippy JSON diagnostic stream.

    The required operation catalog is snapshotted and checked before messages
    are consumed. Task 1 supplies its checked fixture mapping; Task 4 supplies
    the parsed object-form ``clippy.toml`` catalog for production.
    """
    if not isinstance(profile_id, str) or not profile_id:
        raise InventoryError("profile ID must be a non-empty string")
    workspace = Path(root).resolve(strict=False)
    catalog = _validate_operation_catalog(operation_catalog)
    rows: list[dict[str, object]] = []
    identities: set[str] = set()
    sites: dict[str, str] = {}
    for index, raw in enumerate(messages, start=1):
        cargo = _cargo_object(raw, index)
        if cargo.get("reason") != "compiler-message":
            continue
        reason = cargo.get("message")
        if not isinstance(reason, Mapping):
            raise InventoryError(f"compiler message {index} has no diagnostic object")
        text = reason.get("message")
        shaped = OPERATION_MESSAGE.fullmatch(text) if isinstance(text, str) else None
        code = reason.get("code")
        code_name = code.get("code") if isinstance(code, Mapping) else None
        if shaped is not None and code_name != CLIPPY_CODE:
            raise InventoryError(
                "Clippy diagnostic interface drift: disallowed-method message "
                f"has code {code_name!r}"
            )
        if code_name != CLIPPY_CODE:
            continue
        match = shaped
        if match is None or OPERATION_PATH.fullmatch(match.group(1)) is None:
            raise InventoryError(f"unknown Clippy operation message: {text!r}")
        operation = match.group(1)
        catalog_id = catalog.get(operation)
        if catalog_id is None:
            raise InventoryError(
                f"missing operation catalog mapping for diagnostic: {operation}"
            )
        child_catalog_id = _catalog_reason(reason.get("children"))
        if child_catalog_id is not None and child_catalog_id != catalog_id:
            raise InventoryError(
                "diagnostic catalog ID mismatch for "
                f"{operation}: mapped={catalog_id}, child={child_catalog_id}"
            )
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
            "catalog_id": catalog_id,
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
        site = _diagnostic_site_identity(row)
        prior_catalog = sites.get(site)
        if site in sites and prior_catalog != row["catalog_id"]:
            raise InventoryError(f"catalog ID disagreement for diagnostic site: {site}")
        sites[site] = row["catalog_id"]
        rows.append(row)
    return sorted(rows, key=_sort_key)


def merge_profiles(
    profile_rows: Iterable[Iterable[dict[str, object]]],
) -> list[dict[str, object]]:
    """Merge profile membership only for exactly identical diagnostics."""
    merged: dict[str, dict[str, object]] = {}
    catalog_by_site: dict[str, str] = {}
    for batch_index, batch in enumerate(profile_rows, start=1):
        batch_identities: set[str] = set()
        for raw_row in batch:
            row = _validate_actual_row(raw_row, f"profile batch {batch_index}")
            profiles = row["profiles"]
            assert isinstance(profiles, list)
            if len(profiles) != 1:
                raise InventoryError("unmerged profile row must name exactly one profile")
            site = _diagnostic_site_identity(row)
            prior_catalog = catalog_by_site.get(site)
            if site in catalog_by_site and prior_catalog != row["catalog_id"]:
                raise InventoryError(
                    f"catalog ID disagreement for diagnostic site: {site}"
                )
            catalog_by_site[site] = row["catalog_id"]
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
    rows: Sequence[dict[str, object]],
    *,
    allow_unreviewed: bool,
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
    """Require exact reviewed rows for every profile declared as executed.

    All rows require stable non-null catalog IDs. Normalization has already
    bound those IDs to the explicit operation catalog supplied by its caller.
    """
    executed = _profile_set(executed_profiles, "executed")
    required = _profile_set(required_profiles, "required")
    if not executed <= required:
        raise InventoryError(
            "executed profiles are outside required profiles: "
            f"{sorted(executed - required)}"
        )
    actual_by_identity = _actual_index(actual)
    reviewed_by_identity, _ = _reviewed_index(
        expected,
        allow_unreviewed=False,
    )

    for row in actual_by_identity.values():
        profiles = set(row["profiles"])
        if not profiles <= required:
            raise InventoryError(
                "actual row profiles are outside required profiles: "
                f"{sorted(profiles - required)}"
            )
        if not profiles <= executed:
            raise InventoryError(
                f"actual row contains an unexecuted profile: {sorted(profiles - executed)}"
            )

    projected: dict[str, dict[str, object]] = {}
    for identity, reviewed in reviewed_by_identity.items():
        reviewed_profiles = set(reviewed["profiles"])
        if not reviewed_profiles <= required:
            raise InventoryError(
                "expected row profiles are outside required profiles: "
                f"{sorted(reviewed_profiles - required)}"
            )
        profiles = sorted(reviewed_profiles & executed)
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
    missing = sorted(set(reviewed_by_identity) - set(actual_by_identity))
    if missing:
        raise InventoryError(f"refresh is missing expected identity: {missing}")
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


def load_production_catalog(path: Path) -> dict[str, str]:
    """Load only the stable object-form Clippy catalog installed by Task 4."""
    try:
        configuration = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise InventoryError(f"production Clippy catalog is missing: {path}") from error
    except tomllib.TOMLDecodeError as error:
        raise InventoryError(f"production Clippy catalog is malformed: {error}") from error
    entries = configuration.get("disallowed-methods")
    if not isinstance(entries, list) or not entries:
        raise InventoryError(
            "production host-authority catalog is unavailable until Task 4: "
            "clippy.toml has no object-form disallowed-methods entries"
        )
    catalog: dict[str, str] = {}
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise InventoryError(
                f"production catalog entry {index} is not an object with a stable ID"
            )
        operation = entry.get("path")
        reason = entry.get("reason")
        if not isinstance(operation, str) or not isinstance(reason, str):
            raise InventoryError(
                f"production catalog entry {index} lacks path or stable-ID reason"
            )
        match = CATALOG_REASON.match(reason)
        if match is None:
            raise InventoryError(
                f"production catalog entry {operation!r} lacks a stable catalog ID"
            )
        if operation in catalog:
            raise InventoryError(f"duplicate production catalog operation: {operation}")
        catalog[operation] = match.group(1)
    return _validate_operation_catalog(catalog)


def load_inventory(path: Path) -> list[dict[str, object]]:
    """Load the checked review rows without accepting legacy object shapes."""
    raw = _json_file(Path(path), "host-authority inventory")
    if not isinstance(raw, list):
        raise InventoryError("host-authority inventory must be a JSON list")
    if not all(isinstance(row, dict) for row in raw):
        raise InventoryError("host-authority inventory rows must be JSON objects")
    return raw


def run_census(
    matrix: Matrix,
    profiles: Sequence[Profile],
    operation_catalog: Mapping[str, str],
    runner: Any = subprocess.run,
    *,
    root: Path = ROOT,
    current_host: str | None = None,
) -> dict[str, object]:
    """Run a selected local subset and return pure normalized receipt data."""
    selected = list(profiles)
    if not selected:
        raise InventoryError("executed profile subset must be nonempty")
    selected_ids = [profile.id for profile in selected]
    if len(selected_ids) != len(set(selected_ids)):
        raise InventoryError("executed profile subset contains duplicate IDs")
    unknown = sorted(set(selected_ids) - set(matrix.required_profiles))
    if unknown:
        raise InventoryError(f"executed profile subset contains unknown IDs: {unknown}")
    catalog = _validate_operation_catalog(operation_catalog)
    identities = verify_toolchain(matrix, runner=runner, root=Path(root))
    batches = []
    for profile in selected:
        messages = run_profile(
            profile,
            runner=runner,
            root=Path(root),
            current_host=current_host,
        )
        batches.append(
            normalize_messages(messages, profile.id, Path(root), catalog)
        )
    rows = merge_profiles(batches)
    pending = [
        profile_id
        for profile_id in matrix.required_profiles
        if profile_id not in selected_ids
    ]
    return {
        "toolchain": identities,
        "executed_profiles": selected_ids,
        "pending_profiles": pending,
        "rows": rows,
    }


def _unreviewed_candidate_rows(
    actual: list[dict[str, object]],
) -> list[dict[str, object]]:
    indexed = _actual_index(actual)
    rows = []
    for number, row in enumerate(
        sorted(indexed.values(), key=_sort_key), start=1
    ):
        rows.append(
            {
                "review_id": f"HA-{number:06d}",
                **row,
                "classification": "unreviewed",
                "evidence": {},
                "rationale": "",
            }
        )
    return rows


def candidate_document(
    actual: list[dict[str, object]],
    expected: list[dict[str, object]],
    executed_profiles: Sequence[str],
    required_profiles: Sequence[str],
    toolchain: Mapping[str, str],
) -> dict[str, object]:
    """Build an explicit partial or refreshable complete candidate receipt."""
    executed = _profile_set(executed_profiles, "executed")
    required = _profile_set(required_profiles, "required")
    if not executed <= required:
        raise InventoryError(
            f"candidate executed profiles are outside required: {sorted(executed - required)}"
        )
    for row in actual:
        valid = _validate_actual_row(row, "candidate")
        row_profiles = set(valid["profiles"])
        if not row_profiles <= executed:
            raise InventoryError(
                "candidate row contains an unexecuted profile: "
                f"{sorted(row_profiles - executed)}"
            )
    if not isinstance(toolchain, Mapping) or set(toolchain) != {"rustc", "clippy"}:
        raise InventoryError("candidate requires pinned rustc and Clippy identities")
    if not all(isinstance(value, str) and value for value in toolchain.values()):
        raise InventoryError("candidate tool identities must be nonempty strings")
    complete = executed == required
    rows = (
        refresh(actual, expected, True)
        if complete
        else _unreviewed_candidate_rows(actual)
    )
    return {
        "schema": 1,
        "kind": "host-authority-census-candidate",
        "complete": complete,
        "toolchain": dict(toolchain),
        "executed_profiles": sorted(executed),
        "pending_profiles": sorted(required - executed),
        "rows": rows,
    }


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compile the pinned host-authority product matrix and compare "
            "compiler-resolved Clippy diagnostics with reviewed inventory rows."
        ),
        epilog=(
            "Checks may execute a nonempty current-host subset and report all "
            "other required profiles pending. A partial refresh candidate is "
            "written only as explicitly partial, with executed rows unreviewed, "
            "and exits nonzero; only all nine profiles produce a complete "
            "refreshable candidate."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="compare only executed profile rows; never rewrite inventory",
    )
    mode.add_argument(
        "--refresh-candidate",
        metavar="PATH",
        type=Path,
        help=(
            "write a candidate receipt; subsets are marked partial, contain only "
            "unreviewed executed rows, and exit nonzero"
        ),
    )
    parser.add_argument(
        "--profiles",
        metavar="GLOB[,GLOB...]",
        help=(
            "select current-host profile IDs (glob syntax); default selects every "
            "profile available on the current host"
        ),
    )
    return parser


def main(
    argv: Sequence[str],
    *,
    runner: Any = subprocess.run,
    matrix: Matrix | None = None,
    operation_catalog: Mapping[str, str] | None = None,
    expected: list[dict[str, object]] | None = None,
    current_host: str | None = None,
    root: Path = ROOT,
) -> int:
    """Run the fail-closed CLI, with pure dependency injection for tests."""
    arguments = _argument_parser().parse_args(list(argv))
    try:
        checked_matrix = matrix or load_matrix(
            Path(root) / MATRIX_PATH.relative_to(ROOT)
        )
        catalog = (
            dict(operation_catalog)
            if operation_catalog is not None
            else load_production_catalog(
                Path(root) / CLIPPY_CONFIG_PATH.relative_to(ROOT)
            )
        )
        reviews = (
            expected
            if expected is not None
            else load_inventory(Path(root) / INVENTORY_PATH.relative_to(ROOT))
        )
        selected = select_profiles(
            checked_matrix, arguments.profiles, current_host=current_host
        )
        result = run_census(
            checked_matrix,
            selected,
            catalog,
            runner=runner,
            root=Path(root),
            current_host=current_host,
        )
        rows = result["rows"]
        executed = result["executed_profiles"]
        pending = result["pending_profiles"]
        identities = result["toolchain"]
        assert isinstance(rows, list)
        assert isinstance(executed, list)
        assert isinstance(pending, list)
        assert isinstance(identities, Mapping)
        if arguments.refresh_candidate is not None:
            document = candidate_document(
                rows,
                reviews,
                executed,
                checked_matrix.required_profiles,
                identities,
            )
            arguments.refresh_candidate.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if document["complete"] is not True:
                print(
                    "error: wrote an explicitly partial, non-authoritative "
                    f"candidate; pending profiles: {', '.join(pending)}",
                    file=sys.stderr,
                )
                return 1
            print(
                f"wrote complete refresh candidate: {arguments.refresh_candidate}"
            )
            return 0
        validate(rows, reviews, executed, checked_matrix.required_profiles)
        if pending:
            print(
                "host-authority census subset passed; result is partial; "
                f"pending profiles: {', '.join(pending)}"
            )
        else:
            print("host-authority census complete: all required profiles passed")
        return 0
    except InventoryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
