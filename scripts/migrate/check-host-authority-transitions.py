#!/usr/bin/env python3
"""Normalize and review compiler-resolved host-authority diagnostics.

This module deliberately consumes only Cargo/Clippy JSON.  Rust name
resolution, cfg selection, target reachability, imports, and macro resolution
belong to the pinned compiler that produced the diagnostics.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import hashlib
import json
import os
import platform
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
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
HOST_TRIPLES = {
    "macos": "aarch64-apple-darwin",
    "linux": "x86_64-unknown-linux-gnu",
    "freebsd": "x86_64-unknown-freebsd",
    "netbsd": "x86_64-unknown-netbsd",
}

ROOT = Path(__file__).resolve().parents[2]
CARGO_CWD = Path("/")
MATRIX_PATH = ROOT / "scripts" / "migrate" / "host-authority-build-matrix.json"
INVENTORY_PATH = (
    ROOT / "scripts" / "migrate" / "host-authority-transition-inventory.json"
)
CLIPPY_CONFIG_PATH = ROOT / "clippy.toml"
CATALOG_MANIFEST_PATH = (
    ROOT / "scripts" / "migrate" / "host-authority-catalog.json"
)
MACOS_CAPTURE_PATH = (
    ROOT / "scripts" / "migrate" / "host-authority-macos-capture.json"
)
CATALOG_ENTRY_COUNT = 45
REQUIRED_ESCAPE_OPERATIONS = {"libc::syscall", "libc::dlopen", "libc::dlsym"}
LOCAL_MACOS_PROFILES = (
    "macos-cli-default",
    "macos-hvf-default",
    "macos-runtime-default",
)

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
BLANKET_RESOURCE_FRAGMENTS = {
    "artifact selected by the active cli command",
    "artifact explicitly authorized by the active cli command",
}
MAX_IDENTICAL_RESOURCE_REVIEWS = 12


class InventoryError(Exception):
    """Compiler census evidence cannot satisfy the checked review contract."""


class Profile(NamedTuple):
    """One exact product compilation selected by the checked matrix."""

    id: str
    host: str
    host_triple: str
    command: tuple[str, ...]


class Matrix(NamedTuple):
    """Validated product matrix and its pinned compiler identities."""

    schema: int
    rustc_release: str
    clippy_release: str
    required_profiles: tuple[str, ...]
    profiles: dict[str, Profile]


class ExecutionContext(NamedTuple):
    """Isolated Cargo discovery roots for one census invocation."""

    cwd: Path
    cargo_home: Path
    rustup_home: Path
    toolchain_channel: str
    target_root: Path
    cargo_config: Path
    manifest: Path


class CandidateDestination(NamedTuple):
    """Authenticated candidate name bound to one held directory object."""

    display_path: Path
    directory_fd: int
    name: str
    protected_identities: frozenset[tuple[int, int]]


def _expected_profile_commands() -> dict[str, tuple[str, ...]]:
    commands = {
        "macos-cli-default": (
            "cargo",
            "clippy",
            "-p",
            "carrick-cli",
            "--target",
            HOST_TRIPLES["macos"],
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
            "--target",
            HOST_TRIPLES["macos"],
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
            "--target",
            HOST_TRIPLES["macos"],
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
                "--target",
                HOST_TRIPLES[host],
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
            "host_triple",
            "command",
        }:
            raise InventoryError(f"invalid matrix profile {index} schema")
        profile_id = raw_profile.get("id")
        host = raw_profile.get("host")
        host_triple = raw_profile.get("host_triple")
        command = raw_profile.get("command")
        if not isinstance(profile_id, str) or not profile_id:
            raise InventoryError(f"invalid matrix profile ID at row {index}")
        if profile_id in profiles:
            raise InventoryError(f"duplicate matrix profile ID: {profile_id}")
        if not isinstance(host, str) or not host:
            raise InventoryError(f"invalid host for matrix profile {profile_id}")
        if not isinstance(host_triple, str) or not host_triple:
            raise InventoryError(
                f"invalid host triple for matrix profile {profile_id}"
            )
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
        if host_triple != HOST_TRIPLES[host]:
            raise InventoryError(
                f"matrix profile {profile_id} has wrong host triple {host_triple!r}"
            )
        if tuple(command) != expected_command:
            raise InventoryError(
                f"matrix profile {profile_id} does not compile its exact product target"
            )
        profiles[profile_id] = Profile(
            profile_id, host, host_triple, tuple(command)
        )

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


def _authenticated_cargo_cwd(root: Path = CARGO_CWD) -> Path:
    if os.name != "posix":
        raise InventoryError("authority census Cargo execution requires Unix")
    current_host_id()
    try:
        metadata = root.lstat()
    except FileNotFoundError as error:
        raise InventoryError(f"Cargo cwd root is missing: {root}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise InventoryError(f"Cargo cwd root is not a directory: {root}")
    resolved = root.resolve(strict=True)
    resolved_metadata = resolved.stat()
    if (metadata.st_dev, metadata.st_ino) != (
        resolved_metadata.st_dev,
        resolved_metadata.st_ino,
    ):
        raise InventoryError(f"Cargo cwd root is not the expected directory: {root}")
    for config_name in ("config", "config.toml"):
        config = resolved / ".cargo" / config_name
        try:
            config.lstat()
        except FileNotFoundError:
            continue
        raise InventoryError(f"root Cargo config is forbidden: {config}")
    return resolved


def _checked_toolchain_channel(workspace: Path) -> str:
    path = workspace / "rust-toolchain.toml"
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise InventoryError(f"missing checked Rust toolchain file: {path}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise InventoryError(
            f"checked Rust toolchain file is not a regular file: {path}"
        )
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(
            f"malformed checked Rust toolchain TOML at {path}: {error}"
        ) from error
    toolchain = document.get("toolchain") if isinstance(document, dict) else None
    if not isinstance(toolchain, dict):
        raise InventoryError("checked Rust toolchain TOML has no [toolchain] table")
    channel = toolchain.get("channel")
    if not isinstance(channel, str) or not channel:
        raise InventoryError("checked Rust toolchain TOML has no channel string")
    return channel


@contextlib.contextmanager
def _execution_context(root: Path):
    workspace = Path(root).resolve(strict=True)
    toolchain_channel = _checked_toolchain_channel(workspace)
    cargo_config = workspace / ".cargo" / "config.toml"
    manifest = workspace / "Cargo.toml"
    for path, label in (
        (cargo_config, "checked Cargo config"),
        (manifest, "workspace manifest"),
    ):
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            raise InventoryError(f"missing {label}: {path}") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise InventoryError(f"{label} is not a regular checked file: {path}")
    census_root = workspace / "target" / "host-authority-census"
    census_root.mkdir(parents=True, exist_ok=True)
    census_root = census_root.resolve(strict=True)
    if not census_root.is_relative_to(workspace):
        raise InventoryError(
            f"authority census target root escapes workspace: {census_root}"
        )
    cargo_cwd = _authenticated_cargo_cwd()
    with tempfile.TemporaryDirectory(
        prefix=f"task-{workspace.name}-", dir=census_root
    ) as directory:
        task_root = Path(directory)
        cargo_home = task_root / "cargo-home"
        cargo_home.mkdir()
        canonical_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(
            strict=True
        )
        canonical_cargo_home = canonical_home / ".cargo"
        for cache_name in ("registry", "git"):
            cache = canonical_cargo_home / cache_name
            if cache.exists():
                if not cache.is_dir():
                    raise InventoryError(
                        f"canonical Cargo cache is not a directory: {cache}"
                    )
                (cargo_home / cache_name).symlink_to(
                    cache.resolve(strict=True), target_is_directory=True
                )
        yield ExecutionContext(
            cargo_cwd,
            cargo_home,
            canonical_home / ".rustup",
            toolchain_channel,
            census_root,
            cargo_config,
            manifest,
        )


def _sanitized_build_environment(
    cargo_home: Path,
    rustup_home: Path,
    toolchain_channel: str,
    *,
    target_dir: Path | None = None,
) -> dict[str, str]:
    """Construct the minimal tool environment without ambient build controls."""
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(rustup_home),
        "RUSTUP_TOOLCHAIN": toolchain_channel,
    }
    if target_dir is not None:
        environment["CARGO_TARGET_DIR"] = str(target_dir)
    return environment


def _profile_command(
    profile: Profile, execution: ExecutionContext
) -> list[str]:
    if profile.command[:2] != ("cargo", "clippy"):
        raise InventoryError(f"profile {profile.id} is not a Cargo Clippy command")
    return [
        "cargo",
        "--config",
        str(execution.cargo_config),
        "clippy",
        "--manifest-path",
        str(execution.manifest),
        *profile.command[2:],
    ]


def select_profiles(
    matrix: Matrix,
    selector: str | None,
    current_host: str | None = None,
) -> list[str]:
    """Select a nonempty current-host subset, preserving matrix order."""
    host = current_host or current_host_id()
    if selector is None:
        selected = [
            profile.id
            for profile in matrix.profiles.values()
            if profile.host == host
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
        selected = matched_ids
    if not selected:
        raise InventoryError(f"no authority census profile is available on {host}")
    unavailable = [
        profile_id
        for profile_id in selected
        if matrix.profiles[profile_id].host != host
    ]
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


def _rustc_verbose_identity(
    identity: str, required_release: str
) -> tuple[str, str]:
    lines = identity.splitlines()
    if not lines:
        raise InventoryError("rustc identity output is empty")
    first = lines[0].split()
    if len(first) < 2 or first[0] != "rustc" or first[1] != required_release:
        actual = first[1] if len(first) >= 2 else "<missing>"
        raise InventoryError(
            f"rustc release mismatch: required {required_release!r}, got {actual!r}"
        )
    fields: dict[str, str] = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        normalized_key = key.strip()
        if normalized_key in fields:
            raise InventoryError(
                f"rustc identity contains duplicate {normalized_key!r} field"
            )
        fields[normalized_key] = value.strip()
    release = fields.get("release")
    host_triple = fields.get("host")
    if release != required_release:
        raise InventoryError(
            f"rustc release mismatch: required {required_release!r}, got {release!r}"
        )
    if not host_triple:
        raise InventoryError("rustc verbose identity has no host triple")
    return identity, host_triple


def _clippy_identity(identity: str, required_release: str) -> str:
    first = identity.splitlines()[0].split() if identity.splitlines() else []
    if len(first) < 2 or first[0] != "clippy" or first[1] != required_release:
        actual = first[1] if len(first) >= 2 else "<missing>"
        raise InventoryError(
            f"clippy release mismatch: required {required_release!r}, got {actual!r}"
        )
    return identity


def verify_toolchain(
    matrix: Matrix,
    runner: Any = subprocess.run,
    root: Path = ROOT,
    required_host_triple: str | None = None,
    *,
    _execution: ExecutionContext | None = None,
) -> dict[str, str]:
    """Verify and return the exact pinned compiler identities for the receipt."""
    if _execution is None:
        with _execution_context(Path(root)) as execution:
            return verify_toolchain(
                matrix,
                runner=runner,
                root=root,
                required_host_triple=required_host_triple,
                _execution=execution,
            )
    if _execution.toolchain_channel != matrix.rustc_release:
        raise InventoryError(
            "checked Rust toolchain channel mismatch: "
            f"matrix requires {matrix.rustc_release!r}, "
            f"rust-toolchain.toml selects {_execution.toolchain_channel!r}"
        )
    outputs: dict[str, str] = {}
    for label, command in (
        ("rustc", ["rustc", "-Vv"]),
        (
            "clippy",
            [
                "cargo",
                "--config",
                str(_execution.cargo_config),
                "clippy",
                "-V",
            ],
        ),
    ):
        result = _completed_text(
            command,
            runner=runner,
            cwd=_execution.cwd,
            env=_sanitized_build_environment(
                _execution.cargo_home,
                _execution.rustup_home,
                _execution.toolchain_channel,
            ),
        )
        if result.returncode != 0:
            _command_failure(f"{label} identity check", result)
        identity = result.stdout.strip() if isinstance(result.stdout, str) else ""
        outputs[label] = identity
    rustc_identity, host_triple = _rustc_verbose_identity(
        outputs["rustc"], matrix.rustc_release
    )
    clippy_identity = _clippy_identity(outputs["clippy"], matrix.clippy_release)
    if required_host_triple is not None and host_triple != required_host_triple:
        raise InventoryError(
            "rustc host triple mismatch: "
            f"required {required_host_triple!r}, got {host_triple!r}"
        )
    return {
        "rustc": rustc_identity,
        "clippy": clippy_identity,
        "host_triple": host_triple,
    }


def run_profile(
    profile: Profile,
    runner: Any = subprocess.run,
    *,
    root: Path = ROOT,
    current_host: str | None = None,
    _execution: ExecutionContext | None = None,
) -> list[dict[str, object]]:
    """Compile one available product profile and parse its Cargo JSON stream."""
    if _execution is None:
        with _execution_context(Path(root)) as execution:
            return run_profile(
                profile,
                runner=runner,
                root=root,
                current_host=current_host,
                _execution=execution,
            )
    host = current_host or current_host_id()
    if profile.host != host:
        raise InventoryError(
            f"profile {profile.id} is unavailable on current host {host}"
        )
    environment = _sanitized_build_environment(
        _execution.cargo_home,
        _execution.rustup_home,
        _execution.toolchain_channel,
        target_dir=_execution.target_root / profile.id,
    )
    result = _completed_text(
        _profile_command(profile, _execution),
        runner=runner,
        cwd=_execution.cwd,
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


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_complete_catalog(operation_catalog: object) -> dict[str, str]:
    catalog = _validate_operation_catalog(operation_catalog)
    if len(catalog) != CATALOG_ENTRY_COUNT:
        raise InventoryError(
            "host-authority catalog must contain exactly "
            f"{CATALOG_ENTRY_COUNT} operations, got {len(catalog)}"
        )
    missing_escape = sorted(REQUIRED_ESCAPE_OPERATIONS - set(catalog))
    if missing_escape:
        raise InventoryError(
            f"host-authority catalog omits required escape operations: {missing_escape}"
        )
    return catalog


def load_catalog_manifest(path: Path) -> dict[str, str]:
    """Load the independent exact operation-to-catalog-ID authority."""
    raw = _json_file(Path(path), "host-authority catalog manifest")
    if not isinstance(raw, dict) or set(raw) != {"schema", "kind", "operations"}:
        raise InventoryError("invalid host-authority catalog manifest schema")
    if raw.get("schema") != 1 or raw.get("kind") != "host-authority-catalog":
        raise InventoryError("unsupported host-authority catalog manifest")
    operations = raw.get("operations")
    if not isinstance(operations, list):
        raise InventoryError("catalog manifest operations must be a list")
    catalog: dict[str, str] = {}
    for index, row in enumerate(operations, start=1):
        if not isinstance(row, dict) or set(row) != {"operation", "catalog_id"}:
            raise InventoryError(f"invalid catalog manifest row {index}: {row!r}")
        operation = row.get("operation")
        catalog_id = row.get("catalog_id")
        if not isinstance(operation, str) or not isinstance(catalog_id, str):
            raise InventoryError(f"invalid catalog manifest row {index}: {row!r}")
        if operation in catalog:
            raise InventoryError(f"duplicate catalog manifest operation: {operation}")
        catalog[operation] = catalog_id
    if list(catalog) != sorted(catalog):
        raise InventoryError("catalog manifest operations must be sorted")
    return _validate_complete_catalog(catalog)


def load_production_catalog(
    path: Path, operation_manifest: Mapping[str, str]
) -> dict[str, str]:
    """Bind strict object-form Clippy entries to the independent manifest."""
    manifest = _validate_complete_catalog(operation_manifest)
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
        if not isinstance(entry, dict) or set(entry) != {"path", "reason"}:
            raise InventoryError(
                "production catalog entry "
                f"{index} must contain exactly path and reason"
            )
        operation = entry.get("path")
        reason = entry.get("reason")
        if not isinstance(operation, str) or not isinstance(reason, str):
            raise InventoryError(
                f"production catalog entry {index} lacks path or stable-ID reason"
            )
        match = CATALOG_REASON.match(reason)
        if match is None or not reason[match.end() :].strip():
            raise InventoryError(
                "production catalog entry "
                f"{operation!r} lacks a stable catalog ID or explanation"
            )
        if operation in catalog:
            raise InventoryError(f"duplicate production catalog operation: {operation}")
        catalog[operation] = match.group(1)
    catalog = _validate_complete_catalog(catalog)
    if catalog != manifest:
        missing = sorted(set(manifest) - set(catalog))
        extra = sorted(set(catalog) - set(manifest))
        changed = sorted(
            operation
            for operation in set(catalog) & set(manifest)
            if catalog[operation] != manifest[operation]
        )
        raise InventoryError(
            "production Clippy catalog disagrees with independent manifest: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    return catalog


def _capture_profile_rows(matrix: Matrix) -> list[dict[str, object]]:
    rows = []
    for profile_id in LOCAL_MACOS_PROFILES:
        profile = matrix.profiles.get(profile_id)
        if profile is None:
            raise InventoryError(f"capture profile missing from matrix: {profile_id}")
        rows.append(
            {
                "id": profile.id,
                "host": profile.host,
                "host_triple": profile.host_triple,
                "command": list(profile.command),
            }
        )
    return rows


def load_capture_receipt(
    path: Path, matrix: Matrix, operation_catalog: Mapping[str, str]
) -> dict[str, object]:
    """Load and authenticate the checked macOS compiler-capture receipt."""
    raw = _json_file(Path(path), "host-authority macOS capture receipt")
    fields = {
        "schema",
        "kind",
        "source_head",
        "toolchain",
        "executed_profiles",
        "pending_profiles",
        "profiles",
        "diagnostic_counts",
        "catalog_sha256",
        "profiles_sha256",
        "rows_sha256",
        "rows",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise InventoryError("invalid host-authority macOS capture schema")
    if raw.get("schema") != 1 or raw.get("kind") != "host-authority-macos-capture":
        raise InventoryError("unsupported host-authority macOS capture")
    source_head = raw.get("source_head")
    if not isinstance(source_head, str) or re.fullmatch(r"[0-9a-f]{40}", source_head) is None:
        raise InventoryError("capture source_head must be a full lowercase Git hash")

    catalog = _validate_complete_catalog(operation_catalog)
    if raw.get("catalog_sha256") != _canonical_digest(catalog):
        raise InventoryError("capture catalog digest mismatch")

    profiles = raw.get("profiles")
    expected_profiles = _capture_profile_rows(matrix)
    if profiles != expected_profiles:
        raise InventoryError("capture profile metadata disagrees with checked matrix")
    if raw.get("profiles_sha256") != _canonical_digest(expected_profiles):
        raise InventoryError("capture profile digest mismatch")
    if raw.get("executed_profiles") != list(LOCAL_MACOS_PROFILES):
        raise InventoryError("capture executed profiles are not the exact macOS slice")
    expected_pending = sorted(set(matrix.required_profiles) - set(LOCAL_MACOS_PROFILES))
    if raw.get("pending_profiles") != expected_pending:
        raise InventoryError("capture pending profiles disagree with checked matrix")

    toolchain = raw.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "rustc",
        "clippy",
        "host_triple",
    }:
        raise InventoryError("capture has invalid toolchain metadata")
    rustc, host_triple = _rustc_verbose_identity(
        toolchain.get("rustc") if isinstance(toolchain.get("rustc"), str) else "",
        matrix.rustc_release,
    )
    clippy = _clippy_identity(
        toolchain.get("clippy") if isinstance(toolchain.get("clippy"), str) else "",
        matrix.clippy_release,
    )
    if host_triple != HOST_TRIPLES["macos"] or toolchain.get("host_triple") != host_triple:
        raise InventoryError("capture toolchain host triple is not canonical macOS")
    if toolchain != {"rustc": rustc, "clippy": clippy, "host_triple": host_triple}:
        raise InventoryError("capture toolchain identity is not canonical")

    rows = raw.get("rows")
    if not isinstance(rows, list) or not rows:
        raise InventoryError("capture rows must be a nonempty list")
    identities: set[str] = set()
    normalized_rows = []
    for index, row in enumerate(rows, start=1):
        valid = _validate_actual_row(row, f"capture row {index}")
        operation = valid["operation"]
        if valid["catalog_id"] != catalog.get(operation):
            raise InventoryError(f"capture row {index} has wrong catalog binding")
        profiles_for_row = valid["profiles"]
        if not set(profiles_for_row) <= set(LOCAL_MACOS_PROFILES):
            raise InventoryError(f"capture row {index} contains a non-macOS profile")
        identity = diagnostic_identity(valid)
        if identity in identities:
            raise InventoryError(f"duplicate capture diagnostic identity: {identity}")
        identities.add(identity)
        normalized_rows.append(valid)
    if normalized_rows != sorted(normalized_rows, key=_sort_key):
        raise InventoryError("capture rows must be in canonical diagnostic order")
    if raw.get("rows_sha256") != _canonical_digest(normalized_rows):
        raise InventoryError("capture row digest mismatch")

    counts = raw.get("diagnostic_counts")
    expected_counts = {
        profile_id: sum(profile_id in row["profiles"] for row in normalized_rows)
        for profile_id in LOCAL_MACOS_PROFILES
    }
    expected_counts["merged"] = len(normalized_rows)
    if counts != expected_counts:
        raise InventoryError(
            f"capture diagnostic counts mismatch: expected={expected_counts}, got={counts}"
        )
    return raw


def validate_inventory_against_receipt(
    inventory: Sequence[dict[str, object]], receipt: Mapping[str, object]
) -> None:
    """Require exact actual-row equality while independently validating reviews."""
    _reviewed_index(inventory, allow_unreviewed=False)
    validate_source_specific_reviews(inventory)
    projected = [
        {field: row[field] for field in ACTUAL_FIELDS}
        for row in inventory
    ]
    receipt_rows = receipt.get("rows")
    if projected != receipt_rows:
        raise InventoryError(
            "reviewed inventory actual projection disagrees with compiler capture"
        )


def validate_source_specific_reviews(
    inventory: Sequence[dict[str, object]],
) -> None:
    """Enforce structural source bindings without claiming semantic proof."""
    rationales: set[str] = set()
    resources: dict[str, list[dict[str, object]]] = {}
    for row in inventory:
        source = row.get("source")
        operation = row.get("operation")
        rationale = row.get("rationale")
        evidence = row.get("evidence")
        if (
            not isinstance(source, Mapping)
            or not isinstance(operation, str)
            or not isinstance(rationale, str)
            or not isinstance(evidence, Mapping)
        ):
            raise InventoryError("source-specific review has invalid structure")
        source_file = source.get("file")
        source_line = source.get("line")
        source_identity = f"{source_file}:{source_line}"
        if source_identity not in rationale:
            raise InventoryError(
                "review rationale does not bind its exact source file and line: "
                f"{row.get('review_id')}"
            )
        if operation not in rationale:
            raise InventoryError(
                "review rationale does not bind its canonical operation: "
                f"{row.get('review_id')}"
            )
        if rationale in rationales:
            raise InventoryError("review rationales must be unique across inventory")
        rationales.add(rationale)

        resource = evidence.get("resource")
        if not isinstance(resource, str):
            raise InventoryError("source-specific review has invalid evidence resource")
        normalized = _normalized_resource(resource)
        if any(fragment in normalized for fragment in BLANKET_RESOURCE_FRAGMENTS):
            raise InventoryError(
                f"blanket evidence resource is not source-specific: {resource!r}"
            )
        resources.setdefault(normalized, []).append(row)

    for normalized, rows in resources.items():
        if len(rows) > MAX_IDENTICAL_RESOURCE_REVIEWS:
            raise InventoryError(
                "evidence resource is repeated as a blanket substitution: "
                f"{normalized!r} appears {len(rows)} times"
            )
        roles = {
            (row.get("classification"), row["evidence"].get("authority"))
            for row in rows
        }
        if len(roles) != 1:
            raise InventoryError(
                "one evidence resource cannot cross classification or authority: "
                f"{normalized!r}"
            )


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
    profile_ids: Sequence[str],
    operation_catalog: Mapping[str, str],
    runner: Any = subprocess.run,
    *,
    root: Path = ROOT,
    current_host: str | None = None,
) -> dict[str, object]:
    """Run a selected local subset and return pure normalized receipt data."""
    selected_ids = list(profile_ids)
    if not selected_ids:
        raise InventoryError("executed profile subset must be nonempty")
    if not all(isinstance(profile_id, str) for profile_id in selected_ids):
        raise InventoryError("executed profiles must be checked matrix profile IDs")
    if len(selected_ids) != len(set(selected_ids)):
        raise InventoryError("executed profile subset contains duplicate IDs")
    unknown = sorted(set(selected_ids) - set(matrix.required_profiles))
    if unknown:
        raise InventoryError(f"executed profile subset contains unknown IDs: {unknown}")
    selected = [matrix.profiles[profile_id] for profile_id in selected_ids]
    catalog = _validate_operation_catalog(operation_catalog)
    required_triples = {profile.host_triple for profile in selected}
    if len(required_triples) != 1:
        raise InventoryError(
            f"executed profiles span multiple host triples: {sorted(required_triples)}"
        )
    with _execution_context(Path(root)) as execution:
        identities = verify_toolchain(
            matrix,
            runner=runner,
            root=Path(root),
            required_host_triple=next(iter(required_triples)),
            _execution=execution,
        )
        batches = []
        for profile in selected:
            messages = run_profile(
                profile,
                runner=runner,
                root=Path(root),
                current_host=current_host,
                _execution=execution,
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
    matrix: Matrix,
    operation_catalog: Mapping[str, str],
    source_head: str,
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
    if not isinstance(toolchain, Mapping) or set(toolchain) != {
        "rustc",
        "clippy",
        "host_triple",
    }:
        raise InventoryError(
            "candidate requires pinned rustc, Clippy, and host-triple identities"
        )
    if not all(isinstance(value, str) and value for value in toolchain.values()):
        raise InventoryError("candidate tool identities must be nonempty strings")
    complete = executed == required
    rows = (
        refresh(actual, expected, True)
        if complete
        else _unreviewed_candidate_rows(actual)
    )
    capture_receipt = compiler_capture_receipt(
        matrix,
        operation_catalog,
        actual,
        sorted(executed),
        sorted(required - executed),
        toolchain,
        source_head,
    )
    return {
        "schema": 1,
        "kind": "host-authority-census-candidate",
        "complete": complete,
        "toolchain": dict(toolchain),
        "executed_profiles": sorted(executed),
        "pending_profiles": sorted(required - executed),
        "capture_sha256": _canonical_digest(capture_receipt),
        "capture_receipt": capture_receipt,
        "rows": rows,
    }


def compiler_capture_receipt(
    matrix: Matrix,
    operation_catalog: Mapping[str, str],
    actual: Sequence[dict[str, object]],
    executed_profiles: Sequence[str],
    pending_profiles: Sequence[str],
    toolchain: Mapping[str, str],
    source_head: str,
) -> dict[str, object]:
    """Build a self-contained exact receipt for newly executed profiles."""
    if re.fullmatch(r"[0-9a-f]{40}", source_head) is None:
        raise InventoryError("candidate source_head must be a full lowercase Git hash")
    catalog = _validate_operation_catalog(operation_catalog)
    executed = _profile_set(executed_profiles, "capture executed")
    if (
        not isinstance(pending_profiles, Sequence)
        or isinstance(pending_profiles, (str, bytes))
        or not all(
            isinstance(profile_id, str) and profile_id
            for profile_id in pending_profiles
        )
        or list(pending_profiles) != sorted(set(pending_profiles))
    ):
        raise InventoryError("capture pending profiles contain invalid IDs")
    pending = set(pending_profiles)
    required = set(matrix.required_profiles)
    if executed | pending != required or executed & pending:
        raise InventoryError("capture executed and pending profiles must partition matrix")
    profiles = []
    for profile_id in sorted(executed):
        profile = matrix.profiles[profile_id]
        profiles.append(
            {
                "id": profile.id,
                "host": profile.host,
                "host_triple": profile.host_triple,
                "command": list(profile.command),
            }
        )
    normalized_rows = [
        _validate_actual_row(dict(row), "candidate capture") for row in actual
    ]
    for index, row in enumerate(normalized_rows, start=1):
        if row["catalog_id"] != catalog.get(row["operation"]):
            raise InventoryError(
                f"candidate capture row {index} has wrong catalog binding"
            )
    if normalized_rows != sorted(normalized_rows, key=_sort_key):
        raise InventoryError("candidate capture rows are not canonically sorted")
    counts = {
        profile_id: sum(
            profile_id in row["profiles"] for row in normalized_rows
        )
        for profile_id in sorted(executed)
    }
    counts["merged"] = len(normalized_rows)
    return {
        "schema": 1,
        "kind": "host-authority-compiler-capture",
        "source_head": source_head,
        "toolchain": dict(toolchain),
        "executed_profiles": sorted(executed),
        "pending_profiles": sorted(pending),
        "profiles": profiles,
        "diagnostic_counts": counts,
        "catalog_sha256": _canonical_digest(catalog),
        "toolchain_sha256": _canonical_digest(dict(toolchain)),
        "profiles_sha256": _canonical_digest(profiles),
        "rows_sha256": _canonical_digest(normalized_rows),
        "rows": normalized_rows,
    }


def current_source_head(root: Path) -> str:
    """Resolve the exact Git commit associated with a compiler capture."""
    completed = subprocess.run(
        ["git", "-C", str(Path(root).resolve()), "rev-parse", "HEAD"],
        cwd="/",
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    source_head = completed.stdout.strip()
    if completed.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", source_head) is None:
        detail = completed.stderr.strip()
        raise InventoryError(f"cannot resolve candidate source HEAD: {detail}")
    return source_head


def _authenticate_candidate_entry(
    directory_fd: int,
    name: str,
    protected_identities: frozenset[tuple[int, int]],
) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise InventoryError("refresh candidate target is a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise InventoryError("refresh candidate target is not a regular file")
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in protected_identities:
        raise InventoryError(
            "refresh candidate target hardlinks a checked authority artifact"
        )


def protected_candidate_paths(root: Path) -> tuple[Path, ...]:
    """Return every checked authority artifact a candidate may not replace."""
    root = Path(root)
    return tuple(
        root / path.relative_to(ROOT)
        for path in (
            INVENTORY_PATH,
            MACOS_CAPTURE_PATH,
            CATALOG_MANIFEST_PATH,
            MATRIX_PATH,
            CLIPPY_CONFIG_PATH,
        )
    )


@contextlib.contextmanager
def _candidate_destination(
    requested: Path, protected_paths: Sequence[Path]
):
    requested = requested.expanduser()
    try:
        requested_metadata = requested.lstat()
    except FileNotFoundError:
        requested_metadata = None
    if requested_metadata is not None and stat.S_ISLNK(requested_metadata.st_mode):
        raise InventoryError("refresh candidate target is a symlink")
    candidate = requested.resolve(strict=False)
    protected_identities: set[tuple[int, int]] = set()
    for protected_path in protected_paths:
        protected = protected_path.expanduser().resolve(strict=False)
        if candidate == protected:
            raise InventoryError(
                "refresh candidate path resolves to a checked authority artifact"
            )
        try:
            protected_metadata = protected.stat()
        except FileNotFoundError:
            continue
        protected_identities.add(
            (protected_metadata.st_dev, protected_metadata.st_ino)
        )
    frozen_identities = frozenset(protected_identities)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory_fd = os.open(candidate.parent, flags)
    except OSError as error:
        raise InventoryError(
            f"cannot authenticate refresh candidate parent: {error}"
        ) from error
    try:
        opened = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise InventoryError("refresh candidate parent is not a directory")
        _authenticate_candidate_entry(
            directory_fd, candidate.name, frozen_identities
        )
        yield CandidateDestination(
            candidate,
            directory_fd,
            candidate.name,
            frozen_identities,
        )
    finally:
        os.close(directory_fd)


def _write_candidate_atomically(
    destination: CandidateDestination, document: Mapping[str, object]
) -> None:
    """Publish through one authenticated directory descriptor."""
    temporary_name = (
        f".{destination.name}.{secrets.token_hex(12)}.tmp"
    )
    temporary_fd: int | None = None
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=destination.directory_fd,
        )
        with os.fdopen(temporary_fd, mode="w", encoding="utf-8") as stream:
            temporary_fd = None
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        _authenticate_candidate_entry(
            destination.directory_fd,
            destination.name,
            destination.protected_identities,
        )
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=destination.directory_fd,
            dst_dir_fd=destination.directory_fd,
        )
        os.fsync(destination.directory_fd)
    except BaseException:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=destination.directory_fd)
        except FileNotFoundError:
            pass
        raise


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
    mode.add_argument(
        "--static",
        action="store_true",
        help=(
            "validate the independent catalog, capture receipt, and reviewed "
            "inventory without launching Cargo"
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
    catalog_manifest: Mapping[str, str] | None = None,
    expected: list[dict[str, object]] | None = None,
    capture_receipt: Mapping[str, object] | None = None,
    source_head: str | None = None,
    current_host: str | None = None,
    root: Path = ROOT,
) -> int:
    """Run the fail-closed CLI, with pure dependency injection for tests."""
    arguments = _argument_parser().parse_args(list(argv))
    try:
        checked_matrix = matrix or load_matrix(
            Path(root) / MATRIX_PATH.relative_to(ROOT)
        )
        destination_manager = (
            _candidate_destination(
                arguments.refresh_candidate, protected_candidate_paths(root)
            )
            if arguments.refresh_candidate is not None
            else contextlib.nullcontext(None)
        )
        with destination_manager as candidate_destination:
            manifest = (
                dict(catalog_manifest)
                if catalog_manifest is not None
                else load_catalog_manifest(
                    Path(root) / CATALOG_MANIFEST_PATH.relative_to(ROOT)
                )
            )
            catalog = (
                dict(operation_catalog)
                if operation_catalog is not None
                else load_production_catalog(
                    Path(root) / CLIPPY_CONFIG_PATH.relative_to(ROOT),
                    manifest,
                )
            )
            reviews = (
                expected
                if expected is not None
                else load_inventory(
                    Path(root) / INVENTORY_PATH.relative_to(ROOT)
                )
            )
            if candidate_destination is None:
                receipt = (
                    dict(capture_receipt)
                    if capture_receipt is not None
                    else load_capture_receipt(
                        Path(root) / MACOS_CAPTURE_PATH.relative_to(ROOT),
                        checked_matrix,
                        catalog,
                    )
                )
                validate_inventory_against_receipt(reviews, receipt)
                if arguments.static:
                    print(
                        "host-authority static authority passed: exact catalog, "
                        "macOS compiler receipt, and reviewed inventory agree"
                    )
                    return 0
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
            if candidate_destination is not None:
                document = candidate_document(
                    rows,
                    reviews,
                    executed,
                    checked_matrix.required_profiles,
                    identities,
                    checked_matrix,
                    catalog,
                    source_head or current_source_head(root),
                )
                try:
                    _write_candidate_atomically(
                        candidate_destination, document
                    )
                except OSError as error:
                    raise InventoryError(
                        "cannot publish refresh candidate atomically: "
                        f"{error}"
                    ) from error
                if document["complete"] is not True:
                    print(
                        "error: wrote an explicitly partial, non-authoritative "
                        f"candidate; pending profiles: {', '.join(pending)}",
                        file=sys.stderr,
                    )
                    return 1
                print(
                    "wrote complete refresh candidate: "
                    f"{candidate_destination.display_path}"
                )
                return 0
            validate(
                rows, reviews, executed, checked_matrix.required_profiles
            )
            if pending:
                print(
                    "host-authority census subset passed; result is partial; "
                    f"pending profiles: {', '.join(pending)}"
                )
            else:
                print(
                    "host-authority census complete: all required profiles passed"
                )
            return 0
    except InventoryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
