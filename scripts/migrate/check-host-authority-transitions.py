#!/usr/bin/env python3
"""Discover compiler-resolved host-authority diagnostics ephemerally.

This module deliberately consumes only Cargo/Clippy JSON.  Rust name
resolution, cfg selection, target reachability, imports, and macro resolution
belong to the pinned compiler that produced the diagnostics.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import hashlib
import io
import json
import os
import platform
import posixpath
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tarfile
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
CLIPPY_CONFIG_PATH = ROOT / "clippy.toml"
CATALOG_MANIFEST_PATH = (
    ROOT / "scripts" / "migrate" / "host-authority-catalog.json"
)
CATALOG_ENTRY_COUNT = 46
REQUIRED_ESCAPE_OPERATIONS = {"libc::syscall", "libc::dlopen", "libc::dlsym"}
REQUIRED_HOST_PID_OPERATIONS = {
    "libc::getpid",
    "std::process::id",
    "libc::proc_listallpids",
}
LOCAL_MACOS_PROFILES = (
    "macos-cli-default",
    "macos-hvf-default",
    "macos-runtime-default",
)

ACTUAL_FIELDS = {"catalog_id", "operation", "source", "expansion", "profiles"}
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
MAX_CARGO_FAILURE_DIAGNOSTICS = 3
MAX_CARGO_FAILURE_DIAGNOSTIC_CHARS = 4_000
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


class CrossToolchain(NamedTuple):
    """Explicit metadata-only BSD cross compilation, never native coverage."""

    target: str
    cc: str
    cflags: str
    ar: str


class ExecutionContext(NamedTuple):
    """Isolated Cargo discovery roots for one census invocation."""

    cwd: Path
    cargo_home: Path
    rustup_home: Path
    toolchain_channel: str
    target_root: Path
    cargo_config: Path
    manifest: Path


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
def _execution_context(root: Path, *, state_root: Path | None = None):
    workspace = Path(root).resolve(strict=True)
    state_workspace = Path(state_root or workspace).resolve(strict=True)
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
    census_root = state_workspace / "target" / "host-authority-census"
    census_root.mkdir(parents=True, exist_ok=True)
    census_root = census_root.resolve(strict=True)
    if not census_root.is_relative_to(state_workspace):
        raise InventoryError(
            f"authority census target root escapes state workspace: {census_root}"
        )
    if census_root.is_relative_to(workspace) and state_workspace != workspace:
        raise InventoryError("authority census target root is inside source snapshot")
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
    *, cross_target: str | None = None,
) -> list[str]:
    """Select a nonempty current-host subset, preserving matrix order."""
    host = current_host or current_host_id()
    if cross_target is not None and (
        host != "linux"
        or cross_target not in (HOST_TRIPLES["freebsd"], HOST_TRIPLES["netbsd"])
        or selector is None
    ):
        raise InventoryError("cross discovery requires explicit BSD profiles on Linux")
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
        if (matrix.profiles[profile_id].host_triple != cross_target
            if cross_target else matrix.profiles[profile_id].host != host)
    ]
    if unavailable:
        raise InventoryError(
            f"profiles unavailable on current host {host} / target {cross_target}: {sorted(unavailable)}"
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


def _cargo_failure_diagnostics(stdout: object) -> list[str]:
    """Return a bounded, diagnostic-only subset of a Cargo JSON stream."""
    if not isinstance(stdout, str):
        return []
    diagnostics: list[str] = []
    for line in stdout.splitlines():
        try:
            row: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, Mapping) or row.get("reason") != "compiler-message":
            continue
        message = row.get("message")
        if not isinstance(message, Mapping) or message.get("level") != "error":
            continue
        rendered = message.get("rendered")
        detail = (
            rendered
            if isinstance(rendered, str) and rendered.strip()
            else message.get("message")
        )
        if not isinstance(detail, str) or not detail.strip():
            continue
        detail = detail.strip()
        if len(detail) > MAX_CARGO_FAILURE_DIAGNOSTIC_CHARS:
            detail = (
                detail[:MAX_CARGO_FAILURE_DIAGNOSTIC_CHARS]
                + "\n<compiler diagnostic truncated>"
            )
        diagnostics.append(detail)
        if len(diagnostics) == MAX_CARGO_FAILURE_DIAGNOSTICS:
            break
    return diagnostics


def _command_failure(label: str, result: subprocess.CompletedProcess[str]) -> None:
    stderr = result.stderr.strip() if isinstance(result.stderr, str) else ""
    detail = stderr or "<captured stderr was empty>"
    failure = f"{label} failed with exit {result.returncode}; captured stderr: {detail}"
    diagnostics = _cargo_failure_diagnostics(result.stdout)
    if diagnostics:
        failure += (
            "; captured Cargo compiler error(s) from stdout:\n"
            + "\n---\n".join(diagnostics)
        )
        if len(diagnostics) == MAX_CARGO_FAILURE_DIAGNOSTICS:
            failure += "\n<compiler diagnostic limit reached>"
    raise InventoryError(failure)


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
    cross: CrossToolchain | None = None,
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
                cross=cross,
                _execution=execution,
            )
    host = current_host or current_host_id()
    if cross is not None and (
        host != "linux"
        or cross.target not in (HOST_TRIPLES["freebsd"], HOST_TRIPLES["netbsd"])
        or profile.host_triple != cross.target
        or not cross.cc or not cross.cflags or not cross.ar
    ):
        raise InventoryError("invalid explicit BSD cross toolchain/profile")
    if cross is None and profile.host != host:
        raise InventoryError(
            f"profile {profile.id} is unavailable on current host {host}"
        )
    environment = _sanitized_build_environment(
        _execution.cargo_home,
        _execution.rustup_home,
        _execution.toolchain_channel,
        target_dir=_execution.target_root / profile.id,
    )
    if cross is not None:
        suffix = cross.target.replace("-", "_")
        environment[f"CC_{suffix}"] = cross.cc
        environment[f"CFLAGS_{suffix}"] = cross.cflags
        environment[f"AR_{suffix}"] = cross.ar
    environment["CLIPPY_CONF_DIR"] = str(Path(root).resolve(strict=True))
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
    missing_pid = sorted(REQUIRED_HOST_PID_OPERATIONS - set(catalog))
    if missing_pid:
        raise InventoryError(
            f"host-authority catalog omits required host-PID operations: {missing_pid}"
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


def run_census(
    matrix: Matrix,
    profile_ids: Sequence[str],
    operation_catalog: Mapping[str, str],
    runner: Any = subprocess.run,
    *,
    root: Path = ROOT,
    state_root: Path | None = None,
    current_host: str | None = None,
    cross: CrossToolchain | None = None,
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
    with _execution_context(Path(root), state_root=state_root) as execution:
        identities = verify_toolchain(
            matrix,
            runner=runner,
            root=Path(root),
            required_host_triple=HOST_TRIPLES["linux"] if cross else next(iter(required_triples)),
            _execution=execution,
        )
        batches = []
        for profile in selected:
            messages = run_profile(
                profile,
                runner=runner,
                root=Path(root),
                current_host=current_host,
                cross=cross,
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
        **({"cross_target": cross.target} if cross else {}),
        "executed_profiles": selected_ids,
        "pending_profiles": pending,
        "rows": rows,
    }


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Ephemeral live compiler-resolved host discovery")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--profiles")
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--cross-target")
    parser.add_argument("--cross-cc")
    parser.add_argument("--cross-cflags")
    parser.add_argument("--cross-ar")
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        matrix = load_matrix(root / MATRIX_PATH.relative_to(ROOT))
        manifest = load_catalog_manifest(root / CATALOG_MANIFEST_PATH.relative_to(ROOT))
        catalog = load_production_catalog(root / CLIPPY_CONFIG_PATH.relative_to(ROOT), manifest)
        if args.static:
            print("host-authority catalog and nine-profile matrix validated; no live coverage claimed")
            return 0
        cross = None
        cross_values = (args.cross_target, args.cross_cc, args.cross_cflags, args.cross_ar)
        if any(cross_values):
            if not all(cross_values):
                raise InventoryError("cross discovery requires target, cc, cflags and ar")
            cross = CrossToolchain(*cross_values)
        selected = select_profiles(matrix, args.profiles, cross_target=args.cross_target)
        result = run_census(matrix, selected, catalog, root=root, cross=cross)
        # Source positions are transient diagnostic information only. The Rust
        # consumer resolves owners and counts them, then discards these rows.
        print(json.dumps(result))
        return 0
    except InventoryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
