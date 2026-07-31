#!/usr/bin/env python3
"""Prepare and verify immutable Carrick binaries for native ABBA campaigns."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import errno
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Sequence

import native_go_build


ARM_SCHEMA = "carrick.native-perf-arm.v1"
CAMPAIGN_SCHEMA = "carrick.native-go-build-abba.v1"
ARM_ROLES = frozenset(("control", "candidate"))
ARM_FIELDS = frozenset(
    (
        "schema",
        "label",
        "role",
        "source_repo",
        "source_commit",
        "source_branch",
        "source_detached",
        "source_status",
        "binary_path",
        "binary_size",
        "binary_mode",
        "binary_sha256",
        "macho_uuid",
        "codesign_verified",
        "entitlement_sha256",
        "has_dof_carrick",
        "rust_toolchain",
        "build",
        "host",
        "image_ref",
        "image",
    )
)
BUILD_FIELDS = frozenset(
    ("command", "started_at", "finished_at", "status", "stdout", "stderr")
)
HOST_FIELDS = frozenset(("platform", "machine", "node", "os_build"))
IMAGE_FIELDS = frozenset(("architecture", "id", "repo_digests"))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REPO_DIGEST_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
MACHO_UUID_RE = re.compile(
    r"^UUID: ([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}) "
    r"\(arm64\)(?:\s|$)"
)


@dataclasses.dataclass(frozen=True)
class ArmReceipt:
    path: pathlib.Path
    label: str
    role: str
    source_repo: pathlib.Path
    source_commit: str
    source_branch: str | None
    source_detached: bool
    binary_path: pathlib.Path
    binary_size: int
    binary_mode: int
    binary_sha256: str
    macho_uuid: str
    entitlement_sha256: str
    image_ref: str
    image_id: str
    image_repo_digests: tuple[str, ...]


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    descriptor = _open_path_no_symlinks(path, "SHA-256 source")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"SHA-256 source is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _output_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output


def _command_error(name: str, result: subprocess.CompletedProcess) -> RuntimeError:
    detail = _output_text(result.stderr).strip() or _output_text(result.stdout).strip()
    suffix = f": {detail}" if detail else ""
    return RuntimeError(f"{name} failed with status {result.returncode}{suffix}")


def git_output(
    repo: pathlib.Path,
    *args: str,
    optional_locks: bool = True,
) -> str:
    command = ["git"]
    if not optional_locks:
        command.append("--no-optional-locks")
    command.extend(args)
    result = subprocess.run(
        command,
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error(f"git {' '.join(args)}", result)
    return result.stdout.strip()


def rustc_version(source_repo: pathlib.Path) -> str:
    result = subprocess.run(
        ["rustc", "--version"],
        cwd=source_repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error("rustc --version", result)
    version = result.stdout.strip()
    if not version:
        raise RuntimeError("rustc --version returned empty output")
    return version


def verify_codesign(binary: pathlib.Path) -> None:
    result = subprocess.run(
        ["codesign", "--verify", "--strict", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error("codesign signature verification", result)


def entitlement_digest(binary: pathlib.Path) -> str:
    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error("codesign entitlement extraction", result)
    raw = result.stdout
    if isinstance(raw, str):
        raw = raw.encode()
    try:
        entitlement = plistlib.loads(raw)
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise RuntimeError("codesign entitlement output is not a valid plist") from error
    if not isinstance(entitlement, dict) or not entitlement:
        raise RuntimeError("codesign entitlement plist must be nonempty")
    normalized = plistlib.dumps(
        entitlement,
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    return hashlib.sha256(normalized).hexdigest()


def macho_uuid(binary: pathlib.Path) -> str:
    result = subprocess.run(
        ["dwarfdump", "--uuid", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error("Mach-O UUID inspection", result)
    matches = [
        match.group(1).upper()
        for line in _output_text(result.stdout).splitlines()
        if (match := MACHO_UUID_RE.match(line))
    ]
    if len(matches) != 1:
        raise RuntimeError(
            "Mach-O UUID inspection requires exactly one arm64 UUID"
        )
    return matches[0]


def has_dof_carrick(binary: pathlib.Path) -> bool:
    result = subprocess.run(
        ["otool", "-l", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error("DOF inspection", result)
    lines = _output_text(result.stdout).splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "sectname __dof_carrick":
            continue
        section_tail = lines[index + 1 : index + 8]
        if any(candidate.strip() == "segname __DATA" for candidate in section_tail):
            return True
    return False


def host_receipt() -> dict[str, str]:
    machine = platform.machine()
    if machine != "arm64":
        raise RuntimeError(f"native performance arms require an arm64 host, got {machine!r}")
    return {
        "platform": platform.platform(),
        "machine": machine,
        "node": platform.node(),
        "os_build": platform.version(),
    }


def _immutable_repo_digests(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("Docker image RepoDigests must be a nonempty list")
    if not all(isinstance(item, str) and REPO_DIGEST_RE.fullmatch(item) for item in value):
        raise RuntimeError(
            "Docker image RepoDigests must contain immutable sha256 references"
        )
    return tuple(sorted(set(value)))


def _image_receipt(image_ref: str) -> dict[str, object]:
    image = native_go_build.docker_image_provenance(image_ref)
    if set(image) != IMAGE_FIELDS:
        unknown = set(image) - IMAGE_FIELDS
        missing = IMAGE_FIELDS - set(image)
        raise RuntimeError(
            "Docker image provenance has the wrong fields: "
            f"unknown={sorted(unknown)} missing={sorted(missing)}"
        )
    if image["architecture"] != "arm64":
        raise RuntimeError(
            f"Docker oracle image must be native arm64, got {image['architecture']!r}"
        )
    image_id = image["id"]
    if not isinstance(image_id, str) or not DIGEST_RE.fullmatch(image_id):
        raise RuntimeError("Docker image ID must be an immutable sha256 digest")
    digests = _immutable_repo_digests(image["repo_digests"])
    return {
        "architecture": "arm64",
        "id": image_id,
        "repo_digests": list(digests),
    }


def _absolute_without_resolving(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _open_path_no_symlinks(
    path: pathlib.Path,
    description: str,
    *,
    directory: bool = False,
) -> int:
    """Open one absolute path without following any component symlink."""
    absolute = _absolute_without_resolving(path)
    components = absolute.parts
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.open(components[0], directory_flags)
    try:
        for component in components[1:-1]:
            next_directory = os.open(
                component,
                directory_flags,
                dir_fd=current,
            )
            os.close(current)
            current = next_directory
        if len(components) == 1:
            if not directory:
                raise RuntimeError(f"{description} must not be the filesystem root")
            result = current
            current = -1
            return result
        final_flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        if directory:
            final_flags |= getattr(os, "O_DIRECTORY", 0)
        result = os.open(
            components[-1],
            final_flags,
            dir_fd=current,
        )
        return result
    except FileNotFoundError as error:
        raise RuntimeError(f"missing {description}: {absolute}") from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise RuntimeError(
                f"{description} path contains a symlink "
                f"or non-directory component: {absolute}"
            ) from error
        raise RuntimeError(
            f"cannot open {description} without following symlinks: {absolute}"
        ) from error
    finally:
        if current >= 0:
            os.close(current)


def _validate_regular_file(path: pathlib.Path, description: str) -> os.stat_result:
    descriptor = _open_path_no_symlinks(path, description)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{description} must be a regular file: {path}")
        return metadata
    finally:
        os.close(descriptor)


def _validate_directory(path: pathlib.Path, description: str) -> os.stat_result:
    descriptor = _open_path_no_symlinks(
        path,
        description,
        directory=True,
    )
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_unpublished(destination: pathlib.Path) -> None:
    for name in ("arm.json", "carrick"):
        candidate = destination / name
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
    try:
        destination.rmdir()
    except (FileNotFoundError, OSError):
        pass


def _publish_receipt(destination: pathlib.Path, receipt: dict[str, object]) -> None:
    directory_descriptor = _open_path_no_symlinks(
        destination,
        "receipt destination",
        directory=True,
    )
    try:
        descriptor = os.open(
            "arm.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o444,
            dir_fd=directory_descriptor,
        )
        try:
            os.fchmod(descriptor, 0o444)
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                closefd=False,
            ) as stream:
                json.dump(receipt, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _source_status(source_repo: pathlib.Path) -> list[str]:
    return git_output(
        source_repo,
        "status",
        "--porcelain",
        optional_locks=False,
    ).splitlines()


def prepare_arm(
    source_repo: pathlib.Path,
    destination: pathlib.Path,
    *,
    label: str,
    role: str,
    image_ref: str,
) -> dict[str, object]:
    if role not in ARM_ROLES:
        raise ValueError(f"role must be one of {sorted(ARM_ROLES)}, got {role!r}")
    if type(label) is not str or not label:
        raise ValueError("label must be nonempty")
    if type(image_ref) is not str or not image_ref:
        raise ValueError("image_ref must be nonempty")

    resolved_source = source_repo.resolve(strict=True)
    _validate_directory(resolved_source, "source repository")
    absolute_destination = _absolute_without_resolving(destination)
    absolute_destination.parent.mkdir(parents=True, exist_ok=True)
    resolved_destination_parent = absolute_destination.parent.resolve(strict=True)
    _validate_directory(resolved_destination_parent, "destination parent")
    absolute_destination = resolved_destination_parent / absolute_destination.name
    absolute_destination.mkdir(mode=0o755)
    published = False
    try:
        if _source_status(resolved_source):
            raise RuntimeError("arm preparation requires a clean source repository")
        source_commit_before = git_output(resolved_source, "rev-parse", "HEAD")

        build_command = ["just", "build"]
        started_at = utc_now()
        build = subprocess.run(
            build_command,
            cwd=resolved_source,
            capture_output=True,
            text=True,
            check=False,
        )
        finished_at = utc_now()
        build_receipt = {
            "command": build_command,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": build.returncode,
            "stdout": build.stdout,
            "stderr": build.stderr,
        }
        if build.returncode != 0:
            raise _command_error("just build", build)
        if _source_status(resolved_source):
            raise RuntimeError("just build left the source repository non-clean")
        source_commit_after = git_output(resolved_source, "rev-parse", "HEAD")
        if source_commit_after != source_commit_before:
            raise RuntimeError("source commit changed while just build was running")

        built_binary = resolved_source / "target/release/carrick"
        _validate_regular_file(built_binary, "signed release binary")
        copied = absolute_destination / "carrick"
        shutil.copy2(built_binary, copied, follow_symlinks=False)
        copied_metadata = _validate_regular_file(copied, "copied Carrick binary")
        copied.chmod(stat.S_IMODE(copied_metadata.st_mode) & ~0o222)
        copied_metadata = copied.lstat()
        copied_descriptor = _open_path_no_symlinks(
            copied,
            "copied Carrick binary",
        )
        try:
            os.fsync(copied_descriptor)
        finally:
            os.close(copied_descriptor)

        verify_codesign(copied)
        copied_uuid = macho_uuid(copied)
        copied_entitlements = entitlement_digest(copied)
        copied_has_dof = has_dof_carrick(copied)
        if not copied_has_dof:
            raise RuntimeError("copied Carrick binary is missing __DATA,__dof_carrick DOF")
        current_host = host_receipt()
        current_image = _image_receipt(image_ref)
        branch = git_output(resolved_source, "branch", "--show-current")
        source_commit = git_output(resolved_source, "rev-parse", "HEAD")
        if source_commit != source_commit_after:
            raise RuntimeError(
                "source commit changed while arm provenance was collected"
            )
        if _source_status(resolved_source):
            raise RuntimeError(
                "source repository changed while arm provenance was collected"
            )
        receipt = {
            "schema": ARM_SCHEMA,
            "label": label,
            "role": role,
            "source_repo": str(resolved_source),
            "source_commit": source_commit,
            "source_branch": branch or None,
            "source_detached": not bool(branch),
            "source_status": [],
            "binary_path": str(copied),
            "binary_size": copied_metadata.st_size,
            "binary_mode": stat.S_IMODE(copied_metadata.st_mode),
            "binary_sha256": sha256_file(copied),
            "macho_uuid": copied_uuid,
            "codesign_verified": True,
            "entitlement_sha256": copied_entitlements,
            "has_dof_carrick": True,
            "rust_toolchain": rustc_version(resolved_source),
            "build": build_receipt,
            "host": current_host,
            "image_ref": image_ref,
            "image": current_image,
        }
        _publish_receipt(absolute_destination, receipt)
        published = True
        return receipt
    finally:
        if not published:
            _cleanup_unpublished(absolute_destination)


def _read_receipt(path: pathlib.Path) -> tuple[pathlib.Path, dict[str, object]]:
    absolute = _absolute_without_resolving(path)
    descriptor = _open_path_no_symlinks(absolute, "arm receipt")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"arm receipt must be a regular file: {absolute}")
        if stat.S_IMODE(metadata.st_mode) != 0o444:
            raise RuntimeError(
                "arm receipt mode changed: "
                f"expected 0o444, got {stat.S_IMODE(metadata.st_mode):#o}"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            payload = json.load(stream)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"arm receipt is not valid JSON: {absolute}") from error
    finally:
        os.close(descriptor)
    if not isinstance(payload, dict):
        raise ValueError("arm receipt must be a JSON object")
    return absolute, payload


def _require_exact_fields(
    payload: dict[str, object],
    expected: frozenset[str],
    description: str,
) -> None:
    actual = set(payload)
    unknown = actual - expected
    missing = expected - actual
    if unknown or missing:
        raise ValueError(
            f"{description} fields are invalid: "
            f"unknown={sorted(unknown)} missing={sorted(missing)}"
        )


def _require_type(
    payload: dict[str, object],
    key: str,
    expected: type,
    description: str,
):
    value = payload[key]
    if type(value) is not expected:
        raise ValueError(
            f"{description}.{key} must be {expected.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


def _validate_recorded_receipt(
    receipt_path: pathlib.Path,
    payload: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    _require_exact_fields(payload, ARM_FIELDS, "arm receipt")
    if payload["schema"] != ARM_SCHEMA:
        raise ValueError(f"unsupported arm receipt schema: {payload['schema']!r}")
    label = _require_type(payload, "label", str, "arm receipt")
    role = _require_type(payload, "role", str, "arm receipt")
    if not label:
        raise ValueError("arm receipt label must be nonempty")
    if role not in ARM_ROLES:
        raise ValueError(f"arm receipt role is invalid: {role!r}")
    source_repo = _require_type(payload, "source_repo", str, "arm receipt")
    source_commit = _require_type(payload, "source_commit", str, "arm receipt")
    source_detached = _require_type(
        payload, "source_detached", bool, "arm receipt"
    )
    source_branch = payload["source_branch"]
    if source_branch is not None and type(source_branch) is not str:
        raise ValueError("arm receipt source_branch must be a string or null")
    named = isinstance(source_branch, str) and bool(source_branch)
    if named == source_detached:
        raise ValueError(
            "arm receipt requires exactly one named source branch or detached HEAD"
        )
    if not source_repo or not COMMIT_RE.fullmatch(source_commit):
        raise ValueError("arm receipt source identity must be nonempty")
    if payload["source_status"] != []:
        raise ValueError("arm receipt source_status must be exactly empty")

    binary_path = _require_type(payload, "binary_path", str, "arm receipt")
    binary_size = _require_type(payload, "binary_size", int, "arm receipt")
    binary_mode = _require_type(payload, "binary_mode", int, "arm receipt")
    binary_sha256 = _require_type(
        payload, "binary_sha256", str, "arm receipt"
    )
    recorded_uuid = _require_type(payload, "macho_uuid", str, "arm receipt")
    entitlement_sha256 = _require_type(
        payload, "entitlement_sha256", str, "arm receipt"
    )
    if not binary_path or binary_size < 0 or not 0 <= binary_mode <= 0o7777:
        raise ValueError("arm receipt binary metadata is malformed")
    if binary_mode & 0o222 or not binary_mode & 0o111:
        raise ValueError(
            "arm receipt binary mode must be read-only and executable"
        )
    if not SHA256_RE.fullmatch(binary_sha256):
        raise ValueError("arm receipt binary_sha256 is malformed")
    if not SHA256_RE.fullmatch(entitlement_sha256):
        raise ValueError("arm receipt entitlement_sha256 is malformed")
    if not recorded_uuid:
        raise ValueError("arm receipt macho_uuid is empty")
    if payload["codesign_verified"] is not True:
        raise ValueError("arm receipt codesign_verified must be true")
    if payload["has_dof_carrick"] is not True:
        raise ValueError("arm receipt has_dof_carrick must be true")
    rust_toolchain = _require_type(payload, "rust_toolchain", str, "arm receipt")
    image_ref = _require_type(payload, "image_ref", str, "arm receipt")
    if not rust_toolchain or not image_ref:
        raise ValueError("arm receipt toolchain and image reference must be nonempty")

    build = payload["build"]
    host = payload["host"]
    image = payload["image"]
    if not isinstance(build, dict) or not isinstance(host, dict) or not isinstance(image, dict):
        raise ValueError("arm receipt build, host, and image must be objects")
    _require_exact_fields(build, BUILD_FIELDS, "build")
    _require_exact_fields(host, HOST_FIELDS, "host")
    _require_exact_fields(image, IMAGE_FIELDS, "image")
    if build["command"] != ["just", "build"] or type(build["status"]) is not int:
        raise ValueError("arm receipt build command or status is invalid")
    if build["status"] != 0:
        raise ValueError("arm receipt build status must be zero")
    for field in ("started_at", "finished_at", "stdout", "stderr"):
        if type(build[field]) is not str:
            raise ValueError(f"arm receipt build.{field} must be a string")
    try:
        started = datetime.datetime.fromisoformat(build["started_at"])
        finished = datetime.datetime.fromisoformat(build["finished_at"])
    except ValueError as error:
        raise ValueError("arm receipt build timestamps are malformed") from error
    utc = datetime.timedelta(0)
    if (
        started.utcoffset() != utc
        or finished.utcoffset() != utc
        or finished < started
    ):
        raise ValueError("arm receipt build timestamps are not ordered UTC times")

    for field in HOST_FIELDS:
        if type(host[field]) is not str or not host[field]:
            raise ValueError(f"arm receipt host.{field} must be a nonempty string")
    if host["machine"] != "arm64":
        raise ValueError("arm receipt host machine must be arm64")
    if image["architecture"] != "arm64":
        raise ValueError("arm receipt image architecture must be arm64")
    if type(image["id"]) is not str or not DIGEST_RE.fullmatch(image["id"]):
        raise ValueError("arm receipt image ID must be an immutable sha256 digest")
    recorded_digests = _immutable_repo_digests(image["repo_digests"])
    if list(recorded_digests) != image["repo_digests"]:
        raise ValueError("arm receipt image RepoDigests must be sorted and unique")

    expected_binary = receipt_path.parent / "carrick"
    if pathlib.Path(binary_path) != expected_binary:
        raise ValueError(
            f"arm receipt binary_path must be {expected_binary}, got {binary_path}"
        )
    return build, host, image


def load_and_verify_arm(path: pathlib.Path) -> ArmReceipt:
    receipt_path, payload = _read_receipt(path)
    _build, recorded_host, recorded_image = _validate_recorded_receipt(
        receipt_path, payload
    )

    source_repo = pathlib.Path(str(payload["source_repo"]))
    if not source_repo.is_absolute():
        raise ValueError("arm receipt source_repo must be absolute")
    _validate_directory(source_repo, "source repository")
    status = _source_status(source_repo)
    if status:
        raise RuntimeError("arm receipt source repository is no longer clean")
    current_commit = git_output(source_repo, "rev-parse", "HEAD")
    current_branch = git_output(source_repo, "branch", "--show-current")
    if current_commit != payload["source_commit"]:
        raise RuntimeError("arm receipt source commit identity changed")
    if (current_branch or None) != payload["source_branch"]:
        raise RuntimeError("arm receipt source branch identity changed")
    if (not bool(current_branch)) != payload["source_detached"]:
        raise RuntimeError("arm receipt source detached-HEAD identity changed")

    binary_path = pathlib.Path(str(payload["binary_path"]))
    metadata = _validate_regular_file(binary_path, "arm binary")
    expected_size = int(payload["binary_size"])
    expected_mode = int(payload["binary_mode"])
    if metadata.st_size != expected_size:
        raise RuntimeError(
            f"arm binary size changed: expected {expected_size}, got {metadata.st_size}"
        )
    current_mode = stat.S_IMODE(metadata.st_mode)
    if current_mode != expected_mode:
        raise RuntimeError(
            f"arm binary mode changed: expected {expected_mode:#o}, got {current_mode:#o}"
        )
    current_sha256 = sha256_file(binary_path)
    if current_sha256 != payload["binary_sha256"]:
        raise RuntimeError("arm binary sha256 changed")
    current_uuid = macho_uuid(binary_path)
    if current_uuid != payload["macho_uuid"]:
        raise RuntimeError("arm binary Mach-O UUID changed")
    verify_codesign(binary_path)
    current_entitlement = entitlement_digest(binary_path)
    if current_entitlement != payload["entitlement_sha256"]:
        raise RuntimeError("arm binary entitlement digest changed")
    if not has_dof_carrick(binary_path):
        raise RuntimeError("arm binary DOF section changed or is missing")

    current_host = host_receipt()
    if current_host != recorded_host:
        raise RuntimeError("arm receipt host identity changed")
    current_image = _image_receipt(str(payload["image_ref"]))
    if current_image != recorded_image:
        raise RuntimeError("arm receipt image identity changed")

    return ArmReceipt(
        path=receipt_path,
        label=str(payload["label"]),
        role=str(payload["role"]),
        source_repo=source_repo,
        source_commit=str(payload["source_commit"]),
        source_branch=payload["source_branch"],
        source_detached=bool(payload["source_detached"]),
        binary_path=binary_path,
        binary_size=expected_size,
        binary_mode=expected_mode,
        binary_sha256=str(payload["binary_sha256"]),
        macho_uuid=str(payload["macho_uuid"]),
        entitlement_sha256=str(payload["entitlement_sha256"]),
        image_ref=str(payload["image_ref"]),
        image_id=str(recorded_image["id"]),
        image_repo_digests=tuple(recorded_image["repo_digests"]),
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    prepare = subcommands.add_parser(
        "prepare-arm",
        help="build and publish one immutable Carrick benchmark arm",
    )
    prepare.add_argument("--source-repo", required=True, type=pathlib.Path)
    prepare.add_argument("--destination", required=True, type=pathlib.Path)
    prepare.add_argument("--label", required=True)
    prepare.add_argument("--role", required=True, choices=sorted(ARM_ROLES))
    prepare.add_argument("--image", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "prepare-arm":
        receipt = prepare_arm(
            args.source_repo,
            args.destination,
            label=args.label,
            role=args.role,
            image_ref=args.image,
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
