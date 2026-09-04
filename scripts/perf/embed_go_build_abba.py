#!/usr/bin/env python3
"""Receipt-bound ABBA harness for Carrick's implicit embedding path."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import re
import resource
import shutil
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence

import native_go_build
import native_go_build_abba as native_abba
import paired_stats


ARM_SCHEMA = "carrick.embed-implicit-perf-arm.v1"
CAMPAIGN_SCHEMA = "carrick.embed-implicit-go-build-abba.v2"
ARM_ROLES = frozenset(("control", "candidate"))
DRIVER_INPUTS = (
    pathlib.Path("scripts/perf/embed_implicit_driver/Cargo.toml.in"),
    pathlib.Path("scripts/perf/embed_implicit_driver/src/main.rs"),
)
DRIVER_PACKAGE = "carrick-embed-implicit-driver"
DRIVER_BINARY = "embed-driver"
MINIMUM_QUADS = 8
THRESHOLD = 1.0
COMMAND_RECEIPT_FIELDS = frozenset(("command", "status", "stdout", "stderr"))
SIGN_SCRIPT = 'set -euo pipefail; . "$1"; carrick_post_link_sign "$2" "$2" "$3"'
CDHASH_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
ARM_FIELDS = frozenset(
    (
        "schema",
        "label",
        "role",
        "source_repo",
        "source_commit",
        "source_branch",
        "source_status",
        "harness_repo",
        "harness_commit",
        "harness_branch",
        "harness_status",
        "driver_source_sha256",
        "driver_main_path",
        "driver_main_sha256",
        "carrick_embed_path",
        "manifest_path",
        "manifest_sha256",
        "cargo_lock_path",
        "cargo_lock_sha256",
        "source_cargo_lock_sha256",
        "binary_path",
        "binary_size",
        "binary_mode",
        "binary_sha256",
        "cdhash",
        "macho_uuid",
        "codesign_verified",
        "entitlement_sha256",
        "has_dof_carrick",
        "rust_toolchain",
        "build",
        "lock",
        "sign",
        "host",
        "image_ref",
        "image",
    )
)

# Reuse the hardened identity and platform primitives without changing the
# established CLI-binary receipt schema.
git_output = native_abba.git_output
rustc_version = native_abba.rustc_version
verify_codesign = native_abba.verify_codesign
entitlement_digest = native_abba.entitlement_digest
macho_uuid = native_abba.macho_uuid
has_dof_carrick = native_abba.has_dof_carrick
host_receipt = native_abba.host_receipt
sha256_file = native_abba.sha256_file
_image_receipt = native_abba._image_receipt
_source_status = native_abba._source_status
_validate_directory = native_abba._validate_directory
_validate_regular_file = native_abba._validate_regular_file
_exact_probability_below = native_abba._exact_probability_below


@dataclasses.dataclass(frozen=True)
class ArmReceipt:
    path: pathlib.Path
    label: str
    role: str
    source_repo: pathlib.Path
    source_commit: str
    harness_repo: pathlib.Path
    harness_commit: str
    driver_source_sha256: str
    driver_main_path: pathlib.Path
    driver_main_sha256: str
    carrick_embed_path: pathlib.Path
    manifest_sha256: str
    cargo_lock_sha256: str
    source_cargo_lock_sha256: str
    binary_path: pathlib.Path
    binary_size: int
    binary_mode: int
    binary_sha256: str
    cdhash: str
    macho_uuid: str
    entitlement_sha256: str
    rust_toolchain: str
    image_ref: str
    image_id: str
    image_repo_digests: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ArmSpec:
    label: str
    receipt: ArmReceipt
    environment: tuple[tuple[str, str | None], ...]


class CampaignEvidenceError(RuntimeError):
    def __init__(self, message: str, artifact: dict[str, object]):
        super().__init__(message)
        self.artifact = artifact


def _driver_paths(harness_repo: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    return tuple(  # type: ignore[return-value]
        harness_repo / relative for relative in DRIVER_INPUTS
    )


def driver_source_sha256(harness_repo: pathlib.Path) -> str:
    _template, _main, digest = _driver_source_snapshot(harness_repo)
    return digest


def _driver_source_snapshot(
    harness_repo: pathlib.Path,
) -> tuple[bytes, bytes, str]:
    digest = hashlib.sha256()
    payloads: list[bytes] = []
    for relative, path in zip(DRIVER_INPUTS, _driver_paths(harness_repo), strict=True):
        payload = path.read_bytes()
        payloads.append(payload)
        name = relative.as_posix().encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return payloads[0], payloads[1], digest.hexdigest()


def _materialized_manifest(template: str, carrick_embed_path: pathlib.Path) -> str:
    marker = "@CARRICK_EMBED_PATH@"
    if template.count(marker) != 1:
        raise RuntimeError("driver manifest template must contain one embed path marker")
    rendered_path = str(carrick_embed_path).replace("\\", "\\\\").replace('"', '\\"')
    return template.replace(marker, rendered_path)


def _build_receipt(command: list[str], result: subprocess.CompletedProcess) -> dict[str, object]:
    return {
        "command": command,
        "status": result.returncode,
        "stdout": native_abba._output_text(result.stdout),
        "stderr": native_abba._output_text(result.stderr),
    }


def codesign_cdhash(binary: pathlib.Path) -> str:
    result = subprocess.run(
        ["codesign", "-dvvv", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise native_abba._command_error("embed driver CDHash inspection", result)
    lines = native_abba._output_text(result.stdout).splitlines()
    lines.extend(native_abba._output_text(result.stderr).splitlines())
    matches = [line.split("=", 1)[1].lower() for line in lines if line.startswith("CDHash=")]
    if len(matches) != 1 or CDHASH_RE.fullmatch(matches[0]) is None:
        raise RuntimeError("codesign must report exactly one valid embed driver CDHash")
    return matches[0]


def _cleanup_unpublished(destination: pathlib.Path) -> None:
    shutil.rmtree(destination, ignore_errors=True)


def prepare_arm(
    source_repo: pathlib.Path,
    destination: pathlib.Path,
    *,
    harness_repo: pathlib.Path,
    label: str,
    role: str,
    image_ref: str,
) -> dict[str, object]:
    if role not in ARM_ROLES:
        raise ValueError(f"role must be one of {sorted(ARM_ROLES)}, got {role!r}")
    if not label or not image_ref:
        raise ValueError("label and image_ref must be nonempty")

    source = source_repo.resolve(strict=True)
    harness = harness_repo.resolve(strict=True)
    _validate_directory(source, "source repository")
    _validate_directory(harness, "harness repository")
    destination = pathlib.Path(os.path.abspath(os.fspath(destination)))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o755)
    published = False
    try:
        if _source_status(source):
            raise RuntimeError("arm preparation requires a clean source repository")
        if _source_status(harness):
            raise RuntimeError("arm preparation requires a clean harness repository")
        source_commit_before = git_output(source, "rev-parse", "HEAD")
        harness_commit_before = git_output(harness, "rev-parse", "HEAD")
        template_bytes, main_bytes, source_hash = _driver_source_snapshot(harness)

        private_source = destination / "driver-src"
        (private_source / "src").mkdir(parents=True)
        private_main = private_source / "src/main.rs"
        private_main.write_bytes(main_bytes)
        private_main_sha256 = hashlib.sha256(main_bytes).hexdigest()
        carrick_embed_path = (source / "crates/carrick-embed").resolve(strict=True)
        manifest = _materialized_manifest(template_bytes.decode(), carrick_embed_path)
        manifest_path = private_source / "Cargo.toml"
        manifest_path.write_text(manifest)
        cargo_lock_path = private_source / "Cargo.lock"
        source_cargo_lock = source / "Cargo.lock"
        source_cargo_lock_sha256 = sha256_file(source_cargo_lock)
        shutil.copy2(source_cargo_lock, cargo_lock_path, follow_symlinks=False)
        lock_command = [
            "cargo",
            "generate-lockfile",
            "--offline",
            "--manifest-path",
            str(manifest_path),
        ]
        locked = subprocess.run(
            lock_command,
            cwd=private_source,
            capture_output=True,
            text=True,
            check=False,
        )
        if locked.returncode != 0:
            raise native_abba._command_error("embed driver lock derivation", locked)
        _validate_regular_file(private_main, "private embed driver main source")
        if private_main.read_bytes() != main_bytes:
            raise RuntimeError("private driver main changed before build")
        build_toolchain = rustc_version(private_source)

        target_dir = destination / "build-target"
        build_command = [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            str(manifest_path),
            "--target-dir",
            str(target_dir),
        ]
        build = subprocess.run(
            build_command,
            cwd=private_source,
            capture_output=True,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            raise native_abba._command_error("embed driver build", build)
        _validate_regular_file(private_main, "private embed driver main source")
        if private_main.read_bytes() != main_bytes:
            raise RuntimeError("private driver main changed during build")
        if rustc_version(private_source) != build_toolchain:
            raise RuntimeError("Rust toolchain changed during embed driver build")
        private_main.chmod(stat.S_IMODE(private_main.stat().st_mode) & ~0o222)
        built_binary = target_dir / "release" / DRIVER_PACKAGE
        _validate_regular_file(built_binary, "embed driver executable")

        sign_command = [
            "/bin/bash",
            "-c",
            SIGN_SCRIPT,
            "embed-driver-sign",
            str(source / "scripts/lib/post-link-sign.sh"),
            str(built_binary),
            str(source / "scripts/entitlements.plist"),
        ]
        signed = subprocess.run(
            sign_command,
            cwd=source,
            capture_output=True,
            text=True,
            check=False,
        )
        if signed.returncode != 0:
            raise native_abba._command_error("embed driver signing", signed)

        binary = destination / DRIVER_BINARY
        shutil.copy2(built_binary, binary, follow_symlinks=False)
        binary.chmod(stat.S_IMODE(binary.stat().st_mode) & ~0o222)
        metadata = _validate_regular_file(binary, "copied signed embed driver")
        verify_codesign(binary)
        recorded_cdhash = codesign_cdhash(binary)
        recorded_uuid = macho_uuid(binary)
        recorded_entitlement = entitlement_digest(binary)
        if not has_dof_carrick(binary):
            raise RuntimeError("signed embed driver is missing __dof_carrick")

        source_commit = git_output(source, "rev-parse", "HEAD")
        harness_commit = git_output(harness, "rev-parse", "HEAD")
        if source_commit != source_commit_before or _source_status(source):
            raise RuntimeError("source repository changed during arm preparation")
        if harness_commit != harness_commit_before or _source_status(harness):
            raise RuntimeError("harness repository changed during arm preparation")
        if driver_source_sha256(harness) != source_hash:
            raise RuntimeError("driver source changed during arm preparation")
        if private_main.read_bytes() != main_bytes:
            raise RuntimeError("private driver main changed after build")

        image = _image_receipt(image_ref)
        receipt = {
            "schema": ARM_SCHEMA,
            "label": label,
            "role": role,
            "source_repo": str(source),
            "source_commit": source_commit,
            "source_branch": git_output(source, "branch", "--show-current") or None,
            "source_status": [],
            "harness_repo": str(harness),
            "harness_commit": harness_commit,
            "harness_branch": git_output(harness, "branch", "--show-current") or None,
            "harness_status": [],
            "driver_source_sha256": source_hash,
            "driver_main_path": str(private_main),
            "driver_main_sha256": private_main_sha256,
            "carrick_embed_path": str(carrick_embed_path),
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256_file(manifest_path),
            "cargo_lock_path": str(cargo_lock_path),
            "cargo_lock_sha256": sha256_file(cargo_lock_path),
            "source_cargo_lock_sha256": source_cargo_lock_sha256,
            "binary_path": str(binary),
            "binary_size": metadata.st_size,
            "binary_mode": stat.S_IMODE(metadata.st_mode),
            "binary_sha256": sha256_file(binary),
            "cdhash": recorded_cdhash,
            "macho_uuid": recorded_uuid,
            "codesign_verified": True,
            "entitlement_sha256": recorded_entitlement,
            "has_dof_carrick": True,
            "rust_toolchain": build_toolchain,
            "build": _build_receipt(build_command, build),
            "lock": _build_receipt(lock_command, locked),
            "sign": _build_receipt(sign_command, signed),
            "host": host_receipt(),
            "image_ref": image_ref,
            "image": image,
        }
        receipt_path = destination / "arm.json"
        native_go_build.write_json_atomic(receipt_path, receipt, exclusive=True)
        receipt_path.chmod(0o444)
        published = True
        return receipt
    finally:
        if not published:
            _cleanup_unpublished(destination)


def _load_payload(path: pathlib.Path) -> tuple[pathlib.Path, dict[str, object]]:
    path = pathlib.Path(os.path.abspath(os.fspath(path)))
    metadata = _validate_regular_file(path, "embed arm receipt")
    if stat.S_IMODE(metadata.st_mode) != 0o444:
        raise RuntimeError(
            "embed arm receipt mode changed: "
            f"expected 0o444, got {stat.S_IMODE(metadata.st_mode):#o}"
        )
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("arm receipt must be a JSON object")
    native_abba._require_exact_fields(payload, ARM_FIELDS, "embed arm receipt")
    if payload.get("schema") != ARM_SCHEMA:
        raise ValueError(f"unsupported arm receipt schema: {payload.get('schema')!r}")
    if (
        payload["role"] not in ARM_ROLES
        or type(payload["label"]) is not str
        or not payload["label"]
    ):
        raise ValueError("embed arm receipt role or label is invalid")
    for key in ("source_branch", "harness_branch"):
        if payload[key] is not None and type(payload[key]) is not str:
            raise ValueError(f"embed arm receipt {key} must be a string or null")
    for key in ("source_commit", "harness_commit"):
        value = payload[key]
        if not isinstance(value, str) or native_abba.COMMIT_RE.fullmatch(value) is None:
            raise ValueError(f"embed arm receipt {key} is malformed")
    for key in (
        "driver_source_sha256",
        "driver_main_sha256",
        "manifest_sha256",
        "cargo_lock_sha256",
        "source_cargo_lock_sha256",
        "binary_sha256",
        "entitlement_sha256",
    ):
        value = payload[key]
        if not isinstance(value, str) or native_abba.SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"embed arm receipt {key} is malformed")
    cdhash = payload["cdhash"]
    if type(cdhash) is not str or CDHASH_RE.fullmatch(cdhash) is None:
        raise ValueError("embed arm receipt cdhash is malformed")
    if payload["source_status"] != [] or payload["harness_status"] != []:
        raise ValueError("embed arm receipt source statuses must be empty")
    if (
        payload["codesign_verified"] is not True
        or payload["has_dof_carrick"] is not True
    ):
        raise ValueError("embed arm receipt requires signed DOF-bearing driver evidence")
    for key in ("rust_toolchain", "image_ref", "macho_uuid"):
        if type(payload[key]) is not str or not payload[key]:
            raise ValueError(f"embed arm receipt {key} must be a nonempty string")

    recorded_paths: dict[str, pathlib.Path] = {}
    for key in (
        "source_repo",
        "harness_repo",
        "carrick_embed_path",
        "driver_main_path",
        "manifest_path",
        "cargo_lock_path",
        "binary_path",
    ):
        value = payload[key]
        if type(value) is not str or not value:
            raise ValueError(f"embed arm receipt {key} must be a nonempty path")
        recorded = pathlib.Path(value)
        if not recorded.is_absolute():
            raise ValueError("embed arm receipt repository paths must be absolute")
        recorded_paths[key] = recorded

    receipt_root = path.parent
    private_source = receipt_root / "driver-src"
    source = recorded_paths["source_repo"]
    expected_paths = {
        "carrick_embed_path": source / "crates/carrick-embed",
        "driver_main_path": private_source / "src/main.rs",
        "manifest_path": private_source / "Cargo.toml",
        "cargo_lock_path": private_source / "Cargo.lock",
        "binary_path": receipt_root / DRIVER_BINARY,
    }
    for key, expected in expected_paths.items():
        if recorded_paths[key] != expected:
            raise ValueError(
                f"embed arm receipt {key} must be package scoped at {expected}"
            )

    binary_size = payload["binary_size"]
    binary_mode = payload["binary_mode"]
    if (
        type(binary_size) is not int
        or binary_size < 0
        or type(binary_mode) is not int
        or not 0 <= binary_mode <= 0o7777
        or binary_mode & 0o222
        or not binary_mode & 0o111
    ):
        raise ValueError("embed arm receipt binary metadata is invalid")

    for key in ("build", "lock", "sign"):
        row = payload[key]
        if not isinstance(row, dict):
            raise ValueError(f"embed arm receipt {key} evidence is invalid")
        native_abba._require_exact_fields(
            row, COMMAND_RECEIPT_FIELDS, f"embed arm receipt {key}"
        )
        if type(row["command"]) is not list or not all(
            type(argument) is str for argument in row["command"]
        ):
            raise ValueError(f"embed arm receipt {key} command is invalid")
        if type(row["status"]) is not int or row["status"] != 0:
            raise ValueError(f"embed arm receipt {key} status is invalid")
        if type(row["stdout"]) is not str or type(row["stderr"]) is not str:
            raise ValueError(f"embed arm receipt {key} output is invalid")

    manifest_path = recorded_paths["manifest_path"]
    target_dir = receipt_root / "build-target"
    expected_lock_command = [
        "cargo",
        "generate-lockfile",
        "--offline",
        "--manifest-path",
        str(manifest_path),
    ]
    expected_build_command = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        str(manifest_path),
        "--target-dir",
        str(target_dir),
    ]
    expected_sign_command = [
        "/bin/bash",
        "-c",
        SIGN_SCRIPT,
        "embed-driver-sign",
        str(source / "scripts/lib/post-link-sign.sh"),
        str(target_dir / "release" / DRIVER_PACKAGE),
        str(source / "scripts/entitlements.plist"),
    ]
    if payload["lock"]["command"] != expected_lock_command:
        raise ValueError("embed arm receipt lock command is not exact")
    if payload["build"]["command"] != expected_build_command:
        raise ValueError("embed arm receipt build command is not exact")
    if payload["sign"]["command"] != expected_sign_command:
        raise ValueError("embed arm receipt sign command is not exact")

    host = payload["host"]
    image = payload["image"]
    if not isinstance(host, dict) or not isinstance(image, dict):
        raise ValueError("embed arm receipt host and image must be objects")
    native_abba._require_exact_fields(host, native_abba.HOST_FIELDS, "host")
    native_abba._require_exact_fields(image, native_abba.IMAGE_FIELDS, "image")
    if any(type(host[field]) is not str or not host[field] for field in host):
        raise ValueError("embed arm receipt host fields must be nonempty strings")
    if host["machine"] != "arm64" or image["architecture"] != "arm64":
        raise ValueError("embed arm receipt requires arm64 host and image")
    if (
        type(image["id"]) is not str
        or native_abba.DIGEST_RE.fullmatch(image["id"]) is None
    ):
        raise ValueError("embed arm receipt image ID must be an immutable digest")
    digests = image["repo_digests"]
    if (
        not isinstance(digests, list)
        or not digests
        or not all(
            type(digest) is str
            and native_abba.REPO_DIGEST_RE.fullmatch(digest) is not None
            for digest in digests
        )
        or digests != sorted(set(digests))
    ):
        raise ValueError("embed arm receipt image RepoDigests are invalid")
    return path, payload


def _receipt_from_payload(path: pathlib.Path, payload: dict[str, object]) -> ArmReceipt:
    image = payload.get("image")
    if not isinstance(image, dict):
        raise ValueError("arm receipt image must be an object")
    return ArmReceipt(
        path=path,
        label=str(payload["label"]),
        role=str(payload["role"]),
        source_repo=pathlib.Path(str(payload["source_repo"])),
        source_commit=str(payload["source_commit"]),
        harness_repo=pathlib.Path(str(payload["harness_repo"])),
        harness_commit=str(payload["harness_commit"]),
        driver_source_sha256=str(payload["driver_source_sha256"]),
        driver_main_path=pathlib.Path(str(payload["driver_main_path"])),
        driver_main_sha256=str(payload["driver_main_sha256"]),
        carrick_embed_path=pathlib.Path(str(payload["carrick_embed_path"])),
        manifest_sha256=str(payload["manifest_sha256"]),
        cargo_lock_sha256=str(payload["cargo_lock_sha256"]),
        source_cargo_lock_sha256=str(payload["source_cargo_lock_sha256"]),
        binary_path=pathlib.Path(str(payload["binary_path"])),
        binary_size=int(payload["binary_size"]),
        binary_mode=int(payload["binary_mode"]),
        binary_sha256=str(payload["binary_sha256"]),
        cdhash=str(payload["cdhash"]),
        macho_uuid=str(payload["macho_uuid"]),
        entitlement_sha256=str(payload["entitlement_sha256"]),
        rust_toolchain=str(payload["rust_toolchain"]),
        image_ref=str(payload["image_ref"]),
        image_id=str(image["id"]),
        image_repo_digests=tuple(image["repo_digests"]),
    )


def load_recorded_arm(path: pathlib.Path) -> ArmReceipt:
    receipt_path, payload = _load_payload(path)
    return _receipt_from_payload(receipt_path, payload)


def load_and_verify_arm(path: pathlib.Path) -> ArmReceipt:
    receipt_path, payload = _load_payload(path)
    receipt = _receipt_from_payload(receipt_path, payload)
    source = receipt.source_repo.resolve(strict=True)
    harness = receipt.harness_repo.resolve(strict=True)
    if _source_status(source):
        raise RuntimeError("arm receipt source repository is no longer clean")
    if git_output(source, "rev-parse", "HEAD") != receipt.source_commit:
        raise RuntimeError("source commit identity changed")
    if _source_status(harness):
        raise RuntimeError("arm receipt harness repository is no longer clean")
    if git_output(harness, "rev-parse", "HEAD") != receipt.harness_commit:
        raise RuntimeError("harness commit identity changed")
    template_bytes, expected_main, current_driver_hash = _driver_source_snapshot(
        harness
    )
    if current_driver_hash != receipt.driver_source_sha256:
        raise RuntimeError("driver source identity changed")
    if receipt.driver_main_path != receipt_path.parent / "driver-src/src/main.rs":
        raise RuntimeError("private driver main path changed")
    _validate_regular_file(receipt.driver_main_path, "private embed driver main source")
    if receipt.driver_main_path.read_bytes() != expected_main:
        raise RuntimeError("private driver main bytes changed")
    if sha256_file(receipt.driver_main_path) != receipt.driver_main_sha256:
        raise RuntimeError("private driver main sha256 changed")
    if receipt.carrick_embed_path != (source / "crates/carrick-embed").resolve():
        raise RuntimeError("carrick-embed dependency path identity changed")

    manifest_path = pathlib.Path(str(payload["manifest_path"]))
    expected_manifest = _materialized_manifest(
        template_bytes.decode(), receipt.carrick_embed_path
    ).encode()
    if manifest_path.read_bytes() != expected_manifest:
        raise RuntimeError("materialized driver manifest changed")
    if sha256_file(manifest_path) != receipt.manifest_sha256:
        raise RuntimeError("manifest sha256 changed")
    cargo_lock_path = pathlib.Path(str(payload["cargo_lock_path"]))
    if cargo_lock_path != receipt_path.parent / "driver-src/Cargo.lock":
        raise RuntimeError("materialized Cargo.lock path changed")
    if sha256_file(source / "Cargo.lock") != receipt.source_cargo_lock_sha256:
        raise RuntimeError("source Cargo.lock identity changed")
    if sha256_file(cargo_lock_path) != receipt.cargo_lock_sha256:
        raise RuntimeError("materialized Cargo.lock sha256 changed")
    if receipt.binary_path != receipt_path.parent / DRIVER_BINARY:
        raise RuntimeError("arm binary path is not package scoped")
    metadata = _validate_regular_file(receipt.binary_path, "signed embed driver")
    if metadata.st_size != receipt.binary_size:
        raise RuntimeError("arm binary size changed")
    if stat.S_IMODE(metadata.st_mode) != receipt.binary_mode:
        raise RuntimeError("arm binary mode changed")
    if sha256_file(receipt.binary_path) != receipt.binary_sha256:
        raise RuntimeError("binary sha256 changed")
    verify_codesign(receipt.binary_path)
    if codesign_cdhash(receipt.binary_path) != receipt.cdhash:
        raise RuntimeError("binary CDHash changed")
    if macho_uuid(receipt.binary_path) != receipt.macho_uuid:
        raise RuntimeError("binary Mach-O UUID changed")
    if entitlement_digest(receipt.binary_path) != receipt.entitlement_sha256:
        raise RuntimeError("binary entitlement digest changed")
    if not has_dof_carrick(receipt.binary_path):
        raise RuntimeError("binary DOF section changed or is missing")
    if payload.get("codesign_verified") is not True or payload.get("has_dof_carrick") is not True:
        raise RuntimeError("arm receipt does not attest a signed DOF-bearing driver")
    if host_receipt() != payload.get("host"):
        raise RuntimeError("arm receipt host identity changed")
    if _image_receipt(receipt.image_ref) != payload.get("image"):
        raise RuntimeError("arm receipt image identity changed")
    if rustc_version(receipt_path.parent / "driver-src") != receipt.rust_toolchain:
        raise RuntimeError("embed driver Rust toolchain identity changed")
    return receipt


def _validated_environment(arm: ArmSpec) -> dict[str, str | None]:
    keys = tuple(key for key, _value in arm.environment)
    if keys != native_go_build.PERFORMANCE_CONTROL_KEYS or len(set(keys)) != len(keys):
        raise ValueError(
            f"{arm.label} environment must contain PERFORMANCE_CONTROL_KEYS exactly once"
        )
    environment = dict(arm.environment)
    if any(value is not None and type(value) is not str for value in environment.values()):
        raise ValueError(f"{arm.label} environment values must be strings or null")
    perturbing = sorted(
        key
        for key in native_abba.TIMING_PERTURBING_CONTROL_KEYS
        if environment[key] is not None
    )
    if perturbing:
        raise ValueError(f"{arm.label} environment contains timing perturbations: {perturbing}")
    return environment


def validate_arm_mode(control: ArmSpec, candidate: ArmSpec) -> str:
    control_environment = _validated_environment(control)
    candidate_environment = _validated_environment(candidate)
    if control_environment != candidate_environment:
        raise ValueError("binary and environment dimensions cannot both change")
    control_receipt = control.receipt
    candidate_receipt = candidate.receipt
    if hasattr(control_receipt, "role"):
        if control_receipt.role != "control" or candidate_receipt.role != "candidate":
            raise ValueError("ABBA arms require control and candidate roles")
        if control_receipt.source_repo.resolve() == candidate_receipt.source_repo.resolve():
            raise ValueError("ABBA arms require distinct source worktrees")
        if control_receipt.binary_path.resolve() == candidate_receipt.binary_path.resolve():
            raise ValueError("ABBA arms require distinct driver artifacts")
        if (
            control_receipt.harness_repo.resolve()
            != candidate_receipt.harness_repo.resolve()
        ):
            raise ValueError("ABBA arms must use one exact harness path")
        if (
            control_receipt.harness_commit != candidate_receipt.harness_commit
            or control_receipt.driver_source_sha256
            != candidate_receipt.driver_source_sha256
        ):
            raise ValueError("ABBA arms must use one exact harness and driver source")
        if control_receipt.rust_toolchain != candidate_receipt.rust_toolchain:
            raise ValueError("ABBA arms must use one exact Rust toolchain")
    return "two-binary-implicit-embed"


def _campaign_harness_identity(
    harness_repo: pathlib.Path,
    control_receipt: ArmReceipt,
    candidate_receipt: ArmReceipt,
) -> dict[str, object]:
    harness = harness_repo.resolve(strict=True)
    _validate_directory(harness, "campaign harness repository")
    expected = control_receipt.harness_repo.resolve()
    if candidate_receipt.harness_repo.resolve() != expected or harness != expected:
        raise RuntimeError("campaign harness path does not match both arm receipts")
    status = _source_status(harness)
    if status:
        raise RuntimeError("campaign harness repository must remain clean")
    commit = git_output(harness, "rev-parse", "HEAD")
    if (
        commit != control_receipt.harness_commit
        or commit != candidate_receipt.harness_commit
    ):
        raise RuntimeError("campaign harness commit identity changed")
    source_hash = driver_source_sha256(harness)
    if (
        source_hash != control_receipt.driver_source_sha256
        or source_hash != candidate_receipt.driver_source_sha256
    ):
        raise RuntimeError("campaign driver source identity changed")
    return {
        "harness_repo": str(harness),
        "harness_commit": commit,
        "driver_source_sha256": source_hash,
        "harness_status": status,
    }


def build_driver_command(
    binary: pathlib.Path,
    run_id: str,
    *,
    image: str,
) -> list[str]:
    if not run_id or not image:
        raise ValueError("run_id and image must be nonempty")
    command = [
        str(binary),
        "--image",
        image,
        "--run-id",
        run_id,
        "--workdir",
        "/tmp",
        "/bin/sh",
        "-c",
        native_go_build.guest_script(),
    ]
    if "run" in command:
        raise AssertionError("implicit embed driver argv must not contain the CLI run subcommand")
    return command


def _execution_environment(
    base: dict[str, str],
    normalized: dict[str, str | None],
    *,
    run_id: str,
    image: str,
) -> tuple[dict[str, str], dict[str, object] | None]:
    environment = dict(base)
    for key in native_go_build.PERFORMANCE_CONTROL_KEYS:
        environment.pop(key, None)
    environment.update(
        {key: value for key, value in normalized.items() if value is not None}
    )
    environment["CARRICK_RUN_ID"] = run_id
    environment.pop(native_go_build.INSECURE_REGISTRIES_ENV, None)
    transport = native_abba._registry_transport_for_image(image)
    transport_evidence = native_go_build.registry_transport_evidence(transport)
    if transport_evidence is not None and transport_evidence["forward_env"] is not None:
        key, value = str(transport_evidence["forward_env"]).split("=", 1)
        environment[key] = value
    return environment, transport_evidence


def _scoped_cleanup(harness_repo: pathlib.Path, run_id: str) -> dict[str, object]:
    script = harness_repo / "scripts/sudo/kill.sh"
    attempts: list[dict[str, object]] = []
    result = None
    for command in (["sudo", "-n", str(script), run_id], [str(script), run_id]):
        result = subprocess.run(
            command,
            cwd=harness_repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        attempts.append(_build_receipt(command, result))
        if result.returncode == 0:
            break
    assert result is not None
    remaining = None
    for line in native_abba._output_text(result.stdout).splitlines():
        if line.startswith("remaining carrick procs") and "=" in line:
            value = line.rsplit("=", 1)[1].strip()
            if value.isdigit():
                remaining = int(value)
    status = 0 if result.returncode == 0 and remaining == 0 else 1
    return {
        "status": status,
        "remaining_processes": remaining,
        "attempts": attempts,
    }


def _sample_provenance(
    binary: pathlib.Path,
    harness_repo: pathlib.Path,
    *,
    image: str,
    controlled_environment: dict[str, str | None],
    registry_transport: dict[str, object] | None,
    receipt: ArmReceipt | None = None,
    campaign_receipts: tuple[ArmReceipt, ArmReceipt] | None = None,
    owned_binaries: tuple[pathlib.Path, pathlib.Path] | None = None,
) -> dict[str, object]:
    harness_identity = None
    arms_authenticated = False
    owned = tuple(path.resolve() for path in (owned_binaries or ()))
    if receipt is not None:
        if campaign_receipts is None or len(campaign_receipts) != 2:
            raise RuntimeError("sample requires both campaign arm receipts")
        control_receipt, candidate_receipt = campaign_receipts
        verified = tuple(
            load_and_verify_arm(campaign_receipt.path)
            for campaign_receipt in campaign_receipts
        )
        if verified != campaign_receipts:
            raise RuntimeError("sample campaign arm receipt drifted")
        harness_identity = _campaign_harness_identity(
            harness_repo, control_receipt, candidate_receipt
        )
        expected_owned = tuple(
            campaign_receipt.binary_path.resolve()
            for campaign_receipt in campaign_receipts
        )
        if owned != expected_owned or len(set(owned)) != 2:
            raise RuntimeError("sample owned driver allowlist does not match both arms")
        if receipt.path not in tuple(item.path for item in campaign_receipts):
            raise RuntimeError("sample arm is not one of the campaign receipts")
        if binary.resolve() != receipt.binary_path.resolve():
            raise RuntimeError("sample binary does not match its arm receipt")
        arms_authenticated = True
    busy = native_go_build.busy_host_reasons()
    foreign = native_go_build.foreign_workload_census(
        known_receipt_binaries=owned
    )
    docker = native_go_build.running_docker_oracles()
    return {
        "authenticated": arms_authenticated,
        "arms_authenticated": arms_authenticated,
        "arm_receipts": [
            {
                "role": campaign_receipt.role,
                "receipt_path": str(campaign_receipt.path.resolve()),
                "source_commit": campaign_receipt.source_commit,
                "binary_path": str(campaign_receipt.binary_path.resolve()),
                "binary_sha256": campaign_receipt.binary_sha256,
                "rust_toolchain": campaign_receipt.rust_toolchain,
            }
            for campaign_receipt in (campaign_receipts or ())
        ],
        "source_commit": receipt.source_commit if receipt is not None else None,
        "harness": harness_identity,
        "binary_path": str(binary.resolve()),
        "binary_sha256": sha256_file(binary),
        "owned_driver_binaries": [str(path) for path in owned],
        "image_ref": image,
        "image": _image_receipt(image),
        "registry_transport": registry_transport,
        "controlled_environment": controlled_environment,
        "busy_host_reasons": busy,
        "foreign_processes": foreign,
        "docker_oracles": docker,
        "workload_isolation_clean": not busy and not foreign and not docker,
    }


def run_sample(
    binary: pathlib.Path,
    harness_repo: pathlib.Path,
    index: int,
    timeout_seconds: int,
    *,
    environment_overlay: dict[str, str | None],
    image: str,
    current_run_id: str,
    receipt: ArmReceipt | None = None,
    campaign_receipts: tuple[ArmReceipt, ArmReceipt] | None = None,
    owned_binaries: tuple[pathlib.Path, pathlib.Path] | None = None,
) -> dict[str, object]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    normalized = native_go_build.normalized_overlay(environment_overlay)
    native_go_build.reject_ambient_carrick(os.environ, normalized)
    command = build_driver_command(binary, current_run_id, image=image)
    environment, registry_transport = _execution_environment(
        dict(os.environ),
        normalized,
        run_id=current_run_id,
        image=image,
    )
    pre = _sample_provenance(
        binary,
        harness_repo,
        image=image,
        controlled_environment=normalized,
        registry_transport=registry_transport,
        receipt=receipt,
        campaign_receipts=campaign_receipts,
        owned_binaries=owned_binaries,
    )

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    result = None
    timeout = None
    execution_error = None
    try:
        result = subprocess.run(
            command,
            cwd=harness_repo,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        timeout = error
    except Exception as error:  # pragma: no cover - retained in evidence below
        execution_error = error
    finally:
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cleanup = _scoped_cleanup(harness_repo, current_run_id)

    stdout = native_go_build.combined_output(
        timeout.stdout if timeout is not None else getattr(result, "stdout", None), None
    )
    stderr = native_go_build.combined_output(
        None, timeout.stderr if timeout is not None else getattr(result, "stderr", None)
    )
    workload_ns = None
    workload_error = None
    try:
        workload_ns = native_go_build.workload_ns_from_stdout(stdout)
    except ValueError as error:
        workload_error = str(error)
    cpu_user_s = round(after.ru_utime - before.ru_utime, 6)
    cpu_sys_s = round(after.ru_stime - before.ru_stime, 6)
    return_code = getattr(result, "returncode", None)
    build_ok = timeout is None and stdout.splitlines().count("BUILD_OK") == 1
    post = _sample_provenance(
        binary,
        harness_repo,
        image=image,
        controlled_environment=normalized,
        registry_transport=registry_transport,
        receipt=receipt,
        campaign_receipts=campaign_receipts,
        owned_binaries=owned_binaries,
    )
    sample = {
        "engine": "implicit-embed",
        "index": index,
        "run_id": current_run_id,
        "binary_path": str(binary.resolve()),
        "binary_sha256": sha256_file(binary),
        "elapsed_ms": elapsed_ms,
        "cpu_user_s": cpu_user_s,
        "cpu_sys_s": cpu_sys_s,
        "cpu_s": round(cpu_user_s + cpu_sys_s, 6),
        "workload_ns": workload_ns,
        "workload_ms": workload_ns // 1_000_000 if workload_ns is not None else None,
        "return_code": return_code,
        "timed_out": timeout is not None,
        "build_ok": build_ok,
        "command": {"argv": command, "status": return_code, "build_ok": build_ok},
        "controlled_environment": normalized,
        "registry_transport": registry_transport,
        "provenance": {"pre": pre, "post": post},
        "cleanup": cleanup,
        "stdout": stdout,
        "stderr": stderr,
    }
    if timeout is not None:
        raise native_go_build.SampleEvidenceError("implicit embed sample timed out", sample)
    if execution_error is not None:
        raise native_go_build.SampleEvidenceError(
            f"implicit embed sample launch failed: {execution_error}", sample
        )
    if return_code != 0 or not build_ok or workload_error is not None:
        raise native_go_build.SampleEvidenceError(
            f"implicit embed workload failed: rc={return_code} workload={workload_error}",
            sample,
        )
    if cleanup.get("status") != 0 or cleanup.get("remaining_processes") != 0:
        raise native_go_build.SampleEvidenceError("implicit embed scoped cleanup failed", sample)
    if not pre.get("workload_isolation_clean") or not post.get(
        "workload_isolation_clean"
    ):
        raise native_go_build.SampleEvidenceError(
            "implicit embed workload contamination observed", sample
        )
    if pre != post:
        raise native_go_build.SampleEvidenceError("implicit embed provenance drifted", sample)
    return sample


def _numeric(value: object, description: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        raise ValueError(f"{description} must be finite and numeric")
    return float(value)


def _regression_statistics(ratios: Sequence[float]) -> dict[str, object]:
    numeric = [_numeric(value, "quad ratio") for value in ratios]
    if len(numeric) < 2 or len(numeric) > 127 or any(value <= 0.0 for value in numeric):
        raise ValueError("regression statistics require 2..127 positive ratios")
    wins = sum(value > THRESHOLD for value in numeric)
    ties = sum(value == THRESHOLD for value in numeric)
    trials = len(numeric) - ties
    probability = paired_stats.exact_one_sided_sign_probability(wins, trials)
    inverse_bootstrap = paired_stats.paired_bootstrap([1.0 / value for value in numeric])
    return {
        "sign_test": {
            "trials": trials,
            "wins_above_one": wins,
            "ties": ties,
            "probability": paired_stats.exact_probability_json(probability),
        },
        "bootstrap_one_sided_lower": 1.0 / inverse_bootstrap.one_sided_upper,
    }


def _summarize_quads(quads: Sequence[native_abba.Quad]) -> dict[str, object]:
    summary = native_abba.summarize_quads(quads)
    for metric in summary["metrics"].values():
        ratios = [float(row["ratio"]) for row in metric["quads"]]
        regression = _regression_statistics(ratios)
        metric["regression_sign_test"] = regression["sign_test"]
        metric["bootstrap"]["one_sided_lower"] = regression[
            "bootstrap_one_sided_lower"
        ]
    return summary


def _no_regression_decision(
    statistics_payload: dict[str, object],
    *,
    complete: bool,
    artifacts_authenticated: bool,
    preflights_passed: bool,
    evidence_class: str = "official",
) -> dict[str, object]:
    if any(
        type(value) is not bool
        for value in (complete, artifacts_authenticated, preflights_passed)
    ):
        raise ValueError("decision eligibility inputs must be booleans")
    if evidence_class not in {"official", "directional-pilot"}:
        raise ValueError(f"invalid evidence class: {evidence_class!r}")
    quad_count = statistics_payload.get("quad_count")
    if type(quad_count) is not int or quad_count < 0:
        raise ValueError("quad_count must be a nonnegative integer")
    if statistics_payload.get("primary_metric") != "cpu_s":
        raise ValueError("statistics primary_metric must be cpu_s")
    metrics = statistics_payload.get("metrics")
    if not isinstance(metrics, dict) or "cpu_s" not in metrics:
        raise ValueError("statistics must contain the cpu_s primary metric")
    primary = metrics["cpu_s"]
    if not isinstance(primary, dict):
        raise ValueError("cpu_s metric must be an object")
    primary_median = _numeric(primary.get("median_quad_ratio"), "cpu_s median")
    bootstrap = primary.get("bootstrap")
    sign_test = primary.get("regression_sign_test")
    if not isinstance(bootstrap, dict) or not isinstance(sign_test, dict):
        raise ValueError("cpu_s bootstrap and regression_sign_test must be objects")
    primary_lower = _numeric(bootstrap.get("one_sided_lower"), "cpu_s lower bound")
    probability = sign_test.get("probability")
    if not isinstance(probability, dict):
        raise ValueError("cpu_s sign probability must be an object")
    numerator = probability.get("numerator")
    denominator = probability.get("denominator")
    probability_below = _exact_probability_below(
        probability, numerator=1, denominator=20
    )
    primary_supported = (
        primary_median > THRESHOLD
        and primary_lower > THRESHOLD
        and probability_below
    )
    primary_record = {
        "median_quad_ratio": primary_median,
        "bootstrap_one_sided_lower": primary_lower,
        "sign_probability_numerator": numerator,
        "sign_probability_denominator": denominator,
        "median_above_threshold": primary_median > THRESHOLD,
        "lower_bound_above_threshold": primary_lower > THRESHOLD,
        "sign_probability_below_0_05": probability_below,
        "supported_regression": primary_supported,
    }

    secondary_records: dict[str, object] = {}
    medians = [primary_median]
    secondary_supported = False
    for name, metric in metrics.items():
        if name == "cpu_s":
            continue
        if not isinstance(metric, dict) or not isinstance(metric.get("bootstrap"), dict):
            raise ValueError(f"secondary metric {name} is malformed")
        median = _numeric(metric.get("median_quad_ratio"), f"{name} median")
        lower = _numeric(metric["bootstrap"].get("two_sided_lower"), f"{name} lower bound")
        supported = median > THRESHOLD and lower > THRESHOLD
        medians.append(median)
        secondary_supported = secondary_supported or supported
        secondary_records[str(name)] = {
            "median_quad_ratio": median,
            "bootstrap_two_sided_lower": lower,
            "median_above_threshold": median > THRESHOLD,
            "lower_bound_above_threshold": lower > THRESHOLD,
            "supported_regression": supported,
        }

    eligibility_inputs = {
        "complete": complete,
        "quad_count": quad_count,
        "minimum_quads": MINIMUM_QUADS,
        "evidence_class": evidence_class,
        "artifacts_authenticated": artifacts_authenticated,
        "preflights_passed": preflights_passed,
    }
    eligible = (
        evidence_class == "official"
        and complete
        and quad_count >= MINIMUM_QUADS
        and artifacts_authenticated
        and preflights_passed
    )
    supported_fail = eligible and (primary_supported or secondary_supported)
    no_regression_pass = eligible and all(value <= THRESHOLD for value in medians)
    status = (
        "directional"
        if evidence_class == "directional-pilot" and complete
        else "fail"
        if supported_fail
        else "pass"
        if no_regression_pass
        else "unresolved"
    )
    return {
        "status": status,
        "threshold": THRESHOLD,
        "eligible": eligible,
        "no_regression_pass": no_regression_pass,
        "supported_regression_fail": supported_fail,
        "eligibility_inputs": eligibility_inputs,
        "primary": primary_record,
        "secondary": secondary_records,
    }


def _record_decision(
    artifact: dict[str, object], decision: dict[str, object]
) -> None:
    status = decision.get("status")
    if status not in {"pass", "fail", "unresolved", "directional"}:
        raise ValueError(f"invalid no-regression decision status: {status!r}")
    evidence_class = artifact.get("evidence_class", "official")
    if (status == "directional") != (evidence_class == "directional-pilot"):
        raise ValueError(
            "directional decisions require directional-pilot evidence and vice versa"
        )
    artifact["decision"] = decision
    artifact["accepted"] = (
        artifact.get("complete") is True
        and evidence_class == "official"
        and status == "pass"
    )


def _decision_exit_code(artifact: dict[str, object]) -> int:
    decision = artifact.get("decision")
    if not isinstance(decision, dict):
        return 1
    if artifact.get("complete") is not True:
        return 1
    status = decision.get("status")
    if status == "pass" and artifact.get("accepted") is True:
        return 0
    if status == "fail":
        return 2
    if status == "unresolved":
        return 3
    if (
        status == "directional"
        and artifact.get("evidence_class") == "directional-pilot"
        and artifact.get("accepted") is False
    ):
        return 0
    return 1


def _samples_authenticated(
    samples: Sequence[dict[str, object]],
    *,
    harness_identity: dict[str, object],
    owned_binaries: tuple[pathlib.Path, pathlib.Path],
) -> bool:
    expected_owned = [str(path.resolve()) for path in owned_binaries]
    if not samples:
        return False
    for sample in samples:
        provenance = sample.get("provenance")
        if not isinstance(provenance, dict):
            return False
        for phase in ("pre", "post"):
            snapshot = provenance.get(phase)
            if (
                not isinstance(snapshot, dict)
                or snapshot.get("authenticated") is not True
                or snapshot.get("arms_authenticated") is not True
                or snapshot.get("harness") != harness_identity
                or snapshot.get("owned_driver_binaries") != expected_owned
                or snapshot.get("workload_isolation_clean") is not True
            ):
                return False
    return True


def _receipt_manifest(arm: ArmSpec) -> dict[str, object]:
    receipt = arm.receipt
    return {
        "label": arm.label,
        "receipt_path": str(receipt.path.resolve()),
        "source_repo": str(receipt.source_repo.resolve()),
        "source_commit": receipt.source_commit,
        "harness_repo": str(receipt.harness_repo.resolve()),
        "harness_commit": receipt.harness_commit,
        "driver_source_sha256": receipt.driver_source_sha256,
        "driver_main_path": str(receipt.driver_main_path.resolve()),
        "driver_main_sha256": receipt.driver_main_sha256,
        "rust_toolchain": receipt.rust_toolchain,
        "binary_path": str(receipt.binary_path.resolve()),
        "binary_sha256": receipt.binary_sha256,
        "cdhash": receipt.cdhash,
        "macho_uuid": receipt.macho_uuid,
        "entitlement_sha256": receipt.entitlement_sha256,
        "has_dof_carrick": True,
        "environment": dict(arm.environment),
    }


def _immutable_execution_ref(
    control_receipt: ArmReceipt,
    candidate_receipt: ArmReceipt,
    image_ref: str,
) -> str:
    if (
        control_receipt.image_ref != image_ref
        or candidate_receipt.image_ref != image_ref
    ):
        raise RuntimeError("campaign image does not match both receipts")
    control_image = {
        "architecture": "arm64",
        "id": control_receipt.image_id,
        "repo_digests": list(control_receipt.image_repo_digests),
    }
    candidate_image = {
        "architecture": "arm64",
        "id": candidate_receipt.image_id,
        "repo_digests": list(candidate_receipt.image_repo_digests),
    }
    if control_image != candidate_image:
        raise RuntimeError("arm image identities differ")
    if _image_receipt(image_ref) != control_image:
        raise RuntimeError("campaign image identity drifted")
    control_ref = native_abba._executed_image_ref(image_ref, control_receipt)
    candidate_ref = native_abba._executed_image_ref(image_ref, candidate_receipt)
    if control_ref != candidate_ref:
        raise RuntimeError("arm immutable execution references differ")
    return control_ref


def _campaign_preflight(
    control: ArmSpec,
    candidate: ArmSpec,
    *,
    harness_repo: pathlib.Path,
    image_ref: str,
    allow_battery: bool,
) -> dict[str, object]:
    if load_and_verify_arm(control.receipt.path) != control.receipt:
        raise RuntimeError("control arm drifted")
    if load_and_verify_arm(candidate.receipt.path) != candidate.receipt:
        raise RuntimeError("candidate arm drifted")
    harness_identity = _campaign_harness_identity(
        harness_repo, control.receipt, candidate.receipt
    )
    executed_image_ref = _immutable_execution_ref(
        control.receipt,
        candidate.receipt,
        image_ref,
    )
    current_image = _image_receipt(image_ref)
    native_go_build.reject_ambient_carrick(os.environ, {})
    power = native_abba._darwin_power_preflight(allow_battery=allow_battery)
    busy = native_go_build.busy_host_reasons()
    if busy:
        raise RuntimeError("host is not idle enough for an official campaign")
    known = (control.receipt.binary_path, candidate.receipt.binary_path)
    foreign = native_go_build.foreign_workload_census(known_receipt_binaries=known)
    docker = native_go_build.running_docker_oracles()
    if foreign or docker:
        raise RuntimeError("foreign workload or Docker oracle is active")
    return {
        "status": "passed",
        "source_artifacts_authenticated": True,
        "harness": harness_identity,
        "performance_controls_validated": True,
        "power": power,
        "busy_host_reasons": busy,
        "foreign_processes": foreign,
        "docker_oracles": docker,
        "owned_driver_binaries": [str(path.resolve()) for path in known],
        "image": current_image,
        "image_ref": image_ref,
        "executed_image_ref": executed_image_ref,
    }


def _validate_campaign_quads(quads: int, *, pilot: bool) -> str:
    if type(pilot) is not bool:
        raise ValueError("pilot selection must be boolean")
    if type(quads) is int:
        if pilot and 1 <= quads < MINIMUM_QUADS:
            return "directional-pilot"
        if not pilot and MINIMUM_QUADS <= quads <= 127:
            return "official"
    mode = "pilot" if pilot else "official"
    expected = "1 through 7" if pilot else "8 through 127"
    raise ValueError(f"{mode} campaigns require {expected} quads")


def run_campaign(
    harness_repo: pathlib.Path,
    control: ArmSpec,
    candidate: ArmSpec,
    output: pathlib.Path,
    *,
    quads: int = MINIMUM_QUADS,
    cooldown_seconds: float = 2.0,
    timeout_seconds: int = 900,
    image_ref: str = native_go_build.DEFAULT_IMAGE,
    allow_battery: bool = False,
    pilot: bool = False,
) -> dict[str, object]:
    evidence_class = _validate_campaign_quads(quads, pilot=pilot)
    if timeout_seconds <= 0 or cooldown_seconds < 0:
        raise ValueError("timeout must be positive and cooldown nonnegative")
    mode = validate_arm_mode(control, candidate)
    harness = pathlib.Path(os.path.abspath(os.fspath(harness_repo)))
    campaign_receipts = (control.receipt, candidate.receipt)
    owned_binaries = (
        control.receipt.binary_path.resolve(),
        candidate.receipt.binary_path.resolve(),
    )
    campaign_id = f"{os.getpid()}-{uuid.uuid4().hex}"
    artifact: dict[str, object] = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": campaign_id,
        "evidence_class": evidence_class,
        "complete": False,
        "accepted": False,
        "mode": mode,
        "identity": {
            "harness_repo": str(harness),
            "harness_commit": control.receipt.harness_commit,
            "driver_source_sha256": control.receipt.driver_source_sha256,
            "schedule": "excluded-a-b-then-a1-b1-b2-a2-v1",
            "quads": quads,
            "image_ref": image_ref,
            "executed_image_ref": None,
        },
        "control": _receipt_manifest(control),
        "candidate": _receipt_manifest(candidate),
        "preflights": [],
        "samples": [],
        "statistics": None,
        "decision": {"status": "unresolved", "eligible": False},
        "failure": None,
    }
    native_go_build.write_json_atomic(output, artifact, exclusive=True)
    try:
        harness_identity = _campaign_harness_identity(
            harness, control.receipt, candidate.receipt
        )
        artifact["identity"].update(harness_identity)
        native_go_build.write_json_atomic(output, artifact)
        executed_image_ref = None
        for sample_index, position in enumerate(native_abba._campaign_positions(quads), start=1):
            if sample_index == 1 or position["position"] == "a1":
                preflight = _campaign_preflight(
                    control,
                    candidate,
                    harness_repo=harness,
                    image_ref=image_ref,
                    allow_battery=allow_battery,
                )
                if executed_image_ref is None:
                    executed_image_ref = str(preflight["executed_image_ref"])
                    artifact["identity"]["executed_image_ref"] = executed_image_ref
                elif preflight["executed_image_ref"] != executed_image_ref:
                    raise RuntimeError("immutable execution image drifted before quad")
                artifact["preflights"].append(preflight)
                native_go_build.write_json_atomic(output, artifact)
            assert executed_image_ref is not None
            arm = control if position["arm"] == "A" else candidate
            run_id = f"embed-go-build-abba-{campaign_id}-{position['phase']}"
            try:
                sample = run_sample(
                    arm.receipt.binary_path,
                    harness,
                    sample_index,
                    timeout_seconds,
                    environment_overlay=dict(arm.environment),
                    image=executed_image_ref,
                    current_run_id=run_id,
                    receipt=arm.receipt,
                    campaign_receipts=campaign_receipts,
                    owned_binaries=owned_binaries,
                )
            except native_go_build.SampleEvidenceError as error:
                error.sample.update(position)
                artifact["samples"].append(error.sample)
                native_go_build.write_json_atomic(output, artifact)
                raise
            sample.update(position)
            artifact["samples"].append(sample)
            native_go_build.write_json_atomic(output, artifact)
            time.sleep(float(cooldown_seconds))

        by_position = {
            (int(sample["quad_index"]), str(sample["position"])): sample
            for sample in artifact["samples"]
            if sample["quad_index"] is not None
        }
        complete_quads = [
            native_abba.Quad(
                index=index,
                a1=by_position[(index, "a1")],
                b1=by_position[(index, "b1")],
                b2=by_position[(index, "b2")],
                a2=by_position[(index, "a2")],
            )
            for index in range(1, quads + 1)
        ]
        statistics_payload = _summarize_quads(complete_quads)
        artifact["statistics"] = statistics_payload
        artifact["complete"] = True
        preflights_passed = bool(artifact["preflights"]) and all(
            row.get("status") == "passed"
            and row.get("source_artifacts_authenticated") is True
            and row.get("harness") == harness_identity
            for row in artifact["preflights"]
        )
        artifacts_authenticated = _samples_authenticated(
            artifact["samples"],
            harness_identity=harness_identity,
            owned_binaries=owned_binaries,
        )
        decision = _no_regression_decision(
            statistics_payload,
            complete=True,
            artifacts_authenticated=artifacts_authenticated,
            preflights_passed=preflights_passed,
            evidence_class=evidence_class,
        )
        _record_decision(artifact, decision)
        native_go_build.write_json_atomic(output, artifact)
        return artifact
    except Exception as error:
        artifact["failure"] = {"type": type(error).__name__, "message": str(error)}
        artifact["complete"] = False
        artifact["accepted"] = False
        native_go_build.write_json_atomic(output, artifact)
        raise CampaignEvidenceError(str(error), artifact) from error


def _load_overlay(path: pathlib.Path) -> tuple[tuple[str, str | None], ...]:
    return native_abba._load_overlay(path)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    prepare = subcommands.add_parser("prepare-arm", help="build one signed implicit embed arm")
    prepare.add_argument("--source-repo", required=True, type=pathlib.Path)
    prepare.add_argument("--harness-repo", required=True, type=pathlib.Path)
    prepare.add_argument("--destination", required=True, type=pathlib.Path)
    prepare.add_argument("--label", required=True)
    prepare.add_argument("--role", required=True, choices=sorted(ARM_ROLES))
    prepare.add_argument("--image", required=True)
    run = subcommands.add_parser("run", help="run one receipt-bound implicit embed ABBA")
    run.add_argument("--harness-repo", required=True, type=pathlib.Path)
    run.add_argument("--control-receipt", required=True, type=pathlib.Path)
    run.add_argument("--candidate-receipt", required=True, type=pathlib.Path)
    run.add_argument("--control-overlay", required=True, type=pathlib.Path)
    run.add_argument("--candidate-overlay", required=True, type=pathlib.Path)
    run.add_argument("--quads", type=int, default=MINIMUM_QUADS)
    run.add_argument(
        "--pilot",
        action="store_true",
        help="run 1-7 directional quads that can never become accepted evidence",
    )
    run.add_argument("--cooldown-seconds", type=float, default=2.0)
    run.add_argument("--timeout-seconds", type=int, default=900)
    run.add_argument("--image", default=native_go_build.DEFAULT_IMAGE)
    run.add_argument("--allow-battery", action="store_true")
    run.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "prepare-arm":
        receipt = prepare_arm(
            args.source_repo,
            args.destination,
            harness_repo=args.harness_repo,
            label=args.label,
            role=args.role,
            image_ref=args.image,
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    control_receipt = load_recorded_arm(args.control_receipt)
    candidate_receipt = load_recorded_arm(args.candidate_receipt)
    control = ArmSpec(
        control_receipt.label,
        control_receipt,
        _load_overlay(args.control_overlay),
    )
    candidate = ArmSpec(
        candidate_receipt.label,
        candidate_receipt,
        _load_overlay(args.candidate_overlay),
    )
    try:
        artifact = run_campaign(
            args.harness_repo,
            control,
            candidate,
            args.output,
            quads=args.quads,
            cooldown_seconds=args.cooldown_seconds,
            timeout_seconds=args.timeout_seconds,
            image_ref=args.image,
            allow_battery=args.allow_battery,
            pilot=args.pilot,
        )
    except CampaignEvidenceError as error:
        print(json.dumps(error.artifact, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(artifact, indent=2, sort_keys=True))
    return _decision_exit_code(artifact)


if __name__ == "__main__":
    raise SystemExit(main())
