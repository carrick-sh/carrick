#!/usr/bin/env python3
"""Prepare and verify immutable Carrick binaries for native ABBA campaigns."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import errno
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import platform
import plistlib
import re
import secrets
import shutil
import stat
import statistics
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence

import native_go_build
import paired_stats


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
REPO_DIGEST_RE = re.compile(
    r"^(?P<repository>[^@\s]+)@sha256:[0-9a-f]{64}$"
)
MACHO_UUID_RE = re.compile(
    r"^UUID: ([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}) "
    r"\(arm64\)(?:\s|$)"
)
DISABLE_CONTROL_RE = re.compile(r"^CARRICK_DISABLE_[A-Z0-9_]+$")
DEFAULT_ON_ZERO_OPT_OUT_KEYS = frozenset(
    (
        "CARRICK_DSR_DIRECT_BYTES",
        "CARRICK_DSR_SHARED_MAPPED_METADATA",
        "CARRICK_DSR_SHARED_MANIFEST_ARC",
        "CARRICK_DSR_SHARED_MANIFEST_FIXED",
        "CARRICK_DSR_SHARED_SOURCE_FINGERPRINT_REUSE",
        "CARRICK_DSR_SHARED_DYLIB_KEYED_IDENTITY",
        "CARRICK_DSR_SHARED_RECOVERY_LAZY",
        "CARRICK_DSR_SHARED_RECOVERY_RUNS",
        "CARRICK_DSR_STORE_AUGMENTATION",
    )
)
DEFAULT_OFF_ONE_OPT_IN_KEYS = frozenset(
    (
        "CARRICK_DSR_PERSISTENT_STORE",
    )
)
QUAD_METRICS = (
    "cpu_s",
    "cpu_user_s",
    "cpu_sys_s",
    "elapsed_ms",
    "workload_ms",
)
TIMING_PERTURBING_CONTROL_KEYS = frozenset(
    (
        "CARRICK_DSR_PROFILE",
        "CARRICK_NATIVE_TRACE_SYSCALLS",
    )
)
APPROVED_INSECURE_LOOPBACK_REGISTRIES = frozenset(("localhost:5005",))


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


@dataclasses.dataclass(frozen=True)
class ArmSpec:
    label: str
    receipt: ArmReceipt
    environment: tuple[tuple[str, str | None], ...]


@dataclasses.dataclass(frozen=True)
class Quad:
    index: int
    a1: dict[str, object]
    b1: dict[str, object]
    b2: dict[str, object]
    a2: dict[str, object]


class CampaignEvidenceError(RuntimeError):
    """A failed campaign whose durable partial artifact was published."""

    def __init__(self, message: str, artifact: dict[str, object]):
        super().__init__(message)
        self.artifact = artifact


def _campaign_positions(quads: int) -> list[dict[str, object]]:
    if quads <= 0:
        raise ValueError("quads must be positive")
    positions: list[dict[str, object]] = [
        {
            "phase": "warmup",
            "arm": "A",
            "quad_index": None,
            "position": "warmup-a",
            "excluded": True,
        },
        {
            "phase": "warmup",
            "arm": "B",
            "quad_index": None,
            "position": "warmup-b",
            "excluded": True,
        },
    ]
    for index in range(1, quads + 1):
        for position, arm in (("a1", "A"), ("b1", "B"), ("b2", "B"), ("a2", "A")):
            positions.append(
                {
                    "phase": f"quad-{index}-{position}",
                    "arm": arm,
                    "quad_index": index,
                    "position": position,
                    "excluded": False,
                }
            )
    return positions


def _validated_environment(arm: ArmSpec) -> dict[str, str | None]:
    keys = tuple(key for key, _value in arm.environment)
    expected = native_go_build.PERFORMANCE_CONTROL_KEYS
    if keys != expected or len(set(keys)) != len(keys):
        raise ValueError(
            f"{arm.label} environment must contain PERFORMANCE_CONTROL_KEYS "
            "exactly once in canonical order"
        )
    environment: dict[str, str | None] = {}
    for key, value in arm.environment:
        if value is not None and type(value) is not str:
            raise ValueError(f"{arm.label} environment value for {key} must be str or null")
        environment[key] = value
    timing_perturbations = sorted(
        key
        for key in TIMING_PERTURBING_CONTROL_KEYS
        if environment[key] is not None
    )
    if timing_perturbations:
        raise ValueError(
            f"{arm.label} environment contains timing-perturbing controls: "
            + ", ".join(timing_perturbations)
        )
    return environment


def _receipt_content_identity(receipt: ArmReceipt) -> tuple[object, ...]:
    return (
        receipt.binary_path.resolve(),
        receipt.binary_sha256,
        receipt.macho_uuid,
        receipt.entitlement_sha256,
        receipt.image_ref,
        receipt.image_id,
        receipt.image_repo_digests,
    )


def validate_arm_mode(control: ArmSpec, candidate: ArmSpec) -> str:
    control_environment = _validated_environment(control)
    candidate_environment = _validated_environment(candidate)
    legacy_candidate = native_go_build.fixed_variant_overlay(
        native_go_build.VARIANT_CANDIDATE
    )
    if candidate_environment == legacy_candidate:
        raise ValueError(
            "legacy candidate overlay is not a valid sharing comparison"
        )
    same_receipt_path = (
        control.receipt.path.resolve() == candidate.receipt.path.resolve()
    )
    environments_equal = control.environment == candidate.environment

    if not same_receipt_path:
        if control.receipt.binary_path.resolve() == candidate.receipt.binary_path.resolve():
            raise ValueError("two-binary mode requires distinct receipt identities")
        if control.receipt.source_repo.resolve() == candidate.receipt.source_repo.resolve():
            raise ValueError(
                "two-binary mode requires separate source worktrees"
            )
        if (
            control.receipt.role != "control"
            or candidate.receipt.role != "candidate"
        ):
            raise ValueError(
                "two-binary mode requires control and candidate receipt roles"
            )
        if not environments_equal:
            raise ValueError(
                "binary and environment dimensions cannot both change"
            )
        return "two-binary"

    if _receipt_content_identity(control.receipt) != _receipt_content_identity(
        candidate.receipt
    ):
        raise ValueError("same-binary receipt identity drifted")
    if environments_equal:
        return "same-binary"

    semantic_default = native_go_build.fixed_variant_overlay(
        native_go_build.VARIANT_DEFAULT
    )
    semantic_shared = native_go_build.fixed_variant_overlay(
        native_go_build.VARIANT_SHARED
    )
    if (
        control_environment == semantic_default
        and candidate_environment == semantic_shared
    ):
        return "same-binary"

    differences = [
        key
        for key in native_go_build.PERFORMANCE_CONTROL_KEYS
        if control_environment[key] != candidate_environment[key]
    ]
    if len(differences) == 1:
        key = differences[0]
        declared_disable = (
            DISABLE_CONTROL_RE.fullmatch(key) is not None
            and control_environment[key] == "1"
        )
        declared_default_on_opt_out = (
            key in DEFAULT_ON_ZERO_OPT_OUT_KEYS
            and control_environment[key] == "0"
        )
        if candidate_environment[key] is None and (
            declared_disable or declared_default_on_opt_out
        ):
            return "same-binary"
        declared_default_off_opt_in = (
            key in DEFAULT_OFF_ONE_OPT_IN_KEYS
            and control_environment[key] is None
            and candidate_environment[key] == "1"
        )
        if declared_default_off_opt_in:
            return "same-binary"
    raise ValueError(
        "same-binary environments must be equal or one declared variant"
    )


def _metric_value(sample: dict[str, object], metric: str) -> float:
    value = sample.get(metric)
    if type(value) not in (int, float):
        raise ValueError(f"quad metric {metric} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0.0:
        raise ValueError(f"quad metric {metric} must be finite and positive")
    return numeric


def summarize_quads(quads: Sequence[Quad]) -> dict[str, object]:
    if len(quads) < 2:
        raise ValueError("quad statistics require at least two complete quads")
    if len(quads) > 127:
        raise ValueError("quad statistics support at most 127 quads")
    expected_indices = list(range(1, len(quads) + 1))
    if [quad.index for quad in quads] != expected_indices:
        raise ValueError("quad indices must be contiguous and start at one")

    metrics: dict[str, object] = {}
    for metric in QUAD_METRICS:
        rows: list[dict[str, float | int]] = []
        raw_samples: list[dict[str, object]] = []
        control_values: list[float] = []
        candidate_values: list[float] = []
        ratios: list[float] = []
        candidate_wins = 0
        ties = 0
        for quad in quads:
            a1 = _metric_value(quad.a1, metric)
            b1 = _metric_value(quad.b1, metric)
            b2 = _metric_value(quad.b2, metric)
            a2 = _metric_value(quad.a2, metric)
            control_quad = (a1 + a2) / 2.0
            candidate_quad = (b1 + b2) / 2.0
            ratio = candidate_quad / control_quad
            control_values.append(control_quad)
            candidate_values.append(candidate_quad)
            ratios.append(ratio)
            if candidate_quad < control_quad:
                candidate_wins += 1
            elif candidate_quad == control_quad:
                ties += 1
            rows.append(
                {
                    "quad_index": quad.index,
                    "a1": a1,
                    "b1": b1,
                    "b2": b2,
                    "a2": a2,
                    "control_quad": control_quad,
                    "candidate_quad": candidate_quad,
                    "ratio": ratio,
                }
            )
            raw_samples.extend(
                (
                    {
                        "quad_index": quad.index,
                        "position": "a1",
                        "arm": "A",
                        "value": a1,
                    },
                    {
                        "quad_index": quad.index,
                        "position": "b1",
                        "arm": "B",
                        "value": b1,
                    },
                    {
                        "quad_index": quad.index,
                        "position": "b2",
                        "arm": "B",
                        "value": b2,
                    },
                    {
                        "quad_index": quad.index,
                        "position": "a2",
                        "arm": "A",
                        "value": a2,
                    },
                )
            )

        sign_trials = len(quads) - ties
        sign_probability = paired_stats.exact_one_sided_sign_probability(
            candidate_wins,
            sign_trials,
        )
        bootstrap = paired_stats.paired_bootstrap(ratios)
        metrics[metric] = {
            "quads": rows,
            "raw_samples": raw_samples,
            "control_median": paired_stats.median_binary64(control_values),
            "candidate_median": paired_stats.median_binary64(candidate_values),
            "median_quad_ratio": paired_stats.median_binary64(ratios),
            "arithmetic_ratio_sd": statistics.stdev(ratios),
            "log_ratio_sd": statistics.stdev(
                [math.log(ratio) for ratio in ratios]
            ),
            "candidate_wins": candidate_wins,
            "ties": ties,
            "sign_test": {
                "trials": sign_trials,
                "candidate_wins": candidate_wins,
                "probability": paired_stats.exact_probability_json(
                    sign_probability
                ),
            },
            "bootstrap": dataclasses.asdict(bootstrap),
            "resolution": paired_stats.ratio_resolution(ratios),
        }
    return {
        "quad_count": len(quads),
        "primary_metric": "cpu_s",
        "metrics": metrics,
    }


def _receipt_manifest(arm: ArmSpec) -> dict[str, object]:
    receipt = arm.receipt
    return {
        "label": arm.label,
        "receipt_path": str(receipt.path.resolve()),
        "receipt_label": receipt.label,
        "receipt_role": receipt.role,
        "source_repo": str(receipt.source_repo.resolve()),
        "source_commit": receipt.source_commit,
        "source_branch": receipt.source_branch,
        "source_detached": receipt.source_detached,
        "binary_path": str(receipt.binary_path.resolve()),
        "binary_size": receipt.binary_size,
        "binary_mode": receipt.binary_mode,
        "binary_sha256": receipt.binary_sha256,
        "macho_uuid": receipt.macho_uuid,
        "entitlement_sha256": receipt.entitlement_sha256,
        "image_ref": receipt.image_ref,
        "image_id": receipt.image_id,
        "image_repo_digests": list(receipt.image_repo_digests),
        "environment": dict(arm.environment),
    }


def _checked_command(command: list[str], description: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise _command_error(description, result)
    return result


def _darwin_power_preflight() -> dict[str, object]:
    battery = _checked_command(["pmset", "-g", "batt"], "pmset battery preflight")
    battery_lines = [line.strip() for line in battery.stdout.splitlines() if line.strip()]
    on_ac = any("Now drawing from 'AC Power'" in line for line in battery_lines)
    on_battery = any(
        "Now drawing from 'Battery Power'" in line for line in battery_lines
    )
    if not on_ac and not on_battery:
        raise RuntimeError(
            "native performance campaign could not identify the power source: "
            + battery.stdout.strip()
        )

    thermal = _checked_command(["pmset", "-g", "therm"], "pmset thermal preflight")
    thermal_lines = [line.strip() for line in thermal.stdout.splitlines() if line.strip()]
    textual_requirements = (
        "No thermal warning",
        "No performance warning",
        "No CPU power status",
    )
    textual_ok = (
        len(thermal_lines) == len(textual_requirements)
        and all(
            any(requirement in line for line in thermal_lines)
            for requirement in textual_requirements
        )
        and all(
            any(requirement in line for requirement in textual_requirements)
            for line in thermal_lines
        )
    )
    numeric_patterns = {
        "CPU_Speed_Limit": 100,
        "Scheduler_Limit": 100,
        "CPU_Available": 1,
    }
    numeric_values: dict[str, int] = {}
    numeric_only = True
    for line in thermal_lines:
        match = re.fullmatch(r"([A-Za-z_]+)\s*=\s*(\d+)", line)
        if match is None or match.group(1) not in numeric_patterns:
            numeric_only = False
            break
        numeric_values[match.group(1)] = int(match.group(2))
    numeric_ok = (
        numeric_only
        and len(thermal_lines) == len(numeric_patterns)
        and set(numeric_values) == set(numeric_patterns)
        and numeric_values == numeric_patterns
    )
    if not textual_ok and not numeric_ok:
        raise RuntimeError(
            "thermal/power preflight did not report an unlimited state: "
            + thermal.stdout.strip()
        )
    return {
        "power_source": "AC Power" if on_ac else "Battery Power",
        "battery_output": battery.stdout,
        "thermal_output": thermal.stdout,
        "thermal_contract": (
            "explicit-no-warning-lines-v1"
            if textual_ok
            else "numeric-unlimited-fields-v1"
        ),
    }


def _expected_image(receipt: ArmReceipt) -> dict[str, object]:
    return {
        "architecture": "arm64",
        "id": receipt.image_id,
        "repo_digests": list(receipt.image_repo_digests),
    }


def _image_repository(reference: str) -> str:
    repository = reference.rsplit("@", 1)[0]
    if "@" not in reference:
        last_slash = repository.rfind("/")
        last_colon = repository.rfind(":")
        if last_colon > last_slash:
            repository = repository[:last_colon]
    if not repository or any(character.isspace() for character in repository):
        raise ValueError(f"image reference has an invalid repository: {reference!r}")
    components = repository.split("/")
    first = components[0]
    has_explicit_registry = (
        len(components) > 1
        and (
            first == "localhost"
            or "." in first
            or ":" in first
        )
    )
    if has_explicit_registry:
        registry = first.lower()
        repository_path = "/".join(components[1:]).lower()
    else:
        registry = "docker.io"
        repository_path = repository.lower()
    if registry in {"index.docker.io", "registry-1.docker.io"}:
        registry = "docker.io"
    if registry == "docker.io" and "/" not in repository_path:
        repository_path = f"library/{repository_path}"
    if not repository_path:
        raise ValueError(f"image reference has an invalid repository: {reference!r}")
    return f"{registry}/{repository_path}"


def _registry_host(registry: str) -> str:
    if registry.startswith("["):
        closing = registry.find("]")
        if closing < 0:
            raise ValueError(f"registry has an invalid IPv6 authority: {registry!r}")
        return registry[1:closing]
    return registry.split(":", 1)[0]


def _registry_is_loopback(registry: str) -> bool:
    host = _registry_host(registry)
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _registry_transport_for_image(
    image_ref: str,
) -> native_go_build.RegistryTransport:
    registry = _image_repository(image_ref).split("/", 1)[0]
    if registry in APPROVED_INSECURE_LOOPBACK_REGISTRIES:
        return native_go_build.RegistryTransport(
            registry=registry,
            insecure=True,
        )
    if _registry_is_loopback(registry):
        raise RuntimeError(
            f"loopback registry {registry!r} is not approved for insecure "
            "native performance transport"
        )
    return native_go_build.RegistryTransport(
        registry=registry,
        insecure=False,
    )


def _executed_image_ref(image_ref: str, receipt: ArmReceipt) -> str:
    requested_repository = _image_repository(image_ref)
    matches = tuple(
        sorted(
            {
                digest
                for digest in receipt.image_repo_digests
                if REPO_DIGEST_RE.fullmatch(digest)
                and _image_repository(digest) == requested_repository
            }
        )
    )
    if len(matches) > 1:
        raise RuntimeError(
            "arm receipt has ambiguous immutable repo digests for requested "
            f"repository {requested_repository!r}: {list(matches)!r}"
        )
    if not matches:
        raise RuntimeError(
            "arm receipt has no matching immutable repo digest for requested "
            f"repository {requested_repository!r}"
        )
    return matches[0]


def _campaign_preflight(
    control: ArmSpec,
    candidate: ArmSpec,
    *,
    image_ref: str,
    known_receipt_binaries: tuple[pathlib.Path, ...],
) -> dict[str, object]:
    verified_control = load_and_verify_arm(control.receipt.path)
    verified_candidate = load_and_verify_arm(candidate.receipt.path)
    if verified_control != control.receipt:
        raise RuntimeError("control receipt drifted from the campaign arm")
    if verified_candidate != candidate.receipt:
        raise RuntimeError("candidate receipt drifted from the campaign arm")

    if (
        control.receipt.image_ref != image_ref
        or candidate.receipt.image_ref != image_ref
    ):
        raise RuntimeError(
            "campaign image_ref does not match both arm receipts"
        )
    control_image = _expected_image(control.receipt)
    candidate_image = _expected_image(candidate.receipt)
    if control_image != candidate_image:
        raise RuntimeError("arm receipt image ID or repo digests differ")
    control_executed_image = _executed_image_ref(
        image_ref,
        control.receipt,
    )
    candidate_executed_image = _executed_image_ref(
        image_ref,
        candidate.receipt,
    )
    if control_executed_image != candidate_executed_image:
        raise RuntimeError(
            "control and candidate immutable execution references differ"
        )
    current_image = _image_receipt(image_ref)
    if current_image != control_image:
        raise RuntimeError("campaign image identity drifted from arm receipts")
    registry_transport = _registry_transport_for_image(
        control_executed_image
    )

    native_go_build.reject_ambient_carrick(os.environ, {})
    power = _darwin_power_preflight()
    busy_reasons = native_go_build.busy_host_reasons()
    if busy_reasons:
        raise RuntimeError(
            "host is not idle enough for an official campaign: "
            + "; ".join(busy_reasons)
        )
    foreign = native_go_build.foreign_workload_census(
        known_receipt_binaries=known_receipt_binaries,
    )
    if foreign:
        raise RuntimeError(
            "foreign workload census is not empty: "
            + json.dumps(foreign)
        )
    docker_oracles = native_go_build.running_docker_oracles()
    if docker_oracles:
        raise RuntimeError(
            "Docker oracle is running during Carrick campaign: "
            + json.dumps(docker_oracles)
        )
    return {
        "checked_at": utc_now(),
        "receipt_paths": [
            str(control.receipt.path.resolve()),
            str(candidate.receipt.path.resolve()),
        ],
        "known_receipt_binaries": [
            str(path) for path in known_receipt_binaries
        ],
        "image_ref": image_ref,
        "executed_image_ref": control_executed_image,
        "registry_transport": native_go_build.registry_transport_evidence(
            registry_transport
        ),
        "image": current_image,
        "power": power,
        "busy_host_reasons": busy_reasons,
        "foreign_processes": foreign,
        "docker_oracles": docker_oracles,
    }


def _annotated_sample(
    sample: dict[str, object],
    position: dict[str, object],
) -> dict[str, object]:
    annotated = dict(sample)
    annotated.update(
        {
            "phase": position["phase"],
            "arm": position["arm"],
            "quad_index": position["quad_index"],
            "position": position["position"],
            "excluded": position["excluded"],
        }
    )
    return annotated


def _path_matches(value: object, expected: pathlib.Path) -> bool:
    return (
        type(value) is str
        and pathlib.Path(value).resolve() == expected.resolve()
    )


def _validate_sample_evidence(
    sample: dict[str, object],
    arm: ArmSpec,
    *,
    harness_repo: pathlib.Path,
    expected_index: int,
    expected_run_id: str,
    image_ref: str,
    registry_transport: native_go_build.RegistryTransport,
) -> None:
    receipt = arm.receipt
    environment = dict(arm.environment)
    errors: list[str] = []
    if sample.get("engine") != native_go_build.ENGINE_CARRICK:
        errors.append("engine")
    if sample.get("index") != expected_index:
        errors.append("sample index")
    if sample.get("run_id") != expected_run_id:
        errors.append("run ID")
    if not _path_matches(sample.get("binary_path"), receipt.binary_path):
        errors.append("binary path")
    if sample.get("binary_sha256") != receipt.binary_sha256:
        errors.append("binary sha256")
    if sample.get("environment_overlay") != environment:
        errors.append("environment overlay")
    if sample.get("controlled_environment") != environment:
        errors.append("controlled environment")
    expected_transport = native_go_build.registry_transport_evidence(
        registry_transport
    )
    if sample.get("registry_transport") != expected_transport:
        errors.append("registry transport")
    if sample.get("return_code") != 0 or sample.get("timed_out") is not False:
        errors.append("completion status")
    if sample.get("build_ok") is not True:
        errors.append("BUILD_OK status")
    stdout = sample.get("stdout")
    if type(stdout) is not str or stdout.splitlines().count("BUILD_OK") != 1:
        errors.append("BUILD_OK marker")

    command = sample.get("command")
    if not isinstance(command, dict):
        errors.append("command")
    else:
        argv = command.get("argv")
        expected_argv = native_go_build.build_command(
            harness_repo,
            native_go_build.ENGINE_CARRICK,
            expected_run_id,
            binary=receipt.binary_path.resolve(),
            image=image_ref,
            registry_transport=registry_transport,
        )
        if argv != expected_argv:
            errors.append("command argv")
        if command.get("status") != 0 or command.get("build_ok") is not True:
            errors.append("command status")

    cleanup = sample.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("status") != 0:
        errors.append("cleanup")

    for metric in QUAD_METRICS:
        try:
            _metric_value(sample, metric)
        except ValueError:
            errors.append(metric)
    cpu_s = sample.get("cpu_s")
    cpu_user_s = sample.get("cpu_user_s")
    cpu_sys_s = sample.get("cpu_sys_s")
    if all(type(value) in (int, float) for value in (cpu_s, cpu_user_s, cpu_sys_s)):
        if not math.isclose(
            float(cpu_s),
            float(cpu_user_s) + float(cpu_sys_s),
            rel_tol=0.0,
            abs_tol=1e-6,
        ):
            errors.append("CPU total")
    workload_ns = sample.get("workload_ns")
    workload_ms = sample.get("workload_ms")
    if (
        type(workload_ns) is not int
        or workload_ns <= 0
        or type(workload_ms) not in (int, float)
        or float(workload_ms) != workload_ns // 1_000_000
    ):
        errors.append("workload clock")

    provenance = sample.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("provenance")
    else:
        pre = provenance.get("pre")
        post = provenance.get("post")
        if not isinstance(pre, dict) or not isinstance(post, dict):
            errors.append("pre/post provenance")
        else:
            if pre != post:
                errors.append("pre/post provenance drift")
            for name, snapshot in (("pre", pre), ("post", post)):
                if not _path_matches(
                    snapshot.get("binary_path"),
                    receipt.binary_path,
                ):
                    errors.append(f"{name} provenance binary path")
                if snapshot.get("binary_sha256") != receipt.binary_sha256:
                    errors.append(f"{name} provenance binary sha256")
                if snapshot.get("image_ref") != image_ref:
                    errors.append(f"{name} provenance image_ref")
                if snapshot.get("image") != _expected_image(receipt):
                    errors.append(f"{name} provenance image identity")
                if snapshot.get("registry_transport") != expected_transport:
                    errors.append(f"{name} provenance registry transport")
                if snapshot.get("controlled_environment") != environment:
                    errors.append(f"{name} provenance environment")
                if snapshot.get("engine") != native_go_build.ENGINE_CARRICK:
                    errors.append(f"{name} provenance engine")
                if snapshot.get("git_status") != []:
                    errors.append(f"{name} provenance git status")
                if snapshot.get("foreign_processes") != []:
                    errors.append(f"{name} provenance foreign processes")
                if snapshot.get("docker_oracles") != []:
                    errors.append(f"{name} provenance Docker oracle")
    if errors:
        raise ValueError(", ".join(dict.fromkeys(errors)))


def _campaign_decision(
    statistics_payload: dict[str, object],
    *,
    complete: bool,
    statistically_eligible: bool = True,
) -> dict[str, object]:
    metrics = statistics_payload["metrics"]
    primary = metrics["cpu_s"]
    wall = metrics["workload_ms"]
    secondary = [
        metric
        for name, metric in metrics.items()
        if name != "cpu_s"
    ]
    criteria = {
        "complete_with_eight_quads": (
            complete and statistics_payload["quad_count"] >= 8
        ),
        "total_cpu_median_at_most_point_90": (
            primary["median_quad_ratio"] <= 0.90
        ),
        "total_cpu_two_sided_interval_below_one": (
            primary["bootstrap"]["two_sided_upper"] < 1.0
        ),
        "workload_wall_median_below_one": wall["median_quad_ratio"] < 1.0,
        "total_cpu_sign_probability_below_0_05": _exact_probability_below(
            primary["sign_test"]["probability"],
            numerator=1,
            denominator=20,
        ),
        "no_supported_secondary_regression": not any(
            metric["bootstrap"]["two_sided_lower"] > 1.0
            for metric in secondary
        ),
    }
    statistical_pass = statistically_eligible and all(criteria.values())
    return {
        "statistical_pass": statistical_pass,
        "retained": False,
        "reason": (
            "statistical gates passed; external mechanism and correctness gates remain required"
            if statistical_pass
            else "total CPU statistical gates did not establish an improvement"
        ),
        "criteria": criteria,
    }


def _exact_probability_below(
    probability: dict[str, object],
    *,
    numerator: int,
    denominator: int,
) -> bool:
    actual_numerator = probability.get("numerator")
    actual_denominator = probability.get("denominator")
    if (
        type(actual_numerator) is not int
        or type(actual_denominator) is not int
        or actual_numerator < 0
        or actual_denominator <= 0
        or actual_numerator > actual_denominator
        or numerator < 0
        or denominator <= 0
    ):
        raise ValueError("exact probability fields are invalid")
    return actual_numerator * denominator < numerator * actual_denominator


def bind_active_store(
    control: ArmSpec,
    candidate: ArmSpec,
    active_store_dir: pathlib.Path,
) -> tuple[ArmSpec, ArmSpec]:
    """Inject one exact active-store path into both immutable arm overlays."""
    active = str(active_store_dir.resolve())

    def bind(arm: ArmSpec) -> ArmSpec:
        environment = _validated_environment(arm)
        recorded = environment["CARRICK_DSR_STORE_DIR"]
        if recorded is not None and pathlib.Path(recorded).resolve() != pathlib.Path(active):
            raise ValueError(
                f"{arm.label} overlay store path conflicts with active-store receipt"
            )
        environment["CARRICK_DSR_STORE_DIR"] = active
        return dataclasses.replace(
            arm,
            environment=tuple(
                (key, environment[key])
                for key in native_go_build.PERFORMANCE_CONTROL_KEYS
            ),
        )

    return bind(control), bind(candidate)


def run_campaign(
    harness_repo: pathlib.Path,
    control: ArmSpec,
    candidate: ArmSpec,
    output: pathlib.Path,
    *,
    store_seed_dir: pathlib.Path,
    active_store_dir: pathlib.Path,
    quads: int = 8,
    cooldown_seconds: float = 2.0,
    timeout_seconds: int = 900,
    image_ref: str = native_go_build.DEFAULT_IMAGE,
) -> dict[str, object]:
    if type(quads) is not int or quads < 8:
        raise ValueError("official campaigns require at least eight quads")
    if quads > 127:
        raise ValueError("official campaigns support at most 127 quads")
    if (
        type(timeout_seconds) is not int
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a positive integer")
    if (
        type(cooldown_seconds) not in (int, float)
        or not math.isfinite(float(cooldown_seconds))
        or cooldown_seconds < 0
    ):
        raise ValueError("cooldown_seconds must be finite and nonnegative")
    if type(image_ref) is not str or not image_ref:
        raise ValueError("image_ref must be nonempty")
    campaign_store_root = (
        harness_repo / "target/perf/native-store-augmentation"
    ).resolve()
    store_validator = (
        harness_repo / "target/release/examples/native_manifest_census"
    ).resolve()
    if not campaign_store_root.is_dir():
        raise ValueError(
            "native-store campaign root must already exist: "
            f"{campaign_store_root}"
        )
    control, candidate = bind_active_store(
        control,
        candidate,
        active_store_dir,
    )
    mode = validate_arm_mode(control, candidate)
    null_control_control = (
        control.receipt.path.resolve() == candidate.receipt.path.resolve()
        and control.environment == candidate.environment
    )
    if os.path.lexists(output):
        raise FileExistsError(
            f"campaign output already exists and cannot resume: {output}"
        )

    known_receipt_binaries = tuple(
        sorted(
            {
                control.receipt.binary_path.resolve(),
                candidate.receipt.binary_path.resolve(),
            }
        )
    )
    campaign_id = f"{os.getpid()}-{uuid.uuid4().hex}"
    started_at = utc_now()
    artifact: dict[str, object] = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": campaign_id,
        "started_at": started_at,
        "finished_at": None,
        "complete": False,
        "accepted": False,
        "mode": mode,
        "identity": {
            "harness_repo": str(harness_repo.resolve()),
            "quads": quads,
            "cooldown_seconds": float(cooldown_seconds),
            "timeout_seconds": timeout_seconds,
            "image_ref": image_ref,
            "sparse_store": {
                "seed_dir": str(store_seed_dir.resolve()),
                "active_store_dir": str(active_store_dir.resolve()),
                "validator": str(store_validator.resolve()),
                "seed": None,
            },
            "executed_image_ref": None,
            "registry_transport": None,
            "schedule": "excluded-a-b-then-a1-b1-b2-a2-v1",
            "primary_metric": "rusage-children-total-cpu-floor-v1",
        },
        "control": _receipt_manifest(control),
        "candidate": _receipt_manifest(candidate),
        "known_receipt_binaries": [
            str(path) for path in known_receipt_binaries
        ],
        "preflights": [],
        "samples": [],
        "quad_membership": [],
        "statistics": None,
        "failure": None,
        "decision": {
            "statistical_pass": False,
            "retained": False,
            "reason": "campaign incomplete",
        },
        "mechanism": {"status": "external_gate_required"},
        "correctness": {"status": "external_gate_required"},
    }
    native_go_build.write_json_atomic(output, artifact, exclusive=True)
    positions = _campaign_positions(quads)

    try:
        registry_transport = _registry_transport_for_image(image_ref)
        artifact["identity"]["registry_transport"] = (
            native_go_build.registry_transport_evidence(
                registry_transport
            )
        )
        native_go_build.write_json_atomic(output, artifact)
        initial_preflight = _campaign_preflight(
            control,
            candidate,
            image_ref=image_ref,
            known_receipt_binaries=known_receipt_binaries,
        )
        artifact["preflights"].append(initial_preflight)
        executed_image_ref = str(initial_preflight["executed_image_ref"])
        if (
            initial_preflight["registry_transport"]
            != artifact["identity"]["registry_transport"]
        ):
            raise RuntimeError(
                "registry transport drifted from campaign image identity"
            )
        artifact["identity"]["executed_image_ref"] = executed_image_ref
        initial_store = native_go_build.validate_sparse_store_tree(
            store_seed_dir,
            validator=store_validator,
            require_read_only=True,
        )
        artifact["identity"]["sparse_store"]["seed"] = initial_store
        native_go_build.write_json_atomic(output, artifact)
        for sample_index, position in enumerate(positions, start=1):
            if position["position"] == "a1":
                quad_preflight = _campaign_preflight(
                    control,
                    candidate,
                    image_ref=image_ref,
                    known_receipt_binaries=known_receipt_binaries,
                )
                if (
                    quad_preflight["executed_image_ref"]
                    != executed_image_ref
                ):
                    raise RuntimeError(
                        "immutable execution reference drifted before quad"
                    )
                if (
                    quad_preflight["registry_transport"]
                    != artifact["identity"]["registry_transport"]
                ):
                    raise RuntimeError(
                        "registry transport drifted before quad"
                    )
                artifact["preflights"].append(quad_preflight)
                native_go_build.write_json_atomic(output, artifact)
            arm = control if position["arm"] == "A" else candidate
            restore_receipt = native_go_build.restore_sparse_store_seed(
                store_seed_dir,
                active_store_dir,
                campaign_root=campaign_store_root,
                validator=store_validator,
            )
            if (
                restore_receipt["seed"]["tree_sha256"]
                != initial_store["tree_sha256"]
                or restore_receipt["seed"]["entries"]
                != initial_store["entries"]
                or restore_receipt["active"]["tree_sha256"]
                != initial_store["tree_sha256"]
            ):
                raise RuntimeError("sparse-store seed or restore receipt drifted")
            sample_run_id = (
                f"native-go-build-abba-{campaign_id}-{position['phase']}"
            )
            try:
                sample = native_go_build.run_sample(
                    harness_repo,
                    native_go_build.ENGINE_CARRICK,
                    sample_index,
                    timeout_seconds,
                    environment_overlay=dict(arm.environment),
                    binary=arm.receipt.binary_path,
                    image=executed_image_ref,
                    registry_transport=registry_transport,
                    current_run_id=sample_run_id,
                    known_receipt_binaries=known_receipt_binaries,
                )
            except native_go_build.SampleEvidenceError as error:
                raise native_go_build.SampleEvidenceError(
                    str(error),
                    _annotated_sample(error.sample, position),
                ) from error
            annotated = _annotated_sample(sample, position)
            annotated["sparse_store_restore"] = restore_receipt
            try:
                _validate_sample_evidence(
                    annotated,
                    arm,
                    harness_repo=harness_repo,
                    expected_index=sample_index,
                    expected_run_id=sample_run_id,
                    image_ref=executed_image_ref,
                    registry_transport=registry_transport,
                )
            except ValueError as error:
                raise native_go_build.SampleEvidenceError(
                    f"sample evidence did not reconcile: {error}",
                    annotated,
                ) from error
            artifact["samples"].append(annotated)
            native_go_build.write_json_atomic(output, artifact)
            time.sleep(float(cooldown_seconds))

        sample_by_position = {
            (int(sample["quad_index"]), str(sample["position"])): sample
            for sample in artifact["samples"]
            if sample["quad_index"] is not None
        }
        complete_quads = [
            Quad(
                index=index,
                a1=sample_by_position[(index, "a1")],
                b1=sample_by_position[(index, "b1")],
                b2=sample_by_position[(index, "b2")],
                a2=sample_by_position[(index, "a2")],
            )
            for index in range(1, quads + 1)
        ]
        artifact["quad_membership"] = [
            {
                "index": quad.index,
                "a1_run_id": quad.a1["run_id"],
                "b1_run_id": quad.b1["run_id"],
                "b2_run_id": quad.b2["run_id"],
                "a2_run_id": quad.a2["run_id"],
            }
            for quad in complete_quads
        ]
        statistics_payload = summarize_quads(complete_quads)
        artifact["statistics"] = statistics_payload
        artifact["complete"] = True
        artifact["accepted"] = True
        artifact["decision"] = _campaign_decision(
            statistics_payload,
            complete=True,
            statistically_eligible=not null_control_control,
        )
        artifact["finished_at"] = utc_now()
        native_go_build.write_json_atomic(output, artifact)
        return artifact
    except Exception as error:
        failed_sample = (
            error.sample
            if isinstance(error, native_go_build.SampleEvidenceError)
            else None
        )
        reason = str(error)
        artifact["complete"] = False
        artifact["accepted"] = False
        artifact["finished_at"] = utc_now()
        artifact["failure"] = {
            "reason": reason,
            "sample": failed_sample,
        }
        artifact["decision"] = {
            "statistical_pass": False,
            "retained": False,
            "reason": "campaign incomplete",
        }
        native_go_build.write_json_atomic(output, artifact)
        raise CampaignEvidenceError(reason, artifact) from error


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular_bytes(
    path: pathlib.Path,
    description: str,
) -> tuple[bytes, tuple[int, ...]]:
    descriptor = _open_path_no_symlinks(path, description)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"{description} must be a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _metadata_identity(before) != _metadata_identity(after):
            raise RuntimeError(f"{description} drifted while it was read")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise RuntimeError(f"{description} was truncated while it was read")
        return payload, _metadata_identity(before)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> int:
    written = 0
    while written < len(payload):
        count = os.write(descriptor, payload[written:])
        if count <= 0:
            raise RuntimeError("temporary artifact write made no progress")
        written += count
    return written


def _sha256_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _directory_path_matches_descriptor(
    path: pathlib.Path,
    descriptor: int,
) -> bool:
    current = _open_path_no_symlinks(
        path,
        "accepted artifact destination parent",
        directory=True,
    )
    try:
        expected = os.fstat(descriptor)
        actual = os.fstat(current)
        return (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
    finally:
        os.close(current)


def _directory_name_identity(
    directory: int,
    name: str,
) -> tuple[int, int] | None:
    try:
        metadata = os.stat(
            name,
            dir_fd=directory,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    return metadata.st_dev, metadata.st_ino


def _require_directory_name_matches_descriptor(
    directory: int,
    name: str,
    descriptor: int,
    description: str,
) -> None:
    metadata = os.fstat(descriptor)
    if _directory_name_identity(directory, name) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        raise RuntimeError(f"{description} identity drifted")


def _unlink_directory_name_if_owned(
    directory: int,
    name: str,
    descriptor: int,
) -> None:
    metadata = os.fstat(descriptor)
    if _directory_name_identity(directory, name) == (
        metadata.st_dev,
        metadata.st_ino,
    ):
        # Darwin has no conditional unlink-by-inode operation. Leave a
        # mismatched name alone, and tolerate the owned name disappearing
        # between the identity check and this best-effort cleanup.
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass


def publish_accepted_artifact(
    source: pathlib.Path,
    destination: pathlib.Path,
) -> dict[str, object]:
    source = _absolute_without_resolving(source)
    destination = _absolute_without_resolving(destination)
    source_bytes, source_identity = _read_regular_bytes(
        source,
        "accepted artifact source",
    )
    try:
        payload = json.loads(source_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("accepted artifact source is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("accepted artifact source must be a JSON object")
    if (
        payload.get("schema") != CAMPAIGN_SCHEMA
        or payload.get("complete") is not True
        or payload.get("accepted") is not True
    ):
        raise ValueError(
            "accepted artifact source must have the campaign schema and "
            "complete=true accepted=true"
        )
    if os.path.lexists(destination):
        raise FileExistsError(
            f"accepted artifact destination already exists: {destination}"
        )
    _validate_directory(destination.parent, "accepted artifact destination parent")

    parent_descriptor = _open_path_no_symlinks(
        destination.parent,
        "accepted artifact destination parent",
        directory=True,
    )
    temporary_name: str | None = None
    temporary_descriptor = -1
    try:
        for _attempt in range(128):
            candidate_name = f".{destination.name}.{secrets.token_hex(16)}"
            try:
                temporary_descriptor = os.open(
                    candidate_name,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o444,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            temporary_name = candidate_name
            break
        if temporary_name is None or temporary_descriptor < 0:
            raise RuntimeError("could not reserve a random publication temporary")

        copy_bytes, copy_identity = _read_regular_bytes(
            source,
            "accepted artifact source",
        )
        if copy_identity != source_identity or copy_bytes != source_bytes:
            raise RuntimeError(
                "accepted artifact source drifted between verification and copy"
            )
        written = _write_all(temporary_descriptor, copy_bytes)
        os.fchmod(temporary_descriptor, 0o444)
        os.fsync(temporary_descriptor)
        temporary_metadata = os.fstat(temporary_descriptor)
        if written != len(source_bytes) or temporary_metadata.st_size != len(source_bytes):
            raise RuntimeError("publication temporary file is truncated")
        if _sha256_descriptor(temporary_descriptor) != hashlib.sha256(
            source_bytes
        ).hexdigest():
            raise RuntimeError("publication temporary file hash changed")

        final_source_bytes, final_source_identity = _read_regular_bytes(
            source,
            "accepted artifact source",
        )
        if (
            final_source_identity != source_identity
            or final_source_bytes != source_bytes
        ):
            raise RuntimeError(
                "accepted artifact source drifted between verification and copy"
            )
        if not _directory_path_matches_descriptor(
            destination.parent,
            parent_descriptor,
        ):
            raise RuntimeError(
                "accepted artifact destination parent path changed"
            )
        _require_directory_name_matches_descriptor(
            parent_descriptor,
            temporary_name,
            temporary_descriptor,
            "publication temporary pathname",
        )
        try:
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise FileExistsError(
                f"accepted artifact destination already exists: {destination}"
            ) from error
        _require_directory_name_matches_descriptor(
            parent_descriptor,
            destination.name,
            temporary_descriptor,
            "published artifact destination",
        )
        os.fsync(parent_descriptor)
        return payload
    finally:
        if temporary_descriptor >= 0 and temporary_name is not None:
            _unlink_directory_name_if_owned(
                parent_descriptor,
                temporary_name,
                temporary_descriptor,
            )
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        os.close(parent_descriptor)


def _load_overlay(path: pathlib.Path) -> tuple[tuple[str, str | None], ...]:
    class ObjectPairs(list):
        pass

    raw, _identity = _read_regular_bytes(path, "campaign overlay")
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=ObjectPairs,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"campaign overlay is not valid JSON: {path}") from error
    if not isinstance(payload, ObjectPairs):
        raise ValueError("campaign overlay must be a JSON object")
    environment = tuple(payload)
    keys = tuple(key for key, _value in environment)
    if (
        keys != native_go_build.PERFORMANCE_CONTROL_KEYS
        or len(set(keys)) != len(keys)
    ):
        raise ValueError(
            "campaign overlay must contain PERFORMANCE_CONTROL_KEYS "
            "exactly once in canonical order"
        )
    for key, value in environment:
        if type(key) is not str or (value is not None and type(value) is not str):
            raise ValueError("campaign overlay values must be strings or null")
    return environment


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
        ["/usr/bin/dwarfdump", "--uuid", str(binary)],
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
        if any(
            candidate.strip() in {"segname __TEXT", "segname __DATA"}
            for candidate in section_tail
        ):
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
            raise RuntimeError(
                "copied Carrick binary is missing a loadable __dof_carrick DOF section"
            )
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


def _load_recorded_arm(
    path: pathlib.Path,
) -> tuple[
    ArmReceipt,
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    receipt_path, payload = _read_receipt(path)
    _build, recorded_host, recorded_image = _validate_recorded_receipt(
        receipt_path, payload
    )

    source_repo = pathlib.Path(str(payload["source_repo"]))
    if not source_repo.is_absolute():
        raise ValueError("arm receipt source_repo must be absolute")
    binary_path = pathlib.Path(str(payload["binary_path"]))
    receipt = ArmReceipt(
        path=receipt_path,
        label=str(payload["label"]),
        role=str(payload["role"]),
        source_repo=source_repo,
        source_commit=str(payload["source_commit"]),
        source_branch=payload["source_branch"],
        source_detached=bool(payload["source_detached"]),
        binary_path=binary_path,
        binary_size=int(payload["binary_size"]),
        binary_mode=int(payload["binary_mode"]),
        binary_sha256=str(payload["binary_sha256"]),
        macho_uuid=str(payload["macho_uuid"]),
        entitlement_sha256=str(payload["entitlement_sha256"]),
        image_ref=str(payload["image_ref"]),
        image_id=str(recorded_image["id"]),
        image_repo_digests=tuple(recorded_image["repo_digests"]),
    )
    return receipt, payload, recorded_host, recorded_image


def load_recorded_arm(path: pathlib.Path) -> ArmReceipt:
    receipt, _payload, _recorded_host, _recorded_image = _load_recorded_arm(
        path
    )
    return receipt


def load_and_verify_arm(path: pathlib.Path) -> ArmReceipt:
    receipt, payload, recorded_host, recorded_image = _load_recorded_arm(path)

    source_repo = receipt.source_repo
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

    binary_path = receipt.binary_path
    metadata = _validate_regular_file(binary_path, "arm binary")
    expected_size = receipt.binary_size
    expected_mode = receipt.binary_mode
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

    return receipt


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
    run = subcommands.add_parser(
        "run",
        help="run one new receipt-bound official ABBA campaign",
    )
    run.add_argument("--harness-repo", required=True, type=pathlib.Path)
    run.add_argument("--control-receipt", required=True, type=pathlib.Path)
    run.add_argument("--candidate-receipt", required=True, type=pathlib.Path)
    run.add_argument("--control-overlay", required=True, type=pathlib.Path)
    run.add_argument("--candidate-overlay", required=True, type=pathlib.Path)
    run.add_argument("--quads", type=int, default=8)
    run.add_argument("--cooldown-seconds", type=float, default=2.0)
    run.add_argument("--timeout-seconds", type=int, default=900)
    run.add_argument("--image", default=native_go_build.DEFAULT_IMAGE)
    run.add_argument("--store-seed-dir", required=True, type=pathlib.Path)
    run.add_argument("--active-store-dir", required=True, type=pathlib.Path)
    run.add_argument("--output", required=True, type=pathlib.Path)
    publish = subcommands.add_parser(
        "publish",
        help="exclusively publish one complete accepted campaign artifact",
    )
    publish.add_argument("--source", required=True, type=pathlib.Path)
    publish.add_argument("--destination", required=True, type=pathlib.Path)
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
    if args.command == "run":
        control_receipt = load_recorded_arm(args.control_receipt)
        candidate_receipt = load_recorded_arm(args.candidate_receipt)
        control = ArmSpec(
            label=control_receipt.label,
            receipt=control_receipt,
            environment=_load_overlay(args.control_overlay),
        )
        candidate = ArmSpec(
            label=candidate_receipt.label,
            receipt=candidate_receipt,
            environment=_load_overlay(args.candidate_overlay),
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
                store_seed_dir=args.store_seed_dir,
                active_store_dir=args.active_store_dir,
            )
        except CampaignEvidenceError as error:
            print(
                json.dumps(error.artifact, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(artifact, indent=2, sort_keys=True))
        return 0
    if args.command == "publish":
        artifact = publish_accepted_artifact(
            args.source,
            args.destination,
        )
        print(json.dumps(artifact, indent=2, sort_keys=True))
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
