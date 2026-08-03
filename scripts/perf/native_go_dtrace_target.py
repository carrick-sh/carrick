#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import marshal
import sys


_module_frame = sys._getframe()
LOADED_MODULE_CODE = {
    "digest_method": "sha256-canonical-marshal-roundtrip-v1",
    "filename": _module_frame.f_code.co_filename,
    "flags": _module_frame.f_code.co_flags,
    "marshal_sha256": hashlib.sha256(
        marshal.dumps(marshal.loads(marshal.dumps(_module_frame.f_code)))
    ).hexdigest(),
    "marshal_version": marshal.version,
    "optimize": sys.flags.optimize,
    "python_cache_tag": sys.implementation.cache_tag,
}
del _module_frame


__doc__ = """Stable DTrace target launcher for the canonical native Go workload.

Darwin DTrace may reject an ``env``/``execve`` target transition. Keeping this
Python process alive while Carrick runs as its child gives D scripts one stable
``$target`` for attach workflows. Standalone capture instead makes the signed
Carrick binary the direct ``$target`` while keeping controls explicit.
"""


import argparse
import base64
import dataclasses
import json
import os
import pathlib
import re
import signal
import subprocess
import time


REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scripts.perf.native_go_build import (
    DEFAULT_IMAGE,
    ENGINE_CARRICK,
    VARIANT_DEFAULT,
    VARIANT_SHARED,
    RegistryTransport,
    build_command,
    guest_script,
    variant_environment,
    workload_ns_from_stdout,
)
from scripts.perf import native_pc_range_directional, native_pc_range_risk


METADATA_MODE_MAPPED = "mapped"
METADATA_MODE_V2 = "v2"
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,39}")
DIRECT_DTRACE_ARG_PATTERN = re.compile(r"[A-Za-z0-9_./:=,+@%-]+")
DTRACE_DIAGNOSTIC_PATTERNS = (
    re.compile(r"(?im)^dtrace:\s"),
    re.compile(r"(?i)failed to start process notifications"),
    re.compile(r"(?im)^\s*\d+\s+drops?\b"),
)
TRACE_CHILD_IDENTITY = re.compile(
    r"^TRACECHILD1\|euid=(\d+)\|egid=(\d+)\|groups=([0-9,]*)$"
)

@dataclasses.dataclass(frozen=True)
class TraceIdentity:
    euid: int
    egid: int
    supplementary_gids: tuple[int, ...]

    @classmethod
    def current(cls) -> TraceIdentity:
        return cls(os.geteuid(), os.getegid(), tuple(os.getgroups()))

    def receipt(self) -> dict[str, object]:
        return {
            "euid": self.euid,
            "egid": self.egid,
            "supplementary_gids": sorted(set(self.supplementary_gids)),
        }


def validate_run_id(run_id: str) -> str:
    """Apply the established conservative native-capture run-ID grammar."""
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError(
            "run ID must be 1-40 conservative alphanumeric/hyphen characters"
        )
    return run_id


def environment_for(*, metadata_mode: str) -> dict[str, str | None]:
    if metadata_mode == METADATA_MODE_MAPPED:
        value = None
    elif metadata_mode == METADATA_MODE_V2:
        value = "0"
    else:
        raise ValueError(f"unknown metadata mode: {metadata_mode}")
    return {"CARRICK_DSR_SHARED_MAPPED_METADATA": value}


def carrick_trace_command(
    command: list[str],
    *,
    run_id: str,
    overlay: dict[str, str | None],
    trace_script: pathlib.Path,
    trace_output: pathlib.Path,
) -> list[str]:
    """Wrap the canonical Carrick run in its supported libdtrace launcher."""
    if len(command) < 2 or command[1] != "run":
        raise ValueError("Carrick trace requires a canonical Carrick run command")
    traced = [
        command[0],
        "trace",
        "--script",
        str(trace_script),
        "--trace-out",
        str(trace_output),
        "--forward-env",
        f"CARRICK_RUN_ID={run_id}",
    ]
    for key, value in overlay.items():
        if value is not None:
            traced.extend(("--forward-env", f"{key}={value}"))
    traced.extend(("--", *command[1:]))
    return traced


def direct_carrick_command(
    command: list[str],
    *,
    run_id: str,
    overlay: dict[str, str | None],
    identity: TraceIdentity | None = None,
) -> list[str]:
    """Forward scrubbed controls into a direct Carrick DTrace target."""
    if len(command) < 2 or command[1] != "run":
        raise ValueError("direct tracing requires a canonical Carrick run command")
    selected_identity = identity or TraceIdentity.current()
    direct_run = [
        command[0],
        "__trace-child",
        "--trace-uid",
        str(selected_identity.euid),
        "--trace-gid",
        str(selected_identity.egid),
    ]
    if selected_identity.supplementary_gids:
        direct_run.extend(
            (
                "--trace-groups",
                ",".join(str(gid) for gid in selected_identity.supplementary_gids),
            )
        )
    direct_run.extend(
        (
            "--",
            "run",
        )
    )
    direct_run.extend(
        (
            "--forward-env",
            f"CARRICK_RUN_ID={run_id}",
        )
    )
    for key, value in overlay.items():
        if value is not None:
            direct_run.extend(("--forward-env", f"{key}={value}"))
    direct_run.extend(command[2:])
    return direct_run


def standalone_dtrace_command(
    command: list[str],
    *,
    run_id: str,
    overlay: dict[str, str | None],
    trace_script: pathlib.Path,
    trace_output: pathlib.Path,
    identity: TraceIdentity | None = None,
) -> list[str]:
    """Launch DTrace with Carrick as ``$target`` and no quoted argv fields."""
    direct_run = direct_carrick_command(
        command,
        run_id=run_id,
        overlay=overlay,
        identity=identity,
    )
    if direct_run[-3:-1] != ["/bin/sh", "-c"]:
        raise ValueError("standalone DTrace requires the canonical guest shell")
    guest_script = direct_run[-1].encode()
    payload = base64.b64encode(guest_script).decode()
    direct_run[-1] = (
        "eval${IFS}$(printf${IFS}%s${IFS}"
        + payload
        + "|base64${IFS}-d)"
    )
    unsafe_fields = [
        field
        for field in direct_run[:-1]
        if DIRECT_DTRACE_ARG_PATTERN.fullmatch(field) is None
    ]
    if unsafe_fields:
        raise ValueError("direct DTrace argv contains an unsafe dynamic field")
    return [
        "sudo",
        "-n",
        "/usr/sbin/dtrace",
        "-q",
        "-s",
        str(trace_script),
        "-o",
        str(trace_output),
        "-c",
        " ".join(direct_run),
    ]


def _retained_artifact(path: pathlib.Path) -> dict[str, object]:
    return native_pc_range_risk._artifact(path)


def _capture_paths(trace_output: pathlib.Path) -> dict[str, pathlib.Path]:
    return {
        "raw": trace_output,
        "driver_stdout": trace_output.with_suffix(".driver.out"),
        "driver_stderr": trace_output.with_suffix(".driver.err"),
        "analysis": trace_output.with_suffix(".json"),
        "receipt": trace_output.with_suffix(".capture.json"),
    }


def _invalidate_capture_outputs(trace_output: pathlib.Path) -> None:
    paths = _capture_paths(trace_output)
    for role in ("receipt", "analysis", "driver_stderr", "driver_stdout", "raw"):
        paths[role].unlink(missing_ok=True)


def _execution_identity(
    *, binary: pathlib.Path, trace_script: pathlib.Path, overlay_path: pathlib.Path
) -> dict[str, object]:
    analyzer_path = pathlib.Path(native_pc_range_directional.__file__).resolve()
    return {
        "analyzer": {
            **native_pc_range_risk.authenticate_loaded_module_source(
                analyzer_path, native_pc_range_directional.LOADED_MODULE_CODE
            ),
            "schema": native_pc_range_directional.SCHEMA,
        },
        "binary": native_pc_range_risk.inspect_binary_identity(binary),
        "launcher": native_pc_range_risk.authenticate_loaded_module_source(
            pathlib.Path(__file__), LOADED_MODULE_CODE
        ),
        "overlay_source": _retained_artifact(overlay_path),
        "trace_script": _retained_artifact(trace_script),
    }


def _load_predecessor(
    path: pathlib.Path,
    *,
    campaign_id: str,
    pair_id: str,
    pair_ordinal: int,
    arm: str,
) -> tuple[dict[str, object], dict[str, object]]:
    payload_value, capture_artifact = native_pc_range_risk.stable_read_json(path)
    payload = payload_value
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != native_pc_range_risk.CAPTURE_SCHEMA
        or payload.get("status") != "passed"
        or payload.get("campaign_id") != campaign_id
    ):
        raise ValueError("predecessor is not a passed same-campaign v3 receipt")
    pair = payload.get("pair")
    if not isinstance(pair, dict):
        raise ValueError("predecessor pair identity is malformed")
    if arm == "candidate":
        exact = (
            pair.get("arm") == "control"
            and pair.get("ordinal") == pair_ordinal
            and pair.get("id") == pair_id
        )
    else:
        exact = (
            pair.get("arm") == "candidate"
            and pair.get("ordinal") == pair_ordinal - 1
        )
    if not exact:
        raise ValueError("predecessor arm, pair, or ordinal is not exact")
    binding = native_pc_range_risk.predecessor_binding(
        path, payload, capture_artifact
    )
    return payload, binding


def _publish_failed_capture(
    receipt_path: pathlib.Path,
    *,
    campaign_id: str | None,
    run_id: str,
    pair_id: str | None,
    pair_ordinal: int | None,
    arm: str | None,
    failures: list[str],
) -> None:
    native_pc_range_risk.atomic_write_json(
        receipt_path,
        {
            "campaign_id": campaign_id,
            "failures": failures,
            "pair": {
                "arm": arm,
                "id": pair_id,
                "order": 0 if arm == "control" else 1 if arm == "candidate" else None,
                "ordinal": pair_ordinal,
            },
            "run_id": run_id,
            "schema": native_pc_range_risk.CAPTURE_SCHEMA,
            "status": "failed",
        },
    )


def _replay(stream: object, payload: bytes) -> None:
    if not payload:
        return
    text = payload.decode("utf-8", errors="replace")
    write = getattr(stream, "write")
    write(text)
    flush = getattr(stream, "flush", None)
    if flush is not None:
        flush()


def _verify_standalone_capture(
    *,
    process: subprocess.Popen[bytes],
    trace_output: pathlib.Path,
    identity: TraceIdentity,
    run_id: str,
    metadata_mode: str,
    normalized_overlay: dict[str, str | None],
    trace_script: pathlib.Path,
    binary: pathlib.Path,
    pair_id: str,
    pair_ordinal: int,
    campaign_id: str,
    arm: str,
    predecessor_path: pathlib.Path | None,
    predecessor_binding: dict[str, object] | None,
    execution_pre: dict[str, object],
    overlay_source: dict[str, object],
    started_unix_ns: int,
) -> int:
    """Retain and fail closed over every standalone capture evidence stream."""
    stdout, stderr = process.communicate()
    paths = _capture_paths(trace_output)
    stdout_path = paths["driver_stdout"]
    stderr_path = paths["driver_stderr"]
    analysis_path = paths["analysis"]
    receipt_path = paths["receipt"]
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    _replay(sys.stdout, stdout)
    _replay(sys.stderr, stderr)

    decoded_stdout = stdout.decode("utf-8", errors="replace")
    decoded_stderr = stderr.decode("utf-8", errors="replace")
    failures: list[str] = []

    build_markers = [
        line for line in decoded_stdout.splitlines() if line.strip() == "BUILD_OK"
    ]
    if len(build_markers) != 1:
        failures.append(
            f"expected exactly one BUILD_OK marker, found {len(build_markers)}"
        )
    try:
        workload_ns = workload_ns_from_stdout(decoded_stdout)
    except ValueError as error:
        workload_ns = None
        failures.append(str(error))
    child_identity_lines = [
        line.strip()
        for line in decoded_stderr.splitlines()
        if line.startswith("TRACECHILD1|")
    ]
    observed_identity: dict[str, object] | None = None
    if len(child_identity_lines) != 1:
        failures.append(
            "expected exactly one post-drop trace-child identity record, "
            f"found {len(child_identity_lines)}"
        )
    else:
        matched = TRACE_CHILD_IDENTITY.fullmatch(child_identity_lines[0])
        if matched is None:
            failures.append("post-drop trace-child identity record is malformed")
        else:
            euid, egid, groups = matched.groups()
            observed_identity = {
                "egid": int(egid),
                "euid": int(euid),
                "supplementary_gids": (
                    [int(group) for group in groups.split(",")] if groups else []
                ),
            }
            if observed_identity != identity.receipt():
                failures.append(
                    "post-drop trace-child full identity does not match caller: "
                    f"expected={identity.receipt()} observed={observed_identity}"
                )
    guest_stderr = [
        line.strip()
        for line in decoded_stderr.splitlines()
        if line.strip()
        and not line.startswith("NATIVEPERF1|")
        and not line.startswith("TRACECHILD1|")
    ]
    if guest_stderr != ["ok"]:
        failures.append(f"expected exact guest stderr marker ['ok'], got {guest_stderr}")
    if process.returncode != 0:
        failures.append(f"DTrace exited with status {process.returncode}")

    diagnostic_text = "\n".join((decoded_stdout, decoded_stderr))
    matched_diagnostics = [
        pattern.pattern
        for pattern in DTRACE_DIAGNOSTIC_PATTERNS
        if pattern.search(diagnostic_text) is not None
    ]
    if matched_diagnostics:
        failures.append(
            "DTrace diagnostics matched forbidden predicates: "
            + ", ".join(matched_diagnostics)
        )
    if not trace_output.is_file():
        failures.append("DTrace did not retain the requested raw capture")

    analyzer_status: int | None = None
    analysis: dict[str, object] | None = None
    analysis_artifact: dict[str, object] | None = None
    raw_artifact: dict[str, object] | None = None
    if trace_output.is_file():
        analyzer_status = native_pc_range_directional.main(
            [
                "--input",
                str(trace_output),
                "--output",
                str(analysis_path),
                "--strict",
                "--expected-euid",
                str(identity.euid),
                "--expected-egid",
                str(identity.egid),
            ]
        )
        if analyzer_status != 0:
            failures.append(f"strict directional analyzer exited {analyzer_status}")
        elif analysis_path.is_file():
            analysis_value, analysis_artifact = (
                native_pc_range_risk.stable_read_json(analysis_path)
            )
            if isinstance(analysis_value, dict):
                analysis = analysis_value
            else:
                failures.append("strict directional analyzer JSON root is malformed")
        else:
            failures.append("strict directional analyzer retained no JSON receipt")
        try:
            raw_artifact = _retained_artifact(trace_output)
        except (OSError, ValueError) as error:
            failures.append(f"raw capture identity failed closed: {error}")
        if (
            analysis is not None
            and raw_artifact is not None
            and analysis.get("input_artifact") != raw_artifact
        ):
            failures.append(
                "strict directional analysis does not bind the retained raw capture"
            )

    execution_post: dict[str, object] | None = None
    try:
        execution_post = _execution_identity(
            binary=binary,
            trace_script=trace_script,
            overlay_path=native_pc_range_risk.OVERLAY_PATHS[metadata_mode],
        )
    except (OSError, ValueError) as error:
        failures.append(f"post-execution identity failed closed: {error}")
    if execution_post is not None and execution_post != execution_pre:
        failures.append("binary/script/analyzer identity drifted during execution")
    if predecessor_path is not None:
        try:
            _predecessor, observed_binding = _load_predecessor(
                predecessor_path,
                campaign_id=campaign_id,
                pair_id=pair_id,
                pair_ordinal=pair_ordinal,
                arm=arm,
            )
            if observed_binding != predecessor_binding:
                failures.append("predecessor capture drifted during execution")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            failures.append(f"post-execution predecessor authentication failed: {error}")

    required_streams: dict[str, bool] | None = None
    natural_completion = False
    if analysis is not None:
        ranges = analysis.get("ranges", {})
        host_ranges = analysis.get("host_text_ranges", {})
        samples = analysis.get("samples", {})
        leaf = analysis.get("leaf_capture", {})
        stacks = analysis.get("kernel_stack_capture", {})
        completion = analysis.get("completion")
        if all(
            isinstance(value, dict)
            for value in (ranges, host_ranges, samples, leaf, stacks)
        ):
            required_streams = {
                "host_range": host_ranges.get("reported", 0) > 0,
                "identity": analysis.get("effective_identity", {}).get("reported", 0)
                > 0,
                "kernel_pc_stack_per_catalog_exact": (
                    stacks.get("per_catalog_exact") is True
                    and stacks.get("kernel_samples") == stacks.get("stack_samples")
                ),
                "leaf_pc_exact": (
                    leaf.get("expected_outside_private_samples", 0) > 0
                    and leaf.get("expected_outside_private_samples")
                    == leaf.get("observed_outside_private_samples")
                ),
                "private_range": ranges.get("private_reported", 0) > 0,
                "reset": ranges.get("resets", 0) > 0,
                "shared_range": ranges.get("shared_reported", 0) > 0,
                "user_and_kernel_samples": (
                    samples.get("user", 0) > 0 and samples.get("kernel", 0) > 0
                ),
            }
        natural_completion = completion == {"target_exit": 1, "timed_out": 0}
    if required_streams is None or not all(required_streams.values()):
        failures.append("required stream authentication is incomplete")
    if not natural_completion:
        failures.append("capture did not authenticate exact natural completion")

    trace_script = trace_script.resolve()
    artifact_paths = {
        "raw": trace_output,
        "driver_stdout": stdout_path,
        "driver_stderr": stderr_path,
        "analysis": analysis_path,
    }
    completed_unix_ns = time.time_ns()
    receipt = {
        "analyzer": execution_pre.get("analyzer"),
        "analyzer_status": analyzer_status,
        "artifacts": {
            role: (
                analysis_artifact
                if role == "analysis" and analysis_artifact is not None
                else raw_artifact
                if role == "raw" and raw_artifact is not None
                else _retained_artifact(path)
            )
            for role, path in artifact_paths.items()
            if path.is_file()
        },
        "binary": execution_pre.get("binary"),
        "campaign_id": campaign_id,
        "chronology": {
            "completed_unix_ns": completed_unix_ns,
            "predecessor": predecessor_binding,
            "started_unix_ns": started_unix_ns,
        },
        "diagnostic_predicates": [
            pattern.pattern for pattern in DTRACE_DIAGNOSTIC_PATTERNS
        ],
        "dtrace_status": process.returncode,
        "expected_effective_identity": identity.receipt(),
        "execution_identity": {"post": execution_post, "pre": execution_pre},
        "failures": failures,
        "matched_diagnostic_predicates": matched_diagnostics,
        "metadata_mode": metadata_mode,
        "natural_completion": natural_completion,
        "normalized_overlay": normalized_overlay,
        "overlay_source": overlay_source,
        "observed_effective_identity": observed_identity,
        "pair": {
            "arm": arm,
            "id": pair_id,
            "order": 0 if arm == "control" else 1,
            "ordinal": pair_ordinal,
        },
        "required_streams": required_streams,
        "run_id": run_id,
        "schema": native_pc_range_risk.CAPTURE_SCHEMA,
        "status": "passed" if not failures else "failed",
        "trace_script": _retained_artifact(trace_script),
        "workload": {
            "guest_script_bytes": len(guest_script().encode()),
            "guest_script_sha256": hashlib.sha256(guest_script().encode()).hexdigest(),
            "image": DEFAULT_IMAGE,
        },
        "workload_ns": workload_ns,
    }
    native_pc_range_risk.atomic_write_json(receipt_path, receipt)
    if failures:
        for failure in failures:
            print(f"native_go_dtrace_target: {failure}", file=sys.stderr)
        return 2
    return 0


def _has_carrick_proctitle(command: str, run_id: str) -> bool:
    return command.lstrip().startswith(f"carrick:{run_id}:")


def _wait_for_carrick_proctitle(
    process: subprocess.Popen[bytes], run_id: str, timeout_seconds: float = 5.0
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        observed = subprocess.run(
            ["/bin/ps", "-p", str(process.pid), "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
        )
        if observed.returncode == 0 and _has_carrick_proctitle(
            observed.stdout, run_id
        ):
            return True
        time.sleep(0.005)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--variant",
        choices=(VARIANT_DEFAULT, VARIANT_SHARED),
        default=VARIANT_DEFAULT,
    )
    parser.add_argument("--run-id")
    parser.add_argument(
        "--manifest-retention",
        choices=("arc", "clone"),
        default="arc",
        help="select the default shared manifest Arc or its exact deep-clone opt-out",
    )
    parser.add_argument(
        "--metadata-mode",
        choices=(METADATA_MODE_MAPPED, METADATA_MODE_V2),
        default=METADATA_MODE_MAPPED,
        help="map immutable metadata by default or select the exact V2 opt-out",
    )
    parser.add_argument(
        "--manifest-wire",
        choices=("fixed", "varint"),
        default="fixed",
        help="select fixed-width manifest integers or the exact varint opt-out",
    )
    parser.add_argument(
        "--source-fingerprint",
        choices=("reuse", "rehash"),
        default="reuse",
        help="reuse the segment fingerprint or select the exact source-rehash opt-out",
    )
    parser.add_argument(
        "--dylib-identity",
        choices=("keyed", "rehash"),
        default="keyed",
        help="bind the signed keyed export or select the exact full-dylib rehash opt-out",
    )
    parser.add_argument(
        "--recovery-binding",
        choices=("lazy", "eager"),
        default="lazy",
        help="bind shared recovery actions on demand or select the exact eager opt-out",
    )
    parser.add_argument(
        "--recovery-wire",
        choices=("runs", "entries"),
        default="runs",
        help="store shared recovery actions as runs or select the exact entry opt-out",
    )
    parser.add_argument(
        "--stop-child",
        action="store_true",
        help="SIGSTOP Carrick immediately after spawn and print its PID for dtrace -p",
    )
    parser.add_argument(
        "--trace-script",
        type=pathlib.Path,
        help="launch the canonical run through carrick trace with this D program",
    )
    parser.add_argument(
        "--trace-output",
        type=pathlib.Path,
        help="write DTrace records to this path",
    )
    parser.add_argument(
        "--trace-launcher",
        choices=("carrick-trace", "standalone"),
        default="standalone",
        help="use carrick trace or make Carrick DTrace's direct target",
    )
    parser.add_argument(
        "--mechanism-profile",
        action="store_true",
        help="emit the NATIVEPERF mechanism counters for this run",
    )
    parser.add_argument("--pair-id")
    parser.add_argument("--pair-ordinal", type=int)
    parser.add_argument("--campaign-id")
    parser.add_argument("--arm", choices=("control", "candidate"))
    parser.add_argument("--predecessor-capture", type=pathlib.Path)
    arguments = parser.parse_args()
    if (arguments.trace_script is None) != (arguments.trace_output is None):
        parser.error("--trace-script and --trace-output must be supplied together")
    if arguments.stop_child and arguments.trace_script is not None:
        parser.error("--stop-child cannot be combined with trace mode")
    if arguments.trace_script is not None and (
        not arguments.pair_id
        or arguments.pair_ordinal is None
        or arguments.pair_ordinal <= 0
    ):
        parser.error("trace mode requires --pair-id and positive --pair-ordinal")
    standalone_capture = (
        arguments.trace_script is not None
        and arguments.trace_launcher == "standalone"
    )
    if standalone_capture and (not arguments.campaign_id or not arguments.arm):
        parser.error("standalone trace mode requires --campaign-id and --arm")
    run_id = arguments.run_id or os.environ.get("CARRICK_RUN_ID")
    if not run_id:
        parser.error("CARRICK_RUN_ID must be set")
    try:
        run_id = validate_run_id(run_id)
        if arguments.pair_id is not None:
            validate_run_id(arguments.pair_id)
        if arguments.campaign_id is not None:
            validate_run_id(arguments.campaign_id)
    except ValueError as error:
        parser.error(str(error))

    trace_identity = TraceIdentity.current()

    metadata_environment = environment_for(metadata_mode=arguments.metadata_mode)
    environment, overlay = variant_environment(
        os.environ,
        arguments.variant,
        ENGINE_CARRICK,
        {
            **metadata_environment,
            "CARRICK_DSR_PROFILE": "1" if arguments.mechanism_profile else None,
            "CARRICK_DSR_SHARED_MANIFEST_ARC": (
                "0" if arguments.manifest_retention == "clone" else None
            ),
            "CARRICK_DSR_SHARED_MANIFEST_FIXED": (
                "0" if arguments.manifest_wire == "varint" else None
            ),
            "CARRICK_DSR_SHARED_SOURCE_FINGERPRINT_REUSE": (
                "0" if arguments.source_fingerprint == "rehash" else None
            ),
            "CARRICK_DSR_SHARED_DYLIB_KEYED_IDENTITY": (
                "0" if arguments.dylib_identity == "rehash" else None
            ),
            "CARRICK_DSR_SHARED_RECOVERY_LAZY": (
                "0" if arguments.recovery_binding == "eager" else None
            ),
            "CARRICK_DSR_SHARED_RECOVERY_RUNS": (
                "0" if arguments.recovery_wire == "entries" else None
            ),
        },
    )
    environment["CARRICK_RUN_ID"] = run_id
    print(
        "TARGET_PROVENANCE="
        + json.dumps(
            {
                "metadata_mode": arguments.metadata_mode,
                "environment_overlay": overlay,
                "expected_effective_identity": trace_identity.receipt(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    command = build_command(
        REPO,
        ENGINE_CARRICK,
        run_id,
        binary=REPO / "target/release/carrick",
        registry_transport=RegistryTransport("localhost:5005", True),
    )
    execution_pre: dict[str, object] | None = None
    overlay_source: dict[str, object] | None = None
    predecessor_binding: dict[str, object] | None = None
    started_unix_ns: int | None = None
    if standalone_capture:
        assert arguments.trace_output is not None
        assert arguments.trace_script is not None
        assert arguments.campaign_id is not None
        assert arguments.arm is not None
        assert arguments.pair_id is not None
        assert arguments.pair_ordinal is not None
        paths = _capture_paths(arguments.trace_output)
        try:
            _invalidate_capture_outputs(arguments.trace_output)
            overlay_source, expected_overlay = native_pc_range_risk.expected_capture_overlay(
                arguments.metadata_mode
            )
            if overlay != expected_overlay:
                raise ValueError(
                    "standalone capture requires the exact overlay authority, including "
                    "CARRICK_DSR_PERSISTENT_STORE=1, CARRICK_DSR_DIRECT_BINDINGS=1, "
                    "and CARRICK_DSR_PROFILE=1"
                )
            expected_arm = (
                "control"
                if arguments.metadata_mode == METADATA_MODE_V2
                else "candidate"
            )
            if arguments.arm != expected_arm:
                raise ValueError("capture arm does not match metadata mode")
            if arguments.arm == "control" and arguments.pair_ordinal == 1:
                if arguments.predecessor_capture is not None:
                    raise ValueError("pair-one control is the sole root and has no predecessor")
            else:
                if arguments.predecessor_capture is None:
                    raise ValueError("non-root capture requires --predecessor-capture")
                _predecessor, predecessor_binding = _load_predecessor(
                    arguments.predecessor_capture,
                    campaign_id=arguments.campaign_id,
                    pair_id=arguments.pair_id,
                    pair_ordinal=arguments.pair_ordinal,
                    arm=arguments.arm,
                )
            started_unix_ns = time.time_ns()
            if (
                predecessor_binding is not None
                and int(predecessor_binding["completed_unix_ns"]) >= started_unix_ns
            ):
                raise ValueError("predecessor does not complete before capture start")
            execution_pre = _execution_identity(
                binary=REPO / "target/release/carrick",
                trace_script=arguments.trace_script,
                overlay_path=native_pc_range_risk.OVERLAY_PATHS[
                    arguments.metadata_mode
                ],
            )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            try:
                _publish_failed_capture(
                    paths["receipt"],
                    campaign_id=arguments.campaign_id,
                    run_id=run_id,
                    pair_id=arguments.pair_id,
                    pair_ordinal=arguments.pair_ordinal,
                    arm=arguments.arm,
                    failures=[str(error)],
                )
            except OSError as write_error:
                print(
                    f"native_go_dtrace_target: could not publish failed receipt: {write_error}",
                    file=sys.stderr,
                )
            print(f"native_go_dtrace_target: {error}", file=sys.stderr)
            return 2
    if arguments.trace_script is not None:
        if arguments.trace_launcher == "standalone":
            command = standalone_dtrace_command(
                command,
                run_id=run_id,
                overlay=overlay,
                trace_script=arguments.trace_script,
                trace_output=arguments.trace_output,
                identity=trace_identity,
            )
        else:
            command = carrick_trace_command(
                command,
                run_id=run_id,
                overlay=overlay,
                trace_script=arguments.trace_script,
                trace_output=arguments.trace_output,
            )
    try:
        process = subprocess.Popen(
            command,
            cwd=REPO,
            env=environment,
            **(
                {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
                if standalone_capture
                else {}
            ),
        )
    except OSError as error:
        if standalone_capture:
            assert arguments.trace_output is not None
            _publish_failed_capture(
                _capture_paths(arguments.trace_output)["receipt"],
                campaign_id=arguments.campaign_id,
                run_id=run_id,
                pair_id=arguments.pair_id,
                pair_ordinal=arguments.pair_ordinal,
                arm=arguments.arm,
                failures=[f"capture process launch failed: {error}"],
            )
            return 2
        raise
    if standalone_capture:
        assert arguments.trace_output is not None
        assert arguments.campaign_id is not None
        assert arguments.arm is not None
        assert execution_pre is not None
        assert overlay_source is not None
        assert started_unix_ns is not None
        try:
            return _verify_standalone_capture(
                process=process,
                trace_output=arguments.trace_output,
                identity=trace_identity,
                run_id=run_id,
                metadata_mode=arguments.metadata_mode,
                normalized_overlay=overlay,
                trace_script=arguments.trace_script,
                binary=REPO / "target/release/carrick",
                pair_id=arguments.pair_id,
                pair_ordinal=arguments.pair_ordinal,
                campaign_id=arguments.campaign_id,
                arm=arguments.arm,
                predecessor_path=arguments.predecessor_capture,
                predecessor_binding=predecessor_binding,
                execution_pre=execution_pre,
                overlay_source=overlay_source,
                started_unix_ns=started_unix_ns,
            )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            try:
                _publish_failed_capture(
                    _capture_paths(arguments.trace_output)["receipt"],
                    campaign_id=arguments.campaign_id,
                    run_id=run_id,
                    pair_id=arguments.pair_id,
                    pair_ordinal=arguments.pair_ordinal,
                    arm=arguments.arm,
                    failures=[f"capture verification failed: {error}"],
                )
            except OSError as write_error:
                print(
                    f"native_go_dtrace_target: could not publish failed receipt: {write_error}",
                    file=sys.stderr,
                )
            print(f"native_go_dtrace_target: {error}", file=sys.stderr)
            return 2
    if arguments.stop_child:
        if not _wait_for_carrick_proctitle(process, run_id):
            process.terminate()
            process.wait()
            parser.error("Carrick did not publish its traceable proctitle")
        os.kill(process.pid, signal.SIGSTOP)
        print(f"TARGET_PID={process.pid}", flush=True)
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
