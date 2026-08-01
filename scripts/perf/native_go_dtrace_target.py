#!/usr/bin/env python3
"""Stable DTrace target launcher for the canonical native Go workload.

Darwin DTrace may reject an ``env``/``execve`` target transition. Keeping this
Python process alive while Carrick runs as its child gives D scripts one stable
``$target`` for attach workflows. Standalone capture instead makes the signed
Carrick binary the direct ``$target`` while keeping controls explicit.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
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


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _retained_artifact(path: pathlib.Path) -> dict[str, object]:
    absolute = path.resolve()
    return {
        "bytes": absolute.stat().st_size,
        "path": str(absolute),
        "sha256": _sha256(absolute),
    }


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
) -> int:
    """Retain and fail closed over every standalone capture evidence stream."""
    stdout, stderr = process.communicate()
    stdout_path = trace_output.with_suffix(".driver.out")
    stderr_path = trace_output.with_suffix(".driver.err")
    analysis_path = trace_output.with_suffix(".json")
    receipt_path = trace_output.with_suffix(".capture.json")
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
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        else:
            failures.append("strict directional analyzer retained no JSON receipt")

    binary_identity: dict[str, object] | None = None
    try:
        binary_identity = native_pc_range_risk.inspect_binary_identity(binary)
    except (OSError, ValueError) as error:
        failures.append(f"producing binary identity failed closed: {error}")

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

    analyzer_path = pathlib.Path(native_pc_range_directional.__file__).resolve()
    trace_script = trace_script.resolve()
    artifact_paths = {
        "raw": trace_output,
        "driver_stdout": stdout_path,
        "driver_stderr": stderr_path,
        "analysis": analysis_path,
    }
    arm = "control" if metadata_mode == METADATA_MODE_V2 else "candidate"
    receipt = {
        "analyzer": {
            **_retained_artifact(analyzer_path),
            "schema": native_pc_range_directional.SCHEMA,
        },
        "analyzer_status": analyzer_status,
        "artifacts": {
            role: _retained_artifact(path)
            for role, path in artifact_paths.items()
            if path.is_file()
        },
        "binary": binary_identity,
        "diagnostic_predicates": [
            pattern.pattern for pattern in DTRACE_DIAGNOSTIC_PATTERNS
        ],
        "dtrace_status": process.returncode,
        "expected_effective_identity": identity.receipt(),
        "failures": failures,
        "matched_diagnostic_predicates": matched_diagnostics,
        "metadata_mode": metadata_mode,
        "natural_completion": natural_completion,
        "normalized_overlay": normalized_overlay,
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
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
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
    run_id = arguments.run_id or os.environ.get("CARRICK_RUN_ID")
    if not run_id:
        parser.error("CARRICK_RUN_ID must be set")
    try:
        run_id = validate_run_id(run_id)
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
    standalone_capture = (
        arguments.trace_script is not None
        and arguments.trace_launcher == "standalone"
    )
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
    if standalone_capture:
        assert arguments.trace_output is not None
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
        )
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
