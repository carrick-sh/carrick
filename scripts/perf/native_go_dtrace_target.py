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
import json
import os
import pathlib
import signal
import subprocess
import sys
import time


REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scripts.perf.native_go_build import (
    ENGINE_CARRICK,
    VARIANT_DEFAULT,
    VARIANT_SHARED,
    RegistryTransport,
    build_command,
    variant_environment,
)


METADATA_MODE_MAPPED = "mapped"
METADATA_MODE_V2 = "v2"


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
) -> list[str]:
    """Forward scrubbed controls into a direct Carrick DTrace target."""
    if len(command) < 2 or command[1] != "run":
        raise ValueError("direct tracing requires a canonical Carrick run command")
    direct_run = [
        command[0],
        "run",
        "--forward-env",
        f"CARRICK_RUN_ID={run_id}",
    ]
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
) -> list[str]:
    """Launch DTrace with Carrick as ``$target`` and no quoted argv fields."""
    direct_run = direct_carrick_command(command, run_id=run_id, overlay=overlay)
    if direct_run[-3:-1] != ["/bin/sh", "-c"]:
        raise ValueError("standalone DTrace requires the canonical guest shell")
    guest_script = direct_run[-1].encode()
    payload = base64.b64encode(guest_script).decode()
    direct_run[-1] = (
        "eval${IFS}$(printf${IFS}%s${IFS}"
        + payload
        + "|base64${IFS}-d)"
    )
    if any(any(character.isspace() for character in field) for field in direct_run):
        raise ValueError("standalone DTrace command contains a quoted argv field")
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
        default="carrick-trace",
        help="use carrick trace or make Carrick DTrace's direct target",
    )
    parser.add_argument(
        "--mechanism-profile",
        action="store_true",
        help="emit the NATIVEPERF mechanism counters for this run",
    )
    arguments = parser.parse_args()
    if (arguments.trace_script is None) != (arguments.trace_output is None):
        parser.error("--trace-script and --trace-output must be supplied together")
    if arguments.stop_child and arguments.trace_script is not None:
        parser.error("--stop-child cannot be combined with trace mode")
    run_id = arguments.run_id or os.environ.get("CARRICK_RUN_ID")
    if not run_id:
        parser.error("CARRICK_RUN_ID must be set")

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
            )
        else:
            command = carrick_trace_command(
                command,
                run_id=run_id,
                overlay=overlay,
                trace_script=arguments.trace_script,
                trace_output=arguments.trace_output,
            )
    process = subprocess.Popen(command, cwd=REPO, env=environment)
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
