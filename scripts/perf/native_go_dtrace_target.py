#!/usr/bin/env python3
"""Stable DTrace target parent for the canonical native Go workload.

Darwin DTrace may reject an ``env``/``execve`` target transition. Keeping this
Python process alive while Carrick runs as its child gives D scripts one stable
``$target`` and keeps variant controls explicit and auditable.
"""

from __future__ import annotations

import argparse
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
    arguments = parser.parse_args()
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
