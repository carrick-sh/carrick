#!/usr/bin/env python3
"""Build pinned LTP static-musl binaries inside a Carrick-native container."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

DEFAULT_REF = "20260529"
DEFAULT_TAG = "carrick-ltp-native-built:20260529"
DEFAULT_BUILD_JOBS = 8


def positive_jobs(value: str) -> int:
    jobs = int(value)
    if jobs < 1:
        raise argparse.ArgumentTypeError("build jobs must be at least 1")
    return jobs


def host_nameserver() -> str:
    try:
        lines = Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines()
    except OSError:
        return "1.1.1.1"
    for line in lines:
        fields = line.split()
        if len(fields) == 2 and fields[0] == "nameserver" and fields[1] not in {"127.0.0.1", "::1"}:
            return fields[1]
    return "1.1.1.1"


def archive_source(source: Path, ref: str, destination: Path) -> None:
    with destination.open("wb") as output:
        archive = subprocess.run(
            ["git", "-C", str(source), "archive", "--format=tar", ref],
            stdout=output,
            check=False,
        )
    if archive.returncode != 0:
        destination.unlink(missing_ok=True)
        raise OSError(f"archive LTP ref {ref!r} failed: git={archive.returncode}")


def carrick_build_command(
    carrick: Path,
    *,
    tag: str,
    dns: str,
    jobs: int,
    context: Path,
    archive: Path | None,
) -> list[str]:
    command = [
        str(carrick),
        "build",
        "--platform",
        "linux/amd64",
        "--tag",
        tag,
        "--build-arg",
        f"CARRICK_DNS={dns}",
        "--build-arg",
        f"LTP_BUILD_JOBS={jobs}",
    ]
    if archive is not None:
        command.extend(["--output", str(archive)])
    command.append(str(context))
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--carrick", type=Path, default=repo / "target/release/carrick")
    parser.add_argument("--ltp-source", type=Path, required=True)
    parser.add_argument("--ltp-ref", default=DEFAULT_REF)
    parser.add_argument("--dns", default=host_nameserver())
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument(
        "--jobs",
        type=positive_jobs,
        default=DEFAULT_BUILD_JOBS,
        help="bounded LTP compiler jobs inside Carrick (default: %(default)s)",
    )
    parser.add_argument(
        "--archive",
        type=Path,
        help="preserve the exact kaniko Docker archive at this path",
    )
    parser.add_argument("--no-smoke", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo = Path(__file__).resolve().parent.parent
    carrick = args.carrick.resolve()
    source = args.ltp_source.resolve()
    archive_output = args.archive.expanduser().resolve() if args.archive else None
    dockerfile = repo / "docker/ltp-native-musl/Dockerfile"
    if not carrick.is_file():
        print(f"error: missing Carrick binary: {carrick}", file=sys.stderr)
        return 2
    if not source.is_dir():
        print(f"error: missing LTP source: {source}", file=sys.stderr)
        return 2
    if archive_output is not None:
        if archive_output.exists():
            print(f"error: archive output already exists: {archive_output}", file=sys.stderr)
            return 2
        if not archive_output.parent.is_dir():
            print(
                f"error: archive output directory does not exist: {archive_output.parent}",
                file=sys.stderr,
            )
            return 2

    run_id = f"native-x86-ltp-source-image-{os.getpid()}"
    environment = os.environ.copy()
    environment.update(
        {
            "CARRICK_EXEC_BACKEND": "native",
            "CARRICK_MMAP_ARENA_GIB": "1",
            "CARRICK_RUN_ID": run_id,
        }
    )
    try:
        try:
            with tempfile.TemporaryDirectory(prefix="carrick-ltp-source-image-") as temporary:
                context = Path(temporary)
                archive_source(source, args.ltp_ref, context / "ltp.tar")
                shutil.copy2(dockerfile, context / "Dockerfile")
                build = subprocess.run(
                    carrick_build_command(
                        carrick,
                        tag=args.tag,
                        dns=args.dns,
                        jobs=args.jobs,
                        context=context,
                        archive=archive_output,
                    ),
                    env=environment,
                    check=False,
                )
                if build.returncode != 0:
                    return build.returncode
        except OSError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

        if args.no_smoke:
            return 0
        smoke = subprocess.run(
            [
                str(carrick),
                "run",
                "--exec-backend",
                "native",
                "--platform",
                "linux/amd64",
                args.tag,
            ],
            env=environment,
            check=False,
        )
        if smoke.returncode != 0:
            print(f"error: getpid01 image smoke exited {smoke.returncode}", file=sys.stderr)
        return smoke.returncode
    finally:
        subprocess.run(
            [str(repo / "scripts/sudo/kill.sh"), run_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
