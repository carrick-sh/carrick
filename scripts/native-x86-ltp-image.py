#!/usr/bin/env python3
"""Package static-musl LTP binaries with Carrick's native Kaniko builder.

This does not use Podman as an execution oracle. The input binaries are already
cross-built Linux/amd64 static ELFs; Carrick runs Kaniko natively to create a
scratch OCI image, then optionally runs getpid01 as an end-to-end smoke test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

FIXTURE = "ltp-20260529-x86_64-musl-static-pie"
DEFAULT_TAG = "carrick-ltp-static-musl:20260529"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def executable_files(root: Path) -> list[Path]:
    binaries = [
        path
        for path in root.glob("*/*")
        if path.is_file() and path.stat().st_mode & stat.S_IXUSR
    ]
    binaries.sort(key=lambda path: (path.name, str(path)))
    names: set[str] = set()
    for binary in binaries:
        if binary.name in names:
            raise ValueError(f"duplicate flattened LTP binary name: {binary.name}")
        names.add(binary.name)
    if not binaries:
        raise ValueError(f"no executable LTP binaries below {root}")
    return binaries


def prepare_context(context: Path, ltp_root: Path, rootfs: Path) -> dict[str, object]:
    image_root = context / "rootfs"
    image_bin = image_root / "bin"
    image_ltp = image_root / "opt/ltp/testcases/bin"
    (image_root / "tmp").mkdir(parents=True)
    image_bin.mkdir(parents=True)
    image_ltp.mkdir(parents=True)

    helper_hashes: dict[str, str] = {}
    for helper in ("sh", "zcat"):
        source = rootfs / "bin" / helper
        if not source.is_file():
            raise FileNotFoundError(f"prepared rootfs is missing {source}")
        shutil.copy2(source, image_bin / helper)
        helper_hashes[f"bin/{helper}"] = sha256_file(source)

    binary_hashes: dict[str, str] = {}
    for source in executable_files(ltp_root):
        shutil.copy2(source, image_ltp / source.name)
        binary_hashes[source.name] = sha256_file(source)

    manifest: dict[str, object] = {
        "schema": 1,
        "fixture": FIXTURE,
        "platform": "linux/amd64",
        "binaries_sha256": binary_hashes,
        "helpers_sha256": helper_hashes,
    }
    manifest_path = image_root / "opt/ltp/carrick-static-musl-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (context / "Dockerfile").write_text(
        "FROM scratch\n"
        "COPY rootfs /\n"
        'CMD ["/opt/ltp/testcases/bin/getpid01"]\n',
        encoding="utf-8",
    )
    return manifest


def parse_args(argv: list[str]) -> argparse.Namespace:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--carrick", type=Path, default=repo / "target/debug/carrick")
    parser.add_argument("--ltp-bin-root", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument("--no-smoke", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    carrick = args.carrick.resolve()
    ltp_root = args.ltp_bin_root.resolve()
    rootfs = args.rootfs.resolve()
    if not carrick.is_file():
        print(f"error: missing Carrick binary: {carrick}", file=sys.stderr)
        return 2
    if not ltp_root.is_dir():
        print(f"error: missing LTP binary root: {ltp_root}", file=sys.stderr)
        return 2
    if not rootfs.is_dir():
        print(f"error: missing prepared rootfs: {rootfs}", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment.update(
        {
            "CARRICK_EXEC_BACKEND": "native",
            "CARRICK_MMAP_ARENA_GIB": "1",
            "CARRICK_RUN_ID": f"native-x86-ltp-image-{os.getpid()}",
        }
    )
    try:
        with tempfile.TemporaryDirectory(prefix="carrick-ltp-image-") as temporary:
            context = Path(temporary)
            manifest = prepare_context(context, ltp_root, rootfs)
            print(
                f"packaging {len(manifest['binaries_sha256'])} static LTP binaries as {args.tag}",
                file=sys.stderr,
            )
            build = subprocess.run(
                [
                    str(carrick),
                    "build",
                    "--platform",
                    "linux/amd64",
                    "--tag",
                    args.tag,
                    str(context),
                ],
                env=environment,
                check=False,
            )
            if build.returncode != 0:
                return build.returncode
    except (OSError, ValueError) as error:
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
