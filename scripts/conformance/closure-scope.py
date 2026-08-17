#!/usr/bin/env python3
"""Freeze and check Carrick's fixed conformance-discovery scope."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "carrick-closure-scope-v1"
CLOSURE_SUITE_COUNT = 2127
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ScopeError(RuntimeError):
    """The recorded closure scope is incomplete or has drifted."""


def _sha256(path: Path) -> str:
    if not path.is_file():
        raise ScopeError(f"required file is missing: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_inventory(manifest_path: Path) -> tuple[list[str], dict[str, int], list[str]]:
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ScopeError(f"cannot read manifest {manifest_path}: {error}") from error
    suites = manifest.get("suite")
    if not isinstance(suites, list):
        raise ScopeError("manifest must contain [[suite]] rows")

    names: list[str] = []
    ecosystems: Counter[str] = Counter()
    images: set[str] = set()
    for index, suite in enumerate(suites):
        if not isinstance(suite, dict):
            raise ScopeError(f"manifest suite {index} is not a table")
        name = suite.get("name")
        ecosystem = suite.get("ecosystem")
        image = suite.get("image")
        if not all(isinstance(value, str) and value for value in (name, ecosystem, image)):
            raise ScopeError(f"manifest suite {index} lacks name/ecosystem/image")
        names.append(name)
        ecosystems[ecosystem] += 1
        images.add(image)
    if len(names) != CLOSURE_SUITE_COUNT:
        raise ScopeError(
            f"closure manifest has {len(names)} suites; expected {CLOSURE_SUITE_COUNT}"
        )
    if len(set(names)) != len(names):
        duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
        raise ScopeError(f"closure manifest contains duplicate suite names: {duplicates}")
    return sorted(names), dict(sorted(ecosystems.items())), sorted(images)


def _split_image_ref(image: str) -> tuple[str, str, str]:
    if "/" not in image:
        raise ScopeError(f"image is not an explicit registry reference: {image}")
    host, repository_and_tag = image.split("/", 1)
    if ":" not in repository_and_tag.rsplit("/", 1)[-1]:
        tag = "latest"
        repository = repository_and_tag
    else:
        repository, tag = repository_and_tag.rsplit(":", 1)
    return host, repository, tag


def _registry_digest(image: str) -> str:
    host, repository, tag = _split_image_ref(image)
    scheme = "http" if host.startswith("localhost:") or host.startswith("127.0.0.1:") else "https"
    request = urllib.request.Request(
        f"{scheme}://{host}/v2/{repository}/manifests/{tag}",
        headers={
            "Accept": ", ".join(
                [
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                ]
            )
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            digest = response.headers.get("Docker-Content-Digest")
    except (OSError, urllib.error.URLError) as error:
        raise ScopeError(f"cannot resolve registry digest for {image}: {error}") from error
    if not digest or not SHA256_RE.fullmatch(digest):
        raise ScopeError(f"registry returned no valid digest for {image}: {digest!r}")
    return digest


def resolve_images(image_refs: list[str]) -> dict[str, dict[str, Any]]:
    resolved: dict[str, dict[str, Any]] = {}
    for image in image_refs:
        try:
            output = subprocess.run(
                ["docker", "image", "inspect", image],
                check=True,
                capture_output=True,
                text=True,
            )
            rows = json.loads(output.stdout)
        except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
            raise ScopeError(f"cannot inspect Docker image {image}: {error}") from error
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ScopeError(f"Docker inspect returned malformed identity for {image}")
        docker_id = rows[0].get("Id")
        repo_digests = rows[0].get("RepoDigests") or []
        resolved[image] = {
            "docker_id": docker_id,
            "repo_digests": sorted(repo_digests),
            "registry_digest": _registry_digest(image),
        }
    return resolved


def _validate_images(
    declared_refs: list[str], images: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    if set(images) != set(declared_refs):
        missing = sorted(set(declared_refs) - set(images))
        unexpected = sorted(set(images) - set(declared_refs))
        raise ScopeError(f"image inventory drift (missing={missing}, unexpected={unexpected})")
    normalized: dict[str, dict[str, Any]] = {}
    for image in declared_refs:
        row = images[image]
        if not isinstance(row, dict):
            raise ScopeError(f"image identity for {image} is malformed")
        docker_id = row.get("docker_id")
        registry_digest = row.get("registry_digest")
        repo_digests = row.get("repo_digests")
        if not isinstance(docker_id, str) or not SHA256_RE.fullmatch(docker_id):
            raise ScopeError(f"Docker image id is unresolved for {image}")
        if not isinstance(registry_digest, str) or not SHA256_RE.fullmatch(registry_digest):
            raise ScopeError(f"registry digest is unresolved for {image}")
        if not isinstance(repo_digests, list) or not all(
            isinstance(value, str) for value in repo_digests
        ):
            raise ScopeError(f"RepoDigests are malformed for {image}")
        normalized[image] = {
            "docker_id": docker_id,
            "repo_digests": sorted(repo_digests),
            "registry_digest": registry_digest,
        }
    return normalized


def freeze_scope(
    manifest_path: Path,
    images: dict[str, dict[str, Any]],
    *,
    source_head: str,
    binary_path: Path,
) -> dict[str, Any]:
    names, ecosystem_counts, declared_images = _manifest_inventory(Path(manifest_path))
    if not re.fullmatch(r"[0-9a-f]{40,64}", source_head):
        raise ScopeError(f"source HEAD is malformed: {source_head!r}")
    return {
        "schema": SCHEMA,
        "source_head": source_head,
        "binary_sha256": _sha256(Path(binary_path)),
        "manifest_sha256": _sha256(Path(manifest_path)),
        "suite_count": len(names),
        "suite_names": names,
        "suite_counts_by_ecosystem": ecosystem_counts,
        "declared_image_refs": declared_images,
        "images": _validate_images(declared_images, images),
    }


def _git(repo_root: Path, *args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScopeError(f"git {' '.join(args)} failed: {error}") from error


def check_scope(
    scope: dict[str, Any],
    manifest_path: Path,
    images: dict[str, dict[str, Any]],
    *,
    source_head: str,
    binary_path: Path,
    repo_root: Path | None = None,
    require_clean: bool = True,
) -> None:
    if not isinstance(scope, dict):
        raise ScopeError("scope record must be a JSON object")
    expected = freeze_scope(
        Path(manifest_path),
        images,
        source_head=source_head,
        binary_path=Path(binary_path),
    )
    required = set(expected)
    if set(scope) != required:
        raise ScopeError(
            f"scope fields drifted (missing={sorted(required - set(scope))}, "
            f"unexpected={sorted(set(scope) - required)})"
        )
    # source_head is provenance for the frozen binary. The scope file itself is
    # committed after that artifact exists, so current HEAD cannot equal it by
    # construction; live source cleanliness is checked independently below.
    for key, value in expected.items():
        if key != "source_head" and scope.get(key) != value:
            raise ScopeError(f"scope drift in {key}")
    if not isinstance(scope.get("source_head"), str) or not re.fullmatch(
        r"[0-9a-f]{40,64}", scope["source_head"]
    ):
        raise ScopeError("recorded source_head is malformed")
    if require_clean:
        if repo_root is None:
            raise ScopeError("repo_root is required for a clean-source check")
        if _git(repo_root, "status", "--porcelain"):
            raise ScopeError("source worktree is dirty")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    root = _repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["freeze", "check"])
    parser.add_argument("scope", type=Path)
    parser.add_argument(
        "--manifest", type=Path, default=root / "scripts/conformance/suites.toml"
    )
    parser.add_argument("--binary", type=Path, default=root / "target/release/carrick")
    args = parser.parse_args(argv)
    try:
        names, _, image_refs = _manifest_inventory(args.manifest)
        if len(names) != CLOSURE_SUITE_COUNT:  # defensive; inventory already checks
            raise ScopeError("unexpected closure suite count")
        identities = resolve_images(image_refs)
        head = _git(root, "rev-parse", "HEAD")
        if args.action == "freeze":
            scope = freeze_scope(
                args.manifest, identities, source_head=head, binary_path=args.binary
            )
            args.scope.write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n")
            print(f"froze {scope['suite_count']} suites in {args.scope}")
        else:
            try:
                scope = json.loads(args.scope.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ScopeError(f"cannot read scope record {args.scope}: {error}") from error
            check_scope(
                scope,
                args.manifest,
                identities,
                source_head=head,
                binary_path=args.binary,
                repo_root=root,
            )
            print(f"closure scope checked: {scope['suite_count']} suites")
    except ScopeError as error:
        print(f"closure scope error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
