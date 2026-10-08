"""Consume Rust source-census verdicts; never infer Rust scope in Python."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path


class CensusError(Exception):
    """Missing, stale, or rejected Rust census input."""


class CensusVerdict:
    def __init__(self, data):
        if not isinstance(data, dict) or data.get("schema") != 1:
            raise CensusError("missing or unsupported Rust census verdict")
        if data.get("rejections"):
            raise CensusError("\n".join(data["rejections"]))
        if (
            data.get("rejections") != []
            or not data.get("inputs")
            or "files" not in data
        ):
            raise CensusError("missing Rust census verdict fields")
        if data.get("dialect") != "strict":
            raise CensusError("strict Rust dialect verdict required")
        self.data = data
        self._validate_policy()

    def _validate_policy(self):
        for file, digest in self.data["inputs"].items():
            path = Path(self.data["tool_root"]) / file
            if (
                not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest
            ):
                raise CensusError(f"stale Rust census policy: {file}")

    @classmethod
    def load(cls, path):
        if path is None:
            raise CensusError("missing Rust census verdict; supply --census-verdict")
        try:
            return cls(json.loads(Path(path).read_text()))
        except (OSError, ValueError) as error:
            raise CensusError(
                f"missing or invalid Rust census verdict: {error}"
            ) from error

    def validate_tree(self, root):
        self._validate_policy()
        root = Path(root).resolve()
        if root != Path(self.data["root"]):
            raise CensusError("stale Rust census verdict: tree root changed")
        paths = {
            p.relative_to(root).as_posix()
            for p in (root / "crates").glob("*/src/**/*.rs")
            if p.is_file() and p.relative_to(root).parts[1] != "carrick-xtask"
        }
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"],
            cwd=root, capture_output=True, text=True, check=True,
        )
        metadata = json.loads(result.stdout)
        members = set(metadata["workspace_members"])
        build_roots = sorted(
            ({"package": package["name"], "source": str(Path(target["src_path"]).resolve().relative_to(root))}
             for package in metadata["packages"] if package["id"] in members
             for target in package["targets"] if "custom-build" in target["kind"]),
            key=lambda entry: (entry["package"], entry["source"]),
        )
        if build_roots != self.data.get("build_roots"):
            raise CensusError("stale Rust census verdict: Cargo build targets changed")
        build_files = {file for file, record in self.data["files"].items() if record.get("boundary") == "build_time"}
        if paths & build_files:
            raise CensusError("build-time/production source overlap")
        if any(entry["source"] not in build_files for entry in build_roots):
            raise CensusError("missing build target source verdict")
        paths |= build_files
        if paths != self.data["files"].keys():
            raise CensusError("stale Rust census verdict: source file set changed")
        for file in paths:
            self._file(file, (root / file).read_text())

    def source_paths(self, root):
        return [Path(root) / file for file in sorted(self.data["files"])]

    def is_build_file(self, file):
        return self.data["files"].get(file, {}).get("boundary") == "build_time"

    def _file(self, file, source):
        file = Path(file).as_posix()
        record = self.data["files"].get(file)
        if record is None:
            raise CensusError(f"missing Rust census file verdict: {file}")
        if hashlib.sha256(source.encode()).hexdigest() != record.get("sha256"):
            raise CensusError(f"stale Rust census source: {file}")
        return record

    def production_source(self, file, source):
        record = self._file(file, source)
        if record.get("production") is False:
            return "".join(c if c in "\r\n" else " " for c in source)
        if record.get("production") is not True or not isinstance(
            record.get("items"), list
        ):
            raise CensusError(f"missing Rust census classification: {file}")
        encoded = source.encode()
        chars = list(source)
        for item in record["items"]:
            if item.get("production") is True:
                continue
            if item.get("production") is not False:
                raise CensusError(f"missing Rust census item classification: {file}")
            start, end = item["start"], item["end"]
            if not 0 <= start <= end <= len(encoded):
                raise CensusError(f"invalid Rust census item range: {file}")
            # Rust supplies byte offsets; keep Python character positions and
            # line breaks stable, including non-ASCII source and comments.
            left = len(encoded[:start].decode())
            right = len(encoded[:end].decode())
            chars[left:right] = [c if c in "\r\n" else " " for c in chars[left:right]]
        calls = record.get("canonical_calls")
        if not isinstance(calls, list):
            raise CensusError(f"missing Rust canonical call classification: {file}")
        canonical = []
        for call in calls:
            start, end, path = call["start"], call["end"], call["path"]
            if not 0 <= start < end <= len(encoded) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*(?:::[a-zA-Z_][a-zA-Z_0-9]*)+", path):
                raise CensusError(f"invalid Rust canonical call range: {file}")
            left, right = len(encoded[:start].decode()), len(encoded[:end].decode())
            # Excluded scopes remain spaces; their calls cannot seed patterns.
            if any(c != " " for c in chars[left:right]):
                canonical.append((left, right, path))
        return ProductionSource("".join(chars), canonical)


def require(verdict):
    if not isinstance(verdict, CensusVerdict):
        raise CensusError("missing Rust census verdict")
    return verdict


class ProductionSource(str):
    """Source text with Rust-resolved call heads; original offsets are stable."""
    def __new__(cls, source, canonical):
        result = super().__new__(cls, source)
        result.canonical_calls = canonical
        return result


def canonical_tokens(tokens, source):
    """Apply the Rust verdict verbatim; no Python binding/scope resolution."""
    calls = getattr(source, "canonical_calls", ())
    if not calls:
        return tokens
    by_start = {start: (end, path) for start, end, path in calls}
    output = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        call = by_start.get(token.pos)
        if call is None:
            output.append(token)
            index += 1
            continue
        end, path = call
        while index < len(tokens) and tokens[index].pos < end:
            index += 1
        for spelling in re.findall(r"[a-zA-Z_][a-zA-Z_0-9]*|::", path):
            # Each scanner retains its own token-kind convention.
            kind = ("PUNCT" if token.kind.isupper() else "punct") if spelling == "::" else token.kind
            output.append(replace(token, text=spelling, kind=kind))
    return output
