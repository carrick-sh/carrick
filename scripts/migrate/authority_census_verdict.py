"""Consume Rust source-census verdicts; never infer Rust scope in Python."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class CensusError(Exception):
    """Missing, stale, or rejected Rust census input."""


class CensusVerdict:
    def __init__(self, data, *, allow_historical_snapshot=False):
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
        if data.get("dialect") != "strict" and not (
            allow_historical_snapshot
            and data.get("dialect") == "historical_base"
            and not (
                Path(data["root"]) / "scripts/migrate/authority-debt-ceilings.json"
            ).exists()
        ):
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
        if paths != self.data["files"].keys():
            raise CensusError("stale Rust census verdict: source file set changed")
        for file in paths:
            self._file(file, (root / file).read_text())

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
        return "".join(chars)


def require(verdict):
    if not isinstance(verdict, CensusVerdict):
        raise CensusError("missing Rust census verdict")
    return verdict
