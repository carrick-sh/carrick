#!/usr/bin/env python3
"""Reject a second Carrick-owned pipe byte-ring outside carrick-pipe-core."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PIPE_TYPE = re.compile(r"\bstruct\s+([A-Za-z0-9_]*(?:Pipe|Fifo)[A-Za-z0-9_]*)\s*\{", re.I)
BYTE_DEQUE = re.compile(r"\bVecDeque\s*<\s*u8\s*>")
BYTE_STORAGE = re.compile(r"(?:\bVec\s*<\s*u8\s*>|\bBox\s*<\s*\[\s*u8\s*\]\s*>|\[\s*u8\s*;)")
RING_INDEX = re.compile(r"\b(?:head|tail|read_pos|write_pos|capacity)\s*:\s*usize\b")


def matching_brace(source: str, opening: int) -> int:
    depth = 0
    for offset, char in enumerate(source[opening:], opening):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return offset
    return len(source)


def findings(path: Path, source: str) -> list[str]:
    found = []
    for match in PIPE_TYPE.finditer(source):
        opening = source.find("{", match.start())
        body = source[opening : matching_brace(source, opening) + 1]
        owns_ring = BYTE_DEQUE.search(body) or (
            BYTE_STORAGE.search(body) and RING_INDEX.search(body)
        )
        if owns_ring:
            line = source.count("\n", 0, match.start()) + 1
            found.append(f"{path}:{line}: {match.group(1)} owns pipe ring storage")
    return found


def self_test() -> int:
    assert findings(Path("bad.rs"), "struct PipeState { bytes: VecDeque<u8> }")
    assert findings(Path("bad.rs"), "struct GuestFifo { head: usize, bytes: Vec<u8> }")
    assert findings(
        Path("bad.rs"),
        "struct PipeRing { bytes: Box<[u8]>, read_pos: usize, write_pos: usize }",
    )
    assert not findings(Path("good.rs"), "struct PipeAdapter { bytes: Box<[u8]> }")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    violations = []
    for path in sorted((args.root / "crates").glob("*/src/**/*.rs")):
        if "carrick-pipe-core" in path.parts:
            continue
        violations.extend(findings(path.relative_to(args.root), path.read_text()))
    if violations:
        print("pipe-core boundary violation: Carrick pipe rings belong in carrick-pipe-core", file=sys.stderr)
        print("\n".join(violations), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
