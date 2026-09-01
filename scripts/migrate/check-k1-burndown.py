#!/usr/bin/env python3
"""Fail when any K1 authority-escape family grows past its recorded ceiling.

The ceiling is a BURNDOWN target, not a description: it may only be lowered,
and it is lowered in the same commit that removes the call sites. A family that
grows is a new legacy escape being added while the cutover is in flight, which
is the failure mode this gate exists to catch.

Only `production_callsite` taxonomy entries count. The definition modules
(`kernel/objects.rs`, `dispatch/fd_table.rs`) and `#[cfg(test)]` lines are
where the authority types and their own unit tests live; a test that exercises
the write guard's semantics is not a legacy escape from it, and counting one
made the gate refuse the very test that pins the guard's contract.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAXONOMY = ROOT / "scripts/migrate/k1-file-authority-callsite-taxonomy.json"
CEILING = ROOT / "scripts/migrate/k1-burndown-ceiling.json"


def violations(counts: dict[str, int], ceiling: dict[str, int]) -> list[str]:
    found = []
    for family in sorted(set(counts) | set(ceiling)):
        actual = counts.get(family, 0)
        allowed = ceiling.get(family, 0)
        if actual > allowed:
            found.append(f"{family}: {actual} escapes exceeds ceiling {allowed}")
    return found


def self_test() -> int:
    assert violations({"epoll_wait": 3}, {"epoll_wait": 3}) == []
    assert violations({"epoll_wait": 2}, {"epoll_wait": 3}) == []
    assert violations({"epoll_wait": 4}, {"epoll_wait": 3}) == [
        "epoll_wait: 4 escapes exceeds ceiling 3"
    ]
    assert violations({"new_family": 1}, {}) == [
        "new_family: 1 escapes exceeds ceiling 0"
    ]
    print("check-k1-burndown self-test OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print(f"usage: {Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2
    taxonomy = json.loads(TAXONOMY.read_text())
    counts = Counter(
        entry["migration_family"]
        for entry in taxonomy["entries"]
        if entry["scope_kind"] == "production_callsite"
    )
    ceiling = json.loads(CEILING.read_text())["ceiling"]
    found = violations(counts, ceiling)
    if found:
        print("K1 authority-escape burndown regressed:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nA family may only shrink. If you deliberately removed call sites, "
            "lower the ceiling in scripts/migrate/k1-burndown-ceiling.json in the "
            "SAME commit.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
