#!/usr/bin/env python3
"""Reject a second rt_sigaction decoder or disposition map outside carrick-signal-core.

carrick-signal-core owns the disposition table (`policy::ActionTable`), the
`struct sigaction` wire codec and rt_sigaction validation
(`sigaction::{decode_action, encode_action, rt_sigaction}`); see #688 and the
ring-ports ruling #367. Lanes supply only a `SigactionPort`. Outside the core,
production code (test modules and `tests/` excepted) must not:

- keep a disposition map: a `BTreeMap`/`HashMap` whose value is a
  `LinuxSigaction` or a policy `Action`;
- decode a guest `struct sigaction` except inside a `SigactionPort::read_action`
  implementation, which only copies bytes;
- translate `SA_*` wire bits into policy `ActionFlags` (a struct literal that
  reads `sa_flags`).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ACTION_MAP = re.compile(
    r"\b(?:BTreeMap|HashMap)\s*<\s*[\w:]+\s*,\s*(?:[\w:]+::)?(?:LinuxSigaction|Action)\s*>"
)
WIRE_DECODE = re.compile(
    r"\bLinuxSigaction\s*::\s*(?:ref_from_bytes|read_from_bytes|read_from_prefix|mut_from_bytes|ref_from_prefix)\b"
)
FN_NAME = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
FLAGS_LITERAL = re.compile(r"\bActionFlags\s*\{")
TEST_MODULE = re.compile(r"^\s*#\[cfg\(test\)\]\s*\n\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", re.M)


def production_part(source: str) -> str:
    """Source before the first inline test module (Carrick keeps them last)."""
    match = TEST_MODULE.search(source)
    return source if match is None else source[: match.start()]


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


def line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def enclosing_fn(source: str, offset: int) -> str | None:
    names = [m for m in FN_NAME.finditer(source, 0, offset)]
    return names[-1].group(1) if names else None


def findings(path: Path, source: str) -> list[str]:
    source = production_part(source)
    found = []
    for match in ACTION_MAP.finditer(source):
        found.append(f"{path}:{line_of(source, match.start())}: disposition map `{match.group(0)}`")
    for match in WIRE_DECODE.finditer(source):
        if enclosing_fn(source, match.start()) != "read_action":
            found.append(
                f"{path}:{line_of(source, match.start())}: struct sigaction decoded outside SigactionPort::read_action"
            )
    for match in FLAGS_LITERAL.finditer(source):
        opening = source.find("{", match.start())
        body = source[opening : matching_brace(source, opening) + 1]
        if "sa_flags" in body:
            found.append(f"{path}:{line_of(source, match.start())}: SA_* bits translated into ActionFlags")
    return found


def self_test() -> int:
    bad = Path("bad.rs")
    assert findings(bad, "struct Sighand { actions: BTreeMap<LinuxSignal, LinuxSigaction> }")
    assert findings(bad, "struct T { a: HashMap<i32, carrick_signal_core::policy::Action> }")
    assert findings(bad, "fn rt_sigaction() { let a = LinuxSigaction::ref_from_bytes(&b); }")
    assert findings(
        bad,
        "fn decode() { let f = ActionFlags { restart: wire.sa_flags & LINUX_SA_RESTART != 0 }; }",
    )
    good = Path("good.rs")
    assert not findings(good, "fn read_action(&mut self) { LinuxSigaction::read_from_bytes(&b) }")
    assert not findings(good, "struct S { snapshots: BTreeMap<LinuxSignal, VecDeque<LinuxSigaction>> }")
    assert not findings(good, "fn f() { ActionFlags { restart: true, ..ActionFlags::default() } }")
    assert not findings(
        good,
        "fn f() {}\n#[cfg(test)]\nmod tests {\n fn t() { LinuxSigaction::read_from_bytes(&b); }\n}\n",
    )
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
        if "carrick-signal-core" in path.parts or "tests" in path.parts:
            continue
        if path.name == "tests.rs" or path.name.endswith("_tests.rs"):
            continue
        violations.extend(findings(path.relative_to(args.root), path.read_text()))
    if violations:
        print(
            "signal-core boundary violation: rt_sigaction decoding and disposition tables belong in carrick-signal-core",
            file=sys.stderr,
        )
        print("\n".join(violations), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
