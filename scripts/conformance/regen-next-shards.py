#!/usr/bin/env python3
"""Re-materialize the carrick-conformance-next generic probe shards.

The three `SHARD_<n>_PROBES` arrays in
`crates/carrick-conformance-next/tests/common/mod.rs` are the exact modulo-3
partition of the selected generic probes in
`conformance-probes/probe-inventory.json` (class `conformance`, not excluded,
runner `generic`, sorted by name). The shard tests hard-assert that partition,
its per-shard sizes, the cached-lane counts and the derived expected-gap sets,
so every probe addition or reclassification must regenerate all of them
together. Hand-editing the arrays is how shard 0 once absorbed shard 2's tail.

Usage: scripts/conformance/regen-next-shards.py [--check]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "conformance-probes/probe-inventory.json"
COMMON = ROOT / "crates/carrick-conformance-next/tests/common/mod.rs"
SHARD_TESTS = [
    ROOT / f"crates/carrick-conformance-next/tests/probes_shard_{n}.rs" for n in range(3)
]


def selected_probes() -> list[str]:
    inventory = json.loads(INVENTORY.read_text())
    return sorted(
        name
        for name, row in inventory.items()
        if row.get("class") == "conformance"
        and not row.get("excluded", False)
        and row.get("runner") == "generic"
    )


def rust_list(name: str) -> list[str]:
    source = COMMON.read_text()
    match = re.search(rf"pub const {name}: &\[&str\] = &\[(.*?)\];", source, re.S)
    if match is None:
        raise SystemExit(f"{name} not found in {COMMON}")
    return re.findall(r'"([^"]+)"', match.group(1))


def replace_list(source: str, name: str, probes: list[str]) -> str:
    body = "".join(f'    "{probe}",\n' for probe in probes)
    pattern = re.compile(rf"(pub const {name}: &\[&str\] = &\[\n)(.*?)(\];)", re.S)
    if pattern.search(source) is None:
        raise SystemExit(f"{name} not found in {COMMON}")
    return pattern.sub(lambda m: f"{m.group(1)}{body}{m.group(3)}", source, count=1)


def replace_once(source: str, pattern: str, replacement: str, path: Path) -> str:
    updated, count = re.subn(pattern, replacement, source, count=1)
    if count != 1:
        raise SystemExit(f"pattern {pattern!r} not found in {path}")
    return updated


def main() -> int:
    check = "--check" in sys.argv[1:]
    probes = selected_probes()
    shards = [[p for i, p in enumerate(probes) if i % 3 == n] for n in range(3)]
    live = set(rust_list("LIVE_ORACLE_PROBES"))
    out_of_process = set(rust_list("OUT_OF_PROCESS_PROBES"))
    musl_gaps = set(rust_list("MUSL_BASELINE_GAPS"))
    gnu_gaps = set(rust_list("GNU_BASELINE_GAPS"))
    cached = [
        sum(1 for p in shard if p not in live and p not in out_of_process) for shard in shards
    ]

    common = COMMON.read_text()
    updated = common
    for n, shard in enumerate(shards):
        updated = replace_list(updated, f"SHARD_{n}_PROBES", shard)
    updated = replace_once(
        updated,
        r'assert_eq!\(union\.len\(\), \d+, "generic shard union must remain complete"\);',
        f'assert_eq!(union.len(), {len(probes)}, "generic shard union must remain complete");',
        COMMON,
    )
    updated = re.sub(
        r"Hard-asserted to have exactly \d+ sorted unique names",
        f"Hard-asserted to have exactly {len(shards[2])} sorted unique names",
        updated,
    )
    outputs = {COMMON: (common, updated)}

    for n, path in enumerate(SHARD_TESTS):
        original = path.read_text()
        text = original
        size = len(shards[n])
        text = replace_once(
            text,
            rf"const CACHED_SHARD_{n}_PROBE_COUNT: usize = \d+;",
            f"const CACHED_SHARD_{n}_PROBE_COUNT: usize = {cached[n]};",
            path,
        )
        text = re.sub(r"(Hard-assert exactly )\d+( sorted unique names)", rf"\g<1>{size}\g<2>", text)
        text = re.sub(
            rf"(shard {n} must (?:have|contain) exactly )\d+",
            rf"\g<1>{size}",
            text,
        )
        text = re.sub(
            rf"(derived shard {n} must have (?:exactly )?)\d+",
            rf"\g<1>{size}",
            text,
        )
        text = re.sub(
            rf"(SHARD_{n}_PROBES must contain )\d+( unique names)",
            rf"\g<1>{size}\g<2>",
            text,
        )
        text = re.sub(
            r"(expected exactly )\d+( (?:generic )?conformance (?:generic )?probes)",
            rf"\g<1>{len(probes)}\g<2>",
            text,
        )
        # Each `assert_eq!(<expr>, N, "<message naming this shard's size>")`
        # carries the literal beside its message; rewrite the literal that
        # precedes a message we just rewrote.
        text = re.sub(
            rf'(\n\s+)\d+(,\n\s+"(?:shard {n} must|derived shard {n} must|SHARD_{n}_PROBES must contain))',
            rf"\g<1>{size}\g<2>",
            text,
        )
        text = re.sub(
            r'(\n\s+)\d+(,\n\s+"expected exactly)',
            rf"\g<1>{len(probes)}\g<2>",
            text,
        )
        # Fail closed: every size assertion naming this shard must now carry
        # the derived size. A message phrased outside the patterns above would
        # otherwise keep a stale literal that only the test run catches.
        stale = [
            literal
            for literal in re.findall(rf"shard {n}\b[^\"\n]*?must (?:have|contain) (?:exactly )?(\d+)", text)
            if int(literal) != size
        ]
        if stale:
            raise SystemExit(
                f"{path}: shard {n} size assertions {stale} were not rewritten to {size}; "
                "phrase them as `shard N must have exactly N` / `derived shard N must have N items`"
            )
        if n == 0:
            shard_set = set(shards[0])
            musl = sorted(musl_gaps & shard_set)
            gnu = sorted(gnu_gaps & shard_set)

            def fmt(names: list[str]) -> str:
                return "BTreeSet::from([" + ", ".join(f'"{x}"' for x in names) + "])"

            text = replace_once(
                text,
                r"let expected_musl_set = BTreeSet::from\(\[[^\]]*\]\);",
                f"let expected_musl_set = {fmt(musl)};",
                path,
            )
            text = replace_once(
                text,
                r"let expected_gnu_set = BTreeSet::from\(\[[^\]]*\]\);",
                f"let expected_gnu_set = {fmt(gnu)};",
                path,
            )
            text = re.sub(
                r"(\n\s+)\d+(,\n\s+\"musl shard 0 must contain exactly )\d+( baseline gaps?\")",
                rf"\g<1>{len(musl)}\g<2>{len(musl)}\g<3>",
                text,
            )
            text = re.sub(
                r"(\n\s+)\d+(,\n\s+\"gnu shard 0 must contain exactly )\d+( baseline gaps?\")",
                rf"\g<1>{len(gnu)}\g<2>{len(gnu)}\g<3>",
                text,
            )
        outputs[path] = (original, text)

    changed = [path for path, (before, after) in outputs.items() if before != after]
    if check:
        for path in changed:
            print(f"stale: {path.relative_to(ROOT)}")
        print(f"{len(probes)} generic probes; shards {[len(s) for s in shards]}; cached {cached}")
        return 1 if changed else 0
    for path, (_, after) in outputs.items():
        path.write_text(after)
    print(f"{len(probes)} generic probes; shards {[len(s) for s in shards]}; cached {cached}")
    for path in changed:
        print(f"rewrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
