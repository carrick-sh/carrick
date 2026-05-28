#!/usr/bin/env python3
"""Headline conformance metric: how much of the curated coverage map is owned
by a carrick probe/lib-test vs still LTP-only.

Parses `docs/conformance-coverage.md` (the checked-in coverage map) and the
probe binaries on disk, and reports:

  * # owned invariant probes (probes on disk),
  * # invariant ROWS in the map and the % with an owning ✅/🧪 entry,
  * # distinct LTP test IDs the map stands in for and the % owned,
  * any probe on disk NOT cited in the doc (undocumented),
  * any ✅-cited probe NOT on disk (stale doc).

This is the metric the project tracks INSTEAD of "LTP MATCH count": the probe
suite is the authoritative ABI gate (`cargo test --release --test conformance
conformance_probes`), and this script answers "how complete is that gate?".

Run: python3 scripts/coverage-metric.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "conformance-coverage.md")
BIN_DIR = os.path.join(ROOT, "conformance-probes", "src", "bin")


def expand_ltp(stand_in: str) -> list[str]:
    """Extract LTP test IDs from a 'stands in for' cell, expanding
    `foo01/02/03` and `foo01–09` shorthand into individual ids."""
    out: list[str] = []
    for chunk in re.split(r"[ ,;()]+", stand_in):
        # foo01/02/03  →  foo01, foo02, foo03
        m = re.match(r"^([a-z_]+\d+)(/\d+(?:/\d+)*)?$", chunk)
        if m:
            base = m.group(1)
            out.append(base)
            if m.group(2):
                stem = re.match(r"^(.*?)(\d+)$", base).group(1)
                for suf in m.group(2).strip("/").split("/"):
                    out.append(f"{stem}{suf}")
            continue
        # foo01–09 (en-dash or hyphen range)
        m = re.match(r"^([a-z_]+)(\d+)[–-](\d+)$", chunk)
        if m:
            stem, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            width = len(m.group(2))
            for i in range(lo, hi + 1):
                out.append(f"{stem}{i:0{width}d}")
    return out


def main() -> int:
    with open(DOC) as f:
        doc = f.read()

    rows = []  # (invariant, [probes], [ltp_ids], owned: bool)
    for line in doc.splitlines():
        if not line.startswith("|") or "|---|" in line or "Invariant" in line:
            continue
        # Split on unescaped pipes only — markdown cells may contain a
        # literal `\|` (e.g. "CLONE_VM\|CLONE_SIGHAND", "open(O_CREAT\|O_EXCL)").
        cells = [
            c.strip().replace("\\|", "|")
            for c in re.split(r"(?<!\\)\|", line.strip("|"))
        ]
        if len(cells) < 3:
            continue
        invariant, owned_by, stand_in = cells[0], cells[1], cells[2]
        probes = re.findall(r"`([a-z][a-z0-9_]+)`", owned_by)
        owned = "✅" in owned_by or "\U0001f9ea" in owned_by  # ✅ or 🧪
        ltp = expand_ltp(stand_in)
        if probes or ltp or owned:
            rows.append((invariant, probes, ltp, owned))

    disk = {f[:-3] for f in os.listdir(BIN_DIR) if f.endswith(".rs")}

    doc_probes = {p for _, ps, _, _ in rows for p in ps}
    all_ltp = {t for _, _, ts, _ in rows for t in ts}
    owned_ltp = {t for _, ps, ts, _ in rows if ps for t in ts}

    total_rows = len(rows)
    owned_rows = sum(1 for _, _, _, owned in rows if owned)

    print("=" * 60)
    print("CARRICK CONFORMANCE COVERAGE — HEADLINE METRIC")
    print("=" * 60)
    print(f"Owned invariant probes (on disk):  {len(disk)}")
    print(
        f"Invariant rows with an owning test: {owned_rows}/{total_rows} "
        f"({100 * owned_rows / total_rows:.0f}%)"
    )
    print(
        f"Distinct curated LTP tests owned:   {len(owned_ltp)}/{len(all_ltp)} "
        f"({100 * len(owned_ltp) / len(all_ltp):.0f}%)"
    )

    stale = sorted(doc_probes - disk)
    undocumented = sorted(disk - doc_probes)
    ltp_only = sorted(t for t in all_ltp if t not in owned_ltp)

    if stale:
        print(f"\n⚠  ✅-cited probes NOT on disk (stale doc): {stale}")
    if undocumented:
        print(f"\n⚠  probes on disk NOT cited in doc:        {undocumented}")
    if ltp_only:
        print(f"\nLTP-only (no owning probe yet): {ltp_only}")

    # Non-zero exit if the doc cites a probe that doesn't exist — that's a
    # real inconsistency a CI run should catch.
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
