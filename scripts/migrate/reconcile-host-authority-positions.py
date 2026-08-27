#!/usr/bin/env python3
"""Re-bind reviewed host-authority rows to moved source positions.

`check-host-authority-transitions.py --check` fails whenever code MOVES, because
every reviewed row pins an exact file/line/byte span. That happens on any merge
that shifts lines, and the obvious response — overwriting the inventory with the
tool's `--refresh-candidate` output — is WRONG: the candidate's rows are all
`unreviewed` with empty rationales, so a blind refresh silently destroys every
human classification while turning the gate green. That is a re-bless that
launders evidence away, and it is the failure this script exists to prevent.

What this does instead: match each reviewed row to its recompiled counterpart on
(catalog_id, operation, file), pair them in source order, and copy across ONLY
the `source` span, plus the `At <file>:<line>` prefix that rationales use to bind
themselves to a site. Classifications, evidence and rationale prose are never
touched.

It refuses to guess. If a (catalog_id, operation, file) group has a different
row COUNT than the recompiled tree, the group is left alone and reported: a
changed count means a host-authority call was genuinely added or removed, which
is a REVIEW decision, not a position update. Only a group that vanished entirely
is dropped, and it is named in the output so the removal is visible.

Usage:
    python3 scripts/migrate/check-host-authority-transitions.py --refresh-candidate /tmp/cand.json
    python3 scripts/migrate/reconcile-host-authority-positions.py /tmp/cand.json
    # then commit, and re-run --check (it requires a clean tracked tree)

The macOS capture is a machine artifact with no human review, so it is replaced
wholesale from the candidate's receipt, preserving the checked-in file's key set
and its `kind` discriminator.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/host-authority-transition-inventory.json"
CAPTURE = ROOT / "scripts/migrate/host-authority-macos-capture.json"


def key(row: dict) -> tuple:
    return (row["catalog_id"], row["operation"], row["source"]["file"])


def in_source_order(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (r["source"]["line"], r["source"]["byte_start"]))


def main(candidate_path: str) -> int:
    candidate = json.loads(Path(candidate_path).read_text())
    inventory = json.loads(INVENTORY.read_text())

    fresh = collections.defaultdict(list)
    for row in candidate["rows"]:
        fresh[key(row)].append(row)

    reviewed = collections.defaultdict(list)
    for row in inventory:
        reviewed[key(row)].append(row)

    moved = 0
    rebound = 0
    dropped: list[tuple] = []
    ambiguous: list[tuple] = []
    drop_ids: set[int] = set()

    for group, rows in reviewed.items():
        candidates = fresh.get(group, [])
        if len(candidates) == len(rows):
            for old, new in zip(in_source_order(rows), in_source_order(candidates)):
                if old["source"] == new["source"]:
                    continue
                old_line = old["source"]["line"]
                old["source"] = new["source"]
                moved += 1
                rationale = old.get("rationale") or ""
                stale = f"At {group[2]}:{old_line}"
                if stale in rationale:
                    old["rationale"] = rationale.replace(
                        stale, f"At {group[2]}:{new['source']['line']}", 1
                    )
                    rebound += 1
        elif not candidates:
            for row in rows:
                drop_ids.add(id(row))
            dropped.append(group)
        else:
            ambiguous.append((group, len(rows), len(candidates)))

    if ambiguous:
        print("REFUSING to reconcile: row counts changed, which is a review decision:")
        for group, had, now in ambiguous:
            print(f"  {group[0]} {group[1]} {group[2]}: {had} reviewed -> {now} found")
        return 2

    inventory = [row for row in inventory if id(row) not in drop_ids]
    INVENTORY.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")

    receipt = candidate["capture_receipt"]
    capture = json.loads(CAPTURE.read_text())
    kind = capture["kind"]
    refreshed = {k: receipt[k] for k in capture.keys() if k in receipt}
    refreshed["kind"] = kind
    CAPTURE.write_text(json.dumps(refreshed, indent=2, sort_keys=True) + "\n")

    print(f"positions updated: {moved}")
    print(f"rationale site references rebound: {rebound}")
    for group in dropped:
        print(f"dropped (call no longer present): {group[0]} {group[1]} {group[2]}")
    print(f"inventory rows: {len(inventory)}; capture rows: {len(refreshed['rows'])}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
