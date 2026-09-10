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

import argparse
import collections
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/host-authority-transition-inventory.json"
CAPTURE = ROOT / "scripts/migrate/host-authority-macos-capture.json"


class RefusedError(Exception):
    """A change that needs review, not a position rebind."""


def key(row: dict) -> tuple:
    return (row["catalog_id"], row["operation"], row["source"]["file"])


def in_source_order(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (r["source"]["line"], r["source"]["byte_start"]))


def load_brace_deltas(root: Path):
    for candidate_path in (
        root / "scripts/migrate/check-k1-file-authority-inventory.py",
        ROOT / "scripts/migrate/check-k1-file-authority-inventory.py",
    ):
        if candidate_path.is_file():
            spec = importlib.util.spec_from_file_location("k1_inventory", candidate_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = mod
                spec.loader.exec_module(mod)
                return mod.brace_deltas
    return lambda src: [line.count("{") - line.count("}") for line in src.splitlines()]


def find_enclosing_function(source_lines: list[str], target_line: int, brace_deltas_fn) -> str | None:
    scopes: list[tuple[int, str]] = []  # (depth, fn_name)
    current_depth = 0
    fn_re = re.compile(r"\bfn\s+([a-zA-Z0-9_]+)")
    pending_fn: str | None = None
    deltas = brace_deltas_fn("\n".join(source_lines))

    for idx, line in enumerate(source_lines, start=1):
        m = fn_re.search(line)
        if m:
            pending_fn = m.group(1)
        delta = deltas[idx - 1] if idx - 1 < len(deltas) else 0
        if pending_fn and delta > 0:
            scopes.append((current_depth + 1, pending_fn))
            pending_fn = None
        current_depth += delta
        while scopes and current_depth < scopes[-1][0]:
            scopes.pop()
        if idx == target_line:
            if scopes:
                return scopes[-1][1]
            if pending_fn:
                return pending_fn
            return None
    return None


def extract_reviewed_enclosing_function(row: dict) -> str | None:
    rat = row.get("rationale") or ""
    m = re.search(r"At [^:]+:\d+ in `?([a-zA-Z0-9_:]+)`?", rat)
    if not m:
        return None
    fn = m.group(1).strip("`")
    return fn.split("::")[-1]


def canonical_row_sort_key(row: dict) -> tuple:
    source = row.get("source")
    if not isinstance(source, dict):
        return (str(row.get("operation")), "", 0, 0, 0, 0, "")
    return (
        str(row.get("operation")),
        str(source.get("file")),
        int(source.get("byte_start") or 0),
        int(source.get("byte_end") or 0),
        int(source.get("line_start") or 0),
        int(source.get("column_start") or 0),
        json.dumps(row.get("expansion"), sort_keys=True) if row.get("expansion") is not None else "",
    )


def reconcile_host_authority_positions(
    candidate_path: Path | str,
    inventory_path: Path | str = INVENTORY,
    capture_path: Path | str = CAPTURE,
    rehome: bool = False,
    root: Path | str = ROOT,
) -> int:
    candidate_path = Path(candidate_path)
    inventory_path = Path(inventory_path)
    capture_path = Path(capture_path)
    root = Path(root)

    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))

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

    matched_reviewed_ids: set[int] = set()
    matched_candidate_ids: set[int] = set()

    for group, rows in reviewed.items():
        candidates = fresh.get(group, [])
        if len(candidates) == len(rows):
            for old, new in zip(in_source_order(rows), in_source_order(candidates)):
                matched_reviewed_ids.add(id(old))
                matched_candidate_ids.add(id(new))
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
        elif not rehome:
            if not candidates:
                for row in rows:
                    drop_ids.add(id(row))
                dropped.append(group)
            else:
                ambiguous.append((group, len(rows), len(candidates)))

    if not rehome:
        if ambiguous:
            messages = [
                f"  {group[0]} {group[1]} {group[2]}: {had} reviewed -> {now} found"
                for group, had, now in ambiguous
            ]
            raise RefusedError(
                "REFUSING to reconcile: row counts changed, which is a review decision:\n"
                + "\n".join(messages)
            )

        inventory = [row for row in inventory if id(row) not in drop_ids]
        inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        receipt = candidate["capture_receipt"]
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
        kind = capture["kind"]
        refreshed = {k: receipt[k] for k in capture.keys() if k in receipt}
        refreshed["kind"] = kind
        capture_path.write_text(json.dumps(refreshed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(f"positions updated: {moved}")
        print(f"rationale site references rebound: {rebound}")
        for group in dropped:
            print(f"dropped (call no longer present): {group[0]} {group[1]} {group[2]}")
        print(f"inventory rows: {len(inventory)}; capture rows: {len(refreshed['rows'])}")
        return moved

    # --- Rehome path ---
    unmatched_reviewed = [r for r in inventory if id(r) not in matched_reviewed_ids]
    unmatched_candidates = [r for r in candidate["rows"] if id(r) not in matched_candidate_ids]

    if unmatched_reviewed or unmatched_candidates:
        brace_deltas_fn = load_brace_deltas(root)
        file_cache: dict[str, list[str]] = {}

        def get_source_lines(rel_file: str) -> list[str]:
            if rel_file not in file_cache:
                p = root / rel_file if not Path(rel_file).is_absolute() else Path(rel_file)
                if not p.is_file():
                    file_cache[rel_file] = []
                else:
                    file_cache[rel_file] = p.read_text(encoding="utf-8").splitlines()
            return file_cache[rel_file]

        def get_candidate_fn(row: dict) -> str | None:
            src = row.get("source") or {}
            rel_file = src.get("file")
            line_num = src.get("line")
            if not rel_file or not line_num:
                return None
            lines = get_source_lines(rel_file)
            if not lines:
                return None
            return find_enclosing_function(lines, line_num, brace_deltas_fn)

        reviewed_by_fn: dict[tuple, list[dict]] = collections.defaultdict(list)
        candidate_by_fn: dict[tuple, list[dict]] = collections.defaultdict(list)

        for rev in unmatched_reviewed:
            rev_fn = extract_reviewed_enclosing_function(rev)
            if rev_fn is None:
                raise RefusedError(f"host-authority: could not determine enclosing function from rationale: {rev.get('rationale')}")
            key_fn = (rev.get("catalog_id"), rev.get("operation"), rev_fn)
            reviewed_by_fn[key_fn].append(rev)

        for cand in unmatched_candidates:
            cand_fn = get_candidate_fn(cand)
            if cand_fn is None:
                raise RefusedError(f"host-authority: could not determine enclosing function for candidate {cand['source']['file']}:{cand['source']['line']}")
            key_fn = (cand.get("catalog_id"), cand.get("operation"), cand_fn)
            candidate_by_fn[key_fn].append(cand)

        all_keys = set(reviewed_by_fn) | set(candidate_by_fn)
        for key_fn in sorted(all_keys):
            rev_rows = reviewed_by_fn.get(key_fn, [])
            cand_rows = candidate_by_fn.get(key_fn, [])
            if not rev_rows:
                raise RefusedError(
                    f"host-authority site added or unreviewed: {key_fn[0]} {key_fn[1]} in function {key_fn[2]} "
                    f"({len(cand_rows)} candidate(s))"
                )
            if not cand_rows:
                raise RefusedError(
                    f"host-authority site vanished or edited: {key_fn[0]} {key_fn[1]} in function {key_fn[2]} "
                    f"({len(rev_rows)} reviewed row(s))"
                )
            if len(rev_rows) != len(cand_rows):
                raise RefusedError(
                    f"host-authority row count changed in function {key_fn[2]}: {key_fn[0]} {key_fn[1]} "
                    f"{len(rev_rows)} reviewed -> {len(cand_rows)} found"
                )

            for old, new in zip(in_source_order(rev_rows), in_source_order(cand_rows)):
                if old["source"] == new["source"]:
                    continue
                old_file = old["source"]["file"]
                old_line = old["source"]["line"]
                old["source"] = new["source"]
                new_file = new["source"]["file"]
                new_line = new["source"]["line"]
                stale = f"At {old_file}:{old_line}"
                fresh_prefix = f"At {new_file}:{new_line}"
                rationale = old.get("rationale") or ""
                if stale in rationale:
                    old["rationale"] = rationale.replace(stale, fresh_prefix, 1)
                    rebound += 1
                moved += 1

    inventory.sort(key=canonical_row_sort_key)
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    receipt = candidate["capture_receipt"]
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    kind = capture["kind"]
    refreshed = {k: receipt[k] for k in capture.keys() if k in receipt}
    refreshed["kind"] = kind
    capture_path.write_text(json.dumps(refreshed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"positions updated: {moved}")
    print(f"rationale site references rebound: {rebound}")
    print(f"inventory rows: {len(inventory)}; capture rows: {len(refreshed['rows'])}")
    return moved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_path", help="Path to candidate JSON from check-host-authority-transitions.py")
    parser.add_argument("--inventory", type=Path, default=INVENTORY, help="Path to inventory JSON")
    parser.add_argument("--capture", type=Path, default=CAPTURE, help="Path to capture JSON")
    parser.add_argument("--rehome", action="store_true", help="Re-home reviewed rows when functions move files")
    args = parser.parse_args(argv)

    try:
        reconcile_host_authority_positions(
            candidate_path=args.candidate_path,
            inventory_path=args.inventory,
            capture_path=args.capture,
            rehome=args.rehome,
            root=ROOT,
        )
        return 0
    except RefusedError as error:
        print(f"REFUSED ({error})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
