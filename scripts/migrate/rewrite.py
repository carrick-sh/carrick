#!/usr/bin/env python3
"""Deterministic codemod runner for mechanical migrations.

The typed-interfaces migration (docs/typed-interfaces-audit.md) is mostly
mechanical: rename a signature, thread a newtype, insert `.raw()`/`.get()` at a
boundary — across dozens of same-shaped sites. Doing that by hand invites the
exact transposition errors the migration exists to kill, and doing it with
bare `sed` gives no feedback when the tree has drifted. This runner makes each
mechanical pass a REVIEWABLE ARTIFACT with drift detection:

- A spec is a JSON file: `[{"file": ..., "old": ..., "new": ..., "count": N}]`.
  `count` is the EXPECTED number of occurrences (default 1); the run ABORTS
  before writing anything if any spec entry's count mismatches — a mismatch
  means the tree drifted from what the spec was written against, and applying
  anyway would silently miss (or double-apply) sites.
- All-or-nothing per run: every file's rewrites are computed first, then all
  files are written. No partially-applied tree on failure.
- `--check` computes and reports without writing (dry run).

Usage:
  scripts/migrate/rewrite.py spec.json           # apply
  scripts/migrate/rewrite.py --check spec.json   # dry run
  scripts/migrate/rewrite.py --emit file old new [count]  # print a spec entry

Specs used for a landed migration stage belong next to the commit (attach the
spec path in the commit message body) so the pass can be audited and, on a
revert+redo, replayed.
"""

import json
import sys
from pathlib import Path


def load_spec(path: str) -> list[dict]:
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise SystemExit(f"{path}: spec must be a JSON array of rewrite entries")
    for i, e in enumerate(entries):
        for key in ("file", "old", "new"):
            if key not in e:
                raise SystemExit(f"{path}[{i}]: missing required key {key!r}")
        if e["old"] == e["new"]:
            raise SystemExit(f"{path}[{i}]: old == new (no-op entry)")
    return entries


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--emit":
        _, file, old, new, *rest = args
        print(
            json.dumps(
                {"file": file, "old": old, "new": new, "count": int(rest[0]) if rest else 1},
                indent=2,
            )
        )
        return 0

    check_only = False
    if args and args[0] == "--check":
        check_only = True
        args = args[1:]
    if len(args) != 1:
        print(__doc__)
        return 2

    entries = load_spec(args[0])

    # Phase 1 — verify every entry against the CURRENT tree before any write.
    contents: dict[str, str] = {}
    failures: list[str] = []
    for i, e in enumerate(entries):
        f = e["file"]
        if f not in contents:
            p = Path(f)
            if not p.is_file():
                failures.append(f"[{i}] {f}: file not found")
                continue
            contents[f] = p.read_text()
        expected = e.get("count", 1)
        found = contents[f].count(e["old"])
        if found != expected:
            failures.append(
                f"[{i}] {f}: expected {expected} occurrence(s) of pattern, found {found} "
                f"(tree drifted from the spec — regenerate it)\n"
                f"      pattern head: {e['old'].splitlines()[0][:100]!r}"
            )
    if failures:
        print("ABORTED — no files written:", file=sys.stderr)
        for line in failures:
            print("  " + line, file=sys.stderr)
        return 1

    # Phase 2 — apply in memory (entries are order-dependent within a file).
    for e in entries:
        contents[e["file"]] = contents[e["file"]].replace(e["old"], e["new"])

    if check_only:
        print(f"OK (dry run): {len(entries)} rewrite(s) across {len(contents)} file(s)")
        return 0

    for f, text in contents.items():
        Path(f).write_text(text)
    print(f"applied {len(entries)} rewrite(s) across {len(contents)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
