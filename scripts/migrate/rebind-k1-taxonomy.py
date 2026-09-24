#!/usr/bin/env python3
"""Mechanically rebind the K1 FileAuthority call-site taxonomy to the current
operation inventory.

Moved sites (same file, categories, text and scope kind at a new line) are
rebound. Sites that no longer exist are dropped. Genuinely new sites are NOT
classified here: they are listed, and the script exits 1 so a reviewer adds
them (enclosing function + migration family) by hand. Run on a clean tree
after `check-k1-file-authority-inventory.py --write`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/k1-file-authority-operation-inventory.json"
TAXONOMY = ROOT / "scripts/migrate/k1-file-authority-callsite-taxonomy.json"
AUTHORITY = {"table_guard", "description_guard", "description_backing"}


def key(entry: dict) -> tuple:
    return (entry["file"], tuple(entry["categories"]), entry["text"], entry["scope_kind"])


def main() -> int:
    inventory = json.loads(INVENTORY.read_text())
    taxonomy = json.loads(TAXONOMY.read_text())
    expected = [e for e in inventory["entries"] if AUTHORITY & set(e["categories"])]
    pool: dict[tuple, list[dict]] = defaultdict(list)
    for entry in taxonomy["entries"]:
        pool[key(entry)].append(entry)
    for entries in pool.values():
        entries.sort(key=lambda e: e["line"])
    out, new = [], []
    for entry in expected:
        candidates = pool[key(entry)]
        if candidates:
            rebound = dict(candidates.pop(0))
            rebound["line"] = entry["line"]
            out.append(rebound)
        else:
            new.append(entry)
    gone = [e for entries in pool.values() for e in entries]
    if new:
        print("new K1 sites need classification (enclosing_function, migration_family):")
        for entry in new:
            print(f"  {entry['file']}:{entry['line']} {entry['categories']} {entry['text'][:100]}")
        return 1
    old_counts = taxonomy.get("counts", {})
    families = Counter(e["migration_family"] for e in out)
    taxonomy["entries"] = out
    taxonomy["counts"] = {k: families[k] for k in old_counts if k in families} | {
        k: v for k, v in families.items() if k not in old_counts
    }
    TAXONOMY.write_text(json.dumps(taxonomy, indent=2) + "\n")
    for entry in gone:
        print(f"dropped retired site {entry['file']}:{entry['line']} {entry['enclosing_function']}")
    print(f"rebound {len(out)} taxonomy entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
