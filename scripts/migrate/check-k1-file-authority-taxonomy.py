#!/usr/bin/env python3
"""Fail when the checked K1 FileAuthority callsite taxonomy drifts."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "scripts/migrate/k1-file-authority-operation-inventory.json"
TAXONOMY = ROOT / "scripts/migrate/k1-file-authority-callsite-taxonomy.json"
AUTHORITY_CATEGORIES = frozenset(
    {"table_guard", "description_guard", "description_backing"}
)
MIGRATION_FAMILIES = frozenset(
    {
        "inspect_misc",
        "lifecycle",
        "create_install",
        "read_attempt",
        "write_attempt",
        "slot_description_mutation",
        "stream_transfer",
        "mapping_ring",
        "epoll_wait",
    }
)


def inventory_key(entry: dict[str, Any]) -> tuple[object, ...]:
    return (
        entry["file"],
        entry["line"],
        tuple(entry["categories"]),
        entry["text"],
        entry["scope_kind"],
    )


def main(argv: list[str]) -> int:
    if argv:
        print(f"usage: {Path(sys.argv[0]).name}", file=sys.stderr)
        return 2

    inventory = json.loads(INVENTORY.read_text())
    taxonomy = json.loads(TAXONOMY.read_text())
    expected = Counter(
        inventory_key(entry)
        for entry in inventory["entries"]
        if AUTHORITY_CATEGORIES.intersection(entry["categories"])
    )
    actual = Counter(inventory_key(entry) for entry in taxonomy["entries"])
    families = Counter(entry["migration_family"] for entry in taxonomy["entries"])
    unknown_families = sorted(set(families).difference(MIGRATION_FAMILIES))

    errors: list[str] = []
    if taxonomy.get("schema") != 1:
        errors.append(f"unsupported taxonomy schema {taxonomy.get('schema')!r}")
    if expected != actual:
        errors.append(
            "taxonomy entries do not exactly cover the current table/description authority inventory"
        )
    if unknown_families:
        errors.append(f"unknown migration families: {unknown_families}")
    if taxonomy.get("counts") != dict(families):
        errors.append(
            f"family counts drifted: expected {taxonomy.get('counts')}, actual {dict(families)}"
        )
    if any(not entry.get("enclosing_function") for entry in taxonomy["entries"]):
        errors.append("every taxonomy entry must name its enclosing function")

    if not errors:
        return 0
    print("K1 FileAuthority callsite taxonomy drifted", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    print(
        "Classify every added, removed, or moved authority site before updating the taxonomy.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
