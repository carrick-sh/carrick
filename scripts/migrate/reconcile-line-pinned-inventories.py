#!/usr/bin/env python3
"""Re-bind every line-pinned `just lint-domains` inventory after code MOVES.

Five gates in `just lint-domains` pin reviewed rows to exact source positions
and therefore go red on any edit that shifts lines, even when no inventoried
site was added or removed:

- `check-runtime-aborts.py`        (abort fingerprints, three shards)
- `check-host-authority-transitions.py` (file/line/byte spans + macOS capture)
- `check-dispatch-lock-authority.py`    (lock sites keyed by id, pinned line)
- `check-k1-file-authority-inventory.py` (operation inventory, `--write`)
- `check-k1-file-authority-taxonomy.py`  (taxonomy keyed on inventory lines)

Each refresh is a re-bless of reviewed evidence, so this script does ONLY the
position part and refuses everything else: a row whose identity changed, a
(catalog, operation, file) group whose count changed, a K1 category count that
moved, or a taxonomy group that gained or lost a site is left untouched and
reported, because that is a REVIEW decision. A dirty result from this script
must therefore only ever contain line numbers, byte offsets, fingerprints and
`At <file>:<line>` prefixes — `git diff -U0` should show nothing else.

Usage:
    git commit ...        # the code move first: the host-authority capture
                          # refuses a dirty tracked tree
    python3 scripts/migrate/reconcile-line-pinned-inventories.py
    # review `git diff` (positions only), fold it into that commit with
    # `git commit --fixup` + autosquash or commit as `chore: reconcile the
    # line-pinned inventories for <change>`, then `just lint-domains`.

The host-authority step launches Cargo (`--refresh-candidate` compiles the
macOS product profiles); the rest read source directly.
"""
from __future__ import annotations

import collections
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATE = ROOT / "scripts/migrate"


class RefusedError(Exception):
    """A change that needs review, not a position rebind."""


def load_script(name: str):
    """Import a sibling checker as a module so its scanner is the authority."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), MIGRATE / name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def reconcile_runtime_aborts() -> int:
    aborts = load_script("check-runtime-aborts.py")
    findings = aborts.discover_runtime_aborts(ROOT)
    by_shard: dict[str, list] = collections.defaultdict(list)
    for finding in findings:
        by_shard[aborts.route_shard(finding.file)].append(finding)
    rebound = 0
    for shard in aborts.SHARD_NAMES:
        path = MIGRATE / "runtime-aborts" / shard
        ledger = json.loads(path.read_text())
        rows = {
            (r["file"], r["function"], r["ordinal_in_function"]): r for r in ledger["rows"]
        }
        live = {
            (f.file, f.function, f.ordinal_in_function): f for f in by_shard.get(shard, [])
        }
        added = sorted(k for k in live if k not in rows)
        removed = sorted(k for k in rows if k not in live)
        if added or removed:
            raise RefusedError(
                f"runtime-aborts/{shard}: abort sites added={added} removed={removed}"
            )
        changed = 0
        for key, finding in live.items():
            if rows[key]["fingerprint"] != finding.fingerprint:
                rows[key]["fingerprint"] = finding.fingerprint
                changed += 1
        if changed:
            write_json(path, ledger)
        rebound += changed
    return rebound


def reconcile_host_authority() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        candidate = Path(tmp) / "candidate.json"
        # Exits non-zero by design on a single host: the candidate is
        # explicitly partial (non-macOS profiles pending). Only its absence
        # is a failure here.
        subprocess.run(
            [
                sys.executable,
                str(MIGRATE / "check-host-authority-transitions.py"),
                "--refresh-candidate",
                str(candidate),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not candidate.is_file():
            dirty = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=no"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if dirty:
                # The compiler capture only accepts clean tracked inputs, so
                # the code move has to be committed first; fold the rebind in
                # afterwards (`git commit --fixup` + autosquash).
                raise RefusedError(
                    "host-authority: the authoritative capture needs a clean tracked "
                    "tree -- commit the code change first, then rerun"
                )
            raise RefusedError("host-authority: --refresh-candidate produced no candidate")
        result = subprocess.run(
            [
                sys.executable,
                str(MIGRATE / "reconcile-host-authority-positions.py"),
                str(candidate),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    for line in result.stdout.splitlines():
        if line.startswith("positions updated:"):
            return int(line.split(":")[1])
    raise RefusedError("host-authority: reconcile printed no position count")


def reconcile_dispatch_locks() -> int:
    path = MIGRATE / "dispatch-lock-authority.json"
    with tempfile.TemporaryDirectory() as tmp:
        candidate = Path(tmp) / "candidate.json"
        subprocess.run(
            [
                sys.executable,
                str(MIGRATE / "check-dispatch-lock-authority.py"),
                "--candidate",
                str(candidate),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not candidate.is_file():
            raise RefusedError("dispatch-lock-authority: --candidate produced no candidate")
        fresh = json.loads(candidate.read_text())
    inventory = json.loads(path.read_text())

    def rows(document: dict) -> list[dict]:
        for value in document.values():
            if isinstance(value, list) and value and isinstance(value[0], dict) and "id" in value[0]:
                return value
        raise RefusedError("dispatch-lock-authority: no row list found")

    fresh_by_id = {r["id"]: r for r in rows(fresh)}
    inventory_rows = rows(inventory)
    inventory_ids = {r["id"] for r in inventory_rows}
    if set(fresh_by_id) != inventory_ids:
        raise RefusedError(
            "dispatch-lock-authority: lock sites added="
            f"{sorted(set(fresh_by_id) - inventory_ids)} removed="
            f"{sorted(inventory_ids - set(fresh_by_id))}"
        )
    rebound = 0
    for row in inventory_rows:
        fresh_row = fresh_by_id[row["id"]]
        for field in ("expression", "item", "category", "file"):
            if row[field] != fresh_row[field]:
                raise RefusedError(f"dispatch-lock-authority: {row['id']} changed {field}")
        if row["line"] != fresh_row["line"]:
            row["line"] = fresh_row["line"]
            rebound += 1
    if rebound:
        write_json(path, inventory)
    return rebound


K1_INVENTORY = MIGRATE / "k1-file-authority-operation-inventory.json"
K1_TAXONOMY = MIGRATE / "k1-file-authority-callsite-taxonomy.json"


def k1_counts(inventory: dict) -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    for entry in inventory["entries"]:
        for category in entry["categories"]:
            counts[category] += 1
    return counts


def reconcile_k1_inventory() -> int:
    before_text = K1_INVENTORY.read_text()
    before = json.loads(before_text)
    subprocess.run(
        [sys.executable, str(MIGRATE / "check-k1-file-authority-inventory.py"), "--write"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    after = json.loads(K1_INVENTORY.read_text())
    if k1_counts(before) != k1_counts(after):
        K1_INVENTORY.write_text(before_text)
        raise RefusedError(
            "k1 inventory: per-category counts changed "
            f"{dict(k1_counts(before))} -> {dict(k1_counts(after))}; classify first"
        )
    moved = 0
    for old, new in zip(before["entries"], after["entries"]):
        if old != new:
            moved += 1
    return moved


def reconcile_k1_taxonomy() -> int:
    taxonomy_checker = load_script("check-k1-file-authority-taxonomy.py")
    authority = taxonomy_checker.AUTHORITY_CATEGORIES
    inventory = json.loads(K1_INVENTORY.read_text())
    taxonomy = json.loads(K1_TAXONOMY.read_text())

    def group(entry: dict) -> tuple:
        return (entry["file"], tuple(entry["categories"]), entry["text"], entry["scope_kind"])

    fresh: dict[tuple, list[dict]] = collections.defaultdict(list)
    for entry in inventory["entries"]:
        if authority.intersection(entry["categories"]):
            fresh[group(entry)].append(entry)
    current: dict[tuple, list[dict]] = collections.defaultdict(list)
    for entry in taxonomy["entries"]:
        current[group(entry)].append(entry)
    if set(fresh) != set(current):
        raise RefusedError(
            "k1 taxonomy: authority groups added="
            f"{sorted(set(fresh) - set(current))} removed={sorted(set(current) - set(fresh))}"
        )
    moved = 0
    for key, olds in current.items():
        news = sorted(fresh[key], key=lambda e: e["line"])
        olds.sort(key=lambda e: e["line"])
        if len(news) != len(olds):
            raise RefusedError(f"k1 taxonomy: group {key} count {len(olds)} -> {len(news)}")
        for old, new in zip(olds, news):
            if old["line"] != new["line"]:
                old["line"] = new["line"]
                moved += 1
    if moved:
        taxonomy["entries"].sort(key=lambda e: (e["file"], e["line"]))
        write_json(K1_TAXONOMY, taxonomy)
    return moved


def main() -> int:
    steps = (
        ("runtime-aborts fingerprints", reconcile_runtime_aborts),
        ("host-authority positions", reconcile_host_authority),
        ("dispatch-lock-authority lines", reconcile_dispatch_locks),
        ("k1 operation inventory", reconcile_k1_inventory),
        ("k1 callsite taxonomy", reconcile_k1_taxonomy),
    )
    refused: list[str] = []
    for label, step in steps:
        try:
            print(f"{label}: {step()} rebound")
        except RefusedError as error:
            refused.append(str(error))
            print(f"{label}: REFUSED ({error})")
    if refused:
        print("review required before these inventories can be re-blessed:", file=sys.stderr)
        for message in refused:
            print(f"  - {message}", file=sys.stderr)
        return 1
    print("inventories reconciled; review `git diff` (positions only) and commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
