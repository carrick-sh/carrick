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


def load_script(name: str, root: Path = ROOT):
    """Import a sibling checker as a module so its scanner is the authority."""
    migrate_dir = root / "scripts/migrate"
    script_path = migrate_dir / name
    if not script_path.is_file():
        script_path = ROOT / "scripts/migrate" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def normalize_function_name(name: str) -> str:
    """Strip leading lowercase module segments: helper::reset -> reset, helper::Foo::bar -> Foo::bar."""
    parts = name.split("::")
    for i, part in enumerate(parts):
        if part and part[0].isupper():
            return "::".join(parts[i:])
    return parts[-1]


PATH_KEYS = ("path", "file")


def apply_renames(rows, renames):
    """Rewrite the path field of each row whose path starts with an OLD prefix."""
    pairs = [r.split("=", 1) for r in renames]
    changed = 0
    for row in rows:
        for key in PATH_KEYS:
            value = row.get(key)
            if not isinstance(value, str):
                continue
            for old, new in pairs:
                if value.startswith(old):
                    row[key] = new + value[len(old) :]
                    changed += 1
                    break
    return changed


def apply_dispatch_lock_renames(rows, renames):
    """Rewrite `file` on dispatch-lock rows AND the path prefix inside `id`.

    A dispatch-lock row's identity is `f"{file}::{item}::{category}#{ordinal}"`,
    so the generic `apply_renames` (which only touches `PATH_KEYS`) leaves the
    `id` pointing at the old path. The reconciler then finds no id match, falls
    into the rehome matcher, and keys on `(item, category, expression,
    ordinal)` -- which is 1:N the moment two files hold a same-named item (it
    is: `SyntheticProcContext::synthetic_proc_context_observed` exists in both
    `dispatch/fs.rs` and `dispatch/mod.rs`). Rebinding the id prefix here keeps
    the move a 1:1 id match, which is the whole point of `--rename`.
    """
    pairs = [r.split("=", 1) for r in renames]
    changed = 0
    for row in rows:
        old_file = row.get("file")
        if not isinstance(old_file, str):
            continue
        for old, new in pairs:
            if old_file.startswith(old):
                new_file = new + old_file[len(old) :]
                row["file"] = new_file
                row_id = row.get("id")
                if isinstance(row_id, str) and row_id.startswith(old_file + "::"):
                    row["id"] = new_file + row_id[len(old_file) :]
                changed += 1
                break
    return changed


def collect_scan_targets(rows):
    """`rows` plus any nested `source` sub-object each row carries.

    Most inventories keep `path`/`file` directly on the row
    (dispatch-lock-authority.json, the k1 inventories, the runtime-aborts
    shards); `host-authority-transition-inventory.json` instead nests it
    under `row["source"]["file"]`. `apply_renames` only ever looks at the
    top level of whatever it is given, so this is the one place that widens
    the scan to include that nested shape too.
    """
    targets = list(rows)
    for row in rows:
        source = row.get("source") if isinstance(row, dict) else None
        if isinstance(source, dict):
            targets.append(source)
    return targets


def apply_host_authority_renames(rows, renames):
    """Rewrite `source.file` on host-authority rows AND rebind the
    `At <file>:<line>` prefix embedded in `rationale` prose to match.

    `check-host-authority-transitions.py`'s `validate_source_specific_reviews`
    requires the exact `f"{source.file}:{source.line}"` string to appear
    inside `rationale`. The generic `apply_renames` (via `collect_scan_targets`)
    only ever rewrites the nested `source.file` field -- it has no way to see
    the sibling `rationale` string on the same row -- so a rename left the two
    fields pointing at different files and broke that binding. This walks the
    actual row list (not the flattened `collect_scan_targets` view) so both
    fields on one row are available together, and edits them as a pair.
    Only the file segment of the prose is corrected here; if the line number
    also moved, `reconcile_host_authority_positions`'s own
    `At <file>:<line>` matcher rebinds that once `source.file` already agrees.
    """
    pairs = [r.split("=", 1) for r in renames]
    changed = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        source = row.get("source")
        if not isinstance(source, dict):
            continue
        old_file = source.get("file")
        if not isinstance(old_file, str):
            continue
        new_file = None
        for old, new in pairs:
            if old_file.startswith(old):
                new_file = new + old_file[len(old) :]
                break
        if new_file is None or new_file == old_file:
            continue
        source["file"] = new_file
        changed += 1
        rationale = row.get("rationale")
        if isinstance(rationale, str):
            stale = f"At {old_file}:"
            if stale in rationale:
                row["rationale"] = rationale.replace(stale, f"At {new_file}:", 1)
    return changed


def reconcile_runtime_aborts(rehome: bool = False, root: Path = ROOT, renames=None) -> int:
    aborts = load_script("check-runtime-aborts.py", root=root)
    findings = aborts.discover_runtime_aborts(root)
    by_shard: dict[str, list] = collections.defaultdict(list)
    for finding in findings:
        by_shard[aborts.route_shard(finding.file)].append(finding)

    rebound = 0
    all_ledgers: dict[str, dict] = {}
    migrate_dir = root / "scripts/migrate"

    for shard in aborts.SHARD_NAMES:
        path = migrate_dir / "runtime-aborts" / shard
        if path.is_file():
            ledger = json.loads(path.read_text(encoding="utf-8"))
            apply_renames(collect_scan_targets(ledger["rows"]), renames or [])
            all_ledgers[shard] = ledger

    if not rehome:
        for shard in aborts.SHARD_NAMES:
            if shard not in all_ledgers:
                continue
            path = migrate_dir / "runtime-aborts" / shard
            ledger = all_ledgers[shard]
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

    # --- Rehome path ---
    matched_row_keys: set[tuple[str, str, int]] = set()
    matched_finding_keys: set[tuple[str, str, int]] = set()

    for shard, ledger in all_ledgers.items():
        live_for_shard = by_shard.get(shard, [])
        live_map = {(f.file, f.function, f.ordinal_in_function): f for f in live_for_shard}
        for row in ledger["rows"]:
            rkey = (row["file"], row["function"], row["ordinal_in_function"])
            if rkey in live_map:
                finding = live_map[rkey]
                matched_row_keys.add(rkey)
                matched_finding_keys.add(rkey)
                if row["fingerprint"] != finding.fingerprint:
                    row["fingerprint"] = finding.fingerprint
                    rebound += 1

    unmatched_rows: list[tuple[str, dict]] = []
    for shard, ledger in all_ledgers.items():
        for row in ledger["rows"]:
            rkey = (row["file"], row["function"], row["ordinal_in_function"])
            if rkey not in matched_row_keys:
                unmatched_rows.append((shard, row))

    unmatched_findings = [
        f for f in findings
        if (f.file, f.function, f.ordinal_in_function) not in matched_finding_keys
    ]

    if unmatched_rows or unmatched_findings:
        row_matches: dict[int, list] = collections.defaultdict(list)
        finding_matches: dict[int, list] = collections.defaultdict(list)

        for shard, row in unmatched_rows:
            norm_fn = normalize_function_name(row["function"])
            for finding in unmatched_findings:
                f_norm_fn = normalize_function_name(finding.function)
                if (
                    (row["function"] == finding.function or norm_fn == f_norm_fn)
                    and row["ordinal_in_function"] == finding.ordinal_in_function
                    and row["fingerprint"] == finding.fingerprint
                ):
                    row_matches[id(row)].append(finding)
                    finding_matches[id(finding)].append((shard, row))

        for shard, row in unmatched_rows:
            matches = row_matches.get(id(row), [])
            if len(matches) == 0:
                raise RefusedError(
                    f"runtime-aborts/{shard}: abort site removed or fingerprint changed (refused): "
                    f"{(row['file'], row['function'], row['ordinal_in_function'])}"
                )
            if len(matches) > 1:
                raise RefusedError(
                    f"runtime-aborts: ambiguous 1:N match for {row['function']}#{row['ordinal_in_function']}: "
                    f"{[(f.file, f.function) for f in matches]}"
                )

        for finding in unmatched_findings:
            matches = finding_matches.get(id(finding), [])
            if len(matches) == 0:
                raise RefusedError(
                    f"runtime-aborts: abort site added: "
                    f"{(finding.file, finding.function, finding.ordinal_in_function)}"
                )
            if len(matches) > 1:
                raise RefusedError(
                    f"runtime-aborts: ambiguous N:1 match for {finding.function}#{finding.ordinal_in_function}"
                )

        for shard, row in unmatched_rows:
            finding = row_matches[id(row)][0]
            target_shard = aborts.route_shard(finding.file)
            row["file"] = finding.file
            row["function"] = finding.function
            row["ordinal_in_function"] = finding.ordinal_in_function
            if target_shard != shard:
                all_ledgers[shard]["rows"].remove(row)
                all_ledgers[target_shard]["rows"].append(row)
            rebound += 1

    for shard, ledger in all_ledgers.items():
        write_json(migrate_dir / "runtime-aborts" / shard, ledger)

    return rebound


def reconcile_host_authority(
    rehome: bool = False,
    root: Path = ROOT,
    candidate_path: Path | None = None,
    inventory_path: Path | None = None,
    capture_path: Path | None = None,
    renames=None,
    runner=subprocess.run,
) -> int:
    rha = load_script("reconcile-host-authority-positions.py", root=root)
    migrate_dir = root / "scripts/migrate"
    inv_path = inventory_path or (migrate_dir / "host-authority-transition-inventory.json")
    cap_path = capture_path or (migrate_dir / "host-authority-macos-capture.json")

    def apply_inventory_renames() -> None:
        # `reconcile_host_authority_positions` loads inv_path itself, so this
        # is the single point where its rows can be renamed before that load:
        # rewrite the tracked file on disk. This MUST happen only after any
        # live `--refresh-candidate` capture below has already run against
        # the still-clean tree: `product_source_snapshot` requires a clean
        # tracked tree over `scripts/` (PRODUCT_SOURCE_PATHS includes
        # "scripts"), so writing here any earlier would dirty the very tree
        # the capture needs to snapshot, and it would then refuse with
        # "commit the code change first" -- blaming the operator for dirt
        # this function authored itself.
        if not renames or not inv_path.is_file():
            return
        inventory = json.loads(inv_path.read_text(encoding="utf-8"))
        if isinstance(inventory, list) and apply_host_authority_renames(inventory, renames):
            write_json(inv_path, inventory)

    if candidate_path is not None:
        # No live capture in this branch (the caller supplied a candidate
        # directly, e.g. a test fixture), so there is no clean-tree
        # precondition to protect and renaming up front is safe.
        apply_inventory_renames()
        try:
            return rha.reconcile_host_authority_positions(
                candidate_path=candidate_path,
                inventory_path=inv_path,
                capture_path=cap_path,
                rehome=rehome,
                root=root,
            )
        except rha.RefusedError as e:
            raise RefusedError(str(e)) from e

    with tempfile.TemporaryDirectory() as tmp:
        candidate = Path(tmp) / "candidate.json"
        runner(
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
                raise RefusedError(
                    "host-authority: the authoritative capture needs a clean tracked "
                    "tree -- commit the code change first, then rerun"
                )
            raise RefusedError("host-authority: --refresh-candidate produced no candidate")

        # The capture already ran against the clean tree above; it is now
        # safe to rewrite the tracked inventory in place.
        apply_inventory_renames()

        try:
            return rha.reconcile_host_authority_positions(
                candidate_path=candidate,
                inventory_path=inv_path,
                capture_path=cap_path,
                rehome=rehome,
                root=root,
            )
        except rha.RefusedError as e:
            raise RefusedError(str(e)) from e


def reconcile_dispatch_locks(
    rehome: bool = False,
    root: Path = ROOT,
    candidate_path: Path | None = None,
    inventory_path: Path | None = None,
    renames=None,
) -> int:
    path = inventory_path or (root / "scripts/migrate/dispatch-lock-authority.json")
    if candidate_path is not None:
        fresh = json.loads(Path(candidate_path).read_text(encoding="utf-8"))
    else:
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
            fresh = json.loads(candidate.read_text(encoding="utf-8"))

    inventory = json.loads(path.read_text(encoding="utf-8"))

    def rows(document: dict) -> list[dict]:
        for value in document.values():
            if isinstance(value, list) and value and isinstance(value[0], dict) and "id" in value[0]:
                return value
        for key in ("sites", "rows", "locks"):
            if key in document and isinstance(document[key], list):
                return document[key]
        raise RefusedError("dispatch-lock-authority: no row list found")

    fresh_rows = rows(fresh)
    inventory_rows = rows(inventory)
    apply_dispatch_lock_renames(inventory_rows, renames or [])

    fresh_by_id = {r["id"]: r for r in fresh_rows}
    inventory_ids = {r["id"] for r in inventory_rows}

    if not rehome:
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

    # --- Rehome path ---
    matched_ids = set(fresh_by_id) & inventory_ids
    rebound = 0
    for row in inventory_rows:
        if row["id"] in matched_ids:
            fresh_row = fresh_by_id[row["id"]]
            for field in ("expression", "item", "category", "file"):
                if row[field] != fresh_row[field]:
                    raise RefusedError(f"dispatch-lock-authority: {row['id']} changed {field}")
            if row["line"] != fresh_row["line"]:
                row["line"] = fresh_row["line"]
                rebound += 1

    unmatched_inv = [r for r in inventory_rows if r["id"] not in matched_ids]
    unmatched_fresh = [r for r in fresh_rows if r["id"] not in matched_ids]

    if unmatched_inv or unmatched_fresh:
        def lock_key(r: dict) -> tuple:
            return (r["item"], r["category"], r["expression"], r["ordinal"])

        inv_matches: dict[int, list[dict]] = collections.defaultdict(list)
        fresh_matches: dict[int, list[dict]] = collections.defaultdict(list)

        for inv_row in unmatched_inv:
            k = lock_key(inv_row)
            for f_row in unmatched_fresh:
                if lock_key(f_row) == k:
                    inv_matches[id(inv_row)].append(f_row)
                    fresh_matches[id(f_row)].append(inv_row)

        for inv_row in unmatched_inv:
            matches = inv_matches.get(id(inv_row), [])
            if len(matches) == 0:
                raise RefusedError(f"dispatch-lock-authority: lock site removed or modified: {inv_row['id']}")
            if len(matches) > 1:
                raise RefusedError(f"dispatch-lock-authority: ambiguous 1:N match for {inv_row['id']}")

        for f_row in unmatched_fresh:
            matches = fresh_matches.get(id(f_row), [])
            if len(matches) == 0:
                raise RefusedError(f"dispatch-lock-authority: lock site added: {f_row['id']}")
            if len(matches) > 1:
                raise RefusedError(f"dispatch-lock-authority: ambiguous N:1 match for {f_row['id']}")

        for inv_row in unmatched_inv:
            fresh_row = inv_matches[id(inv_row)][0]
            inv_row["id"] = fresh_row["id"]
            inv_row["file"] = fresh_row["file"]
            inv_row["line"] = fresh_row["line"]
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


def reconcile_k1_inventory(rehome: bool = False, root: Path = ROOT) -> int:
    inv_path = root / "scripts/migrate/k1-file-authority-operation-inventory.json"
    before_text = inv_path.read_text(encoding="utf-8")
    before = json.loads(before_text)
    subprocess.run(
        [sys.executable, str(MIGRATE / "check-k1-file-authority-inventory.py"), "--write"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    after = json.loads(inv_path.read_text(encoding="utf-8"))
    if k1_counts(before) != k1_counts(after):
        inv_path.write_text(before_text, encoding="utf-8")
        raise RefusedError(
            "k1 inventory: per-category counts changed "
            f"{dict(k1_counts(before))} -> {dict(k1_counts(after))}; classify first"
        )
    moved = 0
    for old, new in zip(before["entries"], after["entries"]):
        if old != new:
            moved += 1
    return moved


def reconcile_k1_taxonomy(
    rehome: bool = False,
    root: Path = ROOT,
    inventory_path: Path | None = None,
    taxonomy_path: Path | None = None,
    renames=None,
) -> int:
    taxonomy_checker = load_script("check-k1-file-authority-taxonomy.py", root=root)
    authority = taxonomy_checker.AUTHORITY_CATEGORIES
    inv_path = inventory_path or (root / "scripts/migrate/k1-file-authority-operation-inventory.json")
    tax_path = taxonomy_path or (root / "scripts/migrate/k1-file-authority-callsite-taxonomy.json")
    inventory = json.loads(inv_path.read_text(encoding="utf-8"))
    taxonomy = json.loads(tax_path.read_text(encoding="utf-8"))
    # k1-file-authority-operation-inventory.json is regenerated wholesale from
    # the (already moved) source tree by reconcile_k1_inventory earlier in the
    # pipeline, so only the pinned taxonomy rows still carry pre-move paths.
    renamed = apply_renames(collect_scan_targets(taxonomy["entries"]), renames or [])

    def group(entry: dict) -> tuple:
        return (entry["file"], tuple(entry["categories"]), entry["text"], entry["scope_kind"])

    fresh: dict[tuple, list[dict]] = collections.defaultdict(list)
    for entry in inventory["entries"]:
        if authority.intersection(entry["categories"]):
            fresh[group(entry)].append(entry)
    current: dict[tuple, list[dict]] = collections.defaultdict(list)
    for entry in taxonomy["entries"]:
        current[group(entry)].append(entry)

    if not rehome:
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
        if moved or renamed:
            taxonomy["entries"].sort(key=lambda e: (e["file"], e["line"]))
            write_json(tax_path, taxonomy)
        return moved

    # --- Rehome path ---
    matched_current_ids: set[int] = set()
    matched_fresh_ids: set[int] = set()
    moved = 0

    common_groups = set(fresh) & set(current)
    for grp in common_groups:
        olds = sorted(current[grp], key=lambda e: e["line"])
        news = sorted(fresh[grp], key=lambda e: e["line"])
        if len(olds) == len(news):
            for old, new in zip(olds, news):
                matched_current_ids.add(id(old))
                matched_fresh_ids.add(id(new))
                if old["line"] != new["line"]:
                    old["line"] = new["line"]
                    moved += 1

    all_fresh_authority = [
        e for e in inventory["entries"] if authority.intersection(e["categories"])
    ]
    unmatched_current = [e for e in taxonomy["entries"] if id(e) not in matched_current_ids]
    unmatched_fresh = [e for e in all_fresh_authority if id(e) not in matched_fresh_ids]

    if unmatched_current or unmatched_fresh:
        rha = load_script("reconcile-host-authority-positions.py", root=root)
        brace_deltas_fn = rha.load_brace_deltas(root)
        find_fn = rha.find_enclosing_function

        file_cache: dict[str, list[str]] = {}

        def get_source_lines(rel_file: str) -> list[str]:
            if rel_file not in file_cache:
                p = root / rel_file if not Path(rel_file).is_absolute() else Path(rel_file)
                if not p.is_file():
                    file_cache[rel_file] = []
                else:
                    file_cache[rel_file] = p.read_text(encoding="utf-8").splitlines()
            return file_cache[rel_file]

        def get_fresh_fn(entry: dict) -> str | None:
            rel_file = entry["file"]
            line_num = entry["line"]
            lines = get_source_lines(rel_file)
            if not lines:
                return None
            return find_fn(lines, line_num, brace_deltas_fn)

        current_matches: dict[int, list[dict]] = collections.defaultdict(list)
        fresh_matches: dict[int, list[dict]] = collections.defaultdict(list)

        for curr in unmatched_current:
            curr_fn = curr.get("enclosing_function")
            for fr in unmatched_fresh:
                fr_fn = get_fresh_fn(fr)
                if (
                    tuple(fr["categories"]) == tuple(curr["categories"])
                    and fr["text"] == curr["text"]
                    and fr["scope_kind"] == curr["scope_kind"]
                    and fr_fn is not None
                    and curr_fn is not None
                    and fr_fn == curr_fn
                ):
                    current_matches[id(curr)].append(fr)
                    fresh_matches[id(fr)].append(curr)

        for curr in unmatched_current:
            matches = current_matches.get(id(curr), [])
            if len(matches) == 0:
                raise RefusedError(
                    f"k1 taxonomy: site removed or modified: {curr['file']}:{curr['line']} "
                    f"({curr.get('enclosing_function')})"
                )
            if len(matches) > 1:
                raise RefusedError(
                    f"k1 taxonomy: ambiguous 1:N match for {curr['file']}:{curr['line']} "
                    f"({curr.get('enclosing_function')})"
                )

        for fr in unmatched_fresh:
            matches = fresh_matches.get(id(fr), [])
            if len(matches) == 0:
                raise RefusedError(
                    f"k1 taxonomy: site added: {fr['file']}:{fr['line']} "
                    f"({get_fresh_fn(fr)})"
                )
            if len(matches) > 1:
                raise RefusedError(
                    f"k1 taxonomy: ambiguous N:1 match for {fr['file']}:{fr['line']} "
                    f"({get_fresh_fn(fr)})"
                )

        for curr in unmatched_current:
            fr = current_matches[id(curr)][0]
            curr["file"] = fr["file"]
            curr["line"] = fr["line"]
            moved += 1

    if moved or renamed:
        taxonomy["entries"].sort(key=lambda e: (e["file"], e["line"]))
        write_json(tax_path, taxonomy)
    return moved


def rename_only(inventory_path: Path, renames: list[str]) -> int:
    """Apply --rename to one inventory file directly and exit; the test hook.

    Handles the row shapes the reconciler's own inventories use: a bare list
    of rows (host-authority-transition-inventory.json), or a dict whose
    value(s) are lists of rows (the `entries` / `rows` wrapped documents).
    """
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if isinstance(document, list):
        row_lists = [document]
    elif isinstance(document, dict):
        row_lists = [
            value
            for value in document.values()
            if isinstance(value, list) and value and isinstance(value[0], dict)
        ]
        if not row_lists:
            raise RefusedError(f"--rename-only: no row list found in {inventory_path}")
    else:
        raise RefusedError(f"--rename-only: unsupported document shape in {inventory_path}")

    changed = 0
    for rows in row_lists:
        changed += apply_renames(collect_scan_targets(rows), renames)
    write_json(inventory_path, document)
    print(f"--rename-only: {changed} path(s) rewritten in {inventory_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rehome", action="store_true", help="Re-home reviewed rows when functions move files")
    parser.add_argument(
        "--rename",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="rewrite inventory paths starting with OLD to start with NEW before reconciling",
    )
    parser.add_argument(
        "--rename-only",
        metavar="INVENTORY_JSON",
        help="apply --rename to one inventory file and exit (test hook)",
    )
    args = parser.parse_args(argv)

    if args.rename_only is not None:
        try:
            return rename_only(Path(args.rename_only), args.rename)
        except RefusedError as error:
            print(f"--rename-only: REFUSED ({error})", file=sys.stderr)
            return 1

    if args.rename and not args.rehome:
        print(
            "--rename requires --rehome: fingerprints cannot be verified at the old path",
            file=sys.stderr,
        )
        return 1

    steps = (
        (
            "host-authority positions",
            lambda: reconcile_host_authority(rehome=args.rehome, renames=args.rename),
        ),
        (
            "runtime-aborts fingerprints",
            lambda: reconcile_runtime_aborts(rehome=args.rehome, renames=args.rename),
        ),
        (
            "dispatch-lock-authority lines",
            lambda: reconcile_dispatch_locks(rehome=args.rehome, renames=args.rename),
        ),
        ("k1 operation inventory", lambda: reconcile_k1_inventory(rehome=args.rehome)),
        (
            "k1 callsite taxonomy",
            lambda: reconcile_k1_taxonomy(rehome=args.rehome, renames=args.rename),
        ),
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
    raise SystemExit(main(sys.argv[1:]))
