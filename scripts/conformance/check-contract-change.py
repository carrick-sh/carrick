#!/usr/bin/env python3
"""Check that changed guest surfaces have matching conformance contract evidence."""

import argparse
import os
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

# Tooling, test, and host crates outside guest execution surfaces
NON_GUEST_CRATES = {
    "crates/carrick-conformance-contract",
    "crates/carrick-conformance",
    "crates/carrick-conformance-next",
    "crates/carrick-coordinator",
    "crates/carrick-investigation",
    "crates/carrick-test-support",
    "crates/carrick-observability",
    "crates/carrick-ring-audit",
    "crates/carrick-xtask",
}

_VIS_PREFIX = r"(?:pub(?:\s*\(\s*(?:crate|super|self|in\s+[A-Za-z0-9_:]+)\s*\))?\s+)?"
_MOD_DECL_RE = re.compile(rf"^{_VIS_PREFIX}mod\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*\s*;$")
_USE_DECL_RE = re.compile(rf"^{_VIS_PREFIX}use\s+(.+)$")
_USE_BODY_CHARS_RE = re.compile(r"^[A-Za-z0-9_:\s,\{\}\*#]+$")


def is_full_sha(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", s))


def is_comment_or_outer_attr(stripped: str) -> bool:
    if stripped.startswith("//") and not stripped.startswith("//!"):
        return True
    if stripped.startswith("#[") and stripped.endswith("]"):
        return True
    return False


def match_allowlisted_decl_at(lines: list[str], index: int) -> int:
    """If lines[index:] starts with an allowlisted mod/use declaration, return the number of lines consumed."""
    line = lines[index]
    if _MOD_DECL_RE.match(line):
        return 1

    m = _USE_DECL_RE.match(line)
    if not m:
        return 0

    rest = m.group(1).strip()
    if rest.endswith(";"):
        body = rest[:-1].strip()
        if body and _USE_BODY_CHARS_RE.match(body) and body.count("{") == body.count("}"):
            return 1
        return 0

    if not _USE_BODY_CHARS_RE.match(rest):
        return 0
    depth = rest.count("{") - rest.count("}")
    if depth <= 0:
        return 0

    cursor = index + 1
    while cursor < len(lines) and depth > 0:
        cont = lines[cursor]
        if not cont:
            return 0
        if cont.endswith(";"):
            body = cont[:-1].strip()
            if not body or not _USE_BODY_CHARS_RE.match(body):
                return 0
            depth += body.count("{") - body.count("}")
            if depth == 0:
                return (cursor - index) + 1
            return 0
        if not _USE_BODY_CHARS_RE.match(cont):
            return 0
        depth += cont.count("{") - cont.count("}")
        if depth <= 0:
            return 0
        cursor += 1

    return 0


def classify_hunk_removed_blocks(raw_removed: list[str]) -> Counter:
    """Split a hunk's removed lines at blank lines into ordered contiguous blocks."""
    removed_blocks: Counter = Counter()
    current: list[str] = []
    for raw_line in raw_removed:
        stripped = raw_line.strip()
        if stripped == "":
            if current:
                removed_blocks[tuple(current)] += 1
                current = []
        else:
            current.append(stripped)
    if current:
        removed_blocks[tuple(current)] += 1
    return removed_blocks


def classify_hunk_added_blocks(raw_added: list[str]) -> tuple[Counter, Counter]:
    """Classify a hunk's added lines into (required_move_blocks, allowlisted_decl_blocks)."""
    stripped_lines = [line.strip() for line in raw_added]
    is_decl = [False] * len(stripped_lines)

    i = 0
    n = len(stripped_lines)
    while i < n:
        if stripped_lines[i] == "":
            i += 1
            continue

        # Check for a contiguous run of comments/outer attributes attached to a mod/use declaration.
        j = i
        while j < n and stripped_lines[j] != "" and is_comment_or_outer_attr(stripped_lines[j]):
            j += 1

        if j < n:
            decl_len = match_allowlisted_decl_at(stripped_lines, j)
            if decl_len > 0:
                for k in range(i, j + decl_len):
                    is_decl[k] = True
                i = j + decl_len
                continue

        decl_len = match_allowlisted_decl_at(stripped_lines, i)
        if decl_len > 0:
            for k in range(i, i + decl_len):
                is_decl[k] = True
            i += decl_len
            continue

        i += 1

    req_blocks: Counter = Counter()
    decl_blocks: Counter = Counter()
    current_req: list[str] = []
    current_decl: list[str] = []

    def flush_req():
        nonlocal current_req
        if current_req:
            req_blocks[tuple(current_req)] += 1
            current_req = []

    def flush_decl():
        nonlocal current_decl
        if current_decl:
            decl_blocks[tuple(current_decl)] += 1
            current_decl = []

    for line, decl in zip(stripped_lines, is_decl):
        if line == "":
            flush_req()
            flush_decl()
            continue
        if decl:
            flush_req()
            current_decl.append(line)
        else:
            flush_decl()
            current_req.append(line)

    flush_req()
    flush_decl()
    return req_blocks, decl_blocks


def parse_file_diff(root: Path, base_sha: str, head_sha: str, path: str) -> tuple[Counter, Counter, Counter]:
    """Return (removed_blocks, required_added_blocks, allowlisted_decl_added_blocks) for path."""
    res = subprocess.run(
        [
            "git",
            "--literal-pathspecs",
            "diff",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "-U0",
            base_sha,
            head_sha,
            "--",
            path,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    removed: Counter = Counter()
    req_added: Counter = Counter()
    decl_added: Counter = Counter()

    in_hunk = False
    current_hunk_removed: list[str] = []
    current_hunk_added: list[str] = []

    def flush_hunk():
        nonlocal current_hunk_removed, current_hunk_added
        if current_hunk_removed:
            removed.update(classify_hunk_removed_blocks(current_hunk_removed))
            current_hunk_removed = []
        if current_hunk_added:
            h_req, h_decl = classify_hunk_added_blocks(current_hunk_added)
            req_added.update(h_req)
            decl_added.update(h_decl)
            current_hunk_added = []

    for raw_line in res.stdout.splitlines():
        if raw_line.startswith("@@ "):
            flush_hunk()
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw_line.startswith("-"):
            current_hunk_removed.append(raw_line[1:])
        elif raw_line.startswith("+"):
            current_hunk_added.append(raw_line[1:])

    flush_hunk()
    return removed, req_added, decl_added


def detect_move_covered_files(
    root: Path,
    base_sha: str,
    head_sha: str,
    candidate_paths: set[str],
) -> dict[str, int]:
    """Return {path: moved_line_count} for files whose diff is a pure move."""
    file_diffs: dict[str, tuple[Counter, Counter, Counter]] = {}
    for path in sorted(candidate_paths):
        if not path.endswith(".rs"):
            continue
        rem, req, decl = parse_file_diff(root, base_sha, head_sha, path)
        if rem or req or decl:
            file_diffs[path] = (rem, req, decl)

    candidates = set(file_diffs.keys())
    while candidates:
        # Phase 1: monotone per-file pruning. A file f can never be part of any
        # valid move subset of `candidates` if it removes a block more times than
        # all other candidates add it, or requires-adds a block more times than
        # all other candidates remove it.
        monotone_bad: set[str] = set()
        for f in candidates:
            rem_f, req_f, _ = file_diffs[f]
            for block, r_count in rem_f.items():
                other_add = sum(
                    file_diffs[g][1][block] + file_diffs[g][2][block]
                    for g in candidates
                    if g != f
                )
                if r_count > other_add:
                    monotone_bad.add(f)
                    break
            if f in monotone_bad:
                continue
            for block, a_count in req_f.items():
                other_rem = sum(file_diffs[g][0][block] for g in candidates if g != f)
                if a_count > other_rem:
                    monotone_bad.add(f)
                    break

        if monotone_bad:
            candidates -= monotone_bad
            continue

        # Phase 2: exact multiplicity across the remaining candidates.
        all_blocks: set[tuple[str, ...]] = set()
        for f in candidates:
            rem, req, decl = file_diffs[f]
            all_blocks.update(rem.keys())
            all_blocks.update(req.keys())
            all_blocks.update(decl.keys())

        bad_files: set[str] = set()
        for block in all_blocks:
            total_rem = sum(file_diffs[f][0][block] for f in candidates)
            total_req = sum(file_diffs[f][1][block] for f in candidates)
            caps = {
                f: min(
                    file_diffs[f][1][block] + file_diffs[f][2][block],
                    max(0, total_rem - file_diffs[f][0][block]),
                )
                for f in candidates
            }
            total_cap = sum(caps.values())

            block_ok = total_req <= total_rem <= total_cap
            if block_ok:
                for f in candidates:
                    r_f = file_diffs[f][0][block]
                    a_f = file_diffs[f][1][block]
                    if r_f + a_f > total_rem or r_f > (total_cap - caps[f]):
                        block_ok = False
                        break

            if not block_ok:
                for f in candidates:
                    if file_diffs[f][0][block] > 0 or file_diffs[f][1][block] > 0:
                        bad_files.add(f)

        if not bad_files:
            break
        candidates -= bad_files

    if not candidates:
        return {}

    moved_counts: dict[str, int] = {f: 0 for f in candidates}
    all_blocks = set()
    for f in candidates:
        rem, req, decl = file_diffs[f]
        all_blocks.update(rem.keys())
        all_blocks.update(req.keys())
        all_blocks.update(decl.keys())

    for block in all_blocks:
        total_rem = sum(file_diffs[f][0][block] for f in candidates)
        if total_rem == 0:
            continue
        caps = {
            f: min(
                file_diffs[f][1][block] + file_diffs[f][2][block],
                max(0, total_rem - file_diffs[f][0][block]),
            )
            for f in candidates
        }
        matched_add = {f: file_diffs[f][1][block] for f in candidates}
        remaining = total_rem - sum(matched_add.values())
        for f in sorted(candidates):
            if remaining <= 0:
                break
            spare = caps[f] - matched_add[f]
            if spare > 0:
                take = min(spare, remaining)
                matched_add[f] += take
                remaining -= take

        block_len = len(block)
        for f in candidates:
            moved_counts[f] += (file_diffs[f][0][block] + matched_add[f]) * block_len

    if sum(moved_counts.values()) == 0:
        return {}

    return moved_counts


def load_surfaces(root: Path):
    surfaces_file = root / "conformance-contracts" / "surfaces.toml"
    if not surfaces_file.exists():
        return {}
    with surfaces_file.open("rb") as f:
        data = tomllib.load(f)
    mapping = {}
    for entry in data.get("surfaces", []):
        mapping[entry["path"]] = entry.get("contracts", [])
    return mapping


def load_contracts(root: Path):
    contracts_dir = root / "conformance-contracts" / "contracts"
    contracts = {}
    if not contracts_dir.exists():
        return contracts
    for p in contracts_dir.glob("*.toml"):
        with p.open("rb") as f:
            data = tomllib.load(f)
            cid = data.get("id")
            if cid:
                data["_descriptor_path"] = p.relative_to(root).as_posix()
                contracts[cid] = data
    return contracts


def is_evidence_path(path: str, contract_id: str, contracts: dict, surfaces: dict) -> bool:
    # Match the descriptor that actually declared this ID. Filenames are
    # not derived from IDs (scheduler-cost.toml declares preemption-cost).
    if path == contracts.get(contract_id, {}).get("_descriptor_path"):
        return True

    # If the surface path contains tests or probes, it's evidence
    if "/tests/" in path or "conformance-probes/" in path or path.endswith(("/tests.rs", "_test.rs", "_tests.rs")):
        return True

    # Check contract declared bindings
    contract_data = contracts.get(contract_id, {})
    bindings = contract_data.get("bindings", {})
    for layer, target in bindings.items():
        if isinstance(target, str):
            if target.startswith("probe:"):
                probe_name = target.split("probe:")[1]
                if probe_name in path:
                    return True
            elif "::" in target:
                crate_name = target.split("::")[0]
                if f"crates/{crate_name}/" in path and ("/tests/" in path or "/contracts.rs" in path or "contracts/" in path):
                    return True
    return False


def load_and_validate_exemptions(root: Path, exemptions_dir: Path, valid_contracts: set, diff_paths: set, base_sha: str, head_sha: str):
    exempted_paths = set()
    if not exemptions_dir.exists():
        return exempted_paths

    for p in exemptions_dir.glob("*.toml"):
        with p.open("rb") as f:
            data = tomllib.load(f)

        # Check schema
        if data.get("schema") != "carrick.conformance-exemption.v1":
            sys.stderr.write(f"exemption error: {p.name} invalid schema {data.get('schema')}\n")
            sys.exit(1)

        # Check revisions
        base = data.get("base", "")
        head = data.get("head", "")
        if not is_full_sha(base) or not is_full_sha(head):
            sys.stderr.write(f"exemption error: {p.name} base and head must be 40-character commit SHAs\n")
            sys.exit(1)

        # Check contracts
        contracts = data.get("contracts", [])
        for cid in contracts:
            if cid not in valid_contracts:
                sys.stderr.write(f"exemption error: {p.name} unknown contract ID {cid}\n")
                sys.exit(1)

        # Check rationale
        rationale = data.get("rationale", "")
        if len(rationale) < 40:
            sys.stderr.write(f"exemption error: {p.name} rationale must be at least 40 characters\n")
            sys.exit(1)
        if "performance out of scope" in rationale.lower():
            sys.stderr.write(f"exemption error: {p.name} rationale may not declare performance out of scope\n")
            sys.exit(1)

        # Check paths
        paths = data.get("paths", [])
        for path in paths:
            if any(ch in path for ch in ("*", "?", "[", "]")) or path.endswith("/"):
                sys.stderr.write(f"exemption error: {p.name} path contains glob or directory: {path}\n")
                sys.exit(1)

        # A receipt must be committed AFTER its reviewed head is known. It can
        # cover descendants (including a PR merge commit) only while every
        # exact reviewed path remains byte-identical to that ancestor.
        if base == base_sha:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", head, head_sha],
                cwd=root, capture_output=True, check=False,
            )
            if ancestor.returncode != 0:
                continue
            for path in paths:
                if path not in diff_paths:
                    sys.stderr.write(f"exemption error: {p.name} path {path} not in diff\n")
                    sys.exit(1)
            unchanged = subprocess.run(
                ["git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff",
                 "--no-textconv", head, head_sha, "--", *paths],
                cwd=root, capture_output=True, check=False,
            )
            if unchanged.returncode == 0:
                exempted_paths.update(paths)

    return exempted_paths


def is_non_guest_path(path: str) -> bool:
    if not path.endswith(".rs"):
        return True
    if "/tests/" in path:
        return True
    for non_guest in NON_GUEST_CRATES:
        if path.startswith(non_guest + "/") or path == non_guest:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Check contract change coverage.")
    parser.add_argument("--root", default=".", help="Root directory")
    parser.add_argument("--base", required=True, help="Base commit SHA")
    parser.add_argument("--head", default="HEAD", help="Head commit SHA")
    parser.add_argument("--exemptions-dir", default=None, help="Exemptions directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    exemptions_dir = Path(args.exemptions_dir) if args.exemptions_dir else root / "docs" / "conformance-exemptions"

    # Resolve exact base and head full SHAs from git
    base_res = subprocess.run(["git", "rev-parse", args.base], cwd=root, capture_output=True, text=True, check=True)
    base_sha = base_res.stdout.strip()
    head_res = subprocess.run(["git", "rev-parse", args.head], cwd=root, capture_output=True, text=True, check=True)
    head_sha = head_res.stdout.strip()

    # Run git diff --name-status -M
    diff_cmd = ["git", "diff", "--name-status", "-M", base_sha, head_sha]
    diff_res = subprocess.run(diff_cmd, cwd=root, capture_output=True, text=True, check=True)

    surfaces = load_surfaces(root)
    contracts = load_contracts(root)
    valid_contracts = set(contracts.keys())

    all_diff_paths = set()
    added_paths = set()
    modified_paths = set()
    byte_identical_renames = set()
    byte_identical_rename_sources = set()

    for line in diff_res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R"):
            old_path = parts[1]
            new_path = parts[2]
            all_diff_paths.add(old_path)
            all_diff_paths.add(new_path)
            if status == "R100":
                byte_identical_renames.add(new_path)
                byte_identical_rename_sources.add(old_path)
            else:
                modified_paths.add(new_path)
        else:
            path = parts[1]
            all_diff_paths.add(path)
            if status == "A":
                added_paths.add(path)
                modified_paths.add(path)
            elif status != "D":
                modified_paths.add(path)

    move_candidates = all_diff_paths - byte_identical_renames - byte_identical_rename_sources
    move_covered = detect_move_covered_files(root, base_sha, head_sha, move_candidates)
    for path in sorted(move_covered):
        print(f"move-covered: {path} ({move_covered[path]} moved lines)")

    # Load and validate exemptions
    exempted_paths = load_and_validate_exemptions(root, exemptions_dir, valid_contracts, all_diff_paths, base_sha, head_sha)

    # Check for unclassified new paths under crates/
    unclassified = []
    for path in added_paths:
        if (
            path.startswith("crates/")
            and path not in surfaces
            and path not in exempted_paths
            and path not in byte_identical_renames
            and path not in move_covered
        ):
            if not is_non_guest_path(path):
                unclassified.append(path)

    if unclassified:
        sys.stderr.write(f"error: unclassified paths under crates/ found without surface mapping: {unclassified}\n")
        sys.exit(1)

    # Determine which contracts have evidence changed
    contracts_with_evidence = set()
    for path in modified_paths:
        if path in surfaces:
            for cid in surfaces[path]:
                if is_evidence_path(path, cid, contracts, surfaces):
                    contracts_with_evidence.add(cid)
        # Also check contract descriptor files
        for cid in contracts:
            if is_evidence_path(path, cid, contracts, surfaces):
                contracts_with_evidence.add(cid)

    # Check that each modified classified guest surface has evidence or is exempted
    uncovered = []
    for path in modified_paths:
        if path in byte_identical_renames or path in move_covered or path in exempted_paths:
            continue
        if path in surfaces:
            cids = surfaces[path]
            for cid in cids:
                if not is_evidence_path(path, cid, contracts, surfaces):
                    if cid not in contracts_with_evidence:
                        uncovered.append((path, cid))

    if uncovered:
        for path, cid in uncovered:
            sys.stderr.write(f"error: uncovered guest surface: {path} (contract: {cid}) requires contract/test evidence\n")
        sys.exit(1)

    print("conformance contract check passed: all changed surfaces covered or exempted")
    sys.exit(0)


if __name__ == "__main__":
    main()
