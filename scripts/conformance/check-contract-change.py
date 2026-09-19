#!/usr/bin/env python3
"""Check that changed guest surfaces have matching conformance contract evidence."""

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Tooling, test, and host crates outside guest execution surfaces
NON_GUEST_CRATES = {
    "crates/carrick-conformance-contract",
    "crates/carrick-conformance",
    "crates/carrick-conformance-next",
    "crates/carrick-test-support",
    "crates/carrick-observability",
}


def is_full_sha(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", s))


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
                contracts[cid] = data
    return contracts


def is_evidence_path(path: str, contract_id: str, contracts: dict, surfaces: dict) -> bool:
    # Contract descriptor itself is evidence
    for fname in (f"{contract_id}.toml", f"{contract_id.split('.')[-1]}.toml"):
        if path.endswith(fname):
            return True

    # If the surface path contains tests or probes, it's evidence
    if "/tests/" in path or "conformance-probes/" in path or path.endswith("_test.rs"):
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


def load_and_validate_exemptions(exemptions_dir: Path, valid_contracts: set, diff_paths: set, base_sha: str, head_sha: str):
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

        # Check applicability to this diff
        if base == base_sha and head == head_sha:
            for path in paths:
                if path not in diff_paths:
                    sys.stderr.write(f"exemption error: {p.name} path {path} not in diff\n")
                    sys.exit(1)
                exempted_paths.add(path)

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

    # Load and validate exemptions
    exempted_paths = load_and_validate_exemptions(exemptions_dir, valid_contracts, all_diff_paths, base_sha, head_sha)

    # Check for unclassified new paths under crates/
    unclassified = []
    for path in added_paths:
        if path.startswith("crates/") and path not in surfaces and path not in exempted_paths and path not in byte_identical_renames:
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
        if path in byte_identical_renames or path in exempted_paths:
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
