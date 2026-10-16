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


def is_test_or_probe_path(path: str) -> bool:
    return (
        "/tests/" in path
        or "conformance-probes/" in path
        or path.endswith(("/tests.rs", "_test.rs", "_tests.rs"))
    )


GATED_TEST_LANES = {"host", "kvm", "integration", "signed-cli", "signed-hvf"}

_ITEM_DECL_RE = re.compile(
    r"\b(?:fn|struct|enum|type|const|static|trait|union|mod)\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
    r"|\bmacro_rules!\s*(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
)

_GENERIC_ITEM_NAMES = {
    "new",
    "default",
    "from",
    "into",
    "try_from",
    "try_into",
    "drop",
    "fmt",
    "clone",
    "eq",
    "ne",
    "cmp",
    "partial_cmp",
    "hash",
    "deref",
    "deref_mut",
    "index",
    "index_mut",
    "next",
    "poll",
    "run",
    "main",
    "test",
    "tests",
}


class RepoView:
    """Read files and directory listings from either the working tree (when matching HEAD) or a git revision."""

    def __init__(self, root: Path, rev_sha: str, use_worktree: bool = False):
        self.root = root
        self.rev_sha = rev_sha
        self.use_worktree = use_worktree
        self._files: set[str] | None = None
        self._dirs: set[str] | None = None
        self._diff_from_wt: set[str] | None = None
        self._blob_cache: dict[str, bytes] = {}

    def _ensure_tree_index(self):
        if self._files is not None:
            return
        res = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", self.rev_sha],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        files: set[str] = set()
        dirs: set[str] = {""}
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                p = line.strip()
                if not p:
                    continue
                files.add(p)
                parts = p.split("/")
                for i in range(1, len(parts)):
                    dirs.add("/".join(parts[:i]))
        self._files = files
        self._dirs = dirs

        diff_res = subprocess.run(
            ["git", "diff", "--name-only", self.rev_sha],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        if diff_res.returncode == 0:
            self._diff_from_wt = {line.strip() for line in diff_res.stdout.splitlines() if line.strip()}
        else:
            self._diff_from_wt = set(files)

    def is_file(self, rel_path: str) -> bool:
        rel_path = rel_path.strip("/")
        if self.use_worktree:
            return (self.root / rel_path).is_file()
        self._ensure_tree_index()
        assert self._files is not None
        return rel_path in self._files

    def is_dir(self, rel_path: str) -> bool:
        rel_path = rel_path.strip("/")
        if self.use_worktree:
            return (self.root / rel_path).is_dir()
        self._ensure_tree_index()
        assert self._dirs is not None
        return rel_path in self._dirs

    def read_bytes(self, rel_path: str) -> bytes:
        rel_path = rel_path.strip("/")
        if self.use_worktree:
            return (self.root / rel_path).read_bytes()
        self._ensure_tree_index()
        assert self._diff_from_wt is not None
        if rel_path not in self._diff_from_wt and (self.root / rel_path).is_file():
            return (self.root / rel_path).read_bytes()
        if rel_path not in self._blob_cache:
            res = subprocess.run(
                ["git", "show", f"{self.rev_sha}:{rel_path}"],
                cwd=self.root,
                capture_output=True,
                check=True,
            )
            self._blob_cache[rel_path] = res.stdout
        return self._blob_cache[rel_path]

    def read_text(self, rel_path: str) -> str:
        return self.read_bytes(rel_path).decode("utf-8", errors="replace")

    def glob_files(self, rel_dir: str, suffix: str) -> list[str]:
        rel_dir = rel_dir.strip("/")
        if self.use_worktree:
            base = self.root / rel_dir
            if not base.is_dir():
                return []
            return sorted(
                p.relative_to(self.root).as_posix()
                for p in base.rglob(f"*{suffix}")
                if p.is_file()
            )
        self._ensure_tree_index()
        assert self._files is not None
        prefix = f"{rel_dir}/" if rel_dir else ""
        return sorted(
            p for p in self._files if p.startswith(prefix) and p.endswith(suffix)
        )


def load_surfaces_from_view(view: RepoView) -> dict[str, list[str]]:
    surfaces_path = "conformance-contracts/surfaces.toml"
    if not view.is_file(surfaces_path):
        return {}
    data = tomllib.loads(view.read_text(surfaces_path))
    mapping = {}
    for entry in data.get("surfaces", []):
        mapping[entry["path"]] = entry.get("contracts", [])
    return mapping


def load_contracts_from_view(view: RepoView) -> dict[str, dict]:
    contracts = {}
    for rel_path in view.glob_files("conformance-contracts/contracts", ".toml"):
        data = tomllib.loads(view.read_text(rel_path))
        cid = data.get("id")
        if cid:
            data["_descriptor_path"] = rel_path
            contracts[cid] = data
    return contracts


def _split_top_level_semicolons(raw: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in raw:
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth = max(0, depth - 1)
        if ch == ";" and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _expand_single_binding_clause(clause: str) -> list[str]:
    clause = clause.strip()
    if not clause or clause.startswith(("probe:", "ltp:", "go:", "cpython:", "node:")):
        return []

    idx = clause.find("carrick-")
    if idx > 0:
        clause = clause[idx:].strip()
    if not clause.startswith("carrick-") or "::" not in clause:
        return []

    # Check trailing `(...)`: either a list of Rust test identifiers or a prose annotation
    m = re.match(r"^([^\(\)]+?)\s*\(([^\(\)]+)\)\s*$", clause)
    if m:
        prefix = m.group(1).strip().rstrip(":")
        inner = m.group(2).strip()
        raw_items = [x.strip() for x in inner.split(",") if x.strip()]
        is_ident_list = bool(raw_items) and all(
            "_" in item and re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:_\s+[A-Za-z0-9_]+)?$", item)
            for item in raw_items
        )
        if is_ident_list:
            items = [re.sub(r"\s+", "", x) for x in raw_items]
            return [f"{prefix}::{item}" for item in items if item]
        clause = prefix

    # Expand `{a, b, ...}` brace groups recursively
    bm = re.search(r"\{([^{}]+)\}", clause)
    if bm:
        prefix = clause[: bm.start()]
        suffix = clause[bm.end() :]
        items = [re.sub(r"\s+", "", x) for x in bm.group(1).split(",") if x.strip()]
        expanded: list[str] = []
        for item in items:
            expanded.extend(_expand_single_binding_clause(f"{prefix}{item}{suffix}"))
        return expanded

    cleaned = re.sub(r"\s+", "", clause)
    if re.match(r"^carrick-[A-Za-z0-9_-]+(?:::[A-Za-z0-9_]+)+$", cleaned):
        return [cleaned]
    return []


def expand_binding_spec(raw: str) -> list[str]:
    out: list[str] = []
    for clause in _split_top_level_semicolons(raw):
        out.extend(_expand_single_binding_clause(clause))
    return out


def extract_contract_test_bindings(contract_data: dict) -> list[str]:
    bindings = contract_data.get("bindings", {})
    if not isinstance(bindings, dict):
        return []
    specs: list[str] = []
    seen: set[str] = set()
    for key in ("vm_free", "embed"):
        val = bindings.get(key)
        raw_list = [val] if isinstance(val, str) else val if isinstance(val, list) else []
        for raw in raw_list:
            if not isinstance(raw, str):
                continue
            for expanded in expand_binding_spec(raw):
                if expanded not in seen:
                    seen.add(expanded)
                    specs.append(expanded)
    return specs


def _file_defines_test_symbol(view: RepoView, rel_path: str, symbol: str) -> bool:
    if not view.is_file(rel_path):
        return False
    content = view.read_text(rel_path)
    if symbol == "tests":
        return bool(
            re.search(r"\bmod\s+tests\b", content)
            and re.search(r"#\[(?:[\w:]+::)?test\b", content)
        )
    return bool(re.search(rf"\bfn\s+(?:r#)?{re.escape(symbol)}\b", content))


def _discover_integration_targets(view: RepoView, pkg_name: str) -> dict[str, list[str]]:
    crate_dir = f"crates/{pkg_name}"
    targets: dict[str, list[str]] = {}

    cargo_toml = f"{crate_dir}/Cargo.toml"
    if view.is_file(cargo_toml):
        try:
            data = tomllib.loads(view.read_text(cargo_toml))
            for entry in data.get("test", []):
                if isinstance(entry, dict) and "name" in entry and "path" in entry:
                    tpath = f"{crate_dir}/{entry['path'].lstrip('/')}"
                    if view.is_file(tpath):
                        targets.setdefault(entry["name"], []).append(tpath)
        except Exception:
            pass

    tests_dir = f"{crate_dir}/tests"
    for rel_path in view.glob_files(tests_dir, ".rs"):
        sub = rel_path[len(tests_dir) + 1 :]
        parts = sub.split("/")
        if len(parts) == 1:
            tname = parts[0][:-3]
            targets.setdefault(tname, []).append(rel_path)
        else:
            tname = parts[0]
            targets.setdefault(tname, []).append(rel_path)

    return targets


def resolve_binding_at_view(view: RepoView, spec: str) -> tuple[str, str, str] | None:
    """Resolve `pkg::...` at `view` to `(pkg_name, target_name, test_file_rel_path)` or None."""
    parts = [p.strip() for p in spec.split("::") if p.strip()]
    if len(parts) < 2:
        return None
    pkg_name = parts[0]
    rest = parts[1:]
    crate_dir = f"crates/{pkg_name}"
    if not view.is_dir(crate_dir):
        return None

    # 1. Try resolving as a unit test in the `lib` target (`crates/<pkg>/src/...`).
    src_dir = f"{crate_dir}/src"
    if view.is_dir(src_dir):
        for k in range(len(rest), -1, -1):
            mod_parts = rest[:k]
            candidates: list[str] = []
            if k == 0:
                candidates.extend([f"{src_dir}/lib.rs", f"{src_dir}/main.rs"])
            else:
                rel = "/".join(mod_parts)
                candidates.extend([f"{src_dir}/{rel}.rs", f"{src_dir}/{rel}/mod.rs"])
                if mod_parts[-1] == "tests" and k >= 2:
                    parent_rel = "/".join(mod_parts[:-1])
                    candidates.extend(
                        [f"{src_dir}/{parent_rel}_tests.rs", f"{src_dir}/{parent_rel}_test.rs"]
                    )
            for cand in candidates:
                if not view.is_file(cand):
                    continue
                if k == len(rest):
                    content = view.read_text(cand)
                    if re.search(r"#\[(?:[\w:]+::)?test\b", content) or re.search(
                        r"\bfn\s+test_", content
                    ):
                        return (pkg_name, "lib", cand)
                else:
                    fn_name = rest[-1]
                    if _file_defines_test_symbol(view, cand, fn_name):
                        return (pkg_name, "lib", cand)
                    cand_sub_dir = cand[:-7] if cand.endswith("/mod.rs") else cand[:-3]
                    if view.is_dir(cand_sub_dir):
                        for subfile in view.glob_files(cand_sub_dir, ".rs"):
                            if _file_defines_test_symbol(view, subfile, fn_name):
                                return (pkg_name, "lib", subfile)

    # 2. Try resolving in an integration test target (`crates/<pkg>/tests/...`).
    targets = _discover_integration_targets(view, pkg_name)
    if rest[0] in targets:
        tname = rest[0]
        tfiles = targets[tname]
        if len(rest) == 1:
            for tf in tfiles:
                content = view.read_text(tf)
                if re.search(r"#\[(?:[\w:]+::)?test\b", content) or re.search(
                    r"\bfn\s+", content
                ):
                    return (pkg_name, tname, tf)
        else:
            fn_name = rest[-1]
            submods = rest[1:-1]
            for tf in tfiles:
                if submods and not any(sm in tf for sm in submods):
                    continue
                if _file_defines_test_symbol(view, tf, fn_name):
                    return (pkg_name, tname, tf)
            for tf in tfiles:
                if _file_defines_test_symbol(view, tf, fn_name):
                    return (pkg_name, tname, tf)

    fn_name = rest[-1]
    submods = rest[:-1]
    for tname, tfiles in sorted(targets.items()):
        for tf in tfiles:
            if submods and not any(sm in tf for sm in submods):
                continue
            if _file_defines_test_symbol(view, tf, fn_name):
                return (pkg_name, tname, tf)
    for tname, tfiles in sorted(targets.items()):
        for tf in tfiles:
            if _file_defines_test_symbol(view, tf, fn_name):
                return (pkg_name, tname, tf)

    return None


def is_target_in_gated_lane(view: RepoView, pkg_name: str, target_name: str) -> bool:
    """Check `[package.metadata.carrick.test-lanes]` in `crates/<pkg>/Cargo.toml`."""
    cargo_toml = f"crates/{pkg_name}/Cargo.toml"
    if not view.is_file(cargo_toml):
        return True
    data = tomllib.loads(view.read_text(cargo_toml))
    lanes = (
        data.get("package", {})
        .get("metadata", {})
        .get("carrick", {})
        .get("test-lanes", {})
    )
    if not isinstance(lanes, dict):
        return True
    entry = lanes.get(target_name, lanes.get("*", "host"))
    if isinstance(entry, str):
        lane = entry
    elif isinstance(entry, dict):
        lane = entry.get("lane", "host")
    else:
        lane = "host"
    return lane in GATED_TEST_LANES


def is_same_crate_and_module_subtree(surface_path: str, test_file: str) -> bool:
    """Return True if `test_file` is in the same crate and module subtree as `surface_path`."""
    if not (surface_path.startswith("crates/") and test_file.startswith("crates/")):
        return False
    s_parts = surface_path.split("/")
    t_parts = test_file.split("/")
    if len(s_parts) < 3 or len(t_parts) < 3 or s_parts[1] != t_parts[1]:
        return False
    crate_src = f"crates/{s_parts[1]}/src/"
    if not (surface_path.startswith(crate_src) and test_file.startswith(crate_src)):
        return False
    if test_file == surface_path:
        return True
    if surface_path in (f"{crate_src}lib.rs", f"{crate_src}main.rs"):
        return True
    if surface_path.endswith("/mod.rs"):
        mod_dir = surface_path[: -len("mod.rs")]
        return test_file.startswith(mod_dir)
    if surface_path.endswith(".rs"):
        stem_prefix = surface_path[:-3]
        return (
            test_file.startswith(stem_prefix + "/")
            or test_file == stem_prefix + "_test.rs"
            or test_file == stem_prefix + "_tests.rs"
        )
    return False


def extract_changed_surface_items(
    root: Path,
    head_view: RepoView,
    base_sha: str,
    head_sha: str,
    surface_path: str,
) -> set[str]:
    """Extract function, type, const, trait, module, or macro identifiers defined or modified in `surface_path`'s diff."""
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
            surface_path,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    items: set[str] = set()
    hunk_new_starts: list[int] = []

    def add_matches(line: str):
        for m in _ITEM_DECL_RE.finditer(line):
            ident = m.group(1) or m.group(2)
            if ident and ident not in _GENERIC_ITEM_NAMES:
                items.add(ident)

    for raw_line in res.stdout.splitlines():
        if raw_line.startswith("@@ "):
            m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$", raw_line)
            if m:
                hunk_new_starts.append(int(m.group(1)))
                add_matches(m.group(2))
            continue
        if raw_line.startswith(("+++", "---")):
            continue
        if raw_line.startswith(("+", "-")):
            add_matches(raw_line[1:])

    if head_view.is_file(surface_path) and hunk_new_starts:
        lines = head_view.read_text(surface_path).splitlines()
        for start_line in hunk_new_starts:
            idx = min(max(start_line - 1, 0), len(lines) - 1) if lines else -1
            for k in range(idx, -1, -1):
                if _ITEM_DECL_RE.search(lines[k]):
                    add_matches(lines[k])
                    break

    return items


def bound_test_references_surface(
    root: Path,
    head_view: RepoView,
    base_sha: str,
    head_sha: str,
    surface_path: str,
    test_file: str,
    surface_items_cache: dict[str, set[str]],
) -> bool:
    """Return True if a newly added/changed bound test references `surface_path`."""
    if is_same_crate_and_module_subtree(surface_path, test_file):
        return True
    if surface_path not in surface_items_cache:
        surface_items_cache[surface_path] = extract_changed_surface_items(
            root, head_view, base_sha, head_sha, surface_path
        )
    items = surface_items_cache[surface_path]
    if not items or not head_view.is_file(test_file):
        return False
    content = head_view.read_text(test_file)
    for ident in items:
        if re.search(rf"\b{re.escape(ident)}\b", content):
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
    wt_head_res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True)
    wt_head_sha = wt_head_res.stdout.strip()

    head_view = RepoView(root, head_sha, use_worktree=(head_sha == wt_head_sha))
    base_view = RepoView(root, base_sha, use_worktree=False)

    # Run git diff --name-status -M
    diff_cmd = ["git", "diff", "--name-status", "-M", base_sha, head_sha]
    diff_res = subprocess.run(diff_cmd, cwd=root, capture_output=True, text=True, check=True)

    surfaces = load_surfaces_from_view(head_view)
    contracts = load_contracts_from_view(head_view)
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
    for path in sorted(added_paths):
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

    # Check that each modified classified guest surface has a resolvable gated bound test per contract
    any_contract_toml_changed = any(
        p.startswith("conformance-contracts/contracts/") for p in all_diff_paths
    )
    base_contracts = (
        load_contracts_from_view(base_view) if any_contract_toml_changed else contracts
    )
    binding_resolution_cache: dict[str, tuple[str, str, str] | None] = {}
    surface_items_cache: dict[str, set[str]] = {}
    evidenced_lines: list[str] = []
    errors: list[str] = []

    for path in sorted(modified_paths):
        if path in byte_identical_renames or path in move_covered or path in exempted_paths:
            continue
        if is_test_or_probe_path(path):
            continue
        if path not in surfaces:
            continue

        for cid in surfaces[path]:
            contract_data = contracts.get(cid, {})
            head_bindings = extract_contract_test_bindings(contract_data)
            base_bindings = set(extract_contract_test_bindings(base_contracts.get(cid, {})))

            valid_tests: list[str] = []
            had_gaming_error = False

            for b_spec in head_bindings:
                if valid_tests and b_spec in base_bindings:
                    continue
                if b_spec not in binding_resolution_cache:
                    binding_resolution_cache[b_spec] = resolve_binding_at_view(head_view, b_spec)
                resolved = binding_resolution_cache[b_spec]
                if resolved is None:
                    continue
                pkg_name, target_name, test_file = resolved
                if not is_target_in_gated_lane(head_view, pkg_name, target_name):
                    continue

                if b_spec not in base_bindings:
                    if not bound_test_references_surface(
                        root, head_view, base_sha, head_sha, path, test_file, surface_items_cache
                    ):
                        errors.append(
                            f"error: binding {b_spec} added to {cid} does not reference changed surface {path}"
                        )
                        had_gaming_error = True
                        continue

                valid_tests.append(b_spec)

            if valid_tests and not had_gaming_error:
                evidenced_lines.append(f"evidenced: {path} -> {cid}: {valid_tests[0]}")
            elif not valid_tests:
                errors.append(f"error: contract {cid} has no gated bound test for changed surface {path}")

    for line in evidenced_lines:
        print(line)

    if errors:
        for err in errors:
            sys.stderr.write(f"{err}\n")
        sys.exit(1)

    print("conformance contract check passed: all changed surfaces covered or exempted")
    sys.exit(0)


if __name__ == "__main__":
    main()

