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
KNOWN_TEST_LANES = GATED_TEST_LANES | {"manual"}

_RUST_KEYWORDS = {
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "gen",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "macro_rules",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "raw",
    "ref",
    "return",
    "safe",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "try",
    "type",
    "union",
    "unsafe",
    "use",
    "where",
    "while",
    "yield",
    "_",
}

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

_VIS_MOD_PREFIX = r"(?:\bpub(?:\s*\([^)]*\))?\s+)?"
_FN_DECL_RE = re.compile(
    rf"{_VIS_MOD_PREFIX}(?:\b(?:default|const|async|unsafe|extern(?:\s*\"[^\"]*\")?)\s+)*\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
)
_STATIC_DECL_RE = re.compile(
    rf"{_VIS_MOD_PREFIX}\bstatic\s+(?:mut\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
)
_CONST_DECL_RE = re.compile(
    rf"{_VIS_MOD_PREFIX}\bconst\s+(?!fn\b|async\b|unsafe\b|extern\b)(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
)
_TYPE_MOD_DECL_RE = re.compile(
    rf"{_VIS_MOD_PREFIX}(?:\bunsafe\s+)?\b(?:struct|enum|type|trait|union|mod)\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
)
_MACRO_DECL_RE = re.compile(r"\bmacro_rules!\s*(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b")

_TEST_ATTR_RE = re.compile(r"#\s*\[\s*(?:[\w:]+::)?(?:test|test_case|rstest)\b")
_IGNORE_ATTR_RE = re.compile(r"#\s*\[\s*(?:ignore\b|cfg_attr\s*\([^\]]*\bignore\b)")
_CFG_TEST_ATTR_RE = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")


def strip_rust_comments_and_strings(src: str) -> str:
    """Replace Rust comments and string/char literal bodies with spaces, preserving newlines."""
    out: list[str] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            out.append("  ")
            i += 2
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
            continue
        if c in ("r", "b", "c"):
            m = re.match(r"^(?:b?r|cr)(#*)\"", src[i:])
            if m:
                hashes = m.group(1)
                prefix_len = len(m.group(0))
                out.append(" " * (prefix_len - 1) + '"')
                i += prefix_len
                closing = '"' + hashes
                while i < n and not src.startswith(closing, i):
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
                if i < n:
                    out.append('"' + (" " * len(hashes)))
                    i += len(closing)
                continue
        if c == '"':
            out.append('"')
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
            if i < n:
                out.append('"')
                i += 1
            continue
        if c == "'":
            m = re.match(r"^'(?:\\.|[^'\\\n])'", src[i:])
            if m:
                out.append(" " * len(m.group(0)))
                i += len(m.group(0))
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, open_idx: int) -> int:
    """Given `text[open_idx] == '{'`, return index of matching `}` or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def strip_cfg_test_blocks(stripped_src: str) -> str:
    """Blank out `#[cfg(test)] mod ... { ... }` and `#[test] fn ... { ... }` blocks, preserving newlines."""
    chars = list(stripped_src)
    for m in _CFG_TEST_ATTR_RE.finditer(stripped_src):
        pos = m.end()
        # Skip whitespace and additional attributes before `mod` or `fn`
        while pos < len(stripped_src):
            ws = re.match(r"^\s+", stripped_src[pos:])
            if ws:
                pos += ws.end()
                continue
            if stripped_src.startswith("#[", pos):
                # balance `[` `]`
                bdepth = 0
                k = pos
                while k < len(stripped_src):
                    if stripped_src[k] == "[":
                        bdepth += 1
                    elif stripped_src[k] == "]":
                        bdepth -= 1
                        if bdepth == 0:
                            k += 1
                            break
                    k += 1
                pos = k
                continue
            break
        brace_idx = stripped_src.find("{", pos)
        semi_idx = stripped_src.find(";", pos)
        if brace_idx != -1 and (semi_idx == -1 or brace_idx < semi_idx):
            end_idx = _find_matching_brace(stripped_src, brace_idx)
            if end_idx != -1:
                for idx in range(m.start(), end_idx + 1):
                    if chars[idx] != "\n":
                        chars[idx] = " "
    return "".join(chars)


class RepoView:
    """Read files and directory listings strictly from a git revision tree."""

    def __init__(self, root: Path, rev_sha: str, use_worktree: bool = False):
        self.root = root
        self.rev_sha = rev_sha
        self.use_worktree = use_worktree
        self._files: set[str] | None = None
        self._dirs: set[str] | None = None
        self._diff_from_wt: set[str] | None = None
        self._blob_cache: dict[str, bytes] = {}
        self._stripped_cache: dict[str, str] = {}

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
        if res.returncode != 0:
            sys.stderr.write(f"error: git ls-tree failed for {self.rev_sha}: {res.stderr.strip()}\n")
            sys.exit(1)
        files: set[str] = set()
        dirs: set[str] = {""}
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
            ["git", "diff-index", "--name-only", self.rev_sha, "--"],
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
        assert self._files is not None
        assert self._diff_from_wt is not None
        if rel_path not in self._files:
            raise FileNotFoundError(rel_path)
        if rel_path not in self._blob_cache:
            wt_file = self.root / rel_path
            if rel_path not in self._diff_from_wt and wt_file.is_file() and not wt_file.is_symlink():
                self._blob_cache[rel_path] = wt_file.read_bytes()
            else:
                res = subprocess.run(
                    ["git", "show", f"{self.rev_sha}:{rel_path}"],
                    cwd=self.root,
                    capture_output=True,
                    check=False,
                )
                if res.returncode != 0:
                    raise FileNotFoundError(rel_path)
                self._blob_cache[rel_path] = res.stdout
        return self._blob_cache[rel_path]

    def read_text(self, rel_path: str) -> str:
        return self.read_bytes(rel_path).decode("utf-8", errors="replace")

    def read_stripped_rust(self, rel_path: str) -> str:
        rel_path = rel_path.strip("/")
        if rel_path not in self._stripped_cache:
            self._stripped_cache[rel_path] = strip_rust_comments_and_strings(self.read_text(rel_path))
        return self._stripped_cache[rel_path]

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


def _parse_toml(text: str, path_label: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        sys.stderr.write(f"error: malformed TOML in {path_label}: {exc}\n")
        sys.exit(1)


def load_surfaces_from_view(view: RepoView) -> dict[str, list[str]]:
    surfaces_path = "conformance-contracts/surfaces.toml"
    if not view.is_file(surfaces_path):
        return {}
    data = _parse_toml(view.read_text(surfaces_path), surfaces_path)
    mapping = {}
    for entry in data.get("surfaces", []):
        mapping[entry["path"]] = list(entry.get("contracts", []))
    return mapping


def load_contracts_from_view(view: RepoView) -> dict[str, dict]:
    contracts = {}
    for rel_path in view.glob_files("conformance-contracts/contracts", ".toml"):
        data = _parse_toml(view.read_text(rel_path), rel_path)
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

    # Strip trailing prose after `(something)` if followed by `, plus ...`
    if "(" in clause:
        clause = clause[: clause.find("(")].strip().rstrip(":")

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


def _discover_ignored_test_allowlist(view: RepoView) -> list[tuple[str, str | None]]:
    """Parse `justfile` at `view` for recipes that execute tests with `--ignored` or `--include-ignored`.

    Returns list of `(pkg_name, filter_substring_or_None)`.
    """
    if not view.is_file("justfile"):
        return []
    text = view.read_text("justfile")
    allowed: list[tuple[str, str | None]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "--ignored" not in line and "--include-ignored" not in line:
            continue
        m = re.search(r"test-signed\.sh\s+([A-Za-z0-9_-]+)(?:\s+([A-Za-z0-9_:-]+))?", line)
        if m:
            pkg = m.group(1)
            flt = m.group(2)
            if flt and flt.startswith("-"):
                flt = None
            allowed.append((pkg, flt))
    return allowed


def _is_ignored_test_allowed(view: RepoView, pkg_name: str, fn_name: str) -> bool:
    for allowed_pkg, flt in _discover_ignored_test_allowlist(view):
        if allowed_pkg == pkg_name:
            if flt is None or flt in fn_name:
                return True
    return False


def _extract_inline_mod_body(scope_text: str, mod_name: str) -> tuple[str, str] | None:
    """Find `mod <mod_name> { ... }` at top-level (brace depth 0) of `scope_text`.

    Returns `(preceding_attrs, inner_body_text)` or None.
    """
    pattern = re.compile(
        rf"(?:^|[;\}}\s])((?:#\s*\[[^\]]*\]\s*)*){_VIS_MOD_PREFIX}\bmod\s+(?:r#)?{re.escape(mod_name)}\s*\{{",
        re.M,
    )
    # Track brace depth across `scope_text`
    depth = 0
    brace_depth_at: list[int] = [0] * (len(scope_text) + 1)
    for idx, ch in enumerate(scope_text):
        brace_depth_at[idx] = depth
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    brace_depth_at[len(scope_text)] = depth

    for m in pattern.finditer(scope_text):
        mod_kw_pos = m.start(1)
        if brace_depth_at[mod_kw_pos] != 0:
            continue
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(scope_text, open_brace)
        if close_brace != -1:
            return (m.group(1), scope_text[open_brace + 1 : close_brace])
    return None


def _extract_top_level_test_fns(
    scope_text: str,
    enclosing_attrs: str = "",
) -> dict[str, tuple[bool, str]]:
    """Find all `#[test]`-attributed `fn <name>` at brace depth 0 of `scope_text`.

    Returns `{fn_name: (is_ignored, fn_full_text)}`.
    """
    depth = 0
    brace_depth_at: list[int] = [0] * (len(scope_text) + 1)
    for idx, ch in enumerate(scope_text):
        brace_depth_at[idx] = depth
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    brace_depth_at[len(scope_text)] = depth

    fn_pattern = re.compile(
        rf"((?:#\s*\[[^\]]*\]\s*)+){_VIS_MOD_PREFIX}"
        rf"(?:\b(?:default|const|async|unsafe|extern(?:\s*\"[^\"]*\")?)\s+)*"
        rf"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    results: dict[str, tuple[bool, str]] = {}
    enclosing_ignored = bool(_IGNORE_ATTR_RE.search(enclosing_attrs))
    for m in fn_pattern.finditer(scope_text):
        if brace_depth_at[m.start()] != 0:
            continue
        attrs = m.group(1)
        fn_name = m.group(2)
        if not _TEST_ATTR_RE.search(attrs):
            continue
        is_ignored = enclosing_ignored or bool(_IGNORE_ATTR_RE.search(attrs))
        open_brace = scope_text.find("{", m.end())
        fn_body = ""
        if open_brace != -1:
            close_brace = _find_matching_brace(scope_text, open_brace)
            if close_brace != -1:
                fn_body = scope_text[m.start() : close_brace + 1]
        results[fn_name] = (is_ignored, fn_body or m.group(0))
    return results


def _scope_has_valid_test_fn(
    view: RepoView,
    pkg_name: str,
    scope_text: str,
    fn_name: str | None,
    enclosing_attrs: str = "",
) -> str | None:
    """If `fn_name` is given, check that exact `#[test] fn <fn_name>` exists at top level of `scope_text`
    and is not ignored (unless allowed by lane config). If `fn_name` is None, check that at least one
    such `#[test]` fn exists in `scope_text` (or its inline test submodules).
    Returns the matched test function/scope text if valid, else None.
    """
    test_fns = _extract_top_level_test_fns(scope_text, enclosing_attrs)
    if fn_name is not None:
        if fn_name not in test_fns:
            return None
        is_ignored, fn_text = test_fns[fn_name]
        if is_ignored and not _is_ignored_test_allowed(view, pkg_name, fn_name):
            return None
        return fn_text

    # Module-level binding: check top-level test fns or nested inline test modules
    for name, (is_ignored, _) in test_fns.items():
        if not is_ignored or _is_ignored_test_allowed(view, pkg_name, name):
            return scope_text

    # Also check one level of inline `mod <submod> { ... }` (e.g. `mod serial_host`)
    mod_iter = re.finditer(rf"{_VIS_MOD_PREFIX}\bmod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*\{{", scope_text)
    for m in mod_iter:
        sub_res = _extract_inline_mod_body(scope_text, m.group(1))
        if sub_res is not None:
            sub_attrs, sub_body = sub_res
            sub_fns = _extract_top_level_test_fns(sub_body, enclosing_attrs + "\n" + sub_attrs)
            for name, (is_ignored, _) in sub_fns.items():
                if not is_ignored or _is_ignored_test_allowed(view, pkg_name, name):
                    return scope_text
    return None


def _load_crate_cargo_toml(view: RepoView, pkg_name: str) -> dict | None:
    cargo_toml = f"crates/{pkg_name}/Cargo.toml"
    if not view.is_file(cargo_toml):
        return None
    try:
        data = tomllib.loads(view.read_text(cargo_toml))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    pkg_table = data.get("package")
    if not isinstance(pkg_table, dict) or pkg_table.get("name") != pkg_name:
        return None
    return data


def _discover_integration_targets(view: RepoView, pkg_name: str) -> dict[str, str] | None:
    """Return `{target_name: root_rs_rel_path}` for integration test targets from real Cargo metadata rules.

    Returns None if `Cargo.toml` is missing or malformed.
    """
    data = _load_crate_cargo_toml(view, pkg_name)
    if data is None:
        return None
    crate_dir = f"crates/{pkg_name}"
    targets: dict[str, str] = {}

    explicit_tests = data.get("test", [])
    if explicit_tests is not None:
        if not isinstance(explicit_tests, list):
            return None
        for entry in explicit_tests:
            if not isinstance(entry, dict):
                return None
            if entry.get("test") is False:
                continue
            tname = entry.get("name")
            if not isinstance(tname, str) or not tname:
                return None
            rel_p = entry.get("path")
            if isinstance(rel_p, str):
                cand = f"{crate_dir}/{rel_p.lstrip('/')}"
                if view.is_file(cand):
                    targets[tname] = cand
            else:
                for cand in (f"{crate_dir}/tests/{tname}.rs", f"{crate_dir}/tests/{tname}/main.rs"):
                    if view.is_file(cand):
                        targets[tname] = cand
                        break

    autotests = data.get("package", {}).get("autotests", True)
    if autotests is not False:
        tests_dir = f"{crate_dir}/tests"
        for rel_path in view.glob_files(tests_dir, ".rs"):
            sub = rel_path[len(tests_dir) + 1 :]
            parts = sub.split("/")
            if len(parts) == 1:
                tname = parts[0][:-3]
                targets.setdefault(tname, rel_path)
            elif len(parts) == 2 and parts[1] == "main.rs":
                tname = parts[0]
                targets.setdefault(tname, rel_path)

    return targets


def _crate_has_testable_lib_or_bin(view: RepoView, pkg_name: str) -> bool:
    data = _load_crate_cargo_toml(view, pkg_name)
    if data is None:
        return False
    crate_dir = f"crates/{pkg_name}"
    lib_table = data.get("lib")
    if isinstance(lib_table, dict):
        if lib_table.get("test") is False:
            return False
        lib_path = f"{crate_dir}/{lib_table.get('path', 'src/lib.rs').lstrip('/')}"
        if view.is_file(lib_path):
            return True
    elif lib_table is None:
        if view.is_file(f"{crate_dir}/src/lib.rs") or view.is_file(f"{crate_dir}/src/main.rs"):
            return True
    return False


def is_target_in_gated_lane(view: RepoView, pkg_name: str, target_name: str) -> bool:
    """Validate `Cargo.toml` and `[package.metadata.carrick.test-lanes]` fail-closed, modeling `lib` explicitly."""
    data = _load_crate_cargo_toml(view, pkg_name)
    if data is None:
        return False

    int_targets = _discover_integration_targets(view, pkg_name)
    if int_targets is None:
        return False

    carrick_meta = data.get("package", {}).get("metadata", {}).get("carrick")
    lanes = None
    if carrick_meta is not None:
        if not isinstance(carrick_meta, dict):
            return False
        lanes = carrick_meta.get("test-lanes")
        if lanes is not None and not isinstance(lanes, dict):
            return False

    parsed_lanes: dict[str, str] = {}
    if isinstance(lanes, dict):
        for key, val in lanes.items():
            if isinstance(val, str):
                lane = val
                reason = None
            elif isinstance(val, dict):
                lane = val.get("lane")
                reason = val.get("reason")
                if not isinstance(lane, str):
                    return False
                if reason is not None and not isinstance(reason, str):
                    return False
            else:
                return False
            if lane not in KNOWN_TEST_LANES:
                return False
            if lane == "manual" and (not reason or not reason.strip()):
                return False
            if key != "*" and key != "lib" and key not in int_targets:
                return False
            parsed_lanes[key] = lane

    if target_name == "lib":
        if not _crate_has_testable_lib_or_bin(view, pkg_name):
            return False
        # `just test` runs `--lib` on workspace crates (`host` lane) unless explicitly overridden for `lib`
        lane = parsed_lanes.get("lib", "host")
        return lane in GATED_TEST_LANES

    if target_name not in int_targets:
        return False
    lane = parsed_lanes.get(target_name, parsed_lanes.get("*", "host"))
    return lane in GATED_TEST_LANES


def _resolve_in_module_tree(
    view: RepoView,
    pkg_name: str,
    root_files: list[str],
    base_dir: str,
    segments: list[str],
    require_test_module_for_root: bool,
) -> tuple[str, str] | None:
    """Resolve `segments` starting from `root_files` / `base_dir` to `(file_rel_path, matched_test_text)`.

    Every segment in `segments` must be consumed either by an exact submodule file on disk
    or by an exact nested `mod <seg> { ... }` block inside the resolved file, ending at either
    an exact `#[test] fn <segments[-1]>` or a test module containing a valid `#[test]` fn.
    """
    # Try each split point `m` (`0 <= m <= len(segments)`):
    # `segments[:m]` resolves to a `.rs` file on disk, and `segments[m:]` resolves inside that file.
    for m in range(len(segments), -1, -1):
        mod_parts = segments[:m]
        inner_parts = segments[m:]
        candidates: list[str] = []
        if m == 0:
            candidates.extend(f for f in root_files if view.is_file(f))
        else:
            rel = "/".join(mod_parts)
            candidates.extend([f"{base_dir}/{rel}.rs", f"{base_dir}/{rel}/mod.rs"])
            if mod_parts[-1] == "tests" and m >= 2:
                parent_rel = "/".join(mod_parts[:-1])
                candidates.extend(
                    [f"{base_dir}/{parent_rel}_tests.rs", f"{base_dir}/{parent_rel}_test.rs"]
                )
            elif mod_parts[-1] == "tests" and m == 1:
                for rf in root_files:
                    if rf.endswith(".rs") and not rf.endswith("/main.rs") and not rf.endswith("/lib.rs"):
                        stem = rf[:-3]
                        candidates.extend([f"{stem}_tests.rs", f"{stem}_test.rs"])

        for cand in candidates:
            if not view.is_file(cand):
                continue
            stripped = view.read_stripped_rust(cand)

            # Case A: `inner_parts` is empty (`segments` named the module file itself)
            if not inner_parts:
                is_test_mod_file = (
                    "/tests/" in f"/{cand}"
                    or cand.endswith(("/tests.rs", "_test.rs", "_tests.rs"))
                    or (mod_parts and ("tests" in mod_parts or mod_parts[-1].endswith(("_test", "_tests"))))
                    or not require_test_module_for_root
                )
                if not is_test_mod_file:
                    continue
                matched = _scope_has_valid_test_fn(view, pkg_name, stripped, None)
                if matched is not None:
                    return (cand, matched)
                continue

            # Case B: `inner_parts[:-1]` are inline `mod` blocks and `inner_parts[-1]` is a `#[test] fn`
            cur_scope = stripped
            cur_attrs = ""
            ok_inline = True
            for inline_mod in inner_parts[:-1]:
                res = _extract_inline_mod_body(cur_scope, inline_mod)
                if res is None:
                    ok_inline = False
                    break
                m_attrs, cur_scope = res
                cur_attrs = cur_attrs + "\n" + m_attrs

            if ok_inline:
                fn_name = inner_parts[-1]
                # If `cand` is a non-test source file (`require_test_module_for_root` is True and `cand` is not
                # under a tests path), require either `inner_parts[:-1]` to enter an inline `mod` or `cand` itself
                # to be a test module path (`tests` in `mod_parts` or `*_tests.rs`).
                in_test_mod = (
                    bool(inner_parts[:-1])
                    or not require_test_module_for_root
                    or "/tests/" in f"/{cand}"
                    or cand.endswith(("/tests.rs", "_test.rs", "_tests.rs"))
                    or any(p == "tests" or p.endswith(("_test", "_tests")) for p in mod_parts)
                )
                if in_test_mod:
                    matched_fn = _scope_has_valid_test_fn(view, pkg_name, cur_scope, fn_name, cur_attrs)
                    if matched_fn is not None:
                        return (cand, matched_fn)

                # Case C: `inner_parts` all name inline `mod` blocks ending in a test module (e.g. `mod captured_metadata_tests`)
                res_last = _extract_inline_mod_body(cur_scope, inner_parts[-1])
                if res_last is not None:
                    last_attrs, last_body = res_last
                    matched_mod = _scope_has_valid_test_fn(
                        view, pkg_name, last_body, None, cur_attrs + "\n" + last_attrs
                    )
                    if matched_mod is not None:
                        return (cand, matched_mod)

    return None


def _resolve_contract_helper_binding(
    view: RepoView,
    pkg_name: str,
    contract_fn: str,
    int_targets: dict[str, str],
) -> tuple[str, str, str, list[str]] | None:
    """Resolve `<pkg>::<contract_fn>` or `<pkg>::contracts::<contract_fn>` defined in `src/contracts.rs`
    (or `src/contracts/*.rs`) when called by a `#[test]` function in a gated integration test target.
    """
    crate_dir = f"crates/{pkg_name}"
    contract_files: list[str] = []
    if view.is_file(f"{crate_dir}/src/contracts.rs"):
        contract_files.append(f"{crate_dir}/src/contracts.rs")
    contract_files.extend(view.glob_files(f"{crate_dir}/src/contracts", ".rs"))
    if not contract_files:
        return None

    defining_file: str | None = None
    callee_names: set[str] = {contract_fn}
    pub_fn_re = re.compile(
        rf"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+|unsafe\s+|const\s+)*fn\s+(?:r#)?{re.escape(contract_fn)}\b"
    )
    for cf in contract_files:
        stripped = view.read_stripped_rust(cf)
        m = pub_fn_re.search(stripped)
        if m:
            defining_file = cf
            open_brace = stripped.find("{", m.end())
            if open_brace != -1:
                close_brace = _find_matching_brace(stripped, open_brace)
                if close_brace != -1:
                    body = stripped[open_brace + 1 : close_brace]
                    for helper_m in re.finditer(r"\b(run_[A-Za-z0-9_]*_contract)\s*\(", body):
                        callee_names.add(helper_m.group(1))
            break

    if defining_file is None:
        return None

    call_re = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in sorted(callee_names)) + r")\s*\(")
    for tname, tfile in sorted(int_targets.items()):
        if not is_target_in_gated_lane(view, pkg_name, tname):
            continue
        t_stripped = view.read_stripped_rust(tfile)
        if not call_re.search(t_stripped):
            continue
        test_fns = _extract_top_level_test_fns(t_stripped)
        has_runnable_test = any(
            not is_ignored or _is_ignored_test_allowed(view, pkg_name, fn_name)
            for fn_name, (is_ignored, _) in test_fns.items()
        )
        if has_runnable_test:
            ref_texts = [view.read_stripped_rust(defining_file), t_stripped]
            for extra_cf in contract_files:
                if extra_cf != defining_file:
                    ref_texts.append(view.read_stripped_rust(extra_cf))
            return (pkg_name, tname, tfile, ref_texts)

    return None


def resolve_binding_at_view(
    view: RepoView, spec: str
) -> tuple[str, str, str, list[str]] | None:
    """Resolve `pkg::...` at `view` to `(pkg_name, target_name, test_file_rel_path, ref_stripped_texts)` or None."""
    parts = [p.strip() for p in spec.split("::") if p.strip()]
    if len(parts) < 2:
        return None
    pkg_name = parts[0]
    rest = parts[1:]
    if _load_crate_cargo_toml(view, pkg_name) is None:
        return None

    crate_dir = f"crates/{pkg_name}"
    src_dir = f"{crate_dir}/src"

    # 1. Try resolving in the `lib` (or `bin`) target under `crates/<pkg>/src/`
    if view.is_dir(src_dir) and _crate_has_testable_lib_or_bin(view, pkg_name):
        lib_roots = [f"{src_dir}/lib.rs", f"{src_dir}/main.rs"]
        res = _resolve_in_module_tree(
            view,
            pkg_name,
            lib_roots,
            src_dir,
            rest,
            require_test_module_for_root=True,
        )
        if res is not None:
            test_file, matched_text = res
            # If the test lives in its own dedicated test file, allow the whole stripped test file for reference checks;
            # if it is an inline test module inside a production source file, restrict to `matched_text` only.
            if is_test_or_probe_path(test_file):
                ref_texts = [view.read_stripped_rust(test_file)]
            else:
                ref_texts = [matched_text]
            return (pkg_name, "lib", test_file, ref_texts)

    # 2. Try resolving in an integration test target (`crates/<pkg>/tests/...`)
    int_targets = _discover_integration_targets(view, pkg_name)
    if int_targets is None:
        return None

    # 2a. Explicit integration target name in `rest[0]` (or `rest[1]` when `rest[0] == "tests"`)
    target_candidate = None
    after_target: list[str] = []
    if rest[0] in int_targets:
        target_candidate = rest[0]
        after_target = rest[1:]
    elif rest[0] == "tests" and len(rest) >= 2 and rest[1] in int_targets:
        target_candidate = rest[1]
        after_target = rest[2:]

    if target_candidate is not None:
        root_tf = int_targets[target_candidate]
        tf_base_dir = (
            root_tf[: -len("/main.rs")]
            if root_tf.endswith("/main.rs")
            else root_tf[:-3]
        )
        res = _resolve_in_module_tree(
            view,
            pkg_name,
            [root_tf],
            tf_base_dir,
            after_target,
            require_test_module_for_root=False,
        )
        if res is not None:
            test_file, _ = res
            return (pkg_name, target_candidate, test_file, [view.read_stripped_rust(test_file)])

    # 2b. 2-part binding `<pkg>::<fn_name>` (or `<pkg>::contracts::<fn_name>`)
    if len(rest) == 1:
        fn_name = rest[0]
        for tname, root_tf in sorted(int_targets.items()):
            res = _resolve_in_module_tree(
                view,
                pkg_name,
                [root_tf],
                root_tf[:-3],
                [fn_name],
                require_test_module_for_root=False,
            )
            if res is not None:
                test_file, _ = res
                return (pkg_name, tname, test_file, [view.read_stripped_rust(test_file)])

        helper_res = _resolve_contract_helper_binding(view, pkg_name, fn_name, int_targets)
        if helper_res is not None:
            return helper_res
    elif len(rest) == 2 and rest[0] == "contracts":
        helper_res = _resolve_contract_helper_binding(view, pkg_name, rest[1], int_targets)
        if helper_res is not None:
            return helper_res

    return None


def is_same_crate_and_module_subtree(surface_path: str, test_file: str) -> bool:
    """Return True only when `test_file` is the dedicated unit-test module file for a non-root leaf `surface_path`.

    `lib.rs`, `main.rs`, `mod.rs`, and `test_file == surface_path` are excluded and must reference
    a changed code identifier.
    """
    if not (surface_path.startswith("crates/") and test_file.startswith("crates/")):
        return False
    if test_file == surface_path:
        return False
    s_parts = surface_path.split("/")
    t_parts = test_file.split("/")
    if len(s_parts) < 3 or len(t_parts) < 3 or s_parts[1] != t_parts[1]:
        return False
    crate_src = f"crates/{s_parts[1]}/src/"
    if not (surface_path.startswith(crate_src) and test_file.startswith(crate_src)):
        return False
    if surface_path in (f"{crate_src}lib.rs", f"{crate_src}main.rs") or surface_path.endswith("/mod.rs"):
        return False
    if surface_path.endswith(".rs"):
        stem_prefix = surface_path[:-3]
        return test_file in (
            f"{stem_prefix}/tests.rs",
            f"{stem_prefix}/tests/mod.rs",
            f"{stem_prefix}_tests.rs",
            f"{stem_prefix}_test.rs",
        ) or test_file.startswith(f"{stem_prefix}/tests/")
    return False


def _extract_code_decl_identifiers(code_line: str) -> set[str]:
    """Extract declared item identifiers from a comment/string-stripped Rust code line."""
    found: set[str] = set()
    for regex in (_FN_DECL_RE, _STATIC_DECL_RE, _CONST_DECL_RE, _TYPE_MOD_DECL_RE, _MACRO_DECL_RE):
        for m in regex.finditer(code_line):
            ident = m.group(1)
            if (
                ident
                and ident not in _RUST_KEYWORDS
                and ident not in _GENERIC_ITEM_NAMES
                and not ident.startswith("_")
            ):
                found.add(ident)
    return found


def extract_changed_surface_items(
    root: Path,
    base_view: RepoView,
    head_view: RepoView,
    base_sha: str,
    head_sha: str,
    surface_path: str,
    old_surface_path: str | None = None,
) -> set[str]:
    """Extract function, type, const, static, trait, module, or macro identifiers defined or modified in `surface_path`'s diff."""
    base_path = old_surface_path or surface_path
    base_stripped_lines: list[str] = []
    if base_view.is_file(base_path):
        base_stripped_lines = strip_cfg_test_blocks(base_view.read_stripped_rust(base_path)).splitlines()
    head_stripped_lines: list[str] = []
    if head_view.is_file(surface_path):
        head_stripped_lines = strip_cfg_test_blocks(head_view.read_stripped_rust(surface_path)).splitlines()

    if old_surface_path and old_surface_path != surface_path and base_view.is_file(old_surface_path):
        diff_cmd = [
            "git",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "-U0",
            f"{base_sha}:{old_surface_path}",
            f"{head_sha}:{surface_path}",
        ]
    else:
        diff_cmd = [
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
        ]
    res = subprocess.run(diff_cmd, cwd=root, capture_output=True, text=True, check=False)
    if res.returncode not in (0, 1):
        return set()

    items: set[str] = set()
    old_line_no = 0
    new_line_no = 0
    in_hunk = False

    for raw_line in res.stdout.splitlines():
        if raw_line.startswith("@@ "):
            m = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
            if m:
                old_line_no = int(m.group(1))
                new_line_no = int(m.group(2))
                in_hunk = True
            continue
        if not in_hunk or raw_line.startswith(("+++", "---")):
            continue
        if raw_line.startswith("-"):
            if 1 <= old_line_no <= len(base_stripped_lines):
                items.update(_extract_code_decl_identifiers(base_stripped_lines[old_line_no - 1]))
            else:
                items.update(_extract_code_decl_identifiers(strip_rust_comments_and_strings(raw_line[1:])))
            old_line_no += 1
        elif raw_line.startswith("+"):
            if 1 <= new_line_no <= len(head_stripped_lines):
                items.update(_extract_code_decl_identifiers(head_stripped_lines[new_line_no - 1]))
            else:
                items.update(_extract_code_decl_identifiers(strip_rust_comments_and_strings(raw_line[1:])))
            new_line_no += 1

    return items


def bound_test_references_surface(
    root: Path,
    base_view: RepoView,
    head_view: RepoView,
    base_sha: str,
    head_sha: str,
    surface_path: str,
    test_file: str,
    ref_texts: list[str],
    surface_items_cache: dict[str, set[str]],
    renamed_modified_paths: dict[str, str],
) -> bool:
    """Return True if a newly added/changed bound test references `surface_path`."""
    if is_same_crate_and_module_subtree(surface_path, test_file):
        return True
    if surface_path not in surface_items_cache:
        surface_items_cache[surface_path] = extract_changed_surface_items(
            root,
            base_view,
            head_view,
            base_sha,
            head_sha,
            surface_path,
            renamed_modified_paths.get(surface_path),
        )
    items = surface_items_cache[surface_path]
    if not items or not ref_texts:
        return False
    for ident in items:
        pat = re.compile(rf"\b{re.escape(ident)}\b")
        if any(pat.search(txt) for txt in ref_texts):
            return True
    return False


def load_and_validate_exemptions(root: Path, exemptions_dir: Path, valid_contracts: set, diff_paths: set, base_sha: str, head_sha: str):
    exempted_paths = set()
    if not exemptions_dir.exists():
        return exempted_paths

    for p in exemptions_dir.glob("*.toml"):
        data = _parse_toml(p.read_text(encoding="utf-8", errors="replace"), str(p))

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


def _git_rev_parse(root: Path, rev: str) -> str:
    res = subprocess.run(
        ["git", "rev-parse", "--verify", f"{rev}^{{commit}}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        sys.stderr.write(f"error: unable to resolve git revision {rev!r}: {res.stderr.strip()}\n")
        sys.exit(1)
    return res.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description="Check contract change coverage.")
    parser.add_argument("--root", default=".", help="Root directory")
    parser.add_argument("--base", required=True, help="Base commit SHA")
    parser.add_argument("--head", default="HEAD", help="Head commit SHA")
    parser.add_argument("--exemptions-dir", default=None, help="Exemptions directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    exemptions_dir = Path(args.exemptions_dir) if args.exemptions_dir else root / "docs" / "conformance-exemptions"

    base_sha = _git_rev_parse(root, args.base)
    head_sha = _git_rev_parse(root, args.head)

    head_view = RepoView(root, head_sha, use_worktree=False)
    base_view = RepoView(root, base_sha, use_worktree=False)

    diff_cmd = ["git", "diff", "--name-status", "-M", base_sha, head_sha]
    diff_res = subprocess.run(diff_cmd, cwd=root, capture_output=True, text=True, check=False)
    if diff_res.returncode != 0:
        sys.stderr.write(f"error: git diff failed: {diff_res.stderr.strip()}\n")
        sys.exit(1)

    surfaces = load_surfaces_from_view(head_view)
    base_surfaces = load_surfaces_from_view(base_view)
    contracts = load_contracts_from_view(head_view)
    valid_contracts = set(contracts.keys())

    all_diff_paths: set[str] = set()
    added_paths: set[str] = set()
    modified_paths: set[str] = set()
    byte_identical_renames: set[str] = set()
    byte_identical_rename_sources: set[str] = set()
    renamed_modified_paths: dict[str, str] = {}
    rename_old_to_new: dict[str, str] = {}

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
            rename_old_to_new[old_path] = new_path
            if status == "R100":
                byte_identical_renames.add(new_path)
                byte_identical_rename_sources.add(old_path)
            else:
                modified_paths.add(new_path)
                renamed_modified_paths[new_path] = old_path
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

    # Check for unclassified new or R<100 renamed paths under crates/
    unclassified = []
    for path in sorted(added_paths | set(renamed_modified_paths.keys())):
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

    errors: list[str] = []

    # P1-4a: Check for dropped contract mappings on existing or renamed surfaces when surfaces.toml changed
    if "conformance-contracts/surfaces.toml" in all_diff_paths:
        for base_path, base_cids in sorted(base_surfaces.items()):
            if not base_cids:
                continue
            target_path = rename_old_to_new.get(base_path, base_path)
            if target_path in byte_identical_renames or target_path in exempted_paths or base_path in exempted_paths:
                continue
            if not head_view.is_file(target_path):
                continue
            if is_test_or_probe_path(target_path):
                continue
            head_cids = set(surfaces.get(target_path, []))
            dropped = [c for c in base_cids if c not in head_cids]
            if dropped:
                errors.append(
                    f"error: surface {target_path} dropped contract mapping(s) in surfaces.toml: {dropped}"
                )

    # Check that each modified classified guest surface has a resolvable gated bound test per contract
    any_contract_toml_changed = any(
        p.startswith("conformance-contracts/contracts/") for p in all_diff_paths
    )
    base_contracts = (
        load_contracts_from_view(base_view) if any_contract_toml_changed else contracts
    )
    binding_resolution_cache: dict[str, tuple[str, str, str, list[str]] | None] = {}
    surface_items_cache: dict[str, set[str]] = {}
    evidenced_lines: list[str] = []

    def resolve_gated_binding(b_spec: str) -> tuple[str, str, str, list[str]] | None:
        if b_spec not in binding_resolution_cache:
            resolved = resolve_binding_at_view(head_view, b_spec)
            if resolved is not None:
                pkg_name, target_name, _, _ = resolved
                if not is_target_in_gated_lane(head_view, pkg_name, target_name):
                    resolved = None
            binding_resolution_cache[b_spec] = resolved
        return binding_resolution_cache[b_spec]

    active_surfaces_by_cid: dict[str, list[str]] = {}
    active_modified_surfaces: list[str] = []
    for path in sorted(modified_paths):
        if path in byte_identical_renames or path in move_covered or path in exempted_paths:
            continue
        if is_test_or_probe_path(path):
            continue
        if path not in surfaces:
            continue
        active_modified_surfaces.append(path)
        for cid in surfaces[path]:
            active_surfaces_by_cid.setdefault(cid, []).append(path)

    for path in active_modified_surfaces:
        for cid in surfaces[path]:
            contract_data = contracts.get(cid, {})
            head_bindings = extract_contract_test_bindings(contract_data)
            base_bindings = set(extract_contract_test_bindings(base_contracts.get(cid, {})))

            existing_valid: list[str] = []
            added_valid_for_path: list[str] = []
            added_invalid_for_all: list[str] = []

            for b_spec in head_bindings:
                resolved = resolve_gated_binding(b_spec)
                if resolved is None:
                    continue
                _, _, test_file, ref_texts = resolved
                if b_spec in base_bindings:
                    existing_valid.append(b_spec)
                else:
                    if bound_test_references_surface(
                        root,
                        base_view,
                        head_view,
                        base_sha,
                        head_sha,
                        path,
                        test_file,
                        ref_texts,
                        surface_items_cache,
                        renamed_modified_paths,
                    ):
                        added_valid_for_path.append(b_spec)
                    else:
                        # Check if this added binding references ANY changed surface of `cid`
                        other_surfaces = active_surfaces_by_cid.get(cid, [])
                        refs_any = any(
                            other_p != path
                            and bound_test_references_surface(
                                root,
                                base_view,
                                head_view,
                                base_sha,
                                head_sha,
                                other_p,
                                test_file,
                                ref_texts,
                                surface_items_cache,
                                renamed_modified_paths,
                            )
                            for other_p in other_surfaces
                        )
                        if not refs_any:
                            added_invalid_for_all.append(b_spec)

            for bad_spec in added_invalid_for_all:
                errors.append(
                    f"error: binding {bad_spec} added to {cid} does not reference changed surface {path}"
                )

            valid_tests = existing_valid + added_valid_for_path
            if valid_tests and not added_invalid_for_all:
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

