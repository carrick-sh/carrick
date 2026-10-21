#!/usr/bin/env python3
"""Check that changed guest surfaces have matching conformance contract evidence."""

import argparse
import functools
import hashlib
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


_CRATE_FILE_CLASS_CACHE: dict[tuple[int, str], tuple[set[str], set[str], set[str]]] = {}
_FINGERPRINT_META_SEP = "\n/*__CONTRACT_FINGERPRINT_META__*/\n"


GATED_TEST_LANES = {"host", "kvm", "integration", "signed-cli", "signed-hvf"}
KNOWN_TEST_LANES = GATED_TEST_LANES | {"manual"}

_RUST_KEYWORDS = set(
    "as async await break const continue crate dyn else enum extern false fn for gen if impl in "
    "let loop macro_rules match mod move mut pub raw ref return safe self Self static struct "
    "super trait true try type union unsafe use where while yield _".split()
)
_GENERIC_ITEM_NAMES = set(
    "new default from into try_from try_into drop fmt clone eq ne cmp partial_cmp hash deref "
    "deref_mut index index_mut next poll run main test tests".split()
)

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
_CFG_OPEN_RE = re.compile(r"#\s*!?\s*\[\s*cfg\s*\(")


def strip_rust_comments_only(src: str) -> str:
    """Replace Rust comments with spaces, preserving newlines, string literals, and exact character offsets."""
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
                out.append(src[i : i + prefix_len])
                i += prefix_len
                closing = '"' + hashes
                while i < n and not src.startswith(closing, i):
                    out.append(src[i])
                    i += 1
                if i < n:
                    out.append(closing)
                    i += len(closing)
                continue
        if c == '"':
            out.append('"')
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i : i + 2])
                    i += 2
                else:
                    out.append(src[i])
                    i += 1
            if i < n:
                out.append('"')
                i += 1
            continue
        if c == "'":
            m = re.match(r"^'(?:\\.|[^'\\\n])'", src[i:])
            if m:
                out.append(m.group(0))
                i += len(m.group(0))
                continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_rust_comments_and_strings(src: str) -> str:
    """Replace Rust comments and string/char literal bodies with spaces, preserving newlines and exact offsets."""
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
                    out.append(" ")
                    out.append("\n" if src[i + 1] == "\n" else " ")
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


def _find_matching_delim(text: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    in_str = False
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _are_delims_balanced(s: str) -> bool:
    """Return True if all `()`, `[]`, `{}` delimiters in comment/string-stripped `s` are balanced."""
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for ch in s:
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            if not stack or stack[-1] != ch:
                return False
            stack.pop()
    return len(stack) == 0


def _split_cfg_top_level_commas(inner: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    in_str = False
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < n:
                cur.append(inner[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
                cur.append(ch)
            elif ch in pairs:
                stack.append(pairs[ch])
                cur.append(ch)
            elif ch in ")]}":
                if not stack or stack[-1] != ch:
                    return ["__invalid_cfg__"]
                stack.pop()
                cur.append(ch)
            elif ch == "," and not stack:
                part = "".join(cur).strip()
                if part:
                    parts.append(part)
                cur = []
            else:
                cur.append(ch)
        i += 1
    if in_str or stack:
        return ["__invalid_cfg__"]
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _iter_parsed_attributes(
    attr_text: str, attr_stripped: str | None = None
) -> tuple[list[tuple[bool, str]], bool]:
    """Parse a sequence of `#[...]` / `#![...]` attributes using bracket matching (`_find_matching_delim`).

    Returns `(list_of_(is_inner, attr_body), ok)`. Fails closed (`ok=False`) if any non-whitespace
    token is not a bracket-balanced attribute.
    """
    s = attr_stripped if attr_stripped is not None else strip_rust_comments_and_strings(attr_text)
    if len(s) != len(attr_text):
        s = strip_rust_comments_and_strings(attr_text)
    attrs: list[tuple[bool, str]] = []
    attr_open_re = re.compile(r"^#\s*(!?)\s*\[")
    pos = 0
    n = len(s)
    while pos < n:
        while pos < n and s[pos] in " \t\r\n":
            pos += 1
        if pos >= n:
            break
        m = attr_open_re.match(s[pos:])
        if not m:
            return (attrs, False)
        is_inner = m.group(1) == "!"
        open_b = pos + m.end() - 1
        close_b = _find_matching_delim(s, open_b, "[", "]")
        if close_b == -1:
            return (attrs, False)
        inner_s = s[open_b + 1 : close_b]
        if not _are_delims_balanced(inner_s) or re.search(r"#\s*!?\s*\[", inner_s):
            return (attrs, False)
        attrs.append((is_inner, attr_text[open_b + 1 : close_b].strip()))
        pos = close_b + 1
    return (attrs, True)


def _iter_effective_attr_items(body: str) -> tuple[list[tuple[list[str], str]], bool]:
    """Expand an attribute body (flattening `cfg_attr(pred, ...)` recursively) into `(cfg_preds, leaf_attr)`."""
    body_s = strip_rust_comments_and_strings(body).strip()
    if not _are_delims_balanced(body_s) or re.search(r"#\s*!?\s*\[", body_s):
        return ([], False)
    stripped_body = body.strip()
    m_ca = re.match(r"^cfg_attr\s*\((.*)\)\s*$", stripped_body, re.S)
    if m_ca:
        parts = _split_cfg_top_level_commas(m_ca.group(1))
        if len(parts) < 2 or "__invalid_cfg__" in parts:
            return ([], False)
        pred = parts[0].strip()
        if not _is_cfg_expr_decidable(pred):
            return ([], False)
        out: list[tuple[list[str], str]] = []
        for sub in parts[1:]:
            sub_items, sub_ok = _iter_effective_attr_items(sub.strip())
            if not sub_ok:
                return ([], False)
            for sub_preds, leaf in sub_items:
                out.append(([pred] + sub_preds, leaf))
        return (out, True)
    return ([([], stripped_body)], True)


def _has_ignore_attr(attrs_cs: str) -> bool:
    if not attrs_cs or not attrs_cs.strip():
        return False
    attrs, ok = _iter_parsed_attributes(attrs_cs)
    if not ok:
        return True
    for is_inner, body in attrs:
        if is_inner:
            continue
        items, item_ok = _iter_effective_attr_items(body)
        if not item_ok:
            return True
        for _preds, leaf in items:
            if re.match(r"^ignore\b", leaf):
                return True
    return False


def _has_should_panic_attr(attrs_cs: str) -> bool:
    if not attrs_cs or not attrs_cs.strip():
        return False
    attrs, ok = _iter_parsed_attributes(attrs_cs)
    if not ok:
        return True
    for _is_inner, body in attrs:
        items, item_ok = _iter_effective_attr_items(body)
        if not item_ok:
            return True
        for _preds, leaf in items:
            if re.match(r"^should_panic\b", leaf):
                return True
    return False


def _can_cfg_be_true_without_test(expr: str) -> bool:
    """Return True if `expr` can evaluate to True when `test` is False."""
    expr = expr.strip()
    if not expr:
        return True
    m = re.match(r"^(all|any|not)\s*\((.*)\)\s*$", expr, re.S)
    if m:
        op = m.group(1)
        args = _split_cfg_top_level_commas(m.group(2))
        if op == "all":
            return all(_can_cfg_be_true_without_test(a) for a in args)
        if op == "any":
            return any(_can_cfg_be_true_without_test(a) for a in args)
        if op == "not":
            return not _must_cfg_be_true_without_test(args[0]) if len(args) == 1 else True
    if expr == "test":
        return False
    return True


def _must_cfg_be_true_without_test(expr: str) -> bool:
    """Return True if `expr` is unconditionally True when `test` is False."""
    expr = expr.strip()
    if not expr:
        return False
    m = re.match(r"^(all|any|not)\s*\((.*)\)\s*$", expr, re.S)
    if m:
        op = m.group(1)
        args = _split_cfg_top_level_commas(m.group(2))
        if op == "all":
            return all(_must_cfg_be_true_without_test(a) for a in args)
        if op == "any":
            return any(_must_cfg_be_true_without_test(a) for a in args)
        if op == "not":
            return not _can_cfg_be_true_without_test(args[0]) if len(args) == 1 else False
    return False


def _cfg_is_test_only(expr: str) -> bool:
    """Return True if `#[cfg(expr)]` logically entails `test` (cannot hold when `test` is False)."""
    return not _can_cfg_be_true_without_test(expr)


def _is_cfg_expr_decidable(expr: str) -> bool:
    """Return True if every atom in `expr` is a supported, statically decidable CI cfg predicate."""
    expr = expr.strip()
    if not expr or expr == "__invalid_cfg__":
        return False
    if not _are_delims_balanced(strip_rust_comments_and_strings(expr)):
        return False
    m = re.match(r"^(all|any|not)\s*\((.*)\)\s*$", expr, re.S)
    if m:
        op = m.group(1)
        args = _split_cfg_top_level_commas(m.group(2))
        if not args or "__invalid_cfg__" in args:
            return False
        if op == "not" and len(args) != 1:
            return False
        return all(_is_cfg_expr_decidable(a) for a in args)
    if expr in ("test", "unix", "windows", "debug_assertions"):
        return True
    kv = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"$', expr)
    if kv:
        return kv.group(1) in {
            "target_os",
            "target_arch",
            "target_family",
            "target_pointer_width",
            "target_endian",
            "feature",
        }
    return False


def _extract_cfg_from_attr_body(content: str, cond_prefix: list[str]) -> tuple[list[str], list[str]]:
    """Parse the inside of `#[...]` or `#![...]` for `cfg(...)` and `cfg_attr(...)`.

    Returns `(cfg_exprs, conditional_test_preds)`. Uses `"__invalid_cfg__"` to fail closed on
    malformed or undecidable `cfg` / `cfg_attr` predicates.
    """
    content = content.strip()
    content_s = strip_rust_comments_and_strings(content).strip()
    if not _are_delims_balanced(content_s) or re.search(r"#\s*!?\s*\[", content_s):
        return (["__invalid_cfg__"], [])
    m_cfg = re.match(r"^cfg\s*\((.*)\)\s*$", content, re.S)
    if m_cfg:
        inner = m_cfg.group(1).strip()
        if not _is_cfg_expr_decidable(inner):
            return (["__invalid_cfg__"], [])
        if not cond_prefix:
            return ([inner], [])
        cond_all = cond_prefix[0] if len(cond_prefix) == 1 else f"all({', '.join(cond_prefix)})"
        return ([f"any(not({cond_all}), {inner})"], [])

    m_ca = re.match(r"^cfg_attr\s*\((.*)\)\s*$", content, re.S)
    if m_ca:
        parts = _split_cfg_top_level_commas(m_ca.group(1))
        if len(parts) < 2 or "__invalid_cfg__" in parts:
            return (["__invalid_cfg__"], [])
        pred = parts[0].strip()
        if not _is_cfg_expr_decidable(pred):
            return (["__invalid_cfg__"], [])
        new_prefix = cond_prefix + [pred]
        cfgs: list[str] = []
        test_preds: list[str] = []
        for sub in parts[1:]:
            sub_s = sub.strip()
            sub_stripped = strip_rust_comments_and_strings(sub_s).strip()
            if not _are_delims_balanced(sub_stripped) or re.search(r"#\s*!?\s*\[", sub_stripped):
                return (["__invalid_cfg__"], [])
            if re.match(r"^(?:[\w:]+::)?(?:test|test_case|rstest)\b", sub_s):
                cond_all = new_prefix[0] if len(new_prefix) == 1 else f"all({', '.join(new_prefix)})"
                test_preds.append(cond_all)
            elif sub_s.startswith(("cfg", "cfg_attr")) and "(" in sub_s:
                sub_cfgs, sub_tests = _extract_cfg_from_attr_body(sub_s, new_prefix)
                cfgs.extend(sub_cfgs)
                test_preds.extend(sub_tests)
        return (cfgs, test_preds)

    return ([], [])


def _extract_cfg_exprs(attr_text: str, inner_only: bool = False) -> list[str]:
    """Extract `expr` from `#[cfg(expr)]` / `#[cfg_attr(...)]` (or `#![...]` if `inner_only=True`)."""
    if not attr_text or not attr_text.strip():
        return []
    attrs, ok = _iter_parsed_attributes(attr_text)
    if not ok:
        return ["__invalid_cfg__"]
    exprs: list[str] = []
    for is_inner, body in attrs:
        if (inner_only and is_inner) or (not inner_only and not is_inner):
            cfgs, _ = _extract_cfg_from_attr_body(body, [])
            exprs.extend(cfgs)
    return exprs


def strip_cfg_test_blocks(stripped_src: str, comments_stripped_src: str | None = None) -> str:
    """Blank out `#[cfg(test)]` / `#[cfg(all(test, ...))]` items and modules, preserving newlines."""
    attr_source = comments_stripped_src if comments_stripped_src is not None else stripped_src
    chars = list(stripped_src)
    for m in _CFG_OPEN_RE.finditer(attr_source):
        if "!" in m.group(0):
            continue
        open_paren = m.end() - 1
        close_paren = _find_matching_delim(attr_source, open_paren, "(", ")")
        if close_paren == -1:
            continue
        expr = attr_source[open_paren + 1 : close_paren].strip()
        if not _cfg_is_test_only(expr):
            continue
        close_bracket = attr_source.find("]", close_paren)
        if close_bracket == -1:
            continue
        pos = close_bracket + 1
        while pos < len(stripped_src):
            ws = re.match(r"^\s+", stripped_src[pos:])
            if ws:
                pos += ws.end()
                continue
            if stripped_src.startswith("#[", pos) or re.match(r"^#\s*\[", stripped_src[pos:]):
                open_b = stripped_src.find("[", pos)
                close_b = _find_matching_delim(stripped_src, open_b, "[", "]")
                if close_b != -1:
                    pos = close_b + 1
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
        elif semi_idx != -1:
            for idx in range(m.start(), semi_idx + 1):
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
        self._comments_stripped_cache: dict[str, str] = {}
        self._cargo_toml_cache: dict[str, dict | None] = {}
        self._ignored_allowlist_cache: list[tuple[str, str | None]] | None = None
        self._workflow_lane_info_cache: tuple[dict[str, list[tuple[str, str, frozenset[str]]]], dict[str, set[tuple[str, str]]]] | None = None
        self._crate_fn_files_cache: dict[str, dict[str, list[str]]] = {}
        self._file_non_test_fns_cache: dict[tuple[str, str, str], tuple[dict[str, list[tuple[list[str], str, str]]], bool]] = {}

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

    def read_comments_stripped_rust(self, rel_path: str) -> str:
        rel_path = rel_path.strip("/")
        if rel_path not in self._comments_stripped_cache:
            self._comments_stripped_cache[rel_path] = strip_rust_comments_only(self.read_text(rel_path))
        return self._comments_stripped_cache[rel_path]

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
        prefix, annotation = clause.split("(", 1)
        expanded = _expand_single_binding_clause(prefix.strip().rstrip(":"))
        if expanded:
            module = expanded[0].rsplit("::", 1)[0]
            for control in re.findall(r"\bincluding\s+([A-Za-z_][A-Za-z0-9_]*)\b", annotation):
                if "_" in control:
                    expanded.append(f"{module}::{control}")
        return expanded

    cleaned = re.sub(r"\s+", "", clause)
    if re.match(r"^carrick-[A-Za-z0-9_-]+(?:::[A-Za-z0-9_]+)+$", cleaned):
        return [cleaned]
    return []


def expand_binding_spec(raw: str) -> list[str]:
    out: list[str] = []
    last_module: str | None = None
    for clause in _split_top_level_semicolons(raw):
        expanded = _expand_single_binding_clause(clause)
        if expanded:
            out.extend(expanded)
            last_module = expanded[0].rsplit("::", 1)[0]
        elif (
            last_module
            and "tests" in last_module.split("::")
            and "conformance-metrics" not in clause
        ):
            control = re.match(r"^([a-z][a-z0-9_]*_[a-z0-9_]+)\b", clause)
            if control:
                out.append(f"{last_module}::{control.group(1)}")
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
    """Discover `(pkg_name, filter_substring_or_None)` from `justfile` recipes that CI workflows actually invoke
    (transitively) and that execute `scripts/test-signed.sh` with `--ignored` or `--include-ignored`.
    """
    if view._ignored_allowlist_cache is not None:
        return view._ignored_allowlist_cache
    if not view.is_file("justfile"):
        view._ignored_allowlist_cache = []
        return []
    workflow_files = view.glob_files(".github/workflows", ".yml") + view.glob_files(
        ".github/workflows", ".yaml"
    )
    if not workflow_files:
        view._ignored_allowlist_cache = []
        return []

    justfile_text = view.read_text("justfile")
    recipes: dict[str, tuple[list[str], list[str]]] = {}
    cur_recipe: str | None = None
    cur_deps: list[str] = []
    cur_body: list[str] = []

    header_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)(?:\s+[^:]*)?:(?!=)(.*)$")
    for raw_line in justfile_text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line[0].isspace():
            if cur_recipe is not None:
                cur_body.append(raw_line.strip())
            continue
        if cur_recipe is not None:
            recipes[cur_recipe] = (cur_deps, cur_body)
            cur_recipe = None
            cur_deps = []
            cur_body = []
        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:=", raw_line):
            continue
        if raw_line.startswith(("set ", "mod ", "import ", "export ", "[")):
            continue
        hm = header_re.match(raw_line)
        if hm:
            cur_recipe = hm.group(1)
            dep_part = hm.group(2).split("#", 1)[0]
            cur_deps = re.findall(r"\b([A-Za-z_][A-Za-z0-9_-]*)\b", dep_part)
            cur_body = []
    if cur_recipe is not None:
        recipes[cur_recipe] = (cur_deps, cur_body)

    def extract_just_calls_from_line(line: str) -> list[str]:
        s = line.strip().lstrip("@-")
        if not s or s.startswith("#"):
            return []
        if re.match(r"^(?:echo|printf)\b", s):
            return []
        found: list[str] = []
        for m in re.finditer(
            r"(?:^|[;&|()\s])\b(?:just|j)\s+(?:--[A-Za-z0-9_-]+(?:\s+\S+)?\s+)*([A-Za-z_][A-Za-z0-9_-]*)(?:\s+([A-Za-z_][A-Za-z0-9_-]*))?",
            s,
        ):
            r1 = m.group(1)
            r2 = m.group(2)
            if r1 == "lease":
                for sub_m in re.finditer(r"\b(?:just|j)\s+([A-Za-z_][A-Za-z0-9_-]*)", s[m.start() :]):
                    if sub_m.group(1) != "lease":
                        found.append(sub_m.group(1))
            elif r1 == "ci-macos-test" and r2:
                found.append(r1)
                found.append(r2)
            else:
                found.append(r1)
        return found

    seed_recipes: set[str] = set()
    workflow_texts: list[str] = []
    for wf in workflow_files:
        wtxt = view.read_text(wf)
        workflow_texts.append(wtxt)
        for raw_line in wtxt.splitlines():
            for rname in extract_just_calls_from_line(raw_line):
                if rname in recipes:
                    seed_recipes.add(rname)
            for sm in re.finditer(r"\b(scripts/[A-Za-z0-9_./-]+\.sh)\b", raw_line):
                spath = sm.group(1)
                if view.is_file(spath):
                    for sline in view.read_text(spath).splitlines():
                        for rname in extract_just_calls_from_line(sline):
                            if rname in recipes:
                                seed_recipes.add(rname)

    reachable: set[str] = set()
    queue = list(seed_recipes)
    while queue:
        rname = queue.pop()
        if rname in reachable or rname not in recipes:
            continue
        reachable.add(rname)
        deps, body = recipes[rname]
        for d in deps:
            if d in recipes and d not in reachable:
                queue.append(d)
        for bline in body:
            for sub in extract_just_calls_from_line(bline):
                if sub in recipes and sub not in reachable:
                    queue.append(sub)

    cmd_lines_to_scan: list[str] = []
    for rname in sorted(reachable):
        _, body = recipes[rname]
        cmd_lines_to_scan.extend(body)
    for wtxt in workflow_texts:
        cmd_lines_to_scan.extend(wtxt.splitlines())

    allowed: list[tuple[str, str | None]] = []
    signed_cmd_re = re.compile(
        r"^(?:exec\s+|env\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*)*(?:\./)?scripts/test-signed\.sh\s+([A-Za-z0-9_-]+)(?:\s+([A-Za-z0-9_:-]+))?"
    )
    for raw_line in cmd_lines_to_scan:
        line = raw_line.strip().lstrip("@-")
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(?:echo|printf)\b", line):
            continue
        if "--ignored" not in line and "--include-ignored" not in line:
            continue
        m = signed_cmd_re.match(line)
        if m:
            pkg = m.group(1)
            flt = m.group(2)
            if flt and flt.startswith("-"):
                flt = None
            allowed.append((pkg, flt))
    view._ignored_allowlist_cache = allowed
    return allowed


def _is_ignored_test_allowed(view: RepoView, pkg_name: str, fn_name: str) -> bool:
    for allowed_pkg, flt in _discover_ignored_test_allowlist(view):
        if allowed_pkg == pkg_name:
            if flt is None or flt in fn_name:
                return True
    return False


def _load_crate_cargo_toml(view: RepoView, pkg_name: str) -> dict | None:
    if pkg_name in view._cargo_toml_cache:
        return view._cargo_toml_cache[pkg_name]
    cargo_toml = f"crates/{pkg_name}/Cargo.toml"
    if not view.is_file(cargo_toml):
        view._cargo_toml_cache[pkg_name] = None
        return None
    try:
        data = tomllib.loads(view.read_text(cargo_toml))
    except Exception:
        view._cargo_toml_cache[pkg_name] = None
        return None
    if not isinstance(data, dict):
        view._cargo_toml_cache[pkg_name] = None
        return None
    pkg_table = data.get("package")
    if not isinstance(pkg_table, dict) or pkg_table.get("name") != pkg_name:
        view._cargo_toml_cache[pkg_name] = None
        return None
    view._cargo_toml_cache[pkg_name] = data
    return data


def _expand_crate_features(features_table: dict, seed: set[str]) -> set[str]:
    enabled = set(seed)
    queue = list(seed)
    while queue:
        feat = queue.pop()
        deps = features_table.get(feat, [])
        if isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str) and "/" not in dep and not dep.startswith("dep:"):
                    if dep not in enabled:
                        enabled.add(dep)
                        queue.append(dep)
    return enabled


def _discover_workflow_lane_info(
    view: RepoView,
) -> tuple[dict[str, list[tuple[str, str, frozenset[str]]]], dict[str, set[tuple[str, str]]]]:
    """Derive `(lane_envs, pkg_host_envs)` from `.github/workflows/*.yml` and `justfile` when present,
    falling back to Carrick's workflow lane layout when workflow files are absent in synthetic test repos.
    """
    if view._workflow_lane_info_cache is not None:
        return view._workflow_lane_info_cache

    default_lane_envs: dict[str, list[tuple[str, str, frozenset[str]]]] = {
        "host": [("macos", "aarch64", frozenset({"carrick-host-linux"}))],
        "integration": [("macos", "aarch64", frozenset())],
        "kvm": [("linux", "x86_64", frozenset())],
        "signed-cli": [("macos", "aarch64", frozenset())],
        "signed-hvf": [("macos", "aarch64", frozenset())],
    }
    default_pkg_host_envs: dict[str, set[tuple[str, str]]] = {
        "carrick-host-linux": {("linux", "x86_64")},
        "carrick-vmm-kvm": {("linux", "x86_64")},
        "carrick-kernel-example": {("macos", "aarch64"), ("linux", "x86_64"), ("linux", "aarch64")},
    }

    workflow_files = view.glob_files(".github/workflows", ".yml") + view.glob_files(
        ".github/workflows", ".yaml"
    )
    if not view.is_file("justfile") or not workflow_files:
        view._workflow_lane_info_cache = (default_lane_envs, default_pkg_host_envs)
        return view._workflow_lane_info_cache

    justfile_text = view.read_text("justfile")
    recipes: dict[str, tuple[list[str], list[str]]] = {}
    cur_recipe: str | None = None
    cur_deps: list[str] = []
    cur_body: list[str] = []
    header_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)(?:\s+[^:]*)?:(?!=)(.*)$")
    for raw_line in justfile_text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line[0].isspace():
            if cur_recipe is not None:
                cur_body.append(raw_line.strip())
            continue
        if cur_recipe is not None:
            recipes[cur_recipe] = (cur_deps, cur_body)
            cur_recipe, cur_deps, cur_body = None, [], []
        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:=", raw_line) or raw_line.startswith(
            ("set ", "mod ", "import ", "export ", "[")
        ):
            continue
        hm = header_re.match(raw_line)
        if hm:
            cur_recipe = hm.group(1)
            dep_part = hm.group(2).split("#", 1)[0]
            cur_deps = re.findall(r"\b([A-Za-z_][A-Za-z0-9_-]*)\b", dep_part)
            cur_body = []
    if cur_recipe is not None:
        recipes[cur_recipe] = (cur_deps, cur_body)

    def extract_just_calls(line: str) -> list[str]:
        s = line.strip().lstrip("@-")
        if not s or s.startswith("#") or re.match(r"^(?:echo|printf)\b", s):
            return []
        found: list[str] = []
        for m in re.finditer(
            r"(?:^|[;&|()\s])\b(?:just|j)\s+(?:--[A-Za-z0-9_-]+(?:\s+\S+)?\s+)*([A-Za-z_][A-Za-z0-9_-]*)(?:\s+([A-Za-z_][A-Za-z0-9_-]*))?",
            s,
        ):
            r1, r2 = m.group(1), m.group(2)
            if r1 == "lease":
                for sub_m in re.finditer(r"\b(?:just|j)\s+([A-Za-z_][A-Za-z0-9_-]*)", s[m.start() :]):
                    if sub_m.group(1) != "lease":
                        found.append(sub_m.group(1))
            elif r1 == "ci-macos-test" and r2:
                found.extend([r1, r2])
            elif r1 == "accept" and "--profile kvm" in s:
                found.extend(["accept", "test-kvm"])
            else:
                found.append(r1)
        return found

    def recipe_closure(seed: set[str]) -> set[str]:
        reach: set[str] = set()
        q = list(seed)
        while q:
            r = q.pop()
            if r in reach or r not in recipes:
                continue
            reach.add(r)
            deps, body = recipes[r]
            for d in deps:
                if d in recipes and d not in reach:
                    q.append(d)
            for bl in body:
                for sub in extract_just_calls(bl):
                    if sub in recipes and sub not in reach:
                        q.append(sub)
        return reach

    def map_runner_label(label: str) -> tuple[str, str] | None:
        lbl = label.strip().strip("'\"").lower()
        if "macos" in lbl:
            return ("macos", "aarch64")
        if "ubuntu" in lbl or "linux" in lbl or "carrick-kvm" in lbl:
            if "arm" in lbl or "aarch64" in lbl:
                return ("linux", "aarch64")
            return ("linux", "x86_64")
        return None

    lane_envs: dict[str, list[tuple[str, str, frozenset[str]]]] = {
        "host": [],
        "integration": [],
        "kvm": [("linux", "x86_64", frozenset())],
        "signed-cli": [("macos", "aarch64", frozenset())],
        "signed-hvf": [("macos", "aarch64", frozenset())],
    }
    pkg_host_envs: dict[str, set[tuple[str, str]]] = {}

    for wf in workflow_files:
        wtxt = view.read_text(wf)
        job_blocks = re.split(r"\n(?=  [A-Za-z0-9_-]+:\s*\n)", wtxt)
        for jb in job_blocks:
            runners: list[tuple[str, str]] = []
            for rm in re.finditer(r"^\s*runs-on:\s*([^\n#]+)", jb, re.M):
                raw_ro = rm.group(1).strip()
                if "matrix." in raw_ro:
                    for mm in re.finditer(r"^\s*os:\s*\[([^\]]+)\]", jb, re.M):
                        for item in mm.group(1).split(","):
                            mapped = map_runner_label(item)
                            if mapped and mapped not in runners:
                                runners.append(mapped)
                else:
                    mapped = map_runner_label(raw_ro)
                    if mapped and mapped not in runners:
                        runners.append(mapped)
            if not runners:
                continue
            job_seeds: set[str] = set()
            for line in jb.splitlines():
                for rname in extract_just_calls(line):
                    if rname in recipes:
                        job_seeds.add(rname)
            for rname in recipe_closure(job_seeds):
                _deps, body = recipes[rname]
                body_joined = "\n".join(body)
                if rname == "test-integration" or "--lane integration" in body_joined:
                    for os_a, arch_a in runners:
                        entry = (os_a, arch_a, frozenset())
                        if entry not in lane_envs["integration"]:
                            lane_envs["integration"].append(entry)
                elif rname == "test-kvm" or "--lane kvm" in body_joined:
                    for os_a, arch_a in runners:
                        entry = (os_a, arch_a, frozenset())
                        if entry not in lane_envs["kvm"]:
                            lane_envs["kvm"].append(entry)
                elif rname in ("test", "test-shard-a", "test-shard-b") or "--lane host" in body_joined:
                    excl = frozenset(
                        re.findall(r"--exclude(?:-package)?\s+([A-Za-z0-9_-]+)", body_joined)
                    )
                    for os_a, arch_a in runners:
                        entry = (os_a, arch_a, excl)
                        if entry not in lane_envs["host"]:
                            lane_envs["host"].append(entry)
                if rname.startswith("test-"):
                    for bl in body:
                        if "test" in bl and ("-p " in bl or "--package " in bl):
                            for pm in re.finditer(r"(?:-p|--package)\s+([A-Za-z0-9_-]+)", bl):
                                pkg = pm.group(1)
                                for os_a, arch_a in runners:
                                    pkg_host_envs.setdefault(pkg, set()).add((os_a, arch_a))

    if not lane_envs["host"] and not pkg_host_envs:
        lane_envs = default_lane_envs
        pkg_host_envs = default_pkg_host_envs

    view._workflow_lane_info_cache = (lane_envs, pkg_host_envs)
    return view._workflow_lane_info_cache


def _ci_environments_for_target(
    view: RepoView, pkg_name: str, lane: str
) -> list[tuple[str, str, set[str]]]:
    """Return `(target_os, target_arch, enabled_features)` tuples that CI builds for `(pkg_name, lane)`."""
    data = _load_crate_cargo_toml(view, pkg_name) or {}
    features_table = data.get("features", {})
    if not isinstance(features_table, dict):
        features_table = {}

    default_list = features_table.get("default", [])
    default_seed = (
        {f for f in default_list if isinstance(f, str) and "/" not in f and not f.startswith("dep:")}
        if isinstance(default_list, list)
        else set()
    )

    dev_deps = data.get("dev-dependencies", {})
    self_dev_features: set[str] = set()
    if isinstance(dev_deps, dict):
        self_entry = dev_deps.get(pkg_name)
        if isinstance(self_entry, dict):
            f_list = self_entry.get("features", [])
            if isinstance(f_list, list):
                self_dev_features.update(f for f in f_list if isinstance(f, str))
    if pkg_name in ("carrick-kernel", "carrick-vfs") and "test-support" in features_table:
        self_dev_features.add("test-support")

    macos_feats = _expand_crate_features(features_table, default_seed | self_dev_features)
    linux_seed = set(self_dev_features)
    if "platform-linux" in features_table:
        linux_seed.add("platform-linux")
        if "syscall-shim" in features_table:
            linux_seed.add("syscall-shim")
    else:
        linux_seed |= default_seed
    linux_feats = _expand_crate_features(features_table, linux_seed)

    lane_envs, pkg_host_envs = _discover_workflow_lane_info(view)
    os_arch_pairs: list[tuple[str, str]] = []
    if lane == "host":
        for os_a, arch_a, excl in lane_envs.get("host", []):
            if pkg_name not in excl and (os_a, arch_a) not in os_arch_pairs:
                os_arch_pairs.append((os_a, arch_a))
        for os_a, arch_a in sorted(pkg_host_envs.get(pkg_name, set())):
            if (os_a, arch_a) not in os_arch_pairs:
                os_arch_pairs.append((os_a, arch_a))
    else:
        for os_a, arch_a, _excl in lane_envs.get(lane, []):
            if (os_a, arch_a) not in os_arch_pairs:
                os_arch_pairs.append((os_a, arch_a))

    out: list[tuple[str, str, set[str]]] = []
    for os_a, arch_a in os_arch_pairs:
        feats = macos_feats if os_a == "macos" else linux_feats
        out.append((os_a, arch_a, feats))
    return out


def _eval_cfg_expr(
    expr: str,
    test_flag: bool,
    target_os: str,
    target_arch: str,
    enabled_features: set[str],
    debug_assertions: bool = True,
) -> bool:
    expr = expr.strip()
    if not expr:
        return True
    m = re.match(r"^(all|any|not)\s*\((.*)\)\s*$", expr, re.S)
    if m:
        op = m.group(1)
        args = _split_cfg_top_level_commas(m.group(2))
        if op == "all":
            return all(
                _eval_cfg_expr(a, test_flag, target_os, target_arch, enabled_features, debug_assertions)
                for a in args
            )
        if op == "any":
            return any(
                _eval_cfg_expr(a, test_flag, target_os, target_arch, enabled_features, debug_assertions)
                for a in args
            )
        if op == "not":
            if len(args) != 1:
                return False
            return not _eval_cfg_expr(
                args[0], test_flag, target_os, target_arch, enabled_features, debug_assertions
            )
    if expr == "test":
        return test_flag
    if expr == "unix":
        return target_os in ("macos", "linux", "freebsd", "netbsd")
    if expr == "windows":
        return target_os == "windows"
    if expr == "debug_assertions":
        return debug_assertions
    kv = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"$', expr)
    if kv:
        k, v = kv.group(1), kv.group(2)
        if k == "target_os":
            return target_os == v
        if k == "target_arch":
            return target_arch == v
        if k == "target_family":
            if v == "unix":
                return target_os in ("macos", "linux", "freebsd", "netbsd")
            if v == "windows":
                return target_os == "windows"
            return False
        if k == "target_pointer_width":
            return v == "64"
        if k == "target_endian":
            return v == "little"
        if k == "feature":
            return v in enabled_features
        return False
    return False


@functools.lru_cache(maxsize=4096)
def _lane_debug_assertions(view: RepoView, pkg_name: str, lane: str) -> bool:
    # scripts/lib/test-signed-body.sh builds signed executables with --release.
    release = lane in ("signed-hvf", "signed-cli")
    profiles = {}
    if view.is_file("Cargo.toml"):
        profiles = tomllib.loads(view.read_text("Cargo.toml")).get("profile", {})
    profile_names = ["release"] if release else ["dev", "test"]
    enabled = not release
    for name in profile_names:
        profile = profiles.get(name, {})
        enabled = profile.get("debug-assertions", enabled)
        overrides = profile.get("package", {})
        for key in ("*", pkg_name):
            enabled = overrides.get(key, {}).get("debug-assertions", enabled)
    return enabled is True


def _are_cfgs_active_in_ci(
    view: RepoView, pkg_name: str, lane: str, cfg_exprs: list[str]
) -> bool:
    if not cfg_exprs:
        return True
    envs = _ci_environments_for_target(view, pkg_name, lane)
    debug_assertions = _lane_debug_assertions(view, pkg_name, lane)
    return any(
        all(_eval_cfg_expr(expr, True, tos, tarch, feats, debug_assertions) for expr in cfg_exprs)
        for tos, tarch, feats in envs
    )


@functools.lru_cache(maxsize=4096)
def _compute_brace_depths(text: str) -> list[int]:
    depth = 0
    depths = [0] * (len(text) + 1)
    for idx, ch in enumerate(text):
        depths[idx] = depth
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth = max(0, depth - 1)
    depths[len(text)] = depth
    return depths


@functools.lru_cache(maxsize=4096)
def _blank_macro_defs(scope_stripped: str, scope_comments_stripped: str) -> tuple[str, str]:
    """Blank out `macro_rules! <name> { ... }`, `( ... );`, and `[ ... ];` bodies so items inside
    macro definitions are never mistaken for real module or test items. Fails closed to end-of-scope
    if delimiters are unbalanced.
    """
    macro_re = re.compile(r"\bmacro_rules!\s*(?:r#)?[A-Za-z_][A-Za-z0-9_]*\s*([{(\[])")
    if not macro_re.search(scope_stripped):
        return (scope_stripped, scope_comments_stripped)
    s_chars = list(scope_stripped)
    cs_chars = list(scope_comments_stripped)
    pairs = {"{": "}", "(": ")", "[": "]"}
    pos = 0
    n = len(scope_stripped)
    while pos < n:
        m = macro_re.search(scope_stripped, pos)
        if not m:
            break
        open_idx = m.end() - 1
        open_ch = m.group(1)
        close_ch = pairs[open_ch]
        close_idx = _find_matching_delim(scope_stripped, open_idx, open_ch, close_ch)
        end_idx = n if close_idx == -1 else close_idx + 1
        while end_idx < n and scope_stripped[end_idx] in " \t":
            end_idx += 1
        if end_idx < n and scope_stripped[end_idx] == ";":
            end_idx += 1
        for i in range(m.start(), end_idx):
            if s_chars[i] != "\n":
                s_chars[i] = " "
            if i < len(cs_chars) and cs_chars[i] != "\n":
                cs_chars[i] = " "
        pos = end_idx
    return ("".join(s_chars), "".join(cs_chars))


_ATTR_OPEN_RE = re.compile(r"#\s*(!?)\s*\[")


@functools.lru_cache(maxsize=4096)
def _scan_depth0_attributes_cached(scope_stripped: str) -> tuple[dict[int, tuple[int, int, bool]], bool]:
    depths = _compute_brace_depths(scope_stripped)
    attr_by_end: dict[int, tuple[int, int, bool]] = {}
    idx = 0
    n = len(scope_stripped)
    while idx < n:
        hash_pos = scope_stripped.find("#", idx)
        if hash_pos == -1:
            break
        idx = hash_pos
        if depths[idx] != 0:
            idx += 1
            continue
        if (
            idx > 0
            and scope_stripped[idx - 1] == "r"
            and (idx < 2 or not (scope_stripped[idx - 2].isalnum() or scope_stripped[idx - 2] == "_"))
            and idx + 1 < n
            and (scope_stripped[idx + 1].isalpha() or scope_stripped[idx + 1] == "_")
        ):
            idx += 1
            continue
        m = _ATTR_OPEN_RE.match(scope_stripped, idx)
        if not m:
            return ({}, False)
        is_inner = m.group(1) == "!"
        open_b = m.end() - 1
        close_b = _find_matching_delim(scope_stripped, open_b, "[", "]")
        if close_b == -1:
            return ({}, False)
        inner_s = scope_stripped[open_b + 1 : close_b]
        if not _are_delims_balanced(inner_s) or re.search(r"#\s*!?\s*\[", inner_s):
            return ({}, False)
        attr_by_end[close_b + 1] = (idx, close_b + 1, is_inner)
        idx = close_b + 1
    return (attr_by_end, True)


def _scan_depth0_attributes(
    scope_stripped: str, _depths: list[int] | None = None
) -> tuple[dict[int, tuple[int, int, bool]], bool]:
    """Scan all `#` tokens at delimiter depth 0 of `scope_stripped` using `_find_matching_delim`.

    Returns `(attr_by_end_offset, ok)` where each entry is `end_offset: (start_offset, end_offset, is_inner)`.
    Fails closed (`ok=False`) if any depth-0 `#` (outside `r#<ident>`) is not a bracket-balanced attribute.
    """
    return _scan_depth0_attributes_cached(scope_stripped)


def _iter_depth0_attributed_items(
    scope_stripped: str,
    scope_comments_stripped: str,
    item_re: re.Pattern[str],
    require_outer_attr: bool = False,
) -> tuple[list[tuple[re.Match[str], str]], bool]:
    """Find all matches of `item_re` at delimiter depth 0 of `scope_stripped`, along with their
    immediately preceding outer `#[...]` attribute block sliced from `scope_comments_stripped`.

    Returns `(items, ok)` where `ok=False` if any depth-0 attribute in `scope_stripped` is unparseable.
    """
    depths = _compute_brace_depths(scope_stripped)
    attr_by_end, ok = _scan_depth0_attributes(scope_stripped, depths)
    if not ok:
        return ([], False)
    results: list[tuple[re.Match[str], str]] = []
    for m in item_re.finditer(scope_stripped):
        if depths[m.start()] != 0:
            continue
        attr_start = m.start()
        has_outer = False
        cur = m.start()
        while True:
            while cur > 0 and scope_stripped[cur - 1] in " \t\r\n":
                cur -= 1
            attr_info = attr_by_end.get(cur)
            if attr_info is not None and not attr_info[2]:
                attr_start = attr_info[0]
                cur = attr_start
                has_outer = True
            else:
                break
        if cur > 0 and scope_stripped[cur - 1] not in ";}" and not (
            cur in attr_by_end and attr_by_end[cur][2]
        ):
            continue
        if require_outer_attr and not has_outer:
            continue
        attrs_cs = scope_comments_stripped[attr_start : m.start()]
        results.append((m, attrs_cs))
    return (results, True)


def _extract_scope_inner_attrs(scope_stripped: str, scope_comments_stripped: str) -> str:
    """Return all `#![...]` attributes at delimiter depth 0 of `scope_stripped` (excluding nested modules/items)."""
    s, cs = _blank_macro_defs(scope_stripped, scope_comments_stripped)
    depths = _compute_brace_depths(s)
    attr_by_end, ok = _scan_depth0_attributes(s, depths)
    if not ok:
        return "#![cfg(__invalid_cfg__)]"
    parts: list[str] = []
    for start, end, is_inner in sorted(attr_by_end.values(), key=lambda x: x[0]):
        if is_inner:
            parts.append(cs[start:end])
    return "\n".join(parts)


def _extract_test_and_cfg_exprs(attrs_cs: str) -> tuple[bool, list[str]]:
    """Return `(is_test_fn, cfg_exprs)` from outer `#[...]` attributes on a function."""
    attrs, ok = _iter_parsed_attributes(attrs_cs)
    if not ok:
        return (False, ["__invalid_cfg__"])
    has_unconditional_test = False
    all_cfgs: list[str] = []
    all_test_preds: list[str] = []
    for is_inner, body in attrs:
        if is_inner:
            continue
        cfgs, test_preds = _extract_cfg_from_attr_body(body, [])
        if "__invalid_cfg__" in cfgs:
            return (False, ["__invalid_cfg__"])
        if re.match(r"^(?:[\w:]+::)?(?:test|test_case|rstest)\b", body):
            has_unconditional_test = True
        else:
            all_cfgs.extend(cfgs)
            all_test_preds.extend(test_preds)

    if not has_unconditional_test and not all_test_preds:
        return (False, all_cfgs)
    if not has_unconditional_test:
        cond_test = (
            all_test_preds[0]
            if len(all_test_preds) == 1
            else f"any({', '.join(all_test_preds)})"
        )
        all_cfgs.append(cond_test)
    return (True, all_cfgs)


def _find_all_inline_mods(
    scope_stripped: str,
    scope_comments_stripped: str,
    mod_name: str | None = None,
) -> tuple[list[tuple[str, str, str, str]], bool]:
    """Find inline `mod <name> { ... }` at brace depth 0 of `scope_stripped`.

    Returns `([(mod_name, attrs_cs, body_stripped, body_comments_stripped), ...], ok)`.
    """
    original_s, original_cs = scope_stripped, scope_comments_stripped
    scope_stripped, scope_comments_stripped = _blank_macro_defs(
        scope_stripped, scope_comments_stripped
    )
    name_pat = re.escape(mod_name) if mod_name is not None else r"[A-Za-z_][A-Za-z0-9_]*"
    pattern = re.compile(rf"{_VIS_MOD_PREFIX}\bmod\s+(?:r#)?({name_pat})\s*\{{")
    items, ok = _iter_depth0_attributed_items(scope_stripped, scope_comments_stripped, pattern)
    if not ok:
        return ([], False)
    results: list[tuple[str, str, str, str]] = []
    for m, attrs_cs in items:
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(scope_stripped, open_brace)
        if close_brace != -1:
            results.append(
                (
                    m.group(1),
                    attrs_cs,
                    original_s[open_brace + 1 : close_brace],
                    original_cs[open_brace + 1 : close_brace],
                )
            )
    return (results, True)


def _find_inline_mods(
    scope_stripped: str,
    scope_comments_stripped: str,
    mod_name: str,
) -> list[tuple[str, str, str]]:
    """Find all `mod <mod_name> { ... }` at brace depth 0 of `scope_stripped`.

    Returns list of `(attrs_from_comments_stripped, body_stripped, body_comments_stripped)`.
    """
    items, ok = _find_all_inline_mods(scope_stripped, scope_comments_stripped, mod_name)
    if not ok:
        return []
    return [(attrs_cs, body_s, body_cs) for _name, attrs_cs, body_s, body_cs in items]


def _find_all_out_of_line_mods(
    scope_stripped: str,
    scope_comments_stripped: str,
    mod_name: str | None = None,
) -> tuple[list[tuple[str, str]], bool]:
    """Find `mod <name>;` declarations at brace depth 0 of `scope_stripped`.

    Returns `([(mod_name, attrs_cs), ...], ok)`.
    """
    scope_stripped, scope_comments_stripped = _blank_macro_defs(
        scope_stripped, scope_comments_stripped
    )
    name_pat = re.escape(mod_name) if mod_name is not None else r"[A-Za-z_][A-Za-z0-9_]*"
    pattern = re.compile(rf"{_VIS_MOD_PREFIX}\bmod\s+(?:r#)?({name_pat})\s*;")
    items, ok = _iter_depth0_attributed_items(scope_stripped, scope_comments_stripped, pattern)
    if not ok:
        return ([], False)
    return ([(m.group(1), attrs_cs) for m, attrs_cs in items], True)


def _find_out_of_line_mods(
    scope_stripped: str,
    scope_comments_stripped: str,
    mod_name: str,
) -> list[str]:
    """Find all `mod <mod_name>;` declarations at brace depth 0 of `scope_stripped`.

    Returns list of `attrs_from_comments_stripped`.
    """
    items, ok = _find_all_out_of_line_mods(scope_stripped, scope_comments_stripped, mod_name)
    if not ok:
        return []
    return [attrs_cs for _name, attrs_cs in items]


def _extract_path_attr(
    view: RepoView, pkg_name: str, lane: str, attrs_cs: str
) -> str | None:
    if not attrs_cs or not attrs_cs.strip():
        return None
    attrs, ok = _iter_parsed_attributes(attrs_cs)
    if not ok:
        return None
    for is_inner, body in attrs:
        if is_inner:
            continue
        items, item_ok = _iter_effective_attr_items(body)
        if not item_ok:
            return None
        for preds, leaf in items:
            pm = re.match(r'^path\s*=\s*"([^"]+)"\s*$', leaf)
            if pm:
                if not preds or _are_cfgs_active_in_ci(view, pkg_name, lane, preds):
                    return pm.group(1)
    return None


@functools.lru_cache(maxsize=4096)
def _extract_top_level_test_fns(
    scope_stripped: str,
    scope_comments_stripped: str,
    enclosing_attrs_cs: str = "",
) -> dict[str, tuple[bool, list[str], str, str]]:
    """Find all `#[test]`-attributed `fn <name>` at brace depth 0 of `scope_stripped`.

    Rejects `#[should_panic]` tests. Returns `{fn_name: (is_ignored, fn_cfg_exprs, fn_body_only_stripped, attrs_cs)}`.
    """
    if _has_should_panic_attr(enclosing_attrs_cs):
        return {}
    original_cs = scope_comments_stripped
    scope_stripped, scope_comments_stripped = _blank_macro_defs(
        scope_stripped, scope_comments_stripped
    )
    fn_pattern = re.compile(
        rf"{_VIS_MOD_PREFIX}"
        rf"(?:\b(?:default|const|async|unsafe|extern(?:\s*\"[^\"]*\")?)\s+)*"
        rf"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    items, ok = _iter_depth0_attributed_items(
        scope_stripped, scope_comments_stripped, fn_pattern, require_outer_attr=True
    )
    if not ok:
        return {}
    results: dict[str, tuple[bool, list[str], str, str]] = {}
    enclosing_ignored = _has_ignore_attr(enclosing_attrs_cs)
    for m, attrs_cs in items:
        if _has_should_panic_attr(attrs_cs):
            continue
        fn_name = m.group(1)
        is_test, fn_cfgs = _extract_test_and_cfg_exprs(attrs_cs)
        if not is_test:
            continue
        is_ignored = enclosing_ignored or _has_ignore_attr(attrs_cs)
        open_brace = scope_stripped.find("{", m.end())
        if open_brace == -1:
            continue
        close_brace = _find_matching_brace(scope_stripped, open_brace)
        if close_brace == -1:
            continue
        fn_body_only = original_cs[open_brace : close_brace + 1]
        results[fn_name] = (is_ignored, fn_cfgs, fn_body_only, attrs_cs)
    return results


def _extract_non_test_fns_with_attrs(
    scope_stripped: str,
    scope_comments_stripped: str,
    view: RepoView,
    pkg_name: str,
    lane: str,
    accum_cfgs: list[str],
) -> tuple[dict[str, list[tuple[list[str], str, str]]], bool]:
    """Find all non-`#[test]` `fn <name>` at brace depth 0 of `scope_stripped` whose `#[cfg]`s are active in CI.

    Returns `({fn_name: [(cfg_context, fn_body_only_stripped, attrs_cs), ...]}, ok)`.
    """
    original_cs = scope_comments_stripped
    scope_stripped, scope_comments_stripped = _blank_macro_defs(
        scope_stripped, scope_comments_stripped
    )
    fn_pattern = re.compile(
        rf"{_VIS_MOD_PREFIX}"
        rf"(?:\b(?:default|const|async|unsafe|extern(?:\s*\"[^\"]*\")?)\s+)*"
        rf"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    items, ok = _iter_depth0_attributed_items(scope_stripped, scope_comments_stripped, fn_pattern)
    if not ok:
        return ({}, False)
    results: dict[str, list[tuple[list[str], str, str]]] = {}
    for m, attrs_cs in items:
        is_test, fn_cfgs = _extract_test_and_cfg_exprs(attrs_cs)
        if is_test:
            continue
        if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs + fn_cfgs):
            continue
        fn_name = m.group(1)
        open_brace = scope_stripped.find("{", m.end())
        if open_brace == -1:
            continue
        close_brace = _find_matching_brace(scope_stripped, open_brace)
        if close_brace == -1:
            continue
        results.setdefault(fn_name, []).append(
            (accum_cfgs + fn_cfgs, original_cs[open_brace : close_brace + 1], attrs_cs)
        )
    return (results, True)


def _extract_non_test_fns(
    scope_stripped: str,
    scope_comments_stripped: str,
    view: RepoView,
    pkg_name: str,
    lane: str,
    accum_cfgs: list[str],
) -> dict[str, list[tuple[list[str], str]]]:
    """Find all non-`#[test]` `fn <name>` at brace depth 0 of `scope_stripped` whose `#[cfg]`s are active in CI.

    Returns `{fn_name: [(cfg_context, fn_body_only_stripped), ...]}`.
    """
    raw, ok = _extract_non_test_fns_with_attrs(
        scope_stripped, scope_comments_stripped, view, pkg_name, lane, accum_cfgs
    )
    if not ok:
        return {}
    return {
        fn_name: [(cfgs, body) for cfgs, body, _attrs in variants]
        for fn_name, variants in raw.items()
    }


def _body_calls_fn(body: str, callee_name: str) -> bool:
    esc = re.escape(callee_name)
    pat = re.compile(
        rf"(?:(?<![.\w:])|(?:self|super|crate)::)\b{esc}\s*\("
        rf"|\.\s*(?:map|and_then|or_else|filter|inspect|flat_map)\s*\(\s*(?:[\w:]+::)?{esc}\s*\)"
    )
    return bool(pat.search(strip_rust_comments_and_strings(body)))


def _expand_body_with_one_level_helpers(
    view: RepoView,
    pkg_name: str,
    lane: str,
    fn_cfgs: list[str],
    fn_body: str,
    local_helpers: dict[str, list[tuple[list[str], str]]],
) -> str:
    """Append bodies of functions in `local_helpers` that are directly called by `fn_body` (one level only)."""
    if not local_helpers:
        return fn_body
    parts = [fn_body]
    for hname, variants in sorted(local_helpers.items()):
        if _body_calls_fn(fn_body, hname):
            for helper_cfgs, hbody in variants:
                if _are_cfgs_active_in_ci(view, pkg_name, lane, fn_cfgs + helper_cfgs):
                    parts.append(hbody)
    return "\n".join(parts)


_MAX_CALL_CLOSURE_DEPTH = 12
_CALLEE_EXTRACT_RE = re.compile(
    r"(?:(?<![.\w:])|(?<![.\w:])(?:\b[a-z_][A-Za-z0-9_]*::)+)\b(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:::\s*<[^{};]*>\s*)?\("
    r"|\.\s*(?:map|and_then|or_else|filter|inspect|flat_map|map_err)\s*\(\s*(?:(?:\b[a-z_][A-Za-z0-9_]*::)+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_FN_NAME_INDEX_RE = re.compile(r"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b")


def _has_early_return_gutting(fn_body: str) -> bool:
    """Return True if `fn_body` constructs `ContractObservation::default()` or contains an unconditional
    top-level (`depth == 1`) `return ...;` statement followed by unreachable statements in the same block.
    """
    fn_body = strip_rust_comments_and_strings(fn_body)
    fn_body, _ = _blank_macro_defs(fn_body, fn_body)
    if "ContractObservation::default" in fn_body:
        return True
    depths = _compute_brace_depths(fn_body)
    n = len(fn_body)
    for m in re.finditer(r"\breturn\b", fn_body):
        if depths[m.start()] != 1:
            continue
        k = m.start() - 1
        while k >= 0 and fn_body[k] in " \t\r\n":
            k -= 1
        if k < 0 or fn_body[k] not in "{;}":
            continue
        pos = m.end()
        semi = -1
        while pos < n - 1:
            if depths[pos] == 1 and fn_body[pos] == ";":
                semi = pos
                break
            pos += 1
        if semi != -1 and fn_body[semi + 1 : -1].strip():
            return True
    return False


def _get_crate_fn_files(view: RepoView, pkg_name: str) -> dict[str, list[str]]:
    if pkg_name not in view._crate_fn_files_cache:
        idx: dict[str, list[str]] = {}
        for rel_path in view.glob_files(f"crates/{pkg_name}", ".rs"):
            raw = view.read_text(rel_path)
            for m in _FN_NAME_INDEX_RE.finditer(raw):
                fname = m.group(1)
                lst = idx.setdefault(fname, [])
                if not lst or lst[-1] != rel_path:
                    lst.append(rel_path)
        view._crate_fn_files_cache[pkg_name] = idx
    return view._crate_fn_files_cache[pkg_name]


def _extract_file_non_test_fns(
    view: RepoView, pkg_name: str, lane: str, rel_path: str
) -> tuple[dict[str, list[tuple[list[str], str, str]]], bool]:
    key = (pkg_name, lane, rel_path)
    if key in view._file_non_test_fns_cache:
        return view._file_non_test_fns_cache[key]
    s = view.read_stripped_rust(rel_path)
    cs = view.read_comments_stripped_rust(rel_path)
    inner_attrs = _extract_scope_inner_attrs(s, cs)
    if inner_attrs == "#![cfg(__invalid_cfg__)]":
        view._file_non_test_fns_cache[key] = ({}, False)
        return ({}, False)
    if _has_should_panic_attr(inner_attrs):
        view._file_non_test_fns_cache[key] = ({}, True)
        return ({}, True)
    inner_cfgs = _extract_cfg_exprs(inner_attrs, inner_only=True)
    if not _are_cfgs_active_in_ci(view, pkg_name, lane, inner_cfgs):
        view._file_non_test_fns_cache[key] = ({}, True)
        return ({}, True)
    fns, ok = _extract_non_test_fns_with_attrs(s, cs, view, pkg_name, lane, inner_cfgs)
    if not ok:
        view._file_non_test_fns_cache[key] = ({}, False)
        return ({}, False)
    def collect_modules(ms: str, mcs: str, cfgs: list[str]) -> bool:
        mods, mods_ok = _find_all_inline_mods(ms, mcs)
        if not mods_ok:
            return False
        for _name, attrs, body, body_cs in mods:
            inner = _extract_scope_inner_attrs(body, body_cs)
            if inner == "#![cfg(__invalid_cfg__)]":
                return False
            if _has_should_panic_attr(attrs) or _has_should_panic_attr(inner):
                continue
            child_cfgs = cfgs + _extract_cfg_exprs(attrs) + _extract_cfg_exprs(inner, inner_only=True)
            if not _are_cfgs_active_in_ci(view, pkg_name, lane, child_cfgs):
                continue
            children, ok = _extract_non_test_fns_with_attrs(
                body, body_cs, view, pkg_name, lane, child_cfgs
            )
            if not ok:
                return False
            for name, variants in children.items():
                fns.setdefault(name, []).extend(variants)
            if not collect_modules(body, body_cs, child_cfgs):
                return False
        return True

    if not collect_modules(s, cs, inner_cfgs):
        view._file_non_test_fns_cache[key] = ({}, False)
        return ({}, False)
    view._file_non_test_fns_cache[key] = (fns, True)
    return (fns, True)


def _method_dependency_fingerprint(view: RepoView, pkg_name: str) -> str:
    """Conservatively cover local method implementations and all their helpers.

    Receiver inference is incomplete without rustc. A token digest of the local
    implementation corpus includes every possible local callee, without
    pretending same-named methods on unrelated types form one execution path.
    This may invalidate unchanged evidence after an unrelated implementation
    edit; it cannot grandfather a gutted helper. It does not supply relevance.
    """
    cache = getattr(view, "_method_dependency_fingerprints", None)
    if cache is None:
        cache = {}
        view._method_dependency_fingerprints = cache
    if pkg_name not in cache:
        digest = hashlib.sha256()
        for rel_path in view.glob_files(f"crates/{pkg_name}", ".rs"):
            tokens = _fingerprint_tokens(view.read_comments_stripped_rust(rel_path))
            digest.update(repr((rel_path, tokens)).encode("utf-8"))
        cache[pkg_name] = "method-dependencies:" + digest.hexdigest()
    return cache[pkg_name]


def _compute_transitive_call_closure(
    view: RepoView,
    pkg_name: str,
    lane: str,
    fn_cfgs: list[str],
    start_bodies: list[str],
    local_helpers: dict[str, list[tuple[list[str], str]]],
    max_depth: int = _MAX_CALL_CLOSURE_DEPTH,
) -> tuple[str, bool]:
    """Compute the transitive local call closure of `start_bodies` within `pkg_name` up to `max_depth`.

    Fails closed (`ok=False`) if any body in the closure contains early-return gutting, `#[should_panic]`,
    unparseable attributes, or if the local call chain exceeds `max_depth`.
    """
    for b in start_bodies:
        if _has_early_return_gutting(b):
            return ("", False)
    crate_fn_files = _get_crate_fn_files(view, pkg_name)
    closure_parts: list[str] = []
    frontier = list(start_bodies)
    visited: set[str] = set()
    needs_method_snapshot = False

    for depth in range(1, max_depth + 2):
        called_names: set[str] = set()
        for b in frontier:
            code = strip_rust_comments_and_strings(b)
            code, _ = _blank_macro_defs(code, code)
            if any(
                match.group(1) in crate_fn_files
                for match in re.finditer(
                    r"(?:\.|::)\s*(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:::\s*<[^{};]*>\s*)?\(",
                    code,
                )
            ):
                needs_method_snapshot = True
            for cm in _CALLEE_EXTRACT_RE.finditer(code):
                cname = cm.group(1) or cm.group(2)
                if cname and cname not in _RUST_KEYWORDS and cname not in visited:
                    called_names.add(cname)
        if not called_names:
            break
        visited.update(called_names)

        next_frontier: list[str] = []
        for cname in sorted(called_names):
            active_variants: list[tuple[str, str]] = []
            if cname in local_helpers:
                for h_cfgs, h_body in local_helpers[cname]:
                    if _are_cfgs_active_in_ci(view, pkg_name, lane, fn_cfgs + h_cfgs):
                        active_variants.append(("", h_body))
            if not active_variants and cname in crate_fn_files:
                for rel_path in crate_fn_files[cname]:
                    file_fns, file_ok = _extract_file_non_test_fns(view, pkg_name, lane, rel_path)
                    if not file_ok:
                        return ("", False)
                    for h_cfgs, h_body, h_attrs in file_fns.get(cname, []):
                        if _are_cfgs_active_in_ci(view, pkg_name, lane, fn_cfgs + h_cfgs):
                            if _has_should_panic_attr(h_attrs):
                                return ("", False)
                            active_variants.append((h_attrs, h_body))

            for h_attrs, h_body in active_variants:
                if _has_early_return_gutting(h_body):
                    return ("", False)
                if depth > max_depth:
                    return ("", False)
                closure_parts.append(f"{cname}:{h_attrs}\n{h_body}")
                next_frontier.append(h_body)

        if not next_frontier:
            break
        frontier = next_frontier

    if needs_method_snapshot:
        closure_parts.append(_method_dependency_fingerprint(view, pkg_name))
    return ("\n".join(closure_parts), True)


def _scope_valid_test_fn_bodies(
    view: RepoView,
    pkg_name: str,
    lane: str,
    scope_stripped: str,
    scope_comments_stripped: str,
    fn_name: str | None,
    accum_cfgs: list[str],
    enclosing_attrs_cs: str = "",
) -> list[str] | None:
    """Return list of runnable `#[test]` function `{ ... }` bodies (plus 1-level local helpers and
    fingerprint metadata) for `fn_name` (or all in scope if `fn_name` is None), or None if no runnable
    CI-compiled `#[test]` function matches.
    """
    scope_inner_attrs = _extract_scope_inner_attrs(scope_stripped, scope_comments_stripped)
    if _has_should_panic_attr(scope_inner_attrs):
        return None
    scope_inner_cfgs = _extract_cfg_exprs(scope_inner_attrs, inner_only=True)
    accum_cfgs = accum_cfgs + scope_inner_cfgs
    if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs):
        return None
    test_fns = _extract_top_level_test_fns(
        scope_stripped, scope_comments_stripped, enclosing_attrs_cs
    )
    local_helpers = _extract_non_test_fns(
        scope_stripped, scope_comments_stripped, view, pkg_name, lane, accum_cfgs
    )
    if fn_name is not None:
        if fn_name not in test_fns:
            return None
        is_ignored, fn_cfgs, fn_body, fn_attrs_cs = test_fns[fn_name]
        if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs + fn_cfgs):
            return None
        if is_ignored and not _is_ignored_test_allowed(view, pkg_name, fn_name):
            return None
        expanded = _expand_body_with_one_level_helpers(
            view, pkg_name, lane, accum_cfgs + fn_cfgs, fn_body, local_helpers
        )
        closure_meta, closure_ok = _compute_transitive_call_closure(
            view, pkg_name, lane, accum_cfgs + fn_cfgs, [fn_body], local_helpers
        )
        if not closure_ok:
            return None
        return [f"{expanded}{_FINGERPRINT_META_SEP}{enclosing_attrs_cs}\n{scope_inner_attrs}\n{fn_attrs_cs}\n{closure_meta}"]

    bodies: list[str] = []
    for name, (is_ignored, fn_cfgs, fn_body, fn_attrs_cs) in sorted(test_fns.items()):
        if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs + fn_cfgs):
            continue
        if not is_ignored or _is_ignored_test_allowed(view, pkg_name, name):
            expanded = _expand_body_with_one_level_helpers(
                view, pkg_name, lane, accum_cfgs + fn_cfgs, fn_body, local_helpers
            )
            closure_meta, closure_ok = _compute_transitive_call_closure(
                view, pkg_name, lane, accum_cfgs + fn_cfgs, [fn_body], local_helpers
            )
            if not closure_ok:
                return None
            bodies.append(
                f"{expanded}{_FINGERPRINT_META_SEP}{enclosing_attrs_cs}\n{scope_inner_attrs}\n{fn_attrs_cs}\n{closure_meta}"
            )

    inline_mods, mods_ok = _find_all_inline_mods(scope_stripped, scope_comments_stripped)
    if not mods_ok:
        return None
    for _sub_name, sub_attrs_cs, sub_s, sub_cs in inline_mods:
        sub_inner_attrs = _extract_scope_inner_attrs(sub_s, sub_cs)
        if _has_should_panic_attr(sub_inner_attrs):
            continue
        sub_inner_cfgs = _extract_cfg_exprs(sub_inner_attrs, inner_only=True)
        sub_cfgs = accum_cfgs + _extract_cfg_exprs(sub_attrs_cs) + sub_inner_cfgs
        if not _are_cfgs_active_in_ci(view, pkg_name, lane, sub_cfgs):
            continue
        sub_enclosing_attrs = f"{enclosing_attrs_cs}\n{scope_inner_attrs}\n{sub_attrs_cs}\n{sub_inner_attrs}"
        sub_fns = _extract_top_level_test_fns(sub_s, sub_cs, sub_enclosing_attrs)
        sub_helpers = {
            **local_helpers,
            **_extract_non_test_fns(sub_s, sub_cs, view, pkg_name, lane, sub_cfgs),
        }
        for name, (is_ignored, fn_cfgs, fn_body, fn_attrs_cs) in sorted(sub_fns.items()):
            if not _are_cfgs_active_in_ci(view, pkg_name, lane, sub_cfgs + fn_cfgs):
                continue
            if not is_ignored or _is_ignored_test_allowed(view, pkg_name, name):
                expanded = _expand_body_with_one_level_helpers(
                    view, pkg_name, lane, sub_cfgs + fn_cfgs, fn_body, sub_helpers
                )
                closure_meta, closure_ok = _compute_transitive_call_closure(
                    view, pkg_name, lane, sub_cfgs + fn_cfgs, [fn_body], sub_helpers
                )
                if not closure_ok:
                    return None
                bodies.append(
                    f"{expanded}{_FINGERPRINT_META_SEP}{sub_enclosing_attrs}\n{fn_attrs_cs}\n{closure_meta}"
                )

    return bodies if bodies else None


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
        if lib_table.get("test") is False or lib_table.get("harness") is False:
            return False
        lib_path = f"{crate_dir}/{lib_table.get('path', 'src/lib.rs').lstrip('/')}"
        if view.is_file(lib_path):
            return True
    elif lib_table is None:
        if view.is_file(f"{crate_dir}/src/lib.rs") or view.is_file(f"{crate_dir}/src/main.rs"):
            return True
    return False


def get_target_lane(view: RepoView, pkg_name: str, target_name: str) -> str | None:
    """Return the validated lane name for `(pkg_name, target_name)` or None if missing/malformed."""
    data = _load_crate_cargo_toml(view, pkg_name)
    if data is None:
        return None

    int_targets = _discover_integration_targets(view, pkg_name)
    if int_targets is None:
        return None

    carrick_meta = data.get("package", {}).get("metadata", {}).get("carrick")
    lanes = None
    if carrick_meta is not None:
        if not isinstance(carrick_meta, dict):
            return None
        lanes = carrick_meta.get("test-lanes")
        if lanes is not None and not isinstance(lanes, dict):
            return None

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
                    return None
                if reason is not None and not isinstance(reason, str):
                    return None
            else:
                return None
            if lane not in KNOWN_TEST_LANES:
                return None
            if lane == "manual" and (not reason or not reason.strip()):
                return None
            if key != "*" and key != "lib" and key not in int_targets:
                return None
            parsed_lanes[key] = lane

    if target_name == "lib":
        if not _crate_has_testable_lib_or_bin(view, pkg_name):
            return None
        return parsed_lanes.get("lib", "host")

    if target_name not in int_targets:
        return None
    for target in data.get("test", []) or []:
        if target.get("name") == target_name and target.get("harness") is False:
            return None
    return parsed_lanes.get(target_name, parsed_lanes.get("*", "host"))


def is_target_in_gated_lane(view: RepoView, pkg_name: str, target_name: str) -> bool:
    """Validate `Cargo.toml` and `[package.metadata.carrick.test-lanes]` fail-closed, modeling `lib` explicitly."""
    lane = get_target_lane(view, pkg_name, target_name)
    return lane in GATED_TEST_LANES if lane is not None else False


def _resolve_child_mod_files(
    view: RepoView,
    pkg_name: str,
    lane: str,
    cur_file: str,
    cur_mod_dir: str,
    seg: str,
    attrs_cs: str,
    is_file_scope: bool = True,
) -> list[str]:
    parent_dir = cur_file.rsplit("/", 1)[0] if "/" in cur_file else ""
    explicit_path = _extract_path_attr(view, pkg_name, lane, attrs_cs)
    if explicit_path is not None:
        base = parent_dir if is_file_scope else cur_mod_dir
        joined = os.path.normpath(f"{base}/{explicit_path}").replace("\\", "/")
        return [joined] if view.is_file(joined) else []
    out: list[str] = []
    for cand in (f"{cur_mod_dir}/{seg}.rs", f"{cur_mod_dir}/{seg}/mod.rs"):
        if view.is_file(cand) and cand not in out:
            out.append(cand)
    return out


def _find_use_reexports(
    scope_stripped: str,
    scope_comments_stripped: str,
    rem_segments: list[str],
) -> list[tuple[str, bool, list[str]]]:
    """Find `pub use` items at brace depth 0 of `scope_stripped` that alias `rem_segments[0]`
    or glob-re-export (`*`) an intra-crate module path.

    Returns list of `(attrs_from_comments_stripped, is_crate_root, new_rem_segments)`.
    """
    if not rem_segments:
        return []
    seg = rem_segments[0]
    next_rem = rem_segments[1:]
    scope_stripped, scope_comments_stripped = _blank_macro_defs(
        scope_stripped, scope_comments_stripped
    )
    use_re = re.compile(r"\bpub(?:\s*\([^)]*\))?\s+use\s+([^;]+);")
    items, ok = _iter_depth0_attributed_items(scope_stripped, scope_comments_stripped, use_re)
    if not ok:
        return []
    results: list[tuple[str, bool, list[str]]] = []

    def normalize_prefix(raw_segs: list[str]) -> tuple[bool, list[str]] | None:
        if not raw_segs:
            return None
        if raw_segs[0] == "crate":
            rest = raw_segs[1:]
            return (True, rest) if rest else None
        if raw_segs[0] == "self":
            rest = raw_segs[1:]
            return (False, rest) if rest else None
        if raw_segs[0] == "super":
            return None
        return (False, raw_segs)

    for m, attrs_cs in items:
        tree = re.sub(r"\s+", " ", m.group(1).strip()).lstrip(":")

        bm = re.match(r"^([A-Za-z0-9_:]+)::\s*\{([^{}]+)\}\s*$", tree)
        if bm:
            prefix_segs = [s.strip() for s in bm.group(1).split("::") if s.strip()]
            norm = normalize_prefix(prefix_segs)
            if norm is None:
                continue
            is_root, clean_prefix = norm
            for raw_item in bm.group(2).split(","):
                item = raw_item.strip()
                if not item:
                    continue
                if " as " in item:
                    orig, alias = [p.strip() for p in item.split(" as ", 1)]
                else:
                    orig = alias = item
                if alias == seg:
                    target_segs = clean_prefix + ([] if orig == "self" else [orig])
                    if target_segs:
                        results.append((attrs_cs, is_root, target_segs + next_rem))
            continue

        gm = re.match(r"^([A-Za-z0-9_:]+)::\s*\*\s*$", tree)
        if gm:
            prefix_segs = [s.strip() for s in gm.group(1).split("::") if s.strip()]
            norm = normalize_prefix(prefix_segs)
            if norm is not None:
                is_root, clean_prefix = norm
                results.append((attrs_cs, is_root, clean_prefix + rem_segments))
            continue

        sm = re.match(
            r"^([A-Za-z0-9_:]+)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$", tree
        )
        if sm:
            path_segs = [s.strip() for s in sm.group(1).split("::") if s.strip()]
            if len(path_segs) < 2:
                continue
            alias = sm.group(2).strip() if sm.group(2) else path_segs[-1]
            if alias == seg:
                norm = normalize_prefix(path_segs)
                if norm is not None:
                    is_root, clean_path = norm
                    results.append((attrs_cs, is_root, clean_path + next_rem))

    return results


def _scope_declares_mod(scope_s: str, scope_cs: str, mod_name: str) -> bool:
    return bool(
        _find_inline_mods(scope_s, scope_cs, mod_name)
        or _find_out_of_line_mods(scope_s, scope_cs, mod_name)
    )


_MACRO_SCOPE_META = "/*__CONTRACT_MACROS__:"


def _scope_macro_names(scope_s: str, scope_cs: str, inherited: dict[str, str]) -> dict[str, str]:
    names = dict(inherited)
    depths = _compute_brace_depths(scope_s)
    for m in _MACRO_DECL_RE.finditer(scope_s):
        if depths[m.start()] == 0:
            opening = m.end()
            while opening < len(scope_s) and scope_s[opening].isspace():
                opening += 1
            pairs = {"{": "}", "(": ")", "[": "]"}
            closing = _find_matching_delim(scope_s, opening, scope_s[opening], pairs[scope_s[opening]]) if opening < len(scope_s) and scope_s[opening] in pairs else -1
            names[m.group(1)] = scope_cs[m.start():closing + 1] if closing != -1 else "__unresolved_macro__"
    clean, _ = _blank_macro_defs(scope_s, scope_s)
    depths = _compute_brace_depths(clean)
    for m in re.finditer(r"\buse\s+([^;]+);", clean):
        if depths[m.start()] != 0:
            continue
        tree = m.group(1).strip()
        if tree.startswith(("std::", "core::")):
            continue
        # Named imports may shadow a standard assertion, even if the origin
        # is an external macro whose expansion cannot be validated here.
        for name in _KNOWN_EXEC_MACROS:
            if re.search(rf"\b{re.escape(name)}\b", tree):
                names[name] = tree
    return names


def _with_macro_scope(bodies: list[str] | None, macros: dict[str, str]) -> list[str] | None:
    if bodies is None:
        return None
    marker = _MACRO_SCOPE_META + ",".join(sorted(macros)) + "*/"
    implementations = "\n".join(macros[name] for name in sorted(macros))
    return [body + "\n" + marker + "\n" + implementations for body in bodies]


def _resolve_in_module_tree(
    view: RepoView, pkg_name: str, lane: str, root_files: list[str], segments: list[str],
    require_test_module_for_root: bool, require_leaf: bool = False,
) -> tuple[str, list[str]] | None:
    """Resolve `segments` starting from `root_files` via explicit `mod` declarations and active CI `cfg`s."""
    for rf in root_files:
        if not view.is_file(rf):
            continue
        rf_s = view.read_stripped_rust(rf)
        rf_cs = view.read_comments_stripped_rust(rf)
        rf_inner_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(rf_s, rf_cs), inner_only=True)
        rf_mod_dir = rf.rsplit("/", 1)[0] if "/" in rf else ""
        visited: set[tuple[str, str, str, tuple[str, ...], frozenset[str]]] = set()

        def walk(
            cur_file: str, cur_mod_dir: str, is_file_scope: bool, scope_s: str, scope_cs: str,
            rem_segments: list[str], accum_cfgs: list[str], enclosing_attrs_cs: str, entered_test_mod: bool,
            inherited_macros: dict[str, str],
        ) -> tuple[str, list[str]] | None:
            if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs):
                return None
            state_key = (cur_file, cur_mod_dir, scope_cs, tuple(rem_segments), frozenset(accum_cfgs))
            if state_key in visited:
                return None
            visited.add(state_key)

            scope_macros = _scope_macro_names(scope_s, scope_cs, inherited_macros)
            in_test_context = entered_test_mod or not require_test_module_for_root

            if not rem_segments:
                if require_leaf or not in_test_context:
                    return None
                bodies = _scope_valid_test_fn_bodies(
                    view, pkg_name, lane, scope_s, scope_cs, None, accum_cfgs, enclosing_attrs_cs,
                )
                return (cur_file, _with_macro_scope(bodies, scope_macros)) if bodies else None

            if len(rem_segments) == 1 and in_test_context:
                fn_bodies = _scope_valid_test_fn_bodies(
                    view, pkg_name, lane, scope_s, scope_cs, rem_segments[0], accum_cfgs, enclosing_attrs_cs,
                )
                if fn_bodies:
                    return (cur_file, _with_macro_scope(fn_bodies, scope_macros))

            seg = rem_segments[0]
            next_rem = rem_segments[1:]

            # 1. Try inline `mod <seg> { ... }` in `scope_s`
            inline_mods = _find_inline_mods(scope_s, scope_cs, seg)
            for attrs_cs, body_s, body_cs in inline_mods:
                inner_mod_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(body_s, body_cs), inner_only=True)
                mod_cfgs = _extract_cfg_exprs(attrs_cs) + inner_mod_cfgs
                mod_is_test = entered_test_mod or any(_cfg_is_test_only(e) for e in mod_cfgs)
                explicit_inline_path = _extract_path_attr(view, pkg_name, lane, attrs_cs)
                if explicit_inline_path is not None:
                    inline_mod_dir = os.path.normpath(f"{cur_mod_dir}/{explicit_inline_path}").replace("\\", "/")
                else:
                    inline_mod_dir = f"{cur_mod_dir}/{seg}" if cur_mod_dir else seg
                res = walk(
                    cur_file, inline_mod_dir, False, body_s, body_cs, next_rem,
                    accum_cfgs + mod_cfgs, enclosing_attrs_cs + "\n" + attrs_cs, mod_is_test, scope_macros,
                )
                if res is not None:
                    return res

            # 2. Try out-of-line `mod <seg>;` in `scope_s` (both file scope and inline mod scope)
            out_of_line_mods = _find_out_of_line_mods(scope_s, scope_cs, seg)
            for attrs_cs in out_of_line_mods:
                mod_cfgs = _extract_cfg_exprs(attrs_cs)
                if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs + mod_cfgs):
                    continue
                mod_is_test = entered_test_mod or any(_cfg_is_test_only(e) for e in mod_cfgs)
                for child_file in _resolve_child_mod_files(
                    view, pkg_name, lane, cur_file, cur_mod_dir, seg, attrs_cs, is_file_scope,
                ):
                    child_s = view.read_stripped_rust(child_file)
                    child_cs = view.read_comments_stripped_rust(child_file)
                    inner_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(child_s, child_cs), inner_only=True)
                    child_is_test = mod_is_test or any(_cfg_is_test_only(e) for e in inner_cfgs)
                    child_mod_dir = child_file.rsplit("/", 1)[0] if child_file.endswith("/mod.rs") else child_file[:-3]
                    res = walk(
                        child_file, child_mod_dir, True, child_s, child_cs, next_rem,
                        accum_cfgs + mod_cfgs + inner_cfgs, enclosing_attrs_cs + "\n" + attrs_cs, child_is_test, scope_macros,
                    )
                    if res is not None:
                        return res

            # A declared module owns this name; a glob cannot replace its missing child.
            if inline_mods or out_of_line_mods:
                return None

            # 3. Try `pub use` module re-exports in `scope_s`
            for use_attrs_cs, is_crate_root, new_rem in _find_use_reexports(scope_s, scope_cs, rem_segments):
                if not new_rem:
                    continue
                target_s = rf_s if is_crate_root else scope_s
                target_cs = rf_cs if is_crate_root else scope_cs
                if not _scope_declares_mod(target_s, target_cs, new_rem[0]):
                    continue
                use_cfgs = _extract_cfg_exprs(use_attrs_cs)
                if not _are_cfgs_active_in_ci(view, pkg_name, lane, accum_cfgs + use_cfgs):
                    continue
                use_is_test = entered_test_mod or any(_cfg_is_test_only(e) for e in use_cfgs)
                if is_crate_root:
                    res = walk(
                        rf, rf_mod_dir, True, rf_s, rf_cs, new_rem,
                        accum_cfgs + use_cfgs, enclosing_attrs_cs + "\n" + use_attrs_cs, use_is_test, scope_macros,
                    )
                else:
                    res = walk(
                        cur_file, cur_mod_dir, is_file_scope, scope_s, scope_cs, new_rem,
                        accum_cfgs + use_cfgs, enclosing_attrs_cs + "\n" + use_attrs_cs, use_is_test, scope_macros,
                    )
                if res is not None:
                    return res

            return None

        res = walk(
            rf, rf_mod_dir, True, rf_s, rf_cs, segments, rf_inner_cfgs, "",
            any(_cfg_is_test_only(e) for e in rf_inner_cfgs), {},
        )
        if res is not None:
            return res

    return None


def _resolve_contract_helper_binding(
    view: RepoView, pkg_name: str, contract_fn: str, int_targets: dict[str, str],
) -> tuple[str, str, str, list[str]] | None:
    """Resolve `<pkg>::<contract_fn>` or `<pkg>::contracts::<contract_fn>` defined in `src/contracts.rs`."""
    crate_dir = f"crates/{pkg_name}"
    lib_rs = f"{crate_dir}/src/lib.rs"
    if not view.is_file(lib_rs):
        return None
    lib_lane = get_target_lane(view, pkg_name, "lib") or "host"
    lib_s = view.read_stripped_rust(lib_rs)
    lib_cs = view.read_comments_stripped_rust(lib_rs)
    contracts_mod_attrs = _find_out_of_line_mods(lib_s, lib_cs, "contracts")
    if not contracts_mod_attrs:
        return None
    if not any(_are_cfgs_active_in_ci(view, pkg_name, lib_lane, _extract_cfg_exprs(a)) for a in contracts_mod_attrs):
        return None

    contract_files: list[str] = []
    root_contracts = f"{crate_dir}/src/contracts.rs"
    if view.is_file(root_contracts):
        contract_files.append(root_contracts)
        rc_s = view.read_stripped_rust(root_contracts)
        rc_cs = view.read_comments_stripped_rust(root_contracts)
        rc_mod_dir = root_contracts[:-3]
        out_mods, out_ok = _find_all_out_of_line_mods(rc_s, rc_cs)
        if not out_ok:
            return None
        for sub_name, sub_attrs in out_mods:
            if _are_cfgs_active_in_ci(view, pkg_name, lib_lane, _extract_cfg_exprs(sub_attrs)):
                for cf in _resolve_child_mod_files(
                    view, pkg_name, lib_lane, root_contracts, rc_mod_dir, sub_name, sub_attrs
                ):
                    if cf not in contract_files:
                        contract_files.append(cf)
    if not contract_files:
        return None

    contract_fn_body: str | None = None
    contract_fn_attrs_cs: str = ""
    callee_names: set[str] = {contract_fn}
    pub_fn_re = re.compile(
        rf"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+|unsafe\s+|const\s+)*fn\s+(?:r#)?{re.escape(contract_fn)}\b"
    )
    for cf in contract_files:
        stripped = view.read_stripped_rust(cf)
        cs = view.read_comments_stripped_rust(cf)
        s_clean, cs_clean = _blank_macro_defs(stripped, cs)
        items, ok = _iter_depth0_attributed_items(s_clean, cs_clean, pub_fn_re)
        if not ok:
            return None
        if items:
            m, contract_fn_attrs_cs = items[0]
            if _has_should_panic_attr(contract_fn_attrs_cs):
                return None
            if not _are_cfgs_active_in_ci(view, pkg_name, lib_lane, _extract_cfg_exprs(contract_fn_attrs_cs)):
                return None
            open_brace = s_clean.find("{", m.end())
            if open_brace != -1:
                close_brace = _find_matching_brace(s_clean, open_brace)
                if close_brace != -1:
                    contract_fn_body = cs[open_brace : close_brace + 1]
                    for helper_m in re.finditer(r"\b(run_[A-Za-z0-9_]*_contract)\s*\(", strip_rust_comments_and_strings(contract_fn_body)):
                        callee_names.add(helper_m.group(1))
            break

    if contract_fn_body is None:
        return None

    names_alt = "|".join(re.escape(n) for n in sorted(callee_names))
    call_in_test_re = re.compile(
        rf"(?:(?<![.\w:])|(?:[\w:]+::))\b(?:{names_alt})\s*\(|\.\s*map\s*\(\s*(?:[\w:]+::)?(?:{names_alt})\s*\)"
    )
    for tname, tfile in sorted(int_targets.items()):
        tlane = get_target_lane(view, pkg_name, tname)
        if tlane is None or tlane not in GATED_TEST_LANES:
            continue
        t_stripped = view.read_stripped_rust(tfile)
        t_cs = view.read_comments_stripped_rust(tfile)
        t_inner_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(t_stripped, t_cs), inner_only=True)
        if not _are_cfgs_active_in_ci(view, pkg_name, tlane, t_inner_cfgs):
            continue
        test_fns = _extract_top_level_test_fns(t_stripped, t_cs)
        t_helpers = _extract_non_test_fns(t_stripped, t_cs, view, pkg_name, tlane, t_inner_cfgs)
        for fn_name, (is_ignored, fn_cfgs, fn_body, fn_attrs_cs) in sorted(test_fns.items()):
            if not _are_cfgs_active_in_ci(view, pkg_name, tlane, t_inner_cfgs + fn_cfgs):
                continue
            if is_ignored and not _is_ignored_test_allowed(view, pkg_name, fn_name):
                continue
            expanded_test_body = _expand_body_with_one_level_helpers(
                view, pkg_name, tlane, t_inner_cfgs + fn_cfgs, fn_body, t_helpers
            )
            if call_in_test_re.search(strip_rust_comments_and_strings(expanded_test_body)):
                closure_meta, closure_ok = _compute_transitive_call_closure(
                    view, pkg_name, tlane, t_inner_cfgs + fn_cfgs, [contract_fn_body, fn_body], t_helpers
                )
                if not closure_ok:
                    return None
                meta = f"{contract_fn_attrs_cs}\n{t_cs}\n{fn_attrs_cs}\n{expanded_test_body}\n{closure_meta}"
                return (pkg_name, tname, tfile, [f"{contract_fn_body}{_FINGERPRINT_META_SEP}{meta}"])

    return None


def resolve_binding_at_view(
    view: RepoView, spec: str, require_leaf: bool = False
) -> tuple[str, str, str, list[str]] | None:
    """Resolve `pkg::...` at `view` to `(pkg_name, target_name, test_file_rel_path, ref_stripped_texts)` or None."""
    parts = [p.strip() for p in spec.split("::") if p.strip()]
    if len(parts) < 2:
        return None
    pkg_name, rest = parts[0], parts[1:]
    if _load_crate_cargo_toml(view, pkg_name) is None:
        return None

    crate_dir = f"crates/{pkg_name}"
    src_dir = f"{crate_dir}/src"

    lib_lane = get_target_lane(view, pkg_name, "lib")
    if view.is_dir(src_dir) and lib_lane is not None:
        res = _resolve_in_module_tree(
            view, pkg_name, lib_lane, [f"{src_dir}/lib.rs", f"{src_dir}/main.rs"], rest,
            require_test_module_for_root=True, require_leaf=require_leaf,
        )
        if res is not None:
            return (pkg_name, "lib", res[0], res[1])

    int_targets = _discover_integration_targets(view, pkg_name)
    if int_targets is None:
        return None

    target_candidate = None
    after_target: list[str] = []
    if rest[0] in int_targets:
        target_candidate, after_target = rest[0], rest[1:]
    elif rest[0] == "tests" and len(rest) >= 2 and rest[1] in int_targets:
        target_candidate, after_target = rest[1], rest[2:]

    if target_candidate is not None:
        tlane = get_target_lane(view, pkg_name, target_candidate)
        if tlane is not None:
            res = _resolve_in_module_tree(
                view, pkg_name, tlane, [int_targets[target_candidate]], after_target,
                require_test_module_for_root=False, require_leaf=require_leaf,
            )
            if res is not None:
                return (pkg_name, target_candidate, res[0], res[1])

    if len(rest) == 1:
        fn_name = rest[0]
        for tname, root_tf in sorted(int_targets.items()):
            tlane = get_target_lane(view, pkg_name, tname)
            if tlane is None:
                continue
            res = _resolve_in_module_tree(
                view, pkg_name, tlane, [root_tf], [fn_name],
                require_test_module_for_root=False, require_leaf=require_leaf,
            )
            if res is not None:
                return (pkg_name, tname, res[0], res[1])
        helper_res = _resolve_contract_helper_binding(view, pkg_name, fn_name, int_targets)
        if helper_res is not None:
            return helper_res
    elif len(rest) == 2 and rest[0] == "contracts":
        helper_res = _resolve_contract_helper_binding(view, pkg_name, rest[1], int_targets)
        if helper_res is not None:
            return helper_res

    return None


def _extract_code_decl_identifiers(code_line: str) -> set[str]:
    """Extract declared item identifiers from a comment/string-stripped Rust code line."""
    found: set[str] = set()
    for regex in (_FN_DECL_RE, _STATIC_DECL_RE, _CONST_DECL_RE, _TYPE_MOD_DECL_RE, _MACRO_DECL_RE):
        for m in regex.finditer(code_line):
            ident = m.group(1)
            if ident and ident not in _RUST_KEYWORDS and ident not in _GENERIC_ITEM_NAMES and not ident.startswith("_"):
                found.add(ident)
    return found


def _fingerprint_tokens(text: str) -> tuple[str, ...]:
    """Normalize code whitespace while retaining exact Rust literal contents."""
    token_re = re.compile(
        r'(?:b?r|cr)(?P<hashes>\#*)"(?s:.*?)"(?P=hashes)'
        r'|(?:b|c)?"(?:\\[\s\S]|[^"\\])*"'
        r"|b?'(?:\\.|[^'\\\n])'"
        r"|[A-Za-z0-9_]+|[^\sA-Za-z0-9_]"
    )
    return tuple(m.group(0) for m in token_re.finditer(text))


def _tokenize_code_line(code_line: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", code_line))


def extract_changed_surface_items(
    root: Path, base_view: RepoView, head_view: RepoView, base_sha: str, head_sha: str,
    surface_path: str, old_surface_path: str | None = None,
) -> set[str]:
    """Extract item identifiers defined or modified by actual CODE token changes in `surface_path`'s diff."""
    base_path = old_surface_path or surface_path
    base_stripped_lines: list[str] = []
    if base_view.is_file(base_path):
        base_stripped_lines = strip_cfg_test_blocks(
            base_view.read_stripped_rust(base_path), base_view.read_comments_stripped_rust(base_path),
        ).splitlines()
    head_stripped_lines: list[str] = []
    if head_view.is_file(surface_path):
        head_stripped_lines = strip_cfg_test_blocks(
            head_view.read_stripped_rust(surface_path), head_view.read_comments_stripped_rust(surface_path),
        ).splitlines()

    if old_surface_path and old_surface_path != surface_path and base_view.is_file(old_surface_path):
        diff_cmd = [
            "git", "diff", "--no-ext-diff", "--no-textconv", "-U0",
            f"{base_sha}:{old_surface_path}", f"{head_sha}:{surface_path}",
        ]
    else:
        diff_cmd = [
            "git", "--literal-pathspecs", "diff", "--no-renames", "--no-ext-diff", "--no-textconv",
            "-U0", base_sha, head_sha, "--", surface_path,
        ]
    res = subprocess.run(diff_cmd, cwd=root, capture_output=True, text=True, check=False)
    if res.returncode not in (0, 1):
        return set()

    items: set[str] = set()
    old_line_no = 0
    new_line_no = 0
    in_hunk = False
    hunk_old_lines: list[str] = []
    hunk_new_lines: list[str] = []

    def flush_hunk():
        nonlocal hunk_old_lines, hunk_new_lines
        if not hunk_old_lines and not hunk_new_lines:
            return
        old_toks_flat: list[str] = []
        new_toks_flat: list[str] = []
        old_by_norm: list[tuple[tuple[str, ...], str]] = []
        new_by_norm: list[tuple[tuple[str, ...], str]] = []
        for oline in hunk_old_lines:
            toks = _tokenize_code_line(oline)
            old_toks_flat.extend(toks)
            old_by_norm.append((toks, oline))
        for nline in hunk_new_lines:
            toks = _tokenize_code_line(nline)
            new_toks_flat.extend(toks)
            new_by_norm.append((toks, nline))

        hunk_old_lines = []
        hunk_new_lines = []
        if old_toks_flat == new_toks_flat:
            return

        old_counts = Counter(toks for toks, _ in old_by_norm if toks)
        new_counts = Counter(toks for toks, _ in new_by_norm if toks)
        common = old_counts & new_counts

        rem_skip = Counter(common)
        for toks, oline in old_by_norm:
            if not toks:
                continue
            if rem_skip[toks] > 0:
                rem_skip[toks] -= 1
                continue
            items.update(_extract_code_decl_identifiers(oline))

        add_skip = Counter(common)
        for toks, nline in new_by_norm:
            if not toks:
                continue
            if add_skip[toks] > 0:
                add_skip[toks] -= 1
                continue
            items.update(_extract_code_decl_identifiers(nline))

    for raw_line in res.stdout.splitlines():
        if raw_line.startswith("@@ "):
            flush_hunk()
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
                hunk_old_lines.append(base_stripped_lines[old_line_no - 1])
            else:
                hunk_old_lines.append(strip_rust_comments_and_strings(raw_line[1:]))
            old_line_no += 1
        elif raw_line.startswith("+"):
            if 1 <= new_line_no <= len(head_stripped_lines):
                hunk_new_lines.append(head_stripped_lines[new_line_no - 1])
            else:
                hunk_new_lines.append(strip_rust_comments_and_strings(raw_line[1:]))
            new_line_no += 1

    flush_hunk()
    return items


_KNOWN_EXEC_MACROS = frozenset({
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "matches",
    "vec",
    "format",
    "format_args",
    "write",
    "writeln",
    "print",
    "println",
    "eprint",
    "eprintln",
    "dbg",
    "panic",
})


def _strip_non_semantic_ident_occurrences(
    text: str, extra_local_macros: set[str] | None = None
) -> str:
    """Blank out non-executing macro invocations (such as `stringify!(...)` or `nop!{ assert!(...) }`),
    `if false { ... }` / `while false { ... }` blocks, uncalled closures, and local `let [mut] <ident>`
    binding names so non-executing identifier mentions do not satisfy surface relevance.
    (Full semantic call-graph / rustc symbol resolution is tracked in #537.)
    """
    scope_macros: set[str] = set()
    for marker in re.findall(re.escape(_MACRO_SCOPE_META) + r"([^*]*)\*/", text):
        scope_macros.update(filter(None, marker.split(",")))
    text = strip_rust_comments_and_strings(text.split(_FINGERPRINT_META_SEP, 1)[0])
    defined_macros = set(
        re.findall(r"\bmacro_rules!\s*(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b", text)
    )
    defined_macros.update(scope_macros)
    if extra_local_macros:
        defined_macros.update(extra_local_macros)
    text, _ = _blank_macro_defs(text, text)

    chars = list(text)
    pairs = {"(": ")", "[": "]", "{": "}"}
    macro_call_re = re.compile(r"\b(?:[\w:]+::)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)!\s*([(\[{])")
    pos = 0
    n = len(text)
    while pos < n:
        m = macro_call_re.search(text, pos)
        if not m:
            break
        mname = m.group(1)
        if mname in _KNOWN_EXEC_MACROS and mname not in defined_macros:
            pos = m.end()
            continue
        open_idx = m.end() - 1
        open_ch = m.group(2)
        close_idx = _find_matching_delim(text, open_idx, open_ch, pairs[open_ch])
        end_idx = n if close_idx == -1 else close_idx + 1
        for i in range(m.start(), end_idx):
            if chars[i] != "\n":
                chars[i] = " "
        pos = end_idx

    s = "".join(chars)
    chars = list(s)
    false_cond_re = re.compile(r"\b(?:if|while)\s+(?:\(\s*)*(?:false|!\s*true)\b[^{;]*\{")
    pos = 0
    n = len(s)
    while pos < n:
        m = false_cond_re.search(s, pos)
        if not m:
            break
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(s, open_brace)
        end_idx = n if close_brace == -1 else close_brace + 1
        for i in range(m.start(), end_idx):
            if chars[i] != "\n":
                chars[i] = " "
        pos = end_idx

    s = "".join(chars)
    chars = list(s)
    closure_re = re.compile(r"(?:\bmove\s+)?(\|\s*\||\|[^|;{}]*\|)")
    let_closure_re = re.compile(
        r"\blet\s+(?:mut\s+)?(_|(?:r#)?[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;{}]+)?=\s*$"
    )
    pos = 0
    n = len(s)
    while pos < n:
        m = closure_re.search(s, pos)
        if not m:
            break
        prefix = s[: m.start()]
        r_prefix = prefix.rstrip()
        lm = let_closure_re.search(prefix)
        var_name: str | None = None
        is_stmt_closure = False
        is_paren_closure = False
        if lm is not None:
            var_name = lm.group(1)
            is_stmt_closure = True
        elif not r_prefix or r_prefix[-1] in "{;":
            is_stmt_closure = True
        elif r_prefix[-1] == "(":
            before_paren = r_prefix[:-1].rstrip()
            if not before_paren or before_paren[-1] in "{;":
                is_stmt_closure = True
                is_paren_closure = True

        if not is_stmt_closure:
            pos = m.end()
            continue

        body_pos = m.end()
        while body_pos < n and s[body_pos] in " \t\r\n":
            body_pos += 1
        if s.startswith("->", body_pos):
            brace_idx = s.find("{", body_pos + 2)
            if brace_idx != -1:
                body_pos = brace_idx
        if body_pos < n and s[body_pos] == "{":
            close_b = _find_matching_brace(s, body_pos)
            closure_end = n if close_b == -1 else close_b + 1
        else:
            d = 0
            idx = body_pos
            while idx < n:
                ch = s[idx]
                if ch in "([{":
                    d += 1
                elif ch in ")]}":
                    if d == 0:
                        break
                    d -= 1
                elif ch == ";" and d == 0:
                    break
                idx += 1
            closure_end = idx

        after = s[closure_end:].lstrip()
        invoked_immediately = after.startswith("(") or (
            is_paren_closure and after.startswith(")") and after[1:].lstrip().startswith("(")
        )
        if invoked_immediately:
            pos = closure_end
            continue
        if var_name is not None and var_name != "_":
            v_clean = var_name[2:] if var_name.startswith("r#") else var_name
            if re.search(rf"\b(?:r#)?{re.escape(v_clean)}\s*\(", s[closure_end:]):
                pos = closure_end
                continue

        for i in range(m.start(), closure_end):
            if chars[i] != "\n":
                chars[i] = " "
        pos = closure_end

    s = "".join(chars)
    # Blank out simple local variable pattern names in `let [mut] <ident>` (not followed by `::`, `{`, or `(`).
    let_pat_re = re.compile(r"\blet\s+(?:mut\s+)?((?:r#)?[A-Za-z_][A-Za-z0-9_]*)\b(?!\s*(?:::|\{|\())")
    chars = list(s)
    for m in let_pat_re.finditer(s):
        for i in range(m.start(1), m.end(1)):
            chars[i] = " "
    return "".join(chars)


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
    """Return True if a newly added/changed bound test references `surface_path` inside its own body."""
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
    file_macros: set[str] = set()
    if head_view.is_file(test_file):
        file_macros.update(
            re.findall(
                r"\bmacro_rules!\s*(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b",
                head_view.read_stripped_rust(test_file),
            )
        )
    cleaned_texts = [_strip_non_semantic_ident_occurrences(txt, file_macros) for txt in ref_texts]
    for ident in items:
        pat = re.compile(rf"\b{re.escape(ident)}\b")
        if any(pat.search(txt) for txt in cleaned_texts):
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


def _classify_crate_rust_files(view: RepoView, pkg_name: str) -> tuple[set[str], set[str], set[str]]:
    key = (id(view), pkg_name)
    if key in _CRATE_FILE_CLASS_CACHE:
        return _CRATE_FILE_CLASS_CACHE[key]
    crate_dir = f"crates/{pkg_name}"
    prod_files, cfg_test_files, int_test_files = set(), set(), set()
    data = _load_crate_cargo_toml(view, pkg_name)
    lib_lane = get_target_lane(view, pkg_name, "lib") or "host"
    root_candidates: list[str] = [f"{crate_dir}/src/lib.rs", f"{crate_dir}/src/main.rs"]
    if isinstance(data, dict):
        lib_tbl = data.get("lib")
        if isinstance(lib_tbl, dict) and isinstance(lib_tbl.get("path"), str):
            root_candidates.append(f"{crate_dir}/{lib_tbl['path'].lstrip('/')}")
        for b in data.get("bin") or []:
            if isinstance(b, dict) and isinstance(b.get("path"), str):
                root_candidates.append(f"{crate_dir}/{b['path'].lstrip('/')}")
    visited_scopes: set[tuple[str, str, bool, str, bool]] = set()
    unparseable = False

    def walk_scope(cur_file: str, cur_mod_dir: str, is_file_scope: bool, scope_s: str, scope_cs: str, in_test_cfg: bool) -> None:
        nonlocal unparseable
        s, cs = _blank_macro_defs(scope_s, scope_cs)
        state = (cur_file, cur_mod_dir, is_file_scope, cs, in_test_cfg)
        if state in visited_scopes:
            return
        visited_scopes.add(state)
        inline_mods, inline_ok = _find_all_inline_mods(s, cs)
        out_mods, out_ok = _find_all_out_of_line_mods(s, cs)
        if not inline_ok or not out_ok:
            unparseable = True
            return
        for seg, attrs_cs, body_s, body_cs in inline_mods:
            mod_cfgs = _extract_cfg_exprs(attrs_cs) + _extract_cfg_exprs(_extract_scope_inner_attrs(body_s, body_cs), inner_only=True)
            if "__invalid_cfg__" in mod_cfgs:
                unparseable = True
            sub_is_test = in_test_cfg or any(_cfg_is_test_only(e) for e in mod_cfgs)
            explicit_p = _extract_path_attr(view, pkg_name, lib_lane, attrs_cs)
            inline_dir = os.path.normpath(f"{cur_mod_dir}/{explicit_p}").replace("\\", "/") if explicit_p is not None else (f"{cur_mod_dir}/{seg}" if cur_mod_dir else seg)
            walk_scope(cur_file, inline_dir, False, body_s, body_cs, sub_is_test)
        for seg, attrs_cs in out_mods:
            outer_cfgs = _extract_cfg_exprs(attrs_cs)
            if "__invalid_cfg__" in outer_cfgs:
                unparseable = True
            mod_is_test = in_test_cfg or any(_cfg_is_test_only(e) for e in outer_cfgs)
            for child_file in _resolve_child_mod_files(view, pkg_name, lib_lane, cur_file, cur_mod_dir, seg, attrs_cs, is_file_scope):
                child_s, child_cs = view.read_stripped_rust(child_file), view.read_comments_stripped_rust(child_file)
                inner_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(child_s, child_cs), inner_only=True)
                if "__invalid_cfg__" in inner_cfgs:
                    unparseable = True
                child_is_test = mod_is_test or any(_cfg_is_test_only(e) for e in inner_cfgs)
                (cfg_test_files if child_is_test else prod_files).add(child_file)
                child_mod_dir = child_file.rsplit("/", 1)[0] if child_file.endswith("/mod.rs") else child_file[:-3]
                walk_scope(child_file, child_mod_dir, True, child_s, child_cs, child_is_test)

    for rf in dict.fromkeys(root_candidates):
        if not view.is_file(rf):
            continue
        rf_s, rf_cs = view.read_stripped_rust(rf), view.read_comments_stripped_rust(rf)
        rf_inner_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(rf_s, rf_cs), inner_only=True)
        if "__invalid_cfg__" in rf_inner_cfgs:
            unparseable = True
        rf_is_test = any(_cfg_is_test_only(e) for e in rf_inner_cfgs)
        (cfg_test_files if rf_is_test else prod_files).add(rf)
        walk_scope(rf, rf.rsplit("/", 1)[0] if "/" in rf else "", True, rf_s, rf_cs, rf_is_test)

    if unparseable:
        prod_files.update(view.glob_files(crate_dir, ".rs"))
        cfg_test_files.clear()
        int_test_files.clear()
    else:
        int_targets = _discover_integration_targets(view, pkg_name)
        if int_targets:
            int_test_files.update(int_targets.values())
        if (data.get("package", {}).get("autotests", True) if isinstance(data, dict) else True) is not False:
            int_test_files.update(view.glob_files(f"{crate_dir}/tests", ".rs"))
    _CRATE_FILE_CLASS_CACHE[key] = (prod_files, cfg_test_files, int_test_files)
    return prod_files, cfg_test_files, int_test_files


def is_test_only_rust_file(view: RepoView, path: str) -> bool:
    if path.startswith("conformance-probes/"):
        return True
    if not path.startswith("crates/") or not path.endswith(".rs"):
        return False
    parts = path.split("/")
    if len(parts) < 3:
        return False
    if view.is_file(path):
        s_clean, _cs_clean = _blank_macro_defs(view.read_stripped_rust(path), view.read_comments_stripped_rust(path))
        _attrs, ok = _scan_depth0_attributes(s_clean, _compute_brace_depths(s_clean))
        if not ok:
            return False
    prod_files, cfg_test_files, int_test_files = _classify_crate_rust_files(view, parts[1])
    if path in prod_files:
        return False
    if path in cfg_test_files or path in int_test_files:
        return True
    if view.is_file(path):
        inner_cfgs = _extract_cfg_exprs(_extract_scope_inner_attrs(view.read_stripped_rust(path), view.read_comments_stripped_rust(path)), inner_only=True)
        if any(_cfg_is_test_only(e) for e in inner_cfgs):
            return True
    return False


def is_non_guest_path(view: RepoView, path: str) -> bool:
    if not path.endswith(".rs"):
        return True
    if any(path.startswith(ng + "/") or path == ng for ng in NON_GUEST_CRATES):
        return True
    return is_test_only_rust_file(view, path)


def _git_rev_parse(root: Path, rev: str) -> str:
    res = subprocess.run(["git", "rev-parse", "--verify", f"{rev}^{{commit}}"], cwd=root, capture_output=True, text=True, check=False)
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
    deleted_paths: set[str] = set()
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
            elif status == "D":
                deleted_paths.add(path)
            else:
                modified_paths.add(path)

    move_candidates = all_diff_paths - byte_identical_renames - byte_identical_rename_sources
    move_covered = detect_move_covered_files(root, base_sha, head_sha, move_candidates)
    for path in sorted(move_covered):
        print(f"move-covered: {path} ({move_covered[path]} moved lines)")

    # Load and validate exemptions
    exempted_paths = load_and_validate_exemptions(root, exemptions_dir, valid_contracts, all_diff_paths, base_sha, head_sha)

    # Check for unclassified new or renamed paths under crates/ (including R100 renames)
    unclassified = []
    for path in sorted(added_paths | set(renamed_modified_paths.keys()) | byte_identical_renames):
        if (
            path.startswith("crates/")
            and path not in surfaces
            and path not in exempted_paths
        ):
            if not is_non_guest_path(head_view, path):
                unclassified.append(path)

    if unclassified:
        sys.stderr.write(f"error: unclassified paths under crates/ found without surface mapping: {unclassified}\n")
        sys.exit(1)

    errors: list[str] = []

    # P1-2, P1-4a & N3: Check for dropped contract mappings on existing, renamed (including R100), moved, or deleted surfaces
    remapped_on_added: set[str] = {
        c for ap in added_paths for c in surfaces.get(ap, [])
    }
    for base_path, base_cids in sorted(base_surfaces.items()):
        if not base_cids or not base_view.is_file(base_path) or is_test_only_rust_file(base_view, base_path):
            continue
        if base_path in exempted_paths:
            continue
        if base_path in deleted_paths:
            dropped = [c for c in base_cids if c not in remapped_on_added]
            if dropped:
                errors.append(
                    f"error: deleted surface {base_path} dropped contract mapping(s) without exemption or re-mapping: {dropped}"
                )
            continue
        target_path = rename_old_to_new.get(base_path, base_path)
        if target_path in exempted_paths:
            continue
        if not head_view.is_file(target_path):
            continue
        head_cids = set(surfaces.get(target_path, []))
        dropped = [c for c in base_cids if c not in head_cids]
        if dropped:
            errors.append(
                f"error: surface {target_path} dropped contract mapping(s) in surfaces.toml: {dropped}"
            )

    # P1-2: Flag any stale surfaces.toml entry whose path no longer exists at HEAD (including R100 rename sources)
    for s_path in sorted(surfaces):
        if not head_view.is_file(s_path):
            if (
                base_view.is_file(s_path)
                or s_path in all_diff_paths
                or s_path not in base_surfaces
                or surfaces.get(s_path) != base_surfaces.get(s_path)
            ):
                errors.append(f"error: stale surfaces.toml entry for non-existent path {s_path}")

    # Check that each modified classified guest surface has a resolvable gated bound test per contract
    any_contract_toml_changed = any(
        p.startswith("conformance-contracts/contracts/") for p in all_diff_paths
    )
    base_contracts = (
        load_contracts_from_view(base_view) if any_contract_toml_changed else contracts
    )
    head_binding_cache: dict[tuple[str, bool], tuple[str, str, str, list[str]] | None] = {}
    base_binding_cache: dict[str, tuple[str, str, str, list[str]] | None] = {}
    surface_items_cache: dict[str, set[str]] = {}
    evidenced_lines: list[str] = []

    def resolve_head_gated_binding(b_spec: str, require_leaf: bool = False) -> tuple[str, str, str, list[str]] | None:
        key = (b_spec, require_leaf)
        if key not in head_binding_cache:
            resolved = resolve_binding_at_view(head_view, b_spec, require_leaf=require_leaf)
            if resolved is not None and not is_target_in_gated_lane(head_view, resolved[0], resolved[1]):
                resolved = None
            head_binding_cache[key] = resolved
        return head_binding_cache[key]

    def resolve_base_gated_binding(b_spec: str) -> tuple[str, str, str, list[str]] | None:
        if b_spec not in base_binding_cache:
            resolved = resolve_binding_at_view(base_view, b_spec, require_leaf=False)
            if resolved is not None and not is_target_in_gated_lane(base_view, resolved[0], resolved[1]):
                resolved = None
            base_binding_cache[b_spec] = resolved
        return base_binding_cache[b_spec]

    def normalize_ref_tokens(ref_texts: list[str]) -> tuple[tuple[str, ...], ...]:
        return tuple(_fingerprint_tokens(t) for t in ref_texts)

    active_surfaces_by_cid: dict[str, list[str]] = {}
    active_modified_surfaces: list[str] = []
    for path in sorted(modified_paths):
        if path in byte_identical_renames or path in move_covered or path in exempted_paths:
            continue
        if is_test_only_rust_file(head_view, path) or path not in surfaces:
            continue
        active_modified_surfaces.append(path)
        for cid in surfaces[path]:
            active_surfaces_by_cid.setdefault(cid, []).append(path)

    for path in active_modified_surfaces:
        for cid in surfaces[path]:
            contract_data = contracts.get(cid, {})
            head_bindings = extract_contract_test_bindings(contract_data)
            base_bindings = set(extract_contract_test_bindings(base_contracts.get(cid, {})))
            removed_bindings = sorted(base_bindings - set(head_bindings))

            for rem_spec in removed_bindings:
                errors.append(
                    f"error: binding {rem_spec} removed from {cid} while mapped surface {path} changed"
                )

            existing_valid: list[str] = []
            added_valid_for_path: list[str] = []
            added_invalid_for_all: list[str] = []
            added_unresolved: list[str] = []

            for b_spec in head_bindings:
                if b_spec in base_bindings:
                    base_resolved = resolve_base_gated_binding(b_spec)
                    head_resolved_any = resolve_head_gated_binding(b_spec, require_leaf=False)
                    if base_resolved is not None:
                        if head_resolved_any is None:
                            continue
                        if normalize_ref_tokens(base_resolved[3]) == normalize_ref_tokens(head_resolved_any[3]):
                            existing_valid.append(b_spec)
                            continue
                    elif head_resolved_any is None:
                        continue

                resolved_leaf = resolve_head_gated_binding(b_spec, require_leaf=True)
                if resolved_leaf is None:
                    added_unresolved.append(b_spec)
                    continue
                _, _, test_file, ref_texts = resolved_leaf
                if bound_test_references_surface(
                    root, base_view, head_view, base_sha, head_sha, path,
                    test_file, ref_texts, surface_items_cache, renamed_modified_paths,
                ):
                    added_valid_for_path.append(b_spec)
                else:
                    other_surfaces = active_surfaces_by_cid.get(cid, [])
                    refs_any = any(
                        other_p != path and bound_test_references_surface(
                            root, base_view, head_view, base_sha, head_sha, other_p,
                            test_file, ref_texts, surface_items_cache, renamed_modified_paths,
                        )
                        for other_p in other_surfaces
                    )
                    if not refs_any:
                        added_invalid_for_all.append(b_spec)

            for unres_spec in added_unresolved:
                errors.append(
                    f"error: binding {unres_spec} added to {cid} does not resolve to a gated bound test for changed surface {path}"
                )
            for bad_spec in added_invalid_for_all:
                errors.append(
                    f"error: binding {bad_spec} added to {cid} does not reference changed surface {path}"
                )

            valid_tests = existing_valid + added_valid_for_path
            if valid_tests and not added_invalid_for_all and not added_unresolved and not removed_bindings:
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
