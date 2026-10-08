#!/usr/bin/env python3
"""Check and enforce dispatch lock authority across production runtime sources.

This gate inventories raw lock acquisitions in production crate sources:
- `proc` dispatcher state
- `pty_table` state
- `sysv_process` and `sysv_namespace` state
- `file_table_internals`

It enforces that:
1. No unclassified or newly added raw lock acquisitions can appear (fail-closed, shrink-only).
2. Paired SysV mutations use the typed `SysvProcessGuard` -> `SysvNamespacePermit` -> `lock_paired` authority.
3. Standalone SysV operations use the encapsulated `with_state` / `with_sysv_process` closures.
4. Monotone category and total count ceilings cannot be exceeded.
5. Exact trusted boundaries and their classifications are validated.
6. Test scopes, comments, and string literals are ignored.
7. Findings are consumed ephemerally by the position-free authority-debt gate.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import authority_census_verdict as census_verdict

from typing import Sequence


LedgerError = census_verdict.CensusError

REPO_ROOT = Path(__file__).resolve().parents[2]

CATEGORIES = {
    "proc": "raw acquisition of dispatcher `proc` lock",
    "pty_table": "raw acquisition of `pty_table` lock",
    "sysv_process": "raw acquisition of per-process `sysv_process` lock",
    "sysv_namespace": "raw acquisition of shared SysV `state` lock",
    "file_table_internals": "direct acquisition of FileTable internal mutex/rwlock",
}

FILE_TABLE_INTERNAL_FIELDS = frozenset(
    {
        "open_files",
        "next_fd",
        "stdio_cloexec",
        "closed_stdio",
        "fd_open_paths",
        "epoll_fds",
    }
)

# The Rust census and its macro fail-closed check consume this same vocabulary.
LOCK_METHODS = frozenset(
    json.loads((REPO_ROOT / "scripts/migrate/authority-vocabulary.json").read_text())["raw_lock"]
)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    pos: int
    column: int = field(default=0, compare=False)


@dataclass(frozen=True)
class RawLockSite:
    id: str
    file: str
    line: int
    item: str
    category: str
    expression: str
    ordinal: int
    column: int = field(default=0, compare=False)


def lex_rust(source: str) -> list[Token]:
    """Tokenize Rust source while ignoring comments and tracking string/char literals."""
    tokens: list[Token] = []
    i = 0
    line = 1
    length = len(source)

    while i < length:
        char = source[i]
        if char.isspace():
            if char == "\n":
                line += 1
            i += 1
            continue

        if source[i : i + 2] == "//":
            i += 2
            while i < length and source[i] != "\n":
                i += 1
            continue

        if source[i : i + 2] == "/*":
            i += 2
            depth = 1
            while i < length and depth:
                if source[i] == "\n":
                    line += 1
                    i += 1
                elif source[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif source[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue

        raw_prefix = None
        if char == "r":
            raw_prefix = 1
        elif char in {"b", "c"} and i + 1 < length and source[i + 1] == "r":
            raw_prefix = 2
        if raw_prefix is not None:
            cursor = i + raw_prefix
            hashes = 0
            while cursor < length and source[cursor] == "#":
                hashes += 1
                cursor += 1
            if cursor < length and source[cursor] == '"':
                closing = '"' + ("#" * hashes)
                end = source.find(closing, cursor + 1)
                if end < 0:
                    end = length - len(closing)
                end += len(closing)
                text = source[i:end]
                tokens.append(Token("string", text, line, i))
                line += text.count("\n")
                i = end
                continue

        if char == '"' or (
            char in {"b", "c"} and i + 1 < length and source[i + 1] == '"'
        ):
            start = i
            if char in {"b", "c"}:
                i += 1
            i += 1
            while i < length:
                if source[i] == "\n":
                    line += 1
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(Token("string", source[start:i], line, start))
            continue

        if char == "'" or (
            char == "b" and i + 1 < length and source[i + 1] == "'"
        ):
            start = i
            byte_char = char == "b"
            if byte_char:
                i += 1
            i += 1
            if not byte_char and i < length and (
                source[i].isalpha() or source[i] == "_"
            ):
                while i < length and (source[i].isalnum() or source[i] == "_"):
                    i += 1
                if i >= length or source[i] != "'":
                    tokens.append(Token("lifetime", source[start:i], line, start))
                    continue
            while i < length:
                if source[i] == "\\":
                    i += 2
                elif source[i] == "'":
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(Token("char", source[start:i], line, start))
            continue

        # Raw identifiers name the same operation as their ordinary spelling.
        if source.startswith("r#", i) and i + 2 < length and (source[i + 2].isalpha() or source[i + 2] == "_"):
            start_pos = i
            i += 2
            while i < length and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("ident", source[start_pos + 2:i], line, start_pos))
            continue

        if char.isalpha() or char == "_":
            start = i
            i += 1
            while i < length and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(Token("ident", source[start:i], line, start))
            continue

        if char.isdigit():
            start = i
            i += 1
            while i < length and (source[i].isalnum() or source[i] in "._"):
                if source[i] == "." and i + 1 < length and source[i + 1] == ".":
                    break
                i += 1
            tokens.append(Token("number", source[start:i], line, start))
            continue

        two = source[i : i + 2]
        if two in {"::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "..", "+=", "-="}:
            tokens.append(Token("punct", two, line, i))
            i += 2
            continue
        tokens.append(Token("punct", char, line, i))
        i += 1

    return census_verdict.canonical_tokens([
        Token(token.kind, token.text, token.line, token.pos,
              token.pos - source.rfind("\n", 0, token.pos) - 1)
        for token in tokens
    ], source)


def find_enclosing_item(tokens: Sequence[Token], target_idx: int) -> str:
    """Find enclosing type/trait/fn item path."""
    current_impl = None
    current_fn = None

    # Scan backward for nearest fn or impl
    for i in range(target_idx, -1, -1):
        if current_fn is None and tokens[i].text == "fn" and i + 1 < len(tokens) and tokens[i + 1].kind == "ident":
            current_fn = tokens[i + 1].text
        if current_impl is None and tokens[i].text == "impl" and i + 1 < len(tokens):
            ident_candidates = []
            for j in range(i + 1, min(i + 30, len(tokens))):
                if tokens[j].text in {"{", "where", ";"}:
                    break
                if tokens[j].kind == "ident" and tokens[j].text not in {"for", "dyn", "mut", "const"}:
                    ident_candidates.append(tokens[j].text)
            if ident_candidates:
                current_impl = ident_candidates[-1]
        if current_fn and current_impl:
            break

    if current_impl and current_fn:
        return f"{current_impl}::{current_fn}"
    if current_fn:
        return current_fn
    if current_impl:
        return current_impl
    return "<top_level>"


def scan_tokens(tokens: Sequence[Token], relative_path: str, *, source=None, verdict=None) -> list[RawLockSite]:
    """Scan a tokenized Rust file for raw lock acquisition sites."""
    verdict = census_verdict.require(verdict)
    verdict.validate_tree(verdict.data["root"])
    if source is None or tokens != lex_rust(source):
        raise LedgerError("missing or stale source for token scanner")
    production = verdict.production_source(relative_path, source)
    return _scan_production_tokens(lex_rust(production), relative_path)


def _scan_production_tokens(tokens, relative_path):
    raw_occurrences: list[tuple[int, str, str, str, int]] = []  # (line, item, category, expression, column)

    # Track local variable bindings inside functions for local lock alias detection
    fn_aliases: dict[str, str] = {}

    i = 0
    while i < len(tokens):
        if tokens[i].kind == "string":
            i += 1
            continue

        # Check for let binding alias: `let [mut] var_name = ...`
        if tokens[i].text == "let" and i + 1 < len(tokens):
            idx = i + 1
            if idx < len(tokens) and tokens[idx].text == "mut":
                idx += 1
            if idx < len(tokens) and tokens[idx].kind == "ident":
                var_name = tokens[idx].text
                eq_idx = -1
                semi_idx = -1
                for j in range(idx + 1, min(idx + 30, len(tokens))):
                    if tokens[j].text == "=":
                        eq_idx = j
                    elif tokens[j].text in {";", "{"}:
                        semi_idx = j
                        break
                if eq_idx != -1 and semi_idx != -1:
                    rhs_tokens = [t.text for t in tokens[eq_idx + 1 : semi_idx] if t.text not in {"&", "mut", "*", "(", ")"}]
                    if rhs_tokens and rhs_tokens[-1] == "proc":
                        fn_aliases[var_name] = "proc"
                    elif rhs_tokens and rhs_tokens[-1] == "pty_table":
                        fn_aliases[var_name] = "pty_table"
                    elif rhs_tokens and rhs_tokens[-1] == "sysv_process":
                        fn_aliases[var_name] = "sysv_process"
                    elif rhs_tokens and rhs_tokens[-1] == "state" and (
                        "sysv" in rhs_tokens
                        or relative_path.endswith("dispatch/sysv.rs")
                        or relative_path.endswith("dispatch/sysv/lock_authority.rs")
                    ):
                        fn_aliases[var_name] = "sysv_namespace"
                    elif rhs_tokens and rhs_tokens[-1] in FILE_TABLE_INTERNAL_FIELDS:
                        fn_aliases[var_name] = "file_table_internals"

        # Check for lock method invocation: `.<lock_method>(`
        if (
            tokens[i].text == "."
            and i + 1 < len(tokens)
            and tokens[i + 1].text in LOCK_METHODS
            and i + 2 < len(tokens)
            and tokens[i + 2].text == "("
        ):
            lock_method = tokens[i + 1].text
            enclosing = find_enclosing_item(tokens, i)
            category = None
            expr = None

            # Look backwards from `.` at `i`
            # Case 1: Immediately preceded by `)` -> parenthesized or method call
            if i > 0 and tokens[i - 1].text == ")":
                open_idx = -1
                paren_depth = 0
                for k in range(i - 1, -1, -1):
                    if tokens[k].text == ")":
                        paren_depth += 1
                    elif tokens[k].text == "(":
                        paren_depth -= 1
                        if paren_depth == 0:
                            open_idx = k
                            break
                if open_idx != -1:
                    if open_idx > 0 and tokens[open_idx - 1].text == "pty_table":
                        category = "pty_table"
                        expr = f".pty_table.{lock_method}()"
                    else:
                        inner_tokens = [
                            t.text for t in tokens[open_idx + 1 : i - 1] if t.text not in {"(", ")"}
                        ]
                        if inner_tokens:
                            if inner_tokens[-1] == "proc":
                                category = "proc"
                                expr = f".proc.{lock_method}()"
                            elif inner_tokens[-1] == "sysv_process":
                                category = "sysv_process"
                                expr = f".sysv_process.{lock_method}()"
                            elif inner_tokens[-1] == "state" and (
                                "sysv" in inner_tokens
                                or relative_path.endswith("dispatch/sysv.rs")
                                or relative_path.endswith("dispatch/sysv/lock_authority.rs")
                            ):
                                category = "sysv_namespace"
                                expr = f".sysv.state.{lock_method}()" if "sysv" in inner_tokens else f".state.{lock_method}()"
                            elif inner_tokens[-1] == "pty_table":
                                category = "pty_table"
                                expr = f".pty_table.{lock_method}()"
                            elif inner_tokens[-1] in FILE_TABLE_INTERNAL_FIELDS:
                                category = "file_table_internals"
                                expr = f".{inner_tokens[-1]}.{lock_method}()"
                            elif len(inner_tokens) == 1 and inner_tokens[0] in fn_aliases:
                                category = fn_aliases[inner_tokens[0]]
                                expr = f"{inner_tokens[0]}.{lock_method}()"

            # Case 2: Immediately preceded by an ident
            elif i > 0 and tokens[i - 1].kind == "ident":
                prev_ident = tokens[i - 1].text
                if i > 1 and tokens[i - 2].text == ".":
                    if prev_ident == "proc":
                        category = "proc"
                        expr = f".proc.{lock_method}()"
                    elif prev_ident == "pty_table":
                        category = "pty_table"
                        expr = f".pty_table.{lock_method}()"
                    elif prev_ident == "sysv_process":
                        category = "sysv_process"
                        expr = f".sysv_process.{lock_method}()"
                    elif prev_ident == "state":
                        if i > 3 and tokens[i - 3].text == "sysv" and tokens[i - 4].text == ".":
                            category = "sysv_namespace"
                            expr = f".sysv.state.{lock_method}()"
                        elif relative_path.endswith("dispatch/sysv.rs") or relative_path.endswith("dispatch/sysv/lock_authority.rs"):
                            category = "sysv_namespace"
                            expr = f".state.{lock_method}()"
                    elif prev_ident in FILE_TABLE_INTERNAL_FIELDS:
                        category = "file_table_internals"
                        expr = f".{prev_ident}.{lock_method}()"
                elif prev_ident in fn_aliases:
                    category = fn_aliases[prev_ident]
                    expr = f"{prev_ident}.{lock_method}()"

            if category is not None and expr is not None:
                raw_occurrences.append((tokens[i].line, enclosing, category, expr, tokens[i].column))

        i += 1

    # Assign stable ordinals and unique IDs per (file, item, category)
    ordinal_counters: dict[tuple[str, str], int] = {}
    sites: list[RawLockSite] = []
    for line, item, category, expr, column in raw_occurrences:
        key = (item, category)
        ordinal = ordinal_counters.get(key, 0) + 1
        ordinal_counters[key] = ordinal
        site_id = f"{relative_path}::{item}::{category}#{ordinal}"
        sites.append(
            RawLockSite(
                id=site_id,
                file=relative_path,
                line=line,
                item=item,
                category=category,
                expression=expr,
                ordinal=ordinal,
                column=column,
            )
        )

    return sites


def scan_sources(repo_root: Path, *, verdict=None) -> list[RawLockSite]:
    """Scan crate source trees; the Rust census resolves production owners."""
    verdict = census_verdict.require(verdict)
    verdict.validate_tree(repo_root)
    all_sites: list[RawLockSite] = []
    # A declared kernel module can use #[path] outside its physical crate.
    # The Rust census binds these diagnostics to the declaring module owner.
    for rs_file in verdict.source_paths(repo_root):
        relative = str(rs_file.relative_to(repo_root))
        source = rs_file.read_text(encoding="utf-8")
        all_sites.extend(_scan_production_tokens(
            lex_rust(verdict.production_source(relative, source)), relative))

    # Validate that every site ID is globally unique
    seen_ids: set[str] = set()
    for site in all_sites:
        if site.id in seen_ids:
            raise ValueError(f"Duplicate site ID generated: {site.id}")
        seen_ids.add(site.id)

    verdict.validate_tree(repo_root)
    return sorted(all_sites, key=lambda s: (s.file, s.line, s.id))


def validate_sysv_lock_authority_rules(
    repo_root: Path,
    override_sources: dict[str, str] | None = None,
    *, verdict=None,
) -> list[str]:
    """Validate exact visibility tokens and strict caller boundaries for SysV lock authority APIs."""
    verdict = census_verdict.require(verdict)
    verdict.validate_tree(repo_root)
    errors: list[str] = []

    def get_source(rel_path: str) -> str:
        if override_sources and rel_path in override_sources:
            return verdict.production_source(rel_path, override_sources[rel_path])
        full_path = repo_root / rel_path
        return verdict.production_source(rel_path, full_path.read_text(encoding="utf-8")) if full_path.exists() else ""

    # 1. Check exact visibility tokens in crates/carrick-kernel/src/dispatch/sysv.rs
    sysv_source = get_source("crates/carrick-kernel/src/dispatch/sysv.rs")
    expected_restricted_fns = {"with_state", "with_state_mut", "lock_sysv_process", "with_sysv_process", "with_sysv_process_mut"}
    seen_helpers = set()
    if sysv_source:
        sysv_tokens = lex_rust(sysv_source)
        expected_restricted_fns = {
            "with_state",
            "with_state_mut",
            "lock_sysv_process",
            "with_sysv_process",
            "with_sysv_process_mut",
        }
        for idx, token in enumerate(sysv_tokens):
            if token.text == "fn" and idx + 1 < len(sysv_tokens) and sysv_tokens[idx + 1].text in expected_restricted_fns:
                fn_name = sysv_tokens[idx + 1].text
                seen_helpers.add(fn_name)
                # Look backward from `fn` for visibility starting at `pub`
                vis_tokens = []
                k = idx - 1
                found_pub = False
                while k >= 0 and sysv_tokens[k].text not in {"}", ";", "{"}:
                    if sysv_tokens[k].text == "pub":
                        found_pub = True
                        vis_tokens = [t.text for t in sysv_tokens[k:idx]]
                        break
                    k -= 1
                expected_vis = ["pub", "(", "in", "crate", "::", "dispatch", "::", "sysv", ")"]
                if not found_pub or vis_tokens != expected_vis:
                    vis_str = "".join(vis_tokens) if vis_tokens else "private"
                    errors.append(
                        f"crates/carrick-kernel/src/dispatch/sysv.rs: helper '{fn_name}' has unauthorized visibility '{vis_str}' (must be exact 'pub(in crate::dispatch::sysv)')"
                    )

    # with_sysv_process_mut is a cfg(test) fixture helper in production source,
    # so it has no production owner to require. If it becomes production, the
    # same visibility and cross-module rules above/below still apply.
    required_production_helpers = expected_restricted_fns - {"with_sysv_process_mut"}
    missing = required_production_helpers - seen_helpers
    if missing:
        errors.append(f"missing SysV rule owner/helper discovery: {sorted(missing)}")
    paired_source = get_source("crates/carrick-kernel/src/dispatch/sysv/lock_authority.rs")
    paired_tokens = lex_rust(paired_source)
    if not any(t.text == "fn" and i + 1 < len(paired_tokens) and paired_tokens[i + 1].text == "lock_paired" for i, t in enumerate(paired_tokens)):
        errors.append("missing SysvNamespacePermit::lock_paired rule owner discovery")

    # 2. Check strict cross-module caller boundary
    runtime_src = repo_root / "crates/carrick-kernel/src"
    if runtime_src.exists() or override_sources:
        restricted_identifiers = {
            "lock_sysv_process",
            "with_sysv_process",
            "with_sysv_process_mut",
            "SysvProcessGuard",
            "SysvNamespacePermit",
            "SysvPairedNamespaceGuard",
            "lock_paired",
        }
        files_to_check: list[tuple[str, str]] = []
        if override_sources:
            for rpath, src in override_sources.items():
                if (
                    rpath.startswith("crates/carrick-kernel/src/")
                    and not rpath.startswith("crates/carrick-kernel/src/dispatch/sysv")
                    and not rpath.endswith("dispatch/sysv.rs")
                ):
                    files_to_check.append((rpath, src))
        else:
            for path in sorted(runtime_src.rglob("*.rs")):
                rpath = str(path.relative_to(repo_root))
                if not rpath.startswith("crates/carrick-kernel/src/dispatch/sysv") and not rpath.endswith("dispatch/sysv.rs"):
                    files_to_check.append((rpath, path.read_text(encoding="utf-8")))

        for rpath, src in files_to_check:
            tokens = lex_rust(verdict.production_source(rpath, src))
            for idx, token in enumerate(tokens):
                if token.text in restricted_identifiers:
                    errors.append(
                        f"{rpath}:{token.line}: unauthorized cross-module reference to SysV lock authority identifier '{token.text}' outside dispatch::sysv"
                    )
                elif token.text in {"with_state", "with_state_mut"}:
                    # Check if called on sysv namespace
                    if idx > 0 and tokens[idx - 1].text == ".":
                        if idx > 1 and tokens[idx - 2].kind == "ident" and tokens[idx - 2].text in {"sysv", "namespace", "ipc"}:
                            errors.append(
                                f"{rpath}:{token.line}: unauthorized cross-module call to '{token.text}' outside dispatch::sysv"
                            )

    verdict.validate_tree(repo_root)
    return errors


def main():
    parser = argparse.ArgumentParser(description="Discover raw locks and check structural SysV authority")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--discover", action="store_true")
    parser.add_argument("--census-verdict", type=Path, help="Fresh authority-census JSON verdict")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        import subprocess
        return subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", str(REPO_ROOT / "scripts/tests"), "-p", "test_dispatch_locks.py"], cwd=REPO_ROOT)
    verdict = census_verdict.CensusVerdict.load(args.census_verdict)
    errors = validate_sysv_lock_authority_rules(args.root, verdict=verdict)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    sites = scan_sources(args.root, verdict=verdict)
    print(json.dumps([{"file": s.file, "line": s.line, "column": s.column, "category": s.category} for s in sites]))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LedgerError, OSError) as error:
        print(f"error: {Path(__file__).stem}: {error}", file=sys.stderr)
        raise SystemExit(1)
